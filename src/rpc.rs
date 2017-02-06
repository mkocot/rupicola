//    RPC handler for Rupicola.
//    Copyright (C) 2016  Marcin Kocot
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.

use config::*;
use jsonrpc::{JsonRpcServer, JsonRpcRequest, ErrorCode, ErrorJsonRpc, Handler};
use rustc_serialize::json::{ToJson, Json};
use rustc_serialize::base64::{MIME, ToBase64};
use std::process::{Command, Stdio};
use std::collections::HashMap;
use params::{Unroll, MethodParam};
use handlers::{ResponseHandler, HandlerError};
use std::io::{Read, Write, copy, sink};
use std::os::unix::process::CommandExt;
use std::io;
use std::cmp;
use libc;

pub struct RpcHandler {
    /// Methods registered with RPC
    methods: HashMap<String, MethodDefinition>,
}

pub struct RpcHandlerInvokeContext {
    is_auth: bool,
}

impl RpcHandler {
    /// Create new handler for RPC using given methods and names
    pub fn new(methods: HashMap<String, MethodDefinition>) -> RpcHandler {
        RpcHandler { methods: methods }
    }
}

trait MethodInvoke {
    fn invoke(&self, arguments: &[String]) -> Result<Json, ErrorJsonRpc>;
}

impl MethodInvoke for MethodDefinition {
    fn invoke(&self, arguments: &[String]) -> Result<Json, ErrorJsonRpc> {
        let mut base_command = Command::new(&self.path);
        let command = {
            if let RunAs::Custom { gid, uid } = self.run_as {
                base_command.gid(gid).uid(uid)
            } else {
                &mut base_command
            }}
            .args(arguments)
            .stdin(Stdio::null()) // Ignore stdin
            .stderr(Stdio::null()) // Ignore stderr
            .stdout(Stdio::piped()); // Capture stdout

        let command = if self.include_stderr {
            command.stderr(Stdio::piped())
            .before_exec(|| match unsafe { libc::dup2(1, 2) } {
                       code if code >= 0 => Ok(()),
                       code => Err(io::Error::from_raw_os_error(code))
            })
        } else {
            command
        };
        // TODO: Timeout
        command.spawn()
            .and_then(|mut child| {
                // At most limit size
                let mut response_buffer = Vec::new();
                let mut buffer_overrun = false;
                // NOTE: This is wrapped inside {} to allow borrowed stdout go out of scope
                {
                    let mut stdout = if let Some(ref mut stdout) = child.stdout {
                        stdout
                    } else {
                        panic!("No stdout - this is likely a bug in server!");
                    };
                    let mut buffer = [0; 2048];
                    loop {
                        let read = try!(stdout.read(&mut buffer[..]));
                        if read == 0 {
                            debug!("Finished reading response from child stdout");
                            break;
                        }

                        let allowed_write_size = if self.limits.max_response == 0 {
                            read
                        } else {
                            let remaining_response_size =
                                cmp::max(self.limits.max_response as usize - response_buffer.len(),
                                         0);
                            let max_write_chunk = cmp::min(remaining_response_size, read);
                            if max_write_chunk == 0 {
                                error!("Exceed maximum response size! Skipping remaining data!");
                                // TODO: Kill child?
                                try!(copy(stdout, &mut sink()));
                                buffer_overrun = true;
                                break;
                            }
                            if max_write_chunk != read {
                                warn!("Reached maximum allowed response size ({})",
                                      self.limits.max_response);
                            }
                            max_write_chunk as usize
                        };
                        if allowed_write_size > 0 {
                            response_buffer.extend_from_slice(&buffer[0..allowed_write_size]);
                        }
                    }
                }
                let error_code = try!(child.wait());
                if buffer_overrun {
                    Ok(Err((response_buffer, error_code)))
                } else {
                    Ok(Ok((response_buffer, error_code)))
                }
            })
            .map_err(|e| {
                error!("Failed to start command: {}", e);
                ErrorJsonRpc::new(ErrorCode::ServerError(-32001, "Subprocedure failed to run"))
            })
            .and_then(|o| {
                // We could get there in 2 path: normal execution and clamped output execution
                let converted_output = match o {
                    Err((ref o, _)) | Ok((ref o, _)) => {
                        if self.response_encoding == ResponseEncoding::Utf8 {
                            String::from_utf8_lossy(&o).into_owned()
                        } else {
                            o.to_base64(MIME)
                        }
                    }
                };
                match o {
                    Err(_) => {
                        Err(ErrorJsonRpc::new_data(ErrorCode::ServerError(-32003,
                                                                          "Subprocedure exceded \
                                                                           maximum response size"),
                                                   converted_output.to_json()))
                    }
                    Ok((_, error)) if error.success() => Ok(converted_output),
                    Ok((_, error)) => {
                        warn!("[{}] Exit with {}", self.name, error);

                        let mut resp = HashMap::new();
                        resp.insert("exit_code".to_owned(), error.code().unwrap_or(-1).to_json());
                        resp.insert("result".to_owned(), converted_output.to_json());
                        Err(ErrorJsonRpc::new_data(ErrorCode::ServerError(-32005,
                                                                          "Subprocedure \
                                                                           returned error code"),
                                                   resp.to_json()))
                    }
                }
            })
            .and_then(|o| Ok(o.to_json()))
    }
}

impl Handler for RpcHandler {
    type Context = RpcHandlerInvokeContext;
    fn handle(&self, req: &JsonRpcRequest, custom: &Self::Context) -> Result<Json, ErrorJsonRpc> {
        let method = match self.methods.get(req.method) {
            Some(s) if !s.streamed => s,
            _ => {
                error!("[{}] No such method!", req.method);
                return Err(ErrorJsonRpc::new(ErrorCode::MethodNotFound));
            }
        };

        if !custom.is_auth && !method.is_private {
            error!("[{}] Invoking public method without authorization!",
                   req.method);
            return Err(ErrorJsonRpc::new(ErrorCode::ServerError(-32000, "Unauthorized")));
        }
        // TODO: For now hackish solution
        // Allow not only objects but also arrays
        let params = if let Some(p) = req.params {
            p.to_owned()
        } else {
            Json::Null
        };
        // prepare arguments
        let arguments = if let Ok(ok) = get_invoke_arguments(&method.exec_params, &params) {
            ok
        } else {
            error!("[{}] Invalid params for request", req.method);
            return Err(ErrorJsonRpc::new(ErrorCode::InvalidParams));
        };

        info!("[{}] Method invoke with {:?}", req.method, arguments);
        return method.invoke(&arguments);
    }
}

pub fn get_invoke_arguments(exec_params: &[MethodParam], params: &Json) -> Result<Vec<String>, ()> {
    let mut arguments = Vec::new();
    for arg in exec_params {
        match arg.unroll(&params) {
            Ok(Some(s)) => arguments.push(s),
            Err(_) => return Err(()),
            // We dont care about Ok(None)
            _ => {}
        }
    }
    Ok(arguments)
}

impl ResponseHandler for JsonRpcServer<RpcHandler> {
    fn handle_response(&self,
                       req: &str,
                       is_auth: bool,
                       res: &mut Write)
                       -> Result<(), HandlerError> {
        let custom_data = RpcHandlerInvokeContext { is_auth: is_auth };
        try!(res.flush().map_err(|_| HandlerError::InvalidRequest));
        let response = self.handle_request_context(&req, &custom_data);
        if let Some(response) = response {
            info!("Response: {}", response);
            if let Err(e) = res.write(&response.into_bytes()) {
                error!("Error during sending response: {:?}", e);
                return Err(HandlerError::InvalidRequest);
            }
        }
        Ok(())
    }
}
