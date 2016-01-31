use config::*;
use jsonrpc::{JsonRpcServer, JsonRpcRequest, ErrorCode, ErrorJsonRpc, Handler};
use rustc_serialize::json::{ToJson, Json};
use rustc_serialize::base64::{STANDARD, ToBase64};
use std::thread;
use std::time::Duration;
use std::process::{Command, Stdio};
use std::collections::HashMap;
use params::{Unroll, MethodParam};
use handlers::{ResponseHandler, HandlerError};
use std::io::{Read, Write, copy, sink};
use std::os::unix::process::CommandExt;
use std::cmp;

pub struct RpcHandler {
    /// Methods registered with RPC
    methods: HashMap<String, MethodDefinition>,
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
            .args(&arguments)
            .stdin(Stdio::null()) // Ignore stdin
            .stderr(Stdio::null()) // Ignore stderr
            .stdout(Stdio::piped()); // Capture stdout

        command.spawn().and_then(|child| {
            // At most limit size
            let mut response_buffer = Vec::new();
            let mut stdout = if let Some(stdout) = child.stdout {
                stdout
            } else {
                panic!("No stdout - this is likely a bug in server!");
            };
            let mut buffer_overrun = false;
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
                    let remaining_response_size = cmp::max(
                            self.limits.max_response as usize - response_buffer.len(), 0);
                    let max_write_chunk = cmp::min(remaining_response_size, read);
                    if max_write_chunk == 0 {
                        error!("Exceed maximum response size! Skipping remaining data!");
                        try!(copy(&mut stdout, &mut sink()));
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

            if buffer_overrun {
                Ok(Err(response_buffer))
            } else {
                Ok(Ok(response_buffer))
            }
        }).map_err(|e| {
            error!("Failed to start command: {}", e);
            ErrorJsonRpc::new(ErrorCode::ServerError(-32001, "Subprocedure failed to run"))
        }).and_then(|o| {
            // We could get there in 2 path: normal execution and clamped output execution
            let converted_output =  match o {
                Err(ref o) | Ok(ref o) => {
                    if self.response_encoding == ResponseEncoding::Utf8 {
                        String::from_utf8_lossy(&o).into_owned()
                    } else {
                        o.to_base64(STANDARD)
                    }
                },
            };
            match o {
                Err(_) => Err(ErrorJsonRpc::new_data(
                        ErrorCode::ServerError(-32003,
                                "Subprocedure exceded maximum response size"),
                                converted_output.to_json())),
                Ok(_) => Ok(converted_output)
            }
        }).and_then(|o| {
            Ok(o.to_json())
        })
    }
}

impl Handler for RpcHandler {
    fn handle(&self,
              req: &JsonRpcRequest,
              custom: &HashMap<&str, Json>) -> Result<Json, ErrorJsonRpc> {
        let method = if let Some(s) = self.methods.get(req.method) {
            s
        } else {
            error!("[{}] No such method!", req.method);
            return Err(ErrorJsonRpc::new(ErrorCode::MethodNotFound));
        };

        let is_auth = custom["is_auth"].as_boolean().unwrap_or(false);
        if !is_auth && !method.is_private {
            error!("[{}] Invoking public method without authorization!",
                   req.method);
            return Err(ErrorJsonRpc::new(
                    ErrorCode::ServerError(-32000, "Unauthorized")));
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
        if let Some(ref fake_response) = method.use_fake_response {
            // delayed response... this is rare corner case
            // cloning method definition if perfectly acceptable
            info!("[{}] Delayed command execution. Faking response {}",
                  req.method, fake_response);
            let method_clone = method.clone();
            thread::spawn(move || {
                thread::sleep(Duration::new(method_clone.delay as u64, 0));
                info!("Executing delayed ({}ms) command", method_clone.delay);
                let procedure_result = method_clone.invoke(&arguments);
                info!("Delayed execution finished: {:?}", procedure_result);
            });
            //This method support only utf-8 (we just spit whole json from config...)
            return Ok(fake_response.clone());
        } else {
            return method.invoke(&arguments);
        }
    }
}

pub fn get_invoke_arguments(exec_params: &[MethodParam],
                            params: &Json) -> Result<Vec<String>, ()> {
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
                       req: &mut Read,
                       res: &mut Write,
                       is_auth: bool) -> Result<(), HandlerError> {
        let mut request = String::new();
        if req.read_to_string(&mut request).is_err() {
            warn!("Unable to read request");
            return Err(HandlerError::InvalidRequest);
        }
        info!("Processing request: {}", request);
        let mut custom_data = HashMap::new();
        custom_data.insert("is_auth", is_auth.to_json());
        let response = self.handle_request_custom(&request, Some(&custom_data));
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

