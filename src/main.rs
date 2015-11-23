// Local files/dependencies
mod config;

// External dependencies
#[macro_use]
extern crate clap;
extern crate hyper;
extern crate jsonrpc;
#[macro_use]
extern crate log;
extern crate rustc_serialize;
extern crate yaml_rust;

use clap::App;
use config::*;
use hyper::status::StatusCode;
use hyper::server::{Server, Request, Response, Handler};
use hyper::uri::RequestUri;
use hyper::net::Openssl;
use hyper::header::{Authorization, Basic};
use jsonrpc::{JsonRpcServer, JsonRpcRequest, ErrorCode, ErrorJsonRpc};
use rustc_serialize::json::{ToJson, Json};
use rustc_serialize::base64::{STANDARD, ToBase64};
use std::thread;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::collections::HashMap;

struct SenderHandler {
    // unique client request tracing?
    // request_id: u32,
    json_rpc: JsonRpcServer<RpcHandler>,
    config: ServerConfig,
}

struct RpcHandler {
    methods: HashMap<String, MethodDefinition>,
}

impl Handler for SenderHandler {
    fn handle(&self, req: Request, mut res: Response) {
        // Only support of POST
        info!("Processing request from {}. Method {}. Uri {}",
              req.remote_addr,
              req.method,
              req.uri);

        if !self.is_request_authorized(&req) {
            // TODO: is there build-in for this?
            res.headers_mut().set_raw("WWW-Authenticate", vec![b"Basic".to_vec()]);
            *res.status_mut() = StatusCode::Unauthorized;
            return;
        }

        if req.method == hyper::Post {
            if let RequestUri::AbsolutePath(ref path) = req.uri.clone() {
                let path = path as &str;
                if self.config.protocol_definition.stream_path == path {
                    self.handle_streaming(req, res)
                } else if self.config.protocol_definition.rpc_path == path {
                    self.handle_json_rpc(req, res)
                } else {
                    error!("Unknown request path: {}", path);
                    *res.status_mut() = StatusCode::NotFound
                }
            }
        } else {
            warn!("GET is not supported");
            *res.status_mut() = StatusCode::MethodNotAllowed;
        }
    }
}


impl RpcHandler {
    pub fn new(methods: HashMap<String, MethodDefinition>) -> RpcHandler {
        RpcHandler { methods: methods }
    }
}

impl SenderHandler {
    fn new(conf: ServerConfig) -> SenderHandler {
        // Dont like it...
        let json_handler = RpcHandler::new(conf.methods.clone());

        SenderHandler {
            json_rpc: JsonRpcServer::new_handler(json_handler),
            config: conf,
        }
    }

    fn is_request_authorized(&self, req: &Request) -> bool {
        match self.config.protocol_definition.auth {
            AuthMethod::Basic { ref login, ref pass } => {
                info!("Using basic auth");
                // check if user provided required credentials
                let auth_heder = req.headers.get::<Authorization<Basic>>();
                if let Some(ref auth) = auth_heder {
                    // ok.. remove owned string
                    let password = auth.password.clone().unwrap_or("".to_owned());
                    if auth.username != *login || !pass.validate(&password) {
                        warn!("Invalid username or password");
                        false
                    } else {
                        info!("Access granted");
                        true
                    }
                } else {
                    error!("Required basic auth and got none!");
                    false
                }
            }
            AuthMethod::None => true,
        }
    }


    fn handle_streaming(&self, mut req: Request, mut res: Response) {
        // Read streaming method name from path
        // POST /streaming
        let mut request_str = String::new();
        // TODO: Limit read size
        if let Err(e) = req.read_to_string(&mut request_str) {
            error!("Reading request failed {:?}", e);
            *res.status_mut() = StatusCode::BadRequest;
            return;
        }
        info!("--> {}", request_str);
        let request_json = match Json::from_str(&request_str) {
            Ok(s) => s,
            Err(e) => {
                error!("Invalid JSON request: {:?}", e);
                *res.status_mut() = StatusCode::BadRequest;
                return;
            }
        };
        let empty = Json::Null;
        let params = if let Some(j) = request_json.find("params") {
            j
        } else {
            &empty
        };

        //let params = &request_json["params"];
        let method_name = if let Some(s) = request_json["method"].as_string() {
            s
        } else {
            *res.status_mut() = StatusCode::NotFound;
            return;
        };

        let method = match self.config.streams.get(method_name) {
            Some(s) => s,
            None => {
                warn!("Requested method {} not found", method_name);
                *res.status_mut() = StatusCode::NotFound;
                return;
            }
        };

        let arguments = match get_invoke_arguments(&method.exec_params, &params) {
            Err(e) => {
                error!("Error during retrieving arguments: {:?}", e);
                // In case of error terminate right away
                *res.status_mut() = StatusCode::BadRequest;
                return;
            }
            Ok(a) => a,
        };
        info!("Spawn child for {} with args: {:?}", method_name, arguments);
        let mut streaming_response = match res.start() {
            Ok(o) => o,
            Err(e) => {
                error!("Unable to obtain response stream: {:?}", e);
                return;
            }
        };
        // todo: Detect when connection is killed and kill child process
        if let Err(e) = Self::spawn_and_stream(method, &arguments, &mut streaming_response) {
            error!("Processing streamer request failed: {:?}", e);
        }
        if let Err(e) = streaming_response.end() {
            error!("Closing response stream failed: {:?}", e);
            return;
        }
        info!("Reading STDOUT finished")
    }

    fn spawn_and_stream(method: &MethodDefinition,
                        arguments: &[String],
                        streaming_response: &mut Write)
                        -> std::io::Result<()> {
        // Spawn child object
        let mut child_process = try!(Command::new(&method.path)
                                         .args(&arguments)
                                         .stdout(Stdio::piped())
                                         .spawn());

        // Pipe stdout
        let mut reader = if let Some(s) = child_process.stdout {
            s
        } else {
            warn!("Program closed without opening stdout. This is unexpected.");
            try!(child_process.kill());
            return Ok(());
        };

        // Read as bytes chunks
        let mut read_buffer = [0; 2048];
        while let Ok(readed) = reader.read(&mut read_buffer[..]) {
            if readed == 0 {
                info!("End of stream");
                break;
            }
            try!(streaming_response.write(&read_buffer[0..readed]));
            try!(streaming_response.flush());
        } 

        Ok(())
    }

    fn handle_json_rpc(&self, mut req: Request, res: Response) {
        // TODO: check required content type
        let mut request = String::new();
        if req.read_to_string(&mut request).is_err() {
            warn!("Unable to read request");
            return;
        }
        info!("Request: {}", request);
        let response = self.json_rpc.handle_request(&request);
        if let Some(response) = response {
            info!("Response: {}", response);
            if let Err(e) = res.send(&response.into_bytes()) {
                error!("Error during sending response: {:?}", e);
            }
        }
    }
}

fn get_invoke_arguments(exec_params: &Vec<FutureVar>, params: &Json) -> Result<Vec<String>, ()> {
    let mut arguments = Vec::new();
    for arg in exec_params {
        match unroll_variables(arg, &params) {
            Ok(Some(s)) => arguments.push(s),
            Err(_) => return Err(()),
            // We dont care about Ok(None)
            _ => {}
        }
    }
    Ok(arguments)
}

fn unroll_variables(future: &FutureVar, params: &Json) -> Result<Option<String>, ()> {

    match *future {
        FutureVar::Constant(ref s) => Ok(Some(s.clone())),
        FutureVar::Everything => {
            let json = params.to_json().to_string();
            if json.is_empty() {
                Ok(None)
            } else {
                Ok(Some(json))
            }
        }
        FutureVar::Variable(ref v) => {
            // get info from params
            // for now variables support only objects
            match params.find(&v.name as &str) {
                Some(&Json::String(ref s)) if v.param_type == ParameterType::String => {
                    Ok(Some(s.to_owned()))
                }
                Some(&Json::I64(ref i)) if v.param_type == ParameterType::Number => {
                    Ok(Some(i.to_string()))
                }
                Some(&Json::U64(ref i)) if v.param_type == ParameterType::Number => {
                    Ok(Some(i.to_string()))
                }
                Some(&Json::F64(ref s)) if v.param_type == ParameterType::Number => {
                    Ok(Some(s.to_string()))
                }
                // Meh
                Some(ref s) => {
                    error!("Unable to convert. Value = {:?}; target type = {:?}", s, v);
                    Err(())
                }
                None => {
                    if v.optional {
                        Ok(None)
                    } else {
                        error!("Missing required param {:?}", v.name);
                        Err(())
                    }
                }
            }
        }
        FutureVar::Chained(ref c) => {
            let mut result = String::new();
            let mut all_ok = true;

            for e in c.iter() {
                match unroll_variables(e, params) {
                    Ok(Some(ref o)) => result.push_str(o),
                    Ok(None) | Err(_) => {
                        debug!("Optional variable {:?} is missing. Skip whole chain", e);
                        all_ok = false;
                        break;
                    }
                }
            }

            if all_ok {
                Ok(Some(result))
            } else {
                Ok(None)
            }
        }
    }
}

impl jsonrpc::Handler for RpcHandler {
    fn handle(&self, req: &JsonRpcRequest) -> Result<Json, ErrorJsonRpc> {
        let method = if let Some(s) = self.methods.get(req.method) {
            s
        } else {
            error!("Requested method '{}' not found!", req.method);
            return Err(ErrorJsonRpc::new(ErrorCode::MethodNotFound));
        };

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
            error!("Invalid params for request");
            return Err(ErrorJsonRpc::new(ErrorCode::InvalidParams));
        };

        info!("Method invoke with {:?}", arguments);

        if let Some(ref fake_response) = method.use_fake_response {
            // delayed response...
            info!("Delayed command execution. Faking response {}",
                  fake_response);
            let path = method.path.clone();
            let delay = method.delay * 1000;
            thread::spawn(move || {
                thread::sleep_ms(delay);
                info!("Executing delayed ({}ms) command", delay);
                match Command::new(&path).args(&arguments).output() {
                    Ok(o) => {
                        // Log as lossy utf8.
                        // TODO: Limit output size? Eg cat on whole partition?
                        info!("Execution finished\nStatus: {}\nStdout: {}\nStderr: {}\n",
                              o.status,
                              String::from_utf8_lossy(&o.stdout),
                              String::from_utf8_lossy(&o.stderr));
                    }
                    Err(e) => info!("Failed to execute process: {}", e),
                }
            });
            //This method support only utf-8 (we just spit whole json from config...)
            return Ok(fake_response.clone());
        } else {
            //Encode to baseXY?
            let output = Command::new(&method.path)
                             .args(&arguments)
                             .output()
                             .map(|o| { 
                                 if method.response_encoding == ResponseEncoding::Utf8 {
                                    String::from_utf8_lossy(&o.stdout).to_json()
                                 } else {
                                    o.stdout.to_base64(STANDARD).to_json()
                                 }
                             })
                             .map_err(|_| ErrorJsonRpc::new(ErrorCode::InvalidParams));
            return output;
        }
    }
}

/**
 * Main entry point
 * */
fn main() {
    let yml = load_yaml!("app.yml");
    let m = App::from_yaml(yml).get_matches();

    let config_file = m.value_of("config").unwrap_or("/etc/jsonrpcd/jsonrpcd.conf");
    let config = ServerConfig::read_from_file(config_file);
    // set_log_level(config.log_level);
    match config.protocol_definition.protocol.clone() {
        Protocol::Https { ref address, ref port, ref cert, ref key } => {
            // TODO: Manual create context
            //      default values use vulnerable SSLv2, SSLv3
            let ssl = Openssl::with_cert_and_key(cert, key).unwrap();
            Server::https((address as &str, *port), ssl)
                .unwrap()
                .handle(SenderHandler::new(config))
                .unwrap();
        }
        Protocol::Http { ref address, ref port } => {
            Server::http((address as &str, *port))
                .unwrap()
                .handle(SenderHandler::new(config))
                .unwrap();
        }
    }
}
