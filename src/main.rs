#![feature(ip)]

// Local files/dependencies
mod config;
mod params;
mod handlers;
mod lazy_response;
mod rpc;

// External dependencies
extern crate getopts;
extern crate hyper;
extern crate hyperlocal;
extern crate jsonrpc;
#[macro_use]
extern crate log;
extern crate rustc_serialize;
extern crate yaml_rust;

use config::*;
use hyper::status::StatusCode;
use hyper::server::{Server, Request, Response, Handler};
use hyper::uri::RequestUri;
use hyper::net::Openssl;
use hyper::header::{Authorization, Basic};
use hyperlocal::UnixSocketServer;
use jsonrpc::JsonRpcServer;
use rustc_serialize::json::Json;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::os::unix::process::CommandExt;
use std::env;
use getopts::Options;

use lazy_response::LazyResponse;
use rpc::{RpcHandler, get_invoke_arguments};
use handlers::{HandlerError, ResponseHandler};

struct SenderHandler {
    json_rpc: JsonRpcServer<RpcHandler>,
    config: ServerConfig,
}

impl ResponseHandler for SenderHandler {
    fn handle_response(&self,
                       req: &mut Read,
                       res: &mut Write,
                       is_auth: bool) -> Result<(), HandlerError> {
        // Read streaming method name from path
        // POST /streaming
        let mut request_str = String::new();
        // TODO: Limit read size
        if let Err(e) = req.read_to_string(&mut request_str) {
            error!("Reading request failed {:?}", e);
            return Err(HandlerError::InvalidRequest);
        }
        info!("--> {}", request_str);
        let request_json = match Json::from_str(&request_str) {
            Ok(s) => s,
            Err(e) => {
                error!("Invalid JSON request: {:?}", e);
                return Err(HandlerError::InvalidRequest);
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
            return Err(HandlerError::InvalidRequest);
        };

        let method = match self.config.streams.get(method_name) {
            Some(s) => s,
            None => {
                warn!("Requested method {} not found", method_name);
                return Err(HandlerError::NoSuchMethod);
            }
        };

        //check for provate ones
        if !method.is_private && !is_auth {
            warn!("Invoking method requires auth!");
            return Err(HandlerError::Unauthorized);
        }

        let arguments = match get_invoke_arguments(&method.exec_params, &params) {
            Err(e) => {
                error!("Error during retrieving arguments: {:?}", e);
                return Err(HandlerError::InvalidRequest);
            }
            Ok(a) => a,
        };
        info!("Spawn child for {} with args: {:?}", method_name, arguments);

        // todo: Detect when connection is killed and kill child process
        if let Err(e) = Self::spawn_and_stream(method, &arguments, res) {
            error!("Processing streamer request failed: {:?}", e);
            return Err(HandlerError::InvalidRequest);
        }

        info!("Reading STDOUT finished");
        Ok(())
    }
}

impl Handler for SenderHandler {
    fn handle(&self, mut req: Request, mut res: Response) {
        // Only support of POST
        info!("Processing request from {}. Method {}. Uri {}",
              req.remote_addr,
              req.method,
              req.uri);
        // if request is from loopback and requested method is private
        // skip this check
        let is_authorized = self.is_request_authorized(&req);
        let is_loopback = match req.remote_addr {
            std::net::SocketAddr::V4(addr) => {
                // Special case: 0.0.0.0:0 -> Unix domain socket
                // Check for 0.0.0.0 is done by 'is_unspecified'
                addr.port() == 0 && addr.ip().is_unspecified() || addr.ip().is_loopback()
            },
            std::net::SocketAddr::V6(addr) => addr.ip().is_loopback(),
        };

        if is_loopback {
            info!("Response from loopback");
        }

        // Enable this check early for normal requests
        // TODO: This almos repeat what is below in response
        if !is_loopback && !is_authorized {
            // TODO: is there build-in for this?
            res.headers_mut().set_raw("WWW-Authenticate", vec![b"Basic".to_vec()]);
            *res.status_mut() = StatusCode::Unauthorized;
            return;
        }

        if req.method != hyper::Post {
            warn!("{:?} is not supported", req.method);
            *res.status_mut() = StatusCode::MethodNotAllowed;
        }

        if let RequestUri::AbsolutePath(ref path) = req.uri.clone() {
            // 1) Check payload size in header
            // this is sufficient as hyper relies on that
            if let Some(&hyper::header::ContentLength(size)) = req.headers.get::<hyper::header::ContentLength>() {
                if size > self.config.default_limits.payload_size as u64 {
                    error!("Request is too big! ({} > {})",
                            size, self.config.default_limits.payload_size);
                }
            } else {
                error!("Required header: ContentLength is missing!");
            }

            let path = path as &str;
            let mut lazy = LazyResponse::new(res);
            let response = if self.config.protocol_definition.stream_path == path {
                self.handle_response(&mut req, &mut lazy, is_authorized)
            } else if self.config.protocol_definition.rpc_path == path {
                lazy.enable_buffer();
                self.json_rpc.handle_response(&mut req, &mut lazy, is_authorized)
            } else {
                error!("Unknown request path: {}", path);
                Err(HandlerError::NoSuchMethod)
            };

            if let Err(err) = response {
                // Ok Some errors during processing
                match lazy {
                    LazyResponse::Fresh(ref mut resp, _) => {
                        //Set response code etc
                        *resp.status_mut() = match err {
                            HandlerError::NoSuchMethod => StatusCode::NotFound,
                            HandlerError::InvalidRequest => StatusCode::BadRequest,
                            HandlerError::Unauthorized => StatusCode::Unauthorized
                        };

                        if !is_authorized || resp.status() == StatusCode::Unauthorized {
                            resp.headers_mut().set_raw("WWW-Authenticate",
                                                       vec![b"Basic".to_vec()]);
                            *resp.status_mut() = StatusCode::Unauthorized;
                        }
                    }
                    LazyResponse::Streaming(_) => {
                        warn!("Lazy response should be in FRESH state!");
                    }
                    LazyResponse::NONE => {
                        unreachable!();
                    }
                }
            }

            if let Err(ref e) = lazy.end() {
                warn!("Closing lazy writer failed: {}", e);
            }
        }
    
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


    fn spawn_and_stream(method: &MethodDefinition,
                        arguments: &[String],
                        streaming_response: &mut Write)
                        -> std::io::Result<()> {
        // Spawn child object
        let mut base_command = Command::new(&method.path);
        let command = {
            if let RunAs::Custom { gid, uid } = method.run_as {
                base_command.gid(gid).uid(uid)
            } else {
                &mut base_command
            }}
            .args(&arguments).stdout(Stdio::piped());

        let mut child_process = try!(command.spawn());

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

}

/**
 * Main entry point
 * */
fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("c", "config", "Set config file", "CONFIG");
    opts.optflag("h", "help", "Print this help menu");
    opts.optflag("v", "version", "Print program version");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => panic!(e.to_string())
    };
    if matches.opt_present("h") {
        let brief = format!("Simple RPC daemon with streaming.\nUsage: {} [options]", program);
        print!("{}", opts.usage(&brief));
        return;
    }
    if matches.opt_present("v") {
        print!("0.1.0");
        return;
    }
    let config_file = matches.opt_str("c").unwrap_or("/etc/jsonrpcd/jsonrpcd.conf".to_owned());
    let config = ServerConfig::read_from_file(&config_file);
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
        Protocol::Unix { ref address } => {
            UnixSocketServer::new(address)
                .unwrap()
                .handle(SenderHandler::new(config))
                .unwrap();
        }
    }
}
