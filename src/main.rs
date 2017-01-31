//    Main file for Rupicola.
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
#[cfg_attr(feature = "nightly", feature(alloc_system))]
#[cfg(feature = "nightly")]
extern crate alloc_system;

// Local files/dependencies
mod config;
mod params;
mod handlers;
mod lazy_response;
mod rpc;
mod misc;

// External dependencies
extern crate pwhash;

#[cfg(feature = "with_rustls")]
extern crate hyper_rustls;

extern crate getopts;
extern crate hyper;
extern crate hyperlocal;
extern crate jsonrpc;
#[macro_use]
extern crate log;
extern crate rustc_serialize;
extern crate yaml_rust;
extern crate syslog;
extern crate libc;

use config::*;
use hyper::status::StatusCode;
use hyper::server::{Server, Request, Response, Handler};
use hyper::uri::RequestUri;
use hyper::header::{Authorization, Basic};
use hyperlocal::UnixSocketServer;
use jsonrpc::JsonRpcServer;
use rustc_serialize::json::Json;
use std::{env, thread};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::os::unix::process::CommandExt;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};
use getopts::Options;
use std::time::Duration;

use lazy_response::LazyResponse;
use rpc::{RpcHandler, get_invoke_arguments};
use handlers::{HandlerError, ResponseHandler};

// Handler for incoming request
struct SenderHandler {
    /// RPC handler
    json_rpc: JsonRpcServer<RpcHandler>,
    /// Server configuration
    config: Arc<ServerConfig>,
    /// Allow executing private methods from this server instance
    allow_private: bool,
}

impl ResponseHandler for SenderHandler {
    fn handle_response(&self,
                       req: &str,
                       is_auth: bool,
                       res: &mut Write)
                       -> Result<(), HandlerError> {
        // Read streaming method name from path
        // POST /streaming
        info!("--> {}", req);
        let request_json = match Json::from_str(&req) {
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

        let method_name = if let Some(s) = request_json["method"].as_string() {
            s
        } else {
            return Err(HandlerError::InvalidRequest);
        };

        let method = match self.config.methods.get(method_name) {
            Some(s) if s.streamed => s,
            _ => {
                warn!("Requested method {} not found", method_name);
                return Err(HandlerError::NoSuchMethod);
            }
        };

        // check for provate ones
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
        // Enforce request read timeout
        if self.config.default_limits.request_wait != 0 {
            if let Err(e) = req.set_read_timeout(Some(Duration::from_millis(self.config
                .default_limits
                .request_wait
                .into()))) {
                warn!("Changing timeout for request failed: {}", e);
            }
        }
        // if request is from loopback and requested method is private
        // skip this check
        let is_authorized = self.is_request_authorized(&req);

        // Each bind point have it's own permission for loopback requests
        // without checking auth
        let is_loopback = if self.allow_private {
            match req.remote_addr {
                std::net::SocketAddr::V4(addr) => {
                    // Special case: 0.0.0.0:0 -> Unix domain socket
                    addr.port() == 0 && addr.ip().octets() == [0, 0, 0, 0] ||
                    addr.ip().is_loopback()
                }
                std::net::SocketAddr::V6(addr) => addr.ip().is_loopback(),
            }
        } else {
            false
        };

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

        let path = if let RequestUri::AbsolutePath(ref path) = req.uri {
            path.to_owned()
        } else {
            warn!("Invalid path in request");
            return;
        };

        // 1. Check payload size in header
        // this is sufficient as hyper relies on that
        if let Some(&hyper::header::ContentLength(size)) = req.headers
            .get::<hyper::header::ContentLength>() {
            if size > self.config.default_limits.payload_size.into() {
                error!("Request is too big! ({} > {})",
                       size,
                       self.config.default_limits.payload_size);
                return;
            }
        } else {
            error!("Required header: ContentLength is missing!");
            return;
        }

        let mut request_str = String::new();
        let req_result = req.read_to_string(&mut request_str);

        info!("Processing request: {}", request_str);
        let mut lazy = LazyResponse::new(res);
        let response = if let Err(e) = req_result {
            error!("Unable to obtain request data: {}", e);
            Err(HandlerError::InvalidRequest)
        } else if self.config.protocol_definition.stream_path == path {
            self.handle_response(&request_str, is_authorized, &mut lazy)
        } else if self.config.protocol_definition.rpc_path == path {
            self.json_rpc.handle_response(&request_str, is_authorized, &mut lazy)
        } else {
            error!("Unknown request path: {}", path);
            Err(HandlerError::NoSuchMethod)
        };

        if let Err(err) = response {
            // Ok Some errors during processing
            match lazy {
                LazyResponse::Fresh(ref mut resp) => {
                    // Set response code etc
                    *resp.status_mut() = match err {
                        HandlerError::NoSuchMethod => StatusCode::NotFound,
                        HandlerError::InvalidRequest => StatusCode::BadRequest,
                        HandlerError::Unauthorized => StatusCode::Unauthorized,
                    };

                    if !is_authorized || resp.status() == StatusCode::Unauthorized {
                        resp.headers_mut().set_raw("WWW-Authenticate", vec![b"Basic".to_vec()]);
                        *resp.status_mut() = StatusCode::Unauthorized;
                    }
                }
                LazyResponse::Streaming(_) => {
                    warn!("Lazy response should be in FRESH state!");
                }
                LazyResponse::NONE => {
                    error!("Ok somehow something is broken hard");
                    unreachable!();
                }
            }
        }

        if let Err(ref e) = lazy.end() {
            warn!("Closing lazy writer failed: {}", e);
        }
    }
}

impl SenderHandler {
    fn new(conf: Arc<ServerConfig>, allow_private: bool) -> SenderHandler {
        // Dont like it...
        let json_handler = RpcHandler::new(conf.methods.clone());

        SenderHandler {
            json_rpc: JsonRpcServer::new_handler(json_handler),
            config: conf,
            allow_private: allow_private,
        }
    }

    fn is_request_authorized(&self, req: &Request) -> bool {
        let auth_heder = req.headers.get::<Authorization<Basic>>();
        if let Some(ref auth) = auth_heder {
            let password = auth.password.clone().unwrap_or("".to_owned());
            if self.config.protocol_definition.auth.verify(&auth.username, &password) {
                info!("Access granted");
                true
            } else {
                warn!("Invalid username ({}) or password ({})",
                      auth.username,
                      password);
                false
            }
        } else if self.config.protocol_definition.auth.required() {
            // No auth provided but required
            error!("Required basic auth and got none!");
            false
        } else {
            // No auth provided and no required
            true
        }
    }


    fn spawn_and_stream(method: &MethodDefinition,
                        arguments: &[String],
                        streaming_response: &mut Write)
                        -> std::io::Result<()> {
        use std::sync::mpsc::channel;
        // Spawn child object
        let mut base_command = Command::new(&method.path);
        let command = {
                if let RunAs::Custom { gid, uid } = method.run_as {
                    base_command.gid(gid).uid(uid)
                } else {
                    &mut base_command
                }
            }
            .args(arguments)
            .stdout(Stdio::piped());

        let mut child_process = try!(command.spawn());

        // Pipe stdout
        let mut reader = if let Some(s) = child_process.stdout {
            s
        } else {
            warn!("Program closed without opening stdout. This is unexpected.");
            try!(child_process.kill());
            return Ok(());
        };
        // Le't push data from reading thread to main thread using channels
        // this will be much cleaner than fiddling with mutexes on it's own
        let (tx, rx) = channel();
        thread::spawn(move || {
            let mut buffer = [0; 2048];
            loop {
                // it's ok to panic, we catch this event in Err(_) branch
                let result = reader.read(&mut buffer[..]).unwrap();
                tx.send((buffer, result)).unwrap();
                if result == 0 {
                    break;
                }
            }
        });
        try!(streaming_response.flush());
        // TODO: This is ugly and hacky implementation
        let hard_limit_wait = method.limits.read_timeout;
        let mut total_wait_time = 0;
        loop {
            match rx.try_recv() {
                Ok((ref data, size)) => {
                    // Reset sleep timer every time we get data
                    total_wait_time = 0;
                    if size > 0 {
                        try!(streaming_response.write_all(&data[0..size]));
                        try!(streaming_response.flush());
                    } else {
                        info!("End Of Stream");
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // This is ugly ...
                    let wait_timeout = std::time::Duration::new(1, 0);
                    // This is inaccurate as hell
                    total_wait_time += 1000;
                    thread::sleep(wait_timeout);
                    if hard_limit_wait > 0 && total_wait_time > hard_limit_wait {
                        warn!("Timeout while waiting for data");
                        break;
                    }
                }
                Err(_) => {
                    info!("Channel borked");
                    break;
                }
            }
        }

        Ok(())
    }
}

/**
 * Create TLS processing context using Rustls
 * */
#[cfg(feature = "with_rustls")]
fn prepare_ssl_context(cert: &str, key: &str) -> hyper_rustls::TlsServer {
    let certs = hyper_rustls::util::load_certs(cert);
    let key = hyper_rustls::util::load_private_key(key);
    hyper_rustls::TlsServer::new(certs, key)
}

/**
 * Create SSL/TLS processing context using Openssl
 * */
#[cfg(not(feature = "with_rustls"))]
fn prepare_ssl_context(cert: &str, key: &str) -> hyper::net::Openssl {
    hyper::net::Openssl::with_cert_and_key(cert, key).unwrap()
}

impl Protocol {
    pub fn listen(&self,
                  config: Arc<ServerConfig>,
                  barrier: Arc<Barrier>)
                  -> thread::JoinHandle<()> {
        match *self {
            Protocol::Https { ref address, port, ref cert, ref key, allow_private } => {
                let ssl = prepare_ssl_context(cert, key);
                let address = address.clone();
                thread::spawn(move || {
                    match Server::https((&address as &str, port), ssl)
                        .and_then(|s| s.handle(SenderHandler::new(config, allow_private))) {
                        Ok(_) => info!("HTTPS listener started: {}@{}", address, port),
                        Err(e) => error!("Failed listening HTTPS {}@{}: {}", address, port, e),
                    }
                    barrier.wait();
                })
            }
            Protocol::Http { ref address, port, allow_private } => {
                let address = address.clone();
                thread::spawn(move || {
                    match Server::http((&address as &str, port))
                        .and_then(|s| s.handle(SenderHandler::new(config, allow_private))) {
                        Ok(_) => info!("HTTP listener started: {}@{}", address, port),
                        Err(e) => error!("Failed listening HTTP {}@{}: {}", address, port, e),
                    }
                    barrier.wait();
                })
            }
            Protocol::Unix { ref address,
                             allow_private,
                             file_mode,
                             file_owner_uid,
                             file_owner_gid } => {
                let address = address.clone();
                // Try unbind, or just merilly triple over it?
                if let Err(e) = std::fs::remove_file(&address) {
                    info!("Unlink file failed: {}", e);
                }
                thread::spawn(move || {
                    match UnixSocketServer::new(&address)
                        .and_then(|s| s.handle(SenderHandler::new(config, allow_private))) {
                        Ok(mut l) => {
                            info!("Unix listener started: {}", &address);

                            // Ok now correct permissions for socket
                            if let Err(e) = std::fs::metadata(&address).and_then(|p| {
                                let mut p = p.permissions();
                                p.set_mode(file_mode);
                                std::fs::set_permissions(&address, p)
                            }) {
                                error!("Unable to set permission for {}: {}", &address, e);
                                let _ = l.close();
                            }

                            // file uid gid
                            if let Err(e) = misc::chown(&address, file_owner_uid, file_owner_gid) {
                                error!("Unable to set socket owner: {}", e);
                                let _ = l.close();
                            }
                        }
                        Err(e) => error!("Failed listening UNIX {}: {}", &address, e),
                    }

                    // Clean after
                    if let Err(e) = std::fs::remove_file(&address) {
                        info!("Removing socket ({}) failed: {}", &address, e);
                    }
                    barrier.wait();
                })
            }
        }
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
        Err(e) => panic!(e.to_string()),
    };

    if matches.opt_present("h") {
        let brief = format!("Rupicola  Copyright (C) 2016  Marcin Kocot
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions

Usage: {} [options]",
                            program);
        print!("{}", opts.usage(&brief));
        return;
    }

    if matches.opt_present("v") {
        print!("0.1.0");
        return;
    }

    let config_file = matches.opt_str("c").unwrap_or("/etc/rupicola/rupicola.conf".to_owned());

    info!("Starting parsing configuration");
    let config = match ServerConfig::read_from_file(&config_file) {
        Ok(config) => Arc::new(config),
        Err(e) => {
            error!("Unable to parse config file: {}", e);
            error!("Exiting");
            panic!();
        }
    };

    // Barrier will wait for 2 signals before proceeding further
    // this mean 1 signal is always from main thread, and second one only
    // if any listening thread will fail
    info!("Starting listeners");
    let barrier = Arc::new(Barrier::new(2));
    for protocol in config.protocol_definition.bind.iter() {
        protocol.listen(config.clone(), barrier.clone());
    }
    // Beyond this point is only The Land of Bork
    barrier.wait();
    warn!("Atleast one listening thread failed! Exiting now!");
}
