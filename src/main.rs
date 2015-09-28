extern crate hyper;
extern crate jsonrpc;
extern crate rustc_serialize;
#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;
extern crate yaml_rust;
extern crate regex;

use std::thread;
use std::io::{Read, BufReader, BufRead, Write, BufWriter};
use rustc_serialize::json::{ToJson, Json};
use hyper::status::StatusCode;
use hyper::server::{Server, Request, /*Response,*/ Handler};
use hyper::server::response::*;
use hyper::uri::{RequestUri};
use jsonrpc::{JsonRpcServer, JsonRpcRequest, ErrorCode};
use std::process::*;
use log::{LogRecord, LogLevel, LogMetadata};
use clap::App;
use yaml_rust::{YamlLoader, Yaml};
use std::fs::File;
use regex::Regex;
use std::collections::{HashMap, BTreeSet};
use std::str::FromStr;


struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Info
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }
}



enum MethodType {
    Dll,
    Exec
}

struct SenderHandler {
    //unique client request tracing?
    request_id: u32,
    json_rpc: JsonRpcServer,
    config: ServerConfig
}
impl Handler for SenderHandler {
    fn handle(&self, req: Request, mut res: Response) {
        //Only support of POST
        info!("Processing request from {}. Method {}. Uri {}", req.remote_addr, req.method, req.uri);
        if req.method == hyper::Post {
            if let RequestUri::AbsolutePath(ref path) = req.uri.clone() {
                match path as &str {
                "/streaming" => self.handle_streaming(req, res),
                "/jsonrpc" => self.handle_json_rpc(req, res),
                _ => {
                    error!("Unknown request path: {}", path);
                    *res.status_mut() = StatusCode::NotFound
                    }
                }
            }
        } else {
            *res.status_mut() = StatusCode::NotImplemented;
        }
    }
}


struct ServerConfig {
    address: String,
    port: u16,
    methods: HashMap<String, MethodDefinition>,
    streams: HashMap<String, MethodDefinition>,
    log_level: log::LogLevelFilter
}

struct MethodDefinition {
    name: String,
    path: String,
    //how parse request
    exec_params: Vec<String>,
    variables: HashMap<String, Variable>,
    use_fake_response: Option<Json>
}

enum Variable {
    Positional(i32),
    //variable_name
    Named(String)
}


impl ServerConfig {
    pub fn new () -> ServerConfig {
        ServerConfig {
            address: "127.0.0.1".to_string(),
            port: 1337,
            methods: HashMap::new(),
            streams: HashMap::new(),
            log_level: log::LogLevelFilter::Info
        }
    }
}
fn parse_methods(methods: &Vec<Yaml>, config_methods: &mut HashMap<String, MethodDefinition>) {
        for method_def in methods {
            //let method_def = &method_def_map["method"];
            info!("{:?}", method_def);
            let name = method_def["method"].as_str().unwrap();
            info!("Name: {}", name);
            let _type = method_def["type"].as_str().unwrap();
            info!("Type: {}", _type);
            let path = method_def["path"].as_str().unwrap();
            info!("Path: {}", path);
            let params = &method_def["params"];
            let mut parameters = BTreeSet::<String>::new();

            if params.is_null() || params.is_badvalue() {
                info!("No parameters");
            } else {
                info!("Parameters: {:?}", params);
                //get keys
                if let Some(mapa) = params.as_hash() {
                    for key in mapa.keys() {
                        let key = key.as_str().unwrap();
                        parameters.insert(key.to_string());
                    }
                }
            }

            let fake_response = if let Some(json) = method_def["fake_response"].as_str() {
                Some(json.to_json())
            } else {
                None
            };
            //.map(Json::from_str)//unwrap_or(r(())).ok();

            let mut variables_map = HashMap::<String, Variable>::new();
            let mut variables = Vec::<String>::new();

            if let Some(exec_params) = method_def["exec_params"].as_vec() {
                for exec_param in exec_params {
                    info!("Exec param: {:?}", exec_param);
                    variables.push(exec_param.as_str().unwrap().to_string());
                    //search for variables
                    let re = Regex::new(r"(\$[\w]+)").unwrap();
                    for variable in re.captures_iter(exec_param.as_str().unwrap()) {
                        let variable_name = variable.at(1).unwrap();
                        info!("Var name: {}", variable_name);
                        if !variables_map.contains_key(variable_name) {
                            //is that a number?
                            let var = if let Ok(number) = i32::from_str(&variable_name[1..]) {
                                Variable::Positional(number)
                            } else {
                                if parameters.contains(&variable_name[1..].to_string()) {
                                Variable::Named(variable_name[1..].to_string())
                                } else {
                                    panic!("Unbound parameter {}", variable_name);
                                }
                            };
                            variables_map.insert(variable_name.to_string(), var);
                        }
                    }
                }
            } else {
                warn!("No exec params");
            }
            //check if all required variables are used
            //for req_var in v
            let method_definition = MethodDefinition {
                name: name.to_string(),
                path: path.to_string(),
                //required parameters in rpc
                //params: parameters,
                //this contains app invocation arguments, each argument in its own 
                exec_params: variables,
                //this contains mapping from invocation input to method
                variables: variables_map,
                use_fake_response: fake_response
            };
            config_methods.insert(method_definition.name.clone(), method_definition);
        }
}
fn read_config(config_file: &str) -> ServerConfig {
    let mut server_config = ServerConfig::new();

    info!("Using configuration from: {}", config_file);

    //parse config file
    let mut f = File::open(config_file).unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    let config = YamlLoader::load_from_str(&s).unwrap();
    let config_yaml = &config[0];
    
    if let Some(protocol_definition) = config_yaml["protocol"].as_hash() {
        info!("Parsing protocol definition");
        if let Some(protocol_type) = protocol_definition[&Yaml::String("type".to_string())].as_str() {
            info!("Protocol type: {} (for now ignored)", protocol_type);
        }
        if let Some(address) = protocol_definition[&Yaml::String("address".to_string())].as_str() {
            info!("Address: {}", address);
            server_config.address = address.to_owned();
        }
        if let Some(port) = protocol_definition[&Yaml::String("port".to_string())].as_i64() {
            info!("Port: {}", port);
            server_config.port = port as u16;
        }
    }

    if let Some(methods) = config_yaml["methods"].as_vec() {
        parse_methods(methods, &mut server_config.methods);
    }

    if let Some(streams) = config_yaml["streams"].as_vec() {
        parse_methods(streams, &mut server_config.streams);
    }

    if let Some(log_level) = config_yaml["log"]["level"].as_str() {
        server_config.log_level = match &log_level.to_lowercase() as &str {
            "trace" => log::LogLevelFilter::Trace,
            "debug" => log::LogLevelFilter::Debug,
            "info" => log::LogLevelFilter::Info,
            "warn" => log::LogLevelFilter::Warn,
            "error" => log::LogLevelFilter::Error,
            "off" => log::LogLevelFilter::Off,
            unknown => {
                //Just fallback to already set default
                warn!("Unknown log level: {}", unknown);
                server_config.log_level
            }
        };
    }
    server_config
}

impl SenderHandler {
    fn new(conf: ServerConfig) -> SenderHandler {
        SenderHandler {
            request_id: 0,
            json_rpc: JsonRpcServer::new(),
            config: conf
        }
    }


    fn handle_streaming(&self, mut req: Request, mut res: Response) {
        //Read streaming method name from path
        // POST /streaming
        // {"method": "enter method name here", "params": "Optional params", "id": "optional id"}
        let mut request_str = String::new();
        //TODO: Limit read size
        req.read_to_string(&mut request_str).unwrap();
        info!("--> {}", request_str);
        let request_docs = YamlLoader::load_from_str(&request_str).unwrap();
        let request_params = &request_docs[0];

        let method_name = if let Some(s) = request_params["method"].as_str() {
            s
        } else {
            *res.status_mut() = StatusCode::NotFound;
            return;
        };
        
        let method = self.config.streams.get(method_name);
        if method.is_none() {
            warn!("Requested method {} not found", method_name);
            *res.status_mut() = StatusCode::NotFound;
            return;
        }
        let method = method.unwrap();

        //For now: No parameters parsing
        let mut arguments = Vec::new();
        for arg in &method.exec_params {
            arguments.push(arg);
        }
        info!("Spawn child for {} with args: {:?}", method_name, arguments);

        //Spawn child object
        let child_process = Command::new(&method.path)
            .args(&arguments)
            .stdout(Stdio::piped())
            .spawn().unwrap();

        //Pipe stdout
        let stdout_stream = child_process.stdout.unwrap();
        let mut streaming_response = res.start().unwrap();
        let reader = BufReader::new(stdout_stream);
        for line in reader.lines() {
            let line = line.unwrap();
            info!("<-- {}", line);
            let bytes = line.into_bytes();
            streaming_response.write(&bytes).unwrap();
            streaming_response.write(b"\n").unwrap();
            streaming_response.flush().unwrap();
        }
        info!("Reading STDOUT finished");
        streaming_response.end().unwrap();
    }

    fn handle_json_rpc(&self, mut req: Request, res: Response) {
        //TODO: check required content type
        let mut request = String::new();
        if req.read_to_string(&mut request).is_err() {
            warn!("Unable to read request");
            res.send(b"Bah!").unwrap();
            return;
        }
        info!("Request: {}", request);
        let response = self.json_rpc.handle_custom(self, &request);
        if response != "" {
            info!("Response: {}", response);
            res.send(&response.into_bytes()).unwrap();
        } else {
            info!("Just notification");
        }
    }
}

impl jsonrpc::Handler for SenderHandler {
    fn handle(&self, req: &JsonRpcRequest) -> Result<Json, ErrorCode> {
        info!("Call from callback!");
        let method = self.config.methods.get(&req.method);
        if method.is_none() {
            error!("Requested method '{}' not found!", &req.method);
            return Err(ErrorCode::MethodNotFound)
        }
        let method = method.unwrap();
        
        let params = if let Some(ref p) = req.params {
            p.as_object().unwrap()
        } else {
            return Err(ErrorCode::InvalidParams);
        };

        //prepare arguments
        let mut arguments = Vec::new();
        for arg in &method.exec_params {
            let mut arg = arg.clone();
            info!("Argument before evaluation {}", arg);
            for (key,value) in &method.variables {
                info!("Evaluation: {}", key);
                match *value {
                    Variable::Named(ref name) => {
                        arg = arg.replace(key, params.get(name).unwrap().as_string().unwrap());
                    }
                    _ => {}
                };
                //arg = arg.replace(var.key, req.params[var.value]
            }
            info!("Argument after evaluation {}", arg);
            arguments.push(arg);
        }
        if let Some(ref fake_response) = method.use_fake_response {
            //delayed response...
            info!("Delayed command execution. Faking response {}", fake_response);
            let path = method.path.clone();
            thread::spawn(move || {
                thread::sleep_ms(2000);
                info!("Executing delayed command");
                match Command::new(&path).args(&arguments).output() {
                    Ok(o) => {
                        info!("Execution finished\nStatus: {}\nStdout: {}\nStderr: {}\n",
                               o.status,
                               String::from_utf8_lossy(&o.stdout),
                               String::from_utf8_lossy(&o.stderr));
                    },
                    Err(e) => info!("Failed to execute process: {}", e)
                }
                
            });
            return Ok(fake_response.clone());
        } else {
            let output = Command::new(&method.path)
                .args(&arguments)
                .output()
                .map(|o|String::from_utf8_lossy(&o.stdout).to_json())
                .map_err(|_| ErrorCode::InvalidParams);
            return output;
        }
    }
}

fn set_log_level(level: log::LogLevelFilter) {
    if let Err(e) = log::set_logger(|max_log_level| {
        max_log_level.set(level);
        Box::new(SimpleLogger)
    }) {
        println!("Log framework failed {}", e);
    }

}

/**
 * Main entry point
 * */
fn main() {
    //set default sane log level
    set_log_level(log::LogLevelFilter::Info);

    let yml = load_yaml!("app.yml");
    let m = App::from_yaml(yml).get_matches();

    let config_file = m.value_of("config").unwrap();
    let config = read_config(config_file);

    set_log_level(config.log_level);

    Server::http((&config.address as &str, config.port)).unwrap().handle(SenderHandler::new(config)).unwrap();
}
