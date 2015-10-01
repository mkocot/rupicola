extern crate hyper;
extern crate jsonrpc;
extern crate rustc_serialize;
extern crate log;
extern crate clap;
extern crate yaml_rust;
extern crate regex;

use std::io::{Read};
use rustc_serialize::json::{ToJson, Json};
use yaml_rust::{YamlLoader, Yaml};
use self::regex::Regex;
use std::collections::{HashMap, BTreeSet};
use std::str::FromStr;
use std::fs::File;


pub enum MethodType {
    Dll,
    Exec
}

pub struct ServerConfig {
    pub use_https: bool,
    pub address: String,
    pub port: u16,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub methods: HashMap<String, MethodDefinition>,
    pub streams: HashMap<String, MethodDefinition>,
    pub log_level: log::LogLevelFilter
}

#[derive(Clone)]
pub struct MethodDefinition {
    pub name: String,
    pub path: String,
    //how parse request
    pub exec_params: Vec<String>,
    pub variables: HashMap<String, Variable>,
    pub use_fake_response: Option<Json>
}

#[derive(Clone)]
pub enum Variable {
    Positional(i32),
    //variable_name
    Named(String)
}


impl ServerConfig {
    pub fn new () -> ServerConfig {
        ServerConfig {
            use_https: false,
            address: "127.0.0.1".to_string(),
            port: 1337,
            cert: None,
            key: None,
            methods: HashMap::new(),
            streams: HashMap::new(),
            log_level: log::LogLevelFilter::Info
        }
    }

    pub fn read_from_file(config_file: &str) -> ServerConfig {
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
                info!("Protocol type: {}", protocol_type);
                if protocol_type == "https" {
                    server_config.cert = config_yaml["protocol"]["cert"].as_str().map(|o|o.to_owned());
                    server_config.key = config_yaml["protocol"]["key"].as_str().map(|o|o.to_owned());
                    server_config.use_https = true;
                }
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
        let method_definition = MethodDefinition {
            name: name.to_string(),
            path: path.to_string(),
            //this contains app invocation arguments, each argument in its own 
            exec_params: variables,
            //this contains mapping from invocation input to method
            variables: variables_map,
            use_fake_response: fake_response
        };
        config_methods.insert(method_definition.name.clone(), method_definition);
    }
}
