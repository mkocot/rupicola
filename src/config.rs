extern crate hyper;
extern crate jsonrpc;
extern crate rustc_serialize;
extern crate log;
extern crate clap;
extern crate yaml_rust;
extern crate regex;

use std::collections::VecDeque;
use std::sync::Arc;
use std::io::{Read};
use rustc_serialize::json::{ToJson, Json};
use yaml_rust::{YamlLoader, Yaml};
use std::collections::{HashMap, BTreeMap};
use std::fs::File;

pub enum AuthMethod {
    None,
    Basic { login: String, pass: String }
}

#[derive(Clone)]
pub enum Protocol {
    Http {
        address: String,
        port: u16
    },

    Https {
        address: String,
        port: u16,
        cert: String,
        key: String
    }
}

pub struct ProtocolDefinition {
    pub protocol: Protocol,
    pub auth: AuthMethod,
    pub stream_path: String,
    pub rpc_path: String
}

pub struct ServerConfig {
    pub protocol_definition: ProtocolDefinition,
    pub methods: HashMap<String, MethodDefinition>,
    pub streams: HashMap<String, MethodDefinition>,
    pub log_level: log::LogLevelFilter,
}

#[derive(Clone)]
pub struct MethodDefinition {
    pub name: String,
    pub path: String,
    //how parse request
    pub exec_params: Vec<FutureVar>,
    pub variables: HashMap<String, Arc<ParameterDefinition>>,
    pub use_fake_response: Option<Json>,
    /// Delayed execution in seconds
    pub delay: u32
}

//#[derive(Clone)]
//pub enum MethodType {
//    Exec {
//    }
//}

#[derive(Debug, Clone)]
pub enum FutureVar {
    //This is just constant string
    Constant(String),
    //This is ref to parameter definition
    Variable(Arc<ParameterDefinition>),
    Chained(Vec<FutureVar>),
    //Capture all params as one-line json string
    Everything
}

impl FutureVar {
    pub fn is_constant(&self) -> bool {
        match *self {
            FutureVar::Constant(_) => true,
            _ => false
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParameterType {
    String,
    Number
}

#[derive(Debug, Clone)]
pub struct ParameterDefinition {
    pub name: String,
    pub optional: bool,
    pub param_type: ParameterType
}

impl ServerConfig {
    //TODO: remove this
    pub fn new () -> ServerConfig {
        ServerConfig {
            protocol_definition: ProtocolDefinition { protocol: Protocol::Http {
                address: "127.0.0.1".to_owned(),
                port: 1337,
            },
            auth: AuthMethod::None,
            rpc_path: "/jsonrpc".to_owned(),
            stream_path: "/streaming".to_owned()
            },
            methods: HashMap::new(),
            streams: HashMap::new(),
            log_level: log::LogLevelFilter::Info,
        }
    }

    pub fn parse_protocol_definition(config: &Yaml) -> Result<ProtocolDefinition, ()> {
        let protocol_definition = &config["protocol"];
        let auth;
        let protocol;
        if config["protocol"].as_hash().is_some() {
            info!("Parsing protocol definition");
            if let Some(protocol_type) = protocol_definition["type"].as_str() {
                let address = if let Some(addr) = protocol_definition["address"].as_str() {
                    info!("Address: {}", addr);
                    addr.to_owned()
                } else {
                    warn!("No bindpoint! Using 127.0.0.1");
                    "127.0.0.1".to_owned()
                };

                let port = if let Some(port) = protocol_definition["port"].as_i64() {
                    info!("Port: {}", port);
                    port as u16
                } else {
                    error!("No port! Using 1337");
                    1337
                };

                info!("Protocol type: {}", protocol_type);
                let cert = protocol_definition["cert"].as_str().map(|o|o.to_owned());
                let key = protocol_definition["key"].as_str().map(|o|o.to_owned());
                if protocol_type == "https" && (cert.is_none() || key.is_none()) {
                    if cert.is_none() || key.is_none() {
                        error!("Requested https but not provided private key and certificate!");
                        return Err(());
                    } else {
                        protocol = Protocol::Https {
                            address: address,
                            port: port,
                            key: key.unwrap(),
                            cert: cert.unwrap()
                        };
                    }
                } else {
                    protocol = Protocol::Http {
                        address: address,
                        port: port
                    };
                }
            } else {
                error!("No protocol type! Using HTTP");
                return Err(());
            }
            //we want basic auth?
            let basic_auth_config = &protocol_definition["auth-basic"];
            auth = if !basic_auth_config.is_badvalue() {
                //Ok we get non empty node check if we have all required fields
                match (&basic_auth_config["login"], &basic_auth_config["password"]) {
                    (&Yaml::String(ref login), &Yaml::String(ref password)) => {
                        info!("Using basic auth");
                        AuthMethod::Basic { login: login.to_owned(), pass: password.to_owned() }
                    },
                    (&Yaml::String(_), _)  => {
                        error!("basic-auth: login field required");
                        return Err(());
                    },
                    (_, &Yaml::String(_)) => {
                        error!("basic-auth: password field required");
                        return Err(());
                    },
                    _ => {
                        error!("Invalid basic-auth definition!");
                        return Err(());
                    }
                }
            } else {
                warn!("Server is free4all. Consider using some kind of auth");
                AuthMethod::None
            }
        } else {
            error!("No protocol field!");
            return Err(());
        };

        Ok(ProtocolDefinition {
            protocol: protocol,
            auth: auth,
            rpc_path: config["rpc"].as_str().unwrap_or("/jsonrpc").to_owned(),
            stream_path: config["streamed"].as_str().unwrap_or("/streaming").to_owned()
        })
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
        server_config.protocol_definition = Self::parse_protocol_definition(config_yaml).unwrap();

        if let Some(methods) = config_yaml["methods"].as_hash() {
            parse_methods(methods, &mut server_config.methods, &mut server_config.streams);
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

fn parse_param(exec_param: &Yaml, parameters: &HashMap<String, Arc<ParameterDefinition>>) -> Result<FutureVar, ()> {
    //this should make FLAT structure in future
    info!("Exec param: {:?}", exec_param);

    fn extract_simple(exec_param: &Yaml, parameters: &HashMap<String, Arc<ParameterDefinition>>) -> Result<FutureVar, ()> {
        //Bind all simple types
        if let Some(c) = match *exec_param {
            Yaml::Real(ref s) | Yaml::String(ref s) => Some(s.to_owned()),
            Yaml::Integer(ref i) => Some(i.to_string()),
            Yaml::Boolean(ref b) => Some(b.to_string()),
            //Complex types
            _ => None
        } {
            return Ok(FutureVar::Constant(c));
        }
        //Do we have simple parameter reference here?
        if exec_param.as_hash().is_some() {
            match exec_param["param"]
            .as_str()
            .ok_or("Expected {{param: name}} object!")
            .and_then(|s|parameters.get(s).ok_or("No binding for variable."))
            .map(|s|FutureVar::Variable(s.clone())) {
                Ok(s) => return Ok(s),
                Err(e) => {
                    //we need to check if this is case of self
                    match exec_param["param"].as_str() {
                        Some("self")=> return Ok(FutureVar::Everything),
                        _=> {
                    error!("Error: processing {:?} - {}", exec_param["param"], e);
                    return Err(());
                        }
                    }
                }
            }
        }
        Err(())
    };
    //Now comes the bad one...

    if let Some(v) = exec_param.as_vec() {
        //for now just assume this is non nested string array
        let mut ugly_solution = Vec::new();
        //Convert current vector to queue
        let mut current_queue: VecDeque<_> = v.iter().collect();
        info!("Nested structure: {:?}", current_queue);

        while !current_queue.is_empty() {
            //At this point we know it never be empty
            let element = current_queue.pop_front().unwrap();
            match *element {
                //is this simple and well known thingy?
                Yaml::String(_) | Yaml::Real(_) | Yaml::Integer(_) | Yaml::Boolean(_)
                | Yaml::Hash(_) => {
                    let item = extract_simple(&element, parameters).unwrap();

                    let to_add = if ugly_solution.is_empty() || !item.is_constant() {
                        item
                    } else {
                        let last_item = ugly_solution.pop().unwrap();
                        match last_item {
                            FutureVar::Constant(ref s) => { //create new constant
                                let current_item = match item {
                                    FutureVar::Constant(s) => s,
                                    _ => panic!("Impossibru")
                                };
                                let mut a = s.clone();
                                a.push_str(&current_item);
                                info!("Merged: {:?}", a);
                                FutureVar::Constant(a.to_owned())},
                            _ => {
                                info!("Put back");
                                ugly_solution.push(last_item);
                                item
                            }
                        }
                    };
                    ugly_solution.push(to_add);
                }
                Yaml::Array(ref array) => {
                    //ok just shrink by one
                    //Everytime we get there we reomve one level of
                    //We need reverse order when adding parametes
                    //so firs element in array is first in queue
                    for item in array.iter().rev() {
                        info!("Pushing to queue {:?}", item);
                        current_queue.push_front(item);
                    }
                }
                _ => error!("Unsupported element: {:?}", element)
            }
        }
        info!("Final single chain: {:?}", ugly_solution);
        //Great we should have single level vector
        //In case of single element just return it without wrapper
        if ugly_solution.len() == 1 {
            info!("Final chain is single item. Just return this element");
            return Ok(ugly_solution.pop().unwrap());
        }
        return Ok(FutureVar::Chained(ugly_solution));
    } else {
        //Just for printing error
        extract_simple(exec_param, parameters).map_err(|_|{
                error!("Unsupported param type");
            })
    }
}

fn parse_methods(methods: &BTreeMap<Yaml, Yaml>,
                 rpc_config_methods: &mut HashMap<String, MethodDefinition>,
                 str_config_methods: &mut HashMap<String, MethodDefinition>) {
    for (method_name, method_def) in methods {
        //Name method MUST be string
        let name = match method_name.as_str() {
            Some(name) => name,
            None => {warn!("Method name {:?} is invalid", method_name); continue;}
        };
        let invoke = &method_def["invoke"];
        if invoke.as_hash() == None {
            warn!("Method {}: Missing required parameter 'invoke'", name);
            continue;
        }
        let streamed = method_def["streamed"].as_bool().unwrap_or(false);
        //The EXEC type method
        let path = invoke["exec"].as_str().unwrap();
        let delay = invoke["delay"].as_i64()
            .and_then(|delay| if delay < 0 || delay > 30 { None } else {Some(delay)})
            .unwrap_or(10) as u32;
        
        let params = &method_def["params"];
        //contains all required and optional parameters
        let mut parameters = HashMap::new();
        if let Some(mapa) = params.as_hash() {
            for (name_it, definition_it) in mapa {
                //required
                let name = name_it.as_str().unwrap().to_owned();
                if name == "self" {
                    error!("Used restricted keyword 'self'. Ignoring.");
                    continue;
                }
                //optional
                let optional = definition_it["optional"].as_bool().unwrap_or(false);
                //hmm reguired..
                let param_type = match definition_it["type"].as_str().unwrap_or("") {
                    "string" => ParameterType::String,
                    "number" => ParameterType::Number,
                    _ => {
                        error!("No parameter type or invalid value for {:?}", name);
                        continue;
                    }
                };
                let definition = ParameterDefinition {
                    param_type: param_type,
                    name: name.clone(),
                    optional: optional
                };
                info!("Param: {:?}", name);
                parameters.insert(name, Arc::new(definition));
            }
        } else {
            error!("Invalid value for field param");
        }

        let mut variables = Vec::<FutureVar>::new();

        if let Some(exec_params) = invoke["args"].as_vec() {
            for exec_param in exec_params {
                variables.push(parse_param(exec_param, &parameters).unwrap());
            }
        }
        //For now only string...
        let fake_response = if let Some(json) = method_def["response"].as_str() {
            Some(json.to_json())
        } else {
            None
        };


        let method_definition = MethodDefinition {
            name: name.to_owned(),
            path: path.to_owned(),
            //this contains app invocation arguments, each argument in its own
            exec_params: variables,
            //this contains mapping from invocation input to method
            variables: parameters,
            use_fake_response: fake_response,
            delay: delay
        };

        if streamed {
            str_config_methods.insert(method_definition.name.clone(), method_definition);
        } else {
            rpc_config_methods.insert(method_definition.name.clone(), method_definition);
        }
    }
}
