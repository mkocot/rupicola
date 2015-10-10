extern crate hyper;
extern crate jsonrpc;
extern crate rustc_serialize;
extern crate log;
extern crate clap;
extern crate yaml_rust;
extern crate regex;

use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;
use std::io::{Read};
use rustc_serialize::json::{ToJson, Json};
use yaml_rust::{YamlLoader, Yaml};
use self::regex::Regex;
use std::collections::{HashMap, BTreeSet, BTreeMap};
use std::str::FromStr;
use std::fs::File;

pub enum AuthMethod {
    None,
    Basic { login: String, pass: String }
}

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
    pub log_level: log::LogLevelFilter,
    pub auth: AuthMethod,
}

#[derive(Clone)]
pub struct MethodDefinition {
    pub name: String,
    pub path: String,
    //how parse request
    pub exec_params: Vec<FutureVar>,
    pub variables: HashMap<String, ParameterDefinition>,
    pub use_fake_response: Option<Json>,
    /// Delayed execution in seconds
    pub delay: u32
}

#[derive(Debug, Clone)]
pub enum FutureVar {
    //This is just constant string
    Constant(String),
    //This is ref to parameter definition
    Variable(ParameterDefinition),
    Chained(Vec<FutureVar>)
}

impl FutureVar {
    pub fn is_constant(&self) -> bool {
        match *self {
            FutureVar::Constant(_) => true,
            _ => false
        }
    }
}

#[derive(Debug, Clone)]
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
    pub fn new () -> ServerConfig {
        ServerConfig {
            use_https: false,
            address: "127.0.0.1".to_owned(),
            port: 1337,
            cert: None,
            key: None,
            methods: HashMap::new(),
            streams: HashMap::new(),
            log_level: log::LogLevelFilter::Info,
            auth: AuthMethod::None
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
            if let Some(protocol_type) = protocol_definition[&Yaml::String("type".to_owned())].as_str() {
                info!("Protocol type: {}", protocol_type);
                if protocol_type == "https" {
                    server_config.cert = config_yaml["protocol"]["cert"].as_str().map(|o|o.to_owned());
                    server_config.key = config_yaml["protocol"]["key"].as_str().map(|o|o.to_owned());
                    server_config.use_https = true;
                }
            }
            if let Some(address) = protocol_definition[&Yaml::String("address".to_owned())].as_str() {
                info!("Address: {}", address);
                server_config.address = address.to_owned();
            }
            if let Some(port) = protocol_definition[&Yaml::String("port".to_owned())].as_i64() {
                info!("Port: {}", port);
                server_config.port = port as u16;
            }
            //we want basic auth?
            let basic_auth_config = &config_yaml["protocol"]["auth-basic"];
            if !basic_auth_config.is_badvalue() {
                //Ok we get non empty node check if we have all required fields
                match (&basic_auth_config["login"], &basic_auth_config["password"]) {
                    (&Yaml::String(ref login), &Yaml::String(ref password)) => {
                        info!("Using basic auth");
                        server_config.auth = AuthMethod::Basic { login: login.to_owned(), pass: password.to_owned() }
                    },
                    (&Yaml::String(_), _)  => warn!("basic-auth: login field required"),
                    (_, &Yaml::String(_)) => warn!("basic-auth: password field required"),
                    _ => warn!("Invalid basic-auth definition!")
                }
            } else {
                warn!("Server is free4all. Consider using some kind of auth");
            }
        }

        if let Some(methods) = config_yaml["methods"].as_hash() {
            parse_methods(methods, &mut server_config.methods);
        }

        if let Some(streams) = config_yaml["streams"].as_hash() {
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

fn extract_param (h: &Yaml, parameters: &HashMap<String, ParameterDefinition>) -> Option<FutureVar> {
    //Only support if this is {param: name} case
    match h["param"].as_str() {
        Some(s) => {
            let param_ref = parameters.get(s);
            match param_ref {
                None => {
                    error!("No binding for {:?}", s);
                    None
                },
                Some(s) => {
                    Some(FutureVar::Variable(s.clone()))
                }
            }
        },//todo: continue for outer loop
        None => {
            error!("Expected {{param: name}}, but found {:?}", h["param"]);
            None
        }
    }
}

fn parse_param(exec_param: &Yaml, parameters: &HashMap<String, ParameterDefinition>) -> Result<FutureVar, ()> {
    //this should make FLAT structure in future
    info!("Exec param: {:?}", exec_param);

    fn extract_simple(exec_param: &Yaml, parameters: &HashMap<String, ParameterDefinition>) -> Result<FutureVar, ()> {
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
                    error!("Error: processing {:?} - {}", exec_param["param"], e);
                    return Err(());
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

fn parse_methods(methods: &BTreeMap<Yaml, Yaml>, config_methods: &mut HashMap<String, MethodDefinition>) {
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
        //The EXEC type method
        let path = invoke["exec"].as_str().unwrap();
        let delay = invoke["delay"].as_i64()
            .and_then(|delay| if delay < 0 || delay > 30 { None } else {Some(delay)})
            .unwrap_or(10) as u32;
        let params = &method_def["params"];
        //contains all required and optional parameters
        let mut parameters = HashMap::<String, ParameterDefinition>::new();
        if let Some(mapa) = params.as_hash() {
            for (name_it, definition_it) in mapa {
                //required
                let name = name_it.as_str().unwrap().to_owned();
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
                parameters.insert(name, definition);
            }
        } else {
            error!("Invalid value for field param");
        }

        //For now only string...
        let fake_response = if let Some(json) = method_def["response"].as_str() {
            Some(json.to_json())
        } else {
            None
        };

        //let mut variables_map = HashMap::<String, Variable>::new();
        let mut variables = Vec::<FutureVar>::new();

        if let Some(exec_params) = invoke["args"].as_vec() {
            for exec_param in exec_params {
                variables.push(parse_param(exec_param, &parameters).unwrap());
            }
        }

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
        config_methods.insert(method_definition.name.clone(), method_definition);
    }
}
