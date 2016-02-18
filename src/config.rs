extern crate log;
extern crate syslog;

use params::MethodParam;
use rustc_serialize::json::{ToJson, Json};
use rustc_serialize::hex::ToHex;
use std::sync::Arc;
use std::io::Read;
use std::collections::{HashMap, VecDeque, BTreeMap};
use std::fs::File;
use std::os::unix::raw::{gid_t, uid_t, mode_t};
use openssl::crypto::hash::{hash as hash_fn, Type};
use log::{LogRecord, LogLevelFilter, LogMetadata};
use yaml_rust::{YamlLoader, Yaml};
use syslog::Facility;
use ufile;

/// Stored password type
pub enum PassType {
    /// Plaintex
    Plain(String),
    /// Hashed using MD5 as base function
    Md5(String),
    /// Hashed using SHA1 as base function
    Sha1(String),
}

/// Implement validation method for given password storage
impl PassType {
    pub fn validate(&self, pass: &str) -> bool {
        match *self {
            PassType::Plain(ref p) => p == pass,

            PassType::Md5(ref hash) => {
                hash_fn(Type::MD5, pass.as_bytes()).to_hex() == *hash
            },

            PassType::Sha1(ref hash) => {
                hash_fn(Type::SHA1, pass.as_bytes()).to_hex() == *hash
            }
        }
    }
}

/// Access control method
pub enum AuthMethod {
    /// No checking for any permissions
    None,
    /// Check permission based on login and hashed (recommended) password
    Basic {
        /// Login
        login: String,
        /// Selected password checking method
        pass: PassType,
    },
}

/// Internal protocol details required to start server
#[derive(Clone)]
pub enum Protocol {
    /// Base version using TCP listener
    Http {
        /// Listening address
        address: String,
        /// Listening port
        port: u16,
        /// Allow using private methods from loopback
        allow_private: bool,
    },
    /// Extended version using TCP listener and SSL
    Https {
        /// Listening address
        address: String,
        /// Listening port
        port: u16,
        /// Path to PK8 cert
        cert: String,
        /// Path to PK8 private key
        key: String,
        /// Allow using private methods from loopback
        allow_private: bool,
    },
    /// Unix domain socket based version
    Unix {
        address: String,
        /// Allow using private methods from loopback
        allow_private: bool,
        /// Mode to set on socket after creating
        file_mode: mode_t,
        /// Changing group ownership of socket
        file_owner_gid: gid_t,
        /// Changing ownership of socket
        file_owner_uid: uid_t,
    },
}

/// Limits used by various methods
#[derive(Clone, Debug)]
pub struct Limits {
    /// Maximum time delay between reading data from external function.
    pub read_timeout: u32,
    /// Maximum procedure invocation time in ms. Set to 0 to disable.
    pub exec_timeout: u32,
    /// Maximum request size in bytes. Set to 0 to disable.
    pub payload_size: u32,
    /// Maximum response size in bytes. Set to 0 to disable.
    pub max_response: u32,
    /// Maximum waiting time for client request (in ms). Set 0 to disable.
    pub request_wait: u32,
}

impl Limits {
    pub fn new() -> Limits {
        Limits {
            read_timeout: 10000,
            exec_timeout: 0,
            payload_size: 5242880,
            max_response: 5242880,
            request_wait: 30000,
        }
    }
}

/// Server bindpoint and auth method
pub struct ProtocolDefinition {
    /// Listening bindpoints
    pub bind: Vec<Protocol>,
    /// Auth method
    pub auth: AuthMethod,
    /// Path for streaming functions
    pub stream_path: String,
    /// Path for RPC functions
    pub rpc_path: String,
}

/// Server configuration
pub struct ServerConfig {
    pub protocol_definition: ProtocolDefinition,
    pub methods: HashMap<String, MethodDefinition>,
    pub streams: HashMap<String, MethodDefinition>,
    pub log_level: log::LogLevelFilter,
    // Arc to allow easy sharint this among
    // method definition
    pub default_limits: Arc<Limits>,
}

/// Response encoding returned to client
#[derive(Clone, PartialEq)]
pub enum ResponseEncoding {
    /// Return response as utf-8
    Utf8,
    /// Convert response with base64 encoding. Use this for binary data.
    Base64,
}

/// Privilage of called subprocedure
#[derive(Clone)]
pub enum RunAs {
    /// Invoke subprocedure with GID and UID of server process
    Default,
    /// Change GID and UID before starting subprocedure
    Custom { gid: gid_t, uid: uid_t}
}

/// Expected output from called subprocedure
#[derive(Clone, PartialEq)]
pub enum OutputEncoding {
    /// Output is converted to utf-8 string
    Text,
    /// Output is converted to JSON
    Json
}

/// Method description
#[derive(Clone)]
pub struct MethodDefinition {
    /// Method name
    pub name: String,
    /// Path to executable or library
    pub path: String,
    /// Parameters passed to call
    pub exec_params: Vec<MethodParam>,
    /// Variables
    pub variables: HashMap<String, Arc<ParameterDefinition>>,
    /// Fake response used for methods with delayed execution
    pub use_fake_response: Option<Json>,
    /// Delayed execution in seconds
    pub delay: u32,
    /// Response encoding
    pub response_encoding: ResponseEncoding,
    /// Private method - accessible only from loopback and without auth
    pub is_private: bool,
    /// Override limits for execution time and response size
    pub limits: Arc<Limits>,
    /// Desire privilage configuration
    pub run_as: RunAs,
    /// Subprocedure output encoding
    pub output: OutputEncoding,
    /// Method support streaming extension
    pub streamed: bool,
}


impl MethodParam {
    pub fn is_constant(&self) -> bool {
        match *self {
            MethodParam::Constant(_) => true,
            _ => false,
        }
    }
}

/// Type of parameter
#[derive(Debug, Clone, PartialEq)]
pub enum ParameterType {
    /// Any input that can be converted to string
    String,
    /// Input that is valid number (float or integer)
    Number,
    /// Input with true and false value
    Bool
}

/// Description of parameter
#[derive(Debug, Clone)]
pub struct ParameterDefinition {
    /// Name of parameter
    pub name: String,
    /// Is this parameter optional?
    pub optional: bool,
    /// Type of parameter
    pub param_type: ParameterType,
    /// Default value (if any)
    pub default: Option<String>,
}

impl ParameterType {
    pub fn convert(&self, val: &Json) -> Result<Option<String>, ()> {
        match *val {
            Json::String(ref s) if *self == ParameterType::String => Ok(Some(s.to_owned())),
            Json::I64(ref i) if *self == ParameterType::Number => Ok(Some(i.to_string())),
            Json::U64(ref i) if *self == ParameterType::Number => Ok(Some(i.to_string())),
            Json::F64(ref i) if *self == ParameterType::Number => Ok(Some(i.to_string())),
            Json::Boolean(ref b) if *self == ParameterType::Bool => Ok(Some(b.to_string())),
            _ => Err(())
        }
    }

    pub fn convert_yaml(&self, val: &Yaml) -> Result<Option<String>, ()> {
        match *val {
            Yaml::Real(ref r) if *self == ParameterType::Number => Ok(Some(r.to_owned())),
            Yaml::Integer(ref i) if *self == ParameterType::Number => Ok(Some(i.to_string())),
            Yaml::Boolean(ref b) if *self == ParameterType::Bool => Ok(Some(b.to_string())),
            Yaml::String(ref s) if *self == ParameterType::String => Ok(Some(s.to_owned())),
            _ => Err(())
        }
    }
}


struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, _: &LogMetadata) -> bool {
        true
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }
}

fn set_log_level(level: log::LogLevelFilter, backend: &str, path: Option<&str>) {
    if let Err(e) = log::set_logger(|max_log_level| {
        max_log_level.set(level);
        if backend == "syslog" {
            let facility = Facility::LOG_USER;
            if let Some(socket_path) = path {
                syslog::unix_custom(facility, socket_path).unwrap()
            } else {
                syslog::unix(facility).unwrap()
            }
        } else {
            Box::new(SimpleLogger)
        }
    }) {
        println!("Log framework failed {}", e);
    }
}

impl ServerConfig {
    fn parse_bind_point(protocol_definition: &Yaml) -> Result<Protocol, ()> {
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
                // This is error only if protocol is != Unix
                if protocol_type != "unix" {
                    error!("No port defined!");
                    return Err(());
                }
                // just return "random" value it will never be used anyway
                0
            };

            info!("Protocol type: {}", protocol_type);
            let allow_private = protocol_definition["allow_private"].as_bool().unwrap_or(false);
            let cert = protocol_definition["cert"].as_str().map(str::to_owned);
            let key = protocol_definition["key"].as_str().map(str::to_owned);
            if protocol_type == "https" && (cert.is_none() || key.is_none()) {
                if cert.is_none() || key.is_none() {
                    error!("Requested https but not provided private key and certificate!");
                    return Err(());
                } else {
                    return Ok(Protocol::Https {
                        address: address,
                        port: port,
                        key: key.unwrap(),
                        cert: cert.unwrap(),
                        allow_private: allow_private,
                    });
                }
            } else if protocol_type == "http" {
                return Ok(Protocol::Http {
                    address: address,
                    port: port,
                    allow_private: allow_private,
                });
            } else if protocol_type == "unix" {
                let uid = protocol_definition["uid"].as_i64().map(|g|g as uid_t);
                let gid = protocol_definition["gid"].as_i64().map(|g|g as gid_t);
                // This Is Silly! Unable to convert value to string... 
                let file_mode = protocol_definition["mode"].as_i64().and_then(|mode| {
                    match u32::from_str_radix(&format!("{}", mode), 8) {
                        Ok(m) if m <= 0o777 => Some(m),
                        Ok(_) => {
                            info!("Invalid mode: {}", mode);
                            None
                        }
                        Err(e) => {
                            info!("Conversion for mode failed: {}", e);
                            None
                        }
                    }
                }).unwrap_or_else(|| {
                    info!("Using default mode for socket");
                    0o666
                });
                let (file_owner_uid, file_owner_gid) = match (uid, gid) {
                    (Some(uid), Some(gid)) => (uid, gid),
                    (Some(uid), None) => (uid, ufile::getgid()),
                    (None, Some(gid)) => (ufile::getuid(), gid),
                    (None, None) => (ufile::getuid(), ufile::getgid()),
                };
                return Ok(Protocol::Unix {
                    address: address,
                    allow_private: allow_private,
                    file_owner_uid: file_owner_uid,
                    file_owner_gid: file_owner_gid,
                    file_mode: file_mode,
                });
            } else {
                error!("Invalid protocol type '{}'!", protocol_type);
                return Err(());
            }
        } else {
            error!("No protocol type! Using HTTP");
            return Err(());
        }
    }
    pub fn parse_protocol_definition(config: &Yaml) -> Result<ProtocolDefinition, ()> {
        let protocol_definition = &config["protocol"];
        let auth;
        let bind_points;
        if config["protocol"].as_hash().is_some() {
            info!("Parsing protocol definition");
            // Get all bind points
            let points = protocol_definition["bind"].as_vec().map(|v| {
                let x: Vec<_> = v.iter().filter_map(|e| Self::parse_bind_point(e).ok() ).collect();
                x
            });
            bind_points = match points {
                None => {
                    error!("Required field 'bind' is missing");
                    return Err(());
                },
                Some(ref s) if s.is_empty() => {
                    error!("Unable to parse at least one bind point!");
                    return Err(());
                },
                Some(s) => s
            };
            
            let basic_auth_config = &protocol_definition["auth-basic"];
            auth = if !basic_auth_config.is_badvalue() {
                let login = if let Some(s) = basic_auth_config["login"].as_str() {
                    s.to_owned()
                } else {
                    warn!("basic-auth: Invalid or absent login field");
                    return Err(());
                };

                //Digest: None, Md5, Sha1, moar in future
                let pass_digest = basic_auth_config["password"]["digest"].as_str().unwrap_or("none").to_lowercase();
                let pass_hash = if let Some(s) =  basic_auth_config["password"]["hash"].as_str() {
                    s.to_owned()
                } else {
                    warn!("basic-auth: No required hash field");
                    return Err(());
                };

                //type conversion bug again
                let pass = match &pass_digest as &str {
                    "none" => PassType::Plain(pass_hash),
                    "sha1" => PassType::Sha1(pass_hash),
                    "md5" => PassType::Md5(pass_hash),
                    _ => {
                        warn!("basic-auth: Invalid digest!");
                        return Err(());
                    }
                };

                AuthMethod::Basic {
                    login: login,
                    pass: pass
                }
            } else {
                warn!("Server is free4all. Consider using some kind of auth");
                AuthMethod::None
            }
        } else {
            error!("No protocol field!");
            return Err(());
        }
        // Parse limits
        let proto_def = ProtocolDefinition {
            bind: bind_points,
            auth: auth,
            rpc_path: config["uri"]["rpc"].as_str().unwrap_or("/jsonrpc").to_owned(),
            stream_path: config["uri"]["streamed"].as_str().unwrap_or("/streaming").to_owned(),
        };
        info!("Path for RPC: {}", proto_def.rpc_path);
        info!("Path for Stream: {}", proto_def.stream_path);
        Ok(proto_def)
    }

    pub fn read_from_file(config_file: &str) -> ServerConfig {
        // parse config file
        let mut f = match File::open(config_file) {
            Ok(file) => file,
            Err(e) => {
                panic!("Unable to read config file {}. Error: {}", config_file, e);
            }
        };
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        let config = YamlLoader::load_from_str(&s).unwrap();
        let config_yaml = &config[0];

        //let mut server_config = ServerConfig::new();
        let backend = config_yaml["log"]["backend"].as_str().map_or("stdout".to_owned(), |s|s.to_lowercase());
        let path = config_yaml["log"]["path"].as_str();
        let log_level = config_yaml["log"]["level"].as_str().and_then(|s| {
            match &s.to_lowercase() as &str {
                "trace" => Some(LogLevelFilter::Trace),
                "debug" => Some(LogLevelFilter::Debug),
                "info" => Some(LogLevelFilter::Info),
                "warn" => Some(LogLevelFilter::Warn),
                "error" => Some(LogLevelFilter::Error),
                "off" => Some(LogLevelFilter::Off),
                unknown => {
                    println!("Unknown log level: {}", unknown);
                    None
                }
            }}).unwrap_or(LogLevelFilter::Info);

        // set default sane log level (we should set it to max? or max only in debug)
        set_log_level(log_level, &backend, path);
        info!("Using configuration from: {}", config_file);

        let protocol_definition = Self::parse_protocol_definition(config_yaml).unwrap();
        let mut methods = HashMap::<String, MethodDefinition>::new();
        let mut streams = HashMap::<String, MethodDefinition>::new();
        info!("{:?}", config_yaml["limits"]);
        let default_limits = Arc::new(parse_limits(&config_yaml["limits"], &Limits::new()));
        info!("{:?}", default_limits);
        if let Some(methods_node) = config_yaml["methods"].as_hash() {
            parse_methods(methods_node, &mut methods, &mut streams, &default_limits);
        }

        ServerConfig {
            protocol_definition: protocol_definition,
            log_level: log_level,
            methods: methods,
            streams: streams,
            default_limits: default_limits
        }
    }
}

fn parse_limits(node: &Yaml, proto: &Limits) -> Limits {
    Limits {
        read_timeout: node["read-timeout"].as_i64().map_or(proto.read_timeout, |i|i as u32),
        exec_timeout: node["exec-timeout"].as_i64().map_or(proto.exec_timeout, |i|i as u32),
        payload_size: node["payload-size"].as_i64().map_or(proto.payload_size, |i|i as u32),
        max_response: node["max-response"].as_i64().map_or(proto.max_response, |i|i as u32),
        request_wait: node["request-wait"].as_i64().map_or(proto.request_wait, |i|i as u32),
    }
}

fn extract_simple(exec_param: &Yaml,
                  parameters: &HashMap<String, Arc<ParameterDefinition>>)
                  -> Result<MethodParam, ()> {
    // Bind all simple types
    if let Some(c) = match *exec_param {
        Yaml::Real(ref s) | Yaml::String(ref s) => Some(s.to_owned()),
        Yaml::Integer(ref i) => Some(i.to_string()),
        Yaml::Boolean(ref b) => Some(b.to_string()),
        // Complex types
        _ => None,
    } {
        return Ok(MethodParam::Constant(c));
    }
    // Do we have simple parameter reference here?
    if exec_param.as_hash().is_some() {
        let skip_output = exec_param["skip"].as_bool().unwrap_or(false);
        match exec_param["param"]
                  .as_str()
                  .ok_or("Expected {{param: name}} object!")
                  .and_then(|s| parameters.get(s).ok_or("No binding for variable."))
                  .map(|s| MethodParam::Variable(s.clone(), skip_output)) {
            Ok(s) => return Ok(s),
            Err(e) => {
                // we need to check if this is case of self
                match exec_param["param"].as_str() {
                    Some("self") => return Ok(MethodParam::Everything),
                    _ => {
                        error!("Error: processing {:?} - {}", exec_param["param"], e);
                        return Err(());
                    }
                }
            }
        }
    }
    Err(())
}

fn parse_param(exec_param: &Yaml,
               parameters: &HashMap<String, Arc<ParameterDefinition>>)
               -> Result<MethodParam, ()> {
    // this should make FLAT structure in future
    debug!("Exec param: {:?}", exec_param);

    // Now comes the bad one...

    if let Some(v) = exec_param.as_vec() {
        // for now just assume this is non nested string array
        let mut ugly_solution = Vec::new();
        // Convert current vector to queue
        let mut current_queue: VecDeque<_> = v.iter().collect();
        debug!("Nested structure: {:?}", current_queue);

        while !current_queue.is_empty() {
            // At this point we know it never be empty
            let element = if let Some(s) = current_queue.pop_front() {
                s
            } else {
                error!("Empty queue, reported as non empty");
                return Err(());
            };
            match *element {
                // is this simple and well known thingy?
                Yaml::String(_) |
                Yaml::Real(_) |
                Yaml::Integer(_) |
                Yaml::Boolean(_) |
                Yaml::Hash(_) => {
                    let item = if let Ok(s) = extract_simple(&element, parameters) {
                        s
                    } else {
                        error!("Invalid definition in parameter {:?}", element);
                        return Err(());
                    };

                    let to_add = if ugly_solution.is_empty() || !item.is_constant() {
                        item
                    } else {
                        let last_item = if let Some(s) = ugly_solution.pop() {
                            s
                        } else {
                            error!("Empty queue reported as non empty");
                            return Err(());
                        };
                        match last_item {
                            MethodParam::Constant(ref s) => {
                                // create new constant
                                let current_item = match item {
                                    MethodParam::Constant(s) => s,
                                    _ => panic!("Impossibru"),
                                };
                                let mut a = s.clone();
                                a.push_str(&current_item);
                                debug!("Merged: {:?}", a);
                                MethodParam::Constant(a.to_owned())
                            }
                            _ => {
                                debug!("Put back");
                                ugly_solution.push(last_item);
                                item
                            }
                        }
                    };
                    ugly_solution.push(to_add);
                }
                Yaml::Array(ref array) => {
                    // ok just shrink by one
                    // Everytime we get there we reomve one level of
                    // We need reverse order when adding parametes
                    // so firs element in array is first in queue
                    for item in array.iter().rev() {
                        debug!("Pushing to queue {:?}", item);
                        current_queue.push_front(item);
                    }
                }
                _ => error!("Unsupported element: {:?}", element),
            }
        }
        debug!("Final single chain: {:?}", ugly_solution);
        // Great we should have single level vector
        // In case of single element just return it without wrapper
        if ugly_solution.len() == 1 {
            info!("Final chain is single item. Just return this element");
            return Ok(ugly_solution.pop().unwrap());
        }
        return Ok(MethodParam::Chained(ugly_solution));
    } else {
        // Just for printing error
        extract_simple(exec_param, parameters).map_err(|_| {
            error!("Unsupported param type");
        })
    }
}

fn parse_method(method_name: &Yaml, method_def: &Yaml, default_limits: &Arc<Limits>) -> Result<MethodDefinition, String> {
        // Name method MUST be string
        let name = match method_name.as_str() {
            Some(name) => name,
            None => {
                return Err(format!("Method name {:?} is invalid", method_name));
            }
        };
        let invoke = &method_def["invoke"];
        if invoke.as_hash() == None {
            return Err(format!("Method {}: Missing required parameter 'invoke'", name));
        }
        let streamed = method_def["streamed"].as_bool().unwrap_or(false);

        // The EXEC type method
        let path = if let Some(path) = invoke["exec"].as_str() {
            path
        } else {
            return Err(format!("Required parameter missin: path. Skip definition for {}", name));
        };
        let delay = invoke["delay"]
                        .as_i64()
                        .and_then(|delay| {
                            if delay < 0 || delay > 30 {
                                None
                            } else {
                                Some(delay)
                            }
                        })
                        .unwrap_or(10) as u32;

        let params = &method_def["params"];
        // contains all required and optional parameters
        let mut parameters = HashMap::new();
        if let Some(mapa) = params.as_hash() {
            for (name_it, definition_it) in mapa {
                // required
                let name = if let Some(s) = name_it.as_str().map(|s| s.to_owned()) {
                    s
                } else {
                    return Err("Invalid name. Ignored".to_owned());
                };
                if name == "self" {
                    return Err("Used restricted keyword 'self'. Ignoring.".to_owned());
                }
                let optional = definition_it["optional"].as_bool().unwrap_or(false);
                let param_type = match definition_it["type"].as_str().unwrap_or("") {
                    "string" => ParameterType::String,
                    "number" => ParameterType::Number,
                    "bool" => ParameterType::Bool,
                    _ => {
                        return Err(format!("No parameter type or invalid value for {:?}", name));
                    }
                };
                let default_from_settings = &definition_it["default"];
                let default = if let Ok(conv) = param_type.convert_yaml(&default_from_settings) {
                    conv
                } else {
                    if !default_from_settings.is_badvalue() {
                        error!("Provided default value {:?} cannot be converted to {:?}. Leaving empty",
                               default_from_settings, param_type);
                    }
                    None
                };

                let definition = ParameterDefinition {
                    param_type: param_type,
                    name: name.clone(),
                    optional: optional,
                    default: default,
                };
                parameters.insert(name, Arc::new(definition));
            }
        } else if !params.is_badvalue() {
                error!("[{}] Invalid value for field: 'param'", name);
        }
        let mut variables = Vec::<MethodParam>::new();

        if let Some(exec_params) = invoke["args"].as_vec() {
            for exec_param in exec_params {
                if let Ok(ok) = parse_param(exec_param, &parameters) {
                    variables.push(ok);
                } else {
                    warn!("[{}] Invalid arg enntry: {:?}. Skip", name, exec_param);
                }
            }
        }
        // For now only string...
        let fake_response = method_def["response"].as_str().map(|json|json.to_json());

        let is_private = method_def["private"].as_bool().unwrap_or(false);
        //This is a bug? Sometimes rustc cant handle &String to &str conversion
        let response_encoding = match &method_def["encoding"].as_str()
            .map_or("".to_owned(), |s| s.to_lowercase()) as &str {
                "utf-8" => ResponseEncoding::Utf8,
                "base64" => ResponseEncoding::Base64,
                default => {
                    if !default.is_empty() {
                        warn!("[{}] Unknown encoding: {}. Using utf-8", name, default);
                    }
                    ResponseEncoding::Utf8
                }
        };

        if response_encoding != ResponseEncoding::Utf8 && fake_response.is_some() {
            warn!("[{}] Used encoding for fake response. This setting will be ignored", name);
        }

        if response_encoding != ResponseEncoding::Utf8 && streamed {
            warn!("[{}]: Encoding is ignored for streaming mode", name);
        }

        // Do new limits object or reuse default one
        let limits_node = &method_def["limits"];
        let method_limits = if limits_node.as_hash().is_some() {
            Arc::new(parse_limits(limits_node, &default_limits))
        } else {
            default_limits.clone()
        };
        let run_as_node = &method_def["run-as"];
        let run_as = if run_as_node.as_hash().is_some() {
            let gid = if let Some(gid) = run_as_node["gid"].as_i64() {
                gid as gid_t
            } else {
                return Err(format!("[{}]: Invalid gid", name));
            };

            let uid = if let Some(uid) = run_as_node["uid"].as_i64() {
                uid as gid_t
            } else {
                return Err(format!("[{}]: Invalid uid", name));
            };
            info!("[{}]: Using permission: GID: {} UID: {}", name, gid, uid);
            // Check if user exists?
            RunAs::Custom { gid: gid, uid: uid }
        } else {
            debug!("[{}]: Using server UID/GID for execution", name);
            RunAs::Default
        };

        let output_encoding_node = method_def["output"]["format"].as_str();
        // Note: If encoding is base64 disable converting to JSON
        let output_encoding = output_encoding_node.map_or(OutputEncoding::Text, |format| {
            if format == "json" {
                if response_encoding == ResponseEncoding::Utf8 {
                    OutputEncoding::Json
                } else {
                    warn!("Specified JSON encoding for output encoding that is not UTF-8! Fallback to TEXT");
                    OutputEncoding::Text
                }
            } else {
                OutputEncoding::Text
            }
        });
        
        Ok(MethodDefinition {
            name: name.to_owned(),
            path: path.to_owned(),
            // this contains app invocation arguments, each argument in its own
            exec_params: variables,
            // this contains mapping from invocation input to method
            variables: parameters,
            use_fake_response: fake_response,
            delay: delay,
            response_encoding: response_encoding,
            is_private: is_private,
            limits: method_limits,
            run_as: run_as,
            output: output_encoding,
            streamed: streamed,
        })
}

fn parse_methods(methods: &BTreeMap<Yaml, Yaml>,
                 rpc_config_methods: &mut HashMap<String, MethodDefinition>,
                 str_config_methods: &mut HashMap<String, MethodDefinition>,
                 default_limits: &Arc<Limits>) {
    for (method_name, method_def) in methods {
        let method_definition = parse_method(method_name, method_def, default_limits);
        match method_definition {
            Ok(method_definition) => {
                info!("Registered method: {}. Support streaming: {}", method_definition.name, method_definition.streamed);
                if method_definition.streamed {
                    str_config_methods.insert(method_definition.name.clone(), method_definition);
                } else {
                    rpc_config_methods.insert(method_definition.name.clone(), method_definition);
                }
            },
            Err(e) => warn!("Unable to parse method: {}", e)
        }
    }
}
