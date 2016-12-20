//    Configuration parsing for Rupicola.
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

extern crate log;

use params::MethodParam;
use rustc_serialize::json::Json;
use std::sync::Arc;
use std::io::Read;
use std::io;
use std::collections::{HashMap, VecDeque, BTreeMap, HashSet};
use std::fs::File;
use std::path::Path;
use std::fs;
use std::fmt;
use libc::{gid_t, uid_t};
use log::{LogRecord, LogLevelFilter, LogMetadata};
use yaml_rust::{YamlLoader, Yaml};
use syslog::{self, Facility};
use pwhash;
use misc;


/// Access control method
#[derive(PartialEq)]
pub enum AuthMethod {
    /// No checking for any permissions
    None,
    /// Check permission based on login and hashed (recommended) password
    Basic {
        /// Login
        login: String,
        /// Selected password checking method
        hash: String,
    },
}

impl AuthMethod {
    pub fn verify(&self, user_login: &str, user_pass: &str) -> bool {
        match *self {
            AuthMethod::None => true,
            AuthMethod::Basic { ref login, ref hash} => {
                // TODO: string comparison in constant time
                let user_ok = user_login == login;
                let crypt_ok = pwhash::unix::verify(user_pass, hash);
                user_ok & crypt_ok
            }
        }
    }

    pub fn required(&self) -> bool {
        *self != AuthMethod::None
    }
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
        file_mode: u32,
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

impl Default for Limits {
    fn default() -> Limits {
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
    Custom { gid: gid_t, uid: uid_t },
}

/// Expected output from called subprocedure
#[derive(Clone, PartialEq)]
pub enum OutputEncoding {
    /// Output is converted to utf-8 string
    Text,
    /// Output is converted to JSON
    Json,
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
    Bool,
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
            _ => Err(()),
        }
    }

    pub fn convert_yaml(&self, val: &Yaml) -> Result<String, ()> {
        match *val {
            Yaml::Real(ref r) if *self == ParameterType::Number => Ok(r.to_owned()),
            Yaml::Integer(ref i) if *self == ParameterType::Number => Ok(i.to_string()),
            Yaml::Boolean(ref b) if *self == ParameterType::Bool => Ok(b.to_string()),
            Yaml::String(ref s) if *self == ParameterType::String => Ok(s.to_owned()),
            _ => Err(()),
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
    // create config async channel
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

pub enum ParseError {
    MissingField(String),
    InvalidValue(String),
}

impl ParseError {
    pub fn no_field(name: &str) -> ParseError {
        ParseError::MissingField(name.to_owned())
    }
    pub fn bad_value<T: AsRef<str>>(value: T) -> ParseError {
        ParseError::InvalidValue(value.as_ref().to_owned())
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::MissingField(ref field) => write!(f, "Missing required field '{}'", field),
            ParseError::InvalidValue(ref value) => write!(f, "Invalid value '{}'", value),
        }
    }
}

impl ServerConfig {
    fn parse_common_fields(protocol_definition: &Yaml) -> (Option<String>, bool) {
        (protocol_definition["address"].as_str().map(str::to_owned),
         protocol_definition["allow_private"].as_bool().unwrap_or(false))
    }
    fn parse_http_protocol(protocol_definition: &Yaml) -> Result<Protocol, ParseError> {
        let (address, allow_private) = Self::parse_common_fields(protocol_definition);
        let address = try!(address.ok_or(ParseError::no_field("address")));
        let port = try!(protocol_definition["port"]
            .as_i64()
            .map(|p| p as u16)
            .ok_or(ParseError::no_field("port")));
        Ok(Protocol::Http {
            address: address,
            port: port,
            allow_private: allow_private,
        })
    }

    fn parse_https_protocol(protocol_definition: &Yaml) -> Result<Protocol, ParseError> {
        let (address, allow_private) = Self::parse_common_fields(protocol_definition);
        let address = try!(address.ok_or(ParseError::no_field("address")));
        let port = try!(protocol_definition["port"]
            .as_i64()
            .map(|p| p as u16)
            .ok_or(ParseError::no_field("port")));
        let cert = try!(protocol_definition["cert"]
            .as_str()
            .map(str::to_owned)
            .ok_or(ParseError::no_field("cert")));
        let key = try!(protocol_definition["key"]
            .as_str()
            .map(str::to_owned)
            .ok_or(ParseError::no_field("key")));

        Ok(Protocol::Https {
            address: address,
            port: port,
            allow_private: allow_private,
            key: key,
            cert: cert,
        })
    }

    fn parse_unix_protocl(protocol_definition: &Yaml) -> Result<Protocol, ParseError> {
        let (address, allow_private) = Self::parse_common_fields(protocol_definition);
        let address = try!(address.ok_or(ParseError::no_field("address")));
        // This Is Silly! Unable to convert value to string...
        let file_mode = protocol_definition["mode"]
            .as_i64()
            .and_then(|mode| {
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
            })
            .unwrap_or_else(|| {
                info!("Using default mode for socket");
                0o666
            });

        let uid = protocol_definition["uid"].as_i64().map(|g| g as uid_t);
        let gid = protocol_definition["gid"].as_i64().map(|g| g as gid_t);
        let (file_owner_uid, file_owner_gid) = match (uid, gid) {
            (Some(uid), Some(gid)) => (uid, gid),
            (Some(uid), None) => (uid, misc::getgid()),
            (None, Some(gid)) => (misc::getuid(), gid),
            (None, None) => (misc::getuid(), misc::getgid()),
        };
        Ok(Protocol::Unix {
            address: address,
            allow_private: allow_private,
            file_owner_uid: file_owner_uid,
            file_owner_gid: file_owner_gid,
            file_mode: file_mode,
        })
    }

    fn parse_bind_point(protocol_definition: &Yaml) -> Result<Protocol, ParseError> {
        match protocol_definition["type"].as_str() {
            Some("http") => Self::parse_http_protocol(protocol_definition),
            Some("https") => Self::parse_https_protocol(protocol_definition),
            Some("unix") => Self::parse_unix_protocl(protocol_definition),
            Some(prot) => Err(ParseError::bad_value(format!("Invalid protocol name: {}", prot))),
            None => Err(ParseError::no_field("type")),
        }
    }

    pub fn parse_protocol_definition(config: &Yaml) -> Result<ProtocolDefinition, ParseError> {
        let protocol_definition = &config["protocol"];
        let bind_points;
        if config["protocol"].as_hash().is_none() {
            return Err(ParseError::no_field("protocol"));
        }
        info!("Parsing protocol definition");
        // Get all bind points
        let points = protocol_definition["bind"].as_vec().map(|v| {
            let x: Vec<_> = v.iter()
                .filter_map(|e| {
                    Self::parse_bind_point(e)
                        .map_err(|e| {
                            error!("Unable to parse bind point: {}", e);
                            e
                        })
                        .ok()
                })
                .collect();
            x
        });
        bind_points = match points {
            None => {
                return Err(ParseError::no_field("bind"));
            }
            Some(ref s) if s.is_empty() => {
                error!("Unable to parse at least one bind point!");
                return Err(ParseError::bad_value("bind"));
            }
            Some(s) => s,
        };
        fn parse_auth(basic_auth_config: &Yaml) -> Result<AuthMethod, ParseError> {
            if !basic_auth_config.is_badvalue() {
                let login = if let Some(s) = basic_auth_config["login"].as_str() {
                    s.to_owned()
                } else {
                    warn!("basic-auth: Invalid or absent login field");
                    return Err(ParseError::no_field("login"));
                };

                let pass_hash = if let Some(s) = basic_auth_config["password"].as_str() {
                    s.to_owned()
                } else {
                    warn!("basic-auth: No required hash field");
                    return Err(ParseError::no_field("hash"));
                };

                Ok(AuthMethod::Basic {
                    login: login,
                    hash: pass_hash,
                })
            } else {
                warn!("Server is free4all. Consider using some kind of auth");
                Ok(AuthMethod::None)
            }
        }
        let auth = try!(parse_auth(&protocol_definition["auth-basic"]));
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

    fn get_includes(config: &Yaml) -> VecDeque<(String, bool)> {
        config["include"]
            .as_vec()
            .map_or(VecDeque::new(), |v| {
                v.iter()
                    .filter_map(|v| {
                        match (v.as_str(),
                               v.as_hash().and_then(|s| {
                            s.iter().next().map(|(a, b)| {
                                (a.as_str().map(|a| a.to_owned()), b.as_bool().unwrap_or(false))
                            })
                        })) {
                            (Some(s), None) => Some((s.to_owned(), false)),
                            (None, Some((Some(path), required))) => Some((path, required)),
                            _ => None,
                        }
                    })
                    .collect()
            })
    }

    fn merge_dict(next: &BTreeMap<Yaml, Yaml>,
                  base: &mut BTreeMap<Yaml, Yaml>,
                  depth: u32)
                  -> io::Result<()> {
        println!("Current config merge depth: {}", depth);
        // This is arbitrary choosen value
        if depth > 10 {
            Err(io::Error::new(io::ErrorKind::Other,
                               "Config file is too cumbersome! - reached maximum allowed merge \
                                depth"))
        } else {
            for (key, value) in next.iter() {
                if !base.contains_key(key) {
                    base.insert(key.clone(), value.clone());
                } else {
                    match (base.get_mut(key), value) {
                        // if current entry is not in base add
                        (Some(&mut Yaml::String(ref val)), _) if val == "include" => continue,
                        (Some(&mut Yaml::Hash(ref mut base_value)),
                         &Yaml::Hash(ref next_value)) => {
                            if let e @ Err(_) = Self::merge_dict(next_value,
                                                                 base_value,
                                                                 depth + 1) {
                                return e;
                            }
                        }
                        (Some(&mut Yaml::Array(ref mut base_value)),
                         &Yaml::Array(ref next_value)) => {
                            // this is easy, just extend array
                            base_value.extend_from_slice(&next_value);
                        }
                        (Some(ref base_val), ref next_val) => {
                            println!("Found 2 fields with different type ({:?}, {:?}), keeping \
                                      previous",
                                     base_val,
                                     next_val);
                        }
                        _ => {
                            panic!("IMPOSSIBLE");
                        }
                    }
                }
            }
            Ok(())
        }
    }

    fn merge_files<T: AsRef<Path>>(file: T,
                                   base: &mut BTreeMap<Yaml, Yaml>,
                                   pending: &mut VecDeque<(String, bool)>)
                                   -> io::Result<()> {
        println!("Merging config with {:?}", file.as_ref());
        // If this is file we are all set
        // on directory entry list all "*.config" files
        // and add to queue

        if file.as_ref().is_dir() {
            for entry in try!(file.as_ref().read_dir()) {
                let entry = try!(entry);
                match entry.path().extension() {
                    None => {
                        println!("Invalid config path {:?}", entry.path());
                    }
                    Some(some) if some == "conf" => {
                        println!("Teh config");
                        // If path is present then config is required
                        pending.push_back((entry.path().to_string_lossy().into_owned().to_owned(),
                                           true));
                    }
                    Some(_) => {
                        println!("This is not config file: {:?}", entry.path());
                    }
                }
            }
            Ok(())
        } else {
            let config_yaml = match Self::load_yaml(&file).and_then(|mut cfg| {
                cfg.pop().ok_or(io::Error::new(io::ErrorKind::Other, "Empty document"))
            }) {
                Ok(cfg) => cfg,
                Err(e) => {
                    return Err(e);
                }
            };
            let mut includes = Self::get_includes(&config_yaml);
            let config_yaml = config_yaml.as_hash().unwrap();
            if !includes.is_empty() {
                println!("Config from {:?} points to another references: {:?}",
                         file.as_ref(),
                         includes);
                pending.append(&mut includes);
            }
            Self::merge_dict(config_yaml, base, 0)
        }
    }

    fn load_yaml<T: AsRef<Path>>(config_file: T) -> io::Result<Vec<Yaml>> {
        // parse config file
        let mut f = try!(File::open(config_file));
        let mut s = String::new();
        try!(f.read_to_string(&mut s));
        YamlLoader::load_from_str(&s).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    pub fn read_from_file(config_file: &str) -> Result<ServerConfig, ParseError> {
        // parse config file
        let mut config_yaml = BTreeMap::<Yaml, Yaml>::new();
        let mut includes = VecDeque::new();
        includes.push_back((config_file.to_owned(), true));
        let mut already_visited_files = HashSet::new();
        while let Some((ref file, required)) = includes.pop_front() {
            // process includes
            let file_path = match fs::canonicalize(file) {
                Ok(path) => path,
                Err(e) => {
                    println!("Unable to canonicalize path '{}': {}", file, e);
                    if required {
                        panic!("Unable to canonicalize required config '{}': {}", file, e);
                    }
                    continue;
                }
            };
            if !already_visited_files.contains(&file_path) {
                already_visited_files.insert(file_path);
                match Self::merge_files(&file, &mut config_yaml, &mut includes) {
                    Ok(_) => {}
                    Err(e) => {
                        if required {
                            panic!("Unable to load required config file '{}': {:?}", file, e);
                        } else {
                            println!("Loading optional config file '{}' failed: {:?}", file, e);
                        }
                    }
                }
            } else {
                println!("Already visited: {:?} - Skip", &file_path);
            }
        }
        let config_yaml = Yaml::Hash(config_yaml);
        let backend = config_yaml["log"]["backend"]
            .as_str()
            .map_or("stdout".to_owned(), |s| s.to_lowercase());
        let path = config_yaml["log"]["path"].as_str();
        let log_level = config_yaml["log"]["level"]
            .as_str()
            .and_then(|s| {
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
                }
            })
            .unwrap_or(LogLevelFilter::Info);

        // set default sane log level (we should set it to max? or max only in debug)
        // The problem is we are merging files before parsing config...
        set_log_level(log_level, &backend, path);
        info!("Using configuration from: {}", config_file);
        let protocol_definition = try!(Self::parse_protocol_definition(&config_yaml));
        let mut methods = HashMap::new();
        let mut streams = HashMap::new();
        info!("{:?}", config_yaml["limits"]);
        let default_limits = Arc::new(parse_limits(&config_yaml["limits"], &Default::default()));
        info!("{:?}", default_limits);
        if let Some(methods_node) = config_yaml["methods"].as_hash() {
            parse_methods(methods_node, &mut methods, &mut streams, &default_limits);
        }

        Ok(ServerConfig {
            protocol_definition: protocol_definition,
            log_level: log_level,
            methods: methods,
            streams: streams,
            default_limits: default_limits,
        })
    }
}

fn parse_limits(node: &Yaml, proto: &Limits) -> Limits {
    Limits {
        read_timeout: node["read-timeout"].as_i64().map_or(proto.read_timeout, |i| i as u32),
        exec_timeout: node["exec-timeout"].as_i64().map_or(proto.exec_timeout, |i| i as u32),
        payload_size: node["payload-size"].as_i64().map_or(proto.payload_size, |i| i as u32),
        max_response: node["max-response"].as_i64().map_or(proto.max_response, |i| i as u32),
        request_wait: node["request-wait"].as_i64().map_or(proto.request_wait, |i| i as u32),
    }
}

fn extract_simple(exec_param: &Yaml,
                  parameters: &HashMap<String, Arc<ParameterDefinition>>)
                  -> Result<MethodParam, ()> {
    // Bind all simple types
    if let Some(c) = match *exec_param {
        Yaml::Real(ref s) |
        Yaml::String(ref s) => Some(s.to_owned()),
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
                Yaml::String(_) | Yaml::Real(_) | Yaml::Integer(_) | Yaml::Boolean(_) |
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

fn parse_method(method_name: &Yaml,
                method_def: &Yaml,
                default_limits: &Arc<Limits>)
                -> Result<MethodDefinition, String> {
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
        return Err(format!("Required parameter missing: path. Skip definition for {}",
                           name));
    };

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
                Some(conv)
            } else {
                if !default_from_settings.is_badvalue() {
                    error!("Provided default value {:?} cannot be converted to {:?}. Leaving \
                            empty",
                           default_from_settings,
                           param_type);
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
    let mut variables = Vec::new();

    if let Some(exec_params) = invoke["args"].as_vec() {
        for exec_param in exec_params {
            if let Ok(ok) = parse_param(exec_param, &parameters) {
                variables.push(ok);
            } else {
                warn!("[{}] Invalid arg enntry: {:?}. Skip", name, exec_param);
            }
        }
    }
    let is_private = method_def["private"].as_bool().unwrap_or(false);
    // This is a bug? Sometimes rustc cant handle &String to &str conversion
    let response_encoding = match &method_def["encoding"]
        .as_str()
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
    let run_as_node = &invoke["run-as"];
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
        RunAs::Custom {
            gid: gid,
            uid: uid,
        }
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
                warn!("Specified JSON encoding for output encoding that is not UTF-8! Fallback \
                       to TEXT");
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
                info!("Registered method: {}. Support streaming: {}",
                      method_definition.name,
                      method_definition.streamed);
                if method_definition.streamed {
                    str_config_methods.insert(method_definition.name.clone(), method_definition);
                } else {
                    rpc_config_methods.insert(method_definition.name.clone(), method_definition);
                }
            }
            Err(e) => warn!("Unable to parse method: {}", e),
        }
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    // Auth
    #[test]
    fn test_auth_none() {
        let auth = AuthMethod::None;
        assert!(auth.verify("", ""));
        assert!(auth.verify("abcd", "xyz"));
    }

    #[test]
    fn test_auth_basic_plain() {
        let auth = AuthMethod::Basic {
            login: "login".to_owned(),
            hash: "password".to_owned(),
            is_plaintext: true,
        };
        assert!(auth.verify("login", "password"));
        assert!(!auth.verify("bad", "password"));
        assert!(!auth.verify("login", "bad"));
        assert!(!auth.verify("bad", "bad"));
    }

    #[test]
    fn test_auth_basic_crypt() {
        let hash = "$1$JCRURp5H$vXe73x7/v6BNJhlUbs2Bg/";
        let auth = AuthMethod::Basic {
            login: "login".to_owned(),
            hash: hash.to_owned(),
            is_plaintext: false,
        };
        assert!(auth.verify("login", "password"));
        assert!(!auth.verify("bad", "password"));
        assert!(!auth.verify("login", "bad"));
        assert!(!auth.verify("bad", "bad"));
        assert!(!auth.verify("login", hash));

        // TEST 1 + plaintext
        let auth = AuthMethod::Basic {
            login: "login".to_owned(),
            hash: hash.to_owned(),
            is_plaintext: true,
        };

        assert!(auth.verify("login", hash));
        assert!(!auth.verify("login", "password"));
        assert!(!auth.verify("bad", "password"));
        assert!(!auth.verify("login", "bad"));
        assert!(!auth.verify("bad", "bad"));

        // TEST 2
        let hash = "k2ZAZbMvR/eOM";
        let auth = AuthMethod::Basic {
            login: "login".to_owned(),
            hash: hash.to_owned(),
            is_plaintext: false,
        };
        assert!(auth.verify("login", "password"));
        assert!(!auth.verify("bad", "password"));
        assert!(!auth.verify("login", "bad"));
        assert!(!auth.verify("bad", "bad"));
        assert!(!auth.verify("login", hash));

        // TEST 2 + plaintext
        let auth = AuthMethod::Basic {
            login: "login".to_owned(),
            hash: hash.to_owned(),
            is_plaintext: true,
        };

        assert!(auth.verify("login", hash));
        assert!(!auth.verify("login", "password"));
        assert!(!auth.verify("bad", "password"));
        assert!(!auth.verify("login", "bad"));
        assert!(!auth.verify("bad", "bad"));

    }

    #[test]
    fn test_required() {
        assert!(!AuthMethod::None.required());
        assert!(AuthMethod::Basic {
                login: "".to_owned(),
                hash: "".to_owned(),
                is_plaintext: false,
            }
            .required());
    }
}
