extern crate rustc_serialize;

use rustc_serialize::json::{ToJson, Json};
use config::{ParameterDefinition, ParameterType};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum MethodParam {
    /// This is just constant string
    Constant(String),
    /// This is ref to parameter definition
    Variable(Arc<ParameterDefinition>),
    /// Chained MethodParams
    Chained(Vec<MethodParam>),
    /// Capture all params as one-line json string
    Everything,
}

//Helper trait for cleaner implementation
pub trait Unroll {
    fn unroll(&self, params: &Json) -> Result<Option<String>, ()>;
}

impl Unroll for ParameterDefinition {
    fn unroll(&self, params: &Json) -> Result<Option<String>, ()> {
        // get info from params
        // for now variables support only objects
        match params.find(&self.name as &str) {
            Some(&Json::String(ref s)) if self.param_type == ParameterType::String => {
                Ok(Some(s.to_owned()))
            }
            Some(&Json::I64(ref i)) if self.param_type == ParameterType::Number => {
                Ok(Some(i.to_string()))
            }
            Some(&Json::U64(ref i)) if self.param_type == ParameterType::Number => {
                Ok(Some(i.to_string()))
            }
            Some(&Json::F64(ref s)) if self.param_type == ParameterType::Number => {
                Ok(Some(s.to_string()))
            }
            // Meh
            Some(ref s) => {
                error!("Unable to convert. Value = {:?}; target type = {:?}", s, self);
                Err(())
            }
            None => {
                if self.optional {
                    Ok(None)
                } else {
                    error!("Missing required param {:?}", self.name);
                    Err(())
                }
            }
        }
    }
}

impl Unroll for Vec<MethodParam> {
    fn unroll(&self, params: &Json) -> Result<Option<String>, ()> {
        let mut result = String::new();
        let mut all_ok = true;

        for element in self.iter() {
            match element.unroll(params) {
                Ok(Some(ref o)) => result.push_str(o),
                Ok(None) | Err(_) => {
                    debug!("Optional variable {:?} is missing. Skip whole chain", element);
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

impl Unroll for MethodParam {
    fn unroll(&self, params: &Json) -> Result<Option<String>, ()> {
        match *self {
            MethodParam::Constant(ref s) => Ok(Some(s.clone())),
            MethodParam::Everything => {
                let json = params.to_json().to_string();
                if json.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(json))
                }
            }
            MethodParam::Variable(ref v) => v.unroll(params),
            MethodParam::Chained(ref c) => c.unroll(params),
        }
    }
}
