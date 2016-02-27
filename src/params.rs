//    Parameter handling for Rupicola.
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

use rustc_serialize::json::{ToJson, Json};
use config::ParameterDefinition;
use std::sync::Arc;

/// Definition of possible method parameter
#[derive(Debug, Clone)]
pub enum MethodParam {
    /// This is just constant string
    Constant(String),
    /// This is ref to parameter definition
    Variable(Arc<ParameterDefinition>, bool),
    /// Chained MethodParams
    Chained(Vec<MethodParam>),
    /// Capture all params as one-line json string
    Everything,
}

///Helper trait for cleaner implementation
pub trait Unroll {
    /// Unroll self given set of parameters
    fn unroll(&self, params: &Json) -> Result<Option<String>, ()>;
}

/// Implementation of Unroll traif for parameter
/// This simplifies handling validation of parameters into single function
impl Unroll for ParameterDefinition {
    fn unroll(&self, params: &Json) -> Result<Option<String>, ()> {
        // get info from params
        // for now variables support only objects
        match params.find(&self.name as &str) {
            Some(ref s) => {
                let conversion_result = self.param_type.convert(s);
                if conversion_result.is_err() {
                    error!("Unable to convert. Value = {:?}; target type = {:?}", s, self);
                }
                conversion_result
            }
            None => {
                if self.optional {
                    // Just wrap default value
                    Ok(self.default.clone())
                } else {
                    error!("Missing required param {:?}", self.name);
                    Err(())
                }
            }
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
            },
            MethodParam::Variable(ref v, skip) => {
                match v.unroll(params) {
                    // We cannot return Ok(None) (because that wolud skip WHOLE chain)
                    // Empty string dosn't change response and keep all chain
                    Ok(Some(_)) if skip => Ok(Some("".to_owned())),
                    all => all,
                }
            },
            MethodParam::Chained(ref c) => {
                let mut result = String::new();
                for element in c.iter() {
                    match element.unroll(params) {
                        Ok(Some(ref o)) => result.push_str(o),
                        skip @Ok(None) | skip @Err(_) => {
                            if skip.is_ok() {
                                info!("Optional variable {:?} is missing. Skip whole chain", element);
                            }
                            // Return either Ok(None) or Err(..)
                            return skip;
                        }
                    }
                }
                Ok(Some(result))
            },
        }
    }
}
