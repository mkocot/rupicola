use std::io::{Write, Read};


/// Common errors used in data processing
pub enum HandlerError {
    NoSuchMethod,
    InvalidRequest,
    Unauthorized
}

pub trait ResponseHandler {
    fn handle_response(&self, req: &mut Read, resp: &mut Write, is_auth: bool) -> Result<(), HandlerError>;
}

