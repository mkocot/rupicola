use std::io::{Write, Read};


/// Common errors used in data processing
pub enum HandlerError {
    NoSuchMethod,
    InvalidRequest
}

pub trait ResponseHandler {
    fn handle_response(&self, req: &mut Read, resp: &mut Write) -> Result<(), HandlerError>;
}

