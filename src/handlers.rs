use std::io::Write;


/// Common errors used in data processing
pub enum HandlerError {
    /// Requested method is not found
    NoSuchMethod,
    /// Request is invalid (for example: invalid json, invalid parameters)
    InvalidRequest,
    /// Request is not authorized
    Unauthorized
}

/// Trait for all request handlers
pub trait ResponseHandler {
    /// Prepare response for given request (any string)
    /// Write response to writer or return Err on failure
    /// NOTE: As this handle both RPC and Streaming interface success is just ()
    /// as any other return value is not needed
    fn handle_response(&self, req: &str, is_auth: bool, resp: &mut Write) -> Result<(), HandlerError>;
}

