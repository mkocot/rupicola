//    Internal handler trait for Rupicola.
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

