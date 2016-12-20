//    Lazy response for Rupicola.
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

use std::io::{Write, Result as IoResult};
use std::mem;
use hyper::server::Response;
use hyper::net::{Fresh, Streaming};

/// Fancy proxy for lazy hyper response
pub enum LazyResponse<'a> {
    /// Unused inner response (expected state after error in processing request)
    Fresh(Response<'a, Fresh>),

    /// Inner response already consumed (expected after writting some data)
    Streaming(Response<'a, Streaming>),

    /// Transitive state, should never be used in normal usage
    NONE,
}

impl<'a> LazyResponse<'a> {
    pub fn new(resp: Response<'a, Fresh>) -> LazyResponse<'a> {
        LazyResponse::Fresh(resp)
    }

    fn transition(&mut self) {
        // NOTE: First check is for type check! Second one unwrap previous value
        if let LazyResponse::Fresh(_) = *self {
            if let LazyResponse::Fresh(resp) = mem::replace(self, LazyResponse::NONE) {
                let mut started = try!(resp.start());
                mem::replace(self, LazyResponse::Streaming(started));
            } else {
                unreachable!();
            }
        }
        Ok(())
    }

    pub fn end(self) -> IoResult<()> {
        if let LazyResponse::Streaming(s) = self {
            try!(s.end());
            Ok(())
        } else {
            Ok(())
        }
    }
}

impl<'a> Write for LazyResponse<'a> {
    fn flush(&mut self) -> IoResult<()> {
        // We need to make transition from fresh to commited
        self.transition();
        if let LazyResponse::Streaming(ref mut w) = *self {
            w.flush()
        } else {
            Ok(())
        }
    }

    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        // if we are buffering leave it that way
        self.transition();
        if let LazyResponse::Streaming(ref mut w) = *self {
            w.write(buf)
        } else {
            // For now just assume all other states mean End Of File
            Ok(0)
        }
    }
}
