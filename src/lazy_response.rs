use std;
use std::io::Write;
use hyper::server::Response;
use hyper::net::{Fresh, Streaming};

/// Fancy proxy for lazy hyper response
pub enum LazyResponse<'a> {
    /// Unused inner response (expected state after error in processing request)
    Fresh(Response<'a, Fresh>),

    /// Inner response already consumed (expected after writting some data)
    Streaming(Response<'a, Streaming>),

    /// Transitive state, should never be used in normal usage
    NONE
}

impl <'a> LazyResponse<'a> {
    pub fn new(resp: Response<'a, Fresh>) -> LazyResponse<'a> {
       LazyResponse::Fresh(resp)
    }

    fn transition(&mut self) -> std::io::Result<()> {
        // NOTE: First check is for type check! Second one unwrap previous value
        if let LazyResponse::Fresh(_) = *self {
            if let LazyResponse::Fresh(resp) = std::mem::replace(self, LazyResponse::NONE) {
                let started = try!(resp.start());
                std::mem::replace(self, LazyResponse::Streaming(started));
            }
        }
        Ok(())
    }

    pub fn end(self) -> std::io::Result<()> {
        if let LazyResponse::Streaming(s) = self {
            try!(s.end());
            Ok(())
        } else {
            Ok(())
        }
    }
}

impl <'a> Write for LazyResponse<'a> {
    fn flush(&mut self) -> std::io::Result<()> {
        // We need to make transition from fresh to commited
        try!(self.transition());
        if let LazyResponse::Streaming(ref mut w) = *self {
            w.flush()
        } else {
            Ok(())
        }
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        try!(self.transition());
        if let LazyResponse::Streaming(ref mut w) = *self {
            w.write(buf)
        } else {
            //For now just assume all other states mean End Of File
            Ok(0)
        }
    }
}

