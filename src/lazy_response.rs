use std;
use std::io::Write;
use hyper::server::Response;
use hyper::net::{Fresh, Streaming};

/// Fancy proxy for lazy hyper response
pub enum LazyResponse<'a> {
    /// Unused inner response (expected state after error in processing request)
    Fresh(Response<'a, Fresh>, Option<Vec<u8>>),

    /// Inner response already consumed (expected after writting some data)
    Streaming(Response<'a, Streaming>),

    /// Transitive state, should never be used in normal usage
    NONE
}

impl <'a> LazyResponse<'a> {
    pub fn enable_buffer(&mut self) {
        if let LazyResponse::Fresh(_, ref mut buff) = *self {
            if buff.is_none() {
                info!("Enabling buffered response");
                *buff = Some(Vec::new());
            }
        } else {
            // This is the place of great sorrow
            warn!("Multiple invocation of enable_buffer");
        }
    }

    pub fn new(resp: Response<'a, Fresh>) -> LazyResponse<'a> {
       LazyResponse::Fresh(resp, None)
    }

    fn transition(&mut self) -> std::io::Result<()> {
        // NOTE: First check is for type check! Second one unwrap previous value
        if let LazyResponse::Fresh(_,_) = *self {
            if let LazyResponse::Fresh(resp, could_be_buffer) = std::mem::replace(self, LazyResponse::NONE) {
                let mut started = try!(resp.start());
                if let Some(buffer) = could_be_buffer {
                    error!("Transition with buffer, should not happen!");
                    try!(started.write_all(&buffer));
                }
                std::mem::replace(self, LazyResponse::Streaming(started));
                // if buffer is not empty then write it to response]
            }
        }
        Ok(())
    }

    pub fn end(self) -> std::io::Result<()> {
        if let LazyResponse::Streaming(s) = self {
            try!(s.end());
            Ok(())
        } else if let LazyResponse::Fresh(resp, Some(buffer)) = self {
            info!("Finishing with single push!");
            resp.send(&buffer)
        } else {
            Ok(())
        }
    }
    
    fn is_buffered(&self) -> bool {
        match *self {
            LazyResponse::Fresh(_, Some(_)) => true,
            _ => false
        }
    }
}

impl <'a> Write for LazyResponse<'a> {
    fn flush(&mut self) -> std::io::Result<()> {
        // We need to make transition from fresh to commited
        // SKIP when buffered
        if self.is_buffered() {
            info!("Buffered response, skip flush.");
            Ok(())
        } else {
            try!(self.transition());
            if let LazyResponse::Streaming(ref mut w) = *self {
                w.flush()
            } else {
                Ok(())
            }
        }
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // if we are buffering leave it that way
        if let LazyResponse::Fresh(_, Some(ref mut buffer)) = *self {
            info!("Buffered response, store data in buffer");
            buffer.extend_from_slice(buf);
            Ok(buf.len())
        } else {
            try!(self.transition());
            if let LazyResponse::Streaming(ref mut w) = *self {
                w.write(buf)
            } else {
                //For now just assume all other states mean End Of File
                Ok(0)
            }
        }
    }
}

