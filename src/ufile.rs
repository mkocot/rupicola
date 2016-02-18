extern crate libc;

use std::convert::AsRef;
use std::io;
use std::path::Path;
use std::ffi::CString;
use std::os::unix::raw::{gid_t, uid_t};
use std::os::unix::ffi::OsStrExt;

/// Convert libc result to convinient rust Result
fn cvt(v: libc::c_int) -> io::Result<libc::c_int> {
    if v < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(v)
    }
}

/// Change file ownership
pub fn chown<P: AsRef<Path>> (path: P, uid: uid_t, gid: gid_t) -> io::Result<i32> {
    let cstring = try!(CString::new(path.as_ref().as_os_str().as_bytes()));
    unsafe {
        cvt(libc::chown(cstring.as_ptr(), uid, gid))
    }
}

/// Get current process UID
pub fn getuid() -> uid_t {
    unsafe { libc::getuid() }
}

/// Get current process GID
pub fn getgid() -> gid_t {
    unsafe { libc::getgid() }
}
