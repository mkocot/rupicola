//    Miscellaneous support functions for Rupicola
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

extern crate libc;

use std::convert::AsRef;
use std::io;
use std::path::Path;
use std::ffi::CString;
use libc::{gid_t, uid_t};
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
pub fn chown<P: AsRef<Path>>(path: P, uid: uid_t, gid: gid_t) -> io::Result<i32> {
    let cstring = try!(CString::new(path.as_ref().as_os_str().as_bytes()));
    unsafe { cvt(libc::chown(cstring.as_ptr(), uid, gid)) }
}

/// Get current process UID
pub fn getuid() -> uid_t {
    unsafe { libc::getuid() }
}

/// Get current process GID
pub fn getgid() -> gid_t {
    unsafe { libc::getgid() }
}
