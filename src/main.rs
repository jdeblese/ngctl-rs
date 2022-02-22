#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use libc::free;
use std::ptr;
use std::alloc::{alloc, dealloc, Layout};
use std::mem::size_of;
use std::vec::Vec;
use std::convert::TryFrom;
use std::str::Utf8Error;
use std::ffi::{CString, CStr};
use std::os::raw::{c_char, c_int, c_ulong, c_void};
use std::process::id;
use std::result::Result;
use errno::{Errno, errno};
use socket2::Socket;
use std::os::unix::io::{FromRawFd, AsRawFd};


include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl From<(&str, &str, &str)> for ngm_mkpeer {
    fn from(args: (&str, &str, &str)) -> Self {
        let (stype, sour, speer) = args;
        let mut type_: [c_char; NG_TYPESIZ as usize] = [0; NG_TYPESIZ as usize];
        let mut ourhook: [c_char; NG_HOOKSIZ as usize] = [0; NG_HOOKSIZ as usize];
        let mut peerhook: [c_char; NG_HOOKSIZ as usize] = [0; NG_HOOKSIZ as usize];
        for (dst, src) in type_.iter_mut().zip(stype.as_bytes().iter()) {
            *dst = *src as c_char;
        }
        type_[NG_TYPESIZ as usize - 1] = 0;  // just in case
        for (dst, src) in ourhook.iter_mut().zip(sour.as_bytes().iter()) {
            *dst = *src as c_char;
        }
        ourhook[NG_TYPESIZ as usize - 1] = 0;  // just in case
        for (dst, src) in peerhook.iter_mut().zip(speer.as_bytes().iter()) {
            *dst = *src as c_char;
        }
        peerhook[NG_TYPESIZ as usize - 1] = 0;  // just in case
        ngm_mkpeer { type_, ourhook, peerhook }
    }
}


type ControlSocket = Socket;
type DataSocket = Socket;

#[derive(Debug)]
enum MyError {
    SystemError(Errno),
    NotABridge
}


#[allow(dead_code)]
#[derive(Debug)]
struct NodeInfo {
    name: String,
    nodetype: String,
    id: u32,
    hooks: u32
}

impl TryFrom<nodeinfo> for NodeInfo {
    type Error = Utf8Error;

    fn try_from(ninf: nodeinfo) -> Result<Self, Self::Error> {
        let name  = unsafe{CStr::from_ptr(ninf.name.as_ptr())}.to_str()?.to_owned();
        let type_ = unsafe{CStr::from_ptr(ninf.type_.as_ptr())}.to_str()?.to_owned();
        Ok(NodeInfo { name: name,
                      nodetype: type_,
                      id: ninf.id,
                      hooks: ninf.hooks })
    }
}


#[allow(dead_code)]
#[derive(Debug)]
struct LinkInfo {
    ourhook: String,
    peerhook: String,
    peer: NodeInfo
}

impl TryFrom<&linkinfo> for LinkInfo {
    type Error = Utf8Error;

    fn try_from(linf: &linkinfo) -> Result<Self, Self::Error> {
        let ourhook  = unsafe{CStr::from_ptr(linf.ourhook.as_ptr())}.to_str()?.to_owned();
        let peerhook = unsafe{CStr::from_ptr(linf.peerhook.as_ptr())}.to_str()?.to_owned();
        let peer = NodeInfo::try_from(linf.nodeinfo)?;
        Ok(LinkInfo { ourhook, peerhook, peer })
    }
}


fn ng_mk_sock_node(name: String) -> Result<(ControlSocket, DataSocket), Errno> {
    let c_str = CString::new(name).unwrap();
    let mut csp: c_int = 0;
    let mut dsp: c_int = 0;
    let pcsp: *mut c_int = &mut csp;
    let pdsp: *mut c_int = &mut dsp;
    let ret = unsafe { NgMkSockNode(c_str.as_ptr() as *const c_char, pcsp, pdsp) };
    if ret == -1 {
        return Err(errno())
    }
    Ok(unsafe { (Socket::from_raw_fd(csp), Socket::from_raw_fd(dsp)) })
}

unsafe fn ng_alloc_recv_msg(csock: &ControlSocket) -> Result<(*mut ng_mesg, CString), Errno> {
    let cs: c_int = csock.as_raw_fd();
    let mut respptr: *mut ng_mesg = ptr::null_mut();

    let pathlayout = Layout::from_size_align(NG_PATHSIZ as usize, 1).unwrap();  // FIXME
    let pathbuf = alloc(pathlayout) as *mut c_char;
    let ret = NgAllocRecvMsg(cs, &mut respptr, pathbuf);
    let resppath = CStr::from_ptr(pathbuf).to_owned();
    dealloc(pathbuf as *mut u8, pathlayout);
    if ret == -1 {
        return Err(errno())
    }
    Ok((respptr, resppath))
}

unsafe fn ng_send_msg(csock: &ControlSocket, path: &CStr, cookie: c_int, cmd: c_int, parg: *const c_void, arglen: c_ulong) -> Result<(), Errno> {
    let ret = NgSendMsg(csock.as_raw_fd(), path.as_ptr() as *const c_char, cookie, cmd, parg, arglen);
    if ret == -1 {
        return Err(errno())
    }
    Ok(())
}

unsafe fn command_response(csock: &ControlSocket, path: &str, cookie: c_int, cmd: c_int, parg: *const c_void, arglen: c_ulong) -> Result<*mut ng_mesg, Errno> {
    let cpath = CString::new(path).unwrap();  // FIXME
    ng_send_msg(csock, &cpath, cookie, cmd, parg, arglen)?;
    let (msg, _) = ng_alloc_recv_msg(csock)?;
    Ok(msg)
}

fn list_hooks(csock: &ControlSocket, path: &str) -> Result<(NodeInfo, Vec<LinkInfo>), Errno> {
    let parg: *const c_void = ptr::null();
    let respptr: *mut ng_mesg = unsafe { command_response(csock, path, NGM_GENERIC_COOKIE as c_int, NGM_LISTHOOKS as c_int, parg, 0) }?;

    // Pointer should not be null at this point (check?)
    //let hdr = unsafe { (*respptr).header };
    Ok(unsafe {
        let pdata: *const hooklist = (*respptr)
                                        .data
                                        .as_ptr()
                                        .cast();
        let ninf = NodeInfo::try_from((*pdata).nodeinfo).unwrap();
        let mut links: Vec<LinkInfo> = (*pdata).link.as_slice(ninf.hooks.try_into().unwrap()).iter().map(|l| LinkInfo::try_from(l).unwrap()).collect();
        links.sort_unstable_by(|a, b| a.ourhook.cmp(&b.ourhook));
        // ng_mesg is a nested set of flexible-array structs, so one call to free() is enough
        free(respptr as *mut c_void);
        (ninf, links)
    })
}

fn find_free_hook(csock: &ControlSocket, path: &str) -> Result<usize, MyError> {
    let (ninf, links) = list_hooks(csock, path).map_err(|e| MyError::SystemError(e))?;
    if ninf.nodetype != "bridge" {
        return Err(MyError::NotABridge);
    }
    for (n, l) in links.iter().map(|l| l.ourhook[4..].parse::<u32>().unwrap()).enumerate() {
        if l > n.try_into().unwrap() {
            return Ok(n)
        }
    }
    Ok(ninf.hooks.try_into().unwrap())
}

fn make_peer(csock: &ControlSocket, path: &str, nodetype: &str, ourhook: &str, peerhook: &str) -> Result<(), Errno> {
    let cs: c_int = csock.as_raw_fd();
    let cpath = CString::new(path).unwrap();
    let newpeer = ngm_mkpeer::from((nodetype, ourhook, peerhook));
    let pnewpeer: *const ngm_mkpeer = &newpeer;

    // send the makepeer command
    let ret = unsafe { NgSendMsg(cs, cpath.as_ptr() as *const c_char, NGM_GENERIC_COOKIE as c_int, NGM_MKPEER as c_int, pnewpeer as *const c_void, size_of::<ngm_mkpeer>() as u64) };
    if ret == -1 {
        return Err(errno())
    }
    // no response expected
    Ok(())
}

fn get_interface_name(csock: &ControlSocket, path: &str, ourhook: &str) -> Result<CString, Errno> {
    let cs: c_int = csock.as_raw_fd();
    let mut linkpath = String::from(path); // already contains a colon at the end
    linkpath.push_str(&ourhook);
    let clpath = CString::new(linkpath).unwrap();
    let query = CString::new("getifname").unwrap();
    let ret = unsafe { NgSendAsciiMsg(cs, clpath.as_ptr() as *const c_char, query.as_ptr() as *const c_char) };
    if ret == -1 {
        return Err(errno())
    }

    unsafe {
        let (binresp, rpath) = ng_alloc_recv_msg(csock)?;
        let text: *const c_char = (*binresp).data.as_ptr().cast();
        let device = CStr::from_ptr(text).to_owned();  // FIXME
        //let ret = NgSendMsg(cs, rpath.as_ptr() as *const c_char, NGM_GENERIC_COOKIE as c_int, NGM_BINARY2ASCII as c_int, binresp as *const c_void, size_of::<ng_mesg>() as u64 + (*binresp).header.arglen as u64);
        free(binresp as *mut c_void);
        /*
        if ret == -1 {
            return Err(errno())
        }
        let (asciiresp, _) = ng_alloc_recv_msg(csock)?;
        // this is weird: ng_mesg containing an ng_mesg? Taken from ngctl source, but...
        let ascii: *const ng_mesg = (*asciiresp).data.as_ptr().cast();
        let text: *const c_char = (*ascii).data.as_ptr().cast();
        let device = CStr::from_ptr(text).to_owned();  // FIXME
        free(asciiresp as *mut c_void);
        */
        Ok(device)
    }
}

fn go(path: &str) -> Result<(), MyError> {
    let (csock, _) = ng_mk_sock_node(format!("ngctlrs{}", id())).map_err(|e| MyError::SystemError(e))?;
    unsafe { NgSetDebug(2) };
    let link = format!("link{}", find_free_hook(&csock, path)?);
    make_peer(&csock, path, "eiface", &link, "ether").map_err(|e| MyError::SystemError(e))?;
    let device = get_interface_name(&csock, path, &link).map_err(|e| MyError::SystemError(e))?;
    println!("{}", device.to_str().unwrap());
    Ok(())
}

fn main() {
    match go("bridge:") {
        Err(e) => println!("error: {:?}", e),
        Ok(_) => ()
    }
}
