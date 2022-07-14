//! This example demonstrates how to use a tracepoint to trace the connect() system call
//!
//! See also the definition of the structs in `mod.rs`
#![no_std]
#![no_main]

use core::mem::size_of;
use redbpf_probes::tracepoint::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[repr(C, packed(1))]
pub struct TracepointCommonArgs {
    pub ctype: u16,
    pub flags: u8,
    pub preempt_count: u8,
    pub pid: i32,
}

/// Members defined in `cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
/// Note that offset addresses are important here, so ensure the compiler does not add padding.
/// Any required padding will be set explicitly here.
#[repr(C)]
pub struct SysEnterConnectArgs {
    pub common: TracepointCommonArgs,
    pub sys_nr: i32,
    pad: u32,
    pub fd: u64,
    pub useraddr: u64,
    pub addrlen: u64,
}

#[repr(C)]
pub struct SysEnterExecveArgs {
    pub common: TracepointCommonArgs,
    pub sys_nr: i32,
    pad: u32,
    pub filename: u64,
    pub argv: u64,
    pub envp: u64
}
#[tracepoint]
unsafe fn sys_enter_connect(args: *const SysEnterConnectArgs) {
    let args = bpf_probe_read(args).expect("Failed to read arguments");
    let addrlen = args.addrlen;
    if addrlen < size_of::<sockaddr_in>() as u64 {
        return;
    }

    let addr = args.useraddr;
    let family = bpf_probe_read(addr as *const sa_family_t).unwrap_or(u16::MAX) as u32;
    match family {
        AF_INET => {
            let sockaddr_struct = bpf_probe_read(addr as *const sockaddr_in).unwrap();
            let ipv4 = &(sockaddr_struct.sin_addr.s_addr as u64) as *const u64;
            bpf_trace_printk_raw(b"Connected to IPv4 address %pI4\0", ipv4 as u64, 0, 0)
                .expect("printk failed");
        }
        _ => {}
    };
}

#[map]
static mut PROCESS_FILE: HashMap<u64,u64> = HashMap::with_max_entries(1024);

#[tracepoint]
unsafe fn sys_enter_execve(args: *const SysEnterExecveArgs) {
    let args = bpf_probe_read(args).expect("Failed to read arguments");
    PROCESS_FILE.set(&args.filename,&args.argv);
    bpf_trace_printk_raw(b"Process file:%s %s \0",args.filename,args.argv,0);
}

