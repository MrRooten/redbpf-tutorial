
pub const PATHLEN: usize = 256;

#[repr(C, packed(1))]
pub struct TracepointCommonArgs {
    pub ctype: u16,
    pub flags: u8,
    pub preempt_count: u8,
    pub pid: i32,
}
#[repr(C, packed(1))]
pub struct ExecveStruct {
    pub common        : TracepointCommonArgs,
    pub __syscall_nr  : i32,
    pub pad           : u32,
    pub filename_addr : u64,
    pub args_addr     : u64,
    pub envp_addr     : u64,
}
fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/bpf/programs/openmonitor/openmonitor.elf"
    ))
}

use libc;
use std::process;
use tokio::signal::ctrl_c;
use tracing::{error, subscriber, Level};
use tracing_subscriber::FmtSubscriber;
use redbpf::load::Loader;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let mut loaded = Loader::load(probe_code()).expect("error loading probe");
    for tracepoint in loaded.tracepoints_mut() {
        tracepoint.attach_trace_point("syscalls", "sys_enter_execve")
            .expect(format!("error on attach_trace_point to {}", tracepoint.name()).as_str());
    }

    println!("Hit Ctrl-C to quit");
    ctrl_c().await.expect("Error awaiting CTRL-C");
}
