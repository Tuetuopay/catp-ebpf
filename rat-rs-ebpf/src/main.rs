#![no_std]
#![no_main]

use core::ptr::read_volatile;
use aya_bpf::{
    macros::{kprobe, map},
    programs::ProbeContext,
    maps::PerfEventByteArray, BpfContext, helpers::bpf_probe_read_user_buf,
};
use aya_log_ebpf::trace;

#[no_mangle] static PID: u32 = 0;
#[map] static mut WRITES: PerfEventByteArray = PerfEventByteArray::new(0);

// The max stack size is 512 for the eBPF VM, so take half of it.
const BUF_SIZE: usize = 256;

#[kprobe(name="rat_rs")]
pub fn rat_rs(ctx: ProbeContext) -> u32 {
    match unsafe { try_rat_rs(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_rat_rs(ctx: ProbeContext) -> Result<u32, u32> {
    if ctx.pid() != read_volatile(&PID as *const u32) {
        return Ok(0)
    }

    let fd: u32 = ctx.arg(0).ok_or(0u32)?;
    let buffer: *const u8 = ctx.arg(1).ok_or(0u32)?;
    let len: usize = ctx.arg(2).ok_or(0u32)?;

    trace!(&ctx, "write({}, 0x{}, {})", fd, buffer as usize, len);

    let len = len.min(BUF_SIZE);
    let mut buf = [0u8; BUF_SIZE];
    let buf_slice = &mut buf[..len];
    bpf_probe_read_user_buf(buffer, buf_slice).map_err(|e| e as u32)?;

    WRITES.output(&ctx, buf_slice, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
