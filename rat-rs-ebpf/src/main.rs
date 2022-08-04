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
#[no_mangle] static FD: u32 = 0;
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
    if fd != read_volatile(&FD as *const u32) {
        return Ok(0)
    }

    let mut buffer: usize = ctx.arg(1).ok_or(0u32)?;
    let mut len: usize = ctx.arg(2).ok_or(0u32)?;
    let buffer_end = buffer + len;

    trace!(&ctx, "write({}, 0x{}, {})", fd, buffer, len);

    let mut buf = [0u8; BUF_SIZE];

    // Maximum of what passes the verifier. This still nets us 256*15 = 3840 bytes, which is
    // already a pretty long line.
    // while loop is not possible as the ebpf verifier will not be able to prove the loop to be
    // bounded.
    for _ in 0..15 {
        if buffer >= buffer_end { break }

        let buf_slice = &mut buf[..len.min(BUF_SIZE)];
        bpf_probe_read_user_buf(buffer as *const u8, buf_slice).map_err(|e| e as u32)?;
        WRITES.output(&ctx, buf_slice, 0);

        buffer += BUF_SIZE;
        len -= BUF_SIZE;
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
