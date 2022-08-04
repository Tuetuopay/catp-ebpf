use std::io::Write;

use aya::{
    include_bytes_aligned, maps::perf::AsyncPerfEventArray, programs::KProbe, util::online_cpus,
    BpfLoader,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{error, info};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, help = "PID to trace")]
    pid: u32,
    #[clap(
        short,
        long,
        default_value = "1",
        help = "File descriptor to trace. Defaults to stdout."
    )]
    fd: u32,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    let mut loader = BpfLoader::new();
    loader.set_global("PID", &opt.pid);
    loader.set_global("FD", &opt.fd);

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut bpf =
        loader.load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/rat-rs"))?;
    BpfLogger::init(&mut bpf)?;
    let program: &mut KProbe = bpf.program_mut("rat_rs").unwrap().try_into()?;
    program.load()?;
    program.attach("ksys_write", 0)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("WRITES")?)?;
    for cpu in online_cpus()? {
        let mut buf = perf_array.open(cpu, None)?;
        let mut stdout = std::io::stdout();
        tokio::task::spawn(async move {
            let mut bufs = vec![BytesMut::with_capacity(4096); 10];
            loop {
                let events = match buf.read_events(&mut bufs).await {
                    Ok(e) => e,
                    Err(e) => {
                        error!("read_events cpu #{cpu} failed: {e}");
                        continue;
                    }
                };
                for buf in &bufs[0..events.read] {
                    if let Err(e) = stdout.write_all(&buf) {
                        error!("write stdout failed: {e}");
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
