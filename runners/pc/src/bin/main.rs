use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::convert::TryFrom;

use littlefs2::const_ram_storage;
use littlefs2::fs::{Allocation, Filesystem};
use trussed::types::{LfsResult, LfsStorage};
use trussed::{platform, store};
use trussed::service::SeedableRng;
use trussed::pipe::TrussedInterchange;
use interchange::Interchange;

use fido_authenticator::{Authenticator, Config, Conforming};
use ctaphid_dispatch::app::{self as ctaphid, App};

use solo_pc::{UserInterface, SIM_SOCKET_PATH, SIM_UP_SOCKET_PATH};

const PACKET_SIZE: usize = 64;
const INIT_DATA_SIZE: usize = PACKET_SIZE - 7;
const CONT_DATA_SIZE: usize = PACKET_SIZE - 5;
// RAM-backed storage — same types the tests use.
const_ram_storage!(InternalStorage, 4096 * 10);
const_ram_storage!(ExternalStorage, 4096 * 10);
const_ram_storage!(VolatileStorage, 4096 * 10);

store!(SimStore,
    Internal: InternalStorage,
    External: ExternalStorage,
    Volatile: VolatileStorage
);

platform!(SimPlatform,
    R: chacha20::ChaCha8Rng,
    S: SimStore,
    UI: UserInterface,
);

fn main() {
    #[cfg(feature = "test-up-control")]
    start_up_control_listener();

    // Storage types are ~40KB each; heap-allocate to avoid stack overflow.
    let internal_storage = Box::leak(Box::new(InternalStorage::new()));
    let internal_alloc = Box::leak(Box::new(Filesystem::allocate()));
    let external_storage = Box::leak(Box::new(ExternalStorage::new()));
    let external_alloc = Box::leak(Box::new(Filesystem::allocate()));
    let volatile_storage = Box::leak(Box::new(VolatileStorage::new()));
    let volatile_alloc = Box::leak(Box::new(Filesystem::allocate()));

    let store = SimStore::claim().unwrap();
    store.mount(
        internal_alloc, internal_storage,
        external_alloc, external_storage,
        volatile_alloc, volatile_storage,
        true,
    ).unwrap();

    let rng = chacha20::ChaCha8Rng::from_seed([0u8; 32]);
    let board = SimPlatform::new(rng, store, UserInterface::default());
    let mut service = trussed::service::Service::new(board);

    unsafe { TrussedInterchange::reset_claims(); }
    let (requester, responder) = TrussedInterchange::claim().unwrap();
    assert!(service.add_endpoint(responder, "fido".into()).is_ok());
    service.set_seed_if_uninitialized(&[0u8; 32]);

    let client = trussed::ClientImplementation::new(requester, &mut service);

    let up = Conforming {};

    let mut fido = Authenticator::new(
        client, up,
        Config { max_msg_size: 7609, skip_up_timeout: None },
    );

    // --- Socket server ---
    let _ = std::fs::remove_file(SIM_SOCKET_PATH);
    let listener = UnixListener::bind(SIM_SOCKET_PATH).expect("Failed to bind socket");
    eprintln!("Solo2 simulator listening on {}", SIM_SOCKET_PATH);

    for stream in listener.incoming() {
        let mut stream = stream.expect("Accept failed");
        eprintln!("Client connected");
        let mut cid: u32 = 0;

        loop {
            eprintln!("[sim] waiting for packet...");
            match handle_packet(&mut stream, &mut fido, &mut cid) {
                Ok(true) => { eprintln!("[sim] packet handled OK"); continue; }
                Ok(false) => { eprintln!("[sim] client disconnected"); break; }
                Err(e) => { eprintln!("[sim] error: {}", e); break; }
            }
        }
        eprintln!("[sim] connection loop ended, accepting next...");
    }
}

#[cfg(feature = "test-up-control")]
fn start_up_control_listener() {
    let _ = std::fs::remove_file(SIM_UP_SOCKET_PATH);
    std::thread::spawn(|| {
        let listener = UnixListener::bind(SIM_UP_SOCKET_PATH)
            .expect("Failed to bind UP control socket");
        eprintln!("UP control listening on {}", SIM_UP_SOCKET_PATH);
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!("[sim-up] accept failed: {}", err);
                    continue;
                }
            };

            let mut buf = [0u8; 1];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {
                        let ack = match buf[0] {
                            0xFE => 0xAA,
                            other => {
                                apply_up_command(other);
                                0x00
                            }
                        };
                        if let Err(err) = stream.write_all(&[ack]) {
                            eprintln!("[sim-up] write failed: {}", err);
                            break;
                        }
                    }
                    Err(err) => {
                        eprintln!("[sim-up] read failed: {}", err);
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(feature = "test-up-control")]
fn apply_up_command(value: u8) {
    match value {
        0 => solo_pc::up_control::reset(),
        1 => solo_pc::up_control::approve(),
        128 => solo_pc::up_control::deny(),
        129 => solo_pc::up_control::approve_sticky(),
        other => eprintln!("[sim-up] ignoring unknown UP command {}", other),
    }
}

fn handle_packet(
    stream: &mut (impl Read + Write),
    app: &mut impl App,
    cid: &mut u32,
) -> Result<bool, String> {
    let mut pkt = [0u8; PACKET_SIZE];
    match read_exact(stream, &mut pkt) {
        Ok(()) => {}
        Err(_) => return Ok(false),
    }

    let pkt_cid = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
    let cmd_byte = pkt[4];

    if cmd_byte & 0x80 == 0 {
        return Err("Unexpected continuation packet".into());
    }

    let cmd = cmd_byte & 0x7F;
    let msg_len = ((pkt[5] as usize) << 8) | (pkt[6] as usize);

    // Reassemble full message from continuation packets
    let mut data = Vec::with_capacity(msg_len);
    let first_chunk = msg_len.min(INIT_DATA_SIZE);
    data.extend_from_slice(&pkt[7..7 + first_chunk]);

    let mut seq: u8 = 0;
    while data.len() < msg_len {
        let mut cpkt = [0u8; PACKET_SIZE];
        read_exact(stream, &mut cpkt).map_err(|e| format!("Continuation read: {e}"))?;
        let c_cid = u32::from_be_bytes([cpkt[0], cpkt[1], cpkt[2], cpkt[3]]);
        if c_cid != pkt_cid { return Err("CID mismatch".into()); }
        if cpkt[4] != seq { return Err(format!("Bad seq: expected {seq}, got {}", cpkt[4])); }
        let chunk = (msg_len - data.len()).min(CONT_DATA_SIZE);
        data.extend_from_slice(&cpkt[5..5 + chunk]);
        seq += 1;
    }

    // CTAPHID_INIT
    if cmd == 0x06 {
        *cid = (*cid).wrapping_add(1).max(1);
        let mut resp = [0u8; 17];
        if data.len() >= 8 { resp[..8].copy_from_slice(&data[..8]); }
        resp[8..12].copy_from_slice(&cid.to_be_bytes());
        resp[12] = 2; resp[16] = 0x04;
        send_response(stream, pkt_cid, 0x86, &resp)?;
        return Ok(true);
    }

    // CTAPHID_PING
    if cmd == 0x01 {
        send_response(stream, pkt_cid, 0x81, &data)?;
        return Ok(true);
    }

    // Dispatch through App trait
    let command = ctaphid::Command::try_from(cmd)
        .map_err(|_| format!("Unknown command: 0x{cmd:02X}"))?;

    if !app.commands().contains(&command) {
        send_response(stream, pkt_cid, 0xBF, &[0x01])?;
        return Ok(true);
    }

    let mut request_msg: ctaphid::Message = heapless::Vec::new();
    request_msg.extend_from_slice(&data).map_err(|_| "Request too large")?;
    let mut response_msg: ctaphid::Message = heapless::Vec::new();

    match app.call(command, &request_msg, &mut response_msg) {
        Ok(()) => {
            eprintln!("[sim] resp {} bytes: {:02X?}", response_msg.len(),
                &response_msg[..response_msg.len().min(30)]);
            send_response(stream, pkt_cid, cmd | 0x80, &response_msg)?;
        }
        Err(e) => {
            let err_byte = match e {
                ctaphid::Error::InvalidCommand => 0x01,
                ctaphid::Error::InvalidLength => 0x03,
                ctaphid::Error::NoResponse => 0x7F,
            };
            send_response(stream, pkt_cid, 0xBF, &[err_byte])?;
        }
    }
    Ok(true)
}

fn send_response(stream: &mut impl Write, cid: u32, cmd: u8, data: &[u8]) -> Result<(), String> {
    let len = data.len();
    let mut pkt = [0u8; PACKET_SIZE];
    pkt[0..4].copy_from_slice(&cid.to_be_bytes());
    pkt[4] = cmd;
    pkt[5] = (len >> 8) as u8;
    pkt[6] = (len & 0xFF) as u8;
    let first = len.min(INIT_DATA_SIZE);
    pkt[7..7 + first].copy_from_slice(&data[..first]);
    stream.write_all(&pkt).map_err(|e| format!("Write: {e}"))?;

    let mut offset = first;
    let mut seq: u8 = 0;
    while offset < len {
        let mut cpkt = [0u8; PACKET_SIZE];
        cpkt[0..4].copy_from_slice(&cid.to_be_bytes());
        cpkt[4] = seq;
        let chunk = (len - offset).min(CONT_DATA_SIZE);
        cpkt[5..5 + chunk].copy_from_slice(&data[offset..offset + chunk]);
        stream.write_all(&cpkt).map_err(|e| format!("Write cont: {e}"))?;
        offset += chunk;
        seq += 1;
    }
    Ok(())
}

fn read_exact(stream: &mut impl Read, buf: &mut [u8]) -> Result<(), std::io::Error> {
    let mut pos = 0;
    while pos < buf.len() {
        match stream.read(&mut buf[pos..]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed")),
            Ok(n) => pos += n,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
