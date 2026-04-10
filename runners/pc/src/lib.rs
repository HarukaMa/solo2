use std::{fs::File, io::Write};
pub use embedded_hal::blocking::rng;
use littlefs2::{const_ram_storage, consts};
use littlefs2::fs::{Allocation, Filesystem};
use trussed::types::{LfsResult, LfsStorage};

use trussed::platform::{
    ui,
    reboot,
    consent,
};
use trussed::{platform, store};

pub use generic_array::{
    GenericArray,
    typenum::{U16, U512},
};

use generic_array::typenum::{U256, U1022};


const SOLO_STATE: &'static str = "solo-state.bin";
pub const SIM_SOCKET_PATH: &str = "/tmp/solo2-sim.sock";
pub const SIM_UP_SOCKET_PATH: &str = "/tmp/solo2-sim-up.sock";

#[allow(non_camel_case_types)]
pub mod littlefs_params {
    use super::*;
    pub const READ_SIZE: usize = 16;
    pub const WRITE_SIZE: usize = 512;
    pub const BLOCK_SIZE: usize = 512;

    pub const BLOCK_COUNT: usize = 256;
    // no wear-leveling for now
    pub const BLOCK_CYCLES: isize = -1;

    pub type CACHE_SIZE = U512;
    pub type LOOKAHEADWORDS_SIZE = U16;
    /// TODO: We can't actually be changed currently
    pub type FILENAME_MAX_PLUS_ONE = U256;
    pub type PATH_MAX_PLUS_ONE = U256;
    pub const FILEBYTES_MAX: usize = littlefs2::ll::LFS_FILE_MAX as _;
    /// TODO: We can't actually be changed currently
    pub type ATTRBYTES_MAX = U1022;
}

pub struct FileFlash {
    state: [u8; 128 * 1024],
}
impl FileFlash {
    pub fn new() -> Self {
        let mut state = [0u8; 128 * 1024];

        if let Ok(contents) = std::fs::read(SOLO_STATE) {
            println!("loaded {}", SOLO_STATE);
            state.copy_from_slice( contents.as_slice() );
            Self {state}
        } else {
            println!("No state yet, creating");
            Self {state}
        }
    }
}

impl littlefs2::driver::Storage for FileFlash {
    const READ_SIZE: usize = littlefs_params::READ_SIZE;
    const WRITE_SIZE: usize = littlefs_params::WRITE_SIZE;
    const BLOCK_SIZE: usize = littlefs_params::BLOCK_SIZE;

    const BLOCK_COUNT: usize = littlefs_params::BLOCK_COUNT;
    const BLOCK_CYCLES: isize = littlefs_params::BLOCK_CYCLES;

    type CACHE_SIZE = littlefs_params::CACHE_SIZE;
    type LOOKAHEADWORDS_SIZE = littlefs_params::LOOKAHEADWORDS_SIZE;


    fn read(&self, off: usize, buf: &mut [u8]) -> LfsResult<usize> {
        for i in 0 .. buf.len() {
            buf[i] = self.state[i + off];
        }
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> LfsResult<usize> {
        for i in 0 .. data.len() {
            self.state[i + off] = data[i];
        }
        let mut buffer = File::create(SOLO_STATE).unwrap();
        buffer.write(&self.state).unwrap();

        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> LfsResult<usize> {
        for i in 0 .. len {
            self.state[i + off] = 0;
        }
        let mut buffer = File::create(SOLO_STATE).unwrap();
        buffer.write(&self.state).unwrap();
        Ok(len)
    }

}

const_ram_storage!(VolatileStorage, 4096 * 10);
const_ram_storage!(ExternalStorage, 4096 * 10);

store!(Store,
    Internal: FileFlash,
    External: ExternalStorage,
    Volatile: VolatileStorage
);

#[derive(Default)]
pub struct UserInterface {
}

impl trussed::platform::UserInterface for UserInterface
{
    fn check_user_presence(&mut self) -> consent::Level {
        #[cfg(feature = "test-up-control")]
        {
            let level = up_control::take();
            if level == consent::Level::None {
                // Yield CPU while waiting for UP decision (avoids 100% spin)
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            return level;
        }
        #[cfg(not(feature = "test-up-control"))]
        { consent::Level::Normal }
    }

    fn set_status(&mut self, status: ui::Status) {

        println!("Set status: {:?}", status);

    }

    fn refresh(&mut self) {

    }

    fn uptime(&mut self) -> core::time::Duration {
        core::time::Duration::from_millis(1000)
    }

    fn reboot(&mut self, to: reboot::To) -> ! {
        println!("Restart!  ({:?})", to);
        std::process::exit(25);
    }

}

platform!(Board,
    R: chacha20::ChaCha8Rng,
    S: Store,
    UI: UserInterface,
);

/// Programmatic control of user presence checks for testing.
///
/// When the `test-up-control` feature is enabled, `check_user_presence()` reads
/// from a shared atomic instead of returning a hardcoded value. Test code calls
/// `up_approve()` / `up_deny()` before issuing CTAP commands.
#[cfg(feature = "test-up-control")]
pub mod up_control {
    use std::sync::atomic::{AtomicU8, Ordering};

    const AUTO_APPROVE: u8 = 0;
    const APPROVE_ONCE: u8 = 1;
    const APPROVE_STICKY: u8 = 129;
    const DENY_STICKY: u8 = 128;

    static UP_RESPONSE: AtomicU8 = AtomicU8::new(AUTO_APPROVE);

    /// Read the current UP response. One-shot values are consumed.
    pub fn take() -> trussed::platform::consent::Level {
        use trussed::platform::consent::Level;
        let val = UP_RESPONSE.load(Ordering::SeqCst);
        // Consume one-shot values (< 128)
        if val > 0 && val < 128 {
            UP_RESPONSE.compare_exchange(val, AUTO_APPROVE, Ordering::SeqCst, Ordering::Relaxed).ok();
        }
        match val {
            AUTO_APPROVE | APPROVE_ONCE | APPROVE_STICKY => Level::Normal,
            DENY_STICKY => Level::None,
            _ => Level::None,
        }
    }

    /// Approve the next user presence check (consumed after one read).
    pub fn approve() { UP_RESPONSE.store(APPROVE_ONCE, Ordering::SeqCst); }

    /// Approve all user presence checks until `reset()`.
    pub fn approve_sticky() { UP_RESPONSE.store(APPROVE_STICKY, Ordering::SeqCst); }

    /// Deny all user presence checks (loop runs until timeout).
    pub fn deny() { UP_RESPONSE.store(DENY_STICKY, Ordering::SeqCst); }

    /// Clear any pending response.
    pub fn reset() { UP_RESPONSE.store(AUTO_APPROVE, Ordering::SeqCst); }
}

/// RAM-backed storage for tests (no file I/O).
pub mod test_ram {
    use littlefs2::const_ram_storage;
    use trussed::types::{LfsResult, LfsStorage};

    const_ram_storage!(InternalStorage, 4096 * 10);
    const_ram_storage!(ExternalStorage, 4096 * 10);
    const_ram_storage!(VolatileStorage, 4096 * 10);
}
