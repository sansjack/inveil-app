//! Release builds on Windows are windowless, so the background service shows nothing. A command started from a
//! terminal reuses that terminal for its output.

/// True when there is a console to print to.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn attach() -> bool {
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
    }
    // SAFETY: AttachConsole takes a plain integer and has no memory-safety preconditions.
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) != 0 }
}

#[cfg(not(windows))]
pub fn attach() -> bool {
    true
}
