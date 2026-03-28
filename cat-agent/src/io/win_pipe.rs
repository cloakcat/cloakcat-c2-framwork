//! Named pipe server helpers for Windows IPC.

#![cfg(target_os = "windows")]

use anyhow::{bail, Result};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    System::Pipes::{
        CreateNamedPipeW, PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
    },
};

/// Create a named pipe server in message mode.
///
/// `name` must be a valid pipe name (e.g. `\\.\pipe\cloakcat`).
///
/// # Safety
/// The returned HANDLE must be closed via [`close_handle`] when no longer needed.
pub fn create_pipe_server(name: &str) -> Result<HANDLE> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    let h = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,     // nMaxInstances
            65536, // nOutBufferSize
            65536, // nInBufferSize
            0,     // nDefaultTimeOut (use system default)
            std::ptr::null(),
        )
    };

    if h == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        bail!("CreateNamedPipeW failed: error {err}");
    }

    Ok(h)
}

/// Close a Windows HANDLE.
pub fn close_handle(h: HANDLE) {
    unsafe {
        CloseHandle(h);
    }
}
