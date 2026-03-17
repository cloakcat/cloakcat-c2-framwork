//! Host information collection (hostname, username, OS, IPs).

use std::fs;
use std::process::Command as StdCommand;

use get_if_addrs::get_if_addrs;

fn get_env(key: &str) -> Result<String, std::env::VarError> {
    std::env::var(key)
}

pub fn collect_hostname() -> Option<String> {
    get_env("COMPUTERNAME")
        .or_else(|_| get_env("HOSTNAME"))
        .ok()
        .or_else(|| {
            StdCommand::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

pub fn collect_username() -> Option<String> {
    get_env("USERNAME")
        .or_else(|_| get_env("USER"))
        .ok()
        .filter(|s| !s.is_empty())
}

pub fn collect_os_version() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        StdCommand::new("cmd")
            .args(["/C", "ver"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(text) = fs::read_to_string("/etc/os-release") {
            let mut name = None;
            let mut version = None;
            for line in text.lines() {
                if line.starts_with("NAME=") {
                    name = line.split_once('=').map(|(_, v)| v.trim_matches('"').to_string());
                }
                if line.starts_with("VERSION=") {
                    version = line.split_once('=').map(|(_, v)| v.trim_matches('"').to_string());
                }
            }
            match (name, version) {
                (Some(n), Some(v)) => Some(format!("{} {}", n, v)),
                (Some(n), None) => Some(n),
                _ => None,
            }
        } else {
            StdCommand::new("uname")
                .arg("-a")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        }
    }
}

pub fn collect_ip_addrs() -> Option<String> {
    let addrs = get_if_addrs().ok()?;
    let mut v = Vec::new();
    for iface in addrs {
        if iface.is_loopback() {
            continue;
        }
        if let std::net::IpAddr::V4(ip) = iface.ip() {
            v.push(ip.to_string());
        }
    }
    if v.is_empty() {
        None
    } else {
        Some(v.join(","))
    }
}
