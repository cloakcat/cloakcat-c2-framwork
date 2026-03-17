use std::{env, fs, path::Path};

fn main() {
    let cfg = env::var("CLOAKCAT_EMBED_CONFIG").unwrap_or_else(|_| "{}".to_string());
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest = Path::new(&out_dir).join("embedded_config.rs");
    let escaped = cfg.replace('\\', "\\\\").replace('"', "\\\"");
    let content = ["pub const EMBEDDED_CONFIG: &str = \"", &escaped, "\";"].concat();
    fs::write(dest, content).expect("failed to write embedded_config.rs");
    println!("cargo:rerun-if-env-changed=CLOAKCAT_EMBED_CONFIG");
    println!("cargo:rustc-cfg=embed_has_out_dir");
}

