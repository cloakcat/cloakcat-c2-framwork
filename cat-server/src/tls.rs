//! TLS utilities — self-signed certificate generation via rcgen.

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

use cloakcat_protocol::CertConfig;

/// Generate a self-signed PEM certificate and private key.
///
/// Reads CN / O / OU / Country from the optional `cert_cfg`; falls back to
/// `profile_name` as the CN when the config is absent.
///
/// Returns `(cert_pem_bytes, key_pem_bytes)`.
pub fn generate_self_signed(
    cert_cfg: Option<&CertConfig>,
    profile_name: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();

    let cn = cert_cfg
        .and_then(|c| c.cn.as_deref())
        .unwrap_or(profile_name);
    dn.push(DnType::CommonName, cn);

    if let Some(o) = cert_cfg.and_then(|c| c.o.as_deref()) {
        dn.push(DnType::OrganizationName, o);
    }
    if let Some(ou) = cert_cfg.and_then(|c| c.ou.as_deref()) {
        dn.push(DnType::OrganizationalUnitName, ou);
    }
    if let Some(country) = cert_cfg.and_then(|c| c.country.as_deref()) {
        dn.push(DnType::CountryName, country);
    }

    params.distinguished_name = dn;

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert.pem().into_bytes(), key_pair.serialize_pem().into_bytes()))
}

/// Return a `RustlsConfig`, generating cert/key PEM files if they do not exist.
///
/// Paths are created (including parents) as needed. The profile name is used
/// as a fallback CN when `cert_cfg` is `None`.
pub async fn ensure_rustls_config(
    cert_path: &str,
    key_path: &str,
    cert_cfg: Option<&CertConfig>,
    profile_name: &str,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    let cert_missing = !std::path::Path::new(cert_path).exists();
    let key_missing = !std::path::Path::new(key_path).exists();

    if cert_missing || key_missing {
        let cn = cert_cfg
            .and_then(|c| c.cn.as_deref())
            .unwrap_or(profile_name);
        println!("[tls] generating self-signed cert CN={cn} (profile={profile_name})");

        let (cert_pem, key_pem) =
            generate_self_signed(cert_cfg, profile_name).context("cert generation failed")?;

        for path in [cert_path, key_path] {
            if let Some(dir) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("cannot create dir {:?}", dir))?;
            }
        }
        std::fs::write(cert_path, &cert_pem)
            .with_context(|| format!("cannot write cert to {cert_path:?}"))?;
        std::fs::write(key_path, &key_pem)
            .with_context(|| format!("cannot write key to {key_path:?}"))?;

        println!("[tls] cert → {cert_path}");
        println!("[tls] key  → {key_path}");
    }

    axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .with_context(|| format!("failed to load TLS config from {cert_path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_self_signed_no_config() {
        let (cert, key) = generate_self_signed(None, "test-profile").unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
        assert!(std::str::from_utf8(&cert).unwrap().contains("CERTIFICATE"));
        assert!(std::str::from_utf8(&key).unwrap().contains("PRIVATE KEY"));
    }

    #[test]
    fn generate_self_signed_with_cert_config() {
        let cfg = CertConfig {
            cn: Some("s3.amazonaws.com".to_string()),
            o: Some("Amazon.com Inc.".to_string()),
            ou: Some("AWS".to_string()),
            country: Some("US".to_string()),
        };
        let (cert, key) = generate_self_signed(Some(&cfg), "amazon").unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
    }
}
