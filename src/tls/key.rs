use anyhow::anyhow;
use anyhow::Result;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{fs, path::Path};

/// Load private key from a file
#[allow(dead_code)]
pub(crate) fn load_key(key_path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key = fs::read(key_path)?;
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        rustls_pemfile::private_key(&mut &*key)?.ok_or_else(|| anyhow!("no keys found"))?
    };
    Ok(key)
}
