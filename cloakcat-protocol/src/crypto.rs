//! HMAC-SHA256 signing and verification for result messages.
//! Message format: agent_id + '\0' + cmd_id + '\0' + stdout (null-byte separated).

use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use ring::hmac;
use subtle::ConstantTimeEq;

/// Signs a result payload for agent_id + cmd_id + stdout.
/// Returns base64-no-pad encoded HMAC-SHA256.
/// Fields are separated by null bytes to prevent ambiguity.
pub fn sign_result(agent_id: &str, cmd_id: &str, stdout: &str, token: &[u8]) -> String {
    let msg = format!("{}\x00{}\x00{}", agent_id, cmd_id, stdout);
    let key = hmac::Key::new(hmac::HMAC_SHA256, token);
    B64.encode(hmac::sign(&key, msg.as_bytes()).as_ref())
}

/// Verifies a result signature using constant-time comparison.
pub fn verify_result(
    agent_id: &str,
    cmd_id: &str,
    stdout: &str,
    signature: &str,
    token: &[u8],
) -> bool {
    let expected = sign_result(agent_id, cmd_id, stdout, token);
    expected.as_bytes().ct_eq(signature.as_bytes()).into()
}
