//! Envelope message wrapper for typed protocol framing.

use base64::{Engine, engine::general_purpose::STANDARD};
use cloakcat_protocol::{Command, FileChunk, RegisterReq, RegisterResp, ResultReq};
use serde::{Deserialize, Serialize};

/// Top-level protocol envelope — wraps every message exchanged between
/// agent and server so both sides can match on a single tagged enum
/// instead of relying on URL path + content-type conventions.
#[derive(Debug, Serialize, Deserialize)]
pub enum Envelope {
    V1Register(RegisterReq),
    V1RegisterResp(RegisterResp),
    V1Poll { agent_id: String, hold: u64 },
    V1PollResp(Option<Command>),
    V1Result(ResultReq),
    V1Ack,
    V1FetchUpload { agent_id: String, file_id: String },
    V1FetchUploadResp {
        #[serde(with = "base64_serde")]
        data: Vec<u8>,
    },
    V1DownloadChunk(FileChunk),
    V1DownloadChunkAck,
}

mod base64_serde {
    use super::*;

    pub fn serialize<S: serde::Serializer>(data: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&STANDARD.encode(data))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}
