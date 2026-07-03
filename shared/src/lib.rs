#![no_std]

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Role {
    Admin,
    Operator,
    Observer,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandPayload {
    pub role: Role,
    pub target_led: u8, // 0 = Red, 1 = Yellow, 2 = Green
    pub turn_on: bool,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedMessage<'a> {
    pub public_key: &'a [u8], // 32 bytes
    pub signature: &'a [u8],  // 64 bytes
    pub payload: CommandPayload,
}
