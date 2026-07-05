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

pub mod terminology {
    // Roles
    pub const ROLE_SUPERVISOR: &str = "Supervisor";
    pub const ROLE_ADMIN: &str = "Admin";
    pub const ROLE_USER: &str = "User";
    
    // Commands
    pub const CMD_COLOR_RED: &str = "COLOR red";
    pub const CMD_COLOR_YELLOW: &str = "COLOR yellow";
    pub const CMD_COLOR_GREEN: &str = "COLOR green";
    pub const CMD_ADD_ROLE: &str = "ADD_ROLE ";
}
