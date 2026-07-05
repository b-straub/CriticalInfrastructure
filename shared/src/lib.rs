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
    pub const ROLE_OPERATOR: &str = "Operator";
    pub const ROLE_OBSERVER: &str = "Observer";
    
    // Commands
    pub const CMD_COLOR_RED: &str = "COLOR red";
    pub const CMD_COLOR_YELLOW: &str = "COLOR yellow";
    pub const CMD_COLOR_GREEN: &str = "COLOR green";
    pub const CMD_ADD_ROLE: &str = "ADD_ROLE ";
    pub const CMD_LIST_ROLES: &str = "LIST_ROLES";
    pub const CMD_REVOKE_ROLE: &str = "REVOKE_ROLE ";
    pub const CMD_READ_SENSOR: &str = "READ_SENSOR";
    pub const CMD_SET_THRESHOLD: &str = "SET_THRESHOLD ";
    pub const CMD_CLEAR_ALARM: &str = "CLEAR_ALARM";
    pub const CMD_WHOAMI: &str = "WHOAMI";
    
    // Timeouts
    pub const COMMAND_LED_TIMEOUT_MS: u64 = 5000;
}
