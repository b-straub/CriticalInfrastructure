#![no_std]

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    // NOTE: new variants must be appended (postcard encodes the variant index).
    Admin,
    Operator,
    Observer,
    Supervisor,
}

impl Role {
    /// Every role. The single source of truth for the role set.
    pub const ALL: [Role; 4] = [Role::Supervisor, Role::Admin, Role::Operator, Role::Observer];

    /// Canonical wire/display name -- the single source of truth for role strings.
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Supervisor => "Supervisor",
            Role::Admin => "Admin",
            Role::Operator => "Operator",
            Role::Observer => "Observer",
        }
    }

    /// Parse a role from its canonical wire name.
    pub fn from_wire(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

pub mod terminology {
    // Roles -- derived from the Role enum (single source of truth).
    pub const ROLE_SUPERVISOR: &str = super::Role::Supervisor.as_str();
    pub const ROLE_ADMIN: &str = super::Role::Admin.as_str();
    pub const ROLE_OPERATOR: &str = super::Role::Operator.as_str();
    pub const ROLE_OBSERVER: &str = super::Role::Observer.as_str();
    
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

    // Network -- single source of truth for the port on both the firmware and
    // the clients. Served over HTTP/TCP or raw UDP depending on the ROM flavor.
    pub const SUPERVISOR_PORT: u16 = 8080;
}
