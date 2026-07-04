use iced::widget::{button, column, row, text, text_input, pick_list};
use iced::{Center, Element, Task};
use std::io::Write;
use std::net::TcpStream;
use ed25519_dalek::{SigningKey, Signer};

pub fn main() -> iced::Result {
    iced::application(App::default, App::update, App::view)
        .title("Critical Infrastructure Control")
        .run()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Guest,
    User,
    Admin,
}

impl Role {
    const ALL: [Role; 3] = [Role::Guest, Role::User, Role::Admin];
    
    fn as_str(&self) -> &'static str {
        match self {
            Role::Guest => "Guest",
            Role::User => "User",
            Role::Admin => "Admin",
        }
    }
    
    fn get_secret_key(&self) -> [u8; 32] {
        match self {
            Role::Guest => [185, 25, 183, 41, 6, 39, 21, 117, 117, 79, 168, 92, 146, 240, 86, 148, 29, 170, 190, 246, 25, 82, 164, 44, 135, 177, 114, 94, 121, 41, 40, 234],
            Role::User => [170, 194, 45, 243, 130, 13, 185, 164, 138, 241, 16, 4, 233, 95, 69, 225, 104, 9, 170, 157, 114, 183, 27, 223, 185, 210, 230, 174, 24, 80, 72, 223],
            Role::Admin => [63, 37, 193, 237, 30, 97, 66, 72, 23, 60, 88, 50, 49, 253, 248, 253, 59, 14, 194, 186, 205, 193, 70, 125, 191, 91, 21, 48, 125, 211, 61, 30],
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

struct App {
    ip_address: String,
    status: String,
    role: Role,
}

impl Default for App {
    fn default() -> Self {
        Self {
            ip_address: String::new(),
            status: String::from("Waiting..."),
            role: Role::Guest,
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    IpAddressChanged(String),
    SendColor(&'static str),
    RoleSelected(Role),
}

impl App {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::IpAddressChanged(ip) => {
                self.ip_address = ip;
                Task::none()
            }
            Message::RoleSelected(role) => {
                self.role = role;
                Task::none()
            }
            Message::SendColor(color_cmd) => {
                let sk_bytes = self.role.get_secret_key();
                let signing_key = SigningKey::from_bytes(&sk_bytes);
                let signature = signing_key.sign(color_cmd.as_bytes());
                
                let mut sig_hex = String::with_capacity(128);
                for b in signature.to_bytes() {
                    sig_hex.push_str(&format!("{:02x}", b));
                }
                
                let payload = format!("{};{};{}", self.role.as_str(), color_cmd, sig_hex);
                
                match TcpStream::connect(&self.ip_address) {
                    Ok(mut stream) => {
                        if let Err(e) = stream.write_all(payload.as_bytes()) {
                            self.status = format!("Failed to send: {}", e);
                        } else {
                            self.status = format!("Sent '{}' as {}", color_cmd, self.role.as_str());
                        }
                    }
                    Err(e) => {
                        self.status = format!("Connection failed: {}", e);
                    }
                }
                Task::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let ip_input = text_input("IP Address", &self.ip_address)
            .on_input(Message::IpAddressChanged)
            .padding(10);
            
        let role_picker = row![
            text("Role:").size(20),
            pick_list(&Role::ALL[..], Some(self.role), Message::RoleSelected),
        ].spacing(10).align_y(iced::Alignment::Center);

        let buttons = row![
            button("Red").on_press(Message::SendColor("COLOR red")),
            button("Yellow").on_press(Message::SendColor("COLOR yellow")),
            button("Green").on_press(Message::SendColor("COLOR green")),
        ]
        .spacing(20);

        let content = column![
            text("ESP32 LED Controller").size(30),
            ip_input,
            role_picker,
            buttons,
            text(&self.status).size(16)
        ]
        .spacing(20)
        .align_x(iced::Alignment::Center);

        iced::widget::center(content).into()
    }
}
