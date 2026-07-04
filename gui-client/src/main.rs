use iced::widget::{button, column, row, text, text_input, pick_list};
use iced::{Element, Task};
use std::io::{Read, Write};
use std::net::TcpStream;
use ed25519_dalek::{SigningKey, Signer};

pub fn main() -> iced::Result {
    iced::application(App::new, App::update, App::view)
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
    pir_status: bool,
    alarm_active: bool,
}

impl Default for App {
    fn default() -> Self {
        let saved_ip = std::fs::read_to_string("ip_config.txt").unwrap_or_else(|_| String::new());
        Self {
            ip_address: saved_ip.trim().to_string(),
            status: String::from("Waiting..."),
            role: Role::Guest,
            pir_status: false,
            alarm_active: false,
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    IpAddressChanged(String),
    SendColor(&'static str),
    RoleSelected(Role),
    PollPir,
    PirResult(Option<(bool, bool)>),
    CommandResult(String),
}

impl App {
    fn new() -> (Self, Task<Message>) {
        (App::default(), Task::perform(async {}, |_| Message::PollPir))
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::IpAddressChanged(ip) => {
                self.ip_address = ip;
                let _ = std::fs::write("ip_config.txt", &self.ip_address);
                Task::none()
            }
            Message::RoleSelected(role) => {
                self.role = role;
                Task::none()
            }
            Message::PollPir => {
                let ip = self.ip_address.trim().to_string();
                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            if ip.is_empty() { return None; }
                            let mut connect_addr = ip;
                            if !connect_addr.contains(':') {
                                connect_addr.push_str(":8080");
                            }
                            if let Ok(mut stream) = TcpStream::connect(&connect_addr) {
                                let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
                                let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(200)));
                                if stream.write_all(b"GET_PIR").is_ok() {
                                    let mut buf = [0; 32];
                                    if let Ok(n) = stream.read(&mut buf) {
                                        let resp = String::from_utf8_lossy(&buf[..n]);
                                        let mut pir = false;
                                        let mut alarm = false;
                                        if resp.contains("PIR 1") { pir = true; }
                                        if resp.contains("ALARM 1") { alarm = true; }
                                        return Some((pir, alarm));
                                    }
                                }
                            }
                            None
                        }).await.unwrap_or(None)
                    },
                    Message::PirResult
                )
            }
            Message::PirResult(Some((pir_status, alarm_active))) => {
                self.pir_status = pir_status;
                self.alarm_active = alarm_active;
                Task::perform(async { tokio::time::sleep(std::time::Duration::from_millis(100)).await; }, |_| Message::PollPir)
            }
            Message::PirResult(None) => {
                Task::perform(async { tokio::time::sleep(std::time::Duration::from_millis(500)).await; }, |_| Message::PollPir)
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
                let ip = self.ip_address.trim().to_string();
                let role_str = self.role.as_str().to_string();
                
                self.status = format!("Sending '{}'...", color_cmd);
                
                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            let mut connect_addr = ip;
                            if !connect_addr.contains(':') {
                                connect_addr.push_str(":8080");
                            }
                            match TcpStream::connect(&connect_addr) {
                                Ok(mut stream) => {
                                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(1000)));
                                    if let Err(e) = stream.write_all(payload.as_bytes()) {
                                        format!("Failed to send: {}", e)
                                    } else {
                                        format!("Sent '{}' as {}", color_cmd, role_str)
                                    }
                                }
                                Err(e) => format!("Connection failed: {}", e),
                            }
                        }).await.unwrap_or_else(|e| format!("Task error: {}", e))
                    },
                    Message::CommandResult
                )
            }
            Message::CommandResult(res) => {
                self.status = res;
                Task::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let ip_input = row![
            text("ESP32 IP:").size(16),
            text_input("IP Address (e.g. 192.168.1.5:8080)", &self.ip_address)
                .on_input(Message::IpAddressChanged)
                .padding(10)
                .width(iced::Length::Fixed(250.0))
        ].spacing(10).align_y(iced::Alignment::Center);
            
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

        let cancel_btn = button("🔇 Cancel Alarm");
        let cancel_btn = if self.alarm_active {
            cancel_btn.on_press(Message::SendColor("CLEAR alarm"))
        } else {
            cancel_btn
        };

        let siren_buttons = row![cancel_btn].spacing(20);

        let pir_indicator = column![
            if self.alarm_active {
                text("🚨 ALARM ACTIVE 🚨")
                    .size(40)
                    .color(iced::Color::from_rgb(1.0, 0.0, 0.0))
            } else {
                text("")
            },
            if self.pir_status {
                text("PIR Sensor: 🔴 MOTION DETECTED").size(24)
            } else {
                text("PIR Sensor: 🟢 Clear").size(24)
            }
        ].spacing(15).align_x(iced::Alignment::Center);

        let content = column![
            text("ESP32 Security Control").size(30),
            ip_input,
            pir_indicator,
            role_picker,
            buttons,
            siren_buttons,
            text(&self.status).size(16)
        ]
        .spacing(20)
        .align_x(iced::Alignment::Center);

        iced::widget::center(content).into()
    }
}
