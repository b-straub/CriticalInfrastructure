use iced::widget::{button, column, row, text, text_input};
use iced::{Center, Element, Task, Theme};
use std::io::Write;
use std::net::TcpStream;

pub fn main() -> iced::Result {
    iced::application(RemoteControl::default, RemoteControl::update, RemoteControl::view)
        .title("Remote Control")
        .run()
}

#[derive(Default)]
struct RemoteControl {
    ip_address: String,
    status: String,
    stream: Option<TcpStream>,
}

#[derive(Debug, Clone)]
enum Message {
    IpAddressChanged(String),
    Connect,
    SetColor(String),
}

impl RemoteControl {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::IpAddressChanged(ip) => {
                self.ip_address = ip;
                Task::none()
            }
            Message::Connect => {
                let address = format!("{}:8080", self.ip_address);
                match TcpStream::connect(&address) {
                    Ok(stream) => {
                        self.stream = Some(stream);
                        self.status = format!("Connected to {}", address);
                    }
                    Err(e) => {
                        self.status = format!("Failed to connect: {}", e);
                    }
                }
                Task::none()
            }
            Message::SetColor(color) => {
                if let Some(stream) = &mut self.stream {
                    let cmd = format!("COLOR {}\n", color);
                    if let Err(e) = stream.write_all(cmd.as_bytes()) {
                        self.status = format!("Failed to send color: {}", e);
                        self.stream = None;
                    } else {
                        self.status = format!("Sent color: {}", color);
                    }
                } else {
                    self.status = "Not connected".to_string();
                }
                Task::none()
            }
        }
    }

    fn view(&self) -> Element<Message> {
        let ip_input = text_input("IP Address", &self.ip_address)
            .on_input(Message::IpAddressChanged)
            .padding(10);

        let connect_btn = button("Connect").on_press(Message::Connect).padding(10);

        let red_btn = button("Red").on_press(Message::SetColor("red".to_string())).padding(10);
        let yellow_btn = button("Yellow").on_press(Message::SetColor("yellow".to_string())).padding(10);
        let green_btn = button("Green").on_press(Message::SetColor("green".to_string())).padding(10);

        column![
            text("Remote Control").size(40),
            row![ip_input, connect_btn].spacing(10),
            text(&self.status),
            row![red_btn, yellow_btn, green_btn].spacing(10),
        ]
        .padding(20)
        .spacing(20)
        .align_x(Center)
        .into()
    }
}
