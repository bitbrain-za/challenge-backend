use envcrypt::option_envc;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

struct Config {
    pub email_username: String,
    pub email_password: String,
    pub email_smtp_server: String,
    pub email_smtp_port: u16,
}

impl Config {
    pub fn init() -> Self {
        let email_username = option_envc!("EMAIL_USERNAME").unwrap().into();
        let email_password = option_envc!("EMAIL_PASSWORD").unwrap().into();
        let email_smtp_server = option_envc!("EMAIL_SMTP_SERVER").unwrap().into();
        let email_smtp_port = option_envc!("EMAIL_SMTP_PORT")
            .unwrap()
            .parse::<u16>()
            .unwrap();

        Self {
            email_username,
            email_password,
            email_smtp_server,
            email_smtp_port,
        }
    }
}

pub struct Email {
    pub name: String,
    pub to_address: String,
    pub subject: String,
    pub body: String,
}

impl Email {
    pub fn new(name: String, to_address: String, subject: String, body: String) -> Email {
        Email {
            name,
            to_address,
            subject,
            body,
        }
    }

    pub fn new_registration(name: String, to_address: String, verification_link: String) -> Email {
        let subject = "Welcome to the Code Challenge!".to_string();
        let body = format!(
            "Hello {},\n\nWelcome to the Code Challenge! Please click the following link to verify your email address:\n\n{}\n\nThanks!",
            name, verification_link
        );
        Email {
            name,
            to_address,
            subject,
            body,
        }
    }

    pub fn new_password_reset(name: String, to_address: String, reset_link: String) -> Email {
        let subject = "Password Reset".to_string();
        let body = format!(
            "Hello {},\n\nPlease click the following link to reset your password:\n\n{}\n\nThanks!",
            name, reset_link
        );
        Email {
            name,
            to_address,
            subject,
            body,
        }
    }

    pub fn send(&self) -> Result<(), String> {
        let config = Config::init();

        let email = Message::builder()
            .from(
                format!("{} <{}>", config.email_username, config.email_username)
                    .parse()
                    .unwrap(),
            )
            .reply_to(
                format!("{} <{}>", config.email_username, config.email_username)
                    .parse()
                    .unwrap(),
            )
            .to(format!("{} <{}>", self.name, self.to_address)
                .parse()
                .unwrap())
            .subject(self.subject.clone())
            .header(ContentType::TEXT_PLAIN)
            .body(self.body.clone())
            .unwrap();

        let creds = Credentials::new(config.email_username, config.email_password);

        let mailer = SmtpTransport::relay(&config.email_smtp_server)
            .unwrap()
            .credentials(creds)
            .build();

        match mailer.send(&email) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}
