//! OTP mail delivery. This module deliberately supports only authenticated HTTPS
//! APIs and SMTP protected by implicit TLS or mandatory STARTTLS.
use std::{env, str::FromStr, time::Duration};

use lettre::{
    message::{Mailbox, MultiPart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::Serialize;

pub struct Mailer {
    backend: Backend,
}

enum Backend {
    Disabled,
    Api {
        client: reqwest::Client,
        endpoint: String,
        key: String,
        from: Mailbox,
    },
    Smtp {
        client: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
    },
}

#[derive(Serialize)]
struct ApiMail<'a> {
    from: String,
    to: [&'a str; 1],
    subject: &'static str,
    text: String,
    html: String,
}

impl Mailer {
    /// Load provider configuration once at process startup. A partially configured
    /// provider is an error rather than an accidental plaintext/fallback mode.
    pub fn from_env() -> Result<Self, String> {
        let mode = env::var("MAIL_DELIVERY").unwrap_or_else(|_| "disabled".to_owned());
        let backend = match mode.as_str() {
            "disabled" => Backend::Disabled,
            "api" => {
                let key = required("MAIL_API_KEY")?;
                let endpoint = env::var("MAIL_API_URL")
                    .unwrap_or_else(|_| "https://api.resend.com/emails".to_owned());
                let url = reqwest::Url::parse(&endpoint)
                    .map_err(|_| "MAIL_API_URL must be a valid HTTPS URL".to_owned())?;
                if url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                {
                    return Err("MAIL_API_URL must be an HTTPS URL without user info, query, or fragment".into());
                }
                let from = parse_mailbox(&required("MAIL_FROM")?, "MAIL_FROM")?;
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(12))
                    .connect_timeout(Duration::from_secs(5))
                    .no_proxy()
                    .pool_max_idle_per_host(4)
                    .redirect(reqwest::redirect::Policy::none())
                    .user_agent(concat!("Serein/", env!("CARGO_PKG_VERSION")))
                    .build()
                    .map_err(|e| format!("could not initialize mail API client: {e}"))?;
                Backend::Api { client, endpoint, key, from }
            }
            "smtp" => {
                let host = required("SMTP_HOST")?;
                if host.trim() != host || host.is_empty() || host.contains('/') || host.contains('@') {
                    return Err("SMTP_HOST must be a hostname without whitespace, path, or user info".into());
                }
                let tls_mode = env::var("SMTP_TLS_MODE").unwrap_or_else(|_| "starttls".to_owned());
                let port = match env::var("SMTP_PORT") {
                    Ok(raw) => raw.parse::<u16>().map_err(|_| "SMTP_PORT must be a valid port".to_owned())?,
                    Err(_) if tls_mode == "implicit" => 465,
                    Err(_) if tls_mode == "starttls" => 587,
                    Err(_) => return Err("SMTP_TLS_MODE must be 'implicit' or 'starttls'".into()),
                };
                if !matches!(tls_mode.as_str(), "implicit" | "starttls") {
                    return Err("SMTP_TLS_MODE must be 'implicit' or 'starttls'; plaintext SMTP is not supported".into());
                }
                let from = parse_mailbox(&required("MAIL_FROM")?, "MAIL_FROM")?;
                let username = env::var("SMTP_USERNAME").ok();
                let password = env::var("SMTP_PASSWORD").ok();
                if username.as_ref().is_some_and(|value| value.is_empty())
                    || password.as_ref().is_some_and(|value| value.is_empty())
                    || username.is_some() != password.is_some()
                {
                    return Err("SMTP_USERNAME and SMTP_PASSWORD must either both be set or both be omitted".into());
                }
                let transport = match tls_mode.as_str() {
                    "implicit" => AsyncSmtpTransport::<Tokio1Executor>::relay(&host),
                    "starttls" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host),
                    _ => unreachable!(),
                }
                .map_err(|e| format!("invalid SMTP TLS configuration: {e}"))?;
                let mut builder = transport.port(port).timeout(Some(Duration::from_secs(12)));
                if let (Some(username), Some(password)) = (username, password) {
                    builder = builder.credentials(Credentials::new(username, password));
                }
                Backend::Smtp { client: builder.build(), from }
            }
            _ => return Err("MAIL_DELIVERY must be 'disabled', 'api', or 'smtp'".into()),
        };
        Ok(Self { backend })
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(&self.backend, Backend::Disabled)
    }

    pub fn provider_name(&self) -> &'static str {
        match &self.backend {
            Backend::Disabled => "disabled",
            Backend::Api { .. } => "api",
            Backend::Smtp { .. } => "smtp",
        }
    }

    /// Send a short-lived one-time code. Provider errors intentionally exclude
    /// response bodies and credentials so secrets cannot leak into API logs.
    pub async fn send_otp(&self, recipient: &str, code: &str) -> Result<(), String> {
        let plain = format!(
            "Your Serein verification code is {code}. It expires in 10 minutes. If you did not request this, you can ignore this email."
        );
        let html = format!(
            "<p>Your Serein verification code is <strong>{code}</strong>.</p><p>It expires in 10 minutes. If you did not request this, you can ignore this email.</p>"
        );
        match &self.backend {
            Backend::Disabled => Err("Email delivery is not configured".to_owned()),
            Backend::Api { client, endpoint, key, from } => {
                let payload = ApiMail {
                    from: from.to_string(),
                    to: [recipient],
                    subject: "Your Serein verification code",
                    text: plain,
                    html,
                };
                let response = client
                    .post(endpoint.as_str())
                    .bearer_auth(key)
                    .json(&payload)
                    .send()
                    .await
                    .map_err(|_| "mail API connection failed".to_owned())?;
                if !response.status().is_success() {
                    return Err(format!("mail API returned HTTP {}", response.status()));
                }
                Ok(())
            }
            Backend::Smtp { client, from } => {
                let to = Mailbox::from_str(recipient)
                    .map_err(|_| "recipient email address is invalid".to_owned())?;
                let message = Message::builder()
                    .from(from.clone())
                    .to(to)
                    .subject("Your Serein verification code")
                    .multipart(MultiPart::alternative_plain_html(plain, html))
                    .map_err(|e| format!("could not build verification email: {e}"))?;
                client
                    .send(message)
                    .await
                    .map_err(|_| "SMTP delivery failed".to_owned())?;
                Ok(())
            }
        }
    }
}

fn required(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required for the selected mail provider"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(value)
}

fn parse_mailbox(value: &str, name: &str) -> Result<Mailbox, String> {
    value.parse().map_err(|_| format!("{name} must be a valid email mailbox"))
}
