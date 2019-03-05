use std::path::PathBuf;

use handlebars::Handlebars;
use lettre::{EmailTransport, SendmailTransport, FileEmailTransport};
use lettre_email::EmailBuilder;

use serde::Serialize;

use types::Email;
use Result;

#[derive(Serialize, Clone)]
pub struct Context {
    pub token: String,
    pub userid: Option<String>,
    pub domain: String,
}

pub struct Service {
    from: String,
    templates: Handlebars,
    transport: Transport,
}

enum Transport {
    Sendmail,
    Filemail(PathBuf),
}

impl Service {
    /// Sends mail via sendmail.
    pub fn sendmail(from: String, templates: Handlebars) -> Self {
        Self {
            from: from,
            templates: templates,
            transport: Transport::Sendmail,
        }
    }

    /// Sends mail by storing it in the given directory.
    pub fn filemail(from: String, templates: Handlebars, path: PathBuf)
                       -> Self
    {
        Self {
            from: from,
            templates: templates,
            transport: Transport::Filemail(path),
        }
    }

    pub fn send_verification(&self, userid: &Email, token: &str, domain: &str)
                             -> Result<()> {
        let ctx = Context {
            token: token.to_string(),
            userid: Some(userid.to_string()),
            domain: domain.to_string(),
        };

        self.send(
            userid,
            "Please verify your email address",
            "verify",
            ctx,
        )
    }

    pub fn send_confirmation(&self, userid: &Email, token: &str, domain: &str)
                             -> Result<()> {
        let ctx = Context {
            token: token.to_string(),
            userid: None,
            domain: domain.to_string(),
        };

        self.send(
            userid,
            "Please confirm deletion of your key",
            "confirm",
            ctx,
        )
    }

    fn send<T>(&self, to: &Email, subject: &str, template: &str, ctx: T)
               -> Result<()>
        where T: Serialize + Clone,
    {
        let tmpl_html = format!("{}-html", template);
        let tmpl_txt = format!("{}-txt", template);
        let (html, txt) = {
            if let (Ok(inner_html), Ok(inner_txt)) = (
                self.templates.render(&tmpl_html, &ctx),
                self.templates.render(&tmpl_txt, &ctx),
            ) {
                (Some(inner_html), Some(inner_txt))
            } else {
                (None, None)
            }
        };

        let email = EmailBuilder::new()
            .to(to.to_string())
            .from(self.from.clone())
            .subject(subject)
            .alternative(
                html.ok_or(failure::err_msg("Email template failed to render"))?,
                txt.ok_or(failure::err_msg("Email template failed to render"))?,
            )
            .build()
            .unwrap();

        match self.transport {
            Transport::Sendmail => {
                let mut transport = SendmailTransport::new();
                transport.send(&email)?;
            },
            Transport::Filemail(ref path) => {
                let mut transport = FileEmailTransport::new(path);
                transport.send(&email)?;
            },
        }

        Ok(())
    }
}
