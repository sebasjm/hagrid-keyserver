use std::path::PathBuf;

use failure;
use handlebars::Handlebars;
use lettre::{EmailTransport, SendmailTransport, FileEmailTransport};
use lettre_email::EmailBuilder;
use url;
use serde::Serialize;

use database::types::Email;
use Result;

mod context {
    #[derive(Serialize, Clone)]
    pub struct Verification {
        pub primary_fp: String,
        pub uri: String,
        pub userid: String,
        pub base_uri: String,
        pub domain: String,
    }

    #[derive(Serialize, Clone)]
    pub struct Manage {
        pub uri: String,
        pub base_uri: String,
        pub domain: String,
    }
}

pub struct Service {
    from: String,
    base_uri: String,
    domain: String,
    templates: Handlebars,
    transport: Transport,
}

enum Transport {
    Sendmail,
    Filemail(PathBuf),
}

impl Service {
    /// Sends mail via sendmail.
    pub fn sendmail(from: String, base_uri: String, templates: Handlebars)
                    -> Result<Self> {
        Self::new(from, base_uri, templates, Transport::Sendmail)
    }

    /// Sends mail by storing it in the given directory.
    pub fn filemail(from: String, base_uri: String, templates: Handlebars,
                    path: PathBuf)
                    -> Result<Self> {
        Self::new(from, base_uri, templates, Transport::Filemail(path))
    }

    fn new(from: String, base_uri: String, templates: Handlebars,
           transport: Transport)
           -> Result<Self> {
        let domain =
            url::Url::parse(&base_uri)
            ?.host_str().ok_or_else(|| failure::err_msg("No host in base-URI"))
            ?.to_string();
        Ok(Self {
            from: from,
            base_uri: base_uri,
            domain: domain,
            templates: templates,
            transport: transport,
        })
    }

    pub fn send_verification(&self, tpk_name: String, userid: &Email,
                             token: &str)
                             -> Result<()> {
        let ctx = context::Verification {
            primary_fp: tpk_name,
            uri: format!("{}/publish/{}", self.base_uri, token),
            userid: userid.to_string(),
            base_uri: self.base_uri.clone(),
            domain: self.domain.clone(),
        };

        self.send(
            &vec![userid.clone()],
            "Please verify your email address",
            "verify",
            ctx,
        )
    }

    pub fn send_manage_token(&self, recipients: &[Email], uri: &str)
                             -> Result<()> {
        let ctx = context::Manage {
            uri: uri.to_string(),
            base_uri: self.base_uri.clone(),
            domain: self.domain.clone(),
        };

        self.send(
            recipients,
            &format!("{}: Manage your key", &self.domain),
            "manage",
            ctx,
        )
    }

    fn send<T>(&self, to: &[Email], subject: &str, template: &str, ctx: T)
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

        if cfg!(debug_assertions) {
            for recipient in to.iter() {
                println!("To: {}", recipient.to_string());
            }
            println!("{}", txt.as_ref().unwrap().to_string());
        }

        let mut email = EmailBuilder::new()
            .from(self.from.clone())
            .subject(subject)
            .alternative(
                html.ok_or(failure::err_msg("Email template failed to render"))?,
                txt.ok_or(failure::err_msg("Email template failed to render"))?,
            );

        for recipient in to.iter() {
            email.add_to(recipient.to_string());
        }

        let email = email
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
