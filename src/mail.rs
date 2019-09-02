use std::path::PathBuf;

use failure;
use handlebars::Handlebars;
use lettre::{Transport as LettreTransport, SendmailTransport, file::FileTransport};
use lettre_email::{Mailbox,EmailBuilder};
use url;
use serde::Serialize;
use uuid::Uuid;
use crate::counters;

use crate::database::types::Email;
use crate::Result;

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
        pub primary_fp: String,
        pub uri: String,
        pub base_uri: String,
        pub domain: String,
    }

    #[derive(Serialize, Clone)]
    pub struct Welcome {
        pub primary_fp: String,
        pub uri: String,
        pub base_uri: String,
        pub domain: String,
    }
}

pub struct Service {
    from: Mailbox,
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
            from: from.parse().unwrap(),
            domain: domain,
            templates: templates,
            transport: transport,
        })
    }

    pub fn send_verification(&self, base_uri: &str, tpk_name: String, userid: &Email,
                             token: &str)
                             -> Result<()> {
        let ctx = context::Verification {
            primary_fp: tpk_name,
            uri: format!("{}/verify/{}", base_uri, token),
            userid: userid.to_string(),
            base_uri: base_uri.to_owned(),
            domain: self.domain.clone(),
        };

        counters::inc_mail_sent("verify", userid);

        self.send(
            &vec![userid],
            &format!("Verify {} for your key on {}", userid, self.domain),
            "verify",
            ctx,
        )
    }

    pub fn send_manage_token(&self, base_uri: &str, tpk_name: String, recipient: &Email,
                             link_path: &str) -> Result<()> {
        let ctx = context::Manage {
            primary_fp: tpk_name,
            uri: format!("{}{}", base_uri, link_path),
            base_uri: base_uri.to_owned(),
            domain: self.domain.clone(),
        };

        counters::inc_mail_sent("manage", recipient);

        self.send(
            &[recipient],
            &format!("Manage your key on {}", self.domain),
            "manage",
            ctx,
        )
    }

    pub fn send_welcome(&self, base_uri: &str, tpk_name: String, userid: &Email,
                             token: &str)
                             -> Result<()> {
        let ctx = context::Welcome {
            primary_fp: tpk_name,
            uri: format!("{}/upload/{}", base_uri, token),
            base_uri: base_uri.to_owned(),
            domain: self.domain.clone(),
        };

        counters::inc_mail_sent("welcome", userid);

        self.send(
            &vec![userid],
            &format!("Your key upload on {}", self.domain),
            "welcome",
            ctx,
        )
    }

    fn send<T>(&self, to: &[&Email], subject: &str, template: &str, ctx: T)
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

        let email = EmailBuilder::new()
            .from(self.from.clone())
            .subject(subject)
            .alternative(
                html.ok_or(failure::err_msg("Email template failed to render"))?,
                txt.ok_or(failure::err_msg("Email template failed to render"))?,
            )
            .message_id(format!("<{}@{}>", Uuid::new_v4(), self.domain));

        let email = to.iter().fold(email, |email, to| email.to(to.to_string()));

        let email = email.build()?;

        match self.transport {
            Transport::Sendmail => {
                let mut transport = SendmailTransport::new();
                transport.send(email.into())?;
            },
            Transport::Filemail(ref path) => {
                let mut transport = FileTransport::new(path);
                transport.send(email.into())?;
            },
        }

        Ok(())
    }
}
