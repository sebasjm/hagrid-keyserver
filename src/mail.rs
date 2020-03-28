use std::path::PathBuf;

use failure;
use handlebars::Handlebars;
use lettre::{Transport as LettreTransport, SendmailTransport, file::FileTransport};
use lettre::builder::{EmailBuilder, PartBuilder, Mailbox, MimeMultipartType};
use url;
use serde::Serialize;
use uuid::Uuid;
use crate::counters;

use rocket_i18n::I18n;
use gettext_macros::i18n;

use rfc2047::rfc2047_encode;

use crate::template_helpers;

use crate::database::types::Email;
use crate::Result;

mod context {
    #[derive(Serialize, Clone)]
    pub struct Verification {
        pub lang: String,
        pub primary_fp: String,
        pub uri: String,
        pub userid: String,
        pub base_uri: String,
        pub domain: String,
    }

    #[derive(Serialize, Clone)]
    pub struct Manage {
        pub lang: String,
        pub primary_fp: String,
        pub uri: String,
        pub base_uri: String,
        pub domain: String,
    }

    #[derive(Serialize, Clone)]
    pub struct Welcome {
        pub lang: String,
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
    pub fn sendmail(from: String, base_uri: String, template_dir: PathBuf) -> Result<Self> {
        Self::new(from, base_uri, template_dir, Transport::Sendmail)
    }

    /// Sends mail by storing it in the given directory.
    pub fn filemail(from: String, base_uri: String, template_dir: PathBuf, path: PathBuf) -> Result<Self> {
        Self::new(from, base_uri, template_dir, Transport::Filemail(path))
    }

    fn new(from: String, base_uri: String, template_dir: PathBuf, transport: Transport)
           -> Result<Self> {
        let templates = template_helpers::load_handlebars(template_dir)?;
        let domain =
            url::Url::parse(&base_uri)
            ?.host_str().ok_or_else(|| failure::err_msg("No host in base-URI"))
            ?.to_string();
        Ok(Self { from: from.into(), domain, templates, transport })
    }

    pub fn send_verification(
        &self,
        i18n: &I18n,
        base_uri: &str,
        tpk_name: String,
        userid: &Email,
        token: &str
    ) -> Result<()> {
        let ctx = context::Verification {
            lang: i18n.lang.to_string(),
            primary_fp: tpk_name,
            uri: format!("{}/verify/{}", base_uri, token),
            userid: userid.to_string(),
            base_uri: base_uri.to_owned(),
            domain: self.domain.clone(),
        };

        counters::inc_mail_sent("verify", userid);

        self.send(
            &vec![userid],
            &i18n!(
                i18n.catalog,
                context = "Subject for verification email",
                "Verify {userid} for your key on {domain}";
                userid = userid,
                domain = self.domain
            ),
            "verify",
            i18n.lang,
            ctx,
        )
    }

    pub fn send_manage_token(
        &self,
        i18n: &I18n,
        base_uri: &str,
        tpk_name: String,
        recipient: &Email,
        link_path: &str,
    ) -> Result<()> {
        let ctx = context::Manage {
            lang: i18n.lang.to_string(),
            primary_fp: tpk_name,
            uri: format!("{}{}", base_uri, link_path),
            base_uri: base_uri.to_owned(),
            domain: self.domain.clone(),
        };

        counters::inc_mail_sent("manage", recipient);

        self.send(
            &[recipient],
            &i18n!(
                i18n.catalog,
                context = "Subject for manage email",
                "Manage your key on {domain}";
                domain = self.domain
            ),
            "manage",
            i18n.lang,
            ctx,
        )
    }

    pub fn send_welcome(
        &self,
        i18n: &I18n,
        base_uri: &str,
        tpk_name: String,
        userid: &Email,
        token: &str
    ) -> Result<()> {
        let ctx = context::Welcome {
            lang: i18n.lang.to_string(),
            primary_fp: tpk_name,
            uri: format!("{}/upload/{}", base_uri, token),
            base_uri: base_uri.to_owned(),
            domain: self.domain.clone(),
        };

        counters::inc_mail_sent("welcome", userid);

        self.send(
            &vec![userid],
            &format!("Your key upload on {domain}", domain = self.domain),
            "welcome",
            i18n.lang,
            ctx,
        )
    }

    fn render_template(
        &self,
        template: &str,
        locale: &str,
        ctx: impl Serialize
    ) -> Result<(String, String)> {
        let html = self.templates.render(&format!("{}/{}.htm", locale, template), &ctx)
            .or_else(|_| self.templates.render(&format!("{}.htm", template), &ctx))
            .map_err(|_| failure::err_msg("Email template failed to render"))?;
        let txt = self.templates.render(&format!("{}/{}.txt", locale, template), &ctx)
            .or_else(|_| self.templates.render(&format!("{}.txt", template), &ctx))
            .map_err(|_| failure::err_msg("Email template failed to render"))?;

        Ok((html, txt))
    }

    fn send(
        &self,
        to: &[&Email],
        subject: &str,
        template: &str,
        locale: &str,
        ctx: impl Serialize
    ) -> Result<()> {
        let (html, txt) = self.render_template(template, locale, ctx)?;

        if cfg!(debug_assertions) {
            for recipient in to.iter() {
                println!("To: {}", recipient.to_string());
            }
            println!("{}", &txt);
        }

        // build this ourselves, as a temporary workaround for https://github.com/lettre/lettre/issues/400
        let text = PartBuilder::new()
            .body(txt)
            .header(("Content-Type", "text/plain; charset=utf-8"))
            .header(("Content-Transfer-Encoding", "8bit"))
            .build();

        let html = PartBuilder::new()
            .body(html)
            .header(("Content-Type", "text/html; charset=utf-8"))
            .header(("Content-Transfer-Encoding", "8bit"))
            .build();

        let email = EmailBuilder::new()
            .from(self.from.clone())
            .subject(rfc2047_encode(subject))
            .message_id(format!("<{}@{}>", Uuid::new_v4(), self.domain))
            .message_type(MimeMultipartType::Alternative)
            .header(("Content-Transfer-Encoding", "8bit"))
            .child(text)
            .child(html);

        let email = to.iter().fold(email, |email, to| email.to(to.to_string()));

        let email = email.build()?;

        match self.transport {
            Transport::Sendmail => {
                let mut transport = SendmailTransport::new();
                transport.send(email)?;
            },
            Transport::Filemail(ref path) => {
                let mut transport = FileTransport::new(path);
                transport.send(email)?;
            },
        }

        Ok(())
    }
}

