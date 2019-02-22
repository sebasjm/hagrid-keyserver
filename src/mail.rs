use handlebars::Handlebars;
use lettre::{EmailTransport, SendmailTransport};
use lettre_email::EmailBuilder;

use serde::Serialize;

use types::Email;
use Result;

#[derive(Serialize, Clone)]
pub struct Context {
    pub token: String,
    pub userid: String,
    pub domain: String,
}

fn send_mail<T>(
    to: &Email, subject: &str, mail_templates: &Handlebars, template: &str,
    from: &str, ctx: T,
) -> Result<()>
where
    T: Serialize + Clone,
{
    let tmpl_html = format!("{}-html", template);
    let tmpl_txt = format!("{}-txt", template);
    let (html, txt) = {
        if let (Ok(inner_html), Ok(inner_txt)) = (
            mail_templates.render(&tmpl_html, &ctx),
            mail_templates.render(&tmpl_txt, &ctx),
        ) {
            (Some(inner_html), Some(inner_txt))
        } else {
            (None, None)
        }
    };

    let email = EmailBuilder::new()
        .to(to.to_string())
        .from(from)
        .subject(subject)
        .alternative(
            html.ok_or(failure::err_msg("Email template failed to render"))?,
            txt.ok_or(failure::err_msg("Email template failed to render"))?,
        )
        .build()
        .unwrap();

    let mut sender = SendmailTransport::new();
    sender.send(&email)?;
    Ok(())
}

pub fn send_verification_mail(
    userid: &Email, token: &str, mail_templates: &Handlebars, domain: &str,
    from: &str,
) -> Result<()> {
    let ctx = Context {
        token: token.to_string(),
        userid: userid.to_string(),
        domain: domain.to_string(),
    };

    send_mail(
        userid,
        "Please verify your email address",
        mail_templates,
        "verify",
        from,
        ctx,
    )
}

pub fn send_confirmation_mail(
    userid: &Email, token: &str, mail_templates: &Handlebars, domain: &str,
    from: &str,
) -> Result<()> {
    let ctx = Context {
        token: token.to_string(),
        userid: userid.to_string(),
        domain: domain.to_string(),
    };

    send_mail(
        userid,
        "Please confirm deletion of your key",
        mail_templates,
        "confirm",
        from,
        ctx,
    )
}
