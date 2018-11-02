use rocket_contrib::Template;

use lettre::{SendmailTransport, EmailTransport};
use lettre_email::EmailBuilder;

use serde::Serialize;

use Result;
use types::Email;

#[derive(Serialize, Clone)]
pub struct Context{
    pub token: String,
    pub userid: String,
    pub domain: String,
}

fn send_mail<T>(to: &Email, subject: &str, template_dir: &str,
                    template_base: &str, domain: &str, ctx: T)
    -> Result<()> where T: Serialize + Clone
{
    let html = Template::show(template_dir, format!("{}-html", template_base), ctx.clone());
    let txt = Template::show(template_dir, format!("{}-txt", template_base), ctx);
    let email = EmailBuilder::new()
        .to(to.to_string())
        .from(format!("noreply@{}", domain))
        .subject(subject)
        .alternative(
            html.ok_or("Email template failed to render")?,
            txt.ok_or("Email template failed to render")?)
        .build().unwrap();

    let mut sender = SendmailTransport::new();

    sender.send(&email)?;
    Ok(())
}

pub fn send_verification_mail(userid: &Email, token: &str, template_dir: &str,
                              domain: &str)
-> Result<()>
{
    let ctx = Context{
        token: token.to_string(),
        userid: userid.to_string(),
        domain: domain.to_string(),
    };

    send_mail(userid, "Please verify your email address", template_dir,
              "verify-email", domain, ctx)
}

pub fn send_confirmation_mail(userid: &Email, token: &str, template_dir: &str,
                              domain: &str)
-> Result<()>
{
    let ctx = Context{
        token: token.to_string(),
        userid: userid.to_string(),
        domain: domain.to_string(),
    };

    send_mail(userid, "Please confirm deletion of your key", template_dir,
              "confirm-email", domain, ctx)
}
