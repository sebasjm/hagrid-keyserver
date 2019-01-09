use handlebars::Handlebars;
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
                    template_base: &str, from: &str, ctx: T)
    -> Result<()> where T: Serialize + Clone
{
    // TODO: Should be done only on startup
    let tmpl = format!("{}/{}", template_dir, template_base);
    let mut handlebars = Handlebars::new();
    handlebars.register_template_file("html", format!("{}-html.hbs", tmpl)).unwrap();
    handlebars.register_template_file("txt", format!("{}-txt.hbs", tmpl)).unwrap();

    let (html, txt) = {
      if let (Ok(inner_html), Ok(inner_txt)) =
        (handlebars.render("html", &ctx), handlebars.render("txt", &ctx)) {
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
            html.ok_or("Email template failed to render")?,
            txt.ok_or("Email template failed to render")?)
        .build().unwrap();

    let mut sender = SendmailTransport::new();
    sender.send(&email)?;
    Ok(())
}

pub fn send_verification_mail(userid: &Email, token: &str, template_dir: &str,
                              domain: &str, from: &str)
-> Result<()>
{
    let ctx = Context{
        token: token.to_string(),
        userid: userid.to_string(),
        domain: domain.to_string(),
    };

    send_mail(userid, "Please verify your email address", template_dir,
              "verify-email", from, ctx)
}

pub fn send_confirmation_mail(userid: &Email, token: &str, template_dir: &str,
                              domain: &str, from: &str)
-> Result<()>
{
    let ctx = Context{
        token: token.to_string(),
        userid: userid.to_string(),
        domain: domain.to_string(),
    };

    send_mail(userid, "Please confirm deletion of your key", template_dir,
              "confirm-email", from, ctx)
}
