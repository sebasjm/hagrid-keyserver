use gettext_macros::t;

fn _dummy() {
    t!("Error");
    t!("Looks like something went wrong :(");
    t!("<strong>Error:</strong> {{ internal_error }}");
    t!("We found an entry for <span class=\"email\">{{ query }}</span>:");
    t!("debug info");
    t!("Search by Email Address / Key ID / Fingerprint");
    t!("Search");
    t!("You can also <a href=\"/upload\">upload</a> or <a href=\"/manage\">manage</a> your key.");
    t!("Find out more <a href=\"/about\">about this service</a>.");
    t!("News:");
    t!("v{{ version }} built from");
    t!("Powered by <a href=\"https://sequoia-pgp.org\">Sequoia-PGP</a>");
    t!("Background image retrieved from <a href=\"https://www.toptal.com/designers/subtlepatterns/subtle-grey/\">Subtle Patterns</a> under CC BY-SA 3.0");
    t!("Maintenance Mode");
    t!("Manage your key");
    t!("Enter any verified e-mail address of your key");
    t!("Send link");
    t!("We will send you an e-mail with a link you can use to remove any of your e-mail addresses from search.");
    t!("Managing the key <span class=\"fingerprint\"><a href=\"{{ key_link }}\" target=\"_blank\">{{ key_fpr }}</a></span>.");
    t!("Your key is published with the following identity information:");
    t!("Clicking \"delete\" on any address will remove it from this key. It will no longer appear in a search.<br /> To add another address, <a href=\"/upload\">upload</a> the key again.");
    t!("Your key is published as only non-identity information.  (<a href=\"/about\" target=\"_blank\">what does this mean?</a>)");
    t!("To add an address, <a href=\"/upload\">upload</a> the key again.");
    t!("We have sent an email with further instructions to <span class=\"email\">{{ address }}</span>");
    t!("This address was already verified.");
    t!("Your key <span class=\"fingerprint\">{{ key_fpr }}</span> is now published for the identity <a href=\"{{userid_link}}\" target=\"_blank\"><span class=\"email\">{{ userid }}</span></a>.");
    t!("Verification failed! Perhaps the link you used was expired?");
    t!("You can <a href=\"/upload\">try uploading again</a>.");
    t!("Your public key");
    t!("Upload");
    t!("Need more info? Check our <a target=\"_blank\" href=\"/about\">intro</a> and <a target=\"_blank\" href=\"/about/usage\">usage guide</a>!");
    t!("You uploaded the key <span class=\"fingerprint\"><a href=\"{{ key_link }}\" target=\"_blank\">{{ key_fpr }}</a></span>.");
    t!("This key is revoked.");
    t!("It is published without identity information and can't be made available for search by e-mail address");
    t!("what does this mean?");
    t!("This key is now published with the following identity information (<a href=\"/about\" target=\"_blank\">what does this mean?</a>):");
    t!("Published");
    t!("This key is now published with only non-identity information (<a href=\"/about\" target=\"_blank\">what does this mean?</a>)");
    t!("To make the key available for search by e-mail address, you can verify it belongs to you:");
    t!("Verification Pending");
    t!("<strong>Note:</strong> Some providers delay e-mails for up to 15 minutes to prevent spam. Please be patient.");
    t!("Send Verification Mail");
    t!("This key contains one identity that could not be parsed as an email address.<br /> This identity can't be published on <span class=\"brand\">keys.openpgp.org</span>.  (<a href=\"/about/faq#non-email-uids\" target=\"_blank\">why?</a>)");
    t!("This key contains {{ count_unparsed }} identities that could not be parsed as an email address.<br /> These identities can't be published on <span class=\"brand\">keys.openpgp.org</span>.  (<a href=\"/about/faq#non-email-uids\" target=\"_blank\">why?</a>)");
    t!("This key contains one revoked identity, which is not published.");
    t!("(<a href=\"/about/faq#revoked-uids\" target=\"_blank\">Why?</a>)");
    t!("This key contains {{ count_revoked }} revoked identities, which are not published.");
    t!("(<a href=\"/about/faq#revoked-uids\" target=\"_blank\">Why?</a>)");
    t!("Your keys have been successfully uploaded:");
    t!("<strong>Note:</strong> To make keys searchable by address, you must upload them individually.");
    t!("Verifying your email address…");
    t!("If the process doesn't complete after a few seconds, <input type=\"submit\" class=\"textbutton\" value=\"click here\" />.");
}
