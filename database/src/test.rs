// pub, fetch by fpr, verify no uid
// verify uid fetch by fpr fetch by uid
// verify again
// verify other uid fetch by ui1 uid2 fpr
// pub again
// pub with less uid
// pub with new uid
//
// pub & verify
// req del one
// fetch by uid & fpr
// confirm
// fetch by uid & fpr
// confirm again
// fetch by uid & fpr

use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

use Database;
use Query;
use openpgp::tpk::{TPKBuilder, UserIDBinding};
use openpgp::{
    constants::ReasonForRevocation, constants::SignatureType, packet::UserID,
    parse::Parse, Packet, PacketPile, RevocationStatus, TPK,
    packet::KeyFlags
};
use types::{Email, Fingerprint, KeyID};

use TpkStatus;
use EmailAddressStatus;

pub fn test_uid_verification<D: Database>(db: &mut D) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let tpk = TPKBuilder::default()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let uid1 = UserID::from(str_uid1);
    let uid2 = UserID::from(str_uid2);
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload key
    let tpk_status = db.merge(tpk.clone()).unwrap().into_tpk_status();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email1.clone(), EmailAddressStatus::NotPublished),
            (email2.clone(), EmailAddressStatus::NotPublished),
        )
    }, tpk_status);

    {
        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = TPK::from_bytes(raw.as_bytes()).unwrap();

        assert!(key.userids().next().is_none());
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());
    }

    // fail to fetch by uid
    assert!(db.by_email(&email1).is_none());
    assert!(db.by_email(&email2).is_none());

    // verify 1st uid
    db.set_email_published(&fpr, &email1).unwrap();

    {
        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = TPK::from_bytes(raw.as_bytes()).unwrap();

        assert!(key.userids().skip(1).next().is_none());
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let uid = key.userids().next().unwrap().userid().clone();

        assert!((uid == uid1) ^ (uid == uid2));
        let email =
            Email::from_str(&String::from_utf8(uid.value().to_vec()).unwrap())
                .unwrap();
        assert_eq!(db.by_email(&email).unwrap(), raw);

        if email1 == email {
            assert!(db.by_email(&email2).is_none());
        } else if email2 == email {
            assert!(db.by_email(&email1).is_none());
        } else {
            unreachable!()
        }
    }

    // this operation is idempotent - let's try again!
    db.set_email_published(&fpr, &tpk_status.email_status[0].0).unwrap();

    {
        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = TPK::from_bytes(raw.as_bytes()).unwrap();

        assert!(key.userids().skip(1).next().is_none());
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let uid = key.userids().next().unwrap().userid().clone();

        assert!((uid == uid1) ^ (uid == uid2));
        let email =
            Email::from_str(&String::from_utf8(uid.value().to_vec()).unwrap())
                .unwrap();
        assert_eq!(db.by_email(&email).unwrap(), raw);

        if email1 == email {
            assert!(db.by_email(&email2).is_none());
        } else if email2 == email {
            assert!(db.by_email(&email1).is_none());
        } else {
            unreachable!()
        }
    }

    // verify 2nd uid
    db.set_email_published(&fpr, &tpk_status.email_status[1].0).unwrap();

    {
        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = TPK::from_bytes(raw.as_bytes()).unwrap();

        assert_eq!(key.userids().len(), 2);
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let myuid1 = key.userids().next().unwrap().userid().clone();
        let myuid2 = key.userids().skip(1).next().unwrap().userid().clone();

        assert_eq!(db.by_email(&email1).unwrap(), raw);
        assert_eq!(db.by_email(&email2).unwrap(), raw);
        assert!(
            ((myuid1 == uid1) & (myuid2 == uid2))
                ^ ((myuid1 == uid2) & (myuid2 == uid1))
        );
    }

    let tpk_status = db.merge(tpk.clone()).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email1.clone(), EmailAddressStatus::Published),
            (email2.clone(), EmailAddressStatus::Published),
        )
    }, tpk_status);

    // publish w/ one uid less
    {
        let packets =
            tpk.clone().into_packet_pile().into_children().filter(|pkt| {
                match pkt {
                    Packet::UserID(ref uid) => *uid != uid1,
                    _ => true,
                }
            });
        let pile : PacketPile = packets.collect::<Vec<Packet>>().into();
        let short_tpk = TPK::from_packet_pile(pile).unwrap();

        let tpk_status = db.merge(short_tpk).unwrap().into_tpk_status();
        assert_eq!(TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email2.clone(), EmailAddressStatus::Published),
            )
        }, tpk_status);

        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = TPK::from_bytes(raw.as_bytes()).unwrap();

        assert_eq!(key.userids().len(), 2);
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let myuid1 = key.userids().next().unwrap().userid().clone();
        let myuid2 = key.userids().skip(1).next().unwrap().userid().clone();

        assert_eq!(db.by_email(&email1).unwrap(), raw);
        assert_eq!(db.by_email(&email2).unwrap(), raw);
        assert!(
            ((myuid1 == uid1) & (myuid2 == uid2))
                ^ ((myuid1 == uid2) & (myuid2 == uid1))
        );
    }

    // publish w/one uid more
    {
        let mut packets = tpk
            .clone()
            .into_packet_pile()
            .into_children()
            .filter(|pkt| {
                match pkt {
                    Packet::UserID(ref uid) => *uid != uid1,
                    _ => true,
                }
            })
            .collect::<Vec<_>>();
        let str_uid3 = "Test C <test_c@example.com>";
        let uid3 = UserID::from(str_uid3);

        let email3 = Email::from_str(str_uid3).unwrap();
        let key = tpk.primary();
        let mut signer = key.clone().into_keypair().unwrap();
        let bind = UserIDBinding::new(key, uid3.clone(), &mut signer).unwrap();

        packets.push(Packet::UserID(uid3.clone()));
        packets
            .push(Packet::Signature(bind.selfsigs()[0].clone()));

        let pile : PacketPile = packets.into();
        let ext_tpk = TPK::from_packet_pile(pile).unwrap();
        let tpk_status = db.merge(ext_tpk).unwrap().into_tpk_status();

        assert_eq!(TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email2.clone(), EmailAddressStatus::Published),
                (email3.clone(), EmailAddressStatus::NotPublished),
            )
        }, tpk_status);

        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = TPK::from_bytes(raw.as_bytes()).unwrap();

        assert_eq!(key.userids().len(), 2);
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let myuid1 = key.userids().next().unwrap().userid().clone();
        let myuid2 = key.userids().skip(1).next().unwrap().userid().clone();

        assert_eq!(db.by_email(&email1).unwrap(), raw);
        assert_eq!(db.by_email(&email2).unwrap(), raw);
        assert!(
            ((myuid1 == uid1) & (myuid2 == uid2))
                ^ ((myuid1 == uid2) & (myuid2 == uid1))
        );
        assert!(db.by_email(&email3).is_none());
    }
}

pub fn test_reupload<D: Database>(db: &mut D) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let tpk = TPKBuilder::default()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload key
    db.merge(tpk.clone()).unwrap().into_tpk_status();

    // verify 1st uid
    db.set_email_published(&fpr, &email1).unwrap();
    assert!(db.by_email(&email2).is_none() ^ db.by_email(&email1).is_none());

    // reupload
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();

    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email1.clone(), EmailAddressStatus::Published),
            (email2.clone(), EmailAddressStatus::NotPublished),
        )
    }, tpk_status);
    assert!(db.by_email(&email2).is_none() ^ db.by_email(&email1).is_none());
}

pub fn test_uid_replacement<D: Database>(db: &mut D) {
    let str_uid1 = "Test A <test_a@example.com>";
    let tpk1 = TPKBuilder::default().add_userid(str_uid1).generate().unwrap().0;
    let fpr1 = Fingerprint::try_from(tpk1.fingerprint()).unwrap();

    let tpk2 = TPKBuilder::default().add_userid(str_uid1).generate().unwrap().0;
    let fpr2 = Fingerprint::try_from(tpk2.fingerprint()).unwrap();

    let pgp_fpr1 = tpk1.fingerprint();
    let pgp_fpr2 = tpk2.fingerprint();

    let email1 = Email::from_str(str_uid1).unwrap();

    // upload both keys
    db.merge(tpk1).unwrap().into_tpk_status();
    db.merge(tpk2).unwrap().into_tpk_status();

    // verify 1st uid
    db.set_email_published(&fpr1, &email1).unwrap();
    assert!(db.by_email(&email1).is_some());
    assert_eq!(TPK::from_bytes(db.by_email(&email1).unwrap().as_bytes()).unwrap()
               .fingerprint(), pgp_fpr1);

    assert_eq!(TPK::from_bytes(db.by_fpr(&fpr1).unwrap().as_bytes()).unwrap()
               .userids().len(), 1);
    assert_eq!(TPK::from_bytes(db.by_fpr(&fpr2).unwrap().as_bytes()).unwrap()
               .userids().len(), 0);

    // verify uid on other key
    db.set_email_published(&fpr2, &email1).unwrap();
    assert!(db.by_email(&email1).is_some());
    assert_eq!(TPK::from_bytes(db.by_email(&email1).unwrap().as_bytes()).unwrap()
               .fingerprint(), pgp_fpr2);

    assert_eq!(TPK::from_bytes(db.by_fpr(&fpr1).unwrap().as_bytes()).unwrap()
               .userids().len(), 0);
    assert_eq!(TPK::from_bytes(db.by_fpr(&fpr2).unwrap().as_bytes()).unwrap()
               .userids().len(), 1);
}

pub fn test_uid_deletion<D: Database>(db: &mut D) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let tpk = TPKBuilder::default()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .add_signing_subkey()
        .add_encryption_subkey()
        .generate()
        .unwrap()
        .0;
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();
    let n_subkeys = tpk.subkeys().count();
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload key and verify uids
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email1.clone(), EmailAddressStatus::NotPublished),
            (email2.clone(), EmailAddressStatus::NotPublished),
        )
    }, tpk_status);

    db.set_email_published(&fpr, &email1).unwrap();
    db.set_email_published(&fpr, &email2).unwrap();

    // Check that both Mappings are there, and that the TPK is
    // otherwise intact.
    let tpk = db.lookup(&Query::ByEmail(email2.clone())).unwrap().unwrap();
    assert_eq!(tpk.userids().count(), 2);
    assert_eq!(tpk.subkeys().count(), n_subkeys);

    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // Delete second UID.
    db.set_email_unpublished(&fpr, &email2).unwrap();

    // Check that the second is still there, and that the TPK is
    // otherwise intact.
    let tpk = db.lookup(&Query::ByEmail(email1.clone())).unwrap().unwrap();
    assert_eq!(tpk.userids().count(), 1);
    assert_eq!(tpk.subkeys().count(), n_subkeys);

    // Delete first UID.
    db.set_email_unpublished(&fpr, &email1).unwrap();

    // Check that the second is still there, and that the TPK is
    // otherwise intact.
    let tpk =
        db.lookup(&Query::ByFingerprint(tpk.fingerprint().try_into().unwrap()))
        .unwrap().unwrap();
    assert_eq!(tpk.userids().count(), 0);
    assert_eq!(tpk.subkeys().count(), n_subkeys);
}

pub fn test_subkey_lookup<D: Database>(db: &mut D) {
    let tpk = TPKBuilder::default()
        .add_userid("Testy <test@example.com>")
        .add_signing_subkey()
        .add_encryption_subkey()
        .generate()
        .unwrap()
        .0;

    // upload key
    let _ = db.merge(tpk.clone()).unwrap().into_tpk_status();

    // upload key
    let _ = db.merge(tpk.clone()).unwrap().into_tpk_status();
    let fpr_primray = Fingerprint::try_from(tpk.fingerprint()).unwrap();
    let fpr_sign: Fingerprint = tpk.keys_all()
        .signing_capable()
        .map(|(_, _, key)| key.fingerprint().try_into().unwrap())
        .next().unwrap();
    let fpr_encrypt: Fingerprint = tpk.keys_all()
        .key_flags(KeyFlags::empty().set_encrypt_for_transport(true))
        .map(|(_, _, key)| key.fingerprint().try_into().unwrap())
        .next().unwrap();

    let raw1 = db.by_fpr(&fpr_primray).expect("primary fpr must be linked!");
    let raw2 = db.by_fpr(&fpr_sign).expect("signing subkey fpr must be linked!");
    // encryption subkey key id must not be linked!
    assert!(db.by_fpr(&fpr_encrypt).is_none());

    assert_eq!(raw1, raw2);
}

pub fn test_kid_lookup<D: Database>(db: &mut D) {
    let tpk = TPKBuilder::default()
        .add_userid("Testy <test@example.com>")
        .add_signing_subkey()
        .add_encryption_subkey()
        .generate()
        .unwrap()
        .0;

    // upload key
    let _ = db.merge(tpk.clone()).unwrap().into_tpk_status();
    let kid_primray = KeyID::try_from(tpk.fingerprint()).unwrap();
    let kid_sign: KeyID = tpk.keys_all()
        .signing_capable()
        .map(|(_, _, key)| key.fingerprint().try_into().unwrap())
        .next().unwrap();
    let kid_encrypt: KeyID = tpk.keys_all()
        .key_flags(KeyFlags::empty().set_encrypt_for_transport(true))
        .map(|(_, _, key)| key.fingerprint().try_into().unwrap())
        .next().unwrap();

    let raw1 = db.by_kid(&kid_primray).expect("primary key id must be linked!");
    let raw2 = db.by_kid(&kid_sign).expect("signing subkey key id must be linked!");
    // encryption subkey key id must not be linked!
    assert!(db.by_kid(&kid_encrypt).is_none());

    assert_eq!(raw1, raw2);
}

pub fn test_upload_revoked_tpk<D: Database>(db: &mut D) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let (mut tpk, revocation) = TPKBuilder::default()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap();
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    tpk = tpk.merge_packets(vec![revocation.into()]).unwrap();
    match tpk.revoked(None) {
        RevocationStatus::Revoked(_) => (),
        _ => panic!("expected TPK to be revoked"),
    }

    // upload key
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: true,
        email_status: vec!(
            (email1.clone(), EmailAddressStatus::NotPublished),
            (email2.clone(), EmailAddressStatus::NotPublished),
        )
    }, tpk_status);
}

pub fn test_uid_revocation<D: Database>(db: &mut D) {
    use std::{thread, time};

    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let tpk = TPKBuilder::default()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let uid2 = UserID::from(str_uid2);
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // upload key
    let tpk_status = db.merge(tpk.clone()).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email1.clone(), EmailAddressStatus::NotPublished),
            (email2.clone(), EmailAddressStatus::NotPublished),
        )
    }, tpk_status);

    // verify uid
    db.set_email_published(&fpr, &tpk_status.email_status[0].0).unwrap();
    db.set_email_published(&fpr, &tpk_status.email_status[1].0).unwrap();

    // fetch both uids
    assert!(db.by_email(&email1).is_some());
    assert!(db.by_email(&email2).is_some());

    thread::sleep(time::Duration::from_secs(2));

    // revoke one uid
    let sig = {
        let uid = tpk.userids().find(|b| *b.userid() == uid2).unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow, uid.revoked(None));

        let mut keypair = tpk.primary().clone().into_keypair().unwrap();
        uid.revoke(
            &mut keypair,
            ReasonForRevocation::UIDRetired,
            b"It was the maid :/",
        )
        .unwrap()
    };
    assert_eq!(sig.sigtype(), SignatureType::CertificateRevocation);
    let tpk = tpk.merge_packets(vec![sig.into()]).unwrap();
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email1.clone(), EmailAddressStatus::Published),
            (email2.clone(), EmailAddressStatus::Revoked),
        )
    }, tpk_status);

    // Fail to fetch by the revoked uid, ok by the non-revoked one.
    assert!(db.by_email(&email1).is_some());
    assert!(db.by_email(&email2).is_none());
}

pub fn test_unlink_uid<D: Database>(db: &mut D) {
    let uid = "Test A <test_a@example.com>";
    let email = Email::from_str(uid).unwrap();

    // Upload key and verify it.
    let tpk = TPKBuilder::default().add_userid(uid).generate().unwrap().0;
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    db.merge(tpk.clone()).unwrap().into_tpk_status();
    db.set_email_published(&fpr, &email).unwrap();
    assert!(db.by_email(&email).is_some());

    // Create a 2nd key with same uid, and revoke the uid.
    let tpk_evil = TPKBuilder::default().add_userid(uid).generate().unwrap().0;
    let sig = {
        let uid = tpk_evil.userids()
            .find(|b| b.userid().value() == uid.as_bytes()).unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow, uid.revoked(None));

        let mut keypair = tpk_evil.primary().clone().into_keypair().unwrap();
        uid.revoke(
            &mut keypair,
            ReasonForRevocation::UIDRetired,
            b"I just had to quit, I couldn't bear it any longer",
        )
        .unwrap()
    };
    assert_eq!(sig.sigtype(), SignatureType::CertificateRevocation);
    let tpk_evil = tpk_evil.merge_packets(vec![sig.into()]).unwrap();
    let tpk_status = db.merge(tpk_evil).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email.clone(), EmailAddressStatus::Revoked),
        )
    }, tpk_status);

    // Check that when looking up by email, we still get the former
    // TPK.
    assert_eq!(
        db.lookup(&Query::ByEmail(email)).unwrap().unwrap().fingerprint(),
        tpk.fingerprint());
}

pub fn get_userids(armored: &str) -> Vec<UserID> {
    let tpk = TPK::from_bytes(armored.as_bytes()).unwrap();
    tpk.userids().map(|binding| binding.userid().clone()).collect()
}

// If multiple keys have the same email address, make sure things work
// as expected.
pub fn test_same_email_1<D: Database>(db: &mut D) {
    let str_uid1 = "A <test@example.com>";
    let tpk1 = TPKBuilder::default()
        .add_userid(str_uid1)
        .generate()
        .unwrap()
        .0;
    let fpr1 = Fingerprint::try_from(tpk1.fingerprint()).unwrap();
    let uid1 = UserID::from(str_uid1);
    let email1 = Email::from_str(str_uid1).unwrap();

    let str_uid2 = "B <test@example.com>";
    let tpk2 = TPKBuilder::default()
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let fpr2 = Fingerprint::try_from(tpk2.fingerprint()).unwrap();
    let uid2 = UserID::from(str_uid2);
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload keys.
    let tpk_status1 = db.merge(tpk1).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email1.clone(), EmailAddressStatus::NotPublished),
        )
    }, tpk_status1);
    let tpk_status2 = db.merge(tpk2.clone()).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email2.clone(), EmailAddressStatus::NotPublished),
        )
    }, tpk_status2);

    // verify tpk1
    db.set_email_published(&fpr1, &tpk_status1.email_status[0].0).unwrap();

    // fetch by both user ids.  Even though we didn't verify uid2, the
    // email is the same, and both should return tpk1.
    assert_eq!(get_userids(&db.by_email(&email1).unwrap()[..]),
               vec![ uid1.clone() ]);
    assert_eq!(get_userids(&db.by_email(&email2).unwrap()[..]),
               vec![ uid1.clone() ]);

    // verify tpk2
    db.set_email_published(&fpr2, &tpk_status2.email_status[0].0).unwrap();

    // fetch by both user ids.  We should now get tpk2.
    assert_eq!(get_userids(&db.by_email(&email1).unwrap()[..]),
               vec![ uid2.clone() ]);
    assert_eq!(get_userids(&db.by_email(&email2).unwrap()[..]),
               vec![ uid2.clone() ]);

    // revoke tpk2's uid
    let sig = {
        let uid = tpk2.userids().find(|b| *b.userid() == uid2).unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow, uid.revoked(None));

        let mut keypair = tpk2.primary().clone().into_keypair().unwrap();
        uid.revoke(
            &mut keypair,
            ReasonForRevocation::UIDRetired,
            b"It was the maid :/",
        )
        .unwrap()
    };
    assert_eq!(sig.sigtype(), SignatureType::CertificateRevocation);
    let tpk2 = tpk2.merge_packets(vec![sig.into()]).unwrap();
    let tpk_status2 = db.merge(tpk2).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email2.clone(), EmailAddressStatus::Revoked),
        )
    }, tpk_status2);

    // fetch by both user ids.  We should get nothing.
    assert!(&db.by_email(&email1).is_none());
    assert!(&db.by_email(&email2).is_none());
}

// If a key has multiple user ids with the same email address, make
// sure things still work.
pub fn test_same_email_2<D: Database>(db: &mut D) {
    use std::{thread, time};

    let str_uid1 = "A <test@example.com>";
    let str_uid2 = "B <test@example.com>";
    let tpk = TPKBuilder::default()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let uid1 = UserID::from(str_uid1);
    let uid2 = UserID::from(str_uid2);
    let email = Email::from_str(str_uid1).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // upload key
    let tpk_status = db.merge(tpk.clone()).unwrap().into_tpk_status();

    // verify uid1
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email.clone(), EmailAddressStatus::NotPublished),
        )
    }, tpk_status);
    db.set_email_published(&fpr, &tpk_status.email_status[0].0).unwrap();

    // fetch by both user ids.
    assert_eq!(get_userids(&db.by_email(&email).unwrap()[..]),
               vec![ uid1.clone(), uid2.clone() ]);

    thread::sleep(time::Duration::from_secs(2));

    // revoke one uid
    let sig = {
        let uid = tpk.userids().find(|b| *b.userid() == uid2).unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow, uid.revoked(None));

        let mut keypair = tpk.primary().clone().into_keypair().unwrap();
        uid.revoke(
            &mut keypair,
            ReasonForRevocation::UIDRetired,
            b"It was the maid :/",
        )
        .unwrap()
    };
    assert_eq!(sig.sigtype(), SignatureType::CertificateRevocation);
    let tpk = tpk.merge_packets(vec![sig.into()]).unwrap();
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email.clone(), EmailAddressStatus::Published),
        )
    }, tpk_status);

    // fetch by both user ids.  We should still get both user ids.
    // TODO should this still deliver uid2.clone()?
    assert_eq!(get_userids(&db.by_email(&email).unwrap()[..]),
               vec![ uid1.clone() ]);
    assert_eq!(get_userids(&db.by_email(&email).unwrap()[..]),
               vec![ uid1.clone() ]);
}
