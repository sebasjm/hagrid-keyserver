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
};
use types::{Email, Fingerprint, KeyID};

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
    let tokens = db.merge_or_publish(&tpk).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    assert_eq!(tokens.len(), 2);

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
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());

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

    // verify 1st uid again
    assert!(db.verify_token(&tokens[0].1).is_err());

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
    assert!(db.verify_token(&tokens[1].1).unwrap().is_some());

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

    // upload again
    assert_eq!(
        db.merge_or_publish(&tpk).unwrap(),
        Vec::<(Email, String)>::default()
    );

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

        assert_eq!(
            db.merge_or_publish(&short_tpk).unwrap(),
            Vec::<(Email, String)>::default()
        );

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
        let tokens = db.merge_or_publish(&ext_tpk).unwrap();

        assert_eq!(tokens.len(), 1);

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
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload key
    let tokens = db.merge_or_publish(&tpk).unwrap();

    // verify 1st uid
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());
    assert!(db.by_email(&email2).is_none() ^ db.by_email(&email1).is_none());

    // reupload
    let tokens = db.merge_or_publish(&tpk).unwrap();

    assert_eq!(tokens.len(), 1);
    assert!(db.by_email(&email2).is_none() ^ db.by_email(&email1).is_none());
}

pub fn test_uid_replacement<D: Database>(db: &mut D) {
    let str_uid = "Test A <test_a@example.com>";
    let tpk1 = TPKBuilder::default().add_userid(str_uid).generate().unwrap().0;
    let tpk2 = TPKBuilder::default().add_userid(str_uid).generate().unwrap().0;

    let email = Email::from_str(str_uid).unwrap();
    let fpr1 = tpk1.fingerprint();
    let fpr2 = tpk2.fingerprint();

    // upload key
    let tokens = db.merge_or_publish(&tpk1).unwrap();

    // verify 1st uid
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());
    assert_eq!(
        TPK::from_bytes(db.by_email(&email).unwrap().as_bytes()).unwrap().fingerprint(),
        fpr1
    );

    // replace
    let tokens = db.merge_or_publish(&tpk2).unwrap();

    // Before tokens are verified, the first binding is still valid.
    assert!(db.by_email(&email).is_some());
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());
    assert_eq!(
        TPK::from_bytes(&db.by_email(&email).unwrap().as_bytes()).unwrap().fingerprint(),
        fpr2
    );
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
    let n_subkeys = tpk.subkeys().count();
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload key and verify uids
    let tokens = db.merge_or_publish(&tpk).unwrap();

    assert_eq!(tokens.len(), 2);
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());
    assert!(db.verify_token(&tokens[1].1).unwrap().is_some());

    // Check that both Mappings are there, and that the TPK is
    // otherwise intact.
    let tpk = db.lookup(&Query::ByEmail(email2.clone())).unwrap().unwrap();
    assert_eq!(tpk.userids().count(), 2);
    assert_eq!(tpk.subkeys().count(), n_subkeys);

    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // Delete second UID.
    db.delete_userids_matching(&fpr, &email2).unwrap();

    // Check that the second is still there, and that the TPK is
    // otherwise intact.
    let tpk = db.lookup(&Query::ByEmail(email1.clone())).unwrap().unwrap();
    assert_eq!(tpk.userids().count(), 1);
    assert_eq!(tpk.subkeys().count(), n_subkeys);

    // Delete first UID.
    db.delete_userids_matching(&fpr, &email1).unwrap();

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
    let _ = db.merge_or_publish(&tpk).unwrap();
    let primary_fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();
    let sub1_fpr = Fingerprint::try_from(
        tpk.subkeys().next().map(|x| x.subkey().fingerprint()).unwrap(),
    )
    .unwrap();
    let sub2_fpr = Fingerprint::try_from(
        tpk.subkeys().skip(1).next().map(|x| x.subkey().fingerprint()).unwrap(),
    )
    .unwrap();

    let raw1 = db.by_fpr(&primary_fpr).unwrap();
    let raw2 = db.by_fpr(&sub1_fpr).unwrap();
    let raw3 = db.by_fpr(&sub2_fpr).unwrap();

    assert_eq!(raw1, raw2);
    assert_eq!(raw1, raw3);
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
    let _ = db.merge_or_publish(&tpk).unwrap();
    let primary_kid = KeyID::try_from(tpk.fingerprint()).unwrap();
    let sub1_kid = KeyID::try_from(
        tpk.subkeys().next().map(|x| x.subkey().fingerprint()).unwrap(),
    )
    .unwrap();
    let sub2_kid = KeyID::try_from(
        tpk.subkeys().skip(1).next().map(|x| x.subkey().fingerprint()).unwrap(),
    )
    .unwrap();

    let raw1 = db.by_kid(&primary_kid).unwrap();
    let raw2 = db.by_kid(&sub1_kid).unwrap();
    let raw3 = db.by_kid(&sub2_kid).unwrap();

    assert_eq!(raw1, raw2);
    assert_eq!(raw1, raw3);
}

pub fn test_upload_revoked_tpk<D: Database>(db: &mut D) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let (mut tpk, revocation) = TPKBuilder::default()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap();
    tpk = tpk.merge_packets(vec![revocation.into()]).unwrap();
    match tpk.revoked(None) {
        RevocationStatus::Revoked(_) => (),
        _ => panic!("expected TPK to be revoked"),
    }

    // upload key
    let tokens = db.merge_or_publish(&tpk).unwrap();
    assert!(tokens.is_empty());
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

    // upload key
    let tokens = db.merge_or_publish(&tpk).unwrap();

    // verify uid
    assert_eq!(tokens.len(), 2);
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());
    assert!(db.verify_token(&tokens[1].1).unwrap().is_some());

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
    let tokens = db.merge_or_publish(&tpk).unwrap();
    assert_eq!(tokens.len(), 0);

    // Fail to fetch by the revoked uid, ok by the non-revoked one.
    assert!(db.by_email(&email1).is_some());
    assert!(db.by_email(&email2).is_none());
}

pub fn test_steal_uid<D: Database>(db: &mut D) {
    let str_uid1 = "Test A <test_a@example.com>";
    let tpk1 = TPKBuilder::default().add_userid(str_uid1).generate().unwrap().0;
    let tpk2 = TPKBuilder::default().add_userid(str_uid1).generate().unwrap().0;

    let email1 = Email::from_str(str_uid1).unwrap();

    // upload key
    let tokens = db.merge_or_publish(&tpk1).unwrap();

    // verify uid
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());
    assert!(db.by_email(&email1).is_some());

    // upload 2nd key with same uid
    let tokens = db.merge_or_publish(&tpk2).unwrap();

    assert_eq!(tokens.len(), 1);
    // Before tokens are verified, the first binding is still valid.
    assert!(db.by_email(&email1).is_some());
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());

    assert_eq!(
        TPK::from_bytes(&db.by_email(&email1).unwrap().as_bytes()).unwrap().fingerprint(),
        tpk2.fingerprint()
    );
}

pub fn test_unlink_uid<D: Database>(db: &mut D) {
    let uid = "Test A <test_a@example.com>";
    let email = Email::from_str(uid).unwrap();

    // Upload key and verify it.
    let tpk = TPKBuilder::default().add_userid(uid).generate().unwrap().0;
    let tokens = db.merge_or_publish(&tpk).unwrap();
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());
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
    let tokens = db.merge_or_publish(&tpk_evil).unwrap();
    assert_eq!(tokens.len(), 0);

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
    let uid1 = UserID::from(str_uid1);
    let email1 = Email::from_str(str_uid1).unwrap();

    let str_uid2 = "B <test@example.com>";
    let tpk2 = TPKBuilder::default()
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let uid2 = UserID::from(str_uid2);
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload keys.
    let tokens1 = db.merge_or_publish(&tpk1).unwrap();
    assert_eq!(tokens1.len(), 1);
    let tokens2 = db.merge_or_publish(&tpk2).unwrap();
    assert_eq!(tokens2.len(), 1);

    // verify tpk1
    assert!(db.verify_token(&tokens1[0].1).unwrap().is_some());

    // fetch by both user ids.  Even though we didn't verify uid2, the
    // email is the same, and both should return tpk1.
    assert_eq!(get_userids(&db.by_email(&email1).unwrap()[..]),
               vec![ uid1.clone() ]);
    assert_eq!(get_userids(&db.by_email(&email2).unwrap()[..]),
               vec![ uid1.clone() ]);

    // verify tpk2
    assert!(db.verify_token(&tokens2[0].1).unwrap().is_some());

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
    let tokens2 = db.merge_or_publish(&tpk2).unwrap();
    assert_eq!(tokens2.len(), 0);

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
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload key
    let tokens = db.merge_or_publish(&tpk).unwrap();

    // verify uid1
    assert_eq!(tokens.len(), 1);
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());

    // fetch by both user ids.
    assert_eq!(get_userids(&db.by_email(&email1).unwrap()[..]),
               vec![ uid1.clone(), uid2.clone() ]);
    assert_eq!(get_userids(&db.by_email(&email2).unwrap()[..]),
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
    let tokens = db.merge_or_publish(&tpk).unwrap();
    assert_eq!(tokens.len(), 0);

    // fetch by both user ids.  We should still get both user ids.
    assert_eq!(get_userids(&db.by_email(&email1).unwrap()[..]),
               vec![ uid1.clone(), uid2.clone() ]);
    assert_eq!(get_userids(&db.by_email(&email2).unwrap()[..]),
               vec![ uid1.clone(), uid2.clone() ]);
}
