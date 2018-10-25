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

use std::convert::TryFrom;
use std::str::FromStr;

use database::Database;
use openpgp::tpk::{TPKBuilder, UserIDBinding};
use openpgp::{Packet, packet::UserID, TPK, PacketPile};
use types::{Email, Fingerprint};

pub fn test_uid_verification<D: Database>(db: &mut D) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let tpk = TPKBuilder::default()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate().unwrap();
    let mut uid1 = UserID::new();
    let mut uid2 = UserID::new();

    uid1.set_userid_from_bytes(str_uid1.as_bytes());
    uid2.set_userid_from_bytes(str_uid2.as_bytes());

    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload key
    let tokens = db.merge_or_publish(tpk.clone()).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    assert_eq!(tokens.len(), 2);

    {
        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = TPK::from_bytes(&raw[..]).unwrap();

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
        let key = TPK::from_bytes(&raw[..]).unwrap();

        assert!(key.userids().skip(1).next().is_none());
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let uid = key.userids().next().unwrap().userid().clone();

        assert!((uid == uid1) ^ (uid == uid2));
        let email = Email::from_str(&String::from_utf8(uid.userid().to_vec()).unwrap()).unwrap();
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
        let key = TPK::from_bytes(&raw[..]).unwrap();

        assert!(key.userids().skip(1).next().is_none());
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let uid = key.userids().next().unwrap().userid().clone();

        assert!((uid == uid1) ^ (uid == uid2));
        let email = Email::from_str(&String::from_utf8(uid.userid().to_vec()).unwrap()).unwrap();
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
        let key = TPK::from_bytes(&raw[..]).unwrap();

        assert_eq!(key.userids().len(), 2);
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let myuid1 = key.userids().next().unwrap().userid().clone();
        let myuid2 = key.userids().skip(1).next().unwrap().userid().clone();

        assert_eq!(db.by_email(&email1).unwrap(), raw);
        assert_eq!(db.by_email(&email2).unwrap(), raw);
        assert!(((myuid1 == uid1) & (myuid2 == uid2)) ^ ((myuid1 == uid2) & (myuid2 == uid1)));
    }

    // upload again
    assert_eq!(db.merge_or_publish(tpk.clone()).unwrap(), Vec::<(Email,String)>::default());

    // publish w/ one uid less
    {
        let packets = tpk.clone()
            .to_packet_pile()
            .into_children()
            .filter(|pkt| {
                match pkt {
                    Packet::UserID(ref uid) => *uid != uid1,
                    _ => true
                }
            });
        let pile = PacketPile::from_packets(packets.collect());
        let short_tpk = TPK::from_packet_pile(pile).unwrap();

        assert_eq!(db.merge_or_publish(short_tpk.clone()).unwrap(), Vec::<(Email,String)>::default());

        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = TPK::from_bytes(&raw[..]).unwrap();

        assert_eq!(key.userids().len(), 2);
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let myuid1 = key.userids().next().unwrap().userid().clone();
        let myuid2 = key.userids().skip(1).next().unwrap().userid().clone();

        assert_eq!(db.by_email(&email1).unwrap(), raw);
        assert_eq!(db.by_email(&email2).unwrap(), raw);
        assert!(((myuid1 == uid1) & (myuid2 == uid2)) ^ ((myuid1 == uid2) & (myuid2 == uid1)));
    }

    // publish w/one uid more
    {
        let mut packets = tpk.clone()
            .to_packet_pile()
            .into_children()
            .filter(|pkt| {
                match pkt {
                    Packet::UserID(ref uid) => *uid != uid1,
                    _ => true
                }
            }).collect::<Vec<_>>();
        let str_uid3 = "Test C <test_c@example.com>";
        let mut uid3 = UserID::new();
        uid3.set_userid_from_bytes(str_uid3.as_bytes());

        let email3 = Email::from_str(str_uid3).unwrap();
        let key = tpk.primary();
        let bind = UserIDBinding::new(key, uid3.clone(), key).unwrap();

        packets.push(Packet::UserID(uid3.clone()));
        packets.push(Packet::Signature(bind.selfsigs().next().unwrap().clone()));

        let pile = PacketPile::from_packets(packets);
        let ext_tpk = TPK::from_packet_pile(pile).unwrap();
        let tokens = db.merge_or_publish(ext_tpk.clone()).unwrap();

        assert_eq!(tokens.len(), 1);

        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = TPK::from_bytes(&raw[..]).unwrap();

        assert_eq!(key.userids().len(), 2);
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let myuid1 = key.userids().next().unwrap().userid().clone();
        let myuid2 = key.userids().skip(1).next().unwrap().userid().clone();

        assert_eq!(db.by_email(&email1).unwrap(), raw);
        assert_eq!(db.by_email(&email2).unwrap(), raw);
        assert!(((myuid1 == uid1) & (myuid2 == uid2)) ^ ((myuid1 == uid2) & (myuid2 == uid1)));
        assert!(db.by_email(&email3).is_none());
    }
}

pub fn test_uid_deletion<D: Database>(db: &mut D) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let tpk = TPKBuilder::default()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate().unwrap();
    let mut uid1 = UserID::new();
    let mut uid2 = UserID::new();

    uid1.set_userid_from_bytes(str_uid1.as_bytes());
    uid2.set_userid_from_bytes(str_uid2.as_bytes());

    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload key and verify uids
    let tokens = db.merge_or_publish(tpk.clone()).unwrap();

    assert_eq!(tokens.len(), 2);
    assert!(db.verify_token(&tokens[0].1).unwrap().is_some());
    assert!(db.verify_token(&tokens[1].1).unwrap().is_some());

    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // req. deletion
    let del = db.request_deletion(fpr.clone()).unwrap();

    // check it's still there 
    {
        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = TPK::from_bytes(&raw[..]).unwrap();

        assert_eq!(key.userids().len(), 2);
        assert!(key.user_attributes().next().is_none());
        assert!(key.subkeys().next().is_none());

        let myuid1 = key.userids().next().unwrap().userid().clone();
        let myuid2 = key.userids().skip(1).next().unwrap().userid().clone();

        assert_eq!(db.by_email(&email1).unwrap(), raw);
        assert_eq!(db.by_email(&email2).unwrap(), raw);
        assert!(((myuid1 == uid1) & (myuid2 == uid2)) ^ ((myuid1 == uid2) & (myuid2 == uid1)));
    }

    // confirm deletion
    assert!(db.confirm_deletion(&del).unwrap());

    // check it's gone
    assert!(db.by_fpr(&fpr).is_none());
    assert!(db.by_email(&email1).is_none());
    assert!(db.by_email(&email2).is_none());

    // confirm deletion again
    assert!(!db.confirm_deletion(&del).unwrap());

    // check it's still gone
    assert!(db.by_fpr(&fpr).is_none());
    assert!(db.by_email(&email1).is_none());
    assert!(db.by_email(&email2).is_none());
}
