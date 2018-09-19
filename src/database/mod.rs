use std::result;
use std::io::Cursor;
use std::str::FromStr;
use std::convert::TryFrom;
use std::fmt;

use serde::{Serializer, Deserializer, de};
use time;
use openpgp::{self, Signature, TPK, UserID, Packet, PacketPile, constants::SignatureType};
use base64;
use {Error, Result};

mod fs;
pub use self::fs::Filesystem;
mod memory;
pub use self::memory::Memory;
mod poly;
pub use self::poly::Polymorphic;
mod test;


#[derive(Serialize,Deserialize,Clone,Debug,Hash,PartialEq,Eq)]
pub struct Fingerprint([u8; 20]);

impl TryFrom<openpgp::Fingerprint> for Fingerprint {
    type Error = Error;

    fn try_from(fpr: openpgp::Fingerprint) -> Result<Self> {
        match fpr {
            openpgp::Fingerprint::V4(a) => Ok(Fingerprint(a)),
            openpgp::Fingerprint::Invalid(_) => Err("invalid fingerprint".into()),
        }
    }
}

impl ToString for Fingerprint {
    fn to_string(&self) -> String {
        base64::encode_config(&self.0[..], base64::URL_SAFE)
    }
}

impl FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Fingerprint> {
        let vec = base64::decode_config(s, base64::URL_SAFE)
            .map_err(|e| format!("'{}' is not a valid fingerprint: {}", s, e))?;
        if vec.len() == 20 {
            let mut arr = [0u8; 20];

            arr.copy_from_slice(&vec[..]);
            Ok(Fingerprint(arr))
        } else {
            Err(format!("'{}' is not a valid fingerprint", s).into())
        }
    }
}

#[derive(Serialize,Deserialize,Clone,Debug)]
pub struct Verify {
    created: i64,
    packets: Box<[u8]>,
    fpr: Fingerprint,
    #[serde(deserialize_with = "Verify::deserialize_userid", serialize_with = "Verify::serialize_userid")]
    uid: UserID,
}

impl Verify {
    pub fn new(uid: &UserID, sig: &[&Signature], fpr: Fingerprint) -> Result<Self> {
        use openpgp::serialize::Serialize;

        let mut cur = Cursor::new(Vec::default());

        let res: Result<()> = uid.serialize(&mut cur)
            .map_err(|e| format!("openpgp: {}", e).into());
        res?;

        for s in sig {
            let res: Result<()> = s.serialize(&mut cur)
                .map_err(|e| format!("openpgp: {}", e).into());
            res?;
        }

        Ok(Verify{
            created: time::now().to_timespec().sec,
            packets: cur.into_inner().into(),
            fpr: fpr,
            uid: uid.clone(),
        })
    }
    fn deserialize_userid<'de, D>(de: D) -> result::Result<UserID, D::Error> where D: Deserializer<'de> {
        de.deserialize_bytes(UserIDVisitor)
    }

    fn serialize_userid<S>(uid: &UserID, ser: S) -> result::Result<S::Ok, S::Error> where S: Serializer {
        ser.serialize_bytes(uid.userid())
    }
}

struct UserIDVisitor;

impl<'de> de::Visitor<'de> for UserIDVisitor {
    type Value = UserID;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a OpenPGP User ID")
    }

    fn visit_bytes<E>(self, s: &[u8]) -> result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        let mut uid = UserID::new();
        uid.set_userid_from_bytes(s);
        Ok(uid)
    }

    fn visit_seq<A>(self, mut seq: A) -> result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>
    {
        let mut buf = Vec::default();

        while let Some(x) = seq.next_element()? {
            buf.push(x);
        }

        let mut uid = UserID::new();
        uid.set_userid_from_bytes(&buf);
        Ok(uid)
    }
}

#[derive(Serialize,Deserialize,Clone,Debug)]
pub struct Delete {
    created: i64,
    fpr: Fingerprint
}

impl Delete {
    pub fn new(fpr: Fingerprint) -> Self {
        Delete{
            created: time::now().to_timespec().sec,
            fpr: fpr
        }
    }
}

// uid -> uidsig+
// subkey -> subkeysig+

pub trait Database: Sync + Send {
    fn new_verify_token(&self, payload: Verify) -> Result<String>;
    fn new_delete_token(&self, payload: Delete) -> Result<String>;

    fn compare_and_swap(&self, fpr: &Fingerprint, present: Option<&[u8]>, new: Option<&[u8]>) -> Result<bool>;

    fn link_userid(&self, uid: &UserID, fpr: &Fingerprint);
    fn unlink_userid(&self, uid: &UserID, fpr: &Fingerprint);

    // (verified uid, fpr)
    fn pop_verify_token(&self, token: &str) -> Option<Verify>;
    // fpr
    fn pop_delete_token(&self, token: &str) -> Option<Delete>;

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<Box<[u8]>>;
    fn by_uid(&self, uid: &str) -> Option<Box<[u8]>>;
    // fn by_kid<'a>(&self, fpr: &str) -> Option<&[u8]>;

    fn strip_userids(tpk: TPK) -> Result<TPK> {
        let pile = tpk.to_packet_pile().into_children().filter(|pkt| {
            match pkt {
                &Packet::PublicKey(_) | &Packet::PublicSubkey(_) => true,
                &Packet::Signature(ref sig) => sig.sigtype() == SignatureType::DirectKey,
                _ => false,
            }
        }).collect::<Vec<_>>();

        TPK::from_packet_pile(PacketPile::from_packets(pile))
            .map_err(|e| format!("openpgp: {}", e).into())
    }

    fn tpk_into_bytes(tpk: &TPK) -> Result<Vec<u8>> {
        use std::io::Cursor;

        let mut cur = Cursor::new(Vec::default());
        tpk.serialize(&mut cur).map(|_| cur.into_inner()).map_err(|e| format!("{}", e).into())
    }

    fn merge_or_publish(&self, mut tpk: TPK) -> Result<Vec<(UserID,String)>> {
        let fpr = Fingerprint::try_from(tpk.primary().fingerprint())?;
        let mut ret = Vec::default();

        // update verify tokens
        for uid in tpk.userids() {
            let enc = base64::encode_config(&format!("{}", uid.userid()), base64::URL_SAFE);
            if self.by_uid(&enc).is_none() {
                let payload = Verify::new(uid.userid(), &uid.selfsigs().collect::<Vec<_>>(), fpr.clone())?;

                // XXX: send mail
                ret.push((uid.userid().clone(),self.new_verify_token(payload)?));
            }
        }

        tpk = Self::strip_userids(tpk)?;

        for _ in 0..100 /* while cas failed */ {
            // merge or update key db
            match self.by_fpr(&fpr).map(|x| x.to_vec()) {
                Some(old) => {
                    let new = TPK::from_bytes(&old).unwrap();
                    let new = new.merge(tpk.clone()).unwrap();
                    let new = Self::tpk_into_bytes(&new)?;

                    if self.compare_and_swap(&fpr, Some(&old), Some(&new))? {
                        return Ok(ret);
                    }
                }

                None => {
                    let fresh = Self::tpk_into_bytes(&tpk)?;

                    if self.compare_and_swap(&fpr, None, Some(&fresh))? {
                        return Ok(ret);
                    }
                }
            }
        }

        error!("Compare-and-swap of {} failed {} times in a row. Aborting.", fpr.to_string(), 100);
        Err("Database update failed".into())
    }

    // if (uid, fpr) = pop-token(tok) {
    //  while cas-failed() {
    //    tpk = by_fpr(fpr)
    //    merged = add-uid(tpk, uid)
    //    cas(tpk, merged)
    //  }
    // }
    fn verify_token(&self, token: &str) -> Result<Option<(UserID, Fingerprint)>> {
        match self.pop_verify_token(token) {
            Some(Verify{ created, packets, fpr, uid }) => {
                let now = time::now().to_timespec().sec;
                if created > now || now - created > 3 * 3600 { return Ok(None); }

                loop /* while cas falied */ {
                    match self.by_fpr(&fpr).map(|x| x.to_vec()) {
                        Some(old) => {
                            let mut new = old.clone();
                            new.extend(packets.into_iter());

                            if self.compare_and_swap(&fpr, Some(&old), Some(&new))? {
                                self.link_userid(&uid, &fpr);
                                return Ok(Some((uid.clone(), fpr.clone())));
                            }
                        }
                        None => {
                            return Ok(None);
                        }
                    }
                }
            }
            None => Err("No such token".into()),
        }
    }

    fn request_deletion(&self, fpr: Fingerprint) -> Result<String> {
        if self.by_fpr(&fpr).is_none() { return Err("Unknown key".into()); }

        let payload = Delete::new(fpr);
        self.new_delete_token(payload)
    }

    // if fpr = pop-token(tok) {
    //  tpk = by_fpr(fpr)
    //  for uid in tpk.userids {
    //    del-uid(uid)
    //  }
    //  del-fpr(fpr)
    // }
    fn confirm_deletion(&self, token: &str) -> Result<bool> {
        match self.pop_delete_token(token) {
            Some(Delete{ created, fpr }) => {
                let now = time::now().to_timespec().sec;
                if created > now || now - created > 3 * 3600 { return Ok(false); }

                loop {
                    match self.by_fpr(&fpr).map(|x| x.to_vec()) {
                        Some(old) => {
                            let tpk = match TPK::from_bytes(&old) {
                                Ok(tpk) => tpk,
                                Err(e) => {
                                    return Err(format!("Failed to parse old TPK: {:?}", e).into());
                                }
                            };

                            for uid in tpk.userids() {
                                self.unlink_userid(uid.userid(), &fpr);
                            }

                            while !self.compare_and_swap(&fpr, Some(&old), None)? {}
                            return Ok(true);
                        }
                        None => {
                            return Ok(false);
                        }
                    }
                }
            }

            None => Ok(false),
        }
    }
}
