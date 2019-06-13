use failure::Fallible as Result;

use openpgp::{
    TPK,
    RevocationStatus,
    armor::{Writer, Kind},
    packet::{UserID, Tag},
    serialize::Serialize as OpenPgpSerialize,
};

pub fn is_status_revoked(status: RevocationStatus) -> bool {
    match status {
        RevocationStatus::Revoked(_) => true,
        RevocationStatus::CouldBe(_) => false,
        RevocationStatus::NotAsFarAsWeKnow => false,
    }
}

pub fn tpk_to_string(tpk: &TPK) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut armor_writer = Writer::new(&mut buf, Kind::PublicKey, &[][..])?;
        tpk.serialize(&mut armor_writer)?;
    }
    Ok(buf)
}

pub fn tpk_clean(tpk: &TPK) -> Result<TPK> {
    // Iterate over the TPK, pushing packets we want to merge
    // into the accumulator.
    let mut acc = Vec::new();

    // The primary key and related signatures.
    acc.push(tpk.primary().clone().into_packet(Tag::PublicKey)?);
    for s in tpk.selfsigs()          { acc.push(s.clone().into()) }
    for s in tpk.self_revocations()  { acc.push(s.clone().into()) }
    for s in tpk.other_revocations() { acc.push(s.clone().into()) }

    // The subkeys and related signatures.
    for skb in tpk.subkeys() {
        acc.push(skb.subkey().clone().into_packet(Tag::PublicSubkey)?);
        for s in skb.selfsigs()          { acc.push(s.clone().into()) }
        for s in skb.self_revocations()  { acc.push(s.clone().into()) }
        for s in skb.other_revocations() { acc.push(s.clone().into()) }
    }

    // Updates for UserIDs fulfilling `filter`.
    for uidb in tpk.userids() {
        acc.push(uidb.userid().clone().into());
        for s in uidb.selfsigs()          { acc.push(s.clone().into()) }
        for s in uidb.self_revocations()  { acc.push(s.clone().into()) }
        for s in uidb.other_revocations() { acc.push(s.clone().into()) }
    }

    TPK::from_packet_pile(acc.into())
}

/// Filters the TPK, keeping only those UserIDs that fulfill the
/// predicate `filter`.
pub fn tpk_filter_userids<F>(tpk: &TPK, filter: F) -> Result<TPK>
    where F: Fn(&UserID) -> bool
{
    // Iterate over the TPK, pushing packets we want to merge
    // into the accumulator.
    let mut acc = Vec::new();

    // The primary key and related signatures.
    acc.push(tpk.primary().clone().into_packet(Tag::PublicKey)?);
    for s in tpk.selfsigs()          { acc.push(s.clone().into()) }
    for s in tpk.certifications()    { acc.push(s.clone().into()) }
    for s in tpk.self_revocations()  { acc.push(s.clone().into()) }
    for s in tpk.other_revocations() { acc.push(s.clone().into()) }

    // The subkeys and related signatures.
    for skb in tpk.subkeys() {
        acc.push(skb.subkey().clone().into_packet(Tag::PublicSubkey)?);
        for s in skb.selfsigs()          { acc.push(s.clone().into()) }
        for s in skb.certifications()    { acc.push(s.clone().into()) }
        for s in skb.self_revocations()  { acc.push(s.clone().into()) }
        for s in skb.other_revocations() { acc.push(s.clone().into()) }
    }

    // Updates for UserIDs fulfilling `filter`.
    for uidb in tpk.userids() {
        // Only include userids matching filter
        if filter(uidb.userid()) {
            acc.push(uidb.userid().clone().into());
            for s in uidb.selfsigs()          { acc.push(s.clone().into()) }
            for s in uidb.certifications()    { acc.push(s.clone().into()) }
            for s in uidb.self_revocations()  { acc.push(s.clone().into()) }
            for s in uidb.other_revocations() { acc.push(s.clone().into()) }
        }
    }

    TPK::from_packet_pile(acc.into())
}
