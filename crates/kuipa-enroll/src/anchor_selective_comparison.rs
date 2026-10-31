//! Test-only comparison of entry summaries with complete snapshots.

use super::*;
use crate::delegation::DEFAULT_VALIDITY;
use std::time::Instant;
use tang_pqc::{SignatureAlg, SigningKey};

const NOW: u64 = 1_800_000_000;
const REALM: &str = "R";
const MAX_ENTRIES: usize = 10_000;
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
const MAX_ROUNDS: usize = 3;

type Summary = BTreeMap<String, [u8; 32]>;

fn summary(state: &AnchorState) -> (Summary, usize) {
    assert!(state.len() <= MAX_ENTRIES, "summary entry bound exceeded");
    let mut map = Summary::new();
    let mut wire = Writer::new(*b"ISUM");
    wire.u64(state.len() as u64);
    for (id, slot) in state.slots.iter() {
        let tag = [slot.entry.tag()];
        let value = slot.entry.value();
        let digest = primitives::sha256(&[&tag, &value]).expect("summary hash");
        wire.str(id).fixed(&digest);
        map.insert(id.clone(), digest);
    }
    let bytes = wire.finish().len();
    assert!(bytes <= MAX_MESSAGE, "summary byte bound exceeded: {bytes}");
    (map, bytes)
}

fn selection(source: &AnchorState, own: &Summary, peer: &Summary) -> AnchorState {
    let mut selected = AnchorState::default();
    for (id, slot) in source.slots.iter() {
        if peer.get(id) != Some(own.get(id).expect("summary matches snapshot")) {
            selected.slots_mut().insert(id.clone(), slot.clone());
            // A peer can prune a key after summarizing it; carry the key with
            // every selected vouch so admission does not depend on that race.
            if let Entry::Vouch(v) = &slot.entry {
                let key_id = format!("k {}", v.vouch().anchor);
                if let Some(key) = source.slots.get(&key_id) {
                    selected.slots_mut().insert(key_id, key.clone());
                }
            }
        }
    }
    selected
}

fn apply(
    local: &mut AnchorState,
    outgoing: &AnchorState,
    members: &BTreeSet<String>,
    now: u64,
) -> usize {
    let bytes = outgoing.to_bytes();
    assert!(
        bytes.len() <= MAX_MESSAGE,
        "snapshot byte bound exceeded: {}",
        bytes.len()
    );
    let mut inbound = AnchorState::from_bytes(&bytes).expect("decode transfer");
    inbound.admit(local, members, None, REALM, &Policy::default(), now);
    local.merge(&inbound, &GenerationClock::new());
    bytes.len()
}

fn exchange(
    left: &mut AnchorState,
    right: &mut AnchorState,
    members: &BTreeSet<String>,
    selective: bool,
    now: u64,
) -> (usize, usize) {
    let l = left.clone();
    let r = right.clone();
    let (to_left, to_right, summary_bytes) = if selective {
        let (ls, lb) = summary(&l);
        let (rs, rb) = summary(&r);
        (selection(&r, &rs, &ls), selection(&l, &ls, &rs), lb + rb)
    } else {
        (r, l, 0)
    };
    let payload = apply(left, &to_left, members, now) + apply(right, &to_right, members, now);
    (summary_bytes, payload)
}

#[expect(
    clippy::too_many_lines,
    reason = "fixture builds one complete divergent topology"
)]
fn fixture(
    claim_count: usize,
    anchor_count: usize,
) -> (AnchorState, AnchorState, BTreeSet<String>, Vec<SigningKey>) {
    assert!((2..=300).contains(&claim_count), "claims must be 2..=300");
    assert!(
        (2..=claim_count).contains(&anchor_count),
        "anchors must be 2..=claims"
    );
    let keys: Vec<_> = (0..anchor_count)
        .map(|_| SigningKey::generate(SignatureAlg::MlDsa65).expect("generate key"))
        .collect();
    let members: BTreeSet<_> = (0..claim_count).map(|i| format!("server-{i}")).collect();
    let claims: Vec<_> = (0..claim_count)
        .map(|i| Claim {
            realm: REALM.into(),
            server: format!("server-{i}"),
            anchor: keys.get(i).map(|k| *k.public().thumbprint()),
            key: *keys[i % anchor_count].public().thumbprint(),
            iat: NOW - 60,
            exp: NOW + DEFAULT_VALIDITY,
        })
        .collect();
    let leaves: Vec<_> = claims
        .iter()
        .map(|c| {
            c.leaf(TreeHash::for_signer(keys[0].public().alg()))
                .expect("claim leaf")
        })
        .collect();
    let clock = GenerationClock::new();
    let policy = Policy::default();
    let mut base = AnchorState::default();
    for key in &keys {
        base.put(
            Entry::Key(key.public().to_jwk_json()),
            REALM,
            &policy,
            NOW,
            &clock,
        )
        .expect("key");
    }
    for claim in &claims {
        base.put(Entry::Claim(claim.clone()), REALM, &policy, NOW, &clock)
            .expect("claim");
    }
    for key in &keys {
        let v = SignedVouch::issue(
            key,
            REALM,
            leaves.clone(),
            NOW - 60,
            NOW + VOUCH_VALIDITY,
            None,
        )
        .expect("vouch");
        base.put(Entry::Vouch(v), REALM, &policy, NOW, &clock)
            .expect("vouch admission");
    }
    let mut left = base.clone();
    let mut right = base;
    // Distinct content-addressed claims and a missing key/vouch.
    left.slots_mut()
        .remove(&Entry::Claim(claims[0].clone()).id().expect("claim id"));
    right
        .slots_mut()
        .remove(&Entry::Claim(claims[1].clone()).id().expect("claim id"));
    right.slots_mut().remove(
        &Entry::Key(keys[0].public().to_jwk_json())
            .id()
            .expect("key id"),
    );
    right
        .slots_mut()
        .remove(&format!("v {}", keys[0].public().thumbprint()));
    // Both replaceable identities diverge, in opposite directions.
    for (state, index) in [(&mut left, 0), (&mut right, 1)] {
        let v = SignedVouch::issue(
            &keys[index],
            REALM,
            leaves.clone(),
            NOW - 30,
            NOW + VOUCH_VALIDITY,
            None,
        )
        .expect("new vouch");
        state
            .put(Entry::Vouch(v), REALM, &policy, NOW, &clock)
            .expect("replace vouch");
    }
    let old = SignedSuccession::issue(
        &keys[0],
        REALM,
        keys[1].public().thumbprint(),
        NOW - 50,
        NOW + VOUCH_VALIDITY,
    )
    .expect("old succession");
    let new = SignedSuccession::issue(
        &keys[0],
        REALM,
        keys[1].public().thumbprint(),
        NOW - 20,
        NOW + VOUCH_VALIDITY,
    )
    .expect("new succession");
    left.put(Entry::Succession(old), REALM, &policy, NOW, &clock)
        .expect("old succession admission");
    right
        .put(Entry::Succession(new), REALM, &policy, NOW, &clock)
        .expect("new succession admission");
    (left, right, members, keys)
}

#[expect(
    clippy::too_many_lines,
    reason = "comparison follows one state through the complete repair scenario"
)]
fn comparison(claims: usize, anchors: usize) {
    let (left, right, members, keys) = fixture(claims, anchors);
    let mut full_l = left.clone();
    let mut full_r = right.clone();
    let started = Instant::now();
    let encoded_left = left.to_bytes();
    let encoded_right = right.to_bytes();
    let snapshot_encode_us = started.elapsed().as_micros();
    let started = Instant::now();
    std::hint::black_box(
        primitives::sha256(&[b"ipa-ku/anchor-state/v1\0", &encoded_left])
            .expect("left snapshot digest"),
    );
    std::hint::black_box(
        primitives::sha256(&[b"ipa-ku/anchor-state/v1\0", &encoded_right])
            .expect("right snapshot digest"),
    );
    let snapshot_hash_us = started.elapsed().as_micros();
    let started = Instant::now();
    let (left_summary, _) = summary(&left);
    let (right_summary, _) = summary(&right);
    let summary_us = started.elapsed().as_micros();
    let started = Instant::now();
    let _ = selection(&left, &left_summary, &right_summary);
    let _ = selection(&right, &right_summary, &left_summary);
    let selection_us = started.elapsed().as_micros();
    let mut selective_l = left;
    let mut selective_r = right;
    let started = Instant::now();
    let (_, full_bytes) = exchange(&mut full_l, &mut full_r, &members, false, NOW);
    let full_us = started.elapsed().as_micros();
    let started = Instant::now();
    let (summary_bytes, selective_bytes) =
        exchange(&mut selective_l, &mut selective_r, &members, true, NOW);
    let selective_us = started.elapsed().as_micros();
    assert_eq!(full_l, full_r, "full snapshots converge");
    assert_eq!(selective_l, full_l, "selective left matches full state");
    assert_eq!(selective_r, full_r, "selective right matches full state");

    // A stale summary cannot prove the peer still has a prerequisite key.
    let (stale, _) = summary(&selective_r);
    let key_id = Entry::Key(keys[0].public().to_jwk_json())
        .id()
        .expect("key id");
    selective_r.slots_mut().remove(&key_id);
    let live = selective_l
        .vouch(keys[0].public().thumbprint())
        .expect("existing vouch")
        .live()
        .to_vec();
    let fresh = SignedVouch::issue(&keys[0], REALM, live, NOW - 10, NOW + VOUCH_VALIDITY, None)
        .expect("concurrent vouch");
    selective_l
        .put(
            Entry::Vouch(fresh),
            REALM,
            &Policy::default(),
            NOW,
            &GenerationClock::new(),
        )
        .expect("concurrent update");
    let selected = selection(&selective_l, &summary(&selective_l).0, &stale);
    assert!(
        selected.slots.contains_key(&key_id),
        "vouch includes prerequisite key"
    );
    apply(&mut selective_r, &selected, &members, NOW);
    assert_eq!(
        selective_l, selective_r,
        "stale summary transfer preserves admission"
    );

    // Updates after a snapshot are recovered by a later bounded repair round.
    let old_l = selective_l.clone();
    let (old_summary, _) = summary(&selective_r);
    let newer = SignedSuccession::issue(
        &keys[0],
        REALM,
        keys[1].public().thumbprint(),
        NOW - 5,
        NOW + VOUCH_VALIDITY,
    )
    .expect("concurrent succession");
    selective_l
        .put(
            Entry::Succession(newer),
            REALM,
            &Policy::default(),
            NOW,
            &GenerationClock::new(),
        )
        .expect("concurrent succession admission");
    apply(
        &mut selective_r,
        &selection(&old_l, &summary(&old_l).0, &old_summary),
        &members,
        NOW,
    );
    assert_ne!(
        selective_l, selective_r,
        "in-flight update is not acknowledged by old snapshot"
    );
    for _ in 0..MAX_ROUNDS {
        exchange(&mut selective_l, &mut selective_r, &members, true, NOW);
        if selective_l == selective_r {
            break;
        }
    }
    assert_eq!(
        selective_l, selective_r,
        "bounded repair converges after concurrent update"
    );

    // Equal timestamps use serialized content, not arrival order.
    let leaves = selective_l
        .vouch(keys[0].public().thumbprint())
        .expect("vouch")
        .live()
        .to_vec();
    let v1 = SignedVouch::issue(
        &keys[0],
        REALM,
        leaves.clone(),
        NOW - 1,
        NOW + VOUCH_VALIDITY,
        None,
    )
    .expect("tie vouch");
    let v2 = SignedVouch::issue(
        &keys[0],
        REALM,
        leaves[..1].iter().copied(),
        NOW - 1,
        NOW + VOUCH_VALIDITY,
        None,
    )
    .expect("tie vouch");
    let expected_vouch = std::cmp::max(v1.to_bytes(), v2.to_bytes());
    let other = SigningKey::generate(SignatureAlg::MlDsa65).expect("alternate succession target");
    let s1 = SignedSuccession::issue(
        &keys[0],
        REALM,
        keys[1].public().thumbprint(),
        NOW - 1,
        NOW + VOUCH_VALIDITY,
    )
    .expect("tie succession");
    let s2 = SignedSuccession::issue(
        &keys[0],
        REALM,
        other.public().thumbprint(),
        NOW - 1,
        NOW + VOUCH_VALIDITY,
    )
    .expect("tie succession");
    let expected_succession = std::cmp::max(
        s1.to_bytes().expect("encode succession"),
        s2.to_bytes().expect("encode succession"),
    );
    for (state, v, s) in [(&mut selective_l, v1, s1), (&mut selective_r, v2, s2)] {
        state
            .put(
                Entry::Vouch(v),
                REALM,
                &Policy::default(),
                NOW,
                &GenerationClock::new(),
            )
            .expect("tie vouch admission");
        state
            .put(
                Entry::Succession(s),
                REALM,
                &Policy::default(),
                NOW,
                &GenerationClock::new(),
            )
            .expect("tie succession admission");
    }
    let mut tie_full_l = selective_l.clone();
    let mut tie_full_r = selective_r.clone();
    exchange(&mut tie_full_l, &mut tie_full_r, &members, false, NOW);
    exchange(&mut selective_l, &mut selective_r, &members, true, NOW);
    assert_eq!(
        selective_l, tie_full_l,
        "tie comparison matches full snapshot"
    );
    assert_eq!(selective_r, tie_full_r, "tie comparison converges");
    assert_eq!(
        selective_l
            .vouch(keys[0].public().thumbprint())
            .expect("winning vouch")
            .to_bytes(),
        expected_vouch
    );
    assert_eq!(
        selective_l
            .successions()
            .next()
            .expect("winning succession")
            .to_bytes()
            .expect("encode winner"),
        expected_succession
    );

    let expired = NOW + VOUCH_VALIDITY + crate::delegation::CLOCK_SKEW + 1;
    selective_l.retain(&members, REALM, &Policy::default(), expired);
    selective_r.retain(&members, REALM, &Policy::default(), expired);
    assert_eq!(
        selective_l, selective_r,
        "pruning produces equal final states"
    );
    // Expired old values must not be resurrected by an in-flight snapshot.
    let before = selective_r.clone();
    apply(&mut selective_r, &old_l, &members, expired);
    selective_r.retain(&members, REALM, &Policy::default(), expired);
    assert_eq!(
        selective_r, before,
        "expired snapshot cannot resurrect pruned entries"
    );

    println!(
        "{}",
        serde_json::json!({
            "experiment": "anchor-entry-summary-v1", "claims": claims, "anchors": anchors,
            "time": NOW, "hash": "sha256(tag || entry value)", "rounds": 1,
            "full_snapshot_bytes": full_bytes, "summary_bytes": summary_bytes,
            "selective_state_bytes": selective_bytes, "selective_total_bytes": summary_bytes + selective_bytes,
            "summary_us": summary_us, "selection_us": selection_us,
            "snapshot_encode_us": snapshot_encode_us, "snapshot_hash_us": snapshot_hash_us,
            "full_elapsed_us": full_us, "selective_elapsed_us": selective_us,
            "max_entries": MAX_ENTRIES, "max_message_bytes": MAX_MESSAGE, "repair_round_limit": MAX_ROUNDS
        })
    );
}

#[test]
fn runtime_selection_handles_replacements_stale_keys_loss_and_expiry() {
    let (mut left, mut right, members, keys) = fixture(4, 2);
    let mut full_left = left.clone();
    let mut full_right = right.clone();
    exchange(&mut full_left, &mut full_right, &members, false, NOW);

    let left_summary = left.entry_summary().unwrap().clone();
    let right_summary = right.entry_summary().unwrap().clone();
    let to_left = right.select_entries(&left_summary).unwrap();
    let to_right = left.select_entries(&right_summary).unwrap();
    // A lost transfer changes nothing and the next exchange repairs it.
    apply(&mut left, &to_left, &members, NOW);
    assert_ne!(left, right);
    apply(&mut right, &to_right, &members, NOW);
    assert_eq!(left, full_left);
    assert_eq!(right, full_right);

    let stale = right.entry_summary().unwrap().clone();
    let key_id = Entry::Key(keys[0].public().to_jwk_json()).id().unwrap();
    right.slots_mut().remove(&key_id);
    let leaves = left
        .vouch(keys[0].public().thumbprint())
        .unwrap()
        .live()
        .to_vec();
    let newer =
        SignedVouch::issue(&keys[0], REALM, leaves, NOW - 1, NOW + VOUCH_VALIDITY, None).unwrap();
    left.put(
        Entry::Vouch(newer),
        REALM,
        &Policy::default(),
        NOW,
        &GenerationClock::new(),
    )
    .unwrap();
    let selected = left.select_entries(&stale).unwrap();
    assert!(
        selected.slots.contains_key(&key_id),
        "vouch carries its missing prerequisite"
    );
    apply(&mut right, &selected, &members, NOW);
    assert_eq!(left, right, "stale summary must not block vouch admission");

    let old = left.clone();
    let newer = SignedSuccession::issue(
        &keys[0],
        REALM,
        keys[1].public().thumbprint(),
        NOW - 1,
        NOW + VOUCH_VALIDITY,
    )
    .unwrap();
    left.put(
        Entry::Succession(newer),
        REALM,
        &Policy::default(),
        NOW,
        &GenerationClock::new(),
    )
    .unwrap();
    let selected = old
        .select_entries(&right.entry_summary().unwrap().clone())
        .unwrap();
    apply(&mut right, &selected, &members, NOW);
    assert_ne!(
        left, right,
        "an old snapshot cannot acknowledge a later mutation"
    );
    let selected = left
        .select_entries(&right.entry_summary().unwrap().clone())
        .unwrap();
    apply(&mut right, &selected, &members, NOW);
    assert_eq!(left, right);

    let expired = NOW + VOUCH_VALIDITY + crate::delegation::CLOCK_SKEW + 1;
    right.retain(&members, REALM, &Policy::default(), expired);
    let before = right.clone();
    let selected = old
        .select_entries(&right.entry_summary().unwrap().clone())
        .unwrap();
    apply(&mut right, &selected, &members, expired);
    right.retain(&members, REALM, &Policy::default(), expired);
    assert_eq!(right, before, "expired entries cannot be revived");
}

#[test]
fn selective_comparison_correctness() {
    comparison(4, 2);
}

#[test]
fn selection_skips_entries_the_peer_would_not_take() {
    // Right holds a newer vouch by keys[1] than left (fixture).
    let (left, right, _, keys) = fixture(4, 2);
    let name = format!("v {}", keys[1].public().thumbprint());
    let id = entry_id(&name).unwrap();
    let (ls, rs) = (
        left.entry_summary().unwrap(),
        right.entry_summary().unwrap(),
    );
    assert!(ls[&id].order < rs[&id].order);
    assert!(
        !left.select_entries(rs).unwrap().slots.contains_key(&name),
        "an older vouch is not sent"
    );
    assert!(
        right.select_entries(ls).unwrap().slots.contains_key(&name),
        "a newer vouch is sent"
    );
    assert!(
        !right.wanted(ls).unwrap().contains(&id),
        "an older vouch is not wanted"
    );
    assert!(
        left.wanted(rs).unwrap().contains(&id),
        "a newer vouch is wanted"
    );
    // Wanted ids are exactly what the peer's selection would choose.
    let chosen: BTreeSet<EntryId> = left
        .select_entries(rs)
        .unwrap()
        .slots
        .keys()
        .map(|k| entry_id(k).unwrap())
        .collect();
    assert!(right.wanted(ls).unwrap().is_subset(&chosen));
}

#[test]
fn buckets_differ_exactly_where_entries_differ() {
    let (left, right, _, _) = fixture(60, 6);
    let (ls, rs) = (
        left.entry_summary().unwrap(),
        right.entry_summary().unwrap(),
    );
    for bits in [0, 3, MAX_BUCKET_BITS] {
        let differing: BTreeSet<usize> = left
            .bucket_hashes(bits)
            .unwrap()
            .iter()
            .zip(right.bucket_hashes(bits).unwrap())
            .enumerate()
            .filter(|(_, (l, r))| *l != r)
            .map(|(i, _)| i)
            .collect();
        let expected: BTreeSet<usize> = ls
            .keys()
            .chain(rs.keys())
            .filter(|id| ls.get(*id) != rs.get(*id))
            .map(|id| bucket_of(id, bits))
            .collect();
        assert_eq!(differing, expected, "bits {bits}");
        // Selecting within the differing buckets reaches the full selection.
        let theirs = right.bucket_summary(bits, &differing).unwrap();
        let scoped = left
            .select_entries_where(&theirs, |id| differing.contains(&bucket_of(id, bits)))
            .unwrap();
        assert_eq!(scoped, left.select_entries(rs).unwrap(), "bits {bits}");
        assert_eq!(
            right
                .wanted(&left.bucket_summary(bits, &differing).unwrap())
                .unwrap(),
            right.wanted(ls).unwrap()
        );
    }
}

#[test]
#[ignore = "comparison benchmark"]
fn measure_selective_comparison() {
    for (claims, anchors) in [(60, 6), (60, 60), (100, 6), (200, 6), (300, 6), (300, 300)] {
        comparison(claims, anchors);
    }
}
