use super::*;

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = u8::try_from(self.next() & 0xFF).unwrap();
        }
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next()).unwrap() % n
    }
    fn distinct(&mut self, count: usize, n: usize) -> Vec<usize> {
        let mut places = Vec::new();
        while places.len() < count {
            let p = self.below(n);
            if !places.contains(&p) {
                places.push(p);
            }
        }
        places
    }
}

const SEED: [u8; 32] = *b"0123456789abcdef0123456789ABCDEF";
const SALT: [u8; 16] = *b"sixteen byte sal";

fn set(rng: &mut Lcg, threshold: u8, shares: u8, parity: u8) -> Vec<Share> {
    make_shares_with(
        &SEED,
        SALT,
        SetParams {
            threshold,
            shares,
            iterations: DEFAULT_ITERATIONS,
            parity,
            kem_1024: false,
        },
        &mut |b| {
            rng.fill(b);
            Ok(())
        },
    )
    .unwrap()
}

#[test]
fn any_threshold_of_the_shares_give_the_secret_back_and_fewer_do_not() {
    let mut rng = Lcg(5);
    let shares = set(&mut rng, 3, 5, DEFAULT_PARITY);
    for picks in [[0, 1, 2], [4, 2, 0], [1, 3, 4], [2, 3, 4]] {
        let chosen: Vec<Share> = picks.iter().map(|&i| shares[i].clone()).collect();
        let combined = combine(&chosen).unwrap();
        assert_eq!(combined.hidden, SEED);
        assert_eq!(combined.salt, SALT);
        assert_eq!(combined.set_id, shares[0].header.set_id);
    }
    assert_eq!(
        combine(&shares[..2]),
        Err(Error::NotEnough { have: 2, need: 3 })
    );
    // the same share twice is one share
    let twice = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
    assert_eq!(combine(&twice), Err(Error::NotEnough { have: 2, need: 3 }));
    // two shares of three give something that is not the secret
    let wrong = interpolate(&[(1, &shares[0].secret), (2, &shares[1].secret)]);
    assert_ne!(wrong, SEED);
}

#[test]
fn shares_of_two_sets_or_with_other_parameters_are_not_mixed() {
    let mut rng = Lcg(6);
    let a = set(&mut rng, 2, 3, DEFAULT_PARITY);
    let b = set(&mut rng, 2, 3, DEFAULT_PARITY);
    assert!(matches!(
        combine(&[a[0].clone(), b[1].clone()]),
        Err(Error::Mixed(_))
    ));
    let mut odd = a[1].clone();
    odd.salt[0] ^= 1;
    assert!(matches!(
        combine(&[a[0].clone(), odd]),
        Err(Error::Mixed(_))
    ));
    let mut other_kem = a[1].clone();
    other_kem.header.kem_1024 = true;
    assert!(matches!(
        combine(&[a[0].clone(), other_kem]),
        Err(Error::Mixed(_))
    ));
}

#[test]
fn parameters_outside_what_a_share_can_say_are_refused() {
    let mut rng = Lcg(1);
    let mut try_with = |t, m, it, p| {
        make_shares_with(
            &SEED,
            SALT,
            SetParams {
                threshold: t,
                shares: m,
                iterations: it,
                parity: p,
                kem_1024: false,
            },
            &mut |b| {
                rng.fill(b);
                Ok(())
            },
        )
    };
    assert!(try_with(1, 3, 20, 24).is_err());
    assert!(try_with(4, 3, 20, 24).is_err());
    assert!(try_with(2, 17, 20, 24).is_err());
    assert!(try_with(2, 3, 0, 24).is_err());
    assert!(try_with(2, 3, 64, 24).is_err());
    assert!(try_with(2, 3, 20, 3).is_err());
    assert!(try_with(2, 3, 20, 201).is_err());
    assert!(try_with(16, 16, 63, 200).is_ok());
}

#[test]
fn a_share_is_68_words_by_default_and_reads_back_from_them() {
    let mut rng = Lcg(2);
    for share in set(&mut rng, 3, 5, DEFAULT_PARITY) {
        let words = share.symbols();
        assert_eq!(words.len(), 68);
        let (back, repair) =
            Share::from_symbols(&words.iter().map(|&w| Some(w)).collect::<Vec<_>>()).unwrap();
        assert_eq!(back, share);
        assert_eq!(repair, Repair::default());
    }
}

#[test]
fn a_damaged_share_is_repaired_up_to_what_the_check_words_allow() {
    let mut rng = Lcg(9);
    let shares = set(&mut rng, 3, 5, DEFAULT_PARITY);
    let share = &shares[1];
    let words = share.symbols();
    // 24 of 68 words unreadable
    let mut seen: Vec<Option<u16>> = words.iter().map(|&w| Some(w)).collect();
    for p in rng.distinct(24, 68) {
        seen[p] = None;
    }
    assert_eq!(Share::from_symbols(&seen).unwrap().0, *share);
    // 12 words wrong without knowing which
    let mut seen: Vec<Option<u16>> = words.iter().map(|&w| Some(w)).collect();
    for p in rng.distinct(12, 68) {
        seen[p] = Some(seen[p].unwrap() ^ u16::try_from(1 + rng.below(1023)).unwrap());
    }
    let (back, repair) = Share::from_symbols(&seen).unwrap();
    assert_eq!(back, *share);
    assert_eq!(repair.wrong, 12);
    // 10 lost and 7 wrong: 10 + 14 <= 24
    let mut seen: Vec<Option<u16>> = words.iter().map(|&w| Some(w)).collect();
    let places = rng.distinct(17, 68);
    for &p in &places[..10] {
        seen[p] = None;
    }
    for &p in &places[10..] {
        seen[p] = Some(seen[p].unwrap() ^ 0x155);
    }
    assert_eq!(Share::from_symbols(&seen).unwrap().0, *share);
    // 25 lost: one too many
    let mut seen: Vec<Option<u16>> = words.iter().map(|&w| Some(w)).collect();
    for p in rng.distinct(25, 68) {
        seen[p] = None;
    }
    assert_eq!(Share::from_symbols(&seen), Err(Error::Unreadable));
}

#[test]
fn a_share_with_more_check_words_survives_more_damage() {
    let mut rng = Lcg(10);
    let shares = set(&mut rng, 2, 3, 100);
    let words = shares[0].symbols();
    assert_eq!(words.len(), DATA_WORDS + 100);
    let mut seen: Vec<Option<u16>> = words.iter().map(|&w| Some(w)).collect();
    for p in rng.distinct(100, words.len()) {
        seen[p] = None;
    }
    assert_eq!(Share::from_symbols(&seen).unwrap().0, shares[0]);
}

#[test]
fn what_is_not_a_share_is_told_from_damage() {
    let mut rng = Lcg(12);
    let words = set(&mut rng, 2, 3, DEFAULT_PARITY)[0].symbols();
    let some = |w: &[u16]| w.iter().map(|&x| Some(x)).collect::<Vec<_>>();
    assert!(matches!(
        Share::from_symbols(&some(&words[..40])),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        Share::from_symbols(&some(&words[..words.len() - 1])),
        Err(Error::Malformed(_) | Error::Unreadable)
    ));
    // a valid codeword of the right length that is not a share: the header's check-word count lies
    let mut other = some(&words);
    other.push(None);
    assert!(Share::from_symbols(&other).is_err());
}

#[test]
fn the_whole_way_a_passphrase_then_shares_then_the_seed_back() {
    let mut rng = Lcg(21);
    let passphrase = "correct horse battery staple extra";
    let hidden = mask(&SEED, passphrase, &SALT, 1).unwrap();
    assert_ne!(hidden, SEED);
    let shares = make_shares_with(
        &hidden,
        SALT,
        SetParams {
            iterations: 1,
            ..SetParams::new(3, 5, true)
        },
        &mut |b| {
            rng.fill(b);
            Ok(())
        },
    )
    .unwrap();

    // three shares, each damaged, typed back as lines
    let mut read = Vec::new();
    for share in [&shares[4], &shares[0], &shares[2]] {
        let mut words: Vec<Option<u16>> = share.symbols().into_iter().map(Some).collect();
        for p in rng.distinct(15, words.len()) {
            words[p] = None;
        }
        let typed: Vec<String> =
            format_lines(&words.iter().map(|w| w.unwrap_or(0)).collect::<Vec<_>>())
                .into_iter()
                .map(|line| {
                    // blank out the lost words in the line
                    let (number, rest) = line.split_once("  ").unwrap();
                    let line_no: usize = number.parse().unwrap();
                    let shown: Vec<&str> = rest
                        .split(' ')
                        .enumerate()
                        .map(|(k, w)| {
                            if words[(line_no - 1) * WORDS_PER_LINE + k].is_none() {
                                "?"
                            } else {
                                w
                            }
                        })
                        .collect();
                    format!("{number}  {}", shown.join(" "))
                })
                .collect();
        let symbols = parse_lines(&typed.join("\n"), words.len());
        assert_eq!(symbols, words);
        read.push(Share::from_symbols(&symbols).unwrap().0);
    }
    let combined = combine(&read).unwrap();
    assert_eq!(
        mask(
            &combined.hidden,
            passphrase,
            &combined.salt,
            combined.iterations
        )
        .unwrap(),
        SEED
    );
    assert_ne!(
        mask(
            &combined.hidden,
            "a different long passphrase",
            &combined.salt,
            combined.iterations
        )
        .unwrap(),
        SEED
    );
    // and the seed, with the KEM the header names, is the key whose id the page checks
    let made = recovery_key(
        &mask(
            &combined.hidden,
            passphrase,
            &combined.salt,
            combined.iterations,
        )
        .unwrap(),
        combined.kem_1024,
    )
    .unwrap();
    assert_eq!(
        made.public().kid(),
        recovery_key(&SEED, true).unwrap().public().kid()
    );
    assert_ne!(
        made.public().kid(),
        recovery_key(&SEED, false).unwrap().public().kid()
    );
}

#[test]
fn passphrases_are_normalized_so_that_they_type_the_same() {
    // "é" as one character and as e + combining acute, and a full-width letter
    let composed = mask(&SEED, "caf\u{e9} au lait, please!", &SALT, 1).unwrap();
    let decomposed = mask(&SEED, "cafe\u{301} au lait, please!", &SALT, 1).unwrap();
    assert_eq!(composed, decomposed);
    assert_eq!(
        mask(&SEED, "\u{ff21}", &SALT, 1).unwrap(),
        mask(&SEED, "A", &SALT, 1).unwrap()
    );
}

#[test]
fn lines_are_read_by_their_numbers_and_unknown_words_are_lost() {
    let text = "01  academic ? always aluminum\n03  zero yoga\n\n  05 academic";
    let symbols = parse_lines(text, 25);
    let first = lookup("academic").unwrap();
    assert_eq!(symbols[0], Some(first));
    assert_eq!(symbols[1], None);
    assert_eq!(symbols[2], lookup("always"));
    assert_eq!(symbols[4], None); // line 1 has only four words
    assert_eq!(symbols[5..10], [None; 5]); // line 2 is missing
    assert_eq!(symbols[10], lookup("zero"));
    assert_eq!(symbols[20], Some(first));
}

/// The words of one share, fixed so that the format cannot drift: an independent implementation of
/// the format as `docs/DESIGN-recovery.md` §2.1 and the module documentation describe it (the AES-free
/// field `x^10 + x^3 + 1`, check words from the generator with roots `alpha^1..alpha^24`, ten bits per
/// word, most significant first) produced the same 68 symbols.
#[test]
fn a_share_has_these_words_for_these_parameters() {
    let share = Share {
        header: Header {
            set_id: 0x1_F3A1,
            kem_1024: true,
            threshold: 3,
            shares: 5,
            index: 2,
            iterations: 20,
            parity: 24,
        },
        salt: SALT,
        secret: SEED,
    };
    let expected: [u16; 68] = [
        79, 628, 201, 21, 24, 461, 663, 541, 101, 405, 738, 24, 633, 465, 594, 28, 865, 432, 192,
        787, 140, 820, 212, 867, 462, 57, 389, 550, 217, 101, 408, 771, 76, 563, 208, 851, 397,
        824, 229, 20, 144, 836, 277, 96, 94, 440, 747, 466, 455, 976, 237, 173, 951, 824, 316, 517,
        429, 712, 71, 985, 351, 899, 709, 309, 181, 881, 226, 837,
    ];
    assert_eq!(share.symbols(), expected);
}

/// The key a seed makes, fixed so the label and the hash cannot drift: an independent
/// implementation of the labelled HKDF (Extract-Expand with the label as salt and `label ‖
/// " seed"` as info, SHA-256 for ML-KEM-768 and SHA-384 for ML-KEM-1024) produced the same
/// 64 bytes, which is what the private JWK carries as `priv`.
#[test]
fn a_seed_makes_this_key_for_each_kem() {
    for (kem_1024, expected) in [
        (
            false,
            "oH38v8DHgrwhol2UA808M0GRbGHpdXI0BKPviWGRroq5pnJ2cYItxYtWV0_NghWNx21T6jx5Nd06WpDJIXjtrw",
        ),
        (
            true,
            "VgAP8VBp5am-M8lTFAgAUIUjBk-eeAauzd1HjYNYI1P828uLZbsS3PHJPSNvHF-E_PpG0Fz1dULDlXVEm99gGQ",
        ),
    ] {
        let key = recovery_key(&SEED, kem_1024).unwrap();
        assert_eq!(
            key.public().alg().jose_name(),
            if kem_1024 {
                "ML-KEM-1024"
            } else {
                "ML-KEM-768"
            }
        );
        let jwk: serde_json::Value =
            serde_json::from_slice(key.to_jwk().unwrap().as_ref()).unwrap();
        assert_eq!(jwk["priv"].as_str().unwrap(), expected);
    }
}
