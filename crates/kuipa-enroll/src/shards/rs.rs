//! A Reed-Solomon code over GF(2^10), so that one symbol is one word of a recovery shard.
//!
//! Systematic and narrow-sense: a codeword is the data symbols followed by `parity` check symbols,
//! read as the polynomial `c(x) = c[0] x^(n-1) + ... + c[n-1]`, and the generator has the roots
//! `alpha^1 .. alpha^parity`. The decoder fills in **erasures** (symbols known to be lost) and
//! corrects **errors** (symbols wrong at unknown places): `erasures + 2 * errors <= parity`.

use super::gf::Gf1024;

/// The longest codeword the field allows.
pub(crate) const MAX_LEN: usize = 1023;

/// Why a codeword could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// More erasures than check symbols, or a length the field cannot carry.
    TooDamaged,
    /// The damage is beyond what the check symbols correct (or looks like it).
    Uncorrectable,
}

/// What decoding repaired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Repair {
    /// Symbols that were marked as lost.
    pub erased: usize,
    /// Symbols that were wrong without being marked.
    pub wrong: usize,
}

/// Coefficients (lowest power first) of `(x + alpha^1)(x + alpha^2)...(x + alpha^parity)`.
fn generator(parity: usize) -> Vec<u16> {
    let mut g = vec![1u16];
    for j in 1..=parity {
        let root = Gf1024::alpha(j);
        let mut next = vec![0u16; g.len() + 1];
        for (k, &c) in g.iter().enumerate() {
            next[k + 1] ^= c;
            next[k] ^= Gf1024::mul(c, root);
        }
        g = next;
    }
    g
}

/// The `parity` check symbols for `data`, in codeword order (highest power first).
pub(crate) fn parity_of(data: &[u16], parity: usize) -> Vec<u16> {
    let g = generator(parity);
    let mut rem = vec![0u16; parity];
    for &d in data {
        let feedback = d ^ rem[parity - 1];
        for k in (1..parity).rev() {
            rem[k] = rem[k - 1] ^ Gf1024::mul(feedback, g[k]);
        }
        rem[0] = Gf1024::mul(feedback, g[0]);
    }
    rem.reverse();
    rem
}

/// `c(alpha^j)` for `j = 1..=parity`.
fn syndromes(word: &[u16], parity: usize) -> Vec<u16> {
    (1..=parity)
        .map(|j| {
            let x = Gf1024::alpha(j);
            word.iter().fold(0u16, |acc, &c| Gf1024::mul(acc, x) ^ c)
        })
        .collect()
}

fn poly_mul(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut out = vec![0u16; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            out[i + j] ^= Gf1024::mul(x, y);
        }
    }
    out
}

fn poly_eval(poly: &[u16], x: u16) -> u16 {
    poly.iter()
        .rev()
        .fold(0u16, |acc, &c| Gf1024::mul(acc, x) ^ c)
}

/// Repairs `word` in place. `erased` lists the positions known to be lost (their contents are
/// ignored).
pub(crate) fn decode(
    word: &mut [u16],
    erased: &[usize],
    parity: usize,
) -> Result<Repair, DecodeError> {
    let len = word.len();
    if len > MAX_LEN
        || parity == 0
        || parity >= len
        || erased.len() > parity
        || erased.iter().any(|&p| p >= len)
    {
        return Err(DecodeError::TooDamaged);
    }
    let mut erased: Vec<usize> = erased.to_vec();
    erased.sort_unstable();
    erased.dedup();
    for &place in &erased {
        word[place] = 0;
    }

    let syndrome = syndromes(word, parity);
    if syndrome.iter().all(|&v| v == 0) {
        return Ok(Repair {
            erased: erased.len(),
            wrong: 0,
        });
    }

    // The erasure locator, the product of (1 + X x) for each lost place, X = alpha^(len-1-place).
    let mut erasure_locator = vec![1u16];
    for &place in &erased {
        erasure_locator = poly_mul(&erasure_locator, &[1, Gf1024::alpha(len - 1 - place)]);
    }
    let lost = erased.len();

    // The Forney syndromes: the coefficients of S(x) * Gamma(x) from `lost` on describe the errors
    // alone, because the erasures' terms cancel.
    let mut product = poly_mul(&syndrome, &erasure_locator);
    product.resize(parity.max(product.len()), 0);
    let forney = &product[lost..parity];

    // Berlekamp-Massey over the Forney syndromes: the error locator.
    let (mut locator, mut previous) = (vec![1u16], vec![1u16]);
    let (mut degree, mut gap, mut previous_discrepancy) = (0usize, 1usize, 1u16);
    for (i, &next) in forney.iter().enumerate() {
        let mut discrepancy = next;
        for k in 1..=degree.min(locator.len() - 1) {
            discrepancy ^= Gf1024::mul(locator[k], forney[i - k]);
        }
        if discrepancy == 0 {
            gap += 1;
            continue;
        }
        let scale = Gf1024::div(discrepancy, previous_discrepancy);
        let snapshot = locator.clone();
        if locator.len() < previous.len() + gap {
            locator.resize(previous.len() + gap, 0);
        }
        for (k, &coefficient) in previous.iter().enumerate() {
            locator[k + gap] ^= Gf1024::mul(scale, coefficient);
        }
        if 2 * degree <= i {
            degree = i + 1 - degree;
            previous = snapshot;
            previous_discrepancy = discrepancy;
            gap = 1;
        } else {
            gap += 1;
        }
    }
    while locator.len() > 1 && locator.last() == Some(&0) {
        locator.pop();
    }
    if 2 * (locator.len() - 1) > parity - lost {
        return Err(DecodeError::Uncorrectable);
    }

    // The locator of every bad place, and the evaluator of the error values.
    let all_places = poly_mul(&locator, &erasure_locator);
    let mut evaluator = poly_mul(&syndrome, &all_places);
    evaluator.truncate(parity);
    let roots: Vec<usize> = (0..len)
        .filter(|&i| poly_eval(&all_places, Gf1024::inv(Gf1024::alpha(len - 1 - i))) == 0)
        .collect();
    if roots.len() != all_places.len() - 1 || !erased.iter().all(|p| roots.contains(p)) {
        return Err(DecodeError::Uncorrectable);
    }

    // Forney's formula: the value at a place is Omega(1/X) / Psi'(1/X).
    let derivative: Vec<u16> = all_places
        .iter()
        .enumerate()
        .skip(1)
        .map(|(k, &v)| if k % 2 == 1 { v } else { 0 })
        .collect();
    for &place in &roots {
        let x_inverse = Gf1024::inv(Gf1024::alpha(len - 1 - place));
        let denominator = poly_eval(&derivative, x_inverse);
        if denominator == 0 {
            return Err(DecodeError::Uncorrectable);
        }
        word[place] ^= Gf1024::div(poly_eval(&evaluator, x_inverse), denominator);
    }

    if syndromes(word, parity).iter().any(|&v| v != 0) {
        return Err(DecodeError::Uncorrectable);
    }
    Ok(Repair {
        erased: lost,
        wrong: roots.len() - lost,
    })
}

#[cfg(test)]
mod tests {
    use super::{DecodeError, Repair, decode, parity_of};

    /// A small deterministic generator, so the tests need no randomness and can be replayed.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
        fn symbol(&mut self, n: usize) -> u16 {
            u16::try_from(self.below(n)).unwrap()
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

    fn codeword(rng: &mut Lcg, data_len: usize, parity: usize) -> Vec<u16> {
        let mut word: Vec<u16> = (0..data_len).map(|_| rng.symbol(1024)).collect();
        let check = parity_of(&word, parity);
        word.extend(check);
        word
    }

    #[test]
    fn an_undamaged_codeword_decodes_to_itself() {
        let mut rng = Lcg(1);
        let word = codeword(&mut rng, 44, 24);
        let mut copy = word.clone();
        assert_eq!(decode(&mut copy, &[], 24), Ok(Repair::default()));
        assert_eq!(copy, word);
    }

    #[test]
    fn erasures_errors_and_both_are_corrected_up_to_the_bound() {
        let mut rng = Lcg(7);
        for trial in 0..300 {
            let parity = 4 + rng.below(40);
            let data_len = 20 + rng.below(40);
            let word = codeword(&mut rng, data_len, parity);
            let n = word.len();
            // any split of the budget between erasures and errors
            let errors = rng.below(parity / 2 + 1);
            let erasures = rng.below(parity - 2 * errors + 1);
            let places = rng.distinct(erasures + errors, n);
            let mut damaged = word.clone();
            for (k, &p) in places.iter().enumerate() {
                let wrong = 1 + rng.symbol(1023);
                damaged[p] = if k < erasures {
                    rng.symbol(1024)
                } else {
                    damaged[p] ^ wrong
                };
            }
            let lost = &places[..erasures];
            let repair = decode(&mut damaged, lost, parity).unwrap_or_else(|e| {
                panic!("trial {trial}: {e:?} ({erasures} erased, {errors} wrong, parity {parity})")
            });
            assert_eq!(damaged, word, "trial {trial}");
            assert_eq!(
                repair,
                Repair {
                    erased: erasures,
                    wrong: errors
                }
            );
        }
    }

    #[test]
    fn more_erasures_than_check_symbols_are_refused() {
        let mut rng = Lcg(3);
        let mut word = codeword(&mut rng, 30, 8);
        let lost: Vec<usize> = (0..9).collect();
        assert_eq!(decode(&mut word, &lost, 8), Err(DecodeError::TooDamaged));
    }

    #[test]
    fn heavy_damage_is_nearly_always_reported_not_miscorrected() {
        let mut rng = Lcg(11);
        let mut wrong_answers = 0;
        for _ in 0..200 {
            let word = codeword(&mut rng, 44, 24);
            let mut damaged = word.clone();
            for p in rng.distinct(20, word.len()) {
                damaged[p] ^= 1 + rng.symbol(1023);
            }
            match decode(&mut damaged, &[], 24) {
                Err(_) => {}
                Ok(_) if damaged == word => {}
                Ok(_) => wrong_answers += 1,
            }
        }
        assert_eq!(
            wrong_answers, 0,
            "20 wrong words of 68 with 24 parity must not decode to another codeword here"
        );
    }
}
