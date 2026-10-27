//! The 1024-word list a share is written in (SLIP-39's; see `README.md` here).

use std::sync::OnceLock;

static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();

fn words() -> &'static [&'static str] {
    WORDS.get_or_init(|| {
        let list: Vec<&'static str> = include_str!("wordlist.txt").split_whitespace().collect();
        assert_eq!(list.len(), 1024, "the word list has 1024 words");
        list
    })
}

/// The word for a 10-bit symbol.
///
/// # Panics
///
/// When `symbol` is 1024 or more.
#[must_use]
pub fn word(symbol: u16) -> &'static str {
    words()[usize::from(symbol)]
}

/// The symbol a word stands for: the whole word or its first four letters or more (the first four
/// are enough to tell every word of the list apart), in any case. `None` for anything else.
#[must_use]
pub fn lookup(text: &str) -> Option<u16> {
    let text = text.trim().to_ascii_lowercase();
    if text.len() < 4 || !text.is_ascii() {
        return None;
    }
    // The first four letters are unique, so any prefix of four letters or more names one word.
    let found = words().iter().position(|w| w.starts_with(&text));
    found.and_then(|i| u16::try_from(i).ok())
}

#[cfg(test)]
mod tests {
    use super::{lookup, word};

    #[test]
    fn every_word_is_found_by_itself_and_by_its_first_four_letters() {
        for symbol in 0..1024u16 {
            let w = word(symbol);
            assert_eq!(lookup(w), Some(symbol), "{w}");
            assert_eq!(lookup(&w[..4]), Some(symbol), "{w}");
            assert_eq!(lookup(&w.to_uppercase()), Some(symbol), "{w}");
        }
    }

    #[test]
    fn other_text_is_not_a_word() {
        assert_eq!(lookup("?"), None);
        assert_eq!(lookup("zzzzzz"), None);
        assert_eq!(lookup("hum"), None);
        assert_eq!(lookup("hu"), None);
    }
}
