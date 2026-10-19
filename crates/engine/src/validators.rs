//! Checks that cut false positives out of a regex match, so a rule only fires on values that are structurally valid.
use contract::Validator;

const CARD_MIN_DIGITS: usize = 13;
const CARD_MAX_DIGITS: usize = 19;
const IBAN_MIN_LEN: usize = 15;
const IBAN_MAX_LEN: usize = 34;
const IBAN_COUNTRY_AND_CHECK_LEN: usize = 4;
const IBAN_MODULUS: u32 = 97;

pub type CheckFn = fn(&str) -> bool;

pub fn check_for(validator: Option<Validator>) -> CheckFn {
    match validator {
        Some(Validator::Luhn) => luhn,
        Some(Validator::Ssn) => ssn,
        Some(Validator::Iban) => iban,
        None => accept_all,
    }
}

fn accept_all(_text: &str) -> bool {
    true
}

fn luhn(text: &str) -> bool {
    let digits: Vec<u32> = text.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(CARD_MIN_DIGITS..=CARD_MAX_DIGITS).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(position, &digit)| {
            if position % 2 == 0 {
                return digit;
            }
            let doubled = digit * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        })
        .sum();
    sum % 10 == 0
}

fn ssn(text: &str) -> bool {
    let mut parts = text.split('-');
    let (Some(area), Some(group), Some(serial), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !(area == "000" || area == "666" || area.starts_with('9') || group == "00" || serial == "0000")
}

fn iban(text: &str) -> bool {
    if !text.is_ascii() || !(IBAN_MIN_LEN..=IBAN_MAX_LEN).contains(&text.len()) {
        return false;
    }
    let (head, tail) = text.split_at(IBAN_COUNTRY_AND_CHECK_LEN);
    let mut remainder = 0u32;
    for character in tail.chars().chain(head.chars()) {
        let Some(digit) = character.to_digit(36) else {
            return false;
        };
        let scale = if digit < 10 { 10 } else { 100 };
        remainder = (remainder * scale + digit) % IBAN_MODULUS;
    }
    remainder == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_valid_cards_and_rejects_near_misses() {
        assert!(luhn("4111 1111 1111 1111"));
        assert!(!luhn("4111 1111 1111 1112"));
        assert!(!luhn("4111"));
    }

    #[test]
    fn ssn_rejects_reserved_areas_and_zero_groups() {
        assert!(ssn("123-45-6789"));
        for invalid in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "123-00-6789",
            "123-45-0000",
        ] {
            assert!(!ssn(invalid), "{invalid}");
        }
    }

    #[test]
    fn ssn_with_the_wrong_shape_is_rejected_instead_of_panicking() {
        for invalid in ["", "123", "123-45", "123-45-6789-1"] {
            assert!(!ssn(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn iban_checks_the_modulus_and_survives_odd_input() {
        assert!(iban("GB82WEST12345698765432"));
        assert!(!iban("GB82WEST12345698765433"));
        assert!(!iban("GB82WEST1234569876543é"));
        assert!(!iban("short"));
    }
}
