use crate::consts::MAX_PATH;

const CASE_BIT: u8 = 0x20;
pub fn case_insensitive_compare_strs_as_bytes(
    string_bytes: &[u8],
    other_string_bytes: &[u8],
) -> bool {
    if string_bytes.len() != other_string_bytes.len() {
        return false;
    }

    for i in 0..string_bytes.len() {
        let mut val = string_bytes[i];
        let mut val2 = other_string_bytes[i];

        if (0x41..=0x5A).contains(&val) {
            val ^= CASE_BIT
        }
        if (0x41..=0x5A).contains(&val2) {
            val2 ^= CASE_BIT
        }

        if val != val2 {
            return false;
        }
    }

    true
}

// Need internal function for this in unmapped PE state.
pub unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    while *s.add(len) != 0 && len <= MAX_PATH {
        len += 1;
    }

    len
}
