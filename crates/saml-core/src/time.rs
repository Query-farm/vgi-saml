//! XSD `dateTime` → epoch-microseconds (UTC) parsing, dependency-free.
//!
//! SAML timestamps are XSD `dateTime`, e.g. `2026-06-01T12:00:00Z` (occasionally
//! with fractional seconds or a numeric offset). We parse to microseconds since
//! the Unix epoch so the worker can emit `TIMESTAMPTZ` without pulling in a date
//! crate. The worker surfaces the window; it never decides "expired".

/// Parse an XSD `dateTime` to microseconds since the Unix epoch (UTC), or `None`
/// if it is not a well-formed timestamp. Never panics.
pub fn parse_xsd_datetime(s: &str) -> Option<i64> {
    let s = s.trim();
    let bytes = s.as_bytes();
    // YYYY-MM-DDThh:mm:ss
    if s.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let t = bytes[10];
    if t != b'T' && t != b't' {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    // Optional fractional seconds, then optional timezone.
    let mut rest = &s[19..];
    let mut micros_frac: i64 = 0;
    if let Some(stripped) = rest.strip_prefix('.') {
        let frac_end = stripped
            .find(['Z', 'z', '+', '-'])
            .unwrap_or(stripped.len());
        let frac = &stripped[..frac_end];
        if !frac.is_empty() {
            if !frac.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            // Scale to microseconds (6 digits).
            let mut digits = frac.to_string();
            digits.truncate(6);
            while digits.len() < 6 {
                digits.push('0');
            }
            micros_frac = digits.parse().ok()?;
        }
        rest = &stripped[frac_end..];
    }

    // Timezone offset in seconds (UTC = 0). Absent offset → treat as UTC (SAML
    // mandates UTC; we don't reject a missing 'Z').
    let offset_secs: i64 = match rest.chars().next() {
        None => 0,
        Some('Z') | Some('z') => 0,
        Some(sign @ ('+' | '-')) => {
            if rest.len() < 6 || rest.as_bytes()[3] != b':' {
                return None;
            }
            let oh: i64 = rest.get(1..3)?.parse().ok()?;
            let om: i64 = rest.get(4..6)?.parse().ok()?;
            if oh > 23 || om > 59 {
                return None;
            }
            let mag = oh * 3600 + om * 60;
            if sign == '+' {
                mag
            } else {
                -mag
            }
        }
        _ => return None,
    };

    let days = days_from_civil(year, month as u32, day as u32);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs;
    Some(secs * 1_000_000 + micros_frac)
}

/// Days from the Unix epoch (1970-01-01) for a proleptic-Gregorian date.
/// Howard Hinnant's `days_from_civil` algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        assert_eq!(parse_xsd_datetime("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn known_instant() {
        // 2026-06-01T12:00:00Z
        let v = parse_xsd_datetime("2026-06-01T12:00:00Z").unwrap();
        // sanity: positive, divisible by 1e6
        assert!(v > 0 && v % 1_000_000 == 0);
        // round-trips through offset form
        assert_eq!(parse_xsd_datetime("2026-06-01T14:00:00+02:00"), Some(v));
    }

    #[test]
    fn fractional() {
        let a = parse_xsd_datetime("2026-06-01T12:00:00.5Z").unwrap();
        let b = parse_xsd_datetime("2026-06-01T12:00:00Z").unwrap();
        assert_eq!(a - b, 500_000);
    }

    #[test]
    fn garbage_is_none() {
        assert_eq!(parse_xsd_datetime("not a date"), None);
        assert_eq!(parse_xsd_datetime(""), None);
        assert_eq!(parse_xsd_datetime("2026-13-01T00:00:00Z"), None);
    }
}
