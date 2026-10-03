//! Version comparison: Debian (dpkg), Arch (alpm vercmp) and a lenient semver-ish order for
//! upstream releases / OSV fixed versions.

use std::cmp::Ordering;

// ---------------------------------------------------------------------------------------
// Debian: [epoch:]upstream[-revision], dpkg's verrevcmp ('~' sorts before everything).
// ---------------------------------------------------------------------------------------

pub fn deb_cmp(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = deb_split(a);
    let (eb, ub, rb) = deb_split(b);
    ea.cmp(&eb).then_with(|| verrevcmp(ua, ub)).then_with(|| verrevcmp(ra, rb))
}

fn deb_split(v: &str) -> (u64, &str, &str) {
    let v = v.trim();
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) if e.chars().all(|c| c.is_ascii_digit()) && !e.is_empty() => (e.parse().unwrap_or(0), r),
        _ => (0, v),
    };
    match rest.rsplit_once('-') {
        Some((u, r)) => (epoch, u, r),
        None => (epoch, rest, ""),
    }
}

fn deb_order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        // Non-digit prefix, compared char by char with the dpkg order.
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ac = deb_order(a.get(i).copied().filter(|c| !c.is_ascii_digit()));
            let bc = deb_order(b.get(j).copied().filter(|c| !c.is_ascii_digit()));
            if ac != bc {
                return ac.cmp(&bc);
            }
            if i < a.len() && !a[i].is_ascii_digit() {
                i += 1;
            }
            if j < b.len() && !b[j].is_ascii_digit() {
                j += 1;
            }
        }
        while i < a.len() && a[i] == b'0' {
            i += 1;
        }
        while j < b.len() && b[j] == b'0' {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while i < a.len() && a[i].is_ascii_digit() && j < b.len() && b[j].is_ascii_digit() {
            if first_diff == Ordering::Equal {
                first_diff = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if i < a.len() && a[i].is_ascii_digit() {
            return Ordering::Greater;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

// ---------------------------------------------------------------------------------------
// Arch: [epoch:]pkgver[-pkgrel], libalpm's rpmvercmp per part.
// ---------------------------------------------------------------------------------------

pub fn alpm_cmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (ea, va, ra) = alpm_split(a);
    let (eb, vb, rb) = alpm_split(b);
    let e = rpmvercmp(ea, eb);
    if e != Ordering::Equal {
        return e;
    }
    let v = rpmvercmp(va, vb);
    if v != Ordering::Equal {
        return v;
    }
    match (ra, rb) {
        (Some(x), Some(y)) => rpmvercmp(x, y),
        _ => Ordering::Equal,
    }
}

fn alpm_split(v: &str) -> (&str, &str, Option<&str>) {
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) if e.chars().all(|c| c.is_ascii_digit()) => (if e.is_empty() { "0" } else { e }, r),
        _ => ("0", v),
    };
    match rest.rsplit_once('-') {
        Some((ver, rel)) => (epoch, ver, Some(rel)),
        None => (epoch, rest, None),
    }
}

/// Port of libalpm's rpmvercmp (lib/libalpm/version.c), including its separator-length rule
/// and the "final showdown" for trailing parts.
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut one, mut two) = (0, 0);
    let (mut p1, mut p2) = (0, 0);
    while one < a.len() && two < b.len() {
        while one < a.len() && !a[one].is_ascii_alphanumeric() {
            one += 1;
        }
        while two < b.len() && !b[two].is_ascii_alphanumeric() {
            two += 1;
        }
        if one >= a.len() || two >= b.len() {
            break;
        }
        // Different separator lengths: the longer one is newer.
        if one - p1 != two - p2 {
            return (one - p1).cmp(&(two - p2));
        }
        p1 = one;
        p2 = two;
        let isnum = a[p1].is_ascii_digit();
        if isnum {
            while p1 < a.len() && a[p1].is_ascii_digit() {
                p1 += 1;
            }
            while p2 < b.len() && b[p2].is_ascii_digit() {
                p2 += 1;
            }
        } else {
            while p1 < a.len() && a[p1].is_ascii_alphabetic() {
                p1 += 1;
            }
            while p2 < b.len() && b[p2].is_ascii_alphabetic() {
                p2 += 1;
            }
        }
        // Segment types differ: numeric is newer than alpha.
        if two == p2 {
            return if isnum { Ordering::Greater } else { Ordering::Less };
        }
        let (mut s1, mut s2) = (&a[one..p1], &b[two..p2]);
        if isnum {
            s1 = trim_zeros(s1);
            s2 = trim_zeros(s2);
            if s1.len() != s2.len() {
                return s1.len().cmp(&s2.len());
            }
        }
        let rc = s1.cmp(s2);
        if rc != Ordering::Equal {
            return rc;
        }
        one = p1;
        two = p2;
    }
    let (r1, r2) = (&a[one..], &b[two..]);
    if r1.is_empty() && r2.is_empty() {
        return Ordering::Equal;
    }
    // A remaining alpha string never beats an empty one.
    if (r1.is_empty() && !r2[0].is_ascii_alphabetic()) || r1.first().is_some_and(u8::is_ascii_alphabetic) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

fn trim_zeros(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|c| **c == b'0').count();
    &s[n..]
}

// ---------------------------------------------------------------------------------------
// Lenient: "v1.2.3", "1.2.3-rc.1", "2.29.1". Numeric segments numerically; a pre-release
// suffix (-rc, -beta, -alpha, ~) sorts before the release.
// ---------------------------------------------------------------------------------------

pub fn loose_cmp(a: &str, b: &str) -> Ordering {
    let (ca, pa) = loose_split(a);
    let (cb, pb) = loose_split(b);
    let n = ca.len().max(cb.len());
    for k in 0..n {
        let x = ca.get(k).copied().unwrap_or(0);
        let y = cb.get(k).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    match (pa, pb) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => x.cmp(y),
    }
}

fn loose_split(v: &str) -> (Vec<u64>, Option<&str>) {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let (core, pre) = match v.find(['-', '~', '+']) {
        Some(i) if &v[i..i + 1] == "+" => (&v[..i], None),
        Some(i) => (&v[..i], Some(&v[i + 1..])),
        None => (v, None),
    };
    let nums = core.split('.').map(|p| p.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap_or(0)).collect();
    (nums, pre.filter(|p| !p.is_empty()))
}

/// Major component for "a major version behind": 0.x versions use the minor.
pub fn loose_major(v: &str) -> (u64, u64) {
    let (c, _) = loose_split(v);
    let major = c.first().copied().unwrap_or(0);
    if major == 0 { (0, c.get(1).copied().unwrap_or(0)) } else { (major, 0) }
}

/// Looks like a version (starts with a digit after an optional v).
pub fn looks_like_version(s: &str) -> bool {
    s.trim_start_matches(['v', 'V']).chars().next().is_some_and(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    #[test]
    fn debian_vectors() {
        // From dpkg's t/dpkg_version.t and Debian policy examples.
        for (a, b, o) in [
            ("1.0", "1.0", Equal),
            ("1.0-1", "1.0-2", Less),
            ("1:1.0", "2.0", Greater),
            ("1.0~rc1", "1.0", Less),
            ("1.0~~", "1.0~", Less),
            ("1.0", "1.0+b1", Less),
            ("3.5.7-1~deb13u2", "3.5.6-1~deb13u2", Greater),
            ("3.5.6-1~deb13u2", "3.5.6-1", Less),
            ("2.36.1-8+deb13u1", "2.36.1-8", Greater),
            ("1.2.3", "1.2.10", Less),
            ("1.0a", "1.0", Greater),
            ("0:1.0", "1.0", Equal),
            ("1.001", "1.1", Equal),
        ] {
            assert_eq!(deb_cmp(a, b), o, "{a} vs {b}");
            assert_eq!(deb_cmp(b, a), o.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn alpm_vectors() {
        // From pacman's test/util/vercmptest.sh.
        for (a, b, o) in [
            ("1.5.0", "1.5.0", Equal),
            ("1.5.1", "1.5.0", Greater),
            ("1.5-1", "1.5-2", Less),
            ("1.5-1", "1.5", Equal),
            ("1:1.0-1", "2.0-1", Greater),
            ("1.0a", "1.0", Less),
            ("1.0alpha", "1.0", Less),
            ("1.5.a", "1.5", Greater),
            ("1.5.b", "1.5.a", Greater),
            ("1.5.1", "1.5.b", Greater),
            ("1.5b", "1.5.1", Less),
            ("1.0alpha", "1.0b", Less),
            ("1.0beta", "1.0rc", Less),
            ("1.5-1", "1.5.b", Less),
            ("1.5.b-1", "1.5.b", Equal),
            ("1..0", "1.0", Greater),
            ("1.1", "1.1.1", Less),
            ("1.0rc1", "1.0", Less),
            ("6.17.1-2", "6.17.10-1", Less),
            ("2.36.1-1.1", "2.36.1-1", Greater),
        ] {
            assert_eq!(alpm_cmp(a, b), o, "{a} vs {b}");
            assert_eq!(alpm_cmp(b, a), o.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn loose_order() {
        assert_eq!(loose_cmp("v1.121.0", "1.121.3"), Less);
        assert_eq!(loose_cmp("2.29.1", "1.123.17"), Greater);
        assert_eq!(loose_cmp("1.2.0-rc.1", "1.2.0"), Less);
        assert_eq!(loose_cmp("1.2", "1.2.0"), Equal);
        assert_eq!(loose_cmp("1.2.0+build5", "1.2.0"), Equal);
        assert_eq!(loose_major("0.14.2"), (0, 14));
        assert_eq!(loose_major("2.5.0"), (2, 0));
        assert!(looks_like_version("v1.2") && !looks_like_version("latest"));
    }
}
