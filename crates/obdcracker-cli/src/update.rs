//! `obdcracker update`: pick a release (or `main`), check it against what is installed, and run
//! the install script at that exact commit. See docs/install.md#updating.

use std::fmt;

use serde_json::Value;

// The install guide's section for a build that can't be compared with a release.
const INSTALL_DOC: &str = "docs/install.md#updating";

/// A release version, `major.minor.patch` with plain digits and no leading zeros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Version {
    // `1.2.3` and nothing else: a sign, a leading zero or a space would give one version two
    // spellings, and `parse` accepts a leading `+`.
    fn parse(text: &str) -> Option<Self> {
        fn number(part: &str) -> Option<u32> {
            let plain = !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'));
            if plain { part.parse().ok() } else { None }
        }
        let mut parts = text.split('.');
        let version = Version {
            major: number(parts.next()?)?,
            minor: number(parts.next()?)?,
            patch: number(parts.next()?)?,
        };
        parts.next().is_none().then_some(version)
    }

    /// The command line's spelling: `0.2.0` or `v0.2.0`.
    pub(crate) fn parse_request(text: &str) -> Option<Self> {
        Self::parse(text.strip_prefix('v').unwrap_or(text))
    }

    // A release's tag, which is `v` and the version and nothing else.
    fn parse_tag(tag: &str) -> Option<Self> {
        Self::parse(tag.strip_prefix('v')?)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What this build is: its version, and its commit when it records one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Installed {
    pub(crate) version: Version,
    pub(crate) commit: Option<String>,
}

impl Installed {
    /// From the build's version and its commit, which is 40 lowercase hex or `unknown`.
    pub(crate) fn from_build(version: &str, commit: &str) -> Result<Self, String> {
        Ok(Installed {
            version: Version::parse(version).ok_or_else(|| {
                format!("this build's version, {version}, isn't major.minor.patch")
            })?,
            commit: is_sha(commit).then(|| commit.to_owned()),
        })
    }
}

/// What the user asked to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Want {
    Latest,
    Version(Version),
    Main,
}

/// A release or `main`, by the name GitHub resolves to a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) version: Option<Version>,
    pub(crate) git_ref: String,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.version {
            Some(version) => write!(f, "v{version}"),
            None => f.write_str(&self.git_ref),
        }
    }
}

/// How the target's commit stands to the installed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum History {
    /// The installed commit isn't known, so there is nothing to compare.
    Unknown,
    Same,
    /// The target contains the installed commit.
    Ahead,
    /// The installed commit contains the target.
    Behind,
    Diverged,
    /// GitHub doesn't know the installed commit.
    NotFound,
}

/// Why an update was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    NoReleases,
    NotReleased(Version),
    LowerVersion { installed: Version, target: Version },
    Behind,
    Diverged,
    NotOnGithub,
    UnknownCommit { target: Option<Version> },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const FLAG: &str = "pass --allow-downgrade to install it anyway";
        match self {
            Refusal::NoReleases => write!(
                f,
                "GitHub lists no release to install; try --main for the newest commit"
            ),
            Refusal::NotReleased(version) => write!(f, "there is no release v{version}"),
            Refusal::LowerVersion { installed, target } => {
                write!(f, "v{target} is older than the installed {installed}; {FLAG}")
            }
            Refusal::Behind => write!(
                f,
                "the installed commit already contains the target, so this would go back; {FLAG}"
            ),
            Refusal::Diverged => write!(
                f,
                "the installed commit and the target are on different lines of history, so the \
                 target isn't newer; {FLAG}"
            ),
            Refusal::NotOnGithub => write!(
                f,
                "GitHub doesn't know the installed commit (a build from a local checkout?), so it \
                 can't say whether the target is newer; {FLAG}"
            ),
            Refusal::UnknownCommit { target } => {
                match target {
                    Some(version) => write!(
                        f,
                        "this build doesn't record its commit, so it can't be told from v{version}, \
                         which has the same version"
                    )?,
                    None => write!(
                        f,
                        "this build doesn't record its commit, so it can't be compared with main"
                    )?,
                }
                write!(
                    f,
                    "; run the install script once instead (see {INSTALL_DOC}), or {FLAG}"
                )
            }
        }
    }
}

/// What `update` does about a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    UpToDate,
    Install,
    Refused(Refusal),
}

// Exactly what `obdcracker --version` can show, and what the install scripts take as a commit.
fn is_sha(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// The published releases' versions. Every entry is checked, the ones left out too.
fn parse_releases(body: &[u8]) -> Result<Vec<Version>, String> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| format!("GitHub's release list isn't JSON: {e}"))?;
    let entries = value
        .as_array()
        .ok_or("GitHub's release list isn't a list")?;
    let mut versions = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let field = |name: &str| {
            entry
                .get(name)
                .ok_or_else(|| format!("release {index} of GitHub's list has no `{name}`"))
        };
        let tag = field("tag_name")?
            .as_str()
            .ok_or_else(|| format!("release {index}'s `tag_name` isn't text"))?;
        let flag = |name: &str| {
            field(name)?
                .as_bool()
                .ok_or_else(|| format!("release {index}'s `{name}` isn't true or false"))
        };
        let (draft, prerelease) = (flag("draft")?, flag("prerelease")?);
        if !draft && !prerelease {
            versions.extend(Version::parse_tag(tag));
        }
    }
    Ok(versions)
}

fn choose(releases: &[Version], want: &Want) -> Result<Target, Refusal> {
    let release = |version: Version| Target {
        version: Some(version),
        git_ref: format!("v{version}"),
    };
    match want {
        Want::Main => Ok(Target {
            version: None,
            git_ref: "main".to_owned(),
        }),
        Want::Version(version) => releases
            .contains(version)
            .then(|| release(*version))
            .ok_or(Refusal::NotReleased(*version)),
        Want::Latest => releases
            .iter()
            .max()
            .map(|version| release(*version))
            .ok_or(Refusal::NoReleases),
    }
}

// GitHub's bare-commit reply, which may end in a newline.
fn parse_sha(body: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|_| "GitHub's answer for a commit isn't text")?;
    let sha = text.strip_suffix('\n').unwrap_or(text);
    if is_sha(sha) {
        Ok(sha.to_owned())
    } else {
        Err("GitHub's answer for a commit isn't a commit hash".to_owned())
    }
}

// `compare/<installed>...<target>`: `status` is the target's, so `ahead` means it is newer.
fn parse_compare(body: &[u8]) -> Result<History, String> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| format!("GitHub's comparison isn't JSON: {e}"))?;
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .ok_or("GitHub's comparison has no `status`")?;
    match status {
        "identical" => Ok(History::Same),
        "ahead" => Ok(History::Ahead),
        "behind" => Ok(History::Behind),
        "diverged" => Ok(History::Diverged),
        other => Err(format!(
            "GitHub's comparison has an unknown status, {:?}",
            other.chars().take(32).collect::<String>()
        )),
    }
}

// The rule that needs no commit lookup, so it is checked before any is made.
fn lower_version(installed: &Installed, target: &Target, allow: bool) -> Option<Refusal> {
    match target.version {
        Some(version) if version < installed.version && !allow => Some(Refusal::LowerVersion {
            installed: installed.version,
            target: version,
        }),
        _ => None,
    }
}

fn decide(installed: &Installed, target: &Target, history: History, allow: bool) -> Decision {
    if let Some(refusal) = lower_version(installed, target, allow) {
        return Decision::Refused(refusal);
    }
    let refuse = |refusal| {
        if allow {
            Decision::Install
        } else {
            Decision::Refused(refusal)
        }
    };
    match history {
        History::Same => Decision::UpToDate,
        History::Ahead => Decision::Install,
        History::Behind => refuse(Refusal::Behind),
        History::Diverged => refuse(Refusal::Diverged),
        History::NotFound => refuse(Refusal::NotOnGithub),
        History::Unknown => match target.version {
            Some(version) if version > installed.version => Decision::Install,
            version => refuse(Refusal::UnknownCommit { target: version }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn v(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    fn release(version: Version) -> Target {
        Target {
            version: Some(version),
            git_ref: format!("v{}.{}.{}", version.major, version.minor, version.patch),
        }
    }

    fn main_branch() -> Target {
        Target {
            version: None,
            git_ref: "main".to_owned(),
        }
    }

    fn installed(version: Version, known: bool) -> Installed {
        Installed {
            version,
            commit: known.then(|| SHA_A.to_owned()),
        }
    }

    #[test]
    fn versions_are_three_plain_numbers() {
        assert_eq!(Version::parse("0.2.0"), Some(v(0, 2, 0)));
        assert_eq!(Version::parse("10.20.30"), Some(v(10, 20, 30)));
        assert_eq!(Version::parse("0.0.0"), Some(v(0, 0, 0)));
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "1..3",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "+1.2.3",
            "1.+2.3",
            "1.2.-3",
            " 1.2.3",
            "1.2.3 ",
            "1.2.3\n",
            "1.2.3-rc1",
            "1.2.3+b",
            "v1.2.3",
            "1.2.x",
            "١.2.3",
            "4294967296.0.0",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad:?}");
        }
        assert_eq!(Version::parse("4294967295.0.0"), Some(v(u32::MAX, 0, 0)));
    }

    #[test]
    fn a_requested_version_may_have_a_lower_case_v() {
        assert_eq!(Version::parse_request("0.2.0"), Some(v(0, 2, 0)));
        assert_eq!(Version::parse_request("v0.2.0"), Some(v(0, 2, 0)));
        for bad in ["V0.2.0", "vv0.2.0", "v", "", "latest", "v0.2", "main"] {
            assert_eq!(Version::parse_request(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn versions_compare_by_number_not_by_text() {
        assert!(v(0, 10, 0) > v(0, 9, 0));
        assert!(v(1, 0, 0) > v(0, 99, 99));
        assert!(v(0, 2, 10) > v(0, 2, 9));
    }

    #[test]
    fn a_commit_is_forty_lowercase_hex_characters() {
        assert!(is_sha(SHA_A));
        assert!(is_sha("0123456789abcdef0123456789abcdef01234567"));
        for bad in [
            "",
            "main",
            &SHA_A[..39],
            &format!("{SHA_A}a"),
            &SHA_A.to_uppercase(),
            &format!("{}g", &SHA_A[..39]),
            &format!("{}é", &SHA_A[..38]),
            &format!("{SHA_A}\n"),
        ] {
            assert!(!is_sha(bad), "{bad:?}");
        }
    }

    fn release_list(items: &[(&str, bool, bool)]) -> Vec<u8> {
        let items: Vec<Value> = items
            .iter()
            .map(|(tag, draft, prerelease)| {
                serde_json::json!({"tag_name": tag, "draft": draft, "prerelease": prerelease,
                                   "name": "ignored", "id": 1})
            })
            .collect();
        serde_json::to_vec(&items).unwrap()
    }

    #[test]
    fn releases_skip_drafts_prereleases_and_other_tags() {
        let body = release_list(&[
            ("v0.2.0", false, false),
            ("v0.3.0", true, false),
            ("v0.4.0", false, true),
            ("v0.5.0-rc1", false, false),
            ("0.6.0", false, false),
            ("V0.7.0", false, false),
            ("v0.08.0", false, false),
            ("v1.2", false, false),
            ("nightly", false, false),
            ("v0.1.0", false, false),
        ]);
        assert_eq!(parse_releases(&body).unwrap(), vec![v(0, 2, 0), v(0, 1, 0)]);
        assert_eq!(parse_releases(b"[]").unwrap(), vec![]);
    }

    #[test]
    fn a_malformed_release_list_is_an_error() {
        for bad in [
            &b""[..],
            b"not json",
            b"{}",
            b"null",
            b"[1]",
            b"[null]",
            b"[{}]",
            br#"[{"tag_name":"v0.1.0","draft":false}]"#,
            br#"[{"tag_name":"v0.1.0","prerelease":false}]"#,
            br#"[{"draft":false,"prerelease":false}]"#,
            br#"[{"tag_name":1,"draft":false,"prerelease":false}]"#,
            br#"[{"tag_name":"v0.1.0","draft":"no","prerelease":false}]"#,
            br#"[{"tag_name":"v0.1.0","draft":false,"prerelease":null}]"#,
            // A bad entry fails the list even when an earlier one is fine
            br#"[{"tag_name":"v0.1.0","draft":false,"prerelease":false},{"tag_name":2}]"#,
            // And even when the bad entry is one that would have been skipped
            br#"[{"tag_name":"v0.1.0","draft":true,"prerelease":7}]"#,
        ] {
            assert!(
                parse_releases(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn the_latest_release_is_the_highest_version_not_the_newest() {
        let releases = [v(0, 9, 0), v(0, 10, 0), v(0, 2, 0)];
        assert_eq!(
            choose(&releases, &Want::Latest).unwrap(),
            release(v(0, 10, 0))
        );
    }

    #[test]
    fn a_named_release_must_exist() {
        let releases = [v(0, 9, 0), v(0, 10, 0)];
        assert_eq!(
            choose(&releases, &Want::Version(v(0, 9, 0))).unwrap(),
            release(v(0, 9, 0))
        );
        assert_eq!(
            choose(&releases, &Want::Version(v(0, 1, 0))),
            Err(Refusal::NotReleased(v(0, 1, 0)))
        );
    }

    #[test]
    fn no_releases_refuses_latest_but_not_main() {
        assert_eq!(choose(&[], &Want::Latest), Err(Refusal::NoReleases));
        assert_eq!(
            choose(&[], &Want::Version(v(0, 1, 0))),
            Err(Refusal::NotReleased(v(0, 1, 0)))
        );
        assert_eq!(choose(&[], &Want::Main).unwrap(), main_branch());
        assert_eq!(choose(&[v(0, 1, 0)], &Want::Main).unwrap(), main_branch());
    }

    #[test]
    fn a_commit_reply_is_exactly_a_commit() {
        assert_eq!(parse_sha(SHA_A.as_bytes()).unwrap(), SHA_A);
        assert_eq!(parse_sha(format!("{SHA_A}\n").as_bytes()).unwrap(), SHA_A);
        for bad in [
            "",
            "\n",
            "main",
            &SHA_A[..39],
            &format!("{SHA_A}a"),
            &SHA_A.to_uppercase(),
            &format!(" {SHA_A}"),
            &format!("{SHA_A}\n\n"),
            &format!("{SHA_A} x"),
            &format!(r#"{{"sha":"{SHA_A}"}}"#),
        ] {
            assert!(parse_sha(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(parse_sha(&[0xff; 40]).is_err());
    }

    #[test]
    fn a_comparison_reply_has_one_of_four_statuses() {
        for (status, history) in [
            ("identical", History::Same),
            ("ahead", History::Ahead),
            ("behind", History::Behind),
            ("diverged", History::Diverged),
        ] {
            let body = format!(r#"{{"status":"{status}","ahead_by":3,"commits":[]}}"#);
            assert_eq!(parse_compare(body.as_bytes()).unwrap(), history);
        }
        for bad in [
            &br#"{"status":"Ahead"}"#[..],
            br#"{"status":"merged"}"#,
            br#"{"status":""}"#,
            br#"{"status":null}"#,
            br#"{"status":1}"#,
            br#"{"state":"ahead"}"#,
            b"[]",
            b"",
            b"ahead",
        ] {
            assert!(
                parse_compare(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_lower_version_is_refused_without_the_flag() {
        let me = installed(v(0, 3, 0), true);
        let target = release(v(0, 2, 0));
        assert_eq!(
            lower_version(&me, &target, false),
            Some(Refusal::LowerVersion {
                installed: v(0, 3, 0),
                target: v(0, 2, 0)
            })
        );
        assert_eq!(lower_version(&me, &target, true), None);
        assert_eq!(lower_version(&me, &release(v(0, 3, 0)), false), None);
        assert_eq!(lower_version(&me, &release(v(0, 4, 0)), false), None);
        assert_eq!(lower_version(&me, &main_branch(), false), None);
    }

    fn decide_both(me: &Installed, target: &Target, history: History) -> (Decision, Decision) {
        (
            decide(me, target, history, false),
            decide(me, target, history, true),
        )
    }

    #[test]
    fn the_same_commit_is_up_to_date_with_or_without_the_flag() {
        let me = installed(v(0, 2, 0), true);
        for target in [release(v(0, 2, 0)), main_branch()] {
            assert_eq!(
                decide_both(&me, &target, History::Same),
                (Decision::UpToDate, Decision::UpToDate)
            );
        }
    }

    #[test]
    fn a_target_ahead_of_the_installed_commit_installs_without_the_flag() {
        let me = installed(v(0, 2, 0), true);
        for target in [release(v(0, 2, 0)), release(v(0, 3, 0)), main_branch()] {
            assert_eq!(
                decide_both(&me, &target, History::Ahead),
                (Decision::Install, Decision::Install)
            );
        }
    }

    #[test]
    fn a_target_behind_diverged_or_unknown_to_github_needs_the_flag() {
        let me = installed(v(0, 2, 0), true);
        for (history, refusal) in [
            (History::Behind, Refusal::Behind),
            (History::Diverged, Refusal::Diverged),
            (History::NotFound, Refusal::NotOnGithub),
        ] {
            for target in [release(v(0, 2, 0)), release(v(0, 3, 0)), main_branch()] {
                assert_eq!(
                    decide_both(&me, &target, history),
                    (Decision::Refused(refusal), Decision::Install),
                    "{history:?} {target:?}"
                );
            }
        }
    }

    #[test]
    fn a_lower_version_is_refused_whatever_the_commit_history_says() {
        let me = installed(v(0, 3, 0), true);
        let target = release(v(0, 2, 0));
        let lower = Decision::Refused(Refusal::LowerVersion {
            installed: v(0, 3, 0),
            target: v(0, 2, 0),
        });
        for history in [
            History::Ahead,
            History::Behind,
            History::Diverged,
            History::NotFound,
            History::Same,
        ] {
            assert_eq!(decide(&me, &target, history, false), lower, "{history:?}");
        }
        for history in [
            History::Ahead,
            History::Behind,
            History::Diverged,
            History::NotFound,
        ] {
            assert_eq!(
                decide(&me, &target, history, true),
                Decision::Install,
                "{history:?}"
            );
        }
        assert_eq!(
            decide(&me, &target, History::Same, true),
            Decision::UpToDate
        );
    }

    #[test]
    fn an_unknown_installed_commit_takes_only_a_strictly_higher_release() {
        let me = installed(v(0, 2, 0), false);
        for higher in [v(0, 3, 0), v(0, 2, 1), v(1, 0, 0)] {
            assert_eq!(
                decide_both(&me, &release(higher), History::Unknown),
                (Decision::Install, Decision::Install)
            );
        }
    }

    #[test]
    fn an_unknown_installed_commit_needs_the_flag_for_main_and_the_same_version() {
        let me = installed(v(0, 2, 0), false);
        assert_eq!(
            decide_both(&me, &release(v(0, 2, 0)), History::Unknown),
            (
                Decision::Refused(Refusal::UnknownCommit {
                    target: Some(v(0, 2, 0))
                }),
                Decision::Install
            )
        );
        assert_eq!(
            decide_both(&me, &main_branch(), History::Unknown),
            (
                Decision::Refused(Refusal::UnknownCommit { target: None }),
                Decision::Install
            )
        );
    }

    #[test]
    fn an_unknown_installed_commit_refuses_a_lower_release_as_lower() {
        let me = installed(v(0, 2, 0), false);
        assert_eq!(
            decide_both(&me, &release(v(0, 1, 0)), History::Unknown),
            (
                Decision::Refused(Refusal::LowerVersion {
                    installed: v(0, 2, 0),
                    target: v(0, 1, 0)
                }),
                Decision::Install
            )
        );
    }

    #[test]
    fn every_refusal_names_the_flag_that_overrides_it() {
        let overridable = [
            Refusal::LowerVersion {
                installed: v(0, 3, 0),
                target: v(0, 2, 0),
            },
            Refusal::Behind,
            Refusal::Diverged,
            Refusal::NotOnGithub,
            Refusal::UnknownCommit { target: None },
            Refusal::UnknownCommit {
                target: Some(v(0, 2, 0)),
            },
        ];
        for refusal in overridable {
            assert!(
                refusal.to_string().contains("--allow-downgrade"),
                "{refusal}"
            );
        }
        for refusal in [Refusal::NoReleases, Refusal::NotReleased(v(0, 1, 0))] {
            assert!(
                !refusal.to_string().contains("--allow-downgrade"),
                "{refusal}"
            );
        }
        for target in [None, Some(v(0, 2, 0))] {
            let text = Refusal::UnknownCommit { target }.to_string();
            assert!(text.contains("docs/install.md#updating"), "{text}");
        }
    }
}
