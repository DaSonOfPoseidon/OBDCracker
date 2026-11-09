//! `obdcracker update`: pick a release (or `main`), check it against what is installed, and run
//! the install script at that exact commit. See docs/install.md#updating.

mod http;
mod install;

use std::fmt;
use std::io::Write;

use serde_json::Value;

pub(crate) use http::SystemHttp;
use http::{Accept, Http, Reply};
pub(crate) use install::{Setup, SystemRunner};

const REPO: &str = "DaSonOfPoseidon/OBDCracker";
// The install guide's section for a build that can't be compared with a release.
const INSTALL_DOC: &str = "docs/install.md#updating";

const RELEASES_PER_PAGE: usize = 100;
// Ten pages are a thousand releases, far more than this project will make.
const RELEASE_PAGES: usize = 10;
// What each reply may weigh. A comparison lists the files that changed, so it is the largest.
const RELEASES_LIMIT: usize = 8 << 20;
const COMMIT_LIMIT: usize = 64 << 10;
const COMPARE_LIMIT: usize = 32 << 20;

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

/// A release, or `main` when there is no version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) version: Option<Version>,
}

impl Target {
    // The name GitHub's commit lookup takes. `tags/` and `heads/` keep a branch named like a tag
    // from being taken for it.
    fn api_ref(&self) -> String {
        match self.version {
            Some(version) => format!("tags/v{version}"),
            None => "heads/main".to_owned(),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.version {
            Some(version) => write!(f, "v{version}"),
            None => f.write_str("main"),
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
                write!(
                    f,
                    "v{target} is older than the installed {installed}; {FLAG}"
                )
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

// One page of the release list: the published releases' versions, and how many entries the page
// held. Every entry is checked, the ones left out too.
fn parse_releases(body: &[u8]) -> Result<(Vec<Version>, usize), String> {
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
    Ok((versions, entries.len()))
}

fn choose(releases: &[Version], want: &Want) -> Result<Target, Refusal> {
    let release = |version: Version| Target {
        version: Some(version),
    };
    match want {
        Want::Main => Ok(Target { version: None }),
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
    let value: Value =
        serde_json::from_slice(body).map_err(|e| format!("GitHub's comparison isn't JSON: {e}"))?;
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

fn releases_url(page: usize) -> String {
    format!("https://api.github.com/repos/{REPO}/releases?per_page={RELEASES_PER_PAGE}&page={page}")
}

// Every published release, a page of GitHub's list at a time. The highest version can be on any
// page, and so can a version asked for by name.
fn fetch_releases(http: &dyn Http) -> Result<Vec<Version>, String> {
    let mut versions = Vec::new();
    for page in 1..=RELEASE_PAGES {
        let reply = http.get(&releases_url(page), Accept::Json, RELEASES_LIMIT)?;
        let (found, entries) = parse_releases(&ok_body(reply, "the release list")?)?;
        versions.extend(found);
        if entries < RELEASES_PER_PAGE {
            return Ok(versions);
        }
    }
    Err(format!(
        "GitHub lists more than {} releases, more than update reads",
        RELEASE_PAGES * RELEASES_PER_PAGE
    ))
}

fn commit_url(target: &Target) -> String {
    format!(
        "https://api.github.com/repos/{REPO}/commits/{}",
        target.api_ref()
    )
}

fn compare_url(base: &str, head: &str) -> String {
    format!("https://api.github.com/repos/{REPO}/compare/{base}...{head}?per_page=1")
}

// The script as it is at one commit, so what runs is what was looked up.
fn script_url(sha: &str, name: &str) -> String {
    format!("https://raw.githubusercontent.com/{REPO}/{sha}/scripts/{name}")
}

// A reply's body, once GitHub has accepted the request.
fn ok_body(reply: Reply, what: &str) -> Result<Vec<u8>, String> {
    match reply.status {
        200..=299 => Ok(reply.body),
        status @ (403 | 429) => Err(format!(
            "GitHub refused the request for {what} (HTTP {status}); it may be limiting requests \
             (its API allows 60 an hour per address without signing in), so wait and try again"
        )),
        status => Err(format!("GitHub answered HTTP {status} for {what}")),
    }
}

/// What was found out about a target, short of installing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Planned {
    Refused(Refusal),
    UpToDate { target: Target, sha: String },
    Install { target: Target, sha: String },
}

/// Looks up the target and, where the installed commit is known and differs, compares the two:
/// at most the release list, one commit and one comparison.
pub(crate) fn plan(
    http: &dyn Http,
    installed: &Installed,
    want: &Want,
    allow_downgrade: bool,
) -> Result<Planned, String> {
    let releases = if matches!(want, Want::Main) {
        Vec::new()
    } else {
        fetch_releases(http)?
    };
    let target = match choose(&releases, want) {
        Ok(target) => target,
        Err(refusal) => return Ok(Planned::Refused(refusal)),
    };
    if let Some(refusal) = lower_version(installed, &target, allow_downgrade) {
        return Ok(Planned::Refused(refusal));
    }
    let reply = http.get(&commit_url(&target), Accept::Sha, COMMIT_LIMIT)?;
    let sha = parse_sha(&ok_body(reply, &format!("the commit of {target}"))?)?;
    let history = history(http, installed, &sha)?;
    Ok(match decide(installed, &target, history, allow_downgrade) {
        Decision::Refused(refusal) => Planned::Refused(refusal),
        Decision::UpToDate => Planned::UpToDate { target, sha },
        Decision::Install => Planned::Install { target, sha },
    })
}

fn history(http: &dyn Http, installed: &Installed, sha: &str) -> Result<History, String> {
    let Some(commit) = &installed.commit else {
        return Ok(History::Unknown);
    };
    if commit == sha {
        return Ok(History::Same);
    }
    let reply = http.get(&compare_url(commit, sha), Accept::Json, COMPARE_LIMIT)?;
    if reply.status == 404 {
        return Ok(History::NotFound);
    }
    parse_compare(&ok_body(reply, "the comparison of the installed commit")?)
}

/// What `update` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Options {
    pub(crate) want: Want,
    pub(crate) allow_downgrade: bool,
    pub(crate) dry_run: bool,
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(7)]
}

fn installed_text(installed: &Installed) -> String {
    match &installed.commit {
        Some(commit) => format!("{} (commit {})", installed.version, short(commit)),
        None => format!("{} (unknown commit)", installed.version),
    }
}

fn target_text(target: &Target, sha: &str) -> String {
    format!("{target} (commit {})", short(sha))
}

/// Runs `update`: says what it found, and installs when it may. Gives the exit code: 0 when the
/// build is up to date or was updated, the script's own code when it failed, 1 otherwise.
pub(crate) fn run(
    options: &Options,
    installed: &Installed,
    setup: &Setup,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    if setup.windows && !options.dry_run {
        install::remove_stale(setup.exe);
    }
    let planned = plan(
        setup.http,
        installed,
        &options.want,
        options.allow_downgrade,
    );
    let (target, sha) = match planned {
        Err(why) => {
            let _ = writeln!(err, "error: {why}");
            return 1;
        }
        Ok(Planned::Refused(refusal)) => {
            let _ = writeln!(err, "not updating: {refusal}");
            return 1;
        }
        Ok(Planned::UpToDate { target, sha }) => {
            let _ = writeln!(out, "already up to date: {}", target_text(&target, &sha));
            return 0;
        }
        Ok(Planned::Install { target, sha }) => (target, sha),
    };
    let change = format!(
        "{} with {}",
        installed_text(installed),
        target_text(&target, &sha)
    );
    if options.dry_run {
        let name = install::script_name(setup.windows);
        let (program, args) = install::command(setup.windows, std::path::Path::new(name), &sha);
        let args: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
        let _ = writeln!(out, "would replace {change}");
        let _ = writeln!(
            out,
            "would download {} and run: {program} {}",
            script_url(&sha, name),
            args.join(" ")
        );
        let _ = writeln!(out, "dry run: nothing was downloaded or installed");
        return 0;
    }
    let _ = writeln!(out, "replacing {change}");
    match install::run(setup, &sha) {
        Ok(0) => {
            let _ = writeln!(out, "updated to {}", target_text(&target, &sha));
            0
        }
        Ok(code) => {
            let _ = writeln!(err, "error: the install script failed (exit code {code})");
            u8::try_from(code).ok().filter(|c| *c != 0).unwrap_or(1)
        }
        Err(why) => {
            let _ = writeln!(err, "error: {why}");
            1
        }
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
        }
    }

    fn main_branch() -> Target {
        Target { version: None }
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
        // Ten entries on the page, two of them releases
        assert_eq!(
            parse_releases(&body).unwrap(),
            (vec![v(0, 2, 0), v(0, 1, 0)], 10)
        );
        assert_eq!(parse_releases(b"[]").unwrap(), (vec![], 0));
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
        // Nesting past what the parser allows is an error, not a stack overflow
        for deep in [
            "[".repeat(100_000),
            format!(r#"[{{"tag_name":{}}}]"#, "[".repeat(100_000)),
        ] {
            assert!(parse_releases(deep.as_bytes()).is_err());
            assert!(parse_compare(deep.as_bytes()).is_err());
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

#[cfg(test)]
mod flow_tests {
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};

    use super::http::fake::FakeHttp;
    use super::install::Runner;
    use super::*;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const API: &str = "https://api.github.com/repos/DaSonOfPoseidon/OBDCracker";
    const RELEASES: &str =
        "https://api.github.com/repos/DaSonOfPoseidon/OBDCracker/releases?per_page=100&page=1";
    const COMMIT_V2: &str =
        "https://api.github.com/repos/DaSonOfPoseidon/OBDCracker/commits/tags/v0.2.0";
    const COMMIT_MAIN: &str =
        "https://api.github.com/repos/DaSonOfPoseidon/OBDCracker/commits/heads/main";
    const COMPARE_V2: &str = "https://api.github.com/repos/DaSonOfPoseidon/OBDCracker/compare/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?per_page=1";
    const SCRIPT_URL: &str = "https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/scripts/install.sh";
    const SCRIPT: &[u8] = b"#!/bin/sh\necho installing\n";

    fn v(major: u32, minor: u32, patch: u32) -> Version {
        Version::parse(&format!("{major}.{minor}.{patch}")).unwrap()
    }

    fn me(version: Version, commit: Option<&str>) -> Installed {
        Installed {
            version,
            commit: commit.map(str::to_owned),
        }
    }

    fn releases(tags: &[&str]) -> Vec<u8> {
        let items: Vec<Value> = tags
            .iter()
            .map(|t| serde_json::json!({"tag_name": t, "draft": false, "prerelease": false}))
            .collect();
        serde_json::to_vec(&items).unwrap()
    }

    fn compare(status: &str) -> Vec<u8> {
        format!(r#"{{"status":"{status}","commits":[],"files":[]}}"#).into_bytes()
    }

    // GitHub with v0.2.0 as its newest release, at commit B
    fn github() -> FakeHttp {
        FakeHttp::new()
            .reply(RELEASES, 200, &releases(&["v0.1.0", "v0.2.0"]))
            .reply(COMMIT_V2, 200, SHA_B.as_bytes())
            .reply(COMMIT_MAIN, 200, SHA_B.as_bytes())
    }

    #[test]
    fn the_requests_go_to_the_release_list_the_commit_and_the_comparison() {
        let http = github().reply(COMPARE_V2, 200, &compare("ahead"));
        let planned = plan(&http, &me(v(0, 1, 0), Some(SHA_A)), &Want::Latest, false).unwrap();
        let target = Target {
            version: Some(v(0, 2, 0)),
        };
        assert_eq!(
            planned,
            Planned::Install {
                target,
                sha: SHA_B.to_owned()
            }
        );
        assert_eq!(http.urls(), [RELEASES, COMMIT_V2, COMPARE_V2]);
        assert_eq!(http.accepts(), [Accept::Json, Accept::Sha, Accept::Json]);
        assert!(COMPARE_V2.starts_with(API));
    }

    #[test]
    fn main_needs_no_release_list() {
        let http = github().reply(
            "https://api.github.com/repos/DaSonOfPoseidon/OBDCracker/compare/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?per_page=1",
            200,
            &compare("ahead"),
        );
        let planned = plan(&http, &me(v(0, 1, 0), Some(SHA_A)), &Want::Main, false).unwrap();
        assert!(matches!(planned, Planned::Install { .. }), "{planned:?}");
        assert_eq!(http.urls(), [COMMIT_MAIN, COMPARE_V2]);
    }

    #[test]
    fn the_installed_commit_being_the_target_asks_for_no_comparison() {
        let http = github();
        let planned = plan(&http, &me(v(0, 2, 0), Some(SHA_B)), &Want::Latest, false).unwrap();
        assert!(matches!(planned, Planned::UpToDate { .. }), "{planned:?}");
        assert_eq!(http.urls(), [RELEASES, COMMIT_V2]);
    }

    #[test]
    fn an_unknown_installed_commit_asks_for_no_comparison() {
        let http = github();
        let planned = plan(&http, &me(v(0, 1, 0), None), &Want::Latest, false).unwrap();
        assert!(matches!(planned, Planned::Install { .. }), "{planned:?}");
        assert_eq!(http.urls(), [RELEASES, COMMIT_V2]);
    }

    #[test]
    fn a_lower_version_is_refused_after_the_release_list_alone() {
        let http = github();
        let planned = plan(&http, &me(v(0, 3, 0), Some(SHA_A)), &Want::Latest, false).unwrap();
        assert!(
            matches!(planned, Planned::Refused(Refusal::LowerVersion { .. })),
            "{planned:?}"
        );
        assert_eq!(http.urls(), [RELEASES]);
    }

    fn releases_page(page: usize) -> String {
        format!(
            "https://api.github.com/repos/DaSonOfPoseidon/OBDCracker/releases?per_page=100&page={page}"
        )
    }

    // A full page of prereleases, which are all skipped
    fn full_page_of_prereleases() -> Vec<u8> {
        let items: Vec<Value> = (0..100)
            .map(|i| {
                serde_json::json!({"tag_name": format!("v0.0.{i}"), "draft": false, "prerelease": true})
            })
            .collect();
        serde_json::to_vec(&items).unwrap()
    }

    #[test]
    fn releases_past_the_first_page_are_found() {
        let http = FakeHttp::new()
            .reply(&releases_page(1), 200, &full_page_of_prereleases())
            .reply(&releases_page(2), 200, &releases(&["v0.1.0", "v0.2.0"]))
            .reply(COMMIT_V2, 200, SHA_B.as_bytes());
        let installed = me(v(0, 1, 0), None);
        let planned = plan(&http, &installed, &Want::Latest, false).unwrap();
        assert!(matches!(planned, Planned::Install { .. }), "{planned:?}");
        assert_eq!(
            http.urls(),
            [releases_page(1), releases_page(2), COMMIT_V2.to_owned()]
        );
        // A named release on a later page exists too
        let planned = plan(&http, &installed, &Want::Version(v(0, 2, 0)), false).unwrap();
        assert!(matches!(planned, Planned::Install { .. }), "{planned:?}");
    }

    #[test]
    fn a_release_list_that_never_ends_is_an_error() {
        let mut http = FakeHttp::new();
        for page in 1..=RELEASE_PAGES + 1 {
            http = http.reply(&releases_page(page), 200, &full_page_of_prereleases());
        }
        let err = plan(&http, &me(v(0, 1, 0), None), &Want::Latest, false).unwrap_err();
        assert!(err.contains("more than"), "{err}");
        assert_eq!(http.urls().len(), RELEASE_PAGES);
    }

    #[test]
    fn a_short_first_page_is_the_whole_list() {
        let http = github();
        plan(&http, &me(v(0, 1, 0), None), &Want::Latest, false).unwrap();
        assert_eq!(http.urls(), [RELEASES, COMMIT_V2]);
    }

    #[test]
    fn a_missing_release_is_refused_after_the_release_list_alone() {
        let http = github();
        let want = Want::Version(v(0, 9, 0));
        let planned = plan(&http, &me(v(0, 1, 0), Some(SHA_A)), &want, false).unwrap();
        assert_eq!(planned, Planned::Refused(Refusal::NotReleased(v(0, 9, 0))));
        assert_eq!(http.urls(), [RELEASES]);

        let http = FakeHttp::new().reply(RELEASES, 200, b"[]");
        let planned = plan(&http, &me(v(0, 1, 0), Some(SHA_A)), &Want::Latest, false).unwrap();
        assert_eq!(planned, Planned::Refused(Refusal::NoReleases));
    }

    #[test]
    fn a_comparison_github_cannot_make_is_refused_unless_downgrades_are_allowed() {
        let http = github().reply(COMPARE_V2, 404, b"{}");
        let installed = me(v(0, 1, 0), Some(SHA_A));
        assert_eq!(
            plan(&http, &installed, &Want::Latest, false).unwrap(),
            Planned::Refused(Refusal::NotOnGithub)
        );
        assert!(matches!(
            plan(&http, &installed, &Want::Latest, true).unwrap(),
            Planned::Install { .. }
        ));
    }

    #[test]
    fn behind_and_diverged_are_refused_and_identical_is_up_to_date() {
        let installed = me(v(0, 1, 0), Some(SHA_A));
        for (status, expected) in [
            ("behind", Some(Refusal::Behind)),
            ("diverged", Some(Refusal::Diverged)),
            ("identical", None),
        ] {
            let http = github().reply(COMPARE_V2, 200, &compare(status));
            let planned = plan(&http, &installed, &Want::Latest, false).unwrap();
            match expected {
                Some(refusal) => assert_eq!(planned, Planned::Refused(refusal)),
                None => assert!(matches!(planned, Planned::UpToDate { .. }), "{planned:?}"),
            }
        }
    }

    #[test]
    fn a_reply_that_is_not_what_was_asked_for_is_an_error_not_a_decision() {
        let installed = me(v(0, 1, 0), Some(SHA_A));
        let cases = [
            // The release list
            FakeHttp::new().reply(RELEASES, 200, b"<html>"),
            FakeHttp::new().reply(RELEASES, 500, b""),
            FakeHttp::new().fails(RELEASES, "curl failed (6): no host"),
            // The commit
            FakeHttp::new()
                .reply(RELEASES, 200, &releases(&["v0.2.0"]))
                .reply(COMMIT_V2, 200, b"v0.2.0"),
            FakeHttp::new()
                .reply(RELEASES, 200, &releases(&["v0.2.0"]))
                .reply(COMMIT_V2, 404, b""),
            // The comparison
            github().reply(COMPARE_V2, 200, &compare("sideways")),
            github().reply(COMPARE_V2, 200, b"{}"),
            github().reply(COMPARE_V2, 500, b""),
            github().reply(COMPARE_V2, 200, b"oops"),
            github(),
        ];
        for http in cases {
            assert!(plan(&http, &installed, &Want::Latest, true).is_err());
        }
    }

    #[test]
    fn a_rate_limit_says_so() {
        let installed = me(v(0, 1, 0), Some(SHA_A));
        for status in [403, 429] {
            for http in [
                FakeHttp::new().reply(RELEASES, status, b"{}"),
                github().reply(COMPARE_V2, status, b"{}"),
                FakeHttp::new()
                    .reply(RELEASES, 200, &releases(&["v0.2.0"]))
                    .reply(COMMIT_V2, status, b"{}"),
            ] {
                let err = plan(&http, &installed, &Want::Latest, false).unwrap_err();
                assert!(err.contains("60 an hour"), "{err}");
            }
        }
    }

    struct FakeRunner {
        calls: RefCell<Vec<String>>,
        code: i32,
    }

    impl Runner for FakeRunner {
        fn run(&self, program: &str, args: &[OsString]) -> io::Result<i32> {
            let args: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
            self.calls
                .borrow_mut()
                .push(format!("{program} {}", args.join(" ")));
            Ok(self.code)
        }
    }

    struct Session {
        http: FakeHttp,
        runner: FakeRunner,
        temp: PathBuf,
    }

    impl Session {
        fn new(http: FakeHttp, code: i32) -> Self {
            let temp = std::env::temp_dir().join(format!(
                "obdcracker-update-flow-{}-{}",
                std::process::id(),
                std::thread::current()
                    .name()
                    .unwrap_or("t")
                    .replace("::", "-")
            ));
            let _ = std::fs::remove_dir_all(&temp);
            std::fs::create_dir_all(&temp).unwrap();
            Session {
                http,
                runner: FakeRunner {
                    calls: RefCell::new(Vec::new()),
                    code,
                },
                temp,
            }
        }

        // Returns the exit code, standard output and standard error
        fn run(&self, options: &Options, installed: &Installed) -> (u8, String, String) {
            let setup = Setup {
                http: &self.http,
                runner: &self.runner,
                exe: Path::new("/nonexistent/obdcracker"),
                temp_dir: &self.temp,
                windows: false,
            };
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = run(options, installed, &setup, &mut out, &mut err);
            (
                code,
                String::from_utf8(out).unwrap(),
                String::from_utf8(err).unwrap(),
            )
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.temp);
        }
    }

    fn options(want: Want, allow_downgrade: bool, dry_run: bool) -> Options {
        Options {
            want,
            allow_downgrade,
            dry_run,
        }
    }

    fn newer_than_installed() -> FakeHttp {
        github()
            .reply(COMPARE_V2, 200, &compare("ahead"))
            .reply(SCRIPT_URL, 200, SCRIPT)
    }

    #[test]
    fn a_dry_run_reports_the_command_and_downloads_and_runs_nothing() {
        let session = Session::new(newer_than_installed(), 0);
        let installed = me(v(0, 1, 0), Some(SHA_A));
        let (code, out, err) = session.run(&options(Want::Latest, false, true), &installed);
        assert_eq!(code, 0, "{err}");
        assert!(
            out.contains("would replace 0.1.0 (commit aaaaaaa) with v0.2.0 (commit bbbbbbb)"),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "would download {SCRIPT_URL} and run: sh install.sh --ref {SHA_B}"
            )),
            "{out}"
        );
        assert!(out.contains("nothing was downloaded or installed"), "{out}");
        assert_eq!(session.http.urls(), [RELEASES, COMMIT_V2, COMPARE_V2]);
        assert!(session.runner.calls.borrow().is_empty());
    }

    #[test]
    fn an_update_installs_the_commit_that_was_looked_up_and_says_so() {
        let session = Session::new(newer_than_installed(), 0);
        let installed = me(v(0, 1, 0), Some(SHA_A));
        let (code, out, err) = session.run(&options(Want::Latest, false, false), &installed);
        assert_eq!(code, 0, "{err}");
        assert!(
            out.contains("replacing 0.1.0 (commit aaaaaaa) with v0.2.0 (commit bbbbbbb)"),
            "{out}"
        );
        assert!(out.contains("updated to v0.2.0 (commit bbbbbbb)"), "{out}");
        assert_eq!(
            session.http.urls(),
            [RELEASES, COMMIT_V2, COMPARE_V2, SCRIPT_URL]
        );
        let calls = session.runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("sh "), "{calls:?}");
        assert!(
            calls[0].ends_with(&format!("install.sh --ref {SHA_B}")),
            "{calls:?}"
        );
    }

    #[test]
    fn a_replacement_with_the_flag_names_both_builds_before_it_installs() {
        let http = github()
            .reply(COMPARE_V2, 200, &compare("behind"))
            .reply(SCRIPT_URL, 200, SCRIPT);
        let session = Session::new(http, 0);
        let installed = me(v(0, 3, 0), Some(SHA_A));
        let (code, out, err) = session.run(&options(Want::Latest, true, false), &installed);
        assert_eq!(code, 0, "{err}");
        assert!(
            out.starts_with("replacing 0.3.0 (commit aaaaaaa) with v0.2.0 (commit bbbbbbb)"),
            "{out}"
        );
    }

    #[test]
    fn on_windows_an_update_removes_the_old_program_a_dry_run_leaves_it() {
        let session = Session::new(newer_than_installed(), 0);
        let exe = session.temp.join("obdcracker.exe");
        let old = session.temp.join(install::OLD_NAME);
        let installed = me(v(0, 1, 0), Some(SHA_A));
        for (dry_run, left) in [(true, true), (false, false)] {
            std::fs::write(&old, b"stale").unwrap();
            let setup = Setup {
                http: &session.http,
                runner: &session.runner,
                exe: &exe,
                temp_dir: &session.temp,
                windows: true,
            };
            let options = options(Want::Latest, false, dry_run);
            // Not installed: the program isn't there to move aside, so a real run stops there
            let _ = run(
                &options,
                &installed,
                &setup,
                &mut Vec::new(),
                &mut Vec::new(),
            );
            assert_eq!(old.exists(), left, "dry run: {dry_run}");
        }
    }

    #[test]
    fn an_unknown_installed_commit_is_named_as_unknown() {
        let session = Session::new(newer_than_installed(), 0);
        let (_, out, _) = session.run(&options(Want::Latest, false, true), &me(v(0, 1, 0), None));
        assert!(
            out.contains("would replace 0.1.0 (unknown commit) with"),
            "{out}"
        );
    }

    #[test]
    fn the_script_s_failure_code_is_the_exit_code() {
        for (script, expected) in [(2, 2), (255, 255), (256, 1), (-1, 1), (1000, 1)] {
            let session = Session::new(newer_than_installed(), script);
            let installed = me(v(0, 1, 0), Some(SHA_A));
            let (code, out, err) = session.run(&options(Want::Latest, false, false), &installed);
            assert_eq!(code, expected, "{script}");
            assert!(err.contains("the install script failed"), "{err}");
            assert!(!out.contains("updated to"), "{out}");
        }
    }

    #[test]
    fn a_refusal_exits_1_names_the_reason_and_runs_nothing() {
        let session = Session::new(newer_than_installed(), 0);
        let installed = me(v(0, 3, 0), Some(SHA_A));
        let (code, out, err) = session.run(&options(Want::Latest, false, false), &installed);
        assert_eq!(code, 1);
        assert!(
            err.contains("not updating") && err.contains("--allow-downgrade"),
            "{err}"
        );
        assert_eq!(out, "");
        assert!(session.runner.calls.borrow().is_empty());
        assert!(!session.http.urls().contains(&SCRIPT_URL.to_owned()));
    }

    #[test]
    fn being_up_to_date_exits_0_and_runs_nothing() {
        let session = Session::new(newer_than_installed(), 0);
        let installed = me(v(0, 2, 0), Some(SHA_B));
        let (code, out, _) = session.run(&options(Want::Latest, false, false), &installed);
        assert_eq!(code, 0);
        assert!(
            out.contains("already up to date: v0.2.0 (commit bbbbbbb)"),
            "{out}"
        );
        assert!(session.runner.calls.borrow().is_empty());
        let (code, out, _) = session.run(&options(Want::Main, false, false), &installed);
        assert_eq!(code, 0);
        assert!(
            out.contains("already up to date: main (commit bbbbbbb)"),
            "{out}"
        );
    }

    #[test]
    fn a_network_error_exits_1_and_runs_nothing() {
        let session = Session::new(
            FakeHttp::new().fails(RELEASES, "curl failed (6): no host"),
            0,
        );
        let installed = me(v(0, 1, 0), Some(SHA_A));
        let (code, _, err) = session.run(&options(Want::Latest, false, false), &installed);
        assert_eq!(code, 1);
        assert!(err.starts_with("error: curl failed"), "{err}");
        assert!(session.runner.calls.borrow().is_empty());
    }

    #[test]
    fn a_script_that_cannot_be_downloaded_exits_1_and_runs_nothing() {
        let http = github()
            .reply(COMPARE_V2, 200, &compare("ahead"))
            .reply(SCRIPT_URL, 404, b"");
        let session = Session::new(http, 0);
        let installed = me(v(0, 1, 0), Some(SHA_A));
        let (code, out, err) = session.run(&options(Want::Latest, false, false), &installed);
        assert_eq!(code, 1);
        assert!(err.contains("HTTP 404"), "{err}");
        assert!(!out.contains("updated to"), "{out}");
        assert!(session.runner.calls.borrow().is_empty());
    }

    #[test]
    fn the_installed_build_is_read_from_the_version_and_commit_a_build_records() {
        let known = Installed::from_build("0.1.0", SHA_A).unwrap();
        assert_eq!(known, me(v(0, 1, 0), Some(SHA_A)));
        assert_eq!(
            Installed::from_build("0.1.0", "unknown").unwrap().commit,
            None
        );
        // Anything that isn't a full commit is not one to compare
        assert_eq!(Installed::from_build("0.1.0", "main").unwrap().commit, None);
        assert_eq!(
            Installed::from_build("0.1.0", &SHA_A[..39]).unwrap().commit,
            None
        );
        assert!(Installed::from_build("0.1", SHA_A).is_err());
        assert!(Installed::from_build("0.1.0-rc1", SHA_A).is_err());
    }
}
