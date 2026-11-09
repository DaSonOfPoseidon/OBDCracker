//! Downloading the install script for a commit and running it. See docs/install.md#updating.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use super::http::{Accept, Http};
use super::{ok_body, script_url};

// The install scripts are a few tens of kilobytes.
const SCRIPT_LIMIT: usize = 1 << 20;

// Where the running program goes while its replacement is installed: Windows won't overwrite or
// delete a running .exe, but it will rename one.
pub(super) const OLD_NAME: &str = "obdcracker.old.exe";
// The copy made of it, renamed to the program's own name so the path is never empty
const COPY_NAME: &str = "obdcracker.copy.exe";

/// Runs a program, waits for it and gives its exit code.
pub(crate) trait Runner {
    fn run(&self, program: &str, args: &[OsString]) -> io::Result<i32>;
}

#[derive(Debug)]
pub(crate) struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[OsString]) -> io::Result<i32> {
        // A program ended by a signal has no code, and isn't a success
        Ok(Command::new(program)
            .args(args)
            .status()?
            .code()
            .unwrap_or(1))
    }
}

/// Everything installing touches outside the decision.
pub(crate) struct Setup<'a> {
    pub(crate) http: &'a dyn Http,
    pub(crate) runner: &'a dyn Runner,
    /// The running program's own file.
    pub(crate) exe: &'a Path,
    pub(crate) temp_dir: &'a Path,
    pub(crate) windows: bool,
}

pub(super) fn script_name(windows: bool) -> &'static str {
    if windows { "install.ps1" } else { "install.sh" }
}

/// The program and arguments that run the script at `path`, building exactly commit `sha`.
pub(super) fn command(windows: bool, path: &Path, sha: &str) -> (&'static str, Vec<OsString>) {
    if windows {
        let args = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]
            .map(OsString::from)
            .into_iter()
            .chain([path.into(), "-Ref".into(), sha.into()])
            .collect();
        ("powershell", args)
    } else {
        ("sh", vec![path.into(), "--ref".into(), sha.into()])
    }
}

// Not a page of HTML or an empty file in place of the script
fn check_script(body: &[u8], windows: bool) -> Result<(), String> {
    let name = script_name(windows);
    let plausible = !body.contains(&0)
        && if windows {
            body.iter()
                .find(|b| !b.is_ascii_whitespace())
                .is_some_and(|&b| b != b'<')
        } else {
            body.starts_with(b"#!/bin/sh\n")
        };
    if plausible {
        Ok(())
    } else {
        Err(format!("what GitHub sent for {name} isn't the script"))
    }
}

/// Removes the `obdcracker.old.exe` an earlier update left beside `exe`, and the copy of it a
/// cancelled one may have. The old one stays only while something still runs it.
pub(super) fn remove_stale(exe: &Path) {
    for name in [OLD_NAME, COPY_NAME] {
        let _ = fs::remove_file(exe.with_file_name(name));
    }
}

/// Downloads the install script at `sha` and runs it, giving its exit code. On Windows the
/// running program is renamed out of the way first, with a copy left in its place, and put back
/// if the script left nothing there.
pub(crate) fn run(setup: &Setup, sha: &str) -> Result<i32, String> {
    let name = script_name(setup.windows);
    let reply = setup
        .http
        .get(&script_url(sha, name), Accept::Plain, SCRIPT_LIMIT)?;
    let body = ok_body(reply, &format!("{name} at commit {sha}"))?;
    check_script(&body, setup.windows)?;
    let dir = TempDir::create(setup.temp_dir)
        .map_err(|e| format!("couldn't make a folder for {name}: {e}"))?;
    let path = dir.path().join(name);
    write_new(&path, &body).map_err(|e| format!("couldn't save {name}: {e}"))?;
    let (program, args) = command(setup.windows, &path, sha);
    let aside = if setup.windows {
        Some(Aside::new(setup.exe).map_err(|e| {
            format!(
                "couldn't move {} out of the way to replace it: {e}",
                setup.exe.display()
            )
        })?)
    } else {
        None
    };
    let ran = setup.runner.run(program, &args);
    // Before anything is reported, so a failed install never leaves the tool missing
    if let Some(aside) = aside {
        aside.put_back_if_missing()?;
    }
    ran.map_err(|e| format!("couldn't run {program}: {e}"))
}

struct Aside {
    exe: PathBuf,
    old: PathBuf,
}

impl Aside {
    // Windows can't overwrite a running program but can rename it. A copy goes in its place, so
    // the path never stays empty for long: the process is ended without cleanup by Ctrl+C on a
    // console, and nothing here would run after it.
    fn new(exe: &Path) -> io::Result<Self> {
        let old = exe.with_file_name(OLD_NAME);
        let copy = exe.with_file_name(COPY_NAME);
        fs::copy(exe, &copy)?;
        let moved = fs::rename(exe, &old).and_then(|()| fs::rename(&copy, exe));
        if let Err(e) = moved {
            if !exe.exists() {
                let _ = fs::rename(&old, exe);
            }
            let _ = fs::remove_file(&copy);
            return Err(e);
        }
        Ok(Aside {
            exe: exe.to_owned(),
            old,
        })
    }

    // The script puts the new program where the old one was, or somewhere else, which leaves the
    // old path empty.
    fn put_back_if_missing(self) -> Result<(), String> {
        if self.exe.exists() {
            return Ok(());
        }
        fs::rename(&self.old, &self.exe).map_err(|e| {
            format!(
                "the install didn't put a program at {}, and the old one couldn't be put back: {e}; \
                 it is at {}",
                self.exe.display(),
                self.old.display()
            )
        })
    }
}

// A folder only this user can open, so no one else can swap the script between its saving and its
// running; removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn create(parent: &Path) -> io::Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        for attempt in 0..16 {
            let path = parent.join(format!(
                "obdcracker-update-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match private_dir().create(&path) {
                Ok(()) => return Ok(TempDir(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::ErrorKind::AlreadyExists.into())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_dir() -> DirBuilder {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
}

fn write_new(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(body)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::super::http::fake::FakeHttp;
    use super::*;

    const SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SH_URL: &str = "https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/scripts/install.sh";
    const PS1_URL: &str = "https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/scripts/install.ps1";
    const SCRIPT: &[u8] = b"#!/bin/sh\necho installing\n";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "obdcracker-install-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    type Act = Box<dyn Fn(&str, &[OsString]) -> io::Result<i32>>;

    struct FakeRunner {
        calls: RefCell<Vec<(String, Vec<String>)>>,
        act: Act,
    }

    impl FakeRunner {
        fn new(act: impl Fn(&str, &[OsString]) -> io::Result<i32> + 'static) -> Self {
            FakeRunner {
                calls: RefCell::new(Vec::new()),
                act: Box::new(act),
            }
        }

        fn exits(code: i32) -> Self {
            Self::new(move |_, _| Ok(code))
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, program: &str, args: &[OsString]) -> io::Result<i32> {
            let shown = args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            self.calls.borrow_mut().push((program.to_owned(), shown));
            (self.act)(program, args)
        }
    }

    #[test]
    fn the_script_is_run_with_sh_on_unix_and_powershell_on_windows() {
        let path = Path::new("/tmp/x/install.sh");
        let (program, args) = command(false, path, SHA);
        assert_eq!(program, "sh");
        assert_eq!(args, [path.as_os_str(), "--ref".as_ref(), SHA.as_ref()]);
        let path = Path::new("C:\\Temp\\x\\install.ps1");
        let (program, args) = command(true, path, SHA);
        assert_eq!(program, "powershell");
        assert_eq!(
            args,
            [
                "-NoProfile".as_ref(),
                "-ExecutionPolicy".as_ref(),
                "Bypass".as_ref(),
                "-File".as_ref(),
                path.as_os_str(),
                "-Ref".as_ref(),
                SHA.as_ref()
            ]
        );
        assert_eq!(script_name(false), "install.sh");
        assert_eq!(script_name(true), "install.ps1");
    }

    #[test]
    fn something_that_is_not_a_script_is_refused() {
        assert!(check_script(SCRIPT, false).is_ok());
        for bad in [
            &b""[..],
            b"<!DOCTYPE html><html>",
            b"echo hi\n",
            b"#!/bin/sh",
            b"#!/bin/sh\n\0",
        ] {
            assert!(check_script(bad, false).is_err(), "{bad:?}");
        }
        assert!(check_script(b"param(\n)\n", true).is_ok());
        assert!(check_script("\u{feff}# x\n".as_bytes(), true).is_ok());
        for bad in [&b""[..], b"  \n", b"<html>", b" <html>", b"a\0b"] {
            assert!(check_script(bad, true).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_script_downloaded_at_the_commit_is_run_and_its_code_passed_back() {
        let temp = scratch("run");
        for code in [0, 1, 7] {
            let http = FakeHttp::new().reply(SH_URL, 200, SCRIPT);
            let seen = std::rc::Rc::new(RefCell::new(Vec::new()));
            let seen_in = seen.clone();
            let runner = FakeRunner::new(move |_, args| {
                // The file is there, with the downloaded content, while the script runs
                seen_in.borrow_mut().push(fs::read(&args[0]).unwrap());
                Ok(code)
            });
            let setup = Setup {
                http: &http,
                runner: &runner,
                exe: Path::new("/nonexistent/obdcracker"),
                temp_dir: &temp,
                windows: false,
            };
            assert_eq!(run(&setup, SHA), Ok(code));
            assert_eq!(http.urls(), [SH_URL]);
            assert_eq!(http.accepts(), [Accept::Plain]);
            assert_eq!(*seen.borrow(), [SCRIPT.to_vec()]);
            let calls = runner.calls.borrow();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, "sh");
            assert!(calls[0].1[0].ends_with("install.sh"));
            assert_eq!(calls[0].1[1..], ["--ref", SHA]);
            // Nothing of the download is left
            assert_eq!(names(&temp), Vec::<String>::new());
        }
        let _ = fs::remove_dir_all(&temp);
    }

    #[cfg(unix)]
    #[test]
    fn the_downloaded_script_is_in_a_folder_only_its_user_can_open() {
        use std::os::unix::fs::PermissionsExt;
        let temp = scratch("modes");
        let http = FakeHttp::new().reply(SH_URL, 200, SCRIPT);
        let runner = FakeRunner::new(|_, args| {
            let file = Path::new(&args[0]);
            let dir_mode = fs::metadata(file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            let file_mode = fs::metadata(file).unwrap().permissions().mode();
            Ok(i32::from(dir_mode & 0o077 != 0 || file_mode & 0o077 != 0))
        });
        let setup = Setup {
            http: &http,
            runner: &runner,
            exe: Path::new("/nonexistent/obdcracker"),
            temp_dir: &temp,
            windows: false,
        };
        assert_eq!(run(&setup, SHA), Ok(0));
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn nothing_is_run_when_the_download_fails_or_is_not_a_script() {
        let temp = scratch("download");
        for http in [
            FakeHttp::new().reply(SH_URL, 404, b""),
            FakeHttp::new().reply(SH_URL, 200, b"<html>no</html>"),
            FakeHttp::new().reply(SH_URL, 200, b""),
            FakeHttp::new().reply(SH_URL, 500, b"oops"),
            FakeHttp::new().fails(SH_URL, "curl failed (6): no host"),
            FakeHttp::new(),
        ] {
            let runner = FakeRunner::exits(0);
            let setup = Setup {
                http: &http,
                runner: &runner,
                exe: Path::new("/nonexistent/obdcracker"),
                temp_dir: &temp,
                windows: false,
            };
            assert!(run(&setup, SHA).is_err());
            assert!(runner.calls.borrow().is_empty());
            assert_eq!(names(&temp), Vec::<String>::new());
        }
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn a_runner_that_cannot_start_the_script_is_an_error_and_cleans_up() {
        let temp = scratch("cannot-run");
        let http = FakeHttp::new().reply(SH_URL, 200, SCRIPT);
        let runner = FakeRunner::new(|_, _| Err(io::ErrorKind::NotFound.into()));
        let setup = Setup {
            http: &http,
            runner: &runner,
            exe: Path::new("/nonexistent/obdcracker"),
            temp_dir: &temp,
            windows: false,
        };
        let err = run(&setup, SHA).unwrap_err();
        assert!(err.contains("couldn't run sh"), "{err}");
        assert_eq!(names(&temp), Vec::<String>::new());
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn an_unusable_temp_dir_is_an_error_before_anything_runs() {
        let http = FakeHttp::new().reply(SH_URL, 200, SCRIPT);
        let runner = FakeRunner::exits(0);
        let setup = Setup {
            http: &http,
            runner: &runner,
            exe: Path::new("/nonexistent/obdcracker"),
            temp_dir: Path::new("/nonexistent/obdcracker-test/tmp"),
            windows: false,
        };
        assert!(run(&setup, SHA).is_err());
        assert!(runner.calls.borrow().is_empty());
    }

    fn windows_setup<'a>(
        http: &'a FakeHttp,
        runner: &'a FakeRunner,
        exe: &'a Path,
        temp: &'a Path,
    ) -> Setup<'a> {
        Setup {
            http,
            runner,
            exe,
            temp_dir: temp,
            windows: true,
        }
    }

    #[test]
    fn on_windows_the_running_program_is_moved_aside_while_the_script_runs() {
        let dir = scratch("aside-run");
        let temp = scratch("aside-run-temp");
        let exe = dir.join("obdcracker.exe");
        fs::write(&exe, b"old program").unwrap();
        let http = FakeHttp::new().reply(PS1_URL, 200, b"param()\n");
        let exe_in = exe.clone();
        let runner = FakeRunner::new(move |_, _| {
            // The running program is at its new name, and a copy that isn't running is in its
            // place: a script cancelled with Ctrl+C leaves a program that starts
            assert_eq!(fs::read(&exe_in).unwrap(), b"old program");
            assert_eq!(
                fs::read(exe_in.with_file_name(OLD_NAME)).unwrap(),
                b"old program"
            );
            fs::write(&exe_in, b"new program").unwrap();
            Ok(0)
        });
        assert_eq!(run(&windows_setup(&http, &runner, &exe, &temp), SHA), Ok(0));
        assert_eq!(fs::read(&exe).unwrap(), b"new program");
        // The old one stays until the next update removes it
        assert_eq!(fs::read(dir.join(OLD_NAME)).unwrap(), b"old program");
        let calls = runner.calls.borrow();
        assert_eq!(calls[0].0, "powershell");
        assert_eq!(
            calls[0].1[..4],
            ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]
        );
        assert_eq!(calls[0].1[5..], ["-Ref", SHA]);
        assert_eq!(http.urls(), [PS1_URL]);
        remove_stale(&exe);
        assert_eq!(names(&dir), ["obdcracker.exe"]);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn on_windows_a_script_that_removes_the_program_and_fails_gets_it_put_back() {
        let dir = scratch("aside-removed");
        let temp = scratch("aside-removed-temp");
        let exe = dir.join("obdcracker.exe");
        fs::write(&exe, b"old program").unwrap();
        let http = FakeHttp::new().reply(PS1_URL, 200, b"param()\n");
        let exe_in = exe.clone();
        let runner = FakeRunner::new(move |_, _| {
            fs::remove_file(&exe_in).unwrap();
            Ok(1)
        });
        assert_eq!(run(&windows_setup(&http, &runner, &exe, &temp), SHA), Ok(1));
        assert_eq!(fs::read(&exe).unwrap(), b"old program");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn on_windows_a_failed_script_leaves_the_old_program_where_it_was() {
        let dir = scratch("aside-fail");
        let temp = scratch("aside-fail-temp");
        let exe = dir.join("obdcracker.exe");
        fs::write(&exe, b"old program").unwrap();
        let http = FakeHttp::new().reply(PS1_URL, 200, b"param()\n");
        let runner = FakeRunner::exits(1);
        assert_eq!(run(&windows_setup(&http, &runner, &exe, &temp), SHA), Ok(1));
        assert_eq!(fs::read(&exe).unwrap(), b"old program");
        assert_eq!(names(&dir), ["obdcracker.exe", OLD_NAME]);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn on_windows_a_script_that_cannot_start_leaves_the_old_program_too() {
        let dir = scratch("aside-nostart");
        let temp = scratch("aside-nostart-temp");
        let exe = dir.join("obdcracker.exe");
        fs::write(&exe, b"old program").unwrap();
        let http = FakeHttp::new().reply(PS1_URL, 200, b"param()\n");
        let runner = FakeRunner::new(|_, _| Err(io::ErrorKind::NotFound.into()));
        assert!(run(&windows_setup(&http, &runner, &exe, &temp), SHA).is_err());
        assert_eq!(fs::read(&exe).unwrap(), b"old program");
        assert_eq!(names(&dir), ["obdcracker.exe", OLD_NAME]);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn on_windows_a_script_that_installs_elsewhere_still_leaves_this_program() {
        let dir = scratch("aside-elsewhere");
        let temp = scratch("aside-elsewhere-temp");
        let exe = dir.join("obdcracker.exe");
        fs::write(&exe, b"old program").unwrap();
        let http = FakeHttp::new().reply(PS1_URL, 200, b"param()\n");
        let runner = FakeRunner::exits(0);
        assert_eq!(run(&windows_setup(&http, &runner, &exe, &temp), SHA), Ok(0));
        assert_eq!(fs::read(&exe).unwrap(), b"old program");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn on_windows_nothing_runs_when_the_program_cannot_be_moved_aside() {
        let temp = scratch("aside-missing-temp");
        let exe = Path::new("/nonexistent/obdcracker-test/obdcracker.exe");
        let http = FakeHttp::new().reply(PS1_URL, 200, b"param()\n");
        let runner = FakeRunner::exits(0);
        let err = run(&windows_setup(&http, &runner, exe, &temp), SHA).unwrap_err();
        assert!(err.contains("out of the way"), "{err}");
        assert!(runner.calls.borrow().is_empty());
        assert_eq!(names(&temp), Vec::<String>::new());
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn a_stale_old_program_is_removed_and_its_absence_is_fine() {
        let dir = scratch("stale");
        let exe = dir.join("obdcracker.exe");
        fs::write(&exe, b"current").unwrap();
        remove_stale(&exe);
        fs::write(dir.join(OLD_NAME), b"stale").unwrap();
        fs::write(dir.join(COPY_NAME), b"half a copy").unwrap();
        remove_stale(&exe);
        assert_eq!(names(&dir), ["obdcracker.exe"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_script_is_saved_with_a_name_nothing_else_has_taken() {
        let temp = scratch("unique");
        let first = TempDir::create(&temp).unwrap();
        let second = TempDir::create(&temp).unwrap();
        assert_ne!(first.path(), second.path());
        let kept = first.path().to_owned();
        drop(first);
        assert!(!kept.exists());
        assert!(second.path().exists());
        let _ = fs::remove_dir_all(&temp);
    }
}
