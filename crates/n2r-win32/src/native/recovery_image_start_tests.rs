//! The start script of the recovery image: what it does with each way the
//! runner can end.
use super::*;

fn script() -> String {
    let bundle = [7u8; 32];
    let args = vec!["--bundle-sha256".to_owned(), hex::encode(bundle)];
    String::from_utf8(startup(&args, bundle).unwrap()).unwrap()
}

#[test]
fn the_start_script_restarts_on_success_and_on_a_cancelled_conversion_only() {
    let script = script();
    let lines: Vec<&str> = script.split("\r\n").collect();
    let at = |wanted: &str| {
        lines
            .iter()
            .position(|line| *line == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} is not a line of {script}"))
    };
    // The exit code is kept before anything else can change it, and the
    // code of a cancelled conversion is looked at before "not zero".
    let kept = at("set \"N2R_EXIT=%ERRORLEVEL%\"");
    let returned = at(&format!(
        "if \"%N2R_EXIT%\"==\"{RUNNER_EXIT_RETURNED_TO_NTFS}\" goto n2r_returned"
    ));
    let failed = at("if not \"%N2R_EXIT%\"==\"0\" goto n2r_failed");
    assert!(kept < returned && returned < failed, "{script}");
    // Each of the two branches that restart does so itself; the branch of
    // a failure does not, and leaves the console open.
    let reboot = "\"%SystemRoot%\\System32\\wpeutil.exe\" Reboot";
    let reboots: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == reboot)
        .map(|(index, _)| index)
        .collect();
    let (returned_label, failed_label, console_label) =
        (at(":n2r_returned"), at(":n2r_failed"), at(":n2r_console"));
    assert_eq!(reboots.len(), 2, "{script}");
    assert!(
        failed < reboots[0] && reboots[0] < returned_label,
        "{script}"
    );
    assert!(
        returned_label < reboots[1] && reboots[1] < failed_label,
        "{script}"
    );
    assert!(failed_label < console_label, "{script}");
    assert_eq!(
        lines[returned_label + 1],
        "echo The conversion was cancelled before anything was written to the volume. Windows starts again now."
    );
    assert_eq!(
        lines[failed_label + 1],
        "echo Conversion stopped. Preserve recovery artifacts and review the error above."
    );
    // A branch that restarts never falls into the next one.
    assert_eq!(lines[returned_label - 1], "goto n2r_console");
    assert_eq!(lines[failed_label - 1], "goto n2r_console");
    assert!(script.ends_with("exit /b %N2R_EXIT%\r\n"), "{script}");
}

#[test]
fn the_start_script_refuses_an_argument_the_shell_would_read() {
    let bundle = [7u8; 32];
    for unsafe_argument in ["a&b", "a%b", "a\"b", "a(b"] {
        let args = vec![hex::encode(bundle), unsafe_argument.to_owned()];
        assert!(startup(&args, bundle).is_err(), "{unsafe_argument}");
    }
    assert!(startup(&["--other".to_owned()], bundle).is_err());
}
