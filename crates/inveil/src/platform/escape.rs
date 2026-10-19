//! Quoting and escaping for the formats the service definitions and helper commands are written in. Each function
//! returns an error rather than a lossy result when the input cannot be represented.
use super::PlatformError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

const UTF16_LE_BYTE_ORDER_MARK: [u8; 2] = [0xFF, 0xFE];

/// POSIX shell single-quoting: the value is always one word and nothing inside it is interpreted.
pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

pub(super) fn shell_join(arguments: &[String]) -> String {
    arguments
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Escapes text for an XML element body. Control characters are not representable in XML 1.0 and are rejected.
pub(super) fn xml_escape(value: &str) -> Result<String, PlatformError> {
    if let Some(control) = value.chars().find(|character| character.is_control()) {
        return Err(PlatformError::InvalidArgument(format!(
            "control character {control:?} cannot be written to XML"
        )));
    }
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    Ok(escaped)
}

/// Quotes one word of a systemd `ExecStart=` line. `%` and `$` would otherwise be expanded by systemd.
pub(super) fn systemd_quote(value: &str) -> Result<String, PlatformError> {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str(r"\\"),
            '"' => quoted.push_str(r#"\""#),
            '%' => quoted.push_str("%%"),
            '$' => quoted.push_str("$$"),
            '\n' => quoted.push_str(r"\n"),
            '\t' => quoted.push_str(r"\t"),
            control if control.is_control() => {
                return Err(PlatformError::InvalidArgument(format!(
                    "control character {control:?} cannot be written to a systemd unit"
                )));
            }
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

/// Quotes one argument for a Windows command line so that `CommandLineToArgvW` splits it back into the same value.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn windows_quote_argument(value: &str) -> String {
    let needs_quotes = value.is_empty() || value.contains([' ', '\t', '\n', '\x0B', '"']);
    if !needs_quotes {
        return value.to_string();
    }
    let mut quoted = String::from('"');
    let mut backslashes = 0;
    for character in value.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            other => {
                quoted.push_str(&"\\".repeat(backslashes));
                quoted.push(other);
                backslashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn windows_command_line(arguments: &[String]) -> String {
    arguments
        .iter()
        .map(|argument| windows_quote_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The form `powershell -EncodedCommand` takes: base64 of the UTF-16LE script. Keeps the script out of any quoting.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn powershell_encoded_command(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    STANDARD.encode(bytes)
}

/// `schtasks /XML` only reads UTF-16 with a byte order mark.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn utf16_le_with_byte_order_mark(text: &str) -> Vec<u8> {
    let mut bytes = UTF16_LE_BYTE_ORDER_MARK.to_vec();
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const INJECTIONS: [&str; 7] = [
        r#"a"b"#,
        "a'b",
        "a\nb",
        "a&b",
        "a<b>c",
        "$(touch /tmp/pwned)",
        "`id`; rm -rf ~",
    ];

    #[test]
    fn shell_quote_keeps_every_injection_attempt_inside_one_word() {
        for attempt in INJECTIONS {
            let quoted = shell_quote(attempt);
            assert!(
                quoted.starts_with('\'') && quoted.ends_with('\''),
                "{quoted}"
            );
            assert_eq!(
                quoted.matches(r"'\''").count(),
                attempt.matches('\'').count(),
                "{quoted}"
            );
        }
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("$(id)"), "'$(id)'");
    }

    #[test]
    fn shell_join_quotes_each_argument_separately() {
        let arguments = [
            "networksetup".to_string(),
            "-setautoproxyurl".to_string(),
            "Wi-Fi; reboot".to_string(),
        ];
        assert_eq!(
            shell_join(&arguments),
            "'networksetup' '-setautoproxyurl' 'Wi-Fi; reboot'"
        );
    }

    #[test]
    fn shell_quoted_text_round_trips_through_a_real_shell() {
        if cfg!(windows) {
            return;
        }
        for attempt in INJECTIONS {
            let output = std::process::Command::new("sh")
                .args(["-c", &format!("printf %s {}", shell_quote(attempt))])
                .output()
                .unwrap();
            assert_eq!(String::from_utf8(output.stdout).unwrap(), attempt);
        }
    }

    #[test]
    fn xml_escape_neutralises_markup() {
        assert_eq!(
            xml_escape("</string><key>x</key>").unwrap(),
            "&lt;/string&gt;&lt;key&gt;x&lt;/key&gt;"
        );
        assert_eq!(
            xml_escape(r#"a&b "c" 'd'"#).unwrap(),
            "a&amp;b &quot;c&quot; &apos;d&apos;"
        );
        assert_eq!(xml_escape("$(id)").unwrap(), "$(id)");
    }

    #[test]
    fn xml_escape_rejects_control_characters() {
        assert!(xml_escape("a\nb").is_err());
        assert!(xml_escape("a\0b").is_err());
    }

    #[test]
    fn systemd_quote_disables_specifier_and_variable_expansion() {
        assert_eq!(
            systemd_quote("/home/a b/inveil").unwrap(),
            r#""/home/a b/inveil""#
        );
        assert_eq!(systemd_quote("100%$HOME").unwrap(), r#""100%%$$HOME""#);
        assert_eq!(systemd_quote(r#"a"b\c"#).unwrap(), r#""a\"b\\c""#);
        assert_eq!(
            systemd_quote("a\nExecStartPre=/bin/evil").unwrap(),
            r#""a\nExecStartPre=/bin/evil""#
        );
    }

    #[test]
    fn systemd_quote_rejects_other_control_characters() {
        assert!(systemd_quote("a\0b").is_err());
    }

    #[test]
    fn windows_arguments_follow_the_command_line_parsing_rules() {
        assert_eq!(windows_quote_argument("plain"), "plain");
        assert_eq!(windows_quote_argument(""), r#""""#);
        assert_eq!(
            windows_quote_argument(r"C:\Program Files\inveil.exe"),
            r#""C:\Program Files\inveil.exe""#
        );
        assert_eq!(windows_quote_argument(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(
            windows_quote_argument(r"C:\dir with space\"),
            r#""C:\dir with space\\""#
        );
        assert_eq!(windows_quote_argument(r#"a\"b c"#), r#""a\\\"b c""#);
        assert_eq!(windows_quote_argument("a&b c"), r#""a&b c""#);
    }

    #[test]
    fn powershell_encoded_command_is_base64_of_utf16_little_endian() {
        let encoded = powershell_encoded_command("$x = 1");
        let bytes = STANDARD.decode(encoded).unwrap();
        let units: Vec<u16> = bytes
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).unwrap(), "$x = 1");
    }

    #[test]
    fn task_files_start_with_the_utf16_byte_order_mark() {
        assert_eq!(
            utf16_le_with_byte_order_mark("<a"),
            [0xFF, 0xFE, b'<', 0, b'a', 0]
        );
    }
}
