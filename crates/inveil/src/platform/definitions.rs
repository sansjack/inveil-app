//! Text of the files that register the background service on each OS. Pure functions so they are tested on every
//! platform, including with hostile paths.
use super::escape::{systemd_quote, windows_command_line, xml_escape};
use super::PlatformError;

/// The Task Scheduler maximum, so the task keeps restarting after repeated crashes.
const RESTART_ATTEMPTS: u32 = 999;

pub(super) fn launch_agent_plist(label: &str, command: &[String]) -> Result<String, PlatformError> {
    let arguments = command
        .iter()
        .map(|argument| {
            xml_escape(argument).map(|escaped| format!("    <string>{escaped}</string>\n"))
        })
        .collect::<Result<String, _>>()?;
    let label = xml_escape(label)?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{arguments}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
"#
    ))
}

#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(super) fn systemd_user_unit(
    description: &str,
    command: &[String],
) -> Result<String, PlatformError> {
    if description.chars().any(char::is_control) {
        return Err(PlatformError::InvalidArgument(
            "unit description contains a control character".to_string(),
        ));
    }
    let exec_start = command
        .iter()
        .map(|argument| systemd_quote(argument))
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    Ok(format!(
        "[Unit]\nDescription={description}\nAfter=network-online.target\n\n\
         [Service]\nType=simple\nExecStart={exec_start}\nRestart=on-failure\nRestartSec=5\n\n\
         [Install]\nWantedBy=default.target\n"
    ))
}

/// Task Scheduler definition: starts at the user's logon, runs unelevated, and restarts after a failure.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn scheduled_task_xml(user: &str, command: &[String]) -> Result<String, PlatformError> {
    let (program, arguments) = command.split_first().ok_or_else(|| {
        PlatformError::InvalidArgument("the service command is empty".to_string())
    })?;
    let user = xml_escape(user)?;
    let program = xml_escape(program)?;
    let arguments = xml_escape(&windows_command_line(arguments))?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Inveil local data-loss-prevention proxy</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>{RESTART_ATTEMPTS}</Count>
    </RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{program}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTILE_PATH: &str =
        "/Users/o'brien & <co>/$(touch pwned)/inveil\nExecStartPre=/bin/evil";

    fn command(path: &str) -> Vec<String> {
        vec![
            path.to_string(),
            "run".to_string(),
            "--log-file".to_string(),
            format!("{path}.log"),
        ]
    }

    #[test]
    fn plist_lists_each_argument_and_keeps_the_service_alive() {
        let plist = launch_agent_plist(
            "com.inveil.proxy",
            &command("/Users/me/Library/Application Support/inveil/inveil"),
        )
        .unwrap();
        assert!(plist.contains("<string>com.inveil.proxy</string>"));
        assert!(
            plist.contains("<string>/Users/me/Library/Application Support/inveil/inveil</string>")
        );
        assert!(plist.contains("<string>--log-file</string>"));
        assert!(plist.contains("<key>KeepAlive</key>\n  <true/>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>"));
    }

    #[test]
    fn plist_escapes_markup_in_paths_so_it_cannot_add_keys() {
        let plist = launch_agent_plist(
            "l",
            &command("/a/</string><key>RunAtLoad</key><true/><string>/b & c"),
        )
        .unwrap();
        assert_eq!(plist.matches("<key>").count(), 5);
        assert!(plist.contains("&lt;/string&gt;&lt;key&gt;RunAtLoad"));
        assert!(plist.contains("&amp; c"));
    }

    #[test]
    fn plist_rejects_paths_with_newlines() {
        assert!(launch_agent_plist("l", &command(HOSTILE_PATH)).is_err());
    }

    #[test]
    fn systemd_unit_restarts_on_failure_and_starts_with_the_user_session() {
        let unit =
            systemd_user_unit("Inveil", &command("/home/me/.local/share/inveil/inveil")).unwrap();
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(unit.contains(r#"ExecStart="/home/me/.local/share/inveil/inveil" "run" "--log-file" "/home/me/.local/share/inveil/inveil.log""#));
    }

    #[test]
    fn systemd_unit_keeps_hostile_paths_on_the_exec_start_line() {
        let unit = systemd_user_unit("Inveil", &command(HOSTILE_PATH)).unwrap();
        let exec_lines = unit
            .lines()
            .filter(|line| line.starts_with("ExecStart"))
            .count();
        assert_eq!(exec_lines, 1);
        assert!(!unit.lines().any(|line| line.starts_with("ExecStartPre")));
        assert!(unit.contains("$$(touch pwned)"));
    }

    #[test]
    fn systemd_unit_rejects_a_description_with_a_newline() {
        assert!(systemd_user_unit("x\nExecStart=/bin/evil", &command("/a")).is_err());
    }

    #[test]
    fn task_xml_runs_unelevated_at_logon_and_restarts_on_failure() {
        let xml = scheduled_task_xml(
            r"PC\me",
            &command(r"C:\Users\me\AppData\Local\inveil\inveil.exe"),
        )
        .unwrap();
        assert!(xml.contains("<LogonTrigger>"));
        assert!(xml.contains("<UserId>PC\\me</UserId>"));
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(xml.contains("<RestartOnFailure>"));
        assert!(xml.contains(r"<Command>C:\Users\me\AppData\Local\inveil\inveil.exe</Command>"));
        assert!(xml.contains(
            r"<Arguments>run --log-file C:\Users\me\AppData\Local\inveil\inveil.exe.log</Arguments>"
        ));
    }

    #[test]
    fn task_xml_quotes_arguments_with_spaces_and_escapes_markup() {
        let xml =
            scheduled_task_xml("PC\\me", &command(r"C:\Program Files\a&b\<x>\inveil.exe")).unwrap();
        assert!(xml.contains(r"<Command>C:\Program Files\a&amp;b\&lt;x&gt;\inveil.exe</Command>"));
        assert!(xml
            .contains(r"--log-file &quot;C:\Program Files\a&amp;b\&lt;x&gt;\inveil.exe.log&quot;"));
        assert!(!xml.contains("<x>"));
    }

    #[test]
    fn task_xml_escapes_the_user_name() {
        let xml =
            scheduled_task_xml("DOMAIN\\a</UserId><UserId>admin", &command("C:\\a.exe")).unwrap();
        assert_eq!(xml.matches("<UserId>").count(), 2);
    }

    #[test]
    fn task_xml_rejects_an_empty_command() {
        assert!(scheduled_task_xml("PC\\me", &[]).is_err());
    }
}
