//! Live progress output for the commands people run by hand (`install`, `uninstall`, `update`, `health`): one line
//! per step, a spinner while it works, then a tick or a cross. Piped output, `NO_COLOR` and dumb terminals get the
//! same lines without the spinner or colour.
use ::console::{style, Term};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

const SPINNER_INTERVAL: Duration = Duration::from_millis(80);
const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✔"];

pub fn heading(text: &str) {
    println!("\n{}\n", style(text).bold());
}

/// A line of detail under the steps, indented to line up with their labels.
pub fn note(text: &str) {
    println!("  {}", style(text).dim());
}

/// One running step. Finish it with exactly one of `done`, `warn` or `fail`.
pub struct Step {
    bar: ProgressBar,
    label: String,
}

impl Step {
    pub fn start(label: &str) -> Self {
        let bar = if Term::stdout().features().is_attended() {
            let bar = ProgressBar::new_spinner();
            bar.set_style(
                ProgressStyle::with_template("  {spinner:.cyan} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_bar())
                    .tick_strings(SPINNER_FRAMES),
            );
            bar.set_message(label.to_string());
            bar.enable_steady_tick(SPINNER_INTERVAL);
            bar
        } else {
            ProgressBar::hidden()
        };
        Self {
            bar,
            label: label.to_string(),
        }
    }

    pub fn done(self, detail: &str) {
        self.finish(style("✔").green(), detail);
    }

    pub fn warn(self, detail: &str) {
        self.finish(style("!").yellow(), detail);
    }

    pub fn fail(self, detail: &str) {
        self.finish(style("✘").red(), detail);
    }

    fn finish(self, mark: ::console::StyledObject<&str>, detail: &str) {
        self.bar.finish_and_clear();
        let detail = if detail.is_empty() {
            String::new()
        } else {
            format!(" {}", style(detail).dim())
        };
        println!("  {mark} {}{detail}", self.label);
    }
}

/// A finished check, printed at once (nothing to wait for).
pub fn check(ok: bool, label: &str, detail: &str) {
    let step = Step::start(label);
    if ok {
        step.done(detail);
    } else {
        step.fail(detail);
    }
}

/// Runs `work` as one step: done with `detail(&value)` on success, failed with the error text otherwise.
pub fn step<T, E: std::fmt::Display>(
    label: &str,
    work: impl FnOnce() -> Result<T, E>,
    detail: impl FnOnce(&T) -> String,
) -> Result<T, E> {
    let running = Step::start(label);
    match work() {
        Ok(value) => {
            running.done(&detail(&value));
            Ok(value)
        }
        Err(error) => {
            running.fail(&error.to_string());
            Err(error)
        }
    }
}

/// A run of steps under one progress bar: finished steps scroll up as lines, the bar shows how far along the whole
/// job is and which step is running. Piped output gets the lines only.
pub struct Progress {
    bar: ProgressBar,
}

impl Progress {
    pub fn start(total_steps: u64) -> Self {
        let bar = if Term::stdout().features().is_attended() {
            let bar = ProgressBar::new(total_steps);
            bar.set_style(
                ProgressStyle::with_template("  {bar:30.cyan/blue} {pos}/{len} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_bar())
                    .progress_chars("█▉▏ "),
            );
            bar.enable_steady_tick(SPINNER_INTERVAL);
            bar
        } else {
            ProgressBar::hidden()
        };
        Self { bar }
    }

    /// Runs `work` as the next step: a tick line and a longer bar on success, a cross line and an error on failure.
    pub fn step<T, E: std::fmt::Display>(
        &self,
        label: &str,
        work: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.bar.set_message(label.to_string());
        match work() {
            Ok(value) => {
                self.line(&format!("{} {label}", style("✔").green()));
                self.bar.inc(1);
                Ok(value)
            }
            Err(error) => {
                self.line(&format!(
                    "{} {label} {}",
                    style("✘").red(),
                    style(&error).dim()
                ));
                self.bar.abandon();
                Err(error)
            }
        }
    }

    /// A line of detail printed above the bar.
    pub fn note(&self, text: &str) {
        self.line(&format!("  {}", style(text).dim()));
    }

    fn line(&self, text: &str) {
        if self.bar.is_hidden() {
            println!("  {text}");
        } else {
            self.bar.println(format!("  {text}"));
        }
    }

    pub fn finish(self) {
        self.bar.finish_and_clear();
    }
}
