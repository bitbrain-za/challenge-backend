use std::fs::{self, File};
use std::io::prelude::*;
use std::os::unix::prelude::PermissionsExt;

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Submission {
    #[serde(skip)]
    pub player: String,
    filename: String,
    language: String,
    code: String,
    challenge: String,
    #[serde(skip)]
    binary: Option<Vec<u8>>,
    test: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SubmissionResult {
    Success { score: u32, message: String },
    Failure { message: String },
}

impl Submission {
    pub fn run(&self) -> SubmissionResult {
        if self.binary.is_some() {
            return self.run_binary();
        }
        self.run_script()
    }

    fn get_judge() -> String {
        option_env!("JUDGE_PATH").unwrap_or("judge").to_string()
    }

    pub fn sanitise(&mut self) {
        self.challenge = self.challenge.replace(['_', 'C'], "");
        self.language = self.language.to_lowercase();
    }

    pub fn run_script(&self) -> SubmissionResult {
        if let Err(e) = self.save_script() {
            log::error!("Error saving script: {}", e);
            return SubmissionResult::Failure {
                message: format!("Error saving script: {}", e),
            };
        }

        let result = match self.language.as_str() {
            "python" => self.run_script_with("python3"),

            _ => SubmissionResult::Failure {
                message: "Language not yet supported. Please submit a feature request".to_string(),
            },
        };
        let _ = self.delete_file();
        result
    }

    pub fn run_binary(&self) -> SubmissionResult {
        if let Err(e) = self.save_binary() {
            return SubmissionResult::Failure {
                message: format!("Error saving binary: {}", e),
            };
        }

        log::debug!(
            "Running binary: {} for challenge {}. Test: {}",
            self.filename,
            self.challenge,
            self.test
        );

        let mut command = std::process::Command::new(Self::get_judge());
        command
            .current_dir("/tmp/code_challenge")
            .arg("-n")
            .arg(&self.player)
            .arg("-C")
            .arg(&self.challenge)
            .arg("-L")
            .arg(&self.language)
            .arg("-c")
            .arg(self.filename.as_str());

        if self.test {
            command.arg("-t");
        }
        log::debug!("Command: {:?}", command);

        let output = match command.output() {
            Ok(o) => {
                if o.status.success() {
                    SubmissionResult::Success {
                        score: 0,
                        message: String::from_utf8_lossy(&o.stdout).to_string(),
                    }
                } else {
                    SubmissionResult::Failure {
                        message: String::from_utf8_lossy(&o.stderr).to_string(),
                    }
                }
            }
            Err(e) => SubmissionResult::Failure {
                message: format!("Error running command: {}", e),
            },
        };
        // let _ = self.delete_file();
        output
    }

    fn save_binary(&self) -> std::io::Result<()> {
        fs::create_dir_all("/tmp/code_challenge")?;
        let mut file = File::create(format!("/tmp/code_challenge/{}", self.filename))?;
        file.write_all(self.binary.as_ref().unwrap())?;

        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o755);
        file.set_permissions(permissions)
    }

    fn save_script(&self) -> std::io::Result<()> {
        fs::create_dir_all("/tmp/code_challenge")?;
        let mut file = File::create(format!("/tmp/code_challenge/{}", self.filename))?;
        file.write_all(self.code.as_bytes())
    }

    fn delete_file(&self) -> std::io::Result<()> {
        fs::remove_file(format!("/tmp/code_challenge/{}", self.filename))
    }

    fn run_script_with(&self, interpreter: &str) -> SubmissionResult {
        log::debug!("Running script with: {}", interpreter);
        let mut command = std::process::Command::new(Self::get_judge());
        command
            .current_dir("/tmp/code_challenge")
            .arg("-n")
            .arg(&self.player)
            .arg("-C")
            .arg(&self.challenge)
            .arg("-L")
            .arg(&self.language)
            .arg("-c")
            .arg(format!("{} {}", interpreter, self.filename));

        if self.test {
            command.arg("-t");
        }

        let output = match command.output() {
            Ok(o) => {
                if o.status.success() {
                    SubmissionResult::Success {
                        score: 0,
                        message: String::from_utf8_lossy(&o.stdout).to_string(),
                    }
                } else {
                    log::error!(
                        "Error running script: {}, {}",
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    );
                    SubmissionResult::Failure {
                        message: String::from_utf8_lossy(&o.stderr).to_string(),
                    }
                }
            }
            Err(e) => SubmissionResult::Failure {
                message: format!("Error running command: {}", e),
            },
        };
        log::debug!("Output: {:?}", output);
        output
    }
}

pub struct SubmissionBuilder {
    submission: Submission,
    player_set: bool,
    filename_set: bool,
    language_set: bool,
    code_set: bool,
    challenge_set: bool,
    binary_set: bool,
}

impl SubmissionBuilder {
    pub fn new() -> SubmissionBuilder {
        SubmissionBuilder {
            submission: Submission::default(),
            player_set: false,
            filename_set: false,
            language_set: false,
            code_set: false,
            challenge_set: false,
            binary_set: false,
        }
    }

    pub fn set_field(self, field: &str, value: &str) -> Result<SubmissionBuilder, String> {
        match field.to_lowercase().as_str() {
            "player" => Ok(self.player(value)),
            "name" => Ok(self.filename(value)),
            "filename" => Ok(self.filename(value)),
            "language" => Ok(self.language(value)),
            "code" => Ok(self.code(value)),
            "challenge" => Ok(self.challenge(value)),
            "test" => Ok(self.test("true" == value.to_lowercase())),
            _ => Err(format!("Unknown field: {}", field)),
        }
    }

    pub fn player(mut self, player: &str) -> SubmissionBuilder {
        self.submission.player = player.to_string();
        self.player_set = true;
        self
    }

    pub fn filename(mut self, name: &str) -> SubmissionBuilder {
        self.submission.filename = name.to_string();
        self.filename_set = true;
        self
    }

    pub fn language(mut self, language: &str) -> SubmissionBuilder {
        self.submission.language = language.to_string().to_lowercase();
        self.language_set = true;
        self
    }

    pub fn code(mut self, code: &str) -> SubmissionBuilder {
        self.submission.code = code.to_string();
        self.code_set = true;
        self
    }

    pub fn challenge(mut self, challenge: &str) -> SubmissionBuilder {
        self.submission.challenge = challenge.to_string();
        self.submission.challenge = self.submission.challenge.replace(['_', 'C'], "");
        self.challenge_set = true;
        self
    }

    pub fn binary(mut self, binary: Vec<u8>) -> SubmissionBuilder {
        self.submission.binary = Some(binary);
        self.binary_set = true;
        self
    }

    pub fn test(mut self, test: bool) -> SubmissionBuilder {
        self.submission.test = test;
        self
    }

    pub fn build(self) -> Result<Submission, String> {
        if !self.player_set {
            return Err("Player not set".to_string());
        }
        if !self.filename_set {
            return Err("filename not set".to_string());
        }
        if !self.language_set {
            return Err("Language not set".to_string());
        }
        if !self.challenge_set {
            return Err("Challenge not set".to_string());
        }
        if !self.binary_set && !self.code_set {
            return Err("Nothing to run".to_string());
        }
        if self.binary_set && self.code_set {
            return Err("Only set code or binary, not both".to_string());
        }
        Ok(self.submission)
    }
}
