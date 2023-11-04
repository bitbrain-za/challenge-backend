use std::fs::File;
use std::io::prelude::*;

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
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SubmissionResult {
    Success { score: u32, message: String },
    Failure { message: String },
}

impl Submission {
    pub fn run(&self) -> SubmissionResult {
        match self.language.to_lowercase().as_str() {
            "python" => self.run_python(),

            _ => SubmissionResult::Failure {
                message: "Language not yet supported. Please submit a feature request".to_string(),
            },
        }
    }

    fn run_python(&self) -> SubmissionResult {
        let mut file = match File::create(format!("/tmp/2332/{}.py", self.filename)) {
            Ok(f) => f,
            Err(e) => {
                return SubmissionResult::Failure {
                    message: format!("Error creating file: {}", e),
                }
            }
        };
        match file.write_all(self.code.as_bytes()) {
            Ok(_) => (),
            Err(e) => {
                return SubmissionResult::Failure {
                    message: format!("Error writing to file: {}", e),
                };
            }
        };

        let output = match std::process::Command::new(
            "/home/philip/code_challenges/workspace/target/debug/judge",
        )
        .arg("-C")
        .arg("2332")
        .arg("-L")
        .arg("python")
        .arg("-c")
        .arg(format!("python3 /tmp/2332/{}.py", self.filename))
        .arg("-t")
        .output()
        {
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
            "test" => Ok(self),
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
        self.submission.language = language.to_string();
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
        self.challenge_set = true;
        self
    }

    pub fn binary(mut self, binary: Vec<u8>) -> SubmissionBuilder {
        self.submission.binary = Some(binary);
        self.binary_set = true;
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
