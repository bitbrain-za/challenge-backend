use std::fs::File;
use std::io::prelude::*;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Submission {
    player: String,
    name: String,
    language: String,
    code: String,
    challenge: String,
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
        let mut file = match File::create(format!("/tmp/2332/{}.py", self.name)) {
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
        .arg(format!("python3 /tmp/2332/{}.py", self.name))
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
