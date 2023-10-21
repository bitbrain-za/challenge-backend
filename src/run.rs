#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Submission {
    player: String,
    name: String,
    language: String,
    code: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SubmissionResult {
    Success { score: u32, message: String },
    Failure { message: String },
}

impl Submission {
    pub fn run(&self) -> SubmissionResult {
        SubmissionResult::Failure {
            message: "Not implemented".to_string(),
        }
    }
}
