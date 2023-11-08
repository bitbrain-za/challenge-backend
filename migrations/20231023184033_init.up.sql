CREATE TABLE
    code_challenge.users (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        name CHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        verified BOOLEAN NOT NULL DEFAULT FALSE,
        password VARCHAR(100) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        verification_code VARCHAR(255),
        password_reset_token VARCHAR(50)
    );

CREATE INDEX users_email_idx ON code_challenge.users (email);
CREATE INDEX idx_verification_code ON code_challenge.users(verification_code);
CREATE INDEX idx_password_reset_token ON code_challenge.users(password_reset_token);
