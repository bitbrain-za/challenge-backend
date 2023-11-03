CREATE TABLE
    code_challenge.users (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        name CHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        verified BOOLEAN NOT NULL DEFAULT FALSE,
        password VARCHAR(100) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user'
    );

CREATE INDEX users_email_idx ON users (email);