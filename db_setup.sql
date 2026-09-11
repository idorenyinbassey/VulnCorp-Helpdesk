-- VulnCorp Helpdesk - Training Lab Schema
-- FOR USE ON ISOLATED / AUTHORIZED LAB ENVIRONMENTS (e.g. Metasploitable2) ONLY.

DROP DATABASE IF EXISTS vulnapp;
CREATE DATABASE vulnapp;
USE vulnapp;

CREATE TABLE settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    difficulty VARCHAR(20) NOT NULL DEFAULT 'simple'
);
INSERT INTO settings (difficulty) VALUES ('simple');

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,   -- storage format deliberately varies by difficulty tier (see README)
    role ENUM('admin','support','user') NOT NULL DEFAULT 'user',
    full_name VARCHAR(100),
    email VARCHAR(100),
    session_token VARCHAR(64) DEFAULT NULL,
    reset_token VARCHAR(64) DEFAULT NULL,     -- forgot-password flow (see user/forgot_password.php)
    reset_expires DATETIME DEFAULT NULL,
    bonus_claimed TINYINT(1) NOT NULL DEFAULT 0,  -- race-condition module (see user/claim_bonus.php)
    bonus_credits INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed accounts. Passwords intentionally weak for the lab (see README "Credentials" table).
-- Plaintext shown here; app stores them per the current difficulty tier when you re-run seed_users.php.
INSERT INTO users (username, password, role, full_name, email) VALUES
('admin',   MD5('admin123'),   'admin',   'Ada Minstrator', 'admin@vulncorp.lab'),
('sam',     MD5('support123'), 'support', 'Sam Support',    'sam@vulncorp.lab'),
('alice',   MD5('alice123'),   'user',    'Alice User',     'alice@vulncorp.lab'),
('bob',     MD5('bob123'),     'user',    'Bob Builder',    'bob@vulncorp.lab');

CREATE TABLE tickets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    subject VARCHAR(150) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO tickets (user_id, subject, message, status) VALUES
(3, 'Cannot reset password', 'Hi, I forgot my password and the reset link is not arriving.', 'open'),
(4, 'Laptop running slow', 'My laptop has been very slow since the last update.', 'open');

CREATE TABLE uploads (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    stored_path VARCHAR(255) NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE activity_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    action VARCHAR(255),
    ip VARCHAR(45),
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
