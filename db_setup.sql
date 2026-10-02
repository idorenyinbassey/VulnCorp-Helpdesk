-- VulnCorp Helpdesk - Training Lab Schema
-- FOR USE ON ISOLATED / AUTHORIZED LAB ENVIRONMENTS (e.g. Metasploitable2) ONLY.

DROP DATABASE IF EXISTS vulnapp;
CREATE DATABASE vulnapp;
USE vulnapp;

CREATE TABLE settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    difficulty VARCHAR(20) NOT NULL DEFAULT 'simple',
    jwt_secret VARCHAR(64) DEFAULT NULL  -- random per install, see includes/jwt.php - never a fixed value in source
);
INSERT INTO settings (difficulty, jwt_secret) VALUES ('simple', MD5(RAND()));

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,   -- storage format deliberately varies by difficulty tier (see README)
    role ENUM('admin','support','user') NOT NULL DEFAULT 'user',
    full_name VARCHAR(100),
    email VARCHAR(100),
    api_key VARCHAR(64) DEFAULT NULL,  -- API Token (JWT) Auth module, see api/auth_token.php
    session_token VARCHAR(64) DEFAULT NULL,
    reset_token VARCHAR(64) DEFAULT NULL,     -- forgot-password flow (see user/forgot_password.php)
    reset_expires DATETIME DEFAULT NULL,
    bonus_claimed TINYINT(1) NOT NULL DEFAULT 0,  -- race-condition module (see user/claim_bonus.php)
    bonus_credits INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed accounts. Passwords intentionally weak for the lab (see README "Credentials" table).
-- Plaintext shown here; app stores them per the current difficulty tier when you re-run seed_users.php.
-- api_key values are likewise fixed seed data (not meant to resist guessing) -
-- the "The Forgotten Export" CTF chain is about *leaking* one via the
-- profile_export.php IDOR, not brute-forcing it.
INSERT INTO users (username, password, role, full_name, email, api_key) VALUES
('admin',   MD5('admin123'),   'admin',   'Ada Minstrator', 'admin@vulncorp.lab', 'ak_live_9f2a7c3e1b8d4f60'),
('sam',     MD5('support123'), 'support', 'Sam Support',    'sam@vulncorp.lab',   'ak_live_3b6e8a1d2f9c5074'),
('alice',   MD5('alice123'),   'user',    'Alice User',     'alice@vulncorp.lab','ak_live_7d4f1a9b6e2c8035'),
('bob',     MD5('bob123'),     'user',    'Bob Builder',    'bob@vulncorp.lab',  'ak_live_2c9b5f8e4a1d7360');

CREATE TABLE tickets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    subject VARCHAR(150) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    priority VARCHAR(20) NOT NULL DEFAULT 'normal',  -- API mass-assignment module, see api/ticket_update.php
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO tickets (user_id, subject, message, status) VALUES
(3, 'Cannot reset password', 'Hi, I forgot my password and the reset link is not arriving.', 'open'),
(4, 'Laptop running slow', 'My laptop has been very slow since the last update.', 'open'),
(1, 'Internal: Q4 planning doc access', 'FLAG{jwt_forged_the_queue} -- if you can read this, you chained the profile_export.php IDOR into a stolen/forged API token and reached an admin-only ticket. Report this as one finding: the fix is an ownership check on profile_export.php AND treating a leaked api_key as a full credential, not harmless metadata.', 'open');

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

-- Beginner-feedback tools (see feedback/vote.php, feedback/survey.php,
-- admin/feedback.php). Real feedback capture, not part of the training
-- lab itself - built correctly, no intentional vulnerabilities here.
CREATE TABLE challenge_feedback (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    challenge_id VARCHAR(100) NOT NULL,
    rating ENUM('too_easy','just_right','too_hard','stuck') NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_vote (username, challenge_id)
);

CREATE TABLE module_survey (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    tier VARCHAR(20) NOT NULL,
    difficulty_rating INT NOT NULL,
    concept_clarity_rating INT NOT NULL,
    hint_usefulness_rating INT NOT NULL,
    confidence_rating INT NOT NULL,
    most_confusing TEXT,
    other_comments TEXT,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_survey (username, tier)
);

