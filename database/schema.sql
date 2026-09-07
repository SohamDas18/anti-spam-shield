-- MySQL Database Schema for Spam Mail & SMS Phone Threat Analysis System
CREATE DATABASE IF NOT EXISTS spam_detection;
USE spam_detection;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Emails / Messages Table (Supports both Email and SMS)
CREATE TABLE IF NOT EXISTS emails (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NULL,
    message_type VARCHAR(20) DEFAULT 'EMAIL', -- EMAIL or SMS
    sender VARCHAR(255),
    subject VARCHAR(500),
    email_content TEXT NOT NULL,
    classification VARCHAR(20) NOT NULL,
    spam_probability DECIMAL(5, 2) NOT NULL,
    phone_numbers TEXT,
    is_trusted_sender TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_msg_type (message_type),
    INDEX idx_class (classification)
);

-- 3. URL Analysis Table
CREATE TABLE IF NOT EXISTS url_analysis (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email_id INT NOT NULL,
    url TEXT NOT NULL,
    risk_probability DECIMAL(5, 2) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    risk_type VARCHAR(100) NOT NULL,
    possible_consequence TEXT,
    recommendation TEXT,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE,
    INDEX idx_email (email_id)
);

-- 4. Phone Number Analysis Table
CREATE TABLE IF NOT EXISTS phone_analysis (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email_id INT NOT NULL,
    phone_number VARCHAR(50) NOT NULL,
    country VARCHAR(100),
    number_type VARCHAR(50),
    risk_probability DECIMAL(5, 2) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    flags TEXT,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE,
    INDEX idx_phone_email (email_id)
);

-- 5. Trusted Contacts / Whitelist Table (Prevents False Positives from known friends/family)
CREATE TABLE IF NOT EXISTS trusted_contacts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NULL,
    contact_identifier VARCHAR(255) NOT NULL, -- Normalized phone (e.g. 9876543210) or email
    display_name VARCHAR(100) NOT NULL,
    contact_type VARCHAR(20) DEFAULT 'PHONE', -- PHONE or EMAIL
    notes VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_contact (contact_identifier)
);
