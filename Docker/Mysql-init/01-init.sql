-- Create database and user
CREATE DATABASE IF NOT EXISTS raw_wealthy_enterprise;
USE raw_wealthy_enterprise;

-- Create application user
CREATE USER IF NOT EXISTS 'rawwealthy'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON raw_wealthy_enterprise.* TO 'rawwealthy'@'%';
FLUSH PRIVILEGES;
