CREATE USER scanner_user WITH PASSWORD 'scanner_pass';
CREATE DATABASE scanner_db OWNER scanner_user;
SELECT 'Database initialization complete' AS status;
