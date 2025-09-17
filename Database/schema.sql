CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user');
CREATE TABLE treadmill_logs (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, metadata TEXT, geolocation TEXT, threat_score INTEGER, created_at TEXT NOT NULL);
CREATE TABLE auth_attempts (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, success BOOLEAN NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE heart_storage (id INTEGER PRIMARY KEY, user_id TEXT NOT NULL, insight TEXT NOT NULL, created_at TEXT NOT NULL);