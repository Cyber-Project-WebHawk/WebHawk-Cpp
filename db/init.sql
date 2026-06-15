-- WebHawk Database Schema

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE user_sessions (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES users(id) ON DELETE CASCADE,
    jwt_token   TEXT NOT NULL,
    ip_address  VARCHAR(45),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    is_active   BOOLEAN DEFAULT TRUE
);

CREATE TABLE backend_registration (
    id           SERIAL PRIMARY KEY,
    service_name VARCHAR(255) NOT NULL,
    target_url   TEXT NOT NULL,
    api_key      VARCHAR(64) UNIQUE NOT NULL,
    is_active    BOOLEAN DEFAULT TRUE,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE security_logs (
    id          SERIAL PRIMARY KEY,
    backend_id  INT REFERENCES backend_registration(id),
    ip_address  VARCHAR(45) NOT NULL,
    method      VARCHAR(10) NOT NULL,
    endpoint    TEXT NOT NULL,
    attack_type VARCHAR(50),
    was_blocked BOOLEAN DEFAULT TRUE,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    raw_payload TEXT
);

CREATE TABLE rate_limit (
    id            SERIAL PRIMARY KEY,
    ip_address    VARCHAR(45) NOT NULL,
    endpoint      TEXT NOT NULL,
    request_count INT DEFAULT 1,
    window_start  TIMESTAMPTZ DEFAULT NOW(),
    is_blocked    BOOLEAN DEFAULT FALSE,
    UNIQUE(ip_address, endpoint)
);
