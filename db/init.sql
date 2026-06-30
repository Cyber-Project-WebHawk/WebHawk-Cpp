-- WebHawk Database Schema

CREATE TABLE users (
    id                    SERIAL PRIMARY KEY,
    email                 VARCHAR(255) UNIQUE NOT NULL,
    password_hash         TEXT NOT NULL,
    role                  VARCHAR(20) NOT NULL DEFAULT 'user',
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ DEFAULT NOW(),
    updated_at            TIMESTAMPTZ DEFAULT NOW()
);

-- One row per issued refresh token. Access tokens are stateless (JWT) and not stored.
-- The refresh token itself is never stored in plain text — only a SHA-256 hash.
CREATE TABLE user_sessions (
    id                 SERIAL PRIMARY KEY,
    user_id            INT REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,
    ip_address         VARCHAR(45),
    user_agent         TEXT,
    created_at         TIMESTAMPTZ DEFAULT NOW(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    is_active          BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_user_sessions_user_id      ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_token_hash   ON user_sessions(refresh_token_hash);

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
