CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL
);

CREATE TABLE users_auth_info (
    id SERIAL PRIMARY KEY,
    user_guid UUID,
    refresh_token_hash VARCHAR NOT NULL,
    ip_address VARCHAR NOT NULL,
	UNIQUE (user_guid, refresh_token_hash),
    FOREIGN KEY (user_guid) REFERENCES users(id) ON DELETE CASCADE
);