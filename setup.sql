CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE users_auth_info (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID,
    refresh_token_hash VARCHAR,
    ip_address VARCHAR NOT NULL,
	UNIQUE (user_guid, refresh_token_hash),
    FOREIGN KEY (user_guid) REFERENCES users(id) ON DELETE CASCADE
);