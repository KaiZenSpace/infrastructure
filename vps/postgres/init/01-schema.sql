-- Users table with essential fields and API key
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    api_key VARCHAR(64) UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Clients table (WireGuard peers) with clear prefixes and list mode
CREATE TABLE clients (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    wg_ip_address VARCHAR(15) UNIQUE NOT NULL,
    wg_public_key VARCHAR(44) UNIQUE NOT NULL,
    wg_private_key VARCHAR(44),
    wg_preshared_key VARCHAR(44),
    wg_last_seen TIMESTAMP,
    wg_dns_server VARCHAR(15) NOT NULL DEFAULT '172.29.0.3',
    list_mode VARCHAR(10) NOT NULL DEFAULT 'none', -- Only 'none' 'blocklist' or 'whitelist'
    UNIQUE(name, user_id)
);

-- Blocklist files table
CREATE TABLE blocklist_files (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    file_path VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Whitelist files table
CREATE TABLE whitelist_files (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL, 
    file_path VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Client-blocklist relationships
CREATE TABLE client_blocklists (
    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
    blocklist_id INTEGER REFERENCES blocklist_files(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, blocklist_id)
);

-- Client-whitelist relationships
CREATE TABLE client_whitelists (
    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
    whitelist_id INTEGER REFERENCES whitelist_files(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, whitelist_id)
);

-- Create an index on the API key for faster lookups
CREATE INDEX idx_users_api_key ON users(api_key);
