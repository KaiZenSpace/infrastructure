# DNS Blocker API Documentation

The DNS Blocker provides a comprehensive REST API for managing domain filtering. This documentation explains how to use the API to manage blocklists, whitelists, clients, and check domain access permissions.

## API Overview

The API server runs on port 8099 by default and provides endpoints for:
- Managing blocklists and whitelists
- Adding and removing domains from lists
- Configuring clients and their filtering rules
- Checking if domains are blocked for specific clients

## API Endpoints

### List Management

#### Get All Lists

Retrieves metadata for all blocklists and whitelists.

```
GET /api/lists
```

**Response:**
```json
[
  {
    "name": "ads",
    "type": "blocklist",
    "count": 1245,
    "lastModified": "2025-04-12T10:30:00Z"
  },
  {
    "name": "allowedSites",
    "type": "whitelist",
    "count": 50,
    "lastModified": "2025-04-11T15:20:00Z"
  }
]
```

#### Get Lists by Type

Retrieves all lists of a specific type (blocklist or whitelist).

```
GET /api/lists/{type}
```

Where `{type}` is either `blocklist` or `whitelist`.

**Response:**
```json
[
  {
    "name": "ads",
    "type": "blocklist",
    "count": 1245,
    "lastModified": "2025-04-12T10:30:00Z"
  },
  {
    "name": "malware",
    "type": "blocklist",
    "count": 983,
    "lastModified": "2025-04-10T08:15:00Z"
  }
]
```

#### Get List Content

Retrieves all domains in a specific list.

```
GET /api/lists/{type}/{name}
```

Where `{type}` is either `blocklist` or `whitelist` and `{name}` is the list name.

**Response:**
```json
{
  "name": "ads",
  "type": "blocklist",
  "domains": [
    "ads.example.com",
    "tracker.example.net",
    "analytics.example.org !stats"
  ]
}
```

#### Create a New List

Creates a new blocklist or whitelist.

```
POST /api/lists/{type}
```

Where `{type}` is either `blocklist` or `whitelist`.

**Request Body:**
```json
{
  "name": "social-media",
  "domains": [
    "facebook.com",
    "twitter.com",
    "instagram.com !business"
  ]
}
```

**Response:**
```json
{
  "name": "social-media",
  "type": "blocklist",
  "domains": [
    "facebook.com",
    "twitter.com",
    "instagram.com !business"
  ]
}
```

#### Update an Existing List

Updates an existing blocklist or whitelist.

```
PUT /api/lists/{type}/{name}
```

Where `{type}` is either `blocklist` or `whitelist` and `{name}` is the list name.

**Request Body:**
```json
{
  "domains": [
    "facebook.com",
    "twitter.com",
    "instagram.com !business",
    "tiktok.com"
  ]
}
```

**Response:**
```json
{
  "name": "social-media",
  "type": "blocklist",
  "domains": [
    "facebook.com",
    "twitter.com",
    "instagram.com !business",
    "tiktok.com"
  ]
}
```

#### Delete a List

Deletes a blocklist or whitelist.

```
DELETE /api/lists/{type}/{name}
```

Where `{type}` is either `blocklist` or `whitelist` and `{name}` is the list name.

**Response:** HTTP 204 No Content

### Domain Management

#### Add Domains to a List

Adds domains to an existing list.

```
POST /api/lists/{type}/{name}/domains
```

Where `{type}` is either `blocklist` or `whitelist` and `{name}` is the list name.

**Request Body:**
```json
{
  "domains": [
    "newdomain.example.com",
    "another.example.net !subdomain"
  ]
}
```

**Response:** HTTP 200 OK

#### Remove Domains from a List

Removes domains from an existing list.

```
DELETE /api/lists/{type}/{name}/domains
```

Where `{type}` is either `blocklist` or `whitelist` and `{name}` is the list name.

**Request Body:**
```json
{
  "domains": [
    "domain-to-remove.example.com",
    "another-to-remove.example.net"
  ]
}
```

**Response:** HTTP 200 OK

### Client Management

#### Get All Clients

Retrieves all client configurations.

```
GET /api/clients
```

**Response:**
```json
[
  {
    "ip": "192.168.1.10",
    "blocklists": ["ads", "malware"],
    "whitelists": ["trusted-sites"],
    "mode": "blocklist"
  },
  {
    "ip": "192.168.1.20",
    "blocklists": [],
    "whitelists": ["allowed-sites"],
    "mode": "whitelist"
  }
]
```

#### Get Client by IP

Retrieves a specific client configuration.

```
GET /api/clients/{ip}
```

Where `{ip}` is the client's IP address.

**Response:**
```json
{
  "ip": "192.168.1.10",
  "blocklists": ["ads", "malware"],
  "whitelists": ["trusted-sites"],
  "mode": "blocklist"
}
```

#### Create a New Client

Creates a new client configuration.

```
POST /api/clients
```

**Request Body:**
```json
{
  "ip": "192.168.1.30",
  "blocklists": ["social-media", "ads"],
  "whitelists": ["work-sites"],
  "mode": "blocklist"
}
```

**Response:**
```json
{
  "ip": "192.168.1.30",
  "blocklists": ["social-media", "ads"],
  "whitelists": ["work-sites"],
  "mode": "blocklist"
}
```

#### Update a Client

Updates an existing client configuration.

```
PUT /api/clients/{ip}
```

Where `{ip}` is the client's IP address.

**Request Body:**
```json
{
  "blocklists": ["social-media", "ads", "games"],
  "whitelists": ["work-sites"],
  "mode": "blocklist"
}
```

**Response:**
```json
{
  "ip": "192.168.1.30",
  "blocklists": ["social-media", "ads", "games"],
  "whitelists": ["work-sites"],
  "mode": "blocklist"
}
```

#### Delete a Client

Deletes a client configuration.

```
DELETE /api/clients/{ip}
```

Where `{ip}` is the client's IP address.

**Response:** HTTP 204 No Content

### DNS Lookup

#### Check Domain Access

Checks if a client is allowed to access a domain.

```
GET /api/check/{ip}/{domain}
```

Where `{ip}` is the client's IP address and `{domain}` is the domain to check.

**Response:**
```json
{
  "clientIP": "192.168.1.10",
  "domain": "example.com",
  "allowed": true
}
```

## Working with Exceptions

The system supports domain exceptions using the `!` syntax. For example:

```
example.com !mail !forum
```

This entry would block `example.com` and all its subdomains, except for `mail.example.com` and `forum.example.com`.

### Adding Domains with Exceptions

When adding domains with exceptions, format them in the JSON request as shown:

```json
{
  "domains": [
    "example.com !mail !shop",
    "another-domain.com"
  ]
}
```

## Client Modes

The system supports two filtering modes:

1. **Blocklist Mode** (`"mode": "blocklist"`): All domains are allowed except those in the blocklists
2. **Whitelist Mode** (`"mode": "whitelist"`): All domains are blocked except those in the whitelists

## Usage Examples

### Setting Up a Basic Blocklist

1. Create a blocklist:
```bash
curl -X POST http://172.29.0.3:8099/api/lists/blocklist \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ads",
    "domains": [
      "ads.example.com",
      "analytics.example.org",
      "tracker.example.net"
    ]
  }'
```

2. Create a client that uses this blocklist:
```bash
curl -X POST http://172.29.0.3:8099/api/clients \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "blocklists": ["ads"],
    "whitelists": [],
    "mode": "blocklist"
  }'
```

3. Check if a domain is blocked:
```bash
curl http://172.29.0.3:8099/api/check/192.168.1.100/ads.example.com
```

### Setting Up a Whitelist-Only Client

1. Create a whitelist:
```bash
curl -X POST http://172.29.0.3:8099/api/lists/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "name": "allowed-sites",
    "domains": [
      "work.example.com",
      "docs.example.org",
      "mail.example.net"
    ]
  }'
```

2. Create a client that uses this whitelist:
```bash
curl -X POST http://172.29.0.3:8099/api/clients \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.200",
    "blocklists": [],
    "whitelists": ["allowed-sites"],
    "mode": "whitelist"
  }'
```

3. Check if domains are allowed:
```bash
curl http://172.29.0.3:8099/api/check/192.168.1.200/work.example.com
curl http://172.29.0.3:8099/api/check/192.168.1.200/facebook.com
```

## Troubleshooting

### Common Errors

- **404 Not Found**: The specified list or client doesn't exist
- **400 Bad Request**: Invalid request format or parameters
- **409 Conflict**: The resource already exists (e.g., when creating a list or client)

### Verifying System Status

To check if the DNS filter system is running properly:

1. Get all lists:
```bash
curl http://172.29.0.3:8099/api/lists
```

2. Get all clients:
```bash
curl http://172.29.0.3:8099/api/clients
```

If these requests return successfully, the API is running correctly.

## Integration with CoreDNS

The API server is automatically started when the CoreDNS server runs with the IPBlocker plugin enabled. DNS requests will be processed according to the configured lists and client settings.

When a client makes a DNS request:
1. CoreDNS identifies the client by IP address
2. The IPBlocker plugin checks if the requested domain is allowed based on the client's configuration
3. If allowed, the DNS request proceeds normally
4. If blocked, a NXDOMAIN response is returned
