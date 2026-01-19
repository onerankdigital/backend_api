# Anti-Spam Protection

This document describes the anti-spam measures implemented in the Lead Automation Platform.

## Overview

The platform implements multiple layers of anti-spam protection to prevent abuse:

1. **Rate Limiting** - IP and API key based
2. **Duplicate Detection** - Prevents duplicate submissions
3. **Data Validation** - Email and phone format validation
4. **Suspicious Pattern Detection** - Identifies spammy content
5. **Database Duplicate Check** - Prevents duplicate leads in database

## Rate Limiting

### IP-Based Rate Limiting

- **Default Limit**: 100 requests per 60 seconds per IP address
- **Window**: Sliding window algorithm
- **Scope**: Applied to all API endpoints (except health checks and docs)
- **Response**: Returns HTTP 429 (Too Many Requests) with retry information

### API Key-Based Rate Limiting

- **Default Limit**: 50 requests per 60 seconds per API key
- **Scope**: Applied specifically to `/api/leads/ingest` endpoint
- **Purpose**: Prevents API key abuse even if IP changes

### Configuration

Set in `.env`:
```env
RATE_LIMIT_PER_IP=100          # Requests per IP per window
RATE_LIMIT_WINDOW=60            # Time window in seconds
RATE_LIMIT_PER_API_KEY=50       # Requests per API key per window
```

### Rate Limit Headers

All responses include rate limit headers:
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Unix timestamp when limit resets
- `Retry-After`: Seconds to wait before retrying (on 429)

## Duplicate Detection

### In-Memory Duplicate Check (Redis)

- **Cooldown Period**: 5 minutes (300 seconds) default
- **Scope**: Same email or phone + client_id combination
- **Purpose**: Prevents rapid duplicate submissions
- **Storage**: Redis with TTL

### Database Duplicate Check

- **Time Window**: 24 hours
- **Scope**: Same email or phone + client_id in database
- **Purpose**: Prevents duplicate leads even after Redis TTL expires
- **Response**: HTTP 409 (Conflict)

### Configuration

```env
LEAD_DUPLICATE_COOLDOWN_SECONDS=300  # Cooldown period in seconds
```

## Data Validation

### Email Validation

- Validates email format using `email-validator` library
- Checks for valid domain and structure
- Returns HTTP 400 on invalid format

### Phone Validation

- Validates phone number format (7-15 digits)
- Normalizes phone numbers (removes separators, adds country code)
- Returns HTTP 400 on invalid format

### Suspicious Pattern Detection

Detects and blocks:
- Suspicious names: "test", "spam", "fake", "dummy", etc.
- Suspicious email domains: "test.com", "example.com", disposable emails
- Too many special characters in names
- Very short names (< 2 characters)

## Implementation Details

### Rate Limiting Algorithm

Uses **sliding window** algorithm with Redis sorted sets:
- Each request adds a timestamp to a sorted set
- Old entries outside the window are removed
- Count of entries determines if limit is exceeded
- Efficient and accurate

### Duplicate Detection

Uses Redis with TTL:
- Key format: `duplicate:{type}:{value}:{client_id}`
- Types: `email`, `phone`
- TTL matches cooldown period
- Automatic cleanup

### Database Queries

Duplicate checks query the database for:
- Same email + client_id within 24 hours
- Same phone + client_id within 24 hours
- Uses indexed columns for performance

## Error Responses

### Rate Limit Exceeded (429)

```json
{
  "detail": "Rate limit exceeded",
  "error": "too_many_requests",
  "reset_at": 1234567890,
  "limit": 100,
  "window_seconds": 60
}
```

### Duplicate Lead (429)

```json
{
  "detail": "Duplicate lead detected. Please wait 120 seconds before submitting again."
}
```

### Database Duplicate (409)

```json
{
  "detail": "A lead with this email already exists (within last 24 hours)"
}
```

### Invalid Data (400)

```json
{
  "detail": "Invalid email format"
}
```

## Best Practices

1. **Monitor Rate Limits**: Check response headers to track usage
2. **Handle 429 Responses**: Implement exponential backoff
3. **Validate Client-Side**: Validate data before submission
4. **Use Proper Error Handling**: Handle all error cases gracefully
5. **Monitor Redis**: Ensure Redis is available for rate limiting

## Configuration Recommendations

### Development
```env
RATE_LIMIT_PER_IP=1000
RATE_LIMIT_PER_API_KEY=500
LEAD_DUPLICATE_COOLDOWN_SECONDS=60
```

### Production
```env
RATE_LIMIT_PER_IP=100
RATE_LIMIT_PER_API_KEY=50
LEAD_DUPLICATE_COOLDOWN_SECONDS=300
```

### High-Volume Clients
```env
RATE_LIMIT_PER_IP=500
RATE_LIMIT_PER_API_KEY=200
LEAD_DUPLICATE_COOLDOWN_SECONDS=180
```

## Monitoring

Monitor the following metrics:
- Rate limit hits (429 responses)
- Duplicate detection hits
- Suspicious pattern detections
- Redis connection status
- API key usage patterns

## Troubleshooting

### Redis Not Available

If Redis is unavailable, rate limiting falls back to allowing all requests. This is a safety measure but should be monitored.

### False Positives

If legitimate leads are being blocked:
1. Check rate limit configuration
2. Review duplicate cooldown period
3. Adjust suspicious pattern detection rules
4. Whitelist specific IPs or API keys (future feature)

### Performance Impact

- Rate limiting adds minimal overhead (~1-2ms per request)
- Database duplicate checks use indexed queries
- Redis operations are fast (< 1ms)

## Future Enhancements

1. **IP Reputation**: Block known spam IPs
2. **CAPTCHA Integration**: For high-risk submissions
3. **Machine Learning**: Detect spam patterns
4. **Whitelist/Blacklist**: Per-client configuration
5. **Adaptive Rate Limiting**: Adjust limits based on behavior
6. **Geolocation Filtering**: Block submissions from specific regions

