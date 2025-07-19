# FILE LOCATION: /.env
# Environment configuration for WHOIS Intelligence Server with Blacklist Checking
# RAILWAY DEPLOYMENT READY

# Server Configuration
NODE_ENV=production
PORT=3001

# API Authentication
API_KEY=your_secure_api_key_here

# WHOIS API Configuration (optional)
WHOISJSON_API_KEY=your_whoisjson_api_key_here

# Blacklist API Keys (RECOMMENDED for enhanced detection)
# Get free API keys from these services:

# VirusTotal API (Free: 500 requests/day, 4 requests/minute)
# Sign up at: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# AbuseIPDB API (Free: 1000 requests/day)
# Sign up at: https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# AI Configuration (OpenAI for enhanced analysis)
# Get API key at: https://platform.openai.com/api-keys
OPENAI_API_KEY=your_openai_api_key_here

# Railway PostgreSQL Configuration
# Railway automatically provides DATABASE_URL, but you can also set individual values
DATABASE_URL=postgresql://postgres:password@postgres.switchback.proxy.rlwy.net:5432/railway

# Alternative: Individual PostgreSQL settings (if not using DATABASE_URL)
POSTGRES_HOST=postgres.switchback.proxy.rlwy.net
POSTGRES_PORT=5432
POSTGRES_DB=railway
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_railway_postgres_password

# Admin Authentication
JWT_SECRET=your_super_secure_jwt_secret_here_use_crypto_random
ADMIN_USERNAME=admin
ADMIN_PASSWORD=secure_admin_password_123

# Security Configuration
ALLOWED_ORIGINS=https://your-railway-domain.up.railway.app,http://localhost:3000

# Optional: Additional threat intelligence APIs
# URLVoid API (for URL reputation checking)
URLVOID_API_KEY=your_urlvoid_api_key_here

# Hybrid Analysis API (for malware analysis)
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_api_key_here

# Redis Configuration (Railway Redis if you add it)
# REDIS_URL=redis://default:password@redis.railway.internal:6379

# Email Configuration (optional - for alerts and notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password

# Logging Configuration
LOG_LEVEL=info
LOG_FILE=logs/whois-intelligence.log

# Rate Limiting Configuration
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=300
API_RATE_LIMIT_WINDOW_MS=60000
API_RATE_LIMIT_MAX_REQUESTS=60

# Cache Configuration
CACHE_TTL_SECONDS=21600
THREAT_CACHE_TTL_SECONDS=3600
MAX_CACHE_KEYS=2000

# Blacklist Configuration
BLACKLIST_CACHE_POSITIVE_TTL=86400
BLACKLIST_CACHE_NEGATIVE_TTL=3600
BLACKLIST_API_TIMEOUT=10000
BLACKLIST_DNS_TIMEOUT=5000