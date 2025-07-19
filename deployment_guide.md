<!--
FILE LOCATION: /README.md
FILE NAME: README.md
PURPOSE: Enhanced Server Deployment & Testing Guide
DESCRIPTION: Complete setup and deployment instructions for WHOIS Intelligence Enhanced Server
VERSION: 2.0.0
USAGE: Follow this guide to deploy and test your enhanced WHOIS server
-->

# WHOIS Intelligence Enhanced Server - Deployment Guide

## 🚀 Quick Start

### 1. Installation

```bash
# Clone or create your project directory
mkdir whois-intelligence-enhanced
cd whois-intelligence-enhanced

# Install dependencies
npm init -y
npm install express cors express-rate-limit node-cache whois axios geoip-lite helmet compression morgan joi jsonwebtoken bcryptjs uuid dotenv mongoose redis ioredis bull socket.io nodemailer winston express-validator crypto tls net punycode idn-uts46

# Install dev dependencies
npm install --save-dev nodemon jest supertest eslint eslint-config-node prettier
```

### 2. Environment Configuration

Create a `.env` file in your project root:

```env
# Server Configuration
NODE_ENV=development
PORT=3001

# API Keys (Optional - for enhanced features)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
WHOISJSON_API_KEY=your_whoisjson_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here

# Database Configuration (Optional - for production)
MONGODB_URI=mongodb://localhost:27017/whois-intelligence
REDIS_URL=redis://localhost:6379

# Email Configuration (Optional - for alerts)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password

# Security
JWT_SECRET=your_super_secret_jwt_key_here
API_KEY_SALT=your_api_key_salt_here
```

### 3. File Structure

```
whois-intelligence-enhanced/
├── server-enhanced.js          # Main enhanced server file
├── utils/
│   ├── helpers.js             # Helper functions
│   └── validators.js          # Input validation
├── config/
│   ├── database.js            # Database configuration
│   └── cache.js               # Cache configuration
├── middleware/
│   ├── auth.js                # Authentication middleware
│   └── validation.js          # Validation middleware
├── routes/
│   ├── api.js                 # API routes
│   └── admin.js               # Admin routes
├── public/                    # Frontend files
├── tests/                     # Test files
├── package.json
├── .env
└── README.md
```

## 🔧 Core Features Added

### 1. RDAP Integration
- **Endpoint**: `POST /api/rdap`
- **Features**: Modern RDAP protocol support with WHOIS fallback
- **Benefits**: More structured data, better privacy compliance

```javascript
// Example usage
const response = await fetch('/api/rdap', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ domain: 'example.com' })
});
```

### 2. Threat Intelligence & Risk Scoring
- **Endpoint**: `POST /api/threat-analysis`
- **Endpoint**: `POST /api/risk-score`
- **Features**: 
  - Malicious domain detection
  - Phishing pattern analysis
  - Typosquatting detection
  - Comprehensive risk scoring (0-100)

### 3. Security Scanning
- **Endpoint**: `POST /api/security-scan`
- **Features**:
  - DNSSEC validation
  - SSL certificate analysis
  - SPF/DMARC/CAA record checks
  - Vulnerability assessment

### 4. Domain Monitoring
- **Endpoint**: `POST /api/monitor`
- **Features**:
  - Real-time change detection
  - Webhook notifications
  - Email alerts
  - Configurable monitoring intervals

### 5. Historical Data
- **Endpoint**: `GET /api/historical/:domain`
- **Features**:
  - WHOIS history tracking
  - DNS change detection
  - Registrar migration tracking

### 6. Enhanced Bulk Analysis
- **Endpoint**: `POST /api/bulk-analyze`
- **Features**:
  - Tiered access (10/50/100 domains)
  - Optional threat analysis
  - Optional risk scoring
  - Progress tracking

## 🧪 Testing the New Features

### 1. Basic Health Check
```bash
curl http://localhost:3001/health
```

### 2. API Status Check
```bash
curl http://localhost:3001/api/status
```

### 3. RDAP Lookup Test
```bash
curl -X POST http://localhost:3001/api/rdap \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'
```

### 4. Threat Analysis Test
```bash
curl -X POST http://localhost:3001/api/threat-analysis \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"domain": "suspicious-domain.com"}'
```

### 5. Risk Score Test
```bash
curl -X POST http://localhost:3001/api/risk-score \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### 6. Security Scan Test
```bash
curl -X POST http://localhost:3001/api/security-scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "github.com"}'
```

### 7. Enhanced Bulk Analysis Test
```bash
curl -X POST http://localhost:3001/api/bulk-analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: premium-key" \
  -d '{
    "domains": ["google.com", "github.com", "stackoverflow.com"],
    "includeThreatAnalysis": true,
    "includeRiskScore": true
  }'
```

### 8. Domain Monitoring Setup
```bash
curl -X POST http://localhost:3001/api/monitor \
  -H "Content-Type: application/json" \
  -H "X-API-Key: premium-key" \
  -d '{
    "domain": "example.com",
    "webhook": "https://your-webhook-url.com/alerts",
    "email": "alerts@yourcompany.com",
    "interval": 24
  }'
```

## 🔐 API Key System

### Access Tiers
1. **Free Tier** (no API key)
   - 100 requests/hour
   - Basic analysis only
   - 10 domains in bulk requests

2. **Premium Tier** (with API key)
   - 1000 requests/hour
   - All features enabled
   - 50 domains in bulk requests

3. **Enterprise Tier** (special API key)
   - Unlimited requests
   - All features + priority support
   - 100 domains in bulk requests

### Using API Keys
```bash
# Add X-API-Key header to your requests
curl -H "X-API-Key: your-premium-api-key" ...
```

## 📊 Performance Improvements

### Caching Strategy
- **Main Cache**: 6 hours (general analysis)
- **Threat Cache**: 1 hour (threat intelligence)
- **Historical Cache**: 24 hours (historical data)

### Rate Limiting
- **API Endpoints**: 500 requests per 15 minutes
- **Bulk Analysis**: 10 requests per hour
- **Tiered by API key level**

### Memory Management
- Enhanced cache configuration
- Automatic cleanup processes
- Memory usage monitoring

## 🔍 Monitoring & Alerts

### Health Monitoring
```javascript
// Check server health with detailed metrics
const health = await fetch('/health');
const status = await health.json();

console.log('Cache Stats:', status.cache);
console.log('Memory Usage:', status.memory);
console.log('Uptime:', status.uptime);
```

### Domain Monitoring Alerts
```javascript
// Set up webhook endpoint to receive alerts
app.post('/webhook/domain-alerts', (req, res) => {
  const alert = req.body;
  console.log('Domain change detected:', alert);
  
  // Process the alert
  if (alert.changes.some(c => c.type === 'IP_ADDRESS_CHANGE')) {
    // Handle IP change
    console.log('IP address changed for:', alert.domain);
  }
  
  res.json({ received: true });
});
```

## 🛠️ Development Setup

### 1. Development Mode
```bash
npm run dev  # Uses nodemon for auto-restart
```

### 2. Production Mode
```bash
npm start    # Standard production start
```

### 3. Testing
```bash
npm test           # Run all tests
npm run test:watch # Watch mode for development
```

### 4. Linting
```bash
npm run lint       # Check code style
npm run lint:fix   # Fix auto-fixable issues
```

## 🚀 Deployment Options

### Railway Deployment
1. Connect your GitHub repository to Railway
2. Set environment variables in Railway dashboard
3. Deploy with automatic builds

### Docker Deployment
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3001
CMD ["npm", "start"]
```

### Traditional VPS Deployment
1. Install Node.js 18+
2. Clone repository
3. Install dependencies
4. Set up environment variables
5. Use PM2 for process management

```bash
npm install -g pm2
pm2 start server-enhanced.js --name "whois-intel"
pm2 startup
pm2 save
```

## 📈 Next Steps

### Immediate Priorities
1. ✅ Enhanced API endpoints (COMPLETED)
2. ✅ Threat intelligence integration (COMPLETED)
3. ✅ Risk scoring system (COMPLETED)
4. 🔄 Frontend dashboard development
5. 🔄 Database integration for persistence
6. 🔄 User authentication system

### Advanced Features
1. Machine learning risk prediction
2. Real-time threat feed integration
3. Advanced analytics dashboard
4. Multi-tenant support
5. Enterprise reporting features

## 🐛 Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Adjust cache sizes in configuration
   - Monitor with `/health` endpoint

2. **Rate Limiting Errors**
   - Check API key tier
   - Implement request queuing

3. **DNS Timeout Errors**
   - Increase DNS timeout values
   - Implement retry logic

4. **Cache Performance**
   - Monitor cache hit rates
   - Adjust TTL values based on usage

### Debug Mode
```bash
DEBUG=whois:* node server-enhanced.js
```

## 📚 API Documentation

Complete API documentation is available at:
- `/api/status` - Shows all available endpoints
- Individual endpoint documentation in code comments
- Example requests and responses provided

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## 📝 License

MIT License - See LICENSE file for details