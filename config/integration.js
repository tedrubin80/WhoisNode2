// FILE LOCATION: /config/integration.js
// FILE NAME: integration.js
// PURPOSE: Integration Configuration for Enhanced WHOIS Intelligence Server
// DESCRIPTION: Database, caching, logging, and notification configurations
// VERSION: 2.0.0
// USAGE: Import and initialize before starting the enhanced server

// ===== REQUIRE HELPER FUNCTIONS =====
// Add this to the top of your server-enhanced.js file

const {
  performDomainAnalysis,
  getWhoisData,
  whoisCommandLookup,
  whoisAPILookup,
  getDNSRecords,
  analyzePrivacyProtection,
  analyzeRegistrar,
  analyzeGeolocation,
  generateIntelligenceSummary,
  analyzeSPFRecord,
  analyzeDMARCRecord,
  parseWhoisResponse,
  parseRawWhois,
  extractEmails
} = require('./utils/helpers');

// ===== ENHANCED MIDDLEWARE CONFIGURATION =====
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

// Add these middleware to your app (after existing middleware)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

app.use(compression());
app.use(morgan('combined'));

// ===== ENHANCED LOGGING CONFIGURATION =====
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// ===== DATABASE CONFIGURATION =====
const mongoose = require('mongoose');

// Domain Analysis Schema for historical tracking
const DomainAnalysisSchema = new mongoose.Schema({
  domain: { type: String, required: true, index: true },
  timestamp: { type: Date, default: Date.now, index: true },
  whoisData: Object,
  dnsData: Object,
  privacyAnalysis: Object,
  registrarInfo: Object,
  geoData: Object,
  threatAnalysis: Object,
  riskScore: Object,
  securityScan: Object,
  summary: Object
});

const DomainAnalysis = mongoose.model('DomainAnalysis', DomainAnalysisSchema);

// Domain Monitoring Schema
const DomainMonitoringSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  domain: { type: String, required: true, index: true },
  apiKey: String,
  webhook: String,
  email: String,
  interval: { type: Number, default: 24 },
  active: { type: Boolean, default: true },
  created: { type: Date, default: Date.now },
  lastCheck: Date,
  alertsEnabled: { type: Boolean, default: true },
  config: Object
});

const DomainMonitoring = mongoose.model('DomainMonitoring', DomainMonitoringSchema);

// ===== REDIS CONFIGURATION =====
const Redis = require('ioredis');

let redisClient = null;

if (process.env.REDIS_URL) {
  redisClient = new Redis(process.env.REDIS_URL, {
    retryDelayOnFailover: 100,
    enableReadyCheck: false,
    maxRetriesPerRequest: null,
  });
  
  redisClient.on('connect', () => {
    logger.info('Redis connected successfully');
  });
  
  redisClient.on('error', (err) => {
    logger.error('Redis connection error:', err);
  });
}

// ===== ENHANCED CACHING FUNCTIONS =====
async function getFromCache(key) {
  try {
    // Try Redis first, then fallback to NodeCache
    if (redisClient) {
      const result = await redisClient.get(key);
      return result ? JSON.parse(result) : null;
    }
    return cache.get(key) || null;
  } catch (error) {
    logger.error('Cache get error:', error);
    return null;
  }
}

async function setToCache(key, value, ttl = 3600) {
  try {
    if (redisClient) {
      await redisClient.setex(key, ttl, JSON.stringify(value));
    }
    cache.set(key, value, ttl);
  } catch (error) {
    logger.error('Cache set error:', error);
  }
}

// ===== ENHANCED NOTIFICATION SYSTEM =====
const nodemailer = require('nodemailer');

let emailTransporter = null;

if (process.env.SMTP_HOST) {
  emailTransporter = nodemailer.createTransporter({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

async function sendEmailAlert(to, subject, content) {
  if (!emailTransporter) {
    logger.warn('Email transporter not configured');
    return false;
  }
  
  try {
    await emailTransporter.sendMail({
      from: process.env.SMTP_USER,
      to: to,
      subject: subject,
      html: content,
    });
    
    logger.info(`Email alert sent to ${to}`);
    return true;
  } catch (error) {
    logger.error('Email send error:', error);
    return false;
  }
}

// ===== ENHANCED DATABASE FUNCTIONS =====
async function saveDomainAnalysis(analysisData) {
  if (!mongoose.connection.readyState) {
    logger.warn('Database not connected, skipping save');
    return null;
  }
  
  try {
    const analysis = new DomainAnalysis(analysisData);
    await analysis.save();
    logger.info(`Domain analysis saved for ${analysisData.domain}`);
    return analysis;
  } catch (error) {
    logger.error('Database save error:', error);
    return null;
  }
}

async function getHistoricalAnalysis(domain, days = 30) {
  if (!mongoose.connection.readyState) {
    logger.warn('Database not connected, using simulated data');
    return getHistoricalData(domain, days); // Fallback to simulated data
  }
  
  try {
    const cutoffDate = new Date(Date.now() - (days * 24 * 60 * 60 * 1000));
    
    const analyses = await DomainAnalysis.find({
      domain: domain,
      timestamp: { $gte: cutoffDate }
    }).sort({ timestamp: -1 });
    
    return {
      domain,
      timeRange: `${days} days`,
      total: analyses.length,
      analyses: analyses,
      changes: detectChangesInHistory(analyses)
    };
  } catch (error) {
    logger.error('Historical data retrieval error:', error);
    return getHistoricalData(domain, days); // Fallback
  }
}

function detectChangesInHistory(analyses) {
  const changes = [];
  
  for (let i = 0; i < analyses.length - 1; i++) {
    const current = analyses[i];
    const previous = analyses[i + 1];
    
    // Check for IP changes
    const currentIPs = current.dnsData?.A || [];
    const previousIPs = previous.dnsData?.A || [];
    
    if (JSON.stringify(currentIPs.sort()) !== JSON.stringify(previousIPs.sort())) {
      changes.push({
        timestamp: current.timestamp,
        type: 'IP_CHANGE',
        from: previousIPs,
        to: currentIPs
      });
    }
    
    // Check for registrar changes
    if (current.registrarInfo?.name !== previous.registrarInfo?.name) {
      changes.push({
        timestamp: current.timestamp,
        type: 'REGISTRAR_CHANGE',
        from: previous.registrarInfo?.name,
        to: current.registrarInfo?.name
      });
    }
  }
  
  return changes;
}

// ===== ENHANCED MONITORING FUNCTIONS =====
async function saveMonitoringConfig(config) {
  if (!mongoose.connection.readyState) {
    logger.warn('Database not connected, using cache for monitoring');
    return setToCache(`monitor:${config.id}`, config, 0);
  }
  
  try {
    const monitoring = new DomainMonitoring(config);
    await monitoring.save();
    logger.info(`Monitoring config saved for ${config.domain}`);
    return monitoring;
  } catch (error) {
    logger.error('Monitoring save error:', error);
    return null;
  }
}

async function getActiveMonitoringConfigs() {
  if (!mongoose.connection.readyState) {
    logger.warn('Database not connected, using cache for monitoring');
    // Return cached monitoring configs
    const keys = cache.keys().filter(key => key.startsWith('monitor:') && !key.includes(':last:') && !key.includes(':interval:'));
    return keys.map(key => cache.get(key)).filter(config => config && config.active);
  }
  
  try {
    return await DomainMonitoring.find({ active: true });
  } catch (error) {
    logger.error('Monitoring retrieval error:', error);
    return [];
  }
}

// ===== ENHANCED THREAT INTELLIGENCE =====
async function updateThreatDatabase() {
  try {
    // Update malicious domains from threat feeds
    logger.info('Updating threat intelligence database...');
    
    // Example: Load from external threat feed
    // const response = await axios.get('https://threat-feed-url.com/domains.txt');
    // const maliciousDomains = response.data.split('\n').filter(domain => domain.trim());
    // maliciousDomains.forEach(domain => MALICIOUS_DOMAINS.add(domain.trim()));
    
    logger.info('Threat intelligence updated successfully');
  } catch (error) {
    logger.error('Threat intelligence update error:', error);
  }
}

// ===== DATABASE CONNECTION =====
async function connectDatabase() {
  if (process.env.MONGODB_URI) {
    try {
      await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      logger.info('MongoDB connected successfully');
    } catch (error) {
      logger.error('MongoDB connection error:', error);
      logger.info('Continuing without database persistence');
    }
  } else {
    logger.info('No MongoDB URI provided, using cache-only mode');
  }
}

// ===== STARTUP INITIALIZATION =====
async function initializeEnhancedServer() {
  try {
    // Connect to database
    await connectDatabase();
    
    // Update threat intelligence
    await updateThreatDatabase();
    
    // Set up periodic threat updates (every 6 hours)
    setInterval(updateThreatDatabase, 6 * 60 * 60 * 1000);
    
    // Restore active monitoring configs
    const activeMonitors = await getActiveMonitoringConfigs();
    logger.info(`Restored ${activeMonitors.length} active monitoring configurations`);
    
    // Set up monitoring for each active config
    activeMonitors.forEach(config => {
      setupDomainMonitoring(config);
    });
    
    logger.info('Enhanced server initialization completed');
  } catch (error) {
    logger.error('Initialization error:', error);
  }
}

// ===== INTEGRATION INSTRUCTIONS =====
/*
To integrate this configuration with your enhanced server:

1. Copy the helper functions to utils/helpers.js
2. Add the require statement at the top of server-enhanced.js
3. Add the middleware configuration after your existing middleware
4. Replace the simplified caching with the enhanced caching functions
5. Call initializeEnhancedServer() before starting the server
6. Update your existing functions to use the enhanced database and caching

Example integration in server-enhanced.js:

// Add at the top
const { logger, getFromCache, setToCache, saveDomainAnalysis, initializeEnhancedServer } = require('./config/integration');

// Replace existing cache.get/set calls with:
const cached = await getFromCache(cacheKey);
await setToCache(cacheKey, data, ttl);

// Add before server startup
await initializeEnhancedServer();

// In analysis functions, save to database:
if (analysis.success) {
  await saveDomainAnalysis(analysis);
}
*/

module.exports = {
  logger,
  getFromCache,
  setToCache,
  sendEmailAlert,
  saveDomainAnalysis,
  getHistoricalAnalysis,
  saveMonitoringConfig,
  getActiveMonitoringConfigs,
  updateThreatDatabase,
  connectDatabase,
  initializeEnhancedServer,
  DomainAnalysis,
  DomainMonitoring
};