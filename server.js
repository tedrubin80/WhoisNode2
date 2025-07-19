/*
FOLDER STRUCTURE:
whois-intelligence-server/
├── server.js                    (this file - MAIN SERVER)
├── utils/
│   ├── helpers.js               (existing helper functions)
│   └── blacklist-checker.js     (blacklist functionality)
├── public/
│   └── index.html               (frontend dashboard)
├── package.json                 (dependencies)
├── .env                         (environment variables)
└── README.md

FILE LOCATION: /server.js (COMPLETE MAIN SERVER FILE)
*/

// Enhanced WHOIS Intelligence Server with Blacklist Checking - COMPLETE
// Version: 2.2.0 - Integrated Blacklist Functionality

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const whois = require('whois');
const dns = require('dns').promises;
const axios = require('axios');
const geoip = require('geoip-lite');
const path = require('path');

// Import blacklist checker
const { BlacklistChecker, PRIVACY_EMAIL_PATTERNS, PRIVACY_EMAIL_DOMAINS, DNS_BLACKLISTS, BLACKLIST_CONFIG } = require('./utils/blacklist-checker');

const app = express();
const PORT = process.env.PORT || 3001;

// ===== CONFIGURATION =====
const CONFIG = {
  CACHE_TTL: 21600, // 6 hours
  THREAT_CACHE_TTL: 3600, // 1 hour
  MAX_BULK_DOMAINS: 10,
  REQUEST_TIMEOUT: 15000,
  WHOIS_TIMEOUT: 12000,
  DNS_TIMEOUT: 10000
};

// ===== CACHE CONFIGURATION =====
const cache = new NodeCache({ 
  stdTTL: CONFIG.CACHE_TTL,
  checkperiod: 3600,
  maxKeys: 2000
});

const threatCache = new NodeCache({
  stdTTL: CONFIG.THREAT_CACHE_TTL,
  checkperiod: 600,
  maxKeys: 500
});

// Initialize blacklist checker with cache
const blacklistChecker = new BlacklistChecker(cache);

// ===== SECURITY & VALIDATION =====
const VALID_API_KEYS = new Set([
  process.env.API_KEY || 'demo-key-12345678',
  'whois-intelligence-key-2024',
  'demo-key',
  'test-key-123',
  'development-key'
]);

const validateApiKey = (req, res, next) => {
  if (req.path === '/health' || req.path === '/' || req.path.startsWith('/static')) {
    return next();
  }

  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: 'API key required',
      message: 'Please provide an API key in the X-API-Key header or api_key query parameter'
    });
  }
  
  if (!VALID_API_KEYS.has(apiKey)) {
    return res.status(401).json({
      success: false,
      error: 'Invalid API key'
    });
  }
  
  req.apiKey = apiKey;
  next();
};

function sanitizeDomain(domain) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('Domain must be a non-empty string');
  }
  
  return domain.trim()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .split('?')[0]
    .split('#')[0]
    .toLowerCase()
    .replace(/[^a-z0-9.-]/g, '')
    .substring(0, 253);
}

function isValidDomain(domain) {
  if (!domain || domain.length === 0) return false;
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
  return domainRegex.test(domain) && domain.includes('.') && domain.length <= 253;
}

// ===== RATE LIMITING =====
const createRateLimit = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { 
    success: false, 
    error: message 
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.apiKey ? `${req.apiKey}:${req.ip}` : req.ip;
  }
});

const generalLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  300, // requests
  'Rate limit exceeded. Please try again in 15 minutes.'
);

const apiLimiter = createRateLimit(
  60 * 1000, // 1 minute  
  60, // requests
  'API rate limit exceeded. Please slow down your requests.'
);

// ===== MIDDLEWARE =====
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || true,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Requested-With']
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(generalLimiter);

// Serve static files
app.use(express.static(__dirname, {
  maxAge: '1h',
  etag: true
}));

// Logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const apiKey = req.headers['x-api-key'] ? '[API_KEY]' : '[NO_KEY]';
  console.log(`[${timestamp}] ${req.method} ${req.url} - ${req.ip} ${apiKey}`);
  next();
});

// ===== THREAT INTELLIGENCE DATA =====
const THREAT_PATTERNS = {
  PHISHING: [
    /payp[a4]l/i, /amaz[o0]n/i, /g[o0]{2}gle/i, /micr[o0]s[o0]ft/i,
    /[a4]pple/i, /netf1ix/i, /[fa4]ceb[o0]{2}k/i, /tw[i1]tter/i,
    /banks?/i, /secure-?update/i, /verify-?account/i, /suspended-?account/i
  ],
  SUSPICIOUS: [
    /random-?[\w]{6,}/i, /temp-?[\w]{4,}/i, /test-?[\w]{4,}/i,
    /[\d]{4,}-[\w]{4,}/i, /free-?[\w]{4,}/i
  ],
  MALWARE: [
    /download-?now/i, /click-?here/i, /urgent-?update/i, /security-?alert/i
  ]
};

const RISK_SCORES = {
  PRIVACY_PROTECTED: 15,
  RECENT_REGISTRATION: 20,
  SUSPICIOUS_REGISTRAR: 25,
  PHISHING_PATTERN: 35,
  MALWARE_PATTERN: 40,
  NO_CONTACT_INFO: 10,
  SHORT_DOMAIN_AGE: 25,
  MULTIPLE_SUBDOMAINS: 15,
  UNUSUAL_TLD: 10,
  BLACKLISTED_EMAIL: 40,
  BLACKLISTED_IP: 50,
  PRIVACY_EMAIL: 20
};

// ===== HEALTH CHECK =====
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '2.2.0',
    uptime: Math.floor(process.uptime()),
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
    },
    cache: {
      mainCache: {
        keys: cache.keys().length,
        hits: cache.getStats().hits || 0,
        misses: cache.getStats().misses || 0
      },
      threatCache: {
        keys: threatCache.keys().length,
        hits: threatCache.getStats().hits || 0,
        misses: threatCache.getStats().misses || 0
      }
    },
    environment: process.env.NODE_ENV || 'development'
  });
});

// ===== API STATUS =====
app.get('/api/status', validateApiKey, (req, res) => {
  res.json({
    api: 'WHOIS Intelligence Tool - Enhanced with Blacklist Checking',
    version: '2.2.0',
    status: 'operational',
    features: {
      whoisAnalysis: 'enabled',
      privacyInvestigation: 'enabled', 
      recursiveAnalysis: 'enabled',
      threatIntelligence: 'enabled',
      riskScoring: 'enabled',
      bulkAnalysis: 'enabled',
      mxAnalysis: 'enabled',
      blacklistChecking: 'enabled',
      privacyEmailDetection: 'enabled',
      ipReputationChecking: 'enabled'
    },
    endpoints: {
      analysis: '/api/analyze',
      enhancedAnalysis: '/api/analyze-enhanced',
      bulkAnalysis: '/api/bulk-analyze',
      threatAnalysis: '/api/threat-analysis',
      riskScore: '/api/risk-score',
      privacyInvestigation: '/api/privacy-investigation',
      mxAnalysis: '/api/mx-analysis',
      blacklistAnalysis: '/api/blacklist-analysis',
      privacyEmailLookup: '/api/privacy-email-lookup',
      bulkBlacklistAnalysis: '/api/bulk-blacklist-analysis'
    },
    blacklistFeatures: {
      dnsBlacklists: Object.values(DNS_BLACKLISTS).flat().length,
      privacyEmailPatterns: Object.keys(PRIVACY_EMAIL_PATTERNS).length,
      privacyEmailDomains: PRIVACY_EMAIL_DOMAINS.size,
      supportedAPIs: [
        process.env.VIRUSTOTAL_API_KEY ? 'VirusTotal' : null,
        process.env.ABUSEIPDB_API_KEY ? 'AbuseIPDB' : null
      ].filter(Boolean),
      cachingEnabled: true,
      rateLimitingEnabled: true
    },
    limits: {
      rateLimit: '300 requests per 15 minutes',
      apiRateLimit: '60 requests per minute',
      bulkLimit: `${CONFIG.MAX_BULK_DOMAINS} domains per request`
    }
  });
});

// ===== BLACKLIST ENDPOINTS =====

// Blacklist Analysis Endpoint
app.post('/api/blacklist-analysis', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain, emails, ips } = req.body;
    
    if (!domain && (!emails || !ips)) {
      return res.status(400).json({
        success: false,
        error: 'Either domain or emails/ips arrays are required',
        example: { 
          domain: 'example.com',
          emails: ['test@example.com'],
          ips: ['1.2.3.4']
        }
      });
    }
    
    console.log(`[BLACKLIST] Starting blacklist analysis for: ${domain || 'custom data'}`);
    
    let emailsToCheck = emails || [];
    let ipsToCheck = ips || [];
    
    if (domain) {
      const cleanDomain = sanitizeDomain(domain);
      let analysis = cache.get(`analysis:${cleanDomain}`);
      
      if (!analysis) {
        analysis = await performDomainAnalysis(cleanDomain);
        if (analysis.success) {
          cache.set(`analysis:${cleanDomain}`, analysis, CONFIG.CACHE_TTL);
        }
      }
      
      if (analysis.success) {
        if (analysis.whoisData?.emails) {
          emailsToCheck = [...new Set([...emailsToCheck, ...analysis.whoisData.emails])];
        }
        if (analysis.dnsData?.A) {
          ipsToCheck = [...new Set([...ipsToCheck, ...analysis.dnsData.A])];
        }
      }
    }
    
    const blacklistResults = await blacklistChecker.checkEmailAndIPs(emailsToCheck, ipsToCheck);
    
    res.json({
      success: true,
      domain: domain || null,
      timestamp: new Date().toISOString(),
      blacklistAnalysis: blacklistResults,
      responseTime: Date.now() - startTime
    });
    
  } catch (error) {
    console.error('[BLACKLIST ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'Blacklist analysis failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// Enhanced Analysis Endpoint
app.post('/api/analyze-enhanced', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }
    
    const cleanDomain = sanitizeDomain(domain);
    console.log(`[ENHANCED ANALYSIS] Starting for: ${cleanDomain}`);
    
    const analysis = await performDomainAnalysis(cleanDomain);
    
    if (!analysis.success) {
      return res.status(400).json(analysis);
    }
    
    const emails = analysis.whoisData?.emails || [];
    const ips = analysis.dnsData?.A || [];
    
    let blacklistAnalysis = null;
    if (emails.length > 0 || ips.length > 0) {
      try {
        blacklistAnalysis = await blacklistChecker.checkEmailAndIPs(emails, ips);
      } catch (error) {
        console.error('[BLACKLIST ANALYSIS ERROR]', error);
        blacklistAnalysis = {
          error: 'Blacklist analysis failed',
          message: error.message
        };
      }
    }
    
    const [threatData, riskData] = await Promise.allSettled([
      performThreatAnalysis(cleanDomain),
      calculateEnhancedRiskScore(cleanDomain, analysis, null, blacklistAnalysis)
    ]);
    
    res.json({
      ...analysis,
      blacklistAnalysis,
      threatAnalysis: threatData.status === 'fulfilled' ? threatData.value : null,
      riskAnalysis: riskData.status === 'fulfilled' ? riskData.value : null,
      responseTime: Date.now() - startTime
    });
    
  } catch (error) {
    console.error('[ENHANCED ANALYSIS ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'Enhanced analysis failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// Privacy Email Lookup Endpoint
app.post('/api/privacy-email-lookup', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { emails } = req.body;
    
    if (!emails || !Array.isArray(emails)) {
      return res.status(400).json({
        success: false,
        error: 'Emails array is required',
        example: { emails: ['test@example.com', 'privacy@whoisguard.com'] }
      });
    }
    
    console.log(`[PRIVACY LOOKUP] Checking ${emails.length} emails`);
    
    const results = {};
    
    for (const email of emails) {
      const privacyCheck = blacklistChecker.checkPrivacyProtectionEmail(email);
      results[email] = {
        email,
        isPrivacyProtection: privacyCheck.isPrivacy,
        service: privacyCheck.service || null,
        confidence: privacyCheck.confidence || 'low',
        timestamp: new Date().toISOString()
      };
    }
    
    const summary = {
      totalEmails: emails.length,
      privacyEmails: Object.values(results).filter(r => r.isPrivacyProtection).length,
      publicEmails: Object.values(results).filter(r => !r.isPrivacyProtection).length
    };
    
    res.json({
      success: true,
      results,
      summary,
      responseTime: Date.now() - startTime
    });
    
  } catch (error) {
    console.error('[PRIVACY LOOKUP ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'Privacy email lookup failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// Bulk Blacklist Analysis Endpoint
app.post('/api/bulk-blacklist-analysis', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domains } = req.body;
    
    if (!domains || !Array.isArray(domains)) {
      return res.status(400).json({
        success: false,
        error: 'Domains array is required'
      });
    }
    
    if (domains.length > CONFIG.MAX_BULK_DOMAINS) {
      return res.status(400).json({
        success: false,
        error: `Maximum ${CONFIG.MAX_BULK_DOMAINS} domains allowed per request`
      });
    }
    
    console.log(`[BULK BLACKLIST] Processing ${domains.length} domains`);
    
    const results = {};
    
    for (const domain of domains) {
      try {
        const cleanDomain = sanitizeDomain(domain);
        
        let analysis = cache.get(`analysis:${cleanDomain}`);
        if (!analysis) {
          analysis = await performDomainAnalysis(cleanDomain);
        }
        
        if (analysis.success) {
          const emails = analysis.whoisData?.emails || [];
          const ips = analysis.dnsData?.A || [];
          
          if (emails.length > 0 || ips.length > 0) {
            results[cleanDomain] = await blacklistChecker.checkEmailAndIPs(emails, ips);
          } else {
            results[cleanDomain] = {
              timestamp: new Date().toISOString(),
              emails: {},
              ips: {},
              summary: {
                totalEmails: 0,
                totalIPs: 0,
                blacklistedEmails: 0,
                blacklistedIPs: 0,
                privacyEmails: 0,
                suspiciousEmails: 0,
                maliciousIPs: 0,
                overallRisk: 'low'
              },
              message: 'No emails or IPs found for blacklist checking'
            };
          }
        } else {
          results[cleanDomain] = {
            error: 'Domain analysis failed',
            timestamp: new Date().toISOString()
          };
        }
        
        await new Promise(resolve => setTimeout(resolve, 200));
        
      } catch (error) {
        results[domain] = {
          error: error.message,
          timestamp: new Date().toISOString()
        };
      }
    }
    
    const summary = {
      totalDomains: domains.length,
      successfulChecks: Object.values(results).filter(r => !r.error).length,
      failedChecks: Object.values(results).filter(r => r.error).length,
      totalBlacklistedEmails: Object.values(results).reduce((sum, r) => 
        sum + (r.summary?.blacklistedEmails || 0), 0),
      totalBlacklistedIPs: Object.values(results).reduce((sum, r) => 
        sum + (r.summary?.blacklistedIPs || 0), 0),
      totalPrivacyEmails: Object.values(results).reduce((sum, r) => 
        sum + (r.summary?.privacyEmails || 0), 0)
    };
    
    res.json({
      results,
      summary,
      responseTime: Date.now() - startTime
    });
    
  } catch (error) {
    console.error('[BULK BLACKLIST ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'Bulk blacklist analysis failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// ===== ENHANCED EXISTING ENDPOINTS =====

// Main Analysis Endpoint (Enhanced with optional blacklist)
app.post('/api/analyze', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain, includeBlacklist = false } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required',
        example: { domain: 'example.com', includeBlacklist: true }
      });
    }
    
    const cleanDomain = sanitizeDomain(domain);
    
    if (!isValidDomain(cleanDomain)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid domain format',
        domain: cleanDomain
      });
    }
    
    console.log(`[ANALYSIS] Starting analysis for: ${cleanDomain}`);
    
    const cacheKey = `analysis:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    
    if (cached && !includeBlacklist) {
      console.log(`[CACHE HIT] ${cleanDomain}`);
      return res.json({
        ...cached,
        fromCache: true,
        responseTime: Date.now() - startTime
      });
    }
    
    const analysis = await performDomainAnalysis(cleanDomain);
    
    if (includeBlacklist && analysis.success) {
      const emails = analysis.whoisData?.emails || [];
      const ips = analysis.dnsData?.A || [];
      
      if (emails.length > 0 || ips.length > 0) {
        try {
          analysis.blacklistAnalysis = await blacklistChecker.checkEmailAndIPs(emails, ips);
        } catch (error) {
          console.error('[BLACKLIST INTEGRATION ERROR]', error);
          analysis.blacklistAnalysis = {
            error: 'Blacklist analysis failed',
            message: error.message
          };
        }
      }
    }
    
    if (analysis.success) {
      cache.set(cacheKey, analysis, CONFIG.CACHE_TTL);
    }
    
    analysis.responseTime = Date.now() - startTime;
    console.log(`[ANALYSIS COMPLETE] ${cleanDomain} in ${analysis.responseTime}ms`);
    
    res.json(analysis);
    
  } catch (error) {
    console.error('[ANALYSIS ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during analysis',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// Enhanced Risk Scoring (includes blacklist data)
app.post('/api/risk-score', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }
    
    const cleanDomain = sanitizeDomain(domain);
    console.log(`[RISK SCORE] Calculating for: ${cleanDomain}`);
    
    const analysis = await performDomainAnalysis(cleanDomain);
    
    if (!analysis.success) {
      return res.status(400).json({
        success: false,
        error: 'Failed to analyze domain for risk scoring'
      });
    }
    
    const threatAnalysis = await performThreatAnalysis(cleanDomain);
    
    const emails = analysis.whoisData?.emails || [];
    const ips = analysis.dnsData?.A || [];
    let blacklistAnalysis = null;
    
    if (emails.length > 0 || ips.length > 0) {
      try {
        blacklistAnalysis = await blacklistChecker.checkEmailAndIPs(emails, ips);
      } catch (error) {
        console.error('[BLACKLIST ERROR IN RISK]', error);
      }
    }
    
    const riskScore = await calculateEnhancedRiskScore(cleanDomain, analysis, threatAnalysis, blacklistAnalysis);
    
    res.json({
      success: true,
      domain: cleanDomain,
      riskScore: riskScore,
      timestamp: new Date().toISOString(),
      responseTime: Date.now() - startTime
    });
    
  } catch (error) {
    console.error('[RISK SCORE ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'Risk scoring failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// ===== EXISTING ENDPOINTS (keeping all original functionality) =====

// Privacy Investigation Endpoint
app.post('/api/privacy-investigation', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }
    
    const cleanDomain = sanitizeDomain(domain);
    console.log(`[PRIVACY INVESTIGATION] Starting for: ${cleanDomain}`);
    
    const cacheKey = `privacy:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    
    if (cached) {
      return res.json({
        ...cached,
        fromCache: true,
        responseTime: Date.now() - startTime
      });
    }
    
    const basicAnalysis = await performDomainAnalysis(cleanDomain);
    
    if (!basicAnalysis.success) {
      return res.status(400).json({
        success: false,
        error: 'Failed to perform basic domain analysis'
      });
    }
    
    const investigation = {
      domain: cleanDomain,
      timestamp: new Date().toISOString(),
      success: true,
      basicAnalysis: basicAnalysis.summary,
      privacyAnalysis: basicAnalysis.privacyAnalysis,
      responseTime: Date.now() - startTime
    };
    
    cache.set(cacheKey, investigation, CONFIG.CACHE_TTL);
    res.json(investigation);
    
  } catch (error) {
    console.error('[PRIVACY INVESTIGATION ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'Privacy investigation failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// Threat Analysis Endpoint
app.post('/api/threat-analysis', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }
    
    const cleanDomain = sanitizeDomain(domain);
    console.log(`[THREAT] Starting threat analysis for: ${cleanDomain}`);
    
    const cacheKey = `threat:${cleanDomain}`;
    const cached = threatCache.get(cacheKey);
    
    if (cached) {
      return res.json({
        ...cached,
        fromCache: true,
        responseTime: Date.now() - startTime
      });
    }
    
    const threatAnalysis = await performThreatAnalysis(cleanDomain);
    
    if (threatAnalysis.success) {
      threatCache.set(cacheKey, threatAnalysis, CONFIG.THREAT_CACHE_TTL);
    }
    
    threatAnalysis.responseTime = Date.now() - startTime;
    res.json(threatAnalysis);
    
  } catch (error) {
    console.error('[THREAT ANALYSIS ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'Threat analysis failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// MX Analysis Endpoint
app.post('/api/mx-analysis', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required for MX analysis'
      });
    }
    
    const cleanDomain = sanitizeDomain(domain);
    console.log(`[MX ANALYSIS] Starting for: ${cleanDomain}`);
    
    const mxAnalysis = await performComprehensiveMXAnalysis(cleanDomain);
    mxAnalysis.responseTime = Date.now() - startTime;
    
    res.json(mxAnalysis);
    
  } catch (error) {
    console.error('[MX ANALYSIS ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'MX analysis failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// Bulk Analysis Endpoint
app.post('/api/bulk-analyze', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domains } = req.body;
    
    if (!domains || !Array.isArray(domains)) {
      return res.status(400).json({
        success: false,
        error: 'Domains array is required',
        example: { domains: ['example.com', 'test.org'] }
      });
    }
    
    if (domains.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'At least one domain is required'
      });
    }
    
    if (domains.length > CONFIG.MAX_BULK_DOMAINS) {
      return res.status(400).json({
        success: false,
        error: `Maximum ${CONFIG.MAX_BULK_DOMAINS} domains allowed per bulk request`,
        provided: domains.length
      });
    }
    
    console.log(`[BULK ANALYSIS] Processing ${domains.length} domains`);
    
    const results = [];
    let processedCount = 0;
    
    for (const domain of domains) {
      try {
        const cleanDomain = sanitizeDomain(domain);
        
        if (!isValidDomain(cleanDomain)) {
          results.push({
            domain: cleanDomain,
            success: false,
            error: 'Invalid domain format',
            timestamp: new Date().toISOString()
          });
          continue;
        }
        
        const cacheKey = `analysis:${cleanDomain}`;
        let analysis = cache.get(cacheKey);
        
        if (!analysis) {
          analysis = await performDomainAnalysis(cleanDomain);
          if (analysis.success) {
            cache.set(cacheKey, analysis, CONFIG.CACHE_TTL);
          }
        } else {
          analysis.fromCache = true;
        }
        
        results.push(analysis);
        processedCount++;
        
        if (!analysis.fromCache && processedCount < domains.length) {
          await new Promise(resolve => setTimeout(resolve, 500));
        }
        
      } catch (error) {
        console.error(`[BULK ERROR] ${domain}:`, error.message);
        results.push({
          domain: domain,
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    }
    
    const responseTime = Date.now() - startTime;
    const successCount = results.filter(r => r.success).length;
    
    console.log(`[BULK COMPLETE] ${successCount}/${domains.length} successful in ${responseTime}ms`);
    
    res.json({
      results,
      total: results.length,
      successful: successCount,
      failed: results.length - successCount,
      responseTime
    });
    
  } catch (error) {
    console.error('[BULK ANALYSIS ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'Bulk analysis failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// ===== CORE ANALYSIS FUNCTIONS =====

async function performDomainAnalysis(domain) {
  const analysis = {
    domain,
    timestamp: new Date().toISOString(),
    success: true,
    processingTime: null,
    whoisData: null,
    dnsData: null,
    privacyAnalysis: null,
    registrarInfo: null,
    geoData: null,
    summary: {}
  };
  
  const startTime = Date.now();
  
  try {
    console.log(`[WHOIS] Fetching data for ${domain}...`);
    
    analysis.whoisData = await Promise.race([
      getWhoisData(domain),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('WHOIS lookup timeout')), CONFIG.REQUEST_TIMEOUT)
      )
    ]);
    
    console.log(`[DNS] Fetching records for ${domain}...`);
    
    analysis.dnsData = await Promise.race([
      getDNSRecords(domain),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('DNS lookup timeout')), CONFIG.DNS_TIMEOUT)
      )
    ]);
    
    console.log(`[ANALYSIS] Processing intelligence for ${domain}...`);
    
    analysis.privacyAnalysis = await analyzePrivacyProtection(analysis.whoisData);
    analysis.registrarInfo = analyzeRegistrar(analysis.whoisData);
    analysis.geoData = await analyzeGeolocation(analysis.dnsData);
    analysis.summary = generateIntelligenceSummary(analysis);
    
    analysis.processingTime = Date.now() - startTime;
    
  } catch (error) {
    analysis.success = false;
    analysis.error = error.message;
    analysis.processingTime = Date.now() - startTime;
    console.error(`[ANALYSIS FAILED] ${domain}: ${error.message}`);
  }
  
  return analysis;
}

async function performThreatAnalysis(domain) {
  const threatAnalysis = {
    domain,
    success: true,
    timestamp: new Date().toISOString(),
    threats: {
      malicious: false,
      phishing: false,
      malware: false,
      suspicious: false
    },
    indicators: [],
    severity: 'low',
    confidence: 'medium'
  };
  
  try {
    for (const pattern of THREAT_PATTERNS.PHISHING) {
      if (pattern.test(domain)) {
        threatAnalysis.threats.phishing = true;
        threatAnalysis.indicators.push(`Matches phishing pattern`);
        threatAnalysis.severity = 'high';
        break;
      }
    }
    
    for (const pattern of THREAT_PATTERNS.MALWARE) {
      if (pattern.test(domain)) {
        threatAnalysis.threats.malware = true;
        threatAnalysis.indicators.push(`Matches malware pattern`);
        threatAnalysis.severity = 'critical';
        break;
      }
    }
    
    for (const pattern of THREAT_PATTERNS.SUSPICIOUS) {
      if (pattern.test(domain)) {
        threatAnalysis.threats.suspicious = true;
        threatAnalysis.indicators.push(`Matches suspicious pattern`);
        if (threatAnalysis.severity === 'low') {
          threatAnalysis.severity = 'medium';
        }
        break;
      }
    }
    
    if (domain.length > 30) {
      threatAnalysis.threats.suspicious = true;
      threatAnalysis.indicators.push('Unusually long domain name');
    }
    
    if (domain.split('.').length > 3) {
      threatAnalysis.threats.suspicious = true;
      threatAnalysis.indicators.push('Multiple subdomains detected');
    }
    
    const tld = domain.split('.').pop();
    const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'click', 'download', 'zip'];
    if (suspiciousTlds.includes(tld)) {
      threatAnalysis.threats.suspicious = true;
      threatAnalysis.indicators.push(`Suspicious TLD: .${tld}`);
    }
    
    if (threatAnalysis.threats.malware) {
      threatAnalysis.severity = 'critical';
      threatAnalysis.confidence = 'high';
    } else if (threatAnalysis.threats.phishing) {
      threatAnalysis.severity = 'high';
      threatAnalysis.confidence = 'high';
    } else if (threatAnalysis.threats.suspicious && threatAnalysis.indicators.length > 1) {
      threatAnalysis.severity = 'medium';
      threatAnalysis.confidence = 'medium';
    }
    
  } catch (error) {
    threatAnalysis.success = false;
    threatAnalysis.error = error.message;
  }
  
  return threatAnalysis;
}

async function calculateEnhancedRiskScore(domain, analysis, threatAnalysis, blacklistAnalysis) {
  let riskScore = 0;
  const factors = [];
  
  if (analysis.privacyAnalysis?.isPrivate) {
    riskScore += RISK_SCORES.PRIVACY_PROTECTED;
    factors.push({
      factor: 'Privacy Protected',
      score: RISK_SCORES.PRIVACY_PROTECTED,
      description: 'Domain uses privacy protection service'
    });
  }
  
  if (threatAnalysis?.threats?.phishing) {
    riskScore += RISK_SCORES.PHISHING_PATTERN;
    factors.push({
      factor: 'Phishing Pattern',
      score: RISK_SCORES.PHISHING_PATTERN,
      description: 'Domain matches known phishing patterns'
    });
  }
  
  if (threatAnalysis?.threats?.malware) {
    riskScore += RISK_SCORES.MALWARE_PATTERN;
    factors.push({
      factor: 'Malware Pattern',
      score: RISK_SCORES.MALWARE_PATTERN,
      description: 'Domain matches known malware patterns'
    });
  }
  
  // Enhanced blacklist factors
  if (blacklistAnalysis?.summary) {
    if (blacklistAnalysis.summary.blacklistedEmails > 0) {
      riskScore += RISK_SCORES.BLACKLISTED_EMAIL;
      factors.push({
        factor: 'Blacklisted Emails',
        score: RISK_SCORES.BLACKLISTED_EMAIL,
        description: `${blacklistAnalysis.summary.blacklistedEmails} email(s) found on blacklists`
      });
    }
    
    if (blacklistAnalysis.summary.blacklistedIPs > 0) {
      riskScore += RISK_SCORES.BLACKLISTED_IP;
      factors.push({
        factor: 'Blacklisted IPs',
        score: RISK_SCORES.BLACKLISTED_IP,
        description: `${blacklistAnalysis.summary.blacklistedIPs} IP(s) found on blacklists`
      });
    }
    
    if (blacklistAnalysis.summary.privacyEmails > 0) {
      riskScore += RISK_SCORES.PRIVACY_EMAIL;
      factors.push({
        factor: 'Privacy Protection Emails',
        score: RISK_SCORES.PRIVACY_EMAIL,
        description: `${blacklistAnalysis.summary.privacyEmails} privacy protection email(s) detected`
      });
    }
  }
  
  if (!analysis.whoisData?.registrantEmail && !analysis.whoisData?.emails?.length) {
    riskScore += RISK_SCORES.NO_CONTACT_INFO;
    factors.push({
      factor: 'No Contact Information',
      score: RISK_SCORES.NO_CONTACT_INFO,
      description: 'No valid contact information available'
    });
  }
  
  if (analysis.whoisData?.creationDate) {
    const creationDate = new Date(analysis.whoisData.creationDate);
    const daysSinceCreation = (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24);
    
    if (daysSinceCreation < 30) {
      riskScore += RISK_SCORES.SHORT_DOMAIN_AGE;
      factors.push({
        factor: 'Recently Registered',
        score: RISK_SCORES.SHORT_DOMAIN_AGE,
        description: `Domain registered ${Math.floor(daysSinceCreation)} days ago`
      });
    }
  }
  
  let riskLevel = 'low';
  if (riskScore >= 80) {
    riskLevel = 'critical';
  } else if (riskScore >= 60) {
    riskLevel = 'high';
  } else if (riskScore >= 30) {
    riskLevel = 'medium';
  }
  
  return {
    totalScore: Math.min(riskScore, 100),
    maxScore: 100,
    riskLevel: riskLevel,
    factors: factors,
    recommendation: generateRiskRecommendation(riskLevel, riskScore),
    confidence: factors.length >= 3 ? 'high' : factors.length >= 2 ? 'medium' : 'low',
    blacklistFactors: blacklistAnalysis?.summary ? {
      blacklistedEmails: blacklistAnalysis.summary.blacklistedEmails,
      blacklistedIPs: blacklistAnalysis.summary.blacklistedIPs,
      privacyEmails: blacklistAnalysis.summary.privacyEmails,
      overallBlacklistRisk: blacklistAnalysis.summary.overallRisk
    } : null
  };
}

// ===== HELPER FUNCTIONS =====

async function getWhoisData(domain) {
  const methods = [
    () => whoisCommandLookup(domain),
    () => whoisAPILookup(domain)
  ];
  
  for (const method of methods) {
    try {
      const result = await method();
      if (result && result.domain) {
        return result;
      }
    } catch (error) {
      console.log(`[WHOIS METHOD FAILED] ${domain}: ${error.message}`);
    }
  }
  
  throw new Error(`All WHOIS methods failed for ${domain}`);
}

function whoisCommandLookup(domain) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('WHOIS command timeout'));
    }, CONFIG.WHOIS_TIMEOUT);
    
    whois.lookup(domain, { timeout: CONFIG.WHOIS_TIMEOUT - 1000 }, (err, data) => {
      clearTimeout(timeout);
      if (err) {
        reject(new Error(`WHOIS command failed: ${err.message}`));
      } else {
        resolve(parseRawWhois(data, domain));
      }
    });
  });
}

async function whoisAPILookup(domain) {
  try {
    const response = await axios.get(`https://whoisjson.com/api/v1/whois?domain=${domain}`, {
      timeout: CONFIG.WHOIS_TIMEOUT,
      headers: { 
        'User-Agent': 'WHOIS-Intelligence-Tool/2.2',
        ...(process.env.WHOISJSON_API_KEY && { 
          'Authorization': `Bearer ${process.env.WHOISJSON_API_KEY}` 
        })
      }
    });
    
    if (response.data && !response.data.error) {
      return parseWhoisResponse(response.data);
    }
  } catch (error) {
    throw new Error(`WHOIS API failed: ${error.message}`);
  }
  
  return null;
}

async function getDNSRecords(domain) {
  const records = {};
  const startTime = Date.now();
  
  try {
    const [A, AAAA, MX, NS, TXT, SOA] = await Promise.allSettled([
      dns.resolve4(domain),
      dns.resolve6(domain),
      dns.resolveMx(domain),
      dns.resolveNs(domain),
      dns.resolveTxt(domain),
      dns.resolveSoa(domain)
    ]);
    
    records.A = A.status === 'fulfilled' ? A.value : [];
    records.AAAA = AAAA.status === 'fulfilled' ? AAAA.value : [];
    records.MX = MX.status === 'fulfilled' ? MX.value : [];
    records.NS = NS.status === 'fulfilled' ? NS.value : [];
    records.TXT = TXT.status === 'fulfilled' ? TXT.value : [];
    records.SOA = SOA.status === 'fulfilled' ? SOA.value : null;
    
    records.queryTime = Date.now() - startTime;
    
  } catch (error) {
    console.error(`[DNS ERROR] ${domain}: ${error.message}`);
    records.error = error.message;
  }
  
  return records;
}

async function analyzePrivacyProtection(whoisData) {
  const privacyServices = [
    'whoisguard', 'domains by proxy', 'perfect privacy', 'private whois',
    'contact privacy', 'redacted for privacy', 'data protected',
    'privacy service', 'whois privacy', 'private registration'
  ];
  
  const whoisText = JSON.stringify(whoisData).toLowerCase();
  let isPrivate = false;
  let privacyService = null;
  
  for (const service of privacyServices) {
    if (whoisText.includes(service)) {
      isPrivate = true;
      privacyService = service;
      break;
    }
  }
  
  return {
    isPrivate,
    privacyService,
    confidence: isPrivate ? 'high' : 'low'
  };
}

function analyzeRegistrar(whoisData) {
  const registrar = whoisData.registrar || 'Unknown';
  let category = 'Other';
  let isUSBased = false;
  
  const registrarLower = registrar.toLowerCase();
  
  const usRegistrars = {
    'godaddy': { category: 'Major US Commercial', usBased: true },
    'namecheap': { category: 'Discount US Provider', usBased: true },
    'network solutions': { category: 'Legacy US Provider', usBased: true },
    'verisign': { category: 'Legacy US Provider', usBased: true },
    'enom': { category: 'US Wholesale/Reseller', usBased: true },
    'tucows': { category: 'US Wholesale/Reseller', usBased: true },
    'google domains': { category: 'Tech Giant US', usBased: true },
    'amazon': { category: 'Tech Giant US', usBased: true },
    'cloudflare': { category: 'Tech Giant US', usBased: true }
  };
  
  for (const [key, info] of Object.entries(usRegistrars)) {
    if (registrarLower.includes(key)) {
      category = info.category;
      isUSBased = info.usBased;
      break;
    }
  }
  
  return {
    name: registrar,
    category,
    isUSBased,
    country: whoisData.registrantCountry || whoisData.adminCountry || 'Unknown'
  };
}

async function analyzeGeolocation(dnsData) {
  const geoInfo = {
    countries: new Set(),
    regions: new Set(),
    cities: new Set(),
    primaryLocation: null
  };
  
  if (dnsData.A && dnsData.A.length > 0) {
    for (const ip of dnsData.A.slice(0, 3)) {
      const geo = geoip.lookup(ip);
      if (geo) {
        geoInfo.countries.add(geo.country);
        geoInfo.regions.add(geo.region);
        geoInfo.cities.add(geo.city);
        
        if (!geoInfo.primaryLocation) {
          geoInfo.primaryLocation = {
            ip,
            country: geo.country,
            region: geo.region,
            city: geo.city,
            timezone: geo.timezone,
            ll: geo.ll
          };
        }
      }
    }
  }
  
  return {
    countries: Array.from(geoInfo.countries),
    regions: Array.from(geoInfo.regions),
    cities: Array.from(geoInfo.cities),
    primaryLocation: geoInfo.primaryLocation,
    totalIPs: dnsData.A ? dnsData.A.length : 0
  };
}

function generateIntelligenceSummary(analysis) {
  return {
    domain: analysis.domain,
    isUSRegistrar: analysis.registrarInfo?.isUSBased || false,
    registrar: analysis.registrarInfo?.name || 'Unknown',
    registrarCategory: analysis.registrarInfo?.category || 'Unknown',
    isPrivacyProtected: analysis.privacyAnalysis?.isPrivate || false,
    privacyService: analysis.privacyAnalysis?.privacyService || null,
    registrantCountry: analysis.whoisData?.registrantCountry || 'Unknown',
    creationDate: analysis.whoisData?.creationDate || 'Unknown',
    expirationDate: analysis.whoisData?.expirationDate || 'Unknown',
    nameServers: analysis.dnsData?.NS || [],
    primaryIP: analysis.dnsData?.A?.[0] || null,
    geoLocation: analysis.geoData?.primaryLocation || null
  };
}

async function performComprehensiveMXAnalysis(domain) {
  const mxAnalysis = {
    domain,
    timestamp: new Date().toISOString(),
    success: true,
    dnsRecords: null,
    mxRecords: null,
    emailInfrastructure: null,
    securityAnalysis: null
  };
  
  try {
    mxAnalysis.dnsRecords = await getDNSRecords(domain);
    
    if (mxAnalysis.dnsRecords.MX && mxAnalysis.dnsRecords.MX.length > 0) {
      mxAnalysis.mxRecords = await analyzeMXRecords(domain);
    }
    
    mxAnalysis.emailInfrastructure = generateEmailInfrastructureSummary(mxAnalysis);
    mxAnalysis.securityAnalysis = analyzeEmailSecurity(mxAnalysis);
    
  } catch (error) {
    mxAnalysis.success = false;
    mxAnalysis.error = error.message;
  }
  
  return mxAnalysis;
}

async function analyzeMXRecords(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    const mxAnalysis = {
      records: mxRecords,
      providers: [],
      insights: []
    };
    
    for (const mx of mxRecords) {
      const mxDomain = mx.exchange.toLowerCase();
      let provider = 'Unknown';
      
      if (mxDomain.includes('google') || mxDomain.includes('gmail')) {
        provider = 'Google Workspace';
      } else if (mxDomain.includes('outlook') || mxDomain.includes('microsoft')) {
        provider = 'Microsoft 365';
      } else if (mxDomain.includes('amazonaws')) {
        provider = 'Amazon SES';
      }
      
      mxAnalysis.providers.push(provider);
      
      try {
        const mxIPs = await dns.resolve4(mxDomain);
        if (mxIPs.length > 0) {
          const geo = geoip.lookup(mxIPs[0]);
          if (geo) {
            mxAnalysis.insights.push({
              mx: mxDomain,
              ip: mxIPs[0],
              country: geo.country,
              provider: provider,
              priority: mx.priority
            });
          }
        }
      } catch (error) {
        console.log(`MX geo lookup failed for ${mxDomain}`);
      }
    }
    
    return mxAnalysis;
  } catch (error) {
    return { error: error.message };
  }
}

function generateEmailInfrastructureSummary(mxAnalysis) {
  const summary = {
    primaryProvider: 'Unknown',
    isUSBased: false,
    providers: []
  };
  
  if (mxAnalysis.mxRecords && mxAnalysis.mxRecords.providers) {
    summary.providers = [...new Set(mxAnalysis.mxRecords.providers)];
    summary.primaryProvider = summary.providers[0] || 'Unknown';
    summary.isUSBased = summary.providers.some(provider => 
      provider.includes('Google') || 
      provider.includes('Microsoft') || 
      provider.includes('Amazon')
    );
  }
  
  return summary;
}

function analyzeEmailSecurity(mxAnalysis) {
  const security = {
    overallRating: 'Unknown',
    tlsSupport: 'Unknown',
    strengths: [],
    vulnerabilities: []
  };
  
  if (mxAnalysis.mxRecords?.providers?.some(p => 
    p.includes('Google') || p.includes('Microsoft') || p.includes('Amazon')
  )) {
    security.tlsSupport = 'Supported';
    security.strengths.push('TLS encryption supported by email provider');
    security.overallRating = 'Good';
  } else {
    security.overallRating = 'Unknown';
  }
  
  return security;
}

function parseRawWhois(rawData, domain) {
  const lines = rawData.split('\n');
  const parsed = { domain, rawData };
  
  for (const line of lines) {
    const lower = line.toLowerCase();
    
    if (lower.includes('registrar:') && !parsed.registrar) {
      parsed.registrar = line.split(':')[1]?.trim();
    } else if ((lower.includes('creation date:') || lower.includes('created:')) && !parsed.creationDate) {
      parsed.creationDate = line.split(':')[1]?.trim();
    } else if (lower.includes('expir') && !parsed.expirationDate) {
      parsed.expirationDate = line.split(':')[1]?.trim();
    } else if (lower.includes('registrant country:') && !parsed.registrantCountry) {
      parsed.registrantCountry = line.split(':')[1]?.trim();
    }
  }
  
  parsed.emails = extractEmails(rawData);
  
  const nsRegex = /name server:\s*([^\s\r\n]+)/gi;
  const nameServers = [];
  let match;
  while ((match = nsRegex.exec(rawData)) !== null) {
    nameServers.push(match[1].toLowerCase());
  }
  parsed.nameServers = [...new Set(nameServers)];
  
  return parsed;
}

function parseWhoisResponse(data) {
  return {
    domain: data.domain,
    registrar: data.registrar,
    creationDate: data.creation_date || data.created,
    expirationDate: data.expiration_date || data.expires,
    updatedDate: data.updated_date || data.updated,
    status: data.status,
    registrantName: data.registrant_name,
    registrantOrganization: data.registrant_organization,
    registrantEmail: data.registrant_email,
    registrantCountry: data.registrant_country,
    adminEmail: data.admin_email,
    techEmail: data.tech_email,
    nameServers: data.name_servers || data.nameservers,
    emails: extractEmails(JSON.stringify(data)),
    rawData: data
  };
}

function extractEmails(text) {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = text.match(emailRegex) || [];
  return [...new Set(emails.map(email => email.toLowerCase()))];
}

function generateRiskRecommendation(riskLevel, score) {
  switch (riskLevel) {
    case 'critical':
      return `CRITICAL RISK (${score}/100): Immediate action required. This domain poses significant security risks and should be blocked or investigated immediately.`;
    case 'high':
      return `HIGH RISK (${score}/100): Exercise extreme caution. Additional security measures and monitoring recommended.`;
    case 'medium':
      return `MODERATE RISK (${score}/100): Some concerning indicators present. Additional investigation recommended before trusting.`;
    case 'low':
      return `LOW RISK (${score}/100): Domain appears legitimate. Standard security practices should be sufficient.`;
    default:
      return 'Risk assessment inconclusive. Manual review recommended.';
  }
}

// ===== ROOT ENDPOINT =====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ===== ERROR HANDLING =====
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err.stack);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    availableEndpoints: [
      '/health', 
      '/api/status', 
      '/api/analyze', 
      '/api/analyze-enhanced',
      '/api/bulk-analyze', 
      '/api/threat-analysis', 
      '/api/risk-score',
      '/api/privacy-investigation',
      '/api/mx-analysis',
      '/api/blacklist-analysis',
      '/api/privacy-email-lookup',
      '/api/bulk-blacklist-analysis'
    ]
  });
});

// ===== GRACEFUL SHUTDOWN =====
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully...');
  process.exit(0);
});

// ===== SERVER STARTUP =====
app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('🚀 WHOIS Intelligence Enhanced Server v2.2');
  console.log('='.repeat(60));
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 API status: http://localhost:${PORT}/api/status`);
  console.log(`💾 Cache TTL: ${CONFIG.CACHE_TTL / 3600} hours`);
  console.log(`⚡ Rate limits: 300 per 15min (general), 60 per min (API)`);
  console.log(`🔐 API Key validation: ${VALID_API_KEYS.size} keys configured`);
  console.log(`🚫 Blacklist checking: ENABLED`);
  console.log(`📧 Privacy email detection: ${PRIVACY_EMAIL_DOMAINS.size} known services`);
  console.log(`🌐 DNS blacklists: ${Object.values(DNS_BLACKLISTS).flat().length} lists`);
  console.log(`🔍 Features: WHOIS, Privacy Investigation, Threat Analysis, Risk Scoring, MX Analysis, Blacklist Checking`);
  console.log('='.repeat(60));
});

module.exports = app;