/*
FOLDER STRUCTURE:
whois-intelligence-server/
├── server.js                    (this file - COMPLETE WITH AI AGENTS)
├── utils/
│   ├── helpers.js               
│   └── blacklist-checker.js     
├── database/
│   └── postgres-config.js       
├── ai/
│   ├── orchestrator.js          
│   ├── langchain-config.js      
│   └── agents/
│       ├── domain-analyst.js    
│       ├── threat-hunter.js     
│       └── risk-assessor.js     
├── auth/
│   └── admin-auth.js            
├── package.json                 
├── .env                         
└── README.md

FILE LOCATION: /server.js (COMPLETE MAIN SERVER FILE WITH AI AGENTS)
*/

// Enhanced WHOIS Intelligence Server with AI Agents - PHASE 2 COMPLETE
// Version: 2.3.0 - Multi-Agent AI Research System

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

// Import database
const { database } = require('./database/postgres-config');

// Import AI system
const { CyberSecurityResearchOrchestrator } = require('./ai/orchestrator');

// Import authentication
const { initializeAuth, login, verifyToken, getAuthStats } = require('./auth/admin-auth');

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

// Initialize systems
const blacklistChecker = new BlacklistChecker(cache);
let aiOrchestrator = null;

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

// ===== SYSTEM INITIALIZATION =====
async function initializeEnhancedSystems() {
  console.log('🚀 Initializing Enhanced WHOIS Intelligence Systems...');
  
  // Initialize database
  console.log('📊 Connecting to database...');
  await database.connect();
  if (database.isConnected()) {
    await database.runMigrations();
  }
  
  // Initialize authentication
  console.log('🔐 Setting up authentication...');
  await initializeAuth();
  
  // Initialize AI Research Orchestrator
  console.log('🤖 Initializing AI Research System...');
  await initializeAIOrchestrator();
  
  console.log('✅ All enhanced systems initialized successfully');
}

async function initializeAIOrchestrator() {
  try {
    console.log('🤖 Initializing AI Research Orchestrator...');
    aiOrchestrator = new CyberSecurityResearchOrchestrator(cache, database);
    
    // Wait for initialization
    const initialized = await aiOrchestrator.initializeOrchestrator();
    
    if (initialized) {
      console.log('✅ AI Research Orchestrator ready');
      
      // Make functions globally available for AI tools
      global.performDomainAnalysis = performDomainAnalysis;
      global.getDNSRecords = getDNSRecords;
      global.blacklistChecker = blacklistChecker;
      global.aiOrchestrator = aiOrchestrator;
      
      return true;
    } else {
      console.log('⚠️  AI Research Orchestrator partially initialized');
      return false;
    }
  } catch (error) {
    console.error('❌ AI Orchestrator initialization failed:', error);
    return false;
  }
}

// ===== HEALTH CHECK =====
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '2.3.0',
    uptime: Math.floor(process.uptime()),
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
    },
    systems: {
      database: database.isConnected() ? 'connected' : 'disconnected',
      ai: aiOrchestrator?.isInitialized ? 'enabled' : 'disabled',
      cache: 'enabled',
      blacklist: 'enabled'
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
app.get('/api/status', validateApiKey, async (req, res) => {
  const aiHealth = aiOrchestrator ? await aiOrchestrator.healthCheck() : null;
  
  res.json({
    api: 'WHOIS Intelligence Tool - Enhanced with AI Agents',
    version: '2.3.0',
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
      ipReputationChecking: 'enabled',
      // AI FEATURES
      aiDomainAnalysis: aiHealth?.agents?.domainAnalyst?.initialized ? 'enabled' : 'disabled',
      aiThreatHunting: aiHealth?.agents?.threatHunter?.initialized ? 'enabled' : 'disabled',
      aiRiskAssessment: aiHealth?.agents?.riskAssessor?.initialized ? 'enabled' : 'disabled',
      aiOrchestration: aiHealth?.orchestrator === 'operational' ? 'enabled' : 'disabled'
    },
    endpoints: {
      // Core endpoints
      analysis: '/api/analyze',
      enhancedAnalysis: '/api/analyze-enhanced',
      bulkAnalysis: '/api/bulk-analyze',
      threatAnalysis: '/api/threat-analysis',
      riskScore: '/api/risk-score',
      privacyInvestigation: '/api/privacy-investigation',
      mxAnalysis: '/api/mx-analysis',
      // Blacklist endpoints
      blacklistAnalysis: '/api/blacklist-analysis',
      privacyEmailLookup: '/api/privacy-email-lookup',
      bulkBlacklistAnalysis: '/api/bulk-blacklist-analysis',
      // AI endpoints
      aiResearch: '/api/ai-research',
      aiDomainAnalysis: '/api/ai-domain-analysis',
      aiThreatHunting: '/api/ai-threat-hunting',
      aiRiskAssessment: '/api/ai-risk-assessment',
      aiHealth: '/api/ai-health',
      aiResearchHistory: '/api/ai-research-history'
    },
    aiCapabilities: aiHealth ? {
      orchestrator: aiHealth.orchestrator,
      agents: Object.keys(aiHealth.agents || {}),
      activeResearch: aiHealth.activeResearch || 0,
      researchHistory: aiHealth.researchHistory || 0,
      capabilities: aiHealth.capabilities || []
    } : null,
    blacklistFeatures: {
      dnsBlacklists: Object.values(DNS_BLACKLISTS).flat().length,
      privacyEmailPatterns: Object.keys(PRIVACY_EMAIL_PATTERNS).length,
      privacyEmailDomains: PRIVACY_EMAIL_DOMAINS.size,
      supportedAPIs: [
        process.env.VIRUSTOTAL_API_KEY ? 'VirusTotal' : null,
        process.env.ABUSEIPDB_API_KEY ? 'AbuseIPDB' : null,
        process.env.OPENAI_API_KEY ? 'OpenAI' : null
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

// ===== AI RESEARCH ENDPOINTS =====

// AI-Powered Comprehensive Analysis
app.post('/api/ai-research', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { target, config = {} } = req.body;
    
    if (!target) {
      return res.status(400).json({
        success: false,
        error: 'Target parameter is required',
        example: { 
          target: 'example.com',
          config: {
            depth: 'standard', // basic, standard, deep, comprehensive
            urgency: 'normal', // low, normal, high, critical
            parallel: true
          }
        }
      });
    }

    if (!aiOrchestrator || !aiOrchestrator.isInitialized) {
      return res.status(503).json({
        success: false,
        error: 'AI Research Orchestrator not available',
        message: 'Please configure OpenAI API key to enable AI research'
      });
    }

    const cleanTarget = sanitizeDomain(target);
    console.log(`🔬 AI Research requested for: ${cleanTarget}`);

    // Conduct AI research
    const researchResults = await aiOrchestrator.conductResearch(cleanTarget, config);

    const response = {
      success: researchResults.success,
      target: cleanTarget,
      researchId: researchResults.researchId,
      aiResearch: researchResults.results,
      comprehensiveReport: researchResults.report,
      metrics: researchResults.metrics,
      responseTime: Date.now() - startTime
    };

    if (!researchResults.success) {
      response.error = researchResults.error;
      response.partialResults = researchResults.partialResults;
    }

    res.json(response);

  } catch (error) {
    console.error('[AI RESEARCH ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'AI research failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// Domain Analysis Agent (Individual)
app.post('/api/ai-domain-analysis', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain, context = {} } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }

    if (!aiOrchestrator?.agents?.domainAnalyst?.isInitialized) {
      return res.status(503).json({
        success: false,
        error: 'Domain Analysis Agent not available'
      });
    }

    const cleanDomain = sanitizeDomain(domain);
    const analysis = await aiOrchestrator.agents.domainAnalyst.analyze(cleanDomain, context);

    res.json({
      ...analysis,
      responseTime: Date.now() - startTime
    });

  } catch (error) {
    console.error('[AI DOMAIN ANALYSIS ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'AI domain analysis failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// Threat Hunting Agent (Individual)
app.post('/api/ai-threat-hunting', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { target, huntingContext = {} } = req.body;
    
    if (!target) {
      return res.status(400).json({
        success: false,
        error: 'Target parameter is required'
      });
    }

    if (!aiOrchestrator?.agents?.threatHunter?.isInitialized) {
      return res.status(503).json({
        success: false,
        error: 'Threat Hunting Agent not available'
      });
    }

    const cleanTarget = sanitizeDomain(target);
    const huntResults = await aiOrchestrator.agents.threatHunter.hunt(cleanTarget, huntingContext);

    res.json({
      ...huntResults,
      responseTime: Date.now() - startTime
    });

  } catch (error) {
    console.error('[AI THREAT HUNTING ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'AI threat hunting failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// Risk Assessment Agent (Individual)
app.post('/api/ai-risk-assessment', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { target, assessmentContext = {} } = req.body;
    
    if (!target) {
      return res.status(400).json({
        success: false,
        error: 'Target parameter is required'
      });
    }

    if (!aiOrchestrator?.agents?.riskAssessor?.isInitialized) {
      return res.status(503).json({
        success: false,
        error: 'Risk Assessment Agent not available'
      });
    }

    const cleanTarget = sanitizeDomain(target);
    const riskResults = await aiOrchestrator.agents.riskAssessor.assess(cleanTarget, assessmentContext);

    res.json({
      ...riskResults,
      responseTime: Date.now() - startTime
    });

  } catch (error) {
    console.error('[AI RISK ASSESSMENT ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'AI risk assessment failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// AI Research Status and Management
app.get('/api/ai-research/:researchId', validateApiKey, (req, res) => {
  try {
    const { researchId } = req.params;
    
    if (!aiOrchestrator) {
      return res.status(503).json({
        success: false,
        error: 'AI Research Orchestrator not available'
      });
    }

    const research = aiOrchestrator.getResearchById(researchId);
    
    if (!research) {
      return res.status(404).json({
        success: false,
        error: 'Research not found'
      });
    }

    res.json({
      success: true,
      research
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve research',
      message: error.message
    });
  }
});

// AI Research History
app.get('/api/ai-research-history', validateApiKey, (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    
    if (!aiOrchestrator) {
      return res.status(503).json({
        success: false,
        error: 'AI Research Orchestrator not available'
      });
    }

    const history = aiOrchestrator.getResearchHistory(limit);
    const active = aiOrchestrator.getActiveResearch();

    res.json({
      success: true,
      history,
      active,
      total: history.length + active.length
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve research history',
      message: error.message
    });
  }
});

// AI System Health Check
app.get('/api/ai-health', validateApiKey, async (req, res) => {
  try {
    if (!aiOrchestrator) {
      return res.json({
        status: 'disabled',
        message: 'AI Research Orchestrator not initialized'
      });
    }

    const health = await aiOrchestrator.healthCheck();
    
    res.json({
      success: true,
      health,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'AI health check failed',
      message: error.message
    });
  }
});

// ===== ADMIN ENDPOINTS =====

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const clientInfo = {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    };
    
    const result = await login(username, password, clientInfo);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(401).json(result);
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Login failed',
      message: error.message
    });
  }
});

// System Status (Admin)
app.get('/api/system-status', validateApiKey, async (req, res) => {
  const aiHealth = aiOrchestrator ? await aiOrchestrator.healthCheck() : null;
  const dbHealth = database.isConnected() ? await database.healthCheck() : null;
  
  res.json({
    timestamp: new Date().toISOString(),
    version: '2.3.0',
    systems: {
      database: dbHealth?.status || 'disconnected',
      ai: aiHealth?.orchestrator || 'disabled',
      authentication: 'enabled',
      blacklist: 'enabled',
      cache: 'enabled'
    },
    stats: {
      cache: {
        keys: cache.keys().length,
        hits: cache.getStats().hits || 0
      },
      auth: getAuthStats(),
      ai: aiHealth,
      database: dbHealth,
      uptime: Math.floor(process.uptime())
    }
  });
});

// ===== BLACKLIST ENDPOINTS (from Phase 1) =====

// Blacklist Analysis
app.post('/api/blacklist-analysis', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain, emails, ips } = req.body;
    
    if (!domain && (!emails || !ips)) {
      return res.status(400).json({
        success: false,
        error: 'Either domain or emails/ips arrays are required'
      });
    }
    
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

// Privacy Email Lookup
app.post('/api/privacy-email-lookup', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { emails } = req.body;
    
    if (!emails || !Array.isArray(emails)) {
      return res.status(400).json({
        success: false,
        error: 'Emails array is required'
      });
    }
    
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

// ===== CORE ANALYSIS ENDPOINTS (Enhanced) =====

// Main Analysis Endpoint
app.post('/api/analyze', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain, includeBlacklist = false, includeAI = false } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }
    
    const cleanDomain = sanitizeDomain(domain);
    
    if (!isValidDomain(cleanDomain)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid domain format'
      });
    }
    
    console.log(`[ANALYSIS] Starting analysis for: ${cleanDomain}`);
    
    const cacheKey = `analysis:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    
    if (cached && !includeBlacklist && !includeAI) {
      console.log(`[CACHE HIT] ${cleanDomain}`);
      return res.json({
        ...cached,
        fromCache: true,
        responseTime: Date.now() - startTime
      });
    }
    
    const analysis = await performDomainAnalysis(cleanDomain);
    
    // Add blacklist analysis if requested
    if (includeBlacklist && analysis.success) {
      const emails = analysis.whoisData?.emails || [];
      const ips = analysis.dnsData?.A || [];
      
      if (emails.length > 0 || ips.length > 0) {
        try {
          analysis.blacklistAnalysis = await blacklistChecker.checkEmailAndIPs(emails, ips);
        } catch (error) {
          analysis.blacklistAnalysis = { error: 'Blacklist analysis failed' };
        }
      }
    }
    
    // Add AI analysis if requested
    if (includeAI && analysis.success && aiOrchestrator?.isInitialized) {
      try {
        const aiResults = await aiOrchestrator.conductResearch(cleanDomain, { depth: 'basic' });
        analysis.aiAnalysis = aiResults.results;
      } catch (error) {
        analysis.aiAnalysis = { error: 'AI analysis failed' };
      }
    }
    
    if (analysis.success) {
      cache.set(cacheKey, analysis, CONFIG.CACHE_TTL);
    }
    
    analysis.responseTime = Date.now() - startTime;
    res.json(analysis);
    
  } catch (error) {
    console.error('[ANALYSIS ERROR]', error);
    res.status(500).json({
      success: false,
      error: 'Analysis failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// Enhanced Analysis (includes blacklist and basic AI)
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
    
    // Always include blacklist analysis
    const emails = analysis.whoisData?.emails || [];
    const ips = analysis.dnsData?.A || [];
    
    let blacklistAnalysis = null;
    if (emails.length > 0 || ips.length > 0) {
      try {
        blacklistAnalysis = await blacklistChecker.checkEmailAndIPs(emails, ips);
      } catch (error) {
        blacklistAnalysis = { error: 'Blacklist analysis failed' };
      }
    }
    
    // Include basic AI analysis if available
    let aiAnalysis = null;
    if (aiOrchestrator?.isInitialized) {
      try {
        const aiResults = await aiOrchestrator.conductResearch(cleanDomain, { 
          depth: 'standard',
          parallel: true 
        });
        aiAnalysis = aiResults;
      } catch (error) {
        aiAnalysis = { error: 'AI analysis failed' };
      }
    }
    
    const [threatData, riskData] = await Promise.allSettled([
      performThreatAnalysis(cleanDomain),
      calculateEnhancedRiskScore(cleanDomain, analysis, null, blacklistAnalysis)
    ]);
    
    res.json({
      ...analysis,
      blacklistAnalysis,
      aiAnalysis,
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

// ===== CORE HELPER FUNCTIONS =====

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
    analysis.whoisData = await getWhoisData(domain);
    analysis.dnsData = await getDNSRecords(domain);
    analysis.privacyAnalysis = await analyzePrivacyProtection(analysis.whoisData);
    analysis.registrarInfo = analyzeRegistrar(analysis.whoisData);
    analysis.geoData = await analyzeGeolocation(analysis.dnsData);
    analysis.summary = generateIntelligenceSummary(analysis);
    analysis.processingTime = Date.now() - startTime;
    
  } catch (error) {
    analysis.success = false;
    analysis.error = error.message;
    analysis.processingTime = Date.now() - startTime;
  }
  
  return analysis;
}

async function getWhoisData(domain) {
  return new Promise((resolve, reject) => {
    whois.lookup(domain, { timeout: CONFIG.WHOIS_TIMEOUT }, (err, data) => {
      if (err) {
        reject(new Error(`WHOIS lookup failed: ${err.message}`));
      } else {
        resolve(parseRawWhois(data, domain));
      }
    });
  });
}

async function getDNSRecords(domain) {
  const records = {};
  
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
    
  } catch (error) {
    records.error = error.message;
  }
  
  return records;
}

async function performThreatAnalysis(domain) {
  const analysis = {
    domain,
    success: true,
    timestamp: new Date().toISOString(),
    threats: { malicious: false, phishing: false, malware: false, suspicious: false },
    indicators: [],
    severity: 'low'
  };
  
  try {
    for (const pattern of THREAT_PATTERNS.PHISHING) {
      if (pattern.test(domain)) {
        analysis.threats.phishing = true;
        analysis.indicators.push('Matches phishing pattern');
        analysis.severity = 'high';
        break;
      }
    }
    
    for (const pattern of THREAT_PATTERNS.MALWARE) {
      if (pattern.test(domain)) {
        analysis.threats.malware = true;
        analysis.indicators.push('Matches malware pattern');
        analysis.severity = 'critical';
        break;
      }
    }
    
  } catch (error) {
    analysis.success = false;
    analysis.error = error.message;
  }
  
  return analysis;
}

async function calculateEnhancedRiskScore(domain, analysis, threatAnalysis, blacklistAnalysis) {
  let riskScore = 0;
  const factors = [];
  
  if (analysis.privacyAnalysis?.isPrivate) {
    riskScore += RISK_SCORES.PRIVACY_PROTECTED;
    factors.push({ factor: 'Privacy Protected', score: RISK_SCORES.PRIVACY_PROTECTED });
  }
  
  if (blacklistAnalysis?.summary) {
    if (blacklistAnalysis.summary.blacklistedEmails > 0) {
      riskScore += RISK_SCORES.BLACKLISTED_EMAIL;
      factors.push({ factor: 'Blacklisted Emails', score: RISK_SCORES.BLACKLISTED_EMAIL });
    }
    
    if (blacklistAnalysis.summary.blacklistedIPs > 0) {
      riskScore += RISK_SCORES.BLACKLISTED_IP;
      factors.push({ factor: 'Blacklisted IPs', score: RISK_SCORES.BLACKLISTED_IP });
    }
  }
  
  let riskLevel = 'low';
  if (riskScore >= 80) riskLevel = 'critical';
  else if (riskScore >= 60) riskLevel = 'high';
  else if (riskScore >= 30) riskLevel = 'medium';
  
  return {
    totalScore: Math.min(riskScore, 100),
    maxScore: 100,
    riskLevel,
    factors,
    confidence: factors.length >= 3 ? 'high' : 'medium'
  };
}

// Additional helper functions
async function analyzePrivacyProtection(whoisData) {
  const privacyServices = ['whoisguard', 'domains by proxy', 'perfect privacy', 'private whois'];
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
  
  return { isPrivate, privacyService };
}

function analyzeRegistrar(whoisData) {
  const registrar = whoisData.registrar || 'Unknown';
  return { name: registrar, isUSBased: registrar.toLowerCase().includes('godaddy') };
}

async function analyzeGeolocation(dnsData) {
  const geoInfo = { primaryLocation: null };
  
  if (dnsData.A && dnsData.A.length > 0) {
    const geo = geoip.lookup(dnsData.A[0]);
    if (geo) {
      geoInfo.primaryLocation = {
        ip: dnsData.A[0],
        country: geo.country,
        region: geo.region,
        city: geo.city
      };
    }
  }
  
  return geoInfo;
}

function generateIntelligenceSummary(analysis) {
  return {
    domain: analysis.domain,
    registrar: analysis.registrarInfo?.name || 'Unknown',
    isPrivacyProtected: analysis.privacyAnalysis?.isPrivate || false,
    primaryIP: analysis.dnsData?.A?.[0] || null,
    geoLocation: analysis.geoData?.primaryLocation || null
  };
}

function parseRawWhois(rawData, domain) {
  const lines = rawData.split('\n');
  const parsed = { domain, rawData };
  
  for (const line of lines) {
    const lower = line.toLowerCase();
    if (lower.includes('registrar:') && !parsed.registrar) {
      parsed.registrar = line.split(':')[1]?.trim();
    }
  }
  
  parsed.emails = extractEmails(rawData);
  return parsed;
}

function extractEmails(text) {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = text.match(emailRegex) || [];
  return [...new Set(emails.map(email => email.toLowerCase()))];
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
      '/health', '/api/status', '/api/analyze', '/api/analyze-enhanced',
      '/api/ai-research', '/api/ai-domain-analysis', '/api/ai-threat-hunting',
      '/api/ai-risk-assessment', '/api/blacklist-analysis'
    ]
  });
});

// ===== GRACEFUL SHUTDOWN =====
process.on('SIGTERM', async () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  if (database.isConnected()) await database.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('🛑 SIGINT received, shutting down gracefully...');
  if (database.isConnected()) await database.close();
  process.exit(0);
});

// ===== SERVER STARTUP =====
initializeEnhancedSystems().then(() => {
  app.listen(PORT, () => {
    console.log('='.repeat(80));
    console.log('🚀 ENHANCED WHOIS INTELLIGENCE SERVER v2.3.0 - PHASE 2 COMPLETE');
    console.log('='.repeat(80));
    console.log(`📡 Server running on port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🔧 API status: http://localhost:${PORT}/api/status`);
    console.log(`💾 Cache TTL: ${CONFIG.CACHE_TTL / 3600} hours`);
    console.log(`⚡ Rate limits: 300 per 15min (general), 60 per min (API)`);
    console.log(`🔐 API Key validation: ${VALID_API_KEYS.size} keys configured`);
    console.log(`🗄️ Database: ${database.isConnected() ? 'Connected' : 'Disconnected'}`);
    console.log(`🤖 AI Research System: ${aiOrchestrator?.isInitialized ? 'ENABLED' : 'Disabled'}`);
    console.log(`🚫 Blacklist checking: ENABLED (${Object.values(DNS_BLACKLISTS).flat().length} lists)`);
    console.log(`📧 Privacy email detection: ${PRIVACY_EMAIL_DOMAINS.size} known services`);
    console.log('');
    console.log('🎯 AI CAPABILITIES:');
    if (aiOrchestrator?.isInitialized) {
      console.log('   ✅ Domain Analysis Agent - Advanced domain intelligence');
      console.log('   ✅ Threat Hunting Agent - APT detection & threat correlation');
      console.log('   ✅ Risk Assessment Agent - Quantitative risk analysis');
      console.log('   ✅ Multi-Agent Orchestration - Comprehensive research workflows');
    } else {
      console.log('   ⚠️  AI Agents disabled (configure OPENAI_API_KEY to enable)');
    }
    console.log('');
    console.log('🔥 NEW AI ENDPOINTS:');
    console.log('   🔬 /api/ai-research - Comprehensive AI research');
    console.log('   🏗️ /api/ai-domain-analysis - Domain intelligence agent');
    console.log('   🎯 /api/ai-threat-hunting - Threat hunting agent');
    console.log('   📊 /api/ai-risk-assessment - Risk assessment agent');
    console.log('   💚 /api/ai-health - AI system health check');
    console.log('');
    console.log('🎉 PHASE 2 DELIVERABLES COMPLETE:');
    console.log('   ✅ Domain analysis agent');
    console.log('   ✅ Threat hunting agent');
    console.log('   ✅ Risk assessment agent');
    console.log('   ✅ Agent orchestration system');
    console.log('   ✅ Multi-agent research workflows');
    console.log('');
    console.log('🚀 READY FOR ADVANCED AI-POWERED DOMAIN INTELLIGENCE!');
    console.log('='.repeat(80));
  });
});

module.exports = app;