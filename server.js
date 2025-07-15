// Enhanced WHOIS Intelligence Server - Production Ready
// Version: 2.1.0 - Consolidated and Improved

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const whois = require('whois');
const dns = require('dns').promises;
const axios = require('axios');
const geoip = require('geoip-lite');
const path = require('path');
const crypto = require('crypto');

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

// ===== SECURITY & VALIDATION =====
const VALID_API_KEYS = new Set([
  process.env.API_KEY || 'demo-key-12345678',
  'whois-intelligence-key-2024'
]);

const validateApiKey = (req, res, next) => {
  // Skip API key validation for health check and static files
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
  UNUSUAL_TLD: 10
};

// ===== HEALTH CHECK =====
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '2.1.0',
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
    api: 'WHOIS Intelligence Tool - Enhanced',
    version: '2.1.0',
    status: 'operational',
    features: {
      whoisAnalysis: 'enabled',
      privacyInvestigation: 'enabled', 
      recursiveAnalysis: 'enabled',
      threatIntelligence: 'enabled',
      riskScoring: 'enabled',
      bulkAnalysis: 'enabled',
      mxAnalysis: 'enabled'
    },
    endpoints: {
      analysis: '/api/analyze',
      bulkAnalysis: '/api/bulk-analyze',
      threatAnalysis: '/api/threat-analysis',
      riskScore: '/api/risk-score',
      privacyInvestigation: '/api/privacy-investigation',
      mxAnalysis: '/api/mx-analysis'
    },
    limits: {
      rateLimit: '300 requests per 15 minutes',
      apiRateLimit: '60 requests per minute',
      bulkLimit: `${CONFIG.MAX_BULK_DOMAINS} domains per request`
    }
  });
});

// ===== MAIN ANALYSIS ENDPOINT =====
app.post('/api/analyze', validateApiKey, apiLimiter, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required',
        example: { domain: 'example.com' }
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
    
    // Check cache
    const cacheKey = `analysis:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    
    if (cached) {
      console.log(`[CACHE HIT] ${cleanDomain}`);
      return res.json({
        ...cached,
        fromCache: true,
        responseTime: Date.now() - startTime
      });
    }
    
    // Perform analysis
    const analysis = await performDomainAnalysis(cleanDomain);
    
    // Cache successful results
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

// ===== PRIVACY INVESTIGATION ENDPOINT =====
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
    
    // Check cache
    const cacheKey = `privacy:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    
    if (cached) {
      return res.json({
        ...cached,
        fromCache: true,
        responseTime: Date.now() - startTime
      });
    }
    
    // Get basic analysis first
    const basicAnalysis = await performDomainAnalysis(cleanDomain);
    
    if (!basicAnalysis.success) {
      return res.status(400).json({
        success: false,
        error: 'Failed to perform basic domain analysis'
      });
    }
    
    // Enhanced privacy analysis with recursive investigation
    const enhancedPrivacyAnalysis = await analyzePrivacyProtectionEnhanced(
      basicAnalysis.whoisData, 
      cleanDomain
    );
    
    const investigation = {
      domain: cleanDomain,
      timestamp: new Date().toISOString(),
      success: true,
      basicAnalysis: basicAnalysis.summary,
      privacyAnalysis: enhancedPrivacyAnalysis,
      investigationReport: null,
      responseTime: Date.now() - startTime
    };
    
    // Generate comprehensive report
    if (enhancedPrivacyAnalysis.needsInvestigation) {
      investigation.investigationReport = generateComprehensiveReport(
        enhancedPrivacyAnalysis, 
        cleanDomain
      );
    }
    
    // Cache results
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

// ===== THREAT ANALYSIS ENDPOINT =====
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
    
    // Check cache
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

// ===== RISK SCORING ENDPOINT =====
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
    const riskScore = calculateRiskScore(cleanDomain, analysis, threatAnalysis);
    
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

// ===== BULK ANALYSIS ENDPOINT =====
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
        
        // Rate limiting between requests
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

// ===== MX ANALYSIS ENDPOINT =====
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
    
    // WHOIS Lookup with timeout
    analysis.whoisData = await Promise.race([
      getWhoisData(domain),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('WHOIS lookup timeout')), CONFIG.REQUEST_TIMEOUT)
      )
    ]);
    
    console.log(`[DNS] Fetching records for ${domain}...`);
    
    // DNS Records with timeout
    analysis.dnsData = await Promise.race([
      getDNSRecords(domain),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('DNS lookup timeout')), CONFIG.DNS_TIMEOUT)
      )
    ]);
    
    console.log(`[ANALYSIS] Processing intelligence for ${domain}...`);
    
    // Privacy Protection Analysis
    analysis.privacyAnalysis = await analyzePrivacyProtection(analysis.whoisData);
    
    // Registrar Analysis
    analysis.registrarInfo = analyzeRegistrar(analysis.whoisData);
    
    // Geographic Analysis
    analysis.geoData = await analyzeGeolocation(analysis.dnsData);
    
    // Generate Summary
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
        'User-Agent': 'WHOIS-Intelligence-Tool/2.1',
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
    confidence: 'medium',
    detailedAnalysis: {}
  };
  
  try {
    // Check for phishing patterns
    for (const pattern of THREAT_PATTERNS.PHISHING) {
      if (pattern.test(domain)) {
        threatAnalysis.threats.phishing = true;
        threatAnalysis.indicators.push(`Matches phishing pattern: ${pattern.source}`);
        threatAnalysis.severity = 'high';
        break;
      }
    }
    
    // Check for malware patterns
    for (const pattern of THREAT_PATTERNS.MALWARE) {
      if (pattern.test(domain)) {
        threatAnalysis.threats.malware = true;
        threatAnalysis.indicators.push(`Matches malware pattern: ${pattern.source}`);
        threatAnalysis.severity = 'critical';
        break;
      }
    }
    
    // Check for suspicious characteristics
    for (const pattern of THREAT_PATTERNS.SUSPICIOUS) {
      if (pattern.test(domain)) {
        threatAnalysis.threats.suspicious = true;
        threatAnalysis.indicators.push(`Matches suspicious pattern: ${pattern.source}`);
        if (threatAnalysis.severity === 'low') {
          threatAnalysis.severity = 'medium';
        }
        break;
      }
    }
    
    // Additional suspicious indicators
    if (domain.length > 30) {
      threatAnalysis.threats.suspicious = true;
      threatAnalysis.indicators.push('Unusually long domain name');
    }
    
    if (domain.split('.').length > 3) {
      threatAnalysis.threats.suspicious = true;
      threatAnalysis.indicators.push('Multiple subdomains detected');
    }
    
    // Check for unusual TLDs
    const tld = domain.split('.').pop();
    const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'click', 'download', 'zip'];
    if (suspiciousTlds.includes(tld)) {
      threatAnalysis.threats.suspicious = true;
      threatAnalysis.indicators.push(`Suspicious TLD: .${tld}`);
    }
    
    // Update severity and confidence
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

function calculateRiskScore(domain, analysis, threatAnalysis) {
  let riskScore = 0;
  const factors = [];
  
  // Privacy protection
  if (analysis.privacyAnalysis?.isPrivate) {
    riskScore += RISK_SCORES.PRIVACY_PROTECTED;
    factors.push({
      factor: 'Privacy Protected',
      score: RISK_SCORES.PRIVACY_PROTECTED,
      description: 'Domain uses privacy protection service'
    });
  }
  
  // Threat patterns
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
  
  // Missing contact info
  if (!analysis.whoisData?.registrantEmail && !analysis.whoisData?.emails?.length) {
    riskScore += RISK_SCORES.NO_CONTACT_INFO;
    factors.push({
      factor: 'No Contact Information',
      score: RISK_SCORES.NO_CONTACT_INFO,
      description: 'No valid contact information available'
    });
  }
  
  // Domain age (if creation date available)
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
  
  // Multiple subdomains
  if (domain.split('.').length > 3) {
    riskScore += RISK_SCORES.MULTIPLE_SUBDOMAINS;
    factors.push({
      factor: 'Multiple Subdomains',
      score: RISK_SCORES.MULTIPLE_SUBDOMAINS,
      description: 'Domain has multiple subdomain levels'
    });
  }
  
  // Unusual TLD
  const tld = domain.split('.').pop();
  const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'click', 'download', 'zip'];
  if (suspiciousTlds.includes(tld)) {
    riskScore += RISK_SCORES.UNUSUAL_TLD;
    factors.push({
      factor: 'Suspicious TLD',
      score: RISK_SCORES.UNUSUAL_TLD,
      description: `Uses suspicious top-level domain: .${tld}`
    });
  }
  
  // Calculate risk level
  let riskLevel = 'low';
  if (riskScore >= 60) {
    riskLevel = 'critical';
  } else if (riskScore >= 40) {
    riskLevel = 'high';
  } else if (riskScore >= 20) {
    riskLevel = 'medium';
  }
  
  return {
    totalScore: Math.min(riskScore, 100),
    maxScore: 100,
    riskLevel: riskLevel,
    factors: factors,
    recommendation: generateRiskRecommendation(riskLevel, riskScore),
    confidence: factors.length >= 3 ? 'high' : factors.length >= 2 ? 'medium' : 'low'
  };
}

// ===== PRIVACY ANALYSIS FUNCTIONS =====

async function analyzePrivacyProtection(whoisData) {
  const privacyServices = [
    'whoisguard', 'domains by proxy', 'perfect privacy', 'private whois',
    'contact privacy', 'redacted for privacy', 'data protected',
    'privacy service', 'whois privacy', 'private registration',
    'proxy protection', 'domain privacy', 'registration private',
    'withheld for privacy', 'privacy protected', 'domain protection'
  ];
  
  const whoisText = JSON.stringify(whoisData).toLowerCase();
  
  let isPrivate = false;
  let privacyService = null;
  let privacyEmails = [];
  
  // Check for privacy indicators
  for (const service of privacyServices) {
    if (whoisText.includes(service)) {
      isPrivate = true;
      privacyService = service;
      break;
    }
  }
  
  // Extract privacy-related emails
  if (whoisData.emails) {
    for (const email of whoisData.emails) {
      const domain = email.split('@')[1];
      const localPart = email.split('@')[0].toLowerCase();
      
      const isPrivacyEmail = 
        domain.includes('privacy') || 
        domain.includes('whoisguard') || 
        domain.includes('proxy') ||
        localPart.includes('privacy') ||
        localPart.includes('whois');
      
      if (isPrivacyEmail) {
        isPrivate = true;
        privacyEmails.push(email);
      }
    }
  }
  
  return {
    isPrivate,
    privacyService,
    privacyEmails,
    confidence: isPrivate ? 'high' : 'low'
  };
}

async function analyzePrivacyProtectionEnhanced(whoisData, originalDomain) {
  const privacyServices = [
    'whoisguard', 'domains by proxy', 'perfect privacy', 'private whois',
    'contact privacy', 'redacted for privacy', 'data protected',
    'privacy service', 'whois privacy', 'private registration',
    'proxy protection', 'domain privacy', 'registration private',
    'withheld for privacy', 'privacy protected', 'domain protection'
  ];
  
  const whoisText = JSON.stringify(whoisData).toLowerCase();
  
  let isPrivate = false;
  let privacyService = null;
  let privacyEmails = [];
  let privacyDomains = [];
  let recursiveAnalysis = {};
  
  // Check for privacy indicators
  for (const service of privacyServices) {
    if (whoisText.includes(service)) {
      isPrivate = true;
      privacyService = service;
      break;
    }
  }
  
  // Extract ALL privacy-related emails and domains
  if (whoisData.emails) {
    for (const email of whoisData.emails) {
      const domain = email.split('@')[1];
      const localPart = email.split('@')[0].toLowerCase();
      
      const isPrivacyEmail = 
        domain.includes('privacy') || 
        domain.includes('whoisguard') || 
        domain.includes('proxy') ||
        domain.includes('protection') ||
        localPart.includes('privacy') ||
        localPart.includes('whois') ||
        localPart.includes('proxy') ||
        privacyServices.some(service => 
          domain.includes(service.replace(/\s+/g, '')) || 
          localPart.includes(service.replace(/\s+/g, ''))
        );
      
      if (isPrivacyEmail) {
        isPrivate = true;
        privacyEmails.push(email);
        if (!privacyDomains.includes(domain)) {
          privacyDomains.push(domain);
        }
      }
    }
  }
  
  // Perform recursive analysis on privacy domains
  if (isPrivate && privacyDomains.length > 0) {
    console.log(`[PRIVACY RECURSIVE] Found ${privacyDomains.length} privacy domains for ${originalDomain}`);
    
    for (const privacyDomain of privacyDomains.slice(0, 3)) { // Limit to 3 for performance
      if (privacyDomain !== originalDomain) {
        try {
          console.log(`[RECURSIVE] Analyzing privacy domain: ${privacyDomain}`);
          const recursiveData = await performRecursivePrivacyAnalysis(privacyDomain, originalDomain);
          recursiveAnalysis[privacyDomain] = recursiveData;
        } catch (error) {
          console.log(`[RECURSIVE ERROR] Failed to analyze ${privacyDomain}: ${error.message}`);
          recursiveAnalysis[privacyDomain] = { 
            error: error.message,
            analyzedAt: new Date().toISOString()
          };
        }
      }
    }
  }
  
  return {
    isPrivate,
    privacyService,
    privacyEmails,
    privacyDomains,
    recursiveAnalysis,
    confidence: isPrivate ? 'high' : 'low',
    needsInvestigation: isPrivate && Object.keys(recursiveAnalysis).length > 0
  };
}

async function performRecursivePrivacyAnalysis(privacyDomain, originalDomain) {
  const analysis = {
    domain: privacyDomain,
    originalDomain: originalDomain,
    timestamp: new Date().toISOString(),
    whoisData: null,
    dnsRecords: null,
    registrarIntelligence: null,
    geoIntelligence: null,
    companyIntelligence: null,
    investigationSummary: null
  };
  
  try {
    // Get WHOIS data
    analysis.whoisData = await getWhoisData(privacyDomain);
    
    // Get DNS records
    analysis.dnsRecords = await getDNSRecords(privacyDomain);
    
    // Enhanced registrar intelligence
    analysis.registrarIntelligence = enhancedRegistrarAnalysis(analysis.whoisData);
    
    // Geographic intelligence
    analysis.geoIntelligence = await enhancedGeoAnalysis(analysis.dnsRecords, analysis.whoisData);
    
    // Company intelligence
    analysis.companyIntelligence = await detectActualCompany(analysis);
    
    // Generate investigation summary
    analysis.investigationSummary = generateInvestigationSummary(analysis);
    
    return analysis;
    
  } catch (error) {
    console.error(`[RECURSIVE ERROR] ${privacyDomain}:`, error.message);
    analysis.error = error.message;
    return analysis;
  }
}

// ===== HELPER FUNCTIONS =====

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
  
  // Extract emails
  parsed.emails = extractEmails(rawData);
  
  // Extract name servers
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

function analyzeRegistrar(whoisData) {
  const registrar = whoisData.registrar || 'Unknown';
  let isUSBased = false;
  let category = 'Other';
  
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
    'cloudflare': { category: 'Tech Giant US', usBased: true },
    'markmonitor': { category: 'Enterprise US', usBased: true }
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

function enhancedRegistrarAnalysis(whoisData) {
  const registrar = whoisData.registrar || 'Unknown';
  const registrarLower = registrar.toLowerCase();
  
  const registrarIntelligence = {
    name: registrar,
    category: 'Unknown',
    isUSBased: false,
    parentCompany: null,
    headquarters: null,
    confidence: 'medium'
  };
  
  const enhancedRegistrarDB = {
    'namecheap': {
      category: 'Major US Commercial',
      isUSBased: true,
      parentCompany: 'Namecheap, Inc.',
      headquarters: 'Los Angeles, California, USA',
      confidence: 'high'
    },
    'godaddy': {
      category: 'Major US Commercial',
      isUSBased: true,
      parentCompany: 'GoDaddy Inc.',
      headquarters: 'Scottsdale, Arizona, USA',
      confidence: 'high'
    },
    'network solutions': {
      category: 'Legacy US Provider',
      isUSBased: true,
      parentCompany: 'Web.com Group',
      headquarters: 'Herndon, Virginia, USA',
      confidence: 'high'
    }
  };
  
  for (const [key, info] of Object.entries(enhancedRegistrarDB)) {
    if (registrarLower.includes(key)) {
      Object.assign(registrarIntelligence, info);
      break;
    }
  }
  
  return registrarIntelligence;
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

async function enhancedGeoAnalysis(dnsRecords, whoisData) {
  const geoAnalysis = {
    ipLocations: [],
    infrastructureCountries: new Set(),
    usPresence: false,
    primaryCountry: null
  };
  
  if (dnsRecords.A) {
    for (const ip of dnsRecords.A) {
      const geo = geoip.lookup(ip);
      if (geo) {
        geoAnalysis.ipLocations.push({
          ip,
          country: geo.country,
          region: geo.region,
          city: geo.city
        });
        geoAnalysis.infrastructureCountries.add(geo.country);
        if (geo.country === 'US') {
          geoAnalysis.usPresence = true;
        }
      }
    }
  }
  
  const countries = Array.from(geoAnalysis.infrastructureCountries);
  if (countries.length > 0) {
    geoAnalysis.primaryCountry = geoAnalysis.usPresence ? 'US' : countries[0];
  }
  
  return geoAnalysis;
}

async function detectActualCompany(analysis) {
  const companyIntelligence = {
    actualCompany: null,
    confidence: 'low',
    indicators: [],
    usConnections: []
  };
  
  const domain = analysis.domain;
  
  if (domain.includes('namecheap')) {
    companyIntelligence.actualCompany = 'Namecheap, Inc. (US Company)';
    companyIntelligence.confidence = 'high';
    companyIntelligence.indicators.push('Domain contains "namecheap"');
    companyIntelligence.usConnections.push('Namecheap headquarters: Los Angeles, CA');
  }
  
  if (analysis.registrarIntelligence && analysis.registrarIntelligence.isUSBased) {
    companyIntelligence.usConnections.push(`Registrar: ${analysis.registrarIntelligence.name} (US-based)`);
    companyIntelligence.indicators.push('Registered with US-based registrar');
  }
  
  if (analysis.geoIntelligence && analysis.geoIntelligence.usPresence) {
    companyIntelligence.usConnections.push('Infrastructure hosted in US');
    companyIntelligence.indicators.push('US infrastructure presence detected');
  }
  
  if (companyIntelligence.indicators.length >= 2) {
    companyIntelligence.confidence = 'high';
  } else if (companyIntelligence.indicators.length >= 1) {
    companyIntelligence.confidence = 'medium';
  }
  
  return companyIntelligence;
}

function generateInvestigationSummary(analysis) {
  const summary = {
    overallAssessment: 'unknown',
    usJurisdictionLikelihood: 'unknown',
    evidenceStrength: 'weak'
  };
  
  let usIndicators = 0;
  let totalIndicators = 0;
  
  if (analysis.registrarIntelligence?.isUSBased) usIndicators++;
  totalIndicators++;
  
  if (analysis.geoIntelligence?.usPresence) usIndicators++;
  totalIndicators++;
  
  if (analysis.companyIntelligence?.actualCompany) usIndicators++;
  totalIndicators++;
  
  const usPercentage = (usIndicators / totalIndicators) * 100;
  
  if (usPercentage >= 75) {
    summary.usJurisdictionLikelihood = 'very_high';
    summary.overallAssessment = 'us_jurisdiction_likely';
    summary.evidenceStrength = 'strong';
  } else if (usPercentage >= 50) {
    summary.usJurisdictionLikelihood = 'medium';
    summary.overallAssessment = 'mixed_jurisdiction';
    summary.evidenceStrength = 'moderate';
  } else {
    summary.usJurisdictionLikelihood = 'low';
    summary.overallAssessment = 'non_us_jurisdiction';
    summary.evidenceStrength = 'weak';
  }
  
  return summary;
}

function generateComprehensiveReport(privacyAnalysis, originalDomain) {
  const report = {
    summary: {
      totalPrivacyDomains: privacyAnalysis.privacyDomains.length,
      investigatedDomains: Object.keys(privacyAnalysis.recursiveAnalysis).length,
      usJurisdictionLikelihood: 'unknown'
    },
    privacyBypassOptions: [],
    legalRecommendations: [],
    nextSteps: []
  };
  
  let totalUsIndicators = 0;
  let totalInvestigated = 0;
  
  for (const [domain, analysis] of Object.entries(privacyAnalysis.recursiveAnalysis)) {
    if (analysis.error) continue;
    
    totalInvestigated++;
    
    if (analysis.registrarIntelligence?.isUSBased) totalUsIndicators++;
    if (analysis.geoIntelligence?.usPresence) totalUsIndicators++;
    if (analysis.companyIntelligence?.actualCompany) totalUsIndicators++;
  }
  
  if (totalInvestigated > 0) {
    const usPercentage = (totalUsIndicators / (totalInvestigated * 3)) * 100;
    
    if (usPercentage >= 66) {
      report.summary.usJurisdictionLikelihood = 'very_high';
    } else if (usPercentage >= 33) {
      report.summary.usJurisdictionLikelihood = 'medium';
    } else {
      report.summary.usJurisdictionLikelihood = 'low';
    }
  }
  
  // Generate recommendations
  if (report.summary.usJurisdictionLikelihood === 'very_high') {
    report.legalRecommendations.push('Strong case for US jurisdiction - pursue UDRP or federal court action');
    report.nextSteps.push('Engage US-qualified domain dispute counsel');
  }
  
  return report;
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
    // Get DNS records
    mxAnalysis.dnsRecords = await getDNSRecords(domain);
    
    // Analyze MX records
    if (mxAnalysis.dnsRecords.MX && mxAnalysis.dnsRecords.MX.length > 0) {
      mxAnalysis.mxRecords = await analyzeMXRecords(domain);
    }
    
    // Generate email infrastructure summary
    mxAnalysis.emailInfrastructure = generateEmailInfrastructureSummary(mxAnalysis);
    
    // Analyze email security
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

// ===== 404 HANDLER =====
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    availableEndpoints: [
      '/health', 
      '/api/status', 
      '/api/analyze', 
      '/api/bulk-analyze', 
      '/api/threat-analysis', 
      '/api/risk-score',
      '/api/privacy-investigation',
      '/api/mx-analysis'
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
  console.log('🚀 WHOIS Intelligence Enhanced Server v2.1');
  console.log('='.repeat(60));
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 API status: http://localhost:${PORT}/api/status`);
  console.log(`💾 Cache TTL: ${CONFIG.CACHE_TTL / 3600} hours`);
  console.log(`⚡ Rate limits: 300 per 15min (general), 60 per min (API)`);
  console.log(`🔐 API Key validation: ${VALID_API_KEYS.size} keys configured`);
  console.log(`🔍 Features: WHOIS, Privacy Investigation, Threat Analysis, Risk Scoring, MX Analysis`);
  console.log('='.repeat(60));
});

module.exports = app;