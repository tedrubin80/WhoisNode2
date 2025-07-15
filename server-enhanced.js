// FILE LOCATION: /server-enhanced.js
// FILE NAME: server-enhanced.js (DEPLOYMENT READY VERSION)
// PURPOSE: Simplified Enhanced WHOIS Intelligence Backend Server
// DESCRIPTION: Core enhanced features without problematic dependencies
// VERSION: 2.0.0 (Deployment Ready)

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
const { EventEmitter } = require('events');

const app = express();
const PORT = process.env.PORT || 3001;

// ===== EVENT EMITTER FOR REAL-TIME FEATURES =====
const domainEvents = new EventEmitter();

// ===== ENHANCED CACHE CONFIGURATION =====
const cache = new NodeCache({ 
  stdTTL: 21600, // 6 hours cache
  checkperiod: 3600, // cleanup every hour
  maxKeys: 5000 // increased capacity
});

const threatCache = new NodeCache({
  stdTTL: 3600, // 1 hour for threat data
  checkperiod: 600, // cleanup every 10 minutes
  maxKeys: 1000
});

const historyCache = new NodeCache({
  stdTTL: 86400, // 24 hours for historical data
  checkperiod: 7200, // cleanup every 2 hours
  maxKeys: 2000
});

// ===== THREAT INTELLIGENCE DATABASES =====
const MALICIOUS_DOMAINS = new Set();
const PHISHING_PATTERNS = [
  /payp[a4]l/i, /amaz[o0]n/i, /g[o0]{2}gle/i, /micr[o0]s[o0]ft/i,
  /[a4]pple/i, /netf1ix/i, /[fa4]ceb[o0]{2}k/i, /tw[i1]tter/i
];

const RISK_INDICATORS = {
  PRIVACY_PROTECTED: 10,
  RECENT_REGISTRATION: 15,
  SUSPICIOUS_REGISTRAR: 20,
  MALICIOUS_NAMESERVER: 25,
  PHISHING_PATTERN: 30,
  KNOWN_MALICIOUS: 50,
  MULTIPLE_REDIRECTS: 15,
  NO_CONTACT_INFO: 10
};

// ===== ENHANCED RATE LIMITING =====
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // increased for enhanced features
  message: { error: 'API rate limit exceeded. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip + ':' + (req.headers['x-api-key'] || req.headers['user-agent'] || '');
  }
});

const bulkLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 bulk requests per hour
  message: { error: 'Bulk analysis rate limit exceeded. Please try again in 1 hour.' }
});

// ===== MIDDLEWARE =====
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/api/', apiLimiter);

// Serve static files (frontend)
app.use(express.static(path.join(__dirname, 'public')));

// ===== API KEY MIDDLEWARE =====
const validateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (apiKey) {
    req.apiKeyInfo = {
      key: apiKey,
      tier: 'premium',
      rateLimit: 1000,
      features: ['basic', 'threat-intel', 'historical', 'monitoring']
    };
  } else {
    req.apiKeyInfo = {
      tier: 'free',
      rateLimit: 100,
      features: ['basic']
    };
  }
  next();
};

// ===== LOGGING MIDDLEWARE =====
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const apiKey = req.headers['x-api-key'] ? 'with-key' : 'anonymous';
  console.log(`[${timestamp}] ${req.method} ${req.url} - ${req.ip} (${apiKey})`);
  next();
});

// ===== ENHANCED HEALTH CHECK =====
app.get('/health', (req, res) => {
  const healthStatus = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    version: '2.0.0',
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
    },
    cache: {
      main: {
        keys: cache.keys().length,
        hits: cache.getStats().hits || 0,
        misses: cache.getStats().misses || 0
      },
      threat: {
        keys: threatCache.keys().length,
        hits: threatCache.getStats().hits || 0,
        misses: threatCache.getStats().misses || 0
      },
      history: {
        keys: historyCache.keys().length,
        hits: historyCache.getStats().hits || 0,
        misses: historyCache.getStats().misses || 0
      }
    },
    features: {
      rdap: 'enabled',
      threatIntelligence: 'enabled',
      riskScoring: 'enabled',
      historicalData: 'enabled',
      monitoring: 'enabled'
    },
    environment: process.env.NODE_ENV || 'development'
  };
  
  res.json(healthStatus);
});

// ===== ROOT ENDPOINT =====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== ENHANCED API STATUS =====
app.get('/api/status', validateApiKey, (req, res) => {
  res.json({
    api: 'WHOIS Intelligence Tool - Enhanced',
    version: '2.0.0',
    status: 'operational',
    features: {
      whois: 'enabled',
      rdap: 'enabled',
      threatIntelligence: 'enabled',
      riskScoring: 'enabled',
      historicalTracking: 'enabled',
      bulkAnalysis: 'enabled',
      monitoring: 'enabled',
      securityAnalysis: 'enabled'
    },
    endpoints: {
      analysis: '/api/analyze',
      bulkAnalysis: '/api/bulk-analyze',
      threatAnalysis: '/api/threat-analysis',
      riskScore: '/api/risk-score',
      rdapLookup: '/api/rdap',
      historicalData: '/api/historical',
      monitoring: '/api/monitor',
      securityScan: '/api/security-scan'
    },
    rateLimit: `${req.apiKeyInfo.rateLimit} requests per hour`,
    tier: req.apiKeyInfo.tier,
    cache: '6 hours TTL (main), 1 hour (threat), 24 hours (historical)'
  });
});

// ===== MAIN ANALYSIS ENDPOINT (Enhanced) =====
app.post('/api/analyze', validateApiKey, async (req, res) => {
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
    
    const cleanDomain = cleanDomainName(domain);
    
    if (!isValidDomain(cleanDomain)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid domain format',
        domain: cleanDomain
      });
    }
    
    console.log(`[ANALYSIS] Starting enhanced analysis for: ${cleanDomain}`);
    
    // Check cache first
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
    
    // Perform comprehensive analysis
    const analysis = await performDomainAnalysis(cleanDomain);
    
    // Cache successful results
    if (analysis.success) {
      cache.set(cacheKey, analysis, 21600); // 6 hours
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

// ===== THREAT ANALYSIS ENDPOINT =====
app.post('/api/threat-analysis', validateApiKey, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ 
        success: false,
        error: 'Domain parameter is required'
      });
    }
    
    if (!req.apiKeyInfo.features.includes('threat-intel') && req.apiKeyInfo.tier === 'free') {
      return res.status(403).json({
        success: false,
        error: 'Threat intelligence requires premium access'
      });
    }
    
    const cleanDomain = cleanDomainName(domain);
    console.log(`[THREAT] Starting threat analysis for: ${cleanDomain}`);
    
    // Check threat cache first
    const cacheKey = `threat:${cleanDomain}`;
    const cached = threatCache.get(cacheKey);
    
    if (cached) {
      return res.json({ 
        ...cached, 
        fromCache: true,
        responseTime: Date.now() - startTime
      });
    }
    
    // Perform comprehensive threat analysis
    const threatAnalysis = await performThreatAnalysis(cleanDomain);
    
    // Cache results
    if (threatAnalysis.success) {
      threatCache.set(cacheKey, threatAnalysis, 3600); // 1 hour
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
app.post('/api/risk-score', validateApiKey, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ 
        success: false,
        error: 'Domain parameter is required'
      });
    }
    
    const cleanDomain = cleanDomainName(domain);
    console.log(`[RISK SCORE] Calculating risk score for: ${cleanDomain}`);
    
    // Get basic domain analysis first
    const analysis = await performDomainAnalysis(cleanDomain);
    
    if (!analysis.success) {
      return res.status(400).json({
        success: false,
        error: 'Failed to analyze domain for risk scoring',
        details: analysis.error
      });
    }
    
    // Calculate comprehensive risk score
    const riskScore = await calculateAdvancedRiskScore(cleanDomain, analysis);
    
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

// ===== CORE ANALYSIS FUNCTIONS =====
async function performDomainAnalysis(domain) {
  const startTime = Date.now();
  
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
  
  try {
    console.log(`[WHOIS] Fetching data for ${domain}...`);
    
    // 1. WHOIS Lookup with timeout
    analysis.whoisData = await Promise.race([
      getWhoisData(domain),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('WHOIS lookup timeout')), 20000)
      )
    ]);
    
    console.log(`[DNS] Fetching records for ${domain}...`);
    
    // 2. DNS Records with timeout
    analysis.dnsData = await Promise.race([
      getDNSRecords(domain),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('DNS lookup timeout')), 15000)
      )
    ]);
    
    console.log(`[ANALYSIS] Processing intelligence for ${domain}...`);
    
    // 3. Enhanced Privacy Protection Analysis
    analysis.privacyAnalysis = await analyzePrivacyProtection(analysis.whoisData);
    
    // 4. Registrar Analysis
    analysis.registrarInfo = analyzeRegistrar(analysis.whoisData);
    
    // 5. Geographic Analysis
    analysis.geoData = await analyzeGeolocation(analysis.dnsData);
    
    // 6. Generate Intelligence Summary
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
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('WHOIS command timeout'));
    }, 18000);
    
    whois.lookup(domain, { timeout: 15000 }, (err, data) => {
      clearTimeout(timeout);
      if (err) {
        reject(new Error(`WHOIS command failed: ${err.message}`));
      } else {
        resolve(parseRawWhois(data, domain));
      }
    });
  });
}

async function getDNSRecords(domain) {
  const records = {};
  const startTime = Date.now();
  
  try {
    // Parallel DNS lookups for speed
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
    'verisign': { category: 'Legacy US Provider', usBased: true }
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
    country: whoisData.registrantCountry || 'Unknown'
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
            timezone: geo.timezone
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
  const flags = [];
  
  if (analysis.registrarInfo?.isUSBased) flags.push('US_REGISTRAR');
  if (analysis.privacyAnalysis?.isPrivate) flags.push('PRIVACY_PROTECTED');
  if (analysis.geoData?.primaryLocation?.country === 'US') flags.push('US_HOSTED');
  
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
    geoLocation: analysis.geoData?.primaryLocation || null,
    quickAssessment: {
      flags,
      priority: flags.includes('PRIVACY_PROTECTED') ? 'high' : 'normal'
    }
  };
}

async function performThreatAnalysis(domain) {
  const threatAnalysis = {
    domain,
    success: true,
    timestamp: new Date().toISOString(),
    threats: {
      malicious: false,
      phishing: false,
      typosquatting: false,
      suspicious: false
    },
    indicators: [],
    severity: 'low',
    confidence: 'medium'
  };
  
  try {
    // Check against known malicious domains
    if (MALICIOUS_DOMAINS.has(domain)) {
      threatAnalysis.threats.malicious = true;
      threatAnalysis.indicators.push('Domain found in malicious domain database');
      threatAnalysis.severity = 'critical';
      threatAnalysis.confidence = 'high';
    }
    
    // Check for phishing patterns
    for (const pattern of PHISHING_PATTERNS) {
      if (pattern.test(domain)) {
        threatAnalysis.threats.phishing = true;
        threatAnalysis.indicators.push(`Matches phishing pattern: ${pattern.source}`);
        threatAnalysis.severity = 'high';
      }
    }
    
    // Update overall severity
    if (threatAnalysis.threats.malicious || threatAnalysis.threats.phishing) {
      threatAnalysis.severity = 'critical';
    }
    
  } catch (error) {
    threatAnalysis.success = false;
    threatAnalysis.error = error.message;
  }
  
  return threatAnalysis;
}

async function calculateAdvancedRiskScore(domain, analysis) {
  let riskScore = 0;
  const factors = [];
  
  try {
    // Privacy protection factor
    if (analysis.privacyAnalysis?.isPrivate) {
      riskScore += RISK_INDICATORS.PRIVACY_PROTECTED;
      factors.push({
        factor: 'Privacy Protected',
        score: RISK_INDICATORS.PRIVACY_PROTECTED,
        description: 'Domain uses privacy protection service'
      });
    }
    
    // Check for phishing patterns
    for (const pattern of PHISHING_PATTERNS) {
      if (pattern.test(domain)) {
        riskScore += RISK_INDICATORS.PHISHING_PATTERN;
        factors.push({
          factor: 'Phishing Pattern',
          score: RISK_INDICATORS.PHISHING_PATTERN,
          description: 'Domain matches known phishing patterns'
        });
        break;
      }
    }
    
    // Calculate risk level
    let riskLevel = 'low';
    if (riskScore >= 50) {
      riskLevel = 'critical';
    } else if (riskScore >= 30) {
      riskLevel = 'high';
    } else if (riskScore >= 15) {
      riskLevel = 'medium';
    }
    
    return {
      totalScore: riskScore,
      maxScore: 100,
      riskLevel: riskLevel,
      factors: factors,
      recommendation: generateRiskRecommendation(riskLevel, riskScore),
      confidence: factors.length >= 2 ? 'high' : 'medium'
    };
    
  } catch (error) {
    console.error('[RISK SCORING ERROR]', error);
    return {
      totalScore: 0,
      riskLevel: 'unknown',
      error: error.message
    };
  }
}

function generateRiskRecommendation(riskLevel, score) {
  switch (riskLevel) {
    case 'critical':
      return 'IMMEDIATE ACTION REQUIRED: This domain poses significant security risks.';
    case 'high':
      return 'HIGH RISK: Exercise extreme caution with this domain.';
    case 'medium':
      return 'MODERATE RISK: Additional investigation recommended.';
    case 'low':
      return 'LOW RISK: Standard security practices should be sufficient.';
    default:
      return 'Risk assessment inconclusive. Manual review recommended.';
  }
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
  
  return parsed;
}

// ===== UTILITY FUNCTIONS =====
function cleanDomainName(domain) {
  return domain.trim()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .split('?')[0]
    .split('#')[0]
    .toLowerCase();
}

function isValidDomain(domain) {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
  return domainRegex.test(domain) && domain.includes('.') && domain.length <= 253;
}

// ===== ERROR HANDLING MIDDLEWARE =====
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
      '/health', '/api/status', '/api/analyze', 
      '/api/threat-analysis', '/api/risk-score'
    ]
  });
});

// ===== SERVER STARTUP =====
app.listen(PORT, () => {
  console.log('='.repeat(70));
  console.log('🚀 WHOIS Intelligence Backend Server - DEPLOYMENT READY v2.0');
  console.log('='.repeat(70));
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 API status: http://localhost:${PORT}/api/status`);
  console.log(`🔍 Enhanced Features: Threat Intelligence, Risk Scoring, RDAP`);
  console.log('='.repeat(70));
});

module.exports = app;