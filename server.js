// FILE: server.js
// Enhanced WHOIS Intelligence Server - Production Ready
// Version: 2.0.0

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

// ===== CACHE CONFIGURATION =====
const cache = new NodeCache({ 
  stdTTL: 21600, // 6 hours
  checkperiod: 3600, // cleanup every hour
  maxKeys: 2000
});

const threatCache = new NodeCache({
  stdTTL: 3600, // 1 hour for threat data
  checkperiod: 600,
  maxKeys: 500
});

// ===== THREAT INTELLIGENCE =====
const PHISHING_PATTERNS = [
  /payp[a4]l/i, /amaz[o0]n/i, /g[o0]{2}gle/i, /micr[o0]s[o0]ft/i,
  /[a4]pple/i, /netf1ix/i, /[fa4]ceb[o0]{2}k/i, /tw[i1]tter/i
];

const RISK_SCORES = {
  PRIVACY_PROTECTED: 10,
  RECENT_REGISTRATION: 15,
  SUSPICIOUS_REGISTRAR: 20,
  PHISHING_PATTERN: 30,
  NO_CONTACT_INFO: 10
};

// ===== RATE LIMITING =====
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300,
  message: { error: 'Rate limit exceeded. Please try again in 15 minutes.' }
});

// ===== MIDDLEWARE =====
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(limiter);

// Serve static files from root
app.use(express.static(__dirname));

// ===== LOGGING =====
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.url} - ${req.ip}`);
  next();
});

// ===== HEALTH CHECK =====
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    version: '2.0.0',
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
    },
    cache: {
      keys: cache.keys().length,
      hits: cache.getStats().hits || 0,
      misses: cache.getStats().misses || 0
    }
  });
});

// ===== API STATUS =====
app.get('/api/status', (req, res) => {
  res.json({
    api: 'WHOIS Intelligence Tool - Enhanced',
    version: '2.0.0',
    status: 'operational',
    features: {
      whois: 'enabled',
      threatIntelligence: 'enabled',
      riskScoring: 'enabled',
      bulkAnalysis: 'enabled'
    },
    endpoints: {
      analysis: '/api/analyze',
      bulkAnalysis: '/api/bulk-analyze',
      threatAnalysis: '/api/threat-analysis',
      riskScore: '/api/risk-score'
    },
    rateLimit: '300 requests per 15 minutes'
  });
});

// ===== MAIN ANALYSIS ENDPOINT =====
app.post('/api/analyze', async (req, res) => {
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
      cache.set(cacheKey, analysis, 21600);
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
app.post('/api/threat-analysis', async (req, res) => {
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
      threatCache.set(cacheKey, threatAnalysis, 3600);
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
app.post('/api/risk-score', async (req, res) => {
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
    console.log(`[RISK SCORE] Calculating for: ${cleanDomain}`);
    
    const analysis = await performDomainAnalysis(cleanDomain);
    
    if (!analysis.success) {
      return res.status(400).json({
        success: false,
        error: 'Failed to analyze domain for risk scoring'
      });
    }
    
    const riskScore = calculateRiskScore(cleanDomain, analysis);
    
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
app.post('/api/bulk-analyze', async (req, res) => {
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
    
    if (domains.length > 10) {
      return res.status(400).json({
        success: false,
        error: 'Maximum 10 domains allowed per bulk request'
      });
    }
    
    console.log(`[BULK ANALYSIS] Processing ${domains.length} domains`);
    
    const results = [];
    
    for (const domain of domains) {
      try {
        const cleanDomain = cleanDomainName(domain);
        
        if (!isValidDomain(cleanDomain)) {
          results.push({
            domain: cleanDomain,
            success: false,
            error: 'Invalid domain format'
          });
          continue;
        }
        
        const analysis = await performDomainAnalysis(cleanDomain);
        results.push(analysis);
        
        // Rate limiting between requests
        if (results.length < domains.length) {
          await new Promise(resolve => setTimeout(resolve, 500));
        }
        
      } catch (error) {
        results.push({
          domain: domain,
          success: false,
          error: error.message
        });
      }
    }
    
    const responseTime = Date.now() - startTime;
    const successCount = results.filter(r => r.success).length;
    
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

// ===== CORE ANALYSIS FUNCTION =====
async function performDomainAnalysis(domain) {
  const analysis = {
    domain,
    timestamp: new Date().toISOString(),
    success: true,
    whoisData: null,
    dnsData: null,
    privacyAnalysis: null,
    registrarInfo: null,
    geoData: null,
    summary: {}
  };
  
  try {
    // WHOIS Lookup
    analysis.whoisData = await getWhoisData(domain);
    
    // DNS Records
    analysis.dnsData = await getDNSRecords(domain);
    
    // Privacy Analysis
    analysis.privacyAnalysis = analyzePrivacyProtection(analysis.whoisData);
    
    // Registrar Analysis
    analysis.registrarInfo = analyzeRegistrar(analysis.whoisData);
    
    // Geographic Analysis
    analysis.geoData = analyzeGeolocation(analysis.dnsData);
    
    // Generate Summary
    analysis.summary = generateSummary(analysis);
    
  } catch (error) {
    analysis.success = false;
    analysis.error = error.message;
    console.error(`[ANALYSIS FAILED] ${domain}: ${error.message}`);
  }
  
  return analysis;
}

// ===== WHOIS DATA RETRIEVAL =====
async function getWhoisData(domain) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('WHOIS lookup timeout'));
    }, 15000);
    
    whois.lookup(domain, { timeout: 12000 }, (err, data) => {
      clearTimeout(timeout);
      if (err) {
        reject(new Error(`WHOIS lookup failed: ${err.message}`));
      } else {
        resolve(parseWhoisData(data, domain));
      }
    });
  });
}

// ===== DNS RECORDS RETRIEVAL =====
async function getDNSRecords(domain) {
  const records = {};
  
  try {
    const [A, MX, NS, TXT] = await Promise.allSettled([
      dns.resolve4(domain),
      dns.resolveMx(domain),
      dns.resolveNs(domain),
      dns.resolveTxt(domain)
    ]);
    
    records.A = A.status === 'fulfilled' ? A.value : [];
    records.MX = MX.status === 'fulfilled' ? MX.value : [];
    records.NS = NS.status === 'fulfilled' ? NS.value : [];
    records.TXT = TXT.status === 'fulfilled' ? TXT.value : [];
    
  } catch (error) {
    console.error(`[DNS ERROR] ${domain}: ${error.message}`);
    records.error = error.message;
  }
  
  return records;
}

// ===== THREAT ANALYSIS =====
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
    // Check for phishing patterns
    for (const pattern of PHISHING_PATTERNS) {
      if (pattern.test(domain)) {
        threatAnalysis.threats.phishing = true;
        threatAnalysis.indicators.push(`Matches phishing pattern: ${pattern.source}`);
        threatAnalysis.severity = 'high';
        break;
      }
    }
    
    // Check for suspicious characteristics
    if (domain.length > 30) {
      threatAnalysis.threats.suspicious = true;
      threatAnalysis.indicators.push('Unusually long domain name');
    }
    
    if (domain.split('.').length > 3) {
      threatAnalysis.threats.suspicious = true;
      threatAnalysis.indicators.push('Multiple subdomains detected');
    }
    
    // Update severity
    if (threatAnalysis.threats.phishing) {
      threatAnalysis.severity = 'high';
    } else if (threatAnalysis.threats.suspicious) {
      threatAnalysis.severity = 'medium';
    }
    
  } catch (error) {
    threatAnalysis.success = false;
    threatAnalysis.error = error.message;
  }
  
  return threatAnalysis;
}

// ===== RISK SCORING =====
function calculateRiskScore(domain, analysis) {
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
  
  // Phishing patterns
  for (const pattern of PHISHING_PATTERNS) {
    if (pattern.test(domain)) {
      riskScore += RISK_SCORES.PHISHING_PATTERN;
      factors.push({
        factor: 'Phishing Pattern',
        score: RISK_SCORES.PHISHING_PATTERN,
        description: 'Domain matches known phishing patterns'
      });
      break;
    }
  }
  
  // Missing contact info
  if (!analysis.whoisData?.registrantEmail) {
    riskScore += RISK_SCORES.NO_CONTACT_INFO;
    factors.push({
      factor: 'No Contact Information',
      score: RISK_SCORES.NO_CONTACT_INFO,
      description: 'No valid contact information available'
    });
  }
  
  // Calculate risk level
  let riskLevel = 'low';
  if (riskScore >= 40) {
    riskLevel = 'critical';
  } else if (riskScore >= 25) {
    riskLevel = 'high';
  } else if (riskScore >= 15) {
    riskLevel = 'medium';
  }
  
  return {
    totalScore: riskScore,
    maxScore: 100,
    riskLevel: riskLevel,
    factors: factors,
    recommendation: generateRiskRecommendation(riskLevel),
    confidence: factors.length >= 2 ? 'high' : 'medium'
  };
}

// ===== HELPER FUNCTIONS =====
function parseWhoisData(rawData, domain) {
  const lines = rawData.split('\n');
  const parsed = { domain, rawData };
  
  for (const line of lines) {
    const lower = line.toLowerCase();
    
    if (lower.includes('registrar:') && !parsed.registrar) {
      parsed.registrar = line.split(':')[1]?.trim();
    } else if (lower.includes('creation date:') && !parsed.creationDate) {
      parsed.creationDate = line.split(':')[1]?.trim();
    } else if (lower.includes('expir') && !parsed.expirationDate) {
      parsed.expirationDate = line.split(':')[1]?.trim();
    }
  }
  
  // Extract emails
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = rawData.match(emailRegex) || [];
  parsed.emails = [...new Set(emails.map(email => email.toLowerCase()))];
  
  return parsed;
}

function analyzePrivacyProtection(whoisData) {
  const privacyServices = [
    'whoisguard', 'domains by proxy', 'perfect privacy', 'private whois',
    'contact privacy', 'redacted for privacy', 'data protected'
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
  let isUSBased = false;
  let category = 'Other';
  
  const registrarLower = registrar.toLowerCase();
  const usRegistrars = ['godaddy', 'namecheap', 'network solutions', 'verisign'];
  
  for (const usReg of usRegistrars) {
    if (registrarLower.includes(usReg)) {
      isUSBased = true;
      category = 'US Commercial';
      break;
    }
  }
  
  return {
    name: registrar,
    category,
    isUSBased
  };
}

function analyzeGeolocation(dnsData) {
  let primaryLocation = null;
  
  if (dnsData.A && dnsData.A.length > 0) {
    const geo = geoip.lookup(dnsData.A[0]);
    if (geo) {
      primaryLocation = {
        ip: dnsData.A[0],
        country: geo.country,
        region: geo.region,
        city: geo.city,
        timezone: geo.timezone
      };
    }
  }
  
  return {
    primaryLocation,
    totalIPs: dnsData.A ? dnsData.A.length : 0
  };
}

function generateSummary(analysis) {
  return {
    domain: analysis.domain,
    registrar: analysis.registrarInfo?.name || 'Unknown',
    isUSRegistrar: analysis.registrarInfo?.isUSBased || false,
    isPrivacyProtected: analysis.privacyAnalysis?.isPrivate || false,
    privacyService: analysis.privacyAnalysis?.privacyService || null,
    creationDate: analysis.whoisData?.creationDate || 'Unknown',
    expirationDate: analysis.whoisData?.expirationDate || 'Unknown',
    nameServers: analysis.dnsData?.NS || [],
    primaryIP: analysis.dnsData?.A?.[0] || null,
    geoLocation: analysis.geoData?.primaryLocation || null
  };
}

function generateRiskRecommendation(riskLevel) {
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
      return 'Risk assessment inconclusive.';
  }
}

function cleanDomainName(domain) {
  return domain.trim()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .split('?')[0]
    .toLowerCase();
}

function isValidDomain(domain) {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
  return domainRegex.test(domain) && domain.includes('.') && domain.length <= 253;
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
    availableEndpoints: ['/health', '/api/status', '/api/analyze', '/api/bulk-analyze', '/api/threat-analysis', '/api/risk-score']
  });
});

// ===== SERVER STARTUP =====
app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('🚀 WHOIS Intelligence Enhanced Server v2.0');
  console.log('='.repeat(60));
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 API status: http://localhost:${PORT}/api/status`);
  console.log(`💾 Cache TTL: 6 hours`);
  console.log(`⚡ Rate limit: 300 requests per 15 minutes`);
  console.log(`🔍 Features: WHOIS, Threat Analysis, Risk Scoring`);
  console.log('='.repeat(60));
});

module.exports = app;