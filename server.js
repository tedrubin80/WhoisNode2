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
      
      // Check if email is privacy-related
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
  
  // RECURSIVE ANALYSIS: If privacy protection found, analyze privacy domains
  if (isPrivate && privacyDomains.length > 0) {
    console.log(`[PRIVACY RECURSIVE] Found ${privacyDomains.length} privacy domains for ${originalDomain}`);
    
    for (const privacyDomain of privacyDomains) {
      if (privacyDomain !== originalDomain) { // Don't analyze the same domain
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

// ===== RECURSIVE PRIVACY DOMAIN ANALYSIS =====
async function performRecursivePrivacyAnalysis(privacyDomain, originalDomain) {
  const analysis = {
    domain: privacyDomain,
    originalDomain: originalDomain,
    timestamp: new Date().toISOString(),
    whoisData: null,
    dnsRecords: null,
    mxRecords: null,
    registrarIntelligence: null,
    geoIntelligence: null,
    companyIntelligence: null,
    reverseAnalysis: null,
    actualOwnerClues: [],
    usConnections: [],
    investigationSummary: null
  };
  
  try {
    // 1. Get WHOIS data for privacy domain
    console.log(`[RECURSIVE WHOIS] ${privacyDomain}`);
    analysis.whoisData = await getWhoisData(privacyDomain);
    
    // 2. Get comprehensive DNS records
    console.log(`[RECURSIVE DNS] ${privacyDomain}`);
    analysis.dnsRecords = await getDNSRecords(privacyDomain);
    
    // 3. Analyze MX records for email infrastructure
    if (analysis.dnsRecords.MX && analysis.dnsRecords.MX.length > 0) {
      console.log(`[RECURSIVE MX] ${privacyDomain}`);
      analysis.mxRecords = await analyzeMXRecordsDetailed(privacyDomain);
    }
    
    // 4. Enhanced registrar intelligence
    analysis.registrarIntelligence = await enhancedRegistrarAnalysis(analysis.whoisData);
    
    // 5. Geographic and infrastructure intelligence
    analysis.geoIntelligence = await enhancedGeoAnalysis(analysis.dnsRecords, analysis.whoisData);
    
    // 6. Company intelligence (detect actual company behind privacy service)
    analysis.companyIntelligence = await detectActualCompany(analysis);
    
    // 7. Reverse IP analysis for all A records
    if (analysis.dnsRecords.A && analysis.dnsRecords.A.length > 0) {
      console.log(`[RECURSIVE REVERSE] ${analysis.dnsRecords.A[0]}`);
      analysis.reverseAnalysis = await performReverseIPAnalysis(analysis.dnsRecords.A[0]);
    }
    
    // 8. Generate investigation summary
    analysis.investigationSummary = generateInvestigationSummary(analysis);
    
    return analysis;
    
  } catch (error) {
    console.error(`[RECURSIVE ERROR] ${privacyDomain}:`, error.message);
    analysis.error = error.message;
    return analysis;
  }
}

// ===== DETAILED MX RECORDS ANALYSIS =====
async function analyzeMXRecordsDetailed(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    const mxAnalysis = {
      records: mxRecords,
      providers: [],
      infrastructure: [],
      usBasedProviders: [],
      insights: [],
      corporateClues: []
    };
    
    for (const mx of mxRecords) {
      const mxDomain = mx.exchange.toLowerCase();
      
      // Identify email providers and infrastructure
      let provider = 'Unknown';
      let infrastructure = 'Unknown';
      let isUSBased = false;
      
      if (mxDomain.includes('google') || mxDomain.includes('gmail')) {
        provider = 'Google Workspace';
        infrastructure = 'US-based (Google)';
        isUSBased = true;
      } else if (mxDomain.includes('outlook') || mxDomain.includes('microsoft')) {
        provider = 'Microsoft 365';
        infrastructure = 'US-based (Microsoft)';
        isUSBased = true;
      } else if (mxDomain.includes('amazonaws') || mxDomain.includes('aws')) {
        provider = 'Amazon SES';
        infrastructure = 'US-based (Amazon)';
        isUSBased = true;
      } else if (mxDomain.includes('cloudflare')) {
        provider = 'Cloudflare Email';
        infrastructure = 'US-based (Cloudflare)';
        isUSBased = true;
      }
      
      mxAnalysis.providers.push(provider);
      mxAnalysis.infrastructure.push(infrastructure);
      
      if (isUSBased) {
        mxAnalysis.usBasedProviders.push(provider);
      }
      
      // Check for corporate email patterns
      if (mxDomain.includes(domain.split('.')[0]) || 
          (!mxDomain.includes('google') && !mxDomain.includes('microsoft') && !mxDomain.includes('amazon'))) {
        mxAnalysis.corporateClues.push(`Custom email infrastructure: ${mxDomain}`);
      }
      
      // Get geographic info for MX server
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
              priority: mx.priority,
              isUSBased: isUSBased
            });
          }
        }
      } catch (error) {
        console.log(`MX geo lookup failed for ${mxDomain}`);
      }
    }
    
    return mxAnalysis;
    
  } catch (error) {
    console.log(`Detailed MX analysis failed for ${domain}: ${error.message}`);
    return { error: error.message };
  }
}

// ===== ENHANCED REGISTRAR ANALYSIS =====
async function enhancedRegistrarAnalysis(whoisData) {
  const registrar = whoisData.registrar || 'Unknown';
  const registrarLower = registrar.toLowerCase();
  
  const registrarIntelligence = {
    name: registrar,
    category: 'Unknown',
    isUSBased: false,
    parentCompany: null,
    headquarters: null,
    founded: null,
    icannAccredited: null,
    businessModel: null,
    confidence: 'medium'
  };
  
  // Enhanced US registrar database with detailed intelligence
  const enhancedRegistrarDB = {
    'namecheap': {
      category: 'Major US Commercial',
      isUSBased: true,
      parentCompany: 'Namecheap, Inc.',
      headquarters: 'Los Angeles, California, USA',
      founded: '2000',
      icannAccredited: true,
      businessModel: 'Retail domain registrar with hosting services',
      actualLocation: 'USA (despite Reykjavik presence)',
      confidence: 'high'
    },
    'godaddy': {
      category: 'Major US Commercial',
      isUSBased: true,
      parentCompany: 'GoDaddy Inc.',
      headquarters: 'Scottsdale, Arizona, USA',
      founded: '1997',
      icannAccredited: true,
      businessModel: 'Full-service web services provider',
      confidence: 'high'
    },
    'network solutions': {
      category: 'Legacy US Provider',
      isUSBased: true,
      parentCompany: 'Web.com Group',
      headquarters: 'Herndon, Virginia, USA',
      founded: '1979',
      icannAccredited: true,
      businessModel: 'Enterprise-focused domain and hosting',
      confidence: 'high'
    },
    'tucows': {
      category: 'US/Canada Wholesale',
      isUSBased: true,
      parentCompany: 'Tucows Inc.',
      headquarters: 'Toronto, Canada (US operations)',
      founded: '1993',
      icannAccredited: true,
      businessModel: 'Wholesale domain services and reseller platform',
      confidence: 'high'
    },
    'markmonitor': {
      category: 'Enterprise US Brand Protection',
      isUSBased: true,
      parentCompany: 'Clarivate Analytics',
      headquarters: 'San Francisco, California, USA',
      founded: '1999',
      icannAccredited: true,
      businessModel: 'Enterprise brand protection and domain management',
      confidence: 'high'
    }
  };
  
  // Check against enhanced database
  for (const [key, info] of Object.entries(enhancedRegistrarDB)) {
    if (registrarLower.includes(key)) {
      Object.assign(registrarIntelligence, info);
      break;
    }
  }
  
  return registrarIntelligence;
}

// ===== ENHANCED GEOGRAPHIC ANALYSIS =====
async function enhancedGeoAnalysis(dnsRecords, whoisData) {
  const geoAnalysis = {
    ipLocations: [],
    nameServerLocations: [],
    registrantLocation: null,
    infrastructureCountries: new Set(),
    usPresence: false,
    primaryCountry: null,
    corporatePresence: []
  };
  
  // Analyze A record IPs
  if (dnsRecords.A) {
    for (const ip of dnsRecords.A) {
      const geo = geoip.lookup(ip);
      if (geo) {
        geoAnalysis.ipLocations.push({
          ip,
          country: geo.country,
          region: geo.region,
          city: geo.city,
          timezone: geo.timezone,
          isp: geo.org || 'Unknown'
        });
        geoAnalysis.infrastructureCountries.add(geo.country);
        if (geo.country === 'US') {
          geoAnalysis.usPresence = true;
        }
      }
    }
  }
  
  // Analyze name server locations
  if (dnsRecords.NS) {
    for (const ns of dnsRecords.NS) {
      try {
        const nsIPs = await dns.resolve4(ns);
        for (const ip of nsIPs) {
          const geo = geoip.lookup(ip);
          if (geo) {
            geoAnalysis.nameServerLocations.push({
              nameServer: ns,
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
      } catch (error) {
        console.log(`NS geo lookup failed for ${ns}`);
      }
    }
  }
  
  // Enhanced registrant location analysis
  if (whoisData.registrantCountry) {
    geoAnalysis.registrantLocation = whoisData.registrantCountry;
  }
  
  // Determine primary country and corporate presence
  const countries = Array.from(geoAnalysis.infrastructureCountries);
  if (countries.length > 0) {
    geoAnalysis.primaryCountry = geoAnalysis.usPresence ? 'US' : countries[0];
  }
  
  // Detect corporate vs consumer infrastructure patterns
  if (geoAnalysis.ipLocations.length > 1) {
    geoAnalysis.corporatePresence.push('Multiple IP addresses suggest corporate infrastructure');
  }
  
  if (geoAnalysis.nameServerLocations.length > 2) {
    geoAnalysis.corporatePresence.push('Multiple name servers indicate enterprise setup');
  }
  
  return geoAnalysis;
}

// ===== COMPANY INTELLIGENCE DETECTION =====
async function detectActualCompany(analysis) {
  const companyIntelligence = {
    actualCompany: null,
    confidence: 'low',
    indicators: [],
    usConnections: [],
    reasoning: [],
    corporateClues: [],
    privacyBypassMethods: []
  };
  
  const domain = analysis.domain;
  const whoisData = analysis.whoisData;
  const mxAnalysis = analysis.mxRecords;
  const geoAnalysis = analysis.geoIntelligence;
  
  // Method 1: Check for known company patterns in domain name
  if (domain.includes('namecheap')) {
    companyIntelligence.actualCompany = 'Namecheap, Inc. (US Company)';
    companyIntelligence.confidence = 'high';
    companyIntelligence.indicators.push('Domain contains "namecheap"');
    companyIntelligence.usConnections.push('Namecheap headquarters: Los Angeles, CA');
    companyIntelligence.reasoning.push('Despite Reykjavik presence, Namecheap is a US-incorporated company');
  }
  
  // Method 2: Analyze email infrastructure for US connections
  if (mxAnalysis && mxAnalysis.usBasedProviders) {
    mxAnalysis.usBasedProviders.forEach(provider => {
      companyIntelligence.usConnections.push(`Email provider: ${provider} (US-based)`);
      companyIntelligence.indicators.push('Uses US-based email infrastructure');
    });
  }
  
  // Method 3: Corporate email infrastructure analysis
  if (mxAnalysis && mxAnalysis.corporateClues) {
    mxAnalysis.corporateClues.forEach(clue => {
      companyIntelligence.corporateClues.push(clue);
      companyIntelligence.indicators.push('Custom corporate email infrastructure detected');
    });
  }
  
  // Method 4: Infrastructure geographic analysis
  if (geoAnalysis && geoAnalysis.usPresence) {
    companyIntelligence.usConnections.push('Infrastructure hosted in US');
    companyIntelligence.indicators.push('US infrastructure presence detected');
  }
  
  // Method 5: Registrar chain analysis
  if (analysis.registrarIntelligence && analysis.registrarIntelligence.isUSBased) {
    companyIntelligence.usConnections.push(`Registrar: ${analysis.registrarIntelligence.name} (US-based)`);
    companyIntelligence.indicators.push('Registered with US-based registrar');
  }
  
  // Method 6: Technical infrastructure patterns
  if (analysis.dnsRecords && analysis.dnsRecords.NS) {
    const usNameServers = analysis.dnsRecords.NS.filter(ns => 
      ns.includes('namecheap') || 
      ns.includes('godaddy') ||
      ns.includes('amazonaws') ||
      ns.includes('cloudflare') ||
      ns.includes('googledomains')
    );
    
    if (usNameServers.length > 0) {
      companyIntelligence.usConnections.push(`US name servers: ${usNameServers.join(', ')}`);
      companyIntelligence.indicators.push('Uses US-controlled name servers');
    }
  }
  
  // Generate privacy bypass methods
  companyIntelligence.privacyBypassMethods = generatePrivacyBypassMethods(analysis, companyIntelligence);
  
  // Calculate confidence based on indicators
  if (companyIntelligence.indicators.length >= 4) {
    companyIntelligence.confidence = 'very_high';
  } else if (companyIntelligence.indicators.length >= 3) {
    companyIntelligence.confidence = 'high';
  } else if (companyIntelligence.indicators.length >= 2) {
    companyIntelligence.confidence = 'medium';
  }
  
  return companyIntelligence;
}

// ===== PRIVACY BYPASS METHODS =====
function generatePrivacyBypassMethods(analysis, companyIntelligence) {
  const methods = [];
  
  // Email-based methods
  if (analysis.mxRecords && analysis.mxRecords.usBasedProviders.length > 0) {
    methods.push({
      method: 'Email Provider Subpoena',
      description: `Contact ${analysis.mxRecords.usBasedProviders.join(', ')} with legal request`,
      jurisdiction: 'US',
      effectiveness: 'high'
    });
  }
  
  // Registrar-based methods
  if (analysis.registrarIntelligence && analysis.registrarIntelligence.isUSBased) {
    methods.push({
      method: 'Registrar Contact Request',
      description: `Contact ${analysis.registrarIntelligence.name} for registrant information`,
      jurisdiction: 'US',
      effectiveness: 'medium'
    });
  }
  
  // Infrastructure-based methods
  if (companyIntelligence.usConnections.length > 0) {
    methods.push({
      method: 'Infrastructure Provider Request',
      description: 'Contact hosting/DNS providers for customer information',
      jurisdiction: 'US',
      effectiveness: 'medium'
    });
  }
  
  // Legal methods
  if (companyIntelligence.confidence === 'high' || companyIntelligence.confidence === 'very_high') {
    methods.push({
      method: 'UDRP Proceedings',
      description: 'Uniform Domain-Name Dispute-Resolution Policy proceedings',
      jurisdiction: 'ICANN',
      effectiveness: 'high'
    });
  }
  
  return methods;
}

// ===== INVESTIGATION SUMMARY GENERATOR =====
function generateInvestigationSummary(analysis) {
  const summary = {
    overallAssessment: 'unknown',
    keyFindings: [],
    usJurisdictionLikelihood: 'unknown',
    recommendedActions: [],
    evidenceStrength: 'weak',
    nextSteps: []
  };
  
  let usIndicators = 0;
  let totalIndicators = 0;
  
  // Count US-related indicators
  if (analysis.registrarIntelligence?.isUSBased) {
    usIndicators++;
    summary.keyFindings.push(`US-based registrar: ${analysis.registrarIntelligence.name}`);
  }
  totalIndicators++;
  
  if (analysis.geoIntelligence?.usPresence) {
    usIndicators++;
    summary.keyFindings.push('Infrastructure hosted in US');
  }
  totalIndicators++;
  
  if (analysis.mxRecords?.usBasedProviders?.length > 0) {
    usIndicators++;
    summary.keyFindings.push(`US-based email providers: ${analysis.mxRecords.usBasedProviders.join(', ')}`);
  }
  totalIndicators++;
  
  if (analysis.companyIntelligence?.actualCompany) {
    usIndicators++;
    summary.keyFindings.push(`Actual company detected: ${analysis.companyIntelligence.actualCompany}`);
  }
  totalIndicators++;
  
  // Calculate US jurisdiction likelihood
  const usPercentage = (usIndicators / totalIndicators) * 100;
  
  if (usPercentage >= 75) {
    summary.usJurisdictionLikelihood = 'very_high';
    summary.overallAssessment = 'us_jurisdiction_likely';
    summary.evidenceStrength = 'strong';
  } else if (usPercentage >= 50) {
    summary.usJurisdictionLikelihood = 'high';
    summary.overallAssessment = 'us_jurisdiction_possible';
    summary.evidenceStrength = 'moderate';
  } else if (usPercentage >= 25) {
    summary.usJurisdictionLikelihood = 'medium';
    summary.overallAssessment = 'mixed_jurisdiction';
    summary.evidenceStrength = 'weak';
  } else {
    summary.usJurisdictionLikelihood = 'low';
    summary.overallAssessment = 'non_us_jurisdiction';
    summary.evidenceStrength = 'minimal';
  }
  
  // Generate recommended actions
  if (analysis.companyIntelligence?.privacyBypassMethods?.length > 0) {
    summary.recommendedActions.push('Multiple privacy bypass methods available');
    summary.nextSteps.push('Initiate contact with identified service providers');
  }
  
  if (summary.usJurisdictionLikelihood === 'very_high' || summary.usJurisdictionLikelihood === 'high') {
    summary.recommendedActions.push('Pursue US legal remedies (UDRP, federal court)');
    summary.nextSteps.push('Consult with US-qualified legal counsel');
  }
  
  if (analysis.companyIntelligence?.confidence === 'high') {
    summary.recommendedActions.push('Direct contact with identified company');
    summary.nextSteps.push('Attempt direct resolution before legal action');
  }
  
  return summary;
}

// ===== REVERSE IP ANALYSIS =====
async function performReverseIPAnalysis(ip) {
  const reverseAnalysis = {
    ip,
    hostname: null,
    geo: null,
    sharedHosts: [],
    networkInfo: null,
    corporateIndicators: []
  };
  
  try {
    // Reverse DNS lookup
    try {
      const hostnames = await dns.reverse(ip);
      reverseAnalysis.hostname = hostnames[0] || null;
      
      // Analyze hostname for corporate patterns
      if (reverseAnalysis.hostname) {
        const hostname = reverseAnalysis.hostname.toLowerCase();
        
        if (hostname.includes('amazonaws') || hostname.includes('aws')) {
          reverseAnalysis.networkInfo = { 
            provider: 'Amazon Web Services', 
            country: 'US',
            type: 'Cloud Infrastructure'
          };
          reverseAnalysis.corporateIndicators.push('Professional cloud hosting (AWS)');
        } else if (hostname.includes('googleusercontent') || hostname.includes('google')) {
          reverseAnalysis.networkInfo = { 
            provider: 'Google Cloud', 
            country: 'US',
            type: 'Cloud Infrastructure'
          };
          reverseAnalysis.corporateIndicators.push('Professional cloud hosting (Google)');
        } else if (hostname.includes('cloudflare')) {
          reverseAnalysis.networkInfo = { 
            provider: 'Cloudflare', 
            country: 'US',
            type: 'CDN/Security'
          };
          reverseAnalysis.corporateIndicators.push('Professional CDN service (Cloudflare)');
        }
      }
    } catch (error) {
      console.log(`Reverse DNS failed for ${ip}`);
    }
    
    // Geographic analysis
    reverseAnalysis.geo = geoip.lookup(ip);
    
    return reverseAnalysis;
    
  } catch (error) {
    console.error(`Reverse IP analysis failed for ${ip}: ${error.message}`);
    reverseAnalysis.error = error.message;
    return reverseAnalysis;
  }
}

// ===== ADD NEW API ENDPOINT FOR PRIVACY INVESTIGATION =====
// Add this endpoint to your server.js

app.post('/api/privacy-investigation', validateApiKey, async (req, res) => {
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
    console.log(`[PRIVACY INVESTIGATION] Starting comprehensive investigation for: ${cleanDomain}`);
    
    // Get basic analysis first
    const basicAnalysis = await performDomainAnalysis(cleanDomain);
    
    if (!basicAnalysis.success) {
      return res.status(400).json({
        success: false,
        error: 'Failed to perform basic domain analysis'
      });
    }
    
    // Enhanced privacy analysis with recursive investigation
    const enhancedPrivacyAnalysis = await analyzePrivacyProtectionEnhanced(basicAnalysis.whoisData, cleanDomain);
    
    const investigation = {
      domain: cleanDomain,
      timestamp: new Date().toISOString(),
      success: true,
      basicAnalysis: basicAnalysis.summary,
      privacyAnalysis: enhancedPrivacyAnalysis,
      investigationReport: null,
      recommendedActions: [],
      responseTime: Date.now() - startTime
    };
    
    // Generate comprehensive investigation report
    if (enhancedPrivacyAnalysis.needsInvestigation) {
      investigation.investigationReport = generateComprehensiveReport(enhancedPrivacyAnalysis, cleanDomain);
    }
    
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

// ===== COMPREHENSIVE REPORT GENERATOR =====
function generateComprehensiveReport(privacyAnalysis, originalDomain) {
  const report = {
    summary: {
      totalPrivacyDomains: privacyAnalysis.privacyDomains.length,
      investigatedDomains: Object.keys(privacyAnalysis.recursiveAnalysis).length,
      usJurisdictionLikelihood: 'unknown',
      overallConfidence: 'low'
    },
    findings: [],
    usConnections: [],
    privacyBypassOptions: [],
    legalRecommendations: [],
    nextSteps: []
  };
  
  let totalUsIndicators = 0;
  let totalInvestigated = 0;
  
  // Analyze each privacy domain investigation
  for (const [domain, analysis] of Object.entries(privacyAnalysis.recursiveAnalysis)) {
    if (analysis.error) {
      report.findings.push({
        domain: domain,
        status: 'failed',
        error: analysis.error
      });
      continue;
    }
    
    totalInvestigated++;
    
    const finding = {
      domain: domain,
      status: 'analyzed',
      usIndicators: 0,
      keyFindings: []
    };
    
    // Count US indicators for this domain
    if (analysis.registrarIntelligence?.isUSBased) {
      finding.usIndicators++;
      finding.keyFindings.push(`US registrar: ${analysis.registrarIntelligence.name}`);
      report.usConnections.push(`${domain}: US registrar (${analysis.registrarIntelligence.name})`);
    }
    
    if (analysis.geoIntelligence?.usPresence) {
      finding.usIndicators++;
      finding.keyFindings.push('US infrastructure');
      report.usConnections.push(`${domain}: US-hosted infrastructure`);
    }
    
    if (analysis.companyIntelligence?.actualCompany) {
      finding.usIndicators++;
      finding.keyFindings.push(`Company: ${analysis.companyIntelligence.actualCompany}`);
      report.usConnections.push(`${domain}: ${analysis.companyIntelligence.actualCompany}`);
    }
    
    if (analysis.companyIntelligence?.privacyBypassMethods) {
      analysis.companyIntelligence.privacyBypassMethods.forEach(method => {
        report.privacyBypassOptions.push({
          domain: domain,
          method: method.method,
          description: method.description,
          jurisdiction: method.jurisdiction,
          effectiveness: method.effectiveness
        });
      });
    }
    
    totalUsIndicators += finding.usIndicators;
    report.findings.push(finding);
  }
  
  // Calculate overall US jurisdiction likelihood
  if (totalInvestigated > 0) {
    const usPercentage = (totalUsIndicators / (totalInvestigated * 3)) * 100; // 3 possible indicators per domain
    
    if (usPercentage >= 66) {
      report.summary.usJurisdictionLikelihood = 'very_high';
      report.summary.overallConfidence = 'high';
    } else if (usPercentage >= 33) {
      report.summary.usJurisdictionLikelihood = 'medium';
      report.summary.overallConfidence = 'medium';
    } else {
      report.summary.usJurisdictionLikelihood = 'low';
      report.summary.overallConfidence = 'low';
    }
  }
  
  // Generate legal recommendations
  if (report.summary.usJurisdictionLikelihood === 'very_high') {
    report.legalRecommendations.push('Strong case for US jurisdiction - pursue UDRP or federal court action');
    report.nextSteps.push('Engage US-qualified domain dispute counsel');
  } else if (report.summary.usJurisdictionLikelihood === 'medium') {
    report.legalRecommendations.push('Moderate US jurisdiction indicators - consider UDRP proceedings');
    report.nextSteps.push('Evaluate strength of trademark claims');
  }
  
  if (report.privacyBypassOptions.length > 0) {
    report.legalRecommendations.push('Multiple privacy bypass methods identified');
    report.nextSteps.push('Attempt informal resolution before legal action');
  }
  
  return report;
}

module.exports = {
  analyzePrivacyProtectionEnhanced,
  performRecursivePrivacyAnalysis,
  detectActualCompany,
  generateInvestigationSummary
};