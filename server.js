// File Location: /server.js
// WHOIS Backend Server - Production Ready for GitHub Apps + Railway
// Node.js + Express backend for domain intelligence analysis

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const whois = require('whois');
const dns = require('dns').promises;
const axios = require('axios');
const geoip = require('geoip-lite');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// ===== CACHE CONFIGURATION =====
const cache = new NodeCache({ 
  stdTTL: 21600, // 6 hours cache (Railway optimized)
  checkperiod: 3600, // cleanup every hour
  maxKeys: 2000 // increased for better performance
});

// ===== RATE LIMITING =====
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // increased for heavy usage
  message: { error: 'Rate limit exceeded. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip + ':' + (req.headers['user-agent'] || '');
  }
});

// ===== MIDDLEWARE =====
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(limiter);

// Serve static files (frontend)
app.use(express.static(path.join(__dirname, 'public')));

// ===== LOGGING MIDDLEWARE =====
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.url} - ${req.ip}`);
  next();
});

// ===== HEALTH CHECK ENDPOINT =====
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
    },
    cache: {
      keys: cache.keys().length,
      hits: cache.getStats().hits || 0,
      misses: cache.getStats().misses || 0
    },
    environment: process.env.NODE_ENV || 'development'
  });
});

// ===== ROOT ENDPOINT =====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ===== API STATUS ENDPOINT =====
app.get('/api/status', (req, res) => {
  res.json({
    api: 'WHOIS Intelligence Tool',
    version: '1.0.0',
    status: 'operational',
    endpoints: ['/api/analyze', '/api/bulk-analyze'],
    rateLimit: '300 requests per 15 minutes',
    cache: '6 hours TTL'
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
    
    if (domains.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'At least one domain is required'
      });
    }
    
    if (domains.length > 10) {
      return res.status(400).json({
        success: false,
        error: 'Maximum 10 domains allowed per bulk request',
        provided: domains.length
      });
    }
    
    console.log(`[BULK ANALYSIS] Processing ${domains.length} domains`);
    
    const results = [];
    let processedCount = 0;
    
    for (const domain of domains) {
      try {
        const cleanDomain = cleanDomainName(domain);
        
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
            cache.set(cacheKey, analysis, 21600); // 6 hours
          }
        } else {
          analysis.fromCache = true;
        }
        
        results.push(analysis);
        processedCount++;
        
        // Rate limiting between requests (only for non-cached)
        if (!analysis.fromCache && processedCount < domains.length) {
          await new Promise(resolve => setTimeout(resolve, 1000));
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
      error: 'Internal server error during bulk analysis',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// ===== CORE ANALYSIS FUNCTION =====
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
    
    // 3. Privacy Protection Analysis
    analysis.privacyAnalysis = analyzePrivacyProtection(analysis.whoisData);
    
    // 4. Registrar Analysis (US detection)
    analysis.registrarInfo = analyzeRegistrar(analysis.whoisData);
    
    // 5. Geographic Analysis
    analysis.geoData = await analyzeGeolocation(analysis.dnsData);
    
    // 6. Privacy Domain Analysis (if applicable)
    if (analysis.privacyAnalysis.isPrivate && analysis.privacyAnalysis.privacyDomain) {
      console.log(`[PRIVACY] Analyzing privacy domain: ${analysis.privacyAnalysis.privacyDomain}`);
      try {
        const privacyWhois = await Promise.race([
          getWhoisData(analysis.privacyAnalysis.privacyDomain),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Privacy domain timeout')), 15000)
          )
        ]);
        analysis.privacyAnalysis.privacyDomainWhois = privacyWhois;
      } catch (error) {
        console.log(`[PRIVACY WARNING] Privacy domain analysis failed: ${error.message}`);
      }
    }
    
    // 7. Generate Intelligence Summary
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

// ===== WHOIS DATA RETRIEVAL =====
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

async function whoisAPILookup(domain) {
  try {
    const response = await axios.get(`https://whoisjson.com/api/v1/whois?domain=${domain}`, {
      timeout: 12000,
      headers: { 
        'User-Agent': 'WHOIS-Intelligence-Tool/1.0',
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

// ===== DNS RECORDS RETRIEVAL =====
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
    // Return empty records rather than failing
    records.error = error.message;
  }
  
  return records;
}

// ===== PRIVACY PROTECTION ANALYSIS =====
function analyzePrivacyProtection(whoisData) {
  const privacyServices = [
    'whoisguard', 'domains by proxy', 'perfect privacy', 'private whois',
    'contact privacy', 'redacted for privacy', 'data protected',
    'privacy service', 'whois privacy', 'private registration',
    'proxy protection', 'domain privacy', 'registration private'
  ];
  
  const whoisText = JSON.stringify(whoisData).toLowerCase();
  
  let isPrivate = false;
  let privacyService = null;
  let privacyDomain = null;
  
  // Check for privacy indicators
  for (const service of privacyServices) {
    if (whoisText.includes(service)) {
      isPrivate = true;
      privacyService = service;
      break;
    }
  }
  
  // Extract privacy contact domain from emails
  if (isPrivate && whoisData.emails) {
    for (const email of whoisData.emails) {
      const domain = email.split('@')[1];
      if (domain && (
        domain.includes('privacy') || 
        domain.includes('whoisguard') || 
        domain.includes('proxy') ||
        domain.includes('protection')
      )) {
        privacyDomain = domain;
        break;
      }
    }
  }
  
  return {
    isPrivate,
    privacyService,
    privacyDomain,
    confidence: isPrivate ? 'high' : 'low'
  };
}

// ===== REGISTRAR ANALYSIS (US DETECTION) =====
function analyzeRegistrar(whoisData) {
  const registrar = whoisData.registrar || 'Unknown';
  let category = 'Other';
  let isUSBased = false;
  
  const registrarLower = registrar.toLowerCase();
  
  // US Registrar Detection
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
    'markmonitor': { category: 'Enterprise US', usBased: true },
    'csc corporate domains': { category: 'Enterprise US', usBased: true }
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

// ===== GEOGRAPHIC ANALYSIS =====
async function analyzeGeolocation(dnsData) {
  const geoInfo = {
    countries: new Set(),
    regions: new Set(),
    cities: new Set(),
    primaryLocation: null
  };
  
  if (dnsData.A && dnsData.A.length > 0) {
    // Analyze first 3 IPs for geographic diversity
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
            ll: geo.ll // latitude/longitude
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

// ===== INTELLIGENCE SUMMARY GENERATION =====
function generateIntelligenceSummary(analysis) {
  const flags = [];
  
  // Generate workflow flags
  if (analysis.registrarInfo?.isUSBased) flags.push('US_REGISTRAR');
  if (analysis.privacyAnalysis?.isPrivate) flags.push('PRIVACY_PROTECTED');
  if (analysis.privacyAnalysis?.privacyDomain) flags.push('CHECK_PRIVACY_DOMAIN');
  if (analysis.geoData?.primaryLocation?.country === 'US') flags.push('US_HOSTED');
  
  return {
    domain: analysis.domain,
    isUSRegistrar: analysis.registrarInfo?.isUSBased || false,
    registrar: analysis.registrarInfo?.name || 'Unknown',
    registrarCategory: analysis.registrarInfo?.category || 'Unknown',
    isPrivacyProtected: analysis.privacyAnalysis?.isPrivate || false,
    privacyService: analysis.privacyAnalysis?.privacyService || null,
    privacyDomain: analysis.privacyAnalysis?.privacyDomain || null,
    registrantCountry: analysis.whoisData?.registrantCountry || 'Unknown',
    creationDate: analysis.whoisData?.creationDate || 'Unknown',
    expirationDate: analysis.whoisData?.expirationDate || 'Unknown',
    nameServers: analysis.dnsData?.NS || [],
    primaryIP: analysis.dnsData?.A?.[0] || null,
    geoLocation: analysis.geoData?.primaryLocation || null,
    needsPrivacyDomainCheck: analysis.privacyAnalysis?.isPrivate && analysis.privacyAnalysis?.privacyDomain,
    quickAssessment: {
      flags,
      priority: flags.includes('CHECK_PRIVACY_DOMAIN') ? 'high' : 'normal',
      recommendation: generateWorkflowRecommendation(flags)
    }
  };
}

function generateWorkflowRecommendation(flags) {
  if (flags.includes('CHECK_PRIVACY_DOMAIN')) {
    return 'High Priority: Check privacy contact domain for actual registrant details';
  }
  if (flags.includes('PRIVACY_PROTECTED')) {
    return 'Domain uses privacy protection - limited public information available';
  }
  if (flags.includes('US_REGISTRAR')) {
    return 'US-based registrar - UDRP procedures and legal remedies available';
  }
  return 'Standard domain registration - proceed with normal verification';
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

function parseRawWhois(rawData, domain) {
  const lines = rawData.split('\n');
  const parsed = { domain, rawData };
  
  // Extract key fields from raw WHOIS
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

function extractEmails(text) {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = text.match(emailRegex) || [];
  return [...new Set(emails.map(email => email.toLowerCase()))];
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
    availableEndpoints: ['/health', '/api/status', '/api/analyze', '/api/bulk-analyze']
  });
});

// ===== SERVER STARTUP =====
app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('🚀 WHOIS Intelligence Backend Server');
  console.log('='.repeat(60));
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 API status: http://localhost:${PORT}/api/status`);
  console.log(`💾 Cache TTL: 6 hours`);
  console.log(`⚡ Rate limit: 300 requests per 15 minutes`);
  console.log('='.repeat(60));
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

module.exports = app;