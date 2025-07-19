// FILE LOCATION: /server-blacklist-enhanced.js
// FILE NAME: server-blacklist-enhanced.js
// PURPOSE: Enhanced WHOIS Intelligence Server with Blacklist Checking
// DESCRIPTION: Integrates blacklist checking into existing WHOIS intelligence server
// VERSION: 2.1.0

// Add this to your existing server.js file or create as separate enhanced version

const { BlacklistChecker, performBulkBlacklistCheck } = require('./utils/blacklist-checker');

// ===== ADD TO EXISTING SERVER.JS =====

// Initialize blacklist checker
const blacklistChecker = new BlacklistChecker(cache);

// ===== NEW API ENDPOINTS =====

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
          domain: 'example.com' 
        }
      });
    }
    
    console.log(`[BLACKLIST] Starting blacklist analysis for: ${domain || 'custom data'}`);
    
    let emailsToCheck = emails || [];
    let ipsToCheck = ips || [];
    
    // If domain provided, extract emails and IPs from analysis
    if (domain) {
      const cleanDomain = sanitizeDomain(domain);
      
      // Get or perform domain analysis
      let analysis = null;
      const cacheKey = `analysis:${cleanDomain}`;
      analysis = cache.get(cacheKey);
      
      if (!analysis) {
        analysis = await performDomainAnalysis(cleanDomain);
        if (analysis.success) {
          cache.set(cacheKey, analysis, CONFIG.CACHE_TTL);
        }
      }
      
      if (analysis.success) {
        // Extract emails from WHOIS data
        if (analysis.whoisData?.emails) {
          emailsToCheck = [...new Set([...emailsToCheck, ...analysis.whoisData.emails])];
        }
        
        // Extract IPs from DNS data
        if (analysis.dnsData?.A) {
          ipsToCheck = [...new Set([...ipsToCheck, ...analysis.dnsData.A])];
        }
      }
    }
    
    // Perform blacklist checks
    const blacklistResults = await blacklistChecker.checkEmailAndIPs(emailsToCheck, ipsToCheck);
    
    const response = {
      success: true,
      domain: domain || null,
      timestamp: new Date().toISOString(),
      blacklistAnalysis: blacklistResults,
      responseTime: Date.now() - startTime
    };
    
    console.log(`[BLACKLIST COMPLETE] ${domain || 'custom'} in ${response.responseTime}ms`);
    res.json(response);
    
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

// Enhanced Analysis Endpoint (includes blacklist checking)
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
    
    // Perform standard domain analysis
    const analysis = await performDomainAnalysis(cleanDomain);
    
    if (!analysis.success) {
      return res.status(400).json(analysis);
    }
    
    // Extract emails and IPs for blacklist checking
    const emails = analysis.whoisData?.emails || [];
    const ips = analysis.dnsData?.A || [];
    
    // Perform blacklist analysis if we have data to check
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
    
    // Parallel analysis for other endpoints
    const [threatData, riskData] = await Promise.allSettled([
      makeApiCall(API_CONFIG.endpoints.threat, { domain: cleanDomain }),
      makeApiCall(API_CONFIG.endpoints.risk, { domain: cleanDomain })
    ]);
    
    const enhancedResponse = {
      ...analysis,
      blacklistAnalysis,
      threatAnalysis: threatData.status === 'fulfilled' ? threatData.value : null,
      riskAnalysis: riskData.status === 'fulfilled' ? riskData.value : null,
      responseTime: Date.now() - startTime
    };
    
    res.json(enhancedResponse);
    
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
        
        // Get domain analysis (from cache if available)
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
        
        // Rate limiting between domains
        await new Promise(resolve => setTimeout(resolve, 200));
        
      } catch (error) {
        results[domain] = {
          error: error.message,
          timestamp: new Date().toISOString()
        };
      }
    }
    
    // Calculate summary statistics
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

// ===== MODIFY EXISTING ANALYSIS FUNCTION =====
// Add this to the existing performDomainAnalysis function

async function performDomainAnalysisWithBlacklist(domain) {
  const analysis = await performDomainAnalysis(domain);
  
  if (analysis.success) {
    try {
      // Extract emails and IPs
      const emails = analysis.whoisData?.emails || [];
      const ips = analysis.dnsData?.A || [];
      
      // Perform blacklist analysis
      if (emails.length > 0 || ips.length > 0) {
        analysis.blacklistAnalysis = await blacklistChecker.checkEmailAndIPs(emails, ips);
        
        // Add blacklist summary to main summary
        if (analysis.blacklistAnalysis?.summary) {
          analysis.summary.blacklistSummary = {
            hasBlacklistedEmails: analysis.blacklistAnalysis.summary.blacklistedEmails > 0,
            hasBlacklistedIPs: analysis.blacklistAnalysis.summary.blacklistedIPs > 0,
            hasPrivacyEmails: analysis.blacklistAnalysis.summary.privacyEmails > 0,
            overallBlacklistRisk: analysis.blacklistAnalysis.summary.overallRisk
          };
        }
      }
    } catch (error) {
      console.error('[BLACKLIST INTEGRATION ERROR]', error);
      analysis.blacklistAnalysis = {
        error: 'Blacklist analysis failed',
        message: error.message
      };
    }
  }
  
  return analysis;
}

// ===== UPDATE API STATUS ENDPOINT =====
// Modify the existing /api/status endpoint to include blacklist features

app.get('/api/status', validateApiKey, (req, res) => {
  res.json({
    api: 'WHOIS Intelligence Tool - Enhanced with Blacklist Checking',
    version: '2.1.0',
    status: 'operational',
    features: {
      whoisAnalysis: 'enabled',
      privacyInvestigation: 'enabled', 
      recursiveAnalysis: 'enabled',
      threatIntelligence: 'enabled',
      riskScoring: 'enabled',
      bulkAnalysis: 'enabled',
      mxAnalysis: 'enabled',
      blacklistChecking: 'enabled',      // NEW
      privacyEmailDetection: 'enabled',  // NEW
      ipReputationChecking: 'enabled'    // NEW
    },
    endpoints: {
      analysis: '/api/analyze',
      enhancedAnalysis: '/api/analyze-enhanced',     // NEW
      bulkAnalysis: '/api/bulk-analyze',
      threatAnalysis: '/api/threat-analysis',
      riskScore: '/api/risk-score',
      privacyInvestigation: '/api/privacy-investigation',
      mxAnalysis: '/api/mx-analysis',
      blacklistAnalysis: '/api/blacklist-analysis',          // NEW
      privacyEmailLookup: '/api/privacy-email-lookup',       // NEW
      bulkBlacklistAnalysis: '/api/bulk-blacklist-analysis'  // NEW
    },
    blacklistFeatures: {                             // NEW SECTION
      dnsBlacklists: Object.keys(DNS_BLACKLISTS).length,
      privacyEmailPatterns: Object.keys(PRIVACY_EMAIL_PATTERNS).length,
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

// ===== ENVIRONMENT VARIABLES NEEDED =====
/*
Add these to your .env file for full functionality:

# Blacklist API Keys (optional but recommended)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# Additional threat intelligence APIs
URLVOID_API_KEY=your_urlvoid_api_key_here
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_api_key_here
*/

module.exports = {
  BlacklistChecker,
  performBulkBlacklistCheck,
  performDomainAnalysisWithBlacklist
};