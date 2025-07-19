/*
FOLDER STRUCTURE:
whois-intelligence-server/
├── ai/
│   ├── langchain-config.js      (this file)
│   ├── openai-client.js
│   └── basic-analysis.js

FILE LOCATION: /ai/langchain-config.js
*/

// Basic AI Configuration for WHOIS Intelligence - Week 1 Foundation
// FILE: /ai/langchain-config.js

const { ChatOpenAI } = require("@langchain/openai");
const { PromptTemplate } = require("@langchain/core/prompts");
const { LLMChain } = require("langchain/chains");

// AI Configuration
const AI_CONFIG = {
  model: "gpt-3.5-turbo",
  temperature: 0.1, // Low temperature for factual analysis
  maxTokens: 1000,
  timeout: 15000,
  enabled: !!process.env.OPENAI_API_KEY
};

// Initialize OpenAI client
let llm = null;
let isInitialized = false;

function initializeAI() {
  if (!process.env.OPENAI_API_KEY) {
    console.log('⚠️  OpenAI API key not found - AI features disabled');
    console.log('💡 Add OPENAI_API_KEY to .env to enable AI analysis');
    return false;
  }

  try {
    llm = new ChatOpenAI({
      openAIApiKey: process.env.OPENAI_API_KEY,
      modelName: AI_CONFIG.model,
      temperature: AI_CONFIG.temperature,
      maxTokens: AI_CONFIG.maxTokens,
      timeout: AI_CONFIG.timeout
    });

    isInitialized = true;
    console.log('✅ AI system initialized successfully');
    console.log(`🤖 Model: ${AI_CONFIG.model} (temp: ${AI_CONFIG.temperature})`);
    return true;
  } catch (error) {
    console.error('❌ AI initialization failed:', error.message);
    return false;
  }
}

// Basic Domain Analysis AI Chain
class DomainAnalysisAI {
  constructor() {
    this.chain = null;
    this.setupChain();
  }

  setupChain() {
    if (!isInitialized) {
      console.log('⚠️  AI not initialized - skipping chain setup');
      return;
    }

    const prompt = PromptTemplate.fromTemplate(`
You are a cybersecurity expert analyzing domain intelligence data.

Domain: {domain}
WHOIS Data: {whoisData}
DNS Records: {dnsRecords}
Blacklist Results: {blacklistResults}
Risk Score: {riskScore}

Provide a concise security analysis including:
1. Overall Security Assessment (Safe/Caution/Warning/Danger)
2. Key Risk Factors (max 3)
3. Confidence Level (High/Medium/Low)
4. Recommended Action

Keep response under 200 words and be specific about security concerns.

Analysis:
`);

    try {
      this.chain = new LLMChain({
        llm: llm,
        prompt: prompt
      });
      console.log('🔗 Domain analysis AI chain ready');
    } catch (error) {
      console.error('❌ Failed to setup AI chain:', error.message);
    }
  }

  async analyzeDomain(domainData) {
    if (!this.chain) {
      return {
        enabled: false,
        message: 'AI analysis not available - missing API key or initialization failed'
      };
    }

    try {
      console.log(`🤖 Running AI analysis for: ${domainData.domain}`);
      
      const result = await this.chain.call({
        domain: domainData.domain,
        whoisData: JSON.stringify(domainData.whoisData || {}, null, 2),
        dnsRecords: JSON.stringify(domainData.dnsData || {}, null, 2),
        blacklistResults: JSON.stringify(domainData.blacklistAnalysis || {}, null, 2),
        riskScore: domainData.riskScore || 'Not calculated'
      });

      return {
        enabled: true,
        success: true,
        analysis: result.text,
        model: AI_CONFIG.model,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('❌ AI analysis failed:', error.message);
      
      return {
        enabled: true,
        success: false,
        error: error.message,
        fallback: this.generateFallbackAnalysis(domainData)
      };
    }
  }

  generateFallbackAnalysis(domainData) {
    const risk = domainData.riskScore?.riskLevel || 'unknown';
    const hasBlacklist = domainData.blacklistAnalysis?.summary?.blacklistedEmails > 0 || 
                        domainData.blacklistAnalysis?.summary?.blacklistedIPs > 0;
    const isPrivacy = domainData.privacyAnalysis?.isPrivate;

    let assessment = 'Safe';
    let action = 'Standard security practices sufficient';

    if (hasBlacklist) {
      assessment = 'Danger';
      action = 'Block or investigate immediately';
    } else if (risk === 'high' || risk === 'critical') {
      assessment = 'Warning';
      action = 'Exercise extreme caution';
    } else if (isPrivacy || risk === 'medium') {
      assessment = 'Caution';
      action = 'Additional verification recommended';
    }

    return `Automated Analysis:
1. Security Assessment: ${assessment}
2. Primary Risk: ${hasBlacklist ? 'Blacklisted resources' : isPrivacy ? 'Privacy protection detected' : 'Standard domain registration'}
3. Confidence: Medium (rule-based analysis)
4. Recommended Action: ${action}

Note: This is a fallback analysis. Enable OpenAI API for enhanced AI insights.`;
  }
}

// Simple AI-powered risk enhancement
async function enhanceRiskWithAI(riskData, domainData) {
  if (!isInitialized) {
    return riskData;
  }

  try {
    const prompt = `
Based on this risk assessment data, provide a brief AI confidence adjustment:

Risk Level: ${riskData.riskLevel}
Risk Score: ${riskData.totalScore}/100
Domain: ${domainData.domain}
Factors: ${riskData.factors?.map(f => f.factor).join(', ') || 'None'}

Should the risk level be adjusted? Respond with just:
- INCREASE (if risks are underestimated)
- DECREASE (if risks are overestimated)  
- MAINTAIN (if assessment is accurate)
- INSUFFICIENT_DATA

One word response only.
`;

    const result = await llm.call(prompt);
    const adjustment = result.trim().toUpperCase();

    return {
      ...riskData,
      aiEnhancement: {
        enabled: true,
        adjustment: adjustment,
        confidence: adjustment === 'INSUFFICIENT_DATA' ? 'low' : 'medium',
        timestamp: new Date().toISOString()
      }
    };
  } catch (error) {
    console.error('❌ AI risk enhancement failed:', error.message);
    return riskData;
  }
}

// AI system health check
async function aiHealthCheck() {
  if (!isInitialized) {
    return {
      status: 'disabled',
      message: 'AI system not initialized - missing API key'
    };
  }

  try {
    const testResult = await llm.call('Respond with "OK" if you can read this message.');
    
    return {
      status: testResult.trim() === 'OK' ? 'healthy' : 'degraded',
      message: 'AI system operational',
      model: AI_CONFIG.model,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    return {
      status: 'error',
      message: error.message,
      timestamp: new Date().toISOString()
    };
  }
}

// Initialize AI on module load
const domainAnalysisAI = new DomainAnalysisAI();

module.exports = {
  initializeAI,
  isAIEnabled: () => isInitialized,
  domainAnalysisAI,
  enhanceRiskWithAI,
  aiHealthCheck,
  AI_CONFIG
};