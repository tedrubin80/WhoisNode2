/*
FOLDER STRUCTURE:
whois-intelligence-server/
├── ai/
│   ├── orchestrator.js              (this file)
│   ├── agents/
│   │   ├── domain-analyst.js        ✅
│   │   ├── threat-hunter.js         ✅
│   │   ├── risk-assessor.js         ✅
│   │   └── report-generator.js
│   ├── chains/
│   └── tools/

FILE LOCATION: /ai/orchestrator.js
*/

// AI Agent Orchestrator - Multi-Agent Research Coordination
// FILE: /ai/orchestrator.js

const { DomainAnalysisAgent } = require('./agents/domain-analyst');
const { ThreatHuntingAgent } = require('./agents/threat-hunter');
const { RiskAssessmentAgent } = require('./agents/risk-assessor');

class CyberSecurityResearchOrchestrator {
  constructor(cache = null, database = null) {
    this.cache = cache;
    this.database = database;
    this.agents = {};
    this.isInitialized = false;
    this.researchHistory = new Map();
    this.activeResearch = new Map();
    
    this.initializeOrchestrator();
  }

  async initializeOrchestrator() {
    try {
      console.log('🎭 Initializing AI Research Orchestrator...');
      
      // Initialize all agents
      this.agents = {
        domainAnalyst: new DomainAnalysisAgent(this.cache, this.database),
        threatHunter: new ThreatHuntingAgent(this.cache, this.database),
        riskAssessor: new RiskAssessmentAgent(this.cache, this.database)
      };

      // Wait for all agents to initialize
      const initResults = await Promise.allSettled([
        this.waitForAgentInitialization('domainAnalyst'),
        this.waitForAgentInitialization('threatHunter'),
        this.waitForAgentInitialization('riskAssessor')
      ]);

      const successfulAgents = initResults.filter(r => r.status === 'fulfilled').length;
      console.log(`✅ Research Orchestrator: ${successfulAgents}/3 agents initialized`);

      this.isInitialized = true;
      return true;

    } catch (error) {
      console.error('❌ Research Orchestrator initialization failed:', error);
      return false;
    }
  }

  async waitForAgentInitialization(agentName, maxWait = 10000) {
    const startTime = Date.now();
    while (!this.agents[agentName]?.isInitialized && (Date.now() - startTime) < maxWait) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    return this.agents[agentName]?.isInitialized || false;
  }

  async conductResearch(target, researchConfig = {}) {
    if (!this.isInitialized) {
      return {
        success: false,
        error: 'Research Orchestrator not initialized'
      };
    }

    const researchId = this.generateResearchId(target);
    console.log(`🔬 Starting comprehensive research: ${researchId} for ${target}`);

    const research = {
      id: researchId,
      target,
      timestamp: new Date().toISOString(),
      config: {
        depth: researchConfig.depth || 'standard', // standard, deep, comprehensive
        urgency: researchConfig.urgency || 'normal', // low, normal, high, critical
        scope: researchConfig.scope || 'full', // basic, full, extended
        parallel: researchConfig.parallel !== false, // enable parallel execution
        ...researchConfig
      },
      phases: [],
      status: 'in_progress',
      startTime: Date.now()
    };

    this.activeResearch.set(researchId, research);

    try {
      // Execute research phases based on configuration
      if (research.config.parallel && research.config.depth !== 'basic') {
        research.results = await this.executeParallelResearch(target, research.config);
      } else {
        research.results = await this.executeSequentialResearch(target, research.config);
      }

      // Generate comprehensive report
      research.comprehensiveReport = await this.generateComprehensiveReport(research.results, target);
      
      // Calculate research metrics
      research.metrics = this.calculateResearchMetrics(research);
      
      research.status = 'completed';
      research.endTime = Date.now();
      research.duration = research.endTime - research.startTime;

      // Store research results
      this.researchHistory.set(researchId, research);
      this.activeResearch.delete(researchId);

      console.log(`✅ Research completed: ${researchId} in ${research.duration}ms`);

      return {
        success: true,
        researchId,
        target,
        results: research.results,
        report: research.comprehensiveReport,
        metrics: research.metrics,
        duration: research.duration
      };

    } catch (error) {
      research.status = 'failed';
      research.error = error.message;
      research.endTime = Date.now();
      
      console.error(`❌ Research failed: ${researchId}`, error);
      
      return {
        success: false,
        researchId,
        target,
        error: error.message,
        partialResults: research.phases
      };
    }
  }

  async executeParallelResearch(target, config) {
    console.log(`⚡ Executing parallel research for ${target}`);
    
    const researchPromises = [];

    // Phase 1: Core Intelligence Gathering (Parallel)
    if (this.agents.domainAnalyst.isInitialized) {
      researchPromises.push(
        this.executePhase('domain_analysis', () => 
          this.agents.domainAnalyst.analyze(target, { 
            depth: config.depth,
            focus: 'infrastructure' 
          })
        )
      );
    }

    if (this.agents.threatHunter.isInitialized) {
      researchPromises.push(
        this.executePhase('threat_hunting', () => 
          this.agents.threatHunter.hunt(target, { 
            huntingDepth: config.depth,
            urgency: config.urgency 
          })
        )
      );
    }

    // Execute core phases in parallel
    const coreResults = await Promise.allSettled(researchPromises);
    
    // Phase 2: Risk Assessment (depends on core results)
    let riskAssessment = null;
    if (this.agents.riskAssessor.isInitialized) {
      const analysisContext = this.buildRiskContext(coreResults);
      riskAssessment = await this.executePhase('risk_assessment', () =>
        this.agents.riskAssessor.assess(target, analysisContext)
      );
    }

    return {
      domainAnalysis: this.extractResult(coreResults[0]),
      threatHunting: this.extractResult(coreResults[1]),
      riskAssessment,
      executionMode: 'parallel',
      totalPhases: coreResults.length + (riskAssessment ? 1 : 0)
    };
  }

  async executeSequentialResearch(target, config) {
    console.log(`🔄 Executing sequential research for ${target}`);
    
    const results = {
      executionMode: 'sequential',
      phases: []
    };

    // Phase 1: Domain Analysis
    if (this.agents.domainAnalyst.isInitialized) {
      console.log(`📊 Phase 1: Domain Analysis for ${target}`);
      results.domainAnalysis = await this.executePhase('domain_analysis', () =>
        this.agents.domainAnalyst.analyze(target, { depth: config.depth })
      );
      results.phases.push('domain_analysis');
    }

    // Phase 2: Threat Hunting (enhanced with domain context)
    if (this.agents.threatHunter.isInitialized) {
      console.log(`🎯 Phase 2: Threat Hunting for ${target}`);
      const huntingContext = results.domainAnalysis ? {
        domainIntelligence: results.domainAnalysis,
        huntingDepth: config.depth
      } : { huntingDepth: config.depth };
      
      results.threatHunting = await this.executePhase('threat_hunting', () =>
        this.agents.threatHunter.hunt(target, huntingContext)
      );
      results.phases.push('threat_hunting');
    }

    // Phase 3: Risk Assessment (comprehensive context)
    if (this.agents.riskAssessor.isInitialized) {
      console.log(`📈 Phase 3: Risk Assessment for ${target}`);
      const riskContext = {
        domainAnalysis: results.domainAnalysis,
        threatHunting: results.threatHunting,
        assessmentDepth: config.depth
      };
      
      results.riskAssessment = await this.executePhase('risk_assessment', () =>
        this.agents.riskAssessor.assess(target, riskContext)
      );
      results.phases.push('risk_assessment');
    }

    return results;
  }

  async executePhase(phaseName, phaseFunction) {
    const startTime = Date.now();
    
    try {
      console.log(`🔄 Executing phase: ${phaseName}`);
      const result = await phaseFunction();
      const duration = Date.now() - startTime;
      
      console.log(`✅ Phase completed: ${phaseName} (${duration}ms)`);
      
      return {
        ...result,
        phase: phaseName,
        duration,
        timestamp: new Date().toISOString()
      };
      
    } catch (error) {
      console.error(`❌ Phase failed: ${phaseName}`, error);
      return {
        success: false,
        phase: phaseName,
        error: error.message,
        duration: Date.now() - startTime
      };
    }
  }

  buildRiskContext(coreResults) {
    const context = {};
    
    coreResults.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        const data = result.value;
        if (data.agent === 'domain-analyst') {
          context.domainIntelligence = data;
        } else if (data.agent === 'threat-hunter') {
          context.threatIntelligence = data;
        }
      }
    });
    
    return context;
  }

  extractResult(promiseResult) {
    if (promiseResult.status === 'fulfilled') {
      return promiseResult.value;
    } else {
      return {
        success: false,
        error: promiseResult.reason?.message || 'Phase execution failed'
      };
    }
  }

  async generateComprehensiveReport(results, target) {
    const report = {
      target,
      timestamp: new Date().toISOString(),
      executiveSummary: {},
      detailedFindings: {},
      recommendations: [],
      riskProfile: {},
      actionPlan: [],
      appendices: {}
    };

    try {
      // Executive Summary
      report.executiveSummary = {
        overallRisk: this.determineOverallRisk(results),
        keyFindings: this.extractKeyFindings(results),
        criticalActions: this.prioritizeCriticalActions(results),
        businessImpact: this.assessBusinessImpact(results)
      };

      // Detailed Findings
      report.detailedFindings = {
        domainIntelligence: results.domainAnalysis?.analysis || {},
        threatLandscape: results.threatHunting?.huntingResults || {},
        riskAssessment: results.riskAssessment?.riskAssessment || {}
      };

      // Recommendations
      report.recommendations = this.consolidateRecommendations(results);

      // Risk Profile
      report.riskProfile = {
        overallScore: this.calculateOverallRiskScore(results),
        riskCategories: this.categorizeRisks(results),
        mitigationPriority: this.prioritizeMitigation(results)
      };

      // Action Plan
      report.actionPlan = this.generateActionPlan(results);

      console.log(`📄 Comprehensive report generated for ${target}`);
      
    } catch (error) {
      console.error('❌ Error generating comprehensive report:', error);
      report.error = 'Report generation partially failed';
    }

    return report;
  }

  determineOverallRisk(results) {
    const riskLevels = [];
    
    if (results.domainAnalysis?.analysis?.overallAssessment) {
      riskLevels.push(results.domainAnalysis.analysis.overallAssessment);
    }
    
    if (results.threatHunting?.huntingResults?.threatConfidence) {
      riskLevels.push(results.threatHunting.huntingResults.threatConfidence);
    }
    
    if (results.riskAssessment?.riskAssessment?.overallRiskLevel) {
      riskLevels.push(results.riskAssessment.riskAssessment.overallRiskLevel);
    }

    // Determine highest risk level
    const riskHierarchy = ['CRITICAL', 'DANGER', 'HIGH', 'WARNING', 'MEDIUM', 'CAUTION', 'LOW', 'SAFE'];
    
    for (const level of riskHierarchy) {
      if (riskLevels.includes(level)) {
        return level;
      }
    }
    
    return 'UNKNOWN';
  }

  extractKeyFindings(results) {
    const findings = [];
    
    if (results.domainAnalysis?.analysis?.keyFindings) {
      findings.push(...results.domainAnalysis.analysis.keyFindings.slice(0, 3));
    }
    
    if (results.threatHunting?.huntingResults?.indicators) {
      findings.push(...results.threatHunting.huntingResults.indicators.slice(0, 2));
    }
    
    if (results.riskAssessment?.executiveSummary?.keyFindings) {
      findings.push(...results.riskAssessment.executiveSummary.keyFindings.slice(0, 3));
    }
    
    return findings.slice(0, 5); // Top 5 findings
  }

  prioritizeCriticalActions(results) {
    const actions = [];
    
    // Extract critical actions from each agent
    if (results.domainAnalysis?.analysis?.recommendations) {
      actions.push(...results.domainAnalysis.analysis.recommendations.slice(0, 2));
    }
    
    if (results.threatHunting?.huntingResults?.recommendations) {
      actions.push(...results.threatHunting.huntingResults.recommendations.slice(0, 2));
    }
    
    if (results.riskAssessment?.executiveSummary?.criticalActions) {
      actions.push(...results.riskAssessment.executiveSummary.criticalActions.slice(0, 3));
    }
    
    return this.deduplicateActions(actions).slice(0, 5);
  }

  assessBusinessImpact(results) {
    return {
      financialImpact: results.riskAssessment?.executiveSummary?.businessImpact || 'Unknown',
      operationalImpact: 'Moderate',
      reputationalImpact: 'Low to Moderate',
      timeframe: '90 days'
    };
  }

  consolidateRecommendations(results) {
    const recommendations = [];
    
    Object.values(results).forEach(result => {
      if (result?.recommendations) {
        recommendations.push(...result.recommendations);
      }
      if (result?.analysis?.recommendations) {
        recommendations.push(...result.analysis.recommendations);
      }
      if (result?.executiveSummary?.criticalActions) {
        recommendations.push(...result.executiveSummary.criticalActions);
      }
    });
    
    return this.deduplicateActions(recommendations);
  }

  calculateOverallRiskScore(results) {
    const scores = [];
    
    if (results.domainAnalysis?.analysis?.confidenceScore) {
      scores.push(results.domainAnalysis.analysis.confidenceScore);
    }
    
    if (results.riskAssessment?.riskAssessment?.riskScore) {
      scores.push(results.riskAssessment.riskAssessment.riskScore);
    }
    
    return scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b) / scores.length) : 50;
  }

  categorizeRisks(results) {
    return {
      technical: 'Medium',
      operational: 'Medium', 
      compliance: 'Low',
      reputational: 'Low',
      financial: 'Medium'
    };
  }

  prioritizeMitigation(results) {
    return [
      { priority: 1, category: 'Critical vulnerabilities', timeline: '48 hours' },
      { priority: 2, category: 'Security controls', timeline: '2 weeks' },
      { priority: 3, category: 'Monitoring enhancement', timeline: '1 month' }
    ];
  }

  generateActionPlan(results) {
    return [
      {
        phase: 'Immediate (0-7 days)',
        actions: ['Address critical vulnerabilities', 'Enhance monitoring'],
        owner: 'Security Team'
      },
      {
        phase: 'Short-term (1-4 weeks)', 
        actions: ['Implement security controls', 'Update procedures'],
        owner: 'IT/Security Teams'
      },
      {
        phase: 'Medium-term (1-3 months)',
        actions: ['Security awareness training', 'Process improvements'],
        owner: 'All Teams'
      }
    ];
  }

  deduplicateActions(actions) {
    const seen = new Set();
    return actions.filter(action => {
      const normalized = action.toLowerCase().trim();
      if (seen.has(normalized)) {
        return false;
      }
      seen.add(normalized);
      return true;
    });
  }

  calculateResearchMetrics(research) {
    const successfulPhases = research.phases?.filter(p => p.success !== false).length || 0;
    const totalPhases = research.phases?.length || 0;
    
    return {
      successRate: totalPhases > 0 ? (successfulPhases / totalPhases) * 100 : 0,
      totalPhases,
      successfulPhases,
      averagePhaseTime: research.duration && totalPhases > 0 ? research.duration / totalPhases : 0,
      agentsUsed: Object.keys(research.results || {}).length,
      dataPoints: this.countDataPoints(research.results)
    };
  }

  countDataPoints(results) {
    let count = 0;
    
    const countObject = (obj) => {
      if (typeof obj === 'object' && obj !== null) {
        count += Object.keys(obj).length;
        Object.values(obj).forEach(value => {
          if (typeof value === 'object') countObject(value);
        });
      }
    };
    
    countObject(results);
    return count;
  }

  generateResearchId(target) {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 5);
    const targetHash = target.replace(/[^a-zA-Z0-9]/g, '').substr(0, 6);
    return `research_${targetHash}_${timestamp}_${random}`;
  }

  // Research management methods
  getActiveResearch() {
    return Array.from(this.activeResearch.values());
  }

  getResearchHistory(limit = 10) {
    const history = Array.from(this.researchHistory.values());
    return history.slice(-limit).reverse();
  }

  getResearchById(researchId) {
    return this.researchHistory.get(researchId) || this.activeResearch.get(researchId);
  }

  async cancelResearch(researchId) {
    const research = this.activeResearch.get(researchId);
    if (research) {
      research.status = 'cancelled';
      research.endTime = Date.now();
      this.activeResearch.delete(researchId);
      return true;
    }
    return false;
  }

  async healthCheck() {
    const agentHealth = {};
    
    for (const [name, agent] of Object.entries(this.agents)) {
      if (agent.healthCheck) {
        agentHealth[name] = await agent.healthCheck();
      } else {
        agentHealth[name] = { status: 'unknown' };
      }
    }
    
    return {
      orchestrator: 'operational',
      initialized: this.isInitialized,
      agents: agentHealth,
      activeResearch: this.activeResearch.size,
      researchHistory: this.researchHistory.size,
      capabilities: Object.keys(this.agents).filter(name => 
        this.agents[name].isInitialized
      )
    };
  }
}

module.exports = { CyberSecurityResearchOrchestrator };