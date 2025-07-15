/*
FILE LOCATION: /frontend/src/App.js (for React app)
FILE NAME: App.js
PURPOSE: Modern WHOIS Intelligence React Dashboard
DESCRIPTION: React component for domain analysis, threat intelligence, and risk scoring
VERSION: 2.0.0
DEPENDENCIES: react, lucide-react
USAGE: Replace default App.js in React app or use as component
*/

import React, { useState, useEffect } from 'react';
import { Search, Shield, AlertTriangle, Activity, Globe, Database, TrendingUp, Eye } from 'lucide-react';

const WHOISIntelligenceDashboard = () => {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [threatData, setThreatData] = useState(null);
  const [riskScore, setRiskScore] = useState(null);
  const [activeTab, setActiveTab] = useState('analysis');
  const [apiStats, setApiStats] = useState(null);

  // Fetch API status on load
  useEffect(() => {
    fetchApiStatus();
  }, []);

  const fetchApiStatus = async () => {
    try {
      const response = await fetch('/api/status');
      const data = await response.json();
      setApiStats(data);
    } catch (error) {
      console.error('Failed to fetch API status:', error);
    }
  };

  const analyzeDomain = async () => {
    if (!domain.trim()) return;
    
    setLoading(true);
    setAnalysis(null);
    setThreatData(null);
    setRiskScore(null);

    try {
      // Basic domain analysis
      const analysisResponse = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() })
      });
      const analysisData = await analysisResponse.json();
      setAnalysis(analysisData);

      // Threat analysis
      const threatResponse = await fetch('/api/threat-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() })
      });
      const threatResult = await threatResponse.json();
      setThreatData(threatResult);

      // Risk score
      const riskResponse = await fetch('/api/risk-score', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() })
      });
      const riskResult = await riskResponse.json();
      setRiskScore(riskResult);

    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level) => {
    const colors = {
      low: 'text-green-600 bg-green-100',
      medium: 'text-yellow-600 bg-yellow-100',
      high: 'text-orange-600 bg-orange-100',
      critical: 'text-red-600 bg-red-100'
    };
    return colors[level] || 'text-gray-600 bg-gray-100';
  };

  const getThreatSeverityColor = (severity) => {
    const colors = {
      low: 'text-green-600',
      medium: 'text-yellow-600',
      high: 'text-orange-600',
      critical: 'text-red-600'
    };
    return colors[severity] || 'text-gray-600';
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">WHOIS Intelligence</h1>
              <span className="text-sm text-gray-500 bg-gray-100 px-2 py-1 rounded">v2.0 Enhanced</span>
            </div>
            {apiStats && (
              <div className="flex items-center space-x-4 text-sm text-gray-600">
                <span className="flex items-center">
                  <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                  {apiStats.status}
                </span>
                <span>{apiStats.tier} tier</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Search Section */}
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <div className="flex items-center space-x-4">
            <div className="flex-1">
              <label htmlFor="domain" className="block text-sm font-medium text-gray-700 mb-2">
                Domain Analysis
              </label>
              <div className="relative">
                <input
                  type="text"
                  id="domain"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && analyzeDomain()}
                  placeholder="Enter domain (e.g., example.com)"
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <Globe className="absolute left-3 top-3.5 h-5 w-5 text-gray-400" />
              </div>
            </div>
            <button
              onClick={analyzeDomain}
              disabled={loading || !domain.trim()}
              className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
            >
              {loading ? (
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
              ) : (
                <Search className="h-5 w-5" />
              )}
              <span>{loading ? 'Analyzing...' : 'Analyze'}</span>
            </button>
          </div>
        </div>

        {/* Results Section */}
        {(analysis || threatData || riskScore) && (
          <div className="space-y-6">
            {/* Quick Overview Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {/* Domain Status */}
              <div className="bg-white p-4 rounded-lg shadow-sm">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Domain Status</p>
                    <p className="text-lg font-semibold text-gray-900">
                      {analysis?.success ? 'Active' : 'Error'}
                    </p>
                  </div>
                  <Activity className={`h-8 w-8 ${analysis?.success ? 'text-green-500' : 'text-red-500'}`} />
                </div>
              </div>

              {/* Risk Score */}
              <div className="bg-white p-4 rounded-lg shadow-sm">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Risk Score</p>
                    <p className="text-lg font-semibold text-gray-900">
                      {riskScore?.riskScore?.totalScore || 0}/100
                    </p>
                    {riskScore?.riskScore?.riskLevel && (
                      <span className={`text-xs px-2 py-1 rounded-full ${getRiskColor(riskScore.riskScore.riskLevel)}`}>
                        {riskScore.riskScore.riskLevel.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <TrendingUp className="h-8 w-8 text-blue-500" />
                </div>
              </div>

              {/* Threat Level */}
              <div className="bg-white p-4 rounded-lg shadow-sm">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Threat Level</p>
                    <p className={`text-lg font-semibold ${getThreatSeverityColor(threatData?.severity)}`}>
                      {threatData?.severity?.toUpperCase() || 'UNKNOWN'}
                    </p>
                  </div>
                  <AlertTriangle className={`h-8 w-8 ${getThreatSeverityColor(threatData?.severity)}`} />
                </div>
              </div>

              {/* Registrar */}
              <div className="bg-white p-4 rounded-lg shadow-sm">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Registrar</p>
                    <p className="text-lg font-semibold text-gray-900 truncate">
                      {analysis?.summary?.registrar || 'Unknown'}
                    </p>
                    {analysis?.summary?.isUSRegistrar && (
                      <span className="text-xs text-blue-600 bg-blue-100 px-2 py-1 rounded-full">
                        US-based
                      </span>
                    )}
                  </div>
                  <Database className="h-8 w-8 text-gray-500" />
                </div>
              </div>
            </div>

            {/* Detailed Analysis Tabs */}
            <div className="bg-white rounded-lg shadow-sm">
              <div className="border-b border-gray-200">
                <nav className="flex space-x-8 px-6">
                  {[
                    { id: 'analysis', label: 'Domain Analysis', icon: Globe },
                    { id: 'threat', label: 'Threat Intelligence', icon: Shield },
                    { id: 'risk', label: 'Risk Assessment', icon: AlertTriangle },
                    { id: 'dns', label: 'DNS Records', icon: Database }
                  ].map((tab) => {
                    const Icon = tab.icon;
                    return (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 ${
                          activeTab === tab.id
                            ? 'border-blue-500 text-blue-600'
                            : 'border-transparent text-gray-500 hover:text-gray-700'
                        }`}
                      >
                        <Icon className="h-4 w-4" />
                        <span>{tab.label}</span>
                      </button>
                    );
                  })}
                </nav>
              </div>

              <div className="p-6">
                {/* Domain Analysis Tab */}
                {activeTab === 'analysis' && analysis && (
                  <div className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      {/* WHOIS Information */}
                      <div>
                        <h3 className="text-lg font-semibold text-gray-900 mb-4">WHOIS Information</h3>
                        <div className="space-y-3">
                          <div>
                            <span className="text-sm text-gray-600">Creation Date:</span>
                            <p className="text-sm font-medium">{analysis.summary?.creationDate || 'Unknown'}</p>
                          </div>
                          <div>
                            <span className="text-sm text-gray-600">Expiration Date:</span>
                            <p className="text-sm font-medium">{analysis.summary?.expirationDate || 'Unknown'}</p>
                          </div>
                          <div>
                            <span className="text-sm text-gray-600">Registrant Country:</span>
                            <p className="text-sm font-medium">{analysis.summary?.registrantCountry || 'Unknown'}</p>
                          </div>
                          <div>
                            <span className="text-sm text-gray-600">Privacy Protected:</span>
                            <p className={`text-sm font-medium ${analysis.summary?.isPrivacyProtected ? 'text-orange-600' : 'text-green-600'}`}>
                              {analysis.summary?.isPrivacyProtected ? 'Yes' : 'No'}
                            </p>
                          </div>
                        </div>
                      </div>

                      {/* Geographic Information */}
                      <div>
                        <h3 className="text-lg font-semibold text-gray-900 mb-4">Geographic Information</h3>
                        <div className="space-y-3">
                          <div>
                            <span className="text-sm text-gray-600">Primary IP:</span>
                            <p className="text-sm font-medium font-mono">{analysis.summary?.primaryIP || 'Unknown'}</p>
                          </div>
                          {analysis.summary?.geoLocation && (
                            <>
                              <div>
                                <span className="text-sm text-gray-600">Country:</span>
                                <p className="text-sm font-medium">{analysis.summary.geoLocation.country}</p>
                              </div>
                              <div>
                                <span className="text-sm text-gray-600">Region:</span>
                                <p className="text-sm font-medium">{analysis.summary.geoLocation.region}</p>
                              </div>
                              <div>
                                <span className="text-sm text-gray-600">City:</span>
                                <p className="text-sm font-medium">{analysis.summary.geoLocation.city}</p>
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Threat Intelligence Tab */}
                {activeTab === 'threat' && threatData && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Assessment</h3>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                        {Object.entries(threatData.threats || {}).map(([threat, detected]) => (
                          <div key={threat} className="flex items-center space-x-2">
                            <div className={`w-3 h-3 rounded-full ${detected ? 'bg-red-500' : 'bg-green-500'}`}></div>
                            <span className="text-sm capitalize">{threat}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {threatData.indicators && threatData.indicators.length > 0 && (
                      <div>
                        <h4 className="text-md font-semibold text-gray-900 mb-3">Threat Indicators</h4>
                        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                          <ul className="space-y-2">
                            {threatData.indicators.map((indicator, index) => (
                              <li key={index} className="text-sm text-red-800 flex items-start space-x-2">
                                <AlertTriangle className="h-4 w-4 text-red-600 mt-0.5 flex-shrink-0" />
                                <span>{indicator}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Risk Assessment Tab */}
                {activeTab === 'risk' && riskScore && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Assessment</h3>
                      
                      <div className="mb-6">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium text-gray-900">Overall Risk Score</span>
                          <span className="text-sm font-medium text-gray-900">
                            {riskScore.riskScore?.totalScore || 0}/100
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div 
                            className={`h-2 rounded-full ${
                              (riskScore.riskScore?.totalScore || 0) >= 70 ? 'bg-red-600' :
                              (riskScore.riskScore?.totalScore || 0) >= 40 ? 'bg-yellow-600' : 'bg-green-600'
                            }`}
                            style={{ width: `${riskScore.riskScore?.totalScore || 0}%` }}
                          ></div>
                        </div>
                      </div>

                      {riskScore.riskScore?.factors && (
                        <div>
                          <h4 className="text-md font-semibold text-gray-900 mb-3">Risk Factors</h4>
                          <div className="space-y-3">
                            {riskScore.riskScore.factors.map((factor, index) => (
                              <div key={index} className="bg-gray-50 rounded-lg p-3">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-sm font-medium text-gray-900">{factor.factor}</span>
                                  <span className="text-sm text-red-600">+{factor.score}</span>
                                </div>
                                <p className="text-xs text-gray-600">{factor.description}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {riskScore.riskScore?.recommendation && (
                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                          <h4 className="text-sm font-semibold text-blue-900 mb-2">Recommendation</h4>
                          <p className="text-sm text-blue-800">{riskScore.riskScore.recommendation}</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* DNS Records Tab */}
                {activeTab === 'dns' && analysis?.dnsData && (
                  <div className="space-y-6">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">DNS Records</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      {/* A Records */}
                      <div>
                        <h4 className="text-md font-semibold text-gray-900 mb-3">A Records (IPv4)</h4>
                        <div className="bg-gray-50 rounded-lg p-3">
                          {analysis.dnsData.A && analysis.dnsData.A.length > 0 ? (
                            <div className="space-y-1">
                              {analysis.dnsData.A.map((ip, index) => (
                                <p key={index} className="text-sm font-mono text-gray-800">{ip}</p>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-gray-500">No A records found</p>
                          )}
                        </div>
                      </div>

                      {/* MX Records */}
                      <div>
                        <h4 className="text-md font-semibold text-gray-900 mb-3">MX Records (Email)</h4>
                        <div className="bg-gray-50 rounded-lg p-3">
                          {analysis.dnsData.MX && analysis.dnsData.MX.length > 0 ? (
                            <div className="space-y-1">
                              {analysis.dnsData.MX.map((mx, index) => (
                                <p key={index} className="text-sm font-mono text-gray-800">
                                  {mx.priority} {mx.exchange}
                                </p>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-gray-500">No MX records found</p>
                          )}
                        </div>
                      </div>

                      {/* NS Records */}
                      <div>
                        <h4 className="text-md font-semibold text-gray-900 mb-3">NS Records (Name Servers)</h4>
                        <div className="bg-gray-50 rounded-lg p-3">
                          {analysis.dnsData.NS && analysis.dnsData.NS.length > 0 ? (
                            <div className="space-y-1">
                              {analysis.dnsData.NS.map((ns, index) => (
                                <p key={index} className="text-sm font-mono text-gray-800">{ns}</p>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-gray-500">No NS records found</p>
                          )}
                        </div>
                      </div>

                      {/* TXT Records */}
                      <div>
                        <h4 className="text-md font-semibold text-gray-900 mb-3">TXT Records</h4>
                        <div className="bg-gray-50 rounded-lg p-3 max-h-40 overflow-y-auto">
                          {analysis.dnsData.TXT && analysis.dnsData.TXT.length > 0 ? (
                            <div className="space-y-1">
                              {analysis.dnsData.TXT.map((txt, index) => (
                                <p key={index} className="text-xs font-mono text-gray-800 break-all">
                                  {Array.isArray(txt) ? txt.join('') : txt}
                                </p>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-gray-500">No TXT records found</p>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Help Section */}
        {!analysis && !loading && (
          <div className="bg-white rounded-lg shadow-sm p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Enhanced Features</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="text-center p-4">
                <Shield className="h-8 w-8 text-blue-600 mx-auto mb-2" />
                <h3 className="font-medium text-gray-900">Threat Intelligence</h3>
                <p className="text-sm text-gray-600 mt-1">Advanced malware and phishing detection</p>
              </div>
              <div className="text-center p-4">
                <TrendingUp className="h-8 w-8 text-green-600 mx-auto mb-2" />
                <h3 className="font-medium text-gray-900">Risk Scoring</h3>
                <p className="text-sm text-gray-600 mt-1">Comprehensive domain risk assessment</p>
              </div>
              <div className="text-center p-4">
                <Eye className="h-8 w-8 text-purple-600 mx-auto mb-2" />
                <h3 className="font-medium text-gray-900">RDAP Support</h3>
                <p className="text-sm text-gray-600 mt-1">Modern domain registration data protocol</p>
              </div>
              <div className="text-center p-4">
                <Activity className="h-8 w-8 text-orange-600 mx-auto mb-2" />
                <h3 className="font-medium text-gray-900">Real-time Monitoring</h3>
                <p className="text-sm text-gray-600 mt-1">Domain change detection and alerts</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default WHOISIntelligenceDashboard;