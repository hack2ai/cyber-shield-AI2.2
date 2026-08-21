import React, { useState, useEffect, useRef } from 'react';
import { 
  BarChart, Bar, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, PieChart, Pie, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  LineChart, Line
} from 'recharts';
import { 
  Shield, AlertTriangle, CheckCircle, Info, Activity, Globe, Cpu, Terminal, 
  Download, Sparkles, RefreshCcw, TrendingUp, ShieldAlert, Radio, FileText
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { db, collection, query, where, onSnapshot } from '../lib/firebase';

interface ThreatAnalyticsDashboardProps {
  user: any;
}

interface MetricStats {
  totalScans: number;
  maliciousCount: number;
  suspiciousCount: number;
  safeCount: number;
  integrityIndex: number;
  phishingRatio: number;
}

export function ThreatAnalyticsDashboard({ user }: ThreatAnalyticsDashboardProps) {
  const currentUserId = user?.uid || 'guest-operator';
  const isLocalBrowser = typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');
  const isGuestOrMock =
    isLocalBrowser ||
    currentUserId === 'mock-analyst-1337' ||
    currentUserId === 'guest-operator' ||
    currentUserId.startsWith('mock-user-');

  const [scanReports, setScanReports] = useState<any[]>([]);
  const [fileScanReports, setFileScanReports] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<MetricStats>({
    totalScans: 0,
    maliciousCount: 0,
    suspiciousCount: 0,
    safeCount: 0,
    integrityIndex: 100,
    phishingRatio: 0
  });

  // AI-generated intelligence state
  const [aiInsights, setAiInsights] = useState<string[]>([
    "Initial neural link sync: Click 'GENERATE_AI_INSIGHTS' to analyze attack vectors.",
    "Threat index standing by for heuristic projection calculations.",
    "Awaiting operator command payload to initialize telemetry models."
  ]);
  const [aiRecommendations, setAiRecommendations] = useState<string[]>([
    "Standby: Audit rules will refresh upon AI model generation.",
    "Boundary filters running at default compliance parameters.",
    "Verify local agent sync keys to enable automated routing audits."
  ]);
  const [predictedData, setPredictedData] = useState<number[]>([12, 18, 15, 22, 28, 20, 24]);
  const [forecastScore, setForecastScore] = useState<number>(55);
  const [isGeneratingAI, setIsGeneratingAI] = useState<boolean>(false);
  const [aiGenerated, setAiGenerated] = useState<boolean>(false);

  // Live Terminal Logs State
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // 1. Subscribe to Firestore or load from localStorage
  useEffect(() => {
    if (isGuestOrMock) {
      const loadLocalHistory = () => {
        // Load URL scan reports
        const localScans = localStorage.getItem('cyber_shield_mock_scan_reports');
        const parsedScans = localScans ? JSON.parse(localScans) : [];
        setScanReports(parsedScans);

        // Load File scan reports
        const localFileScans = localStorage.getItem('cyber_shield_mock_file_scan_reports');
        const parsedFileScans = localFileScans ? JSON.parse(localFileScans) : [];
        setFileScanReports(parsedFileScans);
      };

      loadLocalHistory();

      // Listen to storage events to keep updated
      const handleStorage = (e: StorageEvent) => {
        if (e.key === 'cyber_shield_mock_scan_reports' || e.key === 'cyber_shield_mock_file_scan_reports') {
          loadLocalHistory();
        }
      };
      window.addEventListener('storage', handleStorage);
      window.addEventListener('cyber_shield_new_report', loadLocalHistory);
      return () => {
        window.removeEventListener('storage', handleStorage);
        window.removeEventListener('cyber_shield_new_report', loadLocalHistory);
      };
    } else {
      const q1 = query(collection(db, 'scanReports'), where('userId', '==', currentUserId));
      const unsubscribe1 = onSnapshot(q1, (snapshot) => {
        const list = snapshot.docs.map(doc => doc.data());
        setScanReports(list);
      }, (err) => console.error("Firestore error scans:", err));

      const q2 = query(collection(db, 'fileScanReports'), where('userId', '==', currentUserId));
      const unsubscribe2 = onSnapshot(q2, (snapshot) => {
        const list = snapshot.docs.map(doc => doc.data());
        setFileScanReports(list);
      }, (err) => console.error("Firestore error files:", err));

      return () => {
        unsubscribe1();
        unsubscribe2();
      };
    }
  }, [currentUserId, isGuestOrMock]);

  // 2. Aggregate metrics on data change
  useEffect(() => {
    const allReports = [...scanReports, ...fileScanReports];
    const total = allReports.length;

    const malicious = allReports.filter(r => r.classification === 'Malicious' || r.classification === 'Phishing').length;
    const suspicious = allReports.filter(r => r.classification === 'Suspicious').length;
    const safe = allReports.filter(r => r.classification === 'Safe').length;
    const displayTotal = total;

    const integrity = displayTotal > 0 ? Math.round((safe / displayTotal) * 100) : 100;
    const phishingRatio = displayTotal > 0 ? Math.round(((malicious + suspicious) / displayTotal) * 100) : 0;

    setMetrics({
      totalScans: displayTotal,
      maliciousCount: malicious,
      suspiciousCount: suspicious,
      safeCount: safe,
      integrityIndex: integrity,
      phishingRatio
    });
  }, [scanReports, fileScanReports]);

  // 3. Simulated Live SOC Terminal Logs
  useEffect(() => {
    const logs = [
      "SYSTEM: SOC analytics node initialized. Uptime status checks normal.",
      "HEURISTICS: Dynamic threat maps loaded from global registry updates.",
      "DATABASE: Synchronized 24 threat classification signatures.",
      "NETWORK: Monitoring active ports on interface eth0...",
      "INTELLIGENCE: Subscribed to Lyzr Threat Feed vector arrays."
    ];
    setTerminalLogs(logs);

    const targets = ["paypal-security.org", "update-bank-login.net", "8.8.8.8", "drive-download.ru", "patch_v1.04.exe", "invoice_9281.pdf"];
    const actions = ["analyzed target", "flagged host", "intercepted connection", "whitelisted query", "decompiled binary signature"];
    const statusLevels = ["INFO", "WARN", "ALERT", "CRITICAL"];

    const interval = setInterval(() => {
      const randomStatus = statusLevels[Math.floor(Math.random() * statusLevels.length)];
      const randomTarget = targets[Math.floor(Math.random() * targets.length)];
      const randomAction = actions[Math.floor(Math.random() * actions.length)];
      const timestamp = new Date().toLocaleTimeString();

      const newLog = `[${timestamp}] ${randomStatus}: AI Agent ${randomAction} -> ${randomTarget}`;
      setTerminalLogs(prev => [...prev.slice(-30), newLog]);
    }, 4000);

    return () => clearInterval(interval);
  }, []);

  // Auto-scroll terminal
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLogs]);

  // 4. API communication for AI prediction
  const generateAIPredictions = async () => {
    setIsGeneratingAI(true);
    try {
      const res = await fetch('/api/threat-analytics/predict', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ metrics })
      });

      if (!res.ok) throw new Error("Failed to reach prediction engine.");
      const data = await res.json();

      if (data.insights) setAiInsights(data.insights);
      if (data.recommendations) setAiRecommendations(data.recommendations);
      if (data.predictions) setPredictedData(data.predictions);
      if (data.threatScoreForecast !== undefined) setForecastScore(data.threatScoreForecast);
      setAiGenerated(true);
    } catch (err) {
      console.error(err);
    } finally {
      setIsGeneratingAI(false);
    }
  };

  // 5. PDF & JSON Exports
  const exportTelemetryJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
      metrics,
      aiInsights,
      aiRecommendations,
      predictions: predictedData,
      scanReportsCount: scanReports.length,
      fileScanReportsCount: fileScanReports.length,
      timestamp: new Date().toISOString()
    }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `cyber_shield_telemetry_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Pre-formatted weekly trend coordinates based on raw logs
  const getWeeklyTrendData = () => {
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const totalCount = metrics.totalScans;
    return days.map((day, idx) => {
      const baseMult = (idx + 1) * 0.45;
      const maliciousFreq = Math.round(metrics.maliciousCount * baseMult * 0.3) + 1;
      const suspiciousFreq = Math.round(metrics.suspiciousCount * baseMult * 0.2) + 1;
      const safeFreq = Math.round(metrics.safeCount * baseMult * 0.4) + 2;
      return {
        name: day,
        Malicious: maliciousFreq,
        Suspicious: suspiciousFreq,
        Safe: safeFreq,
      };
    });
  };

  // Pie chart categories mapping
  const getCategoryData = () => [
    { name: 'Malicious', value: metrics.maliciousCount, color: '#ef4444' },
    { name: 'Suspicious', value: metrics.suspiciousCount, color: '#f59e0b' },
    { name: 'Safe', value: metrics.safeCount, color: '#39FF14' }
  ];

  // Radar metrics mapping
  const getRadarData = () => [
    { subject: 'DNS Spoofing', A: Math.max(10, metrics.maliciousCount * 6), fullMark: 100 },
    { subject: 'URL Rep', A: Math.max(20, metrics.maliciousCount * 9 + metrics.suspiciousCount * 3), fullMark: 100 },
    { subject: 'Magic Bytes', A: Math.max(15, metrics.suspiciousCount * 8), fullMark: 100 },
    { subject: 'File Entropy', A: Math.max(5, metrics.maliciousCount * 4), fullMark: 100 },
    { subject: 'WHOIS Age', A: Math.max(12, metrics.suspiciousCount * 5), fullMark: 100 },
    { subject: 'IP Reputation', A: Math.max(30, metrics.maliciousCount * 8), fullMark: 100 }
  ];

  // Predictions trend list mapping
  const getForecastChartData = () => {
    const days = ['D+1', 'D+2', 'D+3', 'D+4', 'D+5', 'D+6', 'D+7'];
    return days.map((day, idx) => ({
      name: day,
      Predicted: predictedData[idx] || 15
    }));
  };

  // Attack origins suffix metrics
  const getOriginsData = () => [
    { country: 'RUSSIA (.ru)', value: Math.max(2, Math.round(metrics.maliciousCount * 0.4)) },
    { country: 'CHINA (.cn)', value: Math.max(1, Math.round(metrics.maliciousCount * 0.3)) },
    { country: 'UNKNOWN (Proxy)', value: Math.max(3, Math.round(metrics.suspiciousCount * 0.5)) },
    { country: 'USA (Cloudflare)', value: Math.max(4, Math.round(metrics.safeCount * 0.6)) },
    { country: 'GLOBAL (.net)', value: Math.max(2, Math.round(metrics.totalScans * 0.15)) }
  ];

  // Generate heatmap matrix (7 Days vs 6 Hour Intervals)
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const intervals = ['00-04', '04-08', '08-12', '12-16', '16-20', '20-24'];

  return (
    <div className="space-y-4 font-mono select-none" id="analytics-report-pdf">
      
      {/* HEADER CONTROLS */}
      <div className="flex justify-between items-center bg-black/60 border border-cyan-500/20 p-4 glass-panel">
        <div>
          <h2 className="text-sm font-black text-cyan-400 tracking-[0.25em] uppercase flex items-center gap-2">
            <Radio size={16} className="text-cyan-400 animate-pulse" /> THREAT_INTELLIGENCE_ANALYTICS
          </h2>
          <p className="text-[9px] text-zinc-500 uppercase tracking-widest mt-1">SOC Real-Time Threat Modeling and Heuristic Aggregator Node</p>
        </div>
        <div className="flex gap-2">
          <button 
            onClick={generateAIPredictions}
            disabled={isGeneratingAI}
            className="px-3 py-1.5 bg-purple-500/10 border border-purple-500/30 hover:border-purple-400 text-purple-400 text-[9px] font-black uppercase tracking-widest transition-all flex items-center gap-1.5 disabled:opacity-40"
          >
            <Sparkles size={11} className={isGeneratingAI ? "animate-spin" : ""} />
            {isGeneratingAI ? "CALCULATING..." : "GENERATE_AI_INSIGHTS"}
          </button>
          <button 
            onClick={exportTelemetryJson}
            className="px-3 py-1.5 bg-cyan-500/10 border border-cyan-500/30 hover:border-cyan-400 text-cyan-400 text-[9px] font-black uppercase tracking-widest transition-all flex items-center gap-1.5"
          >
            <Download size={11} /> EXPORT_TELEMETRY
          </button>
        </div>
      </div>

      {/* METRICS HUD GRID */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="glass-panel border-cyan-500/20 bg-cyan-950/5 p-4 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/[0.02] rounded-full blur-xl group-hover:bg-cyan-500/[0.05] transition-all" />
          <div className="flex justify-between items-start mb-2">
            <span className="text-[9px] text-zinc-500 uppercase font-black tracking-widest">TOTAL_SCANS_ANALYSED</span>
            <Activity size={14} className="text-cyan-400 opacity-60" />
          </div>
          <p className="text-2xl font-black text-cyan-400 tracking-tighter">{metrics.totalScans}</p>
          <div className="text-[8px] text-cyan-500/50 uppercase mt-1 flex justify-between">
            <span>REAL_TIME_SYNC</span>
            <span className="animate-pulse">● ACTIVE</span>
          </div>
        </div>

        <div className="glass-panel border-red-500/20 bg-red-950/5 p-4 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/[0.02] rounded-full blur-xl group-hover:bg-red-500/[0.05] transition-all" />
          <div className="flex justify-between items-start mb-2">
            <span className="text-[9px] text-zinc-500 uppercase font-black tracking-widest">MALICIOUS_THREATS</span>
            <ShieldAlert size={14} className="text-red-500 opacity-60" />
          </div>
          <p className="text-2xl font-black text-red-500 tracking-tighter">{metrics.maliciousCount}</p>
          <div className="text-[8px] text-red-500/50 uppercase mt-1 flex justify-between">
            <span>DANGER_RATIO</span>
            <span>{metrics.phishingRatio}%</span>
          </div>
        </div>

        <div className="glass-panel border-[#39FF14]/20 bg-emerald-950/5 p-4 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-24 h-24 bg-[#39FF14]/[0.02] rounded-full blur-xl group-hover:bg-[#39FF14]/[0.05] transition-all" />
          <div className="flex justify-between items-start mb-2">
            <span className="text-[9px] text-zinc-500 uppercase font-black tracking-widest">CLEARED_INTEGRITY</span>
            <CheckCircle size={14} className="text-[#39FF14] opacity-60" />
          </div>
          <p className="text-2xl font-black text-[#39FF14] tracking-tighter">{metrics.integrityIndex}%</p>
          <div className="text-[8px] text-[#39FF14]/50 uppercase mt-1 flex justify-between">
            <span>SAFE_COORDINATES</span>
            <span>{metrics.safeCount} HOSTS</span>
          </div>
        </div>

        <div className="glass-panel border-purple-500/20 bg-purple-950/5 p-4 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-24 h-24 bg-purple-500/[0.02] rounded-full blur-xl group-hover:bg-purple-500/[0.05] transition-all" />
          <div className="flex justify-between items-start mb-2">
            <span className="text-[9px] text-zinc-500 uppercase font-black tracking-widest">FORECAST_RISK_INDEX</span>
            <TrendingUp size={14} className="text-purple-400 opacity-60" />
          </div>
          <p className="text-2xl font-black text-purple-400 tracking-tighter">{forecastScore}</p>
          <div className="text-[8px] text-purple-500/50 uppercase mt-1 flex justify-between">
            <span>PREDICTIVE_STAMP</span>
            <span>{aiGenerated ? "AI_CONFIRMED" : "HEURISTICS"}</span>
          </div>
        </div>
      </div>

      {/* CHARTS ROW 1: LINE ACTIVITY & CATEGORIES */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        
        {/* Weekly threat activity */}
        <div className="lg:col-span-2 glass-panel border-[#39FF14]/10 bg-black/60 p-4">
          <h3 className="text-[10px] text-[#39FF14] font-black uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
            <Activity size={12} className="text-cyan-400" /> WEEKLY_THREAT_ACTIVITY_MATRIX
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={240}>
              <AreaChart data={getWeeklyTrendData()} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorSafe" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#39FF14" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#39FF14" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                <XAxis dataKey="name" stroke="#52525b" tick={{ fontSize: 9 }} />
                <YAxis stroke="#52525b" tick={{ fontSize: 9 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#09090b', borderColor: '#3f3f46', fontSize: 11, fontFamily: 'monospace' }}
                  labelStyle={{ color: '#a1a1aa', fontWeight: 'bold' }}
                />
                <Area type="monotone" dataKey="Malicious" stroke="#ef4444" fillOpacity={1} fill="url(#colorMalicious)" strokeWidth={2} />
                <Area type="monotone" dataKey="Safe" stroke="#39FF14" fillOpacity={1} fill="url(#colorSafe)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Categories Pie */}
        <div className="glass-panel border-[#39FF14]/10 bg-black/60 p-4">
          <h3 className="text-[10px] text-[#39FF14] font-black uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
            <Shield size={12} className="text-[#39FF14]" /> THREAT_CATEGORIES_RATIO
          </h3>
          <div className="h-64 flex flex-col justify-between">
            <div className="h-44 relative">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={240}>
                <PieChart>
                  <Pie
                    data={getCategoryData()}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {getCategoryData().map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#09090b', borderColor: '#3f3f46', fontSize: 10, fontFamily: 'monospace' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-[8px] text-zinc-500 uppercase tracking-widest font-black">MAL_RATIO</span>
                <span className="text-lg font-black text-red-500">{metrics.phishingRatio}%</span>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-1 border-t border-zinc-800 pt-3">
              {getCategoryData().map((c) => (
                <div key={c.name} className="text-center font-mono">
                  <p className="text-[8px] text-zinc-500 uppercase tracking-wider">{c.name}</p>
                  <p className="text-[11px] font-black mt-0.5" style={{ color: c.color }}>{c.value}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* CHARTS ROW 2: RADAR RADIALS & BAR GRAPH */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        
        {/* Threat vectors radar */}
        <div className="glass-panel border-[#39FF14]/10 bg-black/60 p-4">
          <h3 className="text-[10px] text-[#39FF14] font-black uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
            <Globe size={12} className="text-purple-400" /> THREAT_VECTOR_COORDINATES
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={240}>
              <RadarChart cx="50%" cy="50%" outerRadius={80} data={getRadarData()}>
                <PolarGrid stroke="#27272a" />
                <PolarAngleAxis dataKey="subject" stroke="#71717a" tick={{ fontSize: 8 }} />
                <PolarRadiusAxis stroke="#27272a" tick={{ fontSize: 8 }} />
                <Radar name="Threat Scope" dataKey="A" stroke="#00F5FF" fill="#00F5FF" fillOpacity={0.15} />
                <Tooltip contentStyle={{ backgroundColor: '#09090b', borderColor: '#3f3f46', fontSize: 10, fontFamily: 'monospace' }} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Origins & domains */}
        <div className="glass-panel border-[#39FF14]/10 bg-black/60 p-4">
          <h3 className="text-[10px] text-[#39FF14] font-black uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
            <ShieldAlert size={12} className="text-red-500" /> ATTACK_ORIGINATIONS_BY_TLD
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={240}>
              <BarChart data={getOriginsData()} layout="vertical" margin={{ top: 5, right: 10, left: 10, bottom: 5 }}>
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" stroke="#52525b" tick={{ fontSize: 9 }} />
                <YAxis dataKey="country" type="category" stroke="#52525b" tick={{ fontSize: 8 }} width={120} />
                <Tooltip contentStyle={{ backgroundColor: '#09090b', borderColor: '#3f3f46', fontSize: 10, fontFamily: 'monospace' }} />
                <Bar dataKey="value" fill="#ef4444" radius={[0, 4, 4, 0]}>
                  {getOriginsData().map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={entry.country.includes('USA') ? '#39FF14' : entry.country.includes('GLOBAL') ? '#00F5FF' : '#ef4444'} 
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* HEATMAP GRID: WEEKLY SCANS INTENSITIES */}
      <div className="glass-panel border-[#39FF14]/10 bg-black/60 p-4">
        <h3 className="text-[10px] text-[#39FF14] font-black uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
          <Terminal size={12} className="text-yellow-500" /> ATTACK_DENSITY_HEATMAP (DAY vs HOUR)
        </h3>
        <div className="overflow-x-auto custom-scrollbar">
          <div className="min-w-[600px] space-y-1 pb-2">
            <div className="flex">
              <div className="w-12 text-[8px] text-zinc-500 font-bold uppercase" />
              {intervals.map((int) => (
                <div key={int} className="flex-1 text-center text-[8px] text-zinc-500 font-bold uppercase">{int}h</div>
              ))}
            </div>
            {days.map((day, dIdx) => (
              <div key={day} className="flex items-center">
                <div className="w-12 text-[9px] text-[#39FF14] font-bold uppercase">{day}</div>
                {intervals.map((int, iIdx) => {
                  // Simulate random activity weights based on metrics
                  const hashWeight = (dIdx * 3 + iIdx * 2) % 7;
                  const intensity = metrics.totalScans > 15 ? hashWeight : Math.max(0, hashWeight - 2);
                  let colorClass = "bg-zinc-900 border border-zinc-950";
                  if (intensity === 1 || intensity === 2) colorClass = "bg-emerald-950/40 border border-[#39FF14]/10";
                  if (intensity === 3 || intensity === 4) colorClass = "bg-emerald-900/60 border border-[#39FF14]/30";
                  if (intensity === 5) colorClass = "bg-[#39FF14]/20 border border-[#39FF14]";
                  if (intensity === 6) colorClass = "bg-red-950/40 border border-red-500/40";
                  return (
                    <div 
                      key={int} 
                      className={`flex-1 h-6 transition-all hover:scale-105 hover:shadow-[0_0_10px_rgba(57,255,20,0.2)] ${colorClass} mx-0.5`}
                      title={`Day: ${day}, Interval: ${int}h, Intensity: ${intensity}/6`}
                    />
                  );
                })}
              </div>
            ))}
          </div>
        </div>
        <div className="flex items-center justify-end gap-3 mt-3 text-[8px] text-zinc-500 font-bold uppercase">
          <span>CLEARED</span>
          <div className="w-3 h-3 bg-zinc-900 border border-zinc-950" />
          <div className="w-3 h-3 bg-emerald-950/40 border border-[#39FF14]/10" />
          <div className="w-3 h-3 bg-emerald-900/60 border border-[#39FF14]/30" />
          <div className="w-3 h-3 bg-[#39FF14]/20 border border-[#39FF14]" />
          <div className="w-3 h-3 bg-red-950/40 border border-red-500/40" />
          <span>CRITICAL_BURST</span>
        </div>
      </div>

      {/* LOWER GRID: AI PREDICTIVE INSIGHTS PANEL */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        
        {/* AI Insight report */}
        <div className="glass-panel border-purple-500/20 bg-black/60 p-5 space-y-4">
          <h3 className="text-[10px] text-purple-400 font-black uppercase tracking-[0.2em] flex items-center gap-2">
            <Sparkles size={12} className="text-purple-400 animate-pulse" /> AI_GENERATED_SOC_INSIGHTS
          </h3>
          <div className="space-y-4">
            <div className="space-y-2">
              <span className="text-[8px] text-zinc-500 uppercase tracking-widest font-black">AI_THREAT_ANALYSIS_SUMMARY</span>
              <ul className="space-y-2 text-[10px] text-purple-300 font-mono leading-relaxed bg-purple-950/5 border border-purple-500/10 p-3">
                {aiInsights.map((ins, i) => (
                  <li key={i} className="flex gap-2 items-start">
                    <span className="text-purple-500 font-bold">[{i + 1}]</span>
                    <span>{ins}</span>
                  </li>
                ))}
              </ul>
            </div>
            
            <div className="space-y-2">
              <span className="text-[8px] text-zinc-500 uppercase tracking-widest font-black">REMEDIAL_ACTION_PLAYBOOKS</span>
              <ul className="space-y-2 text-[10px] text-[#39FF14]/80 font-mono leading-relaxed bg-black/40 border border-[#39FF14]/10 p-3">
                {aiRecommendations.map((rec, i) => (
                  <li key={i} className="flex gap-2 items-start">
                    <span className="text-[#39FF14] font-bold">•</span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Prediction trend chart */}
        <div className="glass-panel border-purple-500/20 bg-black/60 p-5">
          <h3 className="text-[10px] text-purple-400 font-black uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
            <TrendingUp size={12} className="text-purple-400" /> FORECASTED_7D_ATTACK_WAVES
          </h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={240}>
              <LineChart data={getForecastChartData()} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                <XAxis dataKey="name" stroke="#52525b" tick={{ fontSize: 9 }} />
                <YAxis stroke="#52525b" tick={{ fontSize: 9 }} />
                <Tooltip contentStyle={{ backgroundColor: '#09090b', borderColor: '#3f3f46', fontSize: 10, fontFamily: 'monospace' }} />
                <Line type="monotone" dataKey="Predicted" stroke="#a855f7" strokeWidth={3} dot={{ fill: '#a855f7', strokeWidth: 2, r: 4 }} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="p-3 bg-purple-950/10 border border-purple-500/20 text-[9px] text-purple-300 leading-relaxed mt-4">
            <span className="font-bold text-purple-400">TREND_MODEL_FORECAST:</span> Current moving average modeling predicts a {forecastScore > 50 ? "rising trend" : "stable volume"} for inbound payloads over the next 7-day cycle. Security posture upgrades are {forecastScore > 65 ? "strongly recommended" : "optionally advised"}.
          </div>
        </div>
      </div>

      {/* HIDDEN PRINT VIEW LOGO */}
      <div className="hidden print:block text-center pt-8 border-t border-zinc-800 text-[10px] text-zinc-500 uppercase tracking-[0.2em]">
        Cyber Shield SOC Threat Telemetry Report — Confirmed on {new Date().toLocaleString()}
      </div>

    </div>
  );
}
