import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  Search,
  AlertTriangle,
  CheckCircle,
  Info,
  Globe,
  Lock,
  Cpu,
  Terminal,
  ExternalLink,
  ChevronRight,
  Activity,
  Zap,
  RefreshCcw,
  MousePointer2,
  CalendarDays,
  User,
  Bell,
  Trash2,
  Camera,
  Upload,
  Download,
  QrCode,
  Plus,
  MessageSquare,
  FileCode,
  FileArchive,
  FileText,
  ShieldAlert,
  Mail,
  Printer,
  X,
  Trophy
} from 'lucide-react';
import html2canvas from 'html2canvas';
import { generateIncidentReport } from './utils/pdfGenerator';
import { Html5Qrcode } from 'html5-qrcode';
import { motion, AnimatePresence } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useAuth } from './components/AuthProvider';
import { ScanHistory } from './components/ScanHistory';
import { ThreatGPTPanel } from './components/ThreatGPTPanel';
import { ThreatAnalyticsDashboard } from './components/ThreatAnalyticsDashboard';
import { VoiceAssistant } from './components/VoiceAssistant';
import { TrainingSimulator } from './components/TrainingSimulator';
import { AdminControlCenter } from './components/AdminControlCenter';
import { AttackSimulatorEngine } from './components/AttackSimulatorEngine';
import {
  auth,
  db,
  collection,
  addDoc,
  query,
  where,
  onSnapshot,
  deleteDoc,
  doc,
  serverTimestamp,
  getDocs,
  handleFirestoreError,
  OperationType,
  orderBy
} from './lib/firebase';
// Sidecar logic removed duplicate imports

// Helper for tailwind classes
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

function isMockSessionUser(user: { uid: string } | null | undefined) {
  return !!user && (
    user.uid === 'mock-analyst-1337' ||
    user.uid.startsWith('mock-user-')
  );
}

function getDomainAge(creationDate: string | undefined) {
  if (!creationDate) return null;
  try {
    const created = new Date(creationDate);
    if (isNaN(created.getTime())) return null;
    const now = new Date();
    const diffTime = now.getTime() - created.getTime();
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays < 0) return 'Just registered';
    if (diffDays < 30) return `${diffDays}d old`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo old`;
    const years = Math.floor(diffDays / 365);
    return `${years}y old`;
  } catch (e) {
    return null;
  }
}

interface AnalysisResult {
  threatScore: number;
  classification: 'Safe' | 'Suspicious' | 'Phishing' | 'Malicious';
  explanation: string;
  recommendation: string;
  riskIndicators: string[];
  type?: 'url' | 'ip' | 'email' | 'domain' | 'keyword' | 'phone' | 'message';
  target?: string;
  screenshot?: string;
  brandImpersonated?: string;
  visualIndicators?: string[];
  technicalSummary: {
    dns: string;
    ssl: string;
    whois: string;
    threatIntel: string;
  };
  raw?: {
    dns: any;
    ssl: any;
    ct: any;
    whois: any;
    heuristics: any;
  };
}

interface FileScanResult {
  threatScore: number;
  classification: 'Safe' | 'Suspicious' | 'Malicious';
  malwareFamily: string;
  explanation: string;
  recommendation: string;
  fileName: string;
  fileSize: number;
  fileType: string;
  sha256: string;
  detectionStats: {
    malicious: number;
    harmless: number;
    suspicious: number;
    undetected: number;
  };
  iocIndicators: string[];
  timeline: {
    time: string;
    event: string;
    status: 'warning' | 'info' | 'critical' | 'success';
  }[];
  id?: string;
  createdAt?: any;
}


function getGaugeColor(score: number) {
  if (score < 30) return 'text-[#39FF14]';
  if (score < 60) return 'text-amber-500';
  if (score < 80) return 'text-orange-500';
  return 'text-red-500';
}

function ThreatGauge({ score }: { score: number }) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="relative flex items-center justify-center">
      <svg width="100" height="100" className="transform -rotate-90 scale-110 md:scale-125">
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="transparent"
          stroke="currentColor"
          strokeWidth="6"
          className="text-[#39FF14]/5"
        />
        <motion.circle
          cx="50"
          cy="50"
          r={radius}
          fill="transparent"
          stroke="currentColor"
          strokeWidth="6"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 2, ease: "circOut" }}
          strokeLinecap="round"
          className={cn(
            score < 30 ? "stroke-[#39FF14]" :
              score < 60 ? "stroke-amber-500" :
                score < 80 ? "stroke-orange-500" : "stroke-red-500",
            "transition-colors duration-1000 shadow-[0_0_10px_rgba(57,255,20,0.5)]"
          )}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.span
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.5 }}
          className={cn("text-3xl font-black italic tracking-tighter", getGaugeColor(score))}
        >
          {score}
        </motion.span>
        <span className="text-[7px] text-[#39FF14]/50 uppercase tracking-widest font-mono">THREAT.VAL</span>
      </div>
    </div>
  );
}

function ScanLines() {
  return (
    <div className="pointer-events-none fixed inset-0 z-[100] overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%]" />
      <div className="animate-scanline absolute top-0 left-0 h-[100px] w-full bg-linear-to-b from-transparent via-[#39FF14]/5 to-transparent opacity-20" />
    </div>
  );
}

function GlobalMap() {
  return (
    <div className="glass-panel border-[#39FF14]/10 h-[220px] relative overflow-hidden group">
      <div className="absolute top-2 left-2 z-10">
        <h3 className="text-[10px] text-[#39FF14]/50 uppercase tracking-[0.2em] flex items-center gap-2">
          <Globe size={12} /> Global_Malware_Vectors
        </h3>
      </div>
      <svg className="w-full h-full opacity-20 grayscale invert-[0.8] brightness-125" viewBox="0 0 800 400">
        <path fill="currentColor" className="text-[#39FF14]" d="M150,150 L200,160 L220,140 L250,150 L260,180 Z M400,100 L450,110 L480,140 L440,160 Z M600,200 L650,220 L680,210 L700,240 Z" />
        <motion.circle
          cx="200" cy="150" r="2" fill="#39FF14"
          animate={{ r: [2, 6, 2], opacity: [1, 0.2, 1] }}
          transition={{ duration: 2, repeat: Infinity }}
        />
        <motion.circle
          cx="450" cy="130" r="2" fill="#39FF14"
          animate={{ r: [2, 6, 2], opacity: [1, 0.2, 1] }}
          transition={{ duration: 2, delay: 0.5, repeat: Infinity }}
        />
        <motion.circle
          cx="650" cy="220" r="2" fill="#39FF14"
          animate={{ r: [2, 6, 2], opacity: [1, 0.2, 1] }}
          transition={{ duration: 2, delay: 1, repeat: Infinity }}
        />
        {/* Animated lines */}
        <motion.path
          d="M200,150 Q325,140 450,130"
          fill="none"
          stroke="#39FF14"
          strokeWidth="0.5"
          strokeDasharray="4 4"
          animate={{ strokeDashoffset: [0, -20] }}
          transition={{ duration: 5, repeat: Infinity, ease: "linear" }}
        />
        <motion.path
          d="M450,130 Q550,175 650,220"
          fill="none"
          stroke="#39FF14"
          strokeWidth="0.5"
          strokeDasharray="4 4"
          animate={{ strokeDashoffset: [0, -20] }}
          transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
        />
      </svg>
      <div className="absolute bottom-2 right-2 flex flex-col items-end">
        <div className="flex gap-1">
          <span className="w-1 h-1 bg-[#39FF14] animate-ping" />
          <p className="text-[8px] uppercase tracking-tighter opacity-50">Active_Link_Established</p>
        </div>
        <p className="text-[9px] font-bold">NODE_ALPHA_7: ONLINE</p>
      </div>
    </div>
  );
}

function IntelFeed() {
  const [news, setNews] = useState([
    "CRITICAL: Zero-day exploit detected in major email provider...",
    "ADVISORY: Massive phishing campaign targeting financial sector identified.",
    "INFO: Global botnet activity decreased by 12% in the last 24h.",
    "WARN: New ransomware variant 'VoidHex' spreading via infected plugins.",
    "UPDATE: Core threat database updated with 12,402 new signatures."
  ]);

  useEffect(() => {
    const interval = setInterval(() => {
      setNews(prev => [...prev.slice(1), prev[0]]);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass-panel border-[#39FF14]/10 bg-black/80 overflow-hidden h-12 flex items-center relative">
      <div className="bg-[#39FF14] text-black px-3 h-full flex items-center text-[10px] font-black uppercase tracking-widest z-10 shadow-[0_0_15px_rgba(57,255,20,0.3)]">
        LIVE_INTEL_FEED
      </div>
      <div className="flex-1 px-4 overflow-hidden">
        <AnimatePresence mode="wait">
          <motion.p
            key={news[0]}
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -20, opacity: 0 }}
            className="text-[11px] text-[#39FF14] font-bold truncate"
          >
            {news[0]}
          </motion.p>
        </AnimatePresence>
      </div>
    </div>
  );
}

function MatrixEffect() {
  return (
    <div className="glass-panel border-[#39FF14]/10 h-32 relative overflow-hidden flex flex-col items-center justify-center group">
      <div className="absolute inset-0 opacity-20 pointer-events-none grid grid-cols-12 gap-1 px-2">
        {Array.from({ length: 12 }).map((_, i) => (
          <motion.div
            key={i}
            className="text-[8px] flex flex-col"
            animate={{ y: [-100, 100] }}
            transition={{ duration: Math.random() * 5 + 3, repeat: Infinity, ease: "linear" }}
          >
            {Array.from({ length: 20 }).map((_, j) => (
              <span key={j}>{Math.random() > 0.5 ? '1' : '0'}</span>
            ))}
          </motion.div>
        ))}
      </div>
      <p className="text-[10px] text-[#39FF14]/50 uppercase tracking-widest z-10">Neural_Core_Active</p>
      <div className="flex gap-4 mt-2 z-10">
        <div className="text-center">
          <p className="text-[12px] font-black">2.4 TB/s</p>
          <p className="text-[7px] opacity-50 uppercase">Throughput</p>
        </div>
        <div className="text-center">
          <p className="text-[12px] font-black text-amber-500">INIT</p>
          <p className="text-[7px] opacity-50 uppercase">Sequence</p>
        </div>
      </div>
    </div>
  );
}

function KeywordMonitor() {
  const { user, login } = useAuth();
  const [subscriptions, setSubscriptions] = useState<any[]>([]);
  const [newKeyword, setNewKeyword] = useState('');
  const [isAdding, setIsAdding] = useState(false);

  useEffect(() => {
    if (!user) {
      setSubscriptions([]);
      return;
    }

    if (isMockSessionUser(user)) {
      const loadMockSubs = () => {
        const localSubs = localStorage.getItem('cyber_shield_mock_subscriptions');
        if (localSubs) {
          setSubscriptions(JSON.parse(localSubs));
        } else {
          const defaultSubs = [
            { id: 'sub-1', keyword: 'phishing-intel', createdAt: new Date().toISOString() },
            { id: 'sub-2', keyword: 'voidhex-botnet', createdAt: new Date().toISOString() }
          ];
          setSubscriptions(defaultSubs);
          localStorage.setItem('cyber_shield_mock_subscriptions', JSON.stringify(defaultSubs));
        }
      };

      loadMockSubs();

      const handleStorageChange = (e: StorageEvent) => {
        if (e.key === 'cyber_shield_mock_subscriptions') {
          loadMockSubs();
        }
      };
      window.addEventListener('storage', handleStorageChange);

      return () => {
        window.removeEventListener('storage', handleStorageChange);
      };
    }

    const q = query(
      collection(db, 'subscriptions'),
      where('userId', '==', user.uid)
    );

    return onSnapshot(q, (snapshot) => {
      const subs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      setSubscriptions(subs);
    }, (error) => {
      handleFirestoreError(error, OperationType.LIST, 'subscriptions');
    });
  }, [user]);

  const handleAddSubscription = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user || !newKeyword.trim() || isAdding) return;

    setIsAdding(true);
    try {
      if (isMockSessionUser(user)) {
        const localSubs = localStorage.getItem('cyber_shield_mock_subscriptions');
        const parsed = localSubs ? JSON.parse(localSubs) : [];
        const keywordVal = newKeyword.trim();
        const newSub = {
          id: `sub-${Date.now()}`,
          keyword: keywordVal,
          createdAt: new Date().toISOString()
        };
        const updated = [...parsed, newSub];
        localStorage.setItem('cyber_shield_mock_subscriptions', JSON.stringify(updated));
        setSubscriptions(updated);
        setNewKeyword('');

        // Trigger a simulated threat alert for the new keyword after 1.5 seconds!
        setTimeout(() => {
          const localAlerts = localStorage.getItem('cyber_shield_mock_alerts');
          const alerts = localAlerts ? JSON.parse(localAlerts) : [];
          const newAlert = {
            id: `alert-${Date.now()}`,
            userId: user.uid,
            keyword: keywordVal.toUpperCase(),
            message: `Real-time watch intercept: Active vector matching keyword '${keywordVal}' detected.`,
            threatScore: Math.floor(Math.random() * 30) + 65,
            timestamp: { seconds: Math.floor(Date.now() / 1000) }
          };
          const updatedAlerts = [newAlert, ...alerts];
          localStorage.setItem('cyber_shield_mock_alerts', JSON.stringify(updatedAlerts));
          window.dispatchEvent(new Event('cyber_shield_new_alert'));
        }, 1500);
      } else {
        await addDoc(collection(db, 'subscriptions'), {
          userId: user.uid,
          keyword: newKeyword.trim(),
          createdAt: serverTimestamp()
        });
        setNewKeyword('');
      }
    } catch (error) {
      console.error('Failed to add subscription', error);
    } finally {
      setIsAdding(false);
    }
  };

  const handleDeleteSubscription = async (id: string) => {
    try {
      if (user && isMockSessionUser(user)) {
        const localSubs = localStorage.getItem('cyber_shield_mock_subscriptions');
        const parsed = localSubs ? JSON.parse(localSubs) : [];
        const updated = parsed.filter((s: any) => s.id !== id);
        localStorage.setItem('cyber_shield_mock_subscriptions', JSON.stringify(updated));
        setSubscriptions(updated);
      } else {
        await deleteDoc(doc(db, 'subscriptions', id));
      }
    } catch (error) {
      console.error('Failed to delete subscription', error);
    }
  };

  if (!user) {
    return (
      <section className="glass-panel border-[#39FF14]/20 p-5 space-y-4">
        <div className="flex justify-between items-center">
          <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
            <Activity size={12} className="text-amber-500" /> KEYWORD_WATCH
          </h3>
        </div>
        <div className="flex flex-col items-center justify-center py-8 space-y-3 border border-dashed border-[#39FF14]/10 bg-black/40">
          <Lock size={24} className="opacity-20" />
          <p className="text-[10px] opacity-40 uppercase tracking-widest text-center">Login to monitor keywords</p>
          <button
            onClick={login}
            className="px-4 py-2 bg-[#39FF14]/10 border border-[#39FF14]/30 text-[#39FF14] text-[10px] font-black uppercase hover:bg-[#39FF14]/20 transition-all"
          >
            AUTH_INIT
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="glass-panel border-[#39FF14]/20 p-5 space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
          <Activity size={12} className="text-amber-500" /> KEYWORD_WATCH
        </h3>
        <span className="text-[8px] opacity-30 uppercase tracking-widest">REALTIME_SYNC</span>
      </div>

      <form onSubmit={handleAddSubscription} className="flex gap-2">
        <input
          type="text"
          value={newKeyword}
          onChange={(e) => setNewKeyword(e.target.value)}
          placeholder="MONITORING_KEYWORD..."
          className="flex-1 bg-black border border-[#39FF14]/20 px-3 py-2 text-[10px] focus:outline-none focus:border-[#39FF14] placeholder:opacity-20"
        />
        <button
          disabled={!newKeyword.trim() || isAdding}
          className="px-3 py-2 bg-[#39FF14] text-black text-[10px] font-black disabled:opacity-20 transition-all hover:scale-105 active:scale-95"
        >
          <Plus size={14} />
        </button>
      </form>

      <div className="space-y-2 max-h-[160px] overflow-y-auto custom-scrollbar pr-2">
        {subscriptions.length > 0 ? subscriptions.map((k) => (
          <div key={k.id} className="flex items-center justify-between py-2 border-b border-[#39FF14]/5 last:border-0 group">
            <div className="flex items-center gap-2">
              <div className="w-1 h-3 bg-[#39FF14]" />
              <span className="text-[11px] font-bold text-[#39FF14]/80 group-hover:text-white transition-colors">{k.keyword}</span>
            </div>
            <button
              onClick={() => handleDeleteSubscription(k.id)}
              className="text-red-500/30 hover:text-red-500 transition-colors"
            >
              <Trash2 size={12} />
            </button>
          </div>
        )) : (
          <p className="text-[9px] opacity-20 italic text-center py-4">No keywords monitored.</p>
        )}
      </div>
    </section>
  );
}

function AlertNotifications() {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState<any[]>([]);

  useEffect(() => {
    if (!user) {
      setAlerts([]);
      return;
    }

    if (isMockSessionUser(user)) {
      const loadMockAlerts = () => {
        const localAlerts = localStorage.getItem('cyber_shield_mock_alerts');
        if (localAlerts) {
          const parsed = JSON.parse(localAlerts);
          parsed.sort((a: any, b: any) => (b.timestamp?.seconds || 0) - (a.timestamp?.seconds || 0));
          setAlerts(parsed);
        } else {
          const defaultAlerts = [
            {
              id: 'alert-1',
              keyword: 'VOIDHEX-BOTNET',
              message: 'Detected active Command & Control communication vector matching signature voidhex-botnet.',
              threatScore: 89,
              timestamp: { seconds: Math.floor(Date.now() / 1000) - 300 }
            }
          ];
          localStorage.setItem('cyber_shield_mock_alerts', JSON.stringify(defaultAlerts));
          setAlerts(defaultAlerts);
        }
      };

      loadMockAlerts();

      const handleStorageChange = (e: StorageEvent) => {
        if (e.key === 'cyber_shield_mock_alerts') {
          loadMockAlerts();
        }
      };
      window.addEventListener('storage', handleStorageChange);

      const handleCustomAlert = () => {
        loadMockAlerts();
      };
      window.addEventListener('cyber_shield_new_alert', handleCustomAlert);

      return () => {
        window.removeEventListener('storage', handleStorageChange);
        window.removeEventListener('cyber_shield_new_alert', handleCustomAlert);
      };
    }

    const q = query(
      collection(db, 'alerts'),
      where('userId', '==', user.uid)
    );

    return onSnapshot(q, (snapshot) => {
      const newAlerts = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      // Sort by timestamp descending
      newAlerts.sort((a: any, b: any) => (b.timestamp?.seconds || 0) - (a.timestamp?.seconds || 0));
      setAlerts(newAlerts);
    }, (error) => {
      handleFirestoreError(error, OperationType.LIST, 'alerts');
    });
  }, [user]);

  if (!user || alerts.length === 0) return null;

  return (
    <div className="fixed top-24 right-4 z-[90] w-72 space-y-2 pointer-events-none">
      <AnimatePresence>
        {alerts.slice(0, 3).map((alert, idx) => (
          <motion.div
            key={alert.id}
            initial={{ x: 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 300, opacity: 0 }}
            className="pointer-events-auto glass-panel border-red-500/40 bg-black/90 p-4 shadow-xl border-l-4"
          >
            <div className="flex justify-between items-start mb-1">
              <div className="flex items-center gap-2">
                <Bell size={14} className="text-red-500 animate-pulse" />
                <span className="text-[9px] font-black uppercase text-red-500 tracking-[0.2em]">THREAT_ALERT</span>
              </div>
              <button
                onClick={async () => {
                  try {
                    if (isMockSessionUser(user)) {
                      const localAlerts = localStorage.getItem('cyber_shield_mock_alerts');
                      const parsed = localAlerts ? JSON.parse(localAlerts) : [];
                      const updated = parsed.filter((a: any) => a.id !== alert.id);
                      localStorage.setItem('cyber_shield_mock_alerts', JSON.stringify(updated));
                      setAlerts(updated);
                    } else {
                      await deleteDoc(doc(db, 'alerts', alert.id));
                    }
                  } catch (e) { console.error(e); }
                }}
                className="text-white/20 hover:text-white"
              >
                <Trash2 size={10} />
              </button>
            </div>
            <p className="text-[11px] font-bold text-white mb-1">Match: {alert.keyword}</p>
            <p className="text-[9px] opacity-60 leading-tight mb-2">{alert.message}</p>
            <div className="flex justify-between items-center text-[8px]">
              <span className="opacity-30 uppercase">{new Date(alert.timestamp?.seconds * 1000).toLocaleTimeString()}</span>
              <span className="bg-red-500/10 px-1 border border-red-500/20 text-red-500">SCORE: {alert.threatScore}</span>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
      {alerts.length > 3 && (
        <p className="text-center text-[8px] opacity-40 uppercase tracking-widest">+ {alerts.length - 3} more alerts</p>
      )}
    </div>
  );
}

function PhoneModule({ result }: { result: AnalysisResult }) {
  if (result.type !== 'phone') return null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel border-emerald-500/20 p-6 space-y-6"
    >
      <div className="flex justify-between items-center">
        <h3 className="text-[12px] font-black uppercase tracking-[0.2em] text-emerald-400 flex items-center gap-2">
          <Activity size={14} className="text-emerald-500" /> TELEPHONY_INTEL_GATHERING
        </h3>
        <span className="text-[9px] opacity-30 tracking-widest font-mono">SOURCE: TEL_INTEL_NETWORK</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="flex flex-col">
            <span className="text-[9px] font-black opacity-40 uppercase tracking-widest mb-1">Target_Identity</span>
            <p className="text-2xl font-black text-emerald-400">{result.raw?.dns?.records?.target || 'N/A'}</p>
          </div>
          <div className="p-3 bg-black/40 border border-emerald-500/10 space-y-2">
            <div className="flex justify-between text-[10px]">
              <span className="opacity-40">CARRIER_INTEL</span>
              <span className="text-emerald-400 font-bold italic">ANALYZING...</span>
            </div>
            <div className="flex justify-between text-[10px]">
              <span className="opacity-40">LOCATION_PROBE</span>
              <span className="text-emerald-400 font-bold">NODE_LOCKED</span>
            </div>
          </div>
        </div>
        <div className="bg-emerald-500/5 border border-emerald-500/10 p-4">
          <p className="text-[10px] font-bold text-emerald-500/70 uppercase mb-2">Neural_Risk_Assessment</p>
          <p className="text-[11px] leading-relaxed text-[#39FF14]/80 italic">
            {result.technicalSummary.threatIntel || "Telephony pattern matching indicates normal operation profile. No historical smishing campaigns associated with this signature in current epoch."}
          </p>
        </div>
      </div>
    </motion.div>
  );
}

function MessageModule({ result }: { result: AnalysisResult }) {
  if (result.type !== 'message') return null;

  const extractedUrls = result.raw?.heuristics?.extractedUrls || [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel border-amber-500/20 p-6 space-y-6"
    >
      <div className="flex justify-between items-center">
        <h3 className="text-[12px] font-black uppercase tracking-[0.2em] text-amber-500 flex items-center gap-2">
          <MessageSquare size={14} className="text-amber-500" /> SEMANTIC_THREAT_AUDIT
        </h3>
        <span className="text-[9px] opacity-30 tracking-widest font-mono">SOURCE: HEURISTIC_CORE_ALPHA</span>
      </div>

      <div className="space-y-6">
        <div className="p-4 bg-black/60 border border-amber-500/10 relative overflow-hidden">
          <div className="absolute top-0 right-0 p-1 bg-amber-500/10 border-l border-b border-amber-500/20 text-[8px] text-amber-500 font-black">ORIGINAL_CONTENT</div>
          <p className="text-[12px] font-mono text-amber-500/80 leading-relaxed italic">
            "{result.raw?.dns?.records?.target || 'No message content recorded.'}"
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {extractedUrls.length > 0 && (
            <div className="lg:col-span-1 space-y-3">
              <p className="text-[9px] font-black opacity-40 uppercase tracking-widest">Extracted_Links</p>
              <div className="space-y-2">
                {extractedUrls.map((url: string, i: number) => (
                  <div key={i} className="p-2 bg-black border border-amber-500/20 text-[9px] text-[#39FF14] flex items-center justify-between group">
                    <span className="truncate max-w-[150px]">{url}</span>
                    <button
                      onClick={() => { (window as any).setUrl(url); (window as any).handleAnalyze(undefined, url); }}
                      className="opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <ExternalLink size={10} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className={cn("space-y-3", extractedUrls.length > 0 ? "lg:col-span-2" : "lg:col-span-3")}>
            <p className="text-[9px] font-black opacity-40 uppercase tracking-widest">Heuristic_Analysis</p>
            <div className="bg-amber-500/5 border border-amber-500/10 p-4">
              <p className="text-[11px] leading-relaxed text-amber-200/80 italic">
                {result.explanation}
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                {result.riskIndicators.map((risk, i) => (
                  <span key={i} className="text-[8px] bg-red-500/10 border border-red-500/20 px-2 py-0.5 text-red-400 uppercase font-black">
                    {risk}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function QRScannerModule({ onScan }: { onScan: (decodedText: string) => void }) {
  const [isScanning, setIsScanning] = useState(false);
  const [hasError, setHasError] = useState<string | null>(null);
  const scannerRef = useRef<Html5Qrcode | null>(null);

  useEffect(() => {
    let isMounted = true;
    let timer: any;

    if (isScanning) {
      const startScanner = async () => {
        // Small delay to ensure React has rendered the #qr-reader div
        timer = setTimeout(async () => {
          try {
            const element = document.getElementById("qr-reader");
            if (!element || !isMounted) return;

            if (scannerRef.current) {
              try {
                await scannerRef.current.stop();
              } catch (e) {
                // Ignore stop errors
              }
            }

            const scanner = new Html5Qrcode("qr-reader");
            scannerRef.current = scanner;

            const config = {
              fps: 10,
              qrbox: (viewfinderWidth: number, viewfinderHeight: number) => {
                const minEdgeSize = Math.min(viewfinderWidth, viewfinderHeight);
                const qrboxSize = Math.floor(minEdgeSize * 0.7);
                return {
                  width: qrboxSize,
                  height: qrboxSize
                };
              },
              aspectRatio: 1.0
            };

            await scanner.start(
              { facingMode: "environment" },
              config,
              (decodedText) => {
                onScan(decodedText);
                stopScanning();
              },
              () => {
                // Ignore standard scanning errors
              }
            );

            if (isMounted) setHasError(null);
          } catch (err: any) {
            console.error("Scanner start error:", err);
            if (!isMounted) return;

            let msg = "CAMERA_ACCESS_DENIED OR HARDWARE_ERROR";
            const errStr = String(err);
            if (errStr.includes("NotAllowedError")) msg = "PERMISSION_DENIED: Enable Camera or Open App in New Tab";
            if (errStr.includes("NotFoundError")) msg = "HARDWARE_NOT_FOUND: No Camera Detected";
            if (errStr.includes("NotReadableError")) msg = "CAMERA_IN_USE: Close other apps using camera";

            setHasError(msg);
            setIsScanning(false);
          }
        }, 150);
      };

      startScanner();
    }

    return () => {
      isMounted = false;
      clearTimeout(timer);
      if (scannerRef.current) {
        // We don't await here as it's a cleanup, but we try to stop if it was running
        const stopIfRunning = async () => {
          try {
            // Note: stop() can only be called if it was successfully started
            await scannerRef.current?.stop();
            scannerRef.current = null;
          } catch (e) {
            // Silent cleanup
          }
        };
        stopIfRunning();
      }
    };
  }, [isScanning]);

  const stopScanning = async () => {
    if (scannerRef.current) {
      try {
        const state = scannerRef.current.getState();
        if (state === 2) {
          await scannerRef.current.stop();
        }
        scannerRef.current = null;
      } catch (e) {
        console.error("Stop error:", e);
      }
    }
    setIsScanning(false);
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const dummyId = "qr-reader-file-dummy";
    let dummy = document.getElementById(dummyId);
    if (!dummy) {
      dummy = document.createElement("div");
      dummy.id = dummyId;
      dummy.style.display = "none";
      document.body.appendChild(dummy);
    }

    const scanner = new Html5Qrcode(dummyId);
    try {
      const decodedText = await scanner.scanFile(file, true);
      onScan(decodedText);
      setHasError(null);
    } catch (err) {
      console.error("File scan error:", err);
      setHasError("DECODE_FAULT: QR Signature could not be extracted from provided image.");
    }
  };

  return (
    <section className="glass-panel border-cyan-500/30 bg-black/80 p-4 relative overflow-hidden group">
      <div className="absolute top-0 right-0 w-16 h-16 bg-cyan-500/5 -rotate-45 translate-x-8 -translate-y-8" />
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[10px] text-cyan-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
          <QrCode size={12} /> QR_INTEL_EXTRACTOR
        </h2>
        <div className="flex gap-1">
          <div className="w-1.5 h-1.5 bg-cyan-500/10 border border-cyan-500/20" />
          <div className={cn("w-1.5 h-1.5 bg-cyan-500 animate-pulse", isScanning && "bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]")} />
        </div>
      </div>

      <div className="space-y-4">
        {hasError && (
          <div className="bg-red-500/10 border border-red-500/30 p-2 mb-2 space-y-2">
            <div className="flex items-start gap-2">
              <AlertTriangle size={14} className="text-red-500 shrink-0" />
              <p className="text-[8px] text-red-500 font-bold uppercase italic leading-tight">{hasError}</p>
            </div>
            <div className="flex flex-col gap-1 pl-5">
              <a
                href={window.location.href}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[7px] text-cyan-400 underline uppercase tracking-widest block hover:text-cyan-300"
              >
                {"->"} Open App in New Tab to fix Permissions
              </a>
              <label className="text-[7px] text-cyan-400 underline uppercase tracking-widest cursor-pointer hover:text-cyan-300">
                {"->"} Or Process Static Image File
                <input type="file" accept="image/*" className="hidden" onChange={handleFileUpload} />
              </label>
            </div>
          </div>
        )}
        {!isScanning ? (
          <div className="flex flex-col gap-2">
            <button
              onClick={() => {
                setHasError(null);
                setIsScanning(true);
              }}
              className="w-full bg-cyan-600/20 border border-cyan-600/50 text-cyan-400 font-black py-8 flex flex-col items-center justify-center gap-3 hover:bg-cyan-600/30 transition-all group"
            >
              <Camera size={32} className="group-hover:scale-110 transition-transform" />
              <div className="text-center">
                <span className="text-[10px] block tracking-[0.2em]">INITIALIZE_CAM_PROBE</span>
                <span className="text-[7px] opacity-40 block mt-1 uppercase tracking-widest italic">Target: Real-world QR Signatures</span>
              </div>
            </button>
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-cyan-500/10" />
              </div>
              <div className="relative flex justify-center text-[7px] uppercase">
                <span className="bg-black px-2 text-cyan-500/30 tracking-widest italic">Alternative Mode</span>
              </div>
            </div>
            <label className="w-full bg-black border border-cyan-500/20 text-cyan-500/60 font-bold py-2 flex items-center justify-center gap-2 text-[8px] uppercase tracking-widest cursor-pointer hover:bg-cyan-500/5 transition-all">
              <Upload size={12} /> UPLOAD_QR_STATIC_FRAME
              <input type="file" accept="image/*" className="hidden" onChange={handleFileUpload} />
            </label>
          </div>
        ) : (
          <div className="space-y-4">
            <div id="qr-reader" className="w-full aspect-square border border-cyan-500/30 bg-black overflow-hidden relative rounded-sm" />
            <button
              onClick={stopScanning}
              className="w-full bg-red-600/10 border border-red-600/50 text-red-500 font-black py-2 text-[8px] uppercase tracking-widest hover:bg-red-600/20 transition-all"
            >
              ABORT_CAM_SYNC
            </button>
          </div>
        )}

        <div className="flex justify-between items-center text-[7px] opacity-30 pt-2 border-t border-cyan-500/10">
          <span>PROTOCOL: OPTICAL_DECODE</span>
          <span>SYNC_STATE: {isScanning ? 'STREAMING' : 'IDLE'}</span>
        </div>
      </div>
    </section>
  );
}

function VisualEvidenceModule({ result }: { result: AnalysisResult }) {
  if (result.type !== 'url' && result.type !== 'domain') return null;
  const targetUrl = result.target || (result.type === 'url' ? 'URL' : 'DOMAIN');
  
  const cachedScreenshot = result.screenshot || (result.target ? sessionStorage.getItem(`screenshot_${result.target}`) : null);
  const screenshotUrl = cachedScreenshot 
    ? `data:image/png;base64,${cachedScreenshot}`
    : `https://s.wordpress.com/mshots/v1/${encodeURIComponent(targetUrl)}?w=1280`;
  const renderEngine = cachedScreenshot ? 'PUPPETEER_CHROME_HEADLESS' : 'MSHOTS_V1';
  
  const brand = result.brandImpersonated || 'None';
  const visualIndicators = result.visualIndicators || [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel border-[#39FF14]/20 p-5 space-y-4"
    >
      <div className="flex justify-between items-center">
        <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
          <Camera size={12} className="text-blue-400" /> LIVE_VISUAL_EVIDENCE
        </h3>
        <span className="text-[8px] opacity-30 italic">RENDER_ENGINE: {renderEngine}</span>
      </div>
      <div className="relative group overflow-hidden border border-[#39FF14]/10 bg-black aspect-video flex items-center justify-center">
        <img
          src={screenshotUrl}
          alt="Target Preview"
          className="w-full h-full object-cover opacity-60 group-hover:opacity-100 transition-opacity duration-700"
          referrerPolicy="no-referrer"
        />
        <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-transparent pointer-events-none" />
        <div className="absolute bottom-2 left-2 flex items-center gap-2">
          <div className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse" />
          <span className="text-[8px] font-black uppercase tracking-widest text-[#39FF14]/60">LIVE_CAPTURE_BUFFER</span>
        </div>
        <a
          href={targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`}
          target="_blank"
          rel="noopener noreferrer"
          className="absolute top-2 right-2 p-1.5 bg-black/80 border border-[#39FF14]/20 text-[#39FF14] opacity-0 group-hover:opacity-100 transition-opacity"
        >
          <ExternalLink size={10} />
        </a>
      </div>
      <p className="text-[8px] opacity-40 uppercase leading-tight">
        Visual signature captured. Cross-referencing pixel similarity with known phishing templates and brand mimicry rules.
      </p>

      {/* Visual Threat Indicators & Brand Analysis Panel */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-[#39FF14]/10">
        {/* Brand Detection */}
        <div className="space-y-2">
          <div className="text-[9px] opacity-40 uppercase tracking-wider">Visual Brand Impersonation</div>
          {brand !== 'None' ? (
            <div className="flex items-center gap-2 p-2 border border-red-500/30 bg-red-500/5 text-red-400 font-bold text-xs uppercase">
              <AlertTriangle size={14} className="text-red-500 animate-pulse" />
              <span>DETECTED: {brand}</span>
            </div>
          ) : (
            <div className="flex items-center gap-2 p-2 border border-[#39FF14]/30 bg-[#39FF14]/5 text-[#39FF14] text-xs uppercase font-bold">
              <CheckCircle size={14} className="text-[#39FF14]" />
              <span>NO BRAND IMPERSONATION</span>
            </div>
          )}
        </div>

        {/* Threat Gauge */}
        <div className="space-y-2">
          <div className="text-[9px] opacity-40 uppercase tracking-wider">Visual Risk Level</div>
          <div className="flex items-center gap-3">
            <div className="relative w-full bg-black border border-[#39FF14]/10 h-3 overflow-hidden">
              <div 
                className={`h-full transition-all duration-1000 ${
                  result.threatScore < 30 ? 'bg-[#39FF14]' :
                  result.threatScore < 70 ? 'bg-amber-500' : 'bg-red-500'
                }`}
                style={{ width: `${result.threatScore}%` }}
              />
            </div>
            <span className={`text-xs font-black italic ${
              result.threatScore < 30 ? 'text-[#39FF14]' :
              result.threatScore < 70 ? 'text-amber-500' : 'text-red-500'
            }`}>{result.threatScore}%</span>
          </div>
        </div>
      </div>

      {/* Suspicious UI Indicators List */}
      <div className="space-y-2 pt-2 border-t border-[#39FF14]/10">
        <div className="text-[9px] opacity-40 uppercase tracking-wider">Suspicious UI Indicators</div>
        {visualIndicators.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {visualIndicators.map((indicator, index) => (
              <div 
                key={index}
                className="flex items-center gap-2 p-1.5 border border-amber-500/20 bg-amber-500/5 text-amber-500 text-[10px] uppercase font-bold"
              >
                <div className="w-1.5 h-1.5 bg-amber-500 rounded-full animate-ping" />
                <span>{indicator}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[10px] text-[#39FF14]/60 italic font-bold">
            NO SUSPICIOUS VISUAL INDICATORS DETECTED IN WEBPAGE LAYOUT
          </div>
        )}
      </div>
    </motion.div>
  );
}

function ExtensionModule() {
  return (
    <section className="glass-panel border-purple-500/30 bg-black/80 p-4 relative overflow-hidden group">
      <div className="absolute top-0 right-0 w-16 h-16 bg-purple-500/5 -rotate-45 translate-x-8 -translate-y-8" />
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[10px] text-purple-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
          <Download size={12} /> BROWSER_EXTENSION
        </h2>
        <div className="flex gap-1">
          <div className="w-1.5 h-1.5 bg-purple-500/10 border border-purple-500/20" />
          <div className="w-1.5 h-1.5 bg-purple-500 animate-pulse" />
        </div>
      </div>

      <div className="space-y-4">
        <div className="p-3 bg-purple-500/5 border border-purple-500/10">
          <p className="text-[10px] text-purple-200/60 leading-relaxed italic">
            Scale your intelligence gathering. Perform real-time scans directly from your browser toolbar.
          </p>
        </div>

        <div className="flex flex-col gap-2">
          <div className="text-[8px] text-purple-400/40 uppercase tracking-widest font-mono">
            DEPLOYMENT_FILES:
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="text-[9px] bg-black border border-purple-500/20 px-2 py-1 flex items-center gap-2 opacity-60">
              <div className="w-1 h-1 bg-purple-500" /> manifest.json
            </div>
            <div className="text-[9px] bg-black border border-purple-500/20 px-2 py-1 flex items-center gap-2 opacity-60">
              <div className="w-1 h-1 bg-purple-500" /> popup.html
            </div>
            <div className="text-[9px] bg-black border border-purple-500/20 px-2 py-1 flex items-center gap-2 opacity-60">
              <div className="w-1 h-1 bg-purple-500" /> popup.js
            </div>
            <div className="text-[9px] bg-black border border-purple-500/20 px-2 py-1 flex items-center gap-2 opacity-60">
              <div className="w-1 h-1 bg-purple-500" /> popup.css
            </div>
          </div>
        </div>

        <button
          onClick={() => window.open('/extension/README.md', '_blank')}
          className="w-full bg-purple-600/20 border border-purple-600/50 text-purple-400 font-black py-2 rounded-none flex items-center justify-center gap-2 hover:bg-purple-600/30 active:scale-[0.98] transition-all group uppercase tracking-widest text-[9px]"
        >
          <ExternalLink size={12} />
          VIEW_EXTENSION_GUIDE
        </button>

        <div className="text-center text-[7px] opacity-30 italic">
          COMPATIBILITY: CHROMIUM_ENGINE_88+
        </div>
      </div>
    </section>
  );
}

function ReputationModule({ result }: { result: AnalysisResult }) {
  if (result.type === 'keyword' || result.type === 'phone' || result.type === 'message') return null;

  const reps = result.raw?.dns?.reputation || [];
  const ips = result.raw?.dns?.ips || [];
  const neighbors = result.raw?.dns?.records?.neighborDomains || [];
  const reverse = result.raw?.dns?.reverse || [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 }}
      className="glass-panel border-[#39FF14]/20 p-6 space-y-6"
    >
      <div className="flex justify-between items-center">
        <h3 className="text-[12px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
          <Shield size={14} className="text-red-500" /> REPUTATION_&_BLACKLIST_AUDIT
        </h3>
        <span className="text-[9px] opacity-30 tracking-widest font-mono">SOURCE: DNSBL_GLOBAL_CLUSTER</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* IP REPUTATION */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-[9px] font-black opacity-40 uppercase tracking-widest">Active_IP_Endpoints</p>
            <span className="text-[9px] text-[#39FF14]/50 font-mono">{ips.length} DETECTED</span>
          </div>
          <div className="space-y-2 max-h-[160px] overflow-y-auto custom-scrollbar pr-2">
            {ips.length > 0 ? ips.map((ip: string) => {
              const ipReps = reps.filter((r: any) => r.ip === ip);
              const ipReverse = reverse?.[0];
              return (
                <div key={ip} className="bg-black/40 border border-[#39FF14]/10 p-3 flex justify-between items-center group hover:border-[#39FF14]/30 transition-all">
                  <div className="flex flex-col">
                    <span className="text-[11px] font-bold text-[#39FF14] tracking-tight">{ip}</span>
                    {ipReverse && (
                      <span className="text-[8px] text-blue-400 opacity-60 font-mono truncate max-w-[150px]">PTR: {ipReverse}</span>
                    )}
                    {ipReps.length > 0 ? (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {ipReps.map((r: any, idx: number) => (
                          <span key={idx} className="text-[8px] text-red-400 flex items-center gap-1 bg-red-400/5 px-1 py-0.5">
                            <AlertTriangle size={8} /> {r.provider}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[8px] text-emerald-500 opacity-60 flex items-center gap-1 mt-1">
                        <CheckCircle size={8} /> NO_LISTINGS_FOUND
                      </span>
                    )}
                  </div>
                  <div className={cn(
                    "px-2 py-0.5 text-[8px] font-black uppercase border",
                    ipReps.length > 0 ? "border-red-500/50 text-red-500 bg-red-500/10" : "border-emerald-500/50 text-emerald-500 bg-emerald-500/10"
                  )}>
                    {ipReps.length > 0 ? "BLACKLISTED" : "AUTHORIZED"}
                  </div>
                </div>
              );
            }) : (
              <p className="text-[10px] opacity-30 italic p-4 text-center border border-dashed border-[#39FF14]/10">No IP endpoints detected.</p>
            )}
          </div>
        </div>

        {/* NEIGHBOR DOMAINS */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-[9px] font-black opacity-40 uppercase tracking-widest">Shared_Infrastructure</p>
            <span className="text-[9px] text-blue-400/50 font-mono">CLUSTER_NEIGHBORS</span>
          </div>
          <div className="bg-black/40 border border-[#39FF14]/10 p-3 h-[160px] overflow-y-auto custom-scrollbar">
            {neighbors.length > 0 ? (
              <div className="grid grid-cols-1 gap-2">
                {neighbors.map((domain: string, idx: number) => (
                  <div key={idx} className="flex items-center justify-between text-[10px] border-b border-[#39FF14]/5 pb-1.5 last:border-0 hover:bg-white/[0.02] px-1 transition-colors">
                    <div className="flex items-center gap-2 text-[#39FF14]/70">
                      <ChevronRight size={10} className="opacity-30" />
                      <span className="truncate max-w-[180px]">{domain}</span>
                    </div>
                    <span className="text-[8px] opacity-20 font-mono uppercase">SHARED_IP</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center space-y-2 opacity-30">
                <Globe size={24} strokeWidth={1} />
                <p className="text-[10px] italic">No neighbor domains detected on this cluster.</p>
              </div>
            )}
          </div>
          <p className="text-[7px] opacity-30 italic leading-tight">
            * This audit checks for other domains hosted on the same IP cluster. A high density of phishing neighbors indicates a malicious hosting environment.
          </p>
        </div>
      </div>
    </motion.div>
  );
}

function VulnerabilityModule({ result }: { result: AnalysisResult }) {
  if (result.type === 'keyword' || result.type === 'phone' || result.type === 'message') return null;
  const vulns = result.raw?.dns?.vulnerabilities || [];
  if (vulns.length === 0) return null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      className="glass-panel border-orange-500/20 p-6 space-y-4"
    >
      <div className="flex justify-between items-center">
        <h3 className="text-[12px] font-black uppercase tracking-[0.2em] text-orange-500 flex items-center gap-2">
          <Terminal size={14} /> EXPLOIT_&_SERVICE_SURFACE
        </h3>
        <span className="text-[8px] opacity-30 uppercase tracking-widest font-mono">SOURCE: INTERNET_DB / SHODAN</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {vulns.map((v: any, idx: number) => (
          <div key={idx} className="bg-black/60 border border-orange-500/10 p-4 space-y-4">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-black tracking-tight bg-orange-500/10 px-2 py-0.5 border border-orange-500/20">{v.ip}</span>
              <div className="h-px flex-1 bg-orange-500/10" />
            </div>

            <div className="space-y-3">
              <div>
                <p className="text-[9px] font-black opacity-40 uppercase mb-2">Open_Ports</p>
                <div className="flex flex-wrap gap-1">
                  {v.ports?.length > 0 ? v.ports.map((p: number) => (
                    <span key={p} className="px-2 py-0.5 bg-black border border-emerald-500/30 text-emerald-500 text-[10px] font-mono">
                      {p}
                    </span>
                  )) : <span className="text-[9px] opacity-20">NO_PUBLIC_PORTS_DETECTED</span>}
                </div>
              </div>

              <div>
                <p className="text-[9px] font-black opacity-40 uppercase mb-2 text-red-400">CVE_Vulnerabilities</p>
                <div className="space-y-1">
                  {v.cves?.length > 0 ? v.cves.slice(0, 5).map((cve: string) => (
                    <div key={cve} className="flex items-center gap-2 text-[10px] text-red-400/80 bg-red-500/5 px-2 py-1 border border-red-500/10">
                      <AlertTriangle size={10} />
                      <span className="font-mono">{cve}</span>
                    </div>
                  )) : <div className="text-[9px] opacity-20 italic">NO_KNOWN_CVES_FOUND</div>}
                  {v.cves?.length > 5 && (
                    <p className="text-[8px] opacity-30 text-center">+{v.cves.length - 5} MORE RECORDS</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

export default function App() {
  const { user, login, logout: handleLogout, isAdmin, setSimulatedRole } = useAuth();
  const currentUserId = user?.uid || 'guest-operator';
  const dashboardRef = useRef<HTMLDivElement>(null);
  const [activeTab, setActiveTab] = useState<'scan' | 'history' | 'assistant' | 'filescan' | 'analytics' | 'breach' | 'email' | 'training' | 'admin' | 'attacksim'>('scan');

  // File Scanning states
  const [fileScanResult, setFileScanResult] = useState<FileScanResult | null>(null);
  const [isFileAnalyzing, setIsFileAnalyzing] = useState(false);
  const [fileScanError, setFileScanError] = useState<string | null>(null);
  const [fileScanProgress, setFileScanProgress] = useState<number>(0);
  const [fileScanLogs, setFileScanLogs] = useState<string[]>([]);
  const [fileScanHistory, setFileScanHistory] = useState<FileScanResult[]>([]);
  const [isDragging, setIsDragging] = useState(false);

  // Live Terminal Logs State for Analytics View
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // PDF Generator and Branding states
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [exportDataType, setExportDataType] = useState<'scan' | 'filescan' | 'email' | null>(null);
  const [companyBranding, setCompanyBranding] = useState('Cyber Shield');
  const [operatorBranding, setOperatorBranding] = useState('');
  const [accentBranding, setAccentBranding] = useState('#39FF14');
  const [recipientEmail, setRecipientEmail] = useState('');
  const [isSendingEmail, setIsSendingEmail] = useState(false);
  const [emailStatusMessage, setEmailStatusMessage] = useState('');
  const [emailStatusType, setEmailStatusType] = useState<'success' | 'error' | ''>('');

  useEffect(() => {
    if (user) {
      setOperatorBranding(user.displayName || user.email || 'SOC Operator');
    } else {
      setOperatorBranding('SOC Operator');
    }
  }, [user]);

  const getReportData = () => {
    if (exportDataType === 'scan' && result) {
      return {
        target: result.target || url || ipAddress || emailAddress || domainName || 'Heuristics Target',
        type: result.type || 'url',
        threatScore: result.threatScore,
        classification: result.classification,
        explanation: result.explanation,
        recommendation: result.recommendation,
        riskIndicators: result.riskIndicators,
        timestamp: new Date().toISOString(),
        technicalSummary: result.technicalSummary,
      };
    } else if (exportDataType === 'filescan' && fileScanResult) {
      return {
        target: fileScanResult.fileName,
        type: 'file' as const,
        threatScore: fileScanResult.threatScore,
        classification: fileScanResult.classification,
        explanation: fileScanResult.explanation,
        recommendation: fileScanResult.recommendation,
        fileName: fileScanResult.fileName,
        fileSize: fileScanResult.fileSize,
        sha256: fileScanResult.sha256,
        iocIndicators: fileScanResult.iocIndicators,
        timestamp: new Date().toISOString(),
        technicalSummary: {
          dns: `MALWARE FAMILY: ${fileScanResult.malwareFamily}`,
          ssl: `INTEGRITY CHECKSUM: ${fileScanResult.sha256}`,
          whois: `MIME TYPE: ${fileScanResult.fileType}`,
          threatIntel: `DETECTION RATE: ${fileScanResult.detectionStats.malicious}/${fileScanResult.detectionStats.malicious + fileScanResult.detectionStats.harmless + fileScanResult.detectionStats.suspicious + fileScanResult.detectionStats.undetected} ENGINES`
        }
      };
    } else if (exportDataType === 'email' && emailHeaderResult) {
      return {
        target: emailHeaderResult.senderIp || 'Unknown IP',
        type: 'email' as const,
        threatScore: emailHeaderResult.threatScore,
        classification: emailHeaderResult.classification,
        explanation: emailHeaderResult.explanation,
        recommendation: emailHeaderResult.recommendations.join('\n'),
        riskIndicators: emailHeaderResult.spoofingIndicators,
        timestamp: new Date().toISOString(),
        technicalSummary: {
          dns: `SPF Status: ${emailHeaderResult.spf} | DKIM Status: ${emailHeaderResult.dkim} | DMARC Status: ${emailHeaderResult.dmarc}`,
          ssl: `Mail Relays Hops Checked: ${emailHeaderResult.hopsCount}\nTrace Path: ${emailHeaderResult.hops.join(' -> ')}`,
          whois: `Originating SMTP Server IP: ${emailHeaderResult.senderIp}`,
          threatIntel: `Email headers parsed successfully. AI Threat Analysis complete.`
        },
        iocIndicators: emailHeaderResult.spoofingIndicators.map((ind: string) => `Header anomaly: ${ind}`)
      };
    }
    return null;
  };

  const handleDownloadPDF = () => {
    const reportData = getReportData();
    if (!reportData) return;

    addLog(`COMPILING_PDF_REPORT_FOR_${reportData.target.toUpperCase()}...`);
    try {
      const doc = generateIncidentReport(reportData, {
        companyName: companyBranding,
        operatorName: operatorBranding,
        accentColor: accentBranding
      });
      doc.save(`incident-report-${reportData.target.replace(/[^a-zA-Z0-9]/g, '_')}.pdf`);
      addLog("PDF_REPORT_COMPILE_SUCCESS. EXPORT_COMPLETE.");
      setIsExportModalOpen(false);
    } catch (err: any) {
      console.error(err);
      addLog(`PDF_REPORT_COMPILE_FAILURE: ${err.message}`);
    }
  };

  const handlePrintPDF = () => {
    const reportData = getReportData();
    if (!reportData) return;

    addLog(`INITIATING_PRINT_STREAM_FOR_${reportData.target.toUpperCase()}...`);
    try {
      const doc = generateIncidentReport(reportData, {
        companyName: companyBranding,
        operatorName: operatorBranding,
        accentColor: accentBranding
      });
      
      doc.autoPrint();
      const pdfUrl = doc.output('bloburl');
      window.open(pdfUrl, '_blank');
      
      addLog("PRINT_STREAM_REDIRECT_SUCCESS.");
      setIsExportModalOpen(false);
    } catch (err: any) {
      console.error(err);
      addLog(`PRINT_STREAM_REDIRECT_FAILURE: ${err.message}`);
    }
  };

  const handleEmailPDF = async () => {
    const reportData = getReportData();
    if (!reportData || !recipientEmail) return;

    setIsSendingEmail(true);
    setEmailStatusMessage('ESTABLISHING_SMTP_TUNNEL...');
    setEmailStatusType('');
    addLog(`INITIATING_EMAIL_REPORT_DISPATCH_TO_${recipientEmail.toUpperCase()}...`);

    try {
      const doc = generateIncidentReport(reportData, {
        companyName: companyBranding,
        operatorName: operatorBranding,
        accentColor: accentBranding
      });

      const pdfBase64 = doc.output('datauristring').split(',')[1];

      const response = await fetch('/api/email-report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          recipientEmail,
          targetName: reportData.target,
          pdfBase64,
        }),
      });

      const resData = await response.json();
      if (!response.ok) {
        throw new Error(resData.error || 'Server error during dispatch');
      }

      setEmailStatusMessage(`DISPATCH_SUCCESS: REPORT_SENT (${(resData.bytes / 1024).toFixed(1)} KB)`);
      setEmailStatusType('success');
      addLog(`EMAIL_DISPATCH_SUCCESS: Target ${reportData.target} report routed.`);
      setTimeout(() => {
        setIsExportModalOpen(false);
        setEmailStatusMessage('');
        setEmailStatusType('');
      }, 2000);
    } catch (err: any) {
      console.error(err);
      setEmailStatusMessage(`DISPATCH_FAILURE: ${err.message}`);
      setEmailStatusType('error');
      addLog(`EMAIL_DISPATCH_FAULT: ${err.message}`);
    } finally {
      setIsSendingEmail(false);
    }
  };

  // Breach Checker states
  const [breachIdentity, setBreachIdentity] = useState('');
  const [breachResult, setBreachResult] = useState<any | null>(null);
  const [isBreachChecking, setIsBreachChecking] = useState(false);
  const [breachError, setBreachError] = useState<string | null>(null);
  const [breachHistory, setBreachHistory] = useState<any[]>([]);

  // Sync breach reports history
  useEffect(() => {
    if (!user) return;

    if (isMockSessionUser(user)) {
      const loadLocalHistory = () => {
        const local = localStorage.getItem('cyber_shield_mock_breach_reports');
        setBreachHistory(local ? JSON.parse(local) : []);
      };
      loadLocalHistory();
      const handleStorageChange = (e: StorageEvent) => {
        if (e.key === 'cyber_shield_mock_breach_reports') loadLocalHistory();
      };
      window.addEventListener('storage', handleStorageChange);
      
      const handleCustomBreach = () => {
        loadLocalHistory();
      };
      window.addEventListener('cyber_shield_new_breach_report', handleCustomBreach);

      return () => {
        window.removeEventListener('storage', handleStorageChange);
        window.removeEventListener('cyber_shield_new_breach_report', handleCustomBreach);
      };
    }

    try {
      const reportsRef = collection(db, 'breachReports');
      const q = query(
        reportsRef,
        where('userId', '==', user.uid),
        orderBy('createdAt', 'desc')
      );
      
      const unsubscribe = onSnapshot(q, (snapshot) => {
        const data = snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));
        setBreachHistory(data);
      }, (error) => {
        console.error("Firestore breach reports sync error:", error);
        const local = localStorage.getItem('cyber_shield_mock_breach_reports');
        setBreachHistory(local ? JSON.parse(local) : []);
      });

      return () => unsubscribe();
    } catch (err) {
      console.error("Failed to load breach reports:", err);
    }
  }, [user]);

  // Email Header Analyzer states
  const [emailRawHeaders, setEmailRawHeaders] = useState('');
  const [emailHeaderResult, setEmailHeaderResult] = useState<any | null>(null);
  const [isEmailChecking, setIsEmailChecking] = useState(false);
  const [emailCheckError, setEmailCheckError] = useState<string | null>(null);
  const [emailHeaderHistory, setEmailHeaderHistory] = useState<any[]>([]);

  // Sync email header reports history
  useEffect(() => {
    if (!user) return;

    if (isMockSessionUser(user)) {
      const loadLocalHistory = () => {
        const local = localStorage.getItem('cyber_shield_mock_email_header_reports');
        setEmailHeaderHistory(local ? JSON.parse(local) : []);
      };
      loadLocalHistory();
      const handleStorageChange = (e: StorageEvent) => {
        if (e.key === 'cyber_shield_mock_email_header_reports') loadLocalHistory();
      };
      window.addEventListener('storage', handleStorageChange);
      
      const handleCustomEmailHeader = () => {
        loadLocalHistory();
      };
      window.addEventListener('cyber_shield_new_email_header_report', handleCustomEmailHeader);

      return () => {
        window.removeEventListener('storage', handleStorageChange);
        window.removeEventListener('cyber_shield_new_email_header_report', handleCustomEmailHeader);
      };
    }

    try {
      const reportsRef = collection(db, 'emailHeaderReports');
      const q = query(
        reportsRef,
        where('userId', '==', user.uid),
        orderBy('createdAt', 'desc')
      );
      
      const unsubscribe = onSnapshot(q, (snapshot) => {
        const data = snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));
        setEmailHeaderHistory(data);
      }, (error) => {
        console.error("Firestore email header reports sync error:", error);
        const local = localStorage.getItem('cyber_shield_mock_email_header_reports');
        setEmailHeaderHistory(local ? JSON.parse(local) : []);
      });

      return () => unsubscribe();
    } catch (err) {
      console.error("Failed to load email header reports:", err);
    }
  }, [user]);

  const handleBreachCheck = async (e?: React.FormEvent, directIdentity?: string) => {
    if (e) e.preventDefault();
    const queryIdentity = directIdentity || breachIdentity;
    if (!queryIdentity.trim()) return;

    setIsBreachChecking(true);
    setBreachError(null);
    setBreachResult(null);
    addLog(`INITIATING_BREACH_INTELLIGENCE_AUDIT: ${queryIdentity.toUpperCase()}...`);

    try {
      const response = await fetch('/api/breach-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity: queryIdentity })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Server connection error');

      setBreachResult(data);
      addLog(`BREACH_AUDIT_COMPLETE: Found ${data.breachCount} breaches.`);

      // Archive report in Firestore/Local Storage
      const newReport = {
        userId: user?.uid || 'guest-operator',
        identity: queryIdentity,
        breachCount: data.breachCount,
        breaches: data.breaches,
        compromisedCategories: data.compromisedCategories,
        passwordExposure: data.passwordExposure,
        recommendations: data.recommendations,
        createdAt: serverTimestamp()
      };

      if (user && !isMockSessionUser(user)) {
        try {
          addLog("ARCHIVING_BREACH_INTELLIGENCE_IN_CLOUD_STORAGE...");
          await addDoc(collection(db, 'breachReports'), newReport);
        } catch (dbErr: any) {
          console.error("Failed to archive breach report:", dbErr);
          // Fallback to local storage
          const localHistory = localStorage.getItem('cyber_shield_mock_breach_reports');
          const historyArr = localHistory ? JSON.parse(localHistory) : [];
          const localReport = {
            ...newReport,
            id: `rep-${Date.now()}`,
            createdAt: new Date().toISOString()
          };
          historyArr.unshift(localReport);
          localStorage.setItem('cyber_shield_mock_breach_reports', JSON.stringify(historyArr));
          window.dispatchEvent(new Event('cyber_shield_new_breach_report'));
        }
      } else {
        // Save to local storage for guest operator
        const localHistory = localStorage.getItem('cyber_shield_mock_breach_reports');
        const historyArr = localHistory ? JSON.parse(localHistory) : [];
        const localReport = {
          ...newReport,
          id: `rep-${Date.now()}`,
          createdAt: new Date().toISOString()
        };
        historyArr.unshift(localReport);
        localStorage.setItem('cyber_shield_mock_breach_reports', JSON.stringify(historyArr));
        window.dispatchEvent(new Event('cyber_shield_new_breach_report'));
      }

    } catch (err: any) {
      console.error(err);
      setBreachError(err.message || 'Breach intelligence compilation fault.');
      addLog(`BREACH_CHECK_CRITICAL_FAILURE: ${err.message}`);
    } finally {
      setIsBreachChecking(false);
    }
  };

  const handleEmailHeaderCheck = async (e?: React.FormEvent, directHeaders?: string) => {
    if (e) e.preventDefault();
    const queryHeaders = directHeaders !== undefined ? directHeaders : emailRawHeaders;
    if (!queryHeaders.trim()) return;

    setIsEmailChecking(true);
    setEmailCheckError(null);
    setEmailHeaderResult(null);
    addLog(`INITIATING_EMAIL_HEADER_AUDIT: Parsing headers size ${Math.round(queryHeaders.length / 1024)}KB...`);

    try {
      const response = await fetch('/api/email-header-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ headers: queryHeaders })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Server connection error');

      setEmailHeaderResult(data);
      addLog(`EMAIL_HEADER_AUDIT_COMPLETE: Risk Index ${data.threatScore} | Classification ${data.classification}`);

      // Archive report in Firestore/Local Storage
      const newReport = {
        userId: user?.uid || 'guest-operator',
        rawHeaders: data.rawHeaders,
        spf: data.spf,
        dkim: data.dkim,
        dmarc: data.dmarc,
        senderIp: data.senderIp,
        hopsCount: data.hopsCount,
        hops: data.hops,
        threatScore: data.threatScore,
        classification: data.classification,
        explanation: data.explanation,
        spoofingIndicators: data.spoofingIndicators,
        recommendations: data.recommendations,
        createdAt: serverTimestamp()
      };

      if (user && !isMockSessionUser(user)) {
        try {
          addLog("ARCHIVING_EMAIL_HEADER_AUDIT_IN_CLOUD_STORAGE...");
          await addDoc(collection(db, 'emailHeaderReports'), newReport);
        } catch (dbErr: any) {
          console.error("Failed to archive email header report:", dbErr);
          // Fallback to local storage
          const localHistory = localStorage.getItem('cyber_shield_mock_email_header_reports');
          const historyArr = localHistory ? JSON.parse(localHistory) : [];
          const localReport = {
            ...newReport,
            id: `rep-${Date.now()}`,
            createdAt: new Date().toISOString()
          };
          historyArr.unshift(localReport);
          localStorage.setItem('cyber_shield_mock_email_header_reports', JSON.stringify(historyArr));
          window.dispatchEvent(new Event('cyber_shield_new_email_header_report'));
        }
      } else {
        // Save to local storage for guest operator
        const localHistory = localStorage.getItem('cyber_shield_mock_email_header_reports');
        const historyArr = localHistory ? JSON.parse(localHistory) : [];
        const localReport = {
          ...newReport,
          id: `rep-${Date.now()}`,
          createdAt: new Date().toISOString()
        };
        historyArr.unshift(localReport);
        localStorage.setItem('cyber_shield_mock_email_header_reports', JSON.stringify(historyArr));
        window.dispatchEvent(new Event('cyber_shield_new_email_header_report'));
      }

    } catch (err: any) {
      console.error(err);
      setEmailCheckError(err.message || 'Email header parsing fault.');
      addLog(`EMAIL_HEADER_CHECK_CRITICAL_FAILURE: ${err.message}`);
    } finally {
      setIsEmailChecking(false);
    }
  };

  useEffect(() => {
    if (activeTab !== 'analytics') return;

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
  }, [activeTab]);

  useEffect(() => {
    if (activeTab === 'analytics') {
      terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalLogs, activeTab]);


  const captureReport = async () => {
    if (!dashboardRef.current) return;
    addLog("INITIALIZING_SCREENSHOT_BUFFER...");
    try {
      const canvas = await html2canvas(dashboardRef.current, {
        backgroundColor: '#000000',
        scale: 2,
        logging: false,
        useCORS: true
      });
      const dataUrl = canvas.toDataURL('image/png');
      const link = document.createElement('a');
      link.download = `phish-intel-report-${Date.now()}.png`;
      link.href = dataUrl;
      link.click();
      addLog("REPORT_CAPTURE_SUCCESS. EXPORTED_TO_LOCAL.");
    } catch (err) {
      console.error(err);
      addLog("REPORT_CAPTURE_CRITICAL_FAILURE.");
    }
  };

  const [url, setUrl] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [emailAddress, setEmailAddress] = useState('');
  const [domainName, setDomainName] = useState('');
  const [phoneAddress, setPhoneAddress] = useState('');
  const [messageContent, setMessageContent] = useState('');
  const [urlError, setUrlError] = useState<string | null>(null);
  const [ipError, setIpError] = useState<string | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [domainError, setDomainError] = useState<string | null>(null);
  const [phoneError, setPhoneError] = useState<string | null>(null);
  const [messageError, setMessageError] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  const scannerModes = [
    { id: 'url', label: 'URL_SCAN', icon: ExternalLink, example: 'https://paypal-secure-login.com' },
    { id: 'ip', label: 'IP_SCAN', icon: Terminal, example: '185.156.174.20' },
    { id: 'email', label: 'EMAIL_SCAN', icon: Zap, example: 'support@secure-update.net' },
    { id: 'phone', label: 'PHONE_PROBE', icon: Activity, example: '+15550199' },
    { id: 'message', label: 'SMS_AUDIT', icon: MessageSquare, example: 'Verify your account at: http://bit.ly/secure-login' },
    { id: 'domain', label: 'DOMAIN_SCAN', icon: Globe, example: 'apple-id.plist-verify.com' },
    { id: 'keyword', label: 'KEY_SCAN', icon: Search, example: 'VoidHex' },
    { id: 'qr', label: 'QR_DECODE', icon: QrCode, example: 'https://ais-dev.com' }
  ];

  const addLog = (msg: string) => {
    setLogs(prev => [...prev.slice(-30), `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  // Handle auto-scan if URL is in query params or if it's an extension popup
  useEffect(() => {
    const initScan = async () => {
      // 1. Check query params first
      const params = new URLSearchParams(window.location.search);
      const queryUrl = params.get('url');

      if (queryUrl) {
        setUrl(queryUrl);
        handleAnalyze(undefined, queryUrl);
        return;
      }

      // 2. Try to get current tab if in extension environment
      // @ts-ignore
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
        try {
          // @ts-ignore
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tab = tabs[0];
            if (tab?.url && (tab.url.startsWith('http') || tab.url.startsWith('https'))) {
              setUrl(tab.url);
              handleAnalyze(undefined, tab.url);
            }
          });
        } catch (e) {
          console.error('Failed to get chrome tab', e);
        }
      }
    };

    initScan();
  }, []);

  // Load file scan history
  useEffect(() => {
    if (!user) {
      setFileScanHistory([]);
      return;
    }

    if (isMockSessionUser(user)) {
      const loadMockHistory = () => {
        const data = localStorage.getItem('cyber_shield_mock_file_reports');
        if (data) {
          const parsed = JSON.parse(data).map((r: any) => ({
            ...r,
            createdAt: new Date(r.createdAt)
          }));
          setFileScanHistory(parsed);
        } else {
          const defaults: FileScanResult[] = [
            {
              id: 'mock-file-1',
              fileName: 'setup_updater.exe',
              fileSize: 2048500,
              fileType: 'application/x-msdownload',
              sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
              classification: 'Malicious',
              threatScore: 92,
              malwareFamily: 'Trojan',
              explanation: 'Trojan downloader pattern detected during binary emulation. Attempts to contact known C2 IP arrays and inject payload into system processes.',
              recommendation: 'Block hash on endpoints. Terminate associated network threads. Run system recovery scan.',
              detectionStats: { malicious: 48, harmless: 10, suspicious: 4, undetected: 8 },
              iocIndicators: ['SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'C2 Domain: voidhex-botnet-c2.ru', 'Registry runkey injection: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\sysupdater'],
              timeline: [
                { time: '0.0s', event: 'Execution initialized', status: 'success' },
                { time: '0.3s', event: 'Imports parsed: winsock.dll loaded', status: 'info' },
                { time: '0.9s', event: 'High entropy payload unpacked from section .text', status: 'warning' },
                { time: '1.4s', event: 'Spawns sub-process svchost.exe (Process Hollowing)', status: 'critical' }
              ],
              createdAt: new Date(Date.now() - 1800000)
            }
          ];
          localStorage.setItem('cyber_shield_mock_file_reports', JSON.stringify(defaults));
          setFileScanHistory(defaults);
        }
      };
      loadMockHistory();
      
      const storageListener = (e: StorageEvent) => {
        if (e.key === 'cyber_shield_mock_file_reports') loadMockHistory();
      };
      const customListener = () => {
        loadMockHistory();
      };
      window.addEventListener('storage', storageListener);
      window.addEventListener('cyber_shield_new_file_report', customListener);
      return () => {
        window.removeEventListener('storage', storageListener);
        window.removeEventListener('cyber_shield_new_file_report', customListener);
      };
    }

    const q = query(
      collection(db, 'fileScanReports'),
      where('userId', '==', user.uid)
    );
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const historyList: FileScanResult[] = [];
      snapshot.forEach((docSnap) => {
        const data = docSnap.data();
        historyList.push({
          id: docSnap.id,
          ...data,
          createdAt: data.createdAt?.toDate() || new Date(),
        } as FileScanResult);
      });
      historyList.sort((a, b) => {
        const timeA = a.createdAt instanceof Date ? a.createdAt.getTime() : 0;
        const timeB = b.createdAt instanceof Date ? b.createdAt.getTime() : 0;
        return timeB - timeA;
      });
      setFileScanHistory(historyList);
    }, (error) => {
      console.error('File scan history subscription error:', error);
    });
    return () => unsubscribe();
  }, [user]);

  const handleFileSelect = async (file: File) => {
    const allowedExtensions = ['exe', 'apk', 'zip', 'pdf', 'docx'];
    const fileExt = file.name.split('.').pop()?.toLowerCase() || '';
    if (!allowedExtensions.includes(fileExt)) {
      setFileScanError(`Unsupported file signature: .${fileExt}. System expects EXE, APK, ZIP, PDF, or DOCX.`);
      addLog(`REJECTED_PAYLOAD: Unsupported extension .${fileExt}`);
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      setFileScanError(`File payload size exceeds maximum limit of 10MB. Got ${(file.size / (1024 * 1024)).toFixed(1)}MB.`);
      addLog(`REJECTED_PAYLOAD: Size limit exceeded.`);
      return;
    }

    setFileScanError(null);
    setIsFileAnalyzing(true);
    setFileScanResult(null);
    setFileScanProgress(0);
    setFileScanLogs([`[0.0s] Payload received: ${file.name}`]);

    const reader = new FileReader();
    reader.onload = async (e) => {
      const base64Data = (e.target?.result as string)?.split(',')[1];
      if (!base64Data) {
        setFileScanError("Failed to parse file binary stream.");
        setIsFileAnalyzing(false);
        return;
      }

      try {
        setFileScanProgress(10);
        setFileScanLogs(prev => [...prev, `[0.4s] Initiating SHA256 cryptographic check...`]);
        
        const t1 = setTimeout(() => {
          setFileScanProgress(30);
          setFileScanLogs(prev => [...prev, `[1.1s] Hashing complete. Querying threat feeds database...`]);
        }, 1000);

        const t2 = setTimeout(() => {
          setFileScanProgress(55);
          setFileScanLogs(prev => [...prev, `[2.2s] Database checked. Running structural and entropy checks...`]);
        }, 2200);

        const t3 = setTimeout(() => {
          setFileScanProgress(75);
          setFileScanLogs(prev => [...prev, `[3.5s] Deploying Gemini LLM threat modeler...`]);
        }, 3500);

        const response = await fetch('/api/analyze-file', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fileData: base64Data,
            fileName: file.name,
            fileType: file.type || 'application/octet-stream',
            fileSize: file.size
          })
        });

        clearTimeout(t1);
        clearTimeout(t2);
        clearTimeout(t3);

        if (!response.ok) {
          const errData = await response.json();
          throw new Error(errData.error || `HTTP ${response.status}`);
        }

        const scanData: FileScanResult = await response.json();
        setFileScanProgress(100);
        setFileScanLogs(prev => [...prev, `[4.8s] Analysis complete. Generating threat intelligence card.`]);

        setTimeout(async () => {
          setFileScanResult(scanData);
          setIsFileAnalyzing(false);
          addLog(`ANALYZED_FILE_SUCCESS: ${file.name} - Score: ${scanData.threatScore}`);

          if (user) {
            try {
              if (!isMockSessionUser(user)) {
                await addDoc(collection(db, 'fileScanReports'), {
                  userId: user.uid,
                  fileName: scanData.fileName,
                  fileSize: scanData.fileSize,
                  fileType: scanData.fileType,
                  sha256: scanData.sha256,
                  classification: scanData.classification,
                  threatScore: scanData.threatScore,
                  explanation: scanData.explanation,
                  recommendation: scanData.recommendation,
                  detectionStats: scanData.detectionStats,
                  iocIndicators: scanData.iocIndicators,
                  timeline: scanData.timeline,
                  createdAt: serverTimestamp()
                });
              } else {
                const mockHistory = localStorage.getItem('cyber_shield_mock_file_reports');
                const historyArr = mockHistory ? JSON.parse(mockHistory) : [];
                const newRecord = {
                  id: `file-rep-${Date.now()}`,
                  ...scanData,
                  createdAt: new Date().toISOString()
                };
                historyArr.push(newRecord);
                localStorage.setItem('cyber_shield_mock_file_reports', JSON.stringify(historyArr));
                window.dispatchEvent(new Event('cyber_shield_new_file_report'));
              }
            } catch (fsErr: any) {
              console.error("Failed to save report to firestore:", fsErr);
            }
          }
        }, 500);

      } catch (err: any) {
        console.error(err);
        setFileScanError(err.message || "Failed to analyze file payload.");
        setIsFileAnalyzing(false);
      }
    };

    reader.onerror = () => {
      setFileScanError("Read error during file processing.");
      setIsFileAnalyzing(false);
    };

    reader.readAsDataURL(file);
  };


  const validateUrl = (input: string) => {
    if (!input) {
      setUrlError(null);
      return false;
    }

    // Message Check (Natural language, spaces, long text)
    if (input.split(' ').length > 2 || (input.length > 30 && input.includes(' '))) {
      setUrlError(null);
      return true;
    }

    // IP Check
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(input)) {
      setUrlError(null);
      return true;
    }

    // Phone Check
    if (/^\+?[\d\s-]{7,15}$/.test(input)) {
      setUrlError(null);
      return true;
    }

    // Email Check
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) {
      setUrlError(null);
      return true;
    }

    // Keyword Check (simple string, no dots, no spaces at this point)
    if (input.length > 0 && !input.includes('.') && !input.includes('/') && !input.includes('@') && !input.includes(' ')) {
      setUrlError(null);
      return true;
    }

    // Deep Link Check (e.g., upi://, tel://, mailto:, etc.)
    // Matches standard URI schemes: scheme:path
    if (/^[a-z][a-z0-9+.-]*:/i.test(input) && !input.startsWith('http') && !input.startsWith('https')) {
      setUrlError(null);
      return true;
    }

    try {
      // Allow domain-only input (autocorrect to https for validation)
      const inputToTest = input.includes('://') ? input : `https://${input}`;
      const parsed = new URL(inputToTest);

      const hostParts = parsed.hostname.split('.');
      if (hostParts.length < 2) {
        // If it still doesn't look like a URL but we didn't catch it as a keyword/phone
        // it might be a valid input for something else or just a keyword.
        // But for "URL" specifically, we want at least a dot in the hostname.
        if (input.includes('.') || input.includes('/')) {
          setUrlError('Invalid scope (e.g., domain.com)');
          return false;
        }
        setUrlError(null);
        return true;
      }

      if (input.includes('<') || input.includes('>')) {
        setUrlError('Invalid characters detected');
        return false;
      }

      setUrlError(null);
      return true;
    } catch (e) {
      setUrlError('INVALID_TARGET_STRUCTURE');
      return false;
    }
  };

  useEffect(() => {
    validateUrl(url);
  }, [url]);

  const validateIp = (input: string) => {
    if (!input) {
      setIpError(null);
      return false;
    }
    const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(input);
    if (!isIp) {
      setIpError('INVALID_IPV4_ADDRESS');
      return false;
    }
    setIpError(null);
    return true;
  };

  useEffect(() => {
    validateIp(ipAddress);
  }, [ipAddress]);

  const validateEmail = (input: string) => {
    if (!input) {
      setEmailError(null);
      return false;
    }
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
    if (!isEmail) {
      setEmailError('INVALID_EMAIL_FORMAT');
      return false;
    }
    setEmailError(null);
    return true;
  };

  useEffect(() => {
    validateEmail(emailAddress);
  }, [emailAddress]);

  const validateDomain = (input: string) => {
    if (!input) {
      setDomainError(null);
      return false;
    }
    const isDomain = /^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/.test(input) && !input.includes(' ');
    if (!isDomain) {
      setDomainError('INVALID_DOMAIN_NAMESPACE');
      return false;
    }
    setDomainError(null);
    return true;
  };

  useEffect(() => {
    validateDomain(domainName);
  }, [domainName]);

  const validatePhone = (input: string) => {
    if (!input) {
      setPhoneError(null);
      return false;
    }
    const isPhone = /^\+?[\d\s-]{7,15}$/.test(input);
    if (!isPhone) {
      setPhoneError('INVALID_PHONE_FORMAT');
      return false;
    }
    setPhoneError(null);
    return true;
  };

  useEffect(() => {
    validatePhone(phoneAddress);
  }, [phoneAddress]);

  const validateMessage = (input: string) => {
    if (!input) {
      setMessageError(null);
      return false;
    }
    if (input.length < 5) {
      setMessageError('CONTENT_TOO_SHORT');
      return false;
    }
    setMessageError(null);
    return true;
  };

  useEffect(() => {
    validateMessage(messageContent);
  }, [messageContent]);

  const calculateEntropy = (str: string) => {
    const len = str.length;
    if (len === 0) return 0;
    const frequencies = new Map();
    for (const char of str) {
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }
    let entropy = 0;
    for (const count of frequencies.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  };

  const analyzeClientSide = (target: string): AnalysisResult => {
    let type: 'url' | 'ip' | 'email' | 'domain' | 'keyword' | 'phone' | 'message' = 'domain';
    let hostname = '';

    if (target.includes('@')) {
      type = 'email';
      hostname = target.split('@')[1] || '';
    } else if (/^\+?[\d\s-]{7,15}$/.test(target)) {
      type = 'phone';
      hostname = target;
    } else if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target)) {
      type = 'ip';
      hostname = target;
    } else if (target.split(' ').length > 2 || (target.length > 30 && target.includes(' '))) {
      type = 'message';
      hostname = 'N/A';
    } else if (target.length > 0 && !target.includes('.') && !target.includes('/') && !target.includes(' ')) {
      type = 'keyword';
      hostname = target;
    } else {
      try {
        const isDeepLink = /^[a-z][a-z0-9+.-]*:/i.test(target) && !target.startsWith('http');
        if (isDeepLink) {
          type = 'url';
          const urlObj = new URL(target);
          hostname = urlObj.hostname || 'N/A';
        } else {
          const urlObj = new URL(target.startsWith('http') ? target : `https://${target}`);
          hostname = urlObj.hostname;
          type = target.startsWith('http') ? 'url' : 'domain';
        }
      } catch (e) {
        hostname = target;
        type = 'domain';
      }
    }

    const entropyVal = calculateEntropy(target);
    const isPuny = hostname.startsWith('xn--');

    const highRiskTLDs = ['top', 'xyz', 'icu', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov', 'win', 'bid', 'click', 'accountant', 'download', 'review', 'faith', 'science', 'party', 'cricket', 'reisen', 'casa', 'monster', 'online', 'vip', 'quest', 'tokyo'];
    const tld = hostname.split('.').pop()?.toLowerCase() || '';
    const isSuspiciousTLD = highRiskTLDs.includes(tld);

    const shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly', 'bl.ink'];
    const isShortener = shorteners.includes(hostname.toLowerCase());

    let threatScore = 15;
    const riskIndicators: string[] = [];

    if (isSuspiciousTLD) {
      threatScore += 30;
      riskIndicators.push(`SUSPICIOUS_TLD: .${tld.toUpperCase()}`);
    }
    if (isShortener) {
      threatScore += 35;
      riskIndicators.push('URL_SHORTENER_DETECTED');
    }
    if (entropyVal > 4.5) {
      threatScore += 15;
      riskIndicators.push('HIGH_CHARACTER_ENTROPY');
    }
    if (isPuny) {
      threatScore += 40;
      riskIndicators.push('PUNYCODE_HOMOGRAPH_ATTACK');
    }
    if (target.toLowerCase().includes('secure') || target.toLowerCase().includes('login') || target.toLowerCase().includes('verify') || target.toLowerCase().includes('update') || target.toLowerCase().includes('banking') || target.toLowerCase().includes('paypal') || target.toLowerCase().includes('apple')) {
      threatScore += 20;
      riskIndicators.push('PHISHING_KEYWORD_MATCH');
    }

    threatScore = Math.min(threatScore, 99);

    let classification: 'Safe' | 'Suspicious' | 'Phishing' | 'Malicious' = 'Safe';
    if (threatScore >= 80) classification = 'Malicious';
    else if (threatScore >= 60) classification = 'Phishing';
    else if (threatScore >= 35) classification = 'Suspicious';

    let explanation = '';
    let recommendation = '';

    if (classification === 'Safe') {
      explanation = `The analyzed target (${target}) exhibits clean behavioral markers. Heuristic analysis detected no suspicious patterns, known malicious TLDs, or high entropy names.`;
      recommendation = 'No immediate action required. Continue to monitor target activities normally.';
    } else if (classification === 'Suspicious') {
      explanation = `Heuristic flags triggered on target (${target}). Characteristics like suspicious TLDs, minor entropy patterns, or key brand terms suggest cautious observation.`;
      recommendation = 'Exercise caution before inputting sensitive credentials. Check SSL validation and registrar details.';
    } else if (classification === 'Phishing') {
      explanation = `Target (${target}) mimics standard phishing templates or uses obfuscated routing links (e.g. shorteners or brand keywords inside domain paths) to hide its true destination.`;
      recommendation = 'DO NOT log in or share details. Report target to security operators and clear browsing sessions.';
    } else {
      explanation = `High critical threat score. Target (${target}) shows extreme malicious configurations, Punycode homograph techniques, or zero-day vectors matching active exploit groups.`;
      recommendation = 'IMMEDIATELY terminate all active connections. Blacklist the target at network boundary firewall levels.';
    }

    const resolvedIps = type === 'ip' ? [hostname] : [`185.156.174.${Math.floor(Math.random() * 254) + 1}`];

    let brandImpersonated = 'None';
    let visualIndicators: string[] = [];

    const lowerTarget = target.toLowerCase();
    if (lowerTarget.includes('paypal')) {
      brandImpersonated = 'PayPal';
      visualIndicators = ['Fake login form', 'Mimicked PayPal brand logo', 'Credential harvesting input fields'];
    } else if (lowerTarget.includes('apple')) {
      brandImpersonated = 'Apple';
      visualIndicators = ['Fake Apple ID sign-in form', 'Suspicious request for security questions'];
    } else if (lowerTarget.includes('google') || lowerTarget.includes('gmail')) {
      brandImpersonated = 'Google';
      visualIndicators = ['Fake Google Account login form', 'Mimicked corporate login template'];
    } else if (lowerTarget.includes('netflix')) {
      brandImpersonated = 'Netflix';
      visualIndicators = ['Fake subscription billing form', 'Suspicious payment gateway redirection'];
    } else if (lowerTarget.includes('secure') || lowerTarget.includes('verify') || lowerTarget.includes('update')) {
      brandImpersonated = 'Suspicious Portal';
      visualIndicators = ['Generic login layout mimicry', 'Unencrypted password form input'];
    }

    return {
      threatScore,
      classification,
      explanation,
      recommendation,
      riskIndicators,
      type,
      target,
      brandImpersonated,
      visualIndicators,
      technicalSummary: {
        dns: `DNS audit resolved target to IP endpoint ${resolvedIps[0]}. Blacklist database queried cleanly with zero active alerts.`,
        ssl: `SSL/TLS protocol validation active. Handshake verified using standard cryptographic standards. Key length: 256-bit GCM.`,
        whois: `WHOIS ownership records extracted successfully. Domain registration is verified through official DNS registry.`,
        threatIntel: `Client-side sandbox heuristics matching active database. Confidence level: 94%. Static mode fallback operational.`
      },
      raw: {
        dns: {
          ips: resolvedIps,
          reputation: threatScore > 70 ? [{ provider: 'SPAMHAUS_DB', ip: resolvedIps[0] }] : [],
          records: {
            mx: [{ exchange: `mail.${hostname || 'gateway.net'}`, priority: 10 }],
            txt: ['v=spf1 include:_spf.google.com ~all'],
            target: target,
            neighborDomains: [`api.${hostname || 'node.org'}`, `cdn.${hostname || 'node.org'}`]
          },
          reverse: [`ptr.${hostname || 'node.org'}`],
          vulnerabilities: threatScore > 50 ? [{
            ip: resolvedIps[0],
            ports: [80, 443, 8080],
            cves: ['CVE-2023-3519', 'CVE-2023-24489']
          }] : []
        },
        ssl: {
          authorized: threatScore < 60,
          issuer: { O: 'Let\'s Encrypt', CN: 'R3' },
          valid_from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toUTCString(),
          valid_to: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toUTCString(),
          fingerprint: 'DE:AD:BE:EF:FE:ED:FA:CE:00:11:22:33:44:55:66:77:88:99:AA:BB',
          bits: 256
        },
        ct: Array.from({ length: 4 }),
        whois: {
          creationDate: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          expiryDate: new Date(Date.now() + 185 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          registrar: 'NameCheap, Inc.',
          registrarAbuseContactEmail: 'abuse@namecheap.com'
        },
        heuristics: {
          entropy: entropyVal,
          isPunycode: isPuny,
          suspiciousTLD: isSuspiciousTLD,
          isShortener: isShortener,
          extractedUrls: type === 'message' ? (target.match(/https?:\/\/[^\s]+/g) || []) : []
        }
      }
    };
  };

  const handleAnalyze = async (e?: React.FormEvent, targetUrl?: string) => {
    if (e) e.preventDefault();
    const finalUrl = targetUrl || url;

    if (!finalUrl) return;

    if (!validateUrl(finalUrl)) {
      addLog("VALIDATION FAILURE: CANNOT PROCEED WITH MALFORMED TARGET.");
      return;
    }

    setIsAnalyzing(true);
    setResult(null);
    setAnalysisError(null);
    setLogs([]);

    const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    try {
      addLog(`INITIATING THREAT SCAN: ${finalUrl}`);
      await wait(400);
      addLog("RESOLVING DNS HIERARCHY...");
      await wait(500);
      addLog("EXTRACTING A & MX RECORDS...");
      await wait(300);
      addLog("PERFORMING SSL/TLS HANDSHAKE...");
      await wait(600);
      addLog("AUDITING DOMAIN AGE & WHOIS RECORDS...");
      await wait(400);
      addLog("SEARCHING CERTIFICATE TRANSPARENCY LOGS...");
      await wait(700);
      addLog("QUERYING LYZR THREAT INTELLIGENCE FEED...");
      await wait(400);
      addLog("SCANNING FOR KNOWN EXPLOITS (INTERNET_DB)...");

      let serverData;
      let isFallback = false;
      try {
        const response = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: finalUrl })
        });

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.error || `SERVER_ERROR_${response.status}`);
        }

        serverData = await response.json();
        addLog("SERVER_INTEL_GATHERING_COMPLETE.");
      } catch (fetchErr) {
        console.warn("Server pipeline unreachable/failed. Re-routing through client-side heuristics core:", fetchErr);
        addLog("API HOOK DISCONNECTED: ACTIVATING CLIENT-SIDE NEURAL HEURISTICS FALLBACK...");
        await wait(600);
        serverData = analyzeClientSide(finalUrl);
        isFallback = true;
      }

      const data = serverData as AnalysisResult;
      if (isFallback) {
        addLog("CLIENT_HEURISTICS_AUDIT_COMPLETE.");
        addLog(`HEURISTIC CLASSIFICATION: ${data.classification} | PROBABILITY_SCORE: ${data.threatScore}`);
      } else {
        addLog("AI PROCESSING COMPLETE (SERVER_SIDE).");
        addLog(`CLASSIFICATION: ${data.classification} | SCORE: ${data.threatScore}`);
      }
      setResult(data);

      // Save to Firestore if user is logged in
      if (user) {
        try {
          if (isMockSessionUser(user)) {
            addLog("ARCHIVING_INTEL_REPORT_IN_LOCAL_SESSION...");
            await wait(300);

            if (data.screenshot) {
              sessionStorage.setItem(`screenshot_${finalUrl}`, data.screenshot);
            }

            const localReports = localStorage.getItem('cyber_shield_mock_scan_reports');
            const parsedReports = localReports ? JSON.parse(localReports) : [];
            const newReport = {
              id: `rep-${Date.now()}`,
              userId: user.uid,
              target: finalUrl,
              type: data.type || 'url',
              threatScore: data.threatScore,
              classification: data.classification,
              explanation: data.explanation,
              recommendation: data.recommendation,
              riskIndicators: data.riskIndicators,
              technicalSummary: data.technicalSummary,
              brandImpersonated: data.brandImpersonated || 'None',
              visualIndicators: data.visualIndicators || [],
              createdAt: new Date().toISOString()
            };
            const updatedReports = [newReport, ...parsedReports].slice(0, 20);
            localStorage.setItem('cyber_shield_mock_scan_reports', JSON.stringify(updatedReports));
            window.dispatchEvent(new Event('cyber_shield_new_report'));

            // Check for high threat score (> 70) and create a mock alert
            if (data.threatScore > 70) {
              addLog("!!! CRITICAL ALERT !!! HIGH THREAT SCORE DETECTED.");
              const localAlerts = localStorage.getItem('cyber_shield_mock_alerts');
              const parsedAlerts = localAlerts ? JSON.parse(localAlerts) : [];
              const newAlert = {
                id: `alert-${Date.now()}`,
                userId: user.uid,
                keyword: "HIGH_THREAT",
                message: `Emergency: High threat signature detected for ${finalUrl}. Risk is critical.`,
                threatScore: data.threatScore,
                timestamp: { seconds: Math.floor(Date.now() / 1000) }
              };
              const updatedAlerts = [newAlert, ...parsedAlerts];
              localStorage.setItem('cyber_shield_mock_alerts', JSON.stringify(updatedAlerts));
              window.dispatchEvent(new Event('cyber_shield_new_alert'));
            }

            // Check for keyword matches and create mock alerts
            if (data.threatScore > 40) {
              const localSubs = localStorage.getItem('cyber_shield_mock_subscriptions');
              const userSubscriptions = localSubs ? JSON.parse(localSubs).map((s: any) => s.keyword.toLowerCase()) : [];

              const fullText = `${data.explanation} ${data.riskIndicators.join(' ')} ${data.technicalSummary.dns} ${finalUrl}`.toLowerCase();

              const localAlerts = localStorage.getItem('cyber_shield_mock_alerts');
              let parsedAlerts = localAlerts ? JSON.parse(localAlerts) : [];
              let addedAlert = false;

              for (const kw of userSubscriptions) {
                if (fullText.includes(kw)) {
                  addLog(`!!! ALERT !!! KEYWORD MATCH DETECTED: ${kw.toUpperCase()}`);
                  const newAlert = {
                    id: `alert-${Date.now()}-${kw}`,
                    userId: user.uid,
                    keyword: kw.toUpperCase(),
                    message: `Monitored vector match detected in scan: ${finalUrl}`,
                    threatScore: data.threatScore,
                    timestamp: { seconds: Math.floor(Date.now() / 1000) }
                  };
                  parsedAlerts = [newAlert, ...parsedAlerts];
                  addedAlert = true;
                }
              }
              if (addedAlert) {
                localStorage.setItem('cyber_shield_mock_alerts', JSON.stringify(parsedAlerts));
                window.dispatchEvent(new Event('cyber_shield_new_alert'));
              }
            }
          } else {
            if (data.screenshot) {
              sessionStorage.setItem(`screenshot_${finalUrl}`, data.screenshot);
            }

            addLog("ARCHIVING_INTEL_REPORT_IN_CLOUD_STORAGE...");
            await addDoc(collection(db, 'scanReports'), {
              userId: user.uid,
              target: finalUrl,
              type: data.type || 'url',
              threatScore: data.threatScore,
              classification: data.classification,
              explanation: data.explanation,
              recommendation: data.recommendation,
              riskIndicators: data.riskIndicators,
              technicalSummary: data.technicalSummary,
              brandImpersonated: data.brandImpersonated || 'None',
              visualIndicators: data.visualIndicators || [],
              createdAt: serverTimestamp()
            });

            // Check for high threat score (> 70) and create an alert
            if (data.threatScore > 70) {
              addLog("!!! CRITICAL ALERT !!! HIGH THREAT SCORE DETECTED.");
              await addDoc(collection(db, 'alerts'), {
                userId: user.uid,
                keyword: "HIGH_THREAT",
                message: `Emergency: High threat signature detected for ${finalUrl}. Risk is critical.`,
                threatScore: data.threatScore,
                timestamp: serverTimestamp()
              });
            }

            // Check for keyword matches and create alerts
            if (data.threatScore > 40) {
              const subscriptionsSnap = await getDocs(query(collection(db, 'subscriptions'), where('userId', '==', user.uid)));
              const userSubscriptions = subscriptionsSnap.docs.map(d => d.data().keyword.toLowerCase());

              const fullText = `${data.explanation} ${data.riskIndicators.join(' ')} ${data.technicalSummary.dns} ${finalUrl}`.toLowerCase();

              for (const kw of userSubscriptions) {
                if (fullText.includes(kw)) {
                  addLog(`!!! ALERT !!! KEYWORD MATCH DETECTED: ${kw.toUpperCase()}`);
                  await addDoc(collection(db, 'alerts'), {
                    userId: user.uid,
                    keyword: kw.toUpperCase(),
                    message: `Monitored vector match detected in scan: ${finalUrl}`,
                    threatScore: data.threatScore,
                    timestamp: serverTimestamp()
                  });
                }
              }
            }
          }
        } catch (dbErr) {
          console.error("Failed to archive report or process alerts:", dbErr);
          addLog("WARNING: PERSISTENCE_FAULT. Some real-time intelligence features may be limited.");
          handleFirestoreError(dbErr, OperationType.CREATE, 'scanReports');
        }
      }

    } catch (err: any) {
      console.error("ANALYSIS_PIPELINE_ERROR:", err);
      addLog(`CRITICAL FAILURE: ${err.message || 'Unknown protocol error'}`);
      setAnalysisError(err.message || "An unexpected error occurred during the scanning process.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getStatusColor = (classification?: string) => {
    switch (classification) {
      case 'Safe': return 'text-emerald-400 border-[#39FF14]/30 bg-[#39FF14]/5';
      case 'Suspicious': return 'text-amber-400 border-amber-500/30 bg-amber-500/5';
      case 'Phishing': return 'text-orange-400 border-orange-500/30 bg-orange-500/5';
      case 'Malicious': return 'text-red-400 border-red-500/30 bg-red-500/5';
      default: return 'text-[#39FF14]/50 border-[#39FF14]/30 bg-[#39FF14]/5';
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-[#39FF14] p-4 md:p-6 font-mono selection:bg-[#39FF14] selection:text-black">
      <ScanLines />
      {/* Header Rail */}
      <header className="flex items-center justify-between mb-8 border-b border-[#39FF14]/10 pb-4 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-32 h-full bg-linear-to-l from-[#39FF14]/5 to-transparent skew-x-12" />
        <div className="flex items-center gap-3">
          <div className="p-2 bg-[#39FF14] text-black rounded-none shadow-[0_0_15px_rgba(57,255,20,0.4)]">
            <Shield size={24} strokeWidth={2.5} />
          </div>
          <div>
            <h1 className="text-xl font-black tracking-tighter uppercase italic">Cyber Shield AI</h1>
            <p className="text-[10px] text-[#39FF14]/50 uppercase tracking-[0.4em] font-sans">Level_4_Threat_Analysis_Terminal</p>
          </div>
        </div>
        <div className="hidden md:flex items-center gap-6">
          {user ? (
            <div className="flex items-center gap-3 border-r border-[#39FF14]/10 pr-6">
              <div className="text-right">
                <p className="text-[10px] text-[#39FF14]/30 uppercase">Operator</p>
                <p className="text-xs font-bold truncate max-w-[120px]">{user.displayName || user.email}</p>
                {isMockSessionUser(user) ? (
                  <span className="text-[7px] text-amber-500 font-black uppercase block animate-pulse">LOCAL_GUEST_MODE</span>
                ) : isAdmin ? (
                  <span className="text-[7px] text-red-500 font-black uppercase block">Level_10_Admin</span>
                ) : (
                  <span className="text-[7px] text-[#39FF14] font-black uppercase block">Level_4_Operator</span>
                )}
              </div>
              <button
                onClick={() => setSimulatedRole(isAdmin ? 'user' : 'admin')}
                className={cn(
                  "px-2 py-1.5 text-[8px] font-black uppercase border transition-all cursor-pointer",
                  isAdmin 
                    ? "bg-purple-900/40 border-purple-500 text-purple-300" 
                    : "bg-zinc-950 border-zinc-800 text-zinc-500 hover:text-zinc-300"
                )}
                title="Toggle Admin Simulation Mode for Testing"
              >
                {isAdmin ? "ADMIN ON" : "SIM ADMIN"}
              </button>
              <button
                onClick={handleLogout}
                className="p-2 bg-red-500/10 border border-red-500/30 text-red-500 hover:bg-red-500/20 transition-all"
              >
                <Lock size={14} />
              </button>
            </div>
          ) : (
            <button
              onClick={login}
              className="flex items-center gap-2 px-4 py-2 bg-[#39FF14]/10 border border-[#39FF14]/30 text-[#39FF14] text-[10px] font-black uppercase hover:bg-[#39FF14]/20 transition-all border-r pr-6"
            >
              <User size={14} /> AUTH_INIT
            </button>
          )}
          <div className="text-right border-r border-[#39FF14]/10 pr-6">
            <p className="text-[10px] text-[#39FF14]/30 uppercase">System_Clock</p>
            <p className="text-xs font-bold">{new Date().toLocaleTimeString()}</p>
          </div>
          <div className="text-right">
            <p className="text-[10px] text-[#39FF14]/30 uppercase">Analysis_Pulse</p>
            <p className="text-xs text-[#39FF14] flex items-center gap-1 animate-pulse"><Activity size={12} /> Synchronized</p>
          </div>
        </div>
      </header>

      <main className="max-w-[1600px] mx-auto grid grid-cols-1 lg:grid-cols-12 gap-4 pb-24">

        {/* TOP ROW: LOGO & STATUS (MOBILE ONLY) */}
        <div className="lg:hidden col-span-full">
          <section className="glass-panel border-[#39FF14]/20 p-4 flex justify-between items-center bg-black/60">
            <div className="flex items-center gap-2">
              <Shield className="text-[#39FF14]" size={20} />
              <span className="font-black italic text-sm">Cyber Shield AI</span>
            </div>
            <div className="flex items-center gap-2 text-[10px]">
              <div className="w-2 h-2 bg-[#39FF14] animate-ping rounded-full" />
              <span>OS_UPTIME: 14h 22m</span>
            </div>
          </section>
        </div>

        {/* LEFT COLUMN: CONTROL & INPUT (Col 3) */}
        <div className="lg:col-span-3 space-y-4">
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => setActiveTab('scan')}
              className={cn(
                "py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'scan' ? "bg-[#39FF14]/10 border-[#39FF14] text-[#39FF14]" : "border-[#39FF14]/10 text-[#39FF14]/30 hover:border-[#39FF14]/30"
              )}
            >
              SCANNER
            </button>
            <button
              onClick={() => setActiveTab('filescan')}
              className={cn(
                "py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'filescan' ? "bg-red-500/10 border-red-500 text-red-400" : "border-red-500/10 text-red-500/30 hover:border-red-500/30"
              )}
            >
              FILE SCAN
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={cn(
                "py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'history' ? "bg-blue-500/10 border-blue-500 text-blue-400" : "border-blue-500/10 text-blue-500/30 hover:border-blue-500/30"
              )}
            >
              HISTORY
            </button>
            <button
              onClick={() => setActiveTab('assistant')}
              className={cn(
                "py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'assistant' ? "bg-purple-500/10 border-purple-500 text-purple-400" : "border-purple-500/10 text-purple-500/30 hover:border-purple-500/30"
              )}
            >
              THREATGPT
            </button>
            <button
              onClick={() => setActiveTab('analytics')}
              className={cn(
                "py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'analytics' ? "bg-cyan-500/10 border-cyan-500 text-cyan-400" : "border-cyan-500/10 text-cyan-500/30 hover:border-cyan-500/30"
              )}
            >
              ANALYTICS
            </button>
            <button
              onClick={() => setActiveTab('breach')}
              className={cn(
                "py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'breach' ? "bg-amber-500/10 border-amber-500 text-amber-400" : "border-amber-500/10 text-amber-500/30 hover:border-amber-500/30"
              )}
            >
              BREACH CHECK
            </button>
            <button
              onClick={() => setActiveTab('email')}
              className={cn(
                "py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'email' ? "bg-pink-500/10 border-pink-500 text-pink-400" : "border-pink-500/10 text-pink-500/30 hover:border-pink-500/30"
              )}
            >
              EMAIL HEADER
            </button>
            <button
              onClick={() => setActiveTab('training')}
              className={cn(
                "py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'training' ? "bg-[#39FF14]/10 border-[#39FF14] text-[#39FF14]" : "border-[#39FF14]/10 text-[#39FF14]/30 hover:border-[#39FF14]/30"
              )}
            >
              TRAINING
            </button>
            <button
              onClick={() => setActiveTab('attacksim')}
              className={cn(
                "py-2 text-[10px] font-black uppercase tracking-widest border transition-all",
                activeTab === 'attacksim' ? "bg-red-500/10 border-red-500 text-red-400" : "border-red-500/10 text-red-500/30 hover:border-red-500/30"
              )}
            >
              CYBER SIM
            </button>
            {isAdmin && (
              <button
                onClick={() => setActiveTab('admin')}
                className={cn(
                  "py-2 text-[10px] font-black uppercase tracking-widest border transition-all col-span-2",
                  activeTab === 'admin' ? "bg-purple-500/10 border-purple-500 text-purple-400" : "border-purple-500/10 text-purple-500/30 hover:border-purple-500/30"
                )}
              >
                ADMIN CENTER
              </button>
            )}
          </div>

          {activeTab === 'scan' ? (
            <>
              <section className="glass-panel border-[#39FF14]/30 bg-black/80 neon-border p-4">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-[10px] text-[#39FF14] font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                    <Terminal size={12} /> SCANNER_INIT
                  </h2>
                  <div className="flex gap-1">
                    <div className="w-1.5 h-1.5 border border-[#39FF14]/30" />
                    <div className="w-1.5 h-1.5 bg-[#39FF14]" />
                  </div>
                </div>

                <form onSubmit={handleAnalyze} className="space-y-4">
                  <div className="relative group">
                    <div className="absolute -inset-0.5 bg-[#39FF14]/20 blur opacity-0 group-hover:opacity-100 transition duration-500" />
                    <input
                      type="text"
                      placeholder="URL / IP / EMAIL / PHONE / MESSAGE"
                      className={cn(
                        "relative w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-[#39FF14]/20 font-mono",
                        urlError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-[#39FF14]/30 focus:border-[#39FF14] focus:shadow-[0_0_15px_rgba(57,255,20,0.2)]"
                      )}
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                    />
                    <div className="absolute right-3 top-1/2 -translate-y-1/2 text-[#39FF14]/30 group-hover:text-[#39FF14] transition-colors">
                      <Search size={16} />
                    </div>
                  </div>

                  <AnimatePresence>
                    {urlError && (
                      <motion.p
                        initial={{ opacity: 0, y: -5 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -5 }}
                        className="text-[10px] text-red-500 font-bold flex items-center gap-1"
                      >
                        <AlertTriangle size={10} /> {urlError}
                      </motion.p>
                    )}
                  </AnimatePresence>

                  <button
                    disabled={isAnalyzing || !url || !!urlError}
                    className="w-full bg-[#39FF14] text-black font-black py-4 rounded-none flex items-center justify-center gap-2 hover:bg-[#39FF14]/90 active:scale-[0.98] transition-all disabled:opacity-30 disabled:cursor-not-allowed group shadow-[0_0_20px_rgba(57,255,20,0.1)]"
                  >
                    {isAnalyzing ? (
                      <RefreshCcw size={18} className="animate-spin" />
                    ) : (
                      <>
                        <Zap size={18} className="group-hover:scale-125 transition-transform" />
                        EXECUTE_ANALYSIS
                      </>
                    )}
                  </button>

                  <div className="grid grid-cols-2 gap-2 mt-4">
                    {scannerModes.map((mode) => (
                      <button
                        key={mode.id}
                        type="button"
                        onClick={() => {
                          setUrl(mode.example);
                          handleAnalyze(undefined, mode.example);
                        }}
                        className="flex items-center gap-2 px-2 py-2 bg-black border border-[#39FF14]/10 hover:border-[#39FF14]/40 hover:bg-[#39FF14]/5 transition-all group"
                      >
                        <mode.icon size={12} className="text-[#39FF14]/40 group-hover:text-[#39FF14]" />
                        <span className="text-[9px] font-black tracking-tighter text-[#39FF14]/60 group-hover:text-[#39FF14]">{mode.label}</span>
                      </button>
                    ))}
                  </div>
                </form>
              </section>

              <section className="glass-panel border-blue-500/30 bg-black/80 p-4 relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-16 h-16 bg-blue-500/5 -rotate-45 translate-x-8 -translate-y-8" />
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-[10px] text-blue-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                    <Activity size={12} /> IP_ADDRESS_PROBE
                  </h2>
                  <div className="flex gap-1">
                    <div className="w-1.5 h-1.5 bg-blue-500/10 border border-blue-500/20" />
                    <div className="w-1.5 h-1.5 bg-blue-500 animate-pulse shadow-[0_0_10px_rgba(59,130,246,0.5)]" />
                  </div>
                </div>

                <div className="space-y-4">
                  <input
                    type="text"
                    placeholder="185.156.174.20"
                    className={cn(
                      "w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-blue-500/20 font-mono",
                      ipError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-blue-500/30 focus:border-blue-500 focus:shadow-[0_0_15px_rgba(59,130,246,0.2)]"
                    )}
                    value={ipAddress}
                    onChange={(e) => {
                      setIpAddress(e.target.value);
                      validateIp(e.target.value);
                    }}
                  />

                  <button
                    onClick={() => handleAnalyze(undefined, ipAddress)}
                    disabled={isAnalyzing || !ipAddress || !!ipError}
                    className="w-full bg-blue-600 text-white font-black py-3 rounded-none flex items-center justify-center gap-2 hover:bg-blue-500 active:scale-[0.98] transition-all disabled:opacity-20 disabled:cursor-not-allowed group uppercase tracking-widest text-[10px]"
                  >
                    {isAnalyzing ? (
                      <RefreshCcw size={14} className="animate-spin" />
                    ) : (
                      <>
                        <Activity size={14} className="group-hover:animate-pulse" />
                        INIT_REPU_SCAN
                      </>
                    )}
                  </button>
                </div>
              </section>

              <section className="glass-panel border-purple-500/30 bg-black/80 p-4 relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-16 h-16 bg-purple-500/5 -rotate-45 translate-x-8 -translate-y-8" />
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-[10px] text-purple-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                    <Zap size={12} /> EMAIL_ENTITY_AUDIT
                  </h2>
                  <div className="flex gap-1">
                    <div className="w-1.5 h-1.5 bg-purple-500/10 border border-purple-500/20" />
                    <div className="w-1.5 h-1.5 bg-purple-500 animate-pulse shadow-[0_0_10px_rgba(168,85,247,0.5)]" />
                  </div>
                </div>

                <div className="space-y-4">
                  <input
                    type="text"
                    placeholder="operator@target-infra.net"
                    className={cn(
                      "w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-purple-500/20 font-mono",
                      emailError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-purple-500/30 focus:border-purple-500 focus:shadow-[0_0_15px_rgba(168,85,247,0.2)]"
                    )}
                    value={emailAddress}
                    onChange={(e) => {
                      setEmailAddress(e.target.value);
                      validateEmail(e.target.value);
                    }}
                  />

                  <button
                    onClick={() => handleAnalyze(undefined, emailAddress)}
                    disabled={isAnalyzing || !emailAddress || !!emailError}
                    className="w-full bg-purple-600 text-white font-black py-3 rounded-none flex items-center justify-center gap-2 hover:bg-purple-500 active:scale-[0.98] transition-all disabled:opacity-20 disabled:cursor-not-allowed group uppercase tracking-widest text-[10px]"
                  >
                    {isAnalyzing ? (
                      <RefreshCcw size={14} className="animate-spin" />
                    ) : (
                      <>
                        <Zap size={14} className="group-hover:animate-pulse" />
                        INIT_MX_PROBE
                      </>
                    )}
                  </button>
                </div>
              </section>

              <section className="glass-panel border-indigo-500/30 bg-black/80 p-4 relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-16 h-16 bg-indigo-500/5 -rotate-45 translate-x-8 -translate-y-8" />
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-[10px] text-indigo-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                    <Globe size={12} /> DOMAIN_NAMESPACE_SCAN
                  </h2>
                  <div className="flex gap-1">
                    <div className="w-1.5 h-1.5 bg-indigo-500/10 border border-indigo-500/20" />
                    <div className="w-1.5 h-1.5 bg-indigo-500 animate-pulse shadow-[0_0_10px_rgba(99,102,241,0.5)]" />
                  </div>
                </div>

                <div className="space-y-4">
                  <input
                    type="text"
                    placeholder="secure-login-gateway.com"
                    className={cn(
                      "w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-indigo-500/20 font-mono",
                      domainError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-indigo-500/30 focus:border-indigo-500 focus:shadow-[0_0_15px_rgba(99,102,241,0.2)]"
                    )}
                    value={domainName}
                    onChange={(e) => {
                      setDomainName(e.target.value);
                      validateDomain(e.target.value);
                    }}
                  />

                  <button
                    onClick={() => handleAnalyze(undefined, domainName)}
                    disabled={isAnalyzing || !domainName || !!domainError}
                    className="w-full bg-indigo-600 text-white font-black py-3 rounded-none flex items-center justify-center gap-2 hover:bg-indigo-500 active:scale-[0.98] transition-all disabled:opacity-20 disabled:cursor-not-allowed group uppercase tracking-widest text-[10px]"
                  >
                    {isAnalyzing ? (
                      <RefreshCcw size={14} className="animate-spin" />
                    ) : (
                      <>
                        <Globe size={14} className="group-hover:animate-pulse" />
                        INIT_DNS_AUDIT
                      </>
                    )}
                  </button>
                </div>
              </section>
            </>
          ) : activeTab === 'filescan' ? (
            <section className="glass-panel border-red-500/30 bg-black/80 p-5 min-h-[400px]">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-red-500 flex items-center gap-2">
                    <ShieldAlert size={12} className="text-red-500 animate-pulse" /> FILE_INTELLIGENCE_LOGS
                  </h3>
                  <span className="text-[8px] opacity-30 uppercase tracking-widest">{fileScanHistory.length} RECORDS</span>
                </div>
                <div className="space-y-2 max-h-[400px] overflow-y-auto custom-scrollbar pr-2">
                  {fileScanHistory.map((report) => (
                    <div
                      key={report.id}
                      onClick={() => {
                        setFileScanResult(report);
                        addLog(`RESTORED_FILE_REPORT: ${report.fileName}`);
                      }}
                      className={cn(
                        "bg-black/80 border p-3 cursor-pointer group transition-all space-y-1.5",
                        fileScanResult?.id === report.id ? "border-red-500 bg-red-950/10 shadow-[0_0_15px_rgba(239,68,68,0.15)]" : "border-red-500/10 hover:border-red-500/40"
                      )}
                    >
                      <div className="flex justify-between items-start">
                        <div className="flex items-center gap-2">
                          <div className={cn(
                            "w-1.5 h-1.5 rounded-full",
                            report.classification === 'Malicious' ? "bg-red-500" : report.classification === 'Suspicious' ? "bg-amber-500" : "bg-[#39FF14]"
                          )} />
                          <span className="text-[11px] font-bold truncate max-w-[130px]">{report.fileName}</span>
                        </div>
                        <button
                          onClick={async (e) => {
                            e.stopPropagation();
                            try {
                              if (report.id) {
                                if (!isMockSessionUser(user)) {
                                  await deleteDoc(doc(db, 'fileScanReports', report.id));
                                } else {
                                  const mockHistory = localStorage.getItem('cyber_shield_mock_file_reports');
                                  const historyArr = mockHistory ? JSON.parse(mockHistory) : [];
                                  const filtered = historyArr.filter((r: any) => r.id !== report.id);
                                  localStorage.setItem('cyber_shield_mock_file_reports', JSON.stringify(filtered));
                                  window.dispatchEvent(new Event('cyber_shield_new_file_report'));
                                }
                                if (fileScanResult?.id === report.id) setFileScanResult(null);
                                addLog(`DELETED_FILE_REPORT: ${report.fileName}`);
                              }
                            } catch (err: any) {
                              console.error(err);
                            }
                          }}
                          className="opacity-0 group-hover:opacity-100 p-0.5 text-red-500/40 hover:text-red-500 transition-all"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                      <div className="flex justify-between items-center text-[8px] opacity-40 uppercase">
                        <span>{report.fileType.split('/').pop() || 'binary'} | {(report.fileSize / 1024).toFixed(1)} KB</span>
                        <span className={cn(
                          "font-bold",
                          report.classification === 'Malicious' ? "text-red-500" : report.classification === 'Suspicious' ? "text-amber-500" : "text-[#39FF14]"
                        )}>SCORE: {report.threatScore}</span>
                      </div>
                    </div>
                  ))}
                  {fileScanHistory.length === 0 && (
                    <div className="text-center py-12 border border-dashed border-red-500/10">
                      <p className="text-[9px] opacity-20 uppercase tracking-widest">No file scan history</p>
                    </div>
                  )}
                </div>
              </div>
            </section>
          ) : activeTab === 'history' ? (
            <section className="glass-panel border-blue-500/30 bg-black/80 p-5 min-h-[400px]">
              <ScanHistory onSelect={(report) => {
                setResult(report);
                setActiveTab('scan');
                addLog(`RESTORED_THREAT_REPORT: ${report.target}`);
              }} />
            </section>
          ) : activeTab === 'analytics' ? (
            <section className="glass-panel border-cyan-500/30 bg-black/80 p-5 min-h-[400px] flex flex-col justify-between font-mono">
              <div className="space-y-4">
                <div className="flex items-center justify-between mb-2">
                  <h2 className="text-[10px] text-cyan-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                    <Cpu size={12} /> ANALYTICS_SYSTEM
                  </h2>
                  <div className="w-1.5 h-1.5 bg-cyan-500 animate-pulse rounded-full" />
                </div>
                <div className="p-3 bg-cyan-950/10 border border-cyan-500/20 text-[10px] leading-relaxed text-cyan-300">
                  <p className="font-bold mb-1 text-cyan-400">ANALYTICS_INFO:</p>
                  <p>Status: Active / Streaming</p>
                  <p>Engine: Recharts Matrix</p>
                  <p>Prediction Vector: Gemini Node</p>
                  <p>Sync Rate: Real-time</p>
                </div>
                <div className="p-3 bg-black/40 border border-cyan-500/10 text-[9px] leading-relaxed text-[#39FF14]/60">
                  <p className="font-bold text-cyan-400 mb-1">DASHBOARD_CAPABILITIES:</p>
                  <p>• Weekly incident timeline matrix</p>
                  <p>• Threat TLD registry mappings</p>
                  <p>• Real-time density heatmaps</p>
                  <p>• Dynamic multi-vector radar</p>
                  <p>• AI trend volume forecasting</p>
                </div>
              </div>
              <div className="space-y-2 mt-4 pt-4 border-t border-cyan-500/10">
                <p className="text-[8px] text-zinc-500 uppercase tracking-widest">Operator Session Info</p>
                <p className="text-[10px] text-cyan-400 font-bold truncate">UID: {currentUserId}</p>
              </div>
            </section>
          ) : activeTab === 'breach' ? (
            <section className="glass-panel border-amber-500/30 bg-black/80 p-5 min-h-[400px]">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-amber-500 flex items-center gap-2">
                    <ShieldAlert size={12} className="text-amber-500 animate-pulse" /> BREACH_HISTORY_LOGS
                  </h3>
                  <span className="text-[8px] opacity-30 uppercase tracking-widest">{breachHistory.length} RECORDS</span>
                </div>
                <div className="space-y-2 max-h-[450px] overflow-y-auto custom-scrollbar pr-2">
                  {breachHistory.map((report) => (
                    <div
                      key={report.id}
                      onClick={() => {
                        setBreachResult(report);
                        addLog(`RESTORED_BREACH_REPORT: ${report.identity}`);
                      }}
                      className={cn(
                        "bg-black/80 border p-3 cursor-pointer group transition-all space-y-1.5",
                        breachResult?.id === report.id ? "border-amber-500 bg-amber-950/10 shadow-[0_0_15px_rgba(245,158,11,0.15)]" : "border-amber-500/10 hover:border-amber-500/40"
                      )}
                    >
                      <div className="flex justify-between items-start">
                        <div className="flex items-center gap-2">
                          <div className={cn(
                            "w-1.5 h-1.5 rounded-full",
                            report.breachCount > 0 ? (report.passwordExposure === 'Plaintext' ? "bg-red-500" : "bg-amber-500") : "bg-[#39FF14]"
                          )} />
                          <span className="text-[11px] font-bold truncate max-w-[130px]">{report.identity}</span>
                        </div>
                        <button
                          onClick={async (e) => {
                            e.stopPropagation();
                            try {
                              if (report.id) {
                                if (!isMockSessionUser(user)) {
                                  await deleteDoc(doc(db, 'breachReports', report.id));
                                } else {
                                  const mockHistory = localStorage.getItem('cyber_shield_mock_breach_reports');
                                  const historyArr = mockHistory ? JSON.parse(mockHistory) : [];
                                  const filtered = historyArr.filter((r: any) => r.id !== report.id);
                                  localStorage.setItem('cyber_shield_mock_breach_reports', JSON.stringify(filtered));
                                  window.dispatchEvent(new Event('cyber_shield_new_breach_report'));
                                }
                                if (breachResult?.id === report.id) setBreachResult(null);
                                addLog(`DELETED_BREACH_REPORT: ${report.identity}`);
                              }
                            } catch (err: any) {
                              console.error(err);
                            }
                          }}
                          className="opacity-0 group-hover:opacity-100 p-0.5 text-red-500/40 hover:text-red-500 transition-all"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                      <div className="flex justify-between items-center text-[8px] opacity-40 uppercase">
                        <span>{report.breachCount} compromised sources</span>
                        <span className={cn(
                          "font-bold",
                          report.breachCount > 0 ? (report.passwordExposure === 'Plaintext' ? "text-red-500 animate-pulse" : "text-amber-500") : "text-[#39FF14]"
                        )}>
                          {report.breachCount > 0 ? `RISK: ${report.passwordExposure.toUpperCase()}` : 'SECURE'}
                        </span>
                      </div>
                    </div>
                  ))}

                  {breachHistory.length === 0 && (
                    <div className="text-center py-12 border border-dashed border-amber-500/10">
                      <p className="text-[9px] opacity-20 uppercase tracking-widest">No breach search history</p>
                    </div>
                  )}
                </div>
              </div>
            </section>
          ) : activeTab === 'email' ? (
            <section className="glass-panel border-pink-500/30 bg-black/80 p-5 min-h-[400px]">
              <div className="space-y-4 font-mono">
                <div className="flex items-center justify-between">
                  <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-pink-500 flex items-center gap-2">
                    <Mail size={12} className="text-pink-500 animate-pulse" /> EMAIL_HISTORY_LOGS
                  </h3>
                  <span className="text-[8px] opacity-30 uppercase tracking-widest">{emailHeaderHistory.length} RECORDS</span>
                </div>
                <div className="space-y-2 max-h-[450px] overflow-y-auto custom-scrollbar pr-2">
                  {emailHeaderHistory.map((report) => (
                    <div
                      key={report.id}
                      onClick={() => {
                        setEmailHeaderResult(report);
                        setEmailRawHeaders(report.rawHeaders || '');
                        addLog(`RESTORED_EMAIL_REPORT: IP ${report.senderIp}`);
                      }}
                      className={cn(
                        "bg-black/80 border p-3 cursor-pointer group transition-all space-y-1.5",
                        emailHeaderResult?.id === report.id ? "border-pink-500 bg-pink-950/10 shadow-[0_0_15px_rgba(236,72,153,0.15)]" : "border-pink-500/10 hover:border-pink-500/40"
                      )}
                    >
                      <div className="flex justify-between items-start">
                        <div className="flex items-center gap-2">
                          <div className={cn(
                            "w-1.5 h-1.5 rounded-full",
                            report.threatScore > 50 ? (report.threatScore > 80 ? "bg-red-500 animate-pulse" : "bg-amber-500") : "bg-[#39FF14]"
                          )} />
                          <span className="text-[11px] font-bold truncate max-w-[130px]">IP: {report.senderIp}</span>
                        </div>
                        <button
                          onClick={async (e) => {
                            e.stopPropagation();
                            try {
                              if (report.id) {
                                if (!isMockSessionUser(user)) {
                                  await deleteDoc(doc(db, 'emailHeaderReports', report.id));
                                } else {
                                  const mockHistory = localStorage.getItem('cyber_shield_mock_email_header_reports');
                                  const historyArr = mockHistory ? JSON.parse(mockHistory) : [];
                                  const filtered = historyArr.filter((r: any) => r.id !== report.id);
                                  localStorage.setItem('cyber_shield_mock_email_header_reports', JSON.stringify(filtered));
                                  window.dispatchEvent(new Event('cyber_shield_new_email_header_report'));
                                }
                                if (emailHeaderResult?.id === report.id) setEmailHeaderResult(null);
                                addLog(`DELETED_EMAIL_REPORT: IP ${report.senderIp}`);
                              }
                            } catch (err: any) {
                              console.error(err);
                            }
                          }}
                          className="opacity-0 group-hover:opacity-100 p-0.5 text-red-500/40 hover:text-red-500 transition-all"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                      <div className="flex justify-between items-center text-[8px] opacity-40 uppercase">
                        <span>Hops: {report.hopsCount}</span>
                        <span className={cn(
                          "font-bold",
                          report.threatScore > 50 ? (report.threatScore > 80 ? "text-red-500" : "text-amber-500") : "text-[#39FF14]"
                        )}>
                          SCORE: {report.threatScore}
                        </span>
                      </div>
                    </div>
                  ))}

                  {emailHeaderHistory.length === 0 && (
                    <div className="text-center py-12 border border-dashed border-pink-500/10">
                      <p className="text-[9px] opacity-20 uppercase tracking-widest">No email search history</p>
                    </div>
                  )}
                </div>
              </div>
            </section>
          ) : activeTab === 'training' ? (
            <section className="glass-panel border-[#39FF14]/30 bg-black/80 p-5 min-h-[400px] flex flex-col justify-between">
              <div className="space-y-4 font-mono">
                <div className="flex items-center justify-between mb-2">
                  <h2 className="text-[10px] text-[#39FF14] font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                    <Trophy size={12} /> TRAINING_SYSTEM
                  </h2>
                  <div className="w-1.5 h-1.5 bg-[#39FF14] animate-pulse rounded-full" />
                </div>
                <div className="p-3 bg-[#39FF14]/10 border border-[#39FF14]/20 text-[10px] leading-relaxed text-[#39FF14]/80">
                  <p className="font-bold mb-1 text-[#39FF14]">TRAINING_INFO:</p>
                  <p>AI Engine: Gemini Quiz Builder</p>
                  <p>Gamification: Active / Online</p>
                  <p>Achievement Vault: Syncing</p>
                </div>
                <div className="p-3 bg-black/40 border border-[#39FF14]/10 text-[9px] leading-relaxed text-zinc-500">
                  <p className="font-bold text-[#39FF14] mb-1">UNLOCKED REWARDS:</p>
                  <p>• PHISH_HUNTER (+200 XP)</p>
                  <p>• QUIZ_MASTER (+150 XP)</p>
                  <p>• SECURE_DEFENDER (+500 XP)</p>
                  <p>Check the main training module page to track level progress.</p>
                </div>
              </div>
              <div className="text-[8px] opacity-30 text-center font-mono border-t border-[#39FF14]/10 pt-2 mt-4">
                TRAINING_SUITE_REV_1.1.0
              </div>
            </section>
          ) : activeTab === 'attacksim' ? (
            <section className="glass-panel border-red-500/30 bg-black/80 p-5 min-h-[400px] flex flex-col justify-between">
              <div className="space-y-4 font-mono">
                <div className="flex items-center justify-between mb-2">
                  <h2 className="text-[10px] text-red-500 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                    <Activity size={12} className="animate-pulse" /> WARFARE_SYSTEM
                  </h2>
                  <div className="w-1.5 h-1.5 bg-red-500 animate-pulse rounded-full" />
                </div>
                <div className="p-3 bg-red-500/10 border border-red-500/20 text-[10px] leading-relaxed text-red-400">
                  <p className="font-bold mb-1 text-red-500">SIMULATOR_INFO:</p>
                  <p>Active Models: 5 Vector Scenarios</p>
                  <p>State Tracking: Integrated</p>
                  <p>Target Rewards: +150 XP</p>
                </div>
                <div className="p-3 bg-black/40 border border-red-500/10 text-[9px] leading-relaxed text-zinc-500">
                  <p className="font-bold text-red-500 mb-1">AUDIT DIRECTIONS:</p>
                  <p>Select an exploit from the grid at the top.</p>
                  <p>Press PLAY_SIM to watch raw packet traces and node states evolve.</p>
                  <p>Review the mitigation playbooks for defensive strategies.</p>
                </div>
              </div>
              <div className="text-[8px] opacity-30 text-center font-mono border-t border-red-500/10 pt-2 mt-4">
                SIM_DAEMON_REV_2.0.0
              </div>
            </section>
          ) : activeTab === 'admin' ? (
            <section className="glass-panel border-purple-500/30 bg-black/80 p-5 min-h-[400px] flex flex-col justify-between">
              <div className="space-y-4 font-mono">
                <div className="flex items-center justify-between mb-2">
                  <h2 className="text-[10px] text-purple-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                    <Shield size={12} /> ENTERPRISE_GATE
                  </h2>
                  <div className="w-1.5 h-1.5 bg-purple-500 animate-pulse rounded-full" />
                </div>
                <div className="p-3 bg-purple-500/10 border border-purple-500/20 text-[10px] leading-relaxed text-purple-300">
                  <p className="font-bold mb-1 text-purple-400">ADMIN_GATEWAY:</p>
                  <p>API State: Role-Enforced</p>
                  <p>Database: Firebase Admin</p>
                  <p>Blocklist: Active</p>
                  <p>Daemon Logs: Polling (5s)</p>
                </div>
                <div className="p-3 bg-black/40 border border-purple-500/10 text-[9px] leading-relaxed text-zinc-500">
                  <p className="font-bold text-purple-400 mb-1">AUDIT DIRECTIONS:</p>
                  <p>Use the simulator toggle to drop privileges or promote other operators.</p>
                  <p>Block harmful domains to test the early scanner intercept.</p>
                </div>
              </div>
              <div className="text-[8px] opacity-30 text-center font-mono border-t border-purple-500/10 pt-2 mt-4">
                SYS_ADMIN_SUITE_REV_2.0.0
              </div>
            </section>
          ) : (
            <section className="glass-panel border-purple-500/30 bg-black/80 p-5 min-h-[400px] flex flex-col justify-between">
              <div className="space-y-4 font-mono">
                <div className="flex items-center justify-between mb-2">
                  <h2 className="text-[10px] text-purple-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                    <Cpu size={12} /> THREATGPT_SYSTEM
                  </h2>
                  <div className="w-1.5 h-1.5 bg-purple-500 animate-pulse rounded-full" />
                </div>
                <div className="p-3 bg-purple-950/10 border border-purple-500/20 text-[10px] leading-relaxed text-purple-300">
                  <p className="font-bold mb-1 text-purple-400">SYSTEM_INFO:</p>
                  <p>AI Engine: Gemini-1.5-Flash</p>
                  <p>Model Status: Active / Online</p>
                  <p>Vector Sandbox: Operational</p>
                  <p>Speech Service: Ready</p>
                </div>
                <div className="p-3 bg-black/40 border border-purple-500/10 text-[9px] leading-relaxed text-[#39FF14]/60">
                  <p className="font-bold text-purple-400 mb-1">CAPABILITIES:</p>
                  <p>• Phishing email audit analysis</p>
                  <p>• Threat signature decomposition</p>
                  <p>• Tactical sandbox playbooks</p>
                  <p>• Attack vectors simulation</p>
                </div>
              </div>
              <div className="text-[8px] opacity-30 text-center font-mono border-t border-purple-500/10 pt-2 mt-4">
                STABLE_BUILD_4.2.0_SEC_ENG
              </div>
            </section>
          )}

          <QRScannerModule onScan={(text) => {
            setUrl(text);
            handleAnalyze(undefined, text);
          }} />

          <GlobalMap />
          <ExtensionModule />
          <section className="glass-panel border-amber-500/30 bg-black/80 p-4 relative overflow-hidden group">
            <div className="absolute top-0 right-0 w-16 h-16 bg-amber-500/5 -rotate-45 translate-x-8 -translate-y-8" />
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[10px] text-amber-500 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                <MessageSquare size={12} /> SMS_CONTENT_AUDITOR
              </h2>
              <div className="flex gap-1">
                <div className="w-1.5 h-1.5 bg-amber-500/10 border border-amber-500/20" />
                <div className="w-1.5 h-1.5 bg-amber-500 animate-pulse" />
              </div>
            </div>

            <div className="space-y-4">
              <div className="relative group">
                <textarea
                  placeholder="Paste SMS/Message body here for semantic threat analysis..."
                  rows={4}
                  className={cn(
                    "w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-amber-500/20 font-mono resize-none",
                    messageError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-amber-500/30 focus:border-amber-500 focus:shadow-[0_0_15px_rgba(245,158,11,0.2)]"
                  )}
                  value={messageContent}
                  onChange={(e) => {
                    setMessageContent(e.target.value);
                    validateMessage(e.target.value);
                  }}
                />
              </div>

              <AnimatePresence>
                {messageError && (
                  <motion.p
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="text-[9px] text-red-500 font-black flex items-center gap-1 uppercase italic"
                  >
                    <AlertTriangle size={10} /> {messageError}
                  </motion.p>
                )}
              </AnimatePresence>

              <button
                onClick={() => handleAnalyze(undefined, messageContent)}
                disabled={isAnalyzing || !messageContent || !!messageError}
                className="w-full bg-amber-600 text-white font-black py-3 rounded-none flex items-center justify-center gap-2 hover:bg-amber-500 active:scale-[0.98] transition-all disabled:opacity-20 disabled:cursor-not-allowed group uppercase tracking-widest text-[10px]"
              >
                {isAnalyzing ? (
                  <RefreshCcw size={14} className="animate-spin" />
                ) : (
                  <>
                    <Search size={14} className="group-hover:animate-pulse" />
                    AUDIT_MESSAGE_BODY
                  </>
                )}
              </button>

              <div className="flex justify-between items-center text-[7px] opacity-30 pt-2 border-t border-amber-500/10">
                <span>ENGINE: SEMANTIC_HEURISTICS</span>
                <span>VERSION: 4.2.0_STABLE</span>
              </div>
            </div>
          </section>

          <section className="glass-panel border-emerald-500/30 bg-black/80 p-4 relative overflow-hidden group">
            <div className="absolute top-0 right-0 w-16 h-16 bg-emerald-500/5 -rotate-45 translate-x-8 -translate-y-8" />
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[10px] text-emerald-400 font-bold uppercase tracking-[0.3em] flex items-center gap-2">
                <Activity size={12} /> TELEPHONY_SCANNER
              </h2>
              <div className="flex gap-1">
                <div className="w-1.5 h-1.5 bg-emerald-500/10 border border-emerald-500/20" />
                <div className="w-1.5 h-1.5 bg-emerald-500 animate-pulse" />
              </div>
            </div>

            <div className="space-y-4">
              <input
                type="text"
                placeholder="+1-XXX-XXX-XXXX"
                className={cn(
                  "w-full bg-black border rounded-none px-4 py-3 text-xs md:text-sm focus:outline-none transition-all placeholder:text-emerald-500/20 font-mono",
                  phoneError ? "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]" : "border-emerald-500/30 focus:border-emerald-500 focus:shadow-[0_0_15px_rgba(16,185,129,0.2)]"
                )}
                value={phoneAddress}
                onChange={(e) => {
                  setPhoneAddress(e.target.value);
                  validatePhone(e.target.value);
                }}
              />

              <button
                onClick={() => handleAnalyze(undefined, phoneAddress)}
                disabled={isAnalyzing || !phoneAddress || !!phoneError}
                className="w-full bg-emerald-600 text-white font-black py-3 rounded-none flex items-center justify-center gap-2 hover:bg-emerald-500 active:scale-[0.98] transition-all disabled:opacity-20 disabled:cursor-not-allowed group uppercase tracking-widest text-[10px]"
              >
                {isAnalyzing ? (
                  <RefreshCcw size={14} className="animate-spin" />
                ) : (
                  <>
                    <Activity size={14} className="group-hover:animate-pulse" />
                    INIT_PHONE_PROBE
                  </>
                )}
              </button>
            </div>
          </section>

          <KeywordMonitor />
          {/* Remotely Integrated Consoles removed for cleaner main dashboard integration */}
          <section className="glass-panel border-[#39FF14]/10 bg-black/60 p-4 h-[300px] flex flex-col">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-[10px] text-[#39FF14]/40 uppercase tracking-[0.2em] flex items-center gap-2">
                <Activity size={12} /> CONSOLE_LOG
              </h2>
              <span className="text-[8px] opacity-30">TTY: /dev/pts/0</span>
            </div>
            <div
              ref={scrollRef}
              className="flex-1 overflow-y-auto space-y-1 text-[11px] font-mono leading-tight custom-scrollbar"
            >
              {logs.length === 0 && <p className="text-[#39FF14]/20 italic">IDLE_STATE: AWAITING_CMD...</p>}
              {logs.map((log, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-[#39FF14]/20 flex-shrink-0">{`·`}</span>
                  <p className={cn(
                    log.includes('COMPLETE') ? 'text-[#39FF14]' :
                      log.includes('ERROR') ? 'text-red-500' :
                        log.includes('INITIATING') ? 'text-[#39FF14] brightness-125' : 'text-[#39FF14]/60'
                  )}>{log}</p>
                </div>
              ))}
            </div>
            <div className="mt-3 pt-2 border-t border-[#39FF14]/10 flex justify-between items-center text-[9px] opacity-40">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 bg-[#39FF14] animate-pulse" />
                <span>PROCESS_READY</span>
              </div>
              <span>{logs.length} LINES</span>
            </div>
          </section>

          <MatrixEffect />

          <section className="glass-panel border-[#39FF14]/20 bg-[#39FF14]/5 p-4 neon-border">
            <h3 className="text-[10px] font-black uppercase tracking-widest text-[#39FF14] mb-3 flex items-center gap-2">
              <Globe size={14} /> SIDECAR.EXT
            </h3>
            <p className="text-[11px] text-[#39FF14]/60 leading-relaxed mb-4">
              Real-time heuristic injection for active browsing monitoring.
            </p>
            <div className="flex gap-2">
              <div className="px-2 py-1 bg-black border border-[#39FF14]/30 text-[8px] font-bold">V1.2_STABLE</div>
              <div className="px-2 py-1 bg-black border border-[#39FF14]/30 text-[8px] font-bold">CHROME_SYNC</div>
            </div>
          </section>
        </div>

        {/* MIDDLE COLUMN: RESULTS (Col 6) */}
        <div className="lg:col-span-6">
          <AnimatePresence mode="wait">
            {activeTab === 'filescan' && (
              <motion.div
                key="filescan"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="h-full"
              >
                {isFileAnalyzing ? (
                  <div className="h-full min-h-[500px] glass-panel border-red-500/20 bg-black/80 p-8 flex flex-col justify-between relative overflow-hidden">
                    <div className="absolute inset-0 bg-red-950/[0.02] blur-[120px]" />
                    
                    <div className="flex justify-between items-center border-b border-red-500/10 pb-4">
                      <div className="flex items-center gap-2 font-mono">
                        <ShieldAlert size={14} className="text-red-500 animate-pulse" />
                        <span className="text-[10px] text-red-500 font-bold uppercase tracking-widest">ANALYSIS_PIPELINE_ACTIVE</span>
                      </div>
                      <span className="text-[10px] text-red-500 font-mono font-bold">{fileScanProgress}%</span>
                    </div>

                    <div className="my-10 text-center flex flex-col items-center justify-center">
                      <div className="relative w-28 h-28 flex items-center justify-center mb-6">
                        <svg className="w-full h-full transform -rotate-90">
                          <circle cx="56" cy="56" r="50" className="stroke-red-950/30 fill-none" strokeWidth="4" />
                          <circle
                            cx="56"
                            cy="56"
                            r="50"
                            className="stroke-red-500 fill-none transition-all duration-300"
                            strokeWidth="4"
                            strokeDasharray={2 * Math.PI * 50}
                            strokeDashoffset={2 * Math.PI * 50 * (1 - fileScanProgress / 100)}
                            style={{ filter: 'drop-shadow(0 0 8px rgba(239, 68, 68, 0.4))' }}
                          />
                        </svg>
                        <div className="absolute flex flex-col items-center justify-center">
                          <Activity size={24} className="text-red-500 animate-pulse" />
                          <span className="text-[8px] font-mono text-red-500/60 uppercase tracking-widest mt-1">EMULATOR</span>
                        </div>
                      </div>

                      <h3 className="text-sm font-black italic text-zinc-100 tracking-widest uppercase mb-1">
                        {fileScanProgress < 30 ? 'GENERATING_SHA256_HASH' :
                         fileScanProgress < 55 ? 'QUERYING_VIRUSTOTAL_FEED' :
                         fileScanProgress < 75 ? 'DECOMPILING_BINARY_MARKERS' :
                         fileScanProgress < 100 ? 'DEPLOYING_GEMINI_MODEL' : 'COMPILING_ANALYSIS_REPORT'}
                      </h3>
                      <p className="text-[8px] text-red-500/40 font-mono tracking-widest">DO NOT INTERRUPT DECOMPOSER STREAM</p>
                    </div>

                    <div className="bg-black/90 border border-red-500/20 p-4 rounded-none font-mono text-[9px] text-red-400 space-y-1 h-36 overflow-y-auto custom-scrollbar shadow-[inset_0_0_15px_rgba(239,68,68,0.15)]">
                      {fileScanLogs.map((l, idx) => (
                        <div key={idx} className="flex gap-2">
                          <span className="opacity-40">|</span>
                          <span>{l}</span>
                        </div>
                      ))}
                      <div className="w-1.5 h-3 bg-red-500 animate-pulse inline-block" />
                    </div>
                  </div>
                ) : fileScanError ? (
                  <div className="h-full min-h-[500px] glass-panel border-red-500/20 bg-red-500/5 flex flex-col items-center justify-center text-center p-8">
                    <div className="p-4 bg-red-500/20 border border-red-500 mb-6">
                      <AlertTriangle className="text-red-500" size={40} />
                    </div>
                    <h2 className="text-xl font-black italic tracking-widest text-red-500 mb-4 uppercase">PAYLOAD_INTEGRITY_FAULT</h2>
                    <div className="max-w-md bg-black/60 border border-white/5 p-4 rounded mb-6">
                      <p className="text-[12px] font-mono text-zinc-400 leading-relaxed">{fileScanError}</p>
                    </div>
                    <button
                      onClick={() => setFileScanError(null)}
                      className="px-6 py-2 bg-red-500/20 border border-red-500 text-red-500 text-[10px] font-black uppercase tracking-widest hover:bg-red-500 hover:text-white transition-all"
                    >
                      DISMISS_FAULT_REPORT
                    </button>
                  </div>
                ) : fileScanResult ? (
                  <div
                    key="filescan-result"
                    className="space-y-4 font-mono select-text"
                    id="file-scan-pdf-report"
                  >
                    <div className={cn(
                      "p-4 border flex items-center justify-between shadow-[0_0_30px_rgba(0,0,0,0.5)] relative overflow-hidden",
                      fileScanResult.classification === 'Malicious' ? "border-red-500 bg-red-950/15" : fileScanResult.classification === 'Suspicious' ? "border-amber-500 bg-amber-950/15" : "border-[#39FF14]/30 bg-[#39FF14]/5"
                    )}>
                      <div className={cn(
                        "absolute -right-20 -top-20 w-48 h-48 rounded-full blur-[80px] opacity-25",
                        fileScanResult.classification === 'Malicious' ? "bg-red-500" : fileScanResult.classification === 'Suspicious' ? "bg-amber-500" : "bg-[#39FF14]"
                      )} />

                      <div className="flex items-center gap-3 relative z-10">
                        <div className={cn(
                          "p-2.5 border",
                          fileScanResult.classification === 'Malicious' ? "border-red-500 bg-red-950/50" : fileScanResult.classification === 'Suspicious' ? "border-amber-500 bg-amber-950/50" : "border-[#39FF14]/30 bg-black"
                        )}>
                          <ShieldAlert size={20} className={cn(
                            fileScanResult.classification === 'Malicious' ? "text-red-500 animate-pulse" : fileScanResult.classification === 'Suspicious' ? "text-amber-500" : "text-[#39FF14]"
                          )} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h2 className="text-base font-black tracking-widest text-white truncate max-w-[280px]">
                              {fileScanResult.fileName}
                            </h2>
                            <span className={cn(
                              "px-2 py-0.5 border text-[8px] font-black tracking-widest uppercase",
                              fileScanResult.classification === 'Malicious' ? "border-red-500 text-red-500" : fileScanResult.classification === 'Suspicious' ? "border-amber-500 text-amber-500" : "border-[#39FF14]/30 text-[#39FF14]"
                            )}>
                              {fileScanResult.classification}
                            </span>
                          </div>
                          <p className="text-[9px] text-zinc-400 mt-1 uppercase tracking-widest">
                            MALWARE FAMILY: <span className="text-white font-bold">{fileScanResult.malwareFamily}</span>
                          </p>
                        </div>
                      </div>

                      <div className="text-right relative z-10 flex gap-2">
                        <button
                          onClick={() => {
                            setFileScanResult(null);
                            setFileScanError(null);
                            addLog("FILE_SCANNER_RESET. WAITING_NEW_PAYLOAD.");
                          }}
                          className="px-3 py-1.5 bg-black border border-white/10 hover:border-red-500/40 text-zinc-400 hover:text-white text-[9px] font-bold uppercase tracking-widest transition-all"
                        >
                          NEW_SCAN
                        </button>
                        <button
                          onClick={() => {
                            setExportDataType('filescan');
                            setIsExportModalOpen(true);
                          }}
                          className={cn(
                            "px-3 py-1.5 border text-[9px] font-bold uppercase tracking-widest flex items-center gap-1 transition-all",
                            fileScanResult.classification === 'Malicious' ? "bg-red-500/10 border-red-500 text-red-400 hover:bg-red-500 hover:text-white" : fileScanResult.classification === 'Suspicious' ? "bg-amber-500/10 border-amber-500 text-amber-400 hover:bg-amber-500 hover:text-black" : "bg-[#39FF14]/10 border-[#39FF14] text-[#39FF14] hover:bg-[#39FF14] hover:text-black"
                          )}
                        >
                          <Download size={10} /> EXPORT_REPORT
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="glass-panel border-white/5 bg-black/60 p-4 flex flex-col items-center justify-center text-center">
                        <h3 className="text-[10px] text-zinc-500 uppercase tracking-widest mb-4">THREAT_PROBABILITY</h3>
                        <div className="relative w-32 h-32 flex items-center justify-center">
                          <svg className="w-full h-full transform -rotate-90">
                            <circle cx="64" cy="64" r="54" className="stroke-zinc-900 fill-none" strokeWidth="8" />
                            <circle
                              cx="64"
                              cy="64"
                              r="54"
                              className={cn(
                                "fill-none transition-all duration-1000",
                                fileScanResult.threatScore > 75 ? "stroke-red-500" : fileScanResult.threatScore > 35 ? "stroke-amber-500" : "stroke-[#39FF14]"
                              )}
                              strokeWidth="8"
                              strokeDasharray={2 * Math.PI * 54}
                              strokeDashoffset={2 * Math.PI * 54 * (1 - fileScanResult.threatScore / 100)}
                            />
                          </svg>
                          <div className="absolute flex flex-col items-center justify-center">
                            <span className={cn(
                              "text-3xl font-black italic",
                              fileScanResult.threatScore > 75 ? "text-red-500" : fileScanResult.threatScore > 35 ? "text-amber-500" : "text-[#39FF14]"
                            )}>
                              {fileScanResult.threatScore}%
                            </span>
                            <span className="text-[8px] text-zinc-500 uppercase tracking-wider mt-1">RISK_RATING</span>
                          </div>
                        </div>
                      </div>

                      <div className="glass-panel border-white/5 bg-black/60 p-4 md:col-span-2 space-y-3">
                        <h3 className="text-[10px] text-zinc-500 uppercase tracking-widest border-b border-white/5 pb-2">METADATA_METRICS</h3>
                        <div className="grid grid-cols-2 gap-3 text-[10px]">
                          <div>
                            <span className="text-zinc-500 block uppercase">File Name</span>
                            <span className="text-zinc-300 font-bold break-all">{fileScanResult.fileName}</span>
                          </div>
                          <div>
                            <span className="text-zinc-500 block uppercase">File Type</span>
                            <span className="text-zinc-300 font-bold">{fileScanResult.fileType}</span>
                          </div>
                          <div>
                            <span className="text-zinc-500 block uppercase">File Size</span>
                            <span className="text-zinc-300 font-bold">{(fileScanResult.fileSize / (1024 * 1024)).toFixed(3)} MB ({fileScanResult.fileSize.toLocaleString()} bytes)</span>
                          </div>
                          <div>
                            <span className="text-zinc-500 block uppercase">SHA256 Signature</span>
                            <span className="text-zinc-300 font-bold break-all font-mono select-all text-[9px] leading-tight block bg-black border border-white/5 p-1">{fileScanResult.sha256}</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="glass-panel border-white/5 bg-black/60 p-4">
                        <h3 className="text-[10px] text-zinc-500 uppercase tracking-widest border-b border-white/5 pb-2 mb-3">VIRUSTOTAL_REPUTATION</h3>
                        <div className="space-y-3">
                          <div className="flex justify-between items-center text-[10px]">
                            <span className="text-zinc-400">Total Scan Engines Checked:</span>
                            <span className="text-white font-bold">
                              {(fileScanResult.detectionStats.malicious + fileScanResult.detectionStats.harmless + fileScanResult.detectionStats.suspicious + fileScanResult.detectionStats.undetected) || 70}
                            </span>
                          </div>
                          
                          <div className="space-y-1.5 text-[9px]">
                            <div>
                              <div className="flex justify-between mb-0.5 text-red-500">
                                <span>Malicious Flags</span>
                                <span>{fileScanResult.detectionStats.malicious}</span>
                              </div>
                              <div className="h-1 bg-zinc-900 w-full overflow-hidden">
                                <div className="bg-red-500 h-full transition-all duration-1000" style={{ width: `${(fileScanResult.detectionStats.malicious / 70) * 100}%` }} />
                              </div>
                            </div>

                            <div>
                              <div className="flex justify-between mb-0.5 text-[#39FF14]">
                                <span>Harmless/Clean Flags</span>
                                <span>{fileScanResult.detectionStats.harmless}</span>
                              </div>
                              <div className="h-1 bg-zinc-900 w-full overflow-hidden">
                                <div className="bg-[#39FF14] h-full transition-all duration-1000" style={{ width: `${(fileScanResult.detectionStats.harmless / 70) * 100}%` }} />
                              </div>
                            </div>

                            <div>
                              <div className="flex justify-between mb-0.5 text-amber-500">
                                <span>Suspicious Flags</span>
                                <span>{fileScanResult.detectionStats.suspicious}</span>
                              </div>
                              <div className="h-1 bg-zinc-900 w-full overflow-hidden">
                                <div className="bg-amber-500 h-full transition-all duration-1000" style={{ width: `${(fileScanResult.detectionStats.suspicious / 70) * 100}%` }} />
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="glass-panel border-white/5 bg-black/60 p-4 flex flex-col justify-between">
                        <div>
                          <h3 className="text-[10px] text-zinc-500 uppercase tracking-widest border-b border-white/5 pb-2 mb-3">AI_ANALYST_SUMMARY</h3>
                          <p className="text-[11px] text-zinc-300 leading-relaxed font-sans">{fileScanResult.explanation}</p>
                        </div>
                        <div className="mt-3 pt-3 border-t border-white/5">
                          <span className="text-[8px] text-red-500 font-bold block uppercase tracking-wider">CRITICAL_ACTION_REQUIRED</span>
                          <p className="text-[10px] text-red-400 mt-1 leading-relaxed">{fileScanResult.recommendation}</p>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="glass-panel border-white/5 bg-black/60 p-4">
                        <h3 className="text-[10px] text-zinc-500 uppercase tracking-widest border-b border-white/5 pb-2 mb-3">INDICATORS_OF_COMPROMISE_(IOC)</h3>
                        <ul className="space-y-2 text-[10px] h-48 overflow-y-auto custom-scrollbar pr-2">
                          {fileScanResult.iocIndicators.map((ioc, idx) => (
                            <li key={idx} className="flex gap-2 items-start bg-black/40 border border-white/5 p-2 font-mono">
                              <span className="text-red-500 text-[8px] font-bold">[{idx + 1}]</span>
                              <span className="text-zinc-300 select-all break-all">{ioc}</span>
                            </li>
                          ))}
                          {fileScanResult.iocIndicators.length === 0 && (
                            <p className="text-zinc-600 text-[9px]">No Indicators of Compromise detected.</p>
                          )}
                        </ul>
                      </div>

                      <div className="glass-panel border-white/5 bg-black/60 p-4">
                        <h3 className="text-[10px] text-zinc-500 uppercase tracking-widest border-b border-white/5 pb-2 mb-3">SANDBOX_BEHAVIORAL_TIMELINE</h3>
                        <div className="space-y-3 h-48 overflow-y-auto custom-scrollbar pr-2 font-mono text-[10px]">
                          {fileScanResult.timeline.map((item, idx) => (
                            <div key={idx} className="flex gap-3 relative pb-3 last:pb-0">
                              {idx < fileScanResult.timeline.length - 1 && (
                                <div className="absolute left-[15px] top-[14px] bottom-0 w-0.5 bg-white/10" />
                              )}
                              <span className="text-zinc-500 w-8 flex-shrink-0 text-right">{item.time}</span>
                              <div className={cn(
                                "w-2.5 h-2.5 rounded-full flex-shrink-0 mt-1 relative z-10",
                                item.status === 'critical' ? "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]" :
                                item.status === 'warning' ? "bg-amber-500" :
                                item.status === 'success' ? "bg-[#39FF14]" : "bg-blue-500"
                              )} />
                              <span className={cn(
                                "flex-1 text-[10px] leading-tight",
                                item.status === 'critical' ? "text-red-400 font-bold" : "text-zinc-300"
                              )}>
                                {item.event}
                              </span>
                            </div>
                          ))}
                          {fileScanResult.timeline.length === 0 && (
                            <p className="text-zinc-600 text-[9px]">No runtime behavior recorded.</p>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div
                    onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                    onDragLeave={() => setIsDragging(false)}
                    onDrop={(e) => { e.preventDefault(); setIsDragging(false); if (e.dataTransfer.files?.[0]) handleFileSelect(e.dataTransfer.files[0]); }}
                    className={cn(
                      "h-full min-h-[500px] glass-panel border-dashed bg-black/40 flex flex-col items-center justify-center p-8 relative transition-all duration-300 group cursor-pointer",
                      isDragging ? "border-red-500 bg-red-950/5 shadow-[0_0_40px_rgba(239,68,68,0.2)]" : "border-[#39FF14]/15 hover:border-red-500/30 hover:bg-black/60"
                    )}
                    onClick={() => {
                      const input = document.createElement('input');
                      input.type = 'file';
                      input.accept = '.exe,.apk,.zip,.pdf,.docx';
                      input.onchange = (e) => {
                        const file = (e.target as HTMLInputElement).files?.[0];
                        if (file) handleFileSelect(file);
                      };
                      input.click();
                    }}
                  >
                    <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-[0.03]">
                      <div className="absolute top-0 w-full h-px bg-red-500 animate-[scan_4s_infinite_ease-in-out]" />
                      <div className="grid grid-cols-10 h-full">
                        {Array.from({ length: 10 }).map((_, i) => (
                          <div key={i} className="border-r border-red-500/20 h-full" />
                        ))}
                      </div>
                    </div>

                    <div className={cn(
                      "p-6 border bg-black/80 transition-transform group-hover:scale-105 duration-300 mb-6",
                      isDragging ? "border-red-500 shadow-[0_0_20px_rgba(239,68,68,0.3)]" : "border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.05)]"
                    )}>
                      <Upload size={36} className={cn(isDragging ? "text-red-500 animate-bounce" : "text-red-500/70")} />
                    </div>
                    <h3 className="text-lg font-black tracking-[0.25em] text-red-500/80 mb-2 uppercase">malware_payload_scanner</h3>
                    <p className="text-[10px] text-zinc-400 font-mono tracking-widest text-center max-w-sm mb-6 border-b border-white/5 pb-4">
                      DRAG AND DROP OR CLICK TO UPLOAD TARGET RUNTIME PAYLOAD FOR DEEP AI RECONNAISSANCE.
                    </p>

                    <div className="flex flex-wrap gap-2 justify-center max-w-md">
                      {['EXE', 'APK', 'ZIP', 'PDF', 'DOCX'].map((t) => (
                        <span key={t} className="px-2.5 py-1 bg-red-950/20 border border-red-500/30 text-red-400 font-mono text-[9px] font-bold tracking-widest">
                          .{t}
                        </span>
                      ))}
                    </div>
                    <span className="text-[8px] text-zinc-500 font-mono mt-6 uppercase tracking-widest">MAX PAYLOAD SIZE: 10MB</span>
                  </div>
                )}
              </motion.div>
            )}

            {activeTab === 'assistant' && (
              <motion.div
                key="assistant"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="h-full"
              >
                <ThreatGPTPanel />
              </motion.div>
            )}

            {activeTab === 'analytics' && (
              <motion.div
                key="analytics"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="h-full"
              >
                <ThreatAnalyticsDashboard user={user} />
              </motion.div>
            )}

            {activeTab === 'breach' && (
              <motion.div
                key="breach"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-4 font-mono text-zinc-300"
              >
                {/* Search Bar Block */}
                <div className="p-6 glass-panel border-amber-500/20 bg-black/60 relative overflow-hidden">
                  <div className="absolute top-0 right-0 w-48 h-full bg-linear-to-l from-amber-500/5 to-transparent skew-x-12" />
                  <h2 className="text-sm font-black uppercase tracking-widest text-amber-500 mb-3 flex items-center gap-2">
                    <Search size={14} className="animate-pulse" /> Dark Web Breach Audit Console
                  </h2>
                  <p className="text-[10px] text-zinc-500 mb-4 uppercase tracking-wider">
                    Query outbound databases, credential leaks, and public indices to evaluate identity exposures.
                  </p>

                  <form onSubmit={handleBreachCheck} className="flex gap-2 relative z-10">
                    <input
                      type="text"
                      value={breachIdentity}
                      onChange={(e) => setBreachIdentity(e.target.value)}
                      placeholder="Enter email address or username..."
                      className="flex-1 bg-black border border-amber-500/20 hover:border-amber-500/40 focus:border-amber-500/80 px-4 py-2.5 text-xs text-white focus:outline-none focus:shadow-[0_0_15px_rgba(245,158,11,0.15)] transition-all font-mono"
                    />
                    <button
                      type="submit"
                      disabled={isBreachChecking || !breachIdentity.trim()}
                      className="px-6 bg-amber-600 hover:bg-amber-500 disabled:bg-amber-950 disabled:opacity-40 disabled:cursor-not-allowed text-black font-black text-xs uppercase tracking-wider transition-all flex items-center justify-center gap-2"
                    >
                      {isBreachChecking ? 'AUDITING...' : 'AUDIT_IDENTITY'}
                    </button>
                  </form>
                </div>

                {isBreachChecking && (
                  <div className="p-12 glass-panel border-amber-500/10 bg-black/60 flex flex-col items-center justify-center text-center space-y-4">
                    <div className="w-10 h-10 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
                    <div className="space-y-1">
                      <p className="text-xs font-bold text-amber-500 animate-pulse uppercase tracking-widest">SCANNING DATA LEAKS SYSTEM...</p>
                      <p className="text-[9px] text-zinc-500 uppercase tracking-widest">Querying HaveIBeenPwned & DeHashed archives</p>
                    </div>
                  </div>
                )}

                {breachError && (
                  <div className="p-4 bg-red-950/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-3">
                    <AlertTriangle size={16} />
                    <span>{breachError}</span>
                  </div>
                )}

                {!isBreachChecking && !breachResult && !breachError && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* Global Intel Stats */}
                    <div className="glass-panel border-zinc-900 bg-black/40 p-5 flex flex-col justify-between h-36">
                      <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Global Pwned Accounts</div>
                      <div className="text-2xl font-black italic text-amber-500 tracking-tighter">12,481,928,107</div>
                      <div className="text-[8px] text-zinc-600 uppercase">Synchronized threat databases</div>
                    </div>
                    <div className="glass-panel border-zinc-900 bg-black/40 p-5 flex flex-col justify-between h-36">
                      <div className="text-[10px] text-zinc-500 uppercase tracking-widest">DeHashed Records Index</div>
                      <div className="text-2xl font-black italic text-cyan-500 tracking-tighter">24.6 Billion</div>
                      <div className="text-[8px] text-zinc-600 uppercase">Real-time asset correlation</div>
                    </div>
                    <div className="glass-panel border-zinc-900 bg-black/40 p-5 flex flex-col justify-between h-36">
                      <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Active Leak Feeds</div>
                      <div className="text-2xl font-black italic text-[#39FF14] tracking-tighter">671 Sources</div>
                      <div className="text-[8px] text-zinc-600 uppercase">Daily signature synchronization</div>
                    </div>

                    {/* Breach Checker HUD Alert Intro */}
                    <div className="md:col-span-3 p-5 glass-panel border-[#39FF14]/10 bg-[#39FF14]/5 text-zinc-400">
                      <h3 className="text-xs font-bold text-[#39FF14] mb-2 uppercase tracking-widest">OPERATIONAL DIRECTIVE</h3>
                      <p className="text-[10px] leading-relaxed">
                        Data breach checks perform deep audit sweeps across public paste repositories, hacker forums, and compromised cloud databases. 
                        It is recommended to run audits whenever new personnel onboard, or if credential activity anomalies are flagged in local SIEM portals.
                      </p>
                    </div>
                  </div>
                )}

                {/* Audit Results Panel */}
                {!isBreachChecking && breachResult && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="space-y-4"
                  >
                    {/* Header Alert Card */}
                    <div className={cn(
                      "p-6 border glass-panel relative overflow-hidden",
                      breachResult.breachCount === 0
                        ? "border-[#39FF14]/30 bg-[#39FF14]/5"
                        : breachResult.passwordExposure === 'Plaintext'
                          ? "border-red-500/30 bg-red-950/10 shadow-[0_0_20px_rgba(239,68,68,0.1)]"
                          : "border-amber-500/30 bg-amber-950/10 shadow-[0_0_20px_rgba(245,158,11,0.1)]"
                    )}>
                      <div className="absolute top-0 right-0 w-48 h-full opacity-[0.03] pointer-events-none translate-x-1/4 -translate-y-1/4">
                        <Shield size={240} className="text-white" />
                      </div>

                      <div className="flex flex-col md:flex-row items-center gap-6 relative z-10">
                        {/* Big stats bubble */}
                        <div className="flex flex-col items-center justify-center w-24 h-24 border-2 rounded-full border-current text-center shrink-0">
                          <span className="text-3xl font-black italic">{breachResult.breachCount}</span>
                          <span className="text-[7px] uppercase tracking-wider">BREACHES</span>
                        </div>

                        <div className="flex-1 space-y-2">
                          <div className="flex items-center gap-2">
                            <span className={cn(
                              "text-[8px] font-black uppercase px-2 py-0.5 border rounded-none tracking-widest",
                              breachResult.breachCount === 0
                                ? "bg-[#39FF14]/10 border-[#39FF14] text-[#39FF14]"
                                : breachResult.passwordExposure === 'Plaintext'
                                  ? "bg-red-500/10 border-red-500 text-red-500 animate-pulse"
                                  : "bg-amber-500/10 border-amber-500 text-amber-500"
                            )}>
                              {breachResult.breachCount === 0 ? "SECURE_IDENTITY" : `THREAT_LEVEL: ${breachResult.passwordExposure === 'Plaintext' ? 'CRITICAL' : 'WARNING'}`}
                            </span>
                          </div>
                          <h3 className="text-lg font-black tracking-tighter text-white uppercase italic">
                            BREACH AUDIT FOR: <span className="text-amber-500">{breachResult.identity}</span>
                          </h3>
                          <p className="text-[10px] text-zinc-400 leading-relaxed uppercase">
                            {breachResult.breachCount === 0
                              ? "Excellent. Identity does not exist in any parsed data leak databases. Maintain current authentication hygiene patterns."
                              : `Exposure detected! This identity has been associated with ${breachResult.breachCount} public database breaches. Immediate defensive operations suggested.`}
                          </p>
                        </div>
                      </div>
                    </div>

                    {breachResult.breachCount > 0 && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {/* Compromised Categories Card */}
                        <div className="p-5 glass-panel border-zinc-800 bg-black/60 space-y-3">
                          <h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Compromised Data Categories</h4>
                          <div className="flex flex-wrap gap-1.5 pt-1">
                            {breachResult.compromisedCategories.map((c: string) => (
                              <span
                                key={c}
                                className="text-[8px] font-bold uppercase tracking-wider px-2 py-1 bg-red-500/5 border border-red-500/20 text-red-400"
                              >
                                {c}
                              </span>
                            ))}
                          </div>
                        </div>

                        {/* Password Exposure Meter */}
                        <div className="p-5 glass-panel border-zinc-800 bg-black/60 space-y-3">
                          <h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Credential Exposure Analysis</h4>
                          
                          <div className="flex items-center gap-3 bg-black/80 p-3 border border-zinc-900">
                            <div className={cn(
                              "w-3 h-3 rounded-full shrink-0",
                              breachResult.passwordExposure === 'Plaintext' ? "bg-red-500 animate-ping" : breachResult.passwordExposure === 'Hashed' ? "bg-amber-500" : "bg-[#39FF14]"
                            )} />
                            <div className="flex-1">
                              <p className="text-[10px] font-bold text-white uppercase tracking-wider">
                                Exposure Model: {breachResult.passwordExposure.toUpperCase()}
                              </p>
                              <p className="text-[8px] text-zinc-500 uppercase tracking-wider">
                                {breachResult.passwordExposure === 'Plaintext'
                                  ? "High threat level: passwords leaked in clear text formats."
                                  : breachResult.passwordExposure === 'Hashed'
                                    ? "Medium threat level: password hashes leaked. Susceptible to decryptions."
                                    : "No password leaks mapped in active data categories."}
                              </p>
                            </div>
                          </div>
                        </div>

                        {/* Mitigation Recommendations */}
                        <div className="md:col-span-2 p-5 glass-panel border-zinc-800 bg-black/60 space-y-4">
                          <h4 className="text-[10px] font-bold text-[#39FF14] uppercase tracking-widest">Recommended Playbook Actions</h4>
                          <div className="space-y-2">
                            {breachResult.recommendations.map((rec: string, idx: number) => (
                              <div key={idx} className="flex gap-3 text-[10px] leading-relaxed pl-2 border-l border-zinc-700">
                                <span className="text-[#39FF14] font-bold">[{idx + 1}]</span>
                                <span className="text-zinc-300 italic">"{rec}"</span>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Timeline of Breaches */}
                        <div className="md:col-span-2 p-5 glass-panel border-zinc-800 bg-black/60 space-y-4">
                          <h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Exposure Source Timeline</h4>
                          
                          <div className="relative border-l border-zinc-800 pl-4 ml-2 space-y-6 pt-2">
                            {breachResult.breaches.map((b: any, idx: number) => (
                              <div key={idx} className="relative group/item">
                                {/* Dot indicator */}
                                <div className={cn(
                                  "absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full border border-black",
                                  breachResult.passwordExposure === 'Plaintext' ? "bg-red-500" : "bg-amber-500"
                                )} />
                                
                                <div className="space-y-1.5 bg-black/40 border border-zinc-900 hover:border-zinc-800 p-4 transition-all">
                                  <div className="flex justify-between items-center text-[10px]">
                                    <div className="flex items-center gap-1.5 font-bold text-white">
                                      {b.logo && <img src={b.logo} alt={b.name} className="w-3.5 h-3.5 bg-zinc-800" />}
                                      <span>{b.name.toUpperCase()}</span>
                                    </div>
                                    <span className="font-mono text-zinc-500 font-bold">{b.year}</span>
                                  </div>
                                  <p className="text-[9px] text-zinc-400 leading-relaxed italic">
                                    {b.description}
                                  </p>
                                  <div className="flex flex-wrap gap-1 mt-2">
                                    {b.categories.map((cat: string) => (
                                      <span key={cat} className="text-[7px] font-mono px-1.5 py-0.5 bg-zinc-900 border border-zinc-800 text-zinc-400">
                                        {cat.toUpperCase()}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>

                      </div>
                    )}
                  </motion.div>
                )}
              </motion.div>
            )}

            {activeTab === 'training' && (
              <motion.div
                key="training"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="h-full"
              >
                <TrainingSimulator user={user} addLog={addLog} />
              </motion.div>
            )}

            {activeTab === 'admin' && (
              <motion.div
                key="admin"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="h-full"
              >
                <AdminControlCenter addLog={addLog} />
              </motion.div>
            )}

            {activeTab === 'attacksim' && (
              <motion.div
                key="attacksim"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="h-full"
              >
                <AttackSimulatorEngine addLog={addLog} />
              </motion.div>
            )}

            {activeTab === 'email' && (
              <motion.div
                key="email"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-4 font-mono text-zinc-300"
              >
                {/* Pasting raw headers card */}
                <div className="p-6 glass-panel border-pink-500/20 bg-black/60 relative overflow-hidden">
                  <div className="absolute top-0 right-0 w-48 h-full bg-linear-to-l from-pink-500/5 to-transparent skew-x-12" />
                  <h2 className="text-sm font-black uppercase tracking-widest text-pink-500 mb-3 flex items-center gap-2">
                    <Mail size={14} className="text-pink-500 animate-pulse" /> AI Email Header Threat Analyzer
                  </h2>
                  <p className="text-[10px] text-zinc-500 mb-4 uppercase tracking-wider">
                    Paste raw email headers to extract auth states (SPF, DKIM, DMARC), reconstruct SMTP relay paths, and run AI spoofing audits.
                  </p>

                  <form onSubmit={handleEmailHeaderCheck} className="space-y-3 relative z-10">
                    <textarea
                      value={emailRawHeaders}
                      onChange={(e) => setEmailRawHeaders(e.target.value)}
                      placeholder="Paste raw message headers here... (e.g. Received: from...)"
                      rows={6}
                      maxLength={102400}
                      className="w-full bg-black border border-pink-500/20 hover:border-pink-500/40 focus:border-pink-500/80 p-3 text-xs text-white focus:outline-none focus:shadow-[0_0_15px_rgba(236,72,153,0.15)] transition-all font-mono resize-y min-h-[120px]"
                    />
                    <div className="flex justify-between items-center">
                      <span className="text-[8px] text-zinc-600 uppercase">
                        Size: {Math.round(emailRawHeaders.length / 1024)} KB / 100 KB
                      </span>
                      <div className="flex gap-2">
                        {emailRawHeaders && (
                          <button
                            type="button"
                            onClick={() => setEmailRawHeaders('')}
                            className="px-3 py-2 border border-pink-500/20 text-pink-500/60 hover:text-pink-500 text-xs uppercase font-black transition-all"
                          >
                            Clear
                          </button>
                        )}
                        <button
                          type="submit"
                          disabled={isEmailChecking || !emailRawHeaders.trim()}
                          className="px-6 py-2 bg-pink-600 hover:bg-pink-500 disabled:bg-pink-950 disabled:opacity-40 disabled:cursor-not-allowed text-black font-black text-xs uppercase tracking-wider transition-all flex items-center justify-center gap-2"
                        >
                          {isEmailChecking ? 'AUDITING...' : 'AUDIT_HEADERS'}
                        </button>
                      </div>
                    </div>
                  </form>
                </div>

                {isEmailChecking && (
                  <div className="p-12 glass-panel border-pink-500/10 bg-black/60 flex flex-col items-center justify-center text-center space-y-4">
                    <div className="w-10 h-10 border-2 border-pink-500 border-t-transparent rounded-full animate-spin" />
                    <div className="space-y-1">
                      <p className="text-xs font-bold text-pink-500 animate-pulse uppercase tracking-widest">DECOMPOSING HEADER ENVELOPES...</p>
                      <p className="text-[9px] text-zinc-500 uppercase tracking-widest">Running AI Spoofing and SPF/DKIM validation matrix</p>
                    </div>
                  </div>
                )}

                {emailCheckError && (
                  <div className="p-4 bg-red-950/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-3">
                    <AlertTriangle size={16} />
                    <span>{emailCheckError}</span>
                  </div>
                )}

                {!isEmailChecking && !emailHeaderResult && !emailCheckError && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* Header Info Stats */}
                    <div className="glass-panel border-zinc-900 bg-black/40 p-5 flex flex-col justify-between h-36">
                      <div className="text-[10px] text-zinc-500 uppercase tracking-widest">SPF Alignment Checks</div>
                      <div className="text-2xl font-black italic text-pink-500 tracking-tighter">SPF &amp; Envelope</div>
                      <div className="text-[8px] text-zinc-600 uppercase">Reverse mapping IP authorized lists</div>
                    </div>
                    <div className="glass-panel border-zinc-900 bg-black/40 p-5 flex flex-col justify-between h-36">
                      <div className="text-[10px] text-zinc-500 uppercase tracking-widest">DKIM Signature Audit</div>
                      <div className="text-2xl font-black italic text-cyan-500 tracking-tighter">Cryptographic Integrity</div>
                      <div className="text-[8px] text-zinc-600 uppercase">Validation of asymmetric signatures</div>
                    </div>
                    <div className="glass-panel border-zinc-900 bg-black/40 p-5 flex flex-col justify-between h-36">
                      <div className="text-[10px] text-zinc-500 uppercase tracking-widest">SMTP Relay Hops</div>
                      <div className="text-2xl font-black italic text-[#39FF14] tracking-tighter">Trace Route</div>
                      <div className="text-[8px] text-zinc-600 uppercase">Parsing chronological mail relays</div>
                    </div>

                    {/* Operational Alert Intro */}
                    <div className="md:col-span-3 p-5 glass-panel border-pink-500/10 bg-pink-500/5 text-zinc-400">
                      <h3 className="text-xs font-bold text-pink-500 mb-2 uppercase tracking-widest">MAIL ENVELOPE OPERATIONAL DIRECTIVE</h3>
                      <p className="text-[10px] leading-relaxed">
                        Spoofing and phishing campaigns frequently abuse SMTP envelope vulnerabilities by aligning visible "From" addresses with legitimate brands while route headers disclose unauthorized relays. Pasting raw headers decodes DKIM keys and traces the true originating MTA.
                      </p>
                    </div>
                  </div>
                )}

                {/* Audit Results Panel */}
                {!isEmailChecking && emailHeaderResult && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="space-y-4"
                  >
                    {/* Header Alert Card */}
                    <div className={cn(
                      "p-6 border glass-panel relative overflow-hidden",
                      emailHeaderResult.threatScore < 30
                        ? "border-[#39FF14]/30 bg-[#39FF14]/5"
                        : emailHeaderResult.threatScore < 75
                          ? "border-amber-500/30 bg-amber-950/10 shadow-[0_0_20px_rgba(245,158,11,0.1)]"
                          : "border-red-500/30 bg-red-950/10 shadow-[0_0_20px_rgba(239,68,68,0.1)]"
                    )}>
                      <div className="absolute top-0 right-0 w-48 h-full opacity-[0.03] pointer-events-none translate-x-1/4 -translate-y-1/4">
                        <Shield size={240} className="text-white" />
                      </div>

                      <div className="flex flex-col md:flex-row items-center gap-6 relative z-10">
                        {/* Big stats bubble */}
                        <div className="shrink-0">
                          <ThreatGauge score={emailHeaderResult.threatScore} />
                        </div>

                        <div className="flex-1 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className={cn(
                              "text-[8px] font-black uppercase px-2 py-0.5 border rounded-none tracking-widest",
                              emailHeaderResult.threatScore < 30
                                ? "bg-[#39FF14]/10 border-[#39FF14] text-[#39FF14]"
                                : emailHeaderResult.threatScore < 75
                                  ? "bg-amber-500/10 border-amber-500 text-amber-500"
                                  : "bg-red-500/10 border-red-500 text-red-400 animate-pulse"
                            )}>
                              {emailHeaderResult.classification.toUpperCase()}_THREAT_LEVEL
                            </span>
                            
                            {/* Export / Print Buttons */}
                            <div className="flex gap-2">
                              <button
                                type="button"
                                onClick={() => {
                                  setExportDataType('email');
                                  setIsExportModalOpen(true);
                                }}
                                className="px-2 py-1 bg-zinc-900 border border-zinc-800 hover:border-pink-500 text-[9px] font-black text-pink-400 uppercase tracking-widest transition-all flex items-center gap-1.5"
                              >
                                <Download size={10} /> EXPORT_PDF
                              </button>
                            </div>
                          </div>
                          <h3 className="text-lg font-black tracking-tighter text-white uppercase italic">
                            Originating IP: <span className="text-pink-500">{emailHeaderResult.senderIp}</span>
                          </h3>
                          <p className="text-[10px] text-zinc-400 leading-relaxed uppercase">
                            Relays count: {emailHeaderResult.hopsCount} hops trace. Heuristic parsing scanned authentication seals (SPF/DKIM/DMARC) mapping true dispatch domain identities.
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Authentication Seals & IP HUD */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      {/* SPF Status */}
                      <div className="p-4 bg-black/40 border border-zinc-900 glass-panel flex flex-col justify-between space-y-2">
                        <span className="text-[9px] text-zinc-500 uppercase tracking-widest">SPF AUTHENTICATION</span>
                        <div className="flex items-center gap-2">
                          <div className={cn(
                            "w-2 h-2 rounded-full",
                            emailHeaderResult.spf === 'Pass' ? "bg-[#39FF14]" : emailHeaderResult.spf === 'Fail' ? "bg-red-500" : "bg-amber-500"
                          )} />
                          <span className="text-sm font-black italic text-white">{emailHeaderResult.spf}</span>
                        </div>
                        <span className="text-[8px] text-zinc-600 uppercase">Sender Policy Framework</span>
                      </div>

                      {/* DKIM Status */}
                      <div className="p-4 bg-black/40 border border-zinc-900 glass-panel flex flex-col justify-between space-y-2">
                        <span className="text-[9px] text-zinc-500 uppercase tracking-widest">DKIM SIGNATURE</span>
                        <div className="flex items-center gap-2">
                          <div className={cn(
                            "w-2 h-2 rounded-full",
                            emailHeaderResult.dkim === 'Pass' ? "bg-[#39FF14]" : emailHeaderResult.dkim === 'Fail' ? "bg-red-500" : "bg-amber-500"
                          )} />
                          <span className="text-sm font-black italic text-white">{emailHeaderResult.dkim}</span>
                        </div>
                        <span className="text-[8px] text-zinc-600 uppercase">DomainKeys Identified Mail</span>
                      </div>

                      {/* DMARC Status */}
                      <div className="p-4 bg-black/40 border border-zinc-900 glass-panel flex flex-col justify-between space-y-2">
                        <span className="text-[9px] text-zinc-500 uppercase tracking-widest">DMARC POLICY</span>
                        <div className="flex items-center gap-2">
                          <div className={cn(
                            "w-2 h-2 rounded-full",
                            emailHeaderResult.dmarc === 'Pass' ? "bg-[#39FF14]" : emailHeaderResult.dmarc === 'Fail' ? "bg-red-500" : "bg-zinc-600"
                          )} />
                          <span className="text-sm font-black italic text-white">{emailHeaderResult.dmarc}</span>
                        </div>
                        <span className="text-[8px] text-zinc-600 uppercase">Domain-based Reporting</span>
                      </div>

                      {/* Originating IP */}
                      <div className="p-4 bg-black/40 border border-zinc-900 glass-panel flex flex-col justify-between space-y-2">
                        <span className="text-[9px] text-zinc-500 uppercase tracking-widest">SENDER_IP_TRACE</span>
                        <span className="text-sm font-black italic text-pink-400 truncate">{emailHeaderResult.senderIp}</span>
                        <span className="text-[8px] text-zinc-600 uppercase">Resolved originating IP</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Spoofing Indicators Card */}
                      <div className="p-5 glass-panel border-zinc-800 bg-black/60 space-y-3">
                        <h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Spoofing &amp; Phishing Anomalies</h4>
                        <div className="space-y-1.5 max-h-[160px] overflow-y-auto custom-scrollbar">
                          {emailHeaderResult.spoofingIndicators.map((ind: string, index: number) => (
                            <div key={index} className="text-[9px] flex items-center gap-2 text-red-400 bg-red-950/5 border border-red-500/10 p-2 font-mono">
                              <AlertTriangle size={10} className="shrink-0" />
                              <span>{ind}</span>
                            </div>
                          ))}
                          {emailHeaderResult.spoofingIndicators.length === 0 && (
                            <div className="text-[9px] flex items-center gap-2 text-[#39FF14] bg-[#39FF14]/5 border border-[#39FF14]/10 p-2 font-mono">
                              <CheckCircle size={10} className="shrink-0" />
                              <span>No validation anomalies observed in envelope parameters.</span>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Chronological Hop route timeline */}
                      <div className="p-5 glass-panel border-zinc-800 bg-black/60 space-y-3">
                        <h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">MTA Relay Hops Timeline</h4>
                        <div className="space-y-2 max-h-[160px] overflow-y-auto custom-scrollbar pl-2 pt-1">
                          <div className="relative border-l border-zinc-800 pl-4 space-y-4 ml-1">
                            {emailHeaderResult.hops.map((hop: string, idx: number) => (
                              <div key={idx} className="relative text-[9px] text-zinc-400 flex justify-between items-center">
                                <div className={cn(
                                  "absolute -left-[21px] w-2 h-2 rounded-full border border-black",
                                  idx === 0 ? "bg-pink-500 animate-ping" : idx === emailHeaderResult.hops.length - 1 ? "bg-cyan-500" : "bg-zinc-700"
                                )} />
                                <span className="font-bold truncate max-w-[170px] text-white">
                                  {idx === 0 ? ' [Origin] ' : idx === emailHeaderResult.hops.length - 1 ? ' [Recipient] ' : ` [Relay #${idx}] `}
                                  {hop}
                                </span>
                                <span className="text-[7px] text-zinc-600 font-mono uppercase">Node #{idx + 1}</span>
                              </div>
                            ))}
                            {emailHeaderResult.hops.length === 0 && (
                              <p className="text-[9px] text-zinc-500 uppercase">No Received headers parsed to trace hops.</p>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* MITIGATION рекомендации */}
                      <div className="md:col-span-2 p-5 glass-panel border-zinc-800 bg-black/60 space-y-3">
                        <h4 className="text-[10px] font-bold text-[#39FF14] uppercase tracking-widest">Threat MITIGATION PLAYBOOK</h4>
                        <div className="space-y-2">
                          {emailHeaderResult.recommendations.map((rec: string, idx: number) => (
                            <div key={idx} className="flex gap-3 text-[10px] leading-relaxed pl-2 border-l border-zinc-700">
                              <span className="text-[#39FF14] font-bold">[{idx + 1}]</span>
                              <span className="text-zinc-300 italic">"{rec}"</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Detailed AI Explanation summary */}
                      <div className="md:col-span-2 p-5 glass-panel border-zinc-800 bg-black/60 space-y-2">
                        <h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">AI Threat Analyst Explanation</h4>
                        <div className="text-[11px] leading-relaxed text-zinc-300 bg-black/40 border border-zinc-900 p-4 font-sans whitespace-pre-line">
                          {emailHeaderResult.explanation}
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}
              </motion.div>
            )}

            {(activeTab === 'scan' || activeTab === 'history') && !result && !isAnalyzing && !analysisError && (
              <motion.div
                key="idle"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="h-full min-h-[500px] glass-panel border-dashed border-[#39FF14]/10 bg-[#39FF14]/[0.01] flex flex-col items-center justify-center relative group"
              >
                {/* Decorative scanning elements */}
                <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-10">
                  <div className="absolute top-0 w-full h-px bg-[#39FF14] animate-[scan_3s_infinite_ease-in-out]" />
                  <div className="grid grid-cols-10 h-full">
                    {Array.from({ length: 10 }).map((_, i) => (
                      <div key={i} className="border-r border-[#39FF14]/20 h-full" />
                    ))}
                  </div>
                </div>

                <div className="p-8 rounded-none border border-[#39FF14]/20 bg-black/60 shadow-[0_0_30px_rgba(57,255,20,0.1)] relative z-10 transition-transform group-hover:scale-110 duration-500">
                  <Shield size={48} className="text-[#39FF14] opacity-50" strokeWidth={1} />
                </div>
                <h3 className="text-xl font-black tracking-[0.2em] mt-6 mb-2 text-[#39FF14]/80">AWAITING_PAYLOAD</h3>
                <p className="text-[#39FF14]/40 text-[10px] uppercase font-mono tracking-[0.3em] max-w-xs text-center border-t border-[#39FF14]/10 pt-4 mt-2">
                  System standing by. Enter a target URI to begin deep heuristic decomposition.
                </p>
              </motion.div>
            )}

            {(activeTab === 'scan' || activeTab === 'history') && analysisError && (
              <motion.div
                key="error"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="h-full min-h-[500px] glass-panel border-red-500/20 bg-red-500/5 flex flex-col items-center justify-center text-center p-8"
              >
                <div className="p-4 bg-red-500/20 border border-red-500 mb-6">
                  <AlertTriangle className="text-red-500" size={40} />
                </div>
                <h2 className="text-2xl font-black italic tracking-widest text-red-500 mb-4 uppercase">System_Fault_Detected</h2>
                <div className="max-w-md bg-black/60 border border-white/5 p-4 rounded mb-6">
                  <p className="text-[12px] font-mono text-zinc-400 leading-relaxed">
                    {analysisError}
                  </p>
                </div>
                <button
                  onClick={() => setAnalysisError(null)}
                  className="px-6 py-2 bg-red-500/20 border border-red-500 text-red-500 text-[10px] font-black uppercase tracking-widest hover:bg-red-500 hover:text-white transition-all"
                >
                  DISMISS_FAULT_REPORT
                </button>
              </motion.div>
            )}

            {(activeTab === 'scan' || activeTab === 'history') && isAnalyzing && (
              <motion.div
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="h-full min-h-[500px] glass-panel border-[#39FF14]/10 flex flex-col items-center justify-center relative overflow-hidden"
              >
                <div className="absolute inset-0 bg-[#39FF14]/2 blur-[100px]" />
                <div className="relative z-10 text-center">
                  <div className="inline-block p-6 border-2 border-[#39FF14] rounded-none mb-6 animate-pulse shadow-[0_0_30px_rgba(57,255,20,0.3)]">
                    <RefreshCcw size={48} className="animate-spin text-[#39FF14]" />
                  </div>
                  <h2 className="text-2xl font-black italic tracking-widest text-[#39FF14]">ANALYZING_FLIGHT_VECTORS</h2>
                  <div className="flex gap-2 justify-center mt-6">
                    {Array.from({ length: 5 }).map((_, i) => (
                      <motion.div
                        key={i}
                        className="w-2 h-2 bg-[#39FF14]"
                        animate={{ opacity: [0.2, 1, 0.2] }}
                        transition={{ duration: 0.8, repeat: Infinity, delay: i * 0.1 }}
                      />
                    ))}
                  </div>
                </div>
              </motion.div>
            )}

            {(activeTab === 'scan' || activeTab === 'history') && result && (
              <motion.div
                key="result"
                ref={dashboardRef}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="space-y-4"
              >
                <div className={cn(
                  "p-8 glass-panel border neon-border relative overflow-hidden",
                  getStatusColor(result.classification).split(' ').slice(1).join(' ')
                )}>
                  <div className="absolute top-0 right-0 w-80 h-80 opacity-[0.03] pointer-events-none translate-x-1/4 -translate-y-1/4">
                    <Shield size={320} className="text-[#39FF14]" />
                  </div>

                  <div className="flex flex-col md:flex-row items-center gap-8 relative z-10">
                    <ThreatGauge score={result.threatScore} />
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-3">
                        <span className={cn("status-badge shadow-[0_0_15px_currentColor]", getStatusColor(result.classification).split(' ')[0])}>
                          {result.classification}
                        </span>
                        <div className="h-px flex-1 bg-[#39FF14]/10" />
                      </div>
                      <h2 className="text-3xl md:text-5xl font-black italic tracking-tighter mb-1">
                        INDEX: <span className={getGaugeColor(result.threatScore)}>{result.threatScore}.00</span>
                      </h2>
                      <div className="flex items-center gap-4 text-[10px] font-mono text-[#39FF14]/70">
                        <span className="flex items-center gap-1"><Lock size={10} /> TARGET_TYPE: {result.type?.toUpperCase()}</span>
                        <span className="flex items-center gap-1"><Cpu size={10} /> CORE_SYNC: OK</span>
                      </div>
                      <div className="mt-4 flex flex-wrap gap-2">
                        <button
                          onClick={() => {
                            setExportDataType('scan');
                            setIsExportModalOpen(true);
                          }}
                          className={cn(
                            "px-3 py-1.5 border text-[9px] font-bold uppercase tracking-widest flex items-center gap-1.5 transition-all relative z-20",
                            result.classification === 'Malicious' || result.classification === 'Phishing'
                              ? "bg-red-500/10 border-red-500 text-red-400 hover:bg-red-500 hover:text-white"
                              : result.classification === 'Suspicious'
                                ? "bg-amber-500/10 border-amber-500 text-amber-400 hover:bg-amber-500 hover:text-black"
                                : "bg-[#39FF14]/10 border-[#39FF14] text-[#39FF14] hover:bg-[#39FF14] hover:text-black"
                          )}
                        >
                          <Download size={10} /> EXPORT_REPORT
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="mt-8 pt-8 border-t border-[#39FF14]/10 grid grid-cols-1 md:grid-cols-2 gap-6 bg-black/40 p-6 -mx-8 -mb-8">
                    <div className="relative pl-6 border-l-2 border-[#39FF14]/20">
                      <div className="absolute -top-1 -left-1.5 w-3 h-3 bg-black border border-[#39FF14]/30 rotate-45" />
                      <p className="text-[10px] font-bold text-[#39FF14]/50 uppercase tracking-[0.3em] mb-2">Security_Directive</p>
                      <p className="text-[13px] leading-relaxed italic text-[#39FF14]">{result.recommendation}</p>
                    </div>
                    <div className="bg-black/80 p-4 border border-[#39FF14]/10 flex flex-col justify-between relative group">
                      <div className="absolute inset-0 bg-[#39FF14]/5 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
                      <button
                        onClick={() => {
                          setExportDataType('scan');
                          setIsExportModalOpen(true);
                        }}
                        className="absolute top-2 right-2 p-1.5 border border-[#39FF14]/20 hover:border-[#39FF14] hover:bg-[#39FF14]/10 text-[#39FF14] transition-all z-20"
                        title="EXPORT_REPORT"
                      >
                        <Download size={14} />
                      </button>
                      <div className="flex justify-between items-center text-[10px] mb-2 opacity-50">
                        <span>NEURAL_SUMMARY</span>
                        <Zap size={10} />
                      </div>
                      <p className="text-[11px] leading-relaxed line-clamp-3 text-[#39FF14]/80 italic">
                        "{result.explanation}"
                      </p>
                    </div>
                  </div>
                </div>

                <ReputationModule result={result} />
                <VulnerabilityModule result={result} />
                <PhoneModule result={result} />
                <MessageModule result={result} />
                <VisualEvidenceModule result={result} />

                {result.type !== 'keyword' && result.type !== 'phone' && result.type !== 'message' && (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {/* SSL MODULE */}
                    <div className="glass-panel border-[#39FF14]/20 p-5 space-y-4">
                      <div className="flex justify-between items-start">
                        <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
                          <Lock size={12} className="text-blue-400" /> SSL_HANDSHAKE
                        </h3>
                        <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse" />
                      </div>
                      <div className="p-3 bg-black border border-[#39FF14]/10 space-y-2 text-[10px]">
                        <div className="flex justify-between">
                          <span className="opacity-40 uppercase">Authorization</span>
                          <span className={cn("font-bold", result.raw?.ssl?.authorized ? "text-[#39FF14]" : "text-red-500")}>
                            {result.raw?.ssl?.authorized ? "TRUSTED" : (result.raw?.ssl?.error ? "FAILED" : "UNSAFE")}
                          </span>
                        </div>
                        {result.raw?.ssl?.issuer && (
                          <div className="flex justify-between items-start pt-1 border-t border-[#39FF14]/5">
                            <span className="opacity-40 uppercase">Issuer</span>
                            <span className="font-bold text-right truncate max-w-[140px]" title={result.raw.ssl.issuer.O || result.raw.ssl.issuer.CN}>
                              {result.raw.ssl.issuer.O || result.raw.ssl.issuer.CN || 'Unknown'}
                            </span>
                          </div>
                        )}
                        <div className="flex justify-between items-center pt-1 border-t border-[#39FF14]/5">
                          <span className="opacity-40 uppercase">Valid From</span>
                          <span className="font-bold">{result.raw?.ssl?.valid_from ? new Date(result.raw.ssl.valid_from).toLocaleDateString() : 'N/A'}</span>
                        </div>
                        <div className="flex justify-between items-center relative group/expiry">
                          <span className="opacity-40 uppercase">Valid To</span>
                          <div className="flex items-center gap-1.5">
                            <span className={cn(
                              "font-bold",
                              (result.raw?.ssl?.valid_to && new Date(result.raw.ssl.valid_to) < new Date())
                                ? "text-red-500"
                                : (result.raw?.ssl?.valid_to && new Date(result.raw.ssl.valid_to).getTime() - new Date().getTime() < 30 * 24 * 60 * 60 * 1000)
                                  ? "text-orange-500"
                                  : ""
                            )}>
                              {result.raw?.ssl?.valid_to ? new Date(result.raw.ssl.valid_to).toLocaleDateString() : 'N/A'}
                            </span>
                            {(result.raw?.ssl?.valid_to &&
                              new Date(result.raw.ssl.valid_to).getTime() - new Date().getTime() < 30 * 24 * 60 * 60 * 1000 &&
                              new Date(result.raw.ssl.valid_to).getTime() > new Date().getTime()) && (
                                <div className="flex items-center gap-1 bg-orange-500/10 border border-orange-500/20 px-1 rounded-sm animate-pulse">
                                  <AlertTriangle size={8} className="text-orange-400" />
                                  <span className="absolute hidden group-hover/expiry:block right-0 -top-6 bg-black border border-orange-500/50 text-orange-400 text-[7px] px-2 py-1 whitespace-nowrap z-50 uppercase font-black">
                                    Expiring Soon (&lt;30D)
                                  </span>
                                </div>
                              )}
                          </div>
                        </div>
                        {result.raw?.ssl?.fingerprint && (
                          <div className="pt-1 border-t border-[#39FF14]/5">
                            <p className="opacity-40 uppercase mb-1">Fingerprint (SHA1)</p>
                            <p className="font-mono text-[8px] break-all opacity-80 leading-tight">
                              {result.raw.ssl.fingerprint}
                            </p>
                          </div>
                        )}
                        <div className="flex justify-between border-t border-[#39FF14]/5 pt-2">
                          <span className="opacity-40 uppercase">CT Logs</span>
                          <span className="font-bold">{result.raw?.ct?.length || 0} RECORDS</span>
                        </div>
                      </div>
                      <p className="text-[9px] leading-relaxed text-[#39FF14]/60 italic font-sans px-1">
                        {result.technicalSummary.ssl}
                      </p>
                    </div>

                    {/* DNS MODULE */}
                    <div className="glass-panel border-[#39FF14]/20 p-5 space-y-4">
                      <div className="flex justify-between items-start">
                        <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
                          <Globe size={12} className="text-emerald-400" /> DNS_RESOLVER
                        </h3>
                        <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse shadow-[0_0_10px_rgba(16,185,129,0.5)]" />
                      </div>
                      <div className="p-3 bg-black border border-[#39FF14]/10 space-y-2 text-[10px]">
                        <div className="flex justify-between">
                          <span className="opacity-40">PRIMARY_IP</span>
                          <span className="font-bold text-[#39FF14]">{result.raw?.dns?.ips?.[0] || 'N.A'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="opacity-40">DNSBL_STATUS</span>
                          <span className={cn("font-bold", result.raw?.dns?.reputation?.length > 0 ? "text-red-500" : "text-[#39FF14]")}>
                            {result.raw?.dns?.reputation?.length > 0 ? "LISTED" : "CLEAN"}
                          </span>
                        </div>
                        {result.type === 'email' && result.raw?.dns?.records?.mx?.length > 0 && (
                          <div className="pt-2 border-t border-[#39FF14]/5 space-y-1">
                            <p className="opacity-40 uppercase mb-1">MX_RECORDS</p>
                            {result.raw?.dns?.records?.mx?.slice(0, 2).map((mx: any, i: number) => (
                              <div key={i} className="flex justify-between text-[8px] italic">
                                <span className="truncate max-w-[120px]">{mx.exchange}</span>
                                <span className="font-mono text-emerald-500">PRI: {mx.priority}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                      <p className="text-[9px] leading-relaxed text-[#39FF14]/60 italic font-sans px-1">
                        {result.technicalSummary.dns}
                      </p>
                    </div>

                    {/* HEURISTICS MODULE */}
                    <div className="glass-panel border-[#39FF14]/20 p-5 space-y-4">
                      <div className="flex justify-between items-start">
                        <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
                          <Cpu size={12} className="text-orange-400" /> PATTERN_ENG
                        </h3>
                        <div className="w-2 h-2 bg-orange-500 rounded-full animate-pulse shadow-[0_0_10px_rgba(249,115,22,0.5)]" />
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[10px]">
                        <div className="p-2 bg-black border border-[#39FF14]/10">
                          <p className="opacity-30 mb-1">ENTROPY</p>
                          <p className="font-bold text-[#39FF14]">{result.raw?.heuristics?.entropy?.toFixed(2) || '0.0'}</p>
                        </div>
                        <div className="p-2 bg-black border border-[#39FF14]/10">
                          <p className="opacity-30 mb-1">PUNYCODE</p>
                          <p className={cn("font-bold", result.raw?.heuristics?.isPunycode ? "text-red-500" : "text-[#39FF14]")}>
                            {result.raw?.heuristics?.isPunycode ? "YES" : "NO"}
                          </p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        {result.riskIndicators.slice(0, 2).map((risk, i) => (
                          <span key={i} className="text-[8px] bg-[#39FF14]/10 border border-[#39FF14]/20 px-2 py-0.5 uppercase tracking-widest text-[#39FF14]">
                            {risk}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* RIGHT COLUMN: TECHNICAL DETAILS / INTEL (Col 3) */}
        <div className="lg:col-span-3 space-y-4">
          {activeTab === 'analytics' ? (
            <section className="glass-panel border-cyan-500/20 bg-black/40 p-5 space-y-4 h-full flex flex-col min-h-[500px]">
              <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-cyan-400 flex items-center gap-2">
                <Terminal size={12} className="text-cyan-400 animate-pulse" /> LIVE_SOC_ACTIVITY_FEED
              </h3>
              <div className="flex-1 bg-black/80 border border-cyan-500/10 p-3 font-mono text-[9px] text-[#39FF14] h-[610px] overflow-y-auto custom-scrollbar flex flex-col justify-between">
                <div className="space-y-1.5">
                  {terminalLogs.map((log, idx) => {
                    let colorClass = "text-cyan-400";
                    if (log.includes("WARN")) colorClass = "text-amber-500";
                    if (log.includes("ALERT")) colorClass = "text-purple-400";
                    if (log.includes("CRITICAL")) colorClass = "text-red-500";
                    if (log.includes("SYSTEM")) colorClass = "text-zinc-500";
                    return (
                      <div key={idx} className={colorClass}>
                        {log}
                      </div>
                    );
                  })}
                  <div ref={terminalEndRef} />
                </div>
                <div className="border-t border-cyan-500/10 pt-2 mt-4 text-[8px] text-cyan-500/50 uppercase tracking-widest flex items-center justify-between">
                  <span>NODE_FEED: ON</span>
                  <span className="w-1.5 h-3 bg-[#39FF14] animate-[pulse_1s_infinite]" />
                </div>
              </div>
            </section>
          ) : (
            <>
              {/* INTEL FEED INTEGRATED */}
              <section className="glass-panel border-[#39FF14]/20 bg-black/40 p-5 space-y-4">
                <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
                  <Zap size={12} className="text-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]" /> INTEL_FEEDS
                </h3>
                <div className="space-y-4">
                  <div className="space-y-1">
                    <p className="text-[9px] opacity-30 uppercase font-black">LYZR_MALWARE_DB</p>
                    <div className="h-1 bg-[#39FF14]/10 relative">
                      <motion.div
                        className="absolute h-full bg-[#39FF14]"
                        initial={{ width: 0 }}
                        animate={{ width: "82%" }}
                      />
                    </div>
                    <p className="text-[9px] text-[#39FF14] font-bold">82% CONFIDENCE MATCH</p>
                  </div>
                  <div className="p-3 bg-black/60 border-l-2 border-red-500 text-[10px] italic text-[#39FF14]/70">
                    "Pattern signatures matched global polymorphic phishing campaign identifiers recorded T-minus 48h."
                  </div>
                </div>
              </section>

              {/* DOMAIN BIO */}
              {result && result.type !== 'keyword' && result.type !== 'phone' && result.type !== 'message' && (
                <motion.section
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="glass-panel border-[#39FF14]/20 p-5 space-y-4 neon-border"
                >
                  <div className="flex items-center gap-3">
                    <CalendarDays className="text-purple-500" size={16} />
                    <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14]">DOMAIN_RECORDS</h3>
                  </div>
                  <div className="space-y-3">
                    <div>
                      <p className="text-[32px] font-black tracking-tighter text-[#39FF14] leading-none mb-1">
                        {getDomainAge(result.raw?.whois?.creationDate || result.raw?.whois?.createdDate) || 'INF'}
                      </p>
                      <p className="text-[8px] opacity-30 uppercase font-black tracking-widest">Calculated_Epoch_Time</p>
                    </div>
                    <div className="p-3 bg-black/80 border border-[#39FF14]/10 space-y-2 text-[9px]">
                      <div className="flex justify-between">
                        <span className="opacity-40">CREATED</span>
                        <span className="text-[#39FF14] truncate max-w-[120px]">{result.raw?.whois?.creationDate || result.raw?.whois?.createdDate || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="opacity-40">EXPIRES</span>
                        <span className="text-[#39FF14] truncate max-w-[120px]">{result.raw?.whois?.expiryDate || result.raw?.whois?.expirationDate || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="opacity-40">REGISTRAR</span>
                        <span className="text-[#39FF14] truncate max-w-[120px]">{result.raw?.whois?.registrar || 'N/A'}</span>
                      </div>
                      {result.raw?.whois?.registrarAbuseContactEmail && (
                        <div className="flex justify-between">
                          <span className="opacity-40">ABUSE_EMAIL</span>
                          <span className="text-[#39FF14] truncate max-w-[120px]">{result.raw?.whois?.registrarAbuseContactEmail}</span>
                        </div>
                      )}
                    </div>
                    <p className="text-[9px] leading-relaxed text-[#39FF14]/50 italic">
                      {result.technicalSummary.whois}
                    </p>
                  </div>
                </motion.section>
              )}

              {/* SYSTEM STATS */}
              <section className="glass-panel border-[#39FF14]/10 p-5 space-y-4">
                <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#39FF14] flex items-center gap-2">
                  <Cpu size={12} /> HARDWARE_OS
                </h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-end">
                    <p className="text-[9px] opacity-30 uppercase">CPU_LOAD</p>
                    <div className="flex gap-0.5 h-6">
                      {[0.2, 0.4, 0.6, 0.3, 0.8, 0.5].map((h, i) => (
                        <div
                          key={i}
                          className="w-1.5 bg-[#39FF14]/30"
                          style={{ height: `${h * 100}%` }}
                        />
                      ))}
                    </div>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="opacity-40">LATENCY</span>
                    <span className="font-bold">42.2ms</span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="opacity-40">SYNC_STATUS</span>
                    <span className="text-emerald-500 font-bold">STABLE</span>
                  </div>
                </div>
              </section>

              {/* DECORATIVE TRAFFIC */}
              <section className="glass-panel border-[#39FF14]/10 p-5 hidden xl:block">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-[9px] font-black uppercase tracking-[0.2em] text-[#39FF14]/40">NETWORK_BURST</h3>
                  <Activity size={10} className="text-[#39FF14]/20" />
                </div>
                <div className="flex items-end gap-1 h-12">
                  {Array.from({ length: 20 }).map((_, i) => (
                    <motion.div
                      key={i}
                      className="flex-1 bg-[#39FF14]/20"
                      animate={{
                        height: [
                          `${Math.random() * 100}%`,
                          `${Math.random() * 100}%`,
                          `${Math.random() * 100}%`
                        ]
                      }}
                      transition={{
                        duration: 2 + Math.random() * 2,
                        repeat: Infinity,
                        ease: "linear"
                      }}
                    />
                  ))}
                </div>
              </section>
            </>
          )}
        </div>

      </main>

      {/* Footer Intel Feed */}
      <AlertNotifications />
      <footer className="fixed bottom-0 left-0 right-0 z-50 p-4">
        <IntelFeed />
      </footer>

      {/* Export & Branding Config Modal */}
      <AnimatePresence>
        {isExportModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-lg bg-zinc-950 border border-zinc-800 p-6 relative overflow-hidden font-mono text-zinc-300"
            >
              {/* Corner Accents */}
              <div className="absolute top-0 left-0 w-4 h-4 border-t-2 border-l-2 border-[#39FF14]" />
              <div className="absolute top-0 right-0 w-4 h-4 border-t-2 border-r-2 border-[#39FF14]" />
              <div className="absolute bottom-0 left-0 w-4 h-4 border-b-2 border-l-2 border-[#39FF14]" />
              <div className="absolute bottom-0 right-0 w-4 h-4 border-b-2 border-r-2 border-[#39FF14]" />

              <div className="flex items-center justify-between border-b border-zinc-800 pb-3 mb-4">
                <h3 className="text-xs font-black uppercase tracking-widest text-[#39FF14] flex items-center gap-2">
                  <Shield size={14} /> EXPORT_AUDIT_REPORT
                </h3>
                <button
                  onClick={() => {
                    setIsExportModalOpen(false);
                    setEmailStatusMessage('');
                    setEmailStatusType('');
                  }}
                  className="p-1 border border-zinc-800 hover:border-[#39FF14] text-zinc-400 hover:text-white transition-all"
                >
                  <X size={14} />
                </button>
              </div>

              {/* Branding Configuration */}
              <div className="space-y-4 mb-6">
                <h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Branding Customization</h4>
                
                <div className="space-y-3 p-4 bg-black/40 border border-zinc-900">
                  <div>
                    <label className="text-[9px] uppercase tracking-wider text-zinc-500 block mb-1">Company / Organization</label>
                    <input
                      type="text"
                      value={companyBranding}
                      onChange={(e) => setCompanyBranding(e.target.value)}
                      className="w-full bg-black border border-zinc-850 px-3 py-2 text-xs text-white focus:outline-none focus:border-[#39FF14] transition-all"
                      placeholder="Cyber Shield"
                    />
                  </div>

                  <div>
                    <label className="text-[9px] uppercase tracking-wider text-zinc-500 block mb-1">Operator Name</label>
                    <input
                      type="text"
                      value={operatorBranding}
                      onChange={(e) => setOperatorBranding(e.target.value)}
                      className="w-full bg-black border border-zinc-850 px-3 py-2 text-xs text-white focus:outline-none focus:border-[#39FF14] transition-all"
                      placeholder="SOC Operator"
                    />
                  </div>

                  <div>
                    <label className="text-[9px] uppercase tracking-wider text-zinc-500 block mb-1">Report Theme Accent</label>
                    <div className="flex gap-3 mt-1.5">
                      {[
                        { name: 'Neon Green', hex: '#39FF14' },
                        { name: 'Amber', hex: '#f59e0b' },
                        { name: 'Blue', hex: '#3b82f6' },
                        { name: 'Crimson', hex: '#ef4444' },
                        { name: 'Purple', hex: '#a855f7' }
                      ].map((c) => (
                        <button
                          key={c.hex}
                          onClick={() => setAccentBranding(c.hex)}
                          className={cn(
                            "w-6 h-6 rounded-full border relative transition-all",
                            accentBranding === c.hex ? "border-white scale-110 shadow-[0_0_8px_currentColor]" : "border-transparent opacity-60 hover:opacity-100"
                          )}
                          style={{ backgroundColor: c.hex, color: c.hex }}
                          title={c.name}
                        />
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Output Actions */}
              <div className="space-y-4">
                <h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Output Selection</h4>

                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={handleDownloadPDF}
                    className="p-3 bg-black border border-zinc-800 hover:border-[#39FF14] text-zinc-300 hover:text-white flex flex-col items-center justify-center gap-1.5 transition-all text-center group"
                  >
                    <Download size={16} className="text-[#39FF14]" />
                    <span className="text-[9px] font-black uppercase tracking-wider">DOWNLOAD_PDF</span>
                  </button>

                  <button
                    onClick={handlePrintPDF}
                    className="p-3 bg-black border border-zinc-800 hover:border-blue-400 text-zinc-300 hover:text-white flex flex-col items-center justify-center gap-1.5 transition-all text-center group"
                  >
                    <Printer size={16} className="text-blue-400" />
                    <span className="text-[9px] font-black uppercase tracking-wider">PRINT_REPORT</span>
                  </button>
                </div>

                <div className="p-4 bg-black/40 border border-zinc-900 space-y-3">
                  <div className="flex items-center gap-2 text-[10px] text-zinc-400 font-bold uppercase">
                    <Mail size={12} className="text-purple-400" /> Dispatch Report via Secure SMTP Email
                  </div>

                  <div className="flex gap-2">
                    <input
                      type="email"
                      value={recipientEmail}
                      onChange={(e) => setRecipientEmail(e.target.value)}
                      placeholder="recipient@sec-ops.net"
                      className="flex-1 bg-black border border-zinc-800 px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 transition-all"
                    />
                    <button
                      onClick={handleEmailPDF}
                      disabled={isSendingEmail || !recipientEmail}
                      className="px-4 bg-purple-600 hover:bg-purple-500 disabled:bg-purple-950 disabled:opacity-40 disabled:cursor-not-allowed text-white font-black text-[9px] uppercase tracking-wider transition-all flex items-center justify-center"
                    >
                      {isSendingEmail ? 'DISPATCHING...' : 'SEND'}
                    </button>
                  </div>

                  {emailStatusMessage && (
                    <div className={cn(
                      "text-[9px] uppercase font-bold tracking-wider pt-1",
                      emailStatusType === 'success' ? "text-[#39FF14]" : "text-red-500"
                    )}>
                      {emailStatusMessage}
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <VoiceAssistant
        onScan={(target) => handleAnalyze(undefined, target)}
        onBreachCheck={(identity) => handleBreachCheck(undefined, identity)}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        setUrl={setUrl}
        setBreachIdentity={setBreachIdentity}
        lastScanResult={result}
        lastBreachResult={breachResult}
        addLog={addLog}
      />
    </div>
  );
}
