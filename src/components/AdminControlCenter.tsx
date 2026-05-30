import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  Users, 
  Terminal, 
  Activity, 
  Lock, 
  Unlock, 
  Trash2, 
  UserMinus, 
  UserCheck, 
  Plus, 
  Search, 
  RefreshCcw, 
  AlertTriangle,
  Globe
} from 'lucide-react';
import { useAuth } from './AuthProvider';

interface AdminUser {
  uid: string;
  email: string;
  displayName: string;
  role: 'admin' | 'user';
  createdAt: string | Date;
}

interface BlockedDomain {
  domain: string;
  blockedAt: string | Date;
  blockedBy: string;
}

interface SystemScan {
  id: string;
  userId: string;
  target: string;
  classification: 'Safe' | 'Suspicious' | 'Phishing' | 'Malicious';
  threatScore: number;
  createdAt: string | Date;
  type: string;
}

interface SystemLog {
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ALERT' | 'CRITICAL';
  message: string;
}

export function AdminControlCenter({ addLog }: { addLog: (msg: string) => void }) {
  const { user } = useAuth();
  
  // States
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [blockedDomains, setBlockedDomains] = useState<BlockedDomain[]>([]);
  const [scans, setScans] = useState<SystemScan[]>([]);
  const [logs, setLogs] = useState<SystemLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  
  // Form states
  const [newDomain, setNewDomain] = useState('');
  const [userSearch, setUserSearch] = useState('');
  const [domainSearch, setDomainSearch] = useState('');
  
  // Interactive stats
  const [attackVelocity, setAttackVelocity] = useState(1.2); // scans/sec
  const [isSpikeDetected, setIsSpikeDetected] = useState(false);
  const [isLiveReload, setIsLiveReload] = useState(true);

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Get auth headers
  const getAuthHeaders = async (): Promise<Record<string, string>> => {
    if (!user) return {};
    let token = 'mock-admin-token';
    try {
      if (user.uid !== 'mock-analyst-1337') {
        token = await user.getIdToken();
      }
    } catch (e) {
      console.warn('Failed to get real id token, using simulated token:', e);
    }
    return {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    };
  };

  // Fetch admin stats
  const fetchAdminData = async (silent = false) => {
    if (!silent) setLoading(true);
    setErrorMessage(null);
    try {
      const headers = await getAuthHeaders();
      
      // Fetch users
      const usersRes = await fetch('/api/admin/users', { headers });
      if (!usersRes.ok) throw new Error(`Users fetch failed: ${usersRes.statusText}`);
      const usersData = await usersRes.json();
      setUsers(usersData.users || []);

      // Fetch blocked domains
      const domainsRes = await fetch('/api/admin/blocked-domains', { headers });
      if (!domainsRes.ok) throw new Error(`Domains fetch failed: ${domainsRes.statusText}`);
      const domainsData = await domainsRes.json();
      setBlockedDomains(domainsData.blockedDomains || []);

      // Fetch scans
      const scansRes = await fetch('/api/admin/scans', { headers });
      if (!scansRes.ok) throw new Error(`Scans fetch failed: ${scansRes.statusText}`);
      const scansData = await scansRes.json();
      setScans(scansData.scans || []);

      // Fetch logs
      const logsRes = await fetch('/api/admin/logs', { headers });
      if (!logsRes.ok) throw new Error(`Logs fetch failed: ${logsRes.statusText}`);
      const logsData = await logsRes.json();
      setLogs(logsData.logs || []);

      // Calculate threat statistics & spikes
      const recentScans = scansData.scans || [];
      const maliciousCount = recentScans.filter((s: SystemScan) => s.classification === 'Malicious' || s.classification === 'Phishing').length;
      
      // Spike algorithm: if more than 40% of recent scans are malicious, trigger spike warning
      if (recentScans.length >= 3 && maliciousCount / recentScans.length > 0.4) {
        setIsSpikeDetected(true);
      } else {
        setIsSpikeDetected(false);
      }
      
      // Dynamic velocity simulation
      setAttackVelocity(parseFloat((1.0 + Math.random() * 2.0).toFixed(1)));

    } catch (err: any) {
      console.error(err);
      setErrorMessage(err.message || 'Failed to fetch enterprise admin records.');
      addLog(`ADMIN_ERROR: ${err.message}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  // Poll server for updates
  useEffect(() => {
    fetchAdminData();

    let interval: NodeJS.Timeout;
    if (isLiveReload) {
      interval = setInterval(() => {
        fetchAdminData(true);
      }, 5000); // Poll every 5s
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isLiveReload]);

  // Auto-scroll logs terminal
  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Block a domain
  const handleBlockDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain) return;
    
    try {
      const headers = await getAuthHeaders();
      const res = await fetch('/api/admin/block-domain', {
        method: 'POST',
        headers,
        body: JSON.stringify({ domain: newDomain })
      });
      
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to block domain');
      }

      addLog(`ADMIN_ACTION: Domain blocklisted - ${newDomain}`);
      setNewDomain('');
      fetchAdminData(true);
    } catch (err: any) {
      addLog(`ADMIN_ACTION_FAILED: ${err.message}`);
      alert(`Error: ${err.message}`);
    }
  };

  // Unblock a domain
  const handleUnblockDomain = async (domain: string) => {
    if (!confirm(`Are you sure you want to remove ${domain} from the blocklist?`)) return;

    try {
      const headers = await getAuthHeaders();
      const res = await fetch(`/api/admin/blocked-domains/${domain}`, {
        method: 'DELETE',
        headers
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to unblock domain');
      }

      addLog(`ADMIN_ACTION: Domain whitelist restored - ${domain}`);
      fetchAdminData(true);
    } catch (err: any) {
      addLog(`ADMIN_ACTION_FAILED: ${err.message}`);
      alert(`Error: ${err.message}`);
    }
  };

  // Toggle user role
  const handleToggleRole = async (targetUser: AdminUser) => {
    const nextRole = targetUser.role === 'admin' ? 'user' : 'admin';
    if (!confirm(`Confirm promotion/demotion of ${targetUser.displayName} to role: ${nextRole}?`)) return;

    try {
      const headers = await getAuthHeaders();
      const res = await fetch(`/api/admin/users/${targetUser.uid}/role`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ role: nextRole })
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to change role');
      }

      addLog(`ADMIN_ACTION: Updated role for ${targetUser.email} to ${nextRole}`);
      fetchAdminData(true);
    } catch (err: any) {
      addLog(`ADMIN_ACTION_FAILED: ${err.message}`);
      alert(`Error: ${err.message}`);
    }
  };

  // Delete user profile
  const handleDeleteUser = async (uid: string, displayName: string) => {
    if (!confirm(`CAUTION: Are you sure you want to delete operator profile "${displayName}"? This bypasses standard user protection settings.`)) return;

    try {
      const headers = await getAuthHeaders();
      const res = await fetch(`/api/admin/users/${uid}`, {
        method: 'DELETE',
        headers
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to delete user');
      }

      addLog(`ADMIN_ACTION: Operator profile removed - UID: ${uid}`);
      fetchAdminData(true);
    } catch (err: any) {
      addLog(`ADMIN_ACTION_FAILED: ${err.message}`);
      alert(`Error: ${err.message}`);
    }
  };

  // Filter lists based on searches
  const filteredUsers = users.filter(u => 
    u.displayName.toLowerCase().includes(userSearch.toLowerCase()) || 
    u.email.toLowerCase().includes(userSearch.toLowerCase()) ||
    u.role.toLowerCase().includes(userSearch.toLowerCase())
  );

  const filteredDomains = blockedDomains.filter(d => 
    d.domain.toLowerCase().includes(domainSearch.toLowerCase())
  );

  return (
    <div className="space-y-6 font-mono text-zinc-300">
      
      {/* Top Banner Alert / Stats Section */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        
        {/* Metric Card 1 */}
        <div className="glass-panel border-cyan-500/20 bg-black/60 p-4 relative overflow-hidden flex flex-col justify-between">
          <div className="absolute top-0 right-0 w-24 h-full bg-linear-to-l from-cyan-500/5 to-transparent skew-x-12" />
          <div className="flex items-center justify-between text-cyan-400">
            <span className="text-[10px] uppercase tracking-widest">Active_Operators</span>
            <Users size={16} />
          </div>
          <div className="mt-4">
            <span className="text-3xl font-black italic tracking-tighter text-cyan-400">{users.length}</span>
            <p className="text-[9px] text-zinc-500 uppercase mt-1">Managed accounts index</p>
          </div>
        </div>

        {/* Metric Card 2 */}
        <div className="glass-panel border-purple-500/20 bg-black/60 p-4 relative overflow-hidden flex flex-col justify-between">
          <div className="absolute top-0 right-0 w-24 h-full bg-linear-to-l from-purple-500/5 to-transparent skew-x-12" />
          <div className="flex items-center justify-between text-purple-400">
            <span className="text-[10px] uppercase tracking-widest">Sys_Scan_Volume</span>
            <Activity size={16} />
          </div>
          <div className="mt-4">
            <span className="text-3xl font-black italic tracking-tighter text-purple-400">{scans.length}</span>
            <p className="text-[9px] text-zinc-500 uppercase mt-1">Aggregated historical logs</p>
          </div>
        </div>

        {/* Metric Card 3 */}
        <div className="glass-panel border-red-500/20 bg-black/60 p-4 relative overflow-hidden flex flex-col justify-between">
          <div className="absolute top-0 right-0 w-24 h-full bg-linear-to-l from-red-500/5 to-transparent skew-x-12" />
          <div className="flex items-center justify-between text-red-500">
            <span className="text-[10px] uppercase tracking-widest">Domain_Blocklist</span>
            <Lock size={16} />
          </div>
          <div className="mt-4">
            <span className="text-3xl font-black italic tracking-tighter text-red-500">{blockedDomains.length}</span>
            <p className="text-[9px] text-zinc-500 uppercase mt-1">Explicit blacklisted hosts</p>
          </div>
        </div>

        {/* Metric Card 4 - Attack Spike Status */}
        <div className={`glass-panel p-4 relative overflow-hidden flex flex-col justify-between border-2 ${
          isSpikeDetected ? 'border-red-500 bg-red-950/20 animate-pulse' : 'border-emerald-500/20 bg-black/60'
        }`}>
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase tracking-widest">Threat_Velocity</span>
            <AlertTriangle size={16} className={isSpikeDetected ? 'text-red-500' : 'text-emerald-500'} />
          </div>
          <div className="mt-4">
            <span className={`text-3xl font-black italic tracking-tighter ${isSpikeDetected ? 'text-red-500' : 'text-emerald-400'}`}>
              {attackVelocity} /s
            </span>
            <p className="text-[9px] uppercase mt-1 text-zinc-500">
              {isSpikeDetected ? 'CRITICAL SPIKE DETECTED' : 'System nominal'}
            </p>
          </div>
        </div>
      </div>

      {/* Connection & Error banner */}
      {errorMessage && (
        <div className="p-4 bg-red-950/40 border border-red-500/30 text-red-400 text-[10px] flex items-center gap-3">
          <AlertTriangle size={14} className="animate-bounce" />
          <div>
            <p className="font-bold uppercase">DATABASE DISCONNECT DETECTED:</p>
            <p className="opacity-75">{errorMessage}</p>
          </div>
        </div>
      )}

      {/* Cyber Map & Live Terminal Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Threat Map Component */}
        <div className="lg:col-span-2 glass-panel border-[#39FF14]/10 bg-black/60 p-5 relative overflow-hidden h-[320px]">
          <div className="absolute top-2 left-2 z-10">
            <h3 className="text-[10px] text-[#39FF14] uppercase tracking-widest flex items-center gap-2">
              <Globe size={12} className="animate-spin" style={{ animationDuration: '8s' }} /> SOC_REALTIME_THREAT_MAP
            </h3>
          </div>
          
          <div className="w-full h-full flex items-center justify-center relative mt-3">
            {/* SVG Cyberpunk Grid Map */}
            <svg viewBox="0 0 800 350" className="w-full h-full opacity-60">
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(57, 255, 20, 0.05)" strokeWidth="0.5"/>
                </pattern>
                <linearGradient id="neonGlow" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#39FF14" stopOpacity="0.8"/>
                  <stop offset="100%" stopColor="#ec4899" stopOpacity="0.2"/>
                </linearGradient>
              </defs>
              
              <rect width="100%" height="100%" fill="url(#grid)" />

              {/* Map Contours (Mocked grid lines representing vectors) */}
              <circle cx="400" cy="175" r="140" fill="none" stroke="rgba(57,255,20,0.1)" strokeWidth="1" strokeDasharray="5,5" />
              <circle cx="400" cy="175" r="80" fill="none" stroke="rgba(57,255,20,0.15)" strokeWidth="1" />
              <circle cx="400" cy="175" r="220" fill="none" stroke="rgba(57,255,20,0.05)" strokeWidth="1" strokeDasharray="10,10" />

              {/* Central Server Node */}
              <circle cx="400" cy="175" r="6" fill="#39FF14" className="animate-pulse" />
              <circle cx="400" cy="175" r="20" fill="none" stroke="#39FF14" strokeWidth="0.5" className="animate-ping" style={{ animationDuration: '3s' }} />

              {/* Target attack hubs */}
              {/* North America */}
              <circle cx="180" cy="110" r="4" fill="#ef4444" />
              <path d="M 180 110 Q 290 80 400 175" fill="none" stroke="url(#neonGlow)" strokeWidth="1.5" strokeDasharray="3 3" />
              
              {/* East Asia */}
              <circle cx="650" cy="120" r="4" fill="#ef4444" />
              <path d="M 650 120 Q 525 100 400 175" fill="none" stroke="#ef4444" strokeWidth="1.5" strokeDasharray="5 5" />
              
              {/* Eastern Europe */}
              <circle cx="500" cy="90" r="4" fill="#ec4899" />
              <path d="M 500 90 L 400 175" fill="none" stroke="#ec4899" strokeWidth="1" />

              {/* Scanning signals */}
              <motion.circle
                r="3" fill="#39FF14"
                animate={{
                  cx: [180, 400],
                  cy: [110, 175],
                  opacity: [0, 1, 0]
                }}
                transition={{ duration: 3, repeat: Infinity, ease: 'easeIn' }}
              />
              <motion.circle
                r="3" fill="#ef4444"
                animate={{
                  cx: [650, 400],
                  cy: [120, 175],
                  opacity: [0, 1, 0]
                }}
                transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              />
              
              {/* Ping alerts */}
              {isSpikeDetected && (
                <text x="400" y="320" textAnchor="middle" fill="#ef4444" className="text-xs font-black animate-pulse uppercase tracking-widest">
                  ⚠️ TRAFFIC OVERLOAD DETECTED - SPIKE ON ASIA-NODE
                </text>
              )}
            </svg>
          </div>
        </div>

        {/* Console Log Terminal */}
        <div className="glass-panel border-purple-500/20 bg-black/85 p-4 flex flex-col justify-between h-[320px]">
          <div className="flex items-center justify-between border-b border-purple-500/20 pb-2 mb-2">
            <span className="text-[10px] text-purple-400 font-bold uppercase tracking-widest flex items-center gap-2">
              <Terminal size={12} className="animate-pulse" /> LIVE_DAEMON_LOGS
            </span>
            <div className="flex items-center gap-2">
              <span className="text-[8px] text-purple-400/50 uppercase">LIVE</span>
              <button 
                onClick={() => setIsLiveReload(!isLiveReload)} 
                className={`w-2 h-2 rounded-full ${isLiveReload ? 'bg-emerald-500 animate-ping' : 'bg-zinc-600'}`}
              />
            </div>
          </div>
          
          <div className="flex-1 overflow-y-auto text-[9px] leading-relaxed font-mono space-y-1 pr-1 custom-scrollbar">
            {logs.length === 0 ? (
              <p className="text-zinc-600 italic">Logs buffer empty. Awaiting system triggers...</p>
            ) : (
              logs.map((log, i) => (
                <div key={i} className="flex items-start gap-1">
                  <span className="text-zinc-600">[{log.timestamp.slice(11, 19)}]</span>
                  <span className={`font-black ${
                    log.level === 'CRITICAL' || log.level === 'ALERT' ? 'text-red-500' :
                    log.level === 'WARN' ? 'text-amber-500' : 'text-cyan-400'
                  }`}>
                    {log.level}:
                  </span>
                  <span className="text-zinc-400 break-all">{log.message}</span>
                </div>
              ))
            )}
            <div ref={logsEndRef} />
          </div>

          <div className="text-[8px] text-purple-500/50 border-t border-purple-500/10 pt-1 mt-2 text-right">
            BUFFER: {logs.length}/100 ACTIONS
          </div>
        </div>
      </div>

      {/* User Management & Domain Blocklist Section */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        
        {/* User Management */}
        <div className="glass-panel border-cyan-500/10 bg-black/60 p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyan-500/10 pb-3">
            <h3 className="text-xs text-cyan-400 font-bold uppercase tracking-[0.2em] flex items-center gap-2">
              <Users size={14} /> Operator_Credential_Audit
            </h3>
            
            {/* Search */}
            <div className="relative">
              <Search size={10} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-cyan-500/50" />
              <input
                type="text"
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
                placeholder="FILTER OPERATORS..."
                className="bg-black/60 border border-cyan-500/20 text-[9px] pl-7 pr-3 py-1 text-cyan-400 rounded-none focus:outline-none focus:border-cyan-400 uppercase w-full sm:w-44"
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[10px]">
              <thead>
                <tr className="border-b border-cyan-500/10 text-cyan-400/60 text-[8px] uppercase tracking-wider">
                  <th className="py-2">Operator</th>
                  <th className="py-2">Email</th>
                  <th className="py-2">Access_Role</th>
                  <th className="py-2 text-right">Operational_Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyan-500/5">
                {filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-zinc-500 italic">No operators matching search</td>
                  </tr>
                ) : (
                  filteredUsers.map((u) => (
                    <tr key={u.uid} className="hover:bg-cyan-500/5 transition-colors">
                      <td className="py-3 font-bold text-white max-w-[120px] truncate">{u.displayName}</td>
                      <td className="py-3 text-zinc-400 max-w-[150px] truncate">{u.email}</td>
                      <td className="py-3">
                        <span className={`px-1.5 py-0.5 text-[8px] font-black uppercase rounded-xs ${
                          u.role === 'admin' 
                            ? 'bg-purple-500/20 border border-purple-500 text-purple-400' 
                            : 'bg-zinc-800 border border-zinc-700 text-zinc-400'
                        }`}>
                          {u.role}
                        </span>
                      </td>
                      <td className="py-3 text-right space-x-2">
                        {/* Protect self promotion/demotion */}
                        {u.uid !== user?.uid ? (
                          <>
                            <button
                              onClick={() => handleToggleRole(u)}
                              title={u.role === 'admin' ? "DEMOTE TO OPERATOR" : "PROMOTE TO ADMINISTRATOR"}
                              className="text-cyan-400 hover:text-cyan-300 p-1 border border-cyan-500/20 hover:border-cyan-400/50 bg-black/40"
                            >
                              {u.role === 'admin' ? <UserMinus size={10} /> : <UserCheck size={10} />}
                            </button>
                            <button
                              onClick={() => handleDeleteUser(u.uid, u.displayName)}
                              title="DELETE ACCOUNT PROFILE"
                              className="text-red-500 hover:text-red-400 p-1 border border-red-500/20 hover:border-red-500/50 bg-black/40"
                            >
                              <Trash2 size={10} />
                            </button>
                          </>
                        ) : (
                          <span className="text-[8px] text-zinc-600 uppercase">SELF_LOCKED</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Malicious Domain Blocklist */}
        <div className="glass-panel border-red-500/10 bg-black/60 p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-red-500/10 pb-3">
            <h3 className="text-xs text-red-500 font-bold uppercase tracking-[0.2em] flex items-center gap-2">
              <Lock size={14} className="text-red-500" /> Enterprise_Domain_Blacklist
            </h3>
            
            {/* Search */}
            <div className="relative">
              <Search size={10} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-red-500/50" />
              <input
                type="text"
                value={domainSearch}
                onChange={(e) => setDomainSearch(e.target.value)}
                placeholder="FILTER BLACKLIST..."
                className="bg-black/60 border border-red-500/20 text-[9px] pl-7 pr-3 py-1 text-red-500 rounded-none focus:outline-none focus:border-red-500 uppercase w-full sm:w-44"
              />
            </div>
          </div>

          {/* Form to Block Domain */}
          <form onSubmit={handleBlockDomain} className="flex gap-2">
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="ENTER MALICIOUS DOMAIN... (e.g. dangerous.ru)"
              className="flex-1 bg-black/60 border border-red-500/30 text-[9px] px-3 py-1.5 text-red-400 rounded-none focus:outline-none focus:border-red-500 uppercase"
            />
            <button
              type="submit"
              className="bg-red-500/10 hover:bg-red-500/20 border border-red-500 text-red-400 px-3 py-1.5 text-[9px] font-black uppercase tracking-wider flex items-center gap-1.5 transition-colors"
            >
              <Plus size={12} /> BLOCK_HOST
            </button>
          </form>

          {/* Blocked Domains Table */}
          <div className="overflow-x-auto h-[160px] overflow-y-auto custom-scrollbar">
            <table className="w-full text-left border-collapse text-[10px]">
              <thead>
                <tr className="border-b border-red-500/10 text-red-500/60 text-[8px] uppercase tracking-wider">
                  <th className="py-2">Blacklisted_Host</th>
                  <th className="py-2">Blocked_Date</th>
                  <th className="py-2">Enforced_By</th>
                  <th className="py-2 text-right">Policy_Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-red-500/5">
                {filteredDomains.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-zinc-500 italic">No blacklisted hosts matching filters</td>
                  </tr>
                ) : (
                  filteredDomains.map((d) => (
                    <tr key={d.domain} className="hover:bg-red-500/5 transition-colors">
                      <td className="py-2 font-bold text-red-400 max-w-[150px] truncate">{d.domain}</td>
                      <td className="py-2 text-zinc-500">
                        {typeof d.blockedAt === 'string' ? d.blockedAt.slice(0, 10) : new Date(d.blockedAt).toLocaleDateString()}
                      </td>
                      <td className="py-2 text-zinc-400 truncate max-w-[100px]">{d.blockedBy === 'mock-analyst-1337' ? 'analyst@cyber-shield.ai' : d.blockedBy}</td>
                      <td className="py-2 text-right">
                        <button
                          onClick={() => handleUnblockDomain(d.domain)}
                          className="text-red-500 hover:text-red-400 p-1 border border-red-500/20 hover:border-red-500/50 bg-black/40"
                          title="REMOVE BLOCK (WHITELIST)"
                        >
                          <Unlock size={10} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* System Scans Monitor - List of recent scans across the entire system */}
      <div className="glass-panel border-purple-500/10 bg-black/60 p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-purple-500/10 pb-3">
          <h3 className="text-xs text-purple-400 font-bold uppercase tracking-[0.2em] flex items-center gap-2">
            <Activity size={14} /> Enterprise_Scan_Aggregator
          </h3>
          <button 
            onClick={() => fetchAdminData()} 
            className="text-zinc-500 hover:text-purple-400 p-1 hover:bg-purple-500/5 transition-colors"
            title="REFRESH SCAN LIST"
          >
            <RefreshCcw size={10} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>

        <div className="overflow-x-auto max-h-[250px] overflow-y-auto custom-scrollbar">
          <table className="w-full text-left border-collapse text-[10px]">
            <thead>
              <tr className="border-b border-purple-500/10 text-purple-400/60 text-[8px] uppercase tracking-wider">
                <th className="py-2">Scan_Target</th>
                <th className="py-2">Scan_Type</th>
                <th className="py-2">Operator_UID</th>
                <th className="py-2">Classification</th>
                <th className="py-2">Threat_Score</th>
                <th className="py-2 text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-purple-500/5">
              {scans.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-zinc-500 italic">No historical scan entries found</td>
                </tr>
              ) : (
                scans.map((s) => (
                  <tr key={s.id} className="hover:bg-purple-500/5 transition-colors">
                    <td className="py-2.5 font-bold text-white max-w-[200px] truncate" title={s.target}>
                      {s.target}
                    </td>
                    <td className="py-2.5">
                      <span className="px-1 py-0.5 text-[7px] font-black uppercase bg-purple-950/20 border border-purple-500/30 text-purple-300">
                        {s.type}
                      </span>
                    </td>
                    <td className="py-2.5 text-zinc-400 truncate max-w-[100px]" title={s.userId}>
                      {s.userId === 'mock-analyst-1337' ? 'analyst@cyber-shield.ai' : s.userId}
                    </td>
                    <td className="py-2.5">
                      <span className={`font-black ${
                        s.classification === 'Safe' ? 'text-[#39FF14]' :
                        s.classification === 'Suspicious' ? 'text-amber-500' :
                        'text-red-500'
                      }`}>
                        {s.classification}
                      </span>
                    </td>
                    <td className="py-2.5 font-bold">{s.threatScore}</td>
                    <td className="py-2.5 text-right text-zinc-500">
                      {typeof s.createdAt === 'string' ? s.createdAt.slice(11, 19) : new Date(s.createdAt).toLocaleTimeString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
