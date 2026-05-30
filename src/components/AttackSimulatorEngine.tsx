import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Play, 
  Pause, 
  RotateCcw, 
  ChevronRight, 
  ChevronLeft, 
  AlertTriangle, 
  ShieldCheck, 
  Terminal, 
  Activity,
  Award,
  BookOpen
} from 'lucide-react';
import { useAuth } from './AuthProvider';
import { db, doc, setDoc, serverTimestamp } from '../lib/firebase';

interface Node {
  id: string;
  label: string;
  x: number;
  y: number;
  type: 'attacker' | 'security' | 'server' | 'database' | 'target' | 'normal';
}

interface Connection {
  from: string;
  to: string;
}

interface Step {
  stepIndex: number;
  title: string;
  description: string;
  activeNodes: string[]; // Node IDs that highlight
  compromisedNodes: string[]; // Node IDs that turn crimson
  particleFlow?: { from: string; to: string; color: string };
}

interface SimulationScenario {
  id: string;
  title: string;
  vector: string;
  description: string;
  nodes: Node[];
  connections: Connection[];
  steps: Step[];
  preventions: string[];
}

export function AttackSimulatorEngine({ addLog }: { addLog: (msg: string) => void }) {
  const { user } = useAuth();
  const currentUserId = user?.uid || 'guest-operator';

  // State
  const [activeScenarioId, setActiveScenarioId] = useState<string>('phishing');
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [speed, setSpeed] = useState<number>(1); // 1 = 2.5s per step, 2 = 1.25s, 0.5 = 5s
  const [completedSims, setCompletedSims] = useState<string[]>([]);
  const [showRewardModal, setShowRewardModal] = useState<boolean>(false);

  // Scenarios Data
  const scenarios: Record<string, SimulationScenario> = {
    phishing: {
      id: 'phishing',
      title: 'Phishing Attack Simulation',
      vector: 'Email Typo-squatting & Credential Theft',
      description: 'Simulates an attacker delivering a spoofed invoice email to steal an operator\'s corporate credentials.',
      nodes: [
        { id: 'attacker', label: 'Attacker Workspace', x: 80, y: 100, type: 'attacker' },
        { id: 'mail_gateway', label: 'Email Gateway', x: 260, y: 100, type: 'security' },
        { id: 'operator_pc', label: 'Operator Client', x: 260, y: 240, type: 'target' },
        { id: 'phish_server', label: 'Phishing Web Portal', x: 480, y: 100, type: 'server' },
        { id: 'hacker_db', label: 'Attacker Creds Ledger', x: 640, y: 170, type: 'database' }
      ],
      connections: [
        { from: 'attacker', to: 'mail_gateway' },
        { from: 'mail_gateway', to: 'operator_pc' },
        { from: 'operator_pc', to: 'phish_server' },
        { from: 'phish_server', to: 'hacker_db' }
      ],
      steps: [
        {
          stepIndex: 0,
          title: 'Delivery of Spoofed Email',
          description: 'The attacker crafts and delivers a phishing email spoofing service@apple-support.com. The gateway allows it because SPF checks pass but DKIM is missing.',
          activeNodes: ['attacker', 'mail_gateway'],
          compromisedNodes: [],
          particleFlow: { from: 'attacker', to: 'mail_gateway', color: '#ef4444' }
        },
        {
          stepIndex: 1,
          title: 'Operator Intercept',
          description: 'The operator PC receives the email. The message urges the user to verify login details immediately to resolve a billing hold.',
          activeNodes: ['mail_gateway', 'operator_pc'],
          compromisedNodes: [],
          particleFlow: { from: 'mail_gateway', to: 'operator_pc', color: '#f59e0b' }
        },
        {
          stepIndex: 2,
          title: 'Portal Redirection',
          description: 'The user clicks the link inside the email, which redirects them to http://secure-verify-apple.co/auth, a domain owned by the attacker.',
          activeNodes: ['operator_pc', 'phish_server'],
          compromisedNodes: ['operator_pc'],
          particleFlow: { from: 'operator_pc', to: 'phish_server', color: '#ef4444' }
        },
        {
          stepIndex: 3,
          title: 'Credential Harvesting',
          description: 'The user enters their credentials. The phishing web server captures the username and password, storing them into the attacker database.',
          activeNodes: ['phish_server', 'hacker_db'],
          compromisedNodes: ['operator_pc', 'phish_server', 'hacker_db'],
          particleFlow: { from: 'phish_server', to: 'hacker_db', color: '#ef4444' }
        }
      ],
      preventions: [
        'Enforce SPF, DKIM, and DMARC alignment filters on incoming email gateways.',
        'Implement Multi-Factor Authentication (MFA) to prevent compromised credentials from giving access.',
        'Train staff to verify URLs (e.g. check for typo-squatting domains) before inputting any credentials.'
      ]
    },
    sqli: {
      id: 'sqli',
      title: 'SQL Injection Simulation',
      vector: 'Unescaped Query Parameter Bypass',
      description: 'Simulates an attacker injecting SQL statements into a web form to bypass database authentication checks.',
      nodes: [
        { id: 'attacker', label: 'Attacker Terminal', x: 80, y: 150, type: 'attacker' },
        { id: 'web_server', label: 'Vulnerable App Server', x: 300, y: 150, type: 'server' },
        { id: 'db_node', label: 'SQL DB Query Parser', x: 500, y: 150, type: 'database' },
        { id: 'db_data', label: 'Operator Database', x: 660, y: 150, type: 'database' }
      ],
      connections: [
        { from: 'attacker', to: 'web_server' },
        { from: 'web_server', to: 'db_node' },
        { from: 'db_node', to: 'db_data' }
      ],
      steps: [
        {
          stepIndex: 0,
          title: 'Malicious Query Injection',
          description: 'Attacker enters the username input: admin\' OR \'1\'=\'1 --. The input contains SQL escape characters and comments.',
          activeNodes: ['attacker', 'web_server'],
          compromisedNodes: [],
          particleFlow: { from: 'attacker', to: 'web_server', color: '#ef4444' }
        },
        {
          stepIndex: 1,
          title: 'Statement Compilation',
          description: 'The app server compiles the SQL query as a raw string: SELECT * FROM users WHERE user=\'admin\' OR \'1\'=\'1\' -- AND pass=\'\'.',
          activeNodes: ['web_server', 'db_node'],
          compromisedNodes: [],
          particleFlow: { from: 'web_server', to: 'db_node', color: '#f59e0b' }
        },
        {
          stepIndex: 2,
          title: 'Logic Evaluation Bypass',
          description: 'The DBMS parses the query. Since \'1\'=\'1\' is always true, the database bypasses the password condition and returns the admin profile.',
          activeNodes: ['db_node', 'db_data'],
          compromisedNodes: ['db_node'],
          particleFlow: { from: 'db_node', to: 'db_data', color: '#ef4444' }
        },
        {
          stepIndex: 3,
          title: 'Unauthorized Administrative Sign-In',
          description: 'The server receives the admin record and authorizes the attacker. Attacker gains full administrative console access.',
          activeNodes: ['web_server', 'attacker'],
          compromisedNodes: ['web_server', 'attacker'],
          particleFlow: { from: 'web_server', to: 'attacker', color: '#39FF14' }
        }
      ],
      preventions: [
        'Use Parameterized Queries / Prepared Statements to treat inputs strictly as parameters, never executable code.',
        'Utilize Object Relational Mapping (ORM) frameworks to abstract queries securely.',
        'Implement Web Application Firewalls (WAF) to detect and block SQL payloads in request payloads.'
      ]
    },
    bruteforce: {
      id: 'bruteforce',
      title: 'SSH Brute Force Simulation',
      vector: 'Dictionary Login Attack',
      description: 'Simulates an attacker attempting to compromise a server SSH port using a list of common credentials.',
      nodes: [
        { id: 'attacker', label: 'Botnet Master Node', x: 80, y: 150, type: 'attacker' },
        { id: 'network_fw', label: 'Edge Router Firewall', x: 300, y: 150, type: 'security' },
        { id: 'target_ssh', label: 'Workstation SSH Port', x: 520, y: 150, type: 'server' },
        { id: 'root_shell', label: 'Root System Console', x: 680, y: 150, type: 'database' }
      ],
      connections: [
        { from: 'attacker', to: 'network_fw' },
        { from: 'network_fw', to: 'target_ssh' },
        { from: 'target_ssh', to: 'root_shell' }
      ],
      steps: [
        {
          stepIndex: 0,
          title: 'SSH Port Scanning',
          description: 'The attacker identifies public port 22 (SSH) open and accepting inbound TCP connections on target subnet.',
          activeNodes: ['attacker', 'network_fw'],
          compromisedNodes: [],
          particleFlow: { from: 'attacker', to: 'network_fw', color: '#a855f7' }
        },
        {
          stepIndex: 1,
          title: 'Dictionary Storm',
          description: 'Attacker launches a automated login bot script submitting 100 requests per minute with passwords (admin, password123, root).',
          activeNodes: ['network_fw', 'target_ssh'],
          compromisedNodes: [],
          particleFlow: { from: 'network_fw', to: 'target_ssh', color: '#ef4444' }
        },
        {
          stepIndex: 2,
          title: 'Lack of Lockout Policy',
          description: 'The server has no lockout limits or rate-limiting rules (missing Fail2ban config). The attack continues uninterrupted.',
          activeNodes: ['target_ssh'],
          compromisedNodes: [],
        },
        {
          stepIndex: 3,
          title: 'Credential Verification Success',
          description: 'The bot script hits matches for user \'root\' with password \'secret123\'. System verifies login, spawning administrative shell.',
          activeNodes: ['target_ssh', 'root_shell'],
          compromisedNodes: ['target_ssh', 'root_shell'],
          particleFlow: { from: 'target_ssh', to: 'root_shell', color: '#ef4444' }
        }
      ],
      preventions: [
        'Disable password authentication for SSH; enforce secure SSH cryptographic keys instead.',
        'Configure utility rate limits such as Fail2ban or DenyHosts to block IPs after multiple failed attempts.',
        'Change standard default SSH ports (e.g. move SSH from 22 to a non-standard higher port).'
      ]
    },
    ransomware: {
      id: 'ransomware',
      title: 'Ransomware Execution Simulation',
      vector: 'Malicious Executable & Local File Encryption',
      description: 'Simulates the execution of a ransomware binary, showing local directory encryption and the final lockout ransom note.',
      nodes: [
        { id: 'email_attachment', label: 'Email PDF Attachment', x: 80, y: 100, type: 'attacker' },
        { id: 'workstation_os', label: 'Workstation OS Kernel', x: 260, y: 170, type: 'target' },
        { id: 'crypto_process', label: 'Encryption Daemon', x: 440, y: 100, type: 'server' },
        { id: 'c2_server', label: 'Attacker Key Escrow', x: 440, y: 240, type: 'attacker' },
        { id: 'encrypted_drive', label: 'Encrypted HDD Sectors', x: 640, y: 170, type: 'database' }
      ],
      connections: [
        { from: 'email_attachment', to: 'workstation_os' },
        { from: 'workstation_os', to: 'crypto_process' },
        { from: 'crypto_process', to: 'c2_server' },
        { from: 'crypto_process', to: 'encrypted_drive' }
      ],
      steps: [
        {
          stepIndex: 0,
          title: 'Double-Extension Execution',
          description: 'The operator executes a file named invoice_2026.pdf.exe, thinking it is a document. The OS starts the stealth process.',
          activeNodes: ['email_attachment', 'workstation_os'],
          compromisedNodes: [],
          particleFlow: { from: 'email_attachment', to: 'workstation_os', color: '#ef4444' }
        },
        {
          stepIndex: 1,
          title: 'Stealth Key Handshake',
          description: 'The spawned daemon process queries the attacker\'s Command & Control (C2) server, exchanging handshake packets and receiving public encryption key.',
          activeNodes: ['workstation_os', 'crypto_process', 'c2_server'],
          compromisedNodes: [],
          particleFlow: { from: 'crypto_process', to: 'c2_server', color: '#a855f7' }
        },
        {
          stepIndex: 2,
          title: 'Background Local Encryption',
          description: 'The encryptor process begins locking local drives, writing encrypted data blocks and suffixing files with `.locked`.',
          activeNodes: ['crypto_process', 'encrypted_drive'],
          compromisedNodes: ['encrypted_drive'],
          particleFlow: { from: 'crypto_process', to: 'encrypted_drive', color: '#ef4444' }
        },
        {
          stepIndex: 3,
          title: 'Ransom Note Lockout',
          description: 'The ransomware terminates critical services, clears shadow volume backups, and displays a crimson lockout ransom note on operator\'s screen.',
          activeNodes: ['workstation_os', 'encrypted_drive'],
          compromisedNodes: ['workstation_os', 'encrypted_drive', 'crypto_process'],
          particleFlow: { from: 'encrypted_drive', to: 'workstation_os', color: '#ef4444' }
        }
      ],
      preventions: [
        'Establish automated, daily, offline backups that cannot be modified or cleared by active workstations.',
        'Deploy Endpoint Detection and Response (EDR) agents to detect and kill bulk file renaming behaviors.',
        'Configure Windows policies to hide extensions for known file types disabled and block executions from `%TEMP%` folders.'
      ]
    },
    hijacking: {
      id: 'hijacking',
      title: 'Session Hijacking Simulation',
      vector: 'Cookie Theft & Token Replay Exploit',
      description: 'Simulates an attacker sniffing a legal user\'s authentication cookie on an insecure connection to hijack their session.',
      nodes: [
        { id: 'user_browser', label: 'Operator Browser', x: 80, y: 100, type: 'target' },
        { id: 'wifi_sniffer', label: 'Attacker Wi-Fi Sniffer', x: 260, y: 170, type: 'attacker' },
        { id: 'auth_server', label: 'Corporate Auth Server', x: 440, y: 100, type: 'server' },
        { id: 'attacker_browser', label: 'Attacker Session', x: 620, y: 170, type: 'attacker' }
      ],
      connections: [
        { from: 'user_browser', to: 'auth_server' },
        { from: 'user_browser', to: 'wifi_sniffer' },
        { from: 'wifi_sniffer', to: 'attacker_browser' },
        { from: 'attacker_browser', to: 'auth_server' }
      ],
      steps: [
        {
          stepIndex: 0,
          title: 'Unencrypted Session Handshake',
          description: 'The operator signs in to an intranet dashboard. The server authenticates them and transmits a session cookie (session_id=CS_992).',
          activeNodes: ['user_browser', 'auth_server'],
          compromisedNodes: [],
          particleFlow: { from: 'user_browser', to: 'auth_server', color: '#39FF14' }
        },
        {
          stepIndex: 1,
          title: 'Passive Token Sniffing',
          description: 'Because the local network is unencrypted, the attacker running a local sniffer captures the raw TCP cookie headers.',
          activeNodes: ['user_browser', 'wifi_sniffer'],
          compromisedNodes: [],
          particleFlow: { from: 'user_browser', to: 'wifi_sniffer', color: '#f59e0b' }
        },
        {
          stepIndex: 2,
          title: 'Session ID Replay Inject',
          description: 'The attacker imports the stolen cookie identifier `CS_992` into their own browser configuration and queries the web console.',
          activeNodes: ['wifi_sniffer', 'attacker_browser'],
          compromisedNodes: ['wifi_sniffer'],
          particleFlow: { from: 'wifi_sniffer', to: 'attacker_browser', color: '#ef4444' }
        },
        {
          stepIndex: 3,
          title: 'Authentication Spoofing Bypass',
          description: 'The web server receives the request, validates token state, and authorizes the hacker as the legal operator. Session hijacked.',
          activeNodes: ['attacker_browser', 'auth_server'],
          compromisedNodes: ['attacker_browser', 'auth_server'],
          particleFlow: { from: 'attacker_browser', to: 'auth_server', color: '#ef4444' }
        }
      ],
      preventions: [
        'Enforce HTTPS everywhere with HTTP Strict Transport Security (HSTS) flags.',
        'Configure session cookie flags: Secure, HttpOnly, and SameSite=Strict to block XSS read access.',
        'Tie active session tokens dynamically to user fingerprints (e.g. browser User-Agent combined with IP subnet).'
      ]
    }
  };

  const activeScenario = scenarios[activeScenarioId];

  // Playback loops
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isPlaying) {
      const delay = (2500 / speed);
      timer = setTimeout(() => {
        if (currentStep < activeScenario.steps.length - 1) {
          setCurrentStep(prev => prev + 1);
        } else {
          setIsPlaying(false);
          // Sim completed
          handleSimCompletion();
        }
      }, delay);
    }
    return () => clearTimeout(timer);
  }, [isPlaying, currentStep, activeScenarioId, speed]);

  const handleSimCompletion = () => {
    if (!completedSims.includes(activeScenarioId)) {
      const nextCompleted = [...completedSims, activeScenarioId];
      setCompletedSims(nextCompleted);
      
      // Reward points in gamification
      rewardSimulatorPoints();
    }
  };

  const rewardSimulatorPoints = async () => {
    // Reward points local mock
    addLog(`SIMULATION_COMPLETED: Finished "${activeScenario.title}" attack analysis flow.`);
    setShowRewardModal(true);

    // Sync to Firestore `/trainingProgress` if authenticated
    if (user && user.uid !== 'mock-analyst-1337') {
      try {
        const localKey = `cyber_shield_training_${currentUserId}`;
        const rawLocal = localStorage.getItem(localKey);
        let currentProgress: { score: number; completedModules: string[]; badges: string[] } = { score: 0, completedModules: [], badges: [] };
        if (rawLocal) {
          currentProgress = JSON.parse(rawLocal);
        }
        
        const newScore = currentProgress.score + 150;
        const moduleKey = `sim_${activeScenarioId}_completed`;
        const nextModules = currentProgress.completedModules.includes(moduleKey)
          ? currentProgress.completedModules
          : [...currentProgress.completedModules, moduleKey];
        
        // Save back
        localStorage.setItem(localKey, JSON.stringify({
          score: newScore,
          completedModules: nextModules,
          badges: currentProgress.badges
        }));

        await setDoc(doc(db, 'trainingProgress', currentUserId), {
          userId: currentUserId,
          score: newScore,
          completedModules: nextModules,
          badges: currentProgress.badges,
          updatedAt: serverTimestamp()
        }, { merge: true });
        
      } catch (err) {
        console.warn("Failed to sync simulator rewards:", err);
      }
    } else {
      // Local Guest
      const localKey = `cyber_shield_training_${currentUserId}`;
      const rawLocal = localStorage.getItem(localKey);
      let currentProgress: { score: number; completedModules: string[]; badges: string[] } = { score: 0, completedModules: [], badges: [] };
      if (rawLocal) {
        currentProgress = JSON.parse(rawLocal);
      }
      localStorage.setItem(localKey, JSON.stringify({
        score: currentProgress.score + 150,
        completedModules: [...currentProgress.completedModules, `sim_${activeScenarioId}_completed`],
        badges: currentProgress.badges
      }));
    }
  };

  const handleScenarioChange = (id: string) => {
    setActiveScenarioId(id);
    setCurrentStep(0);
    setIsPlaying(false);
  };

  const handleStepForward = () => {
    if (currentStep < activeScenario.steps.length - 1) {
      setCurrentStep(prev => prev + 1);
    } else {
      handleSimCompletion();
    }
  };

  const handleStepBackward = () => {
    if (currentStep > 0) {
      setCurrentStep(prev => prev - 1);
    }
  };

  const handleReset = () => {
    setCurrentStep(0);
    setIsPlaying(false);
  };

  // Helper to draw connecting paths between nodes
  const getNodeCoords = (nodeId: string) => {
    const node = activeScenario.nodes.find(n => n.id === nodeId);
    return node ? { x: node.x, y: node.y } : { x: 0, y: 0 };
  };

  return (
    <div className="space-y-6 font-mono text-zinc-300">
      
      {/* Selector Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
        {Object.values(scenarios).map((s) => (
          <button
            key={s.id}
            onClick={() => handleScenarioChange(s.id)}
            className={`py-2 px-2 text-[9px] font-black uppercase tracking-wider border transition-all ${
              activeScenarioId === s.id
                ? 'bg-red-500/10 border-red-500 text-red-400 shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                : 'border-zinc-900 text-zinc-500 hover:border-zinc-800'
            }`}
          >
            {s.id === 'bruteforce' ? 'BRUTE FORCE' : s.id.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Main Simulation Sandbox & Explanation Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        
        {/* Left Column: Visual Sandbox Canvas */}
        <div className="xl:col-span-2 glass-panel border-red-500/20 bg-black/60 p-5 relative overflow-hidden flex flex-col justify-between h-[420px]">
          
          {/* Header metadata */}
          <div className="flex items-center justify-between border-b border-red-500/20 pb-2 mb-2">
            <div>
              <span className="text-[10px] text-red-500 uppercase tracking-widest font-black flex items-center gap-1.5 animate-pulse">
                <Activity size={12} /> CYBER_WARFARE_SIMULATOR
              </span>
              <h2 className="text-xs font-bold text-white mt-0.5 uppercase tracking-wider">{activeScenario.title}</h2>
            </div>
            <div className="text-right">
              <span className="text-[8px] text-zinc-500 uppercase">VECTOR: {activeScenario.vector}</span>
            </div>
          </div>

          {/* SVG Sandbox Map Canvas */}
          <div className="flex-1 w-full relative flex items-center justify-center">
            <svg viewBox="0 0 720 300" className="w-full h-full">
              {/* Grid Background */}
              <defs>
                <pattern id="simGrid" width="30" height="30" patternUnits="userSpaceOnUse">
                  <path d="M 30 0 L 0 0 0 30" fill="none" stroke="rgba(239, 68, 68, 0.03)" strokeWidth="0.5"/>
                </pattern>
                <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(255, 255, 255, 0.1)" />
                </marker>
              </defs>
              <rect width="100%" height="100%" fill="url(#simGrid)" />

              {/* Connections (Lines) */}
              {activeScenario.connections.map((c, idx) => {
                const start = getNodeCoords(c.from);
                const end = getNodeCoords(c.to);
                return (
                  <line
                    key={idx}
                    x1={start.x}
                    y1={start.y}
                    x2={end.x}
                    y2={end.y}
                    stroke="rgba(255, 255, 255, 0.1)"
                    strokeWidth="1.5"
                    markerEnd="url(#arrow)"
                  />
                );
              })}

              {/* Payload Particle Flow animation */}
              {isPlaying && activeScenario.steps[currentStep].particleFlow && (() => {
                const flow = activeScenario.steps[currentStep].particleFlow!;
                const start = getNodeCoords(flow.from);
                const end = getNodeCoords(flow.to);
                return (
                  <circle r="4" fill={flow.color} className="shadow-[0_0_8px_rgba(239,68,68,1)]">
                    <animate attributeName="cx" from={start.x} to={end.x} dur={`${2.5 / speed}s`} repeatCount="indefinite" />
                    <animate attributeName="cy" from={start.y} to={end.y} dur={`${2.5 / speed}s`} repeatCount="indefinite" />
                  </circle>
                );
              })()}

              {/* Nodes (Circles and Labels) */}
              {activeScenario.nodes.map((n) => {
                const isActive = activeScenario.steps[currentStep].activeNodes.includes(n.id);
                const isCompromised = activeScenario.steps[currentStep].compromisedNodes.includes(n.id);
                
                return (
                  <g key={n.id} className="cursor-pointer">
                    {/* Ring highlight if active */}
                    {isActive && (
                      <circle
                        cx={n.x}
                        cy={n.y}
                        r="22"
                        fill="none"
                        stroke={isCompromised ? '#ef4444' : '#f59e0b'}
                        strokeWidth="1"
                        className="animate-ping"
                        style={{ animationDuration: '3s' }}
                      />
                    )}
                    {/* Outer core circle */}
                    <circle
                      cx={n.x}
                      cy={n.y}
                      r="16"
                      fill="#000"
                      stroke={
                        isCompromised ? '#ef4444' :
                        isActive ? '#f59e0b' :
                        n.type === 'attacker' ? '#a855f7' :
                        n.type === 'security' ? '#39FF14' : 'rgba(255, 255, 255, 0.2)'
                      }
                      strokeWidth="2"
                    />
                    {/* Inner glowing dot */}
                    <circle
                      cx={n.x}
                      cy={n.y}
                      r="6"
                      fill={
                        isCompromised ? '#ef4444' :
                        isActive ? '#f59e0b' :
                        n.type === 'attacker' ? '#a855f7' :
                        n.type === 'security' ? '#39FF14' : 'rgba(255, 255, 255, 0.3)'
                      }
                      className={isCompromised ? 'animate-pulse' : ''}
                    />
                    {/* Node Text Label */}
                    <text
                      x={n.x}
                      y={n.y + 32}
                      textAnchor="middle"
                      fill={isCompromised ? '#ef4444' : isActive ? '#fff' : 'rgba(255, 255, 255, 0.5)'}
                      className="text-[9px] uppercase font-bold tracking-tight"
                    >
                      {n.label}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Sandbox controls footer */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-red-500/10 pt-3">
            {/* Playback Controls */}
            <div className="flex gap-2">
              <button
                onClick={handleStepBackward}
                disabled={currentStep === 0}
                className="p-2 border border-zinc-800 text-zinc-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed bg-black/45"
                title="PREVIOUS STEP"
              >
                <ChevronLeft size={12} />
              </button>
              <button
                onClick={() => setIsPlaying(!isPlaying)}
                className={`px-4 py-2 text-[9px] font-black uppercase flex items-center gap-1.5 ${
                  isPlaying ? 'bg-amber-600 text-black' : 'bg-red-600 text-black hover:bg-red-500'
                }`}
              >
                {isPlaying ? <Pause size={10} /> : <Play size={10} />}
                {isPlaying ? 'PAUSE' : 'PLAY_SIM'}
              </button>
              <button
                onClick={handleStepForward}
                disabled={currentStep === activeScenario.steps.length - 1 && isPlaying}
                className="p-2 border border-zinc-800 text-zinc-500 hover:text-white disabled:opacity-30 bg-black/45"
                title="NEXT STEP"
              >
                <ChevronRight size={12} />
              </button>
              <button
                onClick={handleReset}
                className="p-2 border border-zinc-800 text-zinc-400 hover:text-white bg-black/45"
                title="RESET SIMULATION"
              >
                <RotateCcw size={12} />
              </button>
            </div>

            {/* Speed slider */}
            <div className="flex items-center gap-3">
              <span className="text-[8px] text-zinc-500 uppercase tracking-widest">Speed:</span>
              <div className="flex gap-1">
                {([0.5, 1, 2] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setSpeed(s)}
                    className={`px-2 py-1 text-[8px] border font-black ${
                      speed === s ? 'border-red-500 bg-red-950/20 text-red-400' : 'border-zinc-800 text-zinc-500 hover:border-zinc-700'
                    }`}
                  >
                    {s}x
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Explanations & Timeline */}
        <div className="space-y-4">
          
          {/* Timeline Step Explanations */}
          <div className="glass-panel border-purple-500/20 bg-black/60 p-5 space-y-4 min-h-[190px]">
            <h3 className="text-xs text-purple-400 font-bold uppercase tracking-[0.2em] border-b border-purple-500/10 pb-2 flex items-center gap-2">
              <Terminal size={14} /> Attack_Timeline_Logs
            </h3>
            
            <div className="space-y-4">
              {activeScenario.steps.map((s, idx) => {
                const isActive = idx === currentStep;
                const isPassed = idx < currentStep;
                
                return (
                  <div key={idx} className="flex gap-3 text-[10px] relative">
                    {/* Line connecter */}
                    {idx < activeScenario.steps.length - 1 && (
                      <div className={`absolute left-2.5 top-6 w-[1.5px] h-9 ${
                        isPassed ? 'bg-red-500/40' : 'bg-zinc-800'
                      }`} />
                    )}
                    {/* Dot */}
                    <div className={`w-5 h-5 rounded-full border flex items-center justify-center shrink-0 font-bold ${
                      isActive ? 'border-red-500 bg-red-950 text-red-400 animate-pulse' :
                      isPassed ? 'border-red-500/40 bg-black text-red-500/40' :
                      'border-zinc-800 bg-black text-zinc-600'
                    }`}>
                      {idx + 1}
                    </div>
                    {/* Content */}
                    <div className="space-y-1 mt-0.5">
                      <h4 className={`font-black uppercase tracking-wider ${isActive ? 'text-white' : 'text-zinc-500'}`}>
                        {s.title}
                      </h4>
                      {isActive && (
                        <p className="text-[9px] text-zinc-400 leading-relaxed font-mono">
                          {s.description}
                        </p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Prevention playbook */}
          <div className="glass-panel border-emerald-500/20 bg-black/60 p-5 space-y-3">
            <h3 className="text-xs text-emerald-400 font-bold uppercase tracking-[0.2em] border-b border-emerald-500/10 pb-2 flex items-center gap-2">
              <ShieldCheck size={14} className="text-emerald-400" /> Mitigation_Playbook
            </h3>
            <ul className="space-y-2 text-[10px] leading-relaxed text-zinc-400 list-none pl-0">
              {activeScenario.preventions.map((p, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-[#39FF14] mt-0.5 font-bold shrink-0">✓</span>
                  <span>{p}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* Completion reward popup */}
      <AnimatePresence>
        {showRewardModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs font-mono"
          >
            <motion.div
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              className="bg-zinc-950 border-2 border-red-500 p-6 max-w-sm w-full text-center relative overflow-hidden shadow-[0_0_50px_rgba(239,68,68,0.3)]"
            >
              <div className="absolute top-0 right-0 w-32 h-32 bg-linear-to-bl from-red-500/10 to-transparent skew-y-12" />
              
              <div className="inline-block p-4 border-2 border-red-500 text-red-500 bg-red-950/15 rounded-full animate-bounce mb-4 mt-2">
                <Award size={48} />
              </div>

              <h3 className="text-lg font-black italic tracking-tighter text-red-500 uppercase mb-1">ANALYSIS SUCCESSFUL</h3>
              <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-3">VECTOR MODELLING LOCKED</h4>
              <p className="text-[10px] text-zinc-400 leading-relaxed mb-6 uppercase">
                Simulated threat vectors compiled correctly. +150 XP credentials credited to operator progress tracker.
              </p>

              <button
                onClick={() => setShowRewardModal(false)}
                className="w-full bg-red-600 hover:bg-red-500 text-black py-2.5 text-xs font-black uppercase tracking-wider transition-colors"
              >
                Accept Telemetry Reward
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

    </div>
  );
}
