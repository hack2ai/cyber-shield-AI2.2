import React, { useState, useEffect, useRef } from 'react';
import {
  Send,
  Mic,
  MicOff,
  Copy,
  Share2,
  BookOpen,
  Play,
  Check,
  Sparkles,
  Terminal,
  Shield,
  AlertTriangle,
  CheckCircle,
  RefreshCcw,
  Volume2,
  VolumeX,
  HelpCircle,
  Activity,
  X,
  ChevronRight,
  Info,
  Lock,
  Cpu,
  User
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useAuth } from './AuthProvider';
import {
  db,
  collection,
  query,
  where,
  onSnapshot,
  orderBy,
  limit,
  addDoc,
  serverTimestamp,
  handleFirestoreError,
  OperationType
} from '../lib/firebase';

interface ChatMessage {
  id: string;
  userId: string;
  role: 'user' | 'assistant';
  content: string;
  mode: 'chat' | 'learning' | 'simulation';
  timestamp: any;
}

interface QuizQuestion {
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
}

const SECURITY_QUIZZES: QuizQuestion[] = [
  {
    question: "Which of the following is the primary defense against SQL Injection (SQLi) vulnerabilities?",
    options: [
      "Input character length validation",
      "Parameterized queries (prepared statements)",
      "Disabling browser JavaScript rendering",
      "Implementing secondary HTTPS encryption routers"
    ],
    correctAnswer: 1,
    explanation: "Parameterized queries ensure that user inputs are compiled separate from the SQL command structure, completely preventing execution of malicious payload logic."
  },
  {
    question: "WannaCry ransomware (2017) propagated rapidly across local corporate networks by exploiting which Windows vulnerability?",
    options: [
      "EternalBlue (CVE-2017-0144) exploiting SMBv1 protocols",
      "Log4Shell (CVE-2021-44228) exploiting JNDI lookups",
      "Heartbleed (CVE-2014-0160) exploiting OpenSSL heartbeats",
      "BlueKeep (CVE-2019-0708) exploiting Remote Desktop services"
    ],
    correctAnswer: 0,
    explanation: "WannaCry utilized EternalBlue to exploit the Windows Server Message Block v1 (SMBv1) protocol, enabling remote network code execution and automated propagation without credentials."
  },
  {
    question: "What type of attack vector uses Punycode character substitution (e.g. replacing 'o' with Cyrillic 'о') to mimic legitimate domains?",
    options: [
      "DNS Amplification DDoS Attack",
      "IDN Homograph Phishing Attack",
      "Credential Stuffing Spraying",
      "Man-in-the-Middle (MitM) ARP Spoofing"
    ],
    correctAnswer: 1,
    explanation: "IDN Homograph attacks leverage Internationalized Domain Names (IDNs) and character mappings to render lookalike addresses in the browser address bar to trick operators."
  },
  {
    question: "Which security mechanism enforces that a web browser should only load scripts and resources from trusted, explicitly approved domains?",
    options: [
      "CORS (Cross-Origin Resource Sharing)",
      "CSP (Content Security Policy)",
      "TLS Certificate Pinning Protocol",
      "DNSSEC Authority Verification"
    ],
    correctAnswer: 1,
    explanation: "Content Security Policy (CSP) is an HTTP header configuration that restricts script, stylesheet, and data source domains, neutralizing Cross-Site Scripting (XSS) actions."
  },
  {
    question: "If a security analyst notices a high volume of query requests for long, random subdomains (e.g. `z49f78.attacker-infrastructure.net`), what is likely occurring?",
    options: [
      "A SQL Injection entry point check",
      "DNS Tunneling (Data Exfiltration/C2 Communication)",
      "Cross-Site Request Forgery (CSRF) session hijack",
      "A Syn Flood network socket overflow"
    ],
    correctAnswer: 1,
    explanation: "DNS Tunneling encodes target files or commands into subdomains of DNS requests. Since outbound DNS port 53 is rarely blocked, attackers use it for stealth data egress and C2."
  }
];

const SUGGESTED_PROMPTS = [
  "Is this email phishing?",
  "What is ransomware?",
  "How do hackers steal passwords?",
  "Is this website safe?",
  "Explain SQL injection attacks"
];

// Helper to sanitize class names
function cn(...inputs: any[]) {
  return inputs.filter(Boolean).join(' ');
}

// Custom Markdown Renderer Component
function MarkdownRenderer({ text }: { text: string }) {
  const parts = text.split(/(```[\s\S]*?```)/g);

  return (
    <div className="space-y-2 text-xs md:text-sm font-mono leading-relaxed select-text">
      {parts.map((part, index) => {
        if (part.startsWith('```') && part.endsWith('```')) {
          const codeLines = part.slice(3, -3).trim().split('\n');
          let lang = '';
          let code = part.slice(3, -3).trim();
          if (codeLines[0] && !codeLines[0].includes(' ') && codeLines[0].length < 10) {
            lang = codeLines[0];
            code = codeLines.slice(1).join('\n');
          }
          return (
            <div key={index} className="my-2 border border-purple-500/30 bg-black/90 p-3 rounded-none relative group/code font-mono overflow-x-auto text-[11px] text-purple-300">
              {lang && <span className="absolute top-1 right-2 text-[8px] uppercase tracking-widest text-[#39FF14]/50">{lang}</span>}
              <pre className="whitespace-pre">{code}</pre>
              <button
                onClick={() => navigator.clipboard.writeText(code)}
                className="absolute bottom-1 right-2 opacity-0 group-hover/code:opacity-100 transition-opacity bg-[#39FF14]/10 hover:bg-[#39FF14]/20 border border-[#39FF14]/30 px-1.5 py-0.5 text-[8px] text-[#39FF14] uppercase tracking-wider"
              >
                COPY
              </button>
            </div>
          );
        } else {
          const lines = part.split('\n');
          return lines.map((line, lineIdx) => {
            const trimmed = line.trim();
            if (!trimmed) return <div key={lineIdx} className="h-2" />;

            if (trimmed.startsWith('### ')) {
              return <h4 key={lineIdx} className="text-purple-400 font-bold uppercase tracking-wider text-xs mt-3 mb-1 flex items-center gap-1"><Terminal size={10} /> {trimmed.slice(4)}</h4>;
            }
            if (trimmed.startsWith('## ') || trimmed.startsWith('# ')) {
              const content = trimmed.startsWith('## ') ? trimmed.slice(3) : trimmed.slice(2);
              return <h3 key={lineIdx} className="text-purple-400 font-black uppercase tracking-widest text-sm mt-4 mb-2 border-b border-purple-500/20 pb-1">{content}</h3>;
            }

            if (trimmed.startsWith('* ') || trimmed.startsWith('- ')) {
              return (
                <div key={lineIdx} className="flex gap-2 items-start pl-2 text-zinc-300 text-[11px] leading-normal my-0.5">
                  <span className="text-purple-500 mt-1 flex-shrink-0">▶</span>
                  <span>{parseInlineBold(trimmed.slice(2))}</span>
                </div>
              );
            }

            if (trimmed.startsWith('> ')) {
              return (
                <blockquote key={lineIdx} className="border-l-2 border-purple-500/30 pl-3 italic text-zinc-400 my-1 text-[11px]">
                  {parseInlineBold(trimmed.slice(2))}
                </blockquote>
              );
            }

            return (
              <p key={lineIdx} className="text-zinc-300 text-[11px] leading-relaxed">
                {parseInlineBold(trimmed)}
              </p>
            );
          });
        }
      })}
    </div>
  );
}

function parseInlineBold(text: string) {
  const parts = text.split(/(\*\*.*?\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      const boldText = part.slice(2, -2);
      const boldLower = boldText.toLowerCase();
      if (boldLower.includes('critical') || boldLower.includes('high') || boldLower.includes('danger')) {
        return <strong key={i} className="text-red-500 font-black">{boldText}</strong>;
      }
      if (boldLower.includes('medium') || boldLower.includes('suspicious') || boldLower.includes('warning')) {
        return <strong key={i} className="text-amber-500 font-black">{boldText}</strong>;
      }
      if (boldLower.includes('low') || boldLower.includes('safe') || boldLower.includes('info')) {
        return <strong key={i} className="text-[#39FF14] font-black">{boldText}</strong>;
      }
      return <strong key={i} className="text-[#39FF14] font-bold">{boldText}</strong>;
    }
    return part;
  });
}

export function ThreatGPTPanel() {
  const { user } = useAuth();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isLocalFallback, setIsLocalFallback] = useState(false);

  // App Modes: 'chat' | 'learning' | 'simulation'
  const [activeMode, setActiveMode] = useState<'chat' | 'learning' | 'simulation'>('chat');

  // Learning Mode State
  const [currentQuizIndex, setCurrentQuizIndex] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [showExplanation, setShowExplanation] = useState(false);
  const [quizFeedback, setQuizFeedback] = useState<string | null>(null);

  // Simulation Mode State
  const [selectedSim, setSelectedSim] = useState<'wannacry' | 'sqli'>('wannacry');
  const [simulationLogs, setSimulationLogs] = useState<string[]>([]);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationExplanation, setSimulationExplanation] = useState<string | null>(null);
  const simIntervalRef = useRef<any>(null);

  const consoleEndRef = useRef<HTMLDivElement>(null);
  const speechRecognitionRef = useRef<any>(null);

  // 1. Synchronize / Load History
  useEffect(() => {
    const currentUserId = user?.uid || 'guest-operator';
    const isGuestOrMock = currentUserId === 'mock-analyst-1337' || currentUserId === 'guest-operator';

    if (isGuestOrMock) {
      const loadLocalHistory = () => {
        const storageKey = currentUserId === 'mock-analyst-1337'
          ? 'cyber_shield_mock_chat_history'
          : 'cyber_shield_guest_chat_history';
        const local = localStorage.getItem(storageKey);
        if (local) {
          setMessages(JSON.parse(local));
        } else {
          const defaultMsgs: ChatMessage[] = [
            {
              id: 'init-msg',
              userId: currentUserId,
              role: 'assistant',
              content: "### ThreatGPT Terminal Active\n\nNeural interfaces synchronized. I am ThreatGPT, your tactical AI security advisor. Enter custom payloads, ask threat definition queries, or initialize testing vectors below.",
              mode: 'chat',
              timestamp: new Date().toISOString()
            }
          ];
          localStorage.setItem(storageKey, JSON.stringify(defaultMsgs));
          setMessages(defaultMsgs);
        }
      };
      loadLocalHistory();

      const handleStorage = (e: StorageEvent) => {
        const storageKey = currentUserId === 'mock-analyst-1337'
          ? 'cyber_shield_mock_chat_history'
          : 'cyber_shield_guest_chat_history';
        if (e.key === storageKey) {
          loadLocalHistory();
        }
      };
      window.addEventListener('storage', handleStorage);
      return () => window.removeEventListener('storage', handleStorage);
    } else {
      const loadLocalHistory = () => {
        const storageKey = `cyber_shield_local_chat_history_${currentUserId}`;
        const local = localStorage.getItem(storageKey);
        if (local) {
          setMessages(JSON.parse(local));
        } else {
          const defaultMsg: ChatMessage = {
            id: 'init-msg',
            userId: currentUserId,
            role: 'assistant',
            content: "### ThreatGPT Terminal Active (Local Failover)\n\nNeural interfaces synchronized. I am ThreatGPT, your tactical AI security advisor. Enter custom payloads, ask threat definition queries, or initialize testing vectors below.\n\n*Note: Running in Local Failover mode due to Firestore synchronization issues.*",
            mode: 'chat',
            timestamp: new Date().toISOString()
          };
          setMessages([defaultMsg]);
        }
      };

      if (isLocalFallback) {
        loadLocalHistory();
        return;
      }

      // Live firestore integration
      const q = query(
        collection(db, 'chatHistory'),
        where('userId', '==', currentUserId)
      );

      const unsubscribe = onSnapshot(q, (snapshot) => {
        const list = snapshot.docs.map(doc => {
          const data = doc.data();
          return {
            id: doc.id,
            userId: data.userId,
            role: data.role,
            content: data.content,
            mode: data.mode || 'chat',
            timestamp: data.timestamp ? (data.timestamp.toDate ? data.timestamp.toDate().toISOString() : data.timestamp) : new Date().toISOString()
          } as ChatMessage;
        });

        // Sort in memory to avoid requiring a custom composite index in Firestore
        list.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        const sortedList = list.slice(-50);

        if (sortedList.length === 0) {
          const defaultMsg: ChatMessage = {
            id: 'init-msg',
            userId: currentUserId,
            role: 'assistant',
            content: "### ThreatGPT Terminal Active\n\nNeural interfaces synchronized. I am ThreatGPT, your tactical AI security advisor. Enter custom payloads, ask threat definition queries, or initialize testing vectors below.",
            mode: 'chat',
            timestamp: new Date().toISOString()
          };
          setMessages([defaultMsg]);
        } else {
          setMessages(sortedList);
        }
      }, (error) => {
        console.error('Firestore Error chatHistory:', error);
        setIsLocalFallback(true);
        loadLocalHistory();
      });

      return () => unsubscribe();
    }
  }, [user, isLocalFallback]);

  // Scroll to bottom on message updates
  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isGenerating, simulationLogs]);

  // Clean up simulations on unmount
  useEffect(() => {
    return () => {
      if (simIntervalRef.current) clearInterval(simIntervalRef.current);
    };
  }, []);

  // Web Speech recognition hook initialization
  useEffect(() => {
    const SpeechRecognition = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
    if (SpeechRecognition) {
      const recognition = new SpeechRecognition();
      recognition.continuous = false;
      recognition.lang = 'en-US';
      recognition.interimResults = false;

      recognition.onstart = () => {
        setIsListening(true);
      };

      recognition.onresult = (event: any) => {
        const transcript = event.results[0][0].transcript;
        if (transcript) {
          setInputValue(prev => prev + (prev ? ' ' : '') + transcript);
        }
        setIsListening(false);
      };

      recognition.onerror = (event: any) => {
        console.error('Speech recognition error:', event.error);
        setIsListening(false);
      };

      recognition.onend = () => {
        setIsListening(false);
      };

      speechRecognitionRef.current = recognition;
    }
  }, []);

  // 2. Submit Message logic
  const handleSendMessage = async (textToSend: string) => {
    const trimmed = textToSend.trim();
    if (!trimmed || isGenerating) return;

    const currentUserId = user?.uid || 'guest-operator';
    const isGuestOrMock = currentUserId === 'mock-analyst-1337' || currentUserId === 'guest-operator';

    // Add user message locally/persistently
    const userMsg: Omit<ChatMessage, 'id'> = {
      userId: currentUserId,
      role: 'user',
      content: trimmed,
      mode: activeMode,
      timestamp: new Date().toISOString()
    };

    setIsGenerating(true);
    setInputValue('');

    let currentMessages = [...messages];
    let useLocal = isLocalFallback || isGuestOrMock;

    try {
      if (useLocal) {
        const newMsg = { ...userMsg, id: `msg-${Date.now()}` };
        currentMessages.push(newMsg);
        setMessages(currentMessages);

        const storageKey = isGuestOrMock
          ? (currentUserId === 'mock-analyst-1337' ? 'cyber_shield_mock_chat_history' : 'cyber_shield_guest_chat_history')
          : `cyber_shield_local_chat_history_${currentUserId}`;
        localStorage.setItem(storageKey, JSON.stringify(currentMessages));
      } else {
        try {
          await addDoc(collection(db, 'chatHistory'), {
            ...userMsg,
            timestamp: serverTimestamp()
          });
        } catch (fsErr) {
          console.error("Firestore user message write failed, falling back to local storage:", fsErr);
          setIsLocalFallback(true);
          useLocal = true;

          const newMsg = { ...userMsg, id: `msg-${Date.now()}` };
          currentMessages.push(newMsg);
          setMessages(currentMessages);

          const storageKey = `cyber_shield_local_chat_history_${currentUserId}`;
          localStorage.setItem(storageKey, JSON.stringify(currentMessages));
        }
      }

      // API communication
      // Clean history to match endpoint expectations: { role: 'user'|'assistant', content: string }
      const historyForAPI = currentMessages
        .filter(m => m.id !== 'init-msg') // exclude decorative intro
        .map(m => ({
          role: m.role,
          content: m.content
        }));

      const res = await fetch('/api/assistant', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message: trimmed,
          history: historyForAPI
        })
      });

      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
      const data = await res.json();

      const assistantMsg: Omit<ChatMessage, 'id'> = {
        userId: currentUserId,
        role: 'assistant',
        content: data.reply || "Core intelligence array returned empty telemetry.",
        mode: activeMode,
        timestamp: new Date().toISOString()
      };

      if (useLocal) {
        const newMsg = { ...assistantMsg, id: `msg-${Date.now()}` };
        currentMessages.push(newMsg);
        setMessages(currentMessages);

        const storageKey = isGuestOrMock
          ? (currentUserId === 'mock-analyst-1337' ? 'cyber_shield_mock_chat_history' : 'cyber_shield_guest_chat_history')
          : `cyber_shield_local_chat_history_${currentUserId}`;
        localStorage.setItem(storageKey, JSON.stringify(currentMessages));
      } else {
        try {
          await addDoc(collection(db, 'chatHistory'), {
            ...assistantMsg,
            timestamp: serverTimestamp()
          });
        } catch (fsErr) {
          console.error("Firestore assistant message write failed, falling back to local storage:", fsErr);
          setIsLocalFallback(true);

          const newMsg = { ...assistantMsg, id: `msg-${Date.now()}` };
          currentMessages.push(newMsg);
          setMessages(currentMessages);

          const storageKey = `cyber_shield_local_chat_history_${currentUserId}`;
          localStorage.setItem(storageKey, JSON.stringify(currentMessages));
        }
      }
    } catch (e: any) {
      console.error(e);
      // Fallback local message
      const errorMsg: Omit<ChatMessage, 'id'> = {
        userId: currentUserId,
        role: 'assistant',
        content: `### Telemetry Connection Error\n\nFailed to reach the ThreatGPT endpoint. Verify local Node server is running on port 3000.\n\n* **Details**: ${e.message}`,
        mode: activeMode,
        timestamp: new Date().toISOString()
      };

      if (useLocal) {
        const newMsg = { ...errorMsg, id: `msg-${Date.now()}` };
        currentMessages.push(newMsg);
        setMessages(currentMessages);

        const storageKey = isGuestOrMock
          ? (currentUserId === 'mock-analyst-1337' ? 'cyber_shield_mock_chat_history' : 'cyber_shield_guest_chat_history')
          : `cyber_shield_local_chat_history_${currentUserId}`;
        localStorage.setItem(storageKey, JSON.stringify(currentMessages));
      } else {
        try {
          await addDoc(collection(db, 'chatHistory'), {
            ...errorMsg,
            timestamp: serverTimestamp()
          });
        } catch (fsErr) {
          console.error("Firestore error message write failed, falling back to local storage:", fsErr);
          setIsLocalFallback(true);

          const newMsg = { ...errorMsg, id: `msg-${Date.now()}` };
          currentMessages.push(newMsg);
          setMessages(currentMessages);

          const storageKey = `cyber_shield_local_chat_history_${currentUserId}`;
          localStorage.setItem(storageKey, JSON.stringify(currentMessages));
        }
      }
    } finally {
      setIsGenerating(false);
    }
  };

  // Toggle Voice Input
  const toggleSpeech = () => {
    if (!speechRecognitionRef.current) {
      alert("Web Speech API is not supported in this browser. Please use Google Chrome.");
      return;
    }
    if (isListening) {
      speechRecognitionRef.current.stop();
    } else {
      speechRecognitionRef.current.start();
    }
  };

  // Utility Actions
  const copyToClipboard = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const shareResponse = (text: string) => {
    if (navigator.share) {
      navigator.share({
        title: 'ThreatGPT Incident Telemetry',
        text: text
      }).catch(err => console.log(err));
    } else {
      navigator.clipboard.writeText(text);
      alert("Telemetry payload copied to clipboard!");
    }
  };

  // Learning Mode Handlers
  const handleAnswerQuiz = (index: number) => {
    if (showExplanation) return;
    setSelectedAnswer(index);
    const correct = SECURITY_QUIZZES[currentQuizIndex].correctAnswer;
    if (index === correct) {
      setQuizFeedback("CORRECT");
    } else {
      setQuizFeedback("INCORRECT");
    }
    setShowExplanation(true);
  };

  const handleNextQuiz = () => {
    setSelectedAnswer(null);
    setShowExplanation(false);
    setQuizFeedback(null);
    setCurrentQuizIndex(prev => (prev + 1) % SECURITY_QUIZZES.length);
  };

  const handleAskTutor = () => {
    const q = SECURITY_QUIZZES[currentQuizIndex];
    const prompt = `Explain why the correct answer for the quiz is option "${q.options[q.correctAnswer]}". The question was: "${q.question}"`;
    setActiveMode('chat');
    handleSendMessage(prompt);
  };

  // Threat Simulator Actions
  const startSimulation = () => {
    if (isSimulating) return;
    setIsSimulating(true);
    setSimulationExplanation(null);
    setSimulationLogs([]);

    const wannacryLogs = [
      "🛰️ INITIATING WANNACRY LATERAL SPREAD PLAYBOOK...",
      "🔍 Probing Local Subnet 192.168.1.0/24 on Active Port 445...",
      "⚠️ SMBv1 detected on node 192.168.1.42. (Vulnerable status confirmed)",
      "🧬 Preparing EternalBlue Payload buffer pools (CVE-2017-0144)...",
      "⚡ Injecting kernel exploit code into ring-0 memory spaces...",
      "🔓 Backdoor handshake validated via DoublePulsar payload module.",
      "📦 Dropping main ransomware payload executable 'mssecsvc.exe'...",
      "⚙️ Payload registered as system execution service. Spawning task...",
      "🔒 Initializing AES-128 cryptographic file locks recursively...",
      "📁 Encrypted: C:/Users/Public/financial_database.db",
      "📁 Encrypted: C:/Users/Administrator/documents/source_code.zip",
      "🚩 Displaying Ransom Note window '@WanaDecryptor@' demanding $300 BTC.",
      "🏁 Playbook execution complete. Lateral spread infection halted."
    ];

    const sqliLogs = [
      "🕸️ INITIATING SQL INJECTION AUTH BYPASS PLAYBOOK...",
      "🔍 Resolving target infrastructure login node: https://infra-gateway.net/auth",
      "🧪 Input field 'username' detected. Injecting structural bypass symbols...",
      "📤 POST /auth username=admin' OR '1'='1 & password=null",
      "🔄 Backend compilation of unparameterized DB Query:",
      "🖥️ SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND pass = ''",
      "⚙️ Logic parsing: OR '1'='1' returns logic TRUE. Password verification bypassed.",
      "🔓 DB Record matched: User_Row [uid=1, role=Administrator, name=SystemRoot]",
      "🎫 Web Server generates dynamic authentication session token: JWT_1337_ROOT",
      "👑 Session hijacking successful. Administrator dashboard unlocked.",
      "🏁 Playbook execution complete. Admin privilege escalation verified."
    ];

    const logsToRun = selectedSim === 'wannacry' ? wannacryLogs : sqliLogs;
    let logIdx = 0;

    simIntervalRef.current = setInterval(() => {
      if (logIdx < logsToRun.length) {
        setSimulationLogs(prev => [...prev, logsToRun[logIdx]]);
        logIdx++;
      } else {
        clearInterval(simIntervalRef.current);
        setIsSimulating(false);
        // AI explanation fallback/caching
        if (selectedSim === 'wannacry') {
          setSimulationExplanation(
            "### Threat Simulator Explanation: WannaCry propagation\n\n* **Risk Level**: **Critical**\n* **Threat Vectors**: Lateral network spreading via SMBv1 vulnerabilities (CVE-2017-0144). Attackers gain kernel execution privileges via custom payloads (EternalBlue) and persistent backdoors (DoublePulsar).\n* **Prevention Methods**: Disable legacy SMBv1 protocols, deploy the Microsoft MS17-010 security patch, segment routers, and activate network-based IDS/IPS triggers."
          );
        } else {
          setSimulationExplanation(
            "### Threat Simulator Explanation: SQL Injection (SQLi)\n\n* **Risk Level**: **High**\n* **Threat Vectors**: Unsanitized user inputs concatenated directly into dynamic SQL instructions. Attackers insert logic statements (like `OR '1'='1`) to trick database search engines into bypassing filters.\n* **Prevention Methods**: Mandatory use of **Parameterized Queries** or prepared statements, input sanitization libraries, database user role limitations, and web application firewalls."
          );
        }
      }
    }, 1000);
  };

  return (
    <div className="glass-panel border-purple-500/30 bg-black/80 flex flex-col h-[600px] relative overflow-hidden neon-border">
      {/* Decorative CRT line */}
      <div className="absolute inset-0 pointer-events-none opacity-5 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[size:100%_4px,3px_100%]" />

      {/* Header Panel */}
      <div className="border-b border-purple-500/20 px-4 py-3 flex flex-col sm:flex-row justify-between items-center bg-black/45 z-10 gap-3">
        <div className="flex items-center gap-3">
          <div className="p-1 bg-purple-500/20 border border-purple-500 rounded-none animate-pulse">
            <Sparkles size={16} className="text-purple-400" />
          </div>
          <div>
            <h3 className="text-[11px] font-black uppercase tracking-[0.25em] text-purple-400">
              THREATGPT // INTEL_ASSISTANT
            </h3>
            <div className="flex items-center gap-1.5 text-[8px] text-[#39FF14] font-bold">
              <span className="w-1.5 h-1.5 bg-[#39FF14] rounded-full animate-ping" />
              <span>NEURAL_LINK: SYNCHRONIZED</span>
            </div>
          </div>
        </div>

        {/* View Selection Controls */}
        <div className="flex bg-black border border-purple-500/20 p-0.5 gap-0.5">
          <button
            onClick={() => {
              setActiveMode('chat');
              if (simIntervalRef.current) {
                clearInterval(simIntervalRef.current);
                setIsSimulating(false);
              }
            }}
            className={cn(
              "px-3 py-1 text-[8px] font-black uppercase tracking-wider transition-all",
              activeMode === 'chat' ? "bg-purple-500/20 text-purple-400 border border-purple-500/30" : "text-purple-400/40 hover:text-purple-400"
            )}
          >
            CHAT
          </button>
          <button
            onClick={() => {
              setActiveMode('learning');
              if (simIntervalRef.current) {
                clearInterval(simIntervalRef.current);
                setIsSimulating(false);
              }
            }}
            className={cn(
              "px-3 py-1 text-[8px] font-black uppercase tracking-wider transition-all",
              activeMode === 'learning' ? "bg-purple-500/20 text-purple-400 border border-purple-500/30" : "text-purple-400/40 hover:text-purple-400"
            )}
          >
            LEARNING_MODE
          </button>
          <button
            onClick={() => setActiveMode('simulation')}
            className={cn(
              "px-3 py-1 text-[8px] font-black uppercase tracking-wider transition-all",
              activeMode === 'simulation' ? "bg-purple-500/20 text-purple-400 border border-purple-500/30" : "text-purple-400/40 hover:text-purple-400"
            )}
          >
            THREAT_SIMULATOR
          </button>
        </div>
      </div>

      {/* Main Container Panels */}
      <div className="flex-1 overflow-y-auto p-4 custom-scrollbar relative bg-black/30 z-10">
        <AnimatePresence mode="wait">
          {/* 1. CHAT MODE PANEL */}
          {activeMode === 'chat' && (
            <motion.div
              key="chat"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-4"
            >
              {messages.map((msg) => (
                <div
                  key={msg.id}
                  className={cn(
                    "flex flex-col max-w-[85%] space-y-1 my-2 p-3 border",
                    msg.role === 'user'
                      ? "ml-auto border-[#39FF14]/30 bg-black/60 text-right text-[#39FF14]/90"
                      : "mr-auto border-purple-500/20 bg-purple-950/5 text-purple-200"
                  )}
                >
                  <div className="flex justify-between items-center text-[8px] opacity-40 uppercase tracking-widest font-bold border-b border-white/5 pb-1 mb-1.5">
                    <span className="flex items-center gap-1 font-mono">
                      {msg.role === 'user' ? <User size={8} /> : <Cpu size={8} />}
                      {msg.role === 'user' ? 'OPERATOR' : 'THREATGPT'}
                    </span>
                    <span>{msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : ''}</span>
                  </div>

                  {msg.role === 'user' ? (
                    <p className="text-[12px] font-mono leading-relaxed select-text text-left">{msg.content}</p>
                  ) : (
                    <MarkdownRenderer text={msg.content} />
                  )}

                  {msg.role === 'assistant' && (
                    <div className="flex justify-start gap-2 pt-2 border-t border-purple-500/10 mt-2 text-[9px] opacity-40">
                      <button
                        onClick={() => copyToClipboard(msg.id, msg.content)}
                        className="hover:text-purple-400 flex items-center gap-1 px-1 transition-colors"
                      >
                        {copiedId === msg.id ? (
                          <>
                            <Check size={10} className="text-[#39FF14]" />
                            <span className="text-[#39FF14]">COPIED</span>
                          </>
                        ) : (
                          <>
                            <Copy size={10} />
                            <span>COPY_TELEMETRY</span>
                          </>
                        )}
                      </button>
                      <button
                        onClick={() => shareResponse(msg.content)}
                        className="hover:text-purple-400 flex items-center gap-1 px-1 transition-colors"
                      >
                        <Share2 size={10} />
                        <span>SHARE</span>
                      </button>
                    </div>
                  )}
                </div>
              ))}

              {isGenerating && (
                <div className="mr-auto max-w-[85%] border border-purple-500/20 bg-purple-950/5 p-3 space-y-1">
                  <div className="flex items-center gap-1 text-[8px] opacity-40 font-bold uppercase tracking-widest pb-1 border-b border-white/5 mb-1.5">
                    <Cpu size={8} /> THREATGPT // DECODING_THREAT_FLOW...
                  </div>
                  <div className="flex items-center gap-2 p-2">
                    <div className="flex gap-1.5">
                      <span className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                      <span className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                      <span className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                    </div>
                    <span className="text-[10px] text-purple-400/50 animate-pulse font-mono font-bold uppercase">Synthesizing...</span>
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {/* 2. LEARNING MODE PANEL */}
          {activeMode === 'learning' && (
            <motion.div
              key="learning"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-4"
            >
              <div className="p-4 bg-purple-500/5 border border-purple-500/20">
                <div className="flex justify-between items-center mb-3">
                  <span className="text-[9px] font-black uppercase text-purple-400 tracking-wider">
                    MODULE: SECURITY_TUTOR // QUIZ_{currentQuizIndex + 1}_OF_{SECURITY_QUIZZES.length}
                  </span>
                  <div className="flex gap-0.5">
                    {SECURITY_QUIZZES.map((_, idx) => (
                      <div
                        key={idx}
                        className={cn(
                          "w-3 h-1 border",
                          idx === currentQuizIndex
                            ? "bg-purple-500 border-purple-400"
                            : idx < currentQuizIndex
                              ? "bg-purple-900/40 border-purple-800"
                              : "border-purple-950 bg-transparent"
                        )}
                      />
                    ))}
                  </div>
                </div>

                <div className="p-3 bg-black/60 border border-purple-500/10 mb-4">
                  <h4 className="text-[12px] font-bold text-purple-200 leading-relaxed font-mono">
                    {SECURITY_QUIZZES[currentQuizIndex].question}
                  </h4>
                </div>

                <div className="space-y-2">
                  {SECURITY_QUIZZES[currentQuizIndex].options.map((opt, optIdx) => {
                    const isSelected = selectedAnswer === optIdx;
                    const isCorrectAnswer = SECURITY_QUIZZES[currentQuizIndex].correctAnswer === optIdx;

                    let btnStyle = "border-purple-500/20 hover:border-purple-500/50 hover:bg-purple-500/5 text-purple-300";
                    if (showExplanation) {
                      if (isCorrectAnswer) {
                        btnStyle = "border-emerald-500/50 bg-emerald-500/10 text-emerald-400";
                      } else if (isSelected) {
                        btnStyle = "border-red-500/50 bg-red-500/10 text-red-400";
                      } else {
                        btnStyle = "border-purple-500/5 opacity-40 text-purple-500";
                      }
                    } else if (isSelected) {
                      btnStyle = "border-purple-500 bg-purple-500/10 text-purple-200 shadow-[0_0_10px_rgba(168,85,247,0.2)]";
                    }

                    return (
                      <button
                        key={optIdx}
                        disabled={showExplanation}
                        onClick={() => setSelectedAnswer(optIdx)}
                        className={cn(
                          "w-full text-left p-3 text-[11px] font-mono border transition-all flex items-center justify-between group",
                          btnStyle
                        )}
                      >
                        <span className="flex items-center gap-3">
                          <span className="opacity-30 group-hover:opacity-100 transition-opacity font-bold">
                            {String.fromCharCode(65 + optIdx)})
                          </span>
                          <span>{opt}</span>
                        </span>
                        {showExplanation && isCorrectAnswer && <CheckCircle size={12} className="text-emerald-500" />}
                        {showExplanation && isSelected && !isCorrectAnswer && <AlertTriangle size={12} className="text-red-500" />}
                      </button>
                    );
                  })}
                </div>

                {/* Submitting Actions */}
                <div className="mt-4 flex gap-2">
                  {!showExplanation ? (
                    <button
                      disabled={selectedAnswer === null}
                      onClick={() => handleAnswerQuiz(selectedAnswer!)}
                      className="flex-1 bg-purple-600 hover:bg-purple-500 disabled:opacity-20 text-white font-black py-2.5 text-[9px] uppercase tracking-widest transition-all"
                    >
                      SUBMIT_ANSWER_DECI_VAL
                    </button>
                  ) : (
                    <>
                      <button
                        onClick={handleAskTutor}
                        className="flex-1 border border-purple-500/30 text-purple-400 hover:bg-purple-500/10 font-black py-2 text-[9px] uppercase tracking-widest transition-all flex items-center justify-center gap-1.5"
                      >
                        <HelpCircle size={12} /> ASK_THREATGPT_EXPLAIN
                      </button>
                      <button
                        onClick={handleNextQuiz}
                        className="flex-1 bg-purple-600 hover:bg-purple-500 text-white font-black py-2 text-[9px] uppercase tracking-widest transition-all"
                      >
                        NEXT_QUIZ_MODULE
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Tutor Quiz Feedback / Explanations */}
              <AnimatePresence>
                {showExplanation && (
                  <motion.div
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={cn(
                      "p-4 border",
                      quizFeedback === 'CORRECT' ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-300" : "border-red-500/30 bg-red-500/5 text-red-300"
                    )}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      {quizFeedback === 'CORRECT' ? (
                        <>
                          <CheckCircle size={16} className="text-emerald-500" />
                          <span className="text-[10px] font-black tracking-widest uppercase">EVALUATION: CORRECT_ANSWER</span>
                        </>
                      ) : (
                        <>
                          <AlertTriangle size={16} className="text-red-500" />
                          <span className="text-[10px] font-black tracking-widest uppercase">EVALUATION: INCORRECT_ANSWER</span>
                        </>
                      )}
                    </div>
                    <p className="text-[11px] font-mono leading-relaxed text-zinc-300">
                      <strong>Tutor Notes:</strong> {SECURITY_QUIZZES[currentQuizIndex].explanation}
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )}

          {/* 3. SIMULATION MODE PANEL */}
          {activeMode === 'simulation' && (
            <motion.div
              key="simulation"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-4"
            >
              <div className="p-4 bg-purple-500/5 border border-purple-500/20">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4">
                  <div>
                    <span className="text-[9px] font-black uppercase text-purple-400 tracking-wider">
                      VECTOR_SANDBOX // PLAYBOOK_SIMULATOR
                    </span>
                    <h4 className="text-[12px] font-bold text-white uppercase mt-0.5">ACTIVE EXPLOIT PLAYBOOK</h4>
                  </div>

                  <div className="flex gap-2 w-full sm:w-auto">
                    <select
                      value={selectedSim}
                      onChange={(e: any) => setSelectedSim(e.target.value)}
                      disabled={isSimulating}
                      className="bg-black border border-purple-500/30 text-purple-400 text-[9px] font-bold uppercase tracking-wider py-1.5 px-3 focus:outline-none"
                    >
                      <option value="wannacry">WANNACRY_RANSOMWARE</option>
                      <option value="sqli">SQL_INJECTION_BYPASS</option>
                    </select>

                    <button
                      onClick={startSimulation}
                      disabled={isSimulating}
                      className="bg-purple-600 hover:bg-purple-500 disabled:opacity-30 text-white font-black px-4 py-1.5 text-[9px] uppercase tracking-widest transition-all flex items-center gap-1"
                    >
                      <Play size={10} /> RUN_VECTOR
                    </button>
                  </div>
                </div>

                {/* Simulation Logs Output Terminal */}
                <div className="border border-purple-500/30 bg-black p-4 font-mono text-[10px] leading-relaxed text-purple-400 h-[220px] overflow-y-auto space-y-1 relative select-text custom-scrollbar">
                  <div className="absolute top-1 right-2 text-[7px] text-purple-500/30 select-none">TTY: /dev/sandbox</div>
                  {simulationLogs.length === 0 && (
                    <div className="text-purple-500/30 italic flex items-center justify-center h-full">
                      SANDBOX_INIT: Awaiting exploit vector simulation trigger. Click RUN_VECTOR.
                    </div>
                  )}
                  {simulationLogs.map((log, i) => (
                    <div key={i} className="flex gap-2">
                      <span className="text-purple-500/30 font-bold select-none">{i.toString().padStart(2, '0')}</span>
                      <span>{log}</span>
                    </div>
                  ))}
                  <div ref={consoleEndRef} />
                </div>
              </div>

              {/* Simulation AI Explanations */}
              <AnimatePresence>
                {simulationExplanation && (
                  <motion.div
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="p-4 border border-purple-500/20 bg-purple-950/10 text-purple-200"
                  >
                    <div className="flex items-center gap-2 mb-2 pb-1 border-b border-purple-500/10">
                      <Cpu size={14} className="text-purple-400" />
                      <span className="text-[10px] font-black tracking-widest uppercase text-purple-400">ANALYSIS: INCIDENT_POST_MORTEM</span>
                    </div>
                    <MarkdownRenderer text={simulationExplanation} />
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )}
        </AnimatePresence>
        <div ref={consoleEndRef} />
      </div>

      {/* Suggested Prompts (CHAT MODE ONLY) */}
      {activeMode === 'chat' && (
        <div className="px-4 py-2 border-t border-purple-500/10 flex items-center gap-2 bg-black/25 overflow-x-auto whitespace-nowrap custom-scrollbar z-10">
          <span className="text-[8px] font-bold text-purple-400/40 uppercase tracking-widest flex-shrink-0 flex items-center gap-1 select-none">
            <Sparkles size={8} /> SUGGESTED:
          </span>
          {SUGGESTED_PROMPTS.map((prompt, i) => (
            <button
              key={i}
              onClick={() => handleSendMessage(prompt)}
              disabled={isGenerating}
              className="text-[9px] font-mono border border-purple-500/10 hover:border-purple-500/40 bg-black hover:bg-purple-950/20 text-purple-400/60 hover:text-purple-400 px-2.5 py-1 transition-all flex-shrink-0"
            >
              {prompt}
            </button>
          ))}
        </div>
      )}

      {/* Input controls zone */}
      <div className="border-t border-purple-500/20 p-3 bg-black/45 z-10 flex gap-2 items-center">
        {/* Voice dictation button */}
        <button
          onClick={toggleSpeech}
          type="button"
          className={cn(
            "p-3 border rounded-none transition-all flex items-center justify-center flex-shrink-0",
            isListening
              ? "bg-red-500/20 border-red-500 text-red-500 animate-pulse shadow-[0_0_15px_rgba(239,68,68,0.3)]"
              : "bg-black border-purple-500/30 text-purple-400/60 hover:text-purple-400 hover:border-purple-500"
          )}
          title="Voice Command Dictation"
        >
          {isListening ? <MicOff size={16} /> : <Mic size={16} />}
        </button>

        {/* Input Text Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage(inputValue);
          }}
          className="flex-1 flex gap-2 relative"
        >
          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            disabled={isGenerating}
            placeholder={
              isListening
                ? "Listening... Speak now."
                : activeMode === 'chat'
                  ? "Ask ThreatGPT (e.g. 'Explain SQL injection'...)"
                  : activeMode === 'learning'
                    ? "Select options above to complete current tutor segment"
                    : "Simulate exploit vectors above"
            }
            className="w-full bg-black border border-purple-500/30 rounded-none px-4 py-2.5 text-xs md:text-sm focus:outline-none focus:border-purple-500 focus:shadow-[0_0_15px_rgba(168,85,247,0.15)] text-purple-200 placeholder:text-purple-500/25 font-mono"
          />

          <button
            type="submit"
            disabled={isGenerating || !inputValue.trim()}
            className="bg-purple-600 hover:bg-purple-500 active:scale-95 disabled:opacity-20 text-white font-black px-4 py-2.5 rounded-none flex items-center justify-center gap-1.5 transition-all text-xs flex-shrink-0"
          >
            {isGenerating ? (
              <RefreshCcw size={12} className="animate-spin" />
            ) : (
              <>
                <Send size={12} />
                <span className="hidden sm:inline uppercase font-black text-[9px] tracking-widest">SEND</span>
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
