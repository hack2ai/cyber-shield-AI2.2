import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Mic, MicOff, Volume2, VolumeX, HelpCircle, X, Shield, Terminal } from 'lucide-react';

interface VoiceAssistantProps {
  onScan: (target: string) => Promise<void> | void;
  onBreachCheck: (identity: string) => Promise<void> | void;
  activeTab: string;
  setActiveTab: (tab: any) => void;
  setUrl: (url: string) => void;
  setBreachIdentity: (identity: string) => void;
  lastScanResult: any;
  lastBreachResult: any;
  addLog: (msg: string) => void;
}

export function VoiceAssistant({
  onScan,
  onBreachCheck,
  activeTab,
  setActiveTab,
  setUrl,
  setBreachIdentity,
  lastScanResult,
  lastBreachResult,
  addLog
}: VoiceAssistantProps) {
  const [isSupported, setIsSupported] = useState(true);
  const [isListening, setIsListening] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [transcript, setTranscript] = useState('');
  const [statusText, setStatusText] = useState('SYSTEM READY');
  const [isMuted, setIsMuted] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [isOpen, setIsOpen] = useState(false);

  const recognitionRef = useRef<any>(null);
  const synthRef = useRef<SpeechSynthesis | null>(null);
  const activeUtteranceRef = useRef<SpeechSynthesisUtterance | null>(null);

  // References to avoid reading stale state in results listener
  const scanSourceRef = useRef<'voice' | 'manual' | null>(null);
  const recognitionActiveRef = useRef(false);

  // Initialize Speech Synthesis
  useEffect(() => {
    if (typeof window !== 'undefined') {
      synthRef.current = window.speechSynthesis;
    }
  }, []);

  // Initialize Speech Recognition
  useEffect(() => {
    const SpeechRecognition = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
    if (!SpeechRecognition) {
      setIsSupported(false);
      return;
    }

    const recognition = new SpeechRecognition();
    recognition.continuous = false;
    recognition.lang = 'en-US';
    recognition.interimResults = false;

    recognition.onstart = () => {
      recognitionActiveRef.current = true;
      setIsListening(true);
      setTranscript('');
      setStatusText('LISTENING FOR COMMAND...');
      addLog('VOICE_ASSISTANT: Microphone recording active...');
    };

    recognition.onresult = (event: any) => {
      setIsListening(false);
      recognitionActiveRef.current = false;
      const rawText = event.results[0][0].transcript;
      if (rawText) {
        setTranscript(rawText);
        processVoiceCommand(rawText);
      }
    };

    recognition.onerror = (event: any) => {
      console.error('Voice assistant recognition error:', event.error);
      setIsListening(false);
      recognitionActiveRef.current = false;
      
      const errType = event.error;
      if (errType === 'aborted') {
        setStatusText('SYSTEM READY');
        return;
      }
      
      if (errType === 'no-speech') {
        setStatusText('NO SPEECH DETECTED');
        speakText('No speech was detected. Please try again.');
        return;
      }
      
      if (errType === 'not-allowed') {
        setStatusText('MIC ACCESS DENIED');
        speakText('Microphone access was denied. Please check your browser permissions.');
        return;
      }

      if (errType === 'audio-capture') {
        setStatusText('MIC NOT FOUND');
        speakText('No microphone was found. Please connect a microphone and try again.');
        return;
      }

      if (errType === 'network') {
        setStatusText('NETWORK ERROR');
        speakText('Speech recognition network communication failed. Please check your internet connection.');
        return;
      }

      if (errType === 'service-not-allowed') {
        setStatusText('SERVICE BLOCKED');
        speakText('Speech recognition service is not allowed by your browser. Please ensure the app runs on a secure origin.');
        return;
      }

      setStatusText('ERROR: ' + errType.toUpperCase());
      speakText(`Sorry, there was a recording error: ${errType}. Please try again.`);
    };

    recognition.onend = () => {
      setIsListening(false);
      recognitionActiveRef.current = false;
    };

    recognitionRef.current = recognition;
  }, []);

  // Listen to results and speak when a voice-initiated scan resolves
  useEffect(() => {
    if (scanSourceRef.current === 'voice' && lastScanResult) {
      scanSourceRef.current = null; // reset
      const text = `Scan completed for target ${lastScanResult.target}. The threat level is ${lastScanResult.classification} with a risk score of ${lastScanResult.threatScore} percent. Recommendation: ${lastScanResult.recommendation}`;
      speakText(text);
      setStatusText(`SCAN COMPLETE: SCORE ${lastScanResult.threatScore}`);
    }
  }, [lastScanResult]);

  useEffect(() => {
    if (scanSourceRef.current === 'voice' && lastBreachResult) {
      scanSourceRef.current = null; // reset
      const count = lastBreachResult.breachCount;
      const text = count === 0
        ? `Audit completed. Good news! The identity ${lastBreachResult.identity} has not appeared in any known data breaches.`
        : `Audit completed. Exposure detected. The identity ${lastBreachResult.identity} was found in ${count} database breaches. Recommendations: ${lastBreachResult.recommendations[0]}`;
      speakText(text);
      setStatusText(`BREACH AUDIT COMPLETE: ${count} BREACHES`);
    }
  }, [lastBreachResult]);

  // Clean up speech synthesis on unmount
  useEffect(() => {
    return () => {
      if (synthRef.current) {
        synthRef.current.cancel();
      }
    };
  }, []);

  // Text-to-Speech synthesizer
  const speakText = (text: string) => {
    if (isMuted || !synthRef.current) return;

    // Cancel current speech if any
    synthRef.current.cancel();

    const utterance = new SpeechSynthesisUtterance(text);
    
    // Choose a nice high-quality default voice
    const voices = synthRef.current.getVoices();
    const naturalVoice = voices.find(v => v.name.includes('Google') || v.name.includes('Natural') || v.lang.startsWith('en'));
    if (naturalVoice) {
      utterance.voice = naturalVoice;
    }

    utterance.onstart = () => {
      setIsSpeaking(true);
      setStatusText('SPEAKING...');
    };

    utterance.onend = () => {
      setIsSpeaking(false);
      setStatusText('SYSTEM READY');
    };

    utterance.onerror = () => {
      setIsSpeaking(false);
      setStatusText('SYSTEM READY');
    };

    activeUtteranceRef.current = utterance;
    synthRef.current.speak(utterance);
  };

  // Toggle Listening State
  const toggleListening = () => {
    if (!isSupported) {
      alert("Web Speech API is not supported in this browser. Please use Google Chrome or Microsoft Edge.");
      return;
    }

    // Stop speaking if active
    if (synthRef.current && isSpeaking) {
      synthRef.current.cancel();
      setIsSpeaking(false);
      setStatusText('SYSTEM READY');
      return;
    }

    if (recognitionActiveRef.current) {
      try {
        recognitionRef.current.abort();
      } catch (err) {
        console.error("Failed to abort voice recognition:", err);
      }
    } else {
      try {
        recognitionRef.current.start();
      } catch (err) {
        console.error("Failed to start voice recognition:", err);
        setStatusText('ERROR STARTING');
        speakText('Failed to start speech recognition. Please try again.');
      }
    }
  };

  // Voice command processor
  const processVoiceCommand = (command: string) => {
    setIsProcessing(true);
    setStatusText('PROCESSING COMMAND...');
    addLog(`VOICE_COMMAND_RAW: "${command}"`);

    // Clean up transcription anomalies (e.g., dot, dot com, at, etc.)
    let normalized = command.toLowerCase().trim();
    normalized = normalized
      .replace(/\s+dot\s+/g, '.')
      .replace(/\s+at\s+/g, '@')
      .replace(/\s+/g, ' ');

    console.log('Voice Command Normalized:', normalized);

    // 1. Scan URL command: "scan (this) url [target]" or "scan [target]"
    const urlMatch = normalized.match(/^(?:scan|check|analyze)(?:\s+this)?\s+url\s+([^\s]+)/i) || 
                     normalized.match(/^scan\s+url\s+([^\s]+)/i);

    // 2. Check Email command: "check (this) email [target]" or "check email [target]"
    const emailMatch = normalized.match(/^(?:check|scan|audit)(?:\s+this)?\s+email\s+([^\s]+)/i) ||
                       normalized.match(/^check\s+email\s+([^\s]+)/i);

    // 3. Analyze Domain command: "analyze (this) domain [target]" or "analyze [target]"
    const domainMatch = normalized.match(/^(?:analyze|check|scan)(?:\s+this)?\s+domain\s+([^\s]+)/i) ||
                        normalized.match(/^analyze\s+domain\s+([^\s]+)/i);

    // Fallback simple matches
    if (urlMatch && urlMatch[1]) {
      const target = urlMatch[1].replace(/^(https?:\/\/)?/, 'https://');
      executeScanCommand(target, 'scan');
    } else if (emailMatch && emailMatch[1]) {
      executeBreachCheckCommand(emailMatch[1]);
    } else if (domainMatch && domainMatch[1]) {
      executeScanCommand(domainMatch[1], 'scan');
    } else {
      // General heuristic checks
      if (normalized.includes('@') && (normalized.includes('check') || normalized.includes('email'))) {
        const words = normalized.split(' ');
        const email = words.find(w => w.includes('@'));
        if (email) {
          executeBreachCheckCommand(email);
          return;
        }
      }

      if ((normalized.startsWith('scan ') || normalized.startsWith('analyze ')) && normalized.split(' ').length > 1) {
        const words = normalized.split(' ');
        const target = words[words.length - 1];
        if (target.includes('.') || target.includes('localhost') || target.match(/^\d{1,3}\.\d{1,3}/)) {
          executeScanCommand(target, 'scan');
          return;
        }
      }

      // No match
      setIsProcessing(false);
      setStatusText('COMMAND UNKNOWN');
      speakText("Sorry, I could not recognize that command. Try saying: Scan this URL, check this email, or analyze this domain.");
      addLog(`VOICE_COMMAND_REJECTED: Failed to parse action patterns inside "${command}"`);
    }
  };

  const executeScanCommand = (target: string, tab: any) => {
    setIsProcessing(false);
    scanSourceRef.current = 'voice';
    setUrl(target);
    setActiveTab(tab);
    addLog(`VOICE_DISPATCH: Target URL set to "${target}"`);
    speakText(`Scanning URL target: ${target}`);
    onScan(target);
  };

  const executeBreachCheckCommand = (email: string) => {
    setIsProcessing(false);
    scanSourceRef.current = 'voice';
    setBreachIdentity(email);
    setActiveTab('breach');
    addLog(`VOICE_DISPATCH: Dark Web target identity set to "${email}"`);
    speakText(`Checking Dark Web breaches for user: ${email}`);
    onBreachCheck(email);
  };

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col items-end">
      {/* Panel drawer container */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 15 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 15 }}
            className="mb-4 w-72 glass-panel border-pink-500/30 bg-black/90 p-4 font-mono shadow-[0_0_30px_rgba(236,72,153,0.2)] text-xs text-zinc-300"
          >
            <div className="flex justify-between items-center border-b border-pink-500/20 pb-2 mb-3">
              <span className="flex items-center gap-1.5 text-pink-500 font-black tracking-widest text-[9px] uppercase">
                <Shield size={12} className="animate-pulse" /> VOICE_AI_THREAT_ASSISTANT
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setIsMuted(!isMuted)}
                  className="text-zinc-500 hover:text-white transition-colors"
                  title={isMuted ? "Unmute Assistant" : "Mute Assistant"}
                >
                  {isMuted ? <VolumeX size={13} /> : <Volume2 size={13} />}
                </button>
                <button
                  type="button"
                  onClick={() => setShowHelp(!showHelp)}
                  className="text-zinc-500 hover:text-white transition-colors"
                  title="Show Commands Help"
                >
                  <HelpCircle size={13} />
                </button>
                <button
                  type="button"
                  onClick={() => setIsOpen(false)}
                  className="text-zinc-500 hover:text-white transition-colors"
                >
                  <X size={13} />
                </button>
              </div>
            </div>

            {showHelp ? (
              <div className="space-y-2 mb-3 bg-zinc-950/60 p-2.5 border border-zinc-900 leading-relaxed text-[10px]">
                <div className="flex justify-between items-center font-bold text-pink-400 uppercase">
                  <span>Voice Commands list</span>
                  <button onClick={() => setShowHelp(false)} className="text-[8px] hover:text-white">CLOSE</button>
                </div>
                <ul className="list-disc pl-3 text-zinc-400 space-y-1">
                  <li>Say: <strong className="text-zinc-200">"Scan this URL [url]"</strong></li>
                  <li>Say: <strong className="text-zinc-200">"Check this email [address]"</strong></li>
                  <li>Say: <strong className="text-zinc-200">"Analyze this domain [domain]"</strong></li>
                </ul>
              </div>
            ) : (
              <div className="space-y-3">
                {/* Holographic Assistant Visualizer */}
                <div className="h-28 bg-zinc-950/80 border border-zinc-900 flex flex-col items-center justify-center relative overflow-hidden">
                  {/* Glowing dynamic background circles */}
                  <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-20">
                    <div className="w-20 h-20 rounded-full border border-pink-500 animate-ping" />
                  </div>

                  {/* Animated Waveform Orb */}
                  <div className="relative w-16 h-16 flex items-center justify-center">
                    <motion.div
                      animate={
                        isListening
                          ? { scale: [1, 1.3, 1], rotate: 360 }
                          : isProcessing
                          ? { rotate: 360 }
                          : isSpeaking
                          ? { scale: [1, 1.15, 0.95, 1.1, 1] }
                          : { scale: 1 }
                      }
                      transition={
                        isListening
                          ? { duration: 1.5, repeat: Infinity, ease: "easeInOut" }
                          : isProcessing
                          ? { duration: 1, repeat: Infinity, ease: "linear" }
                          : isSpeaking
                          ? { duration: 0.8, repeat: Infinity, ease: "easeInOut" }
                          : { duration: 2, repeat: Infinity }
                      }
                      className={`absolute inset-0 rounded-full border-2 border-dashed ${
                        isListening
                          ? 'border-emerald-400 shadow-[0_0_15px_rgba(52,211,153,0.3)]'
                          : isProcessing
                          ? 'border-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.3)]'
                          : isSpeaking
                          ? 'border-violet-500 shadow-[0_0_15px_rgba(139,92,246,0.3)]'
                          : 'border-pink-500 shadow-[0_0_15px_rgba(236,72,153,0.2)]'
                      } transition-colors duration-500`}
                    />
                    <div className={`w-8 h-8 rounded-full ${
                      isListening
                        ? 'bg-emerald-400'
                        : isProcessing
                        ? 'bg-cyan-400 animate-pulse'
                        : isSpeaking
                        ? 'bg-violet-500'
                        : 'bg-pink-500'
                    } transition-colors duration-500 flex items-center justify-center text-black`}>
                      <Shield size={14} className={isProcessing ? 'animate-spin' : ''} />
                    </div>
                  </div>

                  <span className="text-[8px] text-zinc-500 uppercase tracking-widest mt-2 block">Voice Telemetry Link</span>
                </div>

                {/* Status Bar */}
                <div className="bg-zinc-950 p-2 border border-zinc-900 flex items-center gap-2">
                  <Terminal size={12} className="text-pink-500 animate-pulse" />
                  <span className="text-[10px] font-black uppercase text-pink-400 tracking-wider truncate">
                    {statusText}
                  </span>
                </div>

                {/* Live Transcript text */}
                {transcript && (
                  <div className="bg-black/80 p-2.5 border border-zinc-900 text-[10px] italic leading-normal text-zinc-400 max-h-[60px] overflow-y-auto custom-scrollbar">
                    <span className="text-[8px] text-zinc-600 font-bold block uppercase not-italic">Transcript</span>
                    "{transcript}"
                  </div>
                )}
              </div>
            )}
            
            <div className="mt-3 text-[7px] text-zinc-600 text-center uppercase tracking-widest border-t border-zinc-900 pt-2">
              accessibility speech systems online
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Pulsing microphone activator button */}
      <div className="relative group">
        {/* Outer glowing waves */}
        <div className={`absolute -inset-1 rounded-full blur-md opacity-30 group-hover:opacity-75 transition duration-500 ${
          isListening ? 'bg-emerald-500 animate-ping' : 'bg-pink-500'
        }`} />

        <button
          onClick={() => {
            setIsOpen(true);
            toggleListening();
          }}
          className={`relative flex items-center justify-center w-14 h-14 rounded-full border text-white transition-all shadow-[0_0_20px_rgba(236,72,153,0.2)] hover:shadow-[0_0_25px_rgba(236,72,153,0.4)] ${
            isListening
              ? 'bg-emerald-600 border-emerald-400 scale-105'
              : 'bg-zinc-950 border-pink-500/40 hover:border-pink-500'
          }`}
          title="Activate Voice AI Threat Scanner"
        >
          {isListening ? (
            <Mic size={20} className="animate-pulse text-white" />
          ) : !isSupported ? (
            <MicOff size={20} className="text-zinc-600" />
          ) : (
            <Mic size={20} className="text-pink-400 group-hover:scale-110 transition-transform" />
          )}
        </button>
      </div>
    </div>
  );
}
