import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Award, 
  BookOpen, 
  CheckCircle, 
  HelpCircle, 
  Mail, 
  Play, 
  RefreshCcw, 
  ShieldAlert, 
  Terminal, 
  Trophy, 
  X, 
  AlertTriangle 
} from 'lucide-react';
import { 
  db, 
  collection, 
  doc, 
  setDoc, 
  getDoc, 
  serverTimestamp 
} from '../lib/firebase';

interface TrainingProgress {
  score: number;
  completedModules: string[];
  badges: string[];
}

export function TrainingSimulator({ user, addLog }: { user: any; addLog: (msg: string) => void }) {
  const [activeModule, setActiveModule] = useState<'phishing' | 'quiz' | 'demos' | 'lessons'>('lessons');
  
  // Gamification States
  const [score, setScore] = useState(0);
  const [completedModules, setCompletedModules] = useState<string[]>([]);
  const [badges, setBadges] = useState<string[]>([]);
  const [unlockedBadge, setUnlockedBadge] = useState<string | null>(null);

  // Firestore/Local Sync
  const currentUserId = user?.uid || 'guest-operator';
  const isGuestMode = currentUserId === 'mock-analyst-1337' || currentUserId === 'guest-operator';

  useEffect(() => {
    // Load initial progress
    const loadProgress = async () => {
      if (!isGuestMode && user) {
        try {
          const docRef = doc(db, 'trainingProgress', user.uid);
          const snap = await getDoc(docRef);
          if (snap.exists()) {
            const data = snap.data();
            setScore(data.score || 0);
            setCompletedModules(data.completedModules || []);
            setBadges(data.badges || []);
          } else {
            // Seed initial
            const initial = {
              userId: user.uid,
              score: 0,
              completedModules: [],
              badges: [],
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp()
            };
            await setDoc(docRef, initial);
          }
        } catch (err) {
          console.error("Failed to load training progress from Firestore, falling back to local:", err);
          loadLocalProgress();
        }
      } else {
        loadLocalProgress();
      }
    };

    const loadLocalProgress = () => {
      const local = localStorage.getItem(`cyber_shield_training_${currentUserId}`);
      if (local) {
        const parsed = JSON.parse(local);
        setScore(parsed.score || 0);
        setCompletedModules(parsed.completedModules || []);
        setBadges(parsed.badges || []);
      }
    };

    loadProgress();
  }, [user]);

  // Persist progress helper
  const saveProgress = async (newScore: number, newModules: string[], newBadges: string[]) => {
    setScore(newScore);
    setCompletedModules(newModules);
    setBadges(newBadges);

    if (!isGuestMode && user) {
      try {
        const docRef = doc(db, 'trainingProgress', user.uid);
        await setDoc(docRef, {
          userId: user.uid,
          score: newScore,
          completedModules: newModules,
          badges: newBadges,
          createdAt: serverTimestamp(), // Will be ignored if exists under update rule, but rules allow setDoc overwrite validation
          updatedAt: serverTimestamp()
        }, { merge: true });
      } catch (err) {
        console.error("Failed to save progress to Firestore, storing locally:", err);
        saveLocalProgress(newScore, newModules, newBadges);
      }
    } else {
      saveLocalProgress(newScore, newModules, newBadges);
    }
  };

  const saveLocalProgress = (s: number, m: string[], b: string[]) => {
    localStorage.setItem(
      `cyber_shield_training_${currentUserId}`,
      JSON.stringify({ score: s, completedModules: m, badges: b })
    );
  };

  // Badge trigger logic
  const checkAndUnlockBadges = (currentScore: number, currentModules: string[], currentBadges: string[]) => {
    const nextBadges = [...currentBadges];
    let newlyUnlocked: string | null = null;

    if (currentScore >= 500 && !nextBadges.includes('SECURE_DEFENDER')) {
      nextBadges.push('SECURE_DEFENDER');
      newlyUnlocked = 'SECURE_DEFENDER';
    }
    
    // Check specific module progress
    if (currentModules.includes('phishing_completed') && !nextBadges.includes('PHISH_HUNTER')) {
      nextBadges.push('PHISH_HUNTER');
      newlyUnlocked = 'PHISH_HUNTER';
    }

    if (currentModules.includes('quiz_completed') && !nextBadges.includes('QUIZ_MASTER')) {
      nextBadges.push('QUIZ_MASTER');
      newlyUnlocked = 'QUIZ_MASTER';
    }

    if (newlyUnlocked) {
      setUnlockedBadge(newlyUnlocked);
      addLog(`ACHIEVEMENT_UNLOCKED: Operator rewarded with "${newlyUnlocked}" badge.`);
    }

    return nextBadges;
  };

  const rewardPoints = (amount: number, moduleCompletedKey?: string) => {
    const nextScore = score + amount;
    const nextModules = moduleCompletedKey && !completedModules.includes(moduleCompletedKey)
      ? [...completedModules, moduleCompletedKey]
      : completedModules;
    
    const nextBadges = checkAndUnlockBadges(nextScore, nextModules, badges);
    saveProgress(nextScore, nextModules, nextBadges);
    addLog(`REWARDED: +${amount} XP points logged.`);
  };

  // --- Sub-Module 1: Phishing Drill ---
  const phishingScenarios = [
    {
      id: 1,
      sender: "PayPal Security <noreply-verify@paypa1-support.com>",
      subject: "URGENT: Your Account Has Been Locked!",
      body: `Dear customer,
      
We detected suspicious login activity from an unknown IP address. To prevent unauthorized access, your account has been locked. 
Please verify your identity within 24 hours to secure your balance.

Click below to confirm your credentials:
http://confirm-balance-paypal.net/auth-secure

Sincerely,
PayPal Security Team`,
      isPhishing: true,
      explanation: "This is a Phishing Attempt. The sender domain uses typo-squatting ('paypa1-support.com' with a number '1' instead of letter 'l') and the link leads to an unauthorized external domain ('confirm-balance-paypal.net')."
    },
    {
      id: 2,
      sender: "Netflix Billings <billing@netflix.com>",
      subject: "Action Required: Update payment method",
      body: `Hello,

Your membership subscription could not be renewed. We tried multiple times but there was a transaction failure with your credit card on file.
Please log in to your account management page to update your payment details:

https://www.netflix.com/youraccount

Regards,
Netflix Customer Care`,
      isPhishing: false,
      explanation: "This is a legitimate email. The sender domain ('netflix.com') matches the official branding envelope, and the link points securely to the official domain ('netflix.com/youraccount') using HTTPS."
    },
    {
      id: 3,
      sender: "Corporate IT Support <it-helpdesk@mycompany-support-tickets.ru>",
      subject: "Security Update Required: Mandatory System Upgrade",
      body: `Dear Employee,
      
Our system administrator is scheduling a mandatory security update to patch critical vulnerabilities in corporate workstations.
Failure to upgrade immediately will result in suspension of your active active directory credentials.

Download the installer utility here:
http://workstation-patch-download.ru/update_workstation.exe

IT Helpdesk Coordinator`,
      isPhishing: true,
      explanation: "This is a highly dangerous spear phishing payload. The sender domain uses an external Russian country-code suffix (.ru) representing a generic support domain, and links directly to an executable binary executable file which contains packed malware loaders."
    }
  ];

  const [currentPhishIndex, setCurrentPhishIndex] = useState(0);
  const [phishVerdict, setPhishVerdict] = useState<'correct' | 'incorrect' | null>(null);
  const [phishCompleted, setPhishCompleted] = useState(false);

  const handlePhishAnswer = (answerIsPhish: boolean) => {
    const current = phishingScenarios[currentPhishIndex];
    if (answerIsPhish === current.isPhishing) {
      setPhishVerdict('correct');
      rewardPoints(100);
    } else {
      setPhishVerdict('incorrect');
    }

    // Mark completed if last index
    if (currentPhishIndex === phishingScenarios.length - 1) {
      setPhishCompleted(true);
      rewardPoints(100, 'phishing_completed');
    }
  };

  const nextPhishScenario = () => {
    setPhishVerdict(null);
    if (currentPhishIndex < phishingScenarios.length - 1) {
      setCurrentPhishIndex(prev => prev + 1);
    }
  };

  const resetPhishingDrill = () => {
    setCurrentPhishIndex(0);
    setPhishVerdict(null);
    setPhishCompleted(false);
  };

  // --- Sub-Module 2: Quizzes ---
  const [quizQuestions, setQuizQuestions] = useState<any[]>([]);
  const [quizTopic, setQuizTopic] = useState('general cybersecurity');
  const [quizLoading, setQuizLoading] = useState(false);
  const [currentQuizIndex, setCurrentQuizIndex] = useState(0);
  const [selectedOption, setSelectedOption] = useState<number | null>(null);
  const [quizScore, setQuizScore] = useState(0);
  const [quizSubmitted, setQuizSubmitted] = useState(false);
  const [quizCompletedState, setQuizCompletedState] = useState(false);
  const [aiQuizInput, setAiQuizInput] = useState('');

  // Fetch or Seed Quizzes
  const fetchAIQuiz = async (topicString?: string) => {
    setQuizLoading(true);
    setQuizCompletedState(false);
    setCurrentQuizIndex(0);
    setSelectedOption(null);
    setQuizScore(0);
    setQuizSubmitted(false);

    try {
      const response = await fetch('/api/training/generate-quiz', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ topic: topicString })
      });
      const data = await response.json();
      setQuizQuestions(data.quiz);
      setQuizTopic(data.topic);
    } catch (err) {
      console.error(err);
    } finally {
      setQuizLoading(false);
    }
  };

  // Seed default quiz
  useEffect(() => {
    if (quizQuestions.length === 0) {
      fetchAIQuiz();
    }
  }, []);

  const handleQuizAnswer = (optionIdx: number) => {
    if (quizSubmitted) return;
    setSelectedOption(optionIdx);
  };

  const submitQuestion = () => {
    if (selectedOption === null || quizSubmitted) return;
    const current = quizQuestions[currentQuizIndex];
    if (selectedOption === current.correctAnswerIndex) {
      setQuizScore(prev => prev + 1);
      rewardPoints(50);
    }
    setQuizSubmitted(true);
  };

  const nextQuizQuestion = () => {
    setSelectedOption(null);
    setQuizSubmitted(false);
    if (currentQuizIndex < quizQuestions.length - 1) {
      setCurrentQuizIndex(prev => prev + 1);
    } else {
      setQuizCompletedState(true);
      // Reward extra points for passing
      if (quizScore === quizQuestions.length) {
        rewardPoints(150, 'quiz_completed');
      } else {
        rewardPoints(50, 'quiz_completed');
      }
    }
  };

  // --- Sub-Module 3: Attack Demonstrations ---
  const [activeDemo, setActiveDemo] = useState<'phish_redirect' | 'brute_force' | 'sqli'>('phish_redirect');
  const [demoStep, setDemoStep] = useState(0);
  const [demoPlaying, setDemoPlaying] = useState(false);

  const demoScenarios = {
    phish_redirect: {
      title: "Phishing Redirect Attack Flow",
      steps: [
        "1. Spammer sends unauthorized envelope From: service@paypal.com.",
        "2. Mail reaches user showing legitimate-looking login prompt.",
        "3. User clicks link pointing to http://login-paypal-verify.net/auth.",
        "4. Web server serves exact replica of PayPal landing portal.",
        "5. User inputs password, which is immediately saved into hacker database.",
        "6. Portal redirects user back to official PayPal page to mask theft."
      ]
    },
    brute_force: {
      title: "SSH Login Dictionary Guessing",
      steps: [
        "1. Attacker locates public port 22 (SSH) open on target host.",
        "2. Attacker launches bot script using standard username 'root'.",
        "3. Script loops through common password dictionary (e.g. admin123, password, admin, root).",
        "4. Rate-limiting check: SSH port allows infinite tries (missing Fail2Ban policy).",
        "5. Log: login verified for root with password 'secret123'. Account compromised."
      ]
    },
    sqli: {
      title: "SQL Injection Authentication Bypass",
      steps: [
        "1. Application has login field querying database directly without validation.",
        "2. Database query looks like: SELECT * FROM users WHERE username = '$user' AND password = '$pw'",
        "3. Attacker inputs username field: admin' OR '1'='1",
        "4. Compiled query becomes: SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = ''",
        "5. Because '1'='1' is always true, SQL parser skips password checks.",
        "6. Application signs attacker in as Admin profile. Access bypass complete."
      ]
    }
  };

  useEffect(() => {
    setDemoStep(0);
    setDemoPlaying(false);
  }, [activeDemo]);

  useEffect(() => {
    let interval: any;
    if (demoPlaying) {
      const currentSteps = demoScenarios[activeDemo].steps;
      interval = setInterval(() => {
        setDemoStep(prev => {
          if (prev < currentSteps.length - 1) {
            return prev + 1;
          } else {
            setDemoPlaying(false);
            clearInterval(interval);
            return prev;
          }
        });
      }, 2500);
    }
    return () => clearInterval(interval);
  }, [demoPlaying, activeDemo]);

  // --- Sub-Module 4: Lessons ---
  const lessons = [
    {
      title: "Lesson 1: Credential Integrity & MFA",
      slides: [
        "Passwords should exceed 12 characters, mixing digits, caps, and special symbols.",
        "Multi-factor Authentication (MFA) protects systems even if passwords are leaked, requiring biometric or SMS pins.",
        "Use local password vaults (e.g., Bitwarden, KeePass) instead of writing credentials inside plain text files."
      ]
    },
    {
      title: "Lesson 2: Dissecting Email Envelope Headers",
      slides: [
        "Always review the 'Authentication-Results' header for SPF validation credentials.",
        "Verify intermediate 'Received:' nodes chronologically. Spoofed emails will trace to unauthorized residential IPs.",
        "Ensure DKIM public keys match domain signatures. If DKIM fails, trust indices are compromised."
      ]
    },
    {
      title: "Lesson 3: Zero Trust Architecture",
      slides: [
        "Never trust automatically, always verify. Every request must authenticate, authorize, and encrypt.",
        "Use least privilege access principles. Limit operators' controls strictly to what is required for active tasks.",
        "Monitor SIEM logs and establish automated alerts on dynamic configuration updates."
      ]
    }
  ];

  const [activeLessonIdx, setActiveLessonIdx] = useState(0);
  const [activeSlideIdx, setActiveSlideIdx] = useState(0);

  const handleNextSlide = () => {
    const currentLesson = lessons[activeLessonIdx];
    if (activeSlideIdx < currentLesson.slides.length - 1) {
      setActiveSlideIdx(prev => prev + 1);
    } else {
      // Completed lesson slide
      const lessonKey = `lesson_${activeLessonIdx}_completed`;
      rewardPoints(100, lessonKey);
      
      // Next lesson
      if (activeLessonIdx < lessons.length - 1) {
        setActiveLessonIdx(prev => prev + 1);
        setActiveSlideIdx(0);
      } else {
        alert("Awesome! You completed all available cyber security lessons.");
      }
    }
  };

  return (
    <div className="space-y-4 font-mono text-zinc-300">
      {/* Gamification Progress HUD */}
      <section className="glass-panel border-[#39FF14]/30 bg-black/85 p-5 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-full bg-linear-to-l from-[#39FF14]/5 to-transparent skew-x-12" />
        <div className="flex flex-col md:flex-row items-center justify-between gap-6 relative z-10">
          <div className="flex items-center gap-4">
            <div className="p-3 border border-[#39FF14] text-[#39FF14] bg-[#39FF14]/10 rounded-full shrink-0 shadow-[0_0_15px_rgba(57,255,20,0.15)] animate-pulse">
              <Trophy size={24} />
            </div>
            <div>
              <h2 className="text-sm font-black uppercase tracking-[0.2em] text-[#39FF14]">OPERATOR_LEARNING_METRIC</h2>
              <div className="flex items-center gap-3 mt-1.5">
                <span className="text-xs text-zinc-400">XP SCORE: <strong className="text-white text-base italic">{score}</strong></span>
                <span className="h-3 w-px bg-zinc-800" />
                <span className="text-[10px] text-zinc-500 uppercase">Level {Math.floor(score / 500) + 1} Defender</span>
              </div>
            </div>
          </div>

          {/* Achievement Badges Row */}
          <div className="flex gap-2">
            <div className={`p-2 border flex items-center gap-1.5 ${badges.includes('PHISH_HUNTER') ? 'border-amber-500/40 text-amber-500 bg-amber-950/10' : 'border-zinc-900 text-zinc-600'}`} title="Spot 3 Phishing scenarios correctly">
              <Award size={14} />
              <span className="text-[9px] font-bold uppercase tracking-wider">PHISH_HUNTER</span>
            </div>
            <div className={`p-2 border flex items-center gap-1.5 ${badges.includes('QUIZ_MASTER') ? 'border-purple-500/40 text-purple-400 bg-purple-950/10' : 'border-zinc-900 text-zinc-600'}`} title="Get 100% on any security quiz">
              <Award size={14} />
              <span className="text-[9px] font-bold uppercase tracking-wider">QUIZ_MASTER</span>
            </div>
            <div className={`p-2 border flex items-center gap-1.5 ${badges.includes('SECURE_DEFENDER') ? 'border-[#39FF14]/40 text-[#39FF14] bg-[#39FF14]/5' : 'border-zinc-900 text-zinc-600'}`} title="Reach 500+ XP points">
              <Award size={14} />
              <span className="text-[9px] font-bold uppercase tracking-wider">SECURE_DEFENDER</span>
            </div>
          </div>
        </div>
      </section>

      {/* Main control navigation */}
      <div className="grid grid-cols-4 gap-2">
        {(['lessons', 'phishing', 'quiz', 'demos'] as const).map((mod) => (
          <button
            key={mod}
            onClick={() => setActiveModule(mod)}
            className={`py-2 text-[10px] font-black uppercase tracking-widest border transition-all ${
              activeModule === mod ? 'bg-[#39FF14]/10 border-[#39FF14] text-[#39FF14]' : 'border-zinc-900 text-zinc-500 hover:border-zinc-800'
            }`}
          >
            {mod.toUpperCase()}
          </button>
        ))}
      </div>

      {/* MODULE panels */}
      <AnimatePresence mode="wait">
        {/* lessons module */}
        {activeModule === 'lessons' && (
          <motion.div
            key="lessons"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="p-6 glass-panel border-[#39FF14]/20 bg-black/60 space-y-4"
          >
            <div className="flex justify-between items-center border-b border-zinc-900 pb-2">
              <h3 className="text-xs font-black uppercase text-[#39FF14] flex items-center gap-1.5">
                <BookOpen size={12} /> Cyber Security Lessons ({activeLessonIdx + 1} / {lessons.length})
              </h3>
              <span className="text-[8px] text-zinc-500">Earn +100 XP on Completion</span>
            </div>

            <div className="bg-black/80 border border-zinc-900 p-5 space-y-4 min-h-[140px] flex flex-col justify-between">
              <h4 className="text-[11px] font-bold text-white uppercase">{lessons[activeLessonIdx].title}</h4>
              <p className="text-xs text-zinc-300 leading-relaxed italic">
                "{lessons[activeLessonIdx].slides[activeSlideIdx]}"
              </p>
              <div className="flex justify-between items-center text-[9px] opacity-40 uppercase pt-2 border-t border-zinc-900">
                <span>Slide {activeSlideIdx + 1} of {lessons[activeLessonIdx].slides.length}</span>
                <span>Active status: reading</span>
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <button
                onClick={() => {
                  setActiveSlideIdx(0);
                  if (activeLessonIdx > 0) {
                    setActiveLessonIdx(prev => prev - 1);
                  }
                }}
                disabled={activeLessonIdx === 0 && activeSlideIdx === 0}
                className="px-4 py-2 border border-zinc-800 text-zinc-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed text-[10px] uppercase font-black"
              >
                Previous
              </button>
              <button
                onClick={handleNextSlide}
                className="px-6 py-2 bg-[#39FF14] hover:bg-[#39FF14]/90 text-black text-[10px] uppercase font-black"
              >
                {activeSlideIdx === lessons[activeLessonIdx].slides.length - 1 ? 'Complete Lesson' : 'Next'}
              </button>
            </div>
          </motion.div>
        )}

        {/* phishing module */}
        {activeModule === 'phishing' && (
          <motion.div
            key="phishing"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="p-6 glass-panel border-[#39FF14]/20 bg-black/60 space-y-4"
          >
            <div className="flex justify-between items-center border-b border-zinc-900 pb-2">
              <h3 className="text-xs font-black uppercase text-[#39FF14] flex items-center gap-1.5">
                <Mail size={12} /> Phishing Drill Simulator ({currentPhishIndex + 1} / {phishingScenarios.length})
              </h3>
              <span className="text-[8px] text-zinc-500">Spot threats to gain XP</span>
            </div>

            {!phishCompleted ? (
              <div className="space-y-4">
                {/* Mock Email Client Container */}
                <div className="bg-black/90 border border-zinc-900 font-sans text-xs">
                  {/* Top Bar */}
                  <div className="bg-zinc-950 border-b border-zinc-900 p-3 font-mono text-[9px] text-zinc-500 flex justify-between uppercase">
                    <span>Inbound Mail Audit client</span>
                    <span className="text-amber-500 animate-pulse">awaiting operator decision</span>
                  </div>
                  {/* Headers */}
                  <div className="p-3 border-b border-zinc-900/50 space-y-1.5">
                    <div><span className="text-zinc-500 font-mono">From:</span> <strong className="text-zinc-300 font-mono">{phishingScenarios[currentPhishIndex].sender}</strong></div>
                    <div><span className="text-zinc-500 font-mono">Subject:</span> <strong className="text-white font-mono">{phishingScenarios[currentPhishIndex].subject}</strong></div>
                  </div>
                  {/* Body */}
                  <div className="p-4 whitespace-pre-wrap leading-relaxed text-zinc-300 min-h-[160px] select-all">
                    {phishingScenarios[currentPhishIndex].body}
                  </div>
                </div>

                {phishVerdict ? (
                  <div className={`p-4 border leading-relaxed ${
                    phishVerdict === 'correct' ? 'border-[#39FF14]/30 bg-[#39FF14]/5 text-emerald-400' : 'border-red-500/30 bg-red-950/10 text-red-400'
                  }`}>
                    <h4 className="text-xs font-bold uppercase mb-1.5 flex items-center gap-1">
                      {phishVerdict === 'correct' ? <CheckCircle size={12} /> : <AlertTriangle size={12} />}
                      {phishVerdict === 'correct' ? 'CORRECT DECISION (+100 XP)' : 'INCORRECT VERDICT'}
                    </h4>
                    <p className="text-[10px] text-zinc-300 font-mono italic">
                      {phishingScenarios[currentPhishIndex].explanation}
                    </p>
                    <div className="flex justify-end mt-3">
                      <button
                        onClick={nextPhishScenario}
                        className="px-4 py-1.5 bg-zinc-900 border border-zinc-800 text-white hover:border-zinc-500 text-[9px] uppercase font-black font-mono"
                      >
                        Proceed to Next Scenario
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="grid grid-cols-2 gap-2 font-mono">
                    <button
                      onClick={() => handlePhishAnswer(false)}
                      className="py-3 bg-emerald-600 hover:bg-emerald-500 text-black font-black uppercase text-xs transition-all"
                    >
                      Trust Email / Click link
                    </button>
                    <button
                      onClick={() => handlePhishAnswer(true)}
                      className="py-3 bg-red-600 hover:bg-red-500 text-black font-black uppercase text-xs transition-all"
                    >
                      Flag &amp; Report Phishing
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-6 text-center space-y-4">
                <div className="inline-block p-4 border-2 border-[#39FF14] text-[#39FF14] bg-[#39FF14]/10 rounded-full animate-bounce">
                  <CheckCircle size={36} />
                </div>
                <h4 className="text-base font-bold text-white uppercase italic">PHISHING DRILL COMPLETE</h4>
                <p className="text-xs text-zinc-400 max-w-sm mx-auto leading-relaxed">
                  Excellent. You went through all sample email logs. Security audits confirm improved domain and link validation parameters.
                </p>
                <button
                  onClick={resetPhishingDrill}
                  className="px-6 py-2 border border-[#39FF14] text-[#39FF14] hover:bg-[#39FF14]/10 text-[10px] uppercase font-black"
                >
                  Restart Simulation
                </button>
              </div>
            )}
          </motion.div>
        )}

        {/* quiz module */}
        {activeModule === 'quiz' && (
          <motion.div
            key="quiz"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="p-6 glass-panel border-[#39FF14]/20 bg-black/60 space-y-4"
          >
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-2 border-b border-zinc-900 pb-2">
              <div>
                <h3 className="text-xs font-black uppercase text-[#39FF14] flex items-center gap-1.5">
                  <HelpCircle size={12} /> Security Quiz Terminal
                </h3>
                <span className="text-[8px] text-zinc-500 uppercase tracking-widest mt-0.5 block">Topic: {quizTopic}</span>
              </div>
              
              {/* AI Quiz form */}
              <div className="flex gap-1.5 w-full md:w-auto">
                <input
                  type="text"
                  placeholder="Quiz topic..."
                  value={aiQuizInput}
                  onChange={(e) => setAiQuizInput(e.target.value)}
                  className="bg-black border border-zinc-800 px-3 py-1.5 text-[9px] focus:outline-none focus:border-[#39FF14] w-full md:w-36 text-white"
                />
                <button
                  type="button"
                  onClick={() => fetchAIQuiz(aiQuizInput)}
                  disabled={quizLoading}
                  className="px-3 bg-[#39FF14]/10 border border-[#39FF14]/30 hover:bg-[#39FF14]/20 text-[#39FF14] text-[8px] font-black uppercase shrink-0"
                >
                  {quizLoading ? 'GENERATING...' : 'AI_GENERATE'}
                </button>
              </div>
            </div>

            {quizLoading ? (
              <div className="py-12 flex flex-col items-center justify-center space-y-3">
                <div className="w-8 h-8 border-2 border-[#39FF14] border-t-transparent rounded-full animate-spin" />
                <p className="text-[10px] text-zinc-500 uppercase animate-pulse">AI Auditor compiling custom quiz questions...</p>
              </div>
            ) : quizQuestions.length > 0 && !quizCompletedState ? (
              <div className="space-y-4">
                {/* Question */}
                <div className="p-4 bg-zinc-950/80 border border-zinc-900 leading-relaxed text-xs text-white">
                  <span className="text-[9px] text-[#39FF14] font-bold block uppercase mb-1">Question {currentQuizIndex + 1} of {quizQuestions.length}</span>
                  "{quizQuestions[currentQuizIndex].question}"
                </div>

                {/* Options */}
                <div className="grid grid-cols-1 gap-2">
                  {quizQuestions[currentQuizIndex].options.map((opt: string, idx: number) => (
                    <button
                      key={idx}
                      onClick={() => handleQuizAnswer(idx)}
                      className={`p-3 text-left text-xs border rounded-none transition-all flex justify-between items-center ${
                        selectedOption === idx
                          ? 'border-[#39FF14] bg-[#39FF14]/5 text-[#39FF14]'
                          : 'border-zinc-900 bg-black/40 text-zinc-400 hover:border-zinc-800'
                      }`}
                    >
                      <span>{opt}</span>
                    </button>
                  ))}
                </div>

                {quizSubmitted ? (
                  <div className={`p-4 border text-[10px] leading-normal ${
                    selectedOption === quizQuestions[currentQuizIndex].correctAnswerIndex
                      ? 'border-[#39FF14]/30 bg-[#39FF14]/5 text-emerald-400'
                      : 'border-red-500/30 bg-red-950/10 text-red-400'
                  }`}>
                    <h4 className="font-bold uppercase mb-1">
                      {selectedOption === quizQuestions[currentQuizIndex].correctAnswerIndex ? 'CORRECT ANSWER (+50 XP)' : 'INCORRECT ANSWER'}
                    </h4>
                    <p className="text-zinc-300 italic">
                      {quizQuestions[currentQuizIndex].explanation}
                    </p>
                    <div className="flex justify-end mt-2.5">
                      <button
                        onClick={nextQuizQuestion}
                        className="px-4 py-1 bg-zinc-900 border border-zinc-800 text-white hover:border-zinc-500 text-[9px] uppercase font-black"
                      >
                        {currentQuizIndex === quizQuestions.length - 1 ? 'Finish Quiz' : 'Next Question'}
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="flex justify-end">
                    <button
                      onClick={submitQuestion}
                      disabled={selectedOption === null}
                      className="px-6 py-2 bg-[#39FF14] text-black font-black uppercase text-[10px] disabled:opacity-30 disabled:cursor-not-allowed"
                    >
                      Submit Answer
                    </button>
                  </div>
                )}
              </div>
            ) : quizCompletedState ? (
              <div className="p-6 text-center space-y-4">
                <div className="inline-block p-4 border-2 border-purple-500 text-purple-400 bg-purple-950/10 rounded-full animate-bounce">
                  <Trophy size={36} />
                </div>
                <h4 className="text-base font-bold text-white uppercase italic">QUIZ TERMINATED SUCCESSFULLY</h4>
                <div className="text-xs text-zinc-400 max-w-sm mx-auto leading-relaxed space-y-1">
                  <p>You scored <strong className="text-white text-sm">{quizScore}</strong> out of {quizQuestions.length} questions correctly.</p>
                  <p className="text-[10px] text-zinc-500 uppercase">
                    {quizScore === quizQuestions.length ? 'Excellent audit. Flawless marks reward you with the Quiz Master badge.' : 'Decent effort. Retake or generate another AI quiz to improve details.'}
                  </p>
                </div>
                <div className="flex justify-center gap-2">
                  <button
                    onClick={() => fetchAIQuiz(quizTopic)}
                    className="px-5 py-2 border border-zinc-800 hover:border-zinc-500 text-[10px] uppercase font-black text-white"
                  >
                    Retake Quiz
                  </button>
                  <button
                    onClick={() => fetchAIQuiz()}
                    className="px-5 py-2 bg-[#39FF14] text-black text-[10px] uppercase font-black"
                  >
                    Next AI Quiz
                  </button>
                </div>
              </div>
            ) : null}
          </motion.div>
        )}

        {/* demos module */}
        {activeModule === 'demos' && (
          <motion.div
            key="demos"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="p-6 glass-panel border-[#39FF14]/20 bg-black/60 space-y-4"
          >
            <div className="flex justify-between items-center border-b border-zinc-900 pb-2">
              <h3 className="text-xs font-black uppercase text-[#39FF14] flex items-center gap-1.5">
                <Terminal size={12} /> Attack Vector Demonstrations
              </h3>
              <span className="text-[8px] text-zinc-500">Run sandbox simulations</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
              {/* Left Selector List */}
              <div className="md:col-span-4 flex flex-row md:flex-col gap-1.5 overflow-x-auto">
                <button
                  onClick={() => setActiveDemo('phish_redirect')}
                  className={`px-3 py-2 text-[9px] text-left font-black uppercase border transition-all ${
                    activeDemo === 'phish_redirect' ? 'border-[#39FF14] bg-[#39FF14]/10 text-[#39FF14]' : 'border-zinc-900 hover:border-zinc-800'
                  }`}
                >
                  Phishing Link Redirect
                </button>
                <button
                  onClick={() => setActiveDemo('brute_force')}
                  className={`px-3 py-2 text-[9px] text-left font-black uppercase border transition-all ${
                    activeDemo === 'brute_force' ? 'border-[#39FF14] bg-[#39FF14]/10 text-[#39FF14]' : 'border-zinc-900 hover:border-zinc-800'
                  }`}
                >
                  SSH Brute Force
                </button>
                <button
                  onClick={() => setActiveDemo('sqli')}
                  className={`px-3 py-2 text-[9px] text-left font-black uppercase border transition-all ${
                    activeDemo === 'sqli' ? 'border-[#39FF14] bg-[#39FF14]/10 text-[#39FF14]' : 'border-zinc-900 hover:border-zinc-800'
                  }`}
                >
                  SQL Auth Bypass
                </button>
              </div>

              {/* Right Terminal Screen */}
              <div className="md:col-span-8 bg-black border border-zinc-900 p-4 font-mono leading-relaxed space-y-4">
                <div className="flex justify-between items-center border-b border-zinc-950 pb-2 mb-2 text-[9px] text-zinc-500">
                  <span className="flex items-center gap-1"><Terminal size={11} /> ATK_SIMULATOR_V1</span>
                  <span>STEPS COMPLETED: {demoStep + 1} / {demoScenarios[activeDemo].steps.length}</span>
                </div>

                <div className="space-y-2 min-h-[160px] overflow-y-auto custom-scrollbar text-[10px]">
                  {demoScenarios[activeDemo].steps.slice(0, demoStep + 1).map((step, idx) => (
                    <div
                      key={idx}
                      className={idx === demoStep ? 'text-red-400 animate-pulse' : 'text-zinc-500'}
                    >
                      {step}
                    </div>
                  ))}
                </div>

                <div className="flex justify-end gap-1.5 border-t border-zinc-950 pt-3">
                  <button
                    onClick={() => {
                      setDemoStep(0);
                      setDemoPlaying(false);
                    }}
                    className="px-3 py-1 bg-zinc-900 border border-zinc-800 hover:border-zinc-500 text-[9px] uppercase font-black text-white"
                  >
                    Reset
                  </button>
                  <button
                    onClick={() => setDemoPlaying(!demoPlaying)}
                    className={`px-5 py-1 text-[9px] font-black uppercase flex items-center gap-1.5 ${
                      demoPlaying ? 'bg-amber-600 text-black' : 'bg-red-600 text-black hover:bg-red-500'
                    }`}
                  >
                    {demoPlaying ? <RefreshCcw size={10} className="animate-spin" /> : <Play size={10} />}
                    {demoPlaying ? 'PAUSE' : 'PLAY_SIM'}
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Pop-up Badge Unlocked Overlay */}
      <AnimatePresence>
        {unlockedBadge && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-xs font-mono"
          >
            <motion.div
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              className="bg-zinc-950 border-2 border-[#39FF14] p-6 max-w-sm w-full text-center relative overflow-hidden shadow-[0_0_50px_rgba(57,255,20,0.3)]"
            >
              <div className="absolute top-0 right-0 w-32 h-32 bg-linear-to-bl from-[#39FF14]/10 to-transparent skew-y-12" />
              <button
                onClick={() => setUnlockedBadge(null)}
                className="absolute top-3 right-3 text-zinc-500 hover:text-white"
              >
                <X size={16} />
              </button>

              <div className="inline-block p-4 border-2 border-[#39FF14] text-[#39FF14] bg-[#39FF14]/10 rounded-full animate-bounce mb-4 mt-2">
                <Award size={48} />
              </div>

              <h3 className="text-lg font-black italic tracking-tighter text-[#39FF14] uppercase mb-1">ACHIEVEMENT UNLOCKED!</h3>
              <h4 className="text-sm font-bold text-white uppercase tracking-wider mb-3">"{unlockedBadge}"</h4>
              
              <p className="text-[10px] text-zinc-400 leading-relaxed mb-6 uppercase">
                Congratulations operator. Your security audit operations have earned you the badge recognition. Maintain system defenses.
              </p>

              <button
                onClick={() => setUnlockedBadge(null)}
                className="w-full bg-[#39FF14] hover:bg-[#39FF14]/90 text-black py-2.5 text-xs font-black uppercase tracking-wider"
              >
                Accept Reward
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
