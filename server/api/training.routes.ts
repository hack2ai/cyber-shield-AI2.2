import { Router, type Request, type Response } from 'express';
import { rateLimit } from '../security/index.js';

export const trainingRouter = Router();
trainingRouter.use(rateLimit);

const QUIZZES: Record<string, Array<{ question: string; options: string[]; correctAnswerIndex: number; explanation: string }>> = {
  'general cybersecurity': [
    {
      question: 'Which control most directly reduces the risk of credential theft after password reuse?',
      options: ['Phishing-resistant MFA', 'Disabling backups', 'Using the same password everywhere', 'Sharing passwords by email'],
      correctAnswerIndex: 0,
      explanation: 'Phishing-resistant MFA adds a strong second factor and reduces the impact of stolen or reused passwords.'
    },
    {
      question: 'What is the safest response to an unexpected login link in an email?',
      options: ['Open it immediately', 'Verify the sender and navigate through a trusted channel', 'Disable antivirus', 'Forward it to coworkers'],
      correctAnswerIndex: 1,
      explanation: 'Verify the request independently and use a trusted application or bookmarked site rather than an unsolicited link.'
    },
    {
      question: 'What does the principle of least privilege mean?',
      options: ['Everyone gets administrator access', 'Users receive only the permissions required for their tasks', 'Passwords are never changed', 'All network traffic is trusted'],
      correctAnswerIndex: 1,
      explanation: 'Least privilege limits access to what is necessary for the task, reducing the blast radius of mistakes or compromise.'
    },
    {
      question: 'Which email authentication mechanism uses cryptographic signatures?',
      options: ['DKIM', 'DHCP', 'NAT', 'ARP'],
      correctAnswerIndex: 0,
      explanation: 'DKIM applies a cryptographic signature that receiving systems can use to validate message integrity and domain alignment.'
    },
    {
      question: 'Why are offline backups important against ransomware?',
      options: ['They make malware faster', 'They provide a recovery path if online copies are encrypted or destroyed', 'They disable MFA', 'They expose credentials'],
      correctAnswerIndex: 1,
      explanation: 'Offline or otherwise isolated backups can provide recovery when attackers compromise accessible systems and backup copies.'
    }
  ],
  phishing: [
    {
      question: 'Which signal is a common phishing indicator?',
      options: ['A verified internal workflow', 'A lookalike domain and urgent credential request', 'A bookmarked official URL', 'A signed internal message'],
      correctAnswerIndex: 1,
      explanation: 'Lookalike domains combined with urgency and requests for credentials are common phishing indicators.'
    },
    {
      question: 'What should you inspect before trusting a link in an email?',
      options: ['The destination domain and context', 'Only the logo', 'The font size', 'The message color'],
      correctAnswerIndex: 0,
      explanation: 'Inspect the actual destination domain and whether it fits the legitimate workflow.'
    },
    {
      question: 'What is the safest way to verify a suspicious payment request?',
      options: ['Reply to the same email', 'Call a trusted contact using independently sourced contact details', 'Click the payment link', 'Send the requested credentials'],
      correctAnswerIndex: 1,
      explanation: 'Use an independent, trusted communication channel rather than relying on contact details supplied by the suspicious message.'
    },
    {
      question: 'What does DMARC help organizations evaluate?',
      options: ['Domain-based email authentication and policy', 'CPU temperature', 'Disk fragmentation', 'Wi-Fi signal strength'],
      correctAnswerIndex: 0,
      explanation: 'DMARC builds on SPF and DKIM to evaluate domain alignment and publish handling policies for authenticated email.'
    },
    {
      question: 'Why should users avoid entering credentials on a page reached from an unexpected message?',
      options: ['The page may impersonate a trusted service', 'Browsers cannot display forms', 'HTTPS is always malicious', 'Email never contains links'],
      correctAnswerIndex: 0,
      explanation: 'Attackers can create convincing lookalike pages that capture credentials. Independent verification reduces this risk.'
    }
  ]
};

function normalizeTopic(value: unknown): string {
  const topic = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!topic) return 'general cybersecurity';
  if (topic.includes('phish')) return 'phishing';
  return 'general cybersecurity';
}

trainingRouter.post('/generate-quiz', (req: Request, res: Response) => {
  const topic = normalizeTopic(req.body?.topic);
  const quiz = QUIZZES[topic];

  res.status(200).json({
    topic,
    provider: 'local-training-bank',
    quiz,
  });
});
