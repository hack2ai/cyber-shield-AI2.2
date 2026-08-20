import {
  initializeTestEnvironment,
  RulesTestEnvironment,
  assertFails,
  assertSucceeds,
} from '@firebase/rules-unit-testing';
import { describe, it, beforeAll, afterAll, beforeEach } from 'vitest';
import { doc, getDoc, setDoc, updateDoc, deleteDoc, collection, query, where, getDocs, serverTimestamp, setLogLevel } from 'firebase/firestore';
import * as fs from 'fs';

let testEnv: RulesTestEnvironment;

beforeAll(async () => {
  // Silence verbose logs
  setLogLevel('error');
  testEnv = await initializeTestEnvironment({
    projectId: 'phish-intel-test',
    firestore: {
      rules: fs.readFileSync('firestore.rules', 'utf8'),
      host: '127.0.0.1',
      port: 8080,
    },
  });
});

afterAll(async () => {
  await testEnv.cleanup();
});

beforeEach(async () => {
  await testEnv.clearFirestore();
});

// Helper to seed user documents
async function seedUser(uid: string, email: string = `${uid}@test.com`, role: string = 'user') {
  await testEnv.withSecurityRulesDisabled(async (context) => {
    const db = context.firestore();
    const userRef = doc(db, 'users', uid);
    await setDoc(userRef, {
      uid,
      email,
      displayName: uid,
      role,
      createdAt: new Date(),
    });
  });
}

describe('Firestore Security Rules', () => {
  // --- Positive verification cases ---

  it('Valid User Creation: should allow user to create their own profile', async () => {
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const userRef = doc(aliceDb, 'users', 'alice');
    await assertSucceeds(setDoc(userRef, {
      uid: 'alice',
      email: 'alice@test.com',
      displayName: 'Alice',
      role: 'user',
      createdAt: serverTimestamp(),
    }));
  });

  it('Valid Report Operations: should allow owner to read/write/list their own reports', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'scanReports', 'report1');
    const report = {
      userId: 'alice',
      target: 'http://test.com',
      classification: 'Phishing',
      createdAt: serverTimestamp(),
      threatScore: 85,
      explanation: 'Matches blocklist',
    };

    // Create
    await assertSucceeds(setDoc(reportRef, report));

    // Get
    await assertSucceeds(getDoc(reportRef));

    // List with query filter
    const reportsQuery = query(collection(aliceDb, 'scanReports'), where('userId', '==', 'alice'));
    await assertSucceeds(getDocs(reportsQuery));
  });

  // --- The Dirty Dozen Payloads verification ---

  it('1. Identity Spoofing: should deny creating a report with someone else\'s userId', async () => {
    await seedUser('alice');
    await seedUser('bob');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'scanReports', 'report1');
    const badReport = {
      userId: 'bob', // Trying to spoof Bob's userId
      target: 'http://malicious.com',
      classification: 'Phishing',
      createdAt: serverTimestamp(),
    };
    await assertFails(setDoc(reportRef, badReport));
  });

  it('2. Role Escalation: should prevent self-promotion to admin on own profile update', async () => {
    await seedUser('alice', 'alice@test.com', 'user');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const userRef = doc(aliceDb, 'users', 'alice');
    
    // Attempting to escalate role
    await assertFails(updateDoc(userRef, { role: 'admin' }));
  });

  it('3. Cross-User Read: should deny reading scan reports belonging to another user', async () => {
    await seedUser('bob');
    // Write a scan report for Bob using admin context
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const db = context.firestore();
      await setDoc(doc(db, 'scanReports', 'bob-report'), {
        userId: 'bob',
        target: 'http://bob-target.com',
        classification: 'Safe',
        createdAt: new Date(),
      });
    });

    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'scanReports', 'bob-report');
    await assertFails(getDoc(reportRef));
  });

  it('4. Anonymous Write: should deny report creation if not signed in', async () => {
    const unauthedDb = testEnv.unauthenticatedContext().firestore();
    const reportRef = doc(unauthedDb, 'scanReports', 'report1');
    const report = {
      userId: 'alice',
      target: 'http://malicious.com',
      classification: 'Phishing',
      createdAt: serverTimestamp(),
    };
    await assertFails(setDoc(reportRef, report));
  });

  it('5. Collection Scraping: should deny listing all scan reports without query filter', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportsColl = collection(aliceDb, 'scanReports');
    await assertFails(getDocs(reportsColl));
  });

  it('6. Data Poisoning: should deny report creation if target field exceeds 2048 character limit', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'scanReports', 'report1');
    const hugeString = 'a'.repeat(2049); // Limit is 2048
    const badReport = {
      userId: 'alice',
      target: hugeString,
      classification: 'Phishing',
      createdAt: serverTimestamp(),
    };
    await assertFails(setDoc(reportRef, badReport));
  });

  it('7. Invalid Score: should deny report creation if threatScore is not between 0 and 100', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'scanReports', 'report1');
    const badReport = {
      userId: 'alice',
      target: 'http://test.com',
      classification: 'Phishing',
      threatScore: 999, // Out of bounds
      createdAt: serverTimestamp(),
    };
    await assertFails(setDoc(reportRef, badReport));
  });

  it('8. Malicious ID: should deny report creation if document ID exceeds 128 characters', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const longId = 'a'.repeat(129); // Limit is 128
    const reportRef = doc(aliceDb, 'scanReports', longId);
    const report = {
      userId: 'alice',
      target: 'http://test.com',
      classification: 'Phishing',
      createdAt: serverTimestamp(),
    };
    await assertFails(setDoc(reportRef, report));
  });

  it('9. Timestamp Manipulation: should deny report creation if createdAt is a future timestamp instead of request.time', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'scanReports', 'report1');
    const badReport = {
      userId: 'alice',
      target: 'http://test.com',
      classification: 'Phishing',
      createdAt: new Date(Date.now() + 100000), // Manipulated timestamp
    };
    await assertFails(setDoc(reportRef, badReport));
  });

  it('10. Shadow Field Injection: should deny report creation with un-whitelisted fields', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'scanReports', 'report1');
    const badReport = {
      userId: 'alice',
      target: 'http://test.com',
      classification: 'Phishing',
      createdAt: serverTimestamp(),
      isVerified: true, // Non-whitelisted field
    };
    await assertFails(setDoc(reportRef, badReport));
  });

  it('11. Bypass Verification: should deny write if user email is not verified', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice', { email_verified: false }).firestore();
    const reportRef = doc(aliceDb, 'scanReports', 'report1');
    const report = {
      userId: 'alice',
      target: 'http://test.com',
      classification: 'Phishing',
      createdAt: serverTimestamp(),
    };
    await assertFails(setDoc(reportRef, report));
  });

  it('12. Orphaned Write: should deny report creation if user document does not exist in /users', async () => {
    // alice is authenticated, but no /users/alice document was seeded
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'scanReports', 'report1');
    const report = {
      userId: 'alice',
      target: 'http://test.com',
      classification: 'Phishing',
      createdAt: serverTimestamp(),
    };
    await assertFails(setDoc(reportRef, report));
  });

  // --- File Scan Reports Verification ---

  it('Valid File Scan Report: should allow owner to read/write/list/delete their own file scan reports', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'fileScanReports', 'report1');
    const fileReport = {
      userId: 'alice',
      fileName: 'malware.exe',
      fileSize: 45678,
      fileType: 'application/x-msdownload',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      classification: 'Malicious',
      createdAt: serverTimestamp(),
      threatScore: 95,
      explanation: 'Signature matches blocklist',
    };

    // Create
    await assertSucceeds(setDoc(reportRef, fileReport));

    // Get
    await assertSucceeds(getDoc(reportRef));

    // List
    const reportsQuery = query(collection(aliceDb, 'fileScanReports'), where('userId', '==', 'alice'));
    await assertSucceeds(getDocs(reportsQuery));

    // Delete
    await assertSucceeds(deleteDoc(reportRef));
  });

  it('File Scan Spoofing: should deny creating a file scan report with another user\'s userId', async () => {
    await seedUser('alice');
    await seedUser('bob');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'fileScanReports', 'report1');
    const badReport = {
      userId: 'bob', // Trying to spoof Bob's ID
      fileName: 'document.pdf',
      fileSize: 1234,
      fileType: 'application/pdf',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      classification: 'Safe',
      createdAt: serverTimestamp(),
    };
    await assertFails(setDoc(reportRef, badReport));
  });

  it('File Scan Invalid Score: should deny file scan report creation if threatScore is out of bounds', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'fileScanReports', 'report1');
    const badReport = {
      userId: 'alice',
      fileName: 'game.apk',
      fileSize: 15000000,
      fileType: 'application/vnd.android.package-archive',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      classification: 'Malicious',
      threatScore: 120, // Limit is 100
      createdAt: serverTimestamp(),
    };
    await assertFails(setDoc(reportRef, badReport));
  });

  it('File Scan Cross-User Read: should deny reading file scan reports belonging to another user', async () => {
    await seedUser('bob');
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const db = context.firestore();
      await setDoc(doc(db, 'fileScanReports', 'bob-file-report'), {
        userId: 'bob',
        fileName: 'confidential.docx',
        fileSize: 12345,
        fileType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        classification: 'Safe',
        createdAt: new Date(),
      });
    });

    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'fileScanReports', 'bob-file-report');
    await assertFails(getDoc(reportRef));
  });

  it('Valid Breach Report: should allow owner to read/write/list their own breach reports', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'breachReports', 'breach1');
    const report = {
      userId: 'alice',
      identity: 'alice@test.com',
      breachCount: 2,
      createdAt: serverTimestamp(),
      breaches: [
        { name: 'Adobe', year: 2013, categories: ['Passwords'], description: 'Adobe leak' }
      ]
    };

    // Create
    await assertSucceeds(setDoc(reportRef, report));

    // Get
    await assertSucceeds(getDoc(reportRef));

    // List
    const breachQuery = query(collection(aliceDb, 'breachReports'), where('userId', '==', 'alice'));
    await assertSucceeds(getDocs(breachQuery));
  });

  it('Breach Report Identity Spoofing: should deny creating a breach report with Bob\'s userId', async () => {
    await seedUser('alice');
    await seedUser('bob');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'breachReports', 'breach1');
    const badReport = {
      userId: 'bob',
      identity: 'alice@test.com',
      breachCount: 2,
      createdAt: serverTimestamp()
    };
    await assertFails(setDoc(reportRef, badReport));
  });

  it('Breach Report Cross-User Read: should deny reading breach reports belonging to another user', async () => {
    await seedUser('bob');
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const db = context.firestore();
      await setDoc(doc(db, 'breachReports', 'bob-breach'), {
        userId: 'bob',
        identity: 'bob@test.com',
        breachCount: 1,
        createdAt: new Date()
      });
    });

    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'breachReports', 'bob-breach');
    await assertFails(getDoc(reportRef));
  });

  it('Valid Email Header Report: should allow owner to read/write/list their own email header reports', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'emailHeaderReports', 'header1');
    const report = {
      userId: 'alice',
      rawHeaders: 'From: support@google.com\nSubject: Critical update',
      threatScore: 12,
      classification: 'Safe',
      createdAt: serverTimestamp(),
      spf: 'Pass',
      dkim: 'Pass',
      dmarc: 'Pass'
    };

    // Create
    await assertSucceeds(setDoc(reportRef, report));

    // Get
    await assertSucceeds(getDoc(reportRef));

    // List
    const headerQuery = query(collection(aliceDb, 'emailHeaderReports'), where('userId', '==', 'alice'));
    await assertSucceeds(getDocs(headerQuery));
  });

  it('Email Header Report Identity Spoofing: should deny creating an email header report with Bob\'s userId', async () => {
    await seedUser('alice');
    await seedUser('bob');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'emailHeaderReports', 'header1');
    const badReport = {
      userId: 'bob',
      rawHeaders: 'From: support@google.com\nSubject: Critical update',
      threatScore: 12,
      classification: 'Safe',
      createdAt: serverTimestamp()
    };
    await assertFails(setDoc(reportRef, badReport));
  });

  it('Email Header Report Cross-User Read: should deny reading email header reports belonging to another user', async () => {
    await seedUser('bob');
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const db = context.firestore();
      await setDoc(doc(db, 'emailHeaderReports', 'bob-header'), {
        userId: 'bob',
        rawHeaders: 'From: support@google.com\nSubject: Critical update',
        threatScore: 88,
        classification: 'Phishing',
        createdAt: new Date()
      });
    });

    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const reportRef = doc(aliceDb, 'emailHeaderReports', 'bob-header');
    await assertFails(getDoc(reportRef));
  });

  // --- Training Progress ---
  it('Valid Training Progress: should allow owner to read, write, and update their own progress', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const progressRef = doc(aliceDb, 'trainingProgress', 'alice-progress');

    // Create progress
    const mockProgress = {
      userId: 'alice',
      score: 100,
      completedModules: ['lessons'],
      badges: ['first_badge'],
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    };

    await assertSucceeds(setDoc(progressRef, mockProgress));

    // Read progress
    await assertSucceeds(getDoc(progressRef));

    // Read back the server-resolved document so we can preserve the
    // original createdAt value during the update.
    const createdSnapshot = await getDoc(progressRef);
    const createdData = createdSnapshot.data();

    if (!createdData?.createdAt) {
      throw new Error('Training progress createdAt was not resolved');
    }

    // Update progress using the resolved createdAt timestamp.
    const updatedProgress = {
      userId: 'alice',
      score: 200,
      completedModules: ['lessons', 'quiz'],
      badges: ['first_badge', 'quiz_master'],
      createdAt: createdData.createdAt,
      updatedAt: serverTimestamp()
    };

    await assertSucceeds(updateDoc(progressRef, updatedProgress));
  });

  it('Training Progress Identity Spoofing: should deny creating or updating training progress with Bob\'s userId', async () => {
    await seedUser('alice');
    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const progressRef = doc(aliceDb, 'trainingProgress', 'alice-progress');

    // Try to create report for Bob
    const badProgress = {
      userId: 'bob',
      score: 100,
      completedModules: ['lessons'],
      badges: ['first_badge'],
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    };
    await assertFails(setDoc(progressRef, badProgress));
  });

  it('Training Progress Cross-User Read: should deny reading training progress belonging to another user', async () => {
    await seedUser('bob');
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const db = context.firestore();
      await setDoc(doc(db, 'trainingProgress', 'bob-progress'), {
        userId: 'bob',
        score: 300,
        completedModules: ['lessons'],
        badges: ['first_badge'],
        createdAt: new Date(),
        updatedAt: new Date()
      });
    });

    const aliceDb = testEnv.authenticatedContext('alice').firestore();
    const progressRef = doc(aliceDb, 'trainingProgress', 'bob-progress');
    await assertFails(getDoc(progressRef));
  });
});