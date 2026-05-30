import { initializeApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, signInWithRedirect, signOut, onAuthStateChanged, User } from 'firebase/auth';
import { 
  getFirestore, 
  collection, 
  addDoc, 
  query, 
  where, 
  onSnapshot, 
  deleteDoc, 
  doc, 
  serverTimestamp, 
  getDocs,
  setDoc,
  getDoc,
  orderBy,
  limit,
  Timestamp,
  getDocFromServer
} from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);

// Test connection CRITICAL directive
async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if(error instanceof Error && error.message.includes('the client is offline')) {
      console.error("Please check your Firebase configuration.");
    }
  }
}
testConnection();

const googleProvider = new GoogleAuthProvider();

export const signInWithGoogle = async () => {
  try {
    const result = await signInWithPopup(auth, googleProvider);
    // After sign in, ensure user document exists
    if (result.user) {
      const userRef = doc(db, 'users', result.user.uid);
      const userSnap = await getDoc(userRef);
      if (!userSnap.exists()) {
        await setDoc(userRef, {
          uid: result.user.uid,
          email: result.user.email,
          displayName: result.user.displayName || result.user.email?.split('@')[0] || 'Operator',
          role: 'user', // Default role
          createdAt: serverTimestamp()
        });
      }
    }
    return result;
  } catch (error: any) {
    const errCode = error?.code || '';
    const errMsg = error?.message || '';

    if (errCode === 'auth/popup-closed-by-user') {
      console.warn('Sign-in popup closed by user before completion.');
      return null;
    }

    if (errCode === 'auth/unauthorized-domain') {
      const activeDomain = window.location.hostname;
      const alertMsg = `🔐 Firebase Auth Domain Restriction:\n\n` +
        `This domain '${activeDomain}' is not authorized for authentication in your Firebase project.\n\n` +
        `To fix this:\n` +
        `1. Go to Firebase Console -> Authentication -> Settings tab.\n` +
        `2. Scroll down to 'Authorized domains' and click 'Add domain'.\n` +
        `3. Add '${activeDomain}' and save.\n\n` +
        `Once added, AUTH_INIT will work instantly!`;
      console.warn(alertMsg);
      console.error(alertMsg);
      return null;
    }

    // If popup is blocked or blocked by browser policies, attempt redirect instead
    if (errCode === 'auth/popup-blocked' || errCode === 'auth/cancelled-popup-request' || errMsg.includes('popup')) {
      console.warn('Popup blocked/failed. Attempting sign-in via redirect...');
      try {
        await signInWithRedirect(auth, googleProvider);
        return null;
      } catch (redirectErr: any) {
        console.error('Redirect sign-in failed as well:', redirectErr);
        throw redirectErr;
      }
    }

    console.error('Firebase Auth Error:', error);
    throw error;
  }
};

export const logout = () => signOut(auth);

// Error Handling helper
export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
  }
}

export function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null) {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
    },
    operationType,
    path
  }
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

export { 
  collection, 
  addDoc, 
  query, 
  where, 
  onSnapshot, 
  deleteDoc, 
  doc, 
  serverTimestamp, 
  getDocs,
  setDoc,
  getDoc,
  orderBy,
  limit,
  onAuthStateChanged,
  Timestamp
};
export type { User };
