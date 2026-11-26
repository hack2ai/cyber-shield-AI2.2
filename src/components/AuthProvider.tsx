import React, { createContext, useContext, useEffect, useState } from 'react';
import { 
  auth, 
  onAuthStateChanged, 
  signInWithGoogle, 
  logout, 
  db, 
  doc, 
  getDoc, 
  setDoc,
  serverTimestamp,
  User 
} from '../lib/firebase';

interface AuthContextType {
  user: User | null;
  profile: any | null;
  loading: boolean;
  login: () => Promise<void>;
  logout: () => Promise<void>;
  isAdmin: boolean;
  setSimulatedRole: (role: string | null) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<any | null>(null);
  const [simulatedRole, setSimulatedRole] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const activateMockSession = (email: string) => {
    const cleanEmail = email.trim().toLowerCase();
    const uid = 'mock-analyst-1337';
    const displayName = cleanEmail.split('@')[0];
    const nameFormatted = displayName.charAt(0).toUpperCase() + displayName.slice(1) + " (Simulated)";
    
    const mockUser = {
      uid,
      email: cleanEmail,
      displayName: nameFormatted,
      isAnonymous: false,
      emailVerified: true,
      metadata: {},
      providerData: [],
      refreshToken: '',
      tenantId: null,
      delete: async () => {},
      getIdToken: async () => 'mock-id-token',
      getIdTokenResult: async () => ({} as any),
      reload: async () => {},
      toJSON: () => ({})
    } as unknown as User;
    setUser(mockUser);
    setProfile({
      uid,
      email: cleanEmail,
      displayName: nameFormatted,
      role: 'user',
      createdAt: new Date()
    });
    setLoading(false);
    localStorage.setItem('cyber_shield_mock_user_email', cleanEmail);
    localStorage.removeItem('cyber_shield_guest_session');
  };

  const activateGuestSession = () => {
    const guestUser = {
      uid: 'mock-analyst-1337',
      email: 'analyst@cyber-shield.ai',
      displayName: 'Guest Security Analyst',
      isAnonymous: false,
      emailVerified: true,
      metadata: {},
      providerData: [],
      refreshToken: '',
      tenantId: null,
      delete: async () => {},
      getIdToken: async () => '',
      getIdTokenResult: async () => ({} as any),
      reload: async () => {},
      toJSON: () => ({})
    } as unknown as User;
    setUser(guestUser);
    setProfile({
      uid: 'mock-analyst-1337',
      email: 'analyst@cyber-shield.ai',
      displayName: 'Guest Security Analyst',
      role: 'user',
      createdAt: new Date()
    });
    setLoading(false);
    localStorage.setItem('cyber_shield_guest_session', 'true');
  };

  useEffect(() => {
    // Real auth only: discard any leftover demo/guest sessions from earlier versions.
    localStorage.removeItem('cyber_shield_mock_user_email');
    localStorage.removeItem('cyber_shield_guest_session');

    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      if (currentUser) {
        localStorage.removeItem('cyber_shield_guest_session');
        setUser(currentUser);
        try {
          const userRef = doc(db, 'users', currentUser.uid);
          const userSnap = await getDoc(userRef);
          if (userSnap.exists()) {
            setProfile(userSnap.data());
          } else {
            console.log("User profile does not exist in Firestore. Creating profile document...");
            const newProfile = {
              uid: currentUser.uid,
              email: currentUser.email,
              displayName: currentUser.displayName || currentUser.email?.split('@')[0] || 'Operator',
              role: 'user',
              createdAt: serverTimestamp()
            };
            await setDoc(userRef, newProfile);
            setProfile({
              ...newProfile,
              createdAt: new Date()
            });
          }
        } catch (error) {
          console.error("Failed to load user profile:", error);
          setProfile({
            uid: currentUser.uid,
            email: currentUser.email,
            displayName: currentUser.displayName || currentUser.email?.split('@')[0] || 'Operator',
            role: 'user',
            createdAt: new Date()
          });
        }
      } else {
        setUser(null);
        setProfile(null);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const login = async () => {
    try {
      await signInWithGoogle();
    } catch (error: any) {
      console.error('Sign-in failed:', error);
      alert('Sign-in failed: ' + (error?.code || error?.message || 'unknown error'));
    }
  };

  const handleLogout = async () => {
    localStorage.removeItem('cyber_shield_guest_session');
    localStorage.removeItem('cyber_shield_mock_user_email');
    try {
      await logout();
    } catch (e) {
      console.warn("Bypassed Firebase signOut error during logout:", e);
    }
    setUser(null);
    setProfile(null);
  };

  const value = {
    user,
    profile: simulatedRole ? { ...profile, role: simulatedRole } : profile,
    loading,
    login,
    logout: handleLogout,
    isAdmin: (simulatedRole || profile?.role) === 'admin',
    setSimulatedRole
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}