import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Database, 
  Upload, 
  ArrowRight, 
  Fingerprint, 
  AlertTriangle,
  CheckCircle2,
  Lock,
  Download,
  Trash2,
  Key,
  LayoutDashboard,
  Search,
  FileBarChart,
  BrainCircuit,
  ChevronRight,
  User as UserIcon,
  ShieldAlert,
  LogOut,
  LogIn,
  Activity,
  FileText
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { GoogleGenAI } from "@google/genai";
import { v4 as uuidv4 } from 'uuid';
import { auth, db } from './lib/firebase';
import { 
  GoogleAuthProvider, 
  signInWithPopup, 
  onAuthStateChanged, 
  User as FirebaseUser,
  signOut
} from 'firebase/auth';
import { 
  collection, 
  addDoc, 
  onSnapshot, 
  query, 
  orderBy, 
  serverTimestamp, 
  writeBatch, 
  doc, 
  deleteDoc, 
  getDocs,
  limit
} from 'firebase/firestore';

// --- Types ---
const DEFAULT_HEADERS = ["SSN", "CUSID", "DOB", "ADDRESS", "MESSAGE"];

interface AIClassification {
  field: string;
  isSensitive: boolean;
  confidence: number;
}

interface StagedRecord {
  id: string;
  data: Record<string, string>;
  classifications: AIClassification[];
  ingestedAt: string;
}

interface VaultedRecord {
  id: string;
  maskedData: Record<string, string>;
  tokens: Record<string, string>;
  hashes: Record<string, string>;
  processedAt: string;
  processedBy: string;
  algorithm: string;
  metadata: AIClassification[];
}

type View = 'ingest' | 'audit' | 'report';

interface MaskConfig {
  algorithm: 'sha256' | 'sha512' | 'aes-256-gcm';
  maskChar: string;
  maskVisibleCount: number;
  fields: string[];
  userSalt: string;
}

// --- AI Initialization ---
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

export default function App() {
  // --- State ---
  const [currentView, setCurrentView] = useState<View>('ingest');
  const [inputText, setInputText] = useState('');
  const [stagingBuffer, setStagingBuffer] = useState<StagedRecord[]>([]);
  const [vaultedRecords, setVaultedRecords] = useState<VaultedRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [config, setConfig] = useState({
    userSalt: '',
    algorithm: 'sha256' as 'sha256' | 'sha512'
  });
  const [isProcessing, setIsProcessing] = useState(false);
  const [isIngesting, setIsIngesting] = useState(false);
  const [alert, setAlert] = useState<{ message: string; type: 'warning' | 'info' | 'success' } | null>(null);
  const [currentUser, setCurrentUser] = useState<FirebaseUser | null>(null);
  const [sessionSignatures, setSessionSignatures] = useState<Set<string>>(new Set());
  const [isAuthLoading, setIsAuthLoading] = useState(true);
  const [pendingApproval, setPendingApproval] = useState<StagedRecord[] | null>(null);

  // --- Firebase Sync ---
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setCurrentUser(user);
      setIsAuthLoading(false);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    if (!currentUser) {
      setVaultedRecords([]);
      return;
    }

    const q = query(collection(db, 'vaulted_records'), orderBy('processedAt', 'desc'));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const records = snapshot.docs.map(doc => {
        const data = doc.data();
        return {
          ...data,
          id: doc.id,
          // Handle Firestore Timestamp to ISO string for consistency
          processedAt: data.processedAt?.toDate ? data.processedAt.toDate().toISOString() : data.processedAt
        };
      }) as VaultedRecord[];
      setVaultedRecords(records);
    }, (error) => {
      console.error("Firestore Listen Error:", error);
      handleFirestoreError(error, 'list', 'vaulted_records');
    });

    return () => unsubscribe();
  }, [currentUser]);

  useEffect(() => {
    if (!currentUser) {
      setAuditLogs([]);
      return;
    }

    const q = query(collection(db, 'audit_logs'), orderBy('timestamp', 'desc'), limit(50));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const logs = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data(),
        timestamp: doc.data().timestamp?.toDate ? doc.data().timestamp.toDate().toISOString() : doc.data().timestamp
      }));
      setAuditLogs(logs);
    }, (error) => {
      handleFirestoreError(error, 'list', 'audit_logs');
    });

    return () => unsubscribe();
  }, [currentUser]);

  const handleFirestoreError = (error: any, op: string, path: string) => {
    const errInfo = {
      error: error.message,
      operationType: op,
      path,
      authInfo: {
        userId: auth.currentUser?.uid,
        email: auth.currentUser?.email,
        emailVerified: auth.currentUser?.emailVerified
      }
    };
    console.error("Critical Security Failure:", JSON.stringify(errInfo));
    setAlert({ message: `Security Rejection: ${error.message}`, type: 'warning' });
  };

  const handleLogin = async () => {
    try {
      const provider = new GoogleAuthProvider();
      await signInWithPopup(auth, provider);
    } catch (err: any) {
      setAlert({ message: `Login Failed: ${err.message}`, type: 'warning' });
    }
  };

  const handleLogout = async () => {
    await signOut(auth);
    setCurrentView('ingest');
  };

  // --- Handlers ---
  const classifyFields = async (header: string[], sampleRow: string[]): Promise<AIClassification[]> => {
    try {
      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: `Analyze these data headers: [${header.join(", ")}]. 
        Sample row values: [${sampleRow.join(", ")}].
        Return a valid JSON array of objects representing a PII classification. 
        Each object MUST have:
        1. "field": (string name of the header)
        2. "isSensitive": (boolean, true for fields like SSN, CUSID, DOB, Address, etc.)
        3. "confidence": (number between 0 and 1)
        ONLY return the JSON array.`,
      });

      const text = response.text || "[]";
      const jsonMatch = text.match(/\[.*\]/s);
      if (jsonMatch) {
         return JSON.parse(jsonMatch[0]);
      }
      throw new Error("Invalid AI structure");
    } catch (err) {
      console.error("AI Classification Error:", err);
      // Heuristic Fallback
      const sensitiveKeywords = ["SSN", "CUSID", "DOB", "ADDRESS", "EMAIL", "PHONE", "PII"];
      return header.map(field => ({
        field,
        isSensitive: sensitiveKeywords.some(k => field.toUpperCase().includes(k)),
        confidence: 0.9
      }));
    }
  };

  const handleIngest = async () => {
    if (!inputText.trim()) return;
    setIsIngesting(true);
    setAlert(null);
    try {
      const lines = inputText.trim().split("\n").filter(l => l.trim().length > 0);
      
      // Determine if headers are present
      // Heuristic: If first line values look like data (starts with digit), use DEFAULT_HEADERS
      const firstLineValues = lines[0].split("|").map(v => v.trim());
      const looksLikeData = firstLineValues.some(v => /^\d/.test(v)) || firstLineValues.length === 5;
      
      let headersToUse = DEFAULT_HEADERS;
      let dataRows = lines;

      if (!looksLikeData && lines.length > 1) {
        headersToUse = firstLineValues.filter(v => v.length > 0);
        dataRows = lines.slice(1);
      }

      const sampleRow = (dataRows[0] || "").split("|").map(v => v.trim());

      // AI Discovery
      const classifications = await classifyFields(headersToUse, sampleRow);

      const res = await fetch('/api/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          rawData: dataRows.join("\n"), 
          classifications,
          headers: headersToUse
        })
      });
      
      const data = await res.json();
      
      if (!res.ok) {
        throw new Error(data.error || "Ingestion failed server-side");
      }
      
      if (data.records && data.records.length > 0) {
        // DUPLICATE CHECK: Filter records using session tracker AND database
        const vaultSignatures = new Set(vaultedRecords.map(r => (r as any).contentSignature));
        const batchSignatures = new Set<string>();
        
        const uniqueRecords = data.records.filter((record: StagedRecord) => {
          const sig = btoa(Object.values(record.data).join('|'));
          // Check database, current batch, AND session history
          if (vaultSignatures.has(sig) || batchSignatures.has(sig) || sessionSignatures.has(sig)) {
            return false;
          }
          batchSignatures.add(sig);
          return true;
        });

        const duplicateCount = data.records.length - uniqueRecords.length;

        // COMPLIANCE CHECK: 3 rows limit
        if (uniqueRecords.length > 3) {
          setAlert({ 
            message: `THREAT ALERT: Batch size (${uniqueRecords.length}) exceeds security limit (3). Processing blocked.`, 
            type: 'warning' 
          });
        } else if (uniqueRecords.length === 0) {
          setAlert({ 
            message: `DUPLICATE ALERT: All ${duplicateCount} records already exist in the secure vault or were processed this session.`, 
            type: 'info' 
          });
        } else {
          setAlert({ message: `Success: ${uniqueRecords.length} unique records ingested. Processing...`, type: 'success' });
          setInputText('');
          await autoProcessBatch(uniqueRecords, classifications);
        }
      } else {
        setAlert({ message: "No valid records found in payload.", type: 'warning' });
      }
    } catch (err: any) {
      console.error("Ingestion Error:", err);
      setAlert({ message: `Ingestion Failed: ${err.message || "Unknown error"}`, type: 'warning' });
    } finally {
      setIsIngesting(false);
    }
  };

  const approveIngestion = () => {
    if (pendingApproval) {
      setStagingBuffer(prev => [...prev, ...pendingApproval]);
      setPendingApproval(null);
      setInputText('');
      setAlert({ message: "Administrative override approved. records committed to staging buffer.", type: 'success' });
      setTimeout(() => {
        setCurrentView('audit');
        setAlert(null);
      }, 1500);
    }
  };

  const autoProcessBatch = async (records: StagedRecord[], classifications: AIClassification[]) => {
    setIsProcessing(true);
    try {
      // Build masking config from classifications
      const sensitiveKeys = classifications.filter(c => c.isSensitive).map(c => c.field);
      const maskingConfig: MaskConfig = {
        algorithm: 'sha256',
        maskChar: '*',
        maskVisibleCount: 0,
        fields: sensitiveKeys,
        userSalt: config.userSalt || 'SYSTEM_DEFAULT_SALT'
      };

      const res = await fetch('/api/mask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          records, 
          config: maskingConfig, 
          currentUser: currentUser?.displayName || currentUser?.email || "Automated System" 
        })
      });
      
      const data = await res.json();
      if (res.ok) {
        // Persist to Firestore
        const batch = writeBatch(db);
        data.processed.forEach((record: any, index: number) => {
          const docRef = doc(db, 'vaulted_records', record.id);
          // Create search signature for future duplicate detection
          const originalRecord = records[index];
          const signature = btoa(Object.values(originalRecord.data).join('|'));

          batch.set(docRef, {
            ...record,
            processedAt: serverTimestamp(),
            contentSignature: signature // Store signature for duplicate check
          });
        });

        // Audit Log entry
        const auditRef = doc(collection(db, 'audit_logs'));
        batch.set(auditRef, {
          batchId: uuidv4(),
          timestamp: serverTimestamp(),
          recordCount: data.processed.length,
          algorithm: maskingConfig.algorithm,
          user: currentUser?.email || "Secure System"
        });

        await batch.commit();

        // Update session signatures to prevent re-ingestion in same session
        const newSigs = new Set(sessionSignatures);
        records.forEach(r => newSigs.add(btoa(Object.values(r.data).join('|'))));
        setSessionSignatures(newSigs);

        setAlert({ message: `Successfully vaulted and persisted ${data.processed.length} records.`, type: 'success' });
        setTimeout(() => {
          setCurrentView('report');
          setAlert(null);
        }, 1500);
      }
    } catch (err: any) {
      handleFirestoreError(err, 'write', 'vaulted_records');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleApplyMasking = async () => {
    if (selectedIds.size === 0) return;
    if (!config.userSalt) {
      setAlert({ message: "CRITICAL: Custom user salt is required for deterministic hashing.", type: 'warning' });
      return;
    }

    setIsProcessing(true);
    const recordsToProcess = stagingBuffer.filter(r => selectedIds.has(r.id));

    try {
      const res = await fetch('/api/mask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          records: recordsToProcess, 
          config, 
          currentUser: currentUser?.displayName || currentUser?.email || "Authenticated User" 
        })
      });
      const data = await res.json();
      if (res.ok) {
        // Persist to Firestore
        const batch = writeBatch(db);
        data.processed.forEach((record: any) => {
          const docRef = doc(db, 'vaulted_records', record.id);
          batch.set(docRef, {
            ...record,
            processedAt: serverTimestamp() // Overwrite server ISO with Firestore Timestamp for order compatibility
          });
        });

        // Audit Log entry
        const auditRef = doc(collection(db, 'audit_logs'));
        batch.set(auditRef, {
          batchId: uuidv4(),
          timestamp: serverTimestamp(),
          recordCount: data.processed.length,
          algorithm: config.algorithm,
          user: currentUser?.email || "Secure System"
        });

        await batch.commit();

        setStagingBuffer(prev => prev.filter(r => !selectedIds.has(r.id)));
        setSelectedIds(new Set());
        setAlert({ message: `Successfully vaulted and persisted ${data.processed.length} records.`, type: 'success' });
        setTimeout(() => setCurrentView('report'), 1000);
      }
    } catch (err: any) {
      handleFirestoreError(err, 'write', 'vaulted_records');
    } finally {
      setIsProcessing(false);
    }
  };

  const injectSampleData = () => {
    const sample = `45210001|7850001|12-04-1981|flat no 424 B block Mahaveer marvel apartments Bangalore 560076|Hi How are you !|
45210002|7850002|23-07-1992|Villa 12, Palm Meadows, Whitefield, Bangalore 560066|Please update my phone number.|
45210003|7850003|05-11-1975|Apt 301, Sunshine Residency, HSR Layout, Bangalore 560102|Is my account active?|
45210004|7850004|18-02-1988|No. 45, Cross Road, Indiranagar, Bangalore 560038|I need a new credit card.|
45210005|7850005|30-09-1995|Flat 102, Green View, Jayanagar, Bangalore 560041|Thanks for the quick response!|`;
    setInputText(sample);
    setAlert({ message: "Sample PII payload loaded into buffer.", type: "info" });
    setTimeout(() => setAlert(null), 3000);
  };

  const clearVault = async () => {
    if (!window.confirm("CRITICAL ACTION: Are you sure you want to PERMANENTLY purge all records and audit trails? This will refresh the system.")) return;
    
    setIsProcessing(true);
    try {
      const collectionsToClear = ['vaulted_records', 'audit_logs'];
      
      for (const colName of collectionsToClear) {
        const snap = await getDocs(collection(db, colName));
        const docs = snap.docs;
        
        // Deleting in chunks of 450 to stay safely under Firestore batch limit of 500
        for (let i = 0; i < docs.length; i += 450) {
          const batch = writeBatch(db);
          const chunk = docs.slice(i, i + 450);
          chunk.forEach(d => batch.delete(d.ref));
          await batch.commit();
        }
      }

      await fetch('/api/clear', { method: 'POST' });

      setAlert({ message: "System purged. Refreshing...", type: "success" });
      
      setTimeout(() => {
        window.location.reload();
      }, 1000);

    } catch (err) {
       console.error("Purge Error:", err);
       handleFirestoreError(err, 'delete', 'vaulted_records');
    } finally {
      setIsProcessing(false);
    }
  };

  const exportCSV = () => {
    if (vaultedRecords.length === 0) return;
    
    // Dynamically get all keys from all records to ensure we don't miss anything
    const allKeysSet = new Set<string>();
    vaultedRecords.forEach(r => {
      Object.keys(r.maskedData || {}).forEach(k => allKeysSet.add(k));
    });
    const headers = [...Array.from(allKeysSet), "VAULTED_AT"];
    const headerRow = headers.join('|') + '|';
    
    const dataRows = vaultedRecords.map(r => {
      const rowData = headers.map(h => {
        if (h === "VAULTED_AT") return r.processedAt || 'N/A';
        const val = r.maskedData[h];
        return val !== null && val !== undefined ? String(val) : 'N/A';
      });
      return rowData.join('|') + '|';
    }).join('\n');
    
    const pipeDelimitedContent = `${headerRow}\n${dataRows}`;
    const blob = new Blob([pipeDelimitedContent], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SecureVault_Export_${new Date().toISOString()}.txt`;
    a.click();
  };

  // --- Sub-Components ---

  const Sidebar = () => (
    <aside className="w-64 bg-slate-900 text-slate-300 flex flex-col h-full border-r border-slate-800">
      <div className="p-6 flex items-center gap-3 border-b border-slate-800">
        <div className="bg-blue-600 p-1.5 rounded shadow-lg shadow-blue-900/40">
          <ShieldCheck className="w-5 h-5 text-white" />
        </div>
        <div className="font-bold text-sm tracking-tight text-white uppercase">Secure Gateway</div>
      </div>

      <nav className="flex-1 p-4 space-y-1">
            <button 
              id="sidebar-nav-ingest"
              onClick={() => setCurrentView('ingest')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 ${currentView === 'ingest' ? 'bg-blue-600 text-white shadow-md' : 'hover:bg-slate-800 hover:text-white'}`}
            >
              <Upload className="w-4 h-4" />
              Ingest & Vault
            </button>
            <button 
              id="sidebar-nav-report"
              onClick={() => setCurrentView('report')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 ${currentView === 'report' ? 'bg-blue-600 text-white shadow-md' : 'hover:bg-slate-800 hover:text-white'}`}
            >
              <FileBarChart className="w-4 h-4" />
              Vault Registry
            </button>
            <button 
              id="sidebar-nav-audit"
              onClick={() => setCurrentView('audit')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 ${currentView === 'audit' ? 'bg-blue-600 text-white shadow-md' : 'hover:bg-slate-800 hover:text-white'}`}
            >
              <Activity className="w-4 h-4" />
              Governance Logs
            </button>
            
            <div className="pt-4 mt-4 border-t border-slate-800">
               <button 
                onClick={clearVault}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-slate-500 hover:bg-rose-950/30 hover:text-rose-400 transition-all duration-200"
              >
                <Trash2 className="w-4 h-4" />
                Purge Security Vault
              </button>
            </div>
      </nav>

      <div className="p-4 border-t border-slate-800 space-y-4">
        <div className="bg-slate-950/50 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-2 mb-2">
            <Lock className="w-3 h-3 text-emerald-500" />
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Gateway Health</span>
          </div>
          <div className="flex items-center justify-between text-[10px]">
            <span className="text-slate-500">Pipeline:</span>
            <span className="text-emerald-500 font-bold">STABLE</span>
          </div>
        </div>
        
        <div className="flex items-center gap-3 px-2">
          <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700 overflow-hidden">
            {currentUser?.photoURL ? (
              <img src={currentUser.photoURL} alt="User" className="w-full h-full object-cover" referrerPolicy="no-referrer" />
            ) : (
              <UserIcon className="w-4 h-4 text-slate-400" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[11px] font-bold text-white truncate">{currentUser?.displayName || currentUser?.email}</div>
            <div className="text-[9px] text-slate-500 truncate uppercase tracking-widest">{currentUser?.emailVerified ? 'Verified Operator' : 'Unverified'}</div>
          </div>
          <LogOut 
            className="w-3.5 h-3.5 text-slate-600 hover:text-rose-400 cursor-pointer transition-colors" 
            onClick={handleLogout}
          />
        </div>
      </div>
    </aside>
  );

  if (isAuthLoading) {
    return (
      <div className="h-screen flex flex-col items-center justify-center bg-slate-950 text-slate-400 font-mono gap-4">
        <motion.div 
          animate={{ rotate: 360 }}
          transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
        >
          <BrainCircuit className="w-8 h-8 text-blue-500" />
        </motion.div>
        <span className="text-[10px] tracking-[0.2em] uppercase font-bold text-slate-600">Verifying Security Protocols...</span>
      </div>
    );
  }

  if (!currentUser) {
    return (
      <div className="h-screen flex items-center justify-center bg-slate-950 overflow-hidden relative">
        <div className="absolute inset-0 opacity-30 pointer-events-none overflow-hidden">
          <div className="absolute top-[-10%] left-[-10%] w-[60%] h-[60%] bg-blue-900/20 rounded-full blur-[120px]"></div>
          <div className="absolute bottom-[-10%] right-[-10%] w-[60%] h-[60%] bg-emerald-900/20 rounded-full blur-[120px]"></div>
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:40px_40px]"></div>
        </div>
        
        <motion.div 
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="relative z-10 max-w-sm w-full bg-slate-900/50 backdrop-blur-2xl p-10 rounded-3xl border border-slate-800 shadow-[0_0_50px_rgba(0,0,0,0.5)] text-center"
        >
          <div className="w-20 h-20 bg-blue-600 rounded-[2rem] flex items-center justify-center mx-auto mb-8 shadow-[0_0_30px_rgba(37,99,235,0.4)] relative">
            <div className="absolute inset-0 rounded-[2.2rem] border-2 border-blue-400/30 animate-ping"></div>
            <ShieldCheck className="w-10 h-10 text-white relative z-10" />
          </div>
          <h1 className="text-3xl font-black text-white mb-3 uppercase tracking-tighter">Gateway 2.0</h1>
          <p className="text-slate-400 text-xs mb-10 leading-relaxed font-medium uppercase tracking-wide">Identity verification required to access cryptographic vault and ingestion pipelines.</p>
          
          <button 
            id="google-signin-button"
            onClick={handleLogin}
            className="group w-full py-4 bg-white text-slate-950 rounded-2xl font-black text-sm uppercase tracking-widest flex items-center justify-center gap-4 hover:bg-slate-100 transition-all active:scale-95 shadow-xl shadow-white/5"
          >
            <LogIn className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            Sign In with Google
          </button>
          
          <div className="mt-12 space-y-2">
            <div className="text-[9px] text-slate-600 uppercase tracking-[0.3em] font-black">Secure Data Environment</div>
            <div className="flex justify-center gap-4 opacity-30 grayscale">
               <ShieldAlert className="w-4 h-4 text-slate-400" />
               <Lock className="w-4 h-4 text-slate-400" />
               <Fingerprint className="w-4 h-4 text-slate-400" />
            </div>
          </div>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-slate-50 overflow-hidden font-sans">
      <Sidebar />

      <main className="flex-1 flex flex-col min-w-0 bg-white relative">
        {/* Top Header */}
        <header className="h-14 border-b border-slate-100 flex items-center justify-between px-8 shrink-0">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-slate-800 uppercase tracking-tight">
              {currentView === 'ingest' && 'Pipeline Ingestion'}
              {currentView === 'audit' && 'AI Data Governance & Auditing'}
              {currentView === 'report' && 'Secure Vault Exports'}
            </h2>
          </div>
          
          <div className="flex items-center gap-6">
            <div className="hidden lg:flex items-center gap-4 text-[10px] font-mono">
              <span className="text-slate-400">ALGO: <span className="text-blue-600 font-bold">{config.algorithm.toUpperCase()}</span></span>
              <span className="text-slate-400">STATE: <span className="text-emerald-600 font-bold">ZERO-TRUST ACTIVE</span></span>
            </div>
            <div className="h-4 w-px bg-slate-200"></div>
            <div className="text-[10px] text-slate-400 italic">bch_v4.2.1-stable</div>
          </div>
        </header>

        {/* View Content */}
        <div className="flex-1 overflow-auto p-4 lg:p-8">
          <AnimatePresence mode="wait">
            {isProcessing && currentView !== 'report' && (
              <div className="fixed inset-0 z-[100] bg-slate-950/40 backdrop-blur-sm flex items-center justify-center">
                <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl shadow-2xl flex flex-col items-center gap-6 max-w-xs text-center">
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ repeat: Infinity, duration: 2, ease: "linear" }}
                    className="w-16 h-16 rounded-full border-2 border-blue-500/20 border-t-blue-500 flex items-center justify-center"
                  >
                    <ShieldCheck className="w-6 h-6 text-blue-500" />
                  </motion.div>
                  <div className="space-y-2">
                    <h3 className="text-white font-bold uppercase tracking-[0.2em] text-xs">AI Vaulting in Progress</h3>
                    <p className="text-slate-500 text-[10px]">Applying cryptographic masks and committing to secure cold-storage cloud.</p>
                  </div>
                </div>
              </div>
            )}

            {currentView === 'ingest' && (
              <motion.div 
                key="ingest"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="max-w-4xl space-y-8"
              >
                <section>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-[11px] font-bold text-slate-500 uppercase flex items-center gap-2">
                      <Upload className="w-3 h-3" />
                      Bulk Ingestion Module
                    </label>
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-mono text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-100 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> PIE COMPLIANT
                      </span>
                      <span className="text-[10px] font-mono text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-100">
                        Standard: Pipe-Delimited (|)
                      </span>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 mb-6 font-medium">Input bulk data streams for automated AI classification and cryptographic segmentation.</p>
                  
                  <div className="bg-slate-50 border border-slate-100 rounded-xl p-4 mb-6">
                    <h4 className="text-[10px] font-bold text-slate-700 uppercase tracking-widest mb-3 flex items-center gap-2">
                      <Lock className="w-3 h-3 text-blue-500" /> Important Sensitive PII Fields
                    </h4>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {[
                        { name: 'SSN', desc: 'Social Security' },
                        { name: 'CUSID', desc: 'Customer ID' },
                        { name: 'DOB', desc: 'Date of Birth' },
                        { name: 'ADDRESS', desc: 'Full Address' }
                      ].map(field => (
                        <div key={field.name} className="bg-white p-2 rounded border border-slate-200">
                          <div className="text-[10px] font-bold text-blue-600">{field.name}</div>
                          <div className="text-[9px] text-slate-400">{field.desc}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-4">
                    <textarea 
                      value={inputText}
                      onChange={(e) => setInputText(e.target.value)}
                      placeholder="54829104|1048592|15-08-1992|Villa 12, Bangalore|Please update my phone...&#10;93847162|3948102|22-11-1985|Apt 301, HSR Layout|Is my account active?|"
                      className={`w-full h-64 bg-slate-50 border ${isIngesting ? 'border-blue-400 opacity-60' : 'border-slate-200'} rounded-xl p-4 font-mono text-xs focus:ring-2 focus:ring-blue-500 outline-none resize-none shadow-inner text-slate-600 transition-all`}
                      disabled={isIngesting}
                    />
                    <div className="flex justify-between items-center pt-2">
                      <div className="flex gap-4">
                        <button 
                          id="ingest-parse-button"
                          onClick={handleIngest}
                          disabled={isIngesting || !inputText.trim() || !!pendingApproval}
                          className="px-8 py-3 bg-slate-800 text-white rounded-lg font-bold text-xs uppercase tracking-widest hover:bg-slate-900 transition-all shadow-md active:scale-95 disabled:opacity-50 flex items-center gap-2"
                        >
                          {isIngesting ? "Classifying..." : "Parse Payload"}
                          <ChevronRight className="w-4 h-4" />
                        </button>

                        <button 
                          onClick={injectSampleData}
                          disabled={isIngesting || !!pendingApproval}
                          className="px-4 py-3 border border-slate-200 text-slate-500 rounded-lg font-bold text-[10px] uppercase tracking-widest hover:bg-slate-50 transition-all flex items-center gap-2"
                        >
                          <FileText className="w-3 h-3" />
                          Load Sample
                        </button>
                        
                        {pendingApproval && (
                          <button 
                            id="ingest-approve-button"
                            onClick={approveIngestion}
                            className="px-8 py-3 bg-rose-600 text-white rounded-lg font-bold text-xs uppercase tracking-widest hover:bg-rose-700 transition-all shadow-md active:scale-95 flex items-center gap-2 animate-pulse"
                          >
                            <ShieldAlert className="w-4 h-4" />
                            Approve Large Batch
                          </button>
                        )}
                      </div>
                      <span className="text-[10px] text-slate-400 font-medium italic">Threshold Limit: 10 Rows</span>
                    </div>
                  </div>
                </section>

                <section className="bg-slate-50 rounded-xl p-6 border border-slate-200/50">
                  <div className="flex items-center gap-3 mb-4">
                    <BrainCircuit className="w-5 h-5 text-blue-500" />
                    <h3 className="text-xs font-bold text-slate-700 uppercase">AI Pre-Scan Logic</h3>
                  </div>
                  <p className="text-xs text-slate-500 leading-relaxed max-w-2xl">
                    Upon ingestion, our Gemini-powered engine scans the payload structure for sensitive identifiers. 
                    Calculates confidence scores based on header semantics and structural patterns.
                    Records are moved to the Audit Staging for human validation before permanent masking.
                  </p>
                </section>
              </motion.div>
            )}

            {currentView === 'audit' && (
              <motion.div 
                key="audit"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 1.02 }}
                className="space-y-6"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h1 className="text-xl font-bold text-slate-800">Compliance Audit Ledger</h1>
                    <p className="text-[11px] text-slate-500 mt-1 uppercase font-bold tracking-widest italic">Non-Repudiable Processing Artifacts</p>
                  </div>
                </div>

                <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-sm">
                  <div className="p-4 border-b border-slate-100 bg-slate-50/50 flex items-center justify-between">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Recent Activity Streams</span>
                    <span className="text-[10px] text-slate-400">Showing last 50 events</span>
                  </div>
                  
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-[10px]">
                      <thead>
                        <tr className="bg-slate-50 text-slate-500 font-bold uppercase tracking-tighter border-b border-slate-200">
                          <th className="px-6 py-3">Event ID</th>
                          <th className="px-6 py-3">Batch Reference</th>
                          <th className="px-6 py-3">Operator</th>
                          <th className="px-6 py-3">Payload Size</th>
                          <th className="px-6 py-3 text-right">Timestamp (UTC)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {auditLogs.length === 0 ? (
                          <tr>
                            <td colSpan={5} className="px-6 py-12 text-center text-slate-400 italic">No audit records found in secure ledger.</td>
                          </tr>
                        ) : auditLogs.map(log => (
                          <tr key={log.id} className="border-b border-slate-100 hover:bg-blue-50/30 transition-colors">
                            <td className="px-6 py-4 font-mono text-blue-600">{log.id.slice(0, 8)}...</td>
                            <td className="px-6 py-4 font-mono">{log.batchId?.slice(0, 12)}</td>
                            <td className="px-6 py-4">
                              <span className="bg-slate-100 px-2 py-1 rounded text-slate-600 font-medium">{log.user}</span>
                            </td>
                            <td className="px-6 py-4 font-bold">{log.recordCount} Records</td>
                            <td className="px-6 py-4 text-right text-slate-500 font-mono">
                              {new Date(log.timestamp).toLocaleString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </motion.div>
            )}

            {currentView === 'report' && (
              <motion.div 
                key="report"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6 h-full flex flex-col"
              >
                <div className="flex items-center justify-between shrink-0">
                  <div>
                    <h1 className="text-xl font-bold text-slate-800">Secure Vault Registry</h1>
                    <p className="text-[11px] text-slate-500 mt-1 uppercase font-bold tracking-wider italic">Processed & Cryptographically Segmented</p>
                  </div>
                  
                  <div className="flex gap-3">
                    <button 
                      onClick={clearVault}
                      disabled={isProcessing}
                      className="p-2 border border-slate-700 text-slate-500 hover:text-rose-500 hover:border-rose-500/30 rounded-lg transition-all"
                      title="Purge Cloud Database"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                    <button 
                      onClick={exportCSV}
                      disabled={vaultedRecords.length === 0}
                      className="bg-slate-800 text-white px-6 py-2 rounded-lg text-xs font-bold hover:bg-slate-900 transition-all uppercase tracking-widest flex items-center gap-2 shadow-lg shadow-slate-200"
                    >
                      <Download className="w-4 h-4" />
                      Generate Export Report
                    </button>
                  </div>
                </div>

                <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col">
                  <div className="overflow-auto flex-1">
                    {vaultedRecords.length === 0 ? (
                      <div className="h-full flex flex-col items-center justify-center text-slate-700">
                        <Fingerprint className="w-12 h-12 mb-3 opacity-10" />
                        <p className="text-xs font-mono uppercase tracking-widest opacity-20">Secure Vault Offline</p>
                      </div>
                    ) : (() => {
                      const columns = DEFAULT_HEADERS;

                      return (
                        <table className="w-full text-left border-collapse text-[10px]">
                          <thead>
                            <tr className="bg-slate-950 border-b border-slate-800 uppercase tracking-widest text-[9px] text-slate-500 font-bold sticky top-0 z-10">
                              {columns.map(header => (
                                <th key={header} className="px-6 py-3 border-r border-slate-800 last:border-r-0 italic">{header} (MASKED)|</th>
                              ))}
                              <th className="px-6 py-3">Audit Security Ledger</th>
                            </tr>
                          </thead>
                          <tbody className="font-mono">
                            {vaultedRecords.map((record) => (
                              <tr key={record.id} className="border-b border-slate-800 hover:bg-slate-800/30 transition-colors">
                                {columns.map((key) => {
                                  // Find value with case-insensitive key lookup to handle slight header mismatches
                                  const actualKey = Object.keys(record.maskedData || {}).find(k => k.trim().toUpperCase() === key.toUpperCase());
                                  const rawVal = actualKey ? record.maskedData[actualKey] : null;
                                  const valString = rawVal !== null && rawVal !== undefined ? String(rawVal) : 'N/A';
                                  
                                  return (
                                    <td key={key} className={`px-6 py-4 border-r border-slate-800 last:border-r-0 ${valString.includes('*') ? 'text-emerald-400 font-bold' : 'text-slate-400'}`}>
                                      {valString} |
                                    </td>
                                  );
                                })}
                                <td className="px-6 py-4">
                                  <div className="flex flex-col gap-1 text-[8px]">
                                    <div className="flex items-center gap-1">
                                      <span className="text-slate-600 uppercase font-bold">Token:</span>
                                      <span className="text-emerald-600 truncate max-w-[80px]">{Object.values(record.tokens)[0] || '...'}</span>
                                    </div>
                                    <div className="flex items-center gap-1">
                                      <span className="text-slate-600 uppercase font-bold">Algo:</span>
                                      <span className="text-blue-500">{record.algorithm.toUpperCase()}</span>
                                    </div>
                                    <div className="flex items-center gap-1">
                                      <span className="text-slate-600 uppercase font-bold">Salt:</span>
                                      <span className="text-slate-500 truncate max-w-[60px]">{(record as any).userSalt || 'SYSTEM'}</span>
                                    </div>
                                    <div className="flex items-center gap-1">
                                      <span className="text-slate-600 uppercase font-bold">Time:</span>
                                      <span className="text-slate-500 truncate max-w-[120px]">{new Date(record.processedAt).toLocaleString()}</span>
                                    </div>
                                    <div className="text-[7px] text-slate-700 italic border-t border-slate-800 pt-1 mt-1">Audit: {record.processedBy}</div>
                                  </div>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      );
                    })()}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Global Notifications */}
        <AnimatePresence>
          {alert && (
            <motion.div 
              initial={{ opacity: 0, y: 50 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 20 }}
              className="absolute bottom-6 right-6 z-50 pointer-events-none"
            >
              <div className={`p-4 rounded-xl border-2 shadow-2xl pointer-events-auto flex gap-4 items-center bg-white ${
                alert.type === 'warning' ? 'border-amber-200' : 'border-blue-200'
              }`}>
                <div className={`p-2 rounded-full ${alert.type === 'warning' ? 'bg-amber-100 text-amber-600' : 'bg-blue-100 text-blue-600'}`}>
                  {alert.type === 'warning' ? <AlertTriangle className="w-5 h-5" /> : <CheckCircle2 className="w-5 h-5" />}
                </div>
                <div className="min-w-[200px]">
                   <p className="text-xs font-bold text-slate-800 uppercase tracking-tighter">System Message</p>
                   <p className="text-[11px] text-slate-500">{alert.message}</p>
                </div>
                <button 
                  onClick={() => setAlert(null)}
                  className="p-1 hover:bg-slate-100 rounded-lg text-slate-400"
                >
                  ✕
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

