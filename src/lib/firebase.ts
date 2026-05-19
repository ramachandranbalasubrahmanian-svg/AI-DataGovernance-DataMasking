import { initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';
import { getFirestore, doc, getDocFromCache, getDocFromServer } from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId); // CRITICAL: Use the specific database ID
export const auth = getAuth(app);

// Connectivity check
async function testConnection() {
  try {
    const testDoc = doc(db, 'test', 'connection');
    await getDocFromServer(testDoc);
    console.log("Firebase connection established successfully.");
  } catch (error) {
    if (error instanceof Error) {
      console.warn("Firestore connectivity test message:", error.message);
      if (error.message.includes('the client is offline')) {
        console.error("Firebase appears to be offline. This may be due to a new project still provisioning or network restrictions.");
      }
    } else {
      console.error("Unknown Firebase initialization error:", error);
    }
  }
}
testConnection();
