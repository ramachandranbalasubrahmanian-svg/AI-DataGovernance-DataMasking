import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

const PORT = 3000;
const SYSTEM_PEPPER = process.env.SYSTEM_PEPPER || "DEFAULT_PEPPER";

// --- Types ---
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

interface MaskConfig {
  userSalt: string;
  algorithm: "sha256" | "sha512";
}

// --- Audit Log Storage (Mock) ---
const auditLogs: any[] = [];
let ingestedCount = 0;
let lastIngestTime = Date.now();

// --- API Endpoints ---

app.post("/api/ingest", async (req, res) => {
  try {
    const { rawData, classifications, headers: explicitHeaders } = req.body;
    if (!rawData) return res.status(400).json({ error: "No data provided" });

    const lines = rawData.trim().split("\n").filter((l: string) => l.trim().length > 0);
    
    let header: string[] = [];
    let rows: string[] = [];

    if (explicitHeaders && Array.isArray(explicitHeaders) && explicitHeaders.length > 0) {
      header = explicitHeaders;
      rows = lines;
    } else {
      if (lines.length < 2) return res.status(400).json({ error: "Invalid format. Requires header and data." });
      header = lines[0].split("|").filter((h: string) => h.trim() !== "").map(h => h.trim());
      rows = lines.slice(1);
    }

    const records: StagedRecord[] = rows.map((line: string) => {
      const values = line.split("|").map(v => v.trim());
      const recordData: Record<string, string> = {};
      header.forEach((key, index) => {
        recordData[key] = values[index] || "";
      });
      return {
        id: uuidv4(),
        data: recordData,
        classifications: classifications || [],
        ingestedAt: new Date().toISOString()
      };
    });

    // Alert Monitoring
    const ssnCount = records.filter(r => r.data.SSN).length;
    ingestedCount += ssnCount;
    const now = Date.now();
    if (now - lastIngestTime > 60000) {
       ingestedCount = ssnCount;
       lastIngestTime = now;
    }

    res.json({ records, alertTriggered: ingestedCount > 50 });
  } catch (err) {
    res.status(500).json({ error: "Failed to parse data" });
  }
});

// Cryptographic Masking Pipeline
app.post("/api/mask", (req, res) => {
  try {
    const { records, config, currentUser }: { records: StagedRecord[], config: MaskConfig, currentUser: string } = req.body;
    const { userSalt, algorithm } = config;

    const processed = records.map(record => {
      const raw = record.data;
      const masked: Record<string, string> = {};
      const tokens: Record<string, string> = {};
      const hashes: Record<string, string> = {};

      // Get sensitive field names from classifications
      const sensitiveFieldNames = record.classifications
        .filter(c => c.isSensitive)
        .map(c => c.field.trim().toUpperCase());

      // Iterate over all possible keys in the record
      Object.keys(raw).forEach(key => {
        const originalValue = raw[key];
        const normalizedKey = key.trim().toUpperCase();
        const isSensitive = sensitiveFieldNames.includes(normalizedKey);

        if (isSensitive && originalValue) {
          // UI Mask: Keep last 2 characters visible
          const safePart = originalValue.length > 2 ? originalValue.slice(-2) : originalValue;
          const maskCount = Math.max(0, originalValue.length - safePart.length);
          masked[key] = "*".repeat(maskCount) + safePart;

          // Cryptographic Transformation
          const saltedData = `${originalValue}${userSalt}${SYSTEM_PEPPER}`;
          
          let hash;
          try {
            hash = crypto.createHash(algorithm).update(saltedData).digest("hex");
          } catch (e) {
            // Fallback to sha256 if algorithm is invalid or not a hash method
            hash = crypto.createHash("sha256").update(saltedData).digest("hex");
          }
          
          hashes[key] = hash;
          tokens[key] = `tok_${crypto.createHash("md5").update(originalValue + userSalt).digest("hex").slice(0, 8)}`;
        } else {
          // Cleartext for non-sensitive fields
          masked[key] = originalValue;
        }
      });

      return {
        id: record.id,
        originalId: record.id,
        maskedData: masked,
        tokens,
        hashes,
        algorithm: algorithm || "sha256",
        userSalt,
        processedBy: currentUser,
        processedAt: new Date().toISOString(),
        metadata: record.classifications.filter(c => sensitiveFieldNames.includes(c.field.toUpperCase()))
      };
    });

    // Audit Logging
    auditLogs.push({
      batchId: uuidv4(),
      timestamp: new Date().toISOString(),
      recordCount: records.length,
      algorithm: algorithm || "sha256",
      user: currentUser
    });

    res.json({ processed });
  } catch (err: any) {
    console.error("Masking Pipeline Error:", err);
    res.status(500).json({ error: err.message || "Failed to mask records" });
  }
});

app.post("/api/clear", (req, res) => {
  auditLogs.length = 0;
  ingestedCount = 0;
  res.json({ success: true });
});

app.get("/api/audit-logs", (req, res) => {
  res.json(auditLogs);
});

// --- Server Setup ---

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
