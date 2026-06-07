# Secure Batch Ingestion Gateway 

A production-grade, zero-trust batch data processing system designed for secure ingestion, PII classification, and cryptographic masking of sensitive data streams.

## Features

- **Gemini-Powered PII Discovery**: Automated sensitive field classification using AI.
- **Zero-Trust Security Rules**: Hardened Firestore rules with recursive relational checks and schema validation.
- **Deterministic Masking**: Cryptographic hashing (SHA-256/SHA-512) with system-level and user-level salt/pepper sequences.
- **Content Integrity**: Automated duplicate detection using base64 content signatures.
- **Audit Trails**: Non-repudiable audit logging for all batch processing operations.
- **Elite Frontend Design**: High-craftsmanship UI using Tailwind CSS, Framer Motion, and Lucide icons.

## Architecture

- **Frontend**: React (Vite) + Framer Motion + Tailwind CSS.
- **Backend Proxy**: Express.js for handling cryptographic operations (preventing key exposure).
- **Storage**: Firebase Firestore with strict zero-trust ACLs.
- **Authentication**: Firebase Authentication (Google OAuth).

## Setup

1. **Environment Variables**:
   Copy `.env.example` to `.env` and provide your secrets.
   ```bash
   GEMINI_API_KEY=your_key
   SYSTEM_PEPPER=your_pepper
   ```

2. **Firebase Configuration**:
   Ensure `firebase-applet-config.json` is populated with your Firebase project details.

3. **Install Dependencies**:
   ```bash
   npm install
   ```

4. **Run Development Server**:
   ```bash
   npm run dev
   ```

## Security Best Practices Implemented

- **No Public API Keys**: Gemini API keys and system peppers are handled server-side.
- **Verified Operations**: Sign-in is restricted to verified email addresses.
- **Schema Enforcement**: Firestore rules validate the exact shape and content of every write.
- **Deterministic Hashing**: Ensures that the same PII always maps to the same hash (when salt is consistent), allowing for secure analytics without cleartext exposure.
