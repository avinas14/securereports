# CareBridge — Secure Health Record Sharing (Health Bento theme)

A vanilla HTML/CSS/JavaScript + Supabase MVP for a hackathon. It demonstrates patient-owned encrypted record entries, provider consent requests, patient approval/denial/revocation, audited provider retrieval, and an access history dashboard.

> **Safety / scope:** This is a hackathon MVP, not a certified electronic health record system. Use synthetic data only. Do not upload real patient data. It has not undergone penetration testing, clinical workflow validation, or a healthcare privacy/compliance review. Do not claim HIPAA, ABDM, DPDP Act, or other regulatory compliance based on this project.

## Project structure

```text
health-bento/
├── index.html
├── README.md
├── .gitignore
├── css/
│   └── styles.css
├── js/
│   ├── config.js
│   └── app.js
└── supabase/
    ├── schema.sql
    └── functions/
        ├── access-record/       # Reserved for a future signed API integration
        └── request-consent/     # Reserved for a future signed API integration
```

The current implementation uses PostgreSQL security-definer RPCs for sensitive operations, so separate Edge Functions are not required for this MVP. All sensitive access checks are enforced in SQL/RLS, not just in the UI.

## Features

- Email/password sign-up, sign-in, sign-out, and password reset through Supabase Auth.
- Patient and healthcare-provider roles. Provider sign-up creates a hospital/clinic record.
- Patient record entry; record details are encrypted in the browser using AES-GCM with a passphrase-derived key (PBKDF2-SHA-256, 250,000 iterations, random salt and IV).
- Provider requests access by patient email with a stated care purpose and expiration period.
- Patient can approve, deny, or revoke a request. Provider retrieval is available only for an active, unexpired consent.
- A database function logs record retrieval in the same transaction before returning encrypted record payloads.
- Patient/provider access-history views and CSV export.
- Search/filter controls, responsive Health Bento dashboard, loading/error/empty states.

## Requirements

- A Supabase project with email/password authentication enabled.
- A modern browser supporting Web Crypto (`crypto.subtle`) and a local static web server.
- Internet access for the Supabase JS CDN and Google Fonts used by the UI.

## Setup

1. Create a Supabase project at https://supabase.com/.
2. Open **SQL Editor** in the Supabase dashboard and run `supabase/schema.sql` in one go. Review any SQL editor errors; do not continue until the script completes successfully.
3. In **Authentication → Providers**, enable Email. For a quick local hackathon demo you may disable email confirmation; for real deployments keep appropriate confirmation and recovery settings. Configure the allowed redirect URLs for your local and production URLs.
4. Copy your project's **Project URL** and **publishable/anon key** from Project Settings → API.
5. Edit `js/config.js` and replace `https://YOUR-PROJECT.supabase.co` and `YOUR_SUPABASE_PUBLISHABLE_OR_ANON_KEY`. Use only the publishable/anon key in this browser file. **Never use a service-role key here.**
6. Serve the folder over HTTP. For example, from the project directory:
   - Python: `python -m http.server 5500`
   - Then open `http://localhost:5500`.
   - VS Code Live Server is also suitable.
7. Create two test accounts: one Patient, and one Hospital / healthcare provider with a clinic name. Use separate email addresses. If email confirmation is enabled, confirm both addresses first.
8. Sign in as patient, add a record with synthetic data and an encryption passphrase (10+ characters). Sign out, sign in as provider, use **Patient lookup** to find the patient's email and request consent. Sign in as patient and approve it. Sign in as provider and open the active grant to retrieve the encrypted records. The patient passphrase must be sent to the provider over a separate secure channel for the demo; it is never stored in the database.
9. Test denial and revocation as well. Once revoked or expired, provider retrieval must fail.

## Database security model

- RLS is enabled for all tables.
- Profiles are private; direct reads return only the current user's profile. The `find_patient_by_email` RPC only returns a matching patient to an authenticated provider.
- Patients can read/create/delete only their own records. Providers cannot directly query `health_records`.
- Providers can insert pending consent requests only for themselves. Only the patient can approve, deny, or revoke through dedicated database functions.
- Providers retrieve encrypted records only through `get_shared_records`, which checks that the grant belongs to the caller, is active, and is unexpired. Each returned record creates an audit row in the same database transaction.
- Audit logs have no client insert/update/delete policy. Read access is limited to the patient and actor involved.
- Roles/hospital assignment cannot be changed from the client.

## Encryption notes and limitations

The **record details field** is encrypted client-side before it is stored. The title, record type, summary, timestamps, and relationship metadata remain queryable plaintext; keep these fields free of sensitive details. Supabase-managed encryption at rest and HTTPS/TLS are additional platform protections, not a substitute for app-level encryption.

The MVP uses a patient-chosen passphrase per record. A provider needs the passphrase from the patient via a separate secure channel to decrypt the content. This is intentionally simple for a short hackathon, but it is not a complete multi-hospital key-management solution. A production implementation should use vetted key management and recipient-specific public-key wrapping, managed secrets/KMS, stronger identity proofing, institutional onboarding, emergency-access governance, immutable/externally anchored audit trails, retention policies, backups, monitoring, and a formal privacy/security review.

## Deployment

You can deploy the static files to Netlify, Vercel static hosting, GitHub Pages, or any HTTPS static host. Upload the project folder as the site's root. Configure `js/config.js` with the Supabase project URL and publishable key for that environment. In Supabase Auth, add the deployed HTTPS URL to the allowed redirect URLs. Then test signup, login, reset-password flow, role-specific navigation, record encryption/decryption, consent approval, retrieval, revocation, and CSV export.

Do not expose database passwords or service-role credentials. The frontend uses a CDN Supabase client, so no npm build step is needed. For production, prefer a build pipeline and environment injection rather than committing environment-specific configuration.

## Verification status

- JavaScript syntax was checked with `node --check js/app.js`.
- Database schema was reviewed for consistent table/function names against the frontend calls, but it has not been executed against a live Supabase project in this environment.
- Live Auth, RLS behavior, RPC permissions, browser UI, and deployment still need to be tested in your own Supabase project. Treat any live test as unverified until you run it.
