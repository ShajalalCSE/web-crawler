#!/usr/bin/env python3
"""
leak_hunter.py v3 - Deep secret & data-leak hunter for YOUR OWN web assets.

What it does (beyond a normal crawler):
  * Discovers Next.js / Turbopack / webpack lazy chunks that are never linked in HTML
    (RSC payloads, build manifests, webpack chunk-id maps, escaped \\u002F paths)
  * Unescapes JSON/RSC payloads before scanning (\\" \\/ \\u002F)
  * Scans JS source maps (sourcesContent) file by file
  * Decodes base64 blobs and scans the decoded text
  * Scans response headers, robots.txt, sitemaps, service workers, Firebase init files
  * --render   : headless Chromium (Playwright) captures every runtime JS/XHR/fetch
                 response, the rendered DOM and localStorage/sessionStorage
  * --wayback  : pulls OLD archived JS/JSON/config files from the Wayback Machine
                 (keys removed from the live site often still live in old builds)
  * --subdomains : finds subdomains via certificate transparency (crt.sh)
  * --firebase-checks : read-only checks of YOUR Firebase project
                 (public RTDB, listable Storage, Firestore collections readable
                 without login, email enumeration, API key restriction)
  * Deduplicates by value, assigns severity, filters common false positives
  * JSON + Markdown report

Usage:
  pip3 install requests beautifulsoup4 --break-system-packages
  python3 leak_hunter.py https://example.com --all
  python3 leak_hunter.py https://example.com --render --wayback --firebase-checks --show-full

  Lab / CTF targets (TryHackMe, HackTheBox - connect to the lab VPN first):
  python3 leak_hunter.py http://10.10.123.45 --show-full
  python3 leak_hunter.py http://10.10.123.45:8080 --render --show-full
  python3 leak_hunter.py http://target.thm --render --show-full   # after adding to /etc/hosts

  For --render:
    pip3 install playwright --break-system-packages && playwright install chromium

Only run against assets you own or are explicitly authorized to test.
"""
import re
import sys
import json
import math
import time
import base64
import random
import string
import argparse
import threading
from collections import deque
from datetime import datetime
from urllib.parse import urljoin, urlparse, urldefrag, quote

import requests
from bs4 import BeautifulSoup

UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

SECRET_PATTERNS = {
    # ---------------- Bunny.net (BunnyCDN) ----------------
    "Bunny.net Account/Stream API Key (keyword+UUID)":
        r"(?i)(bunny|bunnycdn|b-cdn|accesskey|access_key)[\w\s\"':=\-]{0,40}?(" + UUID + r"(?:-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})?)",
    "Bunny.net Storage Password (keyword+UUID)":
        r"(?i)(storage[_-]?(zone)?[_-]?(password|key)|BUNNY_STORAGE)[\w\s\"':=\-]{0,30}?(" + UUID + r"[0-9a-fA-F\-]*)",
    "Bunny.net Storage Endpoint": r"(?i)[a-z0-9.-]*storage\.bunnycdn\.com",
    "Bunny.net API Endpoint": r"(?i)api\.bunny\.net",
    "Bunny.net Stream Library": r"(?i)video\.bunnycdn\.com/library/\d+",
    "Bunny.net Pull Zone": r"(?i)[a-z0-9-]+\.b-cdn\.net",
    "Bunny.net Token Auth Key (keyword)":
        r"(?i)(token[_-]?auth[_-]?key|security[_-]?key)[\w\s\"':=\-]{0,20}?['\"]([0-9a-fA-F\-]{32,})['\"]",

    # ---------------- AWS ----------------
    "AWS Access Key ID": r"\b(AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[0-9A-Z]{16}\b",
    "AWS Secret Access Key (keyword)":
        r"(?i)aws.{0,20}(secret|private).{0,20}['\"=:\s]([0-9a-zA-Z/+]{40})['\"\s]",
    "AWS Session Token (keyword)": r"(?i)aws.{0,10}session.{0,10}token.{0,5}['\"=:\s]([A-Za-z0-9/+=]{100,})",
    "AWS S3 Bucket URL": r"[a-z0-9.-]+\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com",
    "AWS MWS Key": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",

    # ---------------- Google / Firebase / GCP ----------------
    "Google API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "Google OAuth Client Secret": r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b",
    "Google OAuth Access Token": r"\bya29\.[0-9A-Za-z\-_]{30,}",
    "Google OAuth Client ID": r"\b[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com\b",
    "GCP Service Account JSON": r"\"type\"\s*:\s*\"service_account\"",
    "Firebase Realtime DB URL": r"[a-z0-9.-]+\.firebaseio\.com",
    "Firebase App Domain": r"[a-z0-9-]+\.firebaseapp\.com",
    "Firebase Cloud Messaging Server Key": r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b",
    "Google reCAPTCHA Secret (keyword)": r"(?i)recaptcha.{0,15}secret.{0,10}['\"]([0-9A-Za-z_-]{40})['\"]",

    # ---------------- Microsoft Azure ----------------
    "Azure Storage Connection String": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,}",
    "Azure Storage Account Key (keyword)": r"(?i)AccountKey=([A-Za-z0-9+/=]{86,88})",
    "Azure SAS Token": r"(?i)[?&]sig=[A-Za-z0-9%]{40,}&?",
    "Azure Client Secret (keyword)": r"(?i)(azure|client).{0,20}secret.{0,10}['\"]([A-Za-z0-9_~.\-]{34,40})['\"]",
    "Azure DevOps PAT (keyword)": r"(?i)(azure|ado|devops).{0,20}(pat|token).{0,10}['\"]([a-z0-9]{52})['\"]",

    # ---------------- Other Clouds / Hosting ----------------
    "Cloudflare API Token (keyword)": r"(?i)(cloudflare|cf[_-]?api).{0,25}['\"=:\s]([A-Za-z0-9_-]{40})['\"\s]",
    "Cloudflare Global API Key (keyword)": r"(?i)(cloudflare|cf).{0,25}(global|api)[_-]?key.{0,10}['\"=:\s]([0-9a-f]{37})",
    "Cloudflare R2 Endpoint": r"[0-9a-f]{32}\.r2\.cloudflarestorage\.com",
    "DigitalOcean Token": r"\bdo[opr]_v1_[a-f0-9]{64}\b",
    "Heroku API Key (keyword)": r"(?i)heroku.{0,20}['\"=:\s](" + UUID + r")",
    "Vercel Token (keyword)": r"(?i)vercel.{0,20}['\"=:\s]([A-Za-z0-9]{24})['\"\s]",
    "Netlify Token (keyword)": r"(?i)netlify.{0,20}['\"=:\s]([A-Za-z0-9_-]{40,46})['\"\s]",
    "Alibaba Cloud AccessKey ID": r"\bLTAI[A-Za-z0-9]{12,20}\b",
    "Tencent Cloud SecretId": r"\bAKID[A-Za-z0-9]{13,40}\b",
    "Linode/Akamai Token (keyword)": r"(?i)linode.{0,20}['\"=:\s]([a-f0-9]{64})",
    "Vultr API Key (keyword)": r"(?i)vultr.{0,20}['\"=:\s]([A-Z0-9]{36})",
    "Supabase URL": r"https://[a-z0-9]{20}\.supabase\.co",
    "Supabase Service/Anon Key (keyword+JWT)": r"(?i)supabase.{0,40}(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
    "Supabase Secret Key": r"\bsb_secret_[A-Za-z0-9_-]{20,}\b",
    "Cloudinary URL": r"cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z0-9-]+",
    "Doppler Token": r"\bdp\.(pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}\b",
    "HashiCorp Vault Token": r"\bhvs\.[A-Za-z0-9_-]{90,}\b",
    "Terraform Cloud Token": r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,70}\b",
    "Pulumi Token": r"\bpul-[a-f0-9]{40}\b",

    # ---------------- AI / LLM APIs ----------------
    "OpenAI API Key": r"\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b",
    "OpenAI API Key (new format)": r"\bsk-(proj|svcacct|admin)-[A-Za-z0-9_-]{40,}\b",
    "Anthropic API Key": r"\bsk-ant-(api03|admin01)-[A-Za-z0-9_-]{80,}\b",
    "Hugging Face Token": r"\bhf_[A-Za-z0-9]{34,}\b",
    "Groq API Key": r"\bgsk_[A-Za-z0-9]{48,}\b",
    "Replicate Token": r"\br8_[A-Za-z0-9]{37,}\b",
    "Perplexity API Key": r"\bpplx-[A-Za-z0-9]{48,}\b",
    "xAI API Key": r"\bxai-[A-Za-z0-9]{60,}\b",
    "DeepSeek/Generic sk- Key (keyword)": r"(?i)(deepseek|mistral|together|cohere|openrouter).{0,20}['\"=:\s](sk-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{32,})",
    "OpenRouter Key": r"\bsk-or-v1-[a-f0-9]{64}\b",
    "ElevenLabs Key (keyword)": r"(?i)(elevenlabs|xi-api-key).{0,20}['\"=:\s]([a-f0-9]{32}|sk_[a-f0-9]{48})",
    "Pinecone Key (keyword)": r"(?i)pinecone.{0,20}['\"=:\s](pcsk_[A-Za-z0-9_]{50,}|" + UUID + r")",
    "LangSmith Key": r"\blsv2_(pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b",

    # ---------------- Payment Gateways ----------------
    "Stripe Secret Key (live)": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Restricted Key (live)": r"\brk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Publishable Key (live)": r"\bpk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Webhook Secret": r"\bwhsec_[0-9a-zA-Z]{32,}\b",
    "PayPal/Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "PayPal Client Secret (keyword)": r"(?i)paypal.{0,20}secret.{0,10}['\"=:\s]([A-Za-z0-9_-]{60,80})",
    "Square Access Token": r"\bEAAA[A-Za-z0-9_-]{60}\b",
    "Square OAuth Secret": r"\bsq0csp-[0-9A-Za-z\-_]{43}\b",
    "Razorpay Live Key": r"\brzp_live_[A-Za-z0-9]{14}\b",
    "Paystack Secret Key": r"\bsk_live_[a-f0-9]{40}\b",
    "Flutterwave Secret Key": r"\bFLWSECK-[a-f0-9]{32}-X\b",
    "SSLCommerz Store Password (keyword)": r"(?i)(store_passwd|store_password|sslcz).{0,10}['\"=:\s]([A-Za-z0-9@#$]{8,})",
    "bKash App Secret/Password (keyword)": r"(?i)bkash.{0,30}(secret|password|app_key).{0,10}['\"=:\s]([A-Za-z0-9_\-]{8,})",
    "Nagad Merchant Key (keyword)": r"(?i)nagad.{0,30}(private|merchant|secret).{0,10}['\"=:\s]([A-Za-z0-9+/=]{20,})",
    "AamarPay Signature Key (keyword)": r"(?i)(aamarpay|signature_key).{0,10}['\"=:\s]([a-f0-9]{32})",
    "Coinbase/Crypto Key (keyword)": r"(?i)(coinbase|binance|bybit).{0,20}(secret|api).{0,10}['\"=:\s]([A-Za-z0-9]{32,64})",

    # ---------------- Code Hosting / CI/CD / Registries ----------------
    "GitHub Token (classic/app)": r"\bgh[pousr]_[0-9A-Za-z]{36,}\b",
    "GitHub Fine-grained PAT": r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
    "GitLab PAT": r"\bglpat-[0-9A-Za-z_-]{20,}\b",
    "GitLab Runner/Deploy Token": r"\b(glrt|gldt|GR1348941)-?[0-9A-Za-z_-]{20,}\b",
    "Bitbucket App Password (keyword)": r"(?i)bitbucket.{0,20}['\"=:\s](ATBB[A-Za-z0-9_=.-]{28,})",
    "Atlassian API Token": r"\bATATT3[A-Za-z0-9_=\-]{180,}\b",
    "npm Token": r"\bnpm_[A-Za-z0-9]{36}\b",
    "PyPI Token": r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b",
    "Docker Hub PAT": r"\bdckr_pat_[A-Za-z0-9_-]{27,}\b",
    "CircleCI Token (keyword)": r"(?i)circle.{0,20}token.{0,10}['\"=:\s]([a-f0-9]{40})",
    "Travis CI Token (keyword)": r"(?i)travis.{0,20}token.{0,10}['\"=:\s]([A-Za-z0-9_-]{22})",
    "Postman API Key": r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b",
    "JFrog Artifactory Key": r"\bAKC[a-zA-Z0-9]{10,}\b",
    "Sonar Token": r"\b(squ|sqp|sqa)_[a-f0-9]{40}\b",

    # ---------------- Messaging / Social / Webhooks ----------------
    "Slack Token": r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
    "Discord Bot Token": r"\b[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b",
    "Discord Webhook": r"https://(ptb\.|canary\.)?discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
    "Telegram Bot Token": r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b",
    "Facebook/Meta Access Token": r"\bEAA[A-Za-z0-9]{90,}\b",
    "Facebook App Secret (keyword)": r"(?i)(facebook|fb|meta).{0,20}(app)?[_-]?secret.{0,10}['\"=:\s]([a-f0-9]{32})",
    "WhatsApp Cloud API Token (keyword)": r"(?i)whatsapp.{0,30}(EAA[A-Za-z0-9]{90,})",
    "Instagram Graph Token": r"\bIG[A-Za-z0-9]{100,}\b",
    "Twitter/X Bearer Token": r"\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}\b",
    "Twitter/X API Secret (keyword)": r"(?i)(twitter|x_api).{0,20}secret.{0,10}['\"=:\s]([A-Za-z0-9]{45,50})",
    "LinkedIn Client Secret (keyword)": r"(?i)linkedin.{0,20}secret.{0,10}['\"=:\s]([A-Za-z0-9]{16})",
    "Microsoft Teams Webhook": r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[^\s'\"]+",
    "Zoom JWT/Secret (keyword)": r"(?i)zoom.{0,20}(secret|jwt).{0,10}['\"=:\s]([A-Za-z0-9]{32,})",

    # ---------------- Email / SMS ----------------
    "SendGrid API Key": r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
    "Mailgun API Key": r"\bkey-[0-9a-zA-Z]{32}\b",
    "Mailchimp API Key": r"\b[0-9a-f]{32}-us\d{1,2}\b",
    "Mailjet/Brevo Key": r"\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b",
    "Postmark Token (keyword)": r"(?i)postmark.{0,20}['\"=:\s](" + UUID + r")",
    "Resend API Key": r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}\b",
    "Twilio Account SID": r"\bAC[a-f0-9]{32}\b",
    "Twilio API Key SID": r"\bSK[a-f0-9]{32}\b",
    "Twilio Auth Token (keyword)": r"(?i)twilio.{0,20}(auth|token).{0,10}['\"=:\s]([a-f0-9]{32})",
    "Vonage/Nexmo Secret (keyword)": r"(?i)(nexmo|vonage).{0,20}secret.{0,10}['\"=:\s]([A-Za-z0-9]{16})",
    "SMTP Credentials in URL": r"smtps?://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+",
    "BD SMS Gateway Key (keyword)": r"(?i)(bulksmsbd|sslwireless|greenweb|mimsms|smsq|alpha_sms).{0,30}(api_key|token|password).{0,10}['\"=:\s]([A-Za-z0-9]{12,})",

    # ---------------- Databases / Connection Strings ----------------
    "MongoDB URI with creds": r"mongodb(\+srv)?://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+",
    "PostgreSQL URI with creds": r"postgres(ql)?://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+",
    "MySQL URI with creds": r"mysql://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+",
    "Redis URI with creds": r"rediss?://[^:\s'\"]*:[^@\s'\"]+@[^\s'\"]+",
    "AMQP URI with creds": r"amqps?://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+",
    "JDBC with password": r"(?i)jdbc:[a-z]+://[^\s'\"]*password=[^\s'\"&;]+",
    "MSSQL Connection String": r"(?i)(?:Server|Data Source)=[A-Za-z0-9_.:\\\-]{2,100}(?:,\d{1,5})?;[^'\"\n(){}]{0,200}?(?:Password|Pwd)=[^;'\"\s(){},]{3,100}",
    "PlanetScale Token": r"\bpscale_(tkn|pw|oauth)_[A-Za-z0-9_.-]{32,}\b",
    "Neon DB URL": r"postgres(ql)?://[^\s'\"]+@[a-z0-9-]+\.[a-z0-9-]+\.aws\.neon\.tech",
    "Elastic/OpenSearch URL with creds": r"https?://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]*(elastic|es|opensearch)[^\s'\"]*",
    "Algolia Admin Key (keyword)": r"(?i)algolia.{0,20}(admin|api).{0,10}['\"=:\s]([a-f0-9]{32})",

    # ---------------- Monitoring / SaaS ----------------
    "Sentry DSN": r"https://[a-f0-9]{32}@[a-z0-9.-]*sentry\.io/\d+",
    "Sentry Auth Token": r"\bsntrys_[A-Za-z0-9_=]{60,}\b",
    "Datadog API Key (keyword)": r"(?i)(datadog|dd_api).{0,20}['\"=:\s]([a-f0-9]{32})",
    "New Relic Key": r"\bNRAK-[A-Z0-9]{27}\b",
    "Grafana Token": r"\b(glc_|glsa_)[A-Za-z0-9_+/=]{32,}\b",
    "Mapbox Secret Token": r"\bsk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}\b",
    "Mapbox Public Token": r"\bpk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}\b",
    "Shopify Token": r"\bshp(at|ca|pa|ss)_[a-fA-F0-9]{32}\b",
    "Notion Integration Token": r"\b(secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{46})\b",
    "Airtable PAT": r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b",
    "Linear API Key": r"\blin_api_[A-Za-z0-9]{40}\b",
    "Asana PAT": r"\b[0-9]/[0-9]{16}:[A-Za-z0-9]{32}\b",
    "Dropbox Token": r"\bsl\.[A-Za-z0-9_-]{130,}\b",
    "Pusher Secret (keyword)": r"(?i)pusher.{0,20}secret.{0,10}['\"=:\s]([a-f0-9]{20})",
    "Typeform Token": r"\btfp_[A-Za-z0-9_\-.]{59}\b",
    "Okta Token (keyword)": r"(?i)okta.{0,20}['\"=:\s](00[A-Za-z0-9_-]{40})",
    "Auth0 Client Secret (keyword)": r"(?i)auth0.{0,20}secret.{0,10}['\"=:\s]([A-Za-z0-9_-]{64})",
    "Clerk Secret Key": r"\bsk_live_[A-Za-z0-9]{40,}\b",
    "reCAPTCHA/hCaptcha Secret": r"\b0x[0-9a-fA-F]{40}\b",
    "YouTube Data API Key (keyword)": r"(?i)youtube.{0,20}(AIza[0-9A-Za-z\-_]{35})",
    "Vimeo Token (keyword)": r"(?i)vimeo.{0,20}token.{0,10}['\"=:\s]([a-f0-9]{32})",
    "WordPress Salts/Keys": r"define\(\s*['\"](AUTH|SECURE_AUTH|LOGGED_IN|NONCE)_(KEY|SALT)['\"]\s*,\s*['\"][^'\"]{20,}['\"]",
    "WordPress DB Password": r"define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"][^'\"]+['\"]",

    # ---------------- Crypto material / Generic ----------------
    "Private Key Block": r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----",
    "PuTTY Private Key": r"PuTTY-User-Key-File-\d",
    "SSH Public Key Leak (info)": r"ssh-(rsa|ed25519) AAAA[0-9A-Za-z+/]{60,}",
    "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "Basic Auth in URL": r"https?://[A-Za-z0-9._%-]+:[A-Za-z0-9._%!$&*+=-]{3,}@[A-Za-z0-9.-]+",
    "Authorization Bearer header": r"(?i)['\"]?authorization['\"]?\s*[:=]\s*['\"]bearer\s+[A-Za-z0-9._\-]{20,}['\"]",
    "Env-file Secret (KEY=value)":
        r"(?m)^\s*(?:export\s+)?[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|DSN|URI|CREDENTIALS)\s*=\s*['\"]?([^\s#'\"]{6,})",
    "Generic Secret Assignment":
        r"(?i)\b(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|passwd|password|pwd|db[_-]?pass)\b['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",
}


COMPILED = []
for _name, _pat in SECRET_PATTERNS.items():
    try:
        COMPILED.append((_name, re.compile(_pat)))
    except re.error as _e:
        print(f"[regex error] {_name}: {_e}")

UA = "LeakHunter/3.0"
MAX_BODY = 25 * 1024 * 1024
TEXT_TYPES = ("html", "javascript", "ecmascript", "json", "text", "xml", "css",
              "octet-stream", "x-component")
SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp",
            ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mov", ".mp3",
            ".wav", ".m4a", ".pdf", ".zip", ".gz", ".rar", ".7z", ".exe", ".dmg", ".apk")

SEV_RANK = {"INFO": 0, "REVIEW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

CRITICAL_HINTS = ("Private Key Block", "PuTTY", "Secret Access", "URI with creds",
                  "Service Account", "Stripe Secret", "Stripe Restricted", "Bunny.net Account",
                  "Bunny.net Storage Password", "Connection String", "DB Password",
                  "Anthropic", "OpenAI", "Telegram Bot", "SMTP Credentials", "JDBC",
                  "Basic Auth in URL", "readable without login", "publicly readable",
                  "exposed (.git)", "exposed (.env)", "Azure Storage", "Vault Token")
INFO_TYPES = {"Firebase App Domain", "Firebase Realtime DB URL", "AWS S3 Bucket URL",
              "Supabase URL", "Bunny.net Pull Zone", "Bunny.net API Endpoint",
              "Bunny.net Storage Endpoint", "Bunny.net Stream Library",
              "Cloudflare R2 Endpoint", "Google OAuth Client ID",
              "Stripe Publishable Key (live)", "Mapbox Public Token",
              "SSH Public Key Leak (info)", "Sentry DSN", "Twilio Account SID"}
REVIEW_TYPES = {"Google API Key", "JWT", "Generic Secret Assignment", "High-Entropy String",
                "reCAPTCHA/hCaptcha Secret", "PII in JSON response",
                "Supabase Service/Anon Key (keyword+JWT)"}

NOTES = {
    "Google API Key": "Firebase/Google web keys are public by design. Make sure the key is "
                      "HTTP-referrer + API restricted, and that Security Rules are strict "
                      "(run with --firebase-checks).",
    "JWT": "Decode it (jwt.io offline / base64). If role=service_role or it never expires, treat as CRITICAL.",
    "High-Entropy String": "Unknown format - review manually.",
}

PLACEHOLDER_RE = re.compile(
    r"(?i)^(x+|\*+|\.+|-+|0+|password\d*|passwd|secret|token|undefined|null|none|true|false|"
    r"changeme|example.*|your[_-].*|<.*>|\{\{.*\}\}|\$\{.*\}|process\.env.*|test.*|dummy.*|"
    r"sample.*|placeholder.*|enter.*|xxx.*)$")

ENTROPY_KEYWORDS = re.compile(
    r"(?i)(key|secret|token|passw|pwd|auth|credential|bearer|signature|salt|private|apikey)")
ENTROPY_CANDIDATE = re.compile(r"['\"`]([A-Za-z0-9+/=_\-]{24,160})['\"`]")
ENTROPY_THRESHOLD = 4.2
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")

URL_RE = re.compile(
    r"""["'`(]\s*("""
    r"""(?:https?:)?//[^\s"'`<>()\\{}]{3,400}"""
    r"""|(?:/|\./|\.\./)?(?:_next/)?static/[A-Za-z0-9_\-~./%@\[\]]+?\.(?:js|mjs|json|map|css)"""
    r"""|/[A-Za-z0-9_\-~./%@]+?\.(?:js|mjs|json|map|env|txt|xml|ya?ml|config|conf|ini|bak|old|sql|log|php|ts)"""
    r""")\s*["'`)]""")
API_RE = re.compile(r"""["'`](/(?:api|v1|v2|v3|graphql|rest|wp-json)(?:/[A-Za-z0-9_\-.]{1,60}){0,6}/?)["'`]""")
BUILD_ID_RE = re.compile(r'"buildId"\s*:\s*"([A-Za-z0-9_\-]{6,64})"'
                         r'|/_next/static/([A-Za-z0-9_\-]{6,64})/_(?:buildManifest|ssgManifest)\.js')
CHUNK_MAP_RE = re.compile(r"\{(?:\s*\"?[\w\-]{1,40}\"?\s*:\s*\"[0-9a-f]{8,24}\"\s*,?){2,}\}")
CHUNK_PAIR_RE = re.compile(r"\"?([\w\-]{1,40})\"?\s*:\s*\"([0-9a-f]{8,24})\"")
FS_COLLECTION_RE = re.compile(
    r"""(?:collection|collectionGroup)\)?\(\s*(?:[^,()]{1,60},\s*)?["']([A-Za-z0-9_\-]{2,50})["']""")
FB_FIELD_RE = {k: re.compile(r"""["']?""" + k + r"""["']?\s*:\s*["']([^"']{3,200})["']""")
               for k in ("apiKey", "authDomain", "projectId", "storageBucket", "databaseURL",
                         "messagingSenderId", "appId")}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,100}\.[A-Za-z]{2,10}")
BD_PHONE_RE = re.compile(r"(?<!\d)(?:\+?88)?01[3-9]\d{8}(?!\d)")

EXTRA_SEEDS = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/manifest.json", "/site.webmanifest",
    "/sw.js", "/service-worker.js", "/firebase-messaging-sw.js", "/asset-manifest.json",
    "/__/firebase/init.json", "/__/firebase/init.js", "/.well-known/security.txt",
    "/_next/static/chunks/webpack.js", "/api", "/api/health", "/api/config",
]

SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.dev", ".env.development", ".env.development.local",
    ".env.prod", ".env.production", ".env.production.local", ".env.staging", ".env.test",
    ".env.backup", ".env.bak", ".env.old", ".env.save", ".env.example", ".env.sample",
    ".git/HEAD", ".git/config", ".git/logs/HEAD", ".git/index", ".git/FETCH_HEAD",
    ".gitlab-ci.yml", ".github/workflows/main.yml", ".github/workflows/deploy.yml",
    ".svn/entries", ".svn/wc.db", ".hg/hgrc", ".DS_Store", ".npmrc", ".yarnrc", ".pypirc",
    ".dockercfg", ".docker/config.json", ".aws/credentials", ".aws/config", ".ssh/id_rsa",
    ".ssh/id_ed25519", ".bash_history", ".zsh_history", ".htpasswd", ".htaccess",
    ".vscode/settings.json", ".idea/workspace.xml", ".vercel/project.json", ".firebaserc",
    "firebase.json", "firestore.rules", "storage.rules", "database.rules.json",
    "web.config", "config.json", "config.js", "config.yml", "config.yaml", "settings.json",
    "appsettings.json", "appsettings.Development.json", "secrets.json", "secrets.yml",
    "credentials.json", "service-account.json", "serviceAccountKey.json",
    "google-services.json", "GoogleService-Info.plist", "docker-compose.yml",
    "docker-compose.prod.yml", "Dockerfile", "package.json", "package-lock.json",
    "next.config.js", "next.config.mjs", "nuxt.config.js", "vite.config.js",
    "composer.json", "composer.lock", "wp-config.php.bak", "wp-config.php~",
    "wp-config.php.save", "wp-config.old", "config.php.bak", "database.yml",
    "backup.zip", "backup.tar.gz", "site.zip", "www.zip", "public.zip", "build.zip",
    "backup.sql", "db.sql", "dump.sql", "database.sql", "data.sql", "users.sql",
    "error.log", "debug.log", "access.log", "npm-debug.log", "storage/logs/laravel.log",
    "phpinfo.php", "info.php", "test.php", "server-status", "server-info",
    "actuator", "actuator/env", "actuator/heapdump", "actuator/configprops",
    "api/swagger.json", "swagger.json", "swagger-ui.html", "openapi.json", "api-docs",
    "graphql", "admin", "dashboard", "phpmyadmin/",
]
NON_HTML_PATHS = tuple(p for p in SENSITIVE_PATHS
                       if not p.endswith(("/", ".html", ".php")) and p not in
                       ("admin", "dashboard", "graphql", "api-docs", "actuator",
                        "server-status", "server-info"))

FIRESTORE_COMMON = ["users", "user", "students", "profiles", "accounts", "admins", "admin",
                    "orders", "payments", "transactions", "enrollments", "purchases",
                    "coupons", "referrals", "carts", "cart", "messages", "contacts",
                    "settings", "config", "secrets", "keys", "tokens", "logs", "notifications",
                    "courses", "blogs", "products", "categories", "reviews", "certificates",
                    "batches", "instructors", "withdrawals", "invoices"]
FIRESTORE_PUBLIC_OK = {"courses", "blogs", "products", "categories", "reviews",
                       "batches", "instructors"}
RUNTIME_DATA_HOSTS = ("firestore.googleapis.com", "firebasestorage.googleapis.com",
                      "identitytoolkit.googleapis.com", "securetoken.googleapis.com",
                      "firebaseio.com", "b-cdn.net", "bunnycdn.com", "supabase.co")


def shannon_entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def looks_random(s):
    if "__" in s or re.search(r"(?i)(module|chunk|static|webpack|function|return|class|"
                              r"http|www|component|layout|button|container|wrapper)", s):
        return False
    if re.fullmatch(r"[A-Za-z]+", s) or re.fullmatch(r"[a-z0-9\-_/.]+", s):
        return False
    classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[+/=_\-]"))
    return classes >= 3 and shannon_entropy(s) >= ENTROPY_THRESHOLD


def extract_value(m):
    groups = [g for g in m.groups() if g]
    longest = max(groups, key=len, default="")
    return longest if len(longest) >= 16 else m.group(0)


def severity_for(ftype):
    if any(h in ftype for h in CRITICAL_HINTS):
        return "CRITICAL"
    if ftype in INFO_TYPES or ftype.startswith("Sensitive Path (INFO)"):
        return "INFO"
    if ftype in REVIEW_TYPES:
        return "REVIEW"
    if ftype.startswith(("Email enumeration", "API key not referrer")):
        return "MEDIUM"
    return "HIGH"


def unescape(text):
    """Undo JSON / RSC / double-JS escaping (repeated until stable)."""
    for _ in range(3):
        prev = text
        text = (text.replace("\\\\", "\\").replace('\\"', '"').replace("\\/", "/")
                .replace("\\u002F", "/").replace("\\u002f", "/").replace("\\u0026", "&")
                .replace("\\u003d", "=").replace("\\u003D", "=").replace("\\n", "\n"))
        if text == prev:
            break
    return text


class Hunter:
    def __init__(self, args):
        self.args = args
        self.start = args.url.rstrip("/")
        parsed = urlparse(self.start)
        self.root = (parsed.hostname or "").lower()
        if self.root.startswith("www."):
            self.root = self.root[4:]
        self.extra_hosts = [h.lower() for h in args.extra_hosts]
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA, "Accept": "*/*"})
        pool = requests.adapters.HTTPAdapter(pool_connections=args.threads * 2,
                                             pool_maxsize=args.threads * 2, max_retries=1)
        self.session.mount("http://", pool)
        self.session.mount("https://", pool)
        self.lock = threading.Lock()
        self.seen, self.queued = set(), set()
        self.frontier = deque()
        self.findings = {}
        self.html_pages = []
        self.live_hosts = set()
        self.build_ids = set()
        self.fb_projects = {}
        self.fs_collections = set()
        self.stats = {"fetched": 0, "scanned_bytes": 0, "wayback_files": 0, "rendered": 0}

    # ------------------------------------------------------------------ helpers
    def mask(self, v):
        if self.args.show_full or len(v) <= 12:
            return v
        return v[:6] + "..." + v[-4:]

    def in_scope(self, url):
        host = (urlparse(url).hostname or "").lower()
        return any(host == h or host.endswith("." + h) for h in [self.root] + self.extra_hosts)

    def normalize(self, url, base):
        url = url.strip().strip("\\").replace("\\/", "/")
        if not url or url.startswith(("data:", "mailto:", "tel:", "javascript:", "blob:", "#")):
            return None
        if url.startswith(("static/", "./static/")):
            url = "/_next/" + url.lstrip("./")
        try:
            full = urldefrag(urljoin(base, url))[0]
        except ValueError:
            return None
        if not full.startswith("http"):
            return None
        if urlparse(full).path.lower().endswith(SKIP_EXT):
            return None
        return full

    def enqueue(self, url, base=None):
        full = self.normalize(url, base or self.start + "/")
        if not full or not self.in_scope(full):
            return
        with self.lock:
            if full in self.queued:
                return
            if len(self.queued) >= self.args.max_resources:
                return
            self.queued.add(full)
            self.frontier.append(full)

    def fetch(self, url, allow_redirects=True, timeout=None):
        try:
            r = self.session.get(url, timeout=timeout or self.args.timeout,
                                 allow_redirects=allow_redirects, stream=True)
            body = r.raw.read(MAX_BODY, decode_content=True)
            r.close()
            return r.status_code, r.headers, body.decode("utf-8", errors="replace"), r.url
        except Exception:
            return None

    # ------------------------------------------------------------------ findings
    def add(self, ftype, value, source, text=None, pos=None):
        value = value.strip()
        if not value:
            return
        sev = severity_for(ftype)
        context = ""
        if text is not None and pos is not None:
            snippet = text[max(0, pos - 70): pos + len(value) + 70].replace("\n", " ")
            context = snippet.replace(value, self.mask(value))
        with self.lock:
            f = self.findings.get(value)
            new_value = f is None
            if new_value:
                f = self.findings[value] = {"value": value, "types": [], "severity": sev,
                                            "sources": [], "context": context}
            new_type = ftype not in f["types"]
            if new_type:
                f["types"].append(ftype)
            if SEV_RANK[sev] > SEV_RANK[f["severity"]]:
                f["severity"] = sev
            if source not in f["sources"]:
                f["sources"].append(source)
        if new_value or new_type:
            tag = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]",
                   "REVIEW": "[?]", "INFO": "[i]"}[sev]
            print(f"\n{tag} {sev:<8} {ftype} | {self.mask(value)} | {source}")

    def is_noise(self, ftype, value):
        if ftype == "Generic Secret Assignment":
            if PLACEHOLDER_RE.match(value) or re.fullmatch(r"[a-z\-_.]+", value):
                return True
        if ftype in ("Telegram Bot Token", "Discord Bot Token") and value.count(".") > 3:
            return True
        return False

    def scan(self, text, source, allow_entropy=True, depth=0):
        if not text:
            return
        self.stats["scanned_bytes"] += len(text)
        variants = [text]
        if any(e in text for e in ('\\"', "\\/", "\\u002F", "\\u002f")):
            variants.append(unescape(text))
        for t in variants:
            for name, rx in COMPILED:
                for m in rx.finditer(t):
                    v = extract_value(m)
                    if v and not self.is_noise(name, v):
                        self.add(name, v, source, t, m.start())
            if allow_entropy:
                for line in t.splitlines():
                    if len(line) > 20000 or not ENTROPY_KEYWORDS.search(line):
                        continue
                    for m in ENTROPY_CANDIDATE.finditer(line):
                        cand = m.group(1)
                        if cand in self.findings or not looks_random(cand):
                            continue
                        self.add("High-Entropy String", cand, source, line, m.start(1))
        if depth == 0:
            for i, m in enumerate(B64_RE.finditer(text)):
                if i > 400:
                    break
                blob = m.group(1)
                try:
                    dec = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")
                except Exception:
                    continue
                printable = sum(ch in string.printable for ch in dec) / max(len(dec), 1)
                if len(dec) >= 20 and printable > 0.95:
                    self.scan(dec, source + " [base64-decoded]", allow_entropy=False, depth=1)

    # ------------------------------------------------------------------ extraction
    def extract_links(self, text, url, is_html):
        if is_html:
            try:
                soup = BeautifulSoup(text, "html.parser")
                for tag, attr in (("a", "href"), ("script", "src"), ("link", "href"),
                                  ("iframe", "src"), ("form", "action"), ("source", "src"),
                                  ("embed", "src"), ("object", "data"), ("area", "href")):
                    for el in soup.find_all(tag):
                        if el.get(attr):
                            self.enqueue(el.get(attr), url)
                for el in soup.find_all("meta"):
                    c = el.get("content", "")
                    if c.startswith(("http", "/")):
                        self.enqueue(c, url)
            except Exception:
                pass
        for t in (text, unescape(text)) if "\\" in text else (text,):
            for m in URL_RE.finditer(t):
                self.enqueue(m.group(1), url)
            for m in API_RE.finditer(t):
                self.enqueue(m.group(1), url)

    def extract_next_artifacts(self, text, url):
        for m in BUILD_ID_RE.finditer(text):
            bid = m.group(1) or m.group(2)
            if bid and bid not in self.build_ids and not bid.startswith("chunks"):
                self.build_ids.add(bid)
                for f in ("_buildManifest.js", "_ssgManifest.js", "_middlewareManifest.js"):
                    self.enqueue(f"/_next/static/{bid}/{f}")
        if "static/chunks" in text or "chunks/" in text:
            for m in CHUNK_MAP_RE.finditer(text):
                pairs = CHUNK_PAIR_RE.findall(m.group(0))
                if len(pairs) > 800:
                    continue
                for cid, h in pairs:
                    for p in (f"/_next/static/chunks/{cid}.{h}.js",
                              f"/_next/static/chunks/{cid}-{h}.js"):
                        self.enqueue(p)

    def extract_firebase(self, text):
        for m in FB_FIELD_RE["projectId"].finditer(text):
            pid = m.group(1)
            if not re.fullmatch(r"[a-z0-9\-]{4,40}", pid):
                continue
            window = text[max(0, m.start() - 1500): m.end() + 1500]
            cfg = self.fb_projects.setdefault(pid, {"projectId": pid})
            for k, rx in FB_FIELD_RE.items():
                if k not in cfg:
                    mm = rx.search(window)
                    if mm:
                        cfg[k] = mm.group(1)
        for c in FS_COLLECTION_RE.findall(text):
            self.fs_collections.add(c)

    def check_pii(self, text, source):
        emails = set(e.lower() for e in EMAIL_RE.findall(text)
                     if not e.lower().endswith((".png", ".jpg", ".svg", ".webp")))
        phones = set(BD_PHONE_RE.findall(text))
        if len(emails) + len(phones) >= 3:
            self.add("PII in JSON response",
                     f"{len(emails)} emails / {len(phones)} phone numbers @ {source}", source)

    def process(self, url, status, headers, text, final_url):
        self.stats["fetched"] += 1
        if status < 400 and self.in_scope(final_url):
            self.live_hosts.add(urlparse(final_url).netloc.lower())
        if final_url != url and self.in_scope(final_url):
            self.enqueue(final_url)
        ctype = headers.get("Content-Type", "").lower()
        hdr_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
        self.scan(hdr_blob, url + " [headers]", allow_entropy=False)
        if status >= 400 or not text:
            return
        path = urlparse(url).path.lower()
        if ctype and not any(t in ctype for t in TEXT_TYPES) and \
                not path.endswith((".js", ".mjs", ".map", ".json", ".txt")):
            return
        is_html = "html" in ctype
        if is_html:
            self.html_pages.append(url)

        if path.endswith(".map") or ('"sourcesContent"' in text[:5000] and '"mappings"' in text):
            try:
                sm = json.loads(text)
                for i, src in enumerate(sm.get("sourcesContent") or []):
                    name = (sm.get("sources") or [])[i] if i < len(sm.get("sources") or []) else i
                    self.scan(src or "", f"{url} :: {name}")
                    self.extract_firebase(src or "")
                return
            except Exception:
                pass

        self.scan(text, url)
        self.extract_links(text, url, is_html)
        self.extract_next_artifacts(text, url)
        self.extract_firebase(text)
        if "json" in ctype:
            self.check_pii(text, url)
        if path.endswith("robots.txt"):
            for line in text.splitlines():
                m = re.match(r"(?i)\s*(?:dis)?allow\s*:\s*(\S+)|\s*sitemap\s*:\s*(\S+)", line)
                if m:
                    self.enqueue((m.group(1) or m.group(2)).replace("*", "").rstrip("$"), url)
        if "<loc>" in text:
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text):
                self.enqueue(loc, url)
        if (path.endswith((".js", ".mjs")) or "javascript" in ctype) and not self.args.no_maps:
            self.enqueue(url.split("?")[0] + ".map")

    # ------------------------------------------------------------------ phases
    def crawl(self, label="crawl"):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        print(f"\n[*] Phase: {label} (queue={len(self.frontier)})")
        with ThreadPoolExecutor(self.args.threads) as ex:
            while self.frontier:
                batch = []
                while self.frontier and len(batch) < self.args.threads * 4:
                    u = self.frontier.popleft()
                    if u not in self.seen:
                        self.seen.add(u)
                        batch.append(u)
                futs = {ex.submit(self.fetch, u): u for u in batch}
                for fut in as_completed(futs):
                    res = fut.result()
                    if res:
                        self.process(futs[fut], *res)
                sys.stdout.write(f"\r    fetched={self.stats['fetched']} queued={len(self.queued)} "
                                 f"findings={len(self.findings)}   ")
                sys.stdout.flush()
                time.sleep(self.args.delay)

    def discover_subdomains(self):
        print("\n[*] Phase: subdomain discovery (crt.sh)")
        try:
            r = self.session.get(f"https://crt.sh/?q=%25.{self.root}&output=json", timeout=90)
            names = set()
            for e in r.json():
                for n in e.get("name_value", "").split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith(self.root):
                        names.add(n)
            print(f"    {len(names)} subdomains: {', '.join(sorted(names)[:30])}")
            for n in names:
                self.enqueue(f"https://{n}/")
                for s in ("/robots.txt", "/sitemap.xml", "/__/firebase/init.json"):
                    self.enqueue(f"https://{n}{s}")
        except Exception as e:
            print(f"    crt.sh failed: {e}")

    def wayback(self):
        print("\n[*] Phase: Wayback Machine archived files")
        api = ("https://web.archive.org/cdx/search/cdx?url=" + quote(self.root) +
               "&matchType=domain&output=json&fl=original,timestamp,mimetype"
               "&filter=statuscode:200&collapse=digest&limit=100000")
        try:
            rows = self.session.get(api, timeout=120).json()[1:]
        except Exception as e:
            print(f"    CDX query failed: {e}")
            return
        interesting = re.compile(r"(?i)\.(js|mjs|json|map|env|txt|xml|ya?ml|config|conf|ini|"
                                 r"bak|old|sql|log|php|ts)(\?|$)")
        picks = [r for r in rows if interesting.search(urlparse(r[0]).path) or
                 "javascript" in r[2] or "json" in r[2]]
        picks.sort(key=lambda r: r[1], reverse=True)
        picks = picks[: self.args.wayback_limit]
        print(f"    {len(rows)} archived captures, scanning {len(picks)} distinct files")

        from concurrent.futures import ThreadPoolExecutor, as_completed

        def get(row):
            orig, ts, _ = row
            return row, self.fetch(f"https://web.archive.org/web/{ts}id_/{orig}", timeout=60)

        with ThreadPoolExecutor(min(4, self.args.threads)) as ex:
            for fut in as_completed([ex.submit(get, r) for r in picks]):
                (orig, ts, _), res = fut.result()
                if not res or res[0] >= 400:
                    continue
                self.stats["wayback_files"] += 1
                self.scan(res[2], f"wayback:{ts}:{orig}")
                self.extract_firebase(res[2])
                self.extract_links(res[2], orig, "html" in res[1].get("Content-Type", ""))
                self.enqueue(orig)  # old files are often still live on the CDN

    def render(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("\n[-] --render needs Playwright: pip3 install playwright "
                  "--break-system-packages && playwright install chromium")
            return
        pages = list(dict.fromkeys(self.html_pages))[: self.args.render_pages]
        print(f"\n[*] Phase: headless render ({len(pages)} pages)")
        captured = []

        def on_response(resp):
            try:
                ct = resp.headers.get("content-type", "").lower()
                host = (urlparse(resp.url).hostname or "").lower()
                if not (self.in_scope(resp.url) or host.endswith(RUNTIME_DATA_HOSTS)):
                    return
                if any(t in ct for t in TEXT_TYPES) or resp.url.split("?")[0].endswith(
                        (".js", ".json", ".map")):
                    captured.append((resp.url, resp.status, dict(resp.headers), resp.text()))
            except Exception:
                pass

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(user_agent=UA)
            ctx.on("response", on_response)
            page = ctx.new_page()
            for u in pages:
                try:
                    page.goto(u, wait_until="networkidle", timeout=45000)
                    for _ in range(4):
                        page.mouse.wheel(0, 4000)
                        page.wait_for_timeout(500)
                    self.scan(page.content(), u + " [rendered DOM]")
                    store = page.evaluate(
                        "() => JSON.stringify({local: {...localStorage}, session: {...sessionStorage},"
                        " cookies: document.cookie, env: (window.__ENV__ || window.ENV || "
                        "window.__NEXT_DATA__ || null)})")
                    self.scan(store, u + " [browser storage/globals]")
                    self.stats["rendered"] += 1
                except Exception as e:
                    print(f"    render failed {u}: {e}")
            browser.close()
        for url, status, headers, body in captured:
            label = url + " [runtime]"
            self.scan(body, label)
            self.extract_firebase(body)
            if "json" in headers.get("content-type", ""):
                self.check_pii(body, label)
            if self.in_scope(url):
                self.extract_links(body, url, False)
                self.enqueue(url)

    def sensitive_paths(self):
        hosts = sorted(self.live_hosts) or [urlparse(self.start).netloc]
        print(f"\n[*] Phase: sensitive path probing on {len(hosts)} host(s)")
        from concurrent.futures import ThreadPoolExecutor
        for host in hosts:
            base = f"{urlparse(self.start).scheme}://{host}"
            junk = "".join(random.choices(string.ascii_lowercase, k=12))
            b = self.fetch(f"{base}/{junk}.env", allow_redirects=False)
            base_len = len(b[2]) if b and b[0] == 200 else -1

            def probe(path):
                return path, self.fetch(f"{base}/{path}", allow_redirects=False)

            with ThreadPoolExecutor(self.args.threads) as ex:
                for path, res in ex.map(probe, SENSITIVE_PATHS):
                    if not res or res[0] != 200 or not res[2].strip():
                        continue
                    status, headers, text, _ = res
                    if base_len > 0 and abs(len(text) - base_len) < 80:
                        continue
                    ctype = headers.get("Content-Type", "").lower()
                    if path in NON_HTML_PATHS and "html" in ctype and "<html" in text[:500].lower():
                        continue  # SPA fallback page, not the real file
                    url = f"{base}/{path}"
                    if path.startswith(".git/") and ("ref: refs/" in text or "[core]" in text
                                                     or text.startswith("DIRC")):
                        self.add("Sensitive Path exposed (.git) - dump with git-dumper",
                                 url, url)
                    elif path.startswith(".env") and re.search(r"(?m)^[A-Z_]{3,}\s*=", text):
                        self.add("Sensitive Path exposed (.env)", url, url)
                    elif path in ("robots.txt", "sitemap.xml"):
                        self.add("Sensitive Path (INFO)", url, url)
                    else:
                        self.add("Sensitive Path exposed", url, url)
                    self.scan(text, url)

    def firebase_checks(self):
        if not self.fb_projects:
            print("\n[*] Firebase checks: no Firebase config found")
            return
        print(f"\n[*] Phase: Firebase read-only checks {list(self.fb_projects)}")
        for pid, cfg in self.fb_projects.items():
            key = cfg.get("apiKey", "")
            print(f"    project={pid} config={ {k: self.mask(v) for k, v in cfg.items()} }")

            dbs = {cfg.get("databaseURL"), f"https://{pid}-default-rtdb.firebaseio.com",
                   f"https://{pid}.firebaseio.com"}
            for db in filter(None, dbs):
                r = self.fetch(db.rstrip("/") + "/.json?shallow=true", timeout=20)
                if r and r[0] == 200 and r[2].strip() not in ("", "null") and \
                        "Permission denied" not in r[2]:
                    self.add("Firebase RTDB publicly readable", db, db + "/.json", r[2], 0)
                    self.scan(r[2], db + "/.json")

            buckets = {cfg.get("storageBucket"), f"{pid}.appspot.com", f"{pid}.firebasestorage.app"}
            for bucket in filter(None, buckets):
                u = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=20"
                r = self.fetch(u, timeout=20)
                if r and r[0] == 200 and ('"items"' in r[2] or '"prefixes"' in r[2]):
                    self.add("Firebase Storage bucket listable without login", bucket, u)

            cols = sorted(set(FIRESTORE_COMMON) | self.fs_collections)
            print(f"    testing {len(cols)} Firestore collections without auth "
                  f"(found in JS: {sorted(self.fs_collections)})")
            for col in cols:
                u = (f"https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/"
                     f"documents/{col}?pageSize=5" + (f"&key={key}" if key else ""))
                r = self.fetch(u, timeout=20)
                if r and r[0] == 200 and '"documents"' in r[2]:
                    if col in FIRESTORE_PUBLIC_OK:
                        self.add("Firestore public collection (expected?)", f"{pid}/{col}", u)
                    else:
                        self.add("Firestore collection readable without login",
                                 f"{pid}/{col}", u)
                    self.scan(r[2], u)
                    self.check_pii(r[2], u)

            if key:
                probe = f"leakhunter-{random.randint(10**6, 10**7)}@{self.root}"
                try:
                    r = self.session.post(
                        f"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={key}",
                        json={"identifier": probe, "continueUri": self.start}, timeout=20)
                    if r.status_code == 200:
                        self.add("API key not referrer-restricted (works without Referer)",
                                 self.mask(key), "identitytoolkit")
                        if '"registered"' in r.text:
                            self.add("Email enumeration protection is OFF", pid,
                                     "identitytoolkit accounts:createAuthUri")
                except Exception:
                    pass
                r = self.fetch("https://maps.googleapis.com/maps/api/geocode/json?"
                               f"address=Dhaka&key={key}", timeout=20)
                if r and r[0] == 200 and '"REQUEST_DENIED"' not in r[2]:
                    self.add("Google API key usable for paid Maps API (billing abuse)",
                             self.mask(key), "maps.googleapis.com")

    # ------------------------------------------------------------------ report
    def report(self):
        items = sorted(self.findings.values(), key=lambda f: (-SEV_RANK[f["severity"]],
                                                               f["types"][0]))
        out = []
        for f in items:
            note = next((NOTES[t] for t in f["types"] if t in NOTES), "")
            out.append({"severity": f["severity"], "types": f["types"],
                        "value": self.mask(f["value"]), "occurrences": len(f["sources"]),
                        "sources": f["sources"][:15], "context": f["context"][:400],
                        "note": note})
        counts = {s: sum(1 for f in out if f["severity"] == s) for s in SEV_RANK}
        prefix = self.args.output
        data = {"target": self.start, "scanned_at": datetime.now().isoformat(),
                "stats": self.stats, "resources_seen": len(self.seen),
                "severity_counts": counts, "firebase_projects": {
                    p: {k: self.mask(v) for k, v in c.items()} for p, c in self.fb_projects.items()},
                "firestore_collections_in_js": sorted(self.fs_collections),
                "build_ids": sorted(self.build_ids), "live_hosts": sorted(self.live_hosts),
                "findings": out}
        with open(prefix + ".json", "w") as fh:
            json.dump(data, fh, indent=2)
        with open(prefix + ".md", "w") as fh:
            fh.write(f"# Leak Hunter report - {self.start}\n\n")
            fh.write(f"Scanned: {data['scanned_at']}  \nResources fetched: {self.stats['fetched']}"
                     f"  \nWayback files: {self.stats['wayback_files']}  \nRendered pages: "
                     f"{self.stats['rendered']}\n\n")
            fh.write("| Severity | Count |\n|---|---|\n")
            for s in sorted(SEV_RANK, key=lambda s: -SEV_RANK[s]):
                fh.write(f"| {s} | {counts[s]} |\n")
            for f in out:
                fh.write(f"\n## [{f['severity']}] {' / '.join(f['types'])}\n\n")
                fh.write(f"- **Value:** `{f['value']}`\n- **Seen in {f['occurrences']} "
                         f"location(s):** {f['sources'][0]}\n")
                if f["context"]:
                    fh.write(f"- **Context:** `{f['context'][:250]}`\n")
                if f["note"]:
                    fh.write(f"- **Note:** {f['note']}\n")
        print("\n\n================ SUMMARY ================")
        for s in sorted(SEV_RANK, key=lambda s: -SEV_RANK[s]):
            print(f"  {s:<9} {counts[s]}")
        print(f"  resources fetched: {self.stats['fetched']}, wayback files: "
              f"{self.stats['wayback_files']}, rendered: {self.stats['rendered']}")
        print(f"[*] Reports: {prefix}.json  {prefix}.md")

    def run(self):
        a = self.args
        print(f"[*] Target {self.start} | scope *.{self.root} | {len(COMPILED)} patterns")
        self.enqueue(self.start + "/")
        for s in EXTRA_SEEDS:
            self.enqueue(s)
        if a.subdomains:
            self.discover_subdomains()
        self.crawl("live crawl")
        if a.render:
            self.render()
            self.crawl("crawl after render")
        if a.wayback:
            self.wayback()
            self.crawl("re-check archived URLs on live site")
        self.sensitive_paths()
        if a.firebase_checks:
            self.firebase_checks()
        self.report()


def main():
    ap = argparse.ArgumentParser(description="Deep secret/data-leak hunter for your own domain")
    ap.add_argument("url")
    ap.add_argument("--all", action="store_true",
                    help="enable --render --wayback --subdomains --firebase-checks")
    ap.add_argument("--render", action="store_true", help="headless Chromium runtime capture")
    ap.add_argument("--render-pages", type=int, default=60)
    ap.add_argument("--wayback", action="store_true", help="scan archived files")
    ap.add_argument("--wayback-limit", type=int, default=500)
    ap.add_argument("--subdomains", action="store_true", help="crt.sh subdomain discovery")
    ap.add_argument("--firebase-checks", action="store_true", help="read-only Firebase checks")
    ap.add_argument("--extra-hosts", nargs="*", default=[],
                    help="extra in-scope hosts, e.g. example.b-cdn.net")
    ap.add_argument("--max-resources", type=int, default=5000)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--delay", type=float, default=0.2, help="pause between batches")
    ap.add_argument("--no-maps", action="store_true", help="skip .map probing")
    ap.add_argument("--show-full", action="store_true", help="print unmasked secrets")
    ap.add_argument("-o", "--output", default="leak_hunter_report")
    a = ap.parse_args()
    if a.all:
        a.render = a.wayback = a.subdomains = a.firebase_checks = True
    try:
        Hunter(a).run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")


if __name__ == "__main__":
    main()
