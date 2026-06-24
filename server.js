const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Path to database
const dbPath = path.join(__dirname, 'db.json');

// Helper to read database
function readDB() {
  try {
    const data = fs.readFileSync(dbPath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error("Error reading db.json, returning empty template", error);
    return { indicators: [], feeds: [], submissions: [] };
  }
}

// Helper to write database
function writeDB(data) {
  try {
    fs.writeFileSync(dbPath, JSON.stringify(data, null, 2), 'utf8');
  } catch (error) {
    console.error("Error writing to db.json", error);
  }
}

// Seed additional mock feeds periodically in-memory to simulate dynamic Threat Intel aggregation
let dynamicFeeds = [];
const feedSources = ["Public Phishing Feed", "Open Threat Intel", "CERT-In Advisory", "Scam Reports", "PhishTank Feed"];
const threatCategories = ["Phishing Campaign", "KYC Scam", "Credential Harvesting", "UPI Fraud", "Ransomware Delivery", "Spyware CNC", "Fake Lottery Portal"];
const tlds = [".net", ".com", ".info", ".xyz", ".top", ".cc"];
const upiHandles = ["@ybl", "@oksbi", "@paytm", "@ibl", "@okaxis", "@upi"];

setInterval(() => {
  const db = readDB();
  const typeRand = Math.random();
  let type = "domain";
  let value = "";
  let category = threatCategories[Math.floor(Math.random() * threatCategories.length)];
  let source = feedSources[Math.floor(Math.random() * feedSources.length)];

  if (typeRand < 0.3) {
    type = "domain";
    const name = "secure-login-" + Math.random().toString(36).substring(2, 8);
    const tld = tlds[Math.floor(Math.random() * tlds.length)];
    value = `${name}${tld}`;
  } else if (typeRand < 0.6) {
    type = "ip";
    value = `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  } else if (typeRand < 0.8) {
    type = "url";
    const domain = "verify-account-" + Math.random().toString(36).substring(2, 7) + ".info";
    value = `http://${domain}/update/login.php?ref=security`;
  } else {
    type = "upi";
    const user = "refund-agent-" + Math.floor(1000 + Math.random() * 9000);
    const handle = upiHandles[Math.floor(Math.random() * upiHandles.length)];
    value = `${user}${handle}`;
  }

  const newFeedItem = {
    id: `dynamic_feed_${Date.now()}`,
    source: source,
    type: type,
    value: value,
    category: category,
    timestamp: new Date().toISOString()
  };

  dynamicFeeds.unshift(newFeedItem);
  if (dynamicFeeds.length > 50) {
    dynamicFeeds.pop();
  }
}, 30000); // Add a new threat indicator to feeds list every 30 seconds

// Heuristic Threat Intelligence Engine logic
function classifyInput(query) {
  query = query.trim().toLowerCase();
  
  // IP Pattern
  const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  if (ipRegex.test(query)) {
    const parts = query.match(ipRegex);
    const isValidIp = parts.slice(1).every(part => parseInt(part) <= 255);
    if (isValidIp) return "ip";
  }

  // UPI Pattern
  const upiRegex = /^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$/;
  if (upiRegex.test(query)) return "upi";

  // URL Pattern (contains scheme or matches web address structure with path)
  if (query.startsWith("http://") || query.startsWith("https://") || (query.includes("/") && query.indexOf("/") < query.indexOf("@") === false)) {
    return "url";
  }

  // Default to domain
  return "domain";
}

function analyzeQuery(type, query) {
  query = query.trim().toLowerCase();
  const db = readDB();

  // 1. Check exact matches in Database Indicators & User Submissions
  const allIndicators = [...db.indicators, ...db.submissions.map(sub => ({
    type: sub.type,
    value: sub.value,
    riskscore: sub.riskscore || 80,
    category: sub.category,
    status: "Malicious",
    details: {
      domainage: "1 day",
      registrar: "Unknown (User Submitted)",
      hostingprovider: "Reported Hosting",
      ssl: "Not Analyzed",
      ipAddress: "Unknown",
      incidents: 1,
      reportedAt: sub.submittedAt
    }
  }))];

  const match = allIndicators.find(ind => ind.type === type && ind.value.toLowerCase() === query);
  if (match) {
    return { ...match, source: "Aggregated Local Threat Database" };
  }

  // 2. Safeguard for known benign targets
  const safeDomains = ["google.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com", "wikipedia.org", "yahoo.com"];
  const safeIps = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "127.0.0.1"];
  const safeUpis = ["paytm@paytm", "phonepe@ybl", "gpay@okaxis"];

  if (
    (type === "domain" && safeDomains.includes(query)) ||
    (type === "ip" && safeIps.includes(query)) ||
    (type === "upi" && safeUpis.includes(query)) ||
    (type === "url" && safeDomains.some(d => query.includes(d)))
  ) {
    return {
      type,
      value: query,
      riskscore: 2,
      category: "Safe / Verified",
      status: "Safe",
      details: type === "domain" ? {
        domainage: "Over 20 years",
        registrar: "MarkMonitor Inc.",
        hostingprovider: "Google LLC / Multihomed",
        ssl: "Verified SSL (DigiCert Inc)",
        ipAddress: "142.250.190.46",
        incidents: 0,
        reportedAt: null
      } : type === "ip" ? {
        hostingprovider: "Cloudflare / Google Public DNS",
        country: "United States",
        asn: "AS15169",
        openports: [53, 443],
        incidents: 0,
        reportedAt: null
      } : type === "url" ? {
        domainage: "Over 15 years",
        hostingprovider: "Global CDN",
        ssl: "TLS 1.3 Secure Certificate",
        redirections: 0,
        incidents: 0,
        reportedAt: null
      } : {
        verifiedName: "Official Payment Service",
        associatedBank: "Partner Bank",
        incidents: 0,
        scamPattern: "None detected",
        reportedAt: null
      }
    };
  }

  // 3. Heuristic Engine calculation for new/unknown queries
  let riskscore = 15; // baseline risk score
  let category = "Suspicious Activity";
  let status = "Clean";
  let details = {};

  const scamKeywords = ["verify", "bank", "login", "secure", "kyc", "refund", "support", "covid", "update", "prize", "gift", "bonus", "reward", "lottery", "cashback", "paytm", "crypto", "wallet", "block", "suspend", "free", "giftcard"];
  const matchesKeyword = scamKeywords.some(kw => query.includes(kw));

  if (type === "domain") {
    const isSuspiciousTLD = query.endsWith(".xyz") || query.endsWith(".top") || query.endsWith(".cc") || query.endsWith(".info");
    if (matchesKeyword) riskscore += 55;
    if (isSuspiciousTLD) riskscore += 20;
    if (query.length > 25) riskscore += 10; // unreasonably long domain names

    riskscore = Math.min(riskscore, 98);
    status = riskscore > 75 ? "Malicious" : riskscore > 40 ? "Suspicious" : "Clean";
    category = riskscore > 70 ? "Credential Phishing" : "Uncategorized Domain";

    details = {
      domainage: riskscore > 50 ? `${Math.floor(Math.random() * 20) + 1} days` : "3 years",
      registrar: riskscore > 60 ? "NameSilo LLC" : "GoDaddy LLC",
      hostingprovider: riskscore > 70 ? "Kevser Host (Netherlands)" : "Amazon Web Services",
      ssl: riskscore > 80 ? "None (Self-Signed)" : "Sectigo Limited (Expires in 12 days)",
      ipAddress: `192.${Math.floor(Math.random() * 150) + 50}.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 254)}`,
      incidents: riskscore > 50 ? Math.floor(Math.random() * 15) + 3 : 0,
      reportedAt: riskscore > 50 ? new Date(Date.now() - 1000 * 60 * 60 * 24 * 3).toISOString() : null
    };
  } else if (type === "ip") {
    const suspiciousAsns = ["AS32456", "AS41235", "AS63949", "AS9921"];
    const suspiciousCountries = ["Russia", "China", "North Korea", "Nigeria", "Seychelles"];

    const country = suspiciousCountries[Math.floor(Math.random() * suspiciousCountries.length)];
    const hosting = "Offshore Hosting Services";

    if (matchesKeyword) riskscore += 30; // unlikely for IP directly, but check query anyway
    riskscore += Math.floor(Math.random() * 30) + 30; // Unknown IPs have average baseline risk

    riskscore = Math.min(riskscore, 95);
    status = riskscore > 70 ? "Malicious" : riskscore > 40 ? "Suspicious" : "Clean";
    category = riskscore > 70 ? "Spam Botnet Source" : "Scanning / Probe Activity";

    details = {
      hostingprovider: hosting,
      country: country,
      asn: suspiciousAsns[Math.floor(Math.random() * suspiciousAsns.length)],
      openports: [80, 443, 22, 23, 8080],
      incidents: Math.floor(Math.random() * 10) + 1,
      reportedAt: new Date().toISOString()
    };
  } else if (type === "url") {
    const isHttp = query.startsWith("http://");
    if (isHttp) riskscore += 25;
    if (matchesKeyword) riskscore += 50;
    if (query.includes(".xyz/") || query.includes(".info/") || query.includes(".top/")) riskscore += 20;

    riskscore = Math.min(riskscore, 99);
    status = riskscore > 75 ? "Malicious" : riskscore > 45 ? "Suspicious" : "Clean";
    category = riskscore > 70 ? "Social Engineering / KYC Fraud" : "Unverified Redirect Portal";

    details = {
      domainage: riskscore > 50 ? "8 days" : "4 years",
      hostingprovider: "Hostinger International Ltd.",
      ssl: isHttp ? "None (Insecure HTTP Protocol)" : "Let's Encrypt Wildcard TLS",
      redirections: riskscore > 60 ? Math.floor(Math.random() * 3) + 1 : 0,
      incidents: riskscore > 50 ? Math.floor(Math.random() * 22) + 5 : 0,
      reportedAt: new Date().toISOString()
    };
  } else if (type === "upi") {
    // UPI logic
    const suspHandles = ["@ybl", "@oksbi", "@paytm", "@upi"];
    const hasSuspHandle = suspHandles.some(h => query.endsWith(h));
    
    if (matchesKeyword) riskscore += 60;
    if (hasSuspHandle) riskscore += 15;

    riskscore = Math.min(riskscore, 97);
    status = riskscore > 70 ? "Malicious" : riskscore > 40 ? "Suspicious" : "Clean";
    category = riskscore > 70 ? "Impersonation UPI Fraud" : "Unverified Account";

    const parts = query.split('@');
    const nameSeed = parts[0].replace(/[-._]/g, ' ');
    const formattedName = nameSeed.charAt(0).toUpperCase() + nameSeed.slice(1);

    details = {
      verifiedName: riskscore > 60 ? `${formattedName} (Unverified Profile / Reported)` : `${formattedName} (Verified Merchant)`,
      associatedBank: query.endsWith("oksbi") ? "State Bank of India" : query.endsWith("ybl") ? "YES Bank" : query.endsWith("paytm") ? "Paytm Payments Bank" : "HDFC Bank",
      incidents: riskscore > 50 ? Math.floor(Math.random() * 45) + 12 : 0,
      scamPattern: riskscore > 60 ? "Request money spam / fraudulent QR redirect" : "Standard transaction address",
      reportedAt: riskscore > 50 ? new Date().toISOString() : null
    };
  }

  return {
    type,
    value: query,
    riskscore,
    category,
    status,
    details,
    source: "Threat Heuristic Analysis Engine"
  };
}

// REST API Endpoints

// 1. Get Live Feeds (returns static seed feeds + any newly generated feeds)
app.get('/api/feed', (req, res) => {
  const db = readDB();
  const allFeeds = [...dynamicFeeds, ...db.feeds];
  res.json(allFeeds.slice(0, 30));
});

// 2. Get Threat Analytics & Stats
app.get('/api/stats', (req, res) => {
  const db = readDB();
  
  // Consolidate static indicators + dynamic feeds + submissions
  const allIndicators = [...db.indicators, ...db.submissions.map(s => ({
    type: s.type,
    riskscore: s.riskscore || 80,
    category: s.category
  }))];

  // Count by Type
  const typeCounts = { domain: 0, ip: 0, url: 0, upi: 0 };
  allIndicators.forEach(ind => {
    if (typeCounts[ind.type] !== undefined) typeCounts[ind.type]++;
  });

  // Count by Severity
  let maliciousCount = 0;
  let suspiciousCount = 0;
  let safeCount = 0;

  allIndicators.forEach(ind => {
    if (ind.riskscore > 70) maliciousCount++;
    else if (ind.riskscore > 35) suspiciousCount++;
    else safeCount++;
  });

  // Categories distribution
  const categories = {};
  allIndicators.forEach(ind => {
    const cat = ind.category || "General Threat";
    categories[cat] = (categories[cat] || 0) + 1;
  });

  res.json({
    totalThreats: allIndicators.length,
    activeFeeds: 5,
    metrics: {
      typeCounts,
      severity: {
        malicious: maliciousCount,
        suspicious: suspiciousCount,
        safe: safeCount
      },
      categories
    }
  });
});

// 3. Threat Lookup Endpoint
app.post('/api/check', (req, res) => {
  const { query } = req.body;
  let { type } = req.body;

  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: "Invalid query parameter" });
  }

  const trimmedQuery = query.trim();
  if (trimmedQuery.length === 0) {
    return res.status(400).json({ error: "Query cannot be empty" });
  }

  // Auto detect type if not specified
  if (!type || type === 'auto') {
    type = classifyInput(trimmedQuery);
  }

  const analysisResult = analyzeQuery(type, trimmedQuery);
  res.json(analysisResult);
});

// 4. Submit IOC Indicator Endpoint
app.post('/api/submit', (req, res) => {
  const { type, value, category, comments } = req.body;

  if (!type || !value || !category) {
    return res.status(400).json({ error: "Fields type, value, and category are required" });
  }

  const db = readDB();

  // Simple validation
  const existingSub = db.submissions.find(s => s.type === type && s.value.toLowerCase() === value.trim().toLowerCase());
  if (existingSub) {
    return res.json({ message: "Indicator already reported and pending audit.", duplicate: true });
  }

  // Calculate a placeholder riskscore based on user input
  const riskscore = type === "upi" ? 85 : 80;

  const newSubmission = {
    id: `sub_${Date.now()}`,
    type,
    value: value.trim(),
    category,
    comments: comments || "",
    riskscore,
    submittedAt: new Date().toISOString()
  };

  db.submissions.unshift(newSubmission);
  writeDB(db);

  // Add a feed entry as well so it pops up in the feeds list
  db.feeds.unshift({
    id: `feed_sub_${Date.now()}`,
    source: "User Submission Portal",
    type: type,
    value: value.trim(),
    category: category,
    timestamp: new Date().toISOString()
  });
  writeDB(db);

  res.status(201).json({
    message: "Thank you. Indicator submitted successfully to IOC Aggregation database.",
    submission: newSubmission
  });
});

app.listen(PORT, () => {
  console.log(`IOC Aggregator backend server running at http://localhost:${PORT}`);
});
