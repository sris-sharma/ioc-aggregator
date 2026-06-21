// Endpoint Configuration
const API_BASE = window.location.origin.includes("3000") || window.location.origin.includes("localhost")
  ? window.location.origin
  : "http://localhost:3000";
let apiModeActive = false;

// Seed data copy for client-side local fallback engine
const SEED_DATABASE = {
  indicators: [
    { id: "ind_001", type: "domain", value: "example-bank-verify.com", riskscore: 92, category: "KYC Scam", status: "Malicious", details: { domainage: "10 days", registrar: "NameCheap Inc.", hostingprovider: "Hostinger International Ltd.", ssl: "Let's Encrypt (Expires in 80 days)", ipAddress: "185.224.138.42", incidents: 14, reportedAt: "2026-06-10T08:32:00Z" } },
    { id: "ind_002", type: "domain", value: "secure-login-netpoint.net", riskscore: 85, category: "Phishing", status: "Malicious", details: { domainage: "4 days", registrar: "GoDaddy LLC", hostingprovider: "DigitalOcean LLC", ssl: "None (HTTP only)", ipAddress: "104.24.12.89", incidents: 8, reportedAt: "2026-06-12T14:15:00Z" } },
    { id: "ind_003", type: "ip", value: "198.51.100.72", riskscore: 89, category: "Malware Distribution", status: "Malicious", details: { hostingprovider: "Sharktech Hosting", country: "Russia", asn: "AS32456", openports: [80, 443, 8080], incidents: 23, reportedAt: "2026-06-14T21:40:00Z" } },
    { id: "ind_004", type: "ip", value: "203.0.113.195", riskscore: 75, category: "Botnet CNC", status: "Suspicious", details: { hostingprovider: "Linode LLC", country: "Seychelles", asn: "AS63949", openports: [22, 80, 443], incidents: 5, reportedAt: "2026-06-15T02:10:00Z" } },
    { id: "ind_005", type: "url", value: "http://refund-tax-support.in/login/pay.html", riskscore: 98, category: "Tax Refund Scam", status: "Malicious", details: { domainage: "2 days", hostingprovider: "Verio Hosting", ssl: "None (Insecure HTTP)", redirections: 2, incidents: 32, reportedAt: "2026-06-15T09:05:00Z" } },
    { id: "ind_006", type: "upi", value: "fastcash-refund@ybl", riskscore: 95, category: "UPI Fraud", status: "Malicious", details: { verifiedName: "Ramesh Kumar (Unverified Profile)", associatedBank: "YES Bank", incidents: 47, scamPattern: "Lottery prize processing fee request", reportedAt: "2026-06-15T11:12:00Z" } },
    { id: "ind_007", type: "upi", value: "govt-subsidy-online@oksbi", riskscore: 90, category: "Impersonation", status: "Malicious", details: { verifiedName: "State Benefit Portal (Impersonated)", associatedBank: "State Bank of India", incidents: 19, scamPattern: "Gas subsidy registration fee", reportedAt: "2026-06-14T17:45:00Z" } }
  ],
  feeds: [
    { id: "feed_001", source: "CERT-In Advisory", type: "domain", value: "covid-booster-support.org", category: "Phishing Campaign", timestamp: "2026-06-15T16:45:00Z" },
    { id: "feed_002", source: "Public Phishing Feed", type: "url", value: "https://verification-update-portal.net/signin", category: "Credential Harvesting", timestamp: "2026-06-15T16:32:00Z" },
    { id: "feed_003", source: "Open Threat Intel", type: "ip", value: "185.190.140.11", category: "SSH Brute Forcer", timestamp: "2026-06-15T16:15:00Z" },
    { id: "feed_004", source: "Scam Reports", type: "upi", value: "paytm-kyc-agent@paytm", category: "KYC Wallet Scam", timestamp: "2026-06-15T15:58:00Z" },
    { id: "feed_005", source: "CERT-In Advisory", type: "ip", value: "45.142.195.8", category: "Ransomware Distribution CNC", timestamp: "2026-06-15T15:10:00Z" }
  ]
};

// Client-Side Simulated Memory Database (Initializes with seed + localStorage items)
const LocalEngine = {
  indicators: [...SEED_DATABASE.indicators],
  feeds: [...SEED_DATABASE.feeds],
  submissions: [],
  verifiedSafeCount: 84, // static display count for demo purposes

  init() {
    // Load existing local submissions
    const localSubs = localStorage.getItem('ioc_local_submissions');
    if (localSubs) {
      try {
        this.submissions = JSON.parse(localSubs);
        // Prepend them to feeds as user reports
        this.submissions.forEach(sub => {
          this.feeds.unshift({
            id: `feed_sub_local_${sub.id}`,
            source: "User Submission Portal",
            type: sub.type,
            value: sub.value,
            category: sub.category,
            timestamp: sub.submittedAt
          });
        });
      } catch (e) {
        console.error("Failed to parse local submissions", e);
        this.submissions = [];
      }
    }
  },

  saveSubmissions() {
    localStorage.setItem('ioc_local_submissions', JSON.stringify(this.submissions));
  },

  getStats() {
    const allIndicators = [...this.indicators, ...this.submissions.map(s => ({
      type: s.type,
      riskscore: s.riskscore || 80,
      category: s.category
    }))];

    // Type counts
    const typeCounts = { domain: 0, ip: 0, url: 0, upi: 0 };
    allIndicators.forEach(ind => {
      if (typeCounts[ind.type] !== undefined) typeCounts[ind.type]++;
    });

    // Severity counts
    let malicious = 0, suspicious = 0, safe = 0;
    allIndicators.forEach(ind => {
      if (ind.riskscore > 70) malicious++;
      else if (ind.riskscore > 35) suspicious++;
      else safe++;
    });

    // Categories
    const categories = {};
    allIndicators.forEach(ind => {
      const cat = ind.category || "General Threat";
      categories[cat] = (categories[cat] || 0) + 1;
    });

    return {
      totalThreats: allIndicators.length,
      activeFeeds: 5,
      metrics: {
        typeCounts,
        severity: { malicious, suspicious, safe },
        categories
      }
    };
  },

  classifyInput(query) {
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

    // URL Pattern
    if (query.startsWith("http://") || query.startsWith("https://") || (query.includes("/") && query.indexOf("/") < query.indexOf("@") === false)) {
      return "url";
    }

    return "domain";
  },

  analyzeQuery(type, query) {
    query = query.trim().toLowerCase();

    // 1. Check exact matches in Database Indicators & Submissions
    const allIndicators = [...this.indicators, ...this.submissions.map(sub => ({
      type: sub.type,
      value: sub.value,
      riskscore: sub.riskscore || 80,
      category: sub.category,
      status: "Malicious",
      details: {
        domainage: "1 day",
        registrar: "Unknown (User Submitted)",
        hostingprovider: "Reported Hosting Server",
        ssl: "Not Analyzed",
        ipAddress: "Unknown",
        incidents: 1,
        reportedAt: sub.submittedAt
      }
    }))];

    const match = allIndicators.find(ind => ind.type === type && ind.value.toLowerCase() === query);
    if (match) {
      return { ...match, source: "Local Threat Database" };
    }

    // 2. Safeguard for known benign targets
    const safeDomains = ["google.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "wikipedia.org", "yahoo.com"];
    const safeIps = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "127.0.0.1"];
    const safeUpis = ["paytm@paytm", "phonepe@ybl", "gpay@okaxis"];

    if (
      (type === "domain" && safeDomains.includes(query)) ||
      (type === "ip" && safeIps.includes(query)) ||
      (type === "upi" && safeUpis.includes(query)) ||
      (type === "url" && safeDomains.some(d => query.includes(d)))
    ) {
      this.verifiedSafeCount++;
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
          hostingprovider: "Global CDN Network",
          ssl: "TLS 1.3 Secure Certificate",
          redirections: 0,
          incidents: 0,
          reportedAt: null
        } : {
          verifiedName: "Official Payment Handle",
          associatedBank: "Partner Bank Node",
          incidents: 0,
          scamPattern: "None detected",
          reportedAt: null
        },
        source: "Safe Whitelist Analysis"
      };
    }

    // 3. Heuristics for new/unknown queries
    let riskscore = 15;
    let category = "Suspicious Activity";
    let status = "Clean";
    let details = {};

    const scamKeywords = ["verify", "bank", "login", "secure", "kyc", "refund", "support", "covid", "update", "prize", "gift", "bonus", "reward", "lottery", "cashback", "paytm", "crypto", "wallet", "block", "suspend", "free", "giftcard"];
    const matchesKeyword = scamKeywords.some(kw => query.includes(kw));

    if (type === "domain") {
      const isSuspiciousTLD = query.endsWith(".xyz") || query.endsWith(".top") || query.endsWith(".cc") || query.endsWith(".info");
      if (matchesKeyword) riskscore += 55;
      if (isSuspiciousTLD) riskscore += 20;
      if (query.length > 25) riskscore += 10;

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

      riskscore += Math.floor(Math.random() * 30) + 30;
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
  },

  submitThreat(type, value, category, comments) {
    const existing = this.submissions.find(s => s.type === type && s.value.toLowerCase() === value.trim().toLowerCase());
    if (existing) {
      return { duplicate: true };
    }

    const newSub = {
      id: Date.now().toString(),
      type,
      value: value.trim(),
      category,
      comments: comments || "",
      riskscore: type === "upi" ? 85 : 80,
      submittedAt: new Date().toISOString()
    };

    this.submissions.unshift(newSub);
    this.saveSubmissions();

    // Add to feeds in-memory so it immediately populates on rendering
    this.feeds.unshift({
      id: `feed_sub_local_${Date.now()}`,
      source: "User Submission Portal",
      type: type,
      value: value.trim(),
      category: category,
      timestamp: new Date().toISOString()
    });

    return { success: true, submission: newSub };
  },

  generateDynamicFeedItem() {
    const feedSources = ["Public Phishing Feed", "Open Threat Intel", "CERT-In Advisory", "Scam Reports", "PhishTank Feed"];
    const threatCategories = ["Phishing Campaign", "KYC Scam", "Credential Harvesting", "UPI Fraud", "Ransomware Delivery", "Spyware CNC", "Fake Lottery Portal"];
    const tlds = [".net", ".com", ".info", ".xyz", ".top", ".cc"];
    const upiHandles = ["@ybl", "@oksbi", "@paytm", "@ibl", "@okaxis", "@upi"];

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

    const newItem = {
      id: `dynamic_feed_${Date.now()}`,
      source: source,
      type: type,
      value: value,
      category: category,
      timestamp: new Date().toISOString()
    };

    this.feeds.unshift(newItem);
    if (this.feeds.length > 30) {
      this.feeds.pop();
    }
  }
};

// UI Controllers & State management
const UI = {
  currentTab: "auto",
  categoryChart: null,
  typeChart: null,

  elements: {
    platformStatus: document.getElementById("platform-status"),
    engineMode: document.getElementById("engine-mode"),
    statTotalThreats: document.getElementById("stat-total-threats"),
    statUserSubmissions: document.getElementById("stat-user-submissions"),
    statSafeQueries: document.getElementById("stat-safe-queries"),
    
    searchForm: document.getElementById("search-form"),
    searchQuery: document.getElementById("search-query"),
    searchTabBtns: document.querySelectorAll(".tab-btn"),
    searchSamples: document.querySelectorAll(".search-sample"),
    
    resultsPanel: document.getElementById("results-panel"),
    closeResultsBtn: document.getElementById("close-results-btn"),
    resultQueryText: document.getElementById("result-query-text"),
    
    riskScoreText: document.getElementById("risk-score-text"),
    riskScoreCircle: document.getElementById("risk-score-circle"),
    threatStatus: document.getElementById("threat-status"),
    resultCategory: document.getElementById("result-category"),
    resultSource: document.getElementById("result-source"),
    
    detailsDomain: document.getElementById("details-domain"),
    detailsIp: document.getElementById("details-ip"),
    detailsUrl: document.getElementById("details-url"),
    detailsUpi: document.getElementById("details-upi"),
    
    feedList: document.getElementById("feed-list"),
    submissionForm: document.getElementById("submission-form"),
    submissionAlert: document.getElementById("submission-alert")
  },

  async init() {
    LocalEngine.init();
    this.bindEvents();
    
    // Check if Express server is running
    try {
      this.elements.platformStatus.innerText = "Connecting...";
      const res = await fetch(`${API_BASE}/api/stats`);
      if (res.ok) {
        apiModeActive = true;
        this.elements.engineMode.innerText = "REST API Mode";
        this.elements.engineMode.style.borderColor = "var(--neon-emerald)";
        this.elements.engineMode.style.color = "var(--neon-emerald)";
        this.elements.engineMode.style.background = "rgba(0, 245, 160, 0.08)";
        this.elements.platformStatus.innerText = "API Synchronized";
      } else {
        throw new Error("API responded but status not OK");
      }
    } catch (err) {
      console.log("Server API not reachable, running in offline Client Heuristic Mode.", err);
      apiModeActive = false;
      this.elements.engineMode.innerText = "Local Heuristic Engine";
      this.elements.platformStatus.innerText = "Running Locally";
    }

    // Load feeds and statistics
    this.refreshDashboard();

    // Start background live feed simulation for client side (if API is offline)
    setInterval(() => {
      if (!apiModeActive) {
        LocalEngine.generateDynamicFeedItem();
        this.updateFeedList(LocalEngine.feeds);
        this.refreshStatsView();
      } else {
        // In API mode, just poll feeds and stats
        this.refreshDashboard();
      }
    }, 15000);
  },

  bindEvents() {
    // Search tab clicks
    this.elements.searchTabBtns.forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        this.elements.searchTabBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        this.currentTab = btn.getAttribute("data-type");
        
        // Update placeholder based on selected tab
        const placeholders = {
          auto: "Enter domain (e.g. example-bank-verify.com), IP, URL, or UPI ID...",
          domain: "Enter domain name (e.g. verification-portal-scam.net)...",
          ip: "Enter IPv4 address (e.g. 198.51.100.72)...",
          url: "Enter website link (e.g. http://refund-tax-support.in/page)...",
          upi: "Enter UPI ID / Virtual Address (e.g. kyc-update@ybl)..."
        };
        this.elements.searchQuery.placeholder = placeholders[this.currentTab];
      });
    });

    // Sample query clicks
    this.elements.searchSamples.forEach(sample => {
      sample.addEventListener("click", (e) => {
        e.preventDefault();
        this.elements.searchQuery.value = sample.innerText;
        this.elements.searchForm.requestSubmit();
      });
    });

    // Unified Search Submission
    this.elements.searchForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const query = this.elements.searchQuery.value.trim();
      if (query) {
        this.performCheck(query);
      }
    });

    // Close results panel
    this.elements.closeResultsBtn.addEventListener("click", (e) => {
      e.preventDefault();
      this.elements.resultsPanel.classList.add("hidden");
    });

    // Threat Submit Form Submission
    this.elements.submissionForm.addEventListener("submit", (e) => {
      e.preventDefault();
      this.submitIndicator();
    });
  },

  async refreshDashboard() {
    let stats, feeds;

    if (apiModeActive) {
      try {
        const statsRes = await fetch(`${API_BASE}/api/stats`);
        const feedsRes = await fetch(`${API_BASE}/api/feed`);
        if (statsRes.ok && feedsRes.ok) {
          stats = await statsRes.json();
          feeds = await feedsRes.json();
        }
      } catch (err) {
        console.error("Error fetching data from API", err);
      }
    }

    // Fallback to local data if API fetch failed
    if (!stats || !feeds) {
      stats = LocalEngine.getStats();
      feeds = LocalEngine.feeds;
    }

    this.updateStatsCards(stats);
    this.updateFeedList(feeds);
    this.renderCharts(stats.metrics);
  },

  refreshStatsView() {
    const stats = LocalEngine.getStats();
    this.updateStatsCards(stats);
    this.renderCharts(stats.metrics);
  },

  updateStatsCards(stats) {
    this.elements.statTotalThreats.innerText = stats.totalThreats;
    
    if (apiModeActive) {
      this.elements.statUserSubmissions.innerText = stats.metrics.severity.malicious + stats.metrics.severity.suspicious;
      this.elements.statSafeQueries.innerText = stats.metrics.severity.safe;
    } else {
      this.elements.statUserSubmissions.innerText = LocalEngine.submissions.length + 3; // base mock + user additions
      this.elements.statSafeQueries.innerText = LocalEngine.verifiedSafeCount;
    }
  },

  updateFeedList(feeds) {
    this.elements.feedList.innerHTML = "";
    
    if (feeds.length === 0) {
      this.elements.feedList.innerHTML = `<div class="feed-loading">No threats active in feeds.</div>`;
      return;
    }

    feeds.forEach(item => {
      const timeStr = this.formatTimeAgo(item.timestamp);
      
      const feedEl = document.createElement("div");
      feedEl.className = "feed-item";
      feedEl.innerHTML = `
        <div class="feed-item-left">
          <span class="feed-badge-type type-${item.type}">${item.type}</span>
          <div class="feed-info">
            <div class="feed-val" title="${item.value}">${item.value}</div>
            <div class="feed-category">${item.category}</div>
          </div>
        </div>
        <div class="feed-item-right">
          <span class="feed-source">${item.source}</span>
          <span class="feed-time">${timeStr}</span>
        </div>
      `;
      this.elements.feedList.appendChild(feedEl);
    });
  },

  async performCheck(query) {
    let result;

    if (apiModeActive) {
      try {
        const checkRes = await fetch(`${API_BASE}/api/check`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query, type: this.currentTab })
        });
        if (checkRes.ok) {
          result = await checkRes.json();
        }
      } catch (err) {
        console.error("API Search failed", err);
      }
    }

    if (!result) {
      // client-side analysis engine fallback
      const detectedType = this.currentTab === "auto" ? LocalEngine.classifyInput(query) : this.currentTab;
      result = LocalEngine.analyzeQuery(detectedType, query);
    }

    this.renderResult(result);
    
    // Automatically refresh dashboard after checking to update safe/unsafe stats count
    this.refreshDashboard();
  },

  renderResult(res) {
    this.elements.resultsPanel.classList.remove("hidden");
    this.elements.resultQueryText.innerText = res.value;
    
    // Update score text & status badge
    this.elements.riskScoreText.innerText = res.riskscore;
    
    // Animate circular progress ring (radius is 70, circumference is 440)
    const offset = 440 - (res.riskscore / 100) * 440;
    this.elements.riskScoreCircle.style.strokeDashoffset = offset;

    // Apply color theme according to threat severity
    this.elements.threatStatus.className = "threat-status-badge";
    this.elements.threatStatus.innerText = res.status.toUpperCase();
    
    let ringColor = "var(--neon-rose)";
    if (res.status === "Safe") {
      this.elements.threatStatus.classList.add("status-clean");
      ringColor = "var(--neon-emerald)";
    } else if (res.status === "Suspicious") {
      this.elements.threatStatus.classList.add("status-suspicious");
      ringColor = "var(--neon-amber)";
    } else {
      this.elements.threatStatus.classList.add("status-malicious");
      ringColor = "var(--neon-rose)";
    }
    
    this.elements.riskScoreCircle.style.stroke = ringColor;
    this.elements.resultCategory.innerText = res.category;
    this.elements.resultSource.innerText = res.source;

    // Hide all detail subviews
    this.elements.detailsDomain.classList.add("hidden");
    this.elements.detailsIp.classList.add("hidden");
    this.elements.detailsUrl.classList.add("hidden");
    this.elements.detailsUpi.classList.add("hidden");

    // Populate type-specific panel details
    if (res.type === "domain") {
      this.elements.detailsDomain.classList.remove("hidden");
      document.getElementById("det-dom-age").innerText = res.details.domainage;
      document.getElementById("det-dom-registrar").innerText = res.details.registrar;
      document.getElementById("det-dom-hosting").innerText = res.details.hostingprovider;
      document.getElementById("det-dom-ssl").innerText = res.details.ssl;
      document.getElementById("det-dom-ip").innerText = res.details.ipAddress;
      document.getElementById("det-dom-incidents").innerText = res.details.incidents;
    } else if (res.type === "ip") {
      this.elements.detailsIp.classList.remove("hidden");
      document.getElementById("det-ip-hosting").innerText = res.details.hostingprovider;
      document.getElementById("det-ip-country").innerText = res.details.country;
      document.getElementById("det-ip-asn").innerText = res.details.asn;
      document.getElementById("det-ip-ports").innerText = res.details.openports.join(", ");
      document.getElementById("det-ip-incidents").innerText = res.details.incidents;
      document.getElementById("det-ip-reported").innerText = res.details.reportedAt ? new Date(res.details.reportedAt).toLocaleDateString() : "Never";
    } else if (res.type === "url") {
      this.elements.detailsUrl.classList.remove("hidden");
      document.getElementById("det-url-age").innerText = res.details.domainage;
      document.getElementById("det-url-hosting").innerText = res.details.hostingprovider;
      document.getElementById("det-url-ssl").innerText = res.details.ssl;
      document.getElementById("det-url-redirects").innerText = res.details.redirections;
      document.getElementById("det-url-incidents").innerText = res.details.incidents;
      document.getElementById("det-url-date").innerText = res.details.reportedAt ? new Date(res.details.reportedAt).toLocaleDateString() : "Just Now";
    } else if (res.type === "upi") {
      this.elements.detailsUpi.classList.remove("hidden");
      document.getElementById("det-upi-name").innerText = res.details.verifiedName;
      document.getElementById("det-upi-bank").innerText = res.details.associatedBank;
      document.getElementById("det-upi-incidents").innerText = res.details.incidents;
      document.getElementById("det-upi-pattern").innerText = res.details.scamPattern;
      document.getElementById("det-upi-date").innerText = res.details.reportedAt ? new Date(res.details.reportedAt).toLocaleDateString() : "Just Now";
    }

    // Scroll slightly to view results
    this.elements.resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  },

  async submitIndicator() {
    const type = document.getElementById("sub-type").value;
    const value = document.getElementById("sub-value").value.trim();
    const category = document.getElementById("sub-category").value;
    const comments = document.getElementById("sub-comments").value.trim();

    if (!type || !value || !category) return;

    let success = false;
    let duplicate = false;

    if (apiModeActive) {
      try {
        const subRes = await fetch(`${API_BASE}/api/submit`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type, value, category, comments })
        });
        if (subRes.ok) {
          const resJson = await subRes.json();
          duplicate = !!resJson.duplicate;
          success = !duplicate;
        }
      } catch (err) {
        console.error("API submit failed", err);
      }
    }

    if (!apiModeActive) {
      // client fallback submission
      const subResult = LocalEngine.submitThreat(type, value, category, comments);
      duplicate = !!subResult.duplicate;
      success = !!subResult.success;
    }

    this.elements.submissionAlert.className = "alert-box";
    this.elements.submissionAlert.classList.remove("hidden");

    if (success) {
      this.elements.submissionAlert.classList.add("alert-success");
      this.elements.submissionAlert.innerText = `Alert Broadcasted! IOC indicator [${value}] added successfully.`;
      this.elements.submissionForm.reset();
      this.refreshDashboard();
    } else if (duplicate) {
      this.elements.submissionAlert.classList.add("alert-error");
      this.elements.submissionAlert.innerText = "Error: Indicator already reported and logged in database.";
    } else {
      this.elements.submissionAlert.classList.add("alert-error");
      this.elements.submissionAlert.innerText = "An error occurred. Unable to register user submission.";
    }

    setTimeout(() => {
      this.elements.submissionAlert.classList.add("hidden");
    }, 6000);
  },

  renderCharts(metrics) {
    if (typeof Chart === 'undefined') {
      console.warn("Chart.js library is not loaded. Skipping chart rendering.");
      return;
    }
    // 1. Category Chart
    const categoriesData = metrics.categories;
    const catLabels = Object.keys(categoriesData);
    const catValues = Object.values(categoriesData);

    const doughnutCtx = document.getElementById('categoryChart').getContext('2d');

    if (this.categoryChart) {
      this.categoryChart.destroy();
    }

    this.categoryChart = new Chart(doughnutCtx, {
      type: 'doughnut',
      data: {
        labels: catLabels,
        datasets: [{
          data: catValues,
          backgroundColor: [
            '#ff0055', // Phishing
            '#00f2fe', // KYC Scam
            '#ff9f0a', // UPI Fraud
            '#0070f3', // Malware
            '#00f5a0', // Impersonation
            '#9c27b0'  // Others
          ],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#94a3b8',
              font: { size: 9, family: 'Plus Jakarta Sans' },
              boxWidth: 8
            }
          },
          title: {
            display: true,
            text: 'Categories Distribution',
            color: '#f8fafc',
            font: { size: 12, family: 'Outfit', weight: '600' }
          }
        },
        cutout: '60%'
      }
    });

    // 2. Type Distribution Chart
    const typesData = metrics.typeCounts;
    const typeLabels = Object.keys(typesData).map(k => k.toUpperCase());
    const typeValues = Object.values(typesData);

    const barCtx = document.getElementById('typeChart').getContext('2d');

    if (this.typeChart) {
      this.typeChart.destroy();
    }

    this.typeChart = new Chart(barCtx, {
      type: 'bar',
      data: {
        labels: typeLabels,
        datasets: [{
          data: typeValues,
          backgroundColor: 'rgba(0, 242, 254, 0.45)',
          borderColor: 'var(--neon-cyan)',
          borderWidth: 1.5,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          title: {
            display: true,
            text: 'Indicators by Type',
            color: '#f8fafc',
            font: { size: 12, family: 'Outfit', weight: '600' }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: '#94a3b8', font: { size: 9 } }
          },
          y: {
            grid: { color: 'rgba(255, 255, 255, 0.03)' },
            ticks: { color: '#94a3b8', font: { size: 9 }, precision: 0 }
          }
        }
      }
    });
  },

  // Helper: format ISO date/time into relative time ago
  formatTimeAgo(isoString) {
    const date = new Date(isoString);
    const seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 60) return 'just now';
    
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }
};

document.addEventListener("DOMContentLoaded", () => {
  UI.init();
});
