// Cyber Shield Live Protection background service worker
const DEFAULT_API_URL = 'http://localhost:3000';
const scanCache = {}; // Cache: URL string -> AnalysisResult
const bypassList = new Set(); // Bypassed hostnames

console.log("CYBER SHIELD: Background service worker active.");

function getHostname(urlStr) {
  try {
    const url = new URL(urlStr);
    return url.hostname;
  } catch (e) {
    return null;
  }
}

function updateBadge(tabId, score, classification) {
  let badgeText = 'SAFE';
  let badgeColor = '#39FF14'; // Neon Green

  if (score > 70 || classification === 'Phishing' || classification === 'Malicious') {
    badgeText = 'RISK';
    badgeColor = '#ff3131'; // Neon Red
  } else if (score > 30 || classification === 'Suspicious') {
    badgeText = 'WARN';
    badgeColor = '#ffb100'; // Amber Warning
  }

  chrome.action.setBadgeText({ tabId, text: badgeText });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
}

async function scanUrl(urlStr, tabId) {
  if (!urlStr || urlStr.startsWith('chrome') || urlStr.startsWith('about') || urlStr.startsWith('file') || urlStr.includes('block.html')) {
    return;
  }

  const hostname = getHostname(urlStr);
  if (!hostname || bypassList.has(hostname)) {
    updateBadge(tabId, 0, 'Safe');
    return;
  }

  // Check cache
  if (scanCache[urlStr]) {
    const cached = scanCache[urlStr];
    handleScanResult(urlStr, cached, tabId);
    return;
  }

  // Get API URL
  chrome.storage.local.get(['apiUrl'], async (res) => {
    const apiUrl = res.apiUrl || DEFAULT_API_URL;
    try {
      const response = await fetch(`${apiUrl.replace(/\/$/, '')}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlStr })
      });
      
      if (!response.ok) throw new Error('API handshake failed');
      const data = await response.json();
      
      // Cache response
      scanCache[urlStr] = data;
      handleScanResult(urlStr, data, tabId);
    } catch (err) {
      console.error('Scan error:', err);
    }
  });
}

function handleScanResult(urlStr, data, tabId) {
  const score = data.threatScore || 0;
  const classification = data.classification || 'Safe';
  
  updateBadge(tabId, score, classification);

  if (score > 70 || classification === 'Phishing' || classification === 'Malicious') {
    const hostname = getHostname(urlStr);
    if (hostname && !bypassList.has(hostname)) {
      // Redirect tab to warning block page
      const blockUrl = chrome.runtime.getURL(`block.html?url=${encodeURIComponent(urlStr)}&score=${score}&class=${encodeURIComponent(classification)}&brand=${encodeURIComponent(data.brandImpersonated || 'None')}`);
      chrome.tabs.update(tabId, { url: blockUrl });

      // Native browser notification
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon.png',
        title: 'Cyber Shield Blocked Threat',
        message: `Dangerous page intercepted: ${hostname}. Threat Index: ${score}%`,
        priority: 2
      });
    }
  }
}

// Navigation event hooks
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) { // Only main frame navigation
    scanUrl(details.url, details.tabId);
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    scanUrl(changeInfo.url, tabId);
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab && tab.url) {
      const cached = scanCache[tab.url];
      if (cached) {
        updateBadge(activeInfo.tabId, cached.threatScore, cached.classification);
      } else {
        scanUrl(tab.url, activeInfo.tabId);
      }
    }
  });
});

// Runtime messages receiver
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'bypass') {
    const hostname = getHostname(message.url);
    if (hostname) {
      bypassList.add(hostname);
    }
    sendResponse({ status: 'ok' });
  } else if (message.action === 'getCache') {
    sendResponse({ cache: scanCache });
  } else if (message.action === 'scanCurrent') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs[0] && tabs[0].url) {
        await scanUrl(tabs[0].url, tabs[0].id);
        const cached = scanCache[tabs[0].url] || { threatScore: 0, classification: 'Safe', explanation: 'No report' };
        sendResponse({ data: cached });
      } else {
        sendResponse({ error: 'No active tab found' });
      }
    });
    return true; // Keep response channel open async
  }
});
