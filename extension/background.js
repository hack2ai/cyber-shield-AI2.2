// Cyber Shield Live Protection background service worker
const DEFAULT_API_URL = 'http://localhost:3000';
const MAX_SCAN_CACHE_ENTRIES = 250;
const MAX_BYPASS_ENTRIES = 100;
const scanCache = {}; // Cache: URL string -> AnalysisResult
const cacheOrder = [];
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
  let badgeColor = '#39FF14';

  if (score > 70 || classification === 'Phishing' || classification === 'Malicious') {
    badgeText = 'RISK';
    badgeColor = '#ff3131';
  } else if (score > 30 || classification === 'Suspicious') {
    badgeText = 'WARN';
    badgeColor = '#ffb100';
  }

  chrome.action.setBadgeText({ tabId, text: badgeText });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
}

function isTrustedExtensionSender(sender) {
  return sender.id === chrome.runtime.id && typeof sender.url === 'string' && sender.url.startsWith(`chrome-extension://${chrome.runtime.id}/`);
}

function getSenderTabUrl(sender) {
  const tabUrl = sender.tab?.url;
  return typeof tabUrl === 'string' ? tabUrl : null;
}

function cacheScan(urlStr, data) {
  if (Object.prototype.hasOwnProperty.call(scanCache, urlStr)) {
    const existingIndex = cacheOrder.indexOf(urlStr);
    if (existingIndex >= 0) cacheOrder.splice(existingIndex, 1);
  }

  scanCache[urlStr] = data;
  cacheOrder.push(urlStr);

  while (cacheOrder.length > MAX_SCAN_CACHE_ENTRIES) {
    const oldestUrl = cacheOrder.shift();
    if (oldestUrl) delete scanCache[oldestUrl];
  }
}

function addBypassHostname(hostname) {
  if (bypassList.has(hostname)) return;
  bypassList.add(hostname);

  if (bypassList.size > MAX_BYPASS_ENTRIES) {
    const oldest = bypassList.values().next().value;
    if (typeof oldest === 'string') bypassList.delete(oldest);
  }
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

  if (scanCache[urlStr]) {
    const cached = scanCache[urlStr];
    handleScanResult(urlStr, cached, tabId);
    return;
  }

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

      cacheScan(urlStr, data);
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
      const blockUrl = chrome.runtime.getURL(`block.html?url=${encodeURIComponent(urlStr)}&score=${score}&class=${encodeURIComponent(classification)}&brand=${encodeURIComponent(data.brandImpersonated || 'None')}`);
      chrome.tabs.update(tabId, { url: blockUrl });

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

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) {
    scanUrl(details.url, details.tabId);
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
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

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.action !== 'string') {
    return;
  }

  if (message.action === 'bypass') {
    if (!isTrustedExtensionSender(sender)) {
      sendResponse({ error: 'Unauthorized sender' });
      return;
    }

    const hostname = getHostname(typeof message.url === 'string' ? message.url : '');
    if (!hostname) {
      sendResponse({ error: 'Invalid URL' });
      return;
    }

    addBypassHostname(hostname);
    sendResponse({ status: 'ok' });
    return;
  }

  if (message.action === 'getCache') {
    if (isTrustedExtensionSender(sender)) {
      sendResponse({ cache: scanCache });
      return;
    }

    const tabUrl = getSenderTabUrl(sender);
    if (!tabUrl) {
      sendResponse({ error: 'No tab context' });
      return;
    }

    const current = scanCache[tabUrl];
    sendResponse({ cache: current ? { [tabUrl]: current } : {} });
    return;
  }

  if (message.action === 'scanCurrent') {
    if (!isTrustedExtensionSender(sender)) {
      sendResponse({ error: 'Unauthorized sender' });
      return;
    }

    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs[0] && tabs[0].url) {
        await scanUrl(tabs[0].url, tabs[0].id);
        const cached = scanCache[tabs[0].url] || { threatScore: 0, classification: 'Safe', explanation: 'No report' };
        sendResponse({ data: cached });
      } else {
        sendResponse({ error: 'No active tab found' });
      }
    });
    return true;
  }
});
