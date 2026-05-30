// Cyber Shield Extension Popup controller
let currentTabUrl = '';

document.addEventListener('DOMContentLoaded', async () => {
    const scanBtn = document.getElementById('scan-btn');
    const toggleSettings = document.getElementById('toggle-settings');
    const saveSettings = document.getElementById('save-settings');
    const mainView = document.getElementById('main-view');
    const settingsView = document.getElementById('settings-view');
    
    const apiUrlInput = document.getElementById('api-url');
    const syncKeyInput = document.getElementById('sync-key');
    const currentUrlDisplay = document.getElementById('current-url');
    
    const exportLogsBtn = document.getElementById('export-logs-btn');
    const syncFirebaseBtn = document.getElementById('sync-firebase-btn');

    // Load saved settings
    chrome.storage.local.get(['apiUrl', 'syncKey'], (result) => {
        if (result.apiUrl) {
            apiUrlInput.value = result.apiUrl;
        }
        if (result.syncKey) {
            syncKeyInput.value = result.syncKey;
        }
    });

    // Check active tab and load current status
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].url) {
            currentTabUrl = tabs[0].url;
            currentUrlDisplay.textContent = currentTabUrl;
            
            // Check background cache
            chrome.runtime.sendMessage({ action: 'getCache' }, (response) => {
                if (response && response.cache && response.cache[currentTabUrl]) {
                    displayResults(response.cache[currentTabUrl]);
                }
            });
        }
    });

    // Manual Scan click
    scanBtn.addEventListener('click', async () => {
        startScanningMode();
        animateTimeline();

        chrome.runtime.sendMessage({ action: 'scanCurrent' }, (response) => {
            if (response && response.data) {
                setTimeout(() => {
                    displayResults(response.data);
                }, 1500); // sync with timeline animation end
            } else {
                alert('CRITICAL_FAILURE: Could not communicate with background scanner.');
                resetScanningMode();
            }
        });
    });

    // Toggle Settings Panel
    toggleSettings.addEventListener('click', () => {
        const isSettingsVisible = !settingsView.classList.contains('hidden');
        if (isSettingsVisible) {
            settingsView.classList.add('hidden');
            mainView.classList.remove('hidden');
            toggleSettings.textContent = 'CONFIG_SYSTEM';
        } else {
            settingsView.classList.remove('hidden');
            mainView.classList.add('hidden');
            toggleSettings.textContent = 'BACK_TO_DASHBOARD';
        }
    });

    // Save configuration settings
    saveSettings.addEventListener('click', () => {
        const url = apiUrlInput.value.trim();
        const key = syncKeyInput.value.trim();
        chrome.storage.local.set({ apiUrl: url, syncKey: key }, () => {
            alert('System configurations cached successfully.');
            toggleSettings.click();
        });
    });

    // Export log records
    exportLogsBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: 'getCache' }, (response) => {
            if (response && response.cache) {
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(response.cache, null, 2));
                const dlAnchorElem = document.createElement('a');
                dlAnchorElem.setAttribute("href",     dataStr);
                dlAnchorElem.setAttribute("download", `cyber_shield_threat_logs_${Date.now()}.json`);
                dlAnchorElem.click();
            }
        });
    });

    // Sync scan history with Firebase
    syncFirebaseBtn.addEventListener('click', async () => {
        chrome.storage.local.get(['apiUrl', 'syncKey'], async (settings) => {
            const apiUrl = settings.apiUrl || 'http://localhost:3000';
            if (!settings.syncKey) {
                alert("Please configure a FIREBASE_SYNC_KEY in Settings first.");
                toggleSettings.click();
                return;
            }

            syncFirebaseBtn.textContent = 'SYNCING...';
            syncFirebaseBtn.disabled = true;

            try {
                // Get cached reports from extension
                chrome.runtime.sendMessage({ action: 'getCache' }, async (cacheRes) => {
                    const cache = cacheRes ? cacheRes.cache : {};
                    const reports = Object.values(cache);

                    if (reports.length === 0) {
                        alert("No local scan history found to synchronize.");
                        syncFirebaseBtn.textContent = 'SYNC_CLOUD';
                        syncFirebaseBtn.disabled = false;
                        return;
                    }

                    // Forward them to Node Server sync database endpoint
                    const response = await fetch(`${apiUrl.replace(/\/$/, '')}/api/sync`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            syncKey: settings.syncKey,
                            reports: reports
                        })
                    });

                    if (!response.ok) throw new Error("Sync failed");
                    const data = await response.json();
                    alert(`Sync completed! ${data.synced} threat records archived in Cloud Firebase.`);
                });
            } catch (err) {
                console.error(err);
                alert("Sync failed. Check connection to Cyber Shield node server.");
            } finally {
                syncFirebaseBtn.textContent = 'SYNC_CLOUD';
                syncFirebaseBtn.disabled = false;
            }
        });
    });
});

function startScanningMode() {
    const btn = document.getElementById('scan-btn');
    btn.disabled = true;
    btn.textContent = 'SCANNING...';
    document.getElementById('results-panel').classList.add('hidden');
    
    // Clear indicators status
    document.getElementById('connection-status').className = 'status-indicator warning';
    document.getElementById('risk-display').className = 'risk-meter warning';
    document.getElementById('risk-score').textContent = '--';
}

function resetScanningMode() {
    const btn = document.getElementById('scan-btn');
    btn.disabled = false;
    btn.textContent = 'SCAN_ACTIVE_TAB';
}

function animateTimeline() {
    const panel = document.getElementById('results-panel');
    panel.classList.remove('hidden');
    
    const stepDns = document.getElementById('step-dns');
    const stepSsl = document.getElementById('step-ssl');
    const stepGemini = document.getElementById('step-gemini');

    // Reset steps
    stepDns.className = 'step';
    stepSsl.className = 'step';
    stepGemini.className = 'step';

    setTimeout(() => { stepDns.className = 'step active'; }, 300);
    setTimeout(() => { stepSsl.className = 'step active'; }, 800);
    setTimeout(() => { stepGemini.className = 'step active'; }, 1300);
}

function displayResults(data) {
    resetScanningMode();
    
    const panel = document.getElementById('results-panel');
    panel.classList.remove('hidden');

    const score = data.threatScore || 0;
    const classification = data.classification || 'Safe';
    const brand = data.brandImpersonated || 'None';

    const riskScore = document.getElementById('risk-score');
    riskScore.textContent = score;

    const riskDisplay = document.getElementById('risk-display');
    const verdict = document.getElementById('verdict');
    const connStatus = document.getElementById('connection-status');

    // Timeline steps statuses on result
    const stepDns = document.getElementById('step-dns');
    const stepSsl = document.getElementById('step-ssl');
    const stepGemini = document.getElementById('step-gemini');

    stepDns.className = 'step active';
    stepSsl.className = 'step active';
    stepGemini.className = 'step active';

    if (classification === 'Malicious' || classification === 'Phishing' || score > 70) {
        riskDisplay.className = 'risk-meter danger';
        verdict.textContent = classification === 'Phishing' ? 'PHISHING_SIGNATURE' : 'CRITICAL_THREAT';
        verdict.className = 'verdict danger';
        connStatus.className = 'status-indicator danger';
        stepGemini.className = 'step active failed';
    } else if (classification === 'Suspicious' || score > 30) {
        riskDisplay.className = 'risk-meter warning';
        verdict.textContent = 'SUSPICIOUS_ANOMALY';
        verdict.className = 'verdict warning';
        connStatus.className = 'status-indicator warning';
        stepGemini.className = 'step active warning-step';
    } else {
        riskDisplay.className = 'risk-meter safe';
        verdict.textContent = 'SYSTEM_SECURE_OK';
        verdict.className = 'verdict safe';
        connStatus.className = 'status-indicator safe';
    }

    // Detail parameters
    const brandStatus = document.getElementById('brand-status');
    brandStatus.textContent = brand.toUpperCase();
    brandStatus.className = 'value ' + (brand !== 'None' ? 'danger' : 'safe');

    const heuristics = data.raw?.heuristics || {};
    const ssl = data.raw?.ssl || {};

    const tldStatus = document.getElementById('tld-status');
    tldStatus.textContent = heuristics.suspiciousTLD ? 'HIGH_RISK' : 'NEUTRAL';
    tldStatus.className = 'value ' + (heuristics.suspiciousTLD ? 'danger' : 'safe');
    if (heuristics.suspiciousTLD) {
        stepDns.className = 'step active warning-step';
    }

    const sslStatus = document.getElementById('ssl-status');
    sslStatus.textContent = (ssl && ssl.authorized) ? 'VALID' : (ssl.error ? 'NO_SSL' : 'ANOMALY');
    sslStatus.className = 'value ' + ((ssl && ssl.authorized) ? 'safe' : 'danger');
    if (!ssl || !ssl.authorized) {
        stepSsl.className = 'step active failed';
    }
}
