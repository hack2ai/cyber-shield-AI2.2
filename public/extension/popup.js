// Cyber Shield Browser Extension Logic
let currentTabUrl = '';

document.addEventListener('DOMContentLoaded', async () => {
    const scanBtn = document.getElementById('scan-btn');
    const toggleSettings = document.getElementById('toggle-settings');
    const saveSettings = document.getElementById('save-settings');
    const mainView = document.getElementById('main-view');
    const settingsView = document.getElementById('settings-view');
    const apiUrlInput = document.getElementById('api-url');
    const currentUrlDisplay = document.getElementById('current-url');

    // Load saved API URL
    chrome.storage.local.get(['apiUrl'], (result) => {
        if (result.apiUrl) {
            apiUrlInput.value = result.apiUrl;
        }
    });

    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
            currentTabUrl = tabs[0].url;
            currentUrlDisplay.textContent = currentTabUrl;
        }
    });

    scanBtn.addEventListener('click', async () => {
        let apiUrl = apiUrlInput.value.trim();
        if (!apiUrl) {
            alert('Please configure API_GATEWAY_URL in settings first.');
            toggleSettings.click();
            return;
        }

        // Clean trailing slash
        if (apiUrl.endsWith('/')) {
            apiUrl = apiUrl.slice(0, -1);
        }

        startScanningMode();
        
        try {
            const response = await fetch(`${apiUrl}/api/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: currentTabUrl })
            });

            if (!response.ok) throw new Error('Analysis request failed');
            
            const data = await response.json();
            displayResults(data);
        } catch (error) {
            console.error(error);
            alert('CRITICAL_FAILURE: Could not reach Cyber Shield intelligence node.');
            resetScanningMode();
        }
    });

    toggleSettings.addEventListener('click', () => {
        const isSettingsVisible = !settingsView.classList.contains('hidden');
        if (isSettingsVisible) {
            settingsView.classList.add('hidden');
            mainView.classList.remove('hidden');
        } else {
            settingsView.classList.remove('hidden');
            mainView.classList.add('hidden');
        }
    });

    saveSettings.addEventListener('click', () => {
        const url = apiUrlInput.value.trim();
        chrome.storage.local.set({ apiUrl: url }, () => {
            alert('Configuration saved.');
            toggleSettings.click();
        });
    });
});

function startScanningMode() {
    const btn = document.getElementById('scan-btn');
    btn.disabled = true;
    btn.textContent = 'SCANNING...';
    document.getElementById('results-panel').classList.add('hidden');
}

function resetScanningMode() {
    const btn = document.getElementById('scan-btn');
    btn.disabled = false;
    btn.textContent = 'INITIATE_SCAN';
}

function displayResults(data) {
    resetScanningMode();
    const probe = document.getElementById('results-panel');
    probe.classList.remove('hidden');

    const score = data.threatScore || 0;
    const classification = data.classification || 'Safe';

    const riskScore = document.getElementById('risk-score');
    riskScore.textContent = score;
    
    if (classification === 'Malicious' || classification === 'Phishing' || score > 60) {
        riskScore.className = 'score danger';
        document.getElementById('verdict').textContent = classification === 'Phishing' ? 'PHISHING_THREAT' : 'CRITICAL_THREAT_DETECTED';
        document.getElementById('verdict').className = 'verdict danger';
    } else if (classification === 'Suspicious' || score > 30) {
        riskScore.className = 'score warning';
        document.getElementById('verdict').textContent = 'SUSPICIOUS_SIGNATURE';
        document.getElementById('verdict').className = 'verdict warning';
    } else {
        riskScore.className = 'score safe';
        document.getElementById('verdict').textContent = 'NEUTRAL_PROFILE';
        document.getElementById('verdict').className = 'verdict safe';
    }

    const heuristics = data.raw.heuristics;
    document.getElementById('tld-status').textContent = heuristics.suspiciousTLD ? 'HIGH_RISK' : 'NEUTRAL';
    document.getElementById('tld-status').className = 'value ' + (heuristics.suspiciousTLD ? 'danger' : 'safe');
    
    const ssl = data.raw.ssl;
    document.getElementById('ssl-status').textContent = (ssl && ssl.authorized) ? 'VALIDATED' : 'ANOMALY';
    document.getElementById('ssl-status').className = 'value ' + ((ssl && ssl.authorized) ? 'safe' : 'danger');
}
