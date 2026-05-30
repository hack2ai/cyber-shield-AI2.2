// Cyber Shield Content Script
console.log("CYBER SHIELD: Live script injected.");

function injectWarningBanner(message) {
  if (document.getElementById('cyber-shield-warning-banner')) return;

  const banner = document.createElement('div');
  banner.id = 'cyber-shield-warning-banner';
  banner.style.position = 'fixed';
  banner.style.top = '0';
  banner.style.left = '0';
  banner.style.width = '100%';
  banner.style.backgroundColor = '#ff3131';
  banner.style.color = '#000000';
  banner.style.padding = '12px';
  banner.style.textAlign = 'center';
  banner.style.fontFamily = "'Courier New', Courier, monospace";
  banner.style.fontSize = '12px';
  banner.style.fontWeight = 'bold';
  banner.style.zIndex = '999999';
  banner.style.borderBottom = '3px solid #000000';
  banner.style.boxShadow = '0 4px 15px rgba(255, 49, 49, 0.4)';
  banner.style.display = 'flex';
  banner.style.alignItems = 'center';
  banner.style.justifyContent = 'center';
  banner.style.gap = '15px';

  const textNode = document.createElement('span');
  textNode.textContent = `⚠️ CYBER SHIELD WARNING: ${message}`;
  banner.appendChild(textNode);

  const closeBtn = document.createElement('button');
  closeBtn.textContent = 'DISMISS_RISK';
  closeBtn.style.backgroundColor = '#000000';
  closeBtn.style.color = '#ff3131';
  closeBtn.style.border = '1px solid #ff3131';
  closeBtn.style.padding = '4px 10px';
  closeBtn.style.cursor = 'pointer';
  closeBtn.style.fontSize = '10px';
  closeBtn.style.fontWeight = 'bold';
  closeBtn.style.fontFamily = 'inherit';
  closeBtn.addEventListener('click', () => banner.remove());
  banner.appendChild(closeBtn);

  document.body.prepend(banner);
  document.body.style.marginTop = '45px';
}

// Scans forms and triggers alerts
function scanInputs() {
  const passwordField = document.querySelector('input[type="password"]');
  if (passwordField) {
    console.log("CYBER SHIELD: Credentials input field detected. Checking domain integrity...");
    // Ask background script for active tab analysis details
    chrome.runtime.sendMessage({ action: 'getCache' }, (response) => {
      if (response && response.cache) {
        const currentUrl = window.location.href;
        const analysis = response.cache[currentUrl];
        if (analysis) {
          const score = analysis.threatScore || 0;
          const classification = analysis.classification || 'Safe';
          if (score > 30 || classification === 'Suspicious' || classification === 'Phishing') {
            injectWarningBanner(`CREDENTIALS HARVESTING RISK DETECTED! Threat Index: ${score}%.`);
          }
        }
      }
    });
  }
}

// Staggered trigger on page loads
setTimeout(scanInputs, 1500);
