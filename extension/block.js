// Cyber Shield Block Page controller
document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = params.get('url') || 'N/A';
    const score = params.get('score') || '99';
    const classification = params.get('class') || 'Malicious';
    const brand = params.get('brand') || 'None';

    document.getElementById('blocked-url').textContent = blockedUrl;
    document.getElementById('threat-score').textContent = score;
    document.getElementById('class-badge').textContent = `CLASSIFICATION: ${classification}`;
    document.getElementById('brand-badge').textContent = `BRAND_MIMIC: ${brand}`;

    // Return to safety button
    document.getElementById('back-btn').addEventListener('click', () => {
        window.history.back();
        // If history back doesn't work (e.g. opened in new tab)
        setTimeout(() => {
            window.close();
            // Or fallback redirect
            window.location.href = 'https://www.google.com';
        }, 300);
    });

    // Bypass button
    document.getElementById('bypass-btn').addEventListener('click', () => {
        if (confirm("WARNING: Proceeding may compromise your accounts, credentials, or personal information. Are you sure you want to bypass the Cyber Shield protection layer?")) {
            // Message background to whitelist the url
            chrome.runtime.sendMessage({ action: 'bypass', url: blockedUrl }, (response) => {
                // Navigate original URL
                window.location.replace(blockedUrl);
            });
        }
    });
});
