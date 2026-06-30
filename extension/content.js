// Backend URL is configurable via the extension's options page (defaults to local dev).
const DEFAULT_BACKEND_URL = 'http://127.0.0.1:3000';
let backendUrl = DEFAULT_BACKEND_URL;
chrome.storage.sync.get(['backendUrl'], (result) => {
    if (result.backendUrl) backendUrl = result.backendUrl;
});

// Construct an immersive floating control button panel overlay in the lower viewport bounds
const scanButton = document.createElement('div');
scanButton.innerHTML = `<i class="fas fa-shield-halved"></i> Audit with GuardMail AI`;
scanButton.style.position = 'fixed';
scanButton.style.bottom = '30px';
scanButton.style.right = '30px';
scanButton.style.zIndex = '999999';
scanButton.style.background = 'linear-gradient(135deg, #4f46e5, #6366f1)';
scanButton.style.color = '#ffffff';
scanButton.style.padding = '14px 24px';
scanButton.style.borderRadius = '9999px';
scanButton.style.cursor = 'pointer';
scanButton.style.fontFamily = 'system-ui, -apple-system, sans-serif';
scanButton.style.fontSize = '14px';
scanButton.style.fontWeight = '700';
scanButton.style.boxShadow = '0 10px 30px -5px rgba(79, 70, 229, 0.6)';
scanButton.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
scanButton.style.display = 'flex';
scanButton.style.alignItems = 'center';
scanButton.style.gap = '10px';
scanButton.style.letterSpacing = '0.5px';

if (!document.querySelector('link[href*="font-awesome"]')) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css';
    document.head.appendChild(link);
}

document.body.appendChild(scanButton);

scanButton.onmouseenter = () => {
    scanButton.style.transform = 'translateY(-4px) scale(1.02)';
    scanButton.style.boxShadow = '0 20px 40px -6px rgba(99, 102, 241, 0.7)';
};
scanButton.onmouseleave = () => {
    scanButton.style.transform = 'translateY(0) scale(1)';
    scanButton.style.boxShadow = '0 10px 30px -5px rgba(79, 70, 229, 0.6)';
};

scanButton.onclick = function() {
    const subjectNode = document.querySelector('h2.hP');
    const bodyNode = document.querySelector('div.a3s.aiL');
    
    if (!bodyNode) {
        alert("GuardMail AI: Please open an individual email thread before initiating security audits.");
        return;
    }

    let senderAddress = "unknown-sender@domain.com";
    const senderElement = document.querySelector('.gD');
    if (senderElement) {
        // Collect full element context to pass display name configurations down to backend routing logic
        senderAddress = senderElement.innerText + " <" + (senderElement.getAttribute('email') || "") + ">";
    }

    const emailPayload = {
        sender: senderAddress.trim(),
        subject: subjectNode ? subjectNode.innerText : "(No Subject Header Selected)",
        body: bodyNode.innerText.trim()
    };

    scanButton.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Processing Heuristics...`;
    scanButton.style.background = '#1e1b4b';

    fetch(`${backendUrl}/api/analyze-ext`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(emailPayload)
    })
    .then(response => response.json())
    .then(data => {
        scanButton.innerHTML = `<i class="fa-solid fa-square-check text-emerald-400"></i> Audit Synchronized`;
        scanButton.style.background = '#064e3b';
        
        document.getElementById('guardmail-live-ribbon')?.remove();

        const insertionTarget = document.querySelector('.ha') || document.querySelector('h2.hP')?.parentElement;
        if (insertionTarget) {
            const ribbon = document.createElement('div');
            ribbon.id = 'guardmail-live-ribbon';
            ribbon.style.width = '100%';
            ribbon.style.padding = '16px';
            ribbon.style.marginTop = '12px';
            ribbon.style.marginBottom = '12px';
            ribbon.style.borderRadius = '14px';
            ribbon.style.fontFamily = 'system-ui, -apple-system, sans-serif';
            ribbon.style.boxSizing = 'border-box';
            ribbon.style.display = 'flex';
            ribbon.style.alignItems = 'center';
            ribbon.style.justifyContent = 'space-between';
            ribbon.style.gap = '16px';
            
            let bg = "", border = "", text = "", icon = "", copy = "";

            if (data.risk_score >= 75) {
                bg = '#4c0519'; border = '2px solid #f43f5e'; text = '#fda4af';
                icon = '<i class="fa-solid fa-shield-virus" style="color:#f43f5e; font-size:22px;"></i>';
                copy = `<strong>CRITICAL RISK THREAT VERDICT (${data.risk_score}%):</strong> Intercepted indicators matching high-risk vector signatures. ${data.spoofing_detected ? '⚠️ Display Name Brand Spoofing detected!' : ''} Avoid clicking internal contents.`;
            } else if (data.assigned_category === 'Spam' || data.risk_score >= 40) {
                bg = '#451a03'; border = '1px solid #d97706'; text = '#fef3c7';
                icon = '<i class="fa-solid fa-triangle-exclamation text-amber-500" style="font-size:18px;"></i>';
                copy = `<strong>GUARDMAIL FILTER BANNER (${data.risk_score}%):</strong> This inbound payload has been isolated as promotional/bulk advertising content (<b>Spam Bucket</b>).`;
            } else {
                bg = '#022c22'; border = '1px solid #059669'; text = '#d1fae5';
                icon = '<i class="fa-solid fa-circle-check text-emerald-400" style="font-size:18px;"></i>';
                copy = `<strong>SECURITY VERDICT SAFE (${data.risk_score}%):</strong> Semantic evaluations evaluate normal communication criteria: <b>${data.assigned_category}</b>.`;
            }

            ribbon.style.backgroundColor = bg;
            ribbon.style.border = border;
            ribbon.style.color = text;
            
            ribbon.innerHTML = `
                <div style="display:flex; align-items:center; gap:12px;">
                    ${icon}
                    <span style="font-size:13px; line-height:1.5;">${copy}</span>
                </div>
                <a href="${backendUrl}/?emailId=${data.id}" target="_blank" style="background:#4f46e5; color:#ffffff; font-weight:800; font-size:11px; padding:8px 14px; border-radius:10px; text-decoration:none; text-transform:uppercase; letter-spacing:0.5px; white-space:nowrap;">Inspect Sandbox Analysis</a>
            `;
            insertionTarget.appendChild(ribbon);
        }

        setTimeout(() => {
            scanButton.innerHTML = `<i class="fas fa-shield-halved"></i> Audit with GuardMail AI`;
            scanButton.style.background = 'linear-gradient(135deg, #4f46e5, #6366f1)';
        }, 3000);
    })
    .catch(err => {
        console.error(err);
        alert(`Connection Failure: Couldn't reach the GuardMail backend at ${backendUrl}. Check the extension's options page if you've moved it.`);
        scanButton.innerHTML = `<i class="fas fa-shield-halved"></i> Audit with GuardMail AI`;
        scanButton.style.background = 'linear-gradient(135deg, #4f46e5, #6366f1)';
    });
};