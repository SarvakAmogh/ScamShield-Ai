const API_BASE = 'https://scamshield-ai-zs40.onrender.com';

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initScanButtons();
    initUrlEnterKey();
});

function initTabs() {
    const tabs = document.querySelectorAll('.tab-btn');
    const indicator = document.querySelector('.tab-indicator');
    
    function updateIndicator(activeTab) {
        if (!activeTab || !indicator) return;
        indicator.style.width = `${activeTab.offsetWidth}px`;
        indicator.style.left = `${activeTab.offsetLeft}px`;
    }

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetId = tab.getAttribute('data-target');
            
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(targetId).classList.add('active');
            
            updateIndicator(tab);

            if (targetId === 'history-tab') {
                loadHistory();
            }
        });
    });

    setTimeout(() => {
        const activeTab = document.querySelector('.tab-btn.active');
        updateIndicator(activeTab);
    }, 100);
}

function initScanButtons() {
    document.getElementById('scan-message-btn').addEventListener('click', scanMessage);
    document.getElementById('scan-url-btn').addEventListener('click', scanUrl);
}

function initUrlEnterKey() {
    document.getElementById('url-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            scanUrl();
        }
    });
}

async function scanMessage() {
    const input = document.getElementById('message-input').value.trim();
    const source = document.getElementById('message-source').value;
    
    if (!input) {
        showToast('Please enter a message to scan', 'error');
        return;
    }

    const btnId = 'scan-message-btn';
    showLoading(btnId);
    
    try {
        const response = await fetch(`${API_BASE}/api/v1/scan/message`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: input, source: source })
        });
        
        if (!response.ok) throw new Error(`Server returned ${response.status}`);
        
        const data = await response.json();
        renderMessageResult(data);
    } catch (err) {
        showToast(err.message.includes('Failed to fetch') ? 'Could not connect to server' : err.message, 'error');
    } finally {
        hideLoading(btnId);
    }
}

async function scanUrl() {
    const url = document.getElementById('url-input').value.trim();
    
    if (!url) {
        showToast('Please enter a URL to scan', 'error');
        return;
    }

    const btnId = 'scan-url-btn';
    showLoading(btnId);
    
    try {
        const response = await fetch(`${API_BASE}/api/v1/scan/url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });
        
        if (!response.ok) throw new Error(`Server returned ${response.status}`);
        
        const data = await response.json();
        renderUrlResult(data);
    } catch (err) {
        showToast(err.message.includes('Failed to fetch') ? 'Could not connect to server' : err.message, 'error');
    } finally {
        hideLoading(btnId);
    }
}

async function loadHistory() {
    const container = document.getElementById('history-container');
    container.innerHTML = '<div class="loading-state">Loading history...</div>';
    
    try {
        const response = await fetch(`${API_BASE}/api/v1/scan/history?limit=20`);
        if (!response.ok) throw new Error('Failed to load history');
        
        const data = await response.json();
        renderHistory(data);
    } catch (err) {
        container.innerHTML = `<div class="error-state">Failed to load history</div>`;
        showToast(err.message.includes('fetch') ? 'Could not connect to server' : err.message, 'error');
    }
}

function getRiskColor(level) {
    if (!level) return 'var(--text-secondary)';
    switch (level.toLowerCase()) {
        case 'low': return 'var(--risk-low)';
        case 'medium': return 'var(--risk-medium)';
        case 'high': return 'var(--risk-high)';
        case 'critical': return 'var(--risk-critical)';
        default: return 'var(--text-secondary)';
    }
}

function renderMessageResult(result) {
    const container = document.getElementById('message-results');
    container.innerHTML = buildResultHTML(result, result.indicators || [], 'indicators');
    container.classList.remove('hidden');
    animateResult('message-results', result.risk_score, result.risk_level);
}

function renderUrlResult(result) {
    const container = document.getElementById('url-results');
    container.innerHTML = buildResultHTML(result, result.flags || [], 'flags');
    container.classList.remove('hidden');
    animateResult('url-results', result.risk_score, result.risk_level);
}

function buildResultHTML(result, items, itemType) {
    const date = new Date(result.scanned_at || Date.now()).toLocaleString();
    
    let itemsHTML = '';
    if (items.length > 0) {
        itemsHTML = `<div class="indicators-list">
            ${items.map(item => {
                const color = getRiskColor(item.severity);
                const title = item.rule || item.flag;
                const matchHtml = item.matched_text ? `<div class="indicator-match">"${item.matched_text}"</div>` : '';
                return `
                <div class="indicator-item">
                    <div class="indicator-severity-bar" style="background-color: ${color}"></div>
                    <div class="indicator-header">
                        <span class="indicator-rule">${title}</span>
                    </div>
                    <div class="indicator-desc">${item.description}</div>
                    ${matchHtml}
                </div>`;
            }).join('')}
        </div>`;
    } else {
        itemsHTML = `<p style="margin-top: 1rem; color: var(--risk-low);">No suspicious indicators found.</p>`;
    }

    const safeLevel = result.risk_level ? result.risk_level.toLowerCase() : 'low';
    const displayLevel = result.risk_level || 'Unknown';

    return `
        <div class="result-card">
            <div class="risk-header">
                <div class="gauge-container">
                    <svg class="gauge-svg" viewBox="0 0 100 100">
                        <circle class="gauge-bg" cx="50" cy="50" r="40"></circle>
                        <circle class="gauge-progress" cx="50" cy="50" r="40" stroke-dasharray="251.2" stroke-dashoffset="251.2"></circle>
                    </svg>
                    <div class="gauge-text">0</div>
                </div>
                <div class="risk-details">
                    <div class="risk-badge badge-${safeLevel}">${displayLevel} Risk</div>
                    <p class="explanation">${result.explanation || ''}</p>
                    <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.5rem;">Scanned at: ${date}</p>
                </div>
            </div>
            ${itemsHTML}
        </div>
    `;
}

function animateResult(containerId, score, level) {
    const container = document.getElementById(containerId);
    const progressCircle = container.querySelector('.gauge-progress');
    const textEl = container.querySelector('.gauge-text');
    
    const safeScore = score || 0;
    const circumference = 251.2;
    const offset = circumference - (safeScore / 100) * circumference;
    
    progressCircle.style.stroke = getRiskColor(level);
    
    setTimeout(() => {
        progressCircle.style.strokeDashoffset = offset;
    }, 50);

    let current = 0;
    const duration = 1500;
    const interval = 20;
    const step = (safeScore / duration) * interval;
    
    if (safeScore > 0) {
        const timer = setInterval(() => {
            current += step;
            if (current >= safeScore) {
                current = safeScore;
                clearInterval(timer);
            }
            textEl.textContent = Math.round(current);
        }, interval);
    } else {
        textEl.textContent = "0";
    }
}

function renderHistory(scans) {
    const container = document.getElementById('history-container');
    if (!scans || scans.length === 0) {
        container.innerHTML = '<p class="explanation">No recent scans found.</p>';
        return;
    }
    
    container.innerHTML = scans.map(scan => {
        const type = scan.url ? 'URL' : 'Message';
        const target = scan.url || (scan.message ? scan.message.substring(0, 50) + '...' : '');
        const date = new Date(scan.scanned_at || Date.now()).toLocaleDateString();
        const safeLevel = scan.risk_level ? scan.risk_level.toLowerCase() : 'low';
        const displayLevel = scan.risk_level || 'Unknown';
        
        return `
            <div class="history-item glass-card" style="margin-bottom: 1rem; padding: 1rem;">
                <div>
                    <div class="history-type">${type} SCAN - ${date}</div>
                    <div style="margin-top: 0.5rem; font-size: 0.95rem;">${target}</div>
                </div>
                <div class="risk-badge badge-${safeLevel}" style="margin-bottom: 0;">
                    ${displayLevel}
                </div>
            </div>
        `;
    }).join('');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        if(toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 3300);
}

function showLoading(btnId) {
    const btn = document.getElementById(btnId);
    if(btn) {
        btn.classList.add('loading');
        btn.disabled = true;
    }
}

function hideLoading(btnId) {
    const btn = document.getElementById(btnId);
    if(btn) {
        btn.classList.remove('loading');
        btn.disabled = false;
    }
}
