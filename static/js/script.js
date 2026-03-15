// ═══════════════════════════════════════════════════════════════
//  PhishGuard – script.js v5.0
//  Features: Single scan, Batch scan, QR decode, Dark/Light mode,
//            Copy report, PDF export, Scan history persistence,
//            Geolocation panel, auto-fill from URL param
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {

    // ── Theme persistence ────────────────────────────────────────
    const savedTheme = localStorage.getItem('phishguard-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    const themeIcon   = document.getElementById('theme-icon');
    const themeToggle = document.getElementById('theme-toggle');
    if (themeIcon) themeIcon.className = savedTheme === 'dark' ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const cur  = document.documentElement.getAttribute('data-theme');
            const next = cur === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('phishguard-theme', next);
            themeIcon.className = next === 'dark' ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
        });
    }

    // ── DOM refs ─────────────────────────────────────────────────
    const urlInput       = document.getElementById('url-input');
    const scanBtn        = document.getElementById('scan-btn');
    const resetBtn       = document.getElementById('reset-btn');
    const copyBtn        = document.getElementById('copy-btn');
    const printBtn       = document.getElementById('print-btn');
    const errorMsg       = document.getElementById('error-msg');
    const resultsPanel   = document.getElementById('results-panel');
    const infoSection    = document.querySelector('.info-section');
    const statusCard     = document.getElementById('status-card');
    const mlPred         = document.getElementById('ml-pred');
    const mlConf         = document.getElementById('ml-conf');
    const warningModule  = document.getElementById('warning-module');
    const btnText        = document.querySelector('.btn-text');
    const spinner        = document.getElementById('spinner');

    // Diagnostic lists
    const listIds = ['url-features','domain-info','ssl-check','geo-info','content-analysis','api-reports'];

    // ── Auto-fill URL param (for history re-scan links) ──────────
    const params = new URLSearchParams(window.location.search);
    if (params.get('url') && urlInput) {
        urlInput.value = params.get('url');
        setTimeout(handleScan, 400);
    }

    // ── Tab switching ─────────────────────────────────────────────
    window.switchTab = (tab) => {
        ['single','batch','qr'].forEach(t => {
            document.getElementById(`panel-${t}`).style.display = t === tab ? 'block' : 'none';
            document.getElementById(`tab-${t}`).classList.toggle('active', t === tab);
        });
    };

    // ── Single URL Scan ───────────────────────────────────────────
    async function handleScan() {
        const url = urlInput.value.trim();
        if (!url) { showError("Please enter a URL to analyze."); return; }
        showError("");
        setLoadingState(true);
        try {
            const res    = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            if (!res.ok) throw new Error("Server error.");
            displayResults(await res.json());
        } catch(e) {
            showError(e.message || "An error occurred.");
            setLoadingState(false);
        }
    }

    if (scanBtn)  scanBtn.addEventListener('click', handleScan);
    if (urlInput) urlInput.addEventListener('keypress', e => { if (e.key === 'Enter') handleScan(); });
    if (resetBtn) resetBtn.addEventListener('click', resetScan);

    // ── Display single result ─────────────────────────────────────
    function displayResults(result) {
        if (infoSection) infoSection.style.display = 'none';
        resultsPanel.style.display = 'block';
        resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Severity class
        let ringClass, labelClass;
        if (result.score < 30) {
            ringClass  = 'safe';    labelClass = 'SAFE';
            warningModule.style.display = 'none';
        } else if (result.score < 60) {
            ringClass  = 'warning'; labelClass = 'SUSPICIOUS';
            showWarning("Proceed with caution. This URL shows suspicious characteristics.");
        } else {
            ringClass  = 'danger';  labelClass = 'PHISHING DETECTED';
            showWarning("CRITICAL SECURITY THREAT", true);
        }

        // ── Score gauge
        statusCard.innerHTML = `
            <div style="height:160px;position:relative;display:flex;align-items:center;justify-content:center;">
                <svg width="160" height="160" viewBox="0 0 100 100" style="transform:rotate(-90deg);overflow:visible;">
                    <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="8"/>
                    <circle cx="50" cy="50" r="44" fill="none" stroke="currentColor" stroke-width="8"
                            class="${ringClass}"
                            stroke-dasharray="276"
                            stroke-dashoffset="${276 - (276 * result.score) / 100}"
                            style="transition:stroke-dashoffset 1.4s ease;stroke-linecap:round;"/>
                </svg>
                <div class="${ringClass}" style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
                     font-size:2.6rem;font-weight:800;display:flex;align-items:baseline;justify-content:center;width:100%;">
                    ${result.score}<span style="font-size:1rem;opacity:0.5;margin-left:2px;">/100</span>
                </div>
            </div>
            <div class="status-label" style="color:var(--${ringClass})">${labelClass}</div>
            <div style="margin-top:0.75rem;font-size:0.85rem;color:var(--text-muted);word-break:break-all;">
                ${result.url}
            </div>`;

        // ── ML Engine
        if (result.ml_prediction && mlPred) {
            mlPred.textContent = result.ml_prediction.prediction;
            mlPred.className   = result.ml_prediction.prediction === 'Phishing' ? 'danger' : 'safe';
            mlConf.textContent = result.ml_prediction.confidence;
        }

        // ── Target preview via Thum.io (safe CDN thumbnail)
        const box = document.getElementById('screenshot-box');
        if (box) {
            box.style.backgroundImage = `url('https://image.thum.io/get/width/400/crop/800/${result.url}')`;
            box.style.backgroundSize  = 'cover';
            box.style.backgroundPosition = 'top center';
            box.innerHTML = '';
        }

        // ── Diagnostics
        populateList('url-features',   result.url_features);
        populateList('domain-info',    result.domain_info);
        populateList('ssl-check',      result.ssl_check);
        populateList('geo-info',       result.geo_info || []);
        populateList('content-analysis', result.content_analysis);
        populateList('api-reports',    result.api_reports);

        // ── Store result for copy
        window._lastResult = result;
        setLoadingState(false);
    }

    // ── Populate indicator list ───────────────────────────────────
    function populateList(id, items) {
        const el = document.getElementById(id);
        if (!el) return;
        el.innerHTML = '';
        if (!items || items.length === 0) {
            el.innerHTML = `<div class="indicator-item type-info"><i class="fa-solid fa-circle-info"></i>No data extracted.</div>`;
            return;
        }
        const icons = { success:'fa-check-circle', warning:'fa-exclamation-circle', danger:'fa-circle-xmark', info:'fa-circle-info' };
        items.forEach(item => {
            el.innerHTML += `
                <div class="indicator-item type-${item.type}">
                    <i class="fa-solid ${icons[item.type] || 'fa-circle-info'}" style="flex-shrink:0;margin-top:2px;"></i>
                    <span>${item.message}</span>
                </div>`;
        });
    }

    // ── Warning box ───────────────────────────────────────────────
    function showWarning(subtitle, isCritical = false) {
        warningModule.style.display = 'block';
        if (isCritical) {
            warningModule.innerHTML = `
                <h3><i class="fa-solid fa-user-shield"></i> WARNING INITIATED</h3>
                <p>This website triggered multiple threat detection signals and is classified as highly dangerous.</p>
                <strong>Recommendations:</strong>
                <ul>
                    <li>DO NOT enter any login or personal credentials.</li>
                    <li>Avoid downloading or executing files from this domain.</li>
                    <li>Close the page immediately to prevent payload execution.</li>
                </ul>`;
            warningModule.style.cssText = 'display:block;border:1px solid var(--danger);background:rgba(239,68,68,0.1);border-radius:12px;padding:1.5rem;';
        } else {
            warningModule.innerHTML = `
                <h3 style="color:var(--warning)"><i class="fa-solid fa-triangle-exclamation"></i> SUSPICIOUS</h3>
                <p>${subtitle}</p>
                <strong>Recommendations:</strong>
                <ul>
                    <li>Verify the exact spelling of the domain.</li>
                    <li>Do not provide payment or personal information.</li>
                </ul>`;
            warningModule.style.cssText = 'display:block;border:1px solid var(--warning);background:rgba(245,158,11,0.1);border-radius:12px;padding:1.5rem;';
        }
    }

    function resetScan() {
        if (urlInput) urlInput.value = '';
        resultsPanel.style.display = 'none';
        if (infoSection) infoSection.style.display = 'grid';
        showError('');
        if (urlInput) urlInput.focus();
    }

    function setLoadingState(loading) {
        if (!scanBtn) return;
        scanBtn.disabled = loading;
        urlInput.disabled = loading;
        if (btnText)  btnText.textContent  = loading ? 'Extracting...' : 'Extract Intelligence';
        if (spinner)  spinner.style.display = loading ? 'inline-block' : 'none';
    }

    function showError(msg) { if (errorMsg) errorMsg.textContent = msg; }

    // ── Copy Report ───────────────────────────────────────────────
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const r = window._lastResult;
            if (!r) return;
            const lines = [
                `PhishGuard Intelligence Report`,
                `${'='.repeat(40)}`,
                `URL:    ${r.url}`,
                `Score:  ${r.score}/100`,
                `Status: ${r.status}`,
                `ML:     ${r.ml_prediction?.prediction} (${r.ml_prediction?.confidence})`,
                '',
                ...formatSection('URL Features',       r.url_features),
                ...formatSection('Domain Info',        r.domain_info),
                ...formatSection('SSL Check',          r.ssl_check),
                ...formatSection('Geolocation',        r.geo_info || []),
                ...formatSection('Content Analysis',   r.content_analysis),
                ...formatSection('API Threat Reports', r.api_reports),
            ];
            navigator.clipboard.writeText(lines.join('\n')).then(() => {
                copyBtn.innerHTML = '<i class="fa-solid fa-check"></i>';
                setTimeout(() => { copyBtn.innerHTML = '<i class="fa-solid fa-copy"></i>'; }, 2000);
            });
        });
    }

    function formatSection(title, items) {
        if (!items || !items.length) return [];
        return [`\n── ${title} ──`, ...items.map(i => `  [${i.type.toUpperCase()}] ${i.message}`)];
    }

    // ── PDF / Print ───────────────────────────────────────────────
    if (printBtn) {
        printBtn.addEventListener('click', () => window.print());
    }

    // ── Batch Scanner ─────────────────────────────────────────────
    const batchBtn     = document.getElementById('batch-btn');
    const batchInput   = document.getElementById('batch-input');
    const batchResults = document.getElementById('batch-results');

    if (batchBtn) {
        batchBtn.addEventListener('click', async () => {
            const raw  = batchInput.value.trim();
            if (!raw) return;
            const urls = raw.split('\n').map(u => u.trim()).filter(Boolean).slice(0, 15);
            const btnTxt = batchBtn.querySelector('.batch-btn-text');
            batchBtn.disabled = true;
            if (btnTxt) btnTxt.textContent = `Scanning ${urls.length} URLs...`;

            try {
                const res  = await fetch('/api/batch_analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ urls })
                });
                const data = await res.json();
                batchResults.style.display = 'block';
                batchResults.innerHTML = `<h3 style="margin-bottom:1.2rem;">Batch Results – ${data.length} URLs scanned</h3>`;
                data.forEach(r => {
                    const cls   = r.score < 30 ? 'safe' : r.score < 60 ? 'warning' : 'danger';
                    batchResults.innerHTML += `
                        <div class="batch-row">
                            <div class="batch-url" title="${r.url}">${r.url}</div>
                            <div class="batch-score ${cls}">${r.score}/100</div>
                            <span class="indicator-item type-${cls === 'safe' ? 'success' : cls}"
                                  style="padding:0.4rem 0.9rem;font-size:0.8rem;border-radius:20px;white-space:nowrap;">
                                ${r.status}
                            </span>
                        </div>`;
                });
            } catch(e) {
                batchResults.style.display = 'block';
                batchResults.innerHTML = `<p style="color:var(--danger)">Error: ${e.message}</p>`;
            } finally {
                batchBtn.disabled = false;
                if (btnTxt) btnTxt.textContent = 'Scan All URLs';
            }
        });
    }

    // ── QR Code Scanner ───────────────────────────────────────────
    const qrFileInput = document.getElementById('qr-file-input');
    const qrCanvas    = document.getElementById('qr-canvas');
    const qrResult    = document.getElementById('qr-result');

    if (qrFileInput) {
        qrFileInput.addEventListener('change', e => {
            const file = e.target.files[0];
            if (!file) return;
            const img = new Image();
            img.onload = () => {
                qrCanvas.width  = img.width;
                qrCanvas.height = img.height;
                const ctx = qrCanvas.getContext('2d');
                ctx.drawImage(img, 0, 0);
                const imgData = ctx.getImageData(0, 0, img.width, img.height);
                const code    = window.jsQR(imgData.data, imgData.width, imgData.height);
                qrResult.style.display = 'block';
                if (code) {
                    qrResult.innerHTML = `
                        <p style="margin-bottom:1rem;color:var(--success);">
                            <i class="fa-solid fa-check-circle"></i> QR Code decoded successfully!
                        </p>
                        <p style="font-size:0.9rem;color:var(--text-muted);margin-bottom:1rem;">Extracted URL:</p>
                        <code style="word-break:break-all;color:var(--primary);">${code.data}</code>
                        <button onclick="analyzeQR('${code.data}')" class="primary-btn" style="margin-top:1.5rem;width:100%;justify-content:center;">
                            <i class="fa-solid fa-magnifying-glass"></i> Analyze This URL
                        </button>`;
                } else {
                    qrResult.innerHTML = `<p style="color:var(--danger);"><i class="fa-solid fa-circle-xmark"></i> No QR code detected in this image. Try a clearer image.</p>`;
                }
            };
            img.src = URL.createObjectURL(file);
        });
    }

    window.analyzeQR = (url) => {
        switchTab('single');
        if (urlInput) urlInput.value = url;
        handleScan();
    };
});
