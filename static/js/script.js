document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('url-input');
    const scanBtn = document.getElementById('scan-btn');
    const resetBtn = document.getElementById('reset-btn');
    const errorMsg = document.getElementById('error-msg');
    
    // UI Layout Links
    const resultsPanel = document.getElementById('results-panel');
    const infoGrid = document.querySelector('.info-section');
    
    // Status Profile Links
    const statusCard = document.getElementById('status-card');
    const mlPred = document.getElementById('ml-pred');
    const mlConf = document.getElementById('ml-conf');
    const warningModule = document.getElementById('warning-module');
    
    // Diagnostic Modules
    const urlFeaturesList = document.getElementById('url-features');
    const domainInfoList = document.getElementById('domain-info');
    const sslCheckList = document.getElementById('ssl-check');
    const contentAnalysisList = document.getElementById('content-analysis');
    const apiReportsList = document.getElementById('api-reports');
    
    // Controls
    const btnText = document.querySelector('.btn-text');
    const spinner = document.getElementById('spinner');

    const handleScan = async () => {
        const url = urlInput.value.trim();
        if (!url) { showError("Please enter a URL to analyze."); return; }
        
        showError("");
        setLoadingState(true);

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) throw new Error("Failed to process Target Intelligence.");
            
            const result = await response.json();
            displayResults(result);
            
        } catch (error) {
            showError(error.message || "An error occurred. Check connection.");
            setLoadingState(false);
        }
    };

    const displayResults = (result) => {
        infoGrid.style.display = 'none';
        resultsPanel.style.display = 'block';
        resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Calculate visuals based on Risk Score
        let ringClass, labelClass, mlClass;
        let iconClass = 'fa-shield-halved';
        
        if (result.score < 30) {
            ringClass = 'safe'; labelClass = 'SAFE'; mlClass = 'safe'; iconClass = 'fa-shield-check';
            warningModule.style.display = 'none';
        } else if (result.score < 60) {
            ringClass = 'warning'; labelClass = 'SUSPICIOUS'; mlClass = 'danger'; iconClass = 'fa-triangle-exclamation';
            showWarning("Proceed with caution. The URL exhibits suspicious characteristics.");
        } else {
            ringClass = 'danger'; labelClass = 'PHISHING DETECTED'; mlClass = 'danger'; iconClass = 'fa-skull-crossbones';
            showWarning("CRITICAL SECURITY THREAT", true);
        }

        // 1. Update Profile Card
        statusCard.innerHTML = `
            <div class="gauge-container" style="height: 150px; position: relative; display: flex; align-items: center; justify-content: center;">
                <!-- Using a simple dynamic circle relative to score -->
                <svg width="150" height="150" viewBox="0 0 100 100" style="transform: rotate(-90deg); overflow: visible;">
                    <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="8"></circle>
                    <circle cx="50" cy="50" r="45" fill="none" stroke="currentColor" stroke-width="8" class="${ringClass}"
                        stroke-dasharray="283" stroke-dashoffset="${283 - (283 * result.score) / 100}" 
                        style="transition: stroke-dashoffset 1.5s ease; stroke-linecap: round;"></circle>
                </svg>
                <div class="${ringClass}" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 2.5rem; font-weight: 800; display: flex; align-items: baseline; justify-content: center; width: 100%;">
                    ${result.score}<span style="font-size: 1rem; opacity: 0.5; margin-left: 2px;">/100</span>
                </div>
            </div>
            
            <div class="status-label" style="color: var(--${ringClass})">${labelClass}</div>
            <div style="margin-top: 1rem; font-size: 0.9rem; color: var(--text-muted); word-break: break-all;">
                Target: ${result.url}
            </div>
        `;

        // 2. Update Machine Learning
        if (result.ml_prediction) {
            mlPred.textContent = result.ml_prediction.prediction;
            mlPred.className = result.ml_prediction.prediction === 'Phishing' ? 'danger' : 'safe';
            mlConf.textContent = result.ml_prediction.confidence;
        }

        // 2b. Add Actual Target Preview Screenshot
        const screenshotBox = document.querySelector('.screenshot-box');
        if (screenshotBox) {
            screenshotBox.style.background = `url('https://image.thum.io/get/width/400/crop/800/${result.url}') center top / cover no-repeat`;
            screenshotBox.innerHTML = ''; 
        }

        // 3. Populate Diagnostics Sections
        populateList(urlFeaturesList, result.url_features);
        populateList(domainInfoList, result.domain_info);
        populateList(sslCheckList, result.ssl_check);
        populateList(contentAnalysisList, result.content_analysis);
        populateList(apiReportsList, result.api_reports);

        setLoadingState(false);
    };

    const populateList = (element, items) => {
        element.innerHTML = '';
        if (!items || items.length === 0) {
            element.innerHTML = `<div class="indicator-item type-info"><i class="fa-solid fa-circle-info"></i> No data extracted.</div>`;
            return;
        }
        
        items.forEach(ind => {
            let icon = "fa-info-circle";
            if (ind.type === "success") icon = "fa-check-circle";
            else if (ind.type === "warning") icon = "fa-exclamation-circle";
            else if (ind.type === "danger") icon = "fa-circle-xmark";

            element.innerHTML += `
                <div class="indicator-item type-${ind.type}">
                    <i class="fa-solid ${icon}"></i>
                    <div>${ind.message}</div>
                </div>
            `;
        });
    };

    const showWarning = (subtitle, isCritical = false) => {
        warningModule.style.display = 'block';
        if (isCritical) {
            warningModule.innerHTML = `
                <h3><i class="fa-solid fa-user-shield"></i> WARNING INITIATED</h3>
                <p>This website has engaged multiple threat detection triggers and is classified as highly dangerous.</p>
                <strong>Recommendations:</strong>
                <ul>
                    <li>DO NOT enter any login or personal credentials.</li>
                    <li>Avoid downloading or executing files from this domain.</li>
                    <li>Close the page immediately to prevent background payload execution.</li>
                </ul>
            `;
            warningModule.style.border = "1px solid var(--danger)";
            warningModule.style.background = "rgba(239, 68, 68, 0.1)";
        } else {
            warningModule.innerHTML = `
                <h3 style="color: var(--warning);"><i class="fa-solid fa-triangle-exclamation"></i> SUSPICIOUS</h3>
                <p>${subtitle}</p>
                <strong>Recommendations:</strong>
                <ul>
                    <li>Verify the exact spelling of the domain.</li>
                    <li>Do not provide payment information.</li>
                </ul>
            `;
            warningModule.style.border = "1px solid var(--warning)";
            warningModule.style.background = "rgba(245, 158, 11, 0.1)";
        }
    }

    const resetScan = () => {
        urlInput.value = '';
        resultsPanel.style.display = 'none';
        infoGrid.style.display = 'grid';
        showError("");
        urlInput.focus();
    };

    const setLoadingState = (isLoading) => {
        if (isLoading) {
            scanBtn.disabled = true; btnText.style.display = 'none'; spinner.style.display = 'inline-block'; urlInput.disabled = true;
        } else {
            scanBtn.disabled = false; btnText.style.display = 'inline-block'; spinner.style.display = 'none'; urlInput.disabled = false;
        }
    };

    const showError = (message) => { errorMsg.textContent = message; };

    // Event Listeners
    scanBtn.addEventListener('click', handleScan);
    urlInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') handleScan(); });
    resetBtn.addEventListener('click', resetScan);
});
