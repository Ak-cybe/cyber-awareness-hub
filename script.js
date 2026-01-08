document.addEventListener('DOMContentLoaded', () => {
    initPhishingSim();
    initPasswordSim();
    initChecklist();
    initPhishingAnalyzer();
    initAPIConfig();
});

// --- Phishing Simulation (Dynamic) ---
const scenarios = [
    {
        id: "paypal-spoof",
        subject: "URGENT: Your Account will be suspended in 24 hours!!!",
        from: "security@paypa1-support.com",
        body: `
            <p>Dear Valued Customer,</p>
            <p>We noticed unusual activity on your account. To prevent permanent suspension, please verify your identity immediately.</p>
            <p>Failure to act within 24 hours will result in <span class="suspicious clickable-element" data-risk="urgency" role="button" tabindex="0">total loss of funds</span>.</p>
            <div class="cta-container">
                <a href="#" class="btn btn-fake suspicious clickable-element" data-risk="link" onclick="event.preventDefault()">Verify Now</a>
            </div>
            <p>Thank you,<br>The Security Team</p>
        `,
        risks: {
            'sender': '<strong>Look closely at the email address.</strong> "paypa1-support" is a subtle spoof. Legitimate companies come from their official domain (e.g., paypal.com).',
            'subject': '<strong>Urgency is a trap.</strong> Scammers use capitalized exclamation points and short deadlines ("24 hours") to make you panic and stop thinking.',
            'urgency': '<strong>Threats are a red flag.</strong> "Total loss of funds" is designed to trigger fear. Banks rarely threaten you this aggressively via email.',
            'link': '<strong>Hover before you click.</strong> This button likely leads to a malicious credential harvesting site, not the real verification page.'
        }
    },
    {
        id: "invoice-fraud",
        subject: "INV-2024-001 OVERDUE Payment Required",
        from: "billing@vendor-portal-update.com",
        body: `
            <p>Hello Finance Team,</p>
            <p>Attached is the overdue invoice for Aug services. Please remit payment by EOD to avoid service interruption.</p>
            <p><strong>Amount Due: $15,400.00</strong></p>
            <p>Note: Our <span class="suspicious clickable-element" data-risk="bank" role="button" tabindex="0">bank account details have changed</span>. Please use the new details in the link below.</p>
            <div class="cta-container">
                <a href="#" class="btn btn-fake suspicious clickable-element" data-risk="doc" onclick="event.preventDefault()">Download Invoice & Pay</a>
            </div>
            <p>Regards,<br>Accounts Receivable</p>
        `,
        risks: {
            'sender': '<strong>Unknown Domain.</strong> "vendor-portal-update.com" is generic and likely registered recently. Always check against known vendor contacts.',
            'subject': '<strong>Pressure Tactics.</strong> "OVERDUE" and "EOD" create artificial pressure to bypass verification procedures.',
            'bank': '<strong>The Classic Switch.</strong> Sudden changes to bank account details are the #1 sign of Business Email Compromise (BEC). Always verify via phone.',
            'doc': '<strong>Malicious Payload.</strong> Links to "Download" documents often host malware or fake login pages. Never trust unexpected changes.'
        }
    },
    {
        id: "hr-payroll",
        subject: "ACTION REQUIRED: Verify Direct Deposit Info",
        from: "hr-payroll@worIdwide-corp.com", // Typo in 'worldwide' (Capital I)
        body: `
            <p>Hi Team,</p>
            <p>We are switching payroll providers. All employees must confirm their banking information by Friday to ensure timely payment.</p>
            <div class="cta-container">
                <a href="#" class="btn btn-fake suspicious clickable-element" data-risk="link" onclick="event.preventDefault()">Login to Workday</a>
            </div>
            <p>HR Department</p>
        `,
        risks: {
            'sender': '<strong>Typosquatting.</strong> Did you catch it? "worIdwide" is spelled with a capital "I" instead of an "l". Always double-check internal domains.',
            'subject': '<strong>Process Change.</strong> Scammers love major organizational changes (like payroll switches) to trick distracted employees.',
            'link': '<strong>Fake Login Page.</strong> This likely leads to a cloned portal designed to steal your credentials.'
        }
    },
    {
        id: "it-update",
        subject: "CRITICAL: Install Security Patch v4.2",
        from: "admin@it-support-desk.net",
        body: `
            <p>All Staff,</p>
            <p>A critical vulnerability has been found on your workstation. You must install the security patch immediately.</p>
            <p>Download the patch here: <span class="suspicious clickable-element" data-risk="exe" role="button" tabindex="0">Patch_v4.2.exe</span></p>
            <p>IT Support</p>
        `,
        risks: {
            'sender': '<strong>Generic Domain.</strong> "it-support-desk.net" is not your company domain. Real IT updates usually come from a specific internal system.',
            'exe': '<strong>Dangerous File Type.</strong> IT will rarely ask you to manually download and run an .exe file. This is a classic malware loader.'
        }
    },
    {
        id: "mfa-fatigue",
        subject: "Security Alert: New Sign-in Attempt",
        from: "no-reply@auth-service-security.com",
        body: `
            <p>We detected a new sign-in from Lagos, Nigeria.</p>
            <p>If this wasn't you, click the link below to Secure Your Account.</p>
            <div class="cta-container">
                <a href="#" class="btn btn-fake suspicious clickable-element" data-risk="url" onclick="event.preventDefault()">Deny Access</a>
            </div>
        `,
        risks: {
            'sender': '<strong>Generic Service.</strong> "auth-service-security.com" is vague. Real alerts come from Microsoft, Google, or your specific IDP.',
            'url': '<strong>Reverse Psychology.</strong> Clicking "Deny" might actually approve a token or lead to a phishing page. Use your official settings page instead.'
        }
    }
];

let currentScenarioIndex = 0;

// Stats Object
const stats = {
    reported: 0,
    missed: 0,
    history: {} // To track which scenarios have been attempted
};

function initPhishingSim() {
    loadStats();
    renderScenario(currentScenarioIndex);
    updateStatsUI();

    document.getElementById('btn-next-scenario').addEventListener('click', () => {
        currentScenarioIndex = (currentScenarioIndex + 1) % scenarios.length;
        renderScenario(currentScenarioIndex);
    });

    document.getElementById('btn-report').addEventListener('click', handleReport);

    // Add Reset Listener if button exists (it will be added dynamically or needs to be in HTML)
    const statsZone = document.getElementById('stats-zone');
    if (statsZone && !document.getElementById('btn-reset')) {
        const resetBtn = document.createElement('button');
        resetBtn.id = 'btn-reset';
        resetBtn.className = 'btn btn-secondary-glass';
        resetBtn.style.marginTop = '15px';
        resetBtn.style.width = '100%';
        resetBtn.innerText = 'Reset Stats';
        resetBtn.onclick = resetStats;
        statsZone.appendChild(resetBtn);
    }
}

function loadStats() {
    const saved = localStorage.getItem('cyberHubStats');
    if (saved) {
        Object.assign(stats, JSON.parse(saved));
    }
}

function saveStats() {
    localStorage.setItem('cyberHubStats', JSON.stringify(stats));
    updateStatsUI();
}

function updateStatsUI() {
    document.getElementById('stat-reported').innerText = stats.reported;
    document.getElementById('stat-missed').innerText = stats.missed;
}

function handleReport() {
    const data = scenarios[currentScenarioIndex];
    // Check if already interacted
    if (stats.history[data.id]) {
        if (stats.history[data.id] === 'reported') {
            alert("You already reported this one! Good job.");
        } else {
            alert("Too late! You already clicked a link in this email. Review the red flags instead.");
        }
        return;
    }

    // Success!
    stats.reported++;
    stats.history[data.id] = 'reported';
    saveStats();

    // Show Positive Feedback
    const feedbackPanel = document.getElementById('phishing-feedback');
    const feedbackTitle = document.getElementById('feedback-title');
    const feedbackText = document.getElementById('feedback-text');

    if (feedbackTitle) {
        feedbackTitle.innerText = "✅ Well Done!";
        feedbackTitle.style.color = "var(--accent-green)";
    }

    feedbackText.innerHTML = "You correctly identified this email as phishing and reported it. This is the #1 way to stop attacks in the real world.";
    feedbackPanel.hidden = false;
    feedbackPanel.style.border = "1px solid var(--accent-green)";
    feedbackPanel.style.background = "rgba(0, 255, 200, 0.1)";

    feedbackPanel.scrollIntoView({ behavior: 'smooth' });
    feedbackPanel.focus();
}

function resetStats() {
    if (confirm("Are you sure you want to reset your score?")) {
        stats.reported = 0;
        stats.missed = 0;
        stats.history = {};
        saveStats();
        renderScenario(currentScenarioIndex); // Re-render to clear visual state
        alert("Stats reset!");
    }
}

function handleMiss(riskType, riskText) {
    const data = scenarios[currentScenarioIndex];

    // If already categorized, don't punish again for same click
    if (!stats.history[data.id]) {
        stats.missed++;
        stats.history[data.id] = 'missed';
        saveStats();
    }

    const feedbackPanel = document.getElementById('phishing-feedback');
    const feedbackTitle = document.getElementById('feedback-title');
    const feedbackText = document.getElementById('feedback-text');

    if (feedbackTitle) {
        feedbackTitle.innerText = "⚠️ Risky Click!";
        feedbackTitle.style.color = "var(--accent-red)";
    }

    feedbackText.innerHTML = riskText;
    feedbackPanel.hidden = false;
    feedbackPanel.style.border = "1px solid var(--accent-red)";
    feedbackPanel.style.background = "rgba(255, 71, 87, 0.1)";
}

function renderScenario(index) {
    const container = document.getElementById('email-container');
    const feedbackPanel = document.getElementById('phishing-feedback');
    const counter = document.getElementById('scenario-counter');
    const feedbackTitle = document.getElementById('feedback-title');

    const data = scenarios[index];

    // Update Counter
    if (counter) counter.innerText = `Scenario ${index + 1}/${scenarios.length}`;

    // Render HTML
    container.innerHTML = `
        <div class="email-header">
            <div class="email-meta">
                <span class="label">From:</span> 
                <span class="suspicious clickable-element" data-risk="sender" role="button" tabindex="0">${data.from}</span>
            </div>
            <div class="email-meta">
                <span class="label">Subject:</span>
                <span class="suspicious clickable-element" data-risk="subject" role="button" tabindex="0">${data.subject}</span>
            </div>
        </div>
        <div class="email-body">
            ${data.body}
        </div>
    `;

    // Re-attach Event Listeners
    const triggers = container.querySelectorAll('.clickable-element');
    triggers.forEach(el => {
        el.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();

            const riskType = el.getAttribute('data-risk');
            handleMiss(riskType, data.risks[riskType]);

            feedbackPanel.scrollIntoView({ behavior: 'smooth' });
        });
    });

    // Hide and reset feedback
    feedbackPanel.hidden = true;
    feedbackPanel.style.border = "";
    feedbackPanel.style.background = "";

    if (feedbackTitle) {
        feedbackTitle.innerText = "Analysis Result";
        feedbackTitle.style.color = "";
    }

    // Visual indicator if completed
    if (stats.history[data.id] === 'reported') {
        container.style.opacity = '0.7';
        container.style.border = '2px solid var(--accent-green)';
    } else if (stats.history[data.id] === 'missed') {
        container.style.opacity = '0.7';
        container.style.border = '2px solid var(--accent-red)';
    } else {
        container.style.opacity = '1';
        container.style.border = '';
    }
}

// --- Password Strength Lab ---
function initPasswordSim() {
    const input = document.getElementById('password-input');
    const bar = document.getElementById('strength-bar');
    const text = document.getElementById('strength-text');

    // Rule Elements
    const rules = {
        length: document.getElementById('rule-length'),
        variety: document.getElementById('rule-variety'),
        case: document.getElementById('rule-case')
    };

    if (!input) return;

    input.addEventListener('input', (e) => {
        const password = e.target.value;
        let score = 0;

        // Check 1: Length
        const hasLength = password.length >= 12;
        updateRule(rules.length, hasLength);
        if (hasLength) score += 1;

        // Check 2: Numbers/Symbols
        const hasVariety = /[0-9!@#$%^&*]/.test(password);
        updateRule(rules.variety, hasVariety);
        if (hasVariety) score += 1;

        // Check 3: Case
        const hasCase = /[a-z]/.test(password) && /[A-Z]/.test(password);
        updateRule(rules.case, hasCase);
        if (hasCase) score += 1;

        // Update UI
        updateMeter(score, password.length);
    });

    function updateRule(element, isValid) {
        if (isValid) {
            element.classList.add('valid');
        } else {
            element.classList.remove('valid');
        }
    }

    function updateMeter(score, length) {
        let width = 0;
        let color = '#dc3545'; // Red
        let label = 'Critically Weak';

        if (length === 0) {
            width = 0;
            label = '';
        } else if (score === 0 || length < 8) {
            width = 25;
            color = '#dc3545'; // Red
            label = 'Weak';
        } else if (score === 1) {
            width = 50;
            color = '#ffc107'; // Yellow
            label = 'Moderate';
        } else if (score === 2) {
            width = 75;
            color = '#28a745'; // Green
            label = 'Strong';
        } else if (score === 3) {
            width = 100;
            color = '#28a745'; // Green
            label = 'Cyber Guard Approved!';
        }

        bar.style.width = `${width}%`;
        bar.style.backgroundColor = color;
        text.style.color = color;
        text.innerText = label;
    }
}

// --- Hygiene Checklist ---
function initChecklist() {
    const checkboxes = document.querySelectorAll('.checklist-item input[type="checkbox"]');

    // Load state
    checkboxes.forEach(box => {
        const savedState = localStorage.getItem(box.id);
        if (savedState === 'true') {
            box.checked = true;
        }

        // Save state on change
        box.addEventListener('change', () => {
            localStorage.setItem(box.id, box.checked);
        });
    });
}

// ========================================
// PHISHING ANALYZER MODULE
// ========================================

const URL_PATTERNS = {
    suspiciousTLDs: {
        pattern: /\.(xyz|tk|ml|ga|cf|top|pw|cc|club|click|link|site|online|icu|buzz|monster)$/i,
        severity: 'high',
        title: 'Suspicious TLD Detected',
        desc: 'This domain uses a TLD commonly associated with phishing campaigns.'
    },
    ipAddress: {
        pattern: /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
        severity: 'critical',
        title: 'IP Address URL',
        desc: 'Legitimate services use domain names, not raw IP addresses.'
    },
    typosquatting: {
        pattern: /(paypa1|g00gle|amaz0n|micros0ft|app1e|faceb00k|netfl1x|1nstagram|tw1tter|l1nkedin)/i,
        severity: 'critical',
        title: 'Typosquatting Detected',
        desc: 'The domain mimics a well-known brand using character substitution.'
    },
    excessiveSubdomains: {
        pattern: /^https?:\/\/([^\/]+\.){4,}/i,
        severity: 'medium',
        title: 'Excessive Subdomains',
        desc: 'Multiple subdomains can be used to hide the real domain.'
    },
    urlShortener: {
        pattern: /(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|short\.to)/i,
        severity: 'medium',
        title: 'URL Shortener',
        desc: 'Shortened URLs hide the true destination. Verify before clicking.'
    },
    noHTTPS: {
        pattern: /^http:\/\//i,
        severity: 'medium',
        title: 'No HTTPS',
        desc: 'Connection is not encrypted. Never enter credentials on HTTP sites.'
    },
    suspiciousKeywords: {
        pattern: /(verify|confirm|suspend|locked|urgent|update|secure|login|signin|account|password|credential)/i,
        severity: 'low',
        title: 'Suspicious Keywords in URL',
        desc: 'URL contains words commonly used in phishing attacks.'
    },
    dataURI: {
        pattern: /^data:/i,
        severity: 'critical',
        title: 'Data URI Attack',
        desc: 'Data URIs can embed malicious content. Never trust these links.'
    },
    atSymbol: {
        pattern: /^https?:\/\/[^\/]*@/i,
        severity: 'high',
        title: '@ Symbol in URL',
        desc: 'The @ symbol can hide the real domain. Everything before @ is ignored.'
    },
    hexEncoding: {
        pattern: /%[0-9a-f]{2}/i,
        severity: 'medium',
        title: 'URL Encoding Detected',
        desc: 'Encoded characters may be hiding malicious content.'
    }
};

const EMAIL_PATTERNS = {
    urgency: {
        pattern: /(urgent|immediately|right now|within 24 hours|act now|don't delay|time sensitive|expires today|last chance)/gi,
        severity: 'high',
        title: 'Urgency Tactics',
        desc: 'Creates artificial pressure to bypass rational thinking.'
    },
    threats: {
        pattern: /(suspend|terminate|locked|compromised|unauthorized|illegal|violation|permanently deleted|legal action)/gi,
        severity: 'high',
        title: 'Threat Language',
        desc: 'Uses fear to manipulate you into immediate action.'
    },
    credentialRequest: {
        pattern: /(verify your (password|identity|account)|confirm your (credentials|login)|enter your (password|ssn|credit card))/gi,
        severity: 'critical',
        title: 'Credential Harvesting',
        desc: 'Legitimate companies never ask for passwords via email.'
    },
    financialPressure: {
        pattern: /(payment required|invoice overdue|billing issue|update payment|wire transfer|bank account.*changed)/gi,
        severity: 'high',
        title: 'Financial Pressure',
        desc: 'BEC attacks often involve fake invoices or payment changes.'
    },
    genericGreeting: {
        pattern: /^(dear (customer|user|valued member|account holder|sir\/madam))/mi,
        severity: 'low',
        title: 'Generic Greeting',
        desc: 'Legitimate services usually address you by name.'
    },
    spoofedSender: {
        pattern: /(support@.*-update|security@.*-verify|admin@.*-portal|hr@.*-corp|it@.*-desk)/gi,
        severity: 'high',
        title: 'Suspicious Sender Pattern',
        desc: 'Email domain looks like it\'s trying to impersonate a legitimate service.'
    },
    clickHere: {
        pattern: /(click here|click below|click this link|click the link)/gi,
        severity: 'low',
        title: 'Suspicious Call to Action',
        desc: 'Phishing emails often use vague "click here" links.'
    },
    attachmentMention: {
        pattern: /(see attached|open the attachment|download.*attachment|attached.*invoice|attached.*document)/gi,
        severity: 'medium',
        title: 'Attachment Reference',
        desc: 'Be cautious of unexpected attachments - they may contain malware.'
    }
};

const RISK_WEIGHTS = {
    critical: 40,
    high: 25,
    medium: 15,
    low: 5
};

function initPhishingAnalyzer() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const urlPanel = document.getElementById('url-panel');
    const emailPanel = document.getElementById('email-panel');
    const btnAnalyzeUrl = document.getElementById('btn-analyze-url');
    const btnAnalyzeEmail = document.getElementById('btn-analyze-email');

    if (!tabBtns.length) return;

    // Tab switching
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            if (btn.dataset.tab === 'url') {
                urlPanel.style.display = 'block';
                emailPanel.style.display = 'none';
            } else {
                urlPanel.style.display = 'none';
                emailPanel.style.display = 'block';
            }

            // Hide results when switching tabs
            document.getElementById('analysis-results').hidden = true;
        });
    });

    // URL Analysis
    btnAnalyzeUrl.addEventListener('click', () => {
        const url = document.getElementById('url-input').value.trim();
        if (!url) {
            alert('Please enter a URL to analyze');
            return;
        }
        const results = analyzeURL(url);
        displayResults(results);
    });

    // Email Analysis
    btnAnalyzeEmail.addEventListener('click', () => {
        const email = document.getElementById('email-input').value.trim();
        if (!email) {
            alert('Please enter email content to analyze');
            return;
        }
        const results = analyzeEmail(email);
        displayResults(results);
    });
}

function analyzeURL(url) {
    const findings = [];
    let totalScore = 0;

    for (const [key, check] of Object.entries(URL_PATTERNS)) {
        if (check.pattern.test(url)) {
            findings.push({
                severity: check.severity,
                title: check.title,
                desc: check.desc
            });
            totalScore += RISK_WEIGHTS[check.severity];
        }
    }

    // Cap score at 100
    totalScore = Math.min(totalScore, 100);

    return { score: totalScore, findings };
}

function analyzeEmail(emailContent) {
    const findings = [];
    let totalScore = 0;

    for (const [key, check] of Object.entries(EMAIL_PATTERNS)) {
        const matches = emailContent.match(check.pattern);
        if (matches && matches.length > 0) {
            findings.push({
                severity: check.severity,
                title: check.title,
                desc: check.desc,
                matches: matches.slice(0, 3) // Show first 3 matches
            });
            totalScore += RISK_WEIGHTS[check.severity];
        }
    }

    // Cap score at 100
    totalScore = Math.min(totalScore, 100);

    return { score: totalScore, findings };
}

function displayResults(results) {
    const container = document.getElementById('analysis-results');
    const scoreCircle = document.getElementById('score-circle');
    const riskScore = document.getElementById('risk-score');
    const riskLabel = document.getElementById('risk-label');
    const findingsList = document.getElementById('findings-list');

    container.hidden = false;

    // Animate score
    let currentScore = 0;
    const targetScore = results.score;
    const duration = 500;
    const increment = targetScore / (duration / 16);

    const animateScore = () => {
        currentScore += increment;
        if (currentScore >= targetScore) {
            currentScore = targetScore;
            riskScore.textContent = Math.round(currentScore);
        } else {
            riskScore.textContent = Math.round(currentScore);
            requestAnimationFrame(animateScore);
        }
    };
    animateScore();

    // Set risk level styling
    scoreCircle.className = 'score-circle';
    if (results.score <= 20) {
        scoreCircle.classList.add('low');
        riskLabel.textContent = '✅ Low Risk - Likely Safe';
        riskLabel.style.color = 'var(--accent-green)';
    } else if (results.score <= 40) {
        scoreCircle.classList.add('medium');
        riskLabel.textContent = '⚠️ Medium Risk - Exercise Caution';
        riskLabel.style.color = '#ffc107';
    } else if (results.score <= 70) {
        scoreCircle.classList.add('high');
        riskLabel.textContent = '🔴 High Risk - Likely Phishing';
        riskLabel.style.color = '#ff6b35';
    } else {
        scoreCircle.classList.add('critical');
        riskLabel.textContent = '🚨 CRITICAL - Do Not Interact!';
        riskLabel.style.color = 'var(--accent-red)';
    }

    // Display findings
    findingsList.innerHTML = '';
    if (results.findings.length === 0) {
        findingsList.innerHTML = '<p style="color: var(--accent-green);">✓ No suspicious indicators detected</p>';
    } else {
        results.findings.forEach(finding => {
            const icon = finding.severity === 'critical' ? '🚨' :
                finding.severity === 'high' ? '⚠️' :
                    finding.severity === 'medium' ? '⚡' : 'ℹ️';

            findingsList.innerHTML += `
                <div class="finding-item ${finding.severity}">
                    <span class="finding-icon">${icon}</span>
                    <div class="finding-content">
                        <div class="finding-title">${finding.title}</div>
                        <div class="finding-desc">${finding.desc}</div>
                    </div>
                </div>
            `;
        });
    }

    // Scroll to results
    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ========================================
// API CONFIGURATION MODULE
// ========================================

const API_CONFIG = {
    vt: { name: 'VirusTotal', key: null, enabled: false },
    gsb: { name: 'Google Safe Browsing', key: null, enabled: false },
    pt: { name: 'PhishTank', key: null, enabled: false }
};

function initAPIConfig() {
    loadAPIKeys();

    // Save button listeners
    document.querySelectorAll('.btn-save-key').forEach(btn => {
        btn.addEventListener('click', () => {
            const apiId = btn.dataset.api;
            const input = document.getElementById(`${apiId}-api-key`);
            const key = input.value.trim();

            if (key) {
                saveAPIKey(apiId, key);
                input.value = '';
                input.placeholder = '••••••••••••••••';
            }
        });
    });

    // Toggle listeners
    ['vt', 'gsb', 'pt'].forEach(apiId => {
        const toggle = document.getElementById(`${apiId}-enabled`);
        if (toggle) {
            toggle.addEventListener('change', () => {
                API_CONFIG[apiId].enabled = toggle.checked;
                localStorage.setItem(`api_${apiId}_enabled`, toggle.checked);
            });
        }
    });
}

function loadAPIKeys() {
    ['vt', 'gsb', 'pt'].forEach(apiId => {
        const savedKey = localStorage.getItem(`api_${apiId}_key`);
        const savedEnabled = localStorage.getItem(`api_${apiId}_enabled`) === 'true';
        const statusEl = document.getElementById(`${apiId}-status`);
        const toggleEl = document.getElementById(`${apiId}-enabled`);
        const inputEl = document.getElementById(`${apiId}-api-key`);

        if (savedKey) {
            API_CONFIG[apiId].key = savedKey;
            API_CONFIG[apiId].enabled = savedEnabled;

            if (statusEl) {
                statusEl.textContent = 'Active ✓';
                statusEl.classList.add('active');
            }
            if (toggleEl) {
                toggleEl.disabled = false;
                toggleEl.checked = savedEnabled;
            }
            if (inputEl) {
                inputEl.placeholder = '••••••••••••••••';
            }
        }
    });
}

function saveAPIKey(apiId, key) {
    localStorage.setItem(`api_${apiId}_key`, key);
    localStorage.setItem(`api_${apiId}_enabled`, 'true');

    API_CONFIG[apiId].key = key;
    API_CONFIG[apiId].enabled = true;

    const statusEl = document.getElementById(`${apiId}-status`);
    const toggleEl = document.getElementById(`${apiId}-enabled`);

    if (statusEl) {
        statusEl.textContent = 'Active ✓';
        statusEl.classList.add('active');
    }
    if (toggleEl) {
        toggleEl.disabled = false;
        toggleEl.checked = true;
    }

    // Show confirmation
    alert(`${API_CONFIG[apiId].name} API key saved successfully!`);
}

// API Integration Functions (for future use when APIs are configured)
async function checkVirusTotal(url) {
    if (!API_CONFIG.vt.enabled || !API_CONFIG.vt.key) return null;

    try {
        const urlId = btoa(url).replace(/=/g, '');
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
            headers: { 'x-apikey': API_CONFIG.vt.key }
        });
        return await response.json();
    } catch (error) {
        console.error('VirusTotal API error:', error);
        return null;
    }
}

async function checkGoogleSafeBrowsing(url) {
    if (!API_CONFIG.gsb.enabled || !API_CONFIG.gsb.key) return null;

    try {
        const response = await fetch(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_CONFIG.gsb.key}`,
            {
                method: 'POST',
                body: JSON.stringify({
                    client: { clientId: 'cyberawareness', clientVersion: '1.0' },
                    threatInfo: {
                        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                        platformTypes: ['ANY_PLATFORM'],
                        threatEntryTypes: ['URL'],
                        threatEntries: [{ url: url }]
                    }
                })
            }
        );
        return await response.json();
    } catch (error) {
        console.error('Google Safe Browsing API error:', error);
        return null;
    }
}

async function checkPhishTank(url) {
    if (!API_CONFIG.pt.enabled || !API_CONFIG.pt.key) return null;

    // Note: PhishTank requires CORS proxy for browser-based calls
    console.log('PhishTank check would require server-side proxy');
    return null;
}
