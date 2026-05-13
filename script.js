document.addEventListener('DOMContentLoaded', () => {
    initPhishingSim();
    initPasswordSim();
    initChecklist();
    initPhishingAnalyzer();
    initAPIConfig();
    initThreatScanner();

    // Feedback close button (moved from inline onclick for CSP compliance)
    const closeFeedbackBtn = document.getElementById('btn-close-feedback');
    if (closeFeedbackBtn) {
        closeFeedbackBtn.addEventListener('click', () => {
            document.getElementById('phishing-feedback').hidden = true;
        });
    }

    // Launch course button (moved from inline onclick)
    const launchCourseBtn = document.getElementById('btn-launch-course');
    if (launchCourseBtn) {
        launchCourseBtn.addEventListener('click', () => {
            window.open(
                'https://securityawareness.dcsa.mil/cybersecurity/content/Block10/Introduction/page_0010.html',
                'CyberCourse',
                'width=1280,height=720,scrollbars=yes,resizable=yes,noopener,noreferrer'
            );
        });
    }
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
                <a href="#" class="btn btn-fake suspicious clickable-element" data-risk="link">Verify Now</a>
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
                <a href="#" class="btn btn-fake suspicious clickable-element" data-risk="doc">Download Invoice & Pay</a>
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
                <a href="#" class="btn btn-fake suspicious clickable-element" data-risk="link">Login to Workday</a>
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
                <a href="#" class="btn btn-fake suspicious clickable-element" data-risk="url">Deny Access</a>
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

// Cached DOM references for hot-path performance
let DOM_CACHE = {};

function initPhishingSim() {
    // Cache all repeatedly-accessed DOM elements upfront
    DOM_CACHE = {
        emailContainer: document.getElementById('email-container'),
        feedbackPanel: document.getElementById('phishing-feedback'),
        feedbackTitle: document.getElementById('feedback-title'),
        feedbackText: document.getElementById('feedback-text'),
        statReported: document.getElementById('stat-reported'),
        statMissed: document.getElementById('stat-missed'),
        scenarioCounter: document.getElementById('scenario-counter')
    };

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
    try {
        const saved = localStorage.getItem('cyberHubStats');
        if (!saved) return;
        const parsed = JSON.parse(saved);
        if (typeof parsed.reported === 'number') stats.reported = parsed.reported;
        if (typeof parsed.missed === 'number') stats.missed = parsed.missed;
        if (parsed.history && typeof parsed.history === 'object' && !Array.isArray(parsed.history)) {
            stats.history = Object.create(null);
            for (const [k, v] of Object.entries(parsed.history)) {
                if (v === 'reported' || v === 'missed') stats.history[k] = v;
            }
        }
    } catch (e) {
        console.warn('Failed to load stats, resetting:', e);
        localStorage.removeItem('cyberHubStats');
    }
}

function saveStats() {
    localStorage.setItem('cyberHubStats', JSON.stringify(stats));
    updateStatsUI();
}

function updateStatsUI() {
    DOM_CACHE.statReported.innerText = stats.reported;
    DOM_CACHE.statMissed.innerText = stats.missed;
}

function handleReport() {
    const data = scenarios[currentScenarioIndex];
    // Check if already interacted
    if (stats.history[data.id]) {
        if (stats.history[data.id] === 'reported') {
            if(typeof showToast==='function')showToast('You already reported this one! Good job.','success');else alert('You already reported this one!');
        } else {
            if(typeof showToast==='function')showToast('Too late! You already clicked a link. Review the red flags.','warning');else alert('Too late!');
        }
        return;
    }

    // Success!
    stats.reported++;
    stats.history[data.id] = 'reported';
    saveStats();

    // Show Positive Feedback
    const { feedbackPanel, feedbackTitle, feedbackText } = DOM_CACHE;

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
        renderScenario(currentScenarioIndex);
        if(typeof showToast==='function')showToast('Stats reset!','info');else alert('Stats reset!');
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

    const { feedbackPanel, feedbackTitle, feedbackText } = DOM_CACHE;

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
    const { emailContainer: container, feedbackPanel, scenarioCounter: counter, feedbackTitle } = DOM_CACHE;

    const data = scenarios[index];

    // Update Counter
    if (counter) counter.innerText = `Scenario ${index + 1}/${scenarios.length}`;

    // Render HTML
    container.innerHTML = `
        <div class="email-header">
            <div class="email-meta">
                <span class="label">From:</span> 
                <span class="suspicious clickable-element" data-risk="sender" role="button" tabindex="0">${escHtml(data.from)}</span>
            </div>
            <div class="email-meta">
                <span class="label">Subject:</span>
                <span class="suspicious clickable-element" data-risk="subject" role="button" tabindex="0">${escHtml(data.subject)}</span>
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

    // Password visibility toggle
    const toggleBtn = document.getElementById('toggle-pw-visibility');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';
            toggleBtn.textContent = isPassword ? '🙈' : '👁️';
        });
    }

    let debounceTimer = null;
    input.addEventListener('input', (e) => {
        if (debounceTimer) cancelAnimationFrame(debounceTimer);
        debounceTimer = requestAnimationFrame(() => {
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

const DANGEROUS_FILE_EXTENSIONS = /\.(exe|scr|bat|cmd|vbs|js|ps1|msi|dll|pif|com|hta|wsf)$/i;
const DOUBLE_FILE_EXTENSIONS = /\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|bat|cmd|vbs|js|ps1|msi|dll|pif|hta|wsf)$/i;

const URL_PATTERNS = {
    suspiciousTLDs: {
        pattern: /\.(xyz|tk|ml|ga|cf|top|pw|cc|club|click|link|site|online|icu|buzz|monster)$/i,
        severity: 'high',
        title: 'Suspicious TLD Detected',
        desc: 'This domain uses a TLD commonly associated with phishing campaigns.',
        category: 'domain'
    },
    ipAddress: {
        pattern: /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
        severity: 'critical',
        title: 'IP Address URL',
        desc: 'Legitimate services use domain names, not raw IP addresses.',
        category: 'domain'
    },
    typosquatting: {
        pattern: /(paypa1|g00gle|amaz0n|micros0ft|app1e|faceb00k|netfl1x|1nstagram|tw1tter|l1nkedin)/i,
        severity: 'critical',
        title: 'Typosquatting Detected',
        desc: 'The domain mimics a well-known brand using character substitution.',
        category: 'impersonation'
    },
    excessiveSubdomains: {
        pattern: /^https?:\/\/([^\/]+\.){4,}/i,
        severity: 'medium',
        title: 'Excessive Subdomains',
        desc: 'Multiple subdomains can be used to hide the real domain.',
        category: 'domain'
    },
    urlShortener: {
        pattern: /(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|short\.to)/i,
        severity: 'low',
        title: 'URL Shortener',
        desc: 'Shortened URLs hide the true destination. Verify before clicking.',
        category: 'obfuscation'
    },
    noHTTPS: {
        pattern: /^http:\/\//i,
        severity: 'low',
        title: 'No HTTPS',
        desc: 'Connection is not encrypted. Avoid entering credentials on HTTP sites.',
        category: 'transport'
    },
    suspiciousKeywords: {
        pattern: /\/(verify-account|confirm-identity|suspend|locked-account|urgent-update|signin-required|credential-reset)/i,
        severity: 'medium',
        title: 'Suspicious Path Keywords',
        desc: 'URL path contains action-word combos commonly used in phishing lures.',
        category: 'content'
    },
    dataURI: {
        pattern: /^data:/i,
        severity: 'critical',
        title: 'Data URI Attack',
        desc: 'Data URIs can embed malicious content. Never trust these links.',
        category: 'obfuscation'
    },
    atSymbol: {
        pattern: /^https?:\/\/[^\/]*@/i,
        severity: 'high',
        title: '@ Symbol in URL',
        desc: 'The @ symbol can hide the real domain. Everything before @ is ignored.',
        category: 'obfuscation'
    },
    homoglyphDomain: {
        pattern: /xn--/i,
        severity: 'high',
        title: 'Internationalized Domain (Punycode)',
        desc: 'Domain uses non-ASCII characters that can visually mimic legitimate domains.',
        category: 'impersonation'
    },
    cousinDomain: {
        pattern: /(paypal|google|amazon|microsoft|apple|facebook|netflix|instagram|twitter|linkedin|dropbox|chase|wellsfargo|bankofamerica|citibank)[\-_.](secure|login|verify|update|alert|support|help|service|center|portal|team)/i,
        severity: 'critical',
        title: 'Cousin/Lookalike Domain',
        desc: 'Domain uses a known brand name combined with a deceptive suffix — high confidence phishing.',
        category: 'impersonation'
    },
    doubleExtension: {
        pattern: /\.(pdf|doc|xls|jpg|png)\.(exe|scr|bat|cmd|vbs|js|ps1|hta|wsf)/i,
        severity: 'critical',
        title: 'Double File Extension in URL',
        desc: 'URL links to a file with double extension (e.g., invoice.pdf.exe) — malware delivery technique.',
        category: 'delivery'
    },
    embeddedCredentials: {
        pattern: /^https?:\/\/[^:]+:[^@]+@/i,
        severity: 'critical',
        title: 'Embedded Credentials in URL',
        desc: 'URL contains username:password@ format — used to trick browsers into displaying fake domains.',
        category: 'obfuscation'
    },
    suspiciousPort: {
        pattern: /^https?:\/\/[^/]+:((?!80|443)\d{2,5})\//i,
        severity: 'medium',
        title: 'Non-Standard Port',
        desc: 'URL uses a non-standard port — legitimate sites rarely use custom ports for user-facing pages.',
        category: 'domain'
    }
};

const EMAIL_PATTERNS = {
    urgency: {
        pattern: /(act now|within 24 hours|don't delay|time sensitive|expires today|last chance|final warning|respond immediately)/gi,
        severity: 'medium',
        title: 'Urgency Tactics',
        desc: 'Creates artificial time pressure — a common social engineering technique.',
        category: 'manipulation',
        minMatches: 1
    },
    threats: {
        pattern: /(your account will be (suspended|terminated|locked|deleted)|unauthorized access detected|illegal activity|permanently deleted|legal action will be taken)/gi,
        severity: 'high',
        title: 'Threat Language',
        desc: 'Uses fear of consequences to pressure immediate action.',
        category: 'manipulation',
        minMatches: 1
    },
    credentialRequest: {
        pattern: /(verify your (password|identity|account)|confirm your (credentials|login|password)|enter your (password|ssn|credit card|social security))/gi,
        severity: 'critical',
        title: 'Credential Harvesting',
        desc: 'Legitimate companies never ask for passwords or sensitive data via email.',
        category: 'harvesting',
        minMatches: 1
    },
    financialPressure: {
        pattern: /(wire transfer|bank account.*(changed|updated)|update.*(payment|billing).*(method|info|details)|send.*gift card)/gi,
        severity: 'high',
        title: 'Financial Pressure / BEC Indicator',
        desc: 'Business Email Compromise attacks involve payment redirection or gift card scams.',
        category: 'financial',
        minMatches: 1
    },
    genericGreeting: {
        pattern: /^(dear (customer|user|valued member|account holder|sir\/madam))/mi,
        severity: 'info',
        title: 'Generic Greeting',
        desc: 'Legitimate services usually address you by name. Weak signal on its own.',
        category: 'style',
        minMatches: 1
    },
    spoofedSender: {
        pattern: /(support@.*-update|security@.*-verify|admin@.*-portal|hr@.*-corp|it@.*-desk)/gi,
        severity: 'high',
        title: 'Suspicious Sender Pattern',
        desc: 'Sender domain looks constructed to impersonate a legitimate service.',
        category: 'impersonation',
        minMatches: 1
    },
    clickHere: {
        pattern: /(click here|click below|click this link|click the link)/gi,
        severity: 'info',
        title: 'Vague Call to Action',
        desc: 'Vague "click here" links are common in phishing but also in marketing emails. Weak signal alone.',
        category: 'style',
        minMatches: 2
    },
    attachmentMention: {
        pattern: /(open the attachment|download.*attachment|enable (macro|content|editing))/gi,
        severity: 'medium',
        title: 'Suspicious Attachment Reference',
        desc: 'Asks to open/download attachments or enable macros — common malware delivery.',
        category: 'delivery',
        minMatches: 1
    },
    embeddedForm: {
        pattern: /<form[^>]*action\s*=|<input[^>]*type\s*=\s*["']password/gi,
        severity: 'critical',
        title: 'Embedded HTML Form',
        desc: 'Email contains an HTML form (possibly with password field) — classic credential harvesting technique.',
        category: 'harvesting',
        minMatches: 1
    },
    authorityImpersonation: {
        pattern: /(from the (IT department|CEO|CFO|HR department|legal team|security team)|on behalf of (management|the board|your (bank|provider)))/gi,
        severity: 'medium',
        title: 'Authority Impersonation',
        desc: 'Claims to be from a position of authority — social engineering tactic to gain trust.',
        category: 'manipulation',
        minMatches: 1
    },
    rewardLure: {
        pattern: /(you('ve| have) (won|been selected)|congratulations.*winner|claim your (prize|reward|gift)|free.*gift.*card)/gi,
        severity: 'high',
        title: 'Reward / Prize Lure',
        desc: 'Offers unexpected prizes or rewards — a classic bait-and-hook phishing tactic.',
        category: 'manipulation',
        minMatches: 1
    },
    obfuscatedLinks: {
        pattern: /href\s*=\s*["'][^"']*["'][^>]*>\s*(https?:\/\/(?!.*\1)[^\s<]+)/gi,
        severity: 'high',
        title: 'Mismatched Link Text',
        desc: 'Displayed URL text differs from the actual href destination — link masking technique.',
        category: 'obfuscation',
        minMatches: 1
    }
};

const RISK_WEIGHTS = {
    critical: 35,
    high: 20,
    medium: 10,
    low: 5,
    info: 2
};

// Diminishing returns — prevents score stacking from weak signals
function calculateRiskScore(findings) {
    if (findings.length === 0) return 0;
    const categoryScores = {};
    let totalScore = 0;

    // Sort by severity (critical first) so highest-impact findings count first
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...findings].sort((a, b) => (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4));

    for (const f of sorted) {
        const weight = RISK_WEIGHTS[f.severity] || 0;
        const cat = f.category || 'general';

        // First finding in category gets full weight, subsequent get 40% (diminishing returns)
        if (!categoryScores[cat]) {
            categoryScores[cat] = 1;
            totalScore += weight;
        } else {
            categoryScores[cat]++;
            totalScore += Math.round(weight * 0.4);
        }
    }

    // Require signal convergence for high scores
    // Single-category findings can't exceed 50 alone — need cross-category evidence
    const uniqueCategories = Object.keys(categoryScores).filter(c => c !== 'style');
    if (uniqueCategories.length <= 1 && totalScore > 50) {
        totalScore = 50;
    }

    return Math.min(totalScore, 100);
}

function initPhishingAnalyzer() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const urlPanel = document.getElementById('url-panel');
    const emailPanel = document.getElementById('email-panel');
    const btnAnalyzeUrl = document.getElementById('btn-analyze-url');
    const btnAnalyzeEmail = document.getElementById('btn-analyze-email');

    if (!tabBtns.length) return;

    // Tab switching (URL / Email)
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
            document.getElementById('analysis-results').hidden = true;
        });
    });

    // URL Analysis
    btnAnalyzeUrl.addEventListener('click', () => {
        const url = document.getElementById('url-input').value.trim();
        if (!url) { if(typeof showToast==='function')showToast('Please enter a URL to analyze','warning');else alert('Please enter a URL'); return; }
        displayResults(analyzeURL(url));
    });

    // === EMAIL FORENSICS WIRING ===
    const uploadZone = document.getElementById('eml-upload-zone');
    const pasteArea = document.getElementById('email-paste-area');
    const forensicsView = document.getElementById('email-forensics');
    const fileInput = document.getElementById('eml-file-input');

    // Browse file button
    document.getElementById('btn-browse-eml').addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });

    // Paste toggle
    document.getElementById('btn-paste-toggle').addEventListener('click', (e) => {
        e.stopPropagation();
        uploadZone.style.display = 'none';
        pasteArea.style.display = 'block';
    });

    // Back button
    document.getElementById('btn-back-upload').addEventListener('click', () => {
        pasteArea.style.display = 'none';
        uploadZone.style.display = 'block';
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleEMLUpload(e.target.files[0]);
    });

    // Drag and drop
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('drag-over');
    });
    uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) handleEMLUpload(e.dataTransfer.files[0]);
    });

    // Analyze pasted email
    btnAnalyzeEmail.addEventListener('click', () => {
        const raw = document.getElementById('email-input').value.trim();
        if (!raw) { if(typeof showToast==='function')showToast('Please paste email content to analyze','warning');else alert('Paste email content'); return; }
        runEmailForensics(raw);
    });

    // New analysis button
    document.getElementById('btn-new-analysis').addEventListener('click', () => {
        forensicsView.style.display = 'none';
        uploadZone.style.display = 'block';
        pasteArea.style.display = 'none';
        document.getElementById('email-input').value = '';
        fileInput.value = '';
    });

    // Resolve button
    document.getElementById('btn-resolve-email').addEventListener('click', (e) => {
        const btn = e.currentTarget;
        if (!btn.classList.contains('resolved')) {
            btn.classList.add('resolved');
            btn.innerHTML = '✅ Resolved';
        }
    });

    // Forensics tab switching
    document.querySelectorAll('.f-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.f-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            document.querySelectorAll('.ftab-panel').forEach(p => p.classList.remove('active'));
            const target = document.querySelector(`.ftab-panel[data-fp="${tab.dataset.ftab}"]`);
            if (target) target.classList.add('active');
        });
    });

    // Body tab switching
    document.querySelectorAll('.body-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.body-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            document.querySelectorAll('.btab-panel').forEach(p => p.classList.remove('active'));
            const target = document.querySelector(`.btab-panel[data-bp="${tab.dataset.btab}"]`);
            if (target) target.classList.add('active');
        });
    });
}

function analyzeURL(url) {
    const MAX_URL_LENGTH = 10000;
    if (url.length > MAX_URL_LENGTH) {
        return { score: 0, findings: [{ severity: 'info', title: 'Input Too Large', desc: 'URL exceeds maximum length for analysis.', category: 'general' }] };
    }
    const findings = [];

    for (const [key, check] of Object.entries(URL_PATTERNS)) {
        if (check.pattern.test(url)) {
            findings.push({
                severity: check.severity,
                title: check.title,
                desc: check.desc,
                category: check.category || 'general'
            });
        }
    }

    return { score: calculateRiskScore(findings), findings };
}

function analyzeEmail(emailContent) {
    const MAX_EMAIL_LENGTH = 500000;
    if (emailContent.length > MAX_EMAIL_LENGTH) {
        return { score: 0, findings: [{ severity: 'info', title: 'Input Too Large', desc: 'Email content exceeds maximum length for analysis.', category: 'general' }] };
    }
    const findings = [];

    for (const [key, check] of Object.entries(EMAIL_PATTERNS)) {
        const matches = emailContent.match(check.pattern);
        const minRequired = check.minMatches || 1;
        if (matches && matches.length >= minRequired) {
            findings.push({
                severity: check.severity,
                title: check.title,
                desc: check.desc,
                category: check.category || 'general',
                matches: matches.slice(0, 3)
            });
        }
    }

    return { score: calculateRiskScore(findings), findings };
}

function displayResults(results) {
    const container = document.getElementById('analysis-results');
    const scoreCircle = document.getElementById('score-circle');
    const riskScore = document.getElementById('risk-score');
    const riskLabel = document.getElementById('risk-label');
    const findingsList = document.getElementById('findings-list');

    container.hidden = false;

    // Animate score (guard against zero to prevent infinite requestAnimationFrame loop)
    const targetScore = results.score;
    if (targetScore === 0) {
        riskScore.textContent = '0';
    } else {
        let currentScore = 0;
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
    }

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
        findingsList.innerHTML = results.findings.map(finding => {
            const icon = finding.severity === 'critical' ? '🚨' :
                finding.severity === 'high' ? '⚠️' :
                    finding.severity === 'medium' ? '⚡' : 'ℹ️';

            return `
                <div class="finding-item ${escHtml(finding.severity)}">
                    <span class="finding-icon">${icon}</span>
                    <div class="finding-content">
                        <div class="finding-title">${escHtml(finding.title)}</div>
                        <div class="finding-desc">${escHtml(finding.desc)}</div>
                    </div>
                </div>
            `;
        }).join('');
    }

    // Scroll to results
    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ========================================
// EMAIL FORENSICS MODULE
// ========================================

function decodeQuotedPrintable(str) {
    return str.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16)));
}

function parseEMLContent(rawText) {
    const r = {
        headers: {}, from: '', fromEmail: '', fromName: '', to: '', cc: '', bcc: '',
        subject: '', date: '', replyTo: '', returnPath: '', messageId: '', inReplyTo: '',
        sender: '', receivedHeaders: [], authResults: '', xHeaders: {},
        bodyPlain: '', bodyHtml: '', rawSource: rawText, attachments: [], urls: [],
        originatingIP: '', rdns: '', spf: 'none', dkim: 'none', dmarc: 'none',
        displayName: '', contentType: ''
    };

    const splitIdx = rawText.indexOf('\r\n\r\n') !== -1
        ? rawText.indexOf('\r\n\r\n') : rawText.indexOf('\n\n');

    if (splitIdx === -1) { r.bodyPlain = rawText; return r; }

    const headerSection = rawText.substring(0, splitIdx);
    const bodySection = rawText.substring(splitIdx).trim();

    // Parse headers with continuation lines
    const lines = headerSection.split(/\r?\n/);
    let curKey = '', curVal = '';
    const allH = [];

    for (const line of lines) {
        if (/^\s/.test(line) && curKey) {
            curVal += ' ' + line.trim();
        } else {
            if (curKey) allH.push({ key: curKey, value: curVal });
            const ci = line.indexOf(':');
            if (ci > 0) { curKey = line.substring(0, ci).trim(); curVal = line.substring(ci + 1).trim(); }
        }
    }
    if (curKey) allH.push({ key: curKey, value: curVal });

    for (const h of allH) {
        const k = h.key.toLowerCase();
        r.headers[h.key] = h.value;
        switch (k) {
            case 'from':
                r.from = h.value;
                const fm = h.value.match(/(?:"?([^"]*)"?\s)?<?([^>\s]+@[^>\s]+)>?/);
                if (fm) { r.fromName = (fm[1] || '').trim(); r.fromEmail = fm[2] || h.value; }
                else r.fromEmail = h.value;
                r.displayName = r.fromName || r.fromEmail;
                break;
            case 'to': r.to = h.value; break;
            case 'cc': r.cc = h.value; break;
            case 'subject': r.subject = h.value; break;
            case 'date': r.date = h.value; break;
            case 'reply-to': r.replyTo = h.value.replace(/[<>]/g, '').trim(); break;
            case 'return-path': r.returnPath = h.value.replace(/[<>]/g, '').trim(); break;
            case 'message-id': r.messageId = h.value; break;
            case 'in-reply-to': r.inReplyTo = h.value; break;
            case 'sender': r.sender = h.value; break;
            case 'received': r.receivedHeaders.push(h.value); break;
            case 'authentication-results': r.authResults += ' ' + h.value; break;
            case 'content-type': r.contentType = h.value; break;
            default: if (k.startsWith('x-')) r.xHeaders[h.key] = h.value; break;
        }
    }

    // Parse auth results
    if (r.authResults) {
        const sm = r.authResults.match(/spf=(\w+)/i);
        const dm = r.authResults.match(/dkim=(\w+)/i);
        const dmm = r.authResults.match(/dmarc=(\w+)/i);
        if (sm) r.spf = sm[1].toLowerCase();
        if (dm) r.dkim = dm[1].toLowerCase();
        if (dmm) r.dmarc = dmm[1].toLowerCase();
    }
    const rspf = allH.find(h => h.key.toLowerCase() === 'received-spf');
    if (rspf && r.spf === 'none') {
        const m = rspf.value.match(/^(\w+)/);
        if (m) r.spf = m[1].toLowerCase();
    }

    // Extract originating IP
    if (r.receivedHeaders.length > 0) {
        const last = r.receivedHeaders[r.receivedHeaders.length - 1];
        const ipm = last.match(/\[?([\d]+\.[\d]+\.[\d]+\.[\d]+)\]?/);
        if (ipm) r.originatingIP = ipm[1];
        const rdm = last.match(/from\s+([\w\-.]+)/i);
        if (rdm) r.rdns = rdm[1];
    }

    // Parse body (MIME or plain)
    if (r.contentType && r.contentType.includes('multipart')) {
        const bm = r.contentType.match(/boundary="?([^";\s]+)"?/i);
        if (bm) {
            const boundary = bm[1];
            const re = new RegExp('--' + boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
            const parts = bodySection.split(re);
            for (const part of parts) {
                if (!part.trim() || part.trim() === '--') continue;
                const ps = part.indexOf('\n\n') !== -1 ? part.indexOf('\n\n') : part.indexOf('\r\n\r\n');
                if (ps === -1) continue;
                const pH = part.substring(0, ps).trim();
                let pB = part.substring(ps).trim();
                const pCT = pH.match(/Content-Type:\s*([^;\r\n]+)/i);
                const pCTE = pH.match(/Content-Transfer-Encoding:\s*(\S+)/i);
                const pDisp = pH.match(/Content-Disposition:\s*attachment[^]*?filename="?([^";\r\n]+)"?/i);

                if (pDisp) {
                    r.attachments.push({ name: pDisp[1].trim(), type: pCT ? pCT[1].trim() : 'unknown' });
                    continue;
                }
                if (pCTE) {
                    const enc = pCTE[1].toLowerCase();
                    if (enc === 'base64') { try { pB = atob(pB.replace(/\s/g, '')); } catch (e) { } }
                    else if (enc === 'quoted-printable') pB = decodeQuotedPrintable(pB);
                }
                if (pCT) {
                    const t = pCT[1].toLowerCase().trim();
                    if (t.includes('text/plain') && !r.bodyPlain) r.bodyPlain = pB;
                    else if (t.includes('text/html') && !r.bodyHtml) r.bodyHtml = pB;
                }
            }
        }
    } else {
        if (r.contentType && r.contentType.includes('text/html')) r.bodyHtml = bodySection;
        else r.bodyPlain = bodySection;
    }

    if (!r.bodyPlain && r.bodyHtml) {
        r.bodyPlain = r.bodyHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    }
    if (!r.bodyHtml && r.bodyPlain) {
        r.bodyHtml = '<pre>' + r.bodyPlain.replace(/</g, '&lt;') + '</pre>';
    }

    // Extract URLs from body
    const urlRe = /https?:\/\/[^\s"'<>\)]+/gi;
    const bodyText = (r.bodyHtml || '') + ' ' + (r.bodyPlain || '');
    const found = bodyText.match(urlRe);
    if (found) r.urls = [...new Set(found)];

    return r;
}

function analyzeHeaders(parsed) {
    const findings = [];
    const fromDomain = parsed.fromEmail.split('@')[1] || '';

    // From vs Reply-To mismatch — only flag if Reply-To uses a free provider or looks suspicious
    if (parsed.replyTo) {
        const rtDomain = parsed.replyTo.split('@')[1] || '';
        const freeProviders = /gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|protonmail\.com|aol\.com|yandex\.com|mail\.ru/i;
        if (rtDomain && fromDomain && rtDomain.toLowerCase() !== fromDomain.toLowerCase()) {
            // Higher severity if corporate From + free Reply-To (classic BEC pattern)
            const isSuspicious = freeProviders.test(rtDomain) && !freeProviders.test(fromDomain);
            findings.push({
                severity: isSuspicious ? 'high' : 'medium',
                title: 'Reply-To Mismatch',
                desc: isSuspicious
                    ? `Corporate sender "${fromDomain}" routes replies to free provider "${rtDomain}". Strong phishing indicator.`
                    : `Reply-To domain "${rtDomain}" differs from sender "${fromDomain}". May be legitimate (e.g., newsletters).`,
                category: isSuspicious ? 'impersonation' : 'header'
            });
        }
    }

    // Return-Path mismatch
    if (parsed.returnPath) {
        const rpDomain = parsed.returnPath.split('@')[1] || '';
        if (rpDomain && fromDomain && rpDomain.toLowerCase() !== fromDomain.toLowerCase()) {
            findings.push({ severity: 'medium', title: 'Return-Path Mismatch',
                desc: `Return-Path domain "${rpDomain}" differs from From domain "${fromDomain}".`,
                category: 'header' });
        }
    }

    // SPF/DKIM/DMARC failures
    if (parsed.spf === 'fail' || parsed.spf === 'softfail') {
        findings.push({ severity: 'critical', title: 'SPF Failed',
            desc: 'Sender Policy Framework check failed. Email may be spoofed.',
            category: 'authentication' });
    }
    if (parsed.dkim === 'fail') {
        findings.push({ severity: 'critical', title: 'DKIM Failed',
            desc: 'DKIM signature verification failed. Email integrity compromised.',
            category: 'authentication' });
    }
    if (parsed.dmarc === 'fail') {
        findings.push({ severity: 'critical', title: 'DMARC Failed',
            desc: 'DMARC policy check failed. High spoofing probability.',
            category: 'authentication' });
    }

    // Suspicious from domain
    if (fromDomain && URL_PATTERNS.typosquatting.pattern.test(fromDomain)) {
        findings.push({ severity: 'critical', title: 'Typosquatting in Sender',
            desc: `Domain "${fromDomain}" appears to impersonate a known brand.`,
            category: 'impersonation' });
    }

    // Dangerous attachments
    const dangerousExts = DANGEROUS_FILE_EXTENSIONS;
    const doubleExt = DOUBLE_FILE_EXTENSIONS;
    parsed.attachments.forEach(att => {
        if (doubleExt.test(att.name)) {
            findings.push({ severity: 'critical', title: 'Double Extension Attachment',
                desc: `"${att.name}" uses a double file extension to disguise an executable as a document.`,
                category: 'delivery' });
        } else if (dangerousExts.test(att.name)) {
            findings.push({ severity: 'critical', title: 'Dangerous Attachment',
                desc: `"${att.name}" is an executable file type commonly used for malware.`,
                category: 'delivery' });
        }
    });

    // Display Name Spoofing — display name contains a known brand but email is from different domain
    const brandNames = /(paypal|google|amazon|microsoft|apple|facebook|netflix|instagram|twitter|linkedin|dropbox|chase|wells\s?fargo|bank of america|citibank|security|helpdesk|support team)/i;
    if (parsed.fromName && brandNames.test(parsed.fromName)) {
        const brandMatch = parsed.fromName.match(brandNames)[0].toLowerCase().replace(/\s/g, '');
        // If the domain doesn't actually belong to that brand, it's spoofing
        const domainLower = fromDomain.toLowerCase();
        const brandInDomain = domainLower.includes(brandMatch) || domainLower.includes(brandMatch.replace('wellsfargo', 'wellsfargo'));
        if (!brandInDomain) {
            findings.push({ severity: 'high', title: 'Display Name Spoofing',
                desc: `Display name "${parsed.fromName}" impersonates a known brand but email is from "${fromDomain}".`,
                category: 'impersonation' });
        }
    }

    // Missing or empty subject
    if (!parsed.subject || parsed.subject.trim().length === 0) {
        findings.push({ severity: 'low', title: 'Missing Subject',
            desc: 'Email has no subject line — uncommon for legitimate business correspondence.',
            category: 'style' });
    }

    // Received chain anomaly — no received headers at all (locally crafted)
    if (parsed.receivedHeaders.length === 0 && parsed.from) {
        findings.push({ severity: 'medium', title: 'No Received Headers',
            desc: 'Email has no Received headers — may have been locally crafted rather than sent through mail servers.',
            category: 'header' });
    }

    // Too many hops — unusual routing
    if (parsed.receivedHeaders.length > 8) {
        findings.push({ severity: 'low', title: 'Excessive Mail Hops',
            desc: `Email passed through ${parsed.receivedHeaders.length} servers — unusual routing, may indicate relay abuse.`,
            category: 'header' });
    }

    // Sender domain age indicator — newly-created looking domains (lots of dashes or numbers)
    if ((fromDomain && /[\d]{4,}/.test(fromDomain)) || (fromDomain && (fromDomain.match(/-/g) || []).length >= 3)) {
        findings.push({ severity: 'medium', title: 'Suspicious Domain Structure',
            desc: `Domain "${fromDomain}" contains many numbers or hyphens — pattern common in disposable phishing domains.`,
            category: 'domain' });
    }

    return findings;
}

function handleEMLUpload(file) {
    const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    if (file.size > MAX_FILE_SIZE) {
        if(typeof showToast==='function')showToast('File too large. Maximum size is 10MB.','error');else alert('File too large.');
        return;
    }
    if (!file.name.match(/\.(eml|txt|msg)$/i)) {
        if(typeof showToast==='function')showToast('Invalid file type. Please upload .eml or .txt files.','error');else alert('Invalid file type.');
        return;
    }
    const reader = new FileReader();
    reader.onload = (e) => runEmailForensics(e.target.result);
    reader.readAsText(file);
}

function runEmailForensics(rawText) {
    const parsed = parseEMLContent(rawText);
    const headerFindings = analyzeHeaders(parsed);
    const bodyText = parsed.bodyPlain || parsed.bodyHtml || '';
    const contentResults = analyzeEmail(bodyText);

    // Deduplicate by title (header + content analysis may overlap)
    const seenTitles = new Set();
    const allFindings = [];
    for (const f of [...headerFindings, ...contentResults.findings]) {
        if (!seenTitles.has(f.title)) {
            seenTitles.add(f.title);
            allFindings.push(f);
        }
    }

    const totalScore = calculateRiskScore(allFindings);
    renderForensicsView(parsed, { score: totalScore, findings: allFindings });

    // Track email analysis count for Forensic Analyst badge
    const emailCount = parseInt(localStorage.getItem('cyberHubEmailsAnalyzed') || '0') + 1;
    localStorage.setItem('cyberHubEmailsAnalyzed', emailCount);
    if (typeof checkBadges === 'function') checkBadges();
}

function escHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;');
}

function statusClass(val) {
    if (!val || val === 'none') return 'st-neutral';
    if (val === 'pass') return 'st-safe';
    if (val === 'fail' || val === 'softfail') return 'st-danger';
    return 'st-warn';
}

function badgeHtml(val) {
    if (!val || val === 'none') return '<span class="meta-badge badge-none">None</span>';
    if (val === 'pass') return '<span class="meta-badge badge-pass">Pass</span>';
    return '<span class="meta-badge badge-fail">' + escHtml(val) + '</span>';
}

function renderForensicsView(parsed, analysis) {
    // Show forensics, hide upload/paste
    document.getElementById('eml-upload-zone').style.display = 'none';
    document.getElementById('email-paste-area').style.display = 'none';
    const fv = document.getElementById('email-forensics');
    fv.style.display = 'block';

    // Reset resolve button
    const rb = document.getElementById('btn-resolve-email');
    rb.classList.remove('resolved');
    rb.innerHTML = '✅ Resolve';

    // Subject
    document.getElementById('f-subject').textContent = (parsed.subject || 'No Subject') + ' 📎';
    document.getElementById('f-subject-crumb').textContent = parsed.subject || 'Email Analysis';

    // === DETAILS TAB ===
    const fromStatus = analysis.findings.some(f => f.title.includes('Typosquatting') || f.title.includes('Reply-To Mismatch')) ? 'st-warn' : 'st-safe';
    const replyStatus = parsed.replyTo ? (analysis.findings.some(f => f.title === 'Reply-To Mismatch' || f.title === 'Free Email in Reply-To') ? 'st-danger' : 'st-safe') : 'st-neutral';
    const rpStatus = analysis.findings.some(f => f.title === 'Return-Path Mismatch') ? 'st-warn' : (parsed.returnPath ? 'st-safe' : 'st-neutral');

    const detailRows = [
        { status: fromStatus, label: 'From', value: `<span class="flag-icon">🏳️</span> ${escHtml(parsed.from || 'N/A')}`, actions: '⋯' },
        { status: 'st-neutral', label: 'Display name', value: escHtml(parsed.displayName || 'None') },
        { status: 'st-neutral', label: 'Sender', value: escHtml(parsed.sender || 'None') },
        { status: 'st-neutral', label: 'To', value: escHtml(parsed.to || 'N/A') },
        { status: 'st-neutral', label: 'Cc', value: escHtml(parsed.cc || 'None') },
        { status: 'st-neutral', label: 'In-Reply-To', value: escHtml(parsed.inReplyTo || 'None') },
        { status: 'st-neutral', label: 'Timestamp', value: escHtml(parsed.date || 'N/A') },
        { status: replyStatus, label: 'Reply-To', value: parsed.replyTo ? `<span class="flag-icon">${replyStatus === 'st-danger' ? '🔴' : '🏳️'}</span> ${escHtml(parsed.replyTo)}` : 'None', actions: parsed.replyTo ? '⋯' : '' },
        { status: 'st-neutral', label: 'Message-ID', value: `<span style="font-size:0.78rem;color:var(--text-muted);word-break:break-all;">${escHtml(parsed.messageId || 'N/A')}</span>` },
        { status: rpStatus, label: 'Return-Path', value: `<span class="flag-icon">🏳️</span> ${escHtml(parsed.returnPath || 'N/A')}`, actions: '⋯' },
        { status: statusClass(parsed.spf), label: 'Originating IP', value: parsed.originatingIP ? `<a href="#">${escHtml(parsed.originatingIP)}</a> ${badgeHtml(parsed.spf === 'none' ? null : 'Received-SPF')}` : 'N/A', actions: parsed.originatingIP ? '⋯' : '' },
        { status: 'st-neutral', label: 'rDNS', value: escHtml(parsed.rdns || 'N/A') },
    ];

    document.getElementById('fp-details').innerHTML = detailRows.map(row => `
        <div class="meta-row">
            <div class="meta-status ${row.status}"></div>
            <div class="meta-label">${row.label}</div>
            <div class="meta-value">${row.value}</div>
            ${row.actions ? `<div class="meta-actions">${row.actions}</div>` : ''}
        </div>
    `).join('');

    // === AUTHENTICATION TAB ===
    const authChecks = [
        { name: 'SPF', result: parsed.spf, icon: parsed.spf === 'pass' ? '✅' : parsed.spf === 'none' ? '❔' : '❌',
          desc: parsed.spf === 'pass' ? 'Sender IP authorized' : parsed.spf === 'none' ? 'No SPF record found' : 'SPF verification failed' },
        { name: 'DKIM', result: parsed.dkim, icon: parsed.dkim === 'pass' ? '✅' : parsed.dkim === 'none' ? '❔' : '❌',
          desc: parsed.dkim === 'pass' ? 'Email signature valid' : parsed.dkim === 'none' ? 'No DKIM signature' : 'DKIM signature invalid' },
        { name: 'DMARC', result: parsed.dmarc, icon: parsed.dmarc === 'pass' ? '✅' : parsed.dmarc === 'none' ? '❔' : '❌',
          desc: parsed.dmarc === 'pass' ? 'DMARC policy aligned' : parsed.dmarc === 'none' ? 'No DMARC policy' : 'DMARC alignment failed' },
    ];
    document.getElementById('fp-auth').innerHTML = authChecks.map(c => `
        <div class="auth-row">
            <div class="auth-icon">${c.icon}</div>
            <div class="auth-info">
                <strong>${c.name}: ${c.result.toUpperCase()}</strong>
                <span>${c.desc}</span>
            </div>
            ${badgeHtml(c.result)}
        </div>
    `).join('') || '<div class="empty-state"><span class="empty-icon">🔐</span>No authentication data available</div>';

    // Update auth tab dot
    const authHasFail = parsed.spf === 'fail' || parsed.dkim === 'fail' || parsed.dmarc === 'fail';
    const authTab = document.querySelector('.f-tab[data-ftab="authentication"] .tab-dot');
    authTab.className = 'tab-dot ' + (authHasFail ? 'dot-danger' : (parsed.spf === 'pass' ? 'dot-safe' : ''));

    // === URLS TAB === (cache results to avoid double analysis)
    const urlResults = parsed.urls.map(url => ({ url, analysis: analyzeURL(url) }));
    if (urlResults.length > 0) {
        document.getElementById('fp-urls').innerHTML = urlResults.map(({ url, analysis }) => {
            const dotClass = analysis.score > 40 ? 'st-danger' : analysis.score > 15 ? 'st-warn' : 'st-safe';
            const topFinding = analysis.findings[0];
            return `<div class="url-item">
                <div class="url-risk-dot meta-status ${dotClass}"></div>
                <div class="url-text">
                    <a href="#" class="url-display-link">${escHtml(url)}</a>
                    ${topFinding ? `<div class="url-finding">${escHtml(topFinding.title)}: ${escHtml(topFinding.desc)}</div>` : ''}
                </div>
            </div>`;
        }).join('');
    } else {
        document.getElementById('fp-urls').innerHTML = '<div class="empty-state"><span class="empty-icon">🔗</span>No URLs detected</div>';
    }
    const urlTab = document.querySelector('.f-tab[data-ftab="urls"] .tab-dot');
    const hasRiskyUrl = urlResults.some(({ analysis }) => analysis.score > 15);
    urlTab.className = 'tab-dot ' + (hasRiskyUrl ? 'dot-danger' : (urlResults.length > 0 ? 'dot-safe' : ''));

    // === ATTACHMENTS TAB ===
    const dangerousExts = DANGEROUS_FILE_EXTENSIONS;
    if (parsed.attachments.length > 0) {
        document.getElementById('fp-attachments').innerHTML = parsed.attachments.map(att => {
            const isDangerous = dangerousExts.test(att.name);
            const icon = isDangerous ? '⚠️' : '📎';
            return `<div class="attach-item">
                <div class="attach-icon">${icon}</div>
                <div class="attach-info">
                    <strong style="${isDangerous ? 'color:var(--accent-red)' : ''}">${escHtml(att.name)}</strong>
                    <span>${escHtml(att.type)}${isDangerous ? ' — ⚠️ Dangerous file type!' : ''}</span>
                </div>
            </div>`;
        }).join('');
    } else {
        document.getElementById('fp-attachments').innerHTML = '<div class="empty-state"><span class="empty-icon">📎</span>No attachments detected</div>';
    }
    const attTab = document.querySelector('.f-tab[data-ftab="attachments"] .tab-dot');
    const hasDangerous = parsed.attachments.some(a => dangerousExts.test(a.name));
    attTab.className = 'tab-dot ' + (hasDangerous ? 'dot-danger' : (parsed.attachments.length > 0 ? 'dot-warn' : ''));

    // === TRANSMISSION TAB ===
    if (parsed.receivedHeaders.length > 0) {
        document.getElementById('fp-transmission').innerHTML = parsed.receivedHeaders.map((h, i) => `
            <div class="transmission-row">
                <strong>Hop ${i + 1}</strong>
                <p>${escHtml(h)}</p>
            </div>
        `).join('');
    } else {
        document.getElementById('fp-transmission').innerHTML = '<div class="empty-state"><span class="empty-icon">📡</span>No transmission data available</div>';
    }

    // === X-HEADERS TAB ===
    const xKeys = Object.keys(parsed.xHeaders);
    if (xKeys.length > 0) {
        document.getElementById('fp-xheaders').innerHTML = xKeys.map(k => `
            <div class="xheader-row">
                <span class="xheader-key">${escHtml(k)}</span>
                <span class="xheader-val">${escHtml(parsed.xHeaders[k])}</span>
            </div>
        `).join('');
    } else {
        document.getElementById('fp-xheaders').innerHTML = '<div class="empty-state"><span class="empty-icon">📋</span>No X-headers found</div>';
    }

    // === BODY VIEWER ===
    // Render HTML in sandboxed iframe to prevent XSS from malicious .eml files
    const renderedContainer = document.getElementById('bp-rendered');
    renderedContainer.innerHTML = '';
    if (parsed.bodyHtml) {
        const iframe = document.createElement('iframe');
        iframe.sandbox = ''; // fully sandboxed — no scripts, no forms, no popups
        iframe.style.cssText = 'width:100%;min-height:300px;border:none;background:#1a1a1a;border-radius:6px;';
        iframe.srcdoc = `<html><head><style>body{font-family:'Inter',sans-serif;font-size:14px;color:#ddd;background:#1a1a1a;padding:16px;line-height:1.6;margin:0;}a{color:#00d4ff;}</style></head><body>${parsed.bodyHtml}</body></html>`;
        renderedContainer.appendChild(iframe);
    } else {
        renderedContainer.innerHTML = '<div class="rendered-body"><p style="color:#666;">No HTML body available</p></div>';
    }
    document.getElementById('bp-html').innerHTML = `<pre>${escHtml(parsed.bodyHtml || 'No HTML body available')}</pre>`;
    document.getElementById('bp-plaintext').innerHTML = `<pre>${escHtml(parsed.bodyPlain || 'No plaintext body available')}</pre>`;
    document.getElementById('bp-source').innerHTML = `<pre>${escHtml(parsed.rawSource)}</pre>`;

    // === SUMMARY ===
    const scoreClass = analysis.score <= 20 ? 's-low' : analysis.score <= 40 ? 's-med' : analysis.score <= 70 ? 's-high' : 's-crit';
    const riskLabel = analysis.score <= 20 ? '✅ Low Risk — Likely Safe' : analysis.score <= 40 ? '⚠️ Medium Risk — Exercise Caution' :
        analysis.score <= 70 ? '🔴 High Risk — Likely Phishing' : '🚨 CRITICAL — Do Not Interact!';

    let summaryHTML = `
        <div class="summary-header">
            <div class="summary-score ${scoreClass}">${analysis.score}</div>
            <div class="summary-label" style="color:${scoreClass === 's-low' ? 'var(--accent-green)' : scoreClass === 's-med' ? '#ffc107' : scoreClass === 's-high' ? '#ff6b35' : 'var(--accent-red)'}">${riskLabel}</div>
        </div>
        <div class="summary-findings">`;

    if (analysis.findings.length === 0) {
        summaryHTML += '<p style="color:var(--accent-green);text-align:center;padding:10px;">✓ No suspicious indicators detected</p>';
    } else {
        analysis.findings.forEach(f => {
            const icon = f.severity === 'critical' ? '🚨' : f.severity === 'high' ? '⚠️' : f.severity === 'medium' ? '⚡' : 'ℹ️';
            summaryHTML += `<div class="s-finding sf-${f.severity}">
                <span class="s-finding-icon">${icon}</span>
                <div class="s-finding-text"><strong>${escHtml(f.title)}</strong><span>${escHtml(f.desc)}</span></div>
            </div>`;
        });
    }
    summaryHTML += '</div>';
    document.getElementById('forensics-summary').innerHTML = summaryHTML;

    // Update details tab dot
    const detTab = document.querySelector('.f-tab[data-ftab="details"] .tab-dot');
    detTab.className = 'tab-dot ' + (analysis.score > 40 ? 'dot-danger' : analysis.score > 15 ? 'dot-warn' : 'dot-safe');

    // Reset to details tab
    document.querySelectorAll('.f-tab').forEach(t => t.classList.remove('active'));
    document.querySelector('.f-tab[data-ftab="details"]').classList.add('active');
    document.querySelectorAll('.ftab-panel').forEach(p => p.classList.remove('active'));
    document.getElementById('fp-details').classList.add('active');

    // Reset body to rendered
    document.querySelectorAll('.body-tab').forEach(t => t.classList.remove('active'));
    document.querySelector('.body-tab[data-btab="rendered"]').classList.add('active');
    document.querySelectorAll('.btab-panel').forEach(p => p.classList.remove('active'));
    document.getElementById('bp-rendered').classList.add('active');

    // Scroll into view
    fv.scrollIntoView({ behavior: 'smooth', block: 'start' });
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

    // Show confirmation with security warning
    if(typeof showToast==='function')showToast(`${API_CONFIG[apiId].name} API key saved! Keys are encrypted locally.`,'success');else alert(`${API_CONFIG[apiId].name} API key saved!`);
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
        // WARNING: API key is exposed in URL query string (Google Safe Browsing API design).
        // Key appears in browser history, network logs, and DevTools. Use a server-side proxy in production.
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

// ========================================
// ENHANCED THREAT ANALYZER MODULE
// ========================================

// --- Levenshtein Distance ---
function levenshteinDistance(source, target) {
    if (source.length === 0) return target.length;
    if (target.length === 0) return source.length;
    const matrix = [];
    for (let i = 0; i <= target.length; i++) matrix[i] = [i];
    for (let j = 0; j <= source.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= target.length; i++) {
        for (let j = 1; j <= source.length; j++) {
            const cost = source[j - 1] === target[i - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            );
        }
    }
    return matrix[target.length][source.length];
}

// --- Brand Dictionary for Lookalike Detection ---
const BRAND_DICTIONARY = [
    'paypal','google','amazon','microsoft','apple','facebook','netflix','instagram',
    'twitter','linkedin','dropbox','chase','wellsfargo','bankofamerica','citibank',
    'capitalone','usbank','americanexpress','discover','hsbc','barclays','santander',
    'coinbase','binance','kraken','venmo','cashapp','zelle','stripe','shopify',
    'walmart','target','bestbuy','ebay','etsy','aliexpress','alibaba','rakuten',
    'adobe','zoom','slack','teams','discord','telegram','whatsapp','signal',
    'github','gitlab','bitbucket','stackoverflow','reddit','tiktok','snapchat',
    'spotify','youtube','twitch','uber','lyft','airbnb','booking','expedia'
];

// Character substitution map — unidirectional: normalize attacker tricks → real letters
const CHAR_SUBSTITUTIONS = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g', '7': 't',
    '8': 'b', '9': 'g', '@': 'a', '$': 's', '!': 'i'
};

// Multi-char substitutions checked separately
const MULTI_CHAR_SUBS = { 'rn': 'm', 'vv': 'w', 'cl': 'd', 'nn': 'm' };

function detectLookalikeDomain(inputDomain) {
    if (!inputDomain) return [];
    const findings = [];
    const domainLower = inputDomain.toLowerCase().replace(/^www\./, '');
    // Extract the main domain name (before TLD)
    const domainParts = domainLower.split('.');
    const mainName = domainParts[0] || domainLower;

    // Normalize single-char substitutions for comparison
    let normalizedName = mainName;
    for (const [char, replacement] of Object.entries(CHAR_SUBSTITUTIONS)) {
        normalizedName = normalizedName.split(char).join(replacement);
    }
    // Apply multi-char substitutions (rn→m, vv→w, cl→d)
    for (const [chars, replacement] of Object.entries(MULTI_CHAR_SUBS)) {
        normalizedName = normalizedName.split(chars).join(replacement);
    }

    for (const brand of BRAND_DICTIONARY) {
        // Skip exact match
        if (mainName === brand) continue;

        // Check Levenshtein distance
        const distance = levenshteinDistance(mainName, brand);
        if (distance <= 2 && distance > 0) {
            findings.push({
                severity: 'critical',
                title: `Lookalike Domain: "${brand}"`,
                desc: `Domain "${inputDomain}" is ${distance} character(s) away from "${brand}.com". This is a strong indicator of typosquatting.`,
                category: 'impersonation',
                brand: brand,
                distance: distance
            });
        }

        // Check normalized form
        const normalizedDistance = levenshteinDistance(normalizedName, brand);
        if (normalizedDistance === 0 && mainName !== brand) {
            findings.push({
                severity: 'critical',
                title: `Character Substitution Attack: "${brand}"`,
                desc: `Domain "${inputDomain}" uses character substitution to impersonate "${brand}" (e.g., 0→o, 1→l).`,
                category: 'impersonation',
                brand: brand,
                distance: 0
            });
        }

        // Check if brand name is embedded with extra chars (e.g., paypal-secure)
        if (mainName.includes(brand) && mainName !== brand && mainName.length > brand.length + 1) {
            const alreadyFlagged = findings.some(f => f.brand === brand);
            if (!alreadyFlagged) {
                findings.push({
                    severity: 'high',
                    title: `Brand Embedding: "${brand}"`,
                    desc: `Domain contains "${brand}" with added characters — common in cousin/lookalike domains.`,
                    category: 'impersonation',
                    brand: brand
                });
            }
        }
    }

    // Deduplicate by brand (keep highest severity)
    const seenBrands = new Map();
    for (const finding of findings) {
        const existing = seenBrands.get(finding.brand);
        if (!existing || (finding.severity === 'critical' && existing.severity !== 'critical')) {
            seenBrands.set(finding.brand, finding);
        }
    }
    return Array.from(seenBrands.values());
}

// --- Homoglyph (Unicode Confusable) Detection ---
const HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u04BB': 'h',
    '\u0455': 's', '\u0460': 'o', '\u0501': 'd', '\u051B': 'q',
    '\u0261': 'g', '\u026A': 'i', '\u0274': 'n',
    '\u1D00': 'a', '\u1D04': 'c', '\u1D07': 'e', '\u1D0F': 'o',
    '\u2010': '-', '\u2011': '-', '\u2012': '-', '\u2013': '-',
    '\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd', '\uFF45': 'e',
    '\uFF46': 'f', '\uFF47': 'g', '\uFF48': 'h', '\uFF49': 'i', '\uFF4A': 'j',
};

function detectHomoglyphs(text) {
    if (!text) return { found: false, chars: [], deceptionScore: 0 };
    const foundChars = [];
    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        if (HOMOGLYPH_MAP[char]) {
            foundChars.push({
                position: i,
                unicode: char,
                looksLike: HOMOGLYPH_MAP[char],
                codePoint: 'U+' + char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')
            });
        }
    }
    const deceptionScore = Math.min(foundChars.length * 25, 100);
    return {
        found: foundChars.length > 0,
        chars: foundChars,
        deceptionScore: deceptionScore
    };
}

// --- Risky Language Scoring ---
const LANGUAGE_RISK_CATEGORIES = {
    urgency: {
        weight: 3,
        patterns: [
            /\bimmediately\b/gi, /\burgent(ly)?\b/gi, /\bact now\b/gi,
            /\bwithin \d+ hours?\b/gi, /\bdon['']t delay\b/gi, /\btime sensitive\b/gi,
            /\bexpires? (today|soon|immediately)\b/gi, /\blast chance\b/gi,
            /\bfinal warning\b/gi, /\brespond immediately\b/gi, /\bASAP\b/g,
            /\bbefore it['']s too late\b/gi, /\bdeadline\b/gi
        ]
    },
    fear: {
        weight: 4,
        patterns: [
            /\b(account|access) (will be |)(suspended|terminated|locked|deleted|closed)\b/gi,
            /\bunauthorized (access|activity|transaction)\b/gi,
            /\billegal activity\b/gi, /\bpermanently (deleted|removed|closed)\b/gi,
            /\blegal action\b/gi, /\blaw enforcement\b/gi,
            /\byour (data|files|account) (is|are|has been) (at risk|compromised)\b/gi,
            /\bsecurity (breach|incident|alert|violation)\b/gi
        ]
    },
    authority: {
        weight: 2,
        patterns: [
            /\bfrom the (CEO|CFO|CTO|IT department|HR|legal|security team|board)\b/gi,
            /\bon behalf of (management|the board|your (bank|provider|company))\b/gi,
            /\bby (order|request) of\b/gi, /\bofficial notice\b/gi,
            /\bmandatory (action|compliance|update|review)\b/gi
        ]
    },
    reward: {
        weight: 3,
        patterns: [
            /\b(you['']ve |you have )(won|been selected|been chosen)\b/gi,
            /\bcongratulations\b/gi, /\bclaim your (prize|reward|gift|bonus)\b/gi,
            /\bfree (gift|money|reward)\b/gi, /\blimited (time |)offer\b/gi,
            /\bexclusive (deal|offer|invitation)\b/gi,
            /\b(earn|win|receive) \$[\d,]+\b/gi
        ]
    },
    credential_harvest: {
        weight: 5,
        patterns: [
            /\b(verify|confirm|update|validate) your (password|identity|account|credentials|login|SSN|credit card)\b/gi,
            /\benter your (password|SSN|credit card|social security|bank|PIN)\b/gi,
            /\b(click|login|sign in) (here |below |)to (verify|confirm|secure|unlock)\b/gi,
            /\breset your password\b/gi
        ]
    },
    financial: {
        weight: 4,
        patterns: [
            /\bwire transfer\b/gi, /\bbank account.{0,20}(changed|updated)\b/gi,
            /\bupdate.{0,20}(payment|billing).{0,20}(method|info|details)\b/gi,
            /\bsend.{0,20}gift card\b/gi, /\b(bitcoin|crypto).{0,20}(wallet|payment|transfer)\b/gi,
            /\boverdue (invoice|payment|balance)\b/gi,
            /\b(pay|transfer|send) \$[\d,]+\b/gi
        ]
    }
};

function analyzeLanguageRisk(text) {
    if (!text) return { totalScore: 0, categories: {}, topTactics: [] };
    const categories = {};
    let totalWeightedScore = 0;

    for (const [category, config] of Object.entries(LANGUAGE_RISK_CATEGORIES)) {
        let matchCount = 0;
        const matchedPhrases = [];

        for (const pattern of config.patterns) {
            // Reset regex lastIndex
            pattern.lastIndex = 0;
            const matches = text.match(pattern);
            if (matches) {
                matchCount += matches.length;
                matchedPhrases.push(...matches.slice(0, 3));
            }
        }

        if (matchCount > 0) {
            const categoryScore = Math.min(matchCount * config.weight, 30);
            categories[category] = {
                count: matchCount,
                score: categoryScore,
                phrases: [...new Set(matchedPhrases)].slice(0, 5)
            };
            totalWeightedScore += categoryScore;
        }
    }

    // Identify top manipulation tactics
    const topTactics = Object.entries(categories)
        .sort((a, b) => b[1].score - a[1].score)
        .slice(0, 3)
        .map(([name, data]) => ({ name, ...data }));

    return {
        totalScore: Math.min(totalWeightedScore, 100),
        categories,
        topTactics
    };
}

// --- Bulk URL Scanner ---
function bulkAnalyzeURLs(urlListText) {
    const urls = urlListText
        .split(/[\n\r,;]+/)
        .map(u => u.trim())
        .filter(u => u.length > 0 && /^https?:\/\//.test(u));

    if (urls.length === 0) return { urls: [], aggregate: { total: 0, clean: 0, suspicious: 0, dangerous: 0 } };
    if (urls.length > 100) urls.length = 100; // Cap at 100

    const results = urls.map(url => {
        const analysis = analyzeURL(url);
        // Also run lookalike detection on the domain
        try {
            const domainMatch = url.match(/^https?:\/\/([^\/\?#]+)/i);
            if (domainMatch) {
                const lookalikes = detectLookalikeDomain(domainMatch[1]);
                analysis.findings.push(...lookalikes);
                analysis.score = calculateRiskScore(analysis.findings);
            }
        } catch (e) { /* ignore parse failures */ }

        let riskLevel = 'clean';
        if (analysis.score > 60) riskLevel = 'dangerous';
        else if (analysis.score > 25) riskLevel = 'suspicious';
        else if (analysis.score > 10) riskLevel = 'low-risk';

        return { url, analysis, riskLevel };
    });

    const aggregate = {
        total: results.length,
        clean: results.filter(r => r.riskLevel === 'clean').length,
        lowRisk: results.filter(r => r.riskLevel === 'low-risk').length,
        suspicious: results.filter(r => r.riskLevel === 'suspicious').length,
        dangerous: results.filter(r => r.riskLevel === 'dangerous').length,
        avgScore: Math.round(results.reduce((sum, r) => sum + r.analysis.score, 0) / results.length)
    };

    return { urls: results, aggregate };
}

// --- Threat Scanner Initialization ---
function initThreatScanner() {
    // Bulk URL Scanner
    const btnBulkScan = document.getElementById('btn-bulk-scan');
    const bulkInput = document.getElementById('bulk-url-input');
    const bulkResults = document.getElementById('bulk-results');

    if (btnBulkScan) {
        btnBulkScan.addEventListener('click', () => {
            const text = bulkInput.value.trim();
            if (!text) { if(typeof showToast==='function')showToast('Paste URLs to scan (one per line)','warning'); return; }
            const results = bulkAnalyzeURLs(text);
            renderBulkResults(results, bulkResults);
            if(typeof addXP==='function') addXP(results.urls.length * 2);
            // Track for badge
            const prev = parseInt(localStorage.getItem('cyberHubUrlsScanned') || '0');
            localStorage.setItem('cyberHubUrlsScanned', prev + results.urls.length);
        });
    }

    // Lookalike Domain Checker
    const btnDomainCheck = document.getElementById('btn-domain-check');
    const domainInput = document.getElementById('domain-check-input');
    const domainResults = document.getElementById('domain-results');

    if (btnDomainCheck) {
        btnDomainCheck.addEventListener('click', () => {
            const domain = domainInput.value.trim();
            if (!domain) { if(typeof showToast==='function')showToast('Enter a domain to check','warning'); return; }
            const lookalikes = detectLookalikeDomain(domain);
            const homoglyphs = detectHomoglyphs(domain);
            renderDomainResults(domain, lookalikes, homoglyphs, domainResults);
        });
    }

    // Language Risk Analyzer
    const btnLangScan = document.getElementById('btn-language-scan');
    const langInput = document.getElementById('language-input');
    const langResults = document.getElementById('language-results');

    if (btnLangScan) {
        btnLangScan.addEventListener('click', () => {
            const text = langInput.value.trim();
            if (!text) { if(typeof showToast==='function')showToast('Paste email/message text to analyze','warning'); return; }
            const analysis = analyzeLanguageRisk(text);
            renderLanguageResults(analysis, langResults);
        });
    }
}

// --- Render Functions ---
function renderBulkResults(results, container) {
    if (!container) return;
    const { urls, aggregate } = results;

    let html = `
        <div class="bulk-aggregate">
            <div class="agg-stat">
                <span class="agg-number">${aggregate.total}</span>
                <span class="agg-label">Total URLs</span>
            </div>
            <div class="agg-stat agg-clean">
                <span class="agg-number">${aggregate.clean}</span>
                <span class="agg-label">Clean</span>
            </div>
            <div class="agg-stat agg-suspicious">
                <span class="agg-number">${aggregate.suspicious + aggregate.lowRisk}</span>
                <span class="agg-label">Suspicious</span>
            </div>
            <div class="agg-stat agg-dangerous">
                <span class="agg-number">${aggregate.dangerous}</span>
                <span class="agg-label">Dangerous</span>
            </div>
            <div class="agg-stat">
                <span class="agg-number">${aggregate.avgScore}</span>
                <span class="agg-label">Avg Risk</span>
            </div>
        </div>
        <div class="bulk-url-list">`;

    for (const result of urls) {
        const riskClass = result.riskLevel === 'dangerous' ? 'risk-dangerous' :
            result.riskLevel === 'suspicious' ? 'risk-suspicious' :
            result.riskLevel === 'low-risk' ? 'risk-low' : 'risk-clean';
        const riskIcon = result.riskLevel === 'dangerous' ? '🚨' :
            result.riskLevel === 'suspicious' ? '⚠️' :
            result.riskLevel === 'low-risk' ? '⚡' : '✅';

        html += `
            <div class="bulk-url-item ${riskClass}">
                <div class="bulk-url-header">
                    <span class="bulk-risk-icon">${riskIcon}</span>
                    <span class="bulk-url-text">${escHtml(result.url)}</span>
                    <span class="bulk-score">${result.analysis.score}</span>
                </div>
                ${result.analysis.findings.length > 0 ? `
                <div class="bulk-findings">
                    ${result.analysis.findings.slice(0, 3).map(f =>
                        `<span class="bulk-finding-tag bf-${f.severity}">${escHtml(f.title)}</span>`
                    ).join('')}
                </div>` : ''}
            </div>`;
    }
    html += '</div>';
    container.innerHTML = html;
    container.style.display = 'block';
}

function renderDomainResults(domain, lookalikes, homoglyphs, container) {
    if (!container) return;
    let html = '';

    if (homoglyphs.found) {
        html += `
            <div class="domain-alert domain-critical">
                <h4>🚨 Homoglyph Attack Detected!</h4>
                <p>This domain contains Unicode characters that visually mimic ASCII letters.</p>
                <div class="homoglyph-chars">
                    ${homoglyphs.chars.map(c =>
                        `<span class="homoglyph-char">
                            <span class="hg-unicode">"${c.unicode}"</span> →
                            <span class="hg-ascii">"${c.looksLike}"</span>
                            <span class="hg-code">${c.codePoint}</span>
                        </span>`
                    ).join('')}
                </div>
                <div class="deception-meter">
                    <span>Deception Score:</span>
                    <div class="deception-bar-wrap">
                        <div class="deception-bar" style="width:${homoglyphs.deceptionScore}%"></div>
                    </div>
                    <span class="deception-pct">${homoglyphs.deceptionScore}%</span>
                </div>
            </div>`;
    }

    if (lookalikes.length > 0) {
        html += `<div class="domain-alert domain-warning">
            <h4>⚠️ Lookalike Brands Detected</h4>
            <div class="lookalike-list">`;
        for (const finding of lookalikes) {
            html += `
                <div class="lookalike-item li-${finding.severity}">
                    <span class="li-icon">${finding.severity === 'critical' ? '🚨' : '⚠️'}</span>
                    <div class="li-content">
                        <strong>${escHtml(finding.title)}</strong>
                        <p>${escHtml(finding.desc)}</p>
                    </div>
                </div>`;
        }
        html += '</div></div>';
    }

    if (!homoglyphs.found && lookalikes.length === 0) {
        html += `<div class="domain-alert domain-safe">
            <h4>✅ Domain Appears Clean</h4>
            <p>"${escHtml(domain)}" does not closely match any known brands and contains no homoglyph characters.</p>
        </div>`;
    }

    container.innerHTML = html;
    container.style.display = 'block';
}

function renderLanguageResults(analysis, container) {
    if (!container) return;
    const { totalScore, categories, topTactics } = analysis;
    const scoreClass = totalScore <= 15 ? 'lang-safe' : totalScore <= 40 ? 'lang-warn' : 'lang-danger';
    const scoreLabel = totalScore <= 15 ? 'Low Risk Language' : totalScore <= 40 ? 'Moderate Manipulation' : 'High Manipulation Risk';

    const categoryIcons = {
        urgency: '⏰', fear: '😱', authority: '👔', reward: '🎁',
        credential_harvest: '🔑', financial: '💰'
    };
    const categoryLabels = {
        urgency: 'Urgency', fear: 'Fear/Threats', authority: 'Authority',
        reward: 'Reward Lure', credential_harvest: 'Credential Harvesting', financial: 'Financial Pressure'
    };

    let html = `
        <div class="lang-score-header ${scoreClass}">
            <div class="lang-score-circle">${totalScore}</div>
            <div class="lang-score-info">
                <strong>${scoreLabel}</strong>
                <span>${topTactics.length} manipulation tactic(s) detected</span>
            </div>
        </div>`;

    if (topTactics.length > 0) {
        html += '<div class="lang-tactics">';
        for (const [catName, catData] of Object.entries(categories)) {
            const icon = categoryIcons[catName] || '📌';
            const label = categoryLabels[catName] || catName;
            const barWidth = Math.min((catData.score / 30) * 100, 100);

            html += `
                <div class="lang-tactic-row">
                    <div class="tactic-header">
                        <span class="tactic-icon">${icon}</span>
                        <span class="tactic-name">${label}</span>
                        <span class="tactic-count">${catData.count} match(es)</span>
                    </div>
                    <div class="tactic-bar-wrap">
                        <div class="tactic-bar tactic-bar-${catName}" style="width:${barWidth}%"></div>
                    </div>
                    <div class="tactic-phrases">
                        ${catData.phrases.map(p => `<span class="tactic-phrase">"${escHtml(p)}"</span>`).join('')}
                    </div>
                </div>`;
        }
        html += '</div>';
    } else {
        html += '<p style="color:var(--accent-green);text-align:center;padding:16px;">✓ No manipulation tactics detected in this text.</p>';
    }

    container.innerHTML = html;
    container.style.display = 'block';
}
