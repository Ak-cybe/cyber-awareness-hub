document.addEventListener('DOMContentLoaded', () => {
    initPhishingSim();
    initPasswordSim();
    initChecklist();
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
