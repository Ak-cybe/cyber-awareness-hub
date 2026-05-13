/* =============================================
   CYBER AWARENESS HUB — ENHANCEMENTS
   All 25 improvements in one file
   ============================================= */
document.addEventListener('DOMContentLoaded',()=>{
initParticles();initToast();initTheme();initNav();initStagger();
initShortcuts();initProgressRing();initPwEmoji();initQuiz();
initGamification();initDashboardCharts();initThreatFeed();
initScenarioDots();initExportReport();initTrainingModules();
});

/* #1 PARTICLE BACKGROUND */
function initParticles(){
const c=document.getElementById('particle-canvas');if(!c)return;
const ctx=c.getContext('2d');let w,h,particles=[];
function resize(){w=c.width=window.innerWidth;h=c.height=window.innerHeight;}
resize();window.addEventListener('resize',resize);
for(let i=0;i<60;i++)particles.push({x:Math.random()*w,y:Math.random()*h,r:Math.random()*2+0.5,dx:(Math.random()-0.5)*0.4,dy:(Math.random()-0.5)*0.4,o:Math.random()*0.4+0.1});
function draw(){ctx.clearRect(0,0,w,h);
const isDark=!document.documentElement.getAttribute('data-theme');
particles.forEach(p=>{
p.x+=p.dx;p.y+=p.dy;
if(p.x<0||p.x>w)p.dx*=-1;if(p.y<0||p.y>h)p.dy*=-1;
ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
ctx.fillStyle=isDark?`rgba(0,212,255,${p.o})`:`rgba(0,100,200,${p.o*0.5})`;ctx.fill();
});
particles.forEach((a,i)=>{for(let j=i+1;j<particles.length;j++){
const b=particles[j],dx=a.x-b.x,dy=a.y-b.y,d=Math.sqrt(dx*dx+dy*dy);
if(d<120){ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);
ctx.strokeStyle=isDark?`rgba(0,212,255,${0.08*(1-d/120)})`:`rgba(0,100,200,${0.06*(1-d/120)})`;
ctx.stroke();}}});
requestAnimationFrame(draw);}draw();}

/* #3 TOAST NOTIFICATION SYSTEM */
function showToast(msg,type='info',duration=3500){
const container=document.getElementById('toast-container');if(!container)return;
const icons={success:'✅',error:'❌',warning:'⚠️',info:'ℹ️'};
const t=document.createElement('div');
t.className=`toast toast-${type}`;
t.innerHTML=`<span class="toast-icon">${icons[type]||'ℹ️'}</span><span class="toast-msg">${msg}</span><button class="toast-close" aria-label="Close notification">×</button>`;
container.appendChild(t);
t.querySelector('.toast-close').onclick=()=>{t.classList.add('toast-removing');setTimeout(()=>t.remove(),300);};
setTimeout(()=>{if(t.parentNode){t.classList.add('toast-removing');setTimeout(()=>t.remove(),300);}},duration);
}
function initToast(){window.showToast=showToast;}

/* #5 THEME TOGGLE */
function initTheme(){
const btn=document.getElementById('theme-toggle');if(!btn)return;
const saved=localStorage.getItem('cyberHubTheme');
if(saved==='light'){document.documentElement.setAttribute('data-theme','light');btn.textContent='☀️';}
btn.addEventListener('click',()=>{
const isLight=document.documentElement.getAttribute('data-theme')==='light';
document.documentElement.setAttribute('data-theme',isLight?'':'light');
btn.textContent=isLight?'🌙':'☀️';
localStorage.setItem('cyberHubTheme',isLight?'dark':'light');
showToast(isLight?'Dark mode enabled':'Light mode enabled','info',2000);
});}

/* #11 STICKY NAVIGATION */
function initNav(){
const links=document.querySelectorAll('.nav-link[data-target]');
links.forEach(l=>l.addEventListener('click',()=>{
const target=document.getElementById(l.dataset.target);
if(target){target.scrollIntoView({behavior:'smooth',block:'start'});
links.forEach(x=>x.classList.remove('active'));l.classList.add('active');}
}));
const sections=Array.from(links).map(l=>document.getElementById(l.dataset.target)).filter(Boolean);
const obs=new IntersectionObserver(entries=>{entries.forEach(e=>{if(e.isIntersecting){
links.forEach(l=>{l.classList.toggle('active',l.dataset.target===e.target.id);});}});
},{threshold:0.3,rootMargin:'-80px 0px 0px 0px'});
sections.forEach(s=>obs.observe(s));}

/* #2 STAGGERED CARD ANIMATIONS */
function initStagger(){
const obs=new IntersectionObserver(entries=>{entries.forEach(e=>{
if(e.isIntersecting){e.target.classList.add('card-visible');obs.unobserve(e.target);}
});},{threshold:0.1});
document.querySelectorAll('.glass-card').forEach(c=>obs.observe(c));}

/* #4 SVG PROGRESS RING */
function initProgressRing(){window._updateRing=updateProgressRing;}
function updateProgressRing(){
const ring=document.getElementById('progress-ring');
const pct=document.getElementById('progress-ring-pct');
if(!ring||!pct)return;
const reported=parseInt(document.getElementById('stat-reported')?.textContent||'0');
const missed=parseInt(document.getElementById('stat-missed')?.textContent||'0');
const total=reported+missed;
const percent=total===0?0:Math.round((reported/total)*100);
const circumference=2*Math.PI*52;
ring.style.strokeDasharray=circumference;
ring.style.strokeDashoffset=circumference-(percent/100)*circumference;
pct.textContent=percent+'%';
if(percent>=80){ring.style.stroke='var(--accent-green)';pct.style.color='var(--accent-green)';}
else if(percent>=50){ring.style.stroke='#ffc107';pct.style.color='#ffc107';}
else if(total>0){ring.style.stroke='var(--accent-red)';pct.style.color='var(--accent-red)';}
}

/* #14 PASSWORD EMOJI */
function initPwEmoji(){
const input=document.getElementById('password-input');
const emoji=document.getElementById('pw-emoji');
if(!input||!emoji)return;
input.addEventListener('input',()=>{
const len=input.value.length;
let e='🔒';
if(len===0)e='🔒';else if(len<8)e='😰';else if(len<12)e='😐';else e='🛡️';
if(emoji.textContent!==e){emoji.textContent=e;emoji.style.animation='none';
emoji.offsetHeight;emoji.style.animation='emojiPop 0.3s ease';}
});}

/* #12 SCENARIO PROGRESS DOTS */
function initScenarioDots(){
const container=document.getElementById('scenario-dots');if(!container)return;
const count=typeof scenarios!=='undefined'?scenarios.length:5;
container.innerHTML='';
for(let i=0;i<count;i++){
const dot=document.createElement('button');
dot.className='scenario-dot'+(i===0?' active':'');
dot.setAttribute('aria-label','Scenario '+(i+1));
dot.dataset.index=i;
dot.addEventListener('click',()=>{
if(typeof currentScenarioIndex!=='undefined'&&typeof renderScenario==='function'){
currentScenarioIndex=i;renderScenario(i);updateDots();}
});
container.appendChild(dot);}
window._updateDots=updateDots;updateDots();
}
function updateDots(){
const dots=document.querySelectorAll('.scenario-dot');
dots.forEach((d,i)=>{
d.classList.remove('active','completed','missed');
if(typeof currentScenarioIndex!=='undefined'&&i===currentScenarioIndex)d.classList.add('active');
if(typeof stats!=='undefined'&&typeof scenarios!=='undefined'){
const sid=scenarios[i]?.id;
if(stats.history[sid]==='reported')d.classList.add('completed');
else if(stats.history[sid]==='missed')d.classList.add('missed');
}});}

/* #13 KEYBOARD SHORTCUTS */
function initShortcuts(){
const overlay=document.getElementById('kbd-overlay');
const helpBtn=document.getElementById('kbd-help-btn');
const closeBtn=document.getElementById('kbd-close');
if(!overlay)return;
function toggleOverlay(){overlay.hidden=!overlay.hidden;}
if(helpBtn)helpBtn.addEventListener('click',toggleOverlay);
if(closeBtn)closeBtn.addEventListener('click',()=>overlay.hidden=true);
overlay.addEventListener('click',e=>{if(e.target===overlay)overlay.hidden=true;});
document.addEventListener('keydown',e=>{
if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA')return;
switch(e.key){
case'r':case'R':document.getElementById('btn-report')?.click();break;
case'n':case'N':document.getElementById('btn-next-scenario')?.click();if(typeof updateDots==='function')setTimeout(updateDots,50);break;
case'Escape':document.getElementById('phishing-feedback')&&(document.getElementById('phishing-feedback').hidden=true);overlay.hidden=true;break;
case't':case'T':document.getElementById('theme-toggle')?.click();break;
case'?':toggleOverlay();break;
case'1':case'2':case'3':case'4':case'5':
const idx=parseInt(e.key)-1;
if(typeof scenarios!=='undefined'&&idx<scenarios.length){
currentScenarioIndex=idx;if(typeof renderScenario==='function')renderScenario(idx);updateDots();}break;
}});}

/* #15 CONFETTI */
function launchConfetti(){
const c=document.getElementById('confetti-canvas');if(!c)return;
const ctx=c.getContext('2d');c.width=window.innerWidth;c.height=window.innerHeight;
const pieces=[];const colors=['#00ffc8','#00d4ff','#ff4757','#ffc107','#ff6b35','#fff'];
for(let i=0;i<150;i++)pieces.push({x:Math.random()*c.width,y:Math.random()*c.height-c.height,
w:Math.random()*10+5,h:Math.random()*6+3,color:colors[Math.floor(Math.random()*colors.length)],
dy:Math.random()*3+2,dx:(Math.random()-0.5)*2,rot:Math.random()*360,dr:Math.random()*6-3});
let frames=0;
function draw(){ctx.clearRect(0,0,c.width,c.height);
pieces.forEach(p=>{p.y+=p.dy;p.x+=p.dx;p.rot+=p.dr;
ctx.save();ctx.translate(p.x,p.y);ctx.rotate(p.rot*Math.PI/180);
ctx.fillStyle=p.color;ctx.globalAlpha=Math.max(0,1-frames/180);
ctx.fillRect(-p.w/2,-p.h/2,p.w,p.h);ctx.restore();});
frames++;if(frames<200)requestAnimationFrame(draw);
else ctx.clearRect(0,0,c.width,c.height);}draw();}
window.launchConfetti=launchConfetti;

/* #9 GAMIFICATION SYSTEM */
const GAMIFICATION={xp:0,level:'Rookie',badges:{}};
const LEVELS=[{name:'Rookie',min:0},{name:'Analyst',min:100},{name:'Expert',min:300},{name:'Cyber Guardian',min:600}];
const BADGE_DEFS=[
{id:'first_catch',name:'🎣 First Catch',desc:'Report your first phish',check:()=>(typeof stats!=='undefined'&&stats.reported>=1)},
{id:'perfect5',name:'🏆 Perfect 5',desc:'Report all 5 scenarios',check:()=>(typeof stats!=='undefined'&&stats.reported>=5)},
{id:'quiz_ace',name:'🧠 Quiz Ace',desc:'Score 100% on quiz',check:()=>GAMIFICATION.badges.quiz_ace},
{id:'pw_master',name:'🔐 Password Pro',desc:'Create a strong password',check:()=>GAMIFICATION.badges.pw_master},
{id:'hygiene_4',name:'✅ Clean Sweep',desc:'Complete all hygiene tasks',check:()=>{
const checks=['check-mfa','check-update','check-backup','check-lock'];
return checks.every(id=>{const el=document.getElementById(id);return el&&el.checked;});}}
];
function initGamification(){
loadGamification();updateGamificationUI();
setInterval(()=>{checkBadges();updateGamificationUI();updateProgressRing();},1500);
const origSave=window.saveStats;
if(typeof saveStats==='function'){window.saveStats=function(){origSave();addXP(15);checkBadges();updateGamificationUI();updateProgressRing();if(typeof updateDots==='function')updateDots();
if(typeof stats!=='undefined'&&typeof scenarios!=='undefined'&&stats.reported>=scenarios.length){launchConfetti();showToast('🎉 Perfect Score! All phishing emails reported!','success',5000);}
};}
}
function loadGamification(){try{const s=localStorage.getItem('cyberHubGamification');if(s){const p=JSON.parse(s);GAMIFICATION.xp=p.xp||0;GAMIFICATION.badges=p.badges||{};}}catch(e){}}
function saveGamification(){GAMIFICATION.level=getLevel();localStorage.setItem('cyberHubGamification',JSON.stringify(GAMIFICATION));}
function addXP(amount){GAMIFICATION.xp+=amount;saveGamification();updateGamificationUI();}
function getLevel(){for(let i=LEVELS.length-1;i>=0;i--){if(GAMIFICATION.xp>=LEVELS[i].min)return LEVELS[i].name;}return'Rookie';}
function checkBadges(){BADGE_DEFS.forEach(b=>{if(!GAMIFICATION.badges[b.id]&&b.check()){GAMIFICATION.badges[b.id]=true;saveGamification();showToast(`🏅 Badge Earned: ${b.name}`,'success',4000);}});}
function updateGamificationUI(){
const level=getLevel();
const levelEl=document.getElementById('level-display');
const xpEl=document.getElementById('xp-count');
const barEl=document.getElementById('xp-bar');
const badgesEl=document.getElementById('badges-container');
if(levelEl)levelEl.textContent='🎖️ '+level;
if(xpEl)xpEl.textContent=GAMIFICATION.xp;
if(barEl){const curLvl=LEVELS.find(l=>l.name===level);
const nextLvl=LEVELS[LEVELS.indexOf(curLvl)+1];
if(nextLvl){const pct=((GAMIFICATION.xp-curLvl.min)/(nextLvl.min-curLvl.min))*100;barEl.style.width=Math.min(pct,100)+'%';}
else barEl.style.width='100%';}
if(badgesEl){badgesEl.innerHTML=BADGE_DEFS.map(b=>{
const earned=GAMIFICATION.badges[b.id];
return `<span class="badge-item ${earned?'earned':'locked'}" title="${b.desc}">${b.name}</span>`;
}).join('');}
}
window.addXP=addXP;

/* #6 SOCIAL ENGINEERING QUIZ */
const QUIZ_DATA=[
{q:"Your CEO texts you urgently asking to buy $500 in gift cards. What do you do?",
opts:["Buy them immediately — it's the CEO!","Reply asking which store","Call the CEO on their known phone number to verify","Email IT about it"],
correct:2,explain:"Always verify unexpected requests through a separate, known communication channel. Gift card scams are the #1 BEC attack vector."},
{q:"A caller says they're from IT and need your password to fix a server issue. What do you do?",
opts:["Give them the password — IT needs it","Ask for their employee ID and call IT directly","Change your password and then give the old one","Tell them to email you instead"],
correct:1,explain:"Never share passwords verbally. Legitimate IT will never ask. Always verify identity through official channels."},
{q:"You find a USB drive in the parking lot labeled 'Salary Data 2024'. What do you do?",
opts:["Plug it into your work computer to find the owner","Plug it into a personal laptop instead","Turn it in to security/IT without plugging it in","Throw it away"],
correct:2,explain:"USB drops are a classic attack (USB Rubber Ducky). Never plug unknown devices in. Report to security."},
{q:"A coworker sends you a Google Docs link that asks you to re-login. What's suspicious?",
opts:["Nothing, Google asks for re-auth sometimes","The URL doesn't end in google.com","It was sent during business hours","The document was shared correctly"],
correct:1,explain:"Fake login pages hosted on non-Google domains are credential harvesting. Always check the URL domain before entering credentials."},
{q:"You receive a LinkedIn message with a 'job offer' PDF attachment. What do you do?",
opts:["Open it — LinkedIn is trustworthy","Open it in a sandbox/virtual machine only","Download but scan with antivirus first","Verify the recruiter's profile and company independently before opening anything"],
correct:3,explain:"Social media phishing is rising. Verify the sender's identity independently. Fake profiles + malicious PDFs = common combo."},
{q:"Your bank emails you about 'suspicious activity' with a link to verify. What's the safest action?",
opts:["Click the link and check your account","Forward the email to friends for advice","Open your banking app or type the bank URL manually","Reply to the email asking for details"],
correct:2,explain:"Never click links in emails claiming to be from your bank. Always navigate to the site directly or use the official app."},
{q:"A pop-up says 'Your computer is infected! Call this number for Microsoft Support.' What do you do?",
opts:["Call the number immediately","Close the browser and run your own antivirus","Give them remote access to check","Pay for the cleaning service"],
correct:1,explain:"Tech support scams use fake pop-ups. Microsoft never shows phone numbers in pop-ups. Close the browser and scan locally."}
];
let quizIdx=0,quizScore=0,quizAnswered=false;
function initQuiz(){
const container=document.getElementById('quiz-container');if(!container)return;
document.getElementById('btn-next-quiz')?.addEventListener('click',()=>{
if(quizIdx<QUIZ_DATA.length-1){quizIdx++;quizAnswered=false;renderQuizQ();}
else{showToast(`Quiz Complete! Score: ${quizScore}/${QUIZ_DATA.length}`,'success',5000);
addXP(quizScore*10);
if(quizScore===QUIZ_DATA.length){GAMIFICATION.badges.quiz_ace=true;saveGamification();checkBadges();}
quizIdx=0;quizScore=0;quizAnswered=false;renderQuizQ();}
});renderQuizQ();}
function renderQuizQ(){
const d=QUIZ_DATA[quizIdx];
document.getElementById('quiz-question').textContent=d.q;
document.getElementById('quiz-explanation').hidden=true;
document.getElementById('quiz-progress').textContent=`Question ${quizIdx+1}/${QUIZ_DATA.length} • Score: ${quizScore}`;
const optsEl=document.getElementById('quiz-options');
optsEl.innerHTML=d.opts.map((o,i)=>`<button class="quiz-option" data-idx="${i}">${o}</button>`).join('');
optsEl.querySelectorAll('.quiz-option').forEach(btn=>{
btn.addEventListener('click',()=>{
if(quizAnswered)return;quizAnswered=true;
const idx=parseInt(btn.dataset.idx);
const isCorrect=idx===d.correct;
btn.classList.add(isCorrect?'correct':'wrong');
if(isCorrect){quizScore++;addXP(5);}
else{optsEl.querySelectorAll('.quiz-option')[d.correct].classList.add('correct');}
optsEl.querySelectorAll('.quiz-option').forEach(b=>b.disabled=true);
const expEl=document.getElementById('quiz-explanation');
expEl.textContent=d.explain;expEl.hidden=false;
document.getElementById('quiz-progress').textContent=`Question ${quizIdx+1}/${QUIZ_DATA.length} • Score: ${quizScore}`;
});});}

/* #8 DASHBOARD CHARTS */
function initDashboardCharts(){
drawDetectionChart();drawCategoryChart();}
function drawDetectionChart(){
const c=document.getElementById('chart-detection');if(!c)return;
const ctx=c.getContext('2d');const W=c.width=c.offsetWidth*2;const H=c.height=400;
ctx.scale(1,1);
const reported=typeof stats!=='undefined'?stats.reported:0;
const missed=typeof stats!=='undefined'?stats.missed:0;
const data=[reported,missed];const labels=['Reported','Clicked'];
const colors=['#00ffc8','#ff4757'];const max=Math.max(...data,1);
const barW=W/6;const gap=W/8;
ctx.fillStyle='rgba(255,255,255,0.03)';ctx.fillRect(0,0,W,H);
data.forEach((v,i)=>{const x=gap+i*(barW+gap*2);const h=(v/max)*(H-80);const y=H-40-h;
const grd=ctx.createLinearGradient(x,y,x,H-40);
grd.addColorStop(0,colors[i]);grd.addColorStop(1,colors[i]+'33');
ctx.fillStyle=grd;ctx.beginPath();
ctx.roundRect(x,y,barW,h,8);ctx.fill();
ctx.fillStyle='#fff';ctx.font='bold 24px Inter';ctx.textAlign='center';
ctx.fillText(v,x+barW/2,y-12);
ctx.fillStyle='#999';ctx.font='14px Inter';ctx.fillText(labels[i],x+barW/2,H-15);
});}
function drawCategoryChart(){
const c=document.getElementById('chart-categories');if(!c)return;
const ctx=c.getContext('2d');c.width=c.offsetWidth*2;c.height=400;
const W=c.width,H=c.height,cx=W/2,cy=H/2,r=Math.min(W,H)/2-40;
const data=[{label:'Phishing',value:40,color:'#00d4ff'},{label:'Malware',value:25,color:'#ff4757'},
{label:'Social Eng.',value:20,color:'#ffc107'},{label:'BEC',value:15,color:'#00ffc8'}];
const total=data.reduce((s,d)=>s+d.value,0);let startAngle=-Math.PI/2;
data.forEach(d=>{const slice=(d.value/total)*Math.PI*2;
ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,startAngle,startAngle+slice);
ctx.fillStyle=d.color;ctx.fill();startAngle+=slice;});
ctx.beginPath();ctx.arc(cx,cy,r*0.55,0,Math.PI*2);
ctx.fillStyle='rgba(18,18,18,0.95)';ctx.fill();
ctx.fillStyle='#fff';ctx.font='bold 16px Inter';ctx.textAlign='center';ctx.fillText('Threat',cx,cy-8);
ctx.fillStyle='#999';ctx.font='13px Inter';ctx.fillText('Categories',cx,cy+14);
let ly=20;data.forEach(d=>{ctx.fillStyle=d.color;ctx.fillRect(W-130,ly,12,12);
ctx.fillStyle='#ccc';ctx.font='12px Inter';ctx.textAlign='left';ctx.fillText(d.label,W-112,ly+11);ly+=20;});}

/* #23 THREAT FEED */
function initThreatFeed(){
const container=document.getElementById('threat-feed-list');if(!container)return;
const threats=[
{title:'Critical: Zero-Day in Popular Browser Extension',date:'2025-05-10',desc:'Researchers discovered a zero-day vulnerability in a widely-used browser extension affecting millions of users.'},
{title:'Ransomware Group Targets Healthcare Sector',date:'2025-05-08',desc:'A new ransomware variant specifically targets hospital networks, encrypting patient records.'},
{title:'Phishing Campaign Uses AI-Generated Voice Clones',date:'2025-05-06',desc:'Attackers now use deepfake voice cloning in vishing calls to impersonate executives.'},
{title:'Supply Chain Attack via Compromised npm Package',date:'2025-05-04',desc:'Malicious code injected into popular npm package affects thousands of downstream projects.'},
{title:'New QR Code Phishing Wave ("Quishing") Detected',date:'2025-05-02',desc:'Attackers embed malicious URLs in QR codes sent via email, bypassing traditional link scanners.'}
];
container.innerHTML=threats.map(t=>`<div class="threat-feed-item"><h4>🚨 ${t.title}</h4><p>${t.desc}</p><div class="feed-date">📅 ${t.date}</div></div>`).join('');}

/* #22 EXPORT REPORT */
function initExportReport(){
document.getElementById('btn-export-report')?.addEventListener('click',()=>{
showToast('Preparing PDF report...','info',2000);
setTimeout(()=>window.print(),500);});}

/* #19 ENCRYPTED API KEY STORAGE (basic XOR obfuscation) */
window._encryptKey=function(key){
const salt='CyberHub2025';let enc='';
for(let i=0;i<key.length;i++)enc+=String.fromCharCode(key.charCodeAt(i)^salt.charCodeAt(i%salt.length));
return btoa(enc);};
window._decryptKey=function(enc){
try{const salt='CyberHub2025';const dec=atob(enc);let key='';
for(let i=0;i<dec.length;i++)key+=String.fromCharCode(dec.charCodeAt(i)^salt.charCodeAt(i%salt.length));
return key;}catch(e){return enc;}};

/* #20 RATE LIMITER */
const rateLimits={};
window.checkRateLimit=function(apiId,maxPerMin=4){
const now=Date.now();if(!rateLimits[apiId])rateLimits[apiId]=[];
rateLimits[apiId]=rateLimits[apiId].filter(t=>now-t<60000);
if(rateLimits[apiId].length>=maxPerMin){showToast(`Rate limit: wait before next ${apiId} request`,'warning',3000);return false;}
rateLimits[apiId].push(now);return true;};

/* #21 BASIC INPUT SANITIZER */
window.sanitizeInput=function(str){
if(!str)return'';
return str.replace(/<script[\s\S]*?<\/script>/gi,'')
.replace(/on\w+\s*=\s*["'][^"']*["']/gi,'')
.replace(/javascript\s*:/gi,'')
.replace(/<iframe[\s\S]*?<\/iframe>/gi,'');};

/* Password strength triggers badge */
(function(){
const origInput=document.getElementById('password-input');
if(origInput){origInput.addEventListener('input',function(){
if(this.value.length>=12&&/[0-9!@#$%^&*]/.test(this.value)&&/[a-z]/.test(this.value)&&/[A-Z]/.test(this.value)){
GAMIFICATION.badges.pw_master=true;if(typeof saveGamification==='function')saveGamification();
}});}
})();

/* Hygiene checklist XP */
document.querySelectorAll('.checklist-item input').forEach(cb=>{
cb.addEventListener('change',()=>{if(cb.checked)addXP(5);checkBadges();});});

/* ========================================
   CYBER SAFETY TRAINING MODULE
   ======================================== */
const TRAINING_MODULES=[
{id:'mod_phishing',title:'Recognizing Phishing Emails',icon:'📧',desc:'Learn to identify suspicious emails, spoofed senders, and social engineering tactics.',
lessons:[
{title:'What Makes an Email Phishing?',content:'Phishing emails impersonate trusted entities to steal credentials or install malware. Key red flags include: spoofed sender addresses, urgent/threatening language, generic greetings, suspicious links, and unexpected attachments.'},
{title:'Analyzing Sender Information',content:'Always check the full email address, not just the display name. Look for misspelled domains (paypa1.com), free email providers claiming to be corporations, and Reply-To mismatches.'},
{title:'Spotting Malicious Links',content:'Hover over links before clicking. Check for: IP addresses instead of domains, misspelled brand names, excessive subdomains, and URL shorteners hiding the real destination.'}
],
quiz:[
{q:'An email from "support@amaz0n-verify.com" asks you to confirm your order. What\'s the biggest red flag?',opts:['The email mentions an order','The domain uses zero instead of o and has extra words','It came to your inbox','It has a link'],correct:1,explain:'The domain "amaz0n-verify" uses character substitution (0 for o) and adds "-verify" — classic typosquatting.'},
{q:'You receive an email with the display name "Microsoft Security" but the address is msft-alerts@gmail.com. What type of attack is this?',opts:['Spear phishing','Display name spoofing','Whaling','Smishing'],correct:1,explain:'Display name spoofing uses a trusted name with a completely unrelated email address. Microsoft would never send from Gmail.'},
{q:'Which email header check is MOST reliable for detecting spoofed senders?',opts:['Subject line analysis','Display name verification','SPF/DKIM/DMARC authentication results','CC field inspection'],correct:2,explain:'SPF, DKIM, and DMARC are server-level authentication protocols that verify if the sending server is authorized for that domain.'},
{q:'A phishing email contains "Dear Valued Customer" instead of your name. This is an example of:',opts:['Spear phishing','Whaling','Mass phishing with generic greeting','Business Email Compromise'],correct:2,explain:'Generic greetings indicate mass-sent phishing. Legitimate services typically address you by name from their database.'},
{q:'You get an email saying "Your account will be deleted in 2 hours unless you verify now." What manipulation tactic is this?',opts:['Authority impersonation','Reward lure','Urgency and fear','Social proof'],correct:2,explain:'Creating artificial time pressure with threats of loss is the most common social engineering tactic in phishing emails.'}
]},
{id:'mod_urls',title:'Safe Browsing & URL Inspection',icon:'🔗',desc:'Master the art of inspecting URLs and browsing safely to avoid malicious websites.',
lessons:[
{title:'Anatomy of a URL',content:'A URL has: protocol (https://), subdomain, domain name, TLD (.com), path, and query parameters. The domain is what matters most — everything before the first "/" after the protocol.'},
{title:'Common URL Tricks',content:'Attackers use: typosquatting (g00gle.com), subdomain abuse (login.google.evil.com), URL shorteners (bit.ly/xyz), data URIs, and @ symbols to hide real destinations.'},
{title:'Safe Browsing Habits',content:'Always verify HTTPS padlock, type URLs directly instead of clicking links, use bookmarks for sensitive sites, keep browsers updated, and never enter credentials on unfamiliar pages.'}
],
quiz:[
{q:'In the URL "https://secure-login.paypal.com.evil-site.net/verify", what is the actual domain?',opts:['paypal.com','secure-login.paypal.com','evil-site.net','com.evil-site.net'],correct:2,explain:'The actual domain is always the last two parts before the first "/". Here, "evil-site.net" is the real domain — "paypal.com" is just a subdomain trick.'},
{q:'A link shows "https://google.com" as text but hovering reveals "https://g00gle-login.xyz". What technique is this?',opts:['URL shortening','Link text mismatch/masking','Subdomain abuse','DNS spoofing'],correct:1,explain:'Link text mismatch means the visible text differs from the actual href. Always hover to check the real URL.'},
{q:'Which URL is MOST likely safe?',opts:['http://192.168.1.1/banking','https://login-chase-verify.tk','https://www.chase.com/account','https://chase.com@evil.com/login'],correct:2,explain:'Only chase.com with HTTPS is the legitimate domain. Raw IPs, suspicious TLDs (.tk), and @ symbols in URLs are all red flags.'},
{q:'What does a URL shortener (bit.ly) actually hide?',opts:['The protocol type','The true destination URL','The file size','The server location'],correct:1,explain:'URL shorteners mask the real destination. Attackers use them to hide phishing URLs. Use URL expander tools to check them first.'},
{q:'You see "https://" with a padlock. Does this guarantee the site is safe?',opts:['Yes, HTTPS means it\'s verified safe','No, HTTPS only means encrypted connection','Yes, only legitimate sites get certificates','No, but it means no one can hack it'],correct:1,explain:'HTTPS means the connection is encrypted, NOT that the site is trustworthy. Attackers can easily get free SSL certificates for phishing sites.'}
]},
{id:'mod_social',title:'Social Engineering Defense',icon:'🎭',desc:'Recognize and resist manipulation techniques used by cybercriminals.',
lessons:[
{title:'Types of Social Engineering',content:'Common types: Phishing (email), Vishing (voice), Smishing (SMS), Pretexting (fake scenarios), Baiting (USB drops), Quid Pro Quo (fake help desk), and Tailgating (physical access).'},
{title:'Psychological Manipulation Tactics',content:'Attackers exploit: Authority (pretending to be IT/CEO), Urgency (act now!), Scarcity (limited time), Social Proof (everyone else did it), Reciprocity (we gave you something), and Fear (your account is compromised).'},
{title:'Building Your Human Firewall',content:'Verify requests through separate channels, never share passwords verbally or via email, be suspicious of unsolicited contact, report incidents immediately, and trust your instincts when something feels off.'}
],
quiz:[
{q:'A caller claims to be from your IT department and needs your password to "fix a critical server issue." What should you do?',opts:['Give them the password since it sounds urgent','Ask for their employee ID and call IT directly using a known number','Change your password first, then share the old one','Email them the password instead'],correct:1,explain:'Never share passwords. Verify identity by calling back on a known IT number. Legitimate IT never needs your password.'},
{q:'You find a USB drive labeled "Q4 Salary Review" in the parking lot. What\'s the safest action?',opts:['Plug it into a sandbox computer','Open it at home on personal laptop','Turn it in to IT/Security without plugging it in','Check it on your phone'],correct:2,explain:'USB baiting is a real attack vector. USB Rubber Ducky devices can install malware instantly. Never plug in unknown devices.'},
{q:'Your "CEO" sends a WhatsApp message asking you to urgently buy gift cards. What type of attack is this?',opts:['Ransomware','Business Email Compromise via smishing','Adware','Brute force attack'],correct:1,explain:'CEO fraud/BEC via messaging apps is increasingly common. Gift card scams are the #1 BEC payout method. Always verify via official channels.'},
{q:'Which psychological principle does "Only 2 spots left! Claim your prize NOW!" exploit?',opts:['Authority','Reciprocity','Scarcity and urgency','Consistency'],correct:2,explain:'Combining scarcity ("only 2 left") with urgency ("NOW") triggers FOMO and bypasses rational thinking — a powerful manipulation combo.'},
{q:'A "bank representative" calls about "suspicious activity" and asks you to verify your account by providing your SSN. What should you do?',opts:['Provide it since they called about security','Hang up and call the bank\'s official number directly','Ask them to verify their identity first','Give only the last 4 digits'],correct:1,explain:'Banks never ask for full SSN over the phone. Hang up and call the number on your card. This is classic vishing (voice phishing).'}
]},
{id:'mod_passwords',title:'Password & MFA Best Practices',icon:'🔐',desc:'Create unbreakable passwords and leverage multi-factor authentication.',
lessons:[
{title:'Creating Strong Passwords',content:'Use 14+ characters with mixed case, numbers, and symbols. Passphrases are even better (e.g., "Purple-Tiger-Runs-Fast-42!"). Never reuse passwords across sites.'},
{title:'Password Managers',content:'Use a password manager (Bitwarden, 1Password, KeePass) to generate and store unique passwords. You only need to remember one master password. Enable the browser extension for auto-fill.'},
{title:'Multi-Factor Authentication',content:'Enable MFA everywhere possible. Hardware keys (YubiKey) > Authenticator apps (Google Authenticator, Authy) > SMS codes. Never approve MFA prompts you didn\'t initiate (MFA fatigue attack).'}
],
quiz:[
{q:'Which password is STRONGEST?',opts:['P@ssw0rd123!','Correct-Horse-Battery-Staple-7','qwerty123456789','MyBirthday1990!'],correct:1,explain:'Long passphrases with random words, separators, and numbers provide the best entropy. Common substitutions (@ for a) in short passwords are easily cracked.'},
{q:'You get 5 unexpected MFA push notifications in a row. What is happening?',opts:['Your authenticator app is glitching','Someone is attempting an MFA fatigue attack','Your account password expired','The service is sending test notifications'],correct:1,explain:'MFA fatigue attacks flood you with prompts hoping you\'ll approve one by accident. Deny all unexpected prompts and change your password immediately.'},
{q:'What\'s the safest way to store passwords?',opts:['Written on a sticky note','In a text file on your desktop','In a reputable password manager with encryption','In your browser\'s built-in password save'],correct:2,explain:'Dedicated password managers use strong encryption and secure architecture. Browser-saved passwords can be extracted by malware more easily.'},
{q:'How often should you change passwords if no breach is detected?',opts:['Every 30 days','Every 90 days','Only when a breach occurs or compromise is suspected','Every week'],correct:2,explain:'NIST guidelines now recommend changing passwords only after suspected compromise. Frequent changes lead to weaker passwords and sticky notes.'},
{q:'Which MFA method is MOST resistant to phishing?',opts:['SMS text codes','Email verification codes','Hardware security key (FIDO2/WebAuthn)','Authenticator app TOTP codes'],correct:2,explain:'Hardware keys use cryptographic challenge-response tied to the specific domain, making them immune to phishing. SMS codes can be intercepted via SIM swapping.'}
]},
{id:'mod_incident',title:'Incident Reporting & Response',icon:'🚨',desc:'Know what to do when you encounter a security threat or breach.',
lessons:[
{title:'Recognizing a Security Incident',content:'Signs include: unexpected password changes, unfamiliar login locations, missing files, strange system behavior, unauthorized purchases, and colleagues receiving emails you didn\'t send.'},
{title:'Immediate Response Steps',content:'1) Don\'t panic. 2) Disconnect from network if malware suspected. 3) Don\'t delete evidence. 4) Report to IT/Security immediately. 5) Change passwords from a clean device. 6) Document everything.'},
{title:'Organizational Reporting',content:'Know your company\'s incident response plan and contacts. Time is critical — report within minutes, not hours. Provide: what happened, when, what you clicked/opened, and any error messages you saw.'}
],
quiz:[
{q:'You accidentally clicked a phishing link and entered your password. What\'s your FIRST action?',opts:['Delete the email and hope for the best','Immediately change the compromised password from a different device','Run a virus scan first','Wait to see if anything suspicious happens'],correct:1,explain:'Change the password immediately from a known-clean device. Then report the incident, enable MFA if not already active, and monitor for unauthorized access.'},
{q:'Your computer starts encrypting files and shows a ransom note. What should you do first?',opts:['Pay the ransom quickly','Disconnect from the network immediately','Try to decrypt the files yourself','Restart the computer'],correct:1,explain:'Disconnect immediately to prevent spread to network drives and other machines. Then report to IT. Never pay ransom — it funds criminals and doesn\'t guarantee recovery.'},
{q:'When reporting a security incident, which detail is LEAST important?',opts:['Exact time it occurred','What you were wearing','What you clicked or opened','Any error messages displayed'],correct:1,explain:'Incident reports need technical details: timestamps, actions taken, URLs clicked, files opened, and error messages. Personal details are irrelevant.'},
{q:'A coworker tells you they accidentally shared company data with an external party. What should you advise?',opts:['Don\'t worry, it happens','Report it to security/compliance immediately','Try to recall the email','Delete the conversation'],correct:1,explain:'Data exposure must be reported immediately for proper incident response, legal compliance (GDPR, etc.), and damage containment.'},
{q:'After a phishing incident is resolved, what should happen organizationally?',opts:['Nothing, move on','Post-incident review, update training, and share lessons learned','Fire the person who clicked','Block all email links permanently'],correct:1,explain:'Post-incident review identifies gaps, updates defenses, and creates training opportunities. Blame-free culture encourages reporting.'}
]}
];

let trainingProgress={};
let activeModuleId=null;
let activeQuizIdx=0;
let activeQuizScore=0;
let activeQuizAnswered=false;

function initTrainingModules(){
loadTrainingProgress();
renderTrainingGrid();
document.getElementById('btn-back-to-modules')?.addEventListener('click',()=>{
document.getElementById('training-grid-view').style.display='';
document.getElementById('training-active-view').style.display='none';
activeModuleId=null;
});
}

function loadTrainingProgress(){
try{const s=localStorage.getItem('cyberHubTraining');if(s)trainingProgress=JSON.parse(s);}catch(e){trainingProgress={};}}
function saveTrainingProgress(){localStorage.setItem('cyberHubTraining',JSON.stringify(trainingProgress));}

function renderTrainingGrid(){
const grid=document.getElementById('training-modules-grid');if(!grid)return;
const completedCount=TRAINING_MODULES.filter(m=>trainingProgress[m.id]?.completed).length;
grid.innerHTML=TRAINING_MODULES.map((m,i)=>{
const prog=trainingProgress[m.id]||{};
const status=prog.completed?'completed':prog.started?'in-progress':'locked';
const statusLabel=prog.completed?`✅ Passed (${prog.bestScore||0}%)`:prog.started?'🔄 In Progress':(i===0||trainingProgress[TRAINING_MODULES[i-1]?.id]?.completed)?'🔓 Available':'🔒 Locked';
const canStart=i===0||trainingProgress[TRAINING_MODULES[i-1]?.id]?.completed||prog.started;
return `<div class="tm-card ${status}" data-module="${m.id}">
<div class="tm-icon">${m.icon}</div>
<div class="tm-info"><h4>${m.title}</h4><p>${m.desc}</p></div>
<div class="tm-status">${statusLabel}</div>
${canStart?`<button class="btn btn-primary tm-start-btn" data-mid="${m.id}">${prog.completed?'Review':'Start'}</button>`:''}
</div>`;
}).join('')+`<div class="tm-progress-summary">
<div class="tm-prog-bar-wrap"><div class="tm-prog-bar" style="width:${(completedCount/TRAINING_MODULES.length)*100}%"></div></div>
<span>${completedCount}/${TRAINING_MODULES.length} Modules Complete</span>
${completedCount===TRAINING_MODULES.length?'<button class="btn btn-primary" id="btn-get-cert" style="margin-top:12px;">🎓 Get Certificate</button>':''}
</div>`;
// Bind start buttons
grid.querySelectorAll('.tm-start-btn').forEach(btn=>{
btn.addEventListener('click',()=>openModule(btn.dataset.mid));
});
document.getElementById('btn-get-cert')?.addEventListener('click',showCertificate);
}

function openModule(moduleId){
const mod=TRAINING_MODULES.find(m=>m.id===moduleId);if(!mod)return;
activeModuleId=moduleId;activeQuizIdx=0;activeQuizScore=0;activeQuizAnswered=false;
if(!trainingProgress[moduleId])trainingProgress[moduleId]={started:true};
else trainingProgress[moduleId].started=true;
saveTrainingProgress();
document.getElementById('training-grid-view').style.display='none';
const view=document.getElementById('training-active-view');view.style.display='block';
document.getElementById('tm-active-title').textContent=mod.icon+' '+mod.title;
// Render lessons
const lessonsHtml=mod.lessons.map((l,i)=>`<div class="tm-lesson">
<h4>Lesson ${i+1}: ${l.title}</h4><p>${l.content}</p></div>`).join('');
document.getElementById('tm-lessons-content').innerHTML=lessonsHtml;
// Render quiz
document.getElementById('tm-quiz-section').style.display='none';
document.getElementById('tm-lessons-section').style.display='block';
document.getElementById('tm-quiz-results').style.display='none';
document.getElementById('btn-start-module-quiz').onclick=()=>{
document.getElementById('tm-lessons-section').style.display='none';
document.getElementById('tm-quiz-section').style.display='block';
renderModuleQuizQ(mod);
};
}

function renderModuleQuizQ(mod){
const qData=mod.quiz[activeQuizIdx];
document.getElementById('tm-quiz-question').textContent=qData.q;
document.getElementById('tm-quiz-progress').textContent=`Question ${activeQuizIdx+1}/${mod.quiz.length} • Score: ${activeQuizScore}`;
document.getElementById('tm-quiz-explain').hidden=true;
activeQuizAnswered=false;
const optsEl=document.getElementById('tm-quiz-options');
optsEl.innerHTML=qData.opts.map((o,i)=>`<button class="quiz-option" data-idx="${i}">${o}</button>`).join('');
optsEl.querySelectorAll('.quiz-option').forEach(btn=>{
btn.addEventListener('click',()=>{
if(activeQuizAnswered)return;activeQuizAnswered=true;
const idx=parseInt(btn.dataset.idx);const isCorrect=idx===qData.correct;
btn.classList.add(isCorrect?'correct':'wrong');
if(isCorrect){activeQuizScore++;addXP(8);}
else optsEl.querySelectorAll('.quiz-option')[qData.correct].classList.add('correct');
optsEl.querySelectorAll('.quiz-option').forEach(b=>b.disabled=true);
document.getElementById('tm-quiz-explain').textContent=qData.explain;
document.getElementById('tm-quiz-explain').hidden=false;
document.getElementById('tm-quiz-progress').textContent=`Question ${activeQuizIdx+1}/${mod.quiz.length} • Score: ${activeQuizScore}`;
});});
document.getElementById('btn-next-module-quiz').onclick=()=>{
if(!activeQuizAnswered){if(typeof showToast==='function')showToast('Select an answer first','warning');return;}
if(activeQuizIdx<mod.quiz.length-1){activeQuizIdx++;activeQuizAnswered=false;renderModuleQuizQ(mod);}
else finishModuleQuiz(mod);
};
}

function finishModuleQuiz(mod){
const pct=Math.round((activeQuizScore/mod.quiz.length)*100);
const passed=pct>=80;
document.getElementById('tm-quiz-section').style.display='none';
const resultsEl=document.getElementById('tm-quiz-results');resultsEl.style.display='block';
resultsEl.innerHTML=`<div class="tm-result-card ${passed?'tm-pass':'tm-fail'}">
<div class="tm-result-icon">${passed?'🎉':'😔'}</div>
<h3>${passed?'Module Passed!':'Not Quite...'}</h3>
<div class="tm-result-score">${pct}%</div>
<p>${passed?'Excellent work! You demonstrated strong understanding of this topic.':'You need 80% to pass. Review the lessons and try again.'}</p>
<div class="tm-result-detail">${activeQuizScore}/${mod.quiz.length} correct answers</div>
${passed?'':'<button class="btn btn-primary" id="btn-retry-quiz">🔄 Try Again</button>'}
<button class="btn btn-secondary-glass" id="btn-back-modules" style="margin-top:10px;">← Back to Modules</button>
</div>`;
if(passed){
if(!trainingProgress[mod.id])trainingProgress[mod.id]={};
trainingProgress[mod.id].completed=true;
trainingProgress[mod.id].bestScore=Math.max(trainingProgress[mod.id].bestScore||0,pct);
saveTrainingProgress();addXP(30);
if(pct===100){GAMIFICATION.badges.perfect_module=true;saveGamification();}
const allDone=TRAINING_MODULES.every(m=>trainingProgress[m.id]?.completed);
if(allDone){GAMIFICATION.badges.training_grad=true;saveGamification();showToast('🎓 All modules complete! You can now get your certificate!','success',5000);}
checkBadges();
}
document.getElementById('btn-retry-quiz')?.addEventListener('click',()=>{
activeQuizIdx=0;activeQuizScore=0;activeQuizAnswered=false;
document.getElementById('tm-quiz-results').style.display='none';
document.getElementById('tm-quiz-section').style.display='block';
renderModuleQuizQ(mod);
});
document.getElementById('btn-back-modules')?.addEventListener('click',()=>{
document.getElementById('training-active-view').style.display='none';
document.getElementById('training-grid-view').style.display='';
renderTrainingGrid();
});
}

function showCertificate(){
const name=prompt('Enter your full name for the certificate:');
if(!name)return;
const date=new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});
const certHtml=`<div class="cert-container">
<div class="cert-border"><div class="cert-inner">
<div class="cert-badge">🛡️</div>
<h2 class="cert-title">Certificate of Completion</h2>
<p class="cert-subtitle">CYBER SAFETY AWARENESS PROGRAM</p>
<div class="cert-divider"></div>
<p class="cert-present">This certifies that</p>
<h3 class="cert-name">${escHtml(name)}</h3>
<p class="cert-body">has successfully completed all five modules of the Cyber Awareness Hub training program, demonstrating proficiency in phishing detection, safe browsing, social engineering defense, password security, and incident response.</p>
<div class="cert-footer">
<div class="cert-date"><strong>Date:</strong> ${date}</div>
<div class="cert-issuer"><strong>Issued by:</strong> CyberGuard Architect</div>
</div>
<button class="btn btn-primary cert-print-btn no-print" id="cert-print">🖨️ Print Certificate</button>
</div></div></div>`;
const overlay=document.createElement('div');overlay.className='cert-overlay';overlay.innerHTML=certHtml+'<button class="btn btn-secondary-glass cert-close-btn no-print" id="cert-close">✕ Close</button>';
document.body.appendChild(overlay);
document.getElementById('cert-print').addEventListener('click',()=>window.print());
document.getElementById('cert-close').addEventListener('click',()=>overlay.remove());
overlay.addEventListener('click',e=>{if(e.target===overlay)overlay.remove();});
}

/* Extra badges for new features */
BADGE_DEFS.push(
{id:'threat_hunter',name:'🔎 Threat Hunter',desc:'Scan 10+ URLs',check:()=>parseInt(localStorage.getItem('cyberHubUrlsScanned')||'0')>=10},
{id:'student',name:'📚 Student',desc:'Complete first training module',check:()=>TRAINING_MODULES.some(m=>trainingProgress[m.id]?.completed)},
{id:'training_grad',name:'🎓 Graduate',desc:'Complete all training modules',check:()=>TRAINING_MODULES.every(m=>trainingProgress[m.id]?.completed)},
{id:'perfect_module',name:'🏅 Perfect Score',desc:'Score 100% on a training quiz',check:()=>GAMIFICATION.badges.perfect_module},
{id:'forensic_analyst',name:'🔬 Forensic Analyst',desc:'Analyze 5+ emails',check:()=>parseInt(localStorage.getItem('cyberHubEmailsAnalyzed')||'0')>=5}
);
