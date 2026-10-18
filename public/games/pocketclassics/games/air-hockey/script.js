document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements (No changes) ---
    const mainMenu = document.getElementById('main-menu');
    const difficultyMenu = document.getElementById('difficulty-menu');
    const settingsMenu = document.getElementById('settings-menu');
    const gameContainer = document.getElementById('game-container');
    const gameWrapper = document.getElementById('game-wrapper');
    const pvpButton = document.getElementById('pvp-button');
    const pvaButton = document.getElementById('pva-button');
    const settingsButton = document.getElementById('settings-button');
    const homeButton = document.getElementById('home-button');
    const difficultyBackButton = document.getElementById('difficulty-back-button');
    const settingsBackButton = document.getElementById('settings-back-button');
    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');
    const playAgainButton = document.getElementById('play-again-button');
    const backToMenuIngameButton = document.getElementById('back-to-menu-ingame-button');
    const puckSpeedSlider = document.getElementById('puck-speed-slider');
    const puckSpeedValueEl = document.getElementById('puck-speed-value');
    const canvas = document.getElementById('game-canvas');
    const ctx = canvas.getContext('2d');
    const scorePlayer1El = document.getElementById('score-player1');
    const scorePlayer2El = document.getElementById('score-player2');
    const winPopup = document.getElementById('win-popup');
    const winMessageEl = document.getElementById('win-message');
    const particleCanvas = document.getElementById('particle-canvas');
    const particleCtx = particleCanvas.getContext('2d');

    // --- Sound Management (No changes) ---
    const bgMusic = new Audio('sounds/background.mp3');
    const hitSound = new Audio('sounds/hit.wav');
    const scoreSound = new Audio('sounds/score.wav');
    const winSound = new Audio('sounds/win.wav');
    const clickSound = new Audio('sounds/click.wav');
    let isMusicEnabled = true, areSfxEnabled = true;
    function playSound(sound) { if (areSfxEnabled) { sound.currentTime = 0; sound.play().catch(e => {}); } }
    function playMusic() { if (isMusicEnabled && bgMusic.paused) { bgMusic.loop = true; bgMusic.volume = 0.5; bgMusic.play().catch(e => {}); } }
    function stopMusic() { bgMusic.pause(); bgMusic.currentTime = 0; }
    
    // --- Game State & Physics Constants ---
    const WINNING_SCORE = 7;
    const FRICTION = 0.998;
    let puckSpeedMultiplier = 1.0;
    let gameMode = null, difficulty = null, animationId = null, particleAnimationId = null;
    let paddle1, paddle2, puck;
    let lastScoredBy = null;

    // --- UI Navigation & Settings (No changes) ---
    function showScreen(screen) {
        mainMenu.classList.remove('active');
        difficultyMenu.classList.remove('active');
        settingsMenu.classList.remove('active');
        gameContainer.style.display = 'none';
        if (screen === 'main') mainMenu.classList.add('active');
        if (screen === 'difficulty') difficultyMenu.classList.add('active');
        if (screen === 'settings') settingsMenu.classList.add('active');
        if (screen === 'game') gameContainer.style.display = 'block';
    }
    pvpButton.addEventListener('click', () => { playSound(clickSound); gameMode = 'pvp'; startGame(); });
    pvaButton.addEventListener('click', () => { playSound(clickSound); gameMode = 'pva'; showScreen('difficulty'); });
    homeButton.addEventListener('click', () => { 
        playSound(clickSound); 
        if (window.parent && window.parent !== window) {
            window.parent.postMessage({ type: 'ARCADE_EXIT' }, '*');
        } else {
            window.location.href = '/games/hub'; 
        }
    });
    difficultyMenu.querySelectorAll('button[data-difficulty]').forEach(button => { button.addEventListener('click', () => { playSound(clickSound); difficulty = button.dataset.difficulty; startGame(); }); });
    difficultyBackButton.addEventListener('click', () => { playSound(clickSound); showScreen('main'); });
    settingsBackButton.addEventListener('click', () => { playSound(clickSound); showScreen('main'); });
    playAgainButton.addEventListener('click', () => { playSound(clickSound); winPopup.style.display = 'none'; stopParticleAnimation(); showScreen('main'); });
    backToMenuIngameButton.addEventListener('click', () => { playSound(clickSound); if(animationId) cancelAnimationFrame(animationId); animationId = null; showScreen('main'); });
    musicToggle.addEventListener('change', (e) => { isMusicEnabled = e.target.checked; localStorage.setItem('musicEnabled', isMusicEnabled); isMusicEnabled ? playMusic() : stopMusic(); });
    sfxToggle.addEventListener('change', (e) => { areSfxEnabled = e.target.checked; localStorage.setItem('sfxEnabled', areSfxEnabled); clickSound.currentTime = 0; clickSound.play().catch(e => {}); });
    puckSpeedSlider.addEventListener('input', (e) => { puckSpeedMultiplier = parseFloat(e.target.value); puckSpeedValueEl.textContent = `${puckSpeedMultiplier.toFixed(1)}x`; localStorage.setItem('puckSpeed', puckSpeedMultiplier); });
    function loadSettings() {
        const savedMusicSetting = localStorage.getItem('musicEnabled'); if (savedMusicSetting !== null) isMusicEnabled = savedMusicSetting === 'true'; musicToggle.checked = isMusicEnabled;
        const savedSfxSetting = localStorage.getItem('sfxEnabled'); if (savedSfxSetting !== null) areSfxEnabled = savedSfxSetting === 'true'; sfxToggle.checked = areSfxEnabled;
        const savedPuckSpeed = localStorage.getItem('puckSpeed'); if (savedPuckSpeed !== null) { puckSpeedMultiplier = parseFloat(savedPuckSpeed); puckSpeedSlider.value = puckSpeedMultiplier; puckSpeedValueEl.textContent = `${puckSpeedMultiplier.toFixed(1)}x`; }
    }
    
    // --- Game Setup, Initialization & Drawing (No changes) ---
    function resizeCanvas() { const rect = gameWrapper.getBoundingClientRect(); canvas.width = rect.width; canvas.height = rect.height; if (!animationId) initGameObjects(); }
    function initGameObjects() { const paddleRadius = canvas.width * 0.08; const puckRadius = canvas.width * 0.05; const score1 = paddle1 ? paddle1.score : 0; const score2 = paddle2 ? paddle2.score : 0; paddle1 = { x: canvas.width / 2, y: canvas.height * 0.75, radius: paddleRadius, score: score1, color: '#ff00ff', active: false }; paddle2 = { x: canvas.width / 2, y: canvas.height * 0.25, radius: paddleRadius, score: score2, color: '#00ffff', active: false }; puck = { x: canvas.width / 2, y: canvas.height / 2, radius: puckRadius, dx: 0, dy: 0, color: '#ffffff', isStationary: false }; }
    window.addEventListener('resize', resizeCanvas);
    function updateScore() { if(paddle1 && paddle2){ scorePlayer1El.textContent = paddle1.score; scorePlayer2El.textContent = paddle2.score; } }
    function startGame() { resizeCanvas(); resetGame(); showScreen('game'); if (animationId) cancelAnimationFrame(animationId); animationId = null; playMusic(); gameLoop(); }
    function resetGame() { if(paddle1) paddle1.score = 0; if(paddle2) paddle2.score = 0; lastScoredBy = null; updateScore(); resetRound(); }
    function resetRound() { initGameObjects(); updateScore(); puck.dx = 0; puck.dy = 0; puck.isStationary = true; if (lastScoredBy === 1) { puck.y = canvas.height * 0.35; } else if (lastScoredBy === 2) { puck.y = canvas.height * 0.65; } else { puck.y = canvas.height / 2; } setTimeout(() => { const speed = (canvas.height * 0.01) * puckSpeedMultiplier; let angle = Math.random() > 0.5 ? (Math.random() * Math.PI / 2) + Math.PI / 4 : (Math.random() * Math.PI / 2) + Math.PI * 1.25; puck.dx = Math.cos(angle) * speed; puck.dy = Math.sin(angle) * speed; puck.isStationary = false; }, 750); }
    function drawTable() { ctx.clearRect(0, 0, canvas.width, canvas.height); const goalWidth = canvas.width * 0.5; const goalHeight = canvas.height * 0.1; ctx.globalAlpha = 0.2; ctx.shadowBlur = 20; ctx.fillStyle = paddle1.color; ctx.shadowColor = paddle1.color; ctx.fillRect(canvas.width / 2 - goalWidth / 2, 0, goalWidth, goalHeight); ctx.fillStyle = paddle2.color; ctx.shadowColor = paddle2.color; ctx.fillRect(canvas.width / 2 - goalWidth / 2, canvas.height - goalHeight, goalWidth, goalHeight); ctx.globalAlpha = 1.0; ctx.shadowBlur = 0; ctx.shadowColor = '#00ffff'; ctx.shadowBlur = 20; ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)'; ctx.lineWidth = 3; ctx.beginPath(); ctx.moveTo(0, canvas.height / 2); ctx.lineTo(canvas.width, canvas.height / 2); ctx.stroke(); ctx.beginPath(); ctx.arc(canvas.width / 2, canvas.height / 2, canvas.width * 0.2, 0, Math.PI * 2); ctx.stroke(); const mainGoalWidth = canvas.width * 0.4; ctx.shadowColor = '#ff00ff'; ctx.shadowBlur = 15; ctx.lineWidth = 5; ctx.beginPath(); ctx.moveTo(canvas.width/2 - mainGoalWidth/2, 0); ctx.lineTo(canvas.width/2 + mainGoalWidth/2, 0); ctx.stroke(); ctx.beginPath(); ctx.moveTo(canvas.width/2 - mainGoalWidth/2, canvas.height); ctx.lineTo(canvas.width/2 + mainGoalWidth/2, canvas.height); ctx.stroke(); ctx.shadowBlur = 0; }
    function drawCircle(x, y, radius, color) { ctx.shadowColor = color; ctx.shadowBlur = 15; ctx.fillStyle = color; ctx.beginPath(); ctx.arc(x, y, radius, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0; }
    
    // --- Input and AI Logic (No changes) ---
    const activeTouches = {}; function getTouchPos(e) { const rect = canvas.getBoundingClientRect(); return { x: e.clientX - rect.left, y: e.clientY - rect.top }; } function handleDown(e) { e.preventDefault(); const touches = e.changedTouches ? e.changedTouches : [e]; for (const touch of touches) { const pos = getTouchPos(touch); const id = e.changedTouches ? touch.identifier : 'mouse'; if (pos.y > canvas.height / 2) { activeTouches[id] = { paddle: paddle1, pos }; paddle1.active = true; } else if (gameMode === 'pvp') { activeTouches[id] = { paddle: paddle2, pos }; paddle2.active = true; } } } function handleMove(e) { e.preventDefault(); const touches = e.changedTouches ? e.changedTouches : [e]; for (const touch of touches) { const id = e.changedTouches ? touch.identifier : 'mouse'; if (activeTouches[id]) { const pos = getTouchPos(touch); activeTouches[id].paddle.x = pos.x; activeTouches[id].paddle.y = pos.y; } } } function handleUp(e) { e.preventDefault(); const touches = e.changedTouches ? e.changedTouches : [e]; for (const touch of touches) { const id = e.changedTouches ? touch.identifier : 'mouse'; if (activeTouches[id]) { activeTouches[id].paddle.active = false; delete activeTouches[id]; } } } canvas.addEventListener('mousedown', handleDown); canvas.addEventListener('mousemove', handleMove); window.addEventListener('mouseup', handleUp); canvas.addEventListener('touchstart', handleDown, { passive: false }); canvas.addEventListener('touchmove', handleMove, { passive: false }); canvas.addEventListener('touchend', handleUp); canvas.addEventListener('touchcancel', handleUp);
    function clampPaddlePositions() { if (!paddle1 || !paddle2) return; paddle1.x = Math.max(paddle1.radius, Math.min(paddle1.x, canvas.width - paddle1.radius)); paddle1.y = Math.max(canvas.height / 2 + paddle1.radius, Math.min(paddle1.y, canvas.height - paddle1.radius)); if (gameMode === 'pvp') { paddle2.x = Math.max(paddle2.radius, Math.min(paddle2.x, canvas.width - paddle2.radius)); paddle2.y = Math.max(paddle2.radius, Math.min(paddle2.y, canvas.height / 2 - paddle2.radius)); } }
    function moveAI() { if (paddle2.active) return; let targetX = puck.x, speedMultiplier; switch (difficulty) { case 'easy': speedMultiplier = 0.04; break; case 'medium': speedMultiplier = 0.08; break; case 'hard': speedMultiplier = 0.15; break; } if (puck.dy < 0) { paddle2.x += (targetX - paddle2.x) * speedMultiplier; } else { const defensiveY = canvas.height * 0.25; paddle2.x += (canvas.width / 2 - paddle2.x) * 0.04; paddle2.y += (defensiveY - paddle2.y) * 0.04; } paddle2.x = Math.max(paddle2.radius, Math.min(paddle2.x, canvas.width - paddle2.radius)); paddle2.y = Math.max(paddle2.radius, Math.min(paddle2.y, canvas.height / 2 - paddle2.radius)); }
    
    // --- Collision Logic ---
    function checkCollisions() {
        if (!puck || !paddle1 || !paddle2) return;
        if (puck.x < puck.radius) { puck.x = puck.radius; puck.dx *= -1; }
        if (puck.x > canvas.width - puck.radius) { puck.x = canvas.width - puck.radius; puck.dx *= -1; }
        [paddle1, paddle2].forEach(paddle => {
            const dist = Math.hypot(puck.x - paddle.x, puck.y - paddle.y);
            if (dist < puck.radius + paddle.radius) {
                playSound(hitSound);
                const angle = Math.atan2(puck.y - paddle.y, puck.x - paddle.x);
                const overlap = (puck.radius + paddle.radius) - dist;
                puck.x += Math.cos(angle) * overlap;
                puck.y += Math.sin(angle) * overlap;

                // --- THE FIX IS HERE ---
                // EXPLANATION: Instead of a small boost, we establish a new, powerful base speed on every hit.
                // This prevents the puck from getting sluggish during long rallies due to friction.
                const baseHitSpeed = (canvas.height * 0.015) * puckSpeedMultiplier; // A powerful base speed for a satisfying hit
                const maxSpeed = (canvas.height * 0.03) * puckSpeedMultiplier;     // The absolute maximum speed
                const currentSpeed = Math.hypot(puck.dx, puck.dy);

                // The new speed will be the base hit speed, or a little faster than the current speed if it was already moving fast.
                const newSpeed = Math.max(baseHitSpeed, currentSpeed * 1.02);

                // We still cap the speed to prevent it from getting uncontrollably fast.
                const finalSpeed = Math.min(newSpeed, maxSpeed);
                
                puck.dx = Math.cos(angle) * finalSpeed;
                puck.dy = Math.sin(angle) * finalSpeed;
                // --- END OF FIX ---

                if (paddle === paddle2 && gameMode === 'pva') { paddle2.active = true; setTimeout(() => { paddle2.active = false; }, 200); }
            }
        });
        const goalWidth = canvas.width * 0.4; const goalLeft = canvas.width/2 - goalWidth/2; const goalRight = canvas.width/2 + goalWidth/2;
        if (puck.y < puck.radius) { if (puck.x > goalLeft && puck.x < goalRight) { playSound(scoreSound); paddle1.score++; lastScoredBy = 1; if (checkWin()) return; resetRound(); } else { puck.y = puck.radius; puck.dy *= -1; } }
        if (puck.y > canvas.height - puck.radius) { if (puck.x > goalLeft && puck.x < goalRight) { playSound(scoreSound); paddle2.score++; lastScoredBy = 2; if (checkWin()) return; resetRound(); } else { puck.y = canvas.height - puck.radius; puck.dy *= -1; } }
    }
    
    // --- Game Loop, Win, and Particle Logic ---
    function checkWin() { if (paddle1.score >= WINNING_SCORE) { endGame("Player 1 Wins!"); return true; } else if (paddle2.score >= WINNING_SCORE) { endGame(`${gameMode === 'pvp' ? "Player 2" : "AI"} Wins!`); return true; } return false; }
    function endGame(message) { 
        playSound(winSound); 
        if(animationId) cancelAnimationFrame(animationId); 
        animationId = null; 
        winMessageEl.textContent = message; 
        winPopup.style.display = 'flex'; 
        startParticleAnimation(); 

        if (window.parent && window.parent !== window) {
            const player1Won = paddle1.score >= WINNING_SCORE;
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: player1Won ? 'win' : 'loss',
                score: paddle1.score * 20
            }, '*');
        }
    }
    function gameLoop() { if (!puck.isStationary) { puck.dx *= FRICTION; puck.dy *= FRICTION; puck.x += puck.dx; puck.y += puck.dy; } clampPaddlePositions(); if (gameMode === 'pva') { moveAI(); } checkCollisions(); drawTable(); drawCircle(paddle1.x, paddle1.y, paddle1.radius, paddle1.color); drawCircle(paddle2.x, paddle2.y, paddle2.radius, paddle2.color); drawCircle(puck.x, puck.y, puck.radius, puck.color); animationId = requestAnimationFrame(gameLoop); }
    let particles = []; function Particle(x, y, radius, color, velocity) { this.x = x; this.y = y; this.radius = radius; this.color = color; this.velocity = velocity; this.alpha = 1; this.draw = () => { particleCtx.save(); particleCtx.globalAlpha = this.alpha; particleCtx.beginPath(); particleCtx.arc(this.x, this.y, this.radius, 0, Math.PI * 2, false); particleCtx.fillStyle = this.color; particleCtx.fill(); particleCtx.restore(); }; this.update = () => { this.draw(); this.velocity.y += 0.05; this.x += this.velocity.x; this.y += this.velocity.y; this.alpha -= 0.015; }; }
    function initParticles() { particles = []; particleCanvas.width = window.innerWidth; particleCanvas.height = window.innerHeight; const particleCount = 250; const colors = ['#00ffff', '#ff00ff', '#ffffff', '#ff1b4c']; const centerX = particleCanvas.width / 2; const centerY = particleCanvas.height / 2; for (let i = 0; i < particleCount; i++) { const angle = Math.random() * Math.PI * 2; const speed = Math.random() * 12 + 2; const velocity = { x: Math.cos(angle) * speed, y: Math.sin(angle) * speed }; particles.push(new Particle(centerX, centerY, Math.random() * 3 + 1, colors[Math.floor(Math.random() * colors.length)], velocity)); } }
    function animateParticles() { particleCtx.fillStyle = 'rgba(0, 0, 0, 0.1)'; particleCtx.fillRect(0, 0, particleCanvas.width, particleCanvas.height); particles.forEach((p, i) => { p.alpha > 0 ? p.update() : particles.splice(i, 1); }); particleAnimationId = (particles.length > 0) ? requestAnimationFrame(animateParticles) : null; }
    function startParticleAnimation() { initParticles(); animateParticles(); }
    function stopParticleAnimation() { cancelAnimationFrame(particleAnimationId); particleAnimationId = null; particleCtx.clearRect(0, 0, particleCanvas.width, particleCanvas.height); }
    
    // --- Initial setup ---
    document.body.addEventListener('click', playMusic, { once: true });
    document.body.addEventListener('touchstart', playMusic, { once: true });
    loadSettings();
    resizeCanvas();
    showScreen('main');
});