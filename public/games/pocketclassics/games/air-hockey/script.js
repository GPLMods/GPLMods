document.addEventListener('DOMContentLoaded', () => {
    // --- Universal Arcade Helper ---
    const helper = window.ArcadeHelper ? window.ArcadeHelper.init({
        menuMusic: 'sounds/menu-music.mp3',
        gameMusic: 'sounds/background.mp3'
    }) : null;

    // --- DOM Elements ---
    const mainMenu = document.getElementById('main-menu');
    const difficultyMenu = document.getElementById('difficulty-menu');
    const settingsMenu = document.getElementById('settings-menu');
    const gameContainer = document.getElementById('game-container');
    const gameWrapper = document.getElementById('game-wrapper');

    const pvpButton = document.getElementById('pvp-button');
    const pvaButton = document.getElementById('pva-button');
    const settingsButton = document.getElementById('settings-button');
    const difficultyBackButton = document.getElementById('difficulty-back-button');
    const settingsBackButton = document.getElementById('settings-back-button');
    const playAgainButton = document.getElementById('play-again-button');
    const winMenuButton = document.getElementById('win-menu-button');
    const backToMenuIngameButton = document.getElementById('back-to-menu-ingame-button');
    const hudRestartBtn = document.getElementById('hud-restart-btn');
    const hudMatchLabel = document.getElementById('hud-match-label');

    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');
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

    // --- Audio Elements ---
    const hitSound = document.getElementById('hit-sound');
    const scoreSound = document.getElementById('score-sound');
    const winSound = document.getElementById('win-sound');
    const clickSound = document.getElementById('click-sound');

    function playSfx(snd) {
        if (helper) helper.audio.playSfx(snd);
        else if (snd) { snd.currentTime = 0; snd.play().catch(() => {}); }
    }
    function playClick() { playSfx(clickSound); }

    if (helper) helper.audio.playMenuMusic();

    // Sync settings
    if (musicToggle) {
        musicToggle.checked = helper ? helper.audio.musicEnabled : (localStorage.getItem('arc_music_enabled') !== 'false');
        musicToggle.addEventListener('change', (e) => {
            if (helper) helper.audio.setMusicEnabled(e.target.checked);
        });
    }
    if (sfxToggle) {
        sfxToggle.checked = helper ? helper.audio.sfxEnabled : (localStorage.getItem('arc_sfx_enabled') !== 'false');
        sfxToggle.addEventListener('change', (e) => {
            if (helper) helper.audio.setSfxEnabled(e.target.checked);
        });
    }

    // --- Game Physics & Constants ---
    const WINNING_SCORE = 7;
    const FRICTION = 0.994;
    let puckSpeedMultiplier = parseFloat(localStorage.getItem('arc_puck_speed') || '1.0');
    if (puckSpeedSlider) {
        puckSpeedSlider.value = puckSpeedMultiplier;
        if (puckSpeedValueEl) puckSpeedValueEl.textContent = `${puckSpeedMultiplier.toFixed(1)}x`;
        puckSpeedSlider.addEventListener('input', (e) => {
            puckSpeedMultiplier = parseFloat(e.target.value);
            if (puckSpeedValueEl) puckSpeedValueEl.textContent = `${puckSpeedMultiplier.toFixed(1)}x`;
            localStorage.setItem('arc_puck_speed', puckSpeedMultiplier);
        });
    }

    let gameMode = 'pva'; // 'pva' | 'pvp'
    let difficulty = 'medium'; // 'easy' | 'medium' | 'hard'
    let animationId = null;
    let particleAnimationId = null;
    let paddle1 = null, paddle2 = null, puck = null;
    let lastScoredBy = null;
    let isGamePaused = false;

    // --- Match Session Scoreboard Comparison (Requirement: player 1 (4) and player 2 (5)) ---
    let sessP1 = parseInt(localStorage.getItem('arc_airhockey_p1') || '0', 10);
    let sessP2 = parseInt(localStorage.getItem('arc_airhockey_p2') || '0', 10);

    function updateAirHockeyScoreboard() {
        const p1El = document.getElementById('sessP1Wins');
        const p2El = document.getElementById('sessP2Wins');
        const p2Lbl = document.getElementById('sessP2Label');
        const pill1 = document.getElementById('pillP1');
        const pill2 = document.getElementById('pillP2');
        if (p1El) p1El.textContent = sessP1;
        if (p2El) p2El.textContent = sessP2;
        if (p2Lbl) p2Lbl.textContent = gameMode === 'pvp' ? 'P2' : 'AI';
        if (pill1 && pill2) {
            pill1.classList.toggle('leading', sessP1 > sessP2);
            pill2.classList.toggle('leading', sessP2 > sessP1);
        }
    }
    updateAirHockeyScoreboard();

    // Keyboard state
    const keysDown = {};
    window.addEventListener('keydown', (e) => {
        keysDown[e.code] = true;
        if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Space'].includes(e.code)) {
            if (gameContainer.style.display === 'block') e.preventDefault();
        }
    });
    window.addEventListener('keyup', (e) => {
        keysDown[e.code] = false;
    });

    // --- Screen Navigation ---
    function showScreen(screen) {
        mainMenu.classList.remove('active');
        difficultyMenu.classList.remove('active');
        settingsMenu.classList.remove('active');
        winPopup.style.display = 'none';
        stopParticleAnimation();

        if (screen === 'main') {
            gameContainer.style.display = 'none';
            mainMenu.classList.add('active');
            if (animationId) cancelAnimationFrame(animationId);
            animationId = null;
            if (helper) helper.audio.playMenuMusic();
        } else if (screen === 'difficulty') {
            gameContainer.style.display = 'none';
            difficultyMenu.classList.add('active');
            if (helper) helper.audio.playMenuMusic();
        } else if (screen === 'settings') {
            settingsMenu.classList.add('active');
        } else if (screen === 'game') {
            mainMenu.classList.remove('active');
            difficultyMenu.classList.remove('active');
            gameContainer.style.display = 'block';
            if (helper) helper.audio.playGameMusic();
        }
    }

    pvpButton?.addEventListener('click', () => {
        playClick();
        gameMode = 'pvp';
        if (hudMatchLabel) hudMatchLabel.textContent = 'P1 vs P2 (Local)';
        startGame();
    });

    pvaButton?.addEventListener('click', () => {
        playClick();
        gameMode = 'pva';
        showScreen('difficulty');
    });

    settingsButton?.addEventListener('click', () => {
        playClick();
        showScreen('settings');
    });

    difficultyBackButton?.addEventListener('click', () => {
        playClick();
        showScreen('main');
    });

    settingsBackButton?.addEventListener('click', () => {
        playClick();
        showScreen('main');
    });

    difficultyMenu?.querySelectorAll('button[data-difficulty]').forEach(btn => {
        btn.addEventListener('click', () => {
            playClick();
            difficulty = btn.dataset.difficulty;
            if (hudMatchLabel) hudMatchLabel.textContent = `P1 vs AI (${difficulty.toUpperCase()})`;
            startGame();
        });
    });

    backToMenuIngameButton?.addEventListener('click', () => {
        playClick();
        showScreen('main');
    });

    hudRestartBtn?.addEventListener('click', () => {
        playClick();
        resetGame();
    });

    playAgainButton?.addEventListener('click', () => {
        playClick();
        winPopup.style.display = 'none';
        stopParticleAnimation();
        startGame();
    });

    winMenuButton?.addEventListener('click', () => {
        playClick();
        showScreen('main');
    });

    // --- Canvas & Physics Initialization ---
    function resizeCanvas() {
        const rect = gameWrapper.getBoundingClientRect();
        canvas.width = rect.width;
        canvas.height = rect.height;
        if (!paddle1 || !paddle2) initGameObjects();
    }
    window.addEventListener('resize', resizeCanvas);

    function initGameObjects() {
        const pRadius = canvas.width * 0.082;
        const puckRadius = canvas.width * 0.052;
        const s1 = paddle1 ? paddle1.score : 0;
        const s2 = paddle2 ? paddle2.score : 0;

        paddle1 = {
            x: canvas.width / 2,
            y: canvas.height * 0.8,
            targetX: canvas.width / 2,
            targetY: canvas.height * 0.8,
            radius: pRadius,
            score: s1,
            color: '#ff007f',
            glow: 'rgba(255, 0, 127, 0.65)',
            active: false
        };

        paddle2 = {
            x: canvas.width / 2,
            y: canvas.height * 0.2,
            targetX: canvas.width / 2,
            targetY: canvas.height * 0.2,
            radius: pRadius,
            score: s2,
            color: '#00f0ff',
            glow: 'rgba(0, 240, 255, 0.65)',
            active: false
        };

        puck = {
            x: canvas.width / 2,
            y: canvas.height / 2,
            radius: puckRadius,
            dx: 0,
            dy: 0,
            color: '#ffffff',
            isStationary: false
        };
    }

    function updateScoreDisplay() {
        if (paddle1 && scorePlayer1El) scorePlayer1El.textContent = paddle1.score;
        if (paddle2 && scorePlayer2El) scorePlayer2El.textContent = paddle2.score;
    }

    function startGame() {
        resizeCanvas();
        resetGame();
        showScreen('game');
        if (animationId) cancelAnimationFrame(animationId);
        gameLoop();
    }

    function resetGame() {
        if (paddle1) paddle1.score = 0;
        if (paddle2) paddle2.score = 0;
        lastScoredBy = null;
        updateScoreDisplay();
        resetRound();
    }

    function resetRound() {
        initGameObjects();
        updateScoreDisplay();
        puck.dx = 0;
        puck.dy = 0;
        puck.isStationary = true;

        if (lastScoredBy === 1) {
            puck.y = canvas.height * 0.38;
        } else if (lastScoredBy === 2) {
            puck.y = canvas.height * 0.62;
        } else {
            puck.y = canvas.height / 2;
        }

        setTimeout(() => {
            const launchSpeed = (canvas.height * 0.009) * puckSpeedMultiplier;
            const angle = Math.random() > 0.5 
                ? (Math.random() * (Math.PI / 3) + Math.PI / 3) 
                : (Math.random() * (Math.PI / 3) + Math.PI * 1.33);
            puck.dx = Math.cos(angle) * launchSpeed;
            puck.dy = Math.sin(angle) * launchSpeed;
            puck.isStationary = false;
        }, 650);
    }

    // --- Visual Table Rendering ---
    function drawTable() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Center line
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(0, canvas.height / 2);
        ctx.lineTo(canvas.width, canvas.height / 2);
        ctx.stroke();

        // Center circle
        ctx.beginPath();
        ctx.arc(canvas.width / 2, canvas.height / 2, canvas.width * 0.22, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.15)';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Center dot
        ctx.fillStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.beginPath();
        ctx.arc(canvas.width / 2, canvas.height / 2, 5, 0, Math.PI * 2);
        ctx.fill();

        // Goals
        const goalWidth = canvas.width * 0.42;
        const goalLeft = (canvas.width - goalWidth) / 2;
        const goalRight = goalLeft + goalWidth;

        // Player 2 Goal (Top - Cyan)
        ctx.shadowColor = varColor('--neon-cyan', '#00f0ff');
        ctx.shadowBlur = 15;
        ctx.strokeStyle = '#00f0ff';
        ctx.lineWidth = 6;
        ctx.beginPath();
        ctx.moveTo(goalLeft, 0);
        ctx.lineTo(goalRight, 0);
        ctx.stroke();

        // Player 1 Goal (Bottom - Magenta)
        ctx.shadowColor = varColor('--neon-magenta', '#ff007f');
        ctx.shadowBlur = 15;
        ctx.strokeStyle = '#ff007f';
        ctx.lineWidth = 6;
        ctx.beginPath();
        ctx.moveTo(goalLeft, canvas.height);
        ctx.lineTo(goalRight, canvas.height);
        ctx.stroke();
        ctx.shadowBlur = 0;
    }

    function varColor(name, fallback) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
    }

    function drawMallet(p) {
        // Outer glow
        ctx.save();
        ctx.shadowColor = p.glow;
        ctx.shadowBlur = 20;
        ctx.fillStyle = p.color;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fill();

        // Inner rim
        ctx.shadowBlur = 0;
        ctx.fillStyle = 'rgba(0, 0, 0, 0.4)';
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius * 0.65, 0, Math.PI * 2);
        ctx.fill();

        // Core handle
        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius * 0.3, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
    }

    function drawPuck() {
        ctx.save();
        ctx.shadowColor = '#ffffff';
        ctx.shadowBlur = 18;
        ctx.fillStyle = puck.color;
        ctx.beginPath();
        ctx.arc(puck.x, puck.y, puck.radius, 0, Math.PI * 2);
        ctx.fill();

        // Puck inner accent
        ctx.fillStyle = '#38bdf8';
        ctx.beginPath();
        ctx.arc(puck.x, puck.y, puck.radius * 0.45, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
    }

    // --- Touch & Mouse Input Handlers ---
    const activePointers = {};

    function getCoords(e) {
        const rect = canvas.getBoundingClientRect();
        return {
            x: (e.clientX - rect.left) * (canvas.width / rect.width),
            y: (e.clientY - rect.top) * (canvas.height / rect.height)
        };
    }

    function onPointerDown(e) {
        const touches = e.changedTouches ? Array.from(e.changedTouches) : [e];
        touches.forEach(t => {
            const pos = getCoords(t);
            const id = t.identifier !== undefined ? t.identifier : 'mouse';
            if (pos.y > canvas.height / 2) {
                activePointers[id] = { paddle: paddle1 };
                paddle1.x = pos.x;
                paddle1.y = pos.y;
                paddle1.active = true;
            } else if (gameMode === 'pvp') {
                activePointers[id] = { paddle: paddle2 };
                paddle2.x = pos.x;
                paddle2.y = pos.y;
                paddle2.active = true;
            }
        });
    }

    function onPointerMove(e) {
        const touches = e.changedTouches ? Array.from(e.changedTouches) : [e];
        touches.forEach(t => {
            const id = t.identifier !== undefined ? t.identifier : 'mouse';
            if (activePointers[id]) {
                const pos = getCoords(t);
                activePointers[id].paddle.x = pos.x;
                activePointers[id].paddle.y = pos.y;
            }
        });
    }

    function onPointerUp(e) {
        const touches = e.changedTouches ? Array.from(e.changedTouches) : [e];
        touches.forEach(t => {
            const id = t.identifier !== undefined ? t.identifier : 'mouse';
            if (activePointers[id]) {
                activePointers[id].paddle.active = false;
                delete activePointers[id];
            }
        });
    }

    canvas.addEventListener('mousedown', onPointerDown);
    window.addEventListener('mousemove', onPointerMove);
    window.addEventListener('mouseup', onPointerUp);

    canvas.addEventListener('touchstart', onPointerDown, { passive: false });
    window.addEventListener('touchmove', onPointerMove, { passive: false });
    window.addEventListener('touchend', onPointerUp);
    window.addEventListener('touchcancel', onPointerUp);

    // --- Keyboard & Controller Controls ---
    function updatePaddleInputs() {
        const speed = (canvas.width * 0.024);

        // Keyboard Player 1: WASD / Arrow Keys
        if (!paddle1.active) {
            if (keysDown['KeyA'] || keysDown['ArrowLeft']) paddle1.x -= speed;
            if (keysDown['KeyD'] || keysDown['ArrowRight']) paddle1.x += speed;
            if (keysDown['KeyW'] || keysDown['ArrowUp']) paddle1.y -= speed;
            if (keysDown['KeyS'] || keysDown['ArrowDown']) paddle1.y += speed;
        }

        // Keyboard Player 2 in local PvP mode (IJKL keys)
        if (gameMode === 'pvp' && !paddle2.active) {
            if (keysDown['KeyJ']) paddle2.x -= speed;
            if (keysDown['KeyL']) paddle2.x += speed;
            if (keysDown['KeyI']) paddle2.y -= speed;
            if (keysDown['KeyK']) paddle2.y += speed;
        }
    }

    // Gamepad controller listener via ArcadeHelper
    if (helper && helper.gamepad) {
        helper.gamepad.onMoveAnalog((normX, normY) => {
            if (paddle1 && gameContainer.style.display === 'block') {
                const speed = canvas.width * 0.035;
                paddle1.x += normX * speed;
                paddle1.y += normY * speed;
            }
        });

        helper.gamepad.onAction((act) => {
            if (act === 'START') {
                backToMenuIngameButton?.click();
            } else if (act === 'SELECT') {
                hudRestartBtn?.click();
            }
        });
    }

    function clampPaddlePositions() {
        if (!paddle1 || !paddle2) return;
        // Paddle 1 clamped to bottom half
        paddle1.x = Math.max(paddle1.radius, Math.min(paddle1.x, canvas.width - paddle1.radius));
        paddle1.y = Math.max(canvas.height / 2 + paddle1.radius + 2, Math.min(paddle1.y, canvas.height - paddle1.radius));

        // Paddle 2 clamped to top half
        paddle2.x = Math.max(paddle2.radius, Math.min(paddle2.x, canvas.width - paddle2.radius));
        paddle2.y = Math.max(paddle2.radius, Math.min(paddle2.y, canvas.height / 2 - paddle2.radius - 2));
    }

    // --- AI Intelligence ---
    function moveAI() {
        if (paddle2.active) return;
        let speedMult = 0.07;
        let prediction = puck.x;

        if (difficulty === 'easy') speedMult = 0.045;
        else if (difficulty === 'medium') speedMult = 0.085;
        else if (difficulty === 'hard') speedMult = 0.14;

        if (puck.dy < 0) {
            // Puck coming towards AI
            paddle2.x += (prediction - paddle2.x) * speedMult;
            const targetY = canvas.height * 0.22;
            paddle2.y += (targetY - paddle2.y) * (speedMult * 0.7);
        } else {
            // Puck moving away, return to home base
            const homeX = canvas.width / 2;
            const homeY = canvas.height * 0.18;
            paddle2.x += (homeX - paddle2.x) * 0.05;
            paddle2.y += (homeY - paddle2.y) * 0.05;
        }
    }

    // --- Sub-stepping Collision Resolution ---
    function checkCollisions() {
        if (!puck || !paddle1 || !paddle2) return;

        // Side walls reflection with bounds clamp
        if (puck.x < puck.radius) {
            puck.x = puck.radius;
            puck.dx = Math.abs(puck.dx);
            playSfx(hitSound);
        } else if (puck.x > canvas.width - puck.radius) {
            puck.x = canvas.width - puck.radius;
            puck.dx = -Math.abs(puck.dx);
            playSfx(hitSound);
        }

        // Paddle collisions
        [paddle1, paddle2].forEach(paddle => {
            const dist = Math.hypot(puck.x - paddle.x, puck.y - paddle.y);
            const minDist = puck.radius + paddle.radius;

            if (dist < minDist) {
                playSfx(hitSound);
                if (helper) helper.vibrate(18);

                const angle = Math.atan2(puck.y - paddle.y, puck.x - paddle.x);
                const overlap = minDist - dist;
                puck.x += Math.cos(angle) * overlap;
                puck.y += Math.sin(angle) * overlap;

                const baseSpeed = (canvas.height * 0.016) * puckSpeedMultiplier;
                const maxSpeed = (canvas.height * 0.032) * puckSpeedMultiplier;
                const currentSpeed = Math.hypot(puck.dx, puck.dy);
                const newSpeed = Math.min(Math.max(baseSpeed, currentSpeed * 1.03), maxSpeed);

                puck.dx = Math.cos(angle) * newSpeed;
                puck.dy = Math.sin(angle) * newSpeed;
            }
        });

        // Goal detection
        const goalWidth = canvas.width * 0.42;
        const goalLeft = (canvas.width - goalWidth) / 2;
        const goalRight = goalLeft + goalWidth;

        // Top Goal (P2 side)
        if (puck.y < puck.radius) {
            if (puck.x > goalLeft && puck.x < goalRight) {
                playSfx(scoreSound);
                if (helper) helper.vibrate([30, 20, 40]);
                paddle1.score++;
                lastScoredBy = 1;
                if (!checkMatchWin()) resetRound();
            } else {
                puck.y = puck.radius;
                puck.dy = Math.abs(puck.dy);
                playSfx(hitSound);
            }
        }

        // Bottom Goal (P1 side)
        if (puck.y > canvas.height - puck.radius) {
            if (puck.x > goalLeft && puck.x < goalRight) {
                playSfx(scoreSound);
                if (helper) helper.vibrate([30, 20, 40]);
                paddle2.score++;
                lastScoredBy = 2;
                if (!checkMatchWin()) resetRound();
            } else {
                puck.y = canvas.height - puck.radius;
                puck.dy = -Math.abs(puck.dy);
                playSfx(hitSound);
            }
        }
    }

    function checkMatchWin() {
        updateScoreDisplay();
        if (paddle1.score >= WINNING_SCORE) {
            endMatch("PLAYER 1 WINS!");
            return true;
        } else if (paddle2.score >= WINNING_SCORE) {
            endMatch(`${gameMode === 'pvp' ? "PLAYER 2" : "AI"} WINS!`);
            return true;
        }
        return false;
    }

    function endMatch(msg) {
        playSfx(winSound);
        if (helper) {
            helper.vibrate([40, 30, 80]);
            helper.audio.playMenuMusic();
        }
        if (animationId) cancelAnimationFrame(animationId);
        animationId = null;

        const p1Won = paddle1.score >= WINNING_SCORE;
        if (p1Won) {
            sessP1++;
            localStorage.setItem('arc_airhockey_p1', sessP1);
        } else {
            sessP2++;
            localStorage.setItem('arc_airhockey_p2', sessP2);
        }
        updateAirHockeyScoreboard();

        winMessageEl.textContent = msg;
        winPopup.style.display = 'flex';
        startParticleAnimation();

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: p1Won ? 'win' : 'loss',
                score: paddle1.score * 25
            }, '*');
        }
    }

    // --- Game Loop ---
    function gameLoop() {
        if (!puck.isStationary) {
            puck.dx *= FRICTION;
            puck.dy *= FRICTION;
            puck.x += puck.dx;
            puck.y += puck.dy;
        }

        updatePaddleInputs();
        clampPaddlePositions();

        if (gameMode === 'pva') {
            moveAI();
        }

        checkCollisions();
        drawTable();
        drawMallet(paddle1);
        drawMallet(paddle2);
        drawPuck();

        animationId = requestAnimationFrame(gameLoop);
    }

    // --- Victory Particles ---
    let particles = [];
    function Particle(x, y, radius, color, velocity) {
        this.x = x; this.y = y; this.radius = radius; this.color = color; this.velocity = velocity;
        this.alpha = 1;
        this.draw = () => {
            particleCtx.save();
            particleCtx.globalAlpha = this.alpha;
            particleCtx.beginPath();
            particleCtx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            particleCtx.fillStyle = this.color;
            particleCtx.fill();
            particleCtx.restore();
        };
        this.update = () => {
            this.draw();
            this.velocity.y += 0.05;
            this.x += this.velocity.x;
            this.y += this.velocity.y;
            this.alpha -= 0.015;
        };
    }

    function initParticles() {
        particles = [];
        particleCanvas.width = window.innerWidth;
        particleCanvas.height = window.innerHeight;
        const colors = ['#00f0ff', '#ff007f', '#ffffff', '#ffd700'];
        const centerX = particleCanvas.width / 2;
        const centerY = particleCanvas.height / 2;

        for (let i = 0; i < 220; i++) {
            const angle = Math.random() * Math.PI * 2;
            const speed = Math.random() * 11 + 2;
            const velocity = { x: Math.cos(angle) * speed, y: Math.sin(angle) * speed };
            particles.push(new Particle(centerX, centerY, Math.random() * 3 + 1, colors[Math.floor(Math.random() * colors.length)], velocity));
        }
    }

    function animateParticles() {
        particleCtx.fillStyle = 'rgba(0, 0, 0, 0.12)';
        particleCtx.fillRect(0, 0, particleCanvas.width, particleCanvas.height);
        particles.forEach((p, i) => {
            if (p.alpha > 0) p.update();
            else particles.splice(i, 1);
        });
        particleAnimationId = particles.length > 0 ? requestAnimationFrame(animateParticles) : null;
    }

    function startParticleAnimation() {
        initParticles();
        animateParticles();
    }

    function stopParticleAnimation() {
        if (particleAnimationId) cancelAnimationFrame(particleAnimationId);
        particleAnimationId = null;
        particleCtx.clearRect(0, 0, particleCanvas.width, particleCanvas.height);
    }

    // --- Init ---
    resizeCanvas();
    showScreen('main');
});