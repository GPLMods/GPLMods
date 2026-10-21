document.addEventListener('DOMContentLoaded', () => {
    // --- Universal Arcade Helper ---
    const helper = window.ArcadeHelper ? window.ArcadeHelper.init({
        menuMusic: 'sounds/menu-music.mp3',
        gameMusic: 'sounds/bg-music.mp3'
    }) : null;

    // --- DOM Elements ---
    const canvas = document.getElementById('gameCanvas');
    const ctx = canvas.getContext('2d');
    const gameContainer = document.querySelector('.game-container');
    const gameUi = document.getElementById('game-ui');
    const scoreElement = document.getElementById('score');
    const bestScoreElement = document.getElementById('best-score');
    const finalScoreElement = document.getElementById('final-score');

    const screens = {
        mainMenu: document.getElementById('main-menu-screen'),
        settings: document.getElementById('settings-screen'),
        difficulty: document.getElementById('difficulty-screen'),
        pause: document.getElementById('pause-screen'),
        gameOver: document.getElementById('game-over-screen'),
    };

    const playBtn = document.getElementById('play-btn');
    const settingsBtn = document.getElementById('settings-btn');
    const backFromSettingsBtn = document.getElementById('back-from-settings-btn');
    const backFromDifficultyBtn = document.getElementById('back-from-difficulty-btn');
    const startGameBtn = document.getElementById('start-game-btn');
    const pauseBtn = document.getElementById('pause-btn');
    const resumeBtn = document.getElementById('resume-btn');
    const menuFromPauseBtn = document.getElementById('menu-from-pause-btn');
    const restartBtn = document.getElementById('restart-btn');
    const menuFromGameoverBtn = document.getElementById('menu-from-gameover-btn');
    const difficultyBtns = document.querySelectorAll('.difficulty-btn');

    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');

    // --- Sound Assets ---
    const sounds = {
        eat: document.getElementById('eat-sound'),
        gameOver: document.getElementById('game-over-sound'),
        click: document.getElementById('click-sound'),
        turn: document.getElementById('turn-sound')
    };

    function playSound(snd) {
        if (helper) helper.audio.playSfx(snd);
        else if (snd) { snd.currentTime = 0; snd.play().catch(() => {}); }
    }
    function playClick() { playSound(sounds.click); }

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

    // --- Game Physics & Configuration ---
    const GRID_COUNT = 20; // 20x20 grid
    let cellSize = 20;
    let snake = [], food = null, score = 0, bestScore = 0;
    let currentDirection = 'right';
    let directionQueue = []; // Input buffer to prevent 180-degree self-collision bug!
    let gameInterval = null;
    let isPaused = false;
    let isGameOver = false;
    let currentDifficulty = 'medium';

    const difficultySettings = { easy: 150, medium: 100, hard: 65 };

    // --- Screen Navigation ---
    function showScreen(name) {
        Object.values(screens).forEach(s => s && s.classList.remove('active'));
        if (name && screens[name]) screens[name].classList.add('active');

        // Only show virtual D-pad when actively playing (!name) AND on touch devices
        const dpad = document.getElementById('virtualDpad');
        if (dpad) {
            const isTouch = document.body.classList.contains('arc-is-touch') || ('ontouchstart' in window);
            dpad.style.display = (!name && isTouch) ? 'flex' : 'none';
        }

        if (name === 'mainMenu' || name === 'difficulty' || name === 'settings' || name === 'pause' || name === 'gameOver') {
            if (helper) helper.audio.playMenuMusic();
        } else if (!name) {
            // Gameplay active
            if (helper) helper.audio.playGameMusic();
        }
    }

    playBtn?.addEventListener('click', () => {
        playClick();
        showScreen('difficulty');
    });

    settingsBtn?.addEventListener('click', () => {
        playClick();
        showScreen('settings');
    });

    backFromSettingsBtn?.addEventListener('click', () => {
        playClick();
        showScreen('mainMenu');
    });

    backFromDifficultyBtn?.addEventListener('click', () => {
        playClick();
        showScreen('mainMenu');
    });

    difficultyBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            playClick();
            difficultyBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentDifficulty = btn.dataset.difficulty;
        });
    });

    startGameBtn?.addEventListener('click', () => {
        playClick();
        initGame();
    });

    pauseBtn?.addEventListener('click', () => {
        playClick();
        togglePause();
    });

    resumeBtn?.addEventListener('click', () => {
        playClick();
        togglePause();
    });

    menuFromPauseBtn?.addEventListener('click', () => {
        playClick();
        resetToMenu();
    });

    restartBtn?.addEventListener('click', () => {
        playClick();
        initGame();
    });

    menuFromGameoverBtn?.addEventListener('click', () => {
        playClick();
        resetToMenu();
    });

    function resetToMenu() {
        clearInterval(gameInterval);
        isPaused = false;
        isGameOver = true;
        if (gameUi) gameUi.style.opacity = '0';
        showScreen('mainMenu');
    }

    // --- Game Initialization ---
    function resizeCanvas() {
        if (!gameContainer) return;
        const size = Math.floor(Math.min(gameContainer.clientWidth, gameContainer.clientHeight));
        canvas.width = size;
        canvas.height = size;
        cellSize = size / GRID_COUNT;
        if (gameInterval && !isPaused && !isGameOver) {
            draw();
        }
    }
    window.addEventListener('resize', resizeCanvas);

    function initGame() {
        resizeCanvas();
        isPaused = false;
        isGameOver = false;
        score = 0;
        currentDirection = 'right';
        directionQueue = [];

        bestScore = parseInt(localStorage.getItem('snake_best_score') || '0', 10);
        if (bestScoreElement) bestScoreElement.textContent = bestScore;
        if (scoreElement) scoreElement.textContent = '0';

        // Initial 3-segment snake
        snake = [
            { x: 6, y: 10 },
            { x: 5, y: 10 },
            { x: 4, y: 10 }
        ];

        generateFood();
        showScreen(null);
        if (gameUi) gameUi.style.opacity = '1';

        clearInterval(gameInterval);
        gameInterval = setInterval(gameTick, difficultySettings[currentDifficulty]);
    }

    function generateFood() {
        let attempts = 0;
        while (attempts < 500) {
            const rx = Math.floor(Math.random() * GRID_COUNT);
            const ry = Math.floor(Math.random() * GRID_COUNT);
            if (!snake.some(seg => seg.x === rx && seg.y === ry)) {
                food = { x: rx, y: ry };
                return;
            }
            attempts++;
        }
        food = { x: 0, y: 0 };
    }

    // --- Input Queue to prevent 180-degree Suicide Bug ---
    function queueDirection(newDir) {
        if (isPaused || isGameOver) return;
        const opposite = { up: 'down', down: 'up', left: 'right', right: 'left' };
        const lastQueued = directionQueue.length > 0 ? directionQueue[directionQueue.length - 1] : currentDirection;

        if (newDir && newDir !== lastQueued && newDir !== opposite[lastQueued]) {
            if (directionQueue.length < 3) {
                directionQueue.push(newDir);
                playSound(sounds.turn);
            }
        }
    }

    // --- Main Game Loop Tick ---
    function gameTick() {
        if (isPaused || isGameOver) return;

        if (directionQueue.length > 0) {
            currentDirection = directionQueue.shift();
        }

        const head = { ...snake[0] };
        switch (currentDirection) {
            case 'up': head.y -= 1; break;
            case 'down': head.y += 1; break;
            case 'left': head.x -= 1; break;
            case 'right': head.x += 1; break;
        }

        // Boundary Collision (Walls kill)
        if (head.x < 0 || head.x >= GRID_COUNT || head.y < 0 || head.y >= GRID_COUNT) {
            endGame();
            return;
        }

        // Self-collision
        if (snake.some(seg => seg.x === head.x && seg.y === head.y)) {
            endGame();
            return;
        }

        snake.unshift(head);

        // Food Check
        if (food && head.x === food.x && head.y === food.y) {
            score += 10;
            if (scoreElement) scoreElement.textContent = score;
            if (score > bestScore) {
                bestScore = score;
                if (bestScoreElement) bestScoreElement.textContent = bestScore;
                localStorage.setItem('snake_best_score', bestScore);
            }
            playSound(sounds.eat);
            if (helper) helper.vibrate(18);
            generateFood();
        } else {
            snake.pop();
        }

        draw();
    }

    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Cyber grid backdrop
        ctx.fillStyle = '#0a0d18';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Grid lines (subtle)
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
        ctx.lineWidth = 1;
        for (let i = 0; i <= GRID_COUNT; i++) {
            const p = i * cellSize;
            ctx.beginPath();
            ctx.moveTo(p, 0); ctx.lineTo(p, canvas.height);
            ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(0, p); ctx.lineTo(canvas.width, p);
            ctx.stroke();
        }

        // Draw Food (Pulsing glowing orb)
        if (food) {
            const fx = food.x * cellSize + cellSize / 2;
            const fy = food.y * cellSize + cellSize / 2;
            const radius = (cellSize / 2) * 0.78;

            ctx.save();
            ctx.shadowColor = '#ef4444';
            ctx.shadowBlur = 14;
            ctx.fillStyle = '#ef4444';
            ctx.beginPath();
            ctx.arc(fx, fy, radius, 0, Math.PI * 2);
            ctx.fill();

            // Inner highlight
            ctx.fillStyle = '#fca5a5';
            ctx.beginPath();
            ctx.arc(fx - radius * 0.3, fy - radius * 0.3, radius * 0.35, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
        }

        // Draw Snake Segments
        snake.forEach((seg, idx) => {
            const x = seg.x * cellSize;
            const y = seg.y * cellSize;
            const pad = 1.5;
            const w = cellSize - pad * 2;
            const r = idx === 0 ? 6 : 4;

            ctx.save();
            if (idx === 0) {
                // Head
                ctx.shadowColor = '#10b981';
                ctx.shadowBlur = 12;
                ctx.fillStyle = '#34d399';
            } else {
                ctx.fillStyle = idx % 2 === 0 ? '#10b981' : '#059669';
            }

            // Rounded rectangle
            ctx.beginPath();
            ctx.roundRect(x + pad, y + pad, w, w, r);
            ctx.fill();
            ctx.restore();
        });
    }

    function togglePause() {
        if (isGameOver) return;
        isPaused = !isPaused;
        if (isPaused) {
            showScreen('pause');
        } else {
            showScreen(null);
            draw();
        }
    }

    function endGame() {
        isGameOver = true;
        clearInterval(gameInterval);
        playSound(sounds.gameOver);
        if (helper) helper.vibrate([60, 40, 80]);

        if (finalScoreElement) finalScoreElement.textContent = score;
        if (gameUi) gameUi.style.opacity = '0';
        showScreen('gameOver');

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: score >= 50 ? 'win' : 'loss',
                score: score
            }, '*');
        }
    }

    // --- CONTROLLER, KEYBOARD & TOUCH BINDINGS ---
    // 1. Keyboard (WASD + Arrows)
    window.addEventListener('keydown', (e) => {
        if (screens.mainMenu.classList.contains('active') || isGameOver) return;

        const keyMap = {
            ArrowUp: 'up', KeyW: 'up',
            ArrowDown: 'down', KeyS: 'down',
            ArrowLeft: 'left', KeyA: 'left',
            ArrowRight: 'right', KeyD: 'right'
        };

        const dir = keyMap[e.code] || keyMap[e.key];
        if (dir) {
            e.preventDefault();
            queueDirection(dir);
        } else if (e.code === 'Escape' || e.code === 'KeyP') {
            togglePause();
        }
    });

    // 2. Gamepad Controller Support via ArcadeHelper
    if (helper && helper.gamepad) {
        helper.gamepad.onDirection((dir) => {
            if (!screens.mainMenu.classList.contains('active') && !isGameOver) {
                queueDirection(dir);
            }
        });

        helper.gamepad.onAction((act) => {
            if (act === 'START') {
                togglePause();
            } else if (act === 'SELECT' || act === 'A') {
                if (screens.gameOver.classList.contains('active')) {
                    restartBtn?.click();
                }
            }
        });
    }

    // 3. Touch Swipe on Canvas
    if (helper && canvas) {
        helper.bindSwipe(canvas, (dir) => {
            if (!screens.mainMenu.classList.contains('active') && !isGameOver) {
                queueDirection(dir);
            }
        });
    }

    // 4. On-screen Virtual D-Pad
    document.querySelectorAll('.dpad-key').forEach(key => {
        key.addEventListener('click', () => {
            const dir = key.dataset.dir;
            if (dir) queueDirection(dir);
        });
    });

    // Initial setup
    bestScore = parseInt(localStorage.getItem('snake_best_score') || '0', 10);
    if (bestScoreElement) bestScoreElement.textContent = bestScore;
    resizeCanvas();
    showScreen('mainMenu');
});
