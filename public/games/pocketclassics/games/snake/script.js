document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const canvas = document.getElementById('gameCanvas');
    const ctx = canvas.getContext('2d');
    const gameUi = document.getElementById('game-ui');
    const scoreElement = document.getElementById('score');
    const finalScoreElement = document.getElementById('final-score');
    
    const screens = {
        mainMenu: document.getElementById('main-menu-screen'),
        settings: document.getElementById('settings-screen'),
        difficulty: document.getElementById('difficulty-screen'),
        pause: document.getElementById('pause-screen'),
        gameOver: document.getElementById('game-over-screen'),
    };

    // Buttons
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
    const musicToggleBtn = document.getElementById('music-toggle-btn');
    const sfxToggleBtn = document.getElementById('sfx-toggle-btn');
    const homeBtn = document.getElementById('home-btn');
    
    // Audio Elements
    const sounds = {
        music: document.getElementById('bg-music'),
        eat: document.getElementById('eat-sound'),
        gameOver: document.getElementById('game-over-sound'),
        click: document.getElementById('click-sound'),
        // 1. ADD THE NEW TURN SOUND HERE
        turn: document.getElementById('turn-sound'),
    };

    // --- Game & State Variables ---
    const gridSize = 20;
    let snake, food, score, direction, nextDirection, gameInterval, speed, canvasSize, isPaused;
    let currentDifficulty = 'easy';
    let gameSettings = { music: true, sfx: true };
    let touchStartX = 0, touchStartY = 0;
    const difficultySettings = { easy: 150, medium: 100, hard: 60 };
    
    // --- Sound & UI Functions ---
    const playSound = (sound) => { if (gameSettings.sfx) { sound.currentTime = 0; sound.play(); } };
    const toggleMusic = () => { if (gameSettings.music && window.parent === window && sounds.music) { sounds.music.volume = 0.3; sounds.music.play().catch(e => {}); } else if (sounds.music) { sounds.music.pause(); } };
    const showScreen = (screenName) => { Object.values(screens).forEach(screen => { if (screen) screen.classList.remove('active'); }); if (screens[screenName]) { screens[screenName].classList.add('active'); } };
    const resetToMainMenu = () => { clearInterval(gameInterval); gameUi.style.opacity = 0; showScreen('mainMenu'); toggleMusic(); };

    // --- Game Logic ---
    function initGame() { isPaused = false; snake = [{ x: 10, y: 10 }]; score = 0; direction = 'right'; nextDirection = 'right'; scoreElement.textContent = score; speed = difficultySettings[currentDifficulty]; showScreen(null); gameUi.style.opacity = 1; generateFood(); clearInterval(gameInterval); gameInterval = setInterval(update, speed); toggleMusic(); }
    function update() { if (isPaused) return; direction = nextDirection; const head = { ...snake[0] }; switch (direction) { case 'up': head.y -= 1; break; case 'down': head.y += 1; break; case 'left': head.x -= 1; break; case 'right': head.x += 1; break; } if (isCollision(head)) { endGame(); return; } snake.unshift(head); if (head.x === food.x && head.y === food.y) { score++; scoreElement.textContent = score; playSound(sounds.eat); generateFood(); } else { snake.pop(); } draw(); }
    function endGame() { 
        clearInterval(gameInterval); 
        playSound(sounds.gameOver); 
        sounds.music.pause(); 
        finalScoreElement.textContent = score; 
        gameUi.style.opacity = 0; 
        showScreen('gameOver'); 
        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: score > 10 ? 'win' : 'loss',
                score: score
            }, '*');
        }
    }
    function togglePause() { isPaused = !isPaused; if (isPaused) { clearInterval(gameInterval); showScreen('pause'); sounds.music.pause(); } else { showScreen(null); gameInterval = setInterval(update, speed); if (gameSettings.music) sounds.music.play(); } }
    function draw() { ctx.fillStyle = '#222'; ctx.fillRect(0, 0, canvasSize, canvasSize); snake.forEach((segment, index) => { ctx.fillStyle = index === 0 ? '#34d399' : '#2aaa7f'; ctx.fillRect(segment.x * gridSize, segment.y * gridSize, gridSize, gridSize); }); ctx.fillStyle = '#f43f5e'; ctx.fillRect(food.x * gridSize, food.y * gridSize, gridSize, gridSize); }
    function isCollision(head) { return head.x < 0 || head.x >= canvasSize / gridSize || head.y < 0 || head.y >= canvasSize / gridSize || snake.some((segment, index) => index > 0 && segment.x === head.x && segment.y === head.y); }
    function generateFood() { let onSnake; do { food = { x: Math.floor(Math.random() * (canvasSize / gridSize)), y: Math.floor(Math.random() * (canvasSize / gridSize)) }; onSnake = snake.some(segment => segment.x === food.x && segment.y === food.y); } while (onSnake); }
    
    // 2. MODIFY THE changeDirection FUNCTION
    function changeDirection(newDirection) {
        const opposite = { up: 'down', down: 'up', left: 'right', right: 'left' };
        // Check if the new direction is valid and different from the current *next* direction
        if (newDirection && direction !== opposite[newDirection] && nextDirection !== newDirection) {
            nextDirection = newDirection;
            playSound(sounds.turn); // Play the turn sound here!
        }
    }

    // --- Event Listeners (rest of the file is unchanged) ---
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !isPaused && gameInterval) togglePause(); const keyMap = { ArrowUp: 'up', w: 'up', ArrowDown: 'down', s: 'down', ArrowLeft: 'left', a: 'left', ArrowRight: 'right', d: 'right' }; changeDirection(keyMap[e.key]); });
    canvas.addEventListener('touchstart', (e) => { e.preventDefault(); touchStartX = e.touches[0].clientX; touchStartY = e.touches[0].clientY; }, { passive: false });
    canvas.addEventListener('touchend', (e) => { e.preventDefault(); if (!touchStartX || !touchStartY) return; const touchEndX = e.changedTouches[0].clientX; const touchEndY = e.changedTouches[0].clientY; const diffX = touchEndX - touchStartX, diffY = touchEndY - touchStartY; if (Math.abs(diffX) > Math.abs(diffY)) { changeDirection(diffX > 0 ? 'right' : 'left'); } else { changeDirection(diffY > 0 ? 'down' : 'up'); } touchStartX = 0; touchStartY = 0; }, { passive: false });
    playBtn?.addEventListener('click', () => { playSound(sounds.click); showScreen('difficulty'); });
    settingsBtn?.addEventListener('click', () => { playSound(sounds.click); showScreen('settings'); });
    backFromSettingsBtn?.addEventListener('click', () => { playSound(sounds.click); showScreen('mainMenu'); });
    backFromDifficultyBtn?.addEventListener('click', () => { playSound(sounds.click); showScreen('mainMenu'); });
    startGameBtn?.addEventListener('click', () => { playSound(sounds.click); initGame(); });
    pauseBtn?.addEventListener('click', () => { playSound(sounds.click); togglePause(); });
    resumeBtn?.addEventListener('click', () => { playSound(sounds.click); togglePause(); });
    menuFromPauseBtn?.addEventListener('click', () => { playSound(sounds.click); resetToMainMenu(); });
    restartBtn?.addEventListener('click', () => { playSound(sounds.click); initGame(); });
    menuFromGameoverBtn?.addEventListener('click', () => { playSound(sounds.click); resetToMainMenu(); });
    homeBtn?.addEventListener('click', () => { 
        playSound(sounds.click); 
        if (window.parent && window.parent !== window) {
            window.parent.postMessage({ type: 'ARCADE_EXIT' }, '*');
        } else {
            window.location.href = '/games/hub';
        }
    });
    difficultyBtns.forEach(btn => { btn.addEventListener('click', () => { playSound(sounds.click); difficultyBtns.forEach(b => b.classList.remove('active')); btn.classList.add('active'); currentDifficulty = btn.dataset.difficulty; }); });
    musicToggleBtn.addEventListener('click', () => { gameSettings.music = !gameSettings.music; musicToggleBtn.classList.toggle('active', gameSettings.music); playSound(sounds.click); toggleMusic(); });
    sfxToggleBtn.addEventListener('click', () => { gameSettings.sfx = !gameSettings.sfx; sfxToggleBtn.classList.toggle('active', gameSettings.sfx); playSound(sounds.click); });
    function resizeCanvas() { canvasSize = document.querySelector('.game-container').offsetWidth; canvas.width = canvas.height = canvasSize; if(gameInterval) draw(); }
    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();
    resetToMainMenu();
});
