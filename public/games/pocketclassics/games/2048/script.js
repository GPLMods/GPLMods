document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const mainMenu = document.getElementById('main-menu');
    const difficultyMenu = document.getElementById('difficulty-menu');
    const gameContainer = document.getElementById('game-container');
    const gameOverModal = document.getElementById('game-over-modal');
    const settingsModal = document.getElementById('settings-modal');
    const playBtn = document.getElementById('play-btn');
    const settingsBtn = document.getElementById('settings-btn');
    const homeBtn = document.getElementById('home-btn');
    const backToMainBtn = document.getElementById('back-to-main-btn');
    const difficultyButtons = document.querySelectorAll('.difficulty-buttons .btn');
    const closeSettingsBtn = document.getElementById('close-settings-btn');
    const menuBtn = document.getElementById('menu-btn');
    const restartBtn = document.getElementById('restart-btn');
    const modalRestartBtn = document.getElementById('modal-restart-btn');
    const modalMenuBtn = document.getElementById('modal-menu-btn');
    const gameBoard = document.getElementById('game-board');
    const scoreDisplay = document.getElementById('score');
    const bestScoreDisplay = document.getElementById('best-score');
    const finalScoreDisplay = document.getElementById('final-score');
    const modalTitle = document.getElementById('modal-title');
    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');
    const bgMusic = document.getElementById('bg-music');
    const moveSound = document.getElementById('move-sound');
    const mergeSound = document.getElementById('merge-sound');
    const winSound = document.getElementById('win-sound');
    const loseSound = document.getElementById('lose-sound');
    const uiClickSound = document.getElementById('ui-click-sound');
    const confettiCanvas = document.getElementById('confetti-canvas');
    const confettiInstance = confetti.create(confettiCanvas, { resize: true, useWorker: true });

    // --- Game State & Settings ---
    let gridSize, winValue, board, score, bestScore;
    let isGameOver = false;
    let isMoving = false;
    let isMusicOn = false;
    let isSfxOn = false;
    let userHasInteracted = false;

    if (window.parent && window.parent !== window) {
        if (bgMusic) { bgMusic.muted = true; bgMusic.volume = 0; bgMusic.pause(); }
    }

    // --- Settings & Sound Logic ---
    function loadSettings() {
        if (window.parent && window.parent !== window) {
            isMusicOn = false;
        } else {
            isMusicOn = localStorage.getItem('isMusicOn') !== 'false';
        }
        isSfxOn = localStorage.getItem('isSfxOn') !== 'false';
        if (musicToggle) musicToggle.checked = isMusicOn;
        if (sfxToggle) sfxToggle.checked = isSfxOn;
    }
    function saveSettings() { localStorage.setItem('isMusicOn', isMusicOn); localStorage.setItem('isSfxOn', isSfxOn); }
    function playBgMusic() {
        if (window.parent && window.parent !== window) return;
        if (isMusicOn && userHasInteracted && bgMusic) bgMusic.play().catch(e => {});
    }
    function pauseBgMusic() { if (bgMusic) bgMusic.pause(); }
    function playSfx(sound) { if (isSfxOn && sound) { sound.currentTime = 0; sound.play().catch(e => {}); } }
    function playUiClick() { playSfx(uiClickSound); }
    function handleFirstInteraction() { if (!userHasInteracted) { userHasInteracted = true; playBgMusic(); } }

    // --- Menu Navigation ---
    if (playBtn) playBtn.addEventListener('click', () => { handleFirstInteraction(); playUiClick(); mainMenu.classList.add('hidden'); difficultyMenu.classList.remove('hidden'); });
    if (settingsBtn) settingsBtn.addEventListener('click', () => { handleFirstInteraction(); playUiClick(); settingsModal.classList.remove('hidden'); });
    if (homeBtn) {
        homeBtn.addEventListener('click', () => { 
            handleFirstInteraction(); 
            playUiClick(); 
            if (window.parent && window.parent !== window) {
                window.parent.postMessage({ type: 'ARCADE_EXIT' }, '*');
            } else {
                window.location.href = '/games/hub'; 
            }
        });
    }
    backToMainBtn.addEventListener('click', () => { playUiClick(); difficultyMenu.classList.add('hidden'); mainMenu.classList.remove('hidden'); });
    closeSettingsBtn.addEventListener('click', () => { playUiClick(); settingsModal.classList.add('hidden'); });
    musicToggle.addEventListener('change', (e) => { isMusicOn = e.target.checked; isMusicOn ? playBgMusic() : pauseBgMusic(); saveSettings(); });
    sfxToggle.addEventListener('change', (e) => { isSfxOn = e.target.checked; saveSettings(); });

    // --- Game Setup ---
    function startGame(size, win) { gridSize = size; winValue = win; bestScoreDisplay.textContent = localStorage.getItem(`bestScore_${gridSize}`) || 0; bestScore = parseInt(bestScoreDisplay.textContent); difficultyMenu.classList.add('hidden'); gameContainer.classList.remove('hidden'); playBgMusic(); initGame(); }
    function initGame() { board = Array(gridSize * gridSize).fill(0); score = 0; isGameOver = false; isMoving = false; updateScore(0); setupGameBoard(); spawnTile(); spawnTile(); updateDisplay(); }
    function setupGameBoard() { gameBoard.innerHTML = ''; gameBoard.style.gridTemplateColumns = `repeat(${gridSize}, 1fr)`; const boardContainer = document.getElementById('game-board-container'); const gap = 10; const totalGapSize = gap * (gridSize - 1); const totalPadding = gap * 2; const cellSize = (boardContainer.clientWidth - totalPadding - totalGapSize) / gridSize; gameBoard.style.gridTemplateRows = `repeat(${gridSize}, ${cellSize}px)`; for (let i = 0; i < gridSize * gridSize; i++) { const cell = document.createElement('div'); cell.classList.add('grid-cell'); gameBoard.appendChild(cell); } }
    
    // --- Core Logic ---
    function getEmptyCells() { const emptyCells = []; for (let i = 0; i < board.length; i++) { if (board[i] === 0) emptyCells.push(i); } return emptyCells; }
    function spawnTile() { const emptyCells = getEmptyCells(); if (emptyCells.length > 0) { const index = emptyCells[Math.floor(Math.random() * emptyCells.length)]; board[index] = Math.random() < 0.9 ? 2 : 4; } }
    function updateDisplay() { const boardContainer = document.getElementById('game-board-container'); boardContainer.querySelectorAll('.tile').forEach(t => t.remove()); const gap = 10; const cellWidth = (boardContainer.clientWidth - (gap * 2) - (gap * (gridSize - 1))) / gridSize; for (let i = 0; i < board.length; i++) { if (board[i] !== 0) { const row = Math.floor(i / gridSize); const col = i % gridSize; const tile = document.createElement('div'); tile.classList.add('tile'); tile.dataset.value = board[i]; tile.textContent = board[i]; tile.style.width = `${cellWidth}px`; tile.style.height = `${cellWidth}px`; tile.style.top = `${gap + row * (cellWidth + gap)}px`; tile.style.left = `${gap + col * (cellWidth + gap)}px`; if (boardContainer.querySelector(`[data-merged-at="${i}"]`)) { tile.classList.add('merged'); } else { tile.classList.add('show'); } boardContainer.appendChild(tile); } } }
    function updateScore(points) { score += points; scoreDisplay.textContent = score; if (score > bestScore) { bestScore = score; bestScoreDisplay.textContent = bestScore; localStorage.setItem(`bestScore_${gridSize}`, bestScore); } }
    function move(direction) { if (isGameOver || isMoving) return; isMoving = true; let boardChanged = false; let mergeOccurred = false; let tempBoard = [...board]; function slideAndMerge(line) { let filtered = line.filter(num => num !== 0); for (let i = 0; i < filtered.length - 1; i++) { if (filtered[i] === filtered[i + 1]) { filtered[i] *= 2; updateScore(filtered[i]); filtered[i + 1] = 0; mergeOccurred = true; } } let newLine = filtered.filter(num => num !== 0); while (newLine.length < gridSize) newLine.push(0); return newLine; } if (direction === 'up' || direction === 'down') { for (let c = 0; c < gridSize; c++) { let column = []; for (let r = 0; r < gridSize; r++) column.push(tempBoard[r * gridSize + c]); if (direction === 'down') column.reverse(); let newColumn = slideAndMerge(column); if (direction === 'down') newColumn.reverse(); for (let r = 0; r < gridSize; r++) { const index = r * gridSize + c; if (tempBoard[index] !== newColumn[r]) boardChanged = true; tempBoard[index] = newColumn[r]; } } } else { for (let r = 0; r < gridSize; r++) { let row = tempBoard.slice(r * gridSize, r * gridSize + gridSize); if (direction === 'right') row.reverse(); let newRow = slideAndMerge(row); if (direction === 'right') newRow.reverse(); for (let c = 0; c < gridSize; c++) { const index = r * gridSize + c; if (tempBoard[index] !== newRow[c]) boardChanged = true; tempBoard[index] = newRow[c]; } } } if (boardChanged) { board = tempBoard; if (mergeOccurred) playSfx(mergeSound); else playSfx(moveSound); spawnTile(); updateDisplay(); checkGameOver(); } setTimeout(() => { isMoving = false; }, 200); }
    function checkGameOver() { if (board.includes(winValue)) { endGame(true); return; } if (getEmptyCells().length === 0 && !canMove()) { endGame(false); } }
    function endGame(isWin) { 
        isGameOver = true; 
        pauseBgMusic(); 
        if (isWin) { 
            modalTitle.textContent = "You Win!"; 
            playSfx(winSound); 
            triggerConfetti(); 
        } else { 
            modalTitle.textContent = "Game Over!"; 
            playSfx(loseSound); 
        } 
        finalScoreDisplay.textContent = score; 
        setTimeout(() => gameOverModal.classList.remove('hidden'), 500); 

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: isWin ? 'win' : 'loss',
                score: score
            }, '*');
        }
    }
    function triggerConfetti() { const duration = 3 * 1000; const animationEnd = Date.now() + duration; const defaults = { startVelocity: 30, spread: 360, ticks: 60, zIndex: 101 }; function randomInRange(min, max) { return Math.random() * (max - min) + min; } const interval = setInterval(() => { const timeLeft = animationEnd - Date.now(); if (timeLeft <= 0) return clearInterval(interval); const particleCount = 50 * (timeLeft / duration); confettiInstance({ ...defaults, particleCount, origin: { x: randomInRange(0.1, 0.3), y: Math.random() - 0.2 } }); confettiInstance({ ...defaults, particleCount, origin: { x: randomInRange(0.7, 0.9), y: Math.random() - 0.2 } }); }, 250); }
    
    // --- In-Game Buttons ---
    function goBackToMenu() {
        playUiClick();
        // The pauseBgMusic() line was removed from here.
        gameContainer.classList.add('hidden');
        gameOverModal.classList.add('hidden');
        difficultyMenu.classList.remove('hidden');
    }

    menuBtn.addEventListener('click', goBackToMenu);
    modalMenuBtn.addEventListener('click', goBackToMenu);
    restartBtn.addEventListener('click', () => { playUiClick(); initGame(); playBgMusic(); });
    modalRestartBtn.addEventListener('click', () => { playUiClick(); gameOverModal.classList.add('hidden'); initGame(); playBgMusic(); });
    difficultyButtons.forEach(button => button.addEventListener('click', () => { playUiClick(); startGame(parseInt(button.dataset.size), parseInt(button.dataset.win)); }));
    
    // --- Controls ---
    let touchStartX = 0, touchStartY = 0;
    document.addEventListener("keydown", e => { if (gameContainer.classList.contains("hidden")) return; const keyMap = { ArrowUp: "up", ArrowDown: "down", ArrowLeft: "left", ArrowRight: "right" }; if (keyMap[e.key]) { e.preventDefault(); move(keyMap[e.key]); } });
    gameBoard.parentElement.addEventListener("touchstart", e => { touchStartX = e.touches[0].clientX; touchStartY = e.touches[0].clientY; }, { passive: true });
    gameBoard.parentElement.addEventListener("touchend", e => { if (touchStartX === 0 && touchStartY === 0) return; const touchEndX = e.changedTouches[0].clientX; const touchEndY = e.changedTouches[0].clientY; const dx = touchEndX - touchStartX, dy = touchEndY - touchStartY; const swipeThreshold = 50; if (Math.abs(dx) > Math.abs(dy)) { if (Math.abs(dx) > swipeThreshold) move(dx > 0 ? "right" : "left"); } else { if (Math.abs(dy) > swipeThreshold) move(dy > 0 ? "down" : "up"); } touchStartX = 0; touchStartY = 0; });
    
    window.addEventListener("resize", () => { if (!gameContainer.classList.contains('hidden')) { setupGameBoard(); updateDisplay(); } });
    
    // --- Initial Load ---
    loadSettings();
});
