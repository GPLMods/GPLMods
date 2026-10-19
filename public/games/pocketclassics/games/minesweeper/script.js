document.addEventListener('DOMContentLoaded', () => {
    const screens = document.querySelectorAll('.screen'), docEl = document.documentElement;
    let isMusicEnabled = true, isSfxEnabled = true, audioInitialized = false;
    if (window.parent && window.parent !== window) {
        isMusicEnabled = false;
    }
    
    const audio = { music: new Audio('./sounds/music-background.mp3'), click: new Audio('./sounds/sfx-click.wav'), flag: new Audio('./sounds/sfx-flag.wav'), reveal: new Audio('./sounds/sfx-reveal.wav'), explode: new Audio('./sounds/sfx-explode.wav'), win: new Audio('./sounds/sfx-win.mp3'), lose: new Audio('./sounds/sfx-lose.mp3'), };
    audio.music.loop = true;
    if (window.parent && window.parent !== window) {
        audio.music.muted = true;
        audio.music.volume = 0;
    }
    
    function playSound(soundName) { if (!isSfxEnabled || !audio[soundName]) return; audio[soundName].currentTime = 0; audio[soundName].play().catch(e => {}); }
    function playOverlappingSound(soundName) { if (!isSfxEnabled) return; const clone = audio[soundName].cloneNode(); clone.play().catch(e => {}); }
    function toggleMusic() {
        if (window.parent && window.parent !== window) {
            audio.music.pause();
            return;
        }
        isMusicEnabled ? audio.music.play().catch(e => {}) : audio.music.pause();
    }
    function triggerVibration(pattern) { if (navigator.vibrate && isSfxEnabled) navigator.vibrate(pattern); }
    function showScreen(screenId) { screens.forEach(s => { if(s.id !== 'pause-menu') s.classList.remove('active'); }); document.getElementById(screenId).classList.add('active'); }
    
    const playButton = document.getElementById('play-button'), settingsButton = document.getElementById('settings-button'), difficultyButtons = document.querySelectorAll('.difficulty-button'), backToMainButton = document.getElementById('back-to-main-button'), settingsBackButton = document.getElementById('settings-back-button'), musicToggle = document.getElementById('music-toggle'), sfxToggle = document.getElementById('sfx-toggle'), pauseButton = document.getElementById('pause-button'), pauseMenu = document.getElementById('pause-menu'), resumeButton = document.getElementById('resume-button'), pauseLeaveButton = document.getElementById('pause-leave-button'), pauseMusicToggle = document.getElementById('pause-music-toggle'), pauseSfxToggle = document.getElementById('pause-sfx-toggle'), homeButton = document.getElementById('home-button');
    
    function handleFirstInteraction() {
        if (!audioInitialized) {
            audioInitialized = true;
            toggleMusic();
        }
    }
    document.addEventListener('click', handleFirstInteraction, { once: true });
    
    if (playButton) playButton.addEventListener('click', () => { playSound('click'); setTimeout(() => showScreen('difficulty-view'), 50); });
    if (settingsButton) settingsButton.addEventListener('click', () => { playSound('click'); setTimeout(() => showScreen('settings-view'), 50); });
    if (backToMainButton) backToMainButton.addEventListener('click', () => { playSound('click'); setTimeout(() => showScreen('main-menu-view'), 50); });
    if (settingsBackButton) settingsBackButton.addEventListener('click', () => { playSound('click'); setTimeout(() => showScreen('main-menu-view'), 50); });
    if (homeButton) {
        homeButton.addEventListener('click', () => { 
            playSound('click'); 
            setTimeout(() => { 
                if (window.parent && window.parent !== window) {
                    window.parent.postMessage({ type: 'ARCADE_EXIT' }, '*');
                } else {
                    window.location.href = '/games/hub'; 
                }
            }, 150); 
        });
    }
    
    difficultyButtons.forEach(button => {
        button.addEventListener('click', () => {
            playSound('click');
            const difficulty = button.dataset.difficulty;
            setTimeout(() => {
                showScreen('game-view');
                requestAnimationFrame(() => {
                    initGame(difficulty);
                    toggleMusic();
                });
            }, 50);
        });
    });

    const syncSettings = (source, target) => { target.checked = source.checked; };
    musicToggle.addEventListener('change', (e) => { playSound('click'); isMusicEnabled = e.target.checked; localStorage.setItem('minesweeper_musicEnabled', isMusicEnabled); toggleMusic(); syncSettings(e.target, pauseMusicToggle); });
    sfxToggle.addEventListener('change', (e) => { playSound('click'); isSfxEnabled = e.target.checked; localStorage.setItem('minesweeper_sfxEnabled', isSfxEnabled); syncSettings(e.target, pauseSfxToggle); });
    pauseMusicToggle.addEventListener('change', (e) => { musicToggle.checked = e.target.checked; musicToggle.dispatchEvent(new Event('change')); });
    pauseSfxToggle.addEventListener('change', (e) => { sfxToggle.checked = e.target.checked; sfxToggle.dispatchEvent(new Event('change')); });
    function loadSettings() { const musicSetting = localStorage.getItem('minesweeper_musicEnabled'); const sfxSetting = localStorage.getItem('minesweeper_sfxEnabled'); isMusicEnabled = musicSetting !== null ? JSON.parse(musicSetting) : true; isSfxEnabled = sfxSetting !== null ? JSON.parse(sfxSetting) : true; musicToggle.checked = isMusicEnabled; pauseMusicToggle.checked = isMusicEnabled; sfxToggle.checked = isSfxEnabled; pauseSfxToggle.checked = isSfxEnabled; }
    
    pauseButton.addEventListener('click', () => { playSound('click'); pauseGame(); });
    resumeButton.addEventListener('click', () => { playSound('click'); setTimeout(() => resumeGame(), 50); });
    pauseLeaveButton.addEventListener('click', () => { playSound('click'); setTimeout(() => { pauseMenu.classList.remove('active'); showScreen('main-menu-view'); isGameOver = true; clearInterval(timerInterval); audio.music.pause(); }, 50); });
    
    const viewport = document.getElementById('game-board-viewport'), gameBoard = document.getElementById('game-board'), mineCounterDisplay = document.getElementById('mine-counter'), timerDisplay = document.getElementById('timer'), modal = document.getElementById('modal'), modalMessage = document.getElementById('modal-message'), restartButton = document.getElementById('restart-button'), digModeButton = document.getElementById('dig-mode-button'), flagModeButton = document.getElementById('flag-mode-button');
    const difficulties = { easy: { rows: 10, cols: 8, mines: 10 }, medium: { rows: 18, cols: 14, mines: 35 }, hard: { rows: 24, cols: 20, mines: 75 } };
    const googleColors = ['#e53935', '#d81b60', '#8e24aa', '#3949ab', '#1e88e5', '#039be5', '#00acc1', '#00897b', '#43a047', '#f4511e', '#ffb300'];
    let rows, cols, mineCount, board, flags, revealedCells, isGameOver, timerInterval, firstClick, isPaused;
    let currentMode = 'dig';

    function setGameMode(mode) { currentMode = mode; digModeButton.classList.toggle('active', mode === 'dig'); flagModeButton.classList.toggle('active', mode === 'flag'); }
    digModeButton.addEventListener('click', () => { playSound('click'); setGameMode('dig'); });
    flagModeButton.addEventListener('click', () => { playSound('click'); setGameMode('flag'); });
    
    function pauseGame() { if(isGameOver) return; isPaused = true; clearInterval(timerInterval); pauseMenu.classList.add('active'); }
    function resumeGame() { isPaused = false; startTimer(parseInt(timerDisplay.textContent || '0')); pauseMenu.classList.remove('active'); }
    function initGame(difficulty) { const diffSettings = difficulties[difficulty]; rows = diffSettings.rows; cols = diffSettings.cols; mineCount = diffSettings.mines; flags = 0; revealedCells = 0; isGameOver = false; isPaused = false; firstClick = true; clearInterval(timerInterval); timerDisplay.textContent = '000'; mineCounterDisplay.textContent = `${mineCount}`; modal.style.display = 'none'; setGameMode('dig'); renderBoard(); }
    function renderBoard() { gameBoard.innerHTML = ''; gameBoard.style.setProperty('--cols', cols); board = Array.from({ length: rows }, () => Array.from({ length: cols }, () => ({ isMine: false, isRevealed: false, isFlagged: false, neighborMines: 0 }))); for (let r = 0; r < rows; r++) { for (let c = 0; c < cols; c++) { const cellElement = document.createElement('div'); cellElement.classList.add('cell'); cellElement.dataset.row = r; cellElement.dataset.col = c; gameBoard.appendChild(cellElement); }} updateCellSize(); }
    function updateCellSize() { const GAP = 1; const vpWidth = viewport.clientWidth; const vpHeight = viewport.clientHeight; if(vpWidth === 0) return; const sizeBasedOnWidth = (vpWidth - ((cols - 1) * GAP)) / cols; const sizeBasedOnHeight = (vpHeight - ((rows - 1) * GAP)) / rows; const finalSize = Math.floor(Math.min(sizeBasedOnWidth, sizeBasedOnHeight)); docEl.style.setProperty('--cell-size', `${finalSize}px`); }

    gameBoard.addEventListener('click', (e) => {
        if (isGameOver || isPaused) return;
        const cellElement = e.target.closest('.cell');
        if (!cellElement) return;
        const row = parseInt(cellElement.dataset.row), col = parseInt(cellElement.dataset.col);
        if (board[row][col].isRevealed) { if (currentMode === 'dig') { playSound('click'); chord(row, col); } return; }
        if (firstClick) { playSound('click'); revealCell(row, col); return; }
        currentMode === 'dig' ? revealCell(row, col) : toggleFlag(row, col);
    });
    
    function placeMines(firstRow, firstCol) { let minesPlaced = 0; while (minesPlaced < mineCount) { const r = Math.floor(Math.random() * rows); const c = Math.floor(Math.random() * cols); const isSafeZone = Math.abs(r - firstRow) <= 1 && Math.abs(c - firstCol) <= 1; if (!board[r][c].isMine && !isSafeZone) { board[r][c].isMine = true; minesPlaced++; } } for (let r = 0; r < rows; r++) { for (let c = 0; c < cols; c++) { if (board[r][c].isMine) continue; let count = 0; for (let dr = -1; dr <= 1; dr++) { for (let dc = -1; dc <= 1; dc++) { const nr = r + dr, nc = c + dc; if (nr >= 0 && nr < rows && nc >= 0 && nc < cols && board[nr][nc].isMine) count++; } } board[r][c].neighborMines = count; } } }
    function revealCell(row, col) { if (row < 0 || row >= rows || col < 0 || col >= cols || isGameOver || board[row][col].isRevealed || board[row][col].isFlagged) return; if (firstClick) { placeMines(row, col); startTimer(); firstClick = false; } const cell = board[row][col]; cell.isRevealed = true; const cellElement = document.querySelector(`.cell[data-row='${row}'][data-col='${col}']`); cellElement.classList.add('revealed'); if (cell.isMine) { gameOver(false, cellElement); return; } revealedCells++; playSound('reveal'); if (cell.neighborMines > 0) { cellElement.textContent = cell.neighborMines; cellElement.dataset.number = cell.neighborMines; } else { for (let dr = -1; dr <= 1; dr++) { for (let dc = -1; dc <= 1; dc++) { revealCell(row + dr, col + dc); } } } checkWin(); }
    function toggleFlag(row, col) { 
        if (isGameOver || board[row][col].isRevealed) return; 
        playSound('flag'); 
        const cell = board[row][col]; 
        const cellElement = document.querySelector(`.cell[data-row='${row}'][data-col='${col}']`); 
        cell.isFlagged = !cell.isFlagged; 
        flags += cell.isFlagged ? 1 : -1; 
        cellElement.classList.toggle('flagged'); 
        cellElement.innerHTML = cell.isFlagged ? '<i class="fas fa-flag" style="color:#ef4444;"></i>' : ''; 
        mineCounterDisplay.textContent = `${mineCount - flags}`; 
        checkWin(); 
    }
    
    function chord(row, col) { const cell = board[row][col]; if (!cell.isRevealed || cell.neighborMines === 0) return; let flaggedNeighborsCount = 0; const neighborsToProcess = []; for (let dr = -1; dr <= 1; dr++) { for (let dc = -1; dc <= 1; dc++) { if (dr === 0 && dc === 0) continue; const nr = row + dr, nc = col + dc; if (nr >= 0 && nr < rows && nc >= 0 && nc < cols) { const neighbor = board[nr][nc]; if (neighbor.isFlagged) { flaggedNeighborsCount++; } else if (!neighbor.isRevealed) { neighborsToProcess.push({ el: document.querySelector(`.cell[data-row='${nr}'][data-col='${nc}']`), r: nr, c: nc }); } } } } if (flaggedNeighborsCount === cell.neighborMines) { neighborsToProcess.forEach(n => revealCell(n.r, n.c)); } else { triggerVibration(50); neighborsToProcess.forEach(n => { n.el.classList.add('shake'); setTimeout(() => n.el.classList.remove('shake'), 300); }); } }
    function checkWin() { if (revealedCells === rows * cols - mineCount) gameOver(true); }
    
    function gameOver(isWin, clickedCellElement = null) {
        isGameOver = true; clearInterval(timerInterval); audio.music.pause();
        const score = isWin ? 500 : Math.max(0, revealedCells * 10);
        if (isWin) {
            playSound('win'); triggerVibration(500); modalMessage.innerHTML = '<i class="fas fa-trophy" style="color:#f59e0b;"></i> You Win!'; modal.style.display = 'flex';
        } else {
            triggerVibration([200, 100, 200]); modalMessage.innerHTML = '<i class="fas fa-bomb" style="color:#ef4444;"></i> Game Over';
            const minesToExplode = [];
            for (let r = 0; r < rows; r++) { for (let c = 0; c < cols; c++) {
                const cell = board[r][c], cellEl = document.querySelector(`.cell[data-row='${r}'][data-col='${c}']`);
                if (cell.isMine && !cell.isFlagged) { if (cellEl !== clickedCellElement) minesToExplode.push(cellEl); }
                else if (!cell.isMine && cell.isFlagged) { cellEl.classList.add('revealed'); cellEl.innerHTML = '<i class="fas fa-times" style="color:var(--danger-color);"></i>'; cellEl.style.color = 'var(--danger-color)'; }
            }}
            if (clickedCellElement) explodeMine(clickedCellElement);
            minesToExplode.sort(() => Math.random() - 0.5);
            minesToExplode.forEach((mineEl, index) => { setTimeout(() => explodeMine(mineEl), (index + 1) * 120); });
            const totalExplosionTime = (minesToExplode.length * 120) + 1200;
            setTimeout(() => { playSound('lose'); modal.style.display = 'flex'; }, totalExplosionTime);
        }

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: isWin ? 'win' : 'loss',
                score: score
            }, '*');
        }
    }
    
    function explodeMine(mineEl) { playOverlappingSound('explode'); triggerVibration(100); const randomColor = googleColors[Math.floor(Math.random() * googleColors.length)]; mineEl.classList.add('revealed', 'mine-hit'); mineEl.style.animation = 'mine-pop 0.3s ease-out forwards'; mineEl.style.backgroundColor = randomColor; mineEl.style.boxShadow = `0 0 20px ${randomColor}`; createGoogleExplosion(mineEl); }
    function startTimer(startTime = 0) { clearInterval(timerInterval); let seconds = startTime; timerDisplay.textContent = String(seconds).padStart(3, '0'); timerInterval = setInterval(() => { if(!isPaused) { seconds++; timerDisplay.textContent = String(seconds).padStart(3, '0'); } }, 1000); }
    function createGoogleExplosion(cellElement) { const rect = cellElement.getBoundingClientRect(); const container = document.body; const particleCount = 20; for (let i = 0; i < particleCount; i++) { const p = document.createElement('div'); p.classList.add('particle'); const size = Math.random() * 8 + 4; p.style.width = `${size}px`; p.style.height = `${size * (Math.random() > 0.5 ? 1 : 1.5)}px`; p.style.backgroundColor = googleColors[Math.floor(Math.random() * googleColors.length)]; const startX = rect.left + rect.width / 2; const startY = rect.top + rect.height / 2; p.style.left = `${startX}px`; p.style.top = `${startY}px`; p.style.opacity = 1; const angle = Math.random() * 360 * (Math.PI / 180); const distance = Math.random() * 60 + 30; const endX = Math.cos(angle) * distance; const endY = Math.sin(angle) * distance; const rotation = Math.random() * 720 - 360; container.appendChild(p); setTimeout(() => { p.style.transform = `translate(${endX}px, ${endY}px) rotateZ(${rotation}deg) scale(0.5)`; p.style.opacity = 0; }, 10); setTimeout(() => { p.remove(); }, 800); } }
    function debounce(func, wait) { let timeout; return function executedFunction(...args) { const later = () => { clearTimeout(timeout); func(...args); }; clearTimeout(timeout); timeout = setTimeout(later, wait); }; }
    restartButton.addEventListener('click', () => { playSound('click'); setTimeout(() => { showScreen('difficulty-view'); modal.style.display = 'none'; }, 50); });
    window.addEventListener('resize', debounce(updateCellSize, 250));
    
    loadSettings();
    showScreen('main-menu-view');
});
