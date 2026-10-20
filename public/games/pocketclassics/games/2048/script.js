document.addEventListener('DOMContentLoaded', () => {
    // --- Initialize Universal Arcade Helper ---
    const helper = window.ArcadeHelper ? window.ArcadeHelper.init({
        menuMusic: 'sounds/menu-music.mp3',
        gameMusic: 'sounds/music.mp3'
    }) : null;

    // --- DOM Elements ---
    const mainMenu = document.getElementById('main-menu');
    const difficultyMenu = document.getElementById('difficulty-menu');
    const gameContainer = document.getElementById('game-container');
    const gameOverModal = document.getElementById('game-over-modal');
    const settingsModal = document.getElementById('settings-modal');

    const playBtn = document.getElementById('play-btn');
    const settingsBtn = document.getElementById('settings-btn');
    const backToMainBtn = document.getElementById('back-to-main-btn');
    const difficultyButtons = document.querySelectorAll('.diff-card');
    const closeSettingsBtn = document.getElementById('close-settings-btn');
    const menuBtn = document.getElementById('menu-btn');
    const restartBtn = document.getElementById('restart-btn');
    const modalRestartBtn = document.getElementById('modal-restart-btn');
    const modalMenuBtn = document.getElementById('modal-menu-btn');

    const gameBoard = document.getElementById('game-board');
    const boardContainer = document.getElementById('game-board-container');
    const scoreDisplay = document.getElementById('score');
    const bestScoreDisplay = document.getElementById('best-score');
    const finalScoreDisplay = document.getElementById('final-score');
    const modalTitle = document.getElementById('modal-title');
    const modalIcon = document.getElementById('modal-icon');
    const gridModeLabel = document.getElementById('grid-mode-label');

    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');

    const moveSound = document.getElementById('move-sound');
    const mergeSound = document.getElementById('merge-sound');
    const winSound = document.getElementById('win-sound');
    const loseSound = document.getElementById('lose-sound');
    const uiClickSound = document.getElementById('ui-click-sound');

    const confettiCanvas = document.getElementById('confetti-canvas');
    const confettiInstance = window.confetti ? window.confetti.create(confettiCanvas, { resize: true, useWorker: true }) : null;

    // --- Game State ---
    let gridSize = 4;
    let winValue = 2048;
    let board = [];
    let score = 0;
    let bestScore = 0;
    let isGameOver = false;
    let isMoving = false;
    let hasWon = false;

    // --- Audio Helper wrappers ---
    function playSfx(snd) {
        if (helper) helper.audio.playSfx(snd);
        else if (snd) { snd.currentTime = 0; snd.play().catch(() => {}); }
    }
    function playClick() { playSfx(uiClickSound); }

    // Start with Menu Music
    if (helper) {
        helper.audio.playMenuMusic();
    }

    // Settings Toggle sync
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

    // --- Navigation ---
    playBtn?.addEventListener('click', () => {
        playClick();
        mainMenu.classList.add('hidden');
        difficultyMenu.classList.remove('hidden');
    });

    settingsBtn?.addEventListener('click', () => {
        playClick();
        settingsModal.classList.remove('hidden');
    });

    closeSettingsBtn?.addEventListener('click', () => {
        playClick();
        settingsModal.classList.add('hidden');
    });

    backToMainBtn?.addEventListener('click', () => {
        playClick();
        difficultyMenu.classList.add('hidden');
        mainMenu.classList.remove('hidden');
        if (helper) helper.audio.playMenuMusic();
    });

    difficultyButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            playClick();
            const size = parseInt(btn.dataset.size, 10);
            const win = parseInt(btn.dataset.win, 10);
            startGame(size, win);
        });
    });

    function returnToMenu() {
        playClick();
        gameContainer.classList.add('hidden');
        gameOverModal.classList.add('hidden');
        difficultyMenu.classList.add('hidden');
        mainMenu.classList.remove('hidden');
        if (helper) helper.audio.playMenuMusic();
    }

    menuBtn?.addEventListener('click', returnToMenu);
    modalMenuBtn?.addEventListener('click', returnToMenu);

    restartBtn?.addEventListener('click', () => {
        playClick();
        initGame();
        if (helper) helper.audio.playGameMusic();
    });

    modalRestartBtn?.addEventListener('click', () => {
        playClick();
        gameOverModal.classList.add('hidden');
        initGame();
        if (helper) helper.audio.playGameMusic();
    });

    // --- Game Logic ---
    function startGame(size, win) {
        gridSize = size;
        winValue = win;
        hasWon = false;
        if (gridModeLabel) gridModeLabel.textContent = `${gridSize}×${gridSize}`;
        
        bestScore = parseInt(localStorage.getItem(`bestScore_${gridSize}`) || '0', 10);
        if (bestScoreDisplay) bestScoreDisplay.textContent = bestScore;

        difficultyMenu.classList.add('hidden');
        mainMenu.classList.add('hidden');
        gameOverModal.classList.add('hidden');
        gameContainer.classList.remove('hidden');

        // Switch smoothly to Game Music
        if (helper) helper.audio.playGameMusic();

        initGame();
    }

    function initGame() {
        board = Array(gridSize * gridSize).fill(0);
        score = 0;
        isGameOver = false;
        isMoving = false;
        hasWon = false;
        updateScore(0);
        setupGameBoard();
        spawnTile();
        spawnTile();
        updateDisplay();
    }

    function setupGameBoard() {
        gameBoard.innerHTML = '';
        gameBoard.style.gridTemplateColumns = `repeat(${gridSize}, 1fr)`;
        gameBoard.style.gridTemplateRows = `repeat(${gridSize}, 1fr)`;

        for (let i = 0; i < gridSize * gridSize; i++) {
            const cell = document.createElement('div');
            cell.classList.add('grid-cell');
            gameBoard.appendChild(cell);
        }
    }

    function getEmptyCells() {
        const empty = [];
        for (let i = 0; i < board.length; i++) {
            if (board[i] === 0) empty.push(i);
        }
        return empty;
    }

    function spawnTile() {
        const empty = getEmptyCells();
        if (empty.length > 0) {
            const idx = empty[Math.floor(Math.random() * empty.length)];
            board[idx] = Math.random() < 0.9 ? 2 : 4;
        }
    }

    function updateDisplay() {
        if (!boardContainer) return;
        boardContainer.querySelectorAll('.tile').forEach(t => t.remove());

        const pad = 8;
        const gap = 8;
        const totalGap = gap * (gridSize - 1);
        const availWidth = boardContainer.clientWidth - (pad * 2);
        const cellSize = Math.floor((availWidth - totalGap) / gridSize);

        for (let i = 0; i < board.length; i++) {
            if (board[i] !== 0) {
                const r = Math.floor(i / gridSize);
                const c = i % gridSize;
                const tile = document.createElement('div');
                tile.classList.add('tile', 'show');
                tile.dataset.value = board[i];
                tile.textContent = board[i];

                tile.style.width = `${cellSize}px`;
                tile.style.height = `${cellSize}px`;
                tile.style.top = `${pad + r * (cellSize + gap)}px`;
                tile.style.left = `${pad + c * (cellSize + gap)}px`;

                // Adjust font size for larger numbers
                if (board[i] >= 1024) tile.style.fontSize = `${Math.max(12, cellSize * 0.28)}px`;
                else if (board[i] >= 128) tile.style.fontSize = `${Math.max(14, cellSize * 0.35)}px`;
                else tile.style.fontSize = `${Math.max(16, cellSize * 0.42)}px`;

                boardContainer.appendChild(tile);
            }
        }
    }

    function updateScore(pts) {
        score += pts;
        if (scoreDisplay) scoreDisplay.textContent = score;
        if (score > bestScore) {
            bestScore = score;
            if (bestScoreDisplay) bestScoreDisplay.textContent = bestScore;
            localStorage.setItem(`bestScore_${gridSize}`, bestScore);
        }
    }

    function move(dir) {
        if (isGameOver || isMoving) return;
        isMoving = true;
        let boardChanged = false;
        let mergeOccurred = false;
        let tempBoard = [...board];

        function slideAndMerge(line) {
            let filtered = line.filter(num => num !== 0);
            for (let i = 0; i < filtered.length - 1; i++) {
                if (filtered[i] === filtered[i + 1]) {
                    filtered[i] *= 2;
                    updateScore(filtered[i]);
                    filtered[i + 1] = 0;
                    mergeOccurred = true;
                }
            }
            let newLine = filtered.filter(num => num !== 0);
            while (newLine.length < gridSize) newLine.push(0);
            return newLine;
        }

        if (dir === 'up' || dir === 'down') {
            for (let c = 0; c < gridSize; c++) {
                let column = [];
                for (let r = 0; r < gridSize; r++) column.push(tempBoard[r * gridSize + c]);
                if (dir === 'down') column.reverse();
                let newColumn = slideAndMerge(column);
                if (dir === 'down') newColumn.reverse();
                for (let r = 0; r < gridSize; r++) {
                    const idx = r * gridSize + c;
                    if (tempBoard[idx] !== newColumn[r]) boardChanged = true;
                    tempBoard[idx] = newColumn[r];
                }
            }
        } else {
            for (let r = 0; r < gridSize; r++) {
                let row = tempBoard.slice(r * gridSize, r * gridSize + gridSize);
                if (dir === 'right') row.reverse();
                let newRow = slideAndMerge(row);
                if (dir === 'right') newRow.reverse();
                for (let c = 0; c < gridSize; c++) {
                    const idx = r * gridSize + c;
                    if (tempBoard[idx] !== newRow[c]) boardChanged = true;
                    tempBoard[idx] = newRow[c];
                }
            }
        }

        if (boardChanged) {
            board = tempBoard;
            if (mergeOccurred) {
                playSfx(mergeSound);
                if (helper) helper.vibrate(25);
            } else {
                playSfx(moveSound);
                if (helper) helper.vibrate(12);
            }
            spawnTile();
            updateDisplay();
            checkGameState();
        }

        setTimeout(() => { isMoving = false; }, 130);
    }

    function canMove() {
        for (let r = 0; r < gridSize; r++) {
            for (let c = 0; c < gridSize; c++) {
                const val = board[r * gridSize + c];
                if (val === 0) return true;
                if (c < gridSize - 1 && val === board[r * gridSize + (c + 1)]) return true;
                if (r < gridSize - 1 && val === board[(r + 1) * gridSize + c]) return true;
            }
        }
        return false;
    }

    function checkGameState() {
        if (!hasWon && board.includes(winValue)) {
            hasWon = true;
            endGame(true);
            return;
        }
        if (getEmptyCells().length === 0 && !canMove()) {
            endGame(false);
        }
    }

    function endGame(isWin) {
        isGameOver = true;
        if (isWin) {
            modalTitle.textContent = "You Win!";
            if (modalIcon) {
                modalIcon.innerHTML = '<i class="fas fa-trophy"></i>';
                modalIcon.style.color = '#ffd700';
                modalIcon.style.borderColor = '#ffd700';
            }
            playSfx(winSound);
            if (helper) helper.vibrate([40, 30, 60]);
            triggerConfetti();
        } else {
            modalTitle.textContent = "Game Over!";
            if (modalIcon) {
                modalIcon.innerHTML = '<i class="fas fa-skull"></i>';
                modalIcon.style.color = '#ef4444';
                modalIcon.style.borderColor = '#ef4444';
            }
            playSfx(loseSound);
            if (helper) helper.vibrate(50);
        }

        if (finalScoreDisplay) finalScoreDisplay.textContent = score;
        setTimeout(() => {
            gameOverModal.classList.remove('hidden');
            if (helper) helper.audio.playMenuMusic();
        }, 400);

        // Relay result to GPLMods Arcade shell
        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: isWin ? 'win' : 'loss',
                score: score
            }, '*');
        }
    }

    function triggerConfetti() {
        if (!confettiInstance) return;
        confettiInstance({ particleCount: 70, spread: 80, origin: { y: 0.6 } });
        setTimeout(() => {
            confettiInstance({ particleCount: 50, angle: 60, spread: 55, origin: { x: 0 } });
            confettiInstance({ particleCount: 50, angle: 120, spread: 55, origin: { x: 1 } });
        }, 200);
    }

    // --- INPUT SUPPORT ---

    // 1. Keyboard (WASD + Arrows + HJKL)
    window.addEventListener('keydown', (e) => {
        if (gameContainer.classList.contains('hidden') || isGameOver) return;
        const keyMap = {
            ArrowUp: 'up', KeyW: 'up', KeyK: 'up',
            ArrowDown: 'down', KeyS: 'down', KeyJ: 'down',
            ArrowLeft: 'left', KeyA: 'left', KeyH: 'left',
            ArrowRight: 'right', KeyD: 'right', KeyL: 'right'
        };
        const dir = keyMap[e.code] || keyMap[e.key];
        if (dir) {
            e.preventDefault();
            move(dir);
        } else if (e.code === 'KeyR') {
            restartBtn?.click();
        } else if (e.code === 'Escape') {
            menuBtn?.click();
        }
    });

    // 2. Gamepad Controller Support
    if (helper && helper.gamepad) {
        helper.gamepad.onDirection((dir) => {
            if (!gameContainer.classList.contains('hidden') && !isGameOver) {
                move(dir);
            }
        });

        helper.gamepad.onAction((action) => {
            if (action === 'SELECT') {
                restartBtn?.click();
            } else if (action === 'START') {
                if (!gameContainer.classList.contains('hidden')) {
                    menuBtn?.click();
                }
            }
        });
    }

    // 3. Touch Swipe Handling
    if (helper && boardContainer) {
        helper.bindSwipe(boardContainer, (dir) => {
            if (!gameContainer.classList.contains('hidden') && !isGameOver) {
                move(dir);
            }
        });
    }

    // 4. On-screen Virtual D-Pad
    document.querySelectorAll('.dpad-key').forEach(key => {
        key.addEventListener('click', () => {
            const dir = key.dataset.dir;
            if (dir && !gameContainer.classList.contains('hidden') && !isGameOver) {
                move(dir);
            }
        });
    });

    // 5. Responsive Resize Fix
    window.addEventListener('resize', () => {
        if (!gameContainer.classList.contains('hidden')) {
            updateDisplay();
        }
    });
});
