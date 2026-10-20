/**
 * Minesweeper Deluxe - Pocket Classics
 * 3x3 Safe First Click, Session Scoreboard, Win Particles, Gamepad & Full Responsiveness
 */
document.addEventListener('DOMContentLoaded', () => {
    // --- AUDIO CONTROLLER ---
    const audioCtrl = (typeof ArcadeAudioController !== 'undefined')
        ? new ArcadeAudioController({
            menuAudioId: 'music-menu',
            gameAudioId: 'music-game',
            storagePrefix: 'pc_minesweeper_'
        })
        : (window.ArcadeHelper && window.ArcadeHelper.audio ? window.ArcadeHelper.audio : {
            musicEnabled: true, sfxEnabled: true,
            playMenuMusic: () => {}, playGameMusic: () => {}, pauseAll: () => {},
            toggleMusic: () => {}, toggleSfx: () => {}, playSfx: () => {}
        });

    const sfx = {
        click: document.getElementById('sfx-click'),
        flag: document.getElementById('sfx-flag'),
        reveal: document.getElementById('sfx-reveal'),
        explode: document.getElementById('sfx-explode'),
        win: document.getElementById('sfx-win'),
        lose: document.getElementById('sfx-lose')
    };

    function playSfx(sound) {
        if (!sound || !audioCtrl.sfxEnabled) return;
        try {
            sound.currentTime = 0;
            const p = sound.play();
            if (p && p.catch) p.catch(() => {});
        } catch (_) {}
    }

    // --- DOM REFERENCES ---
    const dom = {
        mainMenu: document.getElementById('main-menu'),
        gameContainer: document.getElementById('game-container'),
        resultModal: document.getElementById('result-modal'),
        settingsModal: document.getElementById('settings-modal'),
        confettiCanvas: document.getElementById('confetti-canvas'),
        gameBoard: document.getElementById('game-board'),
        mineCounter: document.getElementById('mine-counter'),
        timer: document.getElementById('timer'),
        scoreCleared: document.getElementById('score-cleared'),
        scoreDetonated: document.getElementById('score-detonated'),
        menuScoreCleared: document.getElementById('menu-score-cleared'),
        menuScoreDetonated: document.getElementById('menu-score-detonated'),
        difficultyBtns: Array.from(document.querySelectorAll('#difficulty-btns .option-btn')),
        startGameBtn: document.getElementById('start-game-btn'),
        openSettingsBtn: document.getElementById('open-settings-btn'),
        closeSettingsBtn: document.getElementById('close-settings-btn'),
        backToMenuBtn: document.getElementById('back-to-menu-btn'),
        restartGameBtn: document.getElementById('restart-game-btn'),
        playAgainBtn: document.getElementById('play-again-btn'),
        modalMenuBtn: document.getElementById('modal-menu-btn'),
        digModeBtn: document.getElementById('dig-mode-btn'),
        flagModeBtn: document.getElementById('flag-mode-btn'),
        resultTitle: document.getElementById('result-title'),
        resultDesc: document.getElementById('result-desc'),
        resultBadgeIcon: document.getElementById('result-badge-icon'),
        modalTimeVal: document.getElementById('modal-time-val'),
        modalDiffVal: document.getElementById('modal-diff-val'),
        musicToggle: document.getElementById('music-toggle'),
        sfxToggle: document.getElementById('sfx-toggle')
    };

    // --- MISSION CONFIGURATIONS ---
    const MISSIONS = {
        easy: { rows: 10, cols: 8, mines: 10, label: 'Novice' },
        medium: { rows: 12, cols: 12, mines: 24, label: 'Adept' },
        hard: { rows: 16, cols: 16, mines: 44, label: 'Expert' }
    };

    let selectedDifficulty = 'easy';
    let currentConfig = MISSIONS.easy;

    // --- GAME STATE ---
    let grid = []; // 2D array of { r, c, isMine, isRevealed, isFlagged, count }
    let isFirstClick = true;
    let isGameOver = false;
    let flagsPlaced = 0;
    let revealedCount = 0;
    let timerSeconds = 0;
    let timerInterval = null;
    let touchMode = 'dig'; // 'dig' or 'flag'
    let cursor = { r: 0, c: 0 };

    // Scoreboard session stats
    const stats = {
        cleared: 0,
        detonated: 0
    };

    function updateScoreDisplay() {
        if (dom.scoreCleared) dom.scoreCleared.textContent = stats.cleared;
        if (dom.scoreDetonated) dom.scoreDetonated.textContent = stats.detonated;
        if (dom.menuScoreCleared) dom.menuScoreCleared.textContent = stats.cleared;
        if (dom.menuScoreDetonated) dom.menuScoreDetonated.textContent = stats.detonated;
    }

    // Audio Settings init
    if (dom.musicToggle) {
        dom.musicToggle.checked = audioCtrl.musicEnabled;
        dom.musicToggle.addEventListener('change', () => {
            audioCtrl.toggleMusic(dom.musicToggle.checked);
        });
    }
    if (dom.sfxToggle) {
        dom.sfxToggle.checked = audioCtrl.sfxEnabled;
        dom.sfxToggle.addEventListener('change', () => {
            audioCtrl.toggleSfx(dom.sfxToggle.checked);
        });
    }

    // Start menu music on load
    audioCtrl.playMenuMusic();

    // --- SCREEN NAVIGATION ---
    function showMainMenu() {
        playSfx(sfx.click);
        stopTimer();
        stopConfetti();
        dom.gameContainer.classList.add('hidden');
        dom.resultModal.classList.add('hidden');
        dom.settingsModal.classList.add('hidden');
        dom.mainMenu.classList.remove('hidden');
        audioCtrl.playMenuMusic();
        updateScoreDisplay();
    }

    function startMission() {
        playSfx(sfx.click);
        stopConfetti();
        dom.mainMenu.classList.add('hidden');
        dom.resultModal.classList.add('hidden');
        dom.settingsModal.classList.add('hidden');
        dom.gameContainer.classList.remove('hidden');

        audioCtrl.playGameMusic();
        initMission();
    }

    function initMission() {
        currentConfig = MISSIONS[selectedDifficulty] || MISSIONS.easy;
        stopTimer();
        isFirstClick = true;
        isGameOver = false;
        flagsPlaced = 0;
        revealedCount = 0;
        timerSeconds = 0;
        updateTimerDisplay();
        updateMineCounter();
        cursor = { r: Math.floor(currentConfig.rows / 2), c: Math.floor(currentConfig.cols / 2) };

        createGrid();
        renderBoard();
        updateScoreDisplay();
    }

    // --- GRID LOGIC ---
    function createGrid() {
        grid = [];
        for (let r = 0; r < currentConfig.rows; r++) {
            const row = [];
            for (let c = 0; c < currentConfig.cols; c++) {
                row.push({
                    r, c,
                    isMine: false,
                    isRevealed: false,
                    isFlagged: false,
                    count: 0
                });
            }
            grid.push(row);
        }
    }

    function populateMines(safeR, safeC) {
        let placed = 0;
        const totalMines = currentConfig.mines;

        while (placed < totalMines) {
            const r = Math.floor(Math.random() * currentConfig.rows);
            const c = Math.floor(Math.random() * currentConfig.cols);

            // Guaranteed 3x3 safe zone around initial click
            const isSafeZone = Math.abs(r - safeR) <= 1 && Math.abs(c - safeC) <= 1;
            if (!grid[r][c].isMine && !isSafeZone) {
                grid[r][c].isMine = true;
                placed++;
            }
        }

        // Calculate surrounding mine counts
        for (let r = 0; r < currentConfig.rows; r++) {
            for (let c = 0; c < currentConfig.cols; c++) {
                if (grid[r][c].isMine) continue;
                let count = 0;
                for (let dr = -1; dr <= 1; dr++) {
                    for (let dc = -1; dc <= 1; dc++) {
                        const nr = r + dr, nc = c + dc;
                        if (nr >= 0 && nr < currentConfig.rows && nc >= 0 && nc < currentConfig.cols) {
                            if (grid[nr][nc].isMine) count++;
                        }
                    }
                }
                grid[r][c].count = count;
            }
        }
    }

    // --- BOARD RENDERING ---
    function renderBoard() {
        const boardEl = dom.gameBoard;
        boardEl.innerHTML = '';
        boardEl.style.gridTemplateColumns = `repeat(${currentConfig.cols}, 1fr)`;
        boardEl.style.gridTemplateRows = `repeat(${currentConfig.rows}, 1fr)`;

        for (let r = 0; r < currentConfig.rows; r++) {
            for (let c = 0; c < currentConfig.cols; c++) {
                const cellData = grid[r][c];
                const cellEl = document.createElement('div');
                cellEl.className = 'cell';
                cellEl.dataset.r = r;
                cellEl.dataset.c = c;

                if (cursor.r === r && cursor.c === c) {
                    cellEl.classList.add('focused');
                }

                if (cellData.isRevealed) {
                    cellEl.classList.add('revealed');
                    if (cellData.isMine) {
                        cellEl.classList.add('mine');
                        cellEl.innerHTML = '<i class="fas fa-bomb"></i>';
                    } else if (cellData.count > 0) {
                        cellEl.dataset.num = cellData.count;
                        cellEl.textContent = cellData.count;
                    }
                } else if (cellData.isFlagged) {
                    cellEl.classList.add('flagged');
                    cellEl.innerHTML = '<i class="fas fa-flag"></i>';
                }

                // Event Listeners
                cellEl.addEventListener('click', (e) => {
                    e.preventDefault();
                    cursor = { r, c };
                    if (touchMode === 'flag') {
                        toggleFlag(r, c);
                    } else {
                        revealCell(r, c);
                    }
                });

                cellEl.addEventListener('contextmenu', (e) => {
                    e.preventDefault();
                    cursor = { r, c };
                    toggleFlag(r, c);
                });

                // Long press support for mobile touch devices
                let touchTimer = null;
                cellEl.addEventListener('touchstart', (e) => {
                    touchTimer = setTimeout(() => {
                        toggleFlag(r, c);
                        touchTimer = null;
                        if (window.ArcadeHelper) window.ArcadeHelper.vibrate(30);
                    }, 260);
                }, { passive: true });

                cellEl.addEventListener('touchend', () => {
                    if (touchTimer) {
                        clearTimeout(touchTimer);
                        touchTimer = null;
                    }
                }, { passive: true });

                boardEl.appendChild(cellEl);
            }
        }
    }

    // --- GAME ACTIONS ---
    function revealCell(r, c) {
        if (isGameOver) return;
        const cell = grid[r][c];
        if (cell.isRevealed || cell.isFlagged) return;

        // Guaranteed safe on first click
        if (isFirstClick) {
            isFirstClick = false;
            populateMines(r, c);
            startTimer();
        }

        cell.isRevealed = true;
        revealedCount++;

        // Hit Mine -> Game Over
        if (cell.isMine) {
            handleExplosion(r, c);
            return;
        }

        playSfx(sfx.reveal);
        if (window.ArcadeHelper) window.ArcadeHelper.vibrate(12);

        // Flood fill empty neighbors
        if (cell.count === 0) {
            floodFill(r, c);
        }

        renderBoard();
        checkVictoryCondition();
    }

    function floodFill(startR, startC) {
        const queue = [{ r: startR, c: startC }];
        while (queue.length > 0) {
            const { r, c } = queue.shift();
            for (let dr = -1; dr <= 1; dr++) {
                for (let dc = -1; dc <= 1; dc++) {
                    const nr = r + dr, nc = c + dc;
                    if (nr >= 0 && nr < currentConfig.rows && nc >= 0 && nc < currentConfig.cols) {
                        const neighbor = grid[nr][nc];
                        if (!neighbor.isRevealed && !neighbor.isFlagged && !neighbor.isMine) {
                            neighbor.isRevealed = true;
                            revealedCount++;
                            if (neighbor.count === 0) {
                                queue.push({ r: nr, c: nc });
                            }
                        }
                    }
                }
            }
        }
    }

    function toggleFlag(r, c) {
        if (isGameOver) return;
        const cell = grid[r][c];
        if (cell.isRevealed) return;

        cell.isFlagged = !cell.isFlagged;
        flagsPlaced += cell.isFlagged ? 1 : -1;
        playSfx(sfx.flag);
        if (window.ArcadeHelper) window.ArcadeHelper.vibrate(20);
        updateMineCounter();
        renderBoard();
    }

    function chordCell(r, c) {
        const cell = grid[r][c];
        if (!cell.isRevealed || cell.count === 0) return;

        let flagsAround = 0;
        for (let dr = -1; dr <= 1; dr++) {
            for (let dc = -1; dc <= 1; dc++) {
                const nr = r + dr, nc = c + dc;
                if (nr >= 0 && nr < currentConfig.rows && nc >= 0 && nc < currentConfig.cols) {
                    if (grid[nr][nc].isFlagged) flagsAround++;
                }
            }
        }

        if (flagsAround === cell.count) {
            for (let dr = -1; dr <= 1; dr++) {
                for (let dc = -1; dc <= 1; dc++) {
                    const nr = r + dr, nc = c + dc;
                    if (nr >= 0 && nr < currentConfig.rows && nc >= 0 && nc < currentConfig.cols) {
                        if (!grid[nr][nc].isFlagged && !grid[nr][nc].isRevealed) {
                            revealCell(nr, nc);
                        }
                    }
                }
            }
        }
    }

    function handleExplosion(hitR, hitC) {
        isGameOver = true;
        stopTimer();
        playSfx(sfx.explode);
        if (window.ArcadeHelper) window.ArcadeHelper.vibrate([60, 40, 100]);
        audioCtrl.playMenuMusic();

        // Reveal all mines
        grid.forEach(row => row.forEach(c => {
            if (c.isMine) c.isRevealed = true;
        }));

        renderBoard();

        const hitEl = document.querySelector(`.cell[data-r='${hitR}'][data-c='${hitC}']`);
        if (hitEl) hitEl.classList.add('triggered');

        stats.detonated++;
        updateScoreDisplay();

        setTimeout(() => {
            showResultModal(false);
        }, 600);

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: 'loss',
                score: Math.max(0, revealedCount * 10)
            }, '*');
        }
    }

    function checkVictoryCondition() {
        const totalNonMines = (currentConfig.rows * currentConfig.cols) - currentConfig.mines;
        if (revealedCount === totalNonMines) {
            isGameOver = true;
            stopTimer();
            playSfx(sfx.win);
            audioCtrl.playMenuMusic();

            stats.cleared++;
            updateScoreDisplay();
            startConfetti();

            setTimeout(() => {
                showResultModal(true);
            }, 500);

            if (window.parent && window.parent !== window) {
                window.parent.postMessage({
                    type: 'ARCADE_GAME_OVER',
                    result: 'win',
                    score: Math.max(100, 1000 - timerSeconds * 5)
                }, '*');
            }
        }
    }

    function showResultModal(isWin) {
        dom.resultBadgeIcon.innerHTML = isWin ? '<i class="fas fa-trophy"></i>' : '<i class="fas fa-bomb"></i>';
        dom.resultBadgeIcon.style.color = isWin ? '#ffd700' : '#ef4444';
        dom.resultBadgeIcon.style.borderColor = isWin ? '#ffd700' : '#ef4444';

        dom.resultTitle.textContent = isWin ? 'Sector Cleared!' : 'Mine Detonated!';
        dom.resultTitle.style.color = isWin ? '#10b981' : '#ef4444';
        dom.resultDesc.textContent = isWin 
            ? 'All hazardous mines identified and neutralized.' 
            : 'Unstable explosive triggered during survey.';

        dom.modalTimeVal.textContent = `${String(timerSeconds).padStart(3, '0')}s`;
        dom.modalDiffVal.textContent = currentConfig.label;

        dom.resultModal.classList.remove('hidden');
    }

    // --- TIMERS & DISPLAY ---
    function startTimer() {
        stopTimer();
        timerInterval = setInterval(() => {
            timerSeconds++;
            if (timerSeconds > 999) timerSeconds = 999;
            updateTimerDisplay();
        }, 1000);
    }

    function stopTimer() {
        if (timerInterval) clearInterval(timerInterval);
        timerInterval = null;
    }

    function updateTimerDisplay() {
        if (dom.timer) dom.timer.textContent = String(timerSeconds).padStart(3, '0');
    }

    function updateMineCounter() {
        const remaining = Math.max(0, currentConfig.mines - flagsPlaced);
        if (dom.mineCounter) dom.mineCounter.textContent = String(remaining).padStart(3, '0');
    }

    // --- CONFETTI PARTICLES ---
    let confettiAnimationId = null;
    let confettiParticles = [];
    function startConfetti() {
        const canvas = dom.confettiCanvas;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        confettiParticles = [];

        const colors = ['#00f0ff', '#ffd700', '#10b981', '#38bdf8', '#ffffff'];
        for (let i = 0; i < 130; i++) {
            confettiParticles.push({
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height - canvas.height,
                radius: Math.random() * 4 + 2,
                color: colors[Math.floor(Math.random() * colors.length)],
                vx: Math.random() * 6 - 3,
                vy: Math.random() * 4 + 3,
                opacity: 1
            });
        }

        function render() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            confettiParticles.forEach((p, idx) => {
                p.x += p.vx;
                p.y += p.vy;
                p.opacity -= 0.006;
                if (p.opacity <= 0) confettiParticles.splice(idx, 1);

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.globalAlpha = Math.max(0, p.opacity);
                ctx.fill();
            });
            ctx.globalAlpha = 1;

            if (confettiParticles.length > 0) {
                confettiAnimationId = requestAnimationFrame(render);
            } else {
                confettiAnimationId = null;
            }
        }
        render();
    }

    function stopConfetti() {
        if (confettiAnimationId) cancelAnimationFrame(confettiAnimationId);
        confettiAnimationId = null;
        if (dom.confettiCanvas) {
            const ctx = dom.confettiCanvas.getContext('2d');
            ctx.clearRect(0, 0, dom.confettiCanvas.width, dom.confettiCanvas.height);
        }
    }

    // --- EVENT LISTENERS & NAVIGATION ---
    dom.startGameBtn?.addEventListener('click', startMission);
    dom.playAgainBtn?.addEventListener('click', startMission);
    dom.modalMenuBtn?.addEventListener('click', showMainMenu);
    dom.backToMenuBtn?.addEventListener('click', showMainMenu);
    dom.restartGameBtn?.addEventListener('click', () => {
        playSfx(sfx.click);
        initMission();
    });

    dom.openSettingsBtn?.addEventListener('click', () => {
        playSfx(sfx.click);
        dom.settingsModal.classList.remove('hidden');
    });
    dom.closeSettingsBtn?.addEventListener('click', () => {
        playSfx(sfx.click);
        dom.settingsModal.classList.add('hidden');
    });
    dom.settingsModal?.addEventListener('click', (e) => {
        if (e.target === dom.settingsModal) dom.settingsModal.classList.add('hidden');
    });

    // Difficulty selection
    dom.difficultyBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            playSfx(sfx.click);
            dom.difficultyBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            selectedDifficulty = btn.dataset.diff;
        });
    });

    // Mobile Dig / Flag Mode Toggle
    dom.digModeBtn?.addEventListener('click', () => {
        touchMode = 'dig';
        dom.digModeBtn.classList.add('active');
        dom.flagModeBtn.classList.remove('active');
    });
    dom.flagModeBtn?.addEventListener('click', () => {
        touchMode = 'flag';
        dom.flagModeBtn.classList.add('active');
        dom.digModeBtn.classList.remove('active');
    });

    // --- KEYBOARD CONTROLS ---
    window.addEventListener('keydown', (e) => {
        if (dom.gameContainer.classList.contains('hidden') || isGameOver) return;

        let moved = false;
        if (e.key === 'ArrowUp' || e.key === 'w' || e.key === 'W') {
            cursor.r = Math.max(0, cursor.r - 1); moved = true;
        } else if (e.key === 'ArrowDown' || e.key === 's' || e.key === 'S') {
            cursor.r = Math.min(currentConfig.rows - 1, cursor.r + 1); moved = true;
        } else if (e.key === 'ArrowLeft' || e.key === 'a' || e.key === 'A') {
            cursor.c = Math.max(0, cursor.c - 1); moved = true;
        } else if (e.key === 'ArrowRight' || e.key === 'd' || e.key === 'D') {
            cursor.c = Math.min(currentConfig.cols - 1, cursor.c + 1); moved = true;
        } else if (e.key === ' ' || e.key === 'Enter') {
            e.preventDefault();
            revealCell(cursor.r, cursor.c);
        } else if (e.key === 'f' || e.key === 'F') {
            e.preventDefault();
            toggleFlag(cursor.r, cursor.c);
        } else if (e.key === 'c' || e.key === 'C') {
            e.preventDefault();
            chordCell(cursor.r, cursor.c);
        }

        if (moved) {
            e.preventDefault();
            renderBoard();
        }
    });

    // --- GAMEPAD CONTROLLER INTEGRATION ---
    if (window.ArcadeGamepadController) {
        new ArcadeGamepadController({
            onDirectionDown: (dir) => {
                if (dom.gameContainer.classList.contains('hidden') || isGameOver) return;
                if (dir === 'up') cursor.r = Math.max(0, cursor.r - 1);
                else if (dir === 'down') cursor.r = Math.min(currentConfig.rows - 1, cursor.r + 1);
                else if (dir === 'left') cursor.c = Math.max(0, cursor.c - 1);
                else if (dir === 'right') cursor.c = Math.min(currentConfig.cols - 1, cursor.c + 1);
                renderBoard();
            },
            onActionDown: (act) => {
                if (act === 'a') {
                    if (!dom.resultModal.classList.contains('hidden')) {
                        startMission();
                    } else if (!dom.mainMenu.classList.contains('hidden')) {
                        startMission();
                    } else if (!dom.gameContainer.classList.contains('hidden') && !isGameOver) {
                        revealCell(cursor.r, cursor.c);
                    }
                } else if (act === 'x') {
                    if (!dom.gameContainer.classList.contains('hidden') && !isGameOver) {
                        toggleFlag(cursor.r, cursor.c);
                    }
                } else if (act === 'y') {
                    if (!dom.gameContainer.classList.contains('hidden') && !isGameOver) {
                        chordCell(cursor.r, cursor.c);
                    }
                } else if (act === 'start') {
                    if (!dom.gameContainer.classList.contains('hidden')) {
                        initMission();
                    }
                } else if (act === 'b') {
                    if (!dom.gameContainer.classList.contains('hidden')) {
                        showMainMenu();
                    }
                }
            }
        });
    }

    window.addEventListener('resize', () => {
        if (confettiAnimationId && dom.confettiCanvas) {
            dom.confettiCanvas.width = window.innerWidth;
            dom.confettiCanvas.height = window.innerHeight;
        }
    });
});
