/**
 * Snakes & Ladders Deluxe - Pocket Classics
 * Full Mobile/Tablet/PC, Gamepad, Touch, Keyboard, Dual-Track Music & Sound
 */
document.addEventListener('DOMContentLoaded', () => {
    // --- AUDIO CONTROLLER ---
    const audioCtrl = (typeof ArcadeAudioController !== 'undefined')
        ? new ArcadeAudioController({
            menuAudioId: 'music-menu',
            gameAudioId: 'music-game',
            storagePrefix: 'pc_snakes_'
        })
        : (window.ArcadeHelper && window.ArcadeHelper.audio ? window.ArcadeHelper.audio : {
            musicEnabled: true, sfxEnabled: true,
            playMenuMusic: () => {}, playGameMusic: () => {}, pauseAll: () => {},
            toggleMusic: () => {}, toggleSfx: () => {}, playSfx: () => {}
        });

    const sfx = {
        dice: document.getElementById('dice-sound'),
        move: document.getElementById('move-sound'),
        ladder: document.getElementById('ladder-sound'),
        snake: document.getElementById('snake-sound'),
        win: document.getElementById('win-sound'),
        click: document.getElementById('click-sound')
    };

    function playSfx(sound) {
        if (!sound || !audioCtrl.sfxEnabled) return;
        try {
            sound.currentTime = 0;
            const p = sound.play();
            if (p && p.catch) p.catch(() => {});
        } catch (e) {}
    }

    // --- GAME CONFIG & STATE ---
    const config = {
        BOARD_SIZE: 100,
        NUM_SNAKES: 7,
        NUM_LADDERS: 7,
        AI_THINK_TIME: 800,
        STEP_DELAY: 110,
        SLIDE_DELAY: 400
    };

    const DICE_GLYPHS = ['⚀', '⚁', '⚂', '⚃', '⚄', '⚅'];
    const PLAYER_NAMES = ['Player 1', 'Player 2', 'Player 3', 'Player 4'];
    const PLAYER_COLORS = ['#00f0ff', '#ffd700', '#ff007f', '#10b981'];

    let state = {
        gameMode: 'pvp', // 'pvp' or 'pva'
        numPlayers: 2,
        playerPositions: [1, 1],
        currentPlayerIndex: 0,
        snakes: {},
        ladders: {},
        isGameOver: false,
        isRolling: false,
        isMoving: false,
        confettiAnimationId: null
    };

    // --- DOM REFERENCES ---
    const dom = {
        mainMenu: document.getElementById('main-menu'),
        gameContainer: document.getElementById('game-container'),
        settingsModal: document.getElementById('settings-modal'),
        winPopup: document.getElementById('win-popup'),
        winMessage: document.getElementById('win-message'),
        confettiCanvas: document.getElementById('confetti-canvas'),
        gameBoard: document.getElementById('game-board'),
        turnInfo: document.getElementById('turn-info'),
        diceDisplay: document.getElementById('dice'),
        diceGlyph: document.getElementById('dice-glyph'),
        rollDiceBtn: document.getElementById('roll-dice-btn'),
        playersRack: document.getElementById('players-rack'),
        messageLog: document.getElementById('message-log'),
        startGameBtn: document.getElementById('start-game-btn'),
        openSettingsBtn: document.getElementById('open-settings-btn'),
        closeSettingsBtn: document.getElementById('close-settings-btn'),
        backToMenuBtn: document.getElementById('back-to-menu-btn'),
        restartGameBtn: document.getElementById('restart-game-btn'),
        playAgainBtn: document.getElementById('play-again-btn'),
        menuFromWinBtn: document.getElementById('menu-from-win-btn'),
        gameModeBtns: document.getElementById('game-mode-btns'),
        playerCountBtns: document.getElementById('player-count-btns'),
        musicToggle: document.getElementById('music-toggle'),
        sfxToggle: document.getElementById('sfx-toggle')
    };

    const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

    // --- SETTINGS INIT ---
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

    // --- Match Session Scoreboard Comparison (Requirement: player 1 (4) and player 2 (5)) ---
    let sessP1 = parseInt(localStorage.getItem('arc_snakes_p1') || '0', 10);
    let sessP2 = parseInt(localStorage.getItem('arc_snakes_p2') || '0', 10);

    function updateSnakesScoreboard() {
        const p1El = document.getElementById('sessP1Wins');
        const p2El = document.getElementById('sessP2Wins');
        const pill1 = document.getElementById('pillP1');
        const pill2 = document.getElementById('pillP2');
        if (p1El) p1El.textContent = sessP1;
        if (p2El) p2El.textContent = sessP2;
        if (pill1 && pill2) {
            pill1.classList.toggle('leading', sessP1 > sessP2);
            pill2.classList.toggle('leading', sessP2 > sessP1);
        }
    }
    updateSnakesScoreboard();

    // Start menu music on initial load/touch
    audioCtrl.playMenuMusic();

    // --- MENU NAVIGATION ---
    function showMainMenu() {
        playSfx(sfx.click);
        stopConfetti();
        dom.gameContainer.classList.add('hidden');
        dom.winPopup.classList.add('hidden');
        dom.settingsModal.classList.add('hidden');
        dom.mainMenu.classList.remove('hidden');
        audioCtrl.playMenuMusic();
    }

    function startNewMatch() {
        playSfx(sfx.click);
        stopConfetti();
        dom.mainMenu.classList.add('hidden');
        dom.winPopup.classList.add('hidden');
        dom.settingsModal.classList.add('hidden');
        dom.gameContainer.classList.remove('hidden');

        audioCtrl.playGameMusic();
        resetMatch();
    }

    // --- BOARD GENERATION ---
    function generateBoard() {
        dom.gameBoard.innerHTML = '';
        for (let i = 0; i < config.BOARD_SIZE; i++) {
            const cell = document.createElement('div');
            cell.className = 'cell';
            const numSpan = document.createElement('span');
            numSpan.className = 'cell-number';
            cell.appendChild(numSpan);
            dom.gameBoard.appendChild(cell);
        }

        // Boustrophedon (snake/zigzag) numbering: 100 down to 1
        const cells = Array.from(dom.gameBoard.children);
        let cellNumber = config.BOARD_SIZE;
        for (let row = 0; row < 10; row++) {
            const rowCells = cells.slice(row * 10, (row * 10) + 10);
            if (row % 2 !== 0) rowCells.reverse();
            for (const cell of rowCells) {
                cell.querySelector('.cell-number').textContent = cellNumber;
                cell.dataset.cell = cellNumber;
                cellNumber--;
            }
        }
    }

    function generateSnakesAndLadders() {
        const occupied = new Set([1, config.BOARD_SIZE]);
        state.snakes = {};
        state.ladders = {};

        // Ladders: bottom to top
        for (let i = 0; i < config.NUM_LADDERS; i++) {
            let start, end;
            let attempts = 0;
            do {
                start = Math.floor(Math.random() * (config.BOARD_SIZE - 25)) + 2;
                end = Math.floor(Math.random() * (config.BOARD_SIZE - start - 10)) + start + 12;
                attempts++;
            } while ((occupied.has(start) || occupied.has(end) || end >= config.BOARD_SIZE) && attempts < 100);

            if (attempts < 100) {
                occupied.add(start);
                occupied.add(end);
                state.ladders[start] = end;
            }
        }

        // Snakes: head to tail
        for (let i = 0; i < config.NUM_SNAKES; i++) {
            let start, end;
            let attempts = 0;
            do {
                start = Math.floor(Math.random() * (config.BOARD_SIZE - 22)) + 22;
                end = Math.floor(Math.random() * (start - 12)) + 2;
                attempts++;
            } while ((occupied.has(start) || occupied.has(end)) && attempts < 100);

            if (attempts < 100) {
                occupied.add(start);
                occupied.add(end);
                state.snakes[start] = end;
            }
        }
    }

    function renderBoardMarkers() {
        document.querySelectorAll('.cell .marker').forEach(m => m.remove());

        const createMarker = (cell, type, destination) => {
            const marker = document.createElement('div');
            marker.className = `marker ${type}`;
            const icon = type === 'snake' 
                ? '<i class="fas fa-worm"></i>' 
                : '<i class="fas fa-arrow-up"></i>';
            marker.innerHTML = `${icon}<span class="marker-target">→ ${destination}</span>`;
            cell.appendChild(marker);
        };

        for (const [start, end] of Object.entries(state.snakes)) {
            const cell = document.querySelector(`[data-cell='${start}']`);
            if (cell) createMarker(cell, 'snake', end);
        }

        for (const [start, end] of Object.entries(state.ladders)) {
            const cell = document.querySelector(`[data-cell='${start}']`);
            if (cell) createMarker(cell, 'ladder', end);
        }
    }

    function renderPlayerTokens() {
        document.querySelectorAll('.player-token').forEach(t => t.remove());

        state.playerPositions.forEach((pos, i) => {
            const cell = document.querySelector(`[data-cell='${pos}']`);
            if (cell) {
                const token = document.createElement('div');
                token.className = `player-token p-${i}`;
                token.title = `${getPlayerLabel(i)} (Sq ${pos})`;
                cell.appendChild(token);
            }
        });

        renderPlayerRack();
    }

    function getPlayerLabel(index) {
        if (state.gameMode === 'pva' && index > 0) {
            return `AI Rival ${index}`;
        }
        return PLAYER_NAMES[index] || `Player ${index + 1}`;
    }

    function renderPlayerRack() {
        dom.playersRack.innerHTML = '';
        for (let i = 0; i < state.numPlayers; i++) {
            const badge = document.createElement('div');
            badge.className = 'player-badge' + (i === state.currentPlayerIndex ? ' active' : '');
            badge.innerHTML = `
                <span class="p-dot" style="background: ${PLAYER_COLORS[i]};"></span>
                <span>${getPlayerLabel(i)}</span>
                <span style="margin-left: auto; color: #ffd700; font-size: 0.72rem;">Sq ${state.playerPositions[i]}</span>
            `;
            dom.playersRack.appendChild(badge);
        }
    }

    function updateTurnInfo() {
        const curr = state.currentPlayerIndex;
        const label = getPlayerLabel(curr);
        dom.turnInfo.textContent = `${label}'s Turn`;
        dom.turnInfo.style.borderColor = PLAYER_COLORS[curr];
        dom.turnInfo.style.boxShadow = `0 0 10px ${PLAYER_COLORS[curr]}44`;

        renderPlayerRack();
    }

    function logMessage(msg) {
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.textContent = msg;
        dom.messageLog.appendChild(entry);
        dom.messageLog.scrollTop = dom.messageLog.scrollHeight;
    }

    function resetMatch() {
        state.isGameOver = false;
        state.isRolling = false;
        state.isMoving = false;
        state.playerPositions = Array(state.numPlayers).fill(1);
        state.currentPlayerIndex = 0;

        dom.messageLog.innerHTML = '<div class="log-entry">Match started! Roll dice to begin.</div>';
        dom.rollDiceBtn.disabled = false;
        dom.diceGlyph.textContent = '⚅';

        generateBoard();
        generateSnakesAndLadders();
        renderBoardMarkers();
        renderPlayerTokens();
        updateTurnInfo();
    }

    // --- DICE ROLLING ---
    async function animateDiceRoll() {
        playSfx(sfx.dice);
        dom.diceDisplay.classList.add('rolling');

        const finalRoll = Math.floor(Math.random() * 6) + 1;
        let shuffleCount = 0;
        const totalShuffles = 10;

        return new Promise(resolve => {
            const interval = setInterval(() => {
                const randomGlyph = DICE_GLYPHS[Math.floor(Math.random() * 6)];
                dom.diceGlyph.textContent = randomGlyph;
                shuffleCount++;
                if (shuffleCount >= totalShuffles) {
                    clearInterval(interval);
                    dom.diceDisplay.classList.remove('rolling');
                    dom.diceGlyph.textContent = DICE_GLYPHS[finalRoll - 1];
                    if (window.ArcadeHelper) window.ArcadeHelper.vibrate(30);
                    resolve(finalRoll);
                }
            }, 60);
        });
    }

    // --- PLAYER MOVEMENT ---
    function stepMove(start, target) {
        return new Promise(resolve => {
            let current = start;
            const isForward = target > start;
            const interval = setInterval(() => {
                if (current === target) {
                    clearInterval(interval);
                    resolve();
                    return;
                }
                current = isForward ? current + 1 : current - 1;
                state.playerPositions[state.currentPlayerIndex] = current;
                playSfx(sfx.move);
                renderPlayerTokens();
            }, config.STEP_DELAY);
        });
    }

    async function handleTurn() {
        if (state.isGameOver || state.isRolling || state.isMoving) return;

        state.isRolling = true;
        dom.rollDiceBtn.disabled = true;

        const diceValue = await animateDiceRoll();
        state.isRolling = false;

        const currIdx = state.currentPlayerIndex;
        const label = getPlayerLabel(currIdx);
        logMessage(`${label} rolled a ${diceValue}!`);

        const startPos = state.playerPositions[currIdx];
        const targetPos = startPos + diceValue;

        state.isMoving = true;

        if (targetPos <= config.BOARD_SIZE) {
            await stepMove(startPos, targetPos);
            let finalPos = state.playerPositions[currIdx];

            // Check Snake
            if (state.snakes[finalPos]) {
                const tailPos = state.snakes[finalPos];
                logMessage(`🐍 Ouch! ${label} bit by snake at ${finalPos}! Sliding down to ${tailPos}.`);
                playSfx(sfx.snake);
                if (window.ArcadeHelper) window.ArcadeHelper.vibrate([40, 60, 40]);
                await wait(config.SLIDE_DELAY);
                await stepMove(finalPos, tailPos);
            } 
            // Check Ladder
            else if (state.ladders[finalPos]) {
                const topPos = state.ladders[finalPos];
                logMessage(`🪜 Wow! ${label} climbed ladder at ${finalPos} up to ${topPos}!`);
                playSfx(sfx.ladder);
                if (window.ArcadeHelper) window.ArcadeHelper.vibrate([20, 40, 80]);
                await wait(config.SLIDE_DELAY);
                await stepMove(finalPos, topPos);
            }
        } else {
            logMessage(`⚠️ Need exact roll to reach 100! ${label} stays at ${startPos}.`);
            await wait(config.SLIDE_DELAY);
        }

        state.isMoving = false;

        // Check Victory
        if (state.playerPositions[currIdx] === config.BOARD_SIZE) {
            handleVictory(currIdx);
            return;
        }

        // Advance to Next Player
        state.currentPlayerIndex = (state.currentPlayerIndex + 1) % state.numPlayers;
        updateTurnInfo();

        // Check if next player is AI
        if (state.gameMode === 'pva' && state.currentPlayerIndex > 0) {
            dom.rollDiceBtn.disabled = true;
            dom.turnInfo.textContent = `${getPlayerLabel(state.currentPlayerIndex)} is thinking...`;
            setTimeout(() => {
                if (!state.isGameOver && !dom.gameContainer.classList.contains('hidden')) {
                    handleTurn();
                }
            }, config.AI_THINK_TIME);
        } else {
            dom.rollDiceBtn.disabled = false;
        }
    }

    function handleVictory(winnerIndex) {
        state.isGameOver = true;
        dom.rollDiceBtn.disabled = true;
        playSfx(sfx.win);
        audioCtrl.playMenuMusic();

        if (winnerIndex === 0) {
            sessP1++;
            localStorage.setItem('arc_snakes_p1', sessP1);
        } else {
            sessP2++;
            localStorage.setItem('arc_snakes_p2', sessP2);
        }
        updateSnakesScoreboard();

        const label = getPlayerLabel(winnerIndex);
        const color = PLAYER_COLORS[winnerIndex];

        dom.winMessage.textContent = `${label} Wins!`;
        dom.winMessage.style.color = color;
        dom.winMessage.style.textShadow = `0 0 16px ${color}88`;
        dom.winPopup.classList.remove('hidden');

        logMessage(`🏆 ${label} reached square 100 and won the game!`);
        startConfetti();

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: winnerIndex === 0 ? 'win' : 'loss',
                score: 100
            }, '*');
        }
    }

    // --- CONFETTI SYSTEM ---
    let confettiParticles = [];
    function startConfetti() {
        const canvas = dom.confettiCanvas;
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        confettiParticles = [];

        const colors = ['#00f0ff', '#ffd700', '#ff007f', '#10b981', '#ffffff'];
        for (let i = 0; i < 150; i++) {
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
                p.opacity -= 0.005;
                if (p.opacity <= 0) confettiParticles.splice(idx, 1);

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.globalAlpha = Math.max(0, p.opacity);
                ctx.fill();
            });
            ctx.globalAlpha = 1;

            if (confettiParticles.length > 0) {
                state.confettiAnimationId = requestAnimationFrame(render);
            } else {
                state.confettiAnimationId = null;
            }
        }
        render();
    }

    function stopConfetti() {
        if (state.confettiAnimationId) cancelAnimationFrame(state.confettiAnimationId);
        state.confettiAnimationId = null;
        const ctx = dom.confettiCanvas.getContext('2d');
        ctx.clearRect(0, 0, dom.confettiCanvas.width, dom.confettiCanvas.height);
    }

    // --- INPUT EVENT HANDLERS ---
    dom.startGameBtn.addEventListener('click', startNewMatch);
    dom.backToMenuBtn.addEventListener('click', showMainMenu);
    dom.menuFromWinBtn.addEventListener('click', showMainMenu);
    dom.playAgainBtn.addEventListener('click', startNewMatch);
    dom.restartGameBtn.addEventListener('click', () => {
        playSfx(sfx.click);
        resetMatch();
    });

    dom.openSettingsBtn.addEventListener('click', () => {
        playSfx(sfx.click);
        dom.settingsModal.classList.remove('hidden');
    });
    dom.closeSettingsBtn.addEventListener('click', () => {
        playSfx(sfx.click);
        dom.settingsModal.classList.add('hidden');
    });
    dom.settingsModal.addEventListener('click', (e) => {
        if (e.target === dom.settingsModal) dom.settingsModal.classList.add('hidden');
    });

    // Game Mode selection
    dom.gameModeBtns.addEventListener('click', (e) => {
        const btn = e.target.closest('button');
        if (!btn) return;
        playSfx(sfx.click);
        Array.from(dom.gameModeBtns.children).forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.gameMode = btn.dataset.mode;
    });

    // Player Count selection
    dom.playerCountBtns.addEventListener('click', (e) => {
        const btn = e.target.closest('button');
        if (!btn) return;
        playSfx(sfx.click);
        Array.from(dom.playerCountBtns.children).forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.numPlayers = parseInt(btn.dataset.count, 10);
    });

    // Roll Dice button & display click
    function onUserRollAttempt() {
        if (state.gameMode === 'pva' && state.currentPlayerIndex > 0) return;
        handleTurn();
    }
    dom.rollDiceBtn.addEventListener('click', onUserRollAttempt);
    dom.diceDisplay.addEventListener('click', onUserRollAttempt);

    // Keyboard support
    window.addEventListener('keydown', (e) => {
        if (e.code === 'Space' || e.key === 'Enter') {
            e.preventDefault();
            if (!dom.winPopup.classList.contains('hidden')) {
                startNewMatch();
            } else if (!dom.mainMenu.classList.contains('hidden')) {
                startNewMatch();
            } else if (!dom.gameContainer.classList.contains('hidden')) {
                onUserRollAttempt();
            }
        } else if (e.key === 'Escape') {
            if (!dom.settingsModal.classList.contains('hidden')) {
                dom.settingsModal.classList.add('hidden');
            } else if (!dom.gameContainer.classList.contains('hidden')) {
                showMainMenu();
            }
        }
    });

    // Gamepad controller integration
    if (window.ArcadeGamepadController) {
        new ArcadeGamepadController({
            onActionDown: (action) => {
                if (action === 'a' || action === 'start') {
                    if (!dom.winPopup.classList.contains('hidden')) {
                        startNewMatch();
                    } else if (!dom.mainMenu.classList.contains('hidden')) {
                        startNewMatch();
                    } else if (!dom.gameContainer.classList.contains('hidden')) {
                        onUserRollAttempt();
                    }
                } else if (action === 'b' || action === 'select') {
                    if (!dom.settingsModal.classList.contains('hidden')) {
                        dom.settingsModal.classList.add('hidden');
                    } else if (!dom.gameContainer.classList.contains('hidden')) {
                        showMainMenu();
                    }
                }
            }
        });
    }

    // Window resize handler
    window.addEventListener('resize', () => {
        if (state.confettiAnimationId) {
            dom.confettiCanvas.width = window.innerWidth;
            dom.confettiCanvas.height = window.innerHeight;
        }
    });
});
