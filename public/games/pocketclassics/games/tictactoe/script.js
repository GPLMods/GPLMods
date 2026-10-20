/**
 * Tic-Tac-Toe Deluxe - Pocket Classics
 * Full Mobile/Tablet/PC, Gamepad, Touch, Keyboard, Dual-Track Music & Sound
 */
document.addEventListener('DOMContentLoaded', () => {
    // --- AUDIO CONTROLLER ---
    const audioCtrl = (typeof ArcadeAudioController !== 'undefined')
        ? new ArcadeAudioController({
            menuAudioId: 'music-menu',
            gameAudioId: 'music-game',
            storagePrefix: 'pc_tictactoe_'
        })
        : (window.ArcadeHelper && window.ArcadeHelper.audio ? window.ArcadeHelper.audio : {
            musicEnabled: true, sfxEnabled: true,
            playMenuMusic: () => {}, playGameMusic: () => {}, pauseAll: () => {},
            toggleMusic: () => {}, toggleSfx: () => {}, playSfx: () => {}
        });

    const sfx = {
        click: document.getElementById('sound-click'),
        win: document.getElementById('sound-win'),
        draw: document.getElementById('sound-draw')
    };

    function playSfx(sound) {
        if (!sound || !audioCtrl.sfxEnabled) return;
        try {
            sound.currentTime = 0;
            const p = sound.play();
            if (p && p.catch) p.catch(() => {});
        } catch (e) {}
    }

    // --- DOM REFERENCES ---
    const dom = {
        mainMenu: document.getElementById('main-menu'),
        settingsScreen: document.getElementById('settings-screen'),
        gameContainer: document.getElementById('game-container'),
        winPopup: document.getElementById('win-popup'),
        boardContainer: document.getElementById('board-container'),
        board: document.getElementById('board'),
        cells: Array.from(document.querySelectorAll('.cell')),
        statusDisplay: document.getElementById('status-display'),
        winMessage: document.getElementById('win-message'),
        winSubtext: document.getElementById('win-subtext'),
        winBadgeIcon: document.getElementById('win-badge-icon'),
        lineCanvas: document.getElementById('line-canvas'),
        particleCanvas: document.getElementById('particle-canvas'),
        scoreX: document.getElementById('score-x'),
        scoreO: document.getElementById('score-o'),
        scoreTies: document.getElementById('score-ties'),
        vsPlayerBtn: document.getElementById('vs-player-btn'),
        vsAiBtn: document.getElementById('vs-ai-btn'),
        settingsBtn: document.getElementById('settings-btn'),
        backToMenuBtn: document.getElementById('back-to-menu-btn'),
        mainMenuBtn: document.getElementById('main-menu-btn'),
        restartBtn: document.getElementById('restart-btn'),
        playAgainBtn: document.getElementById('play-again-btn'),
        modalMenuBtn: document.getElementById('modal-menu-btn'),
        aiDifficultyBox: document.getElementById('ai-difficulty-selection'),
        startAiMatchBtn: document.getElementById('start-ai-match-btn'),
        difficultyBtns: Array.from(document.querySelectorAll('.difficulty-btn')),
        musicToggle: document.getElementById('music-toggle'),
        sfxToggle: document.getElementById('sfx-toggle')
    };

    const lineCtx = dom.lineCanvas.getContext('2d');
    const particleCtx = dom.particleCanvas.getContext('2d');

    // --- GAME STATE ---
    let gameMode = 'pvp'; // 'pvp' or 'ai'
    let aiDifficulty = 'medium'; // 'easy', 'medium', 'hard'
    let currentPlayer = 'X';
    let boardState = Array(9).fill(null);
    let gameActive = false;
    let focusedCellIndex = 4; // Center cell highlighted by default for gamepad/keyboard
    let scores = { X: 0, O: 0, ties: 0 };
    let particleAnimationId = null;

    // Multiplayer bridge support
    let isMultiplayer = false;
    let mySymbol = 'X';
    let isMyTurn = true;

    const winningCombinations = [
        [0, 1, 2], [3, 4, 5], [6, 7, 8], // Rows
        [0, 3, 6], [1, 4, 7], [2, 5, 8], // Columns
        [0, 4, 8], [2, 4, 6]             // Diagonals
    ];

    // --- AUDIO SETTINGS INIT ---
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

    // Play menu music on launch
    audioCtrl.playMenuMusic();

    // --- SCREEN NAVIGATION ---
    function showMainMenu() {
        playSfx(sfx.click);
        stopParticles();
        dom.gameContainer.classList.add('hidden');
        dom.winPopup.classList.add('hidden');
        dom.settingsScreen.classList.add('hidden');
        dom.aiDifficultyBox.classList.add('hidden');
        dom.mainMenu.classList.remove('hidden');
        audioCtrl.playMenuMusic();
    }

    function showSettings() {
        playSfx(sfx.click);
        dom.settingsScreen.classList.remove('hidden');
    }

    function closeSettings() {
        playSfx(sfx.click);
        dom.settingsScreen.classList.add('hidden');
    }

    function startMatch() {
        playSfx(sfx.click);
        stopParticles();
        dom.mainMenu.classList.add('hidden');
        dom.winPopup.classList.add('hidden');
        dom.settingsScreen.classList.add('hidden');
        dom.gameContainer.classList.remove('hidden');

        audioCtrl.playGameMusic();
        resetRound();
    }

    function resetRound() {
        gameActive = true;
        currentPlayer = 'X';
        boardState.fill(null);
        dom.cells.forEach(c => {
            c.innerHTML = '';
            c.classList.remove('x', 'o', 'focused', 'winning-cell');
        });

        clearWinningLine();
        updateFocusedCell(4);
        updateStatus();
    }

    function updateStatus() {
        if (isMultiplayer) {
            dom.statusDisplay.innerHTML = isMyTurn 
                ? `<span class="turn-symbol ${mySymbol === 'X' ? 'x-sym' : 'o-sym'}">${mySymbol}</span>'s Turn (You)`
                : `Opponent's Turn...`;
        } else if (gameMode === 'ai' && currentPlayer === 'O') {
            dom.statusDisplay.innerHTML = `<span class="turn-symbol o-sym">O</span> AI Thinking...`;
        } else {
            const symClass = currentPlayer === 'X' ? 'x-sym' : 'o-sym';
            dom.statusDisplay.innerHTML = `<span class="turn-symbol ${symClass}">${currentPlayer}</span>'s Turn`;
        }
    }

    function updateScoreDisplay() {
        dom.scoreX.textContent = scores.X;
        dom.scoreO.textContent = scores.O;
        dom.scoreTies.textContent = scores.ties;

        const cardX = document.querySelector('.score-card.player-x');
        const cardO = document.querySelector('.score-card.player-o');
        if (cardX && cardO) {
            cardX.classList.toggle('leading', scores.X > scores.O);
            cardO.classList.toggle('leading', scores.O > scores.X);
        }
    }

    // --- GAMEPAD & KEYBOARD FOCUS CURSOR ---
    function updateFocusedCell(newIndex) {
        if (newIndex < 0 || newIndex > 8) return;
        dom.cells.forEach(c => c.classList.remove('focused'));
        focusedCellIndex = newIndex;
        if (dom.cells[focusedCellIndex]) {
            dom.cells[focusedCellIndex].classList.add('focused');
        }
    }

    function moveFocus(dx, dy) {
        let row = Math.floor(focusedCellIndex / 3);
        let col = focusedCellIndex % 3;

        row = Math.max(0, Math.min(2, row + dy));
        col = Math.max(0, Math.min(2, col + dx));

        updateFocusedCell(row * 3 + col);
    }

    // --- MOVE EXECUTION WITH ANIMATED SVG MARKS ---
    function makeMove(index, symbol) {
        boardState[index] = symbol;
        const cell = dom.cells[index];
        cell.classList.remove('x', 'o');
        cell.classList.add(symbol.toLowerCase());

        if (symbol === 'X') {
            cell.innerHTML = `
                <svg class="ttt-mark-svg mark-x" viewBox="0 0 100 100">
                    <line x1="22" y1="22" x2="78" y2="78" stroke="var(--x-color)" stroke-width="12" stroke-linecap="round" class="draw-line-1" />
                    <line x1="78" y1="22" x2="22" y2="78" stroke="var(--x-color)" stroke-width="12" stroke-linecap="round" class="draw-line-2" />
                </svg>
            `;
        } else {
            cell.innerHTML = `
                <svg class="ttt-mark-svg mark-o" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="30" stroke="var(--o-color)" stroke-width="12" fill="none" stroke-linecap="round" class="draw-circle" />
                </svg>
            `;
        }

        playSfx(sfx.click);
        if (window.ArcadeHelper) window.ArcadeHelper.vibrate(25);
    }

    function handleCellClick(index) {
        if (!gameActive || boardState[index] !== null) return;

        // Multiplayer move
        if (isMultiplayer) {
            if (!isMyTurn) return;
            makeMove(index, mySymbol);
            isMyTurn = false;
            updateStatus();

            if (window.parent && window.parent !== window) {
                window.parent.postMessage({
                    type: 'ARCADE_GAME_MOVE',
                    move: { cellIndex: index }
                }, '*');
            }
            checkGameOutcome();
            return;
        }

        // Single / Pass-and-Play move
        makeMove(index, currentPlayer);

        if (!checkGameOutcome()) {
            currentPlayer = currentPlayer === 'X' ? 'O' : 'X';
            updateStatus();

            if (gameMode === 'ai' && currentPlayer === 'O' && gameActive) {
                setTimeout(handleAiTurn, 350);
            }
        }
    }

    // --- AI RIVAL LOGIC ---
    function handleAiTurn() {
        if (!gameActive || currentPlayer !== 'O') return;

        let moveIndex;
        if (aiDifficulty === 'easy') {
            const available = boardState.map((val, idx) => val === null ? idx : null).filter(val => val !== null);
            moveIndex = available[Math.floor(Math.random() * available.length)];
        } else if (aiDifficulty === 'medium') {
            moveIndex = findAdeptMove();
        } else {
            moveIndex = minimax(boardState, 'O').index;
        }

        if (moveIndex !== undefined && boardState[moveIndex] === null) {
            makeMove(moveIndex, 'O');
            if (!checkGameOutcome()) {
                currentPlayer = 'X';
                updateStatus();
            }
        }
    }

    function findAdeptMove() {
        // 1. Can AI win immediately?
        for (let i = 0; i < 9; i++) {
            if (boardState[i] === null) {
                boardState[i] = 'O';
                if (checkWin(boardState)?.winner === 'O') {
                    boardState[i] = null;
                    return i;
                }
                boardState[i] = null;
            }
        }
        // 2. Must AI block opponent?
        for (let i = 0; i < 9; i++) {
            if (boardState[i] === null) {
                boardState[i] = 'X';
                if (checkWin(boardState)?.winner === 'X') {
                    boardState[i] = null;
                    return i;
                }
                boardState[i] = null;
            }
        }
        // 3. Take center if open
        if (boardState[4] === null) return 4;

        // 4. Random available
        const available = boardState.map((val, idx) => val === null ? idx : null).filter(val => val !== null);
        return available[Math.floor(Math.random() * available.length)];
    }

    function minimax(currBoard, player) {
        const avail = currBoard.map((val, idx) => val === null ? idx : null).filter(val => val !== null);
        const win = checkWin(currBoard);

        if (win && win.winner === 'X') return { score: -10 };
        if (win && win.winner === 'O') return { score: 10 };
        if (avail.length === 0) return { score: 0 };

        const moves = [];
        for (let i = 0; i < avail.length; i++) {
            const move = { index: avail[i] };
            currBoard[avail[i]] = player;

            const result = minimax(currBoard, player === 'O' ? 'X' : 'O');
            move.score = result.score;
            currBoard[avail[i]] = null;
            moves.push(move);
        }

        let bestMoveIdx = 0;
        if (player === 'O') {
            let bestScore = -Infinity;
            for (let i = 0; i < moves.length; i++) {
                if (moves[i].score > bestScore) {
                    bestScore = moves[i].score;
                    bestMoveIdx = i;
                }
            }
        } else {
            let bestScore = Infinity;
            for (let i = 0; i < moves.length; i++) {
                if (moves[i].score < bestScore) {
                    bestScore = moves[i].score;
                    bestMoveIdx = i;
                }
            }
        }

        return moves[bestMoveIdx];
    }

    function checkWin(board = boardState) {
        for (let i = 0; i < winningCombinations.length; i++) {
            const [a, b, c] = winningCombinations[i];
            if (board[a] && board[a] === board[b] && board[a] === board[c]) {
                return { winner: board[a], combination: winningCombinations[i] };
            }
        }
        return null;
    }

    // --- OUTCOME & CELEBRATION ---
    function checkGameOutcome() {
        const win = checkWin();
        if (win) {
            endRound(false, win);
            return true;
        }

        if (boardState.every(c => c !== null)) {
            endRound(true, null);
            return true;
        }

        return false;
    }

    function endRound(isDraw, winData) {
        gameActive = false;
        audioCtrl.playMenuMusic();

        let resultType = 'draw';

        if (isDraw) {
            scores.ties++;
            playSfx(sfx.draw);
            dom.winBadgeIcon.innerHTML = '<i class="fas fa-handshake"></i>';
            dom.winBadgeIcon.style.color = '#94a3b8';
            dom.winBadgeIcon.style.borderColor = '#94a3b8';
            dom.winMessage.textContent = "It's a Draw!";
            dom.winSubtext.textContent = "Evenly matched battle of wits!";
            resultType = 'draw';
        } else {
            const winner = winData.winner;
            scores[winner]++;
            playSfx(sfx.win);

            drawWinningStrike(winData.combination);
            startParticles();

            const isPlayerWinner = isMultiplayer 
                ? (winner === mySymbol)
                : (gameMode === 'ai' ? winner === 'X' : true);

            dom.winBadgeIcon.innerHTML = isPlayerWinner 
                ? '<i class="fas fa-trophy"></i>' 
                : '<i class="fas fa-robot"></i>';
            const color = winner === 'X' ? 'var(--x-color)' : 'var(--o-color)';
            dom.winBadgeIcon.style.color = color;
            dom.winBadgeIcon.style.borderColor = color;

            dom.winMessage.textContent = `${winner} Wins!`;
            dom.winSubtext.textContent = "Three aligned in victorious harmony!";

            resultType = isMultiplayer 
                ? (winner === mySymbol ? 'win' : 'loss')
                : (gameMode === 'ai' ? (winner === 'X' ? 'win' : 'loss') : 'win');
        }

        updateScoreDisplay();

        setTimeout(() => {
            dom.winPopup.classList.remove('hidden');
        }, 550);

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: resultType,
                score: resultType === 'win' ? 100 : (resultType === 'draw' ? 30 : 0)
            }, '*');
        }
    }

    // --- ANIMATED WINNING STRIKE LINE ---
    function drawWinningStrike(combination) {
        resizeCanvases();
        const rectBoard = dom.boardContainer.getBoundingClientRect();
        const startCellRect = dom.cells[combination[0]].getBoundingClientRect();
        const endCellRect = dom.cells[combination[2]].getBoundingClientRect();

        const x1 = (startCellRect.left + startCellRect.right) / 2 - rectBoard.left;
        const y1 = (startCellRect.top + startCellRect.bottom) / 2 - rectBoard.top;
        const x2 = (endCellRect.left + endCellRect.right) / 2 - rectBoard.left;
        const y2 = (endCellRect.top + endCellRect.bottom) / 2 - rectBoard.top;

        // Highlight the 3 winning tiles
        combination.forEach(idx => {
            if (dom.cells[idx]) dom.cells[idx].classList.add('winning-cell');
        });

        // Progressive beam animation
        const duration = 240;
        const startTime = performance.now();
        const color = currentPlayer === 'X' ? '#00f0ff' : '#ffd700';

        function step(now) {
            const elapsed = now - startTime;
            const progress = Math.min(1, elapsed / duration);

            const curX = x1 + (x2 - x1) * progress;
            const curY = y1 + (y2 - y1) * progress;

            lineCtx.clearRect(0, 0, dom.lineCanvas.width, dom.lineCanvas.height);
            lineCtx.strokeStyle = color;
            lineCtx.lineWidth = 10;
            lineCtx.lineCap = 'round';
            lineCtx.shadowColor = color;
            lineCtx.shadowBlur = 20;

            lineCtx.beginPath();
            lineCtx.moveTo(x1, y1);
            lineCtx.lineTo(curX, curY);
            lineCtx.stroke();

            if (progress < 1) {
                requestAnimationFrame(step);
            }
        }
        requestAnimationFrame(step);
    }

    function clearWinningLine() {
        lineCtx.clearRect(0, 0, dom.lineCanvas.width, dom.lineCanvas.height);
    }

    function resizeCanvases() {
        const rect = dom.boardContainer.getBoundingClientRect();
        dom.lineCanvas.width = rect.width;
        dom.lineCanvas.height = rect.height;
        dom.particleCanvas.width = window.innerWidth;
        dom.particleCanvas.height = window.innerHeight;
    }

    // --- PARTICLE CONFLICT EFFECT ---
    let particles = [];
    function startParticles() {
        resizeCanvases();
        particles = [];
        const colors = ['#00f0ff', '#ffd700', '#ff007f', '#ffffff'];
        for (let i = 0; i < 90; i++) {
            particles.push({
                x: dom.particleCanvas.width / 2,
                y: dom.particleCanvas.height / 2,
                vx: (Math.random() - 0.5) * 12,
                vy: (Math.random() - 0.5) * 12,
                radius: Math.random() * 4 + 2,
                color: colors[Math.floor(Math.random() * colors.length)],
                life: 100
            });
        }
        animateParticles();
    }

    function animateParticles() {
        particleCtx.clearRect(0, 0, dom.particleCanvas.width, dom.particleCanvas.height);
        particles.forEach((p, idx) => {
            p.x += p.vx;
            p.y += p.vy;
            p.life -= 1.4;
            if (p.life <= 0) particles.splice(idx, 1);

            particleCtx.beginPath();
            particleCtx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            particleCtx.fillStyle = p.color;
            particleCtx.globalAlpha = Math.max(0, p.life / 100);
            particleCtx.fill();
        });
        particleCtx.globalAlpha = 1;

        if (particles.length > 0) {
            particleAnimationId = requestAnimationFrame(animateParticles);
        } else {
            particleCtx.clearRect(0, 0, dom.particleCanvas.width, dom.particleCanvas.height);
            particleAnimationId = null;
        }
    }

    function stopParticles() {
        if (particleAnimationId) cancelAnimationFrame(particleAnimationId);
        particleAnimationId = null;
        particleCtx.clearRect(0, 0, dom.particleCanvas.width, dom.particleCanvas.height);
    }

    // --- LISTENERS & CONTROLLER BINDINGS ---
    // Cell clicks
    dom.cells.forEach((cell, idx) => {
        cell.addEventListener('click', () => {
            updateFocusedCell(idx);
            handleCellClick(idx);
        });
    });

    // Main menu buttons
    dom.vsPlayerBtn.addEventListener('click', () => {
        gameMode = 'pvp';
        startMatch();
    });

    dom.vsAiBtn.addEventListener('click', () => {
        playSfx(sfx.click);
        dom.aiDifficultyBox.classList.toggle('hidden');
    });

    dom.startAiMatchBtn.addEventListener('click', () => {
        gameMode = 'ai';
        startMatch();
    });

    dom.difficultyBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            playSfx(sfx.click);
            dom.difficultyBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            aiDifficulty = btn.dataset.difficulty;
        });
    });

    dom.settingsBtn.addEventListener('click', showSettings);
    dom.backToMenuBtn.addEventListener('click', closeSettings);
    dom.settingsScreen.addEventListener('click', (e) => {
        if (e.target === dom.settingsScreen) closeSettings();
    });

    dom.mainMenuBtn.addEventListener('click', showMainMenu);
    dom.modalMenuBtn.addEventListener('click', showMainMenu);
    dom.restartBtn.addEventListener('click', () => {
        playSfx(sfx.click);
        resetRound();
    });
    dom.playAgainBtn.addEventListener('click', () => {
        playSfx(sfx.click);
        dom.winPopup.classList.add('hidden');
        resetRound();
    });

    // --- KEYBOARD CONTROLS ---
    window.addEventListener('keydown', (e) => {
        // Numpad & number keys direct placement
        const numKeyMap = {
            'Numpad7': 0, 'Numpad8': 1, 'Numpad9': 2,
            'Numpad4': 3, 'Numpad5': 4, 'Numpad6': 5,
            'Numpad1': 6, 'Numpad2': 7, 'Numpad3': 8,
            'Digit1': 0, 'Digit2': 1, 'Digit3': 2,
            'Digit4': 3, 'Digit5': 4, 'Digit6': 5,
            'Digit7': 6, 'Digit8': 7, 'Digit9': 8
        };

        if (numKeyMap[e.code] !== undefined && !dom.gameContainer.classList.contains('hidden') && gameActive) {
            e.preventDefault();
            const targetIdx = numKeyMap[e.code];
            updateFocusedCell(targetIdx);
            handleCellClick(targetIdx);
            return;
        }

        // Arrow navigation
        if (['ArrowUp', 'KeyW'].includes(e.code)) {
            e.preventDefault();
            moveFocus(0, -1);
        } else if (['ArrowDown', 'KeyS'].includes(e.code)) {
            e.preventDefault();
            moveFocus(0, 1);
        } else if (['ArrowLeft', 'KeyA'].includes(e.code)) {
            e.preventDefault();
            moveFocus(-1, 0);
        } else if (['ArrowRight', 'KeyD'].includes(e.code)) {
            e.preventDefault();
            moveFocus(1, 0);
        } else if (e.code === 'Space' || e.key === 'Enter') {
            e.preventDefault();
            if (!dom.winPopup.classList.contains('hidden')) {
                dom.playAgainBtn.click();
            } else if (!dom.mainMenu.classList.contains('hidden')) {
                dom.vsPlayerBtn.click();
            } else if (!dom.gameContainer.classList.contains('hidden') && gameActive) {
                handleCellClick(focusedCellIndex);
            }
        } else if (e.key === 'Escape') {
            if (!dom.settingsScreen.classList.contains('hidden')) {
                closeSettings();
            } else if (!dom.gameContainer.classList.contains('hidden')) {
                showMainMenu();
            }
        }
    });

    // --- GAMEPAD CONTROLLER INTEGRATION ---
    if (window.ArcadeGamepadController) {
        new ArcadeGamepadController({
            onDirectionDown: (dir) => {
                if (dom.gameContainer.classList.contains('hidden') || !gameActive) return;
                if (dir === 'up') moveFocus(0, -1);
                else if (dir === 'down') moveFocus(0, 1);
                else if (dir === 'left') moveFocus(-1, 0);
                else if (dir === 'right') moveFocus(1, 0);
            },
            onActionDown: (action) => {
                if (action === 'a') {
                    if (!dom.winPopup.classList.contains('hidden')) {
                        dom.playAgainBtn.click();
                    } else if (!dom.mainMenu.classList.contains('hidden')) {
                        dom.vsPlayerBtn.click();
                    } else if (!dom.gameContainer.classList.contains('hidden') && gameActive) {
                        handleCellClick(focusedCellIndex);
                    }
                } else if (action === 'b' || action === 'select') {
                    if (!dom.settingsScreen.classList.contains('hidden')) {
                        closeSettings();
                    } else if (!dom.gameContainer.classList.contains('hidden')) {
                        showMainMenu();
                    }
                } else if (action === 'start') {
                    if (!dom.gameContainer.classList.contains('hidden')) {
                        resetRound();
                    } else {
                        dom.vsPlayerBtn.click();
                    }
                }
            }
        });
    }

    // Multiplayer parent message listener
    window.addEventListener('message', (event) => {
        if (!event.data || !event.data.type) return;

        if (event.data.type === 'ARCADE_MATCH_READY') {
            isMultiplayer = true;
            gameMode = 'pvp';
            mySymbol = event.data.isHost ? 'X' : 'O';
            isMyTurn = mySymbol === 'X';
            startMatch();
        } else if (event.data.type === 'ARCADE_OPPONENT_MOVE') {
            const cellIdx = event.data.move && event.data.move.cellIndex;
            if (cellIdx !== undefined && boardState[cellIdx] === null) {
                const oppSymbol = mySymbol === 'X' ? 'O' : 'X';
                makeMove(cellIdx, oppSymbol);
                if (!checkGameOutcome()) {
                    isMyTurn = true;
                    updateStatus();
                }
            }
        }
    });

    window.addEventListener('resize', resizeCanvases);
    resizeCanvases();
});
