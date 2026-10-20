document.addEventListener('DOMContentLoaded', () => {
    // --- Universal Arcade Helper ---
    const helper = window.ArcadeHelper ? window.ArcadeHelper.init({
        menuMusic: 'sounds/menu-music.mp3',
        gameMusic: 'sounds/music.mp3'
    }) : null;

    // --- DOM Elements ---
    const mainMenu = document.getElementById('main-menu');
    const aiDifficultyMenu = document.getElementById('ai-difficulty-menu');
    const gameScreen = document.getElementById('game-screen');
    const settingsMenu = document.getElementById('settings-menu');
    const winPopup = document.getElementById('win-popup-overlay');

    const pvpBtn = document.getElementById('pvp-btn');
    const pvaiBtn = document.getElementById('pvai-btn');
    const settingsBtn = document.getElementById('settings-btn');
    const backToMainBtn = document.getElementById('back-to-main-btn');
    const closeSettingsBtn = document.getElementById('close-settings-btn');
    const backToMenuGameBtn = document.getElementById('back-to-menu-game-btn');
    const restartGameBtn = document.getElementById('restart-game-btn');
    const playAgainBtn = document.getElementById('play-again-btn');
    const winBackToMenuBtn = document.getElementById('win-back-to-menu-btn');

    const boardContainer = document.getElementById('board-container');
    const blackScoreEl = document.getElementById('black-score');
    const whiteScoreEl = document.getElementById('white-score');
    const playerTurnEl = document.getElementById('player-turn');
    const statusMessageEl = document.getElementById('status-message');
    const winResultEl = document.getElementById('win-result');
    const winScoreEl = document.getElementById('win-score');

    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');

    // --- Sounds ---
    const clickSound = document.getElementById('sfx-sound');
    const winSound = document.getElementById('win-sound');
    const uiClickSound = document.getElementById('ui-click-sound');

    function playSound(snd) {
        if (helper) helper.audio.playSfx(snd);
        else if (snd) { snd.currentTime = 0; snd.play().catch(() => {}); }
    }
    function playClick() { playSound(uiClickSound); }

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

    // --- Match Session Scoreboard Comparison (Requirement: player 1 (4) and player 2 (5)) ---
    let sessBlack = parseInt(localStorage.getItem('arc_othello_black') || '0', 10);
    let sessDraw = parseInt(localStorage.getItem('arc_othello_draw') || '0', 10);
    let sessWhite = parseInt(localStorage.getItem('arc_othello_white') || '0', 10);

    function updateOthelloScoreboard() {
        const bEl = document.getElementById('sessBlackWins');
        const dEl = document.getElementById('sessDraws');
        const wEl = document.getElementById('sessWhiteWins');
        const pillB = document.getElementById('pillBlack');
        const pillW = document.getElementById('pillWhite');
        if (bEl) bEl.textContent = sessBlack;
        if (dEl) dEl.textContent = sessDraw;
        if (wEl) wEl.textContent = sessWhite;
        if (pillB && pillW) {
            pillB.classList.toggle('leading', sessBlack > sessWhite);
            pillW.classList.toggle('leading', sessWhite > sessBlack);
        }
    }
    updateOthelloScoreboard();

    function launchWinParticles() {
        const canvas = document.getElementById('win-particles-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const colors = ['#10b981', '#38bdf8', '#ffd700', '#f8fafc', '#a855f7'];
        const particles = Array.from({ length: 90 }, () => ({
            x: canvas.width / 2,
            y: canvas.height * 0.45,
            vx: (Math.random() - 0.5) * 12,
            vy: (Math.random() - 0.7) * 14,
            size: Math.random() * 8 + 4,
            color: colors[Math.floor(Math.random() * colors.length)],
            rotation: Math.random() * 360,
            vr: (Math.random() - 0.5) * 10,
            alpha: 1
        }));
        function frame() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            let active = false;
            particles.forEach(p => {
                p.x += p.vx;
                p.y += p.vy;
                p.vy += 0.25;
                p.rotation += p.vr;
                p.alpha -= 0.012;
                if (p.alpha > 0) {
                    active = true;
                    ctx.save();
                    ctx.globalAlpha = Math.max(0, p.alpha);
                    ctx.translate(p.x, p.y);
                    ctx.rotate((p.rotation * Math.PI) / 180);
                    ctx.fillStyle = p.color;
                    ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size);
                    ctx.restore();
                }
            });
            if (active) requestAnimationFrame(frame);
            else ctx.clearRect(0, 0, canvas.width, canvas.height);
        }
        requestAnimationFrame(frame);
    }

    // --- Game State ---
    const BOARD_SIZE = 8;
    const EMPTY = 0, BLACK = 1, WHITE = 2;
    let board = [];
    let currentPlayer = BLACK; // Black goes first in Othello
    let gameMode = 'pvp'; // 'pvp' | 'pvai'
    let difficulty = 'medium';
    let isGameOver = false;
    let cursor = { r: 3, c: 2 };

    // --- Navigation ---
    pvpBtn?.addEventListener('click', () => {
        playClick();
        gameMode = 'pvp';
        startGame();
    });

    pvaiBtn?.addEventListener('click', () => {
        playClick();
        gameMode = 'pvai';
        mainMenu.classList.add('hidden');
        aiDifficultyMenu.classList.remove('hidden');
    });

    backToMainBtn?.addEventListener('click', () => {
        playClick();
        aiDifficultyMenu.classList.add('hidden');
        mainMenu.classList.remove('hidden');
    });

    document.querySelectorAll('.difficulty-options .diff-card').forEach(btn => {
        btn.addEventListener('click', () => {
            playClick();
            difficulty = btn.dataset.difficulty;
            startGame();
        });
    });

    settingsBtn?.addEventListener('click', () => {
        playClick();
        settingsMenu.classList.remove('hidden');
    });

    closeSettingsBtn?.addEventListener('click', () => {
        playClick();
        settingsMenu.classList.add('hidden');
    });

    function returnToMenu() {
        playClick();
        gameScreen.classList.add('hidden');
        aiDifficultyMenu.classList.add('hidden');
        winPopup.classList.add('hidden');
        mainMenu.classList.remove('hidden');
        if (helper) helper.audio.playMenuMusic();
    }

    backToMenuGameBtn?.addEventListener('click', returnToMenu);
    winBackToMenuBtn?.addEventListener('click', returnToMenu);

    restartGameBtn?.addEventListener('click', () => {
        playClick();
        startGame();
    });

    playAgainBtn?.addEventListener('click', () => {
        playClick();
        winPopup.classList.add('hidden');
        startGame();
    });

    // --- Game Logic ---
    function startGame() {
        mainMenu.classList.add('hidden');
        aiDifficultyMenu.classList.add('hidden');
        winPopup.classList.add('hidden');
        gameScreen.classList.remove('hidden');

        if (helper) helper.audio.playGameMusic();

        board = Array.from({ length: BOARD_SIZE }, () => Array(BOARD_SIZE).fill(EMPTY));
        // Center initial 4 discs
        board[3][3] = WHITE;
        board[3][4] = BLACK;
        board[4][3] = BLACK;
        board[4][4] = WHITE;

        currentPlayer = BLACK;
        isGameOver = false;
        cursor = { r: 3, c: 2 };

        renderBoard();
        updateScores();
        updateTurnDisplay();
    }

    const DIRS = [
        [-1, -1], [-1, 0], [-1, 1],
        [0, -1],           [0, 1],
        [1, -1],  [1, 0],  [1, 1]
    ];

    function getFlippableDiscs(r, c, player) {
        if (board[r][c] !== EMPTY) return [];
        const opponent = player === BLACK ? WHITE : BLACK;
        const flippable = [];

        for (const [dr, dc] of DIRS) {
            const path = [];
            let nr = r + dr, nc = c + dc;

            while (nr >= 0 && nr < BOARD_SIZE && nc >= 0 && nc < BOARD_SIZE && board[nr][nc] === opponent) {
                path.push({ r: nr, c: nc });
                nr += dr;
                nc += dc;
            }

            if (path.length > 0 && nr >= 0 && nr < BOARD_SIZE && nc >= 0 && nc < BOARD_SIZE && board[nr][nc] === player) {
                flippable.push(...path);
            }
        }

        return flippable;
    }

    function getValidMoves(player) {
        const moves = [];
        for (let r = 0; r < BOARD_SIZE; r++) {
            for (let c = 0; c < BOARD_SIZE; c++) {
                const flips = getFlippableDiscs(r, c, player);
                if (flips.length > 0) {
                    moves.push({ r, c, flips });
                }
            }
        }
        return moves;
    }

    function renderBoard() {
        boardContainer.innerHTML = '';
        const validMoves = getValidMoves(currentPlayer);

        for (let r = 0; r < BOARD_SIZE; r++) {
            for (let c = 0; c < BOARD_SIZE; c++) {
                const cell = document.createElement('div');
                cell.classList.add('cell');
                cell.dataset.row = r;
                cell.dataset.col = c;

                if (cursor.r === r && cursor.c === c) {
                    cell.classList.add('gamepad-cursor');
                }

                if (board[r][c] !== EMPTY) {
                    const piece = document.createElement('div');
                    piece.classList.add('piece', board[r][c] === BLACK ? 'black' : 'white');
                    cell.appendChild(piece);
                } else {
                    const move = validMoves.find(m => m.r === r && m.c === c);
                    if (move && (!gameMode === 'pvai' || currentPlayer === BLACK)) {
                        const dot = document.createElement('div');
                        dot.classList.add('valid-move-dot');
                        cell.appendChild(dot);
                    }
                }

                cell.addEventListener('click', () => onCellClick(r, c));
                boardContainer.appendChild(cell);
            }
        }
    }

    function updateScores() {
        let black = 0, white = 0;
        for (let r = 0; r < BOARD_SIZE; r++) {
            for (let c = 0; c < BOARD_SIZE; c++) {
                if (board[r][c] === BLACK) black++;
                else if (board[r][c] === WHITE) white++;
            }
        }
        if (blackScoreEl) blackScoreEl.textContent = black;
        if (whiteScoreEl) whiteScoreEl.textContent = white;
        return { black, white };
    }

    function updateTurnDisplay() {
        const isB = currentPlayer === BLACK;
        playerTurnEl.textContent = isB ? "Black's Turn" : (gameMode === 'pvai' ? "AI Thinking..." : "White's Turn");
        playerTurnEl.style.color = isB ? '#f8fafc' : '#ffd700';
    }

    function onCellClick(r, c) {
        if (isGameOver) return;
        if (gameMode === 'pvai' && currentPlayer === WHITE) return;

        cursor = { r, c };
        const flips = getFlippableDiscs(r, c, currentPlayer);
        if (flips.length === 0) return;

        makeMove(r, c, flips);
    }

    function makeMove(r, c, flips) {
        board[r][c] = currentPlayer;
        playSound(clickSound);
        if (helper) helper.vibrate(18);

        // Flip discs with staggered 3D animation
        flips.forEach((pos, idx) => {
            setTimeout(() => {
                board[pos.r][pos.c] = currentPlayer;
                const cell = document.querySelector(`.cell[data-row="${pos.r}"][data-col="${pos.c}"]`);
                const piece = cell?.querySelector('.piece');
                if (piece) {
                    piece.classList.add('flipping');
                    setTimeout(() => {
                        piece.className = `piece ${currentPlayer === BLACK ? 'black' : 'white'}`;
                        piece.classList.remove('flipping');
                    }, 150);
                }
            }, idx * 40);
        });

        setTimeout(() => {
            updateScores();
            switchTurn();
        }, (flips.length * 40) + 160);
    }

    function switchTurn() {
        const nextPlayer = currentPlayer === BLACK ? WHITE : BLACK;
        const nextMoves = getValidMoves(nextPlayer);

        if (nextMoves.length > 0) {
            currentPlayer = nextPlayer;
            renderBoard();
            updateTurnDisplay();
            if (statusMessageEl) statusMessageEl.textContent = "Select an illuminated circle to flip discs";

            if (gameMode === 'pvai' && currentPlayer === WHITE) {
                setTimeout(makeAiMove, 550);
            }
        } else {
            // Check if current player can move again (pass turn)
            const currentMoves = getValidMoves(currentPlayer);
            if (currentMoves.length > 0) {
                if (statusMessageEl) statusMessageEl.textContent = `${nextPlayer === BLACK ? 'Black' : 'White'} has no legal moves! Turn passed.`;
                if (helper) helper.vibrate(25);
                setTimeout(() => {
                    renderBoard();
                    updateTurnDisplay();
                    if (gameMode === 'pvai' && currentPlayer === WHITE) {
                        setTimeout(makeAiMove, 550);
                    }
                }, 1000);
            } else {
                // Game Over - neither can move
                endGame();
            }
        }
    }

    // --- AI Strategist ---
    function makeAiMove() {
        if (isGameOver) return;
        const moves = getValidMoves(WHITE);
        if (moves.length === 0) {
            switchTurn();
            return;
        }

        // Positional weight matrix for Othello corners and edges
        const CORNER_WEIGHTS = [
            [100, -20,  10,   5,   5,  10, -20, 100],
            [-20, -50,  -2,  -2,  -2,  -2, -50, -20],
            [ 10,  -2,  -1,  -1,  -1,  -1,  -2,  10],
            [  5,  -2,  -1,   0,   0,  -1,  -2,   5],
            [  5,  -2,  -1,   0,   0,  -1,  -2,   5],
            [ 10,  -2,  -1,  -1,  -1,  -1,  -2,  10],
            [-20, -50,  -2,  -2,  -2,  -2, -50, -20],
            [100, -20,  10,   5,   5,  10, -20, 100]
        ];

        let pick = moves[0];

        if (difficulty === 'easy') {
            pick = moves[Math.floor(Math.random() * moves.length)];
        } else if (difficulty === 'medium') {
            // Greedy: most flips
            moves.sort((a, b) => b.flips.length - a.flips.length);
            pick = moves[0];
        } else {
            // Hard: positional corner strategy
            moves.sort((a, b) => {
                const scoreA = CORNER_WEIGHTS[a.r][a.c] + a.flips.length;
                const scoreB = CORNER_WEIGHTS[b.r][b.c] + b.flips.length;
                return scoreB - scoreA;
            });
            pick = moves[0];
        }

        makeMove(pick.r, pick.c, pick.flips);
    }

    function endGame() {
        isGameOver = true;
        playSound(winSound);
        const { black, white } = updateScores();

        let msg = "It's a Draw!";
        if (black > white) {
            msg = gameMode === 'pvai' ? "You Win!" : "Black Wins!";
            sessBlack++;
            localStorage.setItem('arc_othello_black', sessBlack);
            launchWinParticles();
        } else if (white > black) {
            msg = gameMode === 'pvai' ? "AI Wins!" : "White Wins!";
            sessWhite++;
            localStorage.setItem('arc_othello_white', sessWhite);
            launchWinParticles();
        } else {
            sessDraw++;
            localStorage.setItem('arc_othello_draw', sessDraw);
        }
        updateOthelloScoreboard();

        winResultEl.textContent = msg;
        winScoreEl.textContent = `Black: ${black} • White: ${white}`;
        winPopup.classList.remove('hidden');

        if (helper) {
            helper.vibrate([40, 30, 80]);
            helper.audio.playMenuMusic();
        }

        if (window.parent && window.parent !== window) {
            const isPlayerWon = black > white;
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: isPlayerWon ? 'win' : 'loss',
                score: black * 10
            }, '*');
        }
    }

    // --- KEYBOARD & CONTROLLER NAVIGATION ---
    window.addEventListener('keydown', (e) => {
        if (gameScreen.classList.contains('hidden') || isGameOver) return;

        let moved = false;
        if (e.key === 'ArrowUp' || e.key === 'w' || e.key === 'W') {
            cursor.r = Math.max(0, cursor.r - 1); moved = true;
        } else if (e.key === 'ArrowDown' || e.key === 's' || e.key === 'S') {
            cursor.r = Math.min(BOARD_SIZE - 1, cursor.r + 1); moved = true;
        } else if (e.key === 'ArrowLeft' || e.key === 'a' || e.key === 'A') {
            cursor.c = Math.max(0, cursor.c - 1); moved = true;
        } else if (e.key === 'ArrowRight' || e.key === 'd' || e.key === 'D') {
            cursor.c = Math.min(BOARD_SIZE - 1, cursor.c + 1); moved = true;
        } else if (e.key === ' ' || e.key === 'Enter') {
            e.preventDefault();
            onCellClick(cursor.r, cursor.c);
        } else if (e.key === 'Escape') {
            backToMenuGameBtn?.click();
        }

        if (moved) {
            e.preventDefault();
            renderBoard();
        }
    });

    if (helper && helper.gamepad) {
        helper.gamepad.onDirection((dir) => {
            if (!gameScreen.classList.contains('hidden') && !isGameOver) {
                if (dir === 'up') cursor.r = Math.max(0, cursor.r - 1);
                else if (dir === 'down') cursor.r = Math.min(BOARD_SIZE - 1, cursor.r + 1);
                else if (dir === 'left') cursor.c = Math.max(0, cursor.c - 1);
                else if (dir === 'right') cursor.c = Math.min(BOARD_SIZE - 1, cursor.c + 1);
                renderBoard();
            }
        });

        helper.gamepad.onAction((act) => {
            if (!gameScreen.classList.contains('hidden')) {
                if (act === 'A') onCellClick(cursor.r, cursor.c);
                else if (act === 'START') backToMenuGameBtn?.click();
                else if (act === 'SELECT') restartGameBtn?.click();
            }
        });
    }
});
