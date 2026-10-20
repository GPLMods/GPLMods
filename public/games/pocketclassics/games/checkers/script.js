document.addEventListener('DOMContentLoaded', () => {
    // --- Universal Arcade Helper ---
    const helper = window.ArcadeHelper ? window.ArcadeHelper.init({
        menuMusic: 'sounds/menu-music.mp3',
        gameMusic: 'sounds/game-music.mp3'
    }) : null;

    // --- DOM Elements ---
    const boardElement = document.getElementById('board');
    const statusElement = document.getElementById('status');
    const whiteCountEl = document.getElementById('white-count');
    const redCountEl = document.getElementById('red-count');
    const hintText = document.getElementById('hint-text');

    const mainMenu = document.getElementById('main-menu');
    const gameContainer = document.getElementById('game-container');
    const playPlayerBtn = document.getElementById('play-player');
    const playAiBtn = document.getElementById('play-ai');
    const aiDifficultySelector = document.getElementById('ai-difficulty-selector');
    const aiLvlBtns = document.querySelectorAll('.ai-lvl-btn');
    const startAiGameBtn = document.getElementById('start-ai-game');
    const backToMenuBtn = document.getElementById('back-to-menu');
    const restartMatchBtn = document.getElementById('restart-match-btn');

    const settingsBtn = document.getElementById('settings-button');
    const settingsDialog = document.getElementById('settings-dialog');
    const closeSettingsBtn = document.getElementById('close-settings-button');
    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');

    // --- Sounds ---
    const sounds = {
        move: document.getElementById('sound-move'),
        capture: document.getElementById('sound-capture'),
        gameOver: document.getElementById('sound-game-over'),
        uiClick: document.getElementById('sound-ui-click'),
        gameStart: document.getElementById('sound-game-start'),
        select: document.getElementById('sound-select'),
        invalid: document.getElementById('sound-invalid')
    };

    function playSound(k) {
        if (helper) helper.audio.playSfx(sounds[k]);
        else if (sounds[k]) { sounds[k].currentTime = 0; sounds[k].play().catch(() => {}); }
    }
    function playClick() { playSound('uiClick'); }

    if (helper) helper.audio.playMenuMusic();

    // --- Match Session Scoreboard Comparison (Requirement: player 1 (4) and player 2 (5)) ---
    let sessWhite = parseInt(localStorage.getItem('arc_checkers_white') || '0', 10);
    let sessDraw = parseInt(localStorage.getItem('arc_checkers_draw') || '0', 10);
    let sessRed = parseInt(localStorage.getItem('arc_checkers_red') || '0', 10);

    function updateScoreboard() {
        const wEl = document.getElementById('scoreWhiteVal');
        const dEl = document.getElementById('scoreDrawVal');
        const rEl = document.getElementById('scoreRedVal');
        const pillW = document.getElementById('pillWhite');
        const pillR = document.getElementById('pillRed');
        if (wEl) wEl.textContent = sessWhite;
        if (dEl) dEl.textContent = sessDraw;
        if (rEl) rEl.textContent = sessRed;
        if (pillW && pillR) {
            pillW.classList.toggle('leading', sessWhite > sessRed);
            pillR.classList.toggle('leading', sessRed > sessWhite);
        }
    }
    updateScoreboard();

    function launchWinParticles() {
        const canvas = document.getElementById('win-particles-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const colors = ['#ffd700', '#f8fafc', '#ef4444', '#00f0ff', '#10b981'];
        const particles = Array.from({ length: 80 }, () => ({
            x: canvas.width / 2,
            y: canvas.height * 0.4,
            vx: (Math.random() - 0.5) * 12,
            vy: (Math.random() - 0.7) * 13,
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

    // --- Game State ---
    let board = [];
    let currentPlayer = 'w'; // 'w' (White/Bottom) or 'b' (Red/Top)
    let selectedPiece = null; // { r, c }
    let validMoves = []; // array of { r, c, captured: [{r,c}] }
    let gameMode = 'pvp'; // 'pvp' | 'pvai'
    let aiLevel = 'medium';
    let isGameOver = false;

    // Grid cursor for Gamepad / Keyboard navigation
    let cursor = { r: 5, c: 0 };

    // --- AI Difficulty Selection ---
    aiLvlBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            playClick();
            aiLvlBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            aiLevel = btn.dataset.level;
        });
    });

    playPlayerBtn?.addEventListener('click', () => {
        playClick();
        initGame('pvp');
    });

    playAiBtn?.addEventListener('click', () => {
        playClick();
        aiDifficultySelector.classList.toggle('hidden');
    });

    startAiGameBtn?.addEventListener('click', () => {
        playClick();
        initGame('pvai');
    });

    function showMainMenu() {
        gameContainer.classList.add('hidden');
        mainMenu.classList.remove('hidden');
        if (helper) helper.audio.playMenuMusic();
    }

    backToMenuBtn?.addEventListener('click', () => {
        playClick();
        showMainMenu();
    });

    restartMatchBtn?.addEventListener('click', () => {
        playClick();
        initGame(gameMode);
    });

    settingsBtn?.addEventListener('click', () => {
        playClick();
        settingsDialog.classList.remove('hidden');
    });

    closeSettingsBtn?.addEventListener('click', () => {
        playClick();
        settingsDialog.classList.add('hidden');
    });

    // --- Board Setup ---
    function setupBoard() {
        const b = Array.from({ length: 8 }, () => Array(8).fill(null));
        for (let r = 0; r < 3; r++) {
            for (let c = 0; c < 8; c++) {
                if ((r + c) % 2 === 1) b[r][c] = { player: 'b', isKing: false };
            }
        }
        for (let r = 5; r < 8; r++) {
            for (let c = 0; c < 8; c++) {
                if ((r + c) % 2 === 1) b[r][c] = { player: 'w', isKing: false };
            }
        }
        return b;
    }

    function initGame(mode) {
        playSound('gameStart');
        gameMode = mode;
        board = setupBoard();
        currentPlayer = 'w';
        selectedPiece = null;
        validMoves = [];
        isGameOver = false;
        cursor = { r: 5, c: 1 };

        mainMenu.classList.add('hidden');
        gameContainer.classList.remove('hidden');

        if (helper) helper.audio.playGameMusic();

        renderBoard();
        updateStatus();
    }

    // --- Move Calculation ---
    function getValidMoves(r, c) {
        const piece = board[r][c];
        if (!piece || piece.player !== currentPlayer) return [];

        const moves = [];
        const jumps = [];
        const forwardDirs = piece.player === 'w' ? [-1] : [1];
        const directions = piece.isKing ? [-1, 1] : forwardDirs;

        // Check regular diagonal moves
        directions.forEach(dr => {
            [-1, 1].forEach(dc => {
                const nr = r + dr, nc = c + dc;
                if (nr >= 0 && nr < 8 && nc >= 0 && nc < 8) {
                    if (board[nr][nc] === null) {
                        moves.push({ r: nr, c: nc, isJump: false });
                    }
                }
            });
        });

        // Check jumps
        directions.forEach(dr => {
            [-1, 1].forEach(dc => {
                const midR = r + dr, midC = c + dc;
                const landR = r + dr * 2, landC = c + dc * 2;
                if (landR >= 0 && landR < 8 && landC >= 0 && landC < 8) {
                    const midPiece = board[midR][midC];
                    if (midPiece && midPiece.player !== piece.player && board[landR][landC] === null) {
                        jumps.push({ r: landR, c: landC, isJump: true, captured: [{ r: midR, c: midC }] });
                    }
                }
            });
        });

        // Mandatory jumping rule in Checkers: if jumps exist, jumps must be taken
        return jumps.length > 0 ? jumps : moves;
    }

    function getAllAvailableJumps(player) {
        const allJumps = [];
        for (let r = 0; r < 8; r++) {
            for (let c = 0; c < 8; c++) {
                if (board[r][c]?.player === player) {
                    const moves = getValidMoves(r, c);
                    if (moves.some(m => m.isJump)) {
                        allJumps.push({ r, c, jumps: moves.filter(m => m.isJump) });
                    }
                }
            }
        }
        return allJumps;
    }

    // --- Board Rendering ---
    function renderBoard() {
        boardElement.innerHTML = '';
        let wCount = 0, rCount = 0;

        for (let r = 0; r < 8; r++) {
            for (let c = 0; c < 8; c++) {
                const sq = document.createElement('div');
                sq.classList.add('square');
                sq.classList.add((r + c) % 2 === 1 ? 'dark' : 'light');
                sq.dataset.row = r;
                sq.dataset.col = c;

                if (cursor.r === r && cursor.c === c) {
                    sq.classList.add('gamepad-cursor');
                }

                if (selectedPiece && selectedPiece.r === r && selectedPiece.c === c) {
                    sq.classList.add('selected');
                }

                const moveOpt = validMoves.find(m => m.r === r && m.c === c);
                if (moveOpt) {
                    sq.classList.add('valid-move');
                }

                const piece = board[r][c];
                if (piece) {
                    const pieceEl = document.createElement('div');
                    pieceEl.classList.add('piece', piece.player === 'w' ? 'white' : 'red');
                    if (piece.isKing) pieceEl.classList.add('king');
                    sq.appendChild(pieceEl);

                    if (piece.player === 'w') wCount++;
                    else rCount++;
                }

                sq.addEventListener('click', () => onSquareClick(r, c));
                boardElement.appendChild(sq);
            }
        }

        if (whiteCountEl) whiteCountEl.textContent = wCount;
        if (redCountEl) redCountEl.textContent = rCount;
    }

    function updateStatus() {
        if (isGameOver) return;
        const isWhite = currentPlayer === 'w';
        statusElement.textContent = isWhite ? "White's Turn" : (gameMode === 'pvai' ? "AI Thinking..." : "Red's Turn");
        statusElement.style.color = isWhite ? '#f8fafc' : '#ef4444';
        statusElement.style.borderColor = isWhite ? 'rgba(255,255,255,0.4)' : 'rgba(239,68,68,0.4)';
    }

    // --- Square Selection & Movement ---
    function onSquareClick(r, c) {
        if (isGameOver) return;
        if (gameMode === 'pvai' && currentPlayer === 'b') return;

        cursor = { r, c };

        // 1. Move to selected target
        const targetMove = validMoves.find(m => m.r === r && m.c === c);
        if (targetMove && selectedPiece) {
            executeMove(selectedPiece, targetMove);
            return;
        }

        // 2. Select piece
        const piece = board[r][c];
        if (piece && piece.player === currentPlayer) {
            const allJumps = getAllAvailableJumps(currentPlayer);
            if (allJumps.length > 0 && !allJumps.some(j => j.r === r && j.c === c)) {
                playSound('invalid');
                if (hintText) hintText.innerHTML = '<i class="fas fa-exclamation-triangle" style="color:#f59e0b;"></i> Jump is mandatory!';
                return;
            }

            selectedPiece = { r, c };
            validMoves = getValidMoves(r, c);
            playSound('select');
            if (helper) helper.vibrate(10);
            renderBoard();
        } else {
            selectedPiece = null;
            validMoves = [];
            renderBoard();
        }
    }

    function executeMove(from, to) {
        const piece = board[from.r][from.c];
        board[from.r][from.c] = null;
        board[to.r][to.c] = piece;

        let wasJump = false;
        if (to.captured && to.captured.length > 0) {
            wasJump = true;
            to.captured.forEach(cap => {
                board[cap.r][cap.c] = null;
            });
            playSound('capture');
            if (helper) helper.vibrate(30);
        } else {
            playSound('move');
            if (helper) helper.vibrate(15);
        }

        // King promotion
        if (piece.player === 'w' && to.r === 0 && !piece.isKing) {
            piece.isKing = true;
            playSound('capture');
        } else if (piece.player === 'b' && to.r === 7 && !piece.isKing) {
            piece.isKing = true;
            playSound('capture');
        }

        // Multi-jump check
        if (wasJump) {
            const consecutiveJumps = getValidMoves(to.r, to.c).filter(m => m.isJump);
            if (consecutiveJumps.length > 0) {
                selectedPiece = { r: to.r, c: to.c };
                validMoves = consecutiveJumps;
                renderBoard();
                if (hintText) hintText.innerHTML = '<i class="fas fa-bolt" style="color:#ffd700;"></i> Multi-jump available!';
                return;
            }
        }

        selectedPiece = null;
        validMoves = [];
        switchTurn();
    }

    function switchTurn() {
        currentPlayer = currentPlayer === 'w' ? 'b' : 'w';
        renderBoard();
        updateStatus();

        if (checkWin()) return;

        if (gameMode === 'pvai' && currentPlayer === 'b') {
            setTimeout(makeAiMove, 550);
        }
    }

    // --- AI Opponent ---
    function makeAiMove() {
        if (isGameOver) return;
        const allJumps = getAllAvailableJumps('b');
        let choices = [];

        if (allJumps.length > 0) {
            allJumps.forEach(j => {
                j.jumps.forEach(jump => choices.push({ from: { r: j.r, c: j.c }, to: jump }));
            });
        } else {
            for (let r = 0; r < 8; r++) {
                for (let c = 0; c < 8; c++) {
                    if (board[r][c]?.player === 'b') {
                        const moves = getValidMoves(r, c);
                        moves.forEach(m => choices.push({ from: { r, c }, to: m }));
                    }
                }
            }
        }

        if (choices.length === 0) {
            endGame('White (You) Win!');
            return;
        }

        // Easy = random; Medium/Hard = prioritize jumps and center advances
        let pick = choices[Math.floor(Math.random() * choices.length)];
        if (aiLevel !== 'easy') {
            const jumps = choices.filter(c => c.to.isJump);
            if (jumps.length > 0) {
                pick = jumps[Math.floor(Math.random() * jumps.length)];
            } else {
                choices.sort((a, b) => b.to.r - a.to.r);
                pick = choices[0];
            }
        }

        executeMove(pick.from, pick.to);
    }

    function checkWin() {
        let whiteMoves = 0, redMoves = 0;
        let whiteCount = 0, redCount = 0;

        for (let r = 0; r < 8; r++) {
            for (let c = 0; c < 8; c++) {
                const p = board[r][c];
                if (p) {
                    if (p.player === 'w') {
                        whiteCount++;
                        whiteMoves += getValidMoves(r, c).length;
                    } else {
                        redCount++;
                        redMoves += getValidMoves(r, c).length;
                    }
                }
            }
        }

        if (whiteCount === 0 || (currentPlayer === 'w' && whiteMoves === 0)) {
            endGame(gameMode === 'pvai' ? 'AI Wins!' : 'Red Wins!');
            return true;
        }
        if (redCount === 0 || (currentPlayer === 'b' && redMoves === 0)) {
            endGame(gameMode === 'pvai' ? 'You Win!' : 'White Wins!');
            return true;
        }
        return false;
    }

    function endGame(winnerMsg) {
        isGameOver = true;
        playSound('gameOver');
        statusElement.textContent = winnerMsg;
        statusElement.style.color = '#ffd700';
        if (hintText) hintText.textContent = `${winnerMsg} - Tap restart to play again!`;

        const isWhiteWon = winnerMsg.includes('White') || winnerMsg.includes('You');
        const isRedWon = winnerMsg.includes('Red') || winnerMsg.includes('AI');
        if (isWhiteWon) {
            sessWhite++;
            localStorage.setItem('arc_checkers_white', sessWhite);
            launchWinParticles();
        } else if (isRedWon) {
            sessRed++;
            localStorage.setItem('arc_checkers_red', sessRed);
            launchWinParticles();
        } else {
            sessDraw++;
            localStorage.setItem('arc_checkers_draw', sessDraw);
        }
        updateScoreboard();

        if (helper) {
            helper.vibrate([40, 30, 80]);
            helper.audio.playMenuMusic();
        }

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: isWhiteWon ? 'win' : 'loss',
                score: isWhiteWon ? 100 : 20
            }, '*');
        }
    }

    // --- KEYBOARD & CONTROLLER NAVIGATION ---
    window.addEventListener('keydown', (e) => {
        if (gameContainer.classList.contains('hidden') || isGameOver) return;

        let moved = false;
        if (e.key === 'ArrowUp' || e.key === 'w' || e.key === 'W') {
            cursor.r = Math.max(0, cursor.r - 1); moved = true;
        } else if (e.key === 'ArrowDown' || e.key === 's' || e.key === 'S') {
            cursor.r = Math.min(7, cursor.r + 1); moved = true;
        } else if (e.key === 'ArrowLeft' || e.key === 'a' || e.key === 'A') {
            cursor.c = Math.max(0, cursor.c - 1); moved = true;
        } else if (e.key === 'ArrowRight' || e.key === 'd' || e.key === 'D') {
            cursor.c = Math.min(7, cursor.c + 1); moved = true;
        } else if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onSquareClick(cursor.r, cursor.c);
        } else if (e.key === 'Escape') {
            selectedPiece = null;
            validMoves = [];
            renderBoard();
        }

        if (moved) {
            e.preventDefault();
            renderBoard();
        }
    });

    if (helper && helper.gamepad) {
        helper.gamepad.onDirection((dir) => {
            if (!gameContainer.classList.contains('hidden') && !isGameOver) {
                if (dir === 'up') cursor.r = Math.max(0, cursor.r - 1);
                else if (dir === 'down') cursor.r = Math.min(7, cursor.r + 1);
                else if (dir === 'left') cursor.c = Math.max(0, cursor.c - 1);
                else if (dir === 'right') cursor.c = Math.min(7, cursor.c + 1);
                renderBoard();
            }
        });

        helper.gamepad.onAction((act) => {
            if (!gameContainer.classList.contains('hidden')) {
                if (act === 'A') onSquareClick(cursor.r, cursor.c);
                else if (act === 'B') {
                    selectedPiece = null;
                    validMoves = [];
                    renderBoard();
                } else if (act === 'START') {
                    backToMenuBtn?.click();
                }
            }
        });
    }
});
