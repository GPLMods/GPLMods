/**
 * Chess Master - Pocket Classics
 * Non-recursive move generation, Scoreboard Comparison, Win Particles, Controller/Touch/Keyboard
 */
document.addEventListener('DOMContentLoaded', () => {
    // --- Universal Arcade Helper ---
    const helper = window.ArcadeHelper ? window.ArcadeHelper.init({
        menuMusic: 'sounds/menu-music.mp3',
        gameMusic: 'sounds/game-music.mp3'
    }) : null;

    // --- DOM Elements ---
    const boardElement = document.getElementById('board');
    const statusElement = document.getElementById('status');
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

    const scoreWhite = document.getElementById('score-white');
    const scoreBlack = document.getElementById('score-black');
    const scoreDraws = document.getElementById('score-draws');
    const labelBlack = document.getElementById('label-black');
    const confettiCanvas = document.getElementById('confetti-canvas');

    const promotionDialog = document.getElementById('promotion-dialog');
    const promoChoiceBtns = document.querySelectorAll('.promo-choice-btn');

    const settingsBtn = document.getElementById('settings-button');
    const settingsDialog = document.getElementById('settings-dialog');
    const closeSettingsBtn = document.getElementById('close-settings-button');
    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');

    // --- Sound Assets ---
    const sounds = {
        move: document.getElementById('sound-move'),
        capture: document.getElementById('sound-capture'),
        check: document.getElementById('sound-check'),
        gameOver: document.getElementById('sound-game-over'),
        uiClick: document.getElementById('sound-ui-click'),
        gameStart: document.getElementById('sound-game-start'),
        castling: document.getElementById('sound-castling'),
        promotion: document.getElementById('sound-promotion'),
        select: document.getElementById('sound-select'),
        invalid: document.getElementById('sound-invalid')
    };

    function playSound(k) {
        if (helper && helper.audio) helper.audio.playSfx(sounds[k]);
        else if (sounds[k]) {
            try {
                sounds[k].currentTime = 0;
                sounds[k].play().catch(() => {});
            } catch (_) {}
        }
    }
    function playClick() { playSound('uiClick'); }

    if (helper && helper.audio) helper.audio.playMenuMusic();

    // Settings Toggle sync
    if (musicToggle) {
        musicToggle.checked = helper ? helper.audio.musicEnabled : (localStorage.getItem('arc_music_enabled') !== 'false');
        musicToggle.addEventListener('change', (e) => {
            if (helper && helper.audio) helper.audio.setMusicEnabled(e.target.checked);
        });
    }
    if (sfxToggle) {
        sfxToggle.checked = helper ? helper.audio.sfxEnabled : (localStorage.getItem('arc_sfx_enabled') !== 'false');
        sfxToggle.addEventListener('change', (e) => {
            if (helper && helper.audio) helper.audio.setSfxEnabled(e.target.checked);
        });
    }

    // --- Chess Unicode Symbols ---
    const PIECE_UNICODE = {
        w: { k: '♔', q: '♕', r: '♖', b: '♗', n: '♘', p: '♙' },
        b: { k: '♚', q: '♛', r: '♜', b: '♝', n: '♞', p: '♟' }
    };

    // --- Game State ---
    let board = [];
    let currentPlayer = 'w';
    let selectedPiece = null;
    let validMoves = [];
    let gameMode = 'pvp'; // 'pvp' or 'pvai'
    let aiLevel = 'medium';
    let isGameOver = false;
    let pendingPromotion = null;
    let cursor = { r: 6, c: 4 };

    // Scoreboard Comparison State
    const scores = { w: 0, b: 0, draws: 0 };

    function updateScoreDisplay() {
        if (scoreWhite) scoreWhite.textContent = scores.w;
        if (scoreBlack) scoreBlack.textContent = scores.b;
        if (scoreDraws) scoreDraws.textContent = scores.draws;
        if (labelBlack) {
            labelBlack.textContent = gameMode === 'pvai' ? 'BLACK (AI)' : 'BLACK (P2)';
        }
    }

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
        stopConfetti();
        gameContainer.classList.add('hidden');
        mainMenu.classList.remove('hidden');
        if (helper && helper.audio) helper.audio.playMenuMusic();
    }

    backToMenuBtn?.addEventListener('click', () => {
        playClick();
        showMainMenu();
    });

    restartMatchBtn?.addEventListener('click', () => {
        playClick();
        stopConfetti();
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

    // --- Board Initialization ---
    function setupChessBoard() {
        const b = Array.from({ length: 8 }, () => Array(8).fill(null));
        const backRank = ['r', 'n', 'b', 'q', 'k', 'b', 'n', 'r'];

        // Black pieces (top: rank 0 and 1)
        for (let c = 0; c < 8; c++) {
            b[0][c] = { player: 'b', type: backRank[c], hasMoved: false };
            b[1][c] = { player: 'b', type: 'p', hasMoved: false };
        }

        // White pieces (bottom: rank 6 and 7)
        for (let c = 0; c < 8; c++) {
            b[6][c] = { player: 'w', type: 'p', hasMoved: false };
            b[7][c] = { player: 'w', type: backRank[c], hasMoved: false };
        }

        return b;
    }

    function initGame(mode) {
        playSound('gameStart');
        stopConfetti();
        gameMode = mode;
        board = setupChessBoard();
        currentPlayer = 'w';
        selectedPiece = null;
        validMoves = [];
        isGameOver = false;
        pendingPromotion = null;
        cursor = { r: 6, c: 4 };

        mainMenu.classList.add('hidden');
        gameContainer.classList.remove('hidden');

        if (helper && helper.audio) helper.audio.playGameMusic();

        updateScoreDisplay();
        renderBoard();
        updateStatus();
    }

    // --- NON-RECURSIVE SQUARE ATTACK DETECTION ---
    function isSquareAttacked(b, targetR, targetC, byPlayer) {
        // 1. Pawn attacks (pawns only attack diagonally forward)
        // A white pawn at (targetR+1, targetC±1) attacks targetR, targetC
        // A black pawn at (targetR-1, targetC±1) attacks targetR, targetC
        const pawnSourceR = byPlayer === 'w' ? targetR + 1 : targetR - 1;
        if (pawnSourceR >= 0 && pawnSourceR < 8) {
            for (const dc of [-1, 1]) {
                const pc = targetC + dc;
                if (pc >= 0 && pc < 8) {
                    const piece = b[pawnSourceR][pc];
                    if (piece && piece.player === byPlayer && piece.type === 'p') return true;
                }
            }
        }

        // 2. Knight attacks
        const knightOffsets = [
            [-2, -1], [-2, 1], [-1, -2], [-1, 2],
            [1, -2], [1, 2], [2, -1], [2, 1]
        ];
        for (const [dr, dc] of knightOffsets) {
            const nr = targetR + dr, nc = targetC + dc;
            if (nr >= 0 && nr < 8 && nc >= 0 && nc < 8) {
                const piece = b[nr][nc];
                if (piece && piece.player === byPlayer && piece.type === 'n') return true;
            }
        }

        // 3. King adjacent attacks (1 square)
        for (let dr = -1; dr <= 1; dr++) {
            for (let dc = -1; dc <= 1; dc++) {
                if (dr !== 0 || dc !== 0) {
                    const nr = targetR + dr, nc = targetC + dc;
                    if (nr >= 0 && nr < 8 && nc >= 0 && nc < 8) {
                        const piece = b[nr][nc];
                        if (piece && piece.player === byPlayer && piece.type === 'k') return true;
                    }
                }
            }
        }

        // 4. Orthogonal sliders (Rook & Queen)
        const orthoDirs = [[-1, 0], [1, 0], [0, -1], [0, 1]];
        for (const [dr, dc] of orthoDirs) {
            let nr = targetR + dr, nc = targetC + dc;
            while (nr >= 0 && nr < 8 && nc >= 0 && nc < 8) {
                const piece = b[nr][nc];
                if (piece) {
                    if (piece.player === byPlayer && (piece.type === 'r' || piece.type === 'q')) return true;
                    break;
                }
                nr += dr; nc += dc;
            }
        }

        // 5. Diagonal sliders (Bishop & Queen)
        const diagDirs = [[-1, -1], [-1, 1], [1, -1], [1, 1]];
        for (const [dr, dc] of diagDirs) {
            let nr = targetR + dr, nc = targetC + dc;
            while (nr >= 0 && nr < 8 && nc >= 0 && nc < 8) {
                const piece = b[nr][nc];
                if (piece) {
                    if (piece.player === byPlayer && (piece.type === 'b' || piece.type === 'q')) return true;
                    break;
                }
                nr += dr; nc += dc;
            }
        }

        return false;
    }

    function isKingInCheck(b, player) {
        let kingPos = null;
        for (let r = 0; r < 8; r++) {
            for (let c = 0; c < 8; c++) {
                if (b[r][c]?.player === player && b[r][c].type === 'k') {
                    kingPos = { r, c };
                    break;
                }
            }
            if (kingPos) break;
        }
        if (!kingPos) return false;

        const enemy = player === 'w' ? 'b' : 'w';
        return isSquareAttacked(b, kingPos.r, kingPos.c, enemy);
    }

    // --- BASIC PSEUDO-LEGAL MOVES (NO CASTLING, NO RECURSION) ---
    function getRawMoves(b, r, c) {
        const piece = b[r][c];
        if (!piece) return [];
        const moves = [];
        const p = piece.player;
        const enemy = p === 'w' ? 'b' : 'w';

        function addMove(nr, nc) {
            if (nr < 0 || nr >= 8 || nc < 0 || nc >= 8) return false;
            if (b[nr][nc] === null) {
                moves.push({ r: nr, c: nc });
                return true;
            } else if (b[nr][nc].player === enemy) {
                moves.push({ r: nr, c: nc, isCapture: true });
                return false;
            }
            return false;
        }

        function slide(dr, dc) {
            let nr = r + dr, nc = c + dc;
            while (addMove(nr, nc)) {
                nr += dr; nc += dc;
            }
        }

        if (piece.type === 'p') {
            const dir = p === 'w' ? -1 : 1;
            const startRank = p === 'w' ? 6 : 1;

            // 1 square forward
            if (r + dir >= 0 && r + dir < 8 && b[r + dir][c] === null) {
                moves.push({ r: r + dir, c });
                // 2 squares forward from start rank
                if (r === startRank && b[r + dir * 2][c] === null) {
                    moves.push({ r: r + dir * 2, c });
                }
            }
            // Diagonal captures
            [-1, 1].forEach(dc => {
                const nr = r + dir, nc = c + dc;
                if (nr >= 0 && nr < 8 && nc >= 0 && nc < 8) {
                    if (b[nr][nc] && b[nr][nc].player === enemy) {
                        moves.push({ r: nr, c: nc, isCapture: true });
                    }
                }
            });
        } else if (piece.type === 'n') {
            const jumps = [
                [-2, -1], [-2, 1], [-1, -2], [-1, 2],
                [1, -2], [1, 2], [2, -1], [2, 1]
            ];
            jumps.forEach(([dr, dc]) => addMove(r + dr, c + dc));
        } else if (piece.type === 'b') {
            slide(-1, -1); slide(-1, 1); slide(1, -1); slide(1, 1);
        } else if (piece.type === 'r') {
            slide(-1, 0); slide(1, 0); slide(0, -1); slide(0, 1);
        } else if (piece.type === 'q') {
            slide(-1, -1); slide(-1, 1); slide(1, -1); slide(1, 1);
            slide(-1, 0); slide(1, 0); slide(0, -1); slide(0, 1);
        } else if (piece.type === 'k') {
            // King standard 8 squares
            for (let dr = -1; dr <= 1; dr++) {
                for (let dc = -1; dc <= 1; dc++) {
                    if (dr !== 0 || dc !== 0) addMove(r + dr, c + dc);
                }
            }
        }

        return moves;
    }

    // --- FULL LEGAL MOVES (CHECKS & CASTLING EVALUATION) ---
    function getLegalMoves(r, c) {
        const piece = board[r][c];
        if (!piece || piece.player !== currentPlayer) return [];

        const raw = getRawMoves(board, r, c);
        const legal = [];
        const enemy = piece.player === 'w' ? 'b' : 'w';

        // 1. Filter raw moves: simulate on clone, verify king not left in check
        raw.forEach(move => {
            const cloned = board.map(row => row.map(cell => cell ? { ...cell } : null));
            cloned[move.r][move.c] = cloned[r][c];
            cloned[r][c] = null;

            if (!isKingInCheck(cloned, piece.player)) {
                legal.push(move);
            }
        });

        // 2. Add Castling if King
        if (piece.type === 'k' && !piece.hasMoved && !isKingInCheck(board, piece.player)) {
            // Kingside: e1 -> g1 (col 4 -> 6)
            if (
                board[r][7]?.type === 'r' && !board[r][7].hasMoved &&
                board[r][5] === null && board[r][6] === null &&
                !isSquareAttacked(board, r, 5, enemy) &&
                !isSquareAttacked(board, r, 6, enemy)
            ) {
                legal.push({ r, c: 6, isCastle: 'k' });
            }

            // Queenside: e1 -> c1 (col 4 -> 2)
            if (
                board[r][0]?.type === 'r' && !board[r][0].hasMoved &&
                board[r][1] === null && board[r][2] === null && board[r][3] === null &&
                !isSquareAttacked(board, r, 3, enemy) &&
                !isSquareAttacked(board, r, 2, enemy)
            ) {
                legal.push({ r, c: 2, isCastle: 'q' });
            }
        }

        return legal;
    }

    function getAllLegalMoves(player) {
        const all = [];
        for (let r = 0; r < 8; r++) {
            for (let c = 0; c < 8; c++) {
                if (board[r][c]?.player === player) {
                    const moves = getLegalMoves(r, c);
                    moves.forEach(m => all.push({ from: { r, c }, to: m }));
                }
            }
        }
        return all;
    }

    // --- BOARD RENDERING ---
    function renderBoard() {
        boardElement.innerHTML = '';
        const inCheck = isKingInCheck(board, currentPlayer);

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

                const piece = board[r][c];
                if (piece) {
                    if (piece.type === 'k' && piece.player === currentPlayer && inCheck) {
                        sq.classList.add('in-check');
                    }

                    const pieceEl = document.createElement('span');
                    pieceEl.classList.add('piece', piece.player === 'w' ? 'white' : 'black');
                    pieceEl.textContent = PIECE_UNICODE[piece.player][piece.type];
                    sq.appendChild(pieceEl);
                }

                if (validMoves.some(m => m.r === r && m.c === c)) {
                    sq.classList.add('valid-move');
                }

                sq.addEventListener('click', () => onSquareClick(r, c));
                boardElement.appendChild(sq);
            }
        }
    }

    function updateStatus() {
        if (isGameOver) return;
        const isWhite = currentPlayer === 'w';
        const inCheck = isKingInCheck(board, currentPlayer);

        if (inCheck) {
            statusElement.textContent = isWhite ? "White in Check!" : "Black in Check!";
            statusElement.style.color = '#ef4444';
            statusElement.style.borderColor = 'rgba(239, 68, 68, 0.6)';
            playSound('check');
            if (helper) helper.vibrate([30, 20, 30]);
        } else {
            statusElement.textContent = isWhite ? "White's Turn" : "Black's Turn";
            statusElement.style.color = '#ffd700';
            statusElement.style.borderColor = 'rgba(255, 215, 0, 0.3)';
        }

        if (hintText) {
            if (gameMode === 'pvai' && currentPlayer === 'b') {
                hintText.textContent = "AI is thinking...";
            } else {
                hintText.textContent = selectedPiece ? "Choose destination square" : "Select a piece to move";
            }
        }
    }

    // --- SQUARE CLICK HANDLER ---
    function onSquareClick(r, c) {
        if (isGameOver || pendingPromotion) return;
        if (gameMode === 'pvai' && currentPlayer === 'b') return;

        cursor = { r, c };

        // 1. Clicking an already selected piece deselects it
        if (selectedPiece && selectedPiece.r === r && selectedPiece.c === c) {
            selectedPiece = null;
            validMoves = [];
            renderBoard();
            return;
        }

        // 2. Move to valid destination
        const chosenMove = validMoves.find(m => m.r === r && m.c === c);
        if (selectedPiece && chosenMove) {
            executeMove(selectedPiece, chosenMove);
            return;
        }

        // 3. Select a piece belonging to current player
        const piece = board[r][c];
        if (piece && piece.player === currentPlayer) {
            selectedPiece = { r, c };
            validMoves = getLegalMoves(r, c);
            if (validMoves.length > 0) {
                playSound('select');
                if (helper) helper.vibrate(15);
            } else {
                playSound('invalid');
            }
            renderBoard();
        } else {
            selectedPiece = null;
            validMoves = [];
            renderBoard();
        }
    }

    // --- MOVE EXECUTION & SPECIAL RULES ---
    function executeMove(from, to) {
        const piece = board[from.r][from.c];
        const isCapture = to.isCapture || Boolean(board[to.r][to.c]);

        // Move piece
        board[to.r][to.c] = piece;
        board[from.r][from.c] = null;
        piece.hasMoved = true;

        // Handle Castling Rook move
        if (to.isCastle === 'k') {
            board[from.r][5] = board[from.r][7];
            board[from.r][7] = null;
            board[from.r][5].hasMoved = true;
            playSound('castling');
        } else if (to.isCastle === 'q') {
            board[from.r][3] = board[from.r][0];
            board[from.r][0] = null;
            board[from.r][3].hasMoved = true;
            playSound('castling');
        } else if (isCapture) {
            playSound('capture');
            if (helper) helper.vibrate(25);
        } else {
            playSound('move');
            if (helper) helper.vibrate(12);
        }

        selectedPiece = null;
        validMoves = [];

        // Check for Pawn Promotion
        if (piece.type === 'p' && (to.r === 0 || to.r === 7)) {
            if (gameMode === 'pvai' && piece.player === 'b') {
                // AI automatically promotes to Queen
                piece.type = 'q';
                playSound('promotion');
                postMoveChecks();
            } else {
                // Show modal to human player
                pendingPromotion = { r: to.r, c: to.c };
                promotionDialog.classList.remove('hidden');
            }
            renderBoard();
            return;
        }

        renderBoard();
        postMoveChecks();
    }

    // Promotion Dialog selection
    promoChoiceBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            if (!pendingPromotion) return;
            const chosen = btn.dataset.piece;
            board[pendingPromotion.r][pendingPromotion.c].type = chosen;
            pendingPromotion = null;
            promotionDialog.classList.add('hidden');
            playSound('promotion');
            renderBoard();
            postMoveChecks();
        });
    });

    function postMoveChecks() {
        currentPlayer = currentPlayer === 'w' ? 'b' : 'w';
        updateStatus();

        // Check for Checkmate or Stalemate
        const allLegal = getAllLegalMoves(currentPlayer);
        if (allLegal.length === 0) {
            const inCheck = isKingInCheck(board, currentPlayer);
            if (inCheck) {
                const winner = currentPlayer === 'w' ? 'Black' : 'White';
                endGame(`Checkmate! ${winner} Wins!`, winner === 'White' ? 'w' : 'b');
            } else {
                endGame("Stalemate! Game is a Draw.", 'draw');
            }
            return;
        }

        // Trigger AI if in AI mode
        if (gameMode === 'pvai' && currentPlayer === 'b' && !isGameOver) {
            setTimeout(executeAiMove, 450);
        }
    }

    // --- AI MOVE EXECUTION ---
    function executeAiMove() {
        if (isGameOver) return;
        const legal = getAllLegalMoves('b');
        if (legal.length === 0) return;

        let pick = legal[Math.floor(Math.random() * legal.length)];

        if (aiLevel !== 'easy') {
            // Prioritize captures and checks
            const captures = legal.filter(m => m.to.isCapture);
            if (captures.length > 0) {
                pick = captures[Math.floor(Math.random() * captures.length)];
            }
        }

        executeMove(pick.from, pick.to);
    }

    function endGame(msg, result) {
        isGameOver = true;
        playSound('gameOver');
        statusElement.textContent = msg;
        statusElement.style.color = '#ffd700';
        if (hintText) hintText.textContent = `${msg} Tap restart to play again.`;

        if (result === 'w') {
            scores.w++;
            startConfetti();
        } else if (result === 'b') {
            scores.b++;
            if (gameMode === 'pvp') startConfetti();
        } else {
            scores.draws++;
        }
        updateScoreDisplay();

        if (helper) {
            helper.vibrate([40, 30, 80]);
            helper.audio.playMenuMusic();
        }

        if (window.parent && window.parent !== window) {
            const isWhiteWon = result === 'w';
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: isWhiteWon ? 'win' : (result === 'draw' ? 'draw' : 'loss'),
                score: isWhiteWon ? 100 : (result === 'draw' ? 30 : 25)
            }, '*');
        }
    }

    // --- CONFETTI WIN PARTICLES ---
    let confettiAnimationId = null;
    let confettiParticles = [];
    function startConfetti() {
        if (!confettiCanvas) return;
        const ctx = confettiCanvas.getContext('2d');
        confettiCanvas.width = window.innerWidth;
        confettiCanvas.height = window.innerHeight;
        confettiParticles = [];

        const colors = ['#ffd700', '#00f0ff', '#ff007f', '#10b981', '#ffffff'];
        for (let i = 0; i < 120; i++) {
            confettiParticles.push({
                x: Math.random() * confettiCanvas.width,
                y: Math.random() * confettiCanvas.height - confettiCanvas.height,
                radius: Math.random() * 4 + 2,
                color: colors[Math.floor(Math.random() * colors.length)],
                vx: Math.random() * 6 - 3,
                vy: Math.random() * 4 + 3,
                opacity: 1
            });
        }

        function render() {
            ctx.clearRect(0, 0, confettiCanvas.width, confettiCanvas.height);
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
        if (confettiCanvas) {
            const ctx = confettiCanvas.getContext('2d');
            ctx.clearRect(0, 0, confettiCanvas.width, confettiCanvas.height);
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

    window.addEventListener('resize', () => {
        if (confettiAnimationId && confettiCanvas) {
            confettiCanvas.width = window.innerWidth;
            confettiCanvas.height = window.innerHeight;
        }
    });
});
