document.addEventListener('DOMContentLoaded', () => {
    // --- CACHED DOM ELEMENTS ---
    const boardElement = document.getElementById('board');
    const statusElement = document.getElementById('status');
    const mainMenu = document.getElementById('main-menu');
    const gameContainer = document.getElementById('game-container');
    const playPlayerBtn = document.getElementById('play-player');
    const playAiBtn = document.getElementById('play-ai');
    const aiDifficultySelector = document.getElementById('ai-difficulty-selector');
    const aiDifficulty = document.getElementById('ai-difficulty');
    const startAiGameBtn = document.getElementById('start-ai-game');
    const backToMenuBtn = document.getElementById('back-to-menu');
    const homeBtn = document.getElementById('home-button');
    const promotionDialog = document.getElementById('promotion-dialog');
    
    // Settings Elements
    const settingsBtn = document.getElementById('settings-button');
    const settingsDialog = document.getElementById('settings-dialog');
    const closeSettingsBtn = document.getElementById('close-settings-button');
    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');

    // --- AUDIO & GAME STATE ---
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
        invalid: document.getElementById('sound-invalid'),
        menuMusic: document.getElementById('music-menu'),
        gameMusic: document.getElementById('music-game')
    };
    
    let board = [], currentPlayer = 'w', selectedPiece = null, validMoves = [], gameMode = null, aiLevel = 'easy', isGameOver = false, lastMove = { from: null, to: null }, castlingRights = { w: { k: true, q: true }, b: { k: true, q: true } }, enPassantTarget = null;
    const pieces = { 'P': '♙', 'R': '♖', 'N': '♘', 'B': '♗', 'Q': '♕', 'K': '♔', 'p': '♟', 'r': '♜', 'n': '♞', 'b': '♝', 'q': '♛', 'k': '♚' };

    // Sound State
    let isMusicEnabled = true;
    let isSfxEnabled = true;
    let gameOverSoundPlayed = false;

    if (window.parent && window.parent !== window) {
        isMusicEnabled = false;
        if (sounds.menuMusic) { sounds.menuMusic.muted = true; sounds.menuMusic.volume = 0; }
        if (sounds.gameMusic) { sounds.gameMusic.muted = true; sounds.gameMusic.volume = 0; }
    }

    // --- INITIALIZATION & MENU ---
    function showMainMenu() {
        gameContainer.classList.add('hidden');
        mainMenu.classList.remove('hidden');
        aiDifficultySelector.classList.add('hidden');
        stopAllMusic();
        playMusic('menuMusic');
    }

    function initializeGame(mode) {
        playSound('gameStart');
        gameMode = mode;
        if (mode === 'pvai') {
            aiLevel = aiDifficulty.value;
        }
        board = setupBoard();
        currentPlayer = 'w';
        selectedPiece = null;
        validMoves = [];
        isGameOver = false;
        gameOverSoundPlayed = false;
        castlingRights = { w: { k: true, q: true }, b: { k: true, q: true } };
        enPassantTarget = null;
        lastMove = { from: null, to: null };
        mainMenu.classList.add('hidden');
        gameContainer.classList.remove('hidden');
        stopAllMusic();
        playMusic('gameMusic');
        renderBoard();
        updateStatus();
    }
    
    showMainMenu(); // Initial call to display the main menu on page load

    // --- SOUND SYSTEM ---
    function playSound(soundKey) {
        if (!isSfxEnabled) return;
        const sound = sounds[soundKey];
        if (sound) {
            sound.currentTime = 0;
            sound.play().catch(e => {});
        }
    }

    function playMusic(musicKey) {
        if (!isMusicEnabled || (window.parent && window.parent !== window)) return;
        const music = sounds[musicKey];
        if (music) {
            music.currentTime = 0;
            music.play().catch(e => {});
        }
    }

    function stopAllMusic() {
        if (sounds.menuMusic) sounds.menuMusic.pause();
        if (sounds.gameMusic) sounds.gameMusic.pause();
    }

    let isMultiplayer = false;
    let myColor = 'w';

    window.addEventListener('message', (event) => {
        if (!event.data || !event.data.type) return;
        if (event.data.type === 'ARCADE_MATCH_READY') {
            isMultiplayer = true;
            myColor = event.data.isHost ? 'w' : 'b';
            initializeGame('pvp');
            statusElement.textContent = `Multiplayer Match! You are ${myColor === 'w' ? 'White' : 'Black'}`;
        } else if (event.data.type === 'ARCADE_OPPONENT_MOVE') {
            const m = event.data.move;
            if (m && m.from && m.to) {
                makeMove(m.from, m.to);
            }
        }
    });

    // --- EVENT HANDLERS ---
    if (playPlayerBtn) playPlayerBtn.addEventListener('click', () => { playSound('uiClick'); initializeGame('pvp'); });
    if (playAiBtn) playAiBtn.addEventListener('click', () => { playSound('uiClick'); aiDifficultySelector.classList.toggle('hidden'); });
    if (startAiGameBtn) startAiGameBtn.addEventListener('click', () => { playSound('uiClick'); initializeGame('pvai'); });
    if (backToMenuBtn) backToMenuBtn.addEventListener('click', () => { playSound('uiClick'); showMainMenu(); });
    if (homeBtn) {
        homeBtn.addEventListener('click', () => { 
            playSound('uiClick'); 
            if (window.parent && window.parent !== window) {
                window.parent.postMessage({ type: 'ARCADE_EXIT' }, '*');
            } else {
                window.location.href = '/games/hub'; 
            }
        });
    }

    // Settings Event Listeners
    if (settingsBtn) settingsBtn.addEventListener('click', () => { playSound('uiClick'); settingsDialog.classList.remove('hidden'); });
    if (closeSettingsBtn) closeSettingsBtn.addEventListener('click', () => { playSound('uiClick'); settingsDialog.classList.add('hidden'); });
    if (settingsDialog) {
        settingsDialog.addEventListener('click', (event) => { if (event.target === settingsDialog) { playSound('uiClick'); settingsDialog.classList.add('hidden'); } });
    }

    if (musicToggle) {
        musicToggle.addEventListener('change', () => {
            isMusicEnabled = musicToggle.checked;
            playSound('uiClick');
            if (isMusicEnabled && (!window.parent || window.parent === window)) {
                if (!mainMenu.classList.contains('hidden')) {
                    playMusic('menuMusic');
                } else {
                    playMusic('gameMusic');
                }
            } else {
                stopAllMusic();
            }
        });
    }

    if (sfxToggle) {
        sfxToggle.addEventListener('change', () => {
            isSfxEnabled = sfxToggle.checked;
            playSound('uiClick');
        });
    }
    
    // --- CORE GAME LOGIC (Rendering, Interaction, Moves) ---
    function renderBoard() {
        boardElement.innerHTML = '';
        for (let r = 0; r < 8; r++) { for (let c = 0; c < 8; c++) { const square = document.createElement('div'); square.classList.add('square', (r + c) % 2 === 0 ? 'light' : 'dark'); square.dataset.row = r; square.dataset.col = c; const pieceChar = board[r][c]; if (pieceChar) { const pieceElement = document.createElement('div'); pieceElement.classList.add('piece'); pieceElement.classList.add(getPieceColor(pieceChar) === 'w' ? 'white-piece' : 'black-piece'); pieceElement.innerText = pieces[pieceChar]; pieceElement.dataset.piece = pieceChar; square.appendChild(pieceElement); } if ((lastMove.from && lastMove.from.r === r && lastMove.from.c === c) || (lastMove.to && lastMove.to.r === r && lastMove.to.c === c)) { square.classList.add('last-move'); } boardElement.appendChild(square); } }
        boardElement.querySelectorAll('.square').forEach(square => { square.addEventListener('click', handleSquareClick); square.addEventListener('touchstart', handleSquareClick, { passive: false }); });
        highlightValidMoves();
    }
    function highlightValidMoves() { document.querySelectorAll('.valid-move-dot').forEach(dot => dot.remove()); document.querySelectorAll('.selected').forEach(sel => sel.classList.remove('selected')); if (selectedPiece) { const { r, c } = selectedPiece; boardElement.querySelector(`[data-row='${r}'][data-col='${c}']`).classList.add('selected'); validMoves.forEach(move => { const moveSquare = boardElement.querySelector(`[data-row='${move.r}'][data-col='${move.c}']`); if (moveSquare) { const dot = document.createElement('div'); dot.classList.add('valid-move-dot'); moveSquare.appendChild(dot); } }); } }
    function handleSquareClick(event) { event.preventDefault(); if (isGameOver) return; const square = event.currentTarget; const r = parseInt(square.dataset.row); const c = parseInt(square.dataset.col); const piece = board[r][c]; if (selectedPiece) { const isValidMove = validMoves.some(move => move.r === r && move.c === c); if (isValidMove) { makeMove(selectedPiece, { r, c }); } else { playSound('invalid'); deselect(); if (piece && getPieceColor(piece) === currentPlayer) { selectPiece(r, c); } } } else if (piece && getPieceColor(piece) === currentPlayer) { selectPiece(r, c); } }
    function selectPiece(r, c) { playSound('select'); selectedPiece = { r, c, piece: board[r][c] }; validMoves = getValidMovesForPiece(r, c); renderBoard(); }
    function deselect() { selectedPiece = null; validMoves = []; renderBoard(); }
    function makeMove(from, to) { const piece = board[from.r][from.c]; const capturedPiece = board[to.r][to.c]; const isCastling = piece.toLowerCase() === 'k' && Math.abs(from.c - to.c) === 2; if (isCastling) { playSound('castling'); } else if (capturedPiece) { playSound('capture'); } else { playSound('move'); } if (piece.toLowerCase() === 'p' && to.r === enPassantTarget?.r && to.c === enPassantTarget?.c) { const capturedPawnRow = currentPlayer === 'w' ? to.r + 1 : to.r - 1; board[capturedPawnRow][to.c] = null; } board[to.r][to.c] = piece; board[from.r][from.c] = null; if (isCastling) { const rookCol = to.c > from.c ? 7 : 0; const newRookCol = to.c > from.c ? 5 : 3; board[from.r][newRookCol] = board[from.r][rookCol]; board[from.r][rookCol] = null; } if (piece.toLowerCase() === 'p' && Math.abs(from.r - to.r) === 2) { enPassantTarget = { r: (from.r + to.r) / 2, c: from.c }; } else { enPassantTarget = null; } const promotionRank = (currentPlayer === 'w') ? 0 : 7; if (piece.toLowerCase() === 'p' && to.r === promotionRank) { if (gameMode === 'pvai' && currentPlayer === 'b') { board[to.r][to.c] = 'q'; finishMove(from, to); } else { showPromotionDialog(from, to); } return; } finishMove(from, to); }
    function showPromotionDialog(from, to) { promotionDialog.classList.remove('hidden'); promotionDialog.querySelectorAll('button').forEach(button => { const handlePromotion = (event) => { event.preventDefault(); playSound('promotion'); const promotionPiece = event.currentTarget.dataset.piece; promotionDialog.classList.add('hidden'); board[to.r][to.c] = (currentPlayer === 'w') ? promotionPiece.toUpperCase() : promotionPiece.toLowerCase(); finishMove(from, to); }; button.addEventListener('click', handlePromotion, { once: true }); button.addEventListener('touchstart', handlePromotion, { once: true, passive: false }); }); }
    function finishMove(from, to) { updateCastlingRights(from, to); lastMove = { from, to }; deselect(); switchPlayer(); renderBoard(); updateStatus(); if (gameMode === 'pvai' && currentPlayer === 'b' && !isGameOver) { setTimeout(makeAiMove, 500); } }
    function updateStatus() { 
        let statusText = ''; 
        const kingColor = currentPlayer; 
        const inCheck = isKingInCheck(kingColor); 
        const hasMoves = hasAnyValidMoves(kingColor); 
        let gameResult = null;
        if (inCheck && !hasMoves) { 
            isGameOver = true; 
            const winner = kingColor === 'w' ? 'Black' : 'White';
            statusText = `Checkmate! ${winner} wins.`; 
            gameResult = isMultiplayer ? (winner.charAt(0).toLowerCase() === myColor ? 'win' : 'loss') : (winner === 'White' ? 'win' : 'loss');
        } else if (!inCheck && !hasMoves) { 
            isGameOver = true; 
            statusText = 'Stalemate! It\'s a draw.'; 
            gameResult = 'draw';
        } else { 
            statusText = `${kingColor === 'w' ? 'White' : 'Black'}'s Turn`; 
            if (inCheck) { 
                statusText += ' - Check!'; 
                playSound('check'); 
            } 
        } 
        if (isGameOver && !gameOverSoundPlayed) { 
            playSound('gameOver'); 
            gameOverSoundPlayed = true; 
            if (window.parent && window.parent !== window && gameResult) {
                window.parent.postMessage({
                    type: 'ARCADE_GAME_OVER',
                    result: gameResult,
                    score: gameResult === 'win' ? 200 : (gameResult === 'draw' ? 50 : 0)
                }, '*');
            }
        } 
        statusElement.textContent = statusText; 
    }
    
    // --- MOVE VALIDATION & HELPERS ---
    function setupBoard() { return [['r', 'n', 'b', 'q', 'k', 'b', 'n', 'r'],['p', 'p', 'p', 'p', 'p', 'p', 'p', 'p'],[null, null, null, null, null, null, null, null],[null, null, null, null, null, null, null, null],[null, null, null, null, null, null, null, null],[null, null, null, null, null, null, null, null],['P', 'P', 'P', 'P', 'P', 'P', 'P', 'P'],['R', 'N', 'B', 'Q', 'K', 'B', 'N', 'R']];}
    function updateCastlingRights(from, to) { const piece = board[to.r][to.c] || ''; if (piece.toLowerCase() === 'k') { castlingRights[currentPlayer] = { k: false, q: false }; } if (from.r === 0 && from.c === 0) castlingRights.b.q = false; if (from.r === 0 && from.c === 7) castlingRights.b.k = false; if (from.r === 7 && from.c === 0) castlingRights.w.q = false; if (from.r === 7 && from.c === 7) castlingRights.w.k = false; }
    function getValidMovesForPiece(r, c) { const piece = board[r][c]; if (!piece) return []; const color = getPieceColor(piece); let moves = []; const pseudoLegalMoves = getPseudoLegalMoves(r, c, piece, color); moves = pseudoLegalMoves.filter(move => { const tempBoard = board.map(row => [...row]); tempBoard[move.r][move.c] = piece; tempBoard[r][c] = null; return !isKingInCheck(color, tempBoard); }); return moves; }
    function getPseudoLegalMoves(r, c, piece, color) { switch (piece.toLowerCase()) { case 'p': return getPawnMoves(r, c, color); case 'r': return getSlidingMoves(r, c, [[0, 1], [0, -1], [1, 0], [-1, 0]]); case 'n': return getKnightMoves(r, c); case 'b': return getSlidingMoves(r, c, [[1, 1], [1, -1], [-1, 1], [-1, -1]]); case 'q': return getSlidingMoves(r, c, [[0, 1], [0, -1], [1, 0], [-1, 0], [1, 1], [1, -1], [-1, 1], [-1, -1]]); case 'k': return getKingMoves(r, c, color); default: return []; } }
    function getPawnMoves(r, c, color) { const moves = []; const dir = color === 'w' ? -1 : 1; const startRow = color === 'w' ? 6 : 1; if (isValid(r + dir, c) && !board[r + dir][c]) { moves.push({ r: r + dir, c }); if (r === startRow && !board[r + 2 * dir][c]) { moves.push({ r: r + 2 * dir, c }); } } for (let dc of [-1, 1]) { if (isValid(r + dir, c + dc)) { const targetPiece = board[r + dir][c + dc]; if (targetPiece && getPieceColor(targetPiece) !== color) { moves.push({ r: r + dir, c: c + dc }); } if (enPassantTarget && enPassantTarget.r === r + dir && enPassantTarget.c === c + dc) { moves.push({ r: r + dir, c: c + dc }); } } } return moves; }
    function getSlidingMoves(r, c, directions) { const moves = []; const color = getPieceColor(board[r][c]); for (let [dr, dc] of directions) { let cr = r + dr, cc = c + dc; while (isValid(cr, cc)) { const targetPiece = board[cr][cc]; if (targetPiece) { if (getPieceColor(targetPiece) !== color) { moves.push({ r: cr, c: cc }); } break; } moves.push({ r: cr, c: cc }); cr += dr; cc += dc; } } return moves; }
    function getKnightMoves(r, c) { const moves = []; const color = getPieceColor(board[r][c]); const knightMoves = [ [2, 1], [2, -1], [-2, 1], [-2, -1], [1, 2], [1, -2], [-1, 2], [-1, -2] ]; for (let [dr, dc] of knightMoves) { const cr = r + dr, cc = c + dc; if (isValid(cr, cc)) { const targetPiece = board[cr][cc]; if (!targetPiece || getPieceColor(targetPiece) !== color) { moves.push({ r: cr, c: cc }); } } } return moves; }
    function getKingMoves(r, c, color) { const moves = []; const kingMoves = [ [1, 0], [-1, 0], [0, 1], [0, -1], [1, 1], [1, -1], [-1, 1], [-1, -1] ]; for (let [dr, dc] of kingMoves) { const cr = r + dr, cc = c + dc; if (isValid(cr, cc)) { const targetPiece = board[cr][cc]; if (!targetPiece || getPieceColor(targetPiece) !== color) { moves.push({ r: cr, c: cc }); } } } if (castlingRights[color].k && !board[r][c+1] && !board[r][c+2] && !isSquareAttacked(r, c, color) && !isSquareAttacked(r, c+1, color) && !isSquareAttacked(r, c+2, color)) { moves.push({ r, c: c + 2 }); } if (castlingRights[color].q && !board[r][c-1] && !board[r][c-2] && !board[r][c-3] && !isSquareAttacked(r, c, color) && !isSquareAttacked(r, c-1, color) && !isSquareAttacked(r, c-2, color)) { moves.push({ r, c: c - 2 }); } return moves; }
    function isKingInCheck(kingColor, boardState = board) { const kingPos = findKing(kingColor, boardState); if (!kingPos) return true; return isSquareAttacked(kingPos.r, kingPos.c, kingColor, boardState); }
    function isSquareAttacked(r, c, byColor, boardState = board) { const opponentColor = byColor === 'w' ? 'b' : 'w'; for (let i = 0; i < 8; i++) { for (let j = 0; j < 8; j++) { const piece = boardState[i][j]; if (piece && getPieceColor(piece) === opponentColor) { const moves = getPseudoLegalMoves(i, j, piece, opponentColor); if (moves.some(move => move.r === r && move.c === c)) { return true; } } } } return false; }
    function hasAnyValidMoves(color) { for (let r = 0; r < 8; r++) { for (let c = 0; c < 8; c++) { const piece = board[r][c]; if (piece && getPieceColor(piece) === color) { if (getValidMovesForPiece(r, c).length > 0) { return true; } } } } return false; }
    function isValid(r, c) { return r >= 0 && r < 8 && c >= 0 && c < 8; }
    function getPieceColor(piece) { return piece === piece.toUpperCase() ? 'w' : 'b'; }
    function findKing(color, boardState = board) { const kingChar = color === 'w' ? 'K' : 'k'; for (let r = 0; r < 8; r++) { for (let c = 0; c < 8; c++) { if (boardState[r][c] === kingChar) { return { r, c }; } } } return null; }
    
    // --- ARTIFICIAL INTELLIGENCE ---
    function makeAiMove() { if (isGameOver) return; let bestMove = null; if (aiLevel === 'easy') { bestMove = getEasyAiMove(); } else if (aiLevel === 'medium') { bestMove = getMediumAiMove(); } else if (aiLevel === 'hard') { bestMove = getHardAiMove(); } if (bestMove) { makeMove(bestMove.from, bestMove.to); } }
    function getAllValidMoves(color) { const allMoves = []; for (let r = 0; r < 8; r++) { for (let c = 0; c < 8; c++) { const piece = board[r][c]; if (piece && getPieceColor(piece) === color) { const moves = getValidMovesForPiece(r, c); moves.forEach(move => { allMoves.push({ from: { r, c }, to: move }); }); } } } return allMoves; }
    function getEasyAiMove() { const allMoves = getAllValidMoves('b'); if (allMoves.length === 0) return null; return allMoves[Math.floor(Math.random() * allMoves.length)]; }
    function getMediumAiMove() { const allMoves = getAllValidMoves('b'); if (allMoves.length === 0) return null; const pieceValues = { p: 1, n: 3, b: 3, r: 5, q: 9, k: 100 }; let bestMove = null; let maxScore = -1; for (const move of allMoves) { const capturedPiece = board[move.to.r][move.to.c]; let score = 0; if (capturedPiece) { score = pieceValues[capturedPiece.toLowerCase()]; } if (score > maxScore) { maxScore = score; bestMove = move; } } return maxScore > 0 ? bestMove : allMoves[Math.floor(Math.random() * allMoves.length)]; }
    function getHardAiMove() { const depth = 3; let bestMove = null; let bestValue = -Infinity; const allMoves = getAllValidMoves('b'); if (allMoves.length === 0) return null; for (const move of allMoves) { const tempBoard = board.map(row => [...row]); const piece = tempBoard[move.from.r][move.from.c]; tempBoard[move.to.r][move.to.c] = piece; tempBoard[move.from.r][move.from.c] = null; const boardValue = minimax(tempBoard, depth - 1, -Infinity, Infinity, false); if (boardValue > bestValue) { bestValue = boardValue; bestMove = move; } } return bestMove || getEasyAiMove(); }
    function minimax(tempBoard, depth, alpha, beta, isMaximizingPlayer) { if (depth === 0) { return -evaluateBoard(tempBoard); } const color = isMaximizingPlayer ? 'b' : 'w'; const allMoves = getAllValidMovesForBoard(tempBoard, color); if (isMaximizingPlayer) { let maxEval = -Infinity; for (const move of allMoves) { const childBoard = tempBoard.map(row => [...row]); const piece = childBoard[move.from.r][move.from.c]; childBoard[move.to.r][move.to.c] = piece; childBoard[move.from.r][move.from.c] = null; const eval = minimax(childBoard, depth - 1, alpha, beta, false); maxEval = Math.max(maxEval, eval); alpha = Math.max(alpha, eval); if (beta <= alpha) break; } return maxEval; } else { let minEval = Infinity; for (const move of allMoves) { const childBoard = tempBoard.map(row => [...row]); const piece = childBoard[move.from.r][move.from.c]; childBoard[move.to.r][move.to.c] = piece; childBoard[move.from.r][move.from.c] = null; const eval = minimax(childBoard, depth - 1, alpha, beta, true); minEval = Math.min(minEval, eval); beta = Math.min(beta, eval); if (beta <= alpha) break; } return minEval; } }
    function evaluateBoard(evalBoard) { let totalEvaluation = 0; const pieceValues = { p: 1, n: 3, b: 3.2, r: 5, q: 9, k: 100 }; for (let r = 0; r < 8; r++) { for (let c = 0; c < 8; c++) { const piece = evalBoard[r][c]; if (piece) { const value = pieceValues[piece.toLowerCase()]; totalEvaluation += getPieceColor(piece) === 'w' ? value : -value; } } } return totalEvaluation; }
    function getAllValidMovesForBoard(tempBoard, color) { const allMoves = []; for (let r = 0; r < 8; r++) { for (let c = 0; c < 8; c++) { const piece = tempBoard[r][c]; if (piece && getPieceColor(piece) === color) { const moves = getPseudoLegalMoves(r, c, piece, color); moves.forEach(move => allMoves.push({ from: { r, c }, to: move })); } } } return allMoves; }
});
