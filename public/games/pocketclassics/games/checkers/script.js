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
        gameOver: document.getElementById('sound-game-over'),
        menuMusic: document.getElementById('music-menu'),
        gameMusic: document.getElementById('music-game'),
        uiClick: document.getElementById('sound-ui-click'),
        gameStart: document.getElementById('sound-game-start'),
        select: document.getElementById('sound-select'),
        invalid: document.getElementById('sound-invalid')
    };
    
    let board = [], currentPlayer = 'w', selectedPiece = null, validMoves = [], gameMode = null, aiLevel = 'easy', isGameOver = false, lastMove = { from: null, to: null }, mandatoryJumps = [];
    
    // Upgraded Sound State
    let isMusicEnabled = true;
    let isSfxEnabled = true;
    let gameOverSoundPlayed = false;

    isMusicEnabled = localStorage.getItem('arc_music_enabled') !== 'false';
    isSfxEnabled = localStorage.getItem('arc_sfx_enabled') !== 'false';

    // --- INITIALIZATION & MENU ---
    function showMainMenu() { gameContainer.classList.add('hidden'); mainMenu.classList.remove('hidden'); aiDifficultySelector.classList.add('hidden'); stopAllMusic(); playMusic('menuMusic'); }
    function initializeGame(mode) {
        playSound('gameStart');
        gameMode = mode;
        if (mode === 'pvai') { aiLevel = aiDifficulty.value; }
        board = setupBoard(); currentPlayer = 'w'; selectedPiece = null; validMoves = []; isGameOver = false; gameOverSoundPlayed = false; lastMove = { from: null, to: null };
        mainMenu.classList.add('hidden'); gameContainer.classList.remove('hidden');
        stopAllMusic(); playMusic('gameMusic');
        renderBoard(); updateStatus();
    }
    showMainMenu();

    // --- SOUND SYSTEM ---
    function playSound(soundKey) { if (!isSfxEnabled) return; const sound = sounds[soundKey]; if (sound) { sound.currentTime = 0; sound.play().catch(e => {}); } }
    function playMusic(musicKey) {
        if (!isMusicEnabled) return;
        const music = sounds[musicKey];
        if (music) { music.currentTime = 0; music.play().catch(e => {}); }
    }
    function stopAllMusic() { if (sounds.menuMusic) sounds.menuMusic.pause(); if (sounds.gameMusic) sounds.gameMusic.pause(); }

    // --- EVENT HANDLERS ---
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
                makeMove(m.from, m.to, true);
            }
        }
    });

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
    if (settingsBtn) settingsBtn.addEventListener('click', () => { playSound('uiClick'); settingsDialog.classList.remove('hidden'); });
    if (closeSettingsBtn) closeSettingsBtn.addEventListener('click', () => { playSound('uiClick'); settingsDialog.classList.add('hidden'); });
    if (settingsDialog) {
        settingsDialog.addEventListener('click', (event) => { if (event.target === settingsDialog) { playSound('uiClick'); settingsDialog.classList.add('hidden'); } });
    }
    if (musicToggle) {
        musicToggle.addEventListener('change', () => {
            isMusicEnabled = musicToggle.checked;
            playSound('uiClick');
            if (isMusicEnabled) {
                if (!gameContainer.classList.contains('hidden')) {
                    playMusic('gameMusic');
                } else {
                    playMusic('menuMusic');
                }
            } else {
                stopAllMusic();
            }
        });
    }
    if (sfxToggle) {
        sfxToggle.addEventListener('change', () => { isSfxEnabled = sfxToggle.checked; playSound('uiClick'); });
    }

    // --- RENDERING & INTERACTION ---
    function renderBoard() {
        boardElement.innerHTML = '';
        for (let r = 0; r < 8; r++) { for (let c = 0; c < 8; c++) { const square = document.createElement('div'); square.classList.add('square', (r + c) % 2 === 0 ? 'light' : 'dark'); square.dataset.row = r; square.dataset.col = c; const pieceChar = board[r][c]; if (pieceChar) { const pieceElement = document.createElement('div'); pieceElement.classList.add('piece'); pieceElement.classList.add(getPieceColor(pieceChar) === 'w' ? 'white-piece' : 'black-piece'); if (isKing(pieceChar)) { pieceElement.classList.add('king'); } square.appendChild(pieceElement); } if ((lastMove.from && lastMove.from.r === r && lastMove.from.c === c) || (lastMove.to && lastMove.to.r === r && lastMove.to.c === c)) { square.classList.add('last-move'); } boardElement.appendChild(square); } }
        boardElement.querySelectorAll('.square').forEach(square => square.addEventListener('click', handleSquareClick));
        highlightValidMoves();
    }
    function highlightValidMoves() { document.querySelectorAll('.valid-move-dot').forEach(dot => dot.remove()); document.querySelectorAll('.selected').forEach(sel => sel.classList.remove('selected')); if (selectedPiece) { boardElement.querySelector(`[data-row='${selectedPiece.r}'][data-col='${selectedPiece.c}']`).classList.add('selected'); validMoves.forEach(move => { const moveSquare = boardElement.querySelector(`[data-row='${move.to.r}'][data-col='${move.to.c}']`); if (moveSquare) { const dot = document.createElement('div'); dot.classList.add('valid-move-dot'); moveSquare.appendChild(dot); } }); } }
    
    function handleSquareClick(event) {
        if (isGameOver) return;
        const square = event.currentTarget;
        const r = parseInt(square.dataset.row);
        const c = parseInt(square.dataset.col);
        const piece = board[r][c];
        const move = validMoves.find(m => m.to.r === r && m.to.c === c);
        if (move) { makeMove(move.from, move.to); } 
        else {
            deselect();
            if (piece && getPieceColor(piece) === currentPlayer) { selectPiece(r, c); } 
            else { playSound('invalid'); }
        }
    }

    function selectPiece(r, c) {
        if (mandatoryJumps.length > 0 && !mandatoryJumps.some(m => m.from.r === r && m.from.c === c)) { playSound('invalid'); return; }
        playSound('select');
        selectedPiece = { r, c };
        validMoves = mandatoryJumps.length > 0 ? mandatoryJumps.filter(m => m.from.r === r && m.from.c === c) : getAllValidMovesForPiece(r, c);
        renderBoard();
    }

    function deselect() { selectedPiece = null; validMoves = []; renderBoard(); }
    
    function makeMove(from, to) {
        const piece = board[from.r][from.c];
        const isJump = Math.abs(from.r - to.r) === 2;
        if (isJump) { playSound('capture'); const capturedR = (from.r + to.r) / 2; const capturedC = (from.c + to.c) / 2; board[capturedR][capturedC] = null; } 
        else { playSound('move'); }
        board[to.r][to.c] = piece;
        board[from.r][from.c] = null;
        if ((getPieceColor(piece) === 'w' && to.r === 0) || (getPieceColor(piece) === 'b' && to.r === 7)) { if (!isKing(piece)) { board[to.r][to.c] = piece + 'k'; } }
        lastMove = { from, to };
        if (isJump) {
            const nextJumps = getJumpMoves(to.r, to.c, board[to.r][to.c], board);
            if (nextJumps.length > 0) {
                selectedPiece = { r: to.r, c: to.c }; validMoves = nextJumps; mandatoryJumps = nextJumps; renderBoard();
                if (gameMode === 'pvai' && currentPlayer === 'b') { setTimeout(() => makeMove(validMoves[0].from, validMoves[0].to), 500); }
                return;
            }
        }
        finishMove();
    }

    function finishMove() { deselect(); switchPlayer(); renderBoard(); updateStatus(); if (!isGameOver && gameMode === 'pvai' && currentPlayer === 'b') { setTimeout(makeAiMove, 500); } }
    function switchPlayer() { currentPlayer = (currentPlayer === 'w') ? 'b' : 'w'; }
    
    function updateStatus() {
        mandatoryJumps = getAllPlayerMoves(currentPlayer, board).filter(m => m.isJump);
        const regularMoves = getAllPlayerMoves(currentPlayer, board).filter(m => !m.isJump);
        let statusText = '';
        if (mandatoryJumps.length === 0 && regularMoves.length === 0) {
            isGameOver = true; statusText = `No moves left! ${currentPlayer === 'w' ? 'Black' : 'White'} wins.`;
        } else {
            statusText = `${currentPlayer === 'w' ? 'White' : 'Black'}'s Turn`;
            if (mandatoryJumps.length > 0) { statusText += ' - Jump is mandatory!'; }
        }
        if (isGameOver && !gameOverSoundPlayed) { 
            playSound('gameOver'); 
            gameOverSoundPlayed = true; 
            if (window.parent && window.parent !== window) {
                const winnerColor = currentPlayer === 'w' ? 'b' : 'w';
                const result = isMultiplayer ? (winnerColor === myColor ? 'win' : 'loss') : (winnerColor === 'w' ? 'win' : 'loss');
                window.parent.postMessage({
                    type: 'ARCADE_GAME_OVER',
                    result: result,
                    score: result === 'win' ? 150 : 0
                }, '*');
            }
        }
        statusElement.textContent = statusText;
    }

    // --- CHECKERS LOGIC ---
    function setupBoard() { const b = Array(8).fill(null).map(() => Array(8).fill(null)); for (let r = 0; r < 3; r++) { for (let c = 0; c < 8; c++) { if ((r + c) % 2 !== 0) b[r][c] = 'b'; } } for (let r = 5; r < 8; r++) { for (let c = 0; c < 8; c++) { if ((r + c) % 2 !== 0) b[r][c] = 'w'; } } return b; }
    function getPieceColor(p) { return p ? p.charAt(0) : ''; }
    function isKing(p) { return p ? p.length > 1 : false; }
    function isValid(r, c) { return r >= 0 && r < 8 && c >= 0 && c < 8; }
    function getAllPlayerMoves(color, currentBoard) { let moves = []; for (let r = 0; r < 8; r++) { for (let c = 0; c < 8; c++) { if (currentBoard[r][c] && getPieceColor(currentBoard[r][c]) === color) { moves.push(...getAllValidMovesForPiece(r, c, currentBoard)); } } } const jumps = moves.filter(m => m.isJump); return jumps.length > 0 ? jumps : moves; }
    function getAllValidMovesForPiece(r, c, currentBoard = board) { const piece = currentBoard[r][c]; return [...getJumpMoves(r, c, piece, currentBoard), ...getStandardMoves(r, c, piece, currentBoard)]; }
    function getStandardMoves(r, c, piece, board) { const moves = []; const color = getPieceColor(piece); const dirs = isKing(piece) ? [[-1, -1], [-1, 1], [1, -1], [1, 1]] : (color === 'w' ? [[-1, -1], [-1, 1]] : [[1, -1], [1, 1]]); for (const [dr, dc] of dirs) { const newR = r + dr, newC = c + dc; if (isValid(newR, newC) && !board[newR][newC]) { moves.push({ from: { r, c }, to: { r: newR, c: newC }, isJump: false }); } } return moves; }
    
    function getJumpMoves(r, c, piece, board) {
        const jumps = [];
        const color = getPieceColor(piece);
        const opponentColor = color === 'w' ? 'b' : 'w'; // Define the opponent's color for clarity
        const dirs = isKing(piece) ? [[-1, -1], [-1, 1], [1, -1], [1, 1]] : (color === 'w' ? [[-1, -1], [-1, 1]] : [[1, -1], [1, 1]]);

        for (const [dr, dc] of dirs) {
            const opponentR = r + dr, opponentC = c + dc;
            const landingR = r + 2 * dr, landingC = c + 2 * dc;

            if (isValid(landingR, landingC) && !board[landingR][landingC]) {
                const pieceToJump = board[opponentR][opponentC];

                // CRITICAL FIX: Check if the piece being jumped over exists AND belongs to the opponent.
                if (pieceToJump && getPieceColor(pieceToJump) === opponentColor) {
                    jumps.push({ from: { r, c }, to: { r: landingR, c: landingC }, isJump: true });
                }
            }
        }
        return jumps;
    }
    
    // --- AI LOGIC (Unchanged from previous correct version) ---
    function makeAiMove() { if (isGameOver) return; let bestMove = null; if (aiLevel === 'easy') { bestMove = getEasyAiMove(); } else if (aiLevel === 'medium') { bestMove = getMediumAiMove(); } else if (aiLevel === 'hard') { bestMove = getHardAiMove(); } if (bestMove) { makeMove(bestMove.from, bestMove.to); } }
    function getEasyAiMove() { const allMoves = getAllPlayerMoves('b', board); return allMoves.length === 0 ? null : allMoves[Math.floor(Math.random() * allMoves.length)]; }
    function getMediumAiMove() { const allMoves = getAllPlayerMoves('b', board); if (allMoves.length === 0) return null; const jumps = allMoves.filter(m => m.isJump); return jumps.length > 0 ? jumps[Math.floor(Math.random() * jumps.length)] : allMoves[Math.floor(Math.random() * allMoves.length)]; }
    function getHardAiMove() { const result = minimax(board, 3, -Infinity, Infinity, true); return result.move; }
    function minimax(currentBoard, depth, alpha, beta, maximizingPlayer) { if (depth === 0) return { score: evaluateBoard(currentBoard) }; const color = maximizingPlayer ? 'b' : 'w'; const allMoves = getAllPlayerMoves(color, currentBoard); if (allMoves.length === 0) return { score: maximizingPlayer ? -Infinity : Infinity }; let bestMove = null; let bestValue = maximizingPlayer ? -Infinity : Infinity; for (const move of allMoves) { const { newBoard, isMultiJump } = simulateMove(currentBoard, move); let evalNode; if (isMultiJump) { evalNode = minimax(newBoard, depth, alpha, beta, maximizingPlayer); } else { evalNode = minimax(newBoard, depth - 1, alpha, beta, !maximizingPlayer); } if (maximizingPlayer) { if (evalNode.score > bestValue) { bestValue = evalNode.score; bestMove = move; } alpha = Math.max(alpha, bestValue); } else { if (evalNode.score < bestValue) { bestValue = evalNode.score; bestMove = move; } beta = Math.min(beta, bestValue); } if (beta <= alpha) break; } return { score: bestValue, move: bestMove }; }
    function simulateMove(currentBoard, move) { const newBoard = currentBoard.map(row => [...row]); const piece = newBoard[move.from.r][move.from.c]; newBoard[move.to.r][move.to.c] = piece; newBoard[move.from.r][move.from.c] = null; let isMultiJump = false; if (move.isJump) { newBoard[(move.from.r + move.to.r) / 2][(move.from.c + move.to.c) / 2] = null; if (getJumpMoves(move.to.r, move.to.c, piece, newBoard).length > 0) { isMultiJump = true; } } if ((getPieceColor(piece) === 'w' && move.to.r === 0) || (getPieceColor(piece) === 'b' && move.to.r === 7)) { newBoard[move.to.r][move.to.c] = getPieceColor(piece) + 'k'; } return { newBoard, isMultiJump }; }
    function evaluateBoard(evalBoard) { let total = 0; for (let r = 0; r < 8; r++) { for (let c = 0; c < 8; c++) { const p = evalBoard[r][c]; if (!p) continue; const color = getPieceColor(p); let value = isKing(p) ? 2 : 1; if (color === 'w') { value += (7 - r) * 0.1; total += value; } else { value += r * 0.1; total -= value; } } } return total; }
});
