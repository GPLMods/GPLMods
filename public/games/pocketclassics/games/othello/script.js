document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const boardContainer = document.getElementById('board-container');
    const playerTurnEl = document.getElementById('player-turn');
    const blackScoreEl = document.getElementById('black-score');
    const whiteScoreEl = document.getElementById('white-score');
    const statusMessageEl = document.getElementById('status-message');
    const menuOverlay = document.getElementById('menu-overlay');
    const mainMenu = document.getElementById('main-menu');
    const aiDifficultyMenu = document.getElementById('ai-difficulty-menu');
    const gameScreen = document.getElementById('game-screen');
    const settingsMenu = document.getElementById('settings-menu');
    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');
    const bgMusic = document.getElementById('bg-music');
    const sfxSound = document.getElementById('sfx-sound'); // This is now the "flip" sound
    const winSound = document.getElementById('win-sound');
    const uiClickSound = document.getElementById('ui-click-sound'); // NEW: Get the UI click sound element
    const winPopupOverlay = document.getElementById('win-popup-overlay');
    const winParticlesCanvas = document.getElementById('win-particles-canvas');
    const winResultEl = document.getElementById('win-result');
    const winScoreEl = document.getElementById('win-score');
    
    // --- Game State (unchanged) ---
    const BOARD_SIZE = 8, PLAYER_BLACK = 1, PLAYER_WHITE = 2;
    const DIRECTIONS = [ [-1, -1], [-1, 0], [-1, 1], [0, -1], [0, 1], [1, -1], [1, 0], [1, 1] ];
    let board = [], currentPlayer, gameMode, aiDifficulty, gameOver;
    let particles = [];
    let isMusicOn = true, isSfxOn = true;

    // --- UPDATED, ROBUST AUDIO LOGIC ---
    let audioContextUnlocked = false;

    function unlockAllAudio() {
        if (audioContextUnlocked) return;
        bgMusic.play().catch(() => {}); bgMusic.pause();
        sfxSound.play().catch(() => {}); sfxSound.pause();
        winSound.play().catch(() => {}); winSound.pause();
        uiClickSound.play().catch(() => {}); uiClickSound.pause(); // NEW: Unlock the UI sound
        audioContextUnlocked = true;
        console.log("Audio contexts have been unlocked by user interaction.");
    }

    function playSfx() { // This function now ONLY plays the piece "flip" sound
        unlockAllAudio();
        if (isSfxOn && sfxSound.src) { sfxSound.currentTime = 0; sfxSound.play().catch(e => {}); }
    }
    
    // NEW: A separate function for playing the UI button "pop" sound
    function playUiClickSound() {
        unlockAllAudio();
        if (isSfxOn && uiClickSound.src) { uiClickSound.currentTime = 0; uiClickSound.play().catch(e => {}); }
    }
    
    function playWinSound() { // This function is unchanged
        unlockAllAudio();
        if (isSfxOn && winSound.src) { winSound.currentTime = 0; winSound.play().catch(e => {}); }
    }

    musicToggle.addEventListener('change', (e) => {
        isMusicOn = e.target.checked;
        if (isMusicOn) { unlockAllAudio(); bgMusic.play().catch(e => console.error("Error playing background music:", e)); } 
        else { bgMusic.pause(); }
    });

    sfxToggle.addEventListener('change', (e) => isSfxOn = e.target.checked);
    
    // UPDATED: This listener now calls the new UI click sound function
    document.addEventListener('click', (e) => {
        if (e.target.matches('button')) playUiClickSound();
    });
    
    // --- Menu & Navigation Logic (unchanged from your version) ---
    const setupButton = (id, callback) => document.getElementById(id).addEventListener('click', callback);
    setupButton('pvp-btn', () => { gameMode = 'pvp'; startGame(); });
    setupButton('pvai-btn', () => { mainMenu.classList.add('hidden'); aiDifficultyMenu.classList.remove('hidden'); });
    aiDifficultyMenu.addEventListener('click', (e) => { if (e.target.tagName === 'BUTTON' && e.target.dataset.difficulty) { gameMode = 'pvai'; aiDifficulty = e.target.dataset.difficulty; startGame(); } });
    setupButton('back-to-main-btn', () => { aiDifficultyMenu.classList.add('hidden'); mainMenu.classList.remove('hidden'); });
    setupButton('open-settings-btn', () => { menuOverlay.classList.add('invisible'); settingsMenu.classList.remove('invisible'); });
    setupButton('close-settings-btn', () => { settingsMenu.classList.add('invisible'); menuOverlay.classList.remove('invisible'); });
    setupButton('home-btn', () => { 
        if (window.parent && window.parent !== window) {
            window.parent.postMessage({ type: 'ARCADE_EXIT' }, '*');
        } else {
            window.location.href = '/games/hub'; 
        }
    });
    const goBackToMenu = () => { bgMusic.pause(); winPopupOverlay.classList.add('invisible'); gameScreen.classList.add('hidden'); menuOverlay.classList.remove('invisible'); mainMenu.classList.remove('hidden'); particles = []; };
    setupButton('back-to-menu-game-btn', goBackToMenu);
    setupButton('win-back-to-menu-btn', goBackToMenu);
    setupButton('play-again-btn', () => { winPopupOverlay.classList.add('invisible'); particles = []; initGame(); });

    function startGame() {
        unlockAllAudio();
        menuOverlay.classList.add('invisible'); gameScreen.classList.remove('hidden'); aiDifficultyMenu.classList.add('hidden');
        if (isMusicOn && bgMusic.src) bgMusic.play().catch(e => console.error("Error playing music on start:", e));
        initGame();
    }
    
    // --- Core Game Logic and Rendering ---
    function initGame() { board = Array(BOARD_SIZE).fill(0).map(() => Array(BOARD_SIZE).fill(0)); board[3][3] = PLAYER_WHITE; board[3][4] = PLAYER_BLACK; board[4][3] = PLAYER_BLACK; board[4][4] = PLAYER_WHITE; currentPlayer = PLAYER_BLACK; gameOver = false; statusMessageEl.textContent = ''; boardContainer.style.pointerEvents = 'auto'; renderBoard(); updateUI(); highlightValidMoves(); }
    
    boardContainer.addEventListener('click', (e) => { if (gameOver) return; const highlighter = e.target.closest('.valid-move-highlighter'); if (highlighter) { playSfx(); const cell = highlighter.parentElement; makeMove(parseInt(cell.dataset.row), parseInt(cell.dataset.col)); } });
    
    function makeMove(row, col) { const piecesToFlip = getPiecesToFlip(row, col, currentPlayer); if (piecesToFlip.length === 0) return; boardContainer.style.pointerEvents = 'none'; document.querySelectorAll('.valid-move-highlighter').forEach(h => h.remove()); statusMessageEl.textContent = ''; board[row][col] = currentPlayer; piecesToFlip.forEach(p => { board[p.row][p.col] = currentPlayer; }); const playerClass = currentPlayer === 1 ? 'black' : 'white'; const opponentClass = currentPlayer === 1 ? 'white' : 'black'; const newPieceCell = boardContainer.children[row * 8 + col]; const newPiece = document.createElement('div'); newPiece.className = `piece ${playerClass}`; newPiece.style.transform = 'scale(0)'; newPieceCell.appendChild(newPiece); requestAnimationFrame(() => { newPiece.style.transform = 'scale(1)'; }); let maxDelay = 0; piecesToFlip.forEach((p, i) => { const delay = 100 + 50 * i; maxDelay = delay; setTimeout(() => { const pieceToFlip = boardContainer.children[p.row * 8 + p.col].querySelector('.piece'); if (pieceToFlip) { pieceToFlip.style.transform = 'rotateY(180deg)'; setTimeout(() => { pieceToFlip.classList.remove(opponentClass); pieceToFlip.classList.add(playerClass); pieceToFlip.style.transform = ''; }, 300); } }, delay); }); setTimeout(switchPlayer, maxDelay + 600); }
    function switchPlayer() { updateUI(); const opponent = (currentPlayer === 1) ? 2 : 1; if (getValidMoves(opponent).length > 0) { currentPlayer = opponent; } else if (getValidMoves(currentPlayer).length > 0) { statusMessageEl.textContent = `${opponent === 1 ? 'Black' : 'White'} has no moves! Turn skipped.`; } else { endGame(); return; } updateUI(); highlightValidMoves(); if (!gameOver && gameMode === 'pvai' && currentPlayer === 2) { setTimeout(makeAiMove, 800); } else { boardContainer.style.pointerEvents = 'auto'; } }
    function getValidMoves(player) { const moves = []; for (let r = 0; r < 8; r++) for (let c = 0; c < 8; c++) { if (board[r][c] === 0 && getPiecesToFlip(r, c, player).length > 0) moves.push({ row: r, col: c }); } return moves; }
    function getPiecesToFlip(row, col, player) { const opponent = (player === 1) ? 2 : 1; let allPiecesToFlip = []; for (const [dr, dc] of DIRECTIONS) { let path = [], r = row + dr, c = col + dc; while (r >= 0 && r < 8 && c >= 0 && c < 8 && board[r][c] === opponent) { path.push({ row: r, col: c }); r += dr; c += dc; } if (r >= 0 && r < 8 && c >= 0 && c < 8 && board[r][c] === player) { allPiecesToFlip.push(...path); } } return allPiecesToFlip; }
    function endGame() { 
        playWinSound(); 
        gameOver = true; 
        boardContainer.style.pointerEvents = 'none'; 
        const scores = getScores(); 
        let winner; 
        let result = 'draw';
        if (scores.black > scores.white) { 
            winResultEl.textContent = "Black Wins!"; 
            winner = 'black'; 
            result = 'win';
        } else if (scores.white > scores.black) { 
            winResultEl.textContent = "White Wins!"; 
            winner = 'white'; 
            result = 'loss';
        } else { 
            winResultEl.textContent = "It's a Draw!"; 
            winner = 'draw'; 
            result = 'draw';
        } 
        winScoreEl.textContent = `Final Score: Black ${scores.black} - ${scores.white} White`; 
        winPopupOverlay.classList.remove('invisible'); 
        initParticles(winner); 

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: result,
                score: Math.max(scores.black, scores.white) * 10
            }, '*');
        }
    }
    function renderBoard() { boardContainer.innerHTML = ''; for (let r = 0; r < 8; r++) for (let c = 0; c < 8; c++) { const cell = document.createElement('div'); cell.className = 'cell'; cell.dataset.row = r; cell.dataset.col = c; if (board[r][c] !== 0) { const piece = document.createElement('div'); piece.className = `piece ${board[r][c] === 1 ? 'black' : 'white'}`; cell.appendChild(piece); } boardContainer.appendChild(cell); } }
    function updateUI() { const scores = getScores(); blackScoreEl.textContent = scores.black; whiteScoreEl.textContent = scores.white; if (!gameOver) { playerTurnEl.innerHTML = `<div class="piece ${currentPlayer === 1 ? 'black' : 'white'}" style="width:24px; height:24px; display:inline-block; vertical-align:middle; margin: 0 10px;"></div>`; } else { playerTurnEl.innerHTML = ''; } }
    function getScores() { return board.flat().reduce((acc, cell) => { if (cell === 1) acc.black++; else if (cell === 2) acc.white++; return acc; }, { black: 0, white: 0 });}
    function highlightValidMoves() { document.querySelectorAll('.valid-move-highlighter').forEach(h => h.remove()); if(gameOver) return; getValidMoves(currentPlayer).forEach(move => { const cell = boardContainer.children[move.row * 8 + move.col]; const highlighter = document.createElement('div'); highlighter.className = 'valid-move-highlighter'; cell.appendChild(highlighter); }); }
    // UPDATED: AI move now correctly calls playSfx(), the "flip" sound.
    function makeAiMove() { if (gameOver) return; const validMoves = getValidMoves(2); if (validMoves.length === 0) return; let bestMove; switch (aiDifficulty) { case 'easy': bestMove = validMoves[Math.floor(Math.random() * validMoves.length)]; break; case 'medium': bestMove = validMoves.reduce((best, move) => { const flips = getPiecesToFlip(move.row, move.col, 2).length; return flips > best.flips ? { move, flips } : best; }, { move: validMoves[0], flips: 0 }).move; break; case 'hard': const w = [ [120,-20,20,5,5,20,-20,120],[-20,-40,-5,-5,-5,-5,-40,-20],[20,-5,15,3,3,15,-5,20],[5,-5,3,3,3,3,-5,5],[5,-5,3,3,3,3,-5,5],[20,-5,15,3,3,15,-5,20],[-20,-40,-5,-5,-5,-5,-40,-20],[120,-20,20,5,5,20,-20,120]]; bestMove = validMoves.reduce((best, move) => { const score = w[move.row][move.col]; return score > best.score ? { move, score } : best; }, { move: null, score: -Infinity }).move || validMoves[0]; break; } playSfx(); makeMove(bestMove.row, bestMove.col); }
    function initParticles(winner) { const ctx = winParticlesCanvas.getContext('2d'); winParticlesCanvas.width = window.innerWidth; winParticlesCanvas.height = window.innerHeight; const colors = { black: ['#111', '#333', '#555'], white: ['#fff', '#f0f0f0', '#ddd'], draw: ['#111', '#333', '#fff', '#ddd'] }[winner]; particles = []; for (let i = 0; i < 150; i++) { particles.push({ x: winParticlesCanvas.width / 2, y: winParticlesCanvas.height / 2, vx: (Math.random() - 0.5) * 8, vy: (Math.random() - 0.5) * 8, size: Math.random() * 3 + 2, color: colors[Math.floor(Math.random() * colors.length)], life: Math.random() * 100 + 50 }); } animateParticles(ctx); }
    function animateParticles(ctx) { if (particles.length === 0) { ctx.clearRect(0, 0, winParticlesCanvas.width, winParticlesCanvas.height); return; } requestAnimationFrame(() => animateParticles(ctx)); ctx.clearRect(0, 0, winParticlesCanvas.width, winParticlesCanvas.height); for (let i = particles.length - 1; i >= 0; i--) { const p = particles[i]; p.x += p.vx; p.y += p.vy; p.vy += 0.08; p.life--; if (p.life <= 0) { particles.splice(i, 1); continue; } ctx.globalAlpha = p.life / 100; ctx.fillStyle = p.color; ctx.beginPath(); ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1; } }
});
