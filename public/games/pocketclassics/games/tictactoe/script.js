document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const mainMenu = document.getElementById('main-menu');
    const settingsScreen = document.getElementById('settings-screen');
    const gameContainer = document.getElementById('game-container');
    const winPopup = document.getElementById('win-popup');
    const vsPlayerBtn = document.getElementById('vs-player-btn');
    const vsAiBtn = document.getElementById('vs-ai-btn');
    const settingsBtn = document.getElementById('settings-btn');
    const homeBtn = document.getElementById('home-btn'); // NEW: Get the home button
    const aiDifficultySelection = document.getElementById('ai-difficulty-selection');
    const difficultyBtns = document.querySelectorAll('.difficulty-btn');
    const board = document.getElementById('board');
    const cells = document.querySelectorAll('.cell');
    const statusDisplay = document.getElementById('status-display');
    const mainMenuBtn = document.getElementById('main-menu-btn');
    const winMessage = document.getElementById('win-message');
    const playAgainBtn = document.getElementById('play-again-btn');
    const lineCanvas = document.getElementById('line-canvas');
    const lineCtx = lineCanvas.getContext('2d');
    const particleCanvas = document.getElementById('particle-canvas');
    const particleCtx = particleCanvas.getContext('2d');
    const backToMenuBtn = document.getElementById('back-to-menu-btn');
    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');

    // --- Audio Elements ---
    const backgroundMusic = document.getElementById('background-music');
    const clickSound = new Audio('audio/click.wav');
    const winSound = new Audio('audio/win.wav');
    const drawSound = new Audio('audio/draw.wav');
    
    // --- Game & Settings State ---
    let gameMode = null, aiDifficulty = null, currentPlayer = 'X', boardState = Array(9).fill(null), gameActive = false, particleAnimationId, isMusicOn = true, isSfxOn = true;
    const winningCombinations = [[0, 1, 2], [3, 4, 5], [6, 7, 8], [0, 3, 6], [1, 4, 7], [2, 5, 8], [0, 4, 8], [2, 4, 6]];

    // --- Audio & Settings Logic (Unchanged) ---
    function loadSettings() {
        const musicSetting = localStorage.getItem('ticTacToeMusic'), sfxSetting = localStorage.getItem('ticTacToeSfx');
        isMusicOn = musicSetting === null ? true : JSON.parse(musicSetting);
        isSfxOn = sfxSetting === null ? true : JSON.parse(sfxSetting);
        if (musicToggle) musicToggle.checked = isMusicOn; 
        if (sfxToggle) sfxToggle.checked = isSfxOn; 
        updateMusicState();
    }
    function updateMusicState() { 
        if (isMusicOn && window.parent === window && backgroundMusic) { 
            backgroundMusic.play().catch(e => {}); 
        } else if (backgroundMusic) { 
            backgroundMusic.pause(); 
        } 
    }
    function playSound(sound) { if (isSfxOn) { sound.currentTime = 0; sound.play(); } }

    // --- Screen Navigation & Main Menu Buttons ---
    function showScreen(screenToShow) {
        [mainMenu, settingsScreen, gameContainer, winPopup].forEach(screen => { if (screen) { screen.classList.add('hidden'); screen.classList.remove('active'); } });
        if (screenToShow) {
            screenToShow.classList.remove('hidden');
            if (screenToShow === mainMenu || screenToShow === settingsScreen) { screenToShow.classList.add('active'); }
        }
    }

    vsPlayerBtn?.addEventListener('click', () => { playSound(clickSound); gameMode = 'pvp'; startGame(); });
    vsAiBtn?.addEventListener('click', () => { playSound(clickSound); aiDifficultySelection.classList.remove('hidden'); });
    settingsBtn?.addEventListener('click', () => { playSound(clickSound); showScreen(settingsScreen); });
    backToMenuBtn?.addEventListener('click', () => { playSound(clickSound); showScreen(mainMenu); });
    
    let isMultiplayer = false;
    let mySymbol = 'X';
    let isMyTurn = true;

    // Listen for parent messages
    window.addEventListener('message', (event) => {
        if (!event.data || !event.data.type) return;
        if (event.data.type === 'ARCADE_MATCH_READY') {
            isMultiplayer = true;
            gameMode = 'pvp';
            // First player is X, second is O
            mySymbol = event.data.isHost ? 'X' : 'O';
            isMyTurn = mySymbol === 'X';
            startGame();
            statusDisplay.textContent = isMyTurn ? `Your Turn (${mySymbol})` : `Opponent's Turn (${mySymbol === 'X' ? 'O' : 'X'})`;
        } else if (event.data.type === 'ARCADE_OPPONENT_MOVE') {
            const cellIdx = event.data.move && event.data.move.cellIndex;
            if (cellIdx !== undefined && boardState[cellIdx] === null) {
                const oppSymbol = mySymbol === 'X' ? 'O' : 'X';
                makeMove(cellIdx, oppSymbol);
                playSound(clickSound);
                if (!checkGameStatus()) {
                    isMyTurn = true;
                    statusDisplay.textContent = `Your Turn (${mySymbol})`;
                }
            }
        }
    });

    homeBtn?.addEventListener('click', () => {
        playSound(clickSound);
        if (window.parent && window.parent !== window) {
            window.parent.postMessage({ type: 'ARCADE_EXIT' }, '*');
        } else {
            window.location.href = '/games/hub';
        }
    });

    difficultyBtns.forEach(button => { button.addEventListener('click', () => { playSound(clickSound); gameMode = 'ai'; aiDifficulty = button.dataset.difficulty; startGame(); }); });
    mainMenuBtn.addEventListener('click', () => { playSound(clickSound); showScreen(mainMenu); aiDifficultySelection.classList.add('hidden'); if (particleAnimationId) cancelAnimationFrame(particleAnimationId); });
    playAgainBtn.addEventListener('click', () => { playSound(clickSound); startGame(); });
    musicToggle.addEventListener('change', (e) => { playSound(clickSound); isMusicOn = e.target.checked; localStorage.setItem('ticTacToeMusic', isMusicOn); updateMusicState(); });
    sfxToggle.addEventListener('change', (e) => { playSound(clickSound); isSfxOn = e.target.checked; localStorage.setItem('ticTacToeSfx', isSfxOn); });

    // --- Game Logic ---
    function startGame(){
        gameActive = true;
        currentPlayer = "X";
        boardState.fill(null);
        cells.forEach(e => { e.textContent = ""; e.classList.remove("x","o"); });
        statusDisplay.textContent = isMultiplayer ? (isMyTurn ? `Your Turn (${mySymbol})` : `Opponent's Turn`) : `${currentPlayer}'s Turn`;
        showScreen(gameContainer);
        aiDifficultySelection.classList.add("hidden");
        resizeCanvas();
        lineCtx.clearRect(0,0,lineCanvas.width,lineCanvas.height);
        if (particleAnimationId) cancelAnimationFrame(particleAnimationId);
        updateMusicState();
    }

    function handleCellClick(e) {
        const cell = e.target;
        const cellIndex = parseInt(cell.dataset.cellIndex);
        if (boardState[cellIndex] || !gameActive) return;
        
        if (isMultiplayer) {
            if (!isMyTurn) return;
            playSound(clickSound);
            makeMove(cellIndex, mySymbol);
            isMyTurn = false;
            statusDisplay.textContent = "Waiting for opponent...";
            window.parent.postMessage({
                type: 'ARCADE_GAME_MOVE',
                move: { cellIndex: cellIndex }
            }, '*');
            checkGameStatus();
            return;
        }

        playSound(clickSound);
        makeMove(cellIndex, currentPlayer);
        if (!checkGameStatus()) {
            switchPlayer();
            if ("ai" === gameMode && "O" === currentPlayer && gameActive) {
                statusDisplay.textContent = "AI is thinking...";
                setTimeout(aiMove, 500);
            }
        }
    }

    function makeMove(index, symbol){
        boardState[index] = symbol;
        cells[index].textContent = symbol;
        cells[index].classList.add(symbol.toLowerCase());
    }

    function switchPlayer(){
        currentPlayer = "X" === currentPlayer ? "O" : "X";
        statusDisplay.textContent = `${currentPlayer}'s Turn`;
    }

    function checkGameStatus(){
        const win = checkWin();
        if (win) {
            endGame(false, win);
            return true;
        }
        if (boardState.every(e => e !== null)) {
            endGame(true);
            return true;
        }
        return false;
    }

    function checkWin(){
        for(let e=0; e<winningCombinations.length; e++){
            const[l,t,a] = winningCombinations[e];
            if(boardState[l] && boardState[l] === boardState[t] && boardState[l] === boardState[a]) {
                return { winner: boardState[l], combination: winningCombinations[e], index: e };
            }
        }
        return null;
    }

    function endGame(isDraw, winData = null){
        gameActive = false;
        let result = 'draw';
        if (isDraw) {
            winMessage.textContent = "It's a Draw!";
            playSound(drawSound);
            result = 'draw';
        } else {
            winMessage.textContent = `${winData.winner} Wins!`;
            playSound(winSound);
            drawWinningLine(winData.index);
            startParticles();
            if (isMultiplayer) {
                result = winData.winner === mySymbol ? 'win' : 'loss';
            } else {
                result = winData.winner === 'X' ? 'win' : 'loss';
            }
        }
        setTimeout(() => winPopup.classList.remove("hidden"), 500);

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: result,
                score: result === 'win' ? 100 : (result === 'draw' ? 25 : 0)
            }, '*');
        }
    }

    function aiMove(){
        if(!gameActive) return;
        let e;
        if ("easy" === aiDifficulty) {
            const available = boardState.map((val, idx) => val === null ? idx : null).filter(val => val !== null);
            e = available[Math.floor(Math.random() * available.length)];
        } else if ("medium" === aiDifficulty) {
            e = findBestMove("medium");
        } else {
            e = findBestMove("hard");
        }
        makeMove(e, "O");
        playSound(clickSound);
        if(!checkGameStatus()) switchPlayer();
    }

    function findBestMove(difficulty){
        for(let e=0; e<boardState.length; e++) {
            if(boardState[e] === null){
                boardState[e] = "O";
                if(checkWin()?.winner === "O") { boardState[e] = null; return e; }
                boardState[e] = null;
            }
        }
        for(let e=0; e<boardState.length; e++) {
            if(boardState[e] === null){
                boardState[e] = "X";
                if(checkWin()?.winner === "X") { boardState[e] = null; return e; }
                boardState[e] = null;
            }
        }
        if("hard" === difficulty) return minimax(boardState, "O").index;
        const available = boardState.map((val, idx) => val === null ? idx : null).filter(val => val !== null);
        return available.includes(4) ? 4 : available[Math.floor(Math.random() * available.length)];
    }

    function minimax(currBoard, player){
        const avail = currBoard.map((val, idx) => val === null ? idx : null).filter(val => val !== null);
        const win = checkWinForBoard(currBoard);
        if("X" === win?.winner) return { score: -10 };
        if("O" === win?.winner) return { score: 10 };
        if(avail.length === 0) return { score: 0 };
        const moves = [];
        for(let a=0; a<avail.length; a++){
            const move = { index: avail[a] };
            currBoard[avail[a]] = player;
            const res = minimax(currBoard, player === "O" ? "X" : "O");
            move.score = res.score;
            currBoard[avail[a]] = null;
            moves.push(move);
        }
        let bestMove;
        if(player === "O"){
            let bestScore = -10000;
            for(let i=0; i<moves.length; i++){
                if(moves[i].score > bestScore){ bestScore = moves[i].score; bestMove = i; }
            }
        } else {
            let bestScore = 10000;
            for(let i=0; i<moves.length; i++){
                if(moves[i].score < bestScore){ bestScore = moves[i].score; bestMove = i; }
            }
        }
        return moves[bestMove];
    }

    function checkWinForBoard(b){
        for(const[l,t,a] of winningCombinations) {
            if(b[l] && b[l] === b[t] && b[l] === b[a]) return { winner: b[l] };
        }
        return null;
    }

    function resizeCanvas(){
        const rect = board.getBoundingClientRect();
        lineCanvas.width = rect.width;
        lineCanvas.height = rect.height;
        particleCanvas.width = window.innerWidth;
        particleCanvas.height = window.innerHeight;
    }

    function drawWinningLine(index){
        const w = lineCanvas.width, h = lineCanvas.height, seg = w/3, half = seg/2;
        lineCtx.clearRect(0,0,w,h);
        lineCtx.strokeStyle = "#e94560";
        lineCtx.lineWidth = 10;
        lineCtx.lineCap = "round";
        lineCtx.shadowColor = "#e94560";
        lineCtx.shadowBlur = 15;
        lineCtx.beginPath();
        switch(index){
            case 0: lineCtx.moveTo(half, half); lineCtx.lineTo(w-half, half); break;
            case 1: lineCtx.moveTo(half, seg+half); lineCtx.lineTo(w-half, seg+half); break;
            case 2: lineCtx.moveTo(half, 2*seg+half); lineCtx.lineTo(w-half, 2*seg+half); break;
            case 3: lineCtx.moveTo(half, half); lineCtx.lineTo(half, h-half); break;
            case 4: lineCtx.moveTo(seg+half, half); lineCtx.lineTo(seg+half, h-half); break;
            case 5: lineCtx.moveTo(2*seg+half, half); lineCtx.lineTo(2*seg+half, h-half); break;
            case 6: lineCtx.moveTo(half, half); lineCtx.lineTo(w-half, h-half); break;
            case 7: lineCtx.moveTo(w-half, half); lineCtx.lineTo(half, h-half); break;
        }
        lineCtx.stroke();
    }

    let particles = [];
    function startParticles(){
        particles = [];
        for(let e=0; e<100; e++) particles.push(createParticle());
        animateParticles();
    }
    function createParticle(){
        const x = particleCanvas.width/2, y = particleCanvas.height/2, ang = 2*Math.random()*Math.PI, spd = 5*Math.random()+2;
        return { x:x, y:y, vx:Math.cos(ang)*spd, vy:Math.sin(ang)*spd, r:4*Math.random()+1, c:`hsl(${60*Math.random()+20},100%,70%)`, l:100 };
    }
    function animateParticles(){
        particleCtx.clearRect(0,0,particleCanvas.width,particleCanvas.height);
        particles.forEach((p, idx) => {
            p.x += p.vx; p.y += p.vy; p.l--;
            if(p.l <= 0) particles.splice(idx, 1);
            particleCtx.beginPath();
            particleCtx.arc(p.x, p.y, p.r, 0, 2*Math.PI);
            particleCtx.fillStyle = p.c;
            particleCtx.globalAlpha = p.l/100;
            particleCtx.fill();
            particleCtx.closePath();
        });
        if(particles.length > 0) particleAnimationId = requestAnimationFrame(animateParticles);
        else particleCtx.clearRect(0,0,particleCanvas.width,particleCanvas.height);
    }

    cells.forEach(c => c.addEventListener("click", handleCellClick));
    window.addEventListener("resize", resizeCanvas);
    loadSettings();
    showScreen(mainMenu);
});
