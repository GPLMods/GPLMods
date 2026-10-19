document.addEventListener('DOMContentLoaded', () => {
    // --- STATE AND CONFIGURATION ---
    const config = {
        BOARD_SIZE: 100, NUM_SNAKES: 8, NUM_LADDERS: 8, AI_THINK_TIME: 1500,
        SNAKE_LADDER_PAUSE: 400,
    };
    let state = {
        gameMode: 'pvp', numPlayers: 2, playerPositions: [], currentPlayerIndex: 0,
        snakes: {}, ladders: {}, isMusicOn: true, isSfxOn: true,
        isGameOver: false, confettiAnimationId: null
    };

    // --- DOM ELEMENTS ---
    const dom = {
        mainMenu: document.getElementById('main-menu'), gameContainer: document.getElementById('game-container'), startGameBtn: document.getElementById('start-game-btn'),
        backToMenuBtn: document.getElementById('back-to-menu-btn'), homeBtn: document.getElementById('home-btn'), gameBoard: document.getElementById('game-board'),
        rollDiceBtn: document.getElementById('roll-dice-btn'), turnInfo: document.getElementById('turn-info'), messageLog: document.getElementById('message-log'),
        diceFaces: document.querySelectorAll('.dice-face'), winPopup: document.getElementById('win-popup'), winMessage: document.getElementById('win-message'),
        playAgainBtn: document.getElementById('play-again-btn'),
        menuFromWinBtn: document.getElementById('menu-from-win-btn'),
        confettiCanvas: document.getElementById('confetti-canvas'), gameModeBtns: document.getElementById('game-mode-btns'),
        playerCountBtns: document.getElementById('player-count-btns'), openSettingsBtn: document.getElementById('open-settings-btn'), settingsModal: document.getElementById('settings-modal'),
        closeSettingsBtn: document.getElementById('close-settings-btn'), musicToggle: document.getElementById('music-toggle'), sfxToggle: document.getElementById('sfx-toggle'),
    };
    const audio = {
        bgMusic: document.getElementById('bg-music'), dice: document.getElementById('dice-sound'), move: document.getElementById('move-sound'),
        ladder: document.getElementById('ladder-sound'), snake: document.getElementById('snake-sound'), win: document.getElementById('win-sound'), click: document.getElementById('click-sound')
    };
    const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

    // --- SOUND & SETTINGS ---
    function playSoundEffect(sound) { if (state.isSfxOn) { sound.currentTime = 0; sound.play().catch(e => {}); } }
    function updateMusicPlayback() {
        const isMainMenuVisible = !dom.mainMenu.classList.contains('hidden');
        const isGameVisible = !dom.gameContainer.classList.contains('hidden');
        if (state.isMusicOn && (isMainMenuVisible || isGameVisible) && audio.bgMusic) {
            audio.bgMusic.play().catch(e => {});
        } else if (audio.bgMusic) {
            audio.bgMusic.pause();
        }
    }
    function loadSettings() { 
        state.isMusicOn = localStorage.getItem('snakeLadderMusic') !== 'false'; 
        state.isSfxOn = localStorage.getItem('snakeLadderSfx') !== 'false'; 
        if (dom.musicToggle) dom.musicToggle.checked = state.isMusicOn; 
        if (dom.sfxToggle) dom.sfxToggle.checked = state.isSfxOn; 
    }

    // --- EVENT LISTENERS ---
    function goToMainMenu() { playSoundEffect(audio.click); dom.gameContainer.classList.add('hidden'); dom.winPopup.classList.add('hidden'); dom.mainMenu.classList.remove('hidden'); updateMusicPlayback(); if (state.confettiAnimationId) stopConfetti(); }
    dom.openSettingsBtn?.addEventListener('click', () => { playSoundEffect(audio.click); dom.settingsModal.classList.remove('hidden'); });
    dom.closeSettingsBtn?.addEventListener('click', () => { playSoundEffect(audio.click); dom.settingsModal.classList.add('hidden'); });
    dom.settingsModal?.addEventListener('click', (e) => { if (e.target === dom.settingsModal) dom.settingsModal.classList.add('hidden'); });
    dom.musicToggle?.addEventListener('change', () => { state.isMusicOn = dom.musicToggle.checked; localStorage.setItem('snakeLadderMusic', state.isMusicOn); updateMusicPlayback(); });
    dom.sfxToggle?.addEventListener('change', () => { state.isSfxOn = dom.sfxToggle.checked; localStorage.setItem('snakeLadderSfx', state.isSfxOn); });
    function updateActiveButton(buttonGroup, clickedButton) { Array.from(buttonGroup.children).forEach(button => button.classList.remove('active')); clickedButton.classList.add('active'); }
    dom.gameModeBtns?.addEventListener('click', (e) => { if (e.target.tagName === 'BUTTON') { playSoundEffect(audio.click); state.gameMode = e.target.dataset.mode; updateActiveButton(dom.gameModeBtns, e.target); } });
    dom.playerCountBtns?.addEventListener('click', (e) => { if (e.target.tagName === 'BUTTON') { playSoundEffect(audio.click); state.numPlayers = parseInt(e.target.dataset.count, 10); updateActiveButton(dom.playerCountBtns, e.target); } });
    dom.startGameBtn?.addEventListener('click', () => { playSoundEffect(audio.click); startGame(); });
    dom.homeBtn?.addEventListener('click', () => { 
        playSoundEffect(audio.click); 
        if (window.parent && window.parent !== window) {
            window.parent.postMessage({ type: 'ARCADE_EXIT' }, '*');
        } else {
            window.location.href = "/games/hub"; 
        }
    });
    dom.backToMenuBtn.addEventListener('click', goToMainMenu);
    dom.menuFromWinBtn.addEventListener('click', goToMainMenu);
    dom.playAgainBtn.addEventListener('click', () => { playSoundEffect(audio.click); dom.winPopup.classList.add('hidden'); if (state.confettiAnimationId) stopConfetti(); startGame(); });
    dom.rollDiceBtn.addEventListener('click', () => { if (state.gameMode === 'pva' && state.currentPlayerIndex > 0) return; handleTurn(); });
    
    // --- CORE GAME LOGIC ---
    function startGame() { dom.mainMenu.classList.add('hidden'); dom.gameContainer.classList.remove('hidden'); updateMusicPlayback(); resetGame(); generateBoard(); generateSnakesAndLadders(); renderBoard(); updateTurnInfo(); }
    function resetGame() { state.isGameOver = false; state.playerPositions = Array(state.numPlayers).fill(1); state.currentPlayerIndex = 0; state.snakes = {}; state.ladders = {}; dom.messageLog.innerHTML = ''; dom.rollDiceBtn.disabled = false; document.querySelectorAll('.player-token').forEach(t => t.remove()); }
    
    async function handleTurn() {
        if (state.isGameOver) return;
        dom.rollDiceBtn.disabled = true;
        const diceRoll = await rollDice();
        logMessage(`Player ${state.currentPlayerIndex + 1} rolled a ${diceRoll}.`);
        
        let startPos = state.playerPositions[state.currentPlayerIndex];
        let targetPos = startPos + diceRoll;

        // --- FIX #1: IMPLEMENT CORRECT "OVERSHOOT" RULE ---
        if (targetPos <= config.BOARD_SIZE) {
            await movePlayer(startPos, targetPos);
            let finalPos = state.playerPositions[state.currentPlayerIndex];
            if (state.snakes[finalPos]) {
                logMessage(`Oh no! Player ${state.currentPlayerIndex + 1} slid down a snake at ${finalPos}!`);
                playSoundEffect(audio.snake);
                await wait(config.SNAKE_LADDER_PAUSE);
                await movePlayer(finalPos, state.snakes[finalPos], true);
            } else if (state.ladders[finalPos]) {
                logMessage(`Yay! Player ${state.currentPlayerIndex + 1} climbed a ladder at ${finalPos}!`);
                playSoundEffect(audio.ladder);
                await wait(config.SNAKE_LADDER_PAUSE);
                await movePlayer(finalPos, state.ladders[finalPos], true);
            }
        } else {
            logMessage(`Player ${state.currentPlayerIndex + 1} needs to land exactly on ${config.BOARD_SIZE}. No move.`);
            await wait(config.SNAKE_LADDER_PAUSE);
        }

        if (state.playerPositions[state.currentPlayerIndex] === config.BOARD_SIZE) {
            showWinPopup();
            return;
        }

        // Switch to the next player
        state.currentPlayerIndex = (state.currentPlayerIndex + 1) % state.numPlayers;
        updateTurnInfo();

        // Check if the new player is an AI
        if (state.gameMode === 'pva' && state.currentPlayerIndex > 0) {
            dom.rollDiceBtn.disabled = true;
            dom.turnInfo.textContent = `AI ${state.currentPlayerIndex + 1} is thinking...`;
            setTimeout(handleTurn, config.AI_THINK_TIME);
        } else {
            dom.rollDiceBtn.disabled = false;
        }
    }
    
    function generateBoard() { dom.gameBoard.innerHTML = ''; for (let i = 0; i < config.BOARD_SIZE; i++) { const cell = document.createElement('div'); cell.classList.add('cell'); const numberSpan = document.createElement('span'); numberSpan.classList.add('cell-number'); cell.appendChild(numberSpan); dom.gameBoard.appendChild(cell); } const cells = Array.from(dom.gameBoard.children); let num = config.BOARD_SIZE; for (let row = 0; row < 10; row++) { const rowCells = cells.slice(row * 10, (row * 10) + 10); if (row % 2 !== 0) rowCells.reverse(); for (const cell of rowCells) { cell.querySelector('.cell-number').textContent = num; cell.dataset.cell = num--; } } }
    function generateSnakesAndLadders() { const occupied = new Set([1, config.BOARD_SIZE]); state.snakes = {}; state.ladders = {}; for (let i = 0; i < config.NUM_SNAKES; i++) { let start, end; do { start = Math.floor(Math.random()*(config.BOARD_SIZE-20))+21; end = Math.floor(Math.random()*(start-11))+1; } while (occupied.has(start) || occupied.has(end)); occupied.add(start); occupied.add(end); state.snakes[start] = end; } for (let i = 0; i < config.NUM_LADDERS; i++) { let start, end; do { start = Math.floor(Math.random()*(config.BOARD_SIZE-20))+2; end = Math.floor(Math.random()*(config.BOARD_SIZE-start-10))+start+11; } while (occupied.has(start) || occupied.has(end) || end > config.BOARD_SIZE); occupied.add(start); occupied.add(end); state.ladders[start] = end; } }
    function renderBoard() { 
        document.querySelectorAll('.cell').forEach(c => { 
            c.classList.remove('has-marker'); 
            const oldMarker = c.querySelector('.marker'); 
            if (oldMarker) oldMarker.remove(); 
        }); 
        const createMarker = (cell, type, destination) => { 
            cell.classList.add('has-marker'); 
            const marker = document.createElement('div'); 
            marker.className = 'marker'; 
            const icon = document.createElement('span'); 
            icon.className = 'marker-icon'; 
            icon.innerHTML = type === 'snake' ? '<i class="fas fa-worm" style="color:#ef4444;"></i>' : '<i class="fas fa-arrow-up" style="color:#10b981;"></i>'; 
            const text = document.createElement('span'); 
            text.className = 'marker-text'; 
            text.textContent = `to ${destination}`; 
            marker.appendChild(icon); 
            marker.appendChild(text); 
            cell.appendChild(marker); 
        }; 
        for (const [start, end] of Object.entries(state.snakes)) { 
            const startCell = document.querySelector(`[data-cell='${start}']`); 
            if(startCell) createMarker(startCell, 'snake', end); 
        } 
        for (const [start, end] of Object.entries(state.ladders)) { 
            const startCell = document.querySelector(`[data-cell='${start}']`); 
            if(startCell) createMarker(startCell, 'ladder', end); 
        } 
        renderPlayerTokens(); 
    }
    function renderPlayerTokens() { document.querySelectorAll('.player-token').forEach(t => t.remove()); state.playerPositions.forEach((pos, i) => { const token = document.createElement('div'); token.className = `player-token player-${i}`; document.querySelector(`[data-cell='${pos}']`)?.appendChild(token); }); }
    function movePlayer(start, end, isFastTravel = false) { const duration = isFastTravel ? 25 : 100; return new Promise(resolve => { let current = start; const isUp = end > start; const interval = setInterval(() => { if ((isUp && current >= end) || (!isUp && current <= end)) { clearInterval(interval); state.playerPositions[state.currentPlayerIndex] = end; renderPlayerTokens(); resolve(); return; } current = isUp ? current + 1 : current - 1; state.playerPositions[state.currentPlayerIndex] = current; if (!isFastTravel) playSoundEffect(audio.move); renderPlayerTokens(); }, duration); }); }
    function rollDice() { playSoundEffect(audio.dice); const roll = Math.floor(Math.random() * 6) + 1; return new Promise(resolve => { let i = 0; const interval = setInterval(() => { dom.diceFaces[i++ % 6].classList.remove('active'); dom.diceFaces[i % 6].classList.add('active'); }, 50); setTimeout(() => { clearInterval(interval); dom.diceFaces.forEach(f => f.classList.remove('active')); document.querySelector(`.dice-face[data-face='${roll}']`).classList.add('active'); resolve(roll); }, 800); }); }
    function updateTurnInfo() { const type = (state.gameMode === 'pva' && state.currentPlayerIndex > 0) ? 'AI' : 'Player'; dom.turnInfo.textContent = `${type} ${state.currentPlayerIndex + 1}'s Turn`; dom.turnInfo.style.backgroundColor = getComputedStyle(document.documentElement).getPropertyValue(`--player${state.currentPlayerIndex + 1}-color`) || '#f0f0f0'; dom.turnInfo.style.color = (state.currentPlayerIndex === 1) ? '#000' : '#fff'; }
    function logMessage(msg) { const p = document.createElement('p'); p.textContent = msg; dom.messageLog.appendChild(p); dom.messageLog.scrollTop = dom.messageLog.scrollHeight; }
    function showWinPopup() { 
        state.isGameOver = true; 
        playSoundEffect(audio.win); 
        audio.bgMusic.pause(); 
        const playerNumber = state.currentPlayerIndex + 1; 
        const playerColor = getComputedStyle(document.documentElement).getPropertyValue(`--player${playerNumber}-color`); 
        logMessage(`Player ${playerNumber} Wins!`); 
        dom.winMessage.textContent = `Player ${playerNumber} Wins!`; 
        dom.winMessage.style.color = playerColor; 
        dom.winPopup.classList.remove('hidden'); 
        dom.rollDiceBtn.disabled = true; 
        startConfetti(); 

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: state.currentPlayerIndex === 0 ? 'win' : 'loss',
                score: 100
            }, '*');
        }
    }
    let confetti = []; function startConfetti() { const ctx = dom.confettiCanvas.getContext('2d'); dom.confettiCanvas.width = window.innerWidth; dom.confettiCanvas.height = window.innerHeight; confetti = []; const confettiCount = 200, colors = ['#fde19a', '#ff9a9a', '#a2d2ff', '#bde0fe', '#ffc8dd']; for (let i=0; i<confettiCount; i++) { confetti.push({x:Math.random()*dom.confettiCanvas.width, y:Math.random()*dom.confettiCanvas.height - dom.confettiCanvas.height, radius:Math.random()*5+2, color:colors[Math.floor(Math.random()*colors.length)], speedX:Math.random()*6-3, speedY:Math.random()*5+2, opacity:1}); } function animate() { ctx.clearRect(0,0,dom.confettiCanvas.width,dom.confettiCanvas.height); confetti.forEach((p,i)=>{p.x+=p.speedX; p.y+=p.speedY; p.opacity-=0.01; if(p.opacity<=0)confetti.splice(i,1); ctx.beginPath();ctx.arc(p.x,p.y,p.radius,0,Math.PI*2);ctx.fillStyle=`rgba(${parseInt(p.color.slice(1,3),16)}, ${parseInt(p.color.slice(3,5),16)}, ${parseInt(p.color.slice(5,7),16)}, ${p.opacity})`;ctx.fill();}); if(confetti.length > 0) state.confettiAnimationId = requestAnimationFrame(animate); else { state.confettiAnimationId = null; } } animate(); }
    function stopConfetti() { if (state.confettiAnimationId) cancelAnimationFrame(state.confettiAnimationId); confetti = []; const ctx = dom.confettiCanvas.getContext('2d'); ctx.clearRect(0, 0, dom.confettiCanvas.height, dom.confettiCanvas.width); state.confettiAnimationId = null; }
    
    // --- INITIALIZATION ---
    loadSettings();
    updateMusicPlayback();
});
