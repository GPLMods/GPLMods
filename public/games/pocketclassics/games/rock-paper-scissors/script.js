document.addEventListener('DOMContentLoaded', () => {
    // --- Universal Arcade Helper ---
    const helper = window.ArcadeHelper ? window.ArcadeHelper.init({
        menuMusic: 'sounds/menu-music.mp3',
        gameMusic: 'sounds/bg-music.mp3'
    }) : null;

    // --- DOM Elements ---
    const mainMenu = document.getElementById('main-menu');
    const gameScreen = document.getElementById('game-screen');
    const settingsScreen = document.getElementById('settings-screen');

    const playBtn = document.getElementById('play-btn');
    const settingsBtn = document.getElementById('settings-btn');
    const backToMenuBtn = document.getElementById('back-to-menu-btn');
    const restartMatchBtn = document.getElementById('restart-match-btn');
    const backFromSettingsBtn = document.getElementById('back-from-settings-btn');

    const choiceBtns = document.querySelectorAll('.choice-card');
    const playerScoreEl = document.getElementById('player-score');
    const computerScoreEl = document.getElementById('computer-score');
    const resultMessageEl = document.getElementById('result-message');
    const playerChoiceDisplay = document.getElementById('player-choice-display');
    const computerChoiceDisplay = document.getElementById('computer-choice-display');

    const musicToggle = document.getElementById('music-toggle');
    const sfxToggle = document.getElementById('sfx-toggle');

    // --- Sounds ---
    const clickSound = document.getElementById('sfx-click');
    const winSound = document.getElementById('sfx-win');
    const loseSound = document.getElementById('sfx-lose');
    const tieSound = document.getElementById('sfx-tie');

    function playSound(snd) {
        if (helper) helper.audio.playSfx(snd);
        else if (snd) { snd.currentTime = 0; snd.play().catch(() => {}); }
    }
    function playClick() { playSound(clickSound); }

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
    let sessP1 = parseInt(localStorage.getItem('arc_rps_p1') || '0', 10);
    let sessTies = parseInt(localStorage.getItem('arc_rps_ties') || '0', 10);
    let sessCpu = parseInt(localStorage.getItem('arc_rps_cpu') || '0', 10);

    function updateRpsScoreboard() {
        const p1El = document.getElementById('sessP1Wins');
        const tiesEl = document.getElementById('sessTies');
        const cpuEl = document.getElementById('sessCpuWins');
        const pill1 = document.getElementById('pillP1');
        const pillCpu = document.getElementById('pillCpu');
        if (p1El) p1El.textContent = sessP1;
        if (tiesEl) tiesEl.textContent = sessTies;
        if (cpuEl) cpuEl.textContent = sessCpu;
        if (pill1 && pillCpu) {
            pill1.classList.toggle('leading', sessP1 > sessCpu);
            pillCpu.classList.toggle('leading', sessCpu > sessP1);
        }
    }
    updateRpsScoreboard();

    function launchWinParticles() {
        const canvas = document.getElementById('win-particles-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const colors = ['#f59e0b', '#ffd700', '#38bdf8', '#ef4444', '#10b981'];
        const particles = Array.from({ length: 80 }, () => ({
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
    const TARGET_WINS = 3;
    let playerScore = 0, computerScore = 0;
    let isClashing = false;
    let isGameOver = false;

    const choices = ['rock', 'paper', 'scissors'];
    const choiceIcons = {
        rock: '<i class="fas fa-hand-back-fist"></i>',
        paper: '<i class="fas fa-hand"></i>',
        scissors: '<i class="fas fa-hand-scissors"></i>'
    };

    // --- Navigation ---
    function showScreen(screen) {
        [mainMenu, gameScreen, settingsScreen].forEach(s => s && s.classList.add('hidden'));
        screen?.classList.remove('hidden');

        if (screen === mainMenu) {
            if (helper) helper.audio.playMenuMusic();
        } else if (screen === gameScreen) {
            if (helper) helper.audio.playGameMusic();
        }
    }

    playBtn?.addEventListener('click', () => {
        playClick();
        resetGame();
        showScreen(gameScreen);
    });

    settingsBtn?.addEventListener('click', () => {
        playClick();
        showScreen(settingsScreen);
    });

    backToMenuBtn?.addEventListener('click', () => {
        playClick();
        showScreen(mainMenu);
    });

    backFromSettingsBtn?.addEventListener('click', () => {
        playClick();
        showScreen(mainMenu);
    });

    restartMatchBtn?.addEventListener('click', () => {
        playClick();
        resetGame();
    });

    function resetGame() {
        playerScore = 0;
        computerScore = 0;
        isClashing = false;
        isGameOver = false;
        if (playerScoreEl) playerScoreEl.textContent = '0';
        if (computerScoreEl) computerScoreEl.textContent = '0';
        if (resultMessageEl) resultMessageEl.textContent = 'Choose Weapon!';
        if (playerChoiceDisplay) {
            playerChoiceDisplay.innerHTML = '<i class="fas fa-question"></i>';
            playerChoiceDisplay.classList.remove('active');
        }
        if (computerChoiceDisplay) {
            computerChoiceDisplay.innerHTML = '<i class="fas fa-question"></i>';
            computerChoiceDisplay.classList.remove('active');
        }
        enableChoiceButtons(true);
    }

    function enableChoiceButtons(enable) {
        choiceBtns.forEach(btn => {
            btn.disabled = !enable;
        });
    }

    // --- Play Round ---
    function chooseWeapon(playerChoice) {
        if (isClashing || isGameOver) return;
        isClashing = true;
        enableChoiceButtons(false);
        playSound(clickSound);
        if (helper) helper.vibrate(15);

        // Show player choice
        playerChoiceDisplay.innerHTML = choiceIcons[playerChoice];
        playerChoiceDisplay.classList.add('active');
        computerChoiceDisplay.innerHTML = '<i class="fas fa-cog fa-spin"></i>';
        computerChoiceDisplay.classList.remove('active');
        resultMessageEl.textContent = 'Clashing...';

        // Dramatic AI roll animation
        setTimeout(() => {
            const cpuChoice = choices[Math.floor(Math.random() * choices.length)];
            computerChoiceDisplay.innerHTML = choiceIcons[cpuChoice];
            computerChoiceDisplay.classList.add('active');

            resolveRound(playerChoice, cpuChoice);
        }, 500);
    }

    function resolveRound(p, c) {
        let result = '';

        if (p === c) {
            result = 'tie';
            playSound(tieSound);
            if (helper) helper.vibrate(20);
            sessTies++;
            localStorage.setItem('arc_rps_ties', sessTies);
            updateRpsScoreboard();
            resultMessageEl.textContent = "Draw! Both picked identical weapons.";
            resultMessageEl.style.color = '#ffd700';
        } else if (
            (p === 'rock' && c === 'scissors') ||
            (p === 'paper' && c === 'rock') ||
            (p === 'scissors' && c === 'paper')
        ) {
            result = 'win';
            playerScore++;
            playSound(winSound);
            if (helper) helper.vibrate([20, 20, 40]);
            resultMessageEl.textContent = `Round Point! ${p.toUpperCase()} beats ${c.toUpperCase()}.`;
            resultMessageEl.style.color = '#38bdf8';
        } else {
            result = 'loss';
            computerScore++;
            playSound(loseSound);
            if (helper) helper.vibrate(50);
            resultMessageEl.textContent = `CPU Point! ${c.toUpperCase()} beats ${p.toUpperCase()}.`;
            resultMessageEl.style.color = '#ef4444';
        }

        if (playerScoreEl) playerScoreEl.textContent = playerScore;
        if (computerScoreEl) computerScoreEl.textContent = computerScore;

        // Check Match Victory
        if (playerScore >= TARGET_WINS || computerScore >= TARGET_WINS) {
            setTimeout(() => endMatch(playerScore >= TARGET_WINS), 700);
        } else {
            setTimeout(() => {
                isClashing = false;
                enableChoiceButtons(true);
            }, 850);
        }
    }

    function endMatch(isPlayerWin) {
        isGameOver = true;
        isClashing = false;

        if (isPlayerWin) {
            sessP1++;
            localStorage.setItem('arc_rps_p1', sessP1);
            launchWinParticles();
            playSound(winSound);
            if (helper) {
                helper.vibrate([40, 30, 80]);
                helper.audio.playMenuMusic();
            }
            resultMessageEl.textContent = "🏆 CHAMPION! You won the battle!";
            resultMessageEl.style.color = '#ffd700';
        } else {
            sessCpu++;
            localStorage.setItem('arc_rps_cpu', sessCpu);
            playSound(loseSound);
            if (helper) {
                helper.vibrate(80);
                helper.audio.playMenuMusic();
            }
            resultMessageEl.textContent = "💀 DEFEAT! CPU took the crown.";
            resultMessageEl.style.color = '#ef4444';
        }
        updateRpsScoreboard();

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: isPlayerWin ? 'win' : 'loss',
                score: playerScore * 40
            }, '*');
        }
    }

    choiceBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const ch = btn.dataset.choice;
            if (ch) chooseWeapon(ch);
        });
    });

    // --- KEYBOARD & GAMEPAD SHORTCUTS ---
    window.addEventListener('keydown', (e) => {
        if (gameScreen.classList.contains('hidden') || isClashing || isGameOver) return;
        const key = e.key.toLowerCase();

        if (key === '1' || key === 'r') chooseWeapon('rock');
        else if (key === '2' || key === 'p') chooseWeapon('paper');
        else if (key === '3' || key === 's') chooseWeapon('scissors');
        else if (key === 'Escape') backToMenuBtn?.click();
    });

    if (helper && helper.gamepad) {
        helper.gamepad.onAction((act) => {
            if (!gameScreen.classList.contains('hidden') && !isClashing && !isGameOver) {
                if (act === 'X') chooseWeapon('rock');
                else if (act === 'Y') chooseWeapon('paper');
                else if (act === 'B') chooseWeapon('scissors');
                else if (act === 'START') backToMenuBtn?.click();
                else if (act === 'SELECT') restartMatchBtn?.click();
            }
        });
    }
});
