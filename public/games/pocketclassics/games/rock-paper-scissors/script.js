// --- DOM Elements ---
const mainMenu = document.getElementById('main-menu');
const gameScreen = document.getElementById('game-screen');
const settingsScreen = document.getElementById('settings-screen');
const playBtn = document.getElementById('play-btn');
const settingsBtn = document.getElementById('settings-btn');
const backToMenuBtn = document.getElementById('back-to-menu-btn');
const backFromSettingsBtn = document.getElementById('back-from-settings-btn');
const choiceBtns = document.querySelectorAll('.choice-btn');
const playerScoreEl = document.getElementById('player-score');
const computerScoreEl = document.getElementById('computer-score');
const resultMessageEl = document.getElementById('result-message');
const playerChoiceDisplay = document.getElementById('player-choice-display');
const computerChoiceDisplay = document.getElementById('computer-choice-display');
const sfxToggle = document.getElementById('sfx-toggle');
const musicToggle = document.getElementById('music-toggle');
const homeBtn = document.getElementById('home-btn');

// --- Audio Elements ---
const bgMusic = new Audio('sounds/bg-music.mp3');
bgMusic.loop = true;
bgMusic.volume = 1;
const clickSound = new Audio('sounds/click.wav');
const winSound = new Audio('sounds/win.wav');
const loseSound = new Audio('sounds/lose.wav');
const tieSound = new Audio('sounds/tie.wav');

// --- Game & Settings State ---
let playerScore = 0, computerScore = 0;
const choices = ['rock', 'paper', 'scissors'];
const choiceIcons = {
    rock: '<i class="fas fa-hand-back-fist"></i>',
    paper: '<i class="fas fa-hand"></i>',
    scissors: '<i class="fas fa-hand-scissors"></i>'
};
let sfxOn = true, musicOn = true, musicHasStarted = false;
let isMultiplayer = false;
let myTurn = true;

// Listen for messages from parent window
window.addEventListener('message', (event) => {
    if (!event.data || !event.data.type) return;
    if (event.data.type === 'ARCADE_MATCH_READY') {
        isMultiplayer = true;
        showScreen(gameScreen);
        resetGame();
        resultMessageEl.textContent = 'Multiplayer match started! Choose your weapon.';
    } else if (event.data.type === 'ARCADE_OPPONENT_MOVE') {
        const oppChoice = event.data.move && event.data.move.choice;
        if (oppChoice && pendingPlayerChoice) {
            resolveMultiplayerRound(pendingPlayerChoice, oppChoice);
            pendingPlayerChoice = null;
        }
    }
});

let pendingPlayerChoice = null;

// --- Sound Functions ---
function playSfx(sound) {
    if (sfxOn) {
        sound.currentTime = 0;
        sound.play().catch(() => {});
    }
}
function toggleMusic() {
    if (musicOn && !musicHasStarted) {
        bgMusic.play().then(() => {
            musicHasStarted = true;
        }).catch(error => {
            console.error("Music failed to play:", error);
            musicOn = false;
            musicToggle.checked = false;
        });
    } else if (musicOn && musicHasStarted) {
        bgMusic.play().catch(() => {});
    } else {
        bgMusic.pause();
    }
}

// --- Screen Navigation ---
function showScreen(screen) {
    [mainMenu, gameScreen, settingsScreen].forEach(s => s.classList.add('hidden'));
    screen.classList.remove('hidden');
}
playBtn.addEventListener('click', () => {
    playSfx(clickSound);
    showScreen(gameScreen);
    resetGame();
    if (musicOn && !musicHasStarted) {
        toggleMusic();
    }
});
settingsBtn.addEventListener('click', () => {
    playSfx(clickSound);
    showScreen(settingsScreen);
});
backToMenuBtn.addEventListener('click', () => {
    playSfx(clickSound);
    showScreen(mainMenu);
});
backFromSettingsBtn.addEventListener('click', () => {
    playSfx(clickSound);
    showScreen(mainMenu);
});
homeBtn.addEventListener('click', () => {
    playSfx(clickSound);
    if (window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'ARCADE_EXIT' }, '*');
    } else {
        window.location.href = '/games/hub';
    }
});

// --- Settings Toggles ---
sfxToggle.addEventListener('change', (e) => { sfxOn = e.target.checked; });
musicToggle.addEventListener('change', (e) => { musicOn = e.target.checked; toggleMusic(); });

// --- Game Logic ---
choiceBtns.forEach(button => {
    button.addEventListener('click', () => {
        const playerChoice = button.dataset.choice;
        if (isMultiplayer) {
            pendingPlayerChoice = playerChoice;
            resultMessageEl.textContent = 'Choice submitted! Waiting for opponent...';
            playerChoiceDisplay.innerHTML = choiceIcons[playerChoice];
            playerChoiceDisplay.classList.add('active');
            window.parent.postMessage({
                type: 'ARCADE_GAME_MOVE',
                move: { choice: playerChoice }
            }, '*');
        } else {
            const computerChoice = getComputerChoice();
            playRound(playerChoice, computerChoice);
        }
    });
});

function getComputerChoice() {
    return choices[Math.floor(Math.random() * choices.length)];
}

function resolveMultiplayerRound(playerChoice, oppChoice) {
    playRound(playerChoice, oppChoice, true);
}

function playRound(playerChoice, opponentChoice, isPvP = false) {
    let result = '', resultColor = '', roundSound;
    let outcome = 'draw';
    if (playerChoice === opponentChoice) {
        result = "It's a Tie!";
        resultColor = 'var(--tie-color)';
        roundSound = tieSound;
        outcome = 'draw';
    } else if ((playerChoice === 'rock' && opponentChoice === 'scissors') || (playerChoice === 'paper' && opponentChoice === 'rock') || (playerChoice === 'scissors' && opponentChoice === 'paper')) {
        playerScore++;
        result = isPvP ? 'You Win this round!' : 'You Win!';
        resultColor = 'var(--secondary-color)';
        roundSound = winSound;
        outcome = 'win';
    } else {
        computerScore++;
        result = isPvP ? 'Opponent Wins this round!' : 'You Lose!';
        resultColor = 'var(--danger-color)';
        roundSound = loseSound;
        outcome = 'loss';
    }
    playSfx(roundSound);
    updateUI(result, resultColor, playerChoice, opponentChoice);

    // Report game state to parent
    if (window.parent && window.parent !== window) {
        window.parent.postMessage({
            type: 'ARCADE_SCORE_UPDATE',
            score: playerScore
        }, '*');
        if (playerScore >= 3 || computerScore >= 3) {
            const finalResult = playerScore > computerScore ? 'win' : 'loss';
            window.parent.postMessage({
                type: 'ARCADE_GAME_OVER',
                result: finalResult,
                score: playerScore
            }, '*');
        }
    }
}

// --- UI Updates ---
function updateUI(result, color, playerChoice, computerChoice) {
    playerScoreEl.textContent = playerScore;
    computerScoreEl.textContent = computerScore;
    resultMessageEl.textContent = result;
    resultMessageEl.style.color = color;
    playerChoiceDisplay.innerHTML = choiceIcons[playerChoice] || '?';
    computerChoiceDisplay.innerHTML = choiceIcons[computerChoice] || '?';
    playerChoiceDisplay.classList.add('active');
    computerChoiceDisplay.classList.add('active');
}

function resetGame() {
    playerScore = 0;
    computerScore = 0;
    pendingPlayerChoice = null;
    playerScoreEl.textContent = 0;
    computerScoreEl.textContent = 0;
    resultMessageEl.textContent = 'Choose your weapon!';
    resultMessageEl.style.color = 'var(--light-color)';
    playerChoiceDisplay.innerHTML = '?';
    computerChoiceDisplay.innerHTML = '?';
    playerChoiceDisplay.classList.remove('active');
    computerChoiceDisplay.classList.remove('active');
}
