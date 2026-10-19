const express = require('express');
const router = express.Router();
const GameScore = require('../models/gameScore');
const Club = require('../models/community/club');

const GAMES_CATALOG = {
    '2048': {
        id: '2048',
        name: '2048 Classic',
        category: '1P',
        typeLabel: 'Single Player',
        icon: '/games/pocketclassics/assets/2048-icon.png',
        tagline: 'Join the numbers to reach the legendary 2048 tile!',
        description: 'A captivating mathematical puzzle where you slide numbered tiles across a 4x4 grid. When two identical tiles collide, they combine into their sum. Plan ahead to reach 2048 without running out of moves!',
        rules: [
            'Use Arrow Keys, WASD, or Swipe on screen to move all tiles simultaneously.',
            'Tiles with matching numbers merge into a single tile equal to their sum (2+2=4, 4+4=8, etc.).',
            'After each turn, a new 2 or 4 tile spawns randomly in an empty slot.',
            'Reach the 2048 tile to win! The game continues for endless high scores until the board is completely blocked.'
        ],
        screenshots: ['/games/pocketclassics/games/2048/ss1.png', '/games/pocketclassics/games/2048/ss2.png'],
        audio: '/games/pocketclassics/games/2048/sounds/music.mp3',
        isMultiplayer: false
    },
    'air-hockey': {
        id: 'air-hockey',
        name: 'Air Hockey Showdown',
        category: '2P',
        typeLabel: '2 Players',
        icon: '/games/pocketclassics/assets/airhockey-icon.png',
        tagline: 'Fast-paced tabletop puck defense and striking battle!',
        description: 'A classic neon tabletop duel. Slide your mallet to deflect the high-speed hovering puck, guard your goal line, and execute sharp bank shots into your rival’s goal. First to 7 points wins!',
        rules: [
            'Control your mallet via mouse drag or touch drag on your half of the table.',
            'You cannot cross the center red line into the opponent half.',
            'Bank the puck off the side walls to curve your shots around the opponent mallet.',
            'The first player to score 7 goals wins the match.'
        ],
        screenshots: ['/games/pocketclassics/games/air-hockey/ss1.png', '/games/pocketclassics/games/air-hockey/ss2.png'],
        audio: '/games/pocketclassics/games/air-hockey/sounds/background.mp3',
        isMultiplayer: true
    },
    'checkers': {
        id: 'checkers',
        name: 'Checkers (Draughts)',
        category: '2P',
        typeLabel: '2 Players',
        icon: '/games/pocketclassics/assets/checkers-icon.png',
        tagline: 'Tactical diagonal jumping and King promotion board game!',
        description: 'The ancient game of diagonal movement and piece capture. Advance your checkers diagonally across dark squares, leap over opponent pieces to eliminate them, and advance to the back rank to crown Kings!',
        rules: [
            'Pieces move forward diagonally by one square onto unoccupied dark squares.',
            'Capture opponent pieces by jumping over them into an empty square beyond. Consecutive multi-jumps are allowed.',
            'When a piece reaches the opponent back rank, it is promoted to a King, unlocking both forward and backward diagonal movements.',
            'Win by capturing all opponent pieces or blocking them from making any legal move.'
        ],
        screenshots: ['/games/pocketclassics/games/checkers/ss1.png', '/games/pocketclassics/games/checkers/ss2.png'],
        audio: '/games/pocketclassics/games/checkers/sounds/game-music.mp3',
        isMultiplayer: true
    },
    'chess': {
        id: 'chess',
        name: 'Classic Chess Master',
        category: '2P',
        typeLabel: '2 Players',
        icon: '/games/pocketclassics/assets/chess-icon.png',
        tagline: 'The ultimate strategy battle of Kings, Queens, and Grandmasters!',
        description: 'Command your 16 pieces across the 64-square battlefield. Formulate intricate openings, defend your king, orchestrate tactical forks, and deliver an inescapable checkmate!',
        rules: [
            'Pawns move forward 1 square (or 2 on their initial move) and capture diagonally.',
            'Knights move in an "L" shape and can jump over pieces; Bishops move diagonally; Rooks horizontally & vertically; Queens in any direction.',
            'The King moves 1 square in any direction. Protect your King at all costs.',
            'Win by placing the enemy King in "Checkmate" where it is under attack and has no legal escape moves.'
        ],
        screenshots: ['/games/pocketclassics/games/chess/ss1.png', '/games/pocketclassics/games/chess/ss2.png'],
        audio: '/games/pocketclassics/games/chess/sounds/game-music.mp3',
        isMultiplayer: true
    },
    'minesweeper': {
        id: 'minesweeper',
        name: 'Minesweeper Retro',
        category: '1P',
        typeLabel: 'Single Player',
        icon: '/games/pocketclassics/assets/minesweeper-icon.png',
        tagline: 'Clear the danger zone using logic, flags, and tactical deduction!',
        description: 'Test your deduction and risk calculation. Uncover squares on the grid while avoiding hidden explosive mines. Every revealed number tells you how many mines surround that cell!',
        rules: [
            'Click or tap any square to uncover it. Your first click is always guaranteed safe.',
            'Numbers on revealed tiles indicate the exact number of mines touching that tile (including diagonals).',
            'Right-click or toggle the Flag button to mark suspected mine locations.',
            'Clear every single mine-free tile on the board to win! Triggering a mine causes immediate game over.'
        ],
        screenshots: ['/games/pocketclassics/games/minesweeper/ss1.png', '/games/pocketclassics/games/minesweeper/ss2.png'],
        audio: '/games/pocketclassics/games/minesweeper/sounds/music-background.mp3',
        isMultiplayer: false
    },
    'othello': {
        id: 'othello',
        name: 'Othello (Reversi)',
        category: '2P',
        typeLabel: '2 Players',
        icon: '/games/pocketclassics/assets/othello-icon.png',
        tagline: 'A minute to learn, a lifetime to master! Flip discs to dominate.',
        description: 'The world-famous Reversi disc-flipping strategy game. Trap opponent discs between two of your own color along any horizontal, vertical, or diagonal row to flip them to your side!',
        rules: [
            'Each turn, you must place a disc such that at least one opponent disc is trapped between your new disc and another disc of your color.',
            'All trapped opponent discs immediately flip over to your color.',
            'If a player has no legal moves, their turn is passed to the opponent.',
            'When the board is completely filled or neither player can move, the player with the most discs wins!'
        ],
        screenshots: ['/games/pocketclassics/games/othello/ss1.png', '/games/pocketclassics/games/othello/ss2.png'],
        audio: '/games/pocketclassics/games/othello/sounds/music.mp3',
        isMultiplayer: true
    },
    'rock-paper-scissors': {
        id: 'rock-paper-scissors',
        name: 'Rock Paper Scissors',
        category: '2P',
        typeLabel: '2 Players',
        icon: '/games/pocketclassics/assets/rps-icon.png',
        tagline: 'Fast-paced psychological choice clash with online rival duel!',
        description: 'The timeless hand showdown upgraded with high-energy arcade audio and visual effects. Choose Rock, Paper, or Scissors, predict your opponent’s mind, and build win streaks!',
        rules: [
            'Rock smashes Scissors.',
            'Scissors cut Paper.',
            'Paper covers Rock.',
            'Identical choices result in a tie. First to 3 round wins takes the match crown!'
        ],
        screenshots: ['/games/pocketclassics/games/rock-paper-scissors/ss1.png', '/games/pocketclassics/games/rock-paper-scissors/ss2.png'],
        audio: '/games/pocketclassics/games/rock-paper-scissors/sounds/bg-music.mp3',
        isMultiplayer: true
    },
    'snake': {
        id: 'snake',
        name: 'Snake Classic Arcade',
        category: '1P',
        typeLabel: 'Single Player',
        icon: '/games/pocketclassics/assets/snake-icon.png',
        tagline: 'Eat glowing treats, grow longer, and dodge your own serpentine tail!',
        description: 'The golden age of arcade nostalgia! Steer your swift snake across the grid, feast on delicious apples, grow longer with each bite, and challenge your reflexes as speed escalates.',
        rules: [
            'Use Arrow Keys, WASD, or On-Screen Virtual D-Pad to steer the snake.',
            'Each apple eaten awards points and increases the snake length.',
            'Avoid colliding with the perimeter border walls or your own growing body.',
            'Survive as long as possible to set record high scores!'
        ],
        screenshots: ['/games/pocketclassics/games/snake/ss1.png', '/games/pocketclassics/games/snake/ss2.png'],
        audio: '/games/pocketclassics/games/snake/sounds/bg-music.mp3',
        isMultiplayer: false
    },
    'snakes-ladders': {
        id: 'snakes-ladders',
        name: 'Snakes & Ladders Deluxe',
        category: '2P',
        typeLabel: '2 Players',
        icon: '/games/pocketclassics/assets/snakes-ladders-icon.png',
        tagline: 'Roll the dice, climb epic ladders, and escape treacherous snakes!',
        description: 'The ancient historic board game of fate and fortune. Roll the 3D dice to race your token from square 1 to 100. Catch ladders for huge shortcuts, but beware slippery snakes waiting to swallow you down!',
        rules: [
            'Take turns rolling the 6-sided dice to advance forward across the 100 squares.',
            'Landing on the bottom base of a Ladder launches you straight up to its top square.',
            'Landing on the head of a Snake slides you all the way down to its tail.',
            'The first player to reach exact square 100 wins the championship!'
        ],
        screenshots: ['/games/pocketclassics/games/snakes-ladders/ss1.png', '/games/pocketclassics/games/snakes-ladders/ss2.png'],
        audio: '/games/pocketclassics/games/snakes-ladders/assets/dice.mp3',
        isMultiplayer: true
    },
    'tictactoe': {
        id: 'tictactoe',
        name: 'Tic-Tac-Toe Neon',
        category: '2P',
        typeLabel: '2 Players',
        icon: '/games/pocketclassics/assets/tictactoe-icon.png',
        tagline: 'Match 3 in a row across a glowing 3x3 battle grid!',
        description: 'The classic grid duel reimagined with neon animations, particle celebrations, smart AI difficulty settings, and real-time multiplayer room battles with in-room chat.',
        rules: [
            'Players take alternating turns placing their symbol (X or O) into an empty grid square.',
            'Align 3 of your marks horizontally, vertically, or diagonally to win.',
            'If all 9 squares are filled without 3 in a row, the match ends in a Draw.',
            'Play against local friends, challenging AI, or online rivals via Private Room codes!'
        ],
        screenshots: ['/games/pocketclassics/games/tictactoe/ss1.png', '/games/pocketclassics/games/tictactoe/ss2.png'],
        audio: '/games/pocketclassics/games/tictactoe/audio/background.mp3',
        isMultiplayer: true
    }
};

// 1. Splash Screen
router.get('/', (req, res) => {
    if (req.query.skipSplash === 'true') {
        return res.redirect('/games/hub');
    }
    const user = req.user || null;
    res.render('pages/games/index', {
        title: 'Pocket Classics | GPL Arcade',
        user,
        catalog: GAMES_CATALOG
    });
});

// Purge any legacy guest data from the scoreboard upon module load
GameScore.deleteMany({
    $or: [
        { user: null },
        { user: { $exists: false } },
        { username: /^guest/i },
        { username: 'Guest' }
    ]
}).then(r => {
    if (r && r.deletedCount > 0) {
        console.log(`[Arcade DB] Cleared ${r.deletedCount} guest records from scoreboards.`);
    }
}).catch(err => {
    console.warn('[Arcade DB] Guest cleanup notice:', err.message);
});

// 2. Arcade Hub (Main Menu)
router.get('/hub', async (req, res) => {
    try {
        const user = req.user || null;
        const clubId = req.query.clubId || null;
        let clubData = null;
        if (clubId) {
            clubData = await Club.findById(clubId).select('name icon isVerified vanityUrl');
        }

        // Fetch top global leaderboard snapshot (strictly registered users, zero guest data)
        const topScores = await GameScore.find({
            user: { $ne: null },
            username: { $not: /^guest/i }
        })
            .sort({ score: -1 })
            .limit(10)
            .lean();

        res.render('pages/games/hub', {
            title: 'Pocket Classics Arcade - All Games',
            user,
            catalog: GAMES_CATALOG,
            clubId,
            clubData,
            topScores
        });
    } catch (err) {
        console.error('[Games] Hub render error:', err);
        res.status(500).render('pages/error', {
            title: 'Arcade Error',
            message: 'Unable to load Arcade Hub at this time.'
        });
    }
});

// 3. Leaderboard API
router.get('/api/leaderboard', async (req, res) => {
    try {
        const { gameId, metric, filter, country } = req.query;

        // Strictly exclude guest data from scoreboards
        const query = {
            user: { $ne: null },
            username: { $not: /^guest/i }
        };

        if (gameId && gameId !== 'all') {
            query.gameId = gameId;
        }
        if (filter === 'country' && country) {
            query.country = new RegExp('^' + country + '$', 'i');
        }

        let sortField = { score: -1 };
        if (metric === 'playtime') sortField = { playtime: -1 };
        else if (metric === 'wins') sortField = { wins: -1 };

        const leaderboard = await GameScore.find(query)
            .sort(sortField)
            .limit(50)
            .lean();

        return res.json({
            success: true,
            leaderboard,
            metric: metric || 'score',
            filter: filter || 'global',
            gameId: gameId || 'all'
        });
    } catch (err) {
        console.error('[Games] Leaderboard error:', err);
        return res.status(500).json({ success: false, message: 'Failed to load leaderboard.' });
    }
});

// 4. Session / Score Recording API
router.post('/api/record-session', async (req, res) => {
    try {
        const { gameId, score, wins, losses, draws, playtime } = req.body;
        if (!gameId || !GAMES_CATALOG[gameId]) {
            return res.status(400).json({ success: false, message: 'Invalid game.' });
        }

        const user = req.user || null;

        // REQUIREMENT: We do NOT store any guest data in the database
        if (!user) {
            return res.json({ success: true, message: 'Guest session ignored (guest data is not stored).' });
        }

        const username = user.username;
        const country = user.country || 'Global';
        const avatar = user.cardAvatarUrl || user.avatarUrl || user.profileImage || '/images/default-avatar.png';

        // Playtime is tracked strictly per-game ({ user: user._id, gameId }), never combined across games
        const filterQuery = { user: user._id, gameId };

        const updateData = {
            $set: {
                username,
                country,
                avatar,
                lastPlayedAt: new Date()
            },
            $inc: {
                playtime: Math.max(0, parseInt(playtime, 10) || 0),
                wins: Math.max(0, parseInt(wins, 10) || 0),
                losses: Math.max(0, parseInt(losses, 10) || 0),
                draws: Math.max(0, parseInt(draws, 10) || 0)
            }
        };

        if (score !== undefined && score !== null) {
            updateData.$max = { score: parseInt(score, 10) || 0 };
        }

        const record = await GameScore.findOneAndUpdate(filterQuery, updateData, {
            upsert: true,
            new: true,
            setDefaultsOnInsert: true
        });

        return res.json({ success: true, record });
    } catch (err) {
        console.error('[Games] Record session error:', err);
        return res.status(500).json({ success: false, message: 'Failed to record session.' });
    }
});

// 5. Individual Game Page
router.get('/:gameId', async (req, res) => {
    const gameId = req.params.gameId.toLowerCase().trim();
    const game = GAMES_CATALOG[gameId];

    if (!game) {
        return res.redirect('/games/hub');
    }

    const user = req.user || null;
    const roomCode = req.query.room ? req.query.room.toUpperCase().trim() : '';
    const clubId = req.query.clubId || null;
    let clubData = null;
    if (clubId) {
        clubData = await Club.findById(clubId).select('name icon isVerified vanityUrl');
    }

    res.render('pages/games/game-container', {
        title: `${game.name} - Pocket Classics | GPL Arcade`,
        user,
        game,
        catalog: GAMES_CATALOG,
        roomCode,
        clubId,
        clubData
    });
});

module.exports = router;
