const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const GameScoreSchema = new Schema({
    user: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        default: null,
        index: true
    },
    username: {
        type: String,
        required: true,
        trim: true,
        index: true
    },
    country: {
        type: String,
        trim: true,
        default: 'Global',
        index: true
    },
    avatar: {
        type: String,
        default: '/images/default-avatar.png'
    },
    gameId: {
        type: String,
        required: true,
        enum: [
            '2048',
            'air-hockey',
            'checkers',
            'chess',
            'minesweeper',
            'othello',
            'rock-paper-scissors',
            'snake',
            'snakes-ladders',
            'tictactoe'
        ],
        index: true
    },
    score: {
        type: Number,
        default: 0,
        index: true
    },
    wins: {
        type: Number,
        default: 0,
        index: true
    },
    losses: {
        type: Number,
        default: 0
    },
    draws: {
        type: Number,
        default: 0
    },
    playtime: {
        type: Number, // In seconds
        default: 0,
        index: true
    },
    lastPlayedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

GameScoreSchema.index({ gameId: 1, score: -1 });
GameScoreSchema.index({ gameId: 1, wins: -1 });
GameScoreSchema.index({ gameId: 1, playtime: -1 });
GameScoreSchema.index({ user: 1, gameId: 1 }, { unique: true, sparse: true });

module.exports = mongoose.model('GameScore', GameScoreSchema);
