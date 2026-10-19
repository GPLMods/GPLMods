const GameScore = require('../models/gameScore');
const User = require('../models/user');

const arcadeSockets = new Map(); // socket.id -> { user, gameId, roomCode }
const gameRooms = new Map(); // roomCode -> room object
const waitingQuickMatch = new Map(); // gameId -> [roomCode]

function generateRoomCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 6; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

function broadcastPresence(io) {
    const totalOnline = arcadeSockets.size;
    const gameCounts = {};
    for (const [, data] of arcadeSockets) {
        if (data.gameId) {
            gameCounts[data.gameId] = (gameCounts[data.gameId] || 0) + 1;
        }
    }
    io.to('arcade_lobby').emit('arcade_presence_update', {
        totalOnline,
        gameCounts
    });
}

function getPlayerProfile(socket) {
    const user = socket.request && socket.request.user ? socket.request.user : null;
    if (user) {
        return {
            id: String(user._id || socket.id),
            username: user.username || 'GPL Player',
            country: user.country || 'Global',
            avatar: user.cardAvatarUrl || user.avatarUrl || user.profileImage || '/images/default-avatar.png',
            isGuest: false
        };
    }
    return {
        id: socket.id,
        username: socket.data?.username || 'Guest_' + socket.id.substring(0, 4),
        country: socket.data?.country || 'Global',
        avatar: '/images/default-avatar.png',
        isGuest: true
    };
}

module.exports = function initGameSockets(io) {
    io.on('connection', (socket) => {
        // --- ARCADE LOBBY JOIN ---
        socket.on('arcade_join_lobby', (data) => {
            socket.join('arcade_lobby');
            const profile = getPlayerProfile(socket);
            if (data && data.username && profile.isGuest) {
                socket.data.username = data.username;
                profile.username = data.username;
            }
            if (data && data.country && profile.isGuest) {
                socket.data.country = data.country;
                profile.country = data.country;
            }
            arcadeSockets.set(socket.id, {
                profile,
                gameId: data?.gameId || null,
                roomCode: null
            });
            broadcastPresence(io);
        });

        // --- ARCADE ACTIVE GAME TRACKING ---
        socket.on('arcade_set_game', (data) => {
            const entry = arcadeSockets.get(socket.id);
            if (entry) {
                entry.gameId = data?.gameId || null;
                broadcastPresence(io);
            }
        });

        // --- QUICK MATCH ---
        socket.on('arcade_quick_match', (data) => {
            const gameId = data?.gameId;
            if (!gameId) return socket.emit('arcade_error', { message: 'Missing game ID.' });

            const profile = getPlayerProfile(socket);
            if (profile.isGuest) {
                return socket.emit('arcade_error', { message: 'Guests cannot play online multiplayer. Please sign in or register to match with online players.' });
            }

            const queue = waitingQuickMatch.get(gameId) || [];

            // Find an open room in queue
            while (queue.length > 0) {
                const candidateCode = queue.shift();
                const room = gameRooms.get(candidateCode);
                if (room && room.status === 'waiting' && room.host.socketId !== socket.id) {
                    // Match found!
                    room.guest = { ...profile, socketId: socket.id, role: 'player2' };
                    room.status = 'playing';
                    room.turn = 'player1'; // host starts
                    socket.join(candidateCode);

                    const entry = arcadeSockets.get(socket.id);
                    if (entry) entry.roomCode = candidateCode;

                    io.to(candidateCode).emit('arcade_match_found', {
                        roomCode: candidateCode,
                        gameId,
                        host: room.host,
                        guest: room.guest,
                        turn: room.turn,
                        mode: 'quick'
                    });
                    return;
                }
            }

            // No available room, create new one
            let roomCode;
            do {
                roomCode = generateRoomCode();
            } while (gameRooms.has(roomCode));

            const room = {
                roomCode,
                gameId,
                mode: 'quick',
                status: 'waiting',
                host: { ...profile, socketId: socket.id, role: 'player1' },
                guest: null,
                turn: 'player1',
                createdAt: Date.now()
            };

            gameRooms.set(roomCode, room);
            if (!waitingQuickMatch.has(gameId)) waitingQuickMatch.set(gameId, []);
            waitingQuickMatch.get(gameId).push(roomCode);

            socket.join(roomCode);
            const entry = arcadeSockets.get(socket.id);
            if (entry) entry.roomCode = roomCode;

            socket.emit('arcade_room_created', {
                roomCode,
                gameId,
                status: 'waiting',
                isHost: true
            });
        });

        // --- CREATE PRIVATE ROOM ---
        socket.on('arcade_create_private_room', (data) => {
            const gameId = data?.gameId;
            if (!gameId) return socket.emit('arcade_error', { message: 'Missing game ID.' });

            const profile = getPlayerProfile(socket);
            if (profile.isGuest) {
                return socket.emit('arcade_error', { message: 'Guests cannot create private rooms. Please sign in or register to invite friends!' });
            }

            let roomCode;
            do {
                roomCode = generateRoomCode();
            } while (gameRooms.has(roomCode));

            const room = {
                roomCode,
                gameId,
                mode: 'private',
                status: 'waiting',
                host: { ...profile, socketId: socket.id, role: 'player1' },
                guest: null,
                turn: 'player1',
                createdAt: Date.now()
            };

            gameRooms.set(roomCode, room);
            socket.join(roomCode);

            const entry = arcadeSockets.get(socket.id);
            if (entry) entry.roomCode = roomCode;

            socket.emit('arcade_private_room_created', {
                roomCode,
                gameId,
                inviteUrl: `/games/${gameId}?room=${roomCode}`,
                status: 'waiting',
                isHost: true,
                host: room.host
            });
        });

        // --- JOIN PRIVATE ROOM ---
        socket.on('arcade_join_private_room', (data) => {
            const profile = getPlayerProfile(socket);
            if (profile.isGuest) {
                return socket.emit('arcade_error', { message: 'Guests cannot join online rooms. Please sign in or register to play with friends!' });
            }

            const rawCode = (data?.roomCode || '').toUpperCase().trim();
            const room = gameRooms.get(rawCode);

            if (!room) {
                return socket.emit('arcade_error', { message: `Room "${rawCode}" not found or has expired.` });
            }
            if (room.status !== 'waiting' || room.guest) {
                return socket.emit('arcade_error', { message: `Room "${rawCode}" is already full or in progress.` });
            }
            if (room.host.socketId === socket.id) {
                return socket.emit('arcade_error', { message: 'You are already the host of this room.' });
            }
            room.guest = { ...profile, socketId: socket.id, role: 'player2' };
            room.status = 'playing';
            room.turn = 'player1';

            socket.join(rawCode);
            const entry = arcadeSockets.get(socket.id);
            if (entry) entry.roomCode = rawCode;

            io.to(rawCode).emit('arcade_match_found', {
                roomCode: rawCode,
                gameId: room.gameId,
                host: room.host,
                guest: room.guest,
                turn: room.turn,
                mode: 'private'
            });
        });

        // --- GAME PLAY ACTION SYNC ---
        socket.on('arcade_game_action', (data) => {
            const { roomCode, action, payload } = data || {};
            if (!roomCode) return;
            const room = gameRooms.get(roomCode);
            if (!room || room.status !== 'playing') return;

            // Broadcast move/action to opponent
            socket.to(roomCode).emit('arcade_opponent_action', {
                action,
                payload,
                senderSocketId: socket.id
            });
        });

        // --- LIVE IN-ROOM CHAT & EMOJIS ---
        socket.on('arcade_room_message', (data) => {
            const { roomCode, text, emoji } = data || {};
            if (!roomCode) return;
            const room = gameRooms.get(roomCode);
            if (!room) return;

            const profile = getPlayerProfile(socket);
            io.to(roomCode).emit('arcade_room_chat_message', {
                sender: profile.username,
                avatar: profile.avatar,
                country: profile.country,
                text: text ? String(text).slice(0, 100) : '',
                emoji: emoji || '',
                timestamp: Date.now()
            });
        });

        // --- GAME OVER & STATS UPDATE ---
        socket.on('arcade_game_over', async (data) => {
            const { roomCode, gameId, winner, score, playtime } = data || {};
            if (roomCode) {
                const room = gameRooms.get(roomCode);
                if (room) {
                    room.status = 'ended';
                    io.to(roomCode).emit('arcade_game_ended', {
                        winner,
                        roomCode
                    });
                }
            }

            // Persist stats if authenticated or valid
            try {
                const user = socket.request && socket.request.user ? socket.request.user : null;
                const profile = getPlayerProfile(socket);
                const query = user ? { user: user._id, gameId } : { username: profile.username, gameId };

                const isWinner = winner === profile.username || winner === 'win';
                const isLoss = winner && winner !== 'draw' && !isWinner;
                const isDraw = winner === 'draw';

                const update = {
                    $set: {
                        username: profile.username,
                        country: profile.country,
                        avatar: profile.avatar,
                        lastPlayedAt: new Date()
                    },
                    $inc: {
                        playtime: Math.max(0, parseInt(playtime, 10) || 0),
                        wins: isWinner ? 1 : 0,
                        losses: isLoss ? 1 : 0,
                        draws: isDraw ? 1 : 0
                    }
                };

                if (score !== undefined && score !== null) {
                    update.$max = { score: parseInt(score, 10) || 0 };
                }

                await GameScore.findOneAndUpdate(query, update, { upsert: true, new: true, setDefaultsOnInsert: true });
            } catch (err) {
                console.error('[Arcade] Error updating game score:', err);
            }
        });

        // --- LEAVE / DISCONNECT ---
        function handleLeave() {
            const entry = arcadeSockets.get(socket.id);
            if (entry && entry.roomCode) {
                const room = gameRooms.get(entry.roomCode);
                if (room) {
                    socket.to(entry.roomCode).emit('arcade_opponent_left', {
                        roomCode: entry.roomCode,
                        message: 'Opponent disconnected or left the game.'
                    });
                    gameRooms.delete(entry.roomCode);

                    // Remove from waiting queue if present
                    if (waitingQuickMatch.has(room.gameId)) {
                        const q = waitingQuickMatch.get(room.gameId);
                        const idx = q.indexOf(entry.roomCode);
                        if (idx !== -1) q.splice(idx, 1);
                    }
                }
            }
            arcadeSockets.delete(socket.id);
            broadcastPresence(io);
        }

        socket.on('arcade_leave_room', handleLeave);
        socket.on('disconnect', handleLeave);
    });
};
