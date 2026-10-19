/**
 * ============================================================================
 * POCKET CLASSICS - MULTIPLAYER & REALTIME ROOM CLIENT
 * Connects to Socket.IO, manages rooms, matchmaking, in-room chat & stats
 * ============================================================================
 */
(function() {
    class ArcadeMultiplayer {
        constructor() {
            this.socket = null;
            this.currentRoom = null;
            this.isHost = false;
            this.gameId = null;
            this.callbacks = {
                onMatchFound: null,
                onPrivateRoomCreated: null,
                onRoomWaiting: null,
                onOpponentAction: null,
                onChatMessage: null,
                onOpponentLeft: null,
                onPresenceUpdate: null
            };
            this.initSocket();
        }

        initSocket() {
            if (typeof io === 'undefined') return;
            this.socket = io({
                transports: ['websocket', 'polling']
            });

            this.socket.on('connect', () => {
                const username = window.__ARCADE_USER__?.username || 'Guest';
                const country = window.__ARCADE_USER__?.country || 'Global';
                this.socket.emit('arcade_join_lobby', {
                    username,
                    country,
                    gameId: this.gameId
                });
            });

            this.socket.on('arcade_presence_update', (data) => {
                const countBadge = document.getElementById('arcadeTotalOnline');
                if (countBadge && data && data.totalOnline !== undefined) {
                    countBadge.textContent = `${data.totalOnline} Online`;
                }
                if (this.callbacks.onPresenceUpdate) {
                    this.callbacks.onPresenceUpdate(data);
                }
            });

            this.socket.on('arcade_private_room_created', (data) => {
                this.currentRoom = data.roomCode;
                this.isHost = true;
                if (this.callbacks.onPrivateRoomCreated) {
                    this.callbacks.onPrivateRoomCreated(data);
                }
            });

            this.socket.on('arcade_room_created', (data) => {
                this.currentRoom = data.roomCode;
                this.isHost = true;
                if (this.callbacks.onRoomWaiting) {
                    this.callbacks.onRoomWaiting(data);
                }
            });

            this.socket.on('arcade_match_found', (data) => {
                this.currentRoom = data.roomCode;
                this.isHost = (data.host.socketId === this.socket.id);
                if (this.callbacks.onMatchFound) {
                    this.callbacks.onMatchFound(data);
                }
            });

            this.socket.on('arcade_opponent_action', (data) => {
                if (this.callbacks.onOpponentAction) {
                    this.callbacks.onOpponentAction(data);
                }
            });

            this.socket.on('arcade_room_chat_message', (msg) => {
                this.renderChatMessage(msg);
                if (this.callbacks.onChatMessage) {
                    this.callbacks.onChatMessage(msg);
                }
            });

            this.socket.on('arcade_opponent_left', (data) => {
                if (this.callbacks.onOpponentLeft) {
                    this.callbacks.onOpponentLeft(data);
                }
            });

            this.socket.on('arcade_error', (data) => {
                const msg = data?.message || 'Multiplayer Error';
                if (window.ArcadeToast) window.ArcadeToast.show(msg, 'error');
                else alert(msg);
            });
        }

        quickMatch(gameId) {
            this.gameId = gameId;
            if (!this.socket) return;
            this.socket.emit('arcade_quick_match', { gameId });
        }

        createPrivateRoom(gameId) {
            this.gameId = gameId;
            if (!this.socket) return;
            this.socket.emit('arcade_create_private_room', { gameId });
        }

        joinPrivateRoom(roomCode) {
            if (!this.socket || !roomCode) return;
            this.socket.emit('arcade_join_private_room', { roomCode });
        }

        sendAction(action, payload) {
            if (!this.socket || !this.currentRoom) return;
            this.socket.emit('arcade_game_action', {
                roomCode: this.currentRoom,
                action,
                payload
            });
        }

        sendChatMessage(text, emoji) {
            if (!this.socket || !this.currentRoom) return;
            this.socket.emit('arcade_room_message', {
                roomCode: this.currentRoom,
                text,
                emoji
            });
        }

        recordGameOver(winner, score, playtime) {
            if (this.socket && this.currentRoom) {
                this.socket.emit('arcade_game_over', {
                    roomCode: this.currentRoom,
                    gameId: this.gameId,
                    winner,
                    score,
                    playtime
                });
            } else {
                // Post directly via API for solo play
                fetch('/games/api/record-session', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        gameId: this.gameId,
                        score: score || 0,
                        playtime: playtime || 0,
                        wins: winner === 'win' ? 1 : 0,
                        losses: winner === 'lose' ? 1 : 0,
                        draws: winner === 'draw' ? 1 : 0
                    })
                }).catch(err => console.error('[Arcade] Save score error:', err));
            }
        }

        renderChatMessage(msg) {
            const chatBox = document.getElementById('roomChatMessages');
            if (!chatBox) return;
            const bubble = document.createElement('div');
            bubble.style.cssText = 'margin-bottom: 8px; font-size: 0.84rem; display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.05); padding: 6px 10px; border-radius: 8px;';
            bubble.innerHTML = `
                <img src="${msg.avatar}" style="width: 20px; height: 20px; border-radius: 50%; object-fit: cover;">
                <strong style="color: var(--arc-accent);">${msg.sender}:</strong>
                <span>${msg.text} ${msg.emoji ? `<span style="font-size: 1.1rem;">${msg.emoji}</span>` : ''}</span>
            `;
            chatBox.appendChild(bubble);
            chatBox.scrollTop = chatBox.scrollHeight;
        }
    }

    window.ArcadeMP = new ArcadeMultiplayer();
})();
