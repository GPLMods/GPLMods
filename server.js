// server.js
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // Allow connections from any origin (your static site)
    methods: ["GET", "POST"]
  }
});

// This tells Express to serve your static files (HTML, CSS, JS) from the same server.
// We will deploy them separately on Render, but this is good practice.
app.use(express.static(__dirname));

io.on('connection', (socket) => {
    console.log('A user connected!');
    socket.broadcast.emit('chat message', { user: 'System', text: 'A new user has joined.' });

    socket.on('chat message', (msg) => {
        socket.broadcast.emit('chat message', msg);
    });

    socket.on('disconnect', () => {
        console.log('User disconnected');
        io.emit('chat message', { user: 'System', text: 'A user has left.' });
    });
});

// Render provides a PORT environment variable.
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});