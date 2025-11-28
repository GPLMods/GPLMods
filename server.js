// ===================================================================
// GPL MODS - MAIN SERVER FILE (server.js)
// This file is now the "Air Traffic Controller". It directs requests.
// ===================================================================

// --- 1. SETUP & IMPORTS ---
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// --- A. MAINTENANCE MODE SWITCH ---
const IN_MAINTENANCE_MODE = false;

// --- 2. MIDDLEWARE ---
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
    if (IN_MAINTENANCE_MODE && req.path.indexOf('.html') === -1 && req.path !== '/') {
        // Allow assets to load on the coming soon page
    } else if (IN_MAINTENANCE_MODE && req.path !== '/errors-pages/coming-soon.html') {
        return res.status(503).sendFile(path.join(__dirname, 'errors-pages', 'coming-soon.html'));
    }
    next();
});

// --- 3. DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('SUCCESS: Connected to MongoDB Atlas!'))
    .catch(err => console.error('ERROR: Could not connect to MongoDB Atlas.', err));


// --- 4. DEFINE & USE API ROUTES ---
// This is the core change. We are telling Express to use our organized route files.
app.use('/api/auth', require('./routes/api/auth'));
app.use('/api/users', require('./routes/api/users'));
app.use('/api/mods', require('./routes/api/mods'));
// Note: We no longer have any API logic (like app.post('/upload-mod')) in this file. It's all in the routes folder.


// --- 5. CATCH-ALL ROUTE FOR SERVING FILES AND 404s ---
app.use((req, res, next) => {
    const safePath = path.normalize(req.path).replace(/^(\.\.[\/\\])+/, '');
    const filePath = path.join(__dirname, safePath);
    
    if (fs.existsSync(filePath) && fs.lstatSync(filePath).isFile()) {
        return res.sendFile(filePath);
    }
    
    const htmlFilePath = filePath.endsWith('/') ? path.join(filePath, 'index.html') : filePath + '.html';
    if (fs.existsSync(htmlFilePath)) {
        return res.sendFile(htmlFilePath);
    }

    res.status(404).sendFile(path.join(__dirname, 'errors-pages', 'error-404.html'));
});


// --- 6. FINAL ERROR HANDLER (for 500 Server Errors) ---
app.use((err, req, res, next) => {
    console.error('--- UNHANDLED SERVER ERROR ---', err.stack);
    if (!res.headersSent) {
        res.status(500).sendFile(path.join(__dirname, 'errors-pages', 'error-500.html'));
    }
});


// --- 7. SERVER INITIALIZATION ---
app.listen(PORT, () => {
    console.log(`GPL Mods server is live and listening on http://localhost:${PORT}`);
});