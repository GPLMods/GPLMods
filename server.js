// 1. IMPORT DEPENDENCIES
require('dotenv').config(); // Loads .env file contents into process.env
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');
const File = require('./models/file'); // Import our File model
const { Types } = mongoose; // Import 'Types' to validate ObjectID

// TODO: In a later step, we'll move B2 and VirusTotal logic to separate files.
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const axios = require('axios');


// 2. INITIALIZE APP & MIDDLEWARE
const app = express();
const PORT = process.env.PORT || 3000;

// Set the view engine to EJS
app.set('view engine', 'ejs');
// Let Express know where our view files are
app.set('views', path.join(__dirname, 'views'));

// Serve static files (CSS, client-side JS, images) from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));
// Parse URL-encoded bodies (as sent by HTML forms)
app.use(express.urlencoded({ extended: true }));


// 3. CONFIGURE FILE UPLOAD (MULTER)
// We use memoryStorage to hold the file as a buffer before uploading to the cloud
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 } // 100 MB file size limit
});


// 4. DATABASE CONNECTION
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Successfully connected to MongoDB Atlas!'))
    .catch(error => console.error('Error connecting to MongoDB Atlas:', error));


// 5. DEFINE ROUTES
/**
 * GET Route for the Homepage - Updated to show recent files
 */
app.get('/', async (req, res) => {
    try {
        // Fetch all files from the database, sorted by the newest first
        const recentFiles = await File.find().sort({ createdAt: -1 }).limit(12);

        // Render the index page and pass the 'files' variable to it
        res.render('pages/index', { files: recentFiles });

    } catch (error) {
        console.error("Error fetching files for homepage:", error);
        res.status(500).send("Server error.");
    }
});


/**
 * GET Route for the Upload Page
 */
app.get('/upload', (req, res) => {
    // For now, any user can see the upload page. You'll add authentication middleware later.
    res.render('pages/upload');
});

/**
 * POST Route to handle the actual file upload
 */
app.post('/upload', upload.fields([
    { name: 'softwareIcon', maxCount: 1 },
    { name: 'screenshots', maxCount: 4 },
    { name: 'modFile', maxCount: 1 }
]), async (req, res) => {

    // Log for debugging
    console.log('Received files:', req.files);
    console.log('Received body:', req.body);

    const { softwareIcon, screenshots, modFile } = req.files;
    const { softwareName, softwareVersion, modDescription, officialDescription, category, platforms, tags, videoUrl } = req.body;

    // --- Basic Backend Validation ---
    if (!softwareIcon || !screenshots || !modFile || !softwareName || !category) {
        return res.status(400).send("A required field or file is missing.");
    }

    try {
        // --- BACKBLAZE B2 CLIENT SETUP ---
        const s3Client = new S3Client({
            endpoint: process.env.B2_ENDPOINT,
            region: process.env.B2_REGION,
            credentials: {
                accessKeyId: process.env.B2_ACCESS_KEY_ID,
                secretAccessKey: process.env.B2_SECRET_ACCESS_KEY,
            },
        });

        // --- Helper function for uploading ---
        const uploadToB2 = async (file, folder) => {
            const fileName = `${folder}/${Date.now()}-${file.originalname}`;
            const params = {
                Bucket: process.env.B2_BUCKET_NAME,
                Key: fileName,
                Body: file.buffer,
                ContentType: file.mimetype,
            };
            await s3Client.send(new PutObjectCommand(params));
            // Construct the public URL
            // NOTE: You must make your bucket public in Backblaze B2 settings for this URL structure to work.
            const friendlyBucketName = process.env.B2_BUCKET_NAME;
            const b2HostName = process.env.B2_ENDPOINT.split('//')[1];
            return `https://${friendlyBucketName}.${b2HostName}/${fileName}`;
        };

        // --- 1. UPLOAD FILES TO B2 ---
        const iconUrl = await uploadToB2(softwareIcon[0], 'icons');

        const screenshotUrls = [];
        for (const screenshot of screenshots) {
            const url = await uploadToB2(screenshot, 'screenshots');
            screenshotUrls.push(url);
        }

        const fileUrl = await uploadToB2(modFile[0], 'mods');


        // --- 2. (OPTIONAL) SUBMIT FILE TO VIRUSTOTAL ---
        let analysisId = null;
        try {
            const formData = new FormData();
            formData.append('file', new Blob([modFile[0].buffer]), modFile[0].originalname);
            const vtResponse = await axios.post('https://www.virustotal.com/api/v3/files', formData, {
                headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
            });
            analysisId = vtResponse.data.data.id;
            console.log('VirusTotal Analysis ID:', analysisId);
        } catch (vtError) {
            console.error("Error submitting to VirusTotal:", vtError.response?.data);
            // Decide if you want to stop the upload or continue without a scan ID
        }

        // --- 3. SAVE FILE METADATA TO MONGODB ---
        const newFile = new File({
            name: softwareName,
            version: softwareVersion,
            modDescription,
            officialDescription,
            iconUrl,
            screenshotUrls,
            videoUrl,
            fileUrl,
            category,
            platforms: Array.isArray(platforms) ? platforms : [platforms], // Ensure platforms is an array
            tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
            fileSize: modFile[0].size,
            virusTotalAnalysisId: analysisId
        });

        await newFile.save();

        // --- 4. RESPOND TO USER ---
        // You could redirect them to the new file's download page later
        res.status(201).send(`<h1>File uploaded successfully!</h1><p>Thank you for your contribution.</p><a href="/">Go to Homepage</a>`);

    } catch (error) {
        console.error("Upload process failed:", error);
        res.status(500).send("An error occurred during the upload process.");
    }
});


/**
 * GET Route for a specific mod download page.
 * Uses a route parameter ':id' to dynamically catch the file ID from the URL.
 */
app.get('/mods/:id', async (req, res) => {
    try {
        const fileId = req.params.id;

        // --- Basic validation for MongoDB ObjectID ---
        if (!Types.ObjectId.isValid(fileId)) {
            return res.status(404).send("File not found (Invalid ID format).");
        }

        // Find the file in the database by its unique ID
        const file = await File.findById(fileId);

        if (!file) {
            // If no file is found with that ID, send a 404 error
            return res.status(404).send("File not found.");
        }

        // If the file is found, render the 'download' page and pass the file object to it
        res.render('pages/download', { file: file });

    } catch (error) {
        console.error("Error fetching file for download page:", error);
        res.status(500).send("Server error.");
    }
});

/**
 * GET Route for the category page.
 * Uses URL query parameters to filter the results.
 * e.g., /category?cat=windows  or /category?cat=android
 */
app.get('/category', async (req, res) => {
    try {
        const { cat } = req.query; // Destructure to get 'cat' from the query string

        if (!cat) {
            // If no category is specified, maybe redirect to the homepage or an error page
            return res.redirect('/');
        }
        
        // --- Build a dynamic query object for MongoDB ---
        const queryFilter = {
            category: cat // Filter where the 'category' field matches the 'cat' parameter
        };
        
        // Find all files that match the filter, sorted by newest first
        const filteredFiles = await File.find(queryFilter).sort({ createdAt: -1 });

        // Capitalize the category name for display on the page
        const pageTitle = cat.charAt(0).toUpperCase() + cat.slice(1);
        
        // Render the 'category' page, passing it the title and the filtered list of files
        res.render('pages/category', { 
            files: filteredFiles, 
            title: pageTitle,
            currentCategory: cat
        });

    } catch (error) {
        console.error("Error fetching files for category page:", error);
        res.status(500).send("Server error.");
    }
});


/**
 * GET Route to handle the actual file download action.
 * This will increment the download count and redirect to the B2 URL.
 */
app.get('/download-file/:id', async (req, res) => {
    try {
        const fileId = req.params.id;

        if (!Types.ObjectId.isValid(fileId)) {
            return res.status(404).send("File not found.");
        }

        // Use findByIdAndUpdate to increment the download count and retrieve the document in one go
        const file = await File.findByIdAndUpdate(
            fileId,
            { $inc: { downloads: 1 } }, // The '$inc' operator atomically increments a field
            { new: true } // 'new: true' returns the modified document
        );

        if (!file) {
            return res.status(404).send("File not found.");
        }

        // Redirect the user's browser to the actual file URL on Backblaze B2
        res.redirect(file.fileUrl);

    } catch (error) {
        console.error("Error processing file download:", error);
        res.status(500).send("Server error.");
    }
});


// 6. START THE SERVER
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});