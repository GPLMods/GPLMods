// server.js
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

const app = express();
const upload = multer({ dest: 'uploads/' }); // Temporarily store files in an 'uploads' folder

// Serve all your static HTML, CSS, JS files
app.use(express.static(path.join(__dirname)));

// The endpoint your front-end will send the file to
app.post('/scan-file', upload.single('modFile'), async (req, res) => {
    const filePath = req.file.path;
    const VT_API_KEY = process.env.VT_API_KEY; // Securely get API key from Render's environment

    if (!VT_API_KEY) {
        fs.unlinkSync(filePath); // Clean up the uploaded file
        return res.status(500).json({ message: "Server is missing API key." });
    }

    try {
        // Step 1: Upload the file to VirusTotal
        const form = new FormData();
        form.append('file', fs.createReadStream(filePath));

        const uploadResponse = await axios.post('https://www.virustotal.com/api/v3/files', form, {
            headers: {
                ...form.getHeaders(),
                'x-apikey': VT_API_KEY
            }
        });

        const analysisId = uploadResponse.data.data.id;
        
        // Step 2: Get the analysis report
        // In a real app, you might need to poll this endpoint until the status is 'completed'
        const reportResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: { 'x-apikey': VT_API_KEY }
        });

        const stats = reportResponse.data.data.attributes.stats;
        const isMalicious = stats.malicious > 0 || stats.suspicious > 0;
        
        // Clean up the uploaded file from our server
        fs.unlinkSync(filePath);

        // Send the result back to the front-end
        if (isMalicious) {
            res.status(400).json({ 
                message: `Scan complete: Potentially unsafe file detected! (${stats.malicious} detections). Upload rejected.`,
                safe: false 
            });
        } else {
            res.json({ 
                message: `Scan complete: File appears to be safe! (${stats.harmless} engines reported it as harmless).`,
                safe: true 
            });
        }

    } catch (error) {
        fs.unlinkSync(filePath); // Clean up on error too
        console.error("VirusTotal API error:", error.response ? error.response.data : error.message);
        res.status(500).json({ message: "An error occurred during the scan." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});