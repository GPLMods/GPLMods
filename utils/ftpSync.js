const ftp = require("basic-ftp");
const fs = require("fs");
const path = require("path");

/**
 * Uploads a file buffer to the InfinityFree FTP server as a backup mirror.
 * @param {Buffer|String} fileData - The file buffer or path to the temp file.
 * @param {String} b2Key - The exact filename/path we used for B2 (e.g., 'icons/123.png').
 */
async function mirrorToFTP(fileData, b2Key) {
    const client = new ftp.Client();
    // client.ftp.verbose = true; // Uncomment for debugging FTP connection issues

    try {
        await client.access({
            host: process.env.FTP_HOST,
            user: process.env.FTP_USER,
            password: process.env.FTP_PASS,
            secure: false // InfinityFree free tier usually does not support FTPS
        });

        // Split the B2 key to get the folder and the filename
        const parts = b2Key.split('/');
        const folderName = parts[0]; // e.g., 'icons'
        const fileName = parts[1];   // e.g., '123-image.png'

        // Navigate to the base website directory (usually 'htdocs' on InfinityFree)
        const basePath = process.env.FTP_BASE_PATH || '/htdocs';
        await client.cd(basePath);

        // Ensure the subfolder (icons/avatars/screenshots) exists on the FTP server
        await client.ensureDir(folderName);

        // Upload the file
        if (Buffer.isBuffer(fileData)) {
            // If it's a memory buffer (which you are using for uploads now)
            const { Readable } = require('stream');
            const stream = Readable.from(fileData);
            await client.uploadFrom(stream, fileName);
        } else if (typeof fileData === 'string' && fs.existsSync(fileData)) {
            // If it's a physical file path (just in case)
            await client.uploadFrom(fileData, fileName);
        }

        console.log(`[FTP Mirror] Successfully backed up ${b2Key} to InfinityFree.`);

    } catch (err) {
        console.error(`[FTP Mirror] Failed to upload ${b2Key}:`, err);
        // We catch the error but DO NOT throw it. If the backup fails, 
        // we still want the main B2 upload to succeed so the user isn't interrupted.
    } finally {
        client.close();
    }
}

/**
 * Deletes a file from the InfinityFree FTP server.
 * @param {String} b2Key - The exact filename/path (e.g., 'icons/123.png').
 */
async function deleteFromFTP(b2Key) {
    if (!b2Key || b2Key === 'external-link') return;

    const client = new ftp.Client();
    try {
        await client.access({
            host: process.env.FTP_HOST,
            user: process.env.FTP_USER,
            password: process.env.FTP_PASS,
            secure: false
        });

        const fullPath = `${process.env.FTP_BASE_PATH || '/htdocs'}/${b2Key}`;
        
        // Attempt to remove the file
        await client.remove(fullPath);
        console.log(`[FTP Mirror] Successfully deleted ${b2Key} from InfinityFree.`);

    } catch (err) {
        // If it's a 550 error, the file probably just didn't exist, which is fine.
        if (err.code !== 550) {
            console.error(`[FTP Mirror] Failed to delete ${b2Key}:`, err.message);
        }
    } finally {
        client.close();
    }
}

module.exports = { mirrorToFTP, deleteFromFTP };