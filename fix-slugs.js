require('dotenv').config();
const mongoose = require('mongoose');
const File = require('./models/file'); // Adjust path if your models folder is elsewhere

// We reuse the exact same slugify function from server.js
function slugify(text) {
    if (!text) return '';
    return text.toString().toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^\w\-]+/g, '')
        .replace(/\-\-+/g, '-')
        .replace(/^-+/, '')
        .replace(/-+$/, '');
}

async function fixMissingSlugs() {
    try {
        console.log("Connecting to database...");
        await mongoose.connect(process.env.MONGO_URI);
        console.log("Connected. Searching for mods without slugs...");

        // Find all files where the slug field doesn't exist, is null, or is an empty string
        const filesToFix = await File.find({
            $or: [
                { slug: { $exists: false } },
                { slug: null },
                { slug: '' }
            ]
        });

        console.log(`Found ${filesToFix.length} files that need fixing.`);

        for (const file of filesToFix) {
            let baseSlug = slugify(file.name);
            let finalSlug = baseSlug;
            let slugCounter = 1;

            // Ensure the generated slug is unique within its category
            while (await File.findOne({ 
                slug: finalSlug, 
                category: file.category,
                isLatestVersion: true,
                _id: { $ne: file._id } 
            })) {
                finalSlug = `${baseSlug}-${slugCounter}`;
                slugCounter++;
            }

            // Save the new slug to the database
            file.slug = finalSlug;
            await file.save();
            console.log(`Fixed: "${file.name}" -> /${file.category}/${file.slug}`);
        }

        console.log("All missing slugs have been generated successfully!");

    } catch (error) {
        console.error("An error occurred:", error);
    } finally {
        // Disconnect from the database so the script can finish and exit
        await mongoose.disconnect();
        console.log("Database disconnected.");
    }
}

// Run the script
fixMissingSlugs();