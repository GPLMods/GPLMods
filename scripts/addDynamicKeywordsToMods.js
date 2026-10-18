/**
 * GPLMods Dynamic Keyword Migration Script
 * 
 * Iterates through mods in MongoDB and populates:
 * 1. dynamicKeywords: Rich intent search terms generated from mod details, brand unspaced terms, and platform tags
 * 2. tags: Enhanced SEO tags
 * 
 * Usage:
 * node scripts/addDynamicKeywordsToMods.js
 */

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const dns = require('dns');
// Configure Google DNS resolvers to ensure reliable Atlas SRV resolution
dns.setServers([
    '8.8.8.8',
    '8.8.4.4',
    '2001:4860:4860::8888',
    '2001:4860:4860::8844'
]);

const mongoose = require('mongoose');
const File = require('../models/core/file');
const { generateKeywordsForMod, UNSPACED_BRAND_KEYWORDS } = require('../utils/dynamicKeywords');

async function migrateDynamicKeywords() {
    console.log('==================================================');
    console.log('🚀 GPLMODS DYNAMIC KEYWORDS MIGRATION');
    console.log('==================================================\n');

    const mongoUri = process.env.MONGO_URI;
    if (!mongoUri) {
        console.error('❌ Error: MONGO_URI environment variable is missing.');
        process.exit(1);
    }

    try {
        console.log('⏳ Connecting to MongoDB Atlas...');
        await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 15000 });
        console.log('✅ Connected to MongoDB successfully.\n');

        // Query all files with a valid name
        const query = { name: { $exists: true, $ne: '' } };
        const totalMods = await File.countDocuments(query);
        console.log(`📦 Found ${totalMods} mods to process.`);

        const cursor = File.find(query).cursor();
        let processed = 0;
        let updated = 0;

        for (let mod = await cursor.next(); mod != null; mod = await cursor.next()) {
            processed++;

            // 1. Generate intent keywords for this mod
            const modKeywords = generateKeywordsForMod(mod);

            // 2. Build unique keyword set
            const keywordSet = new Set();

            // Include brand unspaced terms
            UNSPACED_BRAND_KEYWORDS.forEach(kw => {
                if (kw) keywordSet.add(kw.toLowerCase().trim());
            });

            // Include mod-specific keywords
            modKeywords.forEach(kw => {
                if (kw) keywordSet.add(kw.toLowerCase().trim());
            });

            // Include existing dynamic keywords if any
            if (Array.isArray(mod.dynamicKeywords)) {
                mod.dynamicKeywords.forEach(kw => {
                    if (kw) keywordSet.add(String(kw).toLowerCase().trim());
                });
            }

            const dynamicKeywordsList = Array.from(keywordSet).slice(0, 50);

            // 3. Ensure tags are also rich and include brand tag
            const existingTags = Array.isArray(mod.tags) ? mod.tags : [];
            const tagSet = new Set(existingTags.map(t => String(t).trim()).filter(Boolean));
            
            // Add brand tag and platform tag
            tagSet.add('gplmods');
            if (mod.category) tagSet.add(mod.category.toLowerCase().trim());
            if (mod.name) tagSet.add(mod.name.toLowerCase().trim());

            const updatedTags = Array.from(tagSet);

            // 4. Update file document in MongoDB
            await File.findByIdAndUpdate(mod._id, {
                $set: {
                    dynamicKeywords: dynamicKeywordsList,
                    tags: updatedTags
                }
            });

            updated++;

            if (processed % 10 === 0 || processed === totalMods) {
                console.log(`  ⚡ Processed ${processed}/${totalMods} mods (${updated} updated)...`);
            }
        }

        console.log('\n==================================================');
        console.log(`🎉 Migration Completed Successfully!`);
        console.log(`   Total mods processed: ${processed}`);
        console.log(`   Total mods updated:   ${updated}`);
        console.log('==================================================\n');

    } catch (err) {
        console.error('❌ Migration Error:', err);
    } finally {
        await mongoose.disconnect();
        console.log('🔌 Disconnected from MongoDB.');
        process.exit(0);
    }
}

migrateDynamicKeywords();
