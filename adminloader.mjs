// adminloader.mjs

// 1. Imports
import 'dotenv/config'; 
import mongoose from 'mongoose';
import dns from 'dns/promises'; // Use the promises version for modern async/await
import { setServers } from 'dns'; // We need the synchronous version just for setting the servers
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

import AdminJS from 'adminjs';
import * as AdminJSMongoose from '@adminjs/mongoose';
import { dark, light } from '@adminjs/themes';

import loaderModule from './components/loader.js';
const { componentLoader, Components } = loaderModule;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==========================================
// FORCE GOOGLE DNS RESOLUTION
// ==========================================
// This tells Node.js to use these specific servers for DNS lookups 
// instead of the system defaults.
setServers([
    '8.8.8.8',
    '8.8.4.4',
    '2001:4860:4860::8888',
    '2001:4860:4860::8844'
]);

// ==========================================
// THEME CONFIGURATION (Must match server.js)
// ==========================================
const gplModsTheme = {
    ...dark,
    id: 'dark', 
    name: 'GPL Mods Premium',
    overrides: {
        ...dark.overrides, 
        colors: {
            ...dark.overrides?.colors, 
            primary100: '#FFD700', primary80: '#e5c200', primary60: '#ccad00', primary40: '#b29700', primary20: '#332b00',  
            bg: '#0a0a0a', container: '#1a1a1a', white: '#1a1a1a', text: '#ffffff', grey100: '#ffffff',    
            grey80: '#c0c0c0', grey60: '#a0a0a0', grey40: '#444444', grey20: '#2a2a2a', border: '#333333',     
            errorLight: '#ffadad', error: '#e53935', errorDark: '#b71c1c', successLight: '#b0ffb0', success: '#43a047',    
            successDark: '#1b5e20', infoLight: '#90caf9', info: '#2196F3', infoDark: '#0d47a1',
        }
    }
};

// ==========================================
// MAIN BUILDER FUNCTION
// ==========================================
async function runAdminBuilder() {
    console.log('\n==================================================');
    console.log('🚀 INITIALIZING ADMINJS PRE-BUILD SEQUENCE');
    console.log('==================================================\n');

    // --- STEP 1: Network Check (Forced via Google DNS) ---
    process.stdout.write('⏳ Checking network connectivity (via 8.8.8.8)... ');
    try {
        // We try to resolve a highly reliable domain (google.com) to verify internet access.
        // Since we ran setServers() above, this lookup goes directly to 8.8.8.8.
        await dns.resolve('google.com'); 
        console.log('✅ Online');
    } catch (e) {
        console.log('❌ Offline');
        console.error('\nCRITICAL: Network resolution failed using Google DNS.');
        console.error('Error details:', e.message);
        console.error('Build aborted to prevent partial compilation.\n');
        process.exit(1);
    }

    // --- STEP 2: Database Check ---
    process.stdout.write('⏳ Checking MongoDB Atlas connection... ');
    if (!process.env.MONGO_URI) {
        console.log('❌ Failed');
        console.error('\nCRITICAL: MONGO_URI environment variable is missing.');
        console.error('Ensure your .env file exists locally, or environment variables are set in Render.\n');
        process.exit(1);
    }
    
    try {
        // A short timeout prevents the script from hanging forever if IP is not whitelisted
        await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 5000 });
        console.log('✅ Connected');
        await mongoose.disconnect(); 
    } catch (e) {
        console.log('❌ Failed');
        console.error('\nCRITICAL: Could not connect to the database.');
        console.error('1. Check if the MONGO_URI is correct.');
        console.error('2. Ensure the server IP (or 0.0.0.0/0) is whitelisted in MongoDB Atlas Network Access.');
        console.error('Error details:', e.message, '\n');
        process.exit(1);
    }

    // --- STEP 3: Cache Check ---
    process.stdout.write('⏳ Checking for existing AdminJS build cache... ');
    const bundlePath = path.join(__dirname, '.adminjs', 'bundle.js');
    
    try {
        await fs.access(bundlePath);
        console.log('✅ Cache Found');
        console.log('\n✨ .adminjs/bundle.js is present.');
        console.log('✨ Skipping expensive Webpack build to save deployment time.\n');
        
        console.log('==================================================');
        console.log('✅ PRE-BUILD SEQUENCE FINISHED SUCCESSFULLY');
        console.log('==================================================\n');
        process.exit(0);
        
    } catch (e) {
        console.log('ℹ️ No Cache Found (or incomplete)');
        console.log('\n⚙️ Starting AdminJS Webpack Build Process. This will take a moment...\n');
    }

    // --- STEP 4: Execute Build ---
    try {
        AdminJS.registerAdapter({
            Database: AdminJSMongoose.Database,
            Resource: AdminJSMongoose.Resource,
        });

        const admin = new AdminJS({
            componentLoader,
            defaultTheme: 'dark', 
            availableThemes: [gplModsTheme, light], 
            dashboard: { component: Components.Dashboard },
            branding: {
                companyName: 'GPL Mods',
                logo: '/images/logo.png', 
                softwareBrothers: false,
                withMadeWithLove: false, 
            },
            resources: [], 
            env: {
                NODE_ENV: 'production' 
            }
        });

        await admin.initialize();

        console.log('\n==================================================');
        console.log('✅ BUILD COMPLETE: Admin components successfully compiled!');
        console.log('✅ Assets saved to the .adminjs/ directory.');
        console.log('==================================================\n');
        process.exit(0);

    } catch (err) {
        console.error('\n==================================================');
        console.error('❌ BUILD FAILED: Error compiling AdminJS components.');
        console.error('==================================================\n');
        console.error(err);
        process.exit(1);
    }
}

runAdminBuilder();