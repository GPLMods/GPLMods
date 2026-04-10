// adminloader.mjs

// 1. Imports
import 'dotenv/config'; // Load environment variables first
import mongoose from 'mongoose';
import dns from 'dns/promises';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

import AdminJS from 'adminjs';
import * as AdminJSMongoose from '@adminjs/mongoose';
import { dark, light } from '@adminjs/themes';

import loaderModule from './components/loader.js';
const { componentLoader, Components } = loaderModule;

// Utility for getting __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

    // --- STEP 1: Network Check ---
    process.stdout.write('⏳ Checking network connectivity (Google DNS)... ');
    try {
        await dns.resolve('8.8.8.8');
        console.log('✅ Online');
    } catch (e) {
        console.log('❌ Offline');
        console.error('CRITICAL: No internet connection detected. Build aborted.');
        process.exit(1);
    }

    // --- STEP 2: Database Check ---
    process.stdout.write('⏳ Checking MongoDB Atlas connection... ');
    if (!process.env.MONGO_URI) {
        console.log('❌ Failed');
        console.error('CRITICAL: MONGO_URI environment variable is missing.');
        process.exit(1);
    }
    
    try {
        await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 5000 });
        console.log('✅ Connected');
        await mongoose.disconnect(); // Disconnect immediately, we only needed a ping
    } catch (e) {
        console.log('❌ Failed');
        console.error('CRITICAL: Could not connect to database. Check credentials and IP whitelist.');
        console.error(e.message);
        process.exit(1);
    }

    // --- STEP 3: Cache Check ---
    process.stdout.write('⏳ Checking for existing AdminJS build cache... ');
    const bundlePath = path.join(__dirname, '.adminjs', 'bundle.js');
    
    try {
        await fs.access(bundlePath);
        // If fs.access succeeds, the file exists!
        console.log('✅ Cache Found');
        console.log('\n✨ .adminjs folder is present and complete.');
        console.log('✨ Skipping build process to save deployment time.\n');
        
        console.log('==================================================');
        console.log('✅ PRE-BUILD SEQUENCE FINISHED SUCCESSFULLY');
        console.log('==================================================\n');
        process.exit(0);
        
    } catch (e) {
        // If fs.access throws an error, the file doesn't exist
        console.log('ℹ️ No Cache Found (or incomplete)');
        console.log('\n⚙️ Starting AdminJS Webpack Build Process. This may take a moment...\n');
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
            resources: [], // Empty for bundling
            env: {
                NODE_ENV: 'production' // Force minification
            }
        });

        // The initialize() method is what actually triggers Webpack to build the assets
        await admin.initialize();

        console.log('\n==================================================');
        console.log('✅ BUILD COMPLETE: Admin components successfully created!');
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

// Execute the script
runAdminBuilder();