// adminloader.mjs
import AdminJS from 'adminjs';
import * as AdminJSMongoose from '@adminjs/mongoose';
import { dark, light } from '@adminjs/themes';

// 1. Import the singleton loader
import loaderModule from './components/loader.js'; 
const { componentLoader, Components } = loaderModule;

console.log('AdminJS Bundler: Starting setup...');

AdminJS.registerAdapter({
    Database: AdminJSMongoose.Database,
    Resource: AdminJSMongoose.Resource,
});

// 2. Define the exact same theme
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

console.log('AdminJS Bundler: Configuring AdminJS instance...');

// 3. Initialize the "Dummy" AdminJS instance for building
const admin = new AdminJS({
    componentLoader, // Pass the singleton!
    defaultTheme: 'dark', 
    availableThemes: [gplModsTheme, light], 
    dashboard: {
        component: Components.Dashboard
    },
    branding: {
        companyName: 'GPL Mods',
        logo: '/images/logo.png', 
        softwareBrothers: false,
        withMadeWithLove: false, 
    },
    resources: [], // Empty for bundling
    env: {
        NODE_ENV: 'production' // Force Webpack to bundle and minify
    }
});

console.log('AdminJS Bundler: Executing build process...');

// 4. Build it
admin.initialize().then(() => {
    console.log('==================================================');
    console.log('✅ AdminJS Bundler: Build finished successfully!');
    console.log('✅ Assets saved to the .adminjs/ folder.');
    console.log('==================================================');
    process.exit(0); 
}).catch(err => {
    console.error('❌ AdminJS Bundler Error: Failed to compile components.');
    console.error(err);
    process.exit(1); 
});