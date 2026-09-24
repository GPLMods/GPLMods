// utils/platformDetector.js

/**
 * Android API Level to Android OS Version Mapping
 */
const ANDROID_API_MAP = {
    1: 'Android 1.0',
    2: 'Android 1.1',
    3: 'Android 1.5',
    4: 'Android 1.6',
    5: 'Android 2.0',
    6: 'Android 2.0.1',
    7: 'Android 2.1',
    8: 'Android 2.2',
    9: 'Android 2.3',
    10: 'Android 2.3.3',
    11: 'Android 3.0',
    12: 'Android 3.1',
    13: 'Android 3.2',
    14: 'Android 4.0',
    15: 'Android 4.0.3',
    16: 'Android 4.1',
    17: 'Android 4.2',
    18: 'Android 4.3',
    19: 'Android 4.4',
    20: 'Android 4.4W',
    21: 'Android 5.0',
    22: 'Android 5.1',
    23: 'Android 6.0',
    24: 'Android 7.0',
    25: 'Android 7.1',
    26: 'Android 8.0',
    27: 'Android 8.1',
    28: 'Android 9.0',
    29: 'Android 10',
    30: 'Android 11',
    31: 'Android 12',
    32: 'Android 12L',
    33: 'Android 13',
    34: 'Android 14',
    35: 'Android 15',
    36: 'Android 16'
};

/**
 * Windows Build / Version Mapping
 */
const WINDOWS_BUILD_MAP = {
    '10.0.19041': 'Windows 10 (2004 / 20H1)',
    '10.0.19042': 'Windows 10 (2004 / 20H1)',
    '10.0.19043': 'Windows 10 (21H1)',
    '10.0.19044': 'Windows 10 (21H2)',
    '10.0.19045': 'Windows 10 (22H2)',
    '10.0.22000': 'Windows 11 (21H2)',
    '10.0.22621': 'Windows 11 (22H2)',
    '10.0.22631': 'Windows 11 (23H2)',
    '10.0.26100': 'Windows 11 (24H2)'
};

/**
 * Detect Platform from file extension or file name
 * @param {string} filename 
 * @returns {string|null}
 */
function detectPlatformFromFilename(filename) {
    if (!filename || typeof filename !== 'string') return null;
    const lower = filename.toLowerCase().trim();

    // Suffix check for Debian packages
    if (lower.endsWith('.deb')) {
        return 'ios-jailbroken';
    }

    const parts = lower.split('.');
    if (parts.length < 2) return null;
    const ext = parts.pop();

    // 1. Android: .apk, .xapk, .apks, .apkm, .aab, .abb
    if (['apk', 'xapk', 'apks', 'apkm', 'aab', 'abb'].includes(ext)) {
        return 'android';
    }

    // 2. iOS Jailed: .ipa, .tipa, .app, .xcarchive
    if (['ipa', 'tipa', 'app', 'xcarchive'].includes(ext)) {
        return 'ios-jailed';
    }

    // 3. Windows: .exe, .msi, .msix, .appx, .appxbundle, .msixbundle, .bat, .cmd, .cpl, .msc, .iso, .rar, .7z
    if (['exe', 'msi', 'msix', 'appx', 'appxbundle', 'msixbundle', 'bat', 'cmd', 'cpl', 'msc', 'iso', 'rar', '7z'].includes(ext)) {
        return 'windows';
    }

    // 4. WordPress: .zip, .php, .css, .json, .js
    if (['zip', 'php', 'css', 'json', 'js'].includes(ext)) {
        return 'wordpress';
    }

    return null;
}

/**
 * Detect Architectures from filename based on target platform
 * @param {string} filename 
 * @param {string} platform 
 * @returns {string[]}
 */
function detectArchitectures(filename, platform) {
    if (!filename || typeof filename !== 'string') return [];
    const lower = filename.toLowerCase();
    const detected = new Set();

    if (platform === 'android') {
        if (/arm64[-_]?v8a?|aarch64/i.test(lower)) detected.add('arm64-v8a');
        if (/armeabi[-_]?v7a?|armv7/i.test(lower)) detected.add('armeabi-v7a');
        if (/x86[-_]?64/i.test(lower)) detected.add('x86_64');
        else if (/(?:^|[^a-z0-9])x86(?:[^a-z0-9]|$)|i[3-6]86/i.test(lower)) detected.add('x86');
        if (/universal|all[-_]arch/i.test(lower)) detected.add('universal');
    } else if (platform === 'ios-jailbroken') {
        if (/iphoneos[-_]arm64e|arm64e/i.test(lower)) detected.add('arm64e');
        else if (/iphoneos[-_]arm64|arm64/i.test(lower)) detected.add('arm64');
        else if (/iphoneos[-_]arm\b|rootful/i.test(lower) || (/(?:^|[^a-z0-9])arm(?:[^a-z0-9]|$)/i.test(lower) && !lower.includes('arm64'))) detected.add('arm');
        if (/armv7/i.test(lower)) detected.add('armv7 / armv7s');
    } else if (platform === 'ios-jailed') {
        if (/apple[-_ ]?silicon|m1|m2|m3|m4/i.test(lower)) {
            detected.add('Apple Silicon Mac (arm64)');
        }
        if (/intel[-_ ]?mac|intel/i.test(lower)) {
            detected.add('Intel Mac (x86-64)');
        }
        if (/arm64e/i.test(lower)) {
            detected.add('arm64e');
        } else if (/arm64/i.test(lower) && !detected.has('Apple Silicon Mac (arm64)')) {
            detected.add('arm64');
        }
        if (/armv7/i.test(lower)) detected.add('armv7 / armv7s');
        if (/universal/i.test(lower)) detected.add('universal');
    } else if (platform === 'windows') {
        if (/x64|amd64|64[-_]?bit/i.test(lower)) detected.add('x64');
        if (/(?:^|[^a-z0-9])x86(?:[^a-z0-9]|$)|i386|32[-_]?bit/i.test(lower)) detected.add('x86');
        if (/arm64|aarch64/i.test(lower)) detected.add('arm64');
        if (/universal|multi/i.test(lower)) detected.add('universal');
    } else if (platform === 'wordpress') {
        detected.add('universal');
    }

    return Array.from(detected);
}

/**
 * Detect Minimum OS Version from filename
 * @param {string} filename 
 * @param {string} platform 
 * @returns {string}
 */
function detectMinOsVersion(filename, platform) {
    if (!filename || typeof filename !== 'string') return '';
    const lower = filename.toLowerCase();
    // Strip extension for cleaner regex matching
    const base = lower.replace(/\.[a-z0-9]+$/i, '');

    // 1. ANDROID
    if (platform === 'android') {
        // API level: -minAPIXX, _apiXX, -apiXX, -sdkXX, -nodpi-sdkXX
        const apiMatch = base.match(/(?:[-_]minapi|[-_]api|[-_]sdk|[-_]nodpi[-_]sdk)(\d{1,2})(?:[^0-9]|$)/i);
        if (apiMatch && apiMatch[1]) {
            const apiLevel = parseInt(apiMatch[1], 10);
            if (ANDROID_API_MAP[apiLevel]) {
                return ANDROID_API_MAP[apiLevel];
            }
        }

        // Version range: e.g., android10-14, android_10-14
        const rangeMatch = base.match(/android[-_]?(\d+)[-_](\d+)/i);
        if (rangeMatch) {
            return `Android ${rangeMatch[1]} - ${rangeMatch[2]}`;
        }

        // Version with plus: e.g., _android5.0+, -minOS-5.0+
        const plusMatch = base.match(/(?:android|minos)[-_]?(\d+(?:\.\d+)?)\+/i);
        if (plusMatch) {
            return `Android ${plusMatch[1]}+`;
        }

        // MinOS or Android version explicit: e.g. -minOS-8.0, android-9.0
        const explicitMatch = base.match(/(?:android|minos)[-_]?(\d+(?:\.\d+)?)/i);
        if (explicitMatch) {
            return `Android ${explicitMatch[1]}`;
        }
    }

    // 2. IOS (JAILED OR JAILBROKEN)
    if (platform === 'ios-jailed' || platform === 'ios-jailbroken') {
        // Range: e.g., iOS_10xx-16xx, iOS_10-16, iOS_14.0-16.5
        const iosRangeMatch = base.match(/ios[-_]?(\d+(?:\.[0-9x]+)?)[-_](\d+(?:\.[0-9x]+)?)/i);
        if (iosRangeMatch) {
            const start = iosRangeMatch[1].replace(/x+/g, 'x');
            const end = iosRangeMatch[2].replace(/x+/g, 'x');
            return `iOS ${start} - ${end}`;
        }

        // Plus variant: e.g., AppName_iOS14+.ipa, iOS_16.4+
        const iosPlusMatch = base.match(/ios[-_]?(\d+(?:\.[0-9x]+)?)\+/i);
        if (iosPlusMatch) {
            return `iOS ${iosPlusMatch[1]}+`;
        }

        // Minimum abbreviation: e.g., AppName_miniOS15.ipa, miniOS16.4
        const minIosMatch = base.match(/min[-_]?ios[-_]?(\d+(?:\.[0-9x]+)?)/i);
        if (minIosMatch) {
            return `iOS ${minIosMatch[1]}+`;
        }

        // Major/Minor version: e.g., AppName_v1.0_iOS_16.4.ipa, iOS_15.xx
        const iosVerMatch = base.match(/ios[-_]?(\d+(?:\.[0-9x]+)?)/i);
        if (iosVerMatch) {
            const v = iosVerMatch[1].replace(/x+/g, 'x');
            return `iOS ${v}`;
        }
    }

    // 3. WINDOWS
    if (platform === 'windows') {
        // Windows build numbers: 10.0.19041, 10.0.22000, 10.0.22621
        const buildMatch = base.match(/(?:^|[^0-9])(10\.0\.\d{5})(?:[^0-9]|$)/);
        if (buildMatch && buildMatch[1]) {
            if (WINDOWS_BUILD_MAP[buildMatch[1]]) {
                return WINDOWS_BUILD_MAP[buildMatch[1]];
            }
            return `Windows 10/11 (Build ${buildMatch[1]})`;
        }

        // Range: e.g., setup_win7-win11.exe, win8-win10
        const winRangeMatch = base.match(/win(?:dows)?[-_]?([0-9]+(?:\.[0-9]+)?)[-_]win(?:dows)?[-_]?([0-9]+(?:\.[0-9]+)?)/i);
        if (winRangeMatch) {
            return `Windows ${winRangeMatch[1]} - ${winRangeMatch[2]}`;
        }

        // Specific Windows version: app_win10_x64.exe, name_win11.exe, win7
        const winVerMatch = base.match(/(?:^|[^a-z0-9])win(?:dows)?[-_]?(11|10|8\.1|8|7|xp|vista)(?:[^a-z0-9]|$)/i);
        if (winVerMatch) {
            return `Windows ${winVerMatch[1]}`;
        }
    }

    // 4. WORDPRESS
    if (platform === 'wordpress') {
        // e.g., plugin-name_php8.3_wp6.7.zip
        const phpMatch = base.match(/php[-_]?(\d+(?:\.\d+)?)/i);
        const wpMatch = base.match(/wp[-_]?(\d+(?:\.\d+)?)/i);
        if (phpMatch && wpMatch) {
            return `PHP ${phpMatch[1]}+, WP ${wpMatch[1]}+`;
        } else if (wpMatch) {
            return `WordPress ${wpMatch[1]}+`;
        } else if (phpMatch) {
            return `PHP ${phpMatch[1]}+`;
        }
    }

    return '';
}

/**
 * Parse Debian Tweak Package filename
 * Example: com.dvntm.ytlite_5.2.1_iphoneos-arm.deb
 * @param {string} filename 
 */
function parseDebianTweakPackage(filename) {
    if (!filename || typeof filename !== 'string' || !filename.toLowerCase().endsWith('.deb')) {
        return null;
    }

    const base = filename.replace(/\.deb$/i, '');
    const parts = base.split('_');

    let packageId = '';
    let developer = '';
    let tweakName = '';
    let version = '';
    let arch = '';

    if (parts.length >= 1) {
        packageId = parts[0];
        const subparts = packageId.split('.');
        if (subparts.length >= 3) {
            developer = subparts[1];
            tweakName = subparts.slice(2).join('.');
        } else if (subparts.length === 2) {
            developer = subparts[0];
            tweakName = subparts[1];
        } else {
            tweakName = packageId;
        }
    }

    if (parts.length >= 2) {
        version = parts[1];
    }

    if (parts.length >= 3) {
        const archPart = parts[2].toLowerCase();
        if (archPart.includes('arm64e')) arch = 'arm64e';
        else if (archPart.includes('arm64')) arch = 'arm64';
        else if (archPart.includes('arm')) arch = 'arm';
    }

    // Clean format for tweakName if found
    if (tweakName) {
        tweakName = tweakName.replace(/[-_]+/g, ' ').trim();
        // Capitalize words
        tweakName = tweakName.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
    }

    return {
        packageId,
        developer,
        tweakName,
        version,
        architecture: arch
    };
}

/**
 * Complete Auto-Detection Analysis for a file name
 * @param {string} filename 
 */
function analyzeFileDetails(filename) {
    const platform = detectPlatformFromFilename(filename);
    const architectures = detectArchitectures(filename, platform);
    const minOsVersion = detectMinOsVersion(filename, platform);
    const tweakInfo = parseDebianTweakPackage(filename);

    return {
        platform,
        category: platform,
        architectures,
        minOsVersion,
        tweakInfo,
        packageId: tweakInfo ? tweakInfo.packageId : '',
        developer: tweakInfo ? tweakInfo.developer : '',
        modName: tweakInfo ? tweakInfo.tweakName : '',
        version: tweakInfo ? tweakInfo.version : ''
    };
}

module.exports = {
    ANDROID_API_MAP,
    WINDOWS_BUILD_MAP,
    detectPlatformFromFilename,
    detectArchitectures,
    detectMinOsVersion,
    parseDebianTweakPackage,
    analyzeFileDetails
};
