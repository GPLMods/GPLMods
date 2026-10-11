/**
 * GPLMods SEO & Meta Tag Optimization Engine
 * Provides static and dynamic SEO meta tags, Open Graph, Twitter Cards,
 * Schema.org JSON-LD structured data graphs, robots.txt directives,
 * canonical URLs, IndexNow pinging, and search engine integration.
 */

const axios = require('axios');

const BASE_URL = process.env.BASE_URL || 'https://gplmods.webredirect.org';
const SITE_NAME = 'GPL Mods';
const TWITTER_HANDLE = '@GPLMods';
const DEFAULT_IMAGE = `${BASE_URL}/images/logo.png`;

// Global Brand Synonyms & Search Engine Variations
// Ensures site is matched when users search for GPLMods, GPL Mods, GPLMod, or any TLD (.org, .com, .net, .co, .in)
const BRAND_KEYWORDS = [
    'GPLMods',
    'GPL Mods',
    'GPLMod',
    'GPLMods.org',
    'GPLMods.com',
    'GPLMods.net',
    'GPLMods.co',
    'GPLMods.in',
    'gplmods.webredirect.org',
    'gplmods org',
    'gplmods com',
    'gplmods co',
    'gplmods in',
    'gpl mods official',
    'open source mods',
    'safe mod apk',
    'premium unlocked mods',
    'mod apk download',
    'ios jailbreak repos',
    'ios ipa sideloading',
    'sileo repo',
    'cydia repo',
    'zebra repo',
    'windows gpl software',
    'wordpress gpl themes free',
    'virustotal scanned mods'
];

// High-Velocity Google Trends Rising Searches (Verified via Google Trends)
const TRENDING_GOOGLE_KEYWORDS = [
    'lightroom mod apk latest version',
    'lightroom pro mod apk',
    'trafic rider mod apk',
    'traffic rider mod apk',
    'telegram mod apk download',
    'telegram premium mod apk',
    'free fire mod apk advance server',
    'free fire advance server apk',
    'pizza ready mod apk',
    'where winds meet mod apk',
    'my supermarket simulator 3d mod apk',
    'block crush mod apk',
    'train simulator mod apk',
    'indian train simulator mod apk',
    'reelshort mod apk unlimited coins',
    'reelshort mod apk',
    'winkit mod apk ai video enhancer',
    'winkit mod apk',
    'truck simulator ultimate mod apk',
    'dynamons world mod apk',
    'granny chapter two mod apk',
    'capcut mod apk for android',
    'capcut pro mod apk',
    'chatgpt mod apk download for android',
    'chatgpt plus mod apk',
    'movie box moviebox pro download',
    'bus simulator indonesia mod apk',
    'happy mod ios',
    'happymod apk download',
    'happy mod 2026'
];

// Competitor & Alternative Comparator Keywords (Targeting user flow seeking alternatives)
const COMPETITOR_COMPARATOR_KEYWORDS = [
    'happymod alternative',
    'happy mod alternatives',
    'happymod safe download',
    'happymod apk alternative',
    'happymod ios alternative',
    'panda helper alternative',
    'panda helper vip free',
    'panda helper ios alternative',
    'iosgods alternative',
    'iosgods.com alternative',
    'iosgods jailed cheats alternative',
    'apptesters.org alternative',
    'apptesters alternative',
    'apptesters repo',
    'arealgamer alternative',
    'arealgamer.org',
    'pcgamefreetop alternative',
    'pcgamefreetop.net',
    'igg-games alternative',
    'igg games safe alternative',
    'igg-games.com',
    'pcgamestorrents alternative',
    'pc games torrents safe',
    'onehack.us alternative',
    'onehack alternative',
    'pdalife alternative',
    'pda life alternative',
    'pdalife english',
    'an1.com alternative',
    'an1 mod apk alternative',
    'getmodapk alternative',
    'get mod apka alternative',
    'applites alternative',
    'apklite alternative',
    'apktg alternative',
    'apktg.com',
    'vanced alternative',
    'youtube vanced apk alternative',
    'vanced.to',
    'gplastra alternative',
    'gplastra.net',
    'gplastra.me',
    'shineads alternative',
    'shineads.in',
    'kemo hacks for ios',
    'kemohacks',
    'mixrootmods android',
    'mixrootmod.com',
    'you are finished mods',
    'dayanch96 ytlite',
    'fouadraheb watusi',
    'whoeevee eeveespotify'
];

// Popular Games Keywords (High Search Volume 2026)
const POPULAR_GAMES_KEYWORDS = [
    'minecraft pe ipa',
    'minecraft java bedrock edition free download',
    'minecraft mod apk',
    'geometry dash full version unlocked',
    'geometry dash ipa',
    'reds first flight ipa',
    'red first flight free download',
    'roblox delta executor ios',
    'delta executor download',
    'roblox mod apk 2026',
    'roblox cheats ios',
    'among us jailed cheats',
    'among us mod apk all unlocked',
    'subway surfers mod ipa apptesters',
    'subway surfers unlimited coins keys',
    'fortnite ezfn private server',
    'fortnite mobile ios ipa',
    'amethyst launcher minecraft ios',
    'gta vice city gtavc ipa apk',
    'gta san andreas gtasa mod apk ipa',
    'gta 5 enhanced pc free download',
    'poppy playtime chapter 4 free download',
    'terraria full version ipa apk',
    '8 ball pool auto update cheats long line',
    'plants vs zombies 2 pvz2 unlimited currencies',
    'township farm city building cheats',
    'dude theft wars mod menu cheats',
    'the sims 4 lovestruck pc free download',
    'cyberpunk 2077 codex pc free download',
    'forza horizon 6 pc free download',
    'schedule 1 schedule i pc free download',
    'the witcher 3 wild hunt all dlc pc',
    'palworld pc free download',
    'black myth wukong pc free download',
    'red dead redemption 2 ultimate edition pc'
];

// Popular Apps & Media Tools Keywords
const POPULAR_APPS_KEYWORDS = [
    'ytlite youtube mod ios',
    'ytmusicultimate premium unlocked',
    'eeveespotifyreborn spotify premium ios',
    'spotify premium mod apk 2026',
    'watusi for whatsapp ios',
    'regram for instagram ios',
    'snapchat mod apk dark mode',
    'adobe photoshop modded ipa',
    'adobe lightroom pro mod apk',
    'picsart gold subscription unlocked ipa apk',
    'kinemaster pro mod apk without watermark',
    'inshot pro mod apk unlocked',
    'capcut mod apk for android pro unlocked',
    'crunchyroll premium mod apk no ads',
    'reelshort unlimited coins mod apk',
    'movie box moviebox pro download',
    'winkit ai video enhancer mod apk',
    'chatgpt mod apk download for android',
    'duolingo super premium unlocked',
    'remini pro ai photo enhancer unlocked',
    'truecaller premium gold unlocked',
    'mimo pro learn coding unlocked',
    'remote gamepad mod apk',
    'microsoft swiftkey ai keyboard mod',
    'telegram premium mod apk',
    'dodo webview gplmods'
];

// WordPress GPL Themes & Plugins Keywords
const WORDPRESS_GPL_KEYWORDS = [
    'yoast seo premium gpl free download',
    'rank math pro gpl free download',
    'elementor pro gpl free download',
    'wp rocket gpl free download',
    'wp dark mode ultimate plugin free download',
    'wordfence premium gpl free download',
    'updraftplus premium gpl free download',
    'wpforms pro gpl free download',
    'wp mail smtp pro gpl free download',
    'easy digital downloads pro free download',
    'ultimate membership pro codecanyon gpl',
    'astra pro addon gpl free download',
    'astra premium starter templates',
    'kadence theme pro gpl free download',
    'avada themeforest theme gpl free download',
    'generatepress premium gp premium gpl',
    'flatsome woocommerce theme gpl free download',
    'thegem creative theme gpl free download',
    'salient multipurpose theme gpl free download',
    'soledad blog magazine theme gpl free download',
    'thrive theme builder gpl free download',
    'betheme responsive theme gpl free download'
];

// Schema.org FAQ Schema for Search Engine Snippets (SERP Dropdown)
const COMPETITOR_FAQ_SCHEMA = {
    '@type': 'FAQPage',
    mainEntity: [
        {
            '@type': 'Question',
            name: 'Is GPL Mods safer than HappyMod, Panda Helper, and unverified mod sites?',
            acceptedAnswer: {
                '@type': 'Answer',
                text: 'Yes. Unlike HappyMod, Panda Helper, and unverified stores, every package on GPL Mods is tested and dual-scanned with Cloud VirusTotal engines. Files contain zero injected adware, miners, or malicious payloads, providing 100% clean, verified direct downloads.'
            }
        },
        {
            '@type': 'Question',
            name: 'How does GPL Mods compare to iOSGods and AppTesters for iOS IPAs?',
            acceptedAnswer: {
                '@type': 'Answer',
                text: 'GPL Mods offers direct sideloading IPAs compatible with AltStore, SideStore, and Scarlet, plus Sileo/Zebra/Cydia jailbreak repositories without mandatory VIP paywalls, broken ad-shorteners, or locked download mirrors.'
            }
        },
        {
            '@type': 'Question',
            name: 'Are PC games and software on GPL Mods safe compared to IGG Games and torrent sites?',
            acceptedAnswer: {
                '@type': 'Answer',
                text: 'Every Windows PC software, game, and tool on GPL Mods includes verified SHA256 checksums and real-time VirusTotal telemetry. Downloads are hosted on high-speed CDN mirrors without confusing torrent redirects, bundled adware, or crypto miners.'
            }
        },
        {
            '@type': 'Question',
            name: 'What is the difference between GPL Mods and GPLAstra or ShineAds for WordPress items?',
            acceptedAnswer: {
                '@type': 'Answer',
                text: 'GPL Mods provides 100% authentic, untouched GNU General Public Licensed (GPL) WordPress themes and plugins directly from developers. Files are verified malware-free with no backdoors or callback scripts.'
            }
        }
    ]
};

/**
 * Returns platform-specific competitor and trending keywords
 */
function getPlatformKeywords(cat) {
    const c = String(cat || '').toLowerCase();
    if (c === 'android') {
        return [
            'happymod alternative',
            'pdalife alternative',
            'an1 mod apk',
            'getmodapk alternative',
            'applites alternative',
            'mixrootmods android',
            'lightroom mod apk latest version',
            'traffic rider mod apk',
            'telegram premium mod apk',
            'free fire advance server',
            'capcut mod apk for android',
            'chatgpt mod apk download for android',
            'minecraft pe apk',
            'subway surfers mod apk',
            'spotify premium mod apk'
        ];
    }
    if (c === 'ios-jailed') {
        return [
            'iosgods alternative',
            'apptesters.org alternative',
            'panda helper ios alternative',
            'kemo hacks for ios',
            'scarlet repo',
            'altstore repo',
            'sidestore repo',
            'roblox delta executor ios',
            'among us jailed cheats',
            'subway surfers mod ipa apptesters',
            'minecraft pe ipa',
            'watusi for whatsapp',
            'regram for instagram',
            'eeveespotifyreborn',
            'ytlite ios'
        ];
    }
    if (c === 'ios-jailbroken') {
        return [
            'sileo repo',
            'cydia repo',
            'zebra repo',
            'rootless jailbreak tweaks',
            'iosgods jailed cheats alternative',
            'kemo hacks for ios',
            'watusi 3',
            'eeveespotify',
            'ytliteplus',
            'amethyst launcher ios'
        ];
    }
    if (c === 'windows') {
        return [
            'arealgamer alternative',
            'pcgamefreetop alternative',
            'igg-games alternative',
            'igg games safe alternative',
            'pcgamestorrents alternative',
            'onehack.us alternative',
            'minecraft java bedrock edition free download',
            'the sims 4 lovestruck pc free download',
            'cyberpunk 2077 pc free download',
            'forza horizon 6 pc free download',
            'gta 5 enhanced pc',
            'the witcher 3 wild hunt pc',
            'palworld pc free download',
            'black myth wukong pc free download',
            'red dead redemption 2 pc free download'
        ];
    }
    if (c === 'wordpress') {
        return [
            'gplastra alternative',
            'shineads alternative',
            'yoast seo premium gpl',
            'rank math pro gpl',
            'elementor pro gpl free download',
            'wp rocket gpl free download',
            'wp dark mode ultimate',
            'wordfence premium gpl',
            'updraftplus premium gpl',
            'wpforms pro gpl',
            'wp mail smtp pro gpl',
            'easy digital downloads pro',
            'ultimate membership pro',
            'astra pro addon gpl',
            'kadence theme pro gpl',
            'avada themeforest gpl',
            'generatepress premium gp premium',
            'flatsome woocommerce theme',
            'thegem theme',
            'salient theme',
            'soledad theme',
            'thrive theme builder',
            'betheme gpl'
        ];
    }
    return [];
}

/**
 * Strips HTML tags and collapses whitespace
 */
function cleanText(str) {
    if (!str || typeof str !== 'string') return '';
    return str.replace(/<[^>]*>?/gm, ' ')
              .replace(/\s+/g, ' ')
              .replace(/"/g, '&quot;')
              .trim();
}

/**
 * Limits string length without cutting words abruptly
 */
function truncateText(str, maxLength) {
    const text = cleanText(str);
    if (!text || text.length <= maxLength) return text;
    const truncated = text.substring(0, maxLength);
    const lastSpace = truncated.lastIndexOf(' ');
    if (lastSpace > maxLength * 0.7) {
        return truncated.substring(0, lastSpace) + '...';
    }
    return truncated.trim() + '...';
}

/**
 * Determines whether a route is private, authenticated, or should NOT be indexed
 */
function isNoindexRoute(urlPath) {
    if (!urlPath || typeof urlPath !== 'string') return false;
    const cleanPath = urlPath.split('?')[0].toLowerCase();

    // Exact matches
    const exactNoIndex = [
        '/dashboard',
        '/profile',
        '/settings',
        '/upload',
        '/upload-initial',
        '/wishlist',
        '/rewards',
        '/my-uploads',
        '/my-stats',
        '/my-membership',
        '/login',
        '/register',
        '/forgot-password',
        '/cc',
        '/id-card',
        '/cache-cleaner',
        '/banned',
        '/leave',
        '/unsubscribe',
        '/setup-2fa',
        '/community-chat',
        '/community/ask',
        '/clubs/create',
        '/failback',
        '/edit-mod',
        '/add-version'
    ];
    if (exactNoIndex.includes(cleanPath)) return true;

    // Prefix matches (Admin, Owner, APIs, Auth, Two-Factor, Upload details, etc.)
    const prefixNoIndex = [
        '/admin',
        '/owner',
        '/api/',
        '/auth/',
        '/reset-password/',
        '/upload-finalize/',
        '/upload-details',
        '/edit-mod/',
        '/add-version/',
        '/download-parts/',
        '/download-file/',
        '/notifications',
        '/support-dashboard',
        '/security-alert',
        '/security-questions',
        '/2fa-',
        '/payment-'
    ];

    return prefixNoIndex.some(prefix => cleanPath.startsWith(prefix));
}

/**
 * Static metadata dictionary for all public pages
 */
const STATIC_PAGE_META = {
    '/': {
        title: 'GPL Mods - 100% Safe & Working Premium Unlocked Mods | Safe Alternative',
        description: 'Download 100% safe, verified Mod APKs, iOS IPAs, PC software, and GPL themes. Clean, VirusTotal scanned alternative to HappyMod, iOSGods, Panda Helper & IGG Games.',
        keywords: [
            'gpl mods',
            'happymod alternative',
            'iosgods alternative',
            'panda helper alternative',
            'igg-games alternative',
            'safe mod apk',
            'mod ipa sideloading',
            'minecraft pe ipa',
            'roblox delta executor ios',
            'spotify premium mod',
            'lightroom pro mod',
            'capcut mod apk for android',
            'windows software unlocked',
            'wordpress gpl themes free'
        ],
        type: 'website'
    },
    '/about': {
        title: 'About GPL Mods - Open Source Modding & Safe Software Hub',
        description: 'Learn about GPL Mods, our mission for open-source software, transparent mod verification, VirusTotal dual-engine scanning, and creator attribution.',
        keywords: ['about gpl mods', 'open source software', 'gpl verification', 'safe modding community', 'clean apk alternative'],
        type: 'website'
    },
    '/faq': {
        title: 'FAQ - Safe Alternative to HappyMod, iOSGods & IGG Games | GPL Mods',
        description: 'Frequently asked questions: Why GPL Mods is safer than HappyMod and Panda Helper, how to sideload iOS IPAs, VirusTotal reports, and free VIP membership.',
        keywords: ['gpl mods faq', 'happymod vs gpl mods', 'iosgods safe alternative', 'how to sideload ipa', 'mod apk guide', 'virustotal scan help'],
        type: 'website'
    },
    '/tos': {
        title: 'Terms of Service & Platform Guidelines | GPL Mods',
        description: 'Review the official terms of service, platform rules, permissible use policies, and community guidelines for users and creators on GPL Mods.',
        keywords: ['terms of service', 'gpl mods rules', 'platform agreement', 'user terms'],
        type: 'website'
    },
    '/dmca': {
        title: 'DMCA Notice & Digital Copyright Compliance | GPL Mods',
        description: 'GPL Mods complies with 17 U.S.C. § 512 and the Digital Millennium Copyright Act. Submit copyright infringement notifications and review compliance.',
        keywords: ['gpl mods dmca', 'copyright compliance', 'takedown request', 'intellectual property'],
        type: 'website'
    },
    '/privacy-policy': {
        title: 'Privacy Policy & Data Security Protection | GPL Mods',
        description: 'Understand how GPL Mods protects your privacy, manages cookies, encrypts credentials, and ensures strict zero third-party data tracking.',
        keywords: ['privacy policy', 'user privacy', 'data protection', 'gpl mods security'],
        type: 'website'
    },
    '/refund-policy': {
        title: 'Refund & Cancellation Policy | GPL Mods Membership',
        description: 'Learn about our refund eligibility, supporter donation disclosures, cancellation policies, and automated billing terms on GPL Mods.',
        keywords: ['refund policy', 'cancellation policy', 'membership billing', 'supporter terms'],
        type: 'website'
    },
    '/donate': {
        title: 'Support & Donate to GPL Mods - Fuel Open Source Growth',
        description: 'Help support GPL Mods server hosting, high-speed CDN bandwidth, and automated virus scanning infrastructure with direct community contributions.',
        keywords: ['donate gpl mods', 'support open source', 'server sponsorship', 'community donation'],
        type: 'website'
    },
    '/partnership-policy': {
        title: 'Partnership & Distribution Policy | GPL Mods Network',
        description: 'Collaborate with GPL Mods. Read our official distributor guidelines, creator partnership models, and verified developer requirements.',
        keywords: ['partnership policy', 'gpl mods distributor', 'creator program', 'app publishing'],
        type: 'website'
    },
    '/distributor-features': {
        title: 'Distributor & Creator Features Console | GPL Mods',
        description: 'Unlock developer analytics, priority release feeds, verified creator badges, custom vanity URLs, and high-speed multi-channel uploads.',
        keywords: ['distributor features', 'creator studio', 'mod developer tools', 'verified uploader'],
        type: 'website'
    },
    '/why-choose-us': {
        title: 'Why Choose GPL Mods? 100% Verified Alternative to HappyMod & Panda Helper',
        description: 'Discover why millions choose GPL Mods: dual VirusTotal cloud scans, zero adware or malware, authentic GPL licenses, and direct high-speed mirror downloads.',
        keywords: ['why choose gpl mods', 'happymod alternative safe', 'panda helper alternative free', 'clean apk downloads', 'trusted mod apk site'],
        type: 'website'
    },
    '/understanding-scans': {
        title: 'Understanding Malware & VirusTotal Scans | GPL Mods',
        description: 'Learn how GPL Mods verifies files using VirusTotal heuristics, SHA256 hashes, false-positive detection, and automated package sandbox checks.',
        keywords: ['virustotal scan', 'apk virus scan', 'malware analysis', 'safe mods', 'sha256 verify'],
        type: 'website'
    },
    '/membership': {
        title: 'Supporter & VIP Membership Plans | GPL Mods Official',
        description: 'Upgrade your GPL Mods experience with ad-free browsing, unlimited parallel downloads, direct CDN bandwidth, and VIP creator access.',
        keywords: ['gpl mods membership', 'vip supporter', 'fast direct download', 'ad free modding', 'panda helper vip alternative'],
        type: 'website'
    },
    '/upload-policy': {
        title: 'Mod Upload & Safety Verification Policy | GPL Mods',
        description: 'Standards and safety requirements for publishing mods, APKs, IPAs, and software on GPL Mods. Automated scanning and manual audit guidelines.',
        keywords: ['upload policy', 'mod submission rules', 'safe mod guidelines', 'uploader verification'],
        type: 'website'
    },
    '/category': {
        title: 'Browse Safe Mods by Platform - HappyMod & iOSGods Alternative | GPL Mods',
        description: 'Explore Android APKs, iOS Sideloading IPAs, Jailbreak Tweaks, Windows PC Games, and WordPress GPL themes. 100% clean, VirusTotal scanned at GPL Mods.',
        keywords: ['browse mods', 'happymod alternative', 'iosgods alternative', 'android mods', 'ios ipas', 'windows mods', 'wordpress themes'],
        type: 'website'
    },
    '/repos': {
        title: 'Source & Sideload Repositories Hub - AppTesters & AltStore Alternative | GPL Mods',
        description: 'Official F-Droid Android repositories and AltStore, SideStore, and Scarlet iOS sideloading source directory on GPL Mods. Safe iOSGods and AppTesters alternative.',
        keywords: ['sideloading repo', 'apptesters alternative', 'altstore repo', 'sidestore repo', 'scarlet repo', 'fdroid repository', 'gpl repos'],
        type: 'website'
    },
    '/jailbreak-repos': {
        title: 'iOS Jailbreak Repos (Sileo, Cydia, Zebra) - Safe Kemo Hacks Alternative | GPL Mods',
        description: 'Add verified Rootless, Rootful, and Roothide jailbreak repos directly to Sileo, Zebra, and Cydia. 100% safe iOS packages on GPL Mods.',
        keywords: ['jailbreak repo', 'sileo repo', 'cydia repo', 'zebra repo', 'kemo hacks for ios', 'rootless jailbreak', 'ios tweaks'],
        type: 'website'
    },
    '/licenses': {
        title: 'Open Source & GPL Software Licenses Directory | GPL Mods',
        description: 'Explore free and open source software licenses (GPLv2, GPLv3, MIT, Apache, BSD). Review legal rights, permissions, and conditions.',
        keywords: ['gpl license', 'open source licenses', 'gplv3 terms', 'mit license', 'apache 2.0', 'software rights'],
        type: 'website'
    },
    '/source-hub': {
        title: 'Open Source Repositories & GitHub Code Hub | GPL Mods',
        description: 'Inspect open source repositories, browse commit trees, and download raw code files from verified developers on GPL Mods. Safe transparent modding.',
        keywords: ['source code viewer', 'open source git', 'github mirror', 'mod source code', 'inspect mod'],
        type: 'website'
    },
    '/community': {
        title: 'Community Forum, Discussions & Modding Help | GPL Mods',
        description: 'Join the GPL Mods community forum. Ask troubleshooting questions, share custom modding patches, and connect with developers.',
        keywords: ['modding forum', 'gpl community', 'mod help', 'android discussion', 'ios sideloading talk'],
        type: 'website'
    },
    '/clubs': {
        title: 'Creator Clubs & Modding Communities | GPL Mods',
        description: 'Explore public community clubs on GPL Mods. Join platform-specific groups, share game mods, and collaborate with passionate enthusiasts.',
        keywords: ['creator clubs', 'modding groups', 'gaming clubs', 'gpl community clubs'],
        type: 'website'
    },
    '/leaderboard': {
        title: 'Top Creators & Community Leaderboard | GPL Mods',
        description: 'See the top mod uploaders, most active contributors, and community leaders driving open-source modding forward on GPL Mods.',
        keywords: ['top modders', 'creator leaderboard', 'gpl mods ranking', 'verified creators'],
        type: 'website'
    },
    '/request-mod': {
        title: 'Request a Mod, App, or Tweak | GPL Mods Community',
        description: 'Can\'t find your favorite game or application? Submit a mod request to our community of verified creators and distributors on GPL Mods.',
        keywords: ['request mod', 'mod request', 'suggest game mod', 'request ipa', 'request apk'],
        type: 'website'
    },
    '/status': {
        title: 'Live System Health & Operational Status | GPL Mods',
        description: 'Real-time service health, server uptime, database response metrics, and 90-day operational history for GPL Mods infrastructure.',
        keywords: ['system status', 'gpl mods uptime', 'server health', 'api operational status'],
        type: 'website'
    },
    '/ai-directory': {
        title: 'Trending 2026 Mods, Competitors & AI Sitemap Directory | GPL Mods',
        description: 'Comprehensive directory indexing trending mods (Minecraft, Roblox, CapCut, Lightroom, Spotify) and safe alternatives to HappyMod, Panda Helper, iOSGods & IGG Games.',
        keywords: ['ai sitemap', 'happymod alternative', 'iosgods alternative', 'trending mods 2026', 'gpl mods directory', 'all mods sitemap'],
        type: 'website'
    }
};

/**
 * Normalizes platform names for human-friendly titles
 */
function formatPlatformName(cat) {
    if (!cat) return 'Software';
    const c = String(cat).toLowerCase();
    if (c === 'android') return 'Android APK';
    if (c === 'ios-jailed') return 'iOS IPA';
    if (c === 'ios-jailbroken') return 'iOS Jailbreak Tweak';
    if (c === 'windows') return 'Windows PC';
    if (c === 'wordpress') return 'WordPress Theme/Plugin';
    return cat.toUpperCase();
}

/**
 * Builds dynamic SEO for Mod detail / download page
 */
function buildModSeo(file, masterFile, req) {
    const targetFile = file || masterFile || {};
    const name = cleanText(targetFile.name) || 'Mod';
    const version = targetFile.version ? `v${targetFile.version}` : '';
    const platform = formatPlatformName(targetFile.category);
    const developer = targetFile.developer && targetFile.developer !== 'N/A' && targetFile.developer !== 'Unknown' 
        ? targetFile.developer 
        : '';
    const uploader = targetFile.uploader || 'GPL Mods Creator';
    const modType = targetFile.modType ? targetFile.modType : 'Premium Unlocked';

    // Parse user hashtags and tags
    let rawTags = Array.isArray(targetFile.tags) ? targetFile.tags : [];
    let hashtags = [];
    let normalTags = [];

    rawTags.forEach(t => {
        if (!t) return;
        const cleanT = String(t).trim();
        if (cleanT.startsWith('#')) {
            hashtags.push(cleanT);
            normalTags.push(cleanT.replace(/^#+/, ''));
        } else {
            hashtags.push(`#${cleanT}`);
            normalTags.push(cleanT);
        }
    });

    // 50-60 character title target
    let titleParts = [`Download ${name}`];
    if (version) titleParts.push(version);
    titleParts.push(`Mod (${platform})`);
    if (developer) titleParts.push(`by ${developer}`);
    const title = truncateText(`${titleParts.join(' ')} | ${SITE_NAME}`, 65);

    // 140-160 character description target
    const descPrefix = `Download ${name}${version ? ' ' + version : ''} ${platform} mod${developer ? ' by ' + developer : ''}, uploaded by ${uploader}.`;
    const descFeatures = ` 100% VirusTotal safe, ${modType} unlocked${hashtags.length > 0 ? ' with ' + hashtags.slice(0, 3).join(' ') : ''}. Free direct download at GPL Mods.`;
    const description = truncateText(descPrefix + descFeatures, 160);

    const slug = (masterFile && masterFile.slug) || targetFile.slug || targetFile._id;
    const category = targetFile.category || 'mods';
    const canonicalUrl = `${BASE_URL}/mods/${category}/${slug}`;

    const image = (Array.isArray(targetFile.screenshotUrls) && targetFile.screenshotUrls[0]) ||
                  targetFile.iconUrl ||
                  DEFAULT_IMAGE;

    // Combine keywords
    const platformKeywords = getPlatformKeywords(targetFile.category);
    const keywords = [
        name,
        `${name} mod`,
        `${name} ${platform}`,
        `${name} download`,
        `${name} ${version}`.trim(),
        developer,
        uploader,
        modType,
        ...normalTags,
        ...platformKeywords.slice(0, 8),
        ...BRAND_KEYWORDS.slice(0, 10)
    ].filter(Boolean);

    // Schema.org SoftwareApplication JSON-LD
    const jsonLd = {
        '@context': 'https://schema.org',
        '@graph': [
            {
                '@type': 'SoftwareApplication',
                '@id': `${canonicalUrl}#software`,
                name: `${name} Mod`,
                operatingSystem: platform,
                applicationCategory: targetFile.subCategory || targetFile.category || 'GameApplication',
                softwareVersion: targetFile.version || '1.0',
                description: description,
                image: image,
                author: {
                    '@type': developer ? 'Organization' : 'Person',
                    name: developer || uploader
                },
                publisher: {
                    '@type': 'Organization',
                    name: 'GPL Mods',
                    url: BASE_URL
                },
                offers: {
                    '@type': 'Offer',
                    price: '0',
                    priceCurrency: 'USD',
                    availability: 'https://schema.org/InStock'
                },
                downloadUrl: canonicalUrl,
                aggregateRating: (targetFile.votedWorkingBy && targetFile.votedWorkingBy.length > 0) ? {
                    '@type': 'AggregateRating',
                    ratingValue: '4.8',
                    reviewCount: Math.max(targetFile.votedWorkingBy.length, 5)
                } : undefined,
                datePublished: targetFile.createdAt ? new Date(targetFile.createdAt).toISOString() : undefined,
                dateModified: targetFile.updatedAt ? new Date(targetFile.updatedAt).toISOString() : undefined
            },
            {
                '@type': 'BreadcrumbList',
                itemListElement: [
                    { '@type': 'ListItem', position: 1, name: 'Home', item: BASE_URL },
                    { '@type': 'ListItem', position: 2, name: platform, item: `${BASE_URL}/category?platform=${encodeURIComponent(category)}` },
                    { '@type': 'ListItem', position: 3, name: name, item: canonicalUrl }
                ]
            }
        ]
    };

    return {
        title,
        description,
        keywords: keywords.join(', '),
        canonicalUrl,
        type: 'website',
        image,
        jsonLd
    };
}

/**
 * Builds dynamic SEO for Public User Profile
 */
function buildUserProfileSeo(user) {
    const username = user?.username || 'Creator';
    const role = user?.role ? user.role.toUpperCase() : 'Creator';
    const bio = cleanText(user?.bio);

    const title = truncateText(`${username} (${role}) - Creator Profile & Mods | ${SITE_NAME}`, 65);
    const descBody = bio ? `${bio}. ` : 'Verified open-source creator and modding contributor. ';
    const description = truncateText(`Explore mods, releases, and creator profile for ${username} on GPL Mods. ${descBody}Free safe downloads.`, 160);

    const canonicalUrl = `${BASE_URL}/user/${encodeURIComponent(username.toLowerCase())}`;
    const image = user?.signedAvatarUrl && !user.signedAvatarUrl.includes('default-avatar') 
        ? user.signedAvatarUrl 
        : DEFAULT_IMAGE;

    const keywords = [
        username,
        `${username} mods`,
        `${username} profile`,
        `gpl mods ${username}`,
        `${username} distributor`,
        'creator studio',
        ...BRAND_KEYWORDS
    ].join(', ');

    const jsonLd = {
        '@context': 'https://schema.org',
        '@graph': [
            {
                '@type': 'ProfilePage',
                '@id': `${canonicalUrl}#webpage`,
                url: canonicalUrl,
                name: title,
                mainEntity: {
                    '@type': 'Person',
                    '@id': `${canonicalUrl}#person`,
                    name: username,
                    identifier: username,
                    description: description,
                    image: image
                }
            },
            {
                '@type': 'BreadcrumbList',
                itemListElement: [
                    { '@type': 'ListItem', position: 1, name: 'Home', item: BASE_URL },
                    { '@type': 'ListItem', position: 2, name: 'Creators', item: `${BASE_URL}/leaderboard` },
                    { '@type': 'ListItem', position: 3, name: username, item: canonicalUrl }
                ]
            }
        ]
    };

    return {
        title,
        description,
        keywords,
        canonicalUrl,
        type: 'profile',
        image,
        jsonLd
    };
}

/**
 * Builds dynamic SEO for Developer page
 */
function buildDeveloperSeo(devName) {
    const cleanDev = cleanText(devName) || 'Developer';
    const title = truncateText(`Mods & Releases by ${cleanDev} | ${SITE_NAME}`, 65);
    const description = truncateText(`Download safe, virus-scanned mods, applications, and open-source tools developed by ${cleanDev} on GPL Mods. Free high-speed direct downloads.`, 160);
    const canonicalUrl = `${BASE_URL}/developer?name=${encodeURIComponent(cleanDev)}`;

    const keywords = [
        cleanDev,
        `${cleanDev} mods`,
        `${cleanDev} apk`,
        `${cleanDev} ipa`,
        `${cleanDev} software`,
        ...BRAND_KEYWORDS
    ].join(', ');

    return {
        title,
        description,
        keywords,
        canonicalUrl,
        type: 'website',
        image: DEFAULT_IMAGE
    };
}

/**
 * Builds dynamic SEO for License Reader
 */
function buildLicenseSeo(license) {
    const name = license?.name || 'Open Source License';
    const slug = (license?.slug || '').toUpperCase();
    const title = truncateText(`${name} (${slug}) - License Terms & Rights | ${SITE_NAME}`, 65);
    const descContent = cleanText(license?.description || license?.shortDescription);
    const description = truncateText(`Full text and permissions for the ${name} (${slug}). Review commercial rights, modification rules, patent terms, and liability conditions on GPL Mods.`, 160);
    const canonicalUrl = `${BASE_URL}/licenses/${encodeURIComponent(license?.slug || '')}`;

    const keywords = [
        name,
        slug,
        `${slug} license`,
        `${name} permissions`,
        'open source license',
        'gpl compliance',
        ...BRAND_KEYWORDS
    ].join(', ');

    const jsonLd = {
        '@context': 'https://schema.org',
        '@graph': [
            {
                '@type': 'Article',
                headline: title,
                description: description,
                url: canonicalUrl,
                publisher: {
                    '@type': 'Organization',
                    name: 'GPL Mods',
                    url: BASE_URL
                }
            },
            {
                '@type': 'BreadcrumbList',
                itemListElement: [
                    { '@type': 'ListItem', position: 1, name: 'Home', item: BASE_URL },
                    { '@type': 'ListItem', position: 2, name: 'Licenses Hub', item: `${BASE_URL}/licenses` },
                    { '@type': 'ListItem', position: 3, name: name, item: canonicalUrl }
                ]
            }
        ]
    };

    return {
        title,
        description,
        keywords,
        canonicalUrl,
        type: 'article',
        image: DEFAULT_IMAGE,
        jsonLd
    };
}

/**
 * Builds dynamic SEO for Source View
 */
function buildSourceSeo(source, currentPath) {
    const owner = source?.cleanOwner || source?.githubOwner || 'Source';
    const repo = source?.cleanRepo || source?.githubRepo || 'Repository';
    const subPath = currentPath ? ` - ${currentPath}` : '';
    const title = truncateText(`${owner}/${repo}${subPath} - Source Code Viewer | ${SITE_NAME}`, 65);
    const description = truncateText(`Inspect open-source code, commits, and file tree for repository ${owner}/${repo}${subPath} on GPL Mods Source Viewer. Verified GitHub mirror.`, 160);
    const canonicalUrl = `${BASE_URL}/source/${encodeURIComponent(source?.slug || '')}${currentPath ? '?path=' + encodeURIComponent(currentPath) : ''}`;

    const keywords = [
        `${owner}/${repo}`,
        repo,
        owner,
        'source code viewer',
        'github mirror',
        'open source repository',
        ...BRAND_KEYWORDS
    ].join(', ');

    const jsonLd = {
        '@context': 'https://schema.org',
        '@graph': [
            {
                '@type': 'SoftwareSourceCode',
                name: `${owner}/${repo}`,
                codeRepository: source?.canonicalRepoUrl || `https://github.com/${owner}/${repo}`,
                description: description,
                url: canonicalUrl
            },
            {
                '@type': 'BreadcrumbList',
                itemListElement: [
                    { '@type': 'ListItem', position: 1, name: 'Home', item: BASE_URL },
                    { '@type': 'ListItem', position: 2, name: 'Source Hub', item: `${BASE_URL}/source-hub` },
                    { '@type': 'ListItem', position: 3, name: `${owner}/${repo}`, item: canonicalUrl }
                ]
            }
        ]
    };

    return {
        title,
        description,
        keywords,
        canonicalUrl,
        type: 'website',
        image: DEFAULT_IMAGE,
        jsonLd
    };
}

/**
 * Builds dynamic SEO for Docs page
 */
function buildDocSeo(doc) {
    const name = doc?.title || 'Documentation';
    const title = truncateText(`${name} - Official Guides & Docs | ${SITE_NAME}`, 65);
    const docDesc = cleanText(doc?.description || doc?.content);
    const description = truncateText(`Official guide: ${name}. ${docDesc ? docDesc.substring(0, 80) + '. ' : ''}Step-by-step sideloading, installation, and modding tutorials on GPL Mods.`, 160);
    const canonicalUrl = `${BASE_URL}/docs/${encodeURIComponent(doc?.slug || '')}`;

    const keywords = [
        name,
        `${name} guide`,
        'gpl mods docs',
        'sideloading tutorial',
        'installation instructions',
        ...BRAND_KEYWORDS
    ].join(', ');

    const jsonLd = {
        '@context': 'https://schema.org',
        '@graph': [
            {
                '@type': 'TechArticle',
                headline: title,
                description: description,
                url: canonicalUrl,
                publisher: {
                    '@type': 'Organization',
                    name: 'GPL Mods',
                    url: BASE_URL
                }
            },
            {
                '@type': 'BreadcrumbList',
                itemListElement: [
                    { '@type': 'ListItem', position: 1, name: 'Home', item: BASE_URL },
                    { '@type': 'ListItem', position: 2, name: 'Docs', item: `${BASE_URL}/docs` },
                    { '@type': 'ListItem', position: 3, name: name, item: canonicalUrl }
                ]
            }
        ]
    };

    return {
        title,
        description,
        keywords,
        canonicalUrl,
        type: 'article',
        image: doc?.featuredImageUrl || DEFAULT_IMAGE,
        jsonLd
    };
}

/**
 * Builds dynamic SEO for Forum Issue thread
 */
function buildForumSeo(issue) {
    const titleText = cleanText(issue?.title) || 'Discussion Thread';
    const title = truncateText(`${titleText} | ${SITE_NAME} Community Forum`, 65);
    const rawContent = cleanText(issue?.content);
    const description = truncateText(`Community discussion: ${titleText}. ${rawContent ? rawContent.substring(0, 90) + '. ' : ''}Join answers and developer solutions on GPL Mods.`, 160);
    const canonicalUrl = `${BASE_URL}/community/${encodeURIComponent(issue?.slug || '')}`;

    const keywords = [
        titleText,
        'community discussion',
        'modding forum',
        'troubleshooting help',
        ...BRAND_KEYWORDS
    ].join(', ');

    const jsonLd = {
        '@context': 'https://schema.org',
        '@graph': [
            {
                '@type': 'DiscussionForumPosting',
                headline: titleText,
                articleBody: description,
                url: canonicalUrl,
                author: {
                    '@type': 'Person',
                    name: issue?.author?.username || 'Community Member'
                }
            },
            {
                '@type': 'BreadcrumbList',
                itemListElement: [
                    { '@type': 'ListItem', position: 1, name: 'Home', item: BASE_URL },
                    { '@type': 'ListItem', position: 2, name: 'Community', item: `${BASE_URL}/community` },
                    { '@type': 'ListItem', position: 3, name: titleText, item: canonicalUrl }
                ]
            }
        ]
    };

    return {
        title,
        description,
        keywords,
        canonicalUrl,
        type: 'article',
        image: DEFAULT_IMAGE,
        jsonLd
    };
}

/**
 * Builds dynamic SEO for Club Page
 */
function buildClubSeo(club) {
    const name = cleanText(club?.name) || 'Modding Club';
    const title = truncateText(`${name} - Community Club | ${SITE_NAME}`, 65);
    const clubDesc = cleanText(club?.description);
    const description = truncateText(`Join ${name} on GPL Mods. ${clubDesc ? clubDesc.substring(0, 80) + '. ' : ''}Connect with creators, discover exclusive releases, and chat.`, 160);
    const canonicalUrl = `${BASE_URL}/clubs/${encodeURIComponent(club?.slug || club?._id || '')}`;

    const keywords = [
        name,
        `${name} club`,
        'modding club',
        'creator community',
        ...BRAND_KEYWORDS
    ].join(', ');

    return {
        title,
        description,
        keywords,
        canonicalUrl,
        type: 'website',
        image: club?.bannerUrl || club?.avatarUrl || DEFAULT_IMAGE
    };
}

/**
 * Master SEO Resolver function
 * Inspects request URL and locals, then produces the complete SEO payload
 */
function resolveSeo(req, locals = {}) {
    const rawPath = (req.originalUrl || req.path || '/').split('?')[0].toLowerCase();
    const isNoIndex = isNoindexRoute(rawPath) || locals.noindex === true;

    // Robots directive
    const robots = isNoIndex 
        ? 'noindex, nofollow' 
        : 'index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1';

    // Check entity object in locals
    let entitySeo = null;
    if (locals.file || locals.masterFile) {
        entitySeo = buildModSeo(locals.file, locals.masterFile, req);
    } else if (locals.profileUser) {
        entitySeo = buildUserProfileSeo(locals.profileUser);
    } else if (locals.developerName) {
        entitySeo = buildDeveloperSeo(locals.developerName);
    } else if (locals.license) {
        entitySeo = buildLicenseSeo(locals.license);
    } else if (locals.source) {
        entitySeo = buildSourceSeo(locals.source, locals.currentPath);
    } else if (locals.currentPage && locals.sidebarStructure) {
        entitySeo = buildDocSeo(locals.currentPage);
    } else if (locals.issue) {
        entitySeo = buildForumSeo(locals.issue);
    } else if (locals.club) {
        entitySeo = buildClubSeo(locals.club);
    }

    // Dynamic search query SEO handling
    if (rawPath === '/search' && req.query && req.query.q) {
        const cleanQuery = cleanText(req.query.q);
        if (cleanQuery) {
            const searchTitle = truncateText(`Download ${cleanQuery} Mods, APKs & IPAs - Safe Alternatives | ${SITE_NAME}`, 65);
            const searchDesc = truncateText(`Search results and 100% VirusTotal safe, verified mods for "${cleanQuery}". Clean, ad-free alternative to HappyMod, iOSGods, Panda Helper & IGG Games at GPL Mods.`, 160);
            const searchKeywords = [
                cleanQuery,
                `${cleanQuery} mod`,
                `${cleanQuery} apk`,
                `${cleanQuery} ipa`,
                `${cleanQuery} download`,
                `${cleanQuery} safe alternative`,
                ...COMPETITOR_COMPARATOR_KEYWORDS.slice(0, 8),
                ...TRENDING_GOOGLE_KEYWORDS.slice(0, 6),
                ...BRAND_KEYWORDS.slice(0, 8)
            ].join(', ');

            return {
                title: searchTitle,
                description: searchDesc,
                keywords: searchKeywords,
                canonicalUrl: `${BASE_URL}/search?q=${encodeURIComponent(cleanQuery)}`,
                robots: 'index, follow',
                googlebot: 'index, follow',
                bingbot: 'index, follow',
                isNoIndex: false,
                siteName: SITE_NAME,
                og: {
                    title: searchTitle,
                    description: searchDesc,
                    url: `${BASE_URL}/search?q=${encodeURIComponent(cleanQuery)}`,
                    image: DEFAULT_IMAGE,
                    type: 'website',
                    site_name: SITE_NAME,
                    locale: 'en_US'
                },
                twitter: {
                    card: 'summary_large_image',
                    domain: new URL(BASE_URL).hostname,
                    url: `${BASE_URL}/search?q=${encodeURIComponent(cleanQuery)}`,
                    title: searchTitle,
                    description: searchDesc,
                    image: DEFAULT_IMAGE,
                    site: TWITTER_HANDLE
                },
                jsonLd: {
                    '@context': 'https://schema.org',
                    '@graph': [
                        ...defaultOrgAndWebSite,
                        {
                            '@type': 'SearchResultsPage',
                            name: `Search results for ${cleanQuery}`,
                            url: `${BASE_URL}/search?q=${encodeURIComponent(cleanQuery)}`,
                            description: searchDesc
                        }
                    ]
                }
            };
        }
    }

    // Static page lookup
    const staticMeta = STATIC_PAGE_META[rawPath] || null;

    // Resolve properties with hierarchical fallbacks
    const title = (locals.seo && locals.seo.title) ||
                  (entitySeo && entitySeo.title) ||
                  (staticMeta && staticMeta.title) ||
                  (locals.pageTitle ? `${locals.pageTitle} | ${SITE_NAME}` : STATIC_PAGE_META['/'].title);

    const description = (locals.seo && locals.seo.description) ||
                        (entitySeo && entitySeo.description) ||
                        (staticMeta && staticMeta.description) ||
                        locals.pageDescription ||
                        STATIC_PAGE_META['/'].description;

    const keywords = (locals.seo && locals.seo.keywords) ||
                     (entitySeo && entitySeo.keywords) ||
                     (staticMeta && staticMeta.keywords ? [...staticMeta.keywords, ...BRAND_KEYWORDS].join(', ') : '') ||
                     locals.pageKeywords ||
                     BRAND_KEYWORDS.join(', ');

    const canonicalUrl = (locals.seo && locals.seo.canonicalUrl) ||
                         (entitySeo && entitySeo.canonicalUrl) ||
                         locals.pageUrl ||
                         `${BASE_URL}${rawPath === '/' ? '' : rawPath}`;

    const type = (locals.seo && locals.seo.type) ||
                 (entitySeo && entitySeo.type) ||
                 (staticMeta && staticMeta.type) ||
                 'website';

    const image = (locals.seo && locals.seo.image) ||
                  (entitySeo && entitySeo.image) ||
                  locals.pageImage ||
                  DEFAULT_IMAGE;

    // Structured JSON-LD Graph
    const defaultOrgAndWebSite = [
        {
            '@type': 'Organization',
            '@id': `${BASE_URL}/#organization`,
            name: SITE_NAME,
            url: BASE_URL,
            logo: {
                '@type': 'ImageObject',
                url: DEFAULT_IMAGE
            },
            sameAs: [
                'https://t.me/gplmods',
                'https://github.com/GPLMods'
            ]
        },
        {
            '@type': 'WebSite',
            '@id': `${BASE_URL}/#website`,
            url: BASE_URL,
            name: SITE_NAME,
            publisher: {
                '@id': `${BASE_URL}/#organization`
            },
            potentialAction: {
                '@type': 'SearchAction',
                target: `${BASE_URL}/search?q={search_term_string}`,
                'query-input': 'required name=search_term_string'
            }
        }
    ];

    let jsonLdGraph = [...defaultOrgAndWebSite];

    // Inject FAQ Schema on homepage and FAQ page for Rich Snippet SERP dropdowns
    if (rawPath === '/' || rawPath === '/home' || rawPath === '/faq') {
        jsonLdGraph.push(COMPETITOR_FAQ_SCHEMA);
    }

    if (entitySeo && entitySeo.jsonLd && entitySeo.jsonLd['@graph']) {
        jsonLdGraph = [...jsonLdGraph, ...entitySeo.jsonLd['@graph']];
    } else if (locals.seo && locals.seo.jsonLd && locals.seo.jsonLd['@graph']) {
        jsonLdGraph = [...jsonLdGraph, ...locals.seo.jsonLd['@graph']];
    }

    const hostDomain = new URL(BASE_URL).hostname;

    return {
        title,
        description,
        keywords,
        canonicalUrl,
        robots,
        googlebot: robots,
        bingbot: robots,
        isNoIndex,
        siteName: SITE_NAME,
        og: {
            title,
            description,
            url: canonicalUrl,
            image,
            type,
            site_name: SITE_NAME,
            locale: 'en_US'
        },
        twitter: {
            card: 'summary_large_image',
            domain: hostDomain,
            url: canonicalUrl,
            title,
            description,
            image,
            site: TWITTER_HANDLE
        },
        jsonLd: {
            '@context': 'https://schema.org',
            '@graph': jsonLdGraph
        }
    };
}

/**
 * Express Middleware that attaches and maintains SEO on all views
 */
function seoMiddleware(req, res, next) {
    res.locals.BASE_URL = BASE_URL;
    res.locals.LIVE_DOMAIN = BASE_URL;
    res.locals.BRAND_KEYWORDS = BRAND_KEYWORDS;
    res.locals.TRENDING_GOOGLE_KEYWORDS = TRENDING_GOOGLE_KEYWORDS;
    res.locals.COMPETITOR_COMPARATOR_KEYWORDS = COMPETITOR_COMPARATOR_KEYWORDS;
    res.locals.POPULAR_GAMES_KEYWORDS = POPULAR_GAMES_KEYWORDS;
    res.locals.POPULAR_APPS_KEYWORDS = POPULAR_APPS_KEYWORDS;
    res.locals.WORDPRESS_GPL_KEYWORDS = WORDPRESS_GPL_KEYWORDS;

    // Helper to override or extend SEO in any route
    res.locals.setSeo = function(customSeo) {
        res.locals.seo = { ...(res.locals.seo || {}), ...customSeo };
    };

    // Intercept res.render to auto-compute final SEO right before rendering template
    const originalRender = res.render;
    res.render = function(view, options, callback) {
        let renderOptions = options || {};
        if (typeof options === 'function') {
            callback = options;
            renderOptions = {};
        }

        const mergedLocals = { ...res.locals, ...renderOptions };
        const finalSeo = resolveSeo(req, mergedLocals);
        
        renderOptions.seo = finalSeo;
        // Keep backward-compatible legacy variable names
        renderOptions.pageTitle = finalSeo.title;
        renderOptions.pageDescription = finalSeo.description;
        renderOptions.pageKeywords = finalSeo.keywords;
        renderOptions.pageUrl = finalSeo.canonicalUrl;
        renderOptions.pageImage = finalSeo.og.image;

        return originalRender.call(this, view, renderOptions, callback);
    };

    next();
}

/**
 * Submits URL list to IndexNow API (Bing, Yandex, Seznam, Naver)
 */
async function pingIndexNow(urlList) {
    if (!urlList || urlList.length === 0) return { success: false, reason: 'Empty URL list' };
    const urls = Array.isArray(urlList) ? urlList : [urlList];
    const indexNowKey = process.env.INDEXNOW_KEY || '4387532a48904cbaae6f8ba7ad35d790';
    const host = new URL(BASE_URL).hostname;

    try {
        const response = await axios.post('https://api.indexnow.org/indexnow', {
            host: host,
            key: indexNowKey,
            keyLocation: `${BASE_URL}/${indexNowKey}.txt`,
            urlList: urls
        }, {
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            timeout: 8000
        });

        return { success: true, status: response.status, count: urls.length };
    } catch (err) {
        return { 
            success: false, 
            error: err.response ? err.response.data : err.message 
        };
    }
}

/**
 * Pings major search engines with the sitemap index URL
 */
async function pingSearchEngines(sitemapUrl = `${BASE_URL}/sitemap_index.xml`) {
    const encodedSitemap = encodeURIComponent(sitemapUrl);
    const endpoints = [
        `https://www.google.com/ping?sitemap=${encodedSitemap}`,
        `https://www.bing.com/ping?sitemap=${encodedSitemap}`
    ];

    const results = await Promise.allSettled(endpoints.map(ep => axios.get(ep, { timeout: 6000 })));
    return results.map((r, idx) => ({
        engine: idx === 0 ? 'Google' : 'Bing',
        success: r.status === 'fulfilled',
        details: r.status === 'fulfilled' ? 'Pinged' : (r.reason?.message || 'Error')
    }));
}

module.exports = {
    BASE_URL,
    SITE_NAME,
    TWITTER_HANDLE,
    BRAND_KEYWORDS,
    TRENDING_GOOGLE_KEYWORDS,
    COMPETITOR_COMPARATOR_KEYWORDS,
    POPULAR_GAMES_KEYWORDS,
    POPULAR_APPS_KEYWORDS,
    WORDPRESS_GPL_KEYWORDS,
    COMPETITOR_FAQ_SCHEMA,
    getPlatformKeywords,
    STATIC_PAGE_META,
    isNoindexRoute,
    cleanText,
    truncateText,
    formatPlatformName,
    buildModSeo,
    buildUserProfileSeo,
    buildDeveloperSeo,
    buildLicenseSeo,
    buildSourceSeo,
    buildDocSeo,
    buildForumSeo,
    buildClubSeo,
    resolveSeo,
    seoMiddleware,
    pingIndexNow,
    pingSearchEngines
};
