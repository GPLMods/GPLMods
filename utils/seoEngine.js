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
        title: 'GPL Mods - 100% Safe & Working Premium Unlocked Mods',
        description: 'Download 100% safe, verified Mod APKs, iOS IPAs, PC software, and GPL themes. Clean, VirusTotal scanned, and premium unlocked for free at GPL Mods.',
        keywords: ['gpl mods', 'mod apk', 'mod ipa', 'safe apk download', 'gpl themes', 'windows software unlocked'],
        type: 'website'
    },
    '/about': {
        title: 'About GPL Mods - Open Source Modding & Safe Software Hub',
        description: 'Learn about GPL Mods, our mission for open-source software, transparent mod verification, VirusTotal dual-engine scanning, and creator attribution.',
        keywords: ['about gpl mods', 'open source software', 'gpl verification', 'safe modding community'],
        type: 'website'
    },
    '/faq': {
        title: 'Frequently Asked Questions (FAQ) | GPL Mods Help Center',
        description: 'Got questions about sideloading IPAs, installing Mod APKs, VirusTotal scanner reports, or memberships? Find quick answers in our official FAQ.',
        keywords: ['gpl mods faq', 'how to sideload', 'mod apk guide', 'virustotal scan help', 'gpl questions'],
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
        title: 'Why Choose GPL Mods? 100% Verified, Clean & Transparent',
        description: 'Discover why millions choose GPL Mods: dual VirusTotal cloud scans, zero malware, authentic GPL licenses, and direct high-speed mirror downloads.',
        keywords: ['why choose gpl mods', 'trusted mod apk site', 'clean apk downloads', 'verified mods'],
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
        keywords: ['gpl mods membership', 'vip supporter', 'fast direct download', 'ad free modding'],
        type: 'website'
    },
    '/upload-policy': {
        title: 'Mod Upload & Safety Verification Policy | GPL Mods',
        description: 'Standards and safety requirements for publishing mods, APKs, IPAs, and software on GPL Mods. Automated scanning and manual audit guidelines.',
        keywords: ['upload policy', 'mod submission rules', 'safe mod guidelines', 'uploader verification'],
        type: 'website'
    },
    '/category': {
        title: 'Browse Mods by Category & Platform | GPL Mods',
        description: 'Explore Android APKs, iOS Sideloading IPAs, Jailbreak Tweaks, Windows Software, and WordPress GPL themes organized by category and platform.',
        keywords: ['browse mods', 'mod categories', 'android mods', 'ios ipas', 'windows mods', 'wordpress themes'],
        type: 'website'
    },
    '/repos': {
        title: 'Source & Sideload Repositories Hub | GPL Mods',
        description: 'Official F-Droid Android repositories and AltStore, SideStore, and Scarlet iOS sideloading source directory on GPL Mods.',
        keywords: ['sideloading repo', 'altstore repo', 'sidestore repo', 'scarlet repo', 'fdroid repository', 'gpl repos'],
        type: 'website'
    },
    '/jailbreak-repos': {
        title: 'iOS Jailbreak Repos (Sileo, Cydia, Zebra) | GPL Mods',
        description: 'Add verified Rootless, Rootful, and Roothide jailbreak repos directly to Sileo, Zebra, and Cydia. 100% safe iOS packages on GPL Mods.',
        keywords: ['jailbreak repo', 'sileo repo', 'cydia repo', 'zebra repo', 'rootless jailbreak', 'ios tweaks'],
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
        description: 'Inspect open source repositories, browse commit trees, and download raw code files from verified developers on GPL Mods.',
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
        title: 'Content & AI Sitemap Directory | GPL Mods Official',
        description: 'Comprehensive HTML sitemap and structured AI directory indexing all verified mods, categories, creators, and open-source documentation.',
        keywords: ['ai sitemap', 'gpl mods directory', 'content index', 'llm directory', 'all mods sitemap'],
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
        ...BRAND_KEYWORDS
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
