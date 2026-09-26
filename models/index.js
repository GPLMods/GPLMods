/**
 * ============================================================================
 * GPLMODS MODELS REGISTRY
 * Categorized export barrel for all database models
 * ============================================================================
 */

// --- CORE MODELS ---
const File = require('./core/file');
const User = require('./core/user');
const Review = require('./core/review');
const Reply = require('./core/reply');
const Donation = require('./donation');
const MembershipOrder = require('./membershipOrder');
const Coupon = require('./coupon');

// --- COMMUNITY MODELS ---
const Issue = require('./community/issue');
const Request = require('./community/request');
const SupportTicket = require('./community/supportTicket');
const UserNotification = require('./community/userNotification');
const UnbanRequest = require('./community/unbanRequest');
const Club = require('./community/club');
const ClubChannel = require('./community/clubChannel');
const ClubRole = require('./community/clubRole');
const ClubMember = require('./community/clubMember');
const ClubMessage = require('./community/clubMessage');
const ClubJoinRequest = require('./community/clubJoinRequest');

// --- CONTENT & DOCS MODELS ---
const DocPage = require('./content/docPage');
const DocCategory = require('./content/docCategory');
const Announcement = require('./content/announcement');
const License = require('./content/license');
const ModPromotion = require('./content/modPromotion');

// --- SYSTEM & MODERATION MODELS ---
const DistributorApplication = require('./system/distributorApplication');
const Dmca = require('./system/dmca');
const Report = require('./system/report');
const IosCert = require('./system/iosCert');
const IosDns = require('./system/iosDns');
const SiteState = require('./system/siteState');
const Subscriber = require('./system/subscriber');
const DailyStat = require('./system/dailyStat');
const AutomatedCampaign = require('./system/automatedCampaign');
const NewsletterCampaign = require('./system/newsletterCampaign');
const PointHistory = require('./system/pointHistory');
const TempDomain = require('./system/tempDomain');
const TranslationCache = require('./system/translationCache');
const TranslationQuota = require('./system/translationQuota');
const ApiLimit = require('./system/apiLimit');
const VpnCache = require('./system/vpnCache');
const SourceCode = require('./sourceCode');
const ChatSession = require('./chatSession');
const ChatSettings = require('./chatSettings');
const AIKnowledge = require('./aiKnowledge');
const VolunteerApplication = require('./system/volunteerApplication');

module.exports = {
    // Core
    File,
    User,
    Review,
    Reply,
    Donation,
    MembershipOrder,
    Coupon,
    ChatSession,
    ChatSettings,
    AIKnowledge,

    // Community
    Issue,
    Request,
    SupportTicket,
    UserNotification,
    UnbanRequest,
    Club,
    ClubChannel,
    ClubRole,
    ClubMember,
    ClubMessage,
    ClubJoinRequest,

    // Content
    DocPage,
    DocCategory,
    Announcement,
    License,
    ModPromotion,

    // System & Moderation
    DistributorApplication,
    Dmca,
    Report,
    IosCert,
    IosDns,
    SiteState,
    Subscriber,
    DailyStat,
    AutomatedCampaign,
    NewsletterCampaign,
    PointHistory,
    TempDomain,
    TranslationCache,
    TranslationQuota,
    ApiLimit,
    VpnCache,
    SourceCode,
    VolunteerApplication,

    // Categorized Namespaces
    Core: { File, User, Review, Reply },
    Community: { Issue, Request, SupportTicket, UserNotification, UnbanRequest, Club, ClubChannel, ClubRole, ClubMember, ClubMessage, ClubJoinRequest },
    Content: { DocPage, DocCategory, Announcement, License, ModPromotion },
    System: { DistributorApplication, VolunteerApplication, Dmca, Report, IosCert, IosDns, SiteState, Subscriber, DailyStat, AutomatedCampaign, NewsletterCampaign, PointHistory, TempDomain, TranslationCache, TranslationQuota, ApiLimit, VpnCache },
    Repositories: { SourceCode }
};
