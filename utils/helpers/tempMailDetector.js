const axios = require('axios');
const TempDomain = require('../../models/tempDomain');
const { reserveApiQuota, releaseApiQuota, disableApiQuotaOnError } = require('../apiQuota');

const API_KEY = process.env.TEMP_MAIL_DETECTOR_API_KEY || 'f28fc2a32bd4940ee7b92836077430f1';
const API_URL = 'https://api.tempmaildetector.com/check';

const DEFAULT_WHITELIST = new Set([
    'gmail.com',
    'outlook.com',
    'yahoo.com',
    'icloud.com'
]);

function extractDomain(emailOrDomain) {
    if (!emailOrDomain || typeof emailOrDomain !== 'string') {
        throw new Error('Invalid email or domain provided.');
    }
    
    const parts = emailOrDomain.trim().toLowerCase().split('@');
    const domain = parts.length > 1 ? parts[parts.length - 1] : parts[0];
    
    return domain.trim();
}

async function checkDomain(emailOrDomain) {
    const domain = extractDomain(emailOrDomain);

    if (DEFAULT_WHITELIST.has(domain)) {
        return {
            domain,
            isDisposable: false,
            blocked: false,
            score: 0,
            meta: {
                block_list: false,
                domain_age: -1,
                website_resolves: true,
                accepts_all_addresses: false,
                valid_email_security: true,
                forwarding: false
            },
            cached: false,
            whitelisted: true,
            reason: 'Whitelisted default domain'
        };
    }

    try {
        const cachedRecord = await TempDomain.findOne({ domain }).lean();
        if (cachedRecord) {
            return {
                domain: cachedRecord.domain,
                isDisposable: cachedRecord.isDisposable,
                blocked: cachedRecord.isDisposable,
                score: cachedRecord.score,
                meta: {
                    block_list: cachedRecord.block_list,
                    domain_age: cachedRecord.domain_age,
                    website_resolves: cachedRecord.website_resolves,
                    accepts_all_addresses: cachedRecord.accepts_all_addresses,
                    valid_email_security: cachedRecord.valid_email_security,
                    forwarding: cachedRecord.forwarding
                },
                cached: true,
                whitelisted: false
            };
        }
    } catch (dbError) {
        console.error(`[TempMailDetector] MongoDB search error for ${domain}:`, dbError.message);
    }

    let reservation;
    try {
        const quota = await reserveApiQuota({ service: 'temp-mail-detector', metric: 'requests', period: 'monthly', amount: 1 });
        if (!quota.allowed) {
            return { domain, isDisposable: false, blocked: false, score: 0, meta: {}, cached: false, whitelisted: false, reason: 'API quota unavailable' };
        }
        reservation = quota.reservation;

        const response = await axios.post(
            API_URL,
            { domain },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${API_KEY}`
                },
                timeout: 5000
            }
        );

        const data = response.data;

        if (data.error || data.message) {
            const errStr = data.error || data.message;
            if (errStr === 'invalid_domain_or_mx' || errStr === 'error_processing_domain') {
                return {
                    domain,
                    isDisposable: true,
                    blocked: true,
                    score: 100,
                    meta: { block_list: true },
                    error: errStr,
                    cached: false,
                    whitelisted: false,
                    reason: `Domain validation failed: ${errStr}`
                };
            }
        }

        const score = data.score !== undefined ? data.score : 0;
        const meta = data.meta || {};
        const blockList = Boolean(meta.block_list);

        const isDisposable = score >= 75 || blockList === true;

        try {
            await TempDomain.findOneAndUpdate(
                { domain },
                {
                    domain,
                    score,
                    isDisposable,
                    block_list: blockList,
                    domain_age: meta.domain_age ?? -1,
                    website_resolves: Boolean(meta.website_resolves),
                    accepts_all_addresses: Boolean(meta.accepts_all_addresses),
                    valid_email_security: Boolean(meta.valid_email_security),
                    forwarding: Boolean(meta.forwarding),
                    rawMeta: meta,
                    checkedAt: new Date()
                },
                { upsert: true, new: true, setDefaultsOnInsert: true }
            );
        } catch (dbSaveError) {
            console.error(`[TempMailDetector] Failed to save domain ${domain} to MongoDB:`, dbSaveError.message);
        }

        return {
            domain: data.domain || domain,
            isDisposable,
            blocked: isDisposable,
            score,
            meta: {
                block_list: blockList,
                domain_age: meta.domain_age ?? -1,
                website_resolves: Boolean(meta.website_resolves),
                accepts_all_addresses: Boolean(meta.accepts_all_addresses),
                valid_email_security: Boolean(meta.valid_email_security),
                forwarding: Boolean(meta.forwarding)
            },
            cached: false,
            whitelisted: false
        };

    } catch (apiError) {
        await releaseApiQuota(reservation).catch(() => {});
        await disableApiQuotaOnError('temp-mail-detector', 'monthly', apiError, 'requests').catch(() => {});
        if (apiError.response) {
            const status = apiError.response.status;
            const resData = apiError.response.data;

            console.error(`[TempMailDetector] API returned HTTP ${status}:`, resData);

            if (status === 400 || resData?.error === 'invalid_domain_or_mx') {
                return {
                    domain,
                    isDisposable: true,
                    blocked: true,
                    score: 100,
                    meta: { block_list: true },
                    reason: 'Invalid domain or MX record',
                    cached: false,
                    whitelisted: false
                };
            }
        } else {
            console.error(`[TempMailDetector] Request error for ${domain}:`, apiError.message);
        }

        return {
            domain,
            isDisposable: false,
            blocked: false,
            score: 0,
            meta: {},
            error: apiError.message,
            cached: false,
            whitelisted: false,
            reason: 'API execution error fallback'
        };
    }
}

function validateTempEmailMiddleware(emailField = 'email') {
    return async (req, res, next) => {
        try {
            const email = req.body[emailField];
            if (!email) {
                return res.status(400).json({ error: `${emailField} field is required.` });
            }

            const result = await checkDomain(email);
            if (result.blocked || result.isDisposable) {
                return res.status(400).json({
                    error: 'Disposable / Temporary email addresses are not allowed. Please use a valid email address.',
                    domain: result.domain,
                    score: result.score
                });
            }

            req.tempMailCheck = result;
            next();
        } catch (err) {
            console.error('[TempMailDetector] Middleware error:', err);
            next();
        }
    };
}

module.exports = {
    checkDomain,
    extractDomain,
    validateTempEmailMiddleware,
    DEFAULT_WHITELIST,
    API_KEY
};
