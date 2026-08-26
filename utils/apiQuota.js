const ApiLimit = require('../models/system/apiLimit');
const TranslationQuota = require('../models/system/translationQuota');

const DEFAULT_LIMITS = {
    deepl: { period: 'monthly', metric: 'characters', limit: 500000, unit: 'characters' }
};

const LIMIT_CATALOG = [
    { service: 'render', metric: 'instance-hours', period: 'monthly', limit: 750, unit: 'hours', trackingOnly: true },
    { service: 'render', metric: 'bandwidth', period: 'monthly', limit: 5, unit: 'GB', trackingOnly: true },
    { service: 'render', metric: 'pipeline-minutes', period: 'monthly', limit: 500, unit: 'minutes', trackingOnly: true },
    { service: 'virustotal', metric: 'requests', period: 'daily', limit: 500, unit: 'requests' },
    { service: 'virustotal', metric: 'requests', period: 'monthly', limit: 15500, unit: 'requests' },
    { service: 'deepl', metric: 'characters', period: 'monthly', limit: 500000, unit: 'characters' },
    { service: 'smtp2go', metric: 'emails', period: 'monthly', limit: 1000, unit: 'emails', resetDay: 7 },
    { service: 'smtp2go', metric: 'emails', period: 'daily', limit: 200, unit: 'emails' },
    { service: 'smtp2go', metric: 'emails', period: 'hourly', limit: 25, unit: 'emails' },
    { service: 'vpnapi.io', metric: 'requests', period: 'daily', limit: 1000, unit: 'requests' },
    { service: 'temp-mail-detector', metric: 'requests', period: 'monthly', limit: 200, unit: 'requests' },
    { service: 'improvmx', metric: 'forwarded-emails', period: 'daily', limit: 500, unit: 'emails', trackingOnly: true },
    { service: 'mongodb', metric: 'storage', period: 'monthly', limit: 512, unit: 'MB', trackingOnly: true },
    { service: 'mongodb', metric: 'network-transfer', period: 'weekly', limit: 10, unit: 'GB', rolling: true, trackingOnly: true },
    { service: 'google-recaptcha', metric: 'requests', period: 'monthly', limit: 10000, unit: 'requests' },
    { service: 'backblaze-b2', metric: 'download', period: 'daily', limit: 1, unit: 'GB', trackingOnly: true },
    { service: 'backblaze-b2', metric: 'class-b', period: 'daily', limit: 2500, unit: 'operations', trackingOnly: true },
    { service: 'backblaze-b2', metric: 'class-c', period: 'daily', limit: 2500, unit: 'operations', trackingOnly: true },
    { service: 'tidio', metric: 'conversations', period: 'monthly', limit: 50, unit: 'conversations', trackingOnly: true },
    { service: 'tidio', metric: 'chatbot-visitors', period: 'monthly', limit: 100, unit: 'visitors', trackingOnly: true },
    { service: 'infinityfree', metric: 'hits', period: 'daily', limit: 50000, unit: 'hits', trackingOnly: true },
    { service: 'infinityfree', metric: 'disk-space', period: 'monthly', limit: 5, unit: 'GB', trackingOnly: true },
    { service: 'cloudflare-workers', metric: 'requests', period: 'daily', limit: 100000, unit: 'requests', trackingOnly: true }
];

function getWindow(period, now = new Date()) {
    const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));

    if (period === 'monthly') {
        start.setUTCDate(1);
        return { start, end: new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + 1, 1)) };
    }

    if (period === 'hourly') {
        const hourlyStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours()));
        return { start: hourlyStart, end: new Date(hourlyStart.getTime() + 60 * 60 * 1000) };
    }

    if (period === 'weekly') {
        const daysSinceMonday = (start.getUTCDay() + 6) % 7;
        start.setUTCDate(start.getUTCDate() - daysSinceMonday);
        return { start, end: new Date(start.getTime() + 7 * 24 * 60 * 60 * 1000) };
    }

    return { start, end: new Date(start.getTime() + 24 * 60 * 60 * 1000) };
}

function getMonthlyDayWindow(resetDay, now = new Date()) {
    const thisMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), resetDay));
    const start = now >= thisMonth ? thisMonth : new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, resetDay));
    return { start, end: new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + 1, resetDay)) };
}

async function ensureApiLimitCatalog() {
    await ApiLimit.updateMany(
        { metric: { $exists: false } },
        { $set: { metric: 'characters', unit: 'characters', resetDay: 1, rolling: false, trackingOnly: false } }
    );
    await ApiLimit.collection.dropIndex('service_1_period_1').catch(() => {});

    for (const definition of LIMIT_CATALOG) {
        const window = definition.period === 'monthly' && definition.resetDay
            ? getMonthlyDayWindow(definition.resetDay)
            : getWindow(definition.period);
        const existing = await ApiLimit.findOne({
            service: definition.service,
            metric: definition.metric,
            period: definition.period
        });
        const legacyMonth = definition.service === 'deepl' && definition.period === 'monthly'
            ? await TranslationQuota.findOne({ monthYear: window.start.toISOString().slice(0, 7) })
            : null;

        await ApiLimit.updateOne(
            { service: definition.service, metric: definition.metric, period: definition.period },
            {
                $setOnInsert: {
                    ...definition,
                    used: legacyMonth ? legacyMonth.characterCount : 0,
                    windowStart: window.start,
                    windowEnd: window.end
                }
            },
            { upsert: true }
        );

        if (existing && existing.windowEnd <= new Date()) {
            await getOrCreateLimit(definition.service, definition.period, definition.metric);
        }
    }
}

async function getOrCreateLimit(service, period, metric = null) {
    const normalizedService = service.toLowerCase();
    const defaults = DEFAULT_LIMITS[normalizedService] || { period, limit: 0 };
    const selectedPeriod = period || defaults.period;
    const selectedMetric = metric || defaults.metric || 'requests';
    let window = getWindow(selectedPeriod);

    let apiLimit = await ApiLimit.findOne({ service: normalizedService, metric: selectedMetric, period: selectedPeriod });
    if (apiLimit && selectedPeriod === 'monthly' && apiLimit.resetDay !== 1) {
        window = getMonthlyDayWindow(apiLimit.resetDay);
    }
    if (!apiLimit) {
        let used = 0;
        if (normalizedService === 'deepl' && selectedPeriod === 'monthly') {
            const monthYear = window.start.toISOString().slice(0, 7);
            const legacyQuota = await TranslationQuota.findOne({ monthYear });
            used = legacyQuota ? legacyQuota.characterCount : 0;
        }

        try {
            apiLimit = await ApiLimit.create({
                service: normalizedService,
                metric: selectedMetric,
                period: selectedPeriod,
                limit: defaults.limit,
                unit: defaults.unit || 'requests',
                used,
                windowStart: window.start,
                windowEnd: window.end
            });
        } catch (error) {
            if (error.code !== 11000) throw error;
            apiLimit = await ApiLimit.findOne({ service: normalizedService, metric: selectedMetric, period: selectedPeriod });
        }
    }

    if (apiLimit.windowEnd <= new Date()) {
        const previousWindowEnd = apiLimit.windowEnd;
        window = apiLimit.period === 'monthly' && apiLimit.resetDay !== 1
            ? getMonthlyDayWindow(apiLimit.resetDay)
            : getWindow(apiLimit.period);
        await ApiLimit.updateOne(
            { _id: apiLimit._id, windowEnd: previousWindowEnd },
            {
                $set: {
                    used: 0,
                    windowStart: window.start,
                    windowEnd: window.end,
                    autoDisabled: false,
                    disabledReason: '',
                    lastErrorAt: null
                }
            }
        );
        apiLimit = await ApiLimit.findById(apiLimit._id);
    }

    return apiLimit;
}

async function reserveApiQuota({ service, period, metric, amount }) {
    if (!Number.isFinite(amount) || amount <= 0) return { allowed: true };

    const apiLimit = await getOrCreateLimit(service, period, metric);
    if (apiLimit.trackingOnly) return { allowed: true };
    if (!apiLimit.enabled) return { allowed: false, reason: 'disabled' };
    if (apiLimit.autoDisabled) return { allowed: false, reason: apiLimit.disabledReason || 'temporarily-disabled' };

    const updated = await ApiLimit.findOneAndUpdate(
        {
            _id: apiLimit._id,
            enabled: true,
            autoDisabled: false,
            limit: { $gte: amount },
            $expr: { $lte: [{ $add: ['$used', amount] }, '$limit'] }
        },
        { $inc: { used: amount } },
        { new: true }
    );

    if (updated) return { allowed: true, reservation: { id: updated._id, amount } };

    await ApiLimit.updateOne(
        { _id: apiLimit._id, enabled: true, autoDisabled: false },
        { $set: { autoDisabled: true, disabledReason: 'limit-reached' } }
    );
    return { allowed: false, reason: 'limit-reached' };
}

async function releaseApiQuota(reservation) {
    if (!reservation) return;
    await ApiLimit.updateOne(
        { _id: reservation.id },
        { $inc: { used: -reservation.amount } }
    );
}

async function disableApiQuotaOnError(service, period, error, metric = null) {
    const apiLimit = await getOrCreateLimit(service, period, metric);
    if (!apiLimit.autoDisableOnError) return;

    await ApiLimit.updateOne(
        { _id: apiLimit._id, enabled: true },
        {
            $set: {
                autoDisabled: true,
                disabledReason: `provider-error: ${String(error.message || error).slice(0, 240)}`,
                lastErrorAt: new Date()
            }
        }
    );
}

async function reserveApiQuotaSet(service, metric, amount, periods) {
    const reservations = [];
    for (const period of periods) {
        const result = await reserveApiQuota({ service, metric, period, amount });
        if (!result.allowed) {
            for (const reservation of reservations) await releaseApiQuota(reservation);
            return result;
        }
        if (result.reservation) reservations.push(result.reservation);
    }
    return { allowed: true, reservations };
}

async function releaseApiQuotaSet(reservations) {
    for (const reservation of reservations || []) await releaseApiQuota(reservation);
}

module.exports = {
    LIMIT_CATALOG,
    ensureApiLimitCatalog,
    getOrCreateLimit,
    reserveApiQuota,
    releaseApiQuota,
    reserveApiQuotaSet,
    releaseApiQuotaSet,
    disableApiQuotaOnError
};
