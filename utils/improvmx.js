const axios = require('axios');

function getClient() {
    return axios.create({
        baseURL: 'https://api.improvmx.com/v4',
        auth: {
            username: 'api',
            password: process.env.IMPROVMX_API_KEY || ''
        },
        timeout: 10000
    });
}

/**
 * Get domain details & MX/DNS health
 */
exports.getDomain = async (domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org') => {
    try {
        const client = getClient();
        const response = await client.get(`/domains/${domain}`);
        return { success: true, domain: response.data.domain };
    } catch (error) {
        console.error("ImprovMX getDomain Error:", error.response ? error.response.data : error.message);
        return { 
            success: false, 
            message: error.response?.data?.message || error.message || "Failed to fetch domain details.",
            status: error.response?.status
        };
    }
};

/**
 * List all email forwarding aliases for the domain
 */
exports.listAliases = async (domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org') => {
    try {
        const client = getClient();
        const response = await client.get(`/domains/${domain}/aliases`);
        return { success: true, aliases: response.data.aliases || [] };
    } catch (error) {
        console.error("ImprovMX listAliases Error:", error.response ? error.response.data : error.message);
        return { 
            success: false, 
            aliases: [],
            message: error.response?.data?.message || error.message || "Failed to list aliases." 
        };
    }
};

/**
 * Creates an email forwarding alias
 */
exports.createAlias = async (alias, forwardToEmail, domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org') => {
    try {
        const client = getClient();
        const response = await client.post(`/domains/${domain}/aliases`, {
            alias: alias,
            forward: forwardToEmail
        });
        return { success: true, data: response.data };
    } catch (error) {
        console.error("ImprovMX Alias Error:", error.response ? error.response.data : error.message);
        return { success: false, message: error.response?.data?.message || error.message || "Failed to create alias." };
    }
};

/**
 * Deletes an email alias
 */
exports.deleteAlias = async (aliasId, domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org') => {
    try {
        const client = getClient();
        const response = await client.delete(`/domains/${domain}/aliases/${aliasId}`);
        return { success: true, data: response.data };
    } catch (error) {
        console.error("ImprovMX deleteAlias Error:", error.response ? error.response.data : error.message);
        return { success: false, message: error.response?.data?.message || error.message || "Failed to delete alias." };
    }
};

/**
 * Creates SMTP credentials so the user can SEND emails
 */
exports.createSmtpCredential = async (username, password, domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org') => {
    try {
        const client = getClient();
        const response = await client.post(`/domains/${domain}/credentials`, {
            username: username,
            password: password
        });
        return { success: true, data: response.data };
    } catch (error) {
        console.error("ImprovMX SMTP Error:", error.response ? error.response.data : error.message);
        return { success: false, message: error.response?.data?.message || error.message || "Failed to create SMTP credentials." };
    }
};

/**
 * Lists SMTP credentials for the domain
 */
exports.listCredentials = async (domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org') => {
    try {
        const client = getClient();
        const response = await client.get(`/domains/${domain}/credentials`);
        return { success: true, credentials: response.data.credentials || [] };
    } catch (error) {
        console.error("ImprovMX listCredentials Error:", error.response ? error.response.data : error.message);
        return { success: false, credentials: [], message: error.response?.data?.message || error.message || "Failed to list credentials." };
    }
};
