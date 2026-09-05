const axios = require('axios');

function getClient() {
    return axios.create({
        baseURL: 'https://api.improvmx.com/v4',
        auth: {
            username: 'api',
            password: process.env.IMPROVMX_API_KEY || ''
        }
    });
}

/**
 * Creates an email forwarding alias
 */
exports.createAlias = async (alias, forwardToEmail) => {
    try {
        const client = getClient();
        const domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org';
        const response = await client.post(`/domains/${domain}/aliases`, {
            alias: alias,
            forward: forwardToEmail
        });
        return { success: true, data: response.data };
    } catch (error) {
        console.error("ImprovMX Alias Error:", error.response ? error.response.data : error.message);
        return { success: false, message: error.response?.data?.message || "Failed to create alias." };
    }
};

/**
 * Creates SMTP credentials so the user can SEND emails
 */
exports.createSmtpCredential = async (username, password) => {
    try {
        const client = getClient();
        const domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org';
        const response = await client.post(`/domains/${domain}/credentials`, {
            username: username,
            password: password
        });
        return { success: true, data: response.data };
    } catch (error) {
        console.error("ImprovMX SMTP Error:", error.response ? error.response.data : error.message);
        return { success: false, message: error.response?.data?.message || "Failed to create SMTP credentials." };
    }
};
