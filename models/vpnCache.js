const mongoose = require('mongoose');

const vpnCacheSchema = new mongoose.Schema({
    ip: { 
        type: String, 
        required: true, 
        unique: true, 
        index: true 
    },
    isVpn: { 
        type: Boolean, 
        required: true 
    },
    security: {
        vpn: { type: Boolean, default: false },
        proxy: { type: Boolean, default: false },
        tor: { type: Boolean, default: false },
        relay: { type: Boolean, default: false }
    },
    location: {
        city: { type: String, default: '' },
        region: { type: String, default: '' },
        country: { type: String, default: '' },
        continent: { type: String, default: '' },
        region_code: { type: String, default: '' },
        country_code: { type: String, default: '' },
        continent_code: { type: String, default: '' },
        latitude: { type: String, default: '' },
        longitude: { type: String, default: '' },
        time_zone: { type: String, default: '' },
        is_in_european_union: { type: Boolean, default: false }
    },
    network: {
        network: { type: String, default: '' },
        autonomous_system_number: { type: String, default: '' },
        autonomous_system_organization: { type: String, default: '' }
    },
    rawResponse: { type: Object }
}, { 
    timestamps: true 
});

module.exports = mongoose.model('VpnCache', vpnCacheSchema);
