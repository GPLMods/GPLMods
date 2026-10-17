/**
 * GPLMods Native Brotli + Gzip Dual Compression Engine
 * Uses Node's built-in zlib Brotli stream via the battle-tested compression engine
 * for maximum compression ratio, zero duplicate wrappers, and zero header collisions.
 * Automatically serves Brotli (br) to modern browsers, falling back to Gzip / Deflate.
 */

const compression = require('compression');
const zlib = require('zlib');

function brotliCompression(options = {}) {
    const quality = options.quality !== undefined ? options.quality : 4;
    const level = options.level !== undefined ? options.level : 6;
    const threshold = options.threshold !== undefined ? options.threshold : 1024;

    return compression({
        level: level,
        threshold: threshold,
        brotli: {
            params: {
                [zlib.constants.BROTLI_PARAM_QUALITY]: quality
            }
        },
        filter: (req, res) => {
            if (req.headers['x-no-compression']) {
                return false;
            }
            return compression.filter(req, res);
        }
    });
}

module.exports = {
    brotliCompression
};

