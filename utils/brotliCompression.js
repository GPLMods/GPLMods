/**
 * GPLMods Native Brotli + Gzip Dual Compression Engine
 * Uses Node's built-in C++ zlib Brotli stream for maximum compression ratio.
 * Automatically falls back to Gzip / Deflate for clients without Brotli support.
 */

const zlib = require('zlib');
const compressible = require('compressible');

function brotliCompression(options = {}) {
    const quality = options.quality || 4; // Quality 4 balances ultra-fast compression speed with 15-25% smaller sizes than Gzip level 6

    return function (req, res, next) {
        // Skip compression if requested or if client doesn't support Brotli
        if (req.headers['x-no-compression']) {
            return next();
        }

        const acceptEncoding = req.headers['accept-encoding'] || '';
        if (!acceptEncoding.includes('br')) {
            // Let downstream compression (Gzip / Deflate) handle it
            return next();
        }

        let brotli = null;
        const originalWrite = res.write;
        const originalEnd = res.end;

        function shouldCompress() {
            const contentType = res.getHeader('content-type');
            return Boolean(contentType && compressible(contentType));
        }

        function getBrotliStream() {
            if (!brotli) {
                brotli = zlib.createBrotliCompress({
                    params: {
                        [zlib.constants.BROTLI_PARAM_QUALITY]: quality
                    }
                });
                res.setHeader('Content-Encoding', 'br');
                res.setHeader('Vary', 'Accept-Encoding');
                res.removeHeader('Content-Length');

                brotli.on('data', chunk => originalWrite.call(res, chunk));
                brotli.on('end', () => originalEnd.call(res));
                brotli.on('error', err => {
                    console.warn('[Brotli Compression Error]:', err.message);
                    originalEnd.call(res);
                });
            }
            return brotli;
        }

        res.write = function (chunk, encoding) {
            if (shouldCompress()) {
                return getBrotliStream().write(chunk, encoding);
            }
            return originalWrite.call(res, chunk, encoding);
        };

        res.end = function (chunk, encoding) {
            if (shouldCompress()) {
                const stream = getBrotliStream();
                if (chunk) {
                    stream.write(chunk, encoding);
                }
                return stream.end();
            }
            return originalEnd.call(res, chunk, encoding);
        };

        next();
    };
}

module.exports = {
    brotliCompression
};
