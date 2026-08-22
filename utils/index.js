/**
 * ============================================================================
 * GPLMODS UTILITIES REGISTRY
 * Categorized export barrel for all utility modules
 * ============================================================================
 */

const ftpSync = require('./storage/ftpSync');
const uploadValidation = require('./storage/uploadValidation');
const mailer = require('./mail/mailer');
const formHelpers = require('./helpers/formHelpers');
const tempMailDetector = require('./helpers/tempMailDetector');

module.exports = {
    // Storage
    ftpSync,
    uploadValidation,
    
    // Mail
    mailer,
    
    // Helpers
    formHelpers,
    tempMailDetector,
    
    // Categorized Namespaces
    Storage: { ftpSync, uploadValidation },
    Mail: { mailer },
    Helpers: { formHelpers, tempMailDetector }
};
