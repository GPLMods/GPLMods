const { normalizeSingleValue } = require('./formHelpers');

const LARGE_FILE_THRESHOLD = 640 * 1024 * 1024;

function getSubmissionValidationErrors({
    actionType,
    formData,
    fileToUpdate,
    iconKey,
    screenshotKeys,
    screenshots,
    isVariant,
    isDistributor,
    ageRating,
    fileSize = 0,
    directDownloadUrlValue,
    manualFileScanUrlValue,
    manualSiteScanUrlValue,
    isValidNameFn
}) {
    if (actionType !== 'submit') {
        return [];
    }

    const errors = [];

    const modName = (formData.modName || '').trim();
    if (!modName) {
        errors.push('Mod name is required to submit the mod.');
    } else if (isValidNameFn && !isValidNameFn(modName)) {
        errors.push('Mod name can only contain letters, numbers, and spaces.');
    }

    if (!formData.modPlatform) {
        errors.push('Platform is required to submit the mod.');
    }

    if (!formData.modCategory) {
        errors.push('Category is required to submit the mod.');
    }

    if (!formData.modVersion || !formData.modVersion.trim()) {
        errors.push('Version is required to submit the mod.');
    }

    if (!formData.developerName || !formData.developerName.trim()) {
        errors.push('Developer name is required to submit the mod.');
    }

    if (!formData.modDescription || !formData.modDescription.trim()) {
        errors.push('Mod description is required to submit the mod.');
    }

    if (!formData.modFeatures || !formData.modFeatures.trim()) {
        errors.push('Mod features are required to submit the mod.');
    }

    if (!formData.officialDescription || !formData.officialDescription.trim()) {
        errors.push('Official description is required to submit the mod.');
    }

    if (!ageRating) {
        errors.push('Age rating is required to submit the mod.');
    }

    if (!isVariant && !iconKey) {
        errors.push('An icon is required to submit the mod.');
    }

    const hasScreenshots = (screenshotKeys && screenshotKeys.length > 0) || (screenshots && screenshots.length > 0);
    if (!hasScreenshots) {
        errors.push('At least one screenshot is required to submit the mod.');
    }

    const isLargeFile = Number(fileSize || fileToUpdate?.fileSize || 0) > LARGE_FILE_THRESHOLD;
    if (isLargeFile && !manualFileScanUrlValue && !manualSiteScanUrlValue) {
        errors.push('Files larger than 640MB require a manual scan URL before publishing.');
    }

    if (formData.modPlatform === 'ios-jailbroken') {
        const archValues = Array.isArray(formData.architectures)
            ? formData.architectures.filter(Boolean)
            : (formData.architectures ? [formData.architectures] : []);

        if (archValues.length === 0) {
            errors.push('Architecture support is required for jailbroken iOS uploads.');
        }
    }

    return errors;
}

module.exports = {
    LARGE_FILE_THRESHOLD,
    getSubmissionValidationErrors
};
