const { normalizeSingleValue } = require('../helpers/formHelpers');

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
    isValidNameFn,
    user
}) {
    if (actionType !== 'submit') {
        return [];
    }

    const errors = [];

    if (user && Number(fileSize || fileToUpdate?.fileSize || 0) > 0) {
        const { validateUploadFileSize } = require('../uploadQuota');
        const sizeCheck = validateUploadFileSize(user, Number(fileSize || fileToUpdate?.fileSize || 0));
        if (!sizeCheck.valid) {
            errors.push(sizeCheck.error);
        }
    }

    const modName = (formData.modName || '').trim();
    if (!modName) {
        errors.push('Mod name is required to submit the mod.');
    } else if (isValidNameFn && !isValidNameFn(modName)) {
        errors.push("Mod name can only contain letters, numbers, spaces, and standard developer characters (. , : - & + ( ) [ ] _ ' \" ! / \\ % # ~). Emojis and unsupported special symbols are not allowed.");
    }

    if (!isVariant && !formData.modPlatform && (!fileToUpdate || !fileToUpdate.category || fileToUpdate.category === 'n/a')) {
        errors.push('Platform is required to submit the mod.');
    }

    const isMultiPart = formData.isMultiPart === 'true' || formData.isMultiPart === true;
    const isExternal = Boolean(fileToUpdate?.fileKey === 'external-link' || formData.externalDownloadUrl || isMultiPart);
    if (isExternal) {
        if (isMultiPart) {
            const pUrls = Array.isArray(formData.partUrls) ? formData.partUrls.filter(Boolean) : (formData.partUrls ? [formData.partUrls] : []);
            if (pUrls.length === 0) {
                errors.push('At least one part download URL is required for multi-part downloads.');
            }
        } else {
            const extUrl = (formData.externalDownloadUrl || fileToUpdate?.externalDownloadUrl || '').trim();
            if (!extUrl && fileToUpdate?.fileKey === 'external-link') {
                errors.push('External download URL is required for external link uploads.');
            }
        }
    }

    // For variants, all metadata fields are optional and inherit from the master mod
    if (!isVariant) {
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

        if (!iconKey) {
            errors.push('An icon is required to submit the mod.');
        }

        const currentScreenshotsCount = (screenshotKeys && screenshotKeys.length) ? screenshotKeys.length : (screenshots ? screenshots.length : 0);
        if (currentScreenshotsCount === 0) {
            errors.push('At least one screenshot is required to submit the mod.');
        }

        if (formData.modPlatform === 'ios-jailbroken') {
            const archValues = Array.isArray(formData.architectures)
                ? formData.architectures.filter(Boolean)
                : (formData.architectures ? [formData.architectures] : []);

            if (archValues.length === 0) {
                errors.push('Architecture support is required for jailbroken iOS uploads.');
            }
        }
    }

    const currentScreenshotsCount = (screenshotKeys && screenshotKeys.length) ? screenshotKeys.length : (screenshots ? screenshots.length : 0);
    if (currentScreenshotsCount > 4) {
        errors.push(`You have uploaded more then 4 Screenshot of the app/game. There are only 4 maximum screenshot are allowed for an app or game please remove unnecessary ${currentScreenshotsCount - 4} of Screenshot`);
    }

    const isLargeFile = Number(fileSize || fileToUpdate?.fileSize || 0) > LARGE_FILE_THRESHOLD;
    if (isLargeFile && !manualFileScanUrlValue && !manualSiteScanUrlValue) {
        errors.push('Files larger than 640MB require a manual scan URL before publishing.');
    }

    return errors;
}

module.exports = {
    LARGE_FILE_THRESHOLD,
    getSubmissionValidationErrors
};
