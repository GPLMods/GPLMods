const test = require('node:test');
const assert = require('node:assert/strict');
const { getSubmissionValidationErrors } = require('../utils/uploadValidation');

function isValidName(name) {
  return /^[A-Za-z0-9 ]+$/.test(name);
}

test('submit validation requires the new core fields before publishing', () => {
  const errors = getSubmissionValidationErrors({
    actionType: 'submit',
    formData: {},
    fileToUpdate: { fileSize: 0 },
    iconKey: null,
    screenshotKeys: [],
    screenshots: [],
    isVariant: false,
    isDistributor: false,
    ageRating: '',
    fileSize: 0,
    directDownloadUrlValue: '',
    manualFileScanUrlValue: '',
    manualSiteScanUrlValue: '',
    isValidNameFn: isValidName
  });

  assert.ok(errors.some((message) => message.includes('Mod name')));
  assert.ok(errors.some((message) => message.includes('Platform')));
  assert.ok(errors.some((message) => message.includes('Developer name')));
  assert.ok(errors.some((message) => message.includes('At least one screenshot')));
});

test('draft submission skips the full submit validation', () => {
  const errors = getSubmissionValidationErrors({
    actionType: 'draft',
    formData: {},
    fileToUpdate: { fileSize: 0 },
    iconKey: null,
    screenshotKeys: [],
    screenshots: [],
    isVariant: false,
    isDistributor: false,
    ageRating: '',
    fileSize: 0,
    directDownloadUrlValue: '',
    manualFileScanUrlValue: '',
    manualSiteScanUrlValue: '',
    isValidNameFn: isValidName
  });

  assert.deepEqual(errors, []);
});
