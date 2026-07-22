const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeSingleValue } = require('../utils/formHelpers');

test('normalizeSingleValue turns array form values into a single string', () => {
  assert.equal(normalizeSingleValue(['https://example.com/a', 'https://example.com/b']), 'https://example.com/a');
  assert.equal(normalizeSingleValue(['   ', 'https://example.com/b']), 'https://example.com/b');
  assert.equal(normalizeSingleValue('  https://example.com/c  '), 'https://example.com/c');
  assert.equal(normalizeSingleValue(undefined), '');
});
