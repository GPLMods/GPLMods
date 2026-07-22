function normalizeSingleValue(value) {
    if (Array.isArray(value)) {
        const firstValidValue = value.find(v => typeof v === 'string' && v.trim());
        return firstValidValue ? firstValidValue.trim() : '';
    }

    if (typeof value === 'string') {
        return value.trim();
    }

    return '';
}

module.exports = { normalizeSingleValue };
