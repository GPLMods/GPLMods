import React from 'react';

const VariantBadge = (props) => {
  const { record, property } = props;
  const isVariant = record.params[property.name];

  if (isVariant === true || isVariant === 'true') {
    return (
      <span
        className="admin-custom-chip"
        data-badge-val="variant-child"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '3px 10px',
          borderRadius: '20px',
          fontSize: '11px',
          fontWeight: 700,
          letterSpacing: '0.06em',
          textTransform: 'uppercase',
          background: 'linear-gradient(145deg, rgba(186, 104, 200, 0.22) 0%, rgba(65, 25, 75, 0.25) 100%)',
          color: '#ce93d8',
          border: '1px solid rgba(186, 104, 200, 0.6)',
          boxShadow: 'inset 0 1.5px 2px rgba(255, 255, 255, 0.2), inset 0 -1.5px 2px rgba(0, 0, 0, 0.8), 0 0 10px rgba(186, 104, 200, 0.25)',
          textShadow: '0 0 6px rgba(206, 147, 216, 0.4)',
          fontFamily: "'Poppins', sans-serif"
        }}
      >
        Variant
      </span>
    );
  }

  return (
    <span
      className="admin-custom-chip"
      data-badge-val="variant-master"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: '3px 10px',
        borderRadius: '20px',
        fontSize: '11px',
        fontWeight: 700,
        letterSpacing: '0.06em',
        textTransform: 'uppercase',
        background: 'linear-gradient(145deg, rgba(255, 215, 0, 0.22) 0%, rgba(90, 70, 15, 0.25) 100%)',
        color: '#FFD700',
        border: '1px solid rgba(255, 215, 0, 0.65)',
        boxShadow: 'inset 0 1.5px 2px rgba(255, 255, 255, 0.22), inset 0 -1.5px 2px rgba(0, 0, 0, 0.8), 0 0 10px rgba(255, 215, 0, 0.25)',
        textShadow: '0 0 6px rgba(255, 215, 0, 0.4)',
        fontFamily: "'Poppins', sans-serif"
      }}
    >
      Master
    </span>
  );
};

export default VariantBadge;
