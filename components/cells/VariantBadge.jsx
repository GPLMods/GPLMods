import React from 'react';

const VariantBadge = (props) => {
  const { record, property } = props;
  if (!record || !record.params || !property) return null;
  const isVariant = record.params[property.name];
  const isVar = isVariant === true || isVariant === 'true';
  const masterId = record.params.masterFile;
  const recordId = record.params._id || record.id;

  const handleClick = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (isVar && masterId) {
      window.location.href = `/admin/resources/File/records/${masterId}/show`;
    } else {
      window.location.href = `/admin/resources/File?filters.masterFile=${recordId}`;
    }
  };

  if (isVar) {
    return (
      <a
        href={masterId ? `/admin/resources/File/records/${masterId}/show` : '#'}
        onClick={handleClick}
        title={masterId ? `Click to view Master App (${masterId})` : 'Variant Mod'}
        className="admin-custom-chip"
        data-badge-val="variant-child"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '4px 11px',
          borderRadius: '20px',
          fontSize: '11px',
          fontWeight: 700,
          letterSpacing: '0.06em',
          textTransform: 'uppercase',
          background: 'linear-gradient(145deg, rgba(186, 104, 200, 0.28) 0%, rgba(65, 25, 75, 0.35) 100%)',
          color: '#e1bee7',
          border: '1px solid rgba(186, 104, 200, 0.7)',
          boxShadow: 'inset 0 1.5px 2px rgba(255, 255, 255, 0.2), 0 0 10px rgba(186, 104, 200, 0.3)',
          textShadow: '0 0 6px rgba(206, 147, 216, 0.4)',
          fontFamily: "'Poppins', sans-serif",
          textDecoration: 'none',
          cursor: 'pointer',
          transition: 'all 0.2s ease'
        }}
        onMouseEnter={(e) => { e.currentTarget.style.transform = 'scale(1.05)'; e.currentTarget.style.borderColor = '#ce93d8'; }}
        onMouseLeave={(e) => { e.currentTarget.style.transform = 'scale(1)'; e.currentTarget.style.borderColor = 'rgba(186, 104, 200, 0.7)'; }}
      >
        <span style={{ fontSize: '10px' }}>⚡</span> Variant
      </a>
    );
  }

  return (
    <a
      href={`/admin/resources/File?filters.masterFile=${recordId}`}
      onClick={handleClick}
      title="Click to view all Variants of this Master Mod"
      className="admin-custom-chip"
      data-badge-val="variant-master"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: '4px 11px',
        borderRadius: '20px',
        fontSize: '11px',
        fontWeight: 700,
        letterSpacing: '0.06em',
        textTransform: 'uppercase',
        background: 'linear-gradient(145deg, rgba(255, 215, 0, 0.25) 0%, rgba(90, 70, 15, 0.3) 100%)',
        color: '#FFD700',
        border: '1px solid rgba(255, 215, 0, 0.75)',
        boxShadow: 'inset 0 1.5px 2px rgba(255, 255, 255, 0.22), 0 0 10px rgba(255, 215, 0, 0.3)',
        textShadow: '0 0 6px rgba(255, 215, 0, 0.4)',
        fontFamily: "'Poppins', sans-serif",
        textDecoration: 'none',
        cursor: 'pointer',
        transition: 'all 0.2s ease'
      }}
      onMouseEnter={(e) => { e.currentTarget.style.transform = 'scale(1.05)'; e.currentTarget.style.borderColor = '#fff'; }}
      onMouseLeave={(e) => { e.currentTarget.style.transform = 'scale(1)'; e.currentTarget.style.borderColor = 'rgba(255, 215, 0, 0.75)'; }}
    >
      <span style={{ fontSize: '10px' }}>👑</span> Master
    </a>
  );
};

export default VariantBadge;
