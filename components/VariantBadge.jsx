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
      window.location.href = `/admin/resources/File/actions/list?filters.masterFile=${recordId}`;
    }
  };

  if (isVar) {
    return (
      <a
        href={masterId ? `/admin/resources/File/records/${masterId}/show` : '#'}
        onClick={handleClick}
        title={masterId ? `Click to view Master App (${masterId})` : 'Variant Mod'}
        className="admin-custom-chip"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '4px 11px',
          borderRadius: '20px',
          fontSize: '11px',
          fontWeight: 700,
          background: 'linear-gradient(145deg, rgba(186, 104, 200, 0.28) 0%, rgba(65, 25, 75, 0.35) 100%)',
          color: '#e1bee7',
          border: '1px solid rgba(186, 104, 200, 0.7)',
          textDecoration: 'none',
          cursor: 'pointer'
        }}
      >
        ⚡ Variant
      </a>
    );
  }

  return (
    <a
      href={`/admin/resources/File/actions/list?filters.masterFile=${recordId}`}
      onClick={handleClick}
      title="Click to view all Variants of this Master Mod"
      className="admin-custom-chip"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: '4px 11px',
        borderRadius: '20px',
        fontSize: '11px',
        fontWeight: 700,
        background: 'linear-gradient(145deg, rgba(255, 215, 0, 0.25) 0%, rgba(90, 70, 15, 0.3) 100%)',
        color: '#FFD700',
        border: '1px solid rgba(255, 215, 0, 0.75)',
        textDecoration: 'none',
        cursor: 'pointer'
      }}
    >
      👑 Master
    </a>
  );
};

export default VariantBadge;