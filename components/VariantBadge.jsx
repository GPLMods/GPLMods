import React from 'react';
import { Badge } from '@adminjs/design-system';

const VariantBadge = (props) => {
  const { record, property } = props;
  const isVariant = record.params[property.name];

  if (isVariant === true || isVariant === 'true') {
    return (
      <Badge variant="primary" style={{ backgroundColor: '#2196F3', color: '#fff', border: 'none' }}>
        Variant
      </Badge>
    );
  }

  // If it's false, it's a Master file
  return (
    <Badge style={{ backgroundColor: '#333', color: '#aaa', border: '1px solid #555' }}>
      Master
    </Badge>
  );
};

export default VariantBadge;