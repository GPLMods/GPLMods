import React from 'react';
import { Box } from '@adminjs/design-system';

const ImagePreview = (props) => {
    const { record, property } = props;
    const value = record.params[property.name];

    if (!value) {
        return <div style={{ color: '#888', fontSize: '12px' }}>N/A</div>;
    }

    // Helper to safely build the URL
    const getSmartUrl = (key) => {
        if (key.startsWith('http')) return key;
        // Use the exact B2 URL structure you provided
        return `https://f003.backblazeb2.com/file/gpl-cloud/${key}`;
    };

    const imageUrl = getSmartUrl(value);

    return (
        <Box>
            <img 
                src={imageUrl} 
                alt="Preview" 
                style={{ 
                    maxWidth: '50px', 
                    maxHeight: '50px', 
                    borderRadius: '8px',
                    objectFit: 'contain', // Changed to contain so icons aren't cropped
                    backgroundColor: '#1a1a1a',
                    border: '1px solid #333'
                }} 
            />
        </Box>
    );
};

export default ImagePreview;