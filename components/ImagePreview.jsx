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
        
        // If it's a B2 key, we need a public URL. 
        // Since AdminJS components run in the browser, they don't have access to your server's s3Client.
        // For a fully secure private bucket, you would need an API route like /api/admin/signed-url?key=...
        // However, if your bucket is public (or has a public CDN in front of it like Cloudflare), 
        // you can just construct the URL here:
        
        // REPLACEME: If your bucket is public, put the base URL here.
        // Example: return `https://f003.backblazeb2.com/file/your-bucket-name/${key}`;
        
        // If your bucket is strictly private and you MUST use signed URLs, 
        // this component becomes an async fetch component (more complex). 
        // For now, let's assume you have a public endpoint or we just show the key.
        
        // For demonstration, we will try to construct a standard B2 URL.
        // You MUST update 'your-bucket-name' and 'f00X' to match your actual B2 info.
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
                    objectFit: 'cover',
                    backgroundColor: '#1a1a1a',
                    border: '1px solid #333'
                }} 
            />
        </Box>
    );
};

export default ImagePreview;