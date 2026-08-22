import React, { useState, useEffect } from 'react';
import { Box } from '@adminjs/design-system';

const ImagePreview = (props) => {
    const { record, property, where } = props; 
    const value = record.params[property.name];

    const [imageUrl, setImageUrl] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        if (!value) {
            setLoading(false);
            return;
        }

        if (value.startsWith('http://') || value.startsWith('https://')) {
            setImageUrl(value);
            setLoading(false);
            return;
        }

        const fetchSignedUrl = async () => {
            try {
                const response = await fetch(`/api/admin/signed-url?key=${encodeURIComponent(value)}`);
                if (response.ok) {
                    const data = await response.json();
                    setImageUrl(data.url);
                } else {
                    console.error("Failed to fetch signed URL.");
                }
            } catch (error) {
                console.error("Network error fetching signed URL:", error);
            } finally {
                setLoading(false);
            }
        };

        fetchSignedUrl();
    }, [value]);

    if (loading) return <Box style={{ color: '#FFD700', fontSize: '12px' }}>Loading...</Box>;
    if (!imageUrl) return <Box style={{ color: '#888', fontSize: '12px' }}>N/A</Box>;

    const size = where === 'list' ? '40px' : '150px';
    const radius = property.name === 'profileImageKey' ? '50%' : '8px';

    return (
        <Box>
            <img 
                src={imageUrl} 
                alt="Preview" 
                style={{ 
                    width: size, 
                    height: size, 
                    borderRadius: radius,
                    objectFit: 'cover',
                    backgroundColor: '#1a1a1a',
                    border: '1px solid #333'
                }} 
            />
        </Box>
    );
};

export default ImagePreview;
