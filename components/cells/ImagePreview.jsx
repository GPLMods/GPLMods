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

    const isAvatar = property.name === 'profileImageKey' || property.name === 'cardAvatarUrl' || property.name === 'avatar';
    const defaultImage = isAvatar ? '/images/default-avatar.png' : '/images/default-app-icon.png';
    const displayUrl = imageUrl || defaultImage;

    const size = where === 'list' ? '40px' : '150px';
    const radius = isAvatar ? '50%' : '8px';

    return (
        <Box>
            <img 
                src={displayUrl} 
                alt="Preview" 
                style={{ 
                    width: size, 
                    height: size, 
                    borderRadius: radius,
                    objectFit: 'cover',
                    backgroundColor: '#1a1a1a',
                    border: '1px solid #333'
                }} 
                onError={(e) => {
                    if (e.currentTarget.src !== defaultImage) {
                        e.currentTarget.src = defaultImage;
                    }
                }}
            />
        </Box>
    );
};

export default ImagePreview;
