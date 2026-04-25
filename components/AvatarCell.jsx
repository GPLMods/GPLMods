import React, { useState, useEffect } from 'react';
import { Box } from '@adminjs/design-system';

const AvatarCell = (props) => {
    const { record, property, where } = props; 
    const key = record.params[property.name]; // This is the profileImageKey
    const username = record.params.username || 'User';

    const[imageUrl, setImageUrl] = useState(null);
    const [loading, setLoading] = useState(true);
    const[hasError, setHasError] = useState(false);

    useEffect(() => {
        if (!key) {
            setLoading(false);
            return;
        }

        // If it's a standard web URL, use it directly
        if (key.startsWith('http://') || key.startsWith('https://')) {
            setImageUrl(key);
            setLoading(false);
            return;
        }

        // Otherwise, fetch the signed URL securely
        const fetchSignedUrl = async () => {
            try {
                const response = await fetch(`/api/admin/signed-url?key=${encodeURIComponent(key)}`);
                if (response.ok) {
                    const data = await response.json();
                    setImageUrl(data.url);
                } else {
                    setHasError(true);
                }
            } catch (error) {
                console.error("Error fetching avatar URL:", error);
                setHasError(true);
            } finally {
                setLoading(false);
            }
        };

        fetchSignedUrl();
    }, [key]);

    // Set size based on whether we are looking at the table list or the detail view
    const size = where === 'list' ? '32px' : '120px';

    // 1. Loading State
    if (loading) {
        return <Box style={{ width: size, height: size, borderRadius: '50%', backgroundColor: '#333' }} />;
    }

    // 2. Fallback State (No image, or image failed to load)
    if (!imageUrl || hasError) {
        return (
            <Box style={{ 
                width: size, 
                height: size, 
                borderRadius: '50%', 
                backgroundColor: '#FFD700', // GPL Gold
                color: '#0a0a0a',          // GPL Black
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center',
                fontWeight: 'bold',
                fontSize: where === 'list' ? '14px' : '48px',
                border: '2px solid #333'
            }}>
                {username.charAt(0).toUpperCase()}
            </Box>
        );
    }

    // 3. Success State (Image loaded)
    return (
        <Box>
            <img 
                src={imageUrl} 
                alt={username}
                style={{ 
                    width: size, 
                    height: size, 
                    borderRadius: '50%', 
                    objectFit: 'cover',
                    border: '2px solid #FFD700'
                }} 
                onError={() => setHasError(true)} // Instantly switch to initials if the image breaks!
            />
        </Box>
    );
};

export default AvatarCell;