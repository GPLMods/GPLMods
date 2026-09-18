import React, { useState, useEffect } from 'react';
import { Box } from '@adminjs/design-system';

const AvatarCell = (props) => {
    const { record, property, where } = props; 
    if (!record || !record.params || !property) return null;
    const key = record.params[property.name];
    const username = record.params.username || 'User';

    const [imageUrl, setImageUrl] = useState(null);
    const [loading, setLoading] = useState(true);
    const [hasError, setHasError] = useState(false);

    useEffect(() => {
        if (!key) {
            setLoading(false);
            return;
        }

        if (key.startsWith('http://') || key.startsWith('https://')) {
            setImageUrl(key);
            setLoading(false);
            return;
        }

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

    const size = where === 'list' ? '32px' : '120px';

    if (loading) {
        return <Box style={{ width: size, height: size, borderRadius: '50%', backgroundColor: '#333' }} />;
    }

    const defaultAvatar = '/images/default-avatar.png';

    return (
        <Box>
            <img 
                src={(!imageUrl || hasError) ? defaultAvatar : imageUrl} 
                alt={username}
                style={{ 
                    width: size, 
                    height: size, 
                    borderRadius: '50%', 
                    objectFit: 'cover',
                    border: '2px solid #FFD700',
                    backgroundColor: '#1a1a1a'
                }} 
                onError={(e) => {
                    if (e.currentTarget.src !== defaultAvatar) {
                        e.currentTarget.src = defaultAvatar;
                    }
                }}
            />
        </Box>
    );
};

export default AvatarCell;
