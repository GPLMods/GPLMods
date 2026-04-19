import React, { useState, useEffect } from 'react';
import { Box } from '@adminjs/design-system';

const ImagePreview = (props) => {
    const { record, property } = props;
    const value = record.params[property.name];

    // State to hold the final, secure URL
    const [imageUrl, setImageUrl] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // If there's no image key, stop loading immediately
        if (!value) {
            setLoading(false);
            return;
        }

        // If the admin pasted a direct web URL (e.g., imgur, google drive), use it immediately
        if (value.startsWith('http://') || value.startsWith('https://')) {
            setImageUrl(value);
            setLoading(false);
            return;
        }

        // If it's a private Backblaze B2 key, fetch a secure signed URL from our backend
        const fetchSignedUrl = async () => {
            try {
                // Call the new secure API endpoint we built in server.js
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
    }, [value]); // Re-run if the value changes

    // Loading state
    if (loading) {
        return <div style={{ color: '#FFD700', fontSize: '12px' }}>Loading...</div>;
    }

    // Empty state
    if (!imageUrl) {
        return <div style={{ color: '#888', fontSize: '12px' }}>N/A</div>;
    }

    // Success state: Render the secure image
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