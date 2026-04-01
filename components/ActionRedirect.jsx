import React, { useEffect } from 'react';
import { Box, Text, Loader } from '@adminjs/design-system';
import { useNotice } from 'adminjs';

const ActionRedirect = (props) => {
    const { record, action } = props;
    const sendNotice = useNotice();

    useEffect(() => {
        // We defined redirectUrl in our handler in admin.js
        const url = record?.params?.redirectUrl;
        
        if (url) {
            // Give a tiny delay so the user sees the notice
            setTimeout(() => {
                window.open(url, '_blank'); // Open in a new tab is usually best for these actions
                // Or use window.location.href = url; to stay in the same tab
            }, 500);
        } else {
            sendNotice({ message: 'Error: No redirect URL provided.', type: 'error' });
        }
    }, [record]);

    return (
        <Box flex flexDirection="column" alignItems="center" justifyContent="center" p="xxl">
            <Loader />
            <Text mt="lg" variant="h4">Redirecting...</Text>
        </Box>
    );
};

export default ActionRedirect;