import React, { useEffect } from 'react';
import { Box, Text, Loader } from '@adminjs/design-system';
import { useNotice } from 'adminjs';

const ActionRedirect = (props) => {
    const { record, action } = props;
    const sendNotice = useNotice();

    useEffect(() => {
        const url = record?.params?.redirectUrl;
        
        if (url) {
            setTimeout(() => {
                window.open(url, '_blank');
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
