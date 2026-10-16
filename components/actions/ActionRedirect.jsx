import React, { useEffect } from 'react';
import { Box, Text, Loader, Button, Icon } from '@adminjs/design-system';
import { useNotice } from 'adminjs';

const ActionRedirect = (props) => {
    const { record } = props;
    const sendNotice = useNotice();
    const url = record?.params?.redirectUrl;

    useEffect(() => {
        if (!url) {
            sendNotice({ message: 'Error: No redirect URL provided.', type: 'error' });
            return;
        }

        // Internal admin navigation: Redirect in the SAME tab so user is not stuck on spinner
        if (url.startsWith('/admin')) {
            window.location.href = url;
        } else {
            // External or frontend route: open in new tab, and restore previous history in admin tab
            window.open(url, '_blank');
            setTimeout(() => {
                if (window.history.length > 1) {
                    window.history.back();
                } else if (record?.params?._id) {
                    window.location.href = `/admin/resources/File/records/${record.params._id}/show`;
                }
            }, 600);
        }
    }, [record, url]);

    return (
        <Box flex flexDirection="column" alignItems="center" justifyContent="center" p="xxl">
            <Loader />
            <Text mt="lg" variant="h4">Redirecting...</Text>
            {url && (
                <Box mt="md">
                    <Button
                        size="sm"
                        variant="primary"
                        onClick={() => { window.location.href = url; }}
                        style={{ cursor: 'pointer' }}
                    >
                        <Icon icon="ExternalLink" style={{ marginRight: '6px' }} />
                        Click here if not redirected automatically
                    </Button>
                </Box>
            )}
        </Box>
    );
};

export default ActionRedirect;
