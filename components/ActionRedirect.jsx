import React, { useEffect } from 'react';
import { Box, Text, Loader, Button, Icon } from '@adminjs/design-system';
import { useNotice } from 'adminjs';

const ActionRedirect = (props) => {
    const { record, action } = props;
    const sendNotice = useNotice();
    let url = record?.params?.redirectUrl;

    if (!url && record && record.params) {
        const actionName = action?.name;
        const recId = record.params._id || record.id;
        const isVar = record.params.isVariant === true || record.params.isVariant === 'true';
        const masterId = record.params.masterFile;

        if (actionName === 'viewVariants' || (!actionName && (isVar || masterId))) {
            if (isVar && masterId) {
                url = `/admin/resources/File/records/${masterId}/show`;
            } else if (recId) {
                url = `/admin/resources/File?filters.masterFile=${recId}`;
            }
        } else if (actionName === 'viewOnSite' && recId) {
            url = `/mods/${recId}`;
        } else if (actionName === 'viewVirusTotal') {
            const vtHash = record.params.virusTotalId || '';
            const vtAnalysis = record.params.virusTotalAnalysisId || '';
            if (vtHash.length === 64) url = `https://www.virustotal.com/gui/file/${vtHash}`;
            else if (vtAnalysis) url = `https://www.virustotal.com/gui/file-analysis/${vtAnalysis}`;
            else if (vtHash) url = `https://www.virustotal.com/gui/file-analysis/${vtHash}`;
            else url = `https://www.virustotal.com/`;
        }
    }

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