import React from 'react';
import { Box, H2, Text, H5, Illustration } from '@adminjs/design-system';

const Dashboard = () => {
  return (
    <Box variant="grey" style={{ padding: '60px 20px', textAlign: 'center', minHeight: '100vh' }}>
        
        <img 
            src="/images/logo.png" 
            alt="GPL Mods Logo" 
            style={{ maxWidth: '250px', marginBottom: '30px' }} 
            onError={(e) => e.target.style.display = 'none'} 
        />
        
        <H2 style={{ marginBottom: '15px' }}>Welcome to the Command Center</H2>
        
        <Text style={{ maxWidth: '600px', margin: '0 auto 40px auto' }}>
            You are now logged into the GPL Mods administration panel. Use the sidebar on the left to manage your community, review user uploads, and configure site settings.
        </Text>

        <Box flex justifyContent="center" style={{ gap: '20px' }}>
            <Box variant="white" p="lg" style={{ width: '200px', borderRadius: '10px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}>
                <H5>Manage Mods</H5>
                <Text variant="sm">Review and approve new files.</Text>
            </Box>
            <Box variant="white" p="lg" style={{ width: '200px', borderRadius: '10px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}>
                <H5>Moderate</H5>
                <Text variant="sm">Check reports and DMCA claims.</Text>
            </Box>
        </Box>
    </Box>
  );
};

export default Dashboard;