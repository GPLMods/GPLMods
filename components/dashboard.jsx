import React from 'react';
import { Box, H2, Text, H5 } from '@adminjs/design-system';

const Dashboard = () => {
  return (
    // 'variant="grey"' automatically grabs the dark background from the theme
    <Box variant="grey" style={{ padding: '60px 20px', textAlign: 'center', minHeight: '100vh' }}>
        
        <img 
            src="/images/logo.png" 
            alt="GPL Mods Logo" 
            style={{ maxWidth: '250px', marginBottom: '30px' }} 
            onError={(e) => e.target.style.display = 'none'} 
        />
        
        {/* We use the theme's primary color (Gold) for the heading */}
        <H2 style={{ color: '#FFD700', marginBottom: '15px', textShadow: '0 0 15px rgba(255, 215, 0, 0.3)' }}>
            Welcome to the Command Center
        </H2>
        
        <Text style={{ maxWidth: '600px', margin: '0 auto 40px auto', color: '#c0c0c0' }}>
            You are now logged into the GPL Mods administration panel. Use the sidebar on the left to manage your community, review user uploads, and configure site settings.
        </Text>

        <Box flex justifyContent="center" style={{ gap: '20px' }}>
            {/* 'variant="white"' tells AdminJS to use the 'container' color (#1a1a1a) in dark mode */}
            <Box variant="white" p="lg" style={{ width: '200px', borderRadius: '10px', border: '1px solid #333' }}>
                <H5 style={{ color: '#FFD700' }}>Manage Mods</H5>
                <Text variant="sm" style={{ color: '#999' }}>Review and approve new files.</Text>
            </Box>
            <Box variant="white" p="lg" style={{ width: '200px', borderRadius: '10px', border: '1px solid #333' }}>
                <H5 style={{ color: '#FFD700' }}>Moderate</H5>
                <Text variant="sm" style={{ color: '#999' }}>Check reports and DMCA claims.</Text>
            </Box>
        </Box>
    </Box>
  );
};

export default Dashboard;