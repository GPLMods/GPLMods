import React from 'react';
import { Box, H2, Text, H5 } from '@adminjs/design-system';

const Dashboard = () => {
  return (
    <Box style={{ padding: '60px 20px', textAlign: 'center', minHeight: '100vh', backgroundColor: '#0a0a0a' }}>
        
        <img 
            src="/images/logo.png" 
            alt="GPL Mods Logo" 
            style={{ maxWidth: '250px', marginBottom: '30px' }} 
            onError={(e) => e.target.style.display = 'none'} 
        />
        
        <H2 style={{ color: '#FFD700', marginBottom: '15px', textShadow: '0 0 15px rgba(255, 215, 0, 0.4)', fontWeight: 'bold' }}>
            Welcome to the Command Center
        </H2>
        
        <Text style={{ maxWidth: '600px', margin: '0 auto 40px auto', color: '#c0c0c0', fontSize: '1.1em', lineHeight: '1.6' }}>
            You are now logged into the GPL Mods administration panel. Use the sidebar on the left to manage your community, review user uploads, and configure site settings.
        </Text>

        {/* Dashboard Cards Container */}
        <Box flex justifyContent="center" flexWrap="wrap" style={{ gap: '25px', marginTop: '20px' }}>
            
            {/* Card 1: Mods */}
            <Box p="lg" style={{ width: '260px', backgroundColor: '#1a1a1a', borderRadius: '15px', border: '1px solid #333', boxShadow: '0 5px 15px rgba(0,0,0,0.5)' }}>
                <H5 style={{ color: '#FFD700', marginBottom: '10px' }}>Manage Mods</H5>
                <Text variant="sm" style={{ color: '#c0c0c0', lineHeight: '1.5' }}>Review, approve, or reject new files uploaded by the community.</Text>
            </Box>

            {/* Card 2: Moderation */}
            <Box p="lg" style={{ width: '260px', backgroundColor: '#1a1a1a', borderRadius: '15px', border: '1px solid #333', boxShadow: '0 5px 15px rgba(0,0,0,0.5)' }}>
                <H5 style={{ color: '#FFD700', marginBottom: '10px' }}>Moderate</H5>
                <Text variant="sm" style={{ color: '#c0c0c0', lineHeight: '1.5' }}>Check user reports, moderate reviews, and process DMCA claims.</Text>
            </Box>

            {/* Card 3: Users */}
            <Box p="lg" style={{ width: '260px', backgroundColor: '#1a1a1a', borderRadius: '15px', border: '1px solid #333', boxShadow: '0 5px 15px rgba(0,0,0,0.5)' }}>
                <H5 style={{ color: '#FFD700', marginBottom: '10px' }}>Users & Community</H5>
                <Text variant="sm" style={{ color: '#c0c0c0', lineHeight: '1.5' }}>Manage accounts, assign admin roles, and post site announcements.</Text>
            </Box>

        </Box>
    </Box>
  );
};

export default Dashboard;