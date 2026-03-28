import React from 'react';
import { Box, Link } from '@adminjs/design-system';

const SidebarBranding = () => {
  return (
    <Box 
      flex 
      alignItems="center" 
      justifyContent="center" 
      p="lg" 
      style={{ borderBottom: '1px solid #333', backgroundColor: '#0a0a0a', padding: '20px 0' }}
    >
      <Link to="/admin" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '10px' }}>
        
        {/* Optional Logo Icon */}
        <img 
          src="/images/logo.png" 
          alt="Logo" 
          style={{ height: '35px', width: 'auto' }} 
          onError={(e) => e.target.style.display = 'none'}
        />
        
        {/* The Custom Colored Text */}
        <div style={{ fontSize: '24px', fontWeight: 'bold', fontFamily: 'Poppins, sans-serif' }}>
            <span style={{ color: '#FFD700', textShadow: '0 0 10px rgba(255, 215, 0, 0.4)' }}>GPL</span>
            <span style={{ color: '#c0c0c0', marginLeft: '5px' }}>Mods</span>
        </div>

      </Link>
    </Box>
  );
};

export default SidebarBranding;