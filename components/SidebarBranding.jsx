import React from 'react';
import { Box, Link } from '@adminjs/design-system';

const SidebarBranding = () => {
  return (
    // Box is a layout component from AdminJS design system
    <Box 
      flex 
      alignItems="center" 
      justifyContent="center" 
      p="lg" 
      style={{ borderBottom: '1px solid #333', backgroundColor: '#0a0a0a' }}
    >
      {/* Link back to the admin dashboard */}
      <Link to="/admin" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '15px' }}>
        
        {/* Your Site Logo */}
        <img 
          src="/images/logo.png" 
          alt="GPL Mods" 
          style={{ height: '40px', width: 'auto' }} 
          onError={(e) => e.target.style.display = 'none'}
        />
        
        {/* Glowing Gold Text */}
        <span style={{ 
          color: '#FFD700', 
          fontSize: '22px', 
          fontWeight: 'bold', 
          textShadow: '0 0 15px rgba(255, 215, 0, 0.5)',
          letterSpacing: '1px'
        }}>
          GPL Mods
        </span>

      </Link>
    </Box>
  );
};

export default SidebarBranding;