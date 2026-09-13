import React from 'react';
import { Box, Link } from '@adminjs/design-system';

const SidebarBranding = () => {
  return (
    <Box 
      flex 
      alignItems="center" 
      justifyContent="center" 
      p="lg" 
      style={{ 
        borderBottom: '1px solid #2a2a2a', 
        backgroundColor: '#0a0a0a', 
        padding: '22px 0',
        position: 'relative',
        overflow: 'hidden'
      }}
    >
      {/* Subtle gold glow underline */}
      <div style={{
        position: 'absolute',
        bottom: 0,
        left: '50%',
        transform: 'translateX(-50%)',
        width: '60%',
        height: '1px',
        background: 'linear-gradient(90deg, transparent, rgba(255,215,0,0.5), transparent)'
      }} />

      <Link to="/admin" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '10px' }}>
        <img 
          src="/images/logo.png" 
          alt="Logo" 
          style={{ height: '32px', width: 'auto', filter: 'drop-shadow(0 0 6px rgba(255,215,0,0.3))' }} 
          onError={(e) => e.target.style.display = 'none'}
        />
        <div style={{ fontSize: '22px', fontWeight: 'bold', fontFamily: 'Inter, system-ui, sans-serif', display: 'flex', alignItems: 'baseline', gap: '4px' }}>
          <span style={{ color: '#FFD700', textShadow: '0 0 12px rgba(255, 215, 0, 0.4)' }}>GPL</span>
          <span style={{ color: '#c0c0c0' }}>Mods</span>
          <span style={{ fontSize: '9px', color: '#555', fontWeight: 600, marginLeft: '6px', letterSpacing: '0.05em' }}>v2.5</span>
        </div>
      </Link>
    </Box>
  );
};

export default SidebarBranding;
