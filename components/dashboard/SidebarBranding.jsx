import React from 'react';
import { Box, Icon } from '@adminjs/design-system';

const SidebarBranding = () => {
  return (
    <Box 
      flex 
      flexDirection="column"
      alignItems="center" 
      justifyContent="center" 
      p="lg" 
      style={{ 
        borderBottom: '1px solid #2a2a2a', 
        backgroundColor: '#0a0a0a', 
        padding: '20px 16px',
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

      {/* Main Logo & Title Link */}
      <a 
        href="/admin" 
        style={{ 
          textDecoration: 'none', 
          display: 'flex', 
          alignItems: 'center', 
          gap: '10px',
          cursor: 'pointer',
          transition: 'opacity 0.2s ease'
        }}
        onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.85'; }}
        onMouseLeave={(e) => { e.currentTarget.style.opacity = '1'; }}
      >
        <img 
          src="/images/team-logo.png" 
          alt="Logo" 
          style={{ height: '32px', width: '32px', objectFit: 'cover', borderRadius: '6px', filter: 'drop-shadow(0 0 6px rgba(255,215,0,0.3))' }} 
          onError={(e) => e.target.style.display = 'none'}
        />
        <div style={{ fontSize: '22px', fontWeight: 'bold', fontFamily: "'Poppins', sans-serif", display: 'flex', alignItems: 'baseline', gap: '4px' }}>
          <span style={{ color: '#FFD700', textShadow: '0 0 12px rgba(255, 215, 0, 0.4)' }}>GPL</span>
          <span style={{ color: '#c0c0c0', textShadow: '0 0 12px rgba(192, 192, 192, 0.5)' }}>Mods</span>
          <span style={{ fontSize: '9px', color: '#555', fontWeight: 600, marginLeft: '6px', letterSpacing: '0.05em' }}>v2.5</span>
        </div>
      </a>

      {/* Quick Dashboard Shortcut Button */}
      <a 
        href="/admin" 
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '8px',
          marginTop: '12px',
          padding: '6px 16px',
          width: '85%',
          borderRadius: '8px',
          backgroundColor: 'rgba(255, 215, 0, 0.08)',
          border: '1px solid rgba(255, 215, 0, 0.25)',
          color: '#FFD700',
          textDecoration: 'none',
          fontSize: '12px',
          fontWeight: 700,
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          transition: 'all 0.2s ease',
          cursor: 'pointer'
        }}
        onMouseEnter={(e) => { 
          e.currentTarget.style.backgroundColor = 'rgba(255, 215, 0, 0.2)'; 
          e.currentTarget.style.boxShadow = '0 0 14px rgba(255,215,0,0.3)'; 
        }}
        onMouseLeave={(e) => { 
          e.currentTarget.style.backgroundColor = 'rgba(255, 215, 0, 0.08)'; 
          e.currentTarget.style.boxShadow = 'none'; 
        }}
      >
        <Icon icon="Home" size={13} color="#FFD700" />
        <span>Dashboard</span>
      </a>
    </Box>
  );
};

export default SidebarBranding;
