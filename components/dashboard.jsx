import React from 'react';

const Dashboard = () => {
  return (
    <div style={{ 
        padding: '60px 20px', 
        textAlign: 'center', 
        backgroundColor: '#0a0a0a', 
        minHeight: '100vh', 
        color: '#ffffff', 
        fontFamily: "'Poppins', sans-serif" 
    }}>
        {/* Make sure you have a logo image at public/images/logo.png! */}
        {/* If you don't have one yet, it will just show the broken image icon, or you can delete this img tag */}
        <img 
            src="/images/logo.png" 
            alt="GPL Mods Logo" 
            style={{ maxWidth: '250px', marginBottom: '30px' }} 
            onError={(e) => e.target.style.display = 'none'} // Hides image if it doesn't exist
        />
        
        <h1 style={{ color: '#FFD700', fontSize: '3rem', marginBottom: '15px', textShadow: '0 0 15px rgba(255, 215, 0, 0.5)' }}>
            Welcome to the Command Center
        </h1>
        
        <p style={{ color: '#c0c0c0', fontSize: '1.2rem', maxWidth: '600px', margin: '0 auto 40px auto' }}>
            You are now logged into the GPL Mods administration panel. Use the sidebar on the left to manage your community, review user uploads, and configure site settings.
        </p>

        <div style={{ display: 'flex', justifyContent: 'center', gap: '20px' }}>
            <div style={{ padding: '20px', backgroundColor: '#1a1a1a', border: '1px solid #333', borderRadius: '10px', width: '200px' }}>
                <h3 style={{ color: '#FFD700', margin: '0 0 10px 0' }}>Manage Mods</h3>
                <p style={{ color: '#999', fontSize: '0.9rem', margin: 0 }}>Review and approve new files.</p>
            </div>
            <div style={{ padding: '20px', backgroundColor: '#1a1a1a', border: '1px solid #333', borderRadius: '10px', width: '200px' }}>
                <h3 style={{ color: '#FFD700', margin: '0 0 10px 0' }}>Moderate</h3>
                <p style={{ color: '#999', fontSize: '0.9rem', margin: 0 }}>Check reports and DMCA claims.</p>
            </div>
        </div>
    </div>
  );
};

export default Dashboard;