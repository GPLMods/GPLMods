import React, { useState, useEffect } from 'react';
import { ApiClient } from 'adminjs';

const api = new ApiClient();

const section = {
  maxWidth: '1120px',
  margin: '0 auto',
  padding: '28px',
  color: '#f5f5f5',
  fontFamily: 'Inter, system-ui, sans-serif',
};
const header = {
  display: 'flex',
  flexWrap: 'wrap',
  justifyContent: 'space-between',
  gap: '14px',
  alignItems: 'flex-end',
  paddingBottom: '20px',
  borderBottom: '1px solid #333',
};
const title = { margin: 0, fontSize: '2rem', color: '#fff' };
const subtitle = { margin: '8px 0 0', color: '#aaa', maxWidth: '720px' };
const linkButton = {
  display: 'inline-block',
  color: '#ffd700',
  border: '1px solid #ffd700',
  borderRadius: '10px',
  padding: '10px 16px',
  textDecoration: 'none',
  fontWeight: 700,
};
const grid = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
  gap: '18px',
  marginTop: '30px',
};
const card = {
  background: '#121212',
  border: '1px solid #2d2d2d',
  borderRadius: '16px',
  padding: '22px',
  minHeight: '140px',
};
const label = { fontSize: '0.8rem', color: '#9d9d9d', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '14px' };
const value = { fontSize: '2.4rem', color: '#fff', margin: 0 };
const note = { fontSize: '0.95rem', color: '#b0b0b0', marginTop: '12px' };
const empty = { display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '140px', color: '#777' };

const Dashboard = () => {
  const [data, setData] = useState({ stats: {}, modsByPlatform: [], uploadChartData: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.getDashboard()
      .then((response) => {
        setData(response.data || { stats: {}, modsByPlatform: [], uploadChartData: [] });
        setLoading(false);
      })
      .catch((fetchError) => {
        console.error('Dashboard fetch error:', fetchError);
        setError('Failed to load telemetry data.');
        setLoading(false);
      });
  }, []);

  const stats = data.stats || {};

  if (loading) {
    return (
      <div style={{ ...section, minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <p style={{ color: '#ccc' }}>Loading real-time telemetry…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ ...section, minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <p style={{ color: '#f06464' }}>{error}</p>
      </div>
    );
  }

  return (
    <div style={section}>
      <div style={header}>
        <div>
          <h1 style={title}>GPL Mods Admin Dashboard</h1>
          <p style={subtitle}>A clean, compatible admin overview with core platform metrics.</p>
        </div>
        <a href="/home" target="_blank" rel="noopener noreferrer" style={linkButton}>
          View live site
        </a>
      </div>

      {/* --- STATS GRID --- */}
      <div style={grid}>
        <div style={card}>
          <div style={label}>Total Users</div>
          <p style={value}>{(stats.totalUsers || 0).toLocaleString()}</p>
          <div style={note}>{(stats.newUsersThisMonth || 0).toLocaleString()} new users this month</div>
        </div>
        
        <div style={card}>
          <div style={label}>Total Mods</div>
          <p style={value}>{(stats.totalMods || 0).toLocaleString()}</p>
          <div style={note}>{(stats.newModsThisMonth || 0).toLocaleString()} new mods this month</div>
        </div>
        
        <div style={card}>
          <div style={label}>Total Downloads</div>
          <p style={value}>{(stats.totalDownloads || 0).toLocaleString()}</p>
          <div style={note}>Lifetime downloads across the platform</div>
        </div>

        {/* ✅ NEW: TOTAL VIEWS CARD ADDED HERE */}
        <div style={card}>
          <div style={label}>Total Views</div>
          <p style={value}>{(stats.totalViews || 0).toLocaleString()}</p>
          <div style={note}>All-time global views across the platform</div>
        </div>
      </div>

      <div style={{ ...grid, marginTop: '24px' }}>
        <div style={card}>
          <div style={label}>Upload Activity</div>
          {Array.isArray(data.uploadChartData) && data.uploadChartData.length > 0 ? (
            <div style={{ color: '#ccc' }}>
              <p style={{ margin: 0 }}>Showing recent activity for the last 7 days.</p>
              <pre style={{ color: '#ddd', marginTop: '14px', whiteSpace: 'pre-wrap' }}>
                {JSON.stringify(data.uploadChartData, null, 2)}
              </pre>
            </div>
          ) : (
            <div style={empty}>No upload activity this week.</div>
          )}
        </div>

        <div style={card}>
          <div style={label}>Mods by Platform</div>
          {Array.isArray(data.modsByPlatform) && data.modsByPlatform.length > 0 ? (
            <div style={{ color: '#ccc' }}>
              <p style={{ margin: 0 }}>Platform distribution data is available.</p>
              <pre style={{ color: '#ddd', marginTop: '14px', whiteSpace: 'pre-wrap' }}>
                {JSON.stringify(data.modsByPlatform, null, 2)}
              </pre>
            </div>
          ) : (
            <div style={empty}>No platform distribution data available.</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;