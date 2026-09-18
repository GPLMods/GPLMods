import React, { useState, useEffect } from 'react';
import { ApiClient } from 'adminjs';
import { Box, H2, H5, Text, Icon, Badge } from '@adminjs/design-system';

const api = new ApiClient();

/* ─── colour tokens ─── */
const C = {
  bg: '#0a0a0a', surface: '#131313', surfaceAlt: '#1a1a1a',
  border: '#2a2a2a', borderHover: '#3a3a3a',
  gold: '#FFD700', goldDim: 'rgba(255,215,0,0.15)', goldGlow: 'rgba(255,215,0,0.35)',
  blue: '#2196F3', green: '#43a047', purple: '#9C27B0', red: '#e53935', orange: '#FF9800',
  text: '#ffffff', textMuted: '#e2e8f0', textDim: '#cbd5e1',
};

/* ─── platform chart colours ─── */
const PLATFORM_COLORS = ['#A4C639', '#0078D6', '#21759B', '#FF9800', '#9C27B0', '#e53935', '#43a047', '#FFD700'];

/* ─── reusable card style ─── */
const cardStyle = (accentColor) => ({
  backgroundColor: C.surface,
  borderRadius: '16px',
  border: `1px solid ${C.border}`,
  borderLeft: accentColor ? `4px solid ${accentColor}` : `1px solid ${C.border}`,
  padding: 'clamp(16px, 2.5vw, 24px)',
  transition: 'all 0.25s ease',
  cursor: 'default',
  boxSizing: 'border-box',
});

/* ─── Inline SVG Area Chart ─── */
const AreaChart = ({ data, width = 500, height = 170, color = C.gold }) => {
  if (!data || data.length === 0) return null;
  const maxVal = Math.max(...data.map(d => d.value), 1);
  const padX = 35;
  const padY = 16;
  const chartW = width - padX * 2;
  const chartH = height - padY * 2;

  const points = data.map((d, i) => ({
    x: padX + (i / Math.max(data.length - 1, 1)) * chartW,
    y: padY + chartH - (d.value / maxVal) * chartH,
  }));

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x},${p.y}`).join(' ');
  const areaPath = `${linePath} L${points[points.length - 1].x},${padY + chartH} L${points[0].x},${padY + chartH} Z`;

  // Grid lines
  const gridLines = [0, 0.25, 0.5, 0.75, 1].map(pct => {
    const y = padY + chartH - pct * chartH;
    const label = Math.round(pct * maxVal);
    return { y, label };
  });

  const step = data.length > 8 ? Math.ceil(data.length / 5) : 1;

  return (
    <div style={{ width: '100%', overflow: 'hidden' }}>
      <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{ display: 'block', maxWidth: '100%' }}>
        <defs>
          <linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.35" />
            <stop offset="100%" stopColor={color} stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {/* Grid */}
        {gridLines.map((g, i) => (
          <g key={i}>
            <line x1={padX} y1={g.y} x2={width - padX} y2={g.y} stroke={C.border} strokeWidth="1" strokeDasharray="3 3" />
            <text x={padX - 6} y={g.y + 4} fill="#94a3b8" fontSize="9" fontFamily="'Poppins', sans-serif" textAnchor="end">{g.label}</text>
          </g>
        ))}
        {/* Area fill */}
        <path d={areaPath} fill="url(#areaFill)" />
        {/* Line */}
        <path d={linePath} fill="none" stroke={color} strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />
        {/* Dots + labels */}
        {points.map((p, i) => {
          const showLabel = (i === 0 || i === data.length - 1 || i % step === 0);
          return (
            <g key={i}>
              <circle cx={p.x} cy={p.y} r="3" fill={C.bg} stroke={color} strokeWidth="2" />
              {showLabel && (
                <text x={p.x} y={padY + chartH + 14} fill="#cbd5e1" fontSize="9" fontFamily="'Poppins', sans-serif" textAnchor="middle">{data[i].label}</text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
};

/* ─── Inline SVG Donut Chart ─── */
const DonutChart = ({ data, size = 200 }) => {
  if (!data || data.length === 0) return null;
  const total = data.reduce((s, d) => s + d.value, 0);
  if (total === 0) return null;
  const cx = size / 2;
  const cy = size / 2;
  const outerR = size / 2 - 10;
  const innerR = outerR * 0.6;
  let cumAngle = -Math.PI / 2;

  const slices = data.map((d, i) => {
    const angle = (d.value / total) * Math.PI * 2;
    const startAngle = cumAngle;
    cumAngle += angle;
    const endAngle = cumAngle;

    const x1 = cx + outerR * Math.cos(startAngle);
    const y1 = cy + outerR * Math.sin(startAngle);
    const x2 = cx + outerR * Math.cos(endAngle);
    const y2 = cy + outerR * Math.sin(endAngle);
    const ix1 = cx + innerR * Math.cos(endAngle);
    const iy1 = cy + innerR * Math.sin(endAngle);
    const ix2 = cx + innerR * Math.cos(startAngle);
    const iy2 = cy + innerR * Math.sin(startAngle);
    const largeArc = angle > Math.PI ? 1 : 0;
    const color = PLATFORM_COLORS[i % PLATFORM_COLORS.length];

    const path = `M${x1},${y1} A${outerR},${outerR} 0 ${largeArc} 1 ${x2},${y2} L${ix1},${iy1} A${innerR},${innerR} 0 ${largeArc} 0 ${ix2},${iy2} Z`;
    return { path, color, name: d.name, value: d.value, pct: Math.round((d.value / total) * 100) };
  });

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '24px', flexWrap: 'wrap', justifyContent: 'center' }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {slices.map((s, i) => (
          <path key={i} d={s.path} fill={s.color} stroke={C.bg} strokeWidth="2">
            <title>{s.name}: {s.value} ({s.pct}%)</title>
          </path>
        ))}
        <text x={cx} y={cy - 6} fill={C.text} fontSize="22" fontWeight="bold" textAnchor="middle">{total}</text>
        <text x={cx} y={cy + 14} fill={C.textMuted} fontSize="10" textAnchor="middle">TOTAL</text>
      </svg>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {slices.map((s, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
            <span style={{ width: 12, height: 12, borderRadius: '3px', backgroundColor: s.color, display: 'inline-block', flexShrink: 0 }} />
            <span style={{ color: C.text }}>{s.name}</span>
            <span style={{ color: C.textDim, marginLeft: 'auto' }}>{s.value} ({s.pct}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
};

/* ─── Stat Card ─── */
const StatCard = ({ icon, label, value, delta, deltaLabel, accentColor }) => (
  <Box style={{ ...cardStyle(accentColor), flex: '1', minWidth: '220px' }}
    onMouseEnter={e => { e.currentTarget.style.borderColor = accentColor || C.borderHover; e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = `0 8px 24px rgba(0,0,0,0.4)`; }}
    onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.borderLeftColor = accentColor; e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
      <Icon icon={icon} color={accentColor} />
      <Text style={{ color: C.textMuted, fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</Text>
    </div>
    <H2 style={{ color: C.text, margin: '0 0 8px 0', fontSize: '2.2rem' }}>{value}</H2>
    {delta !== undefined && (
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
        <Icon icon="ArrowUp" size={14} color={C.green} />
        <Text style={{ color: C.green, fontSize: '13px', fontWeight: 600 }}>+{delta} {deltaLabel || 'this month'}</Text>
      </div>
    )}
  </Box>
);

/* ─── Action Badge Card ─── */
const ActionCard = ({ icon, label, count, accentColor, resourceId }) => (
  <a href={`/admin/resources/${resourceId}`} style={{ textDecoration: 'none', flex: '1', minWidth: '180px' }}>
    <Box style={{ ...cardStyle(accentColor), display: 'flex', alignItems: 'center', gap: '16px' }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = accentColor; e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = `0 6px 20px rgba(0,0,0,0.3)`; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.borderLeftColor = accentColor; e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; }}
    >
      <div style={{ width: 44, height: 44, borderRadius: '12px', backgroundColor: `${accentColor}15`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
        <Icon icon={icon} size={22} color={accentColor} />
      </div>
      <div>
        <Text style={{ color: C.textMuted, fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</Text>
        <H5 style={{ color: count > 0 ? accentColor : C.textDim, margin: '4px 0 0 0' }}>{count}</H5>
      </div>
      <Icon icon="ChevronRight" color={C.textDim} style={{ marginLeft: 'auto' }} />
    </Box>
  </a>
);

/* ─── Format date nicely ─── */
const fmtDate = (d) => {
  if (!d) return '—';
  const dt = new Date(d);
  return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
};

/* ─── Status badge color ─── */
const statusColor = (s) => {
  if (!s) return C.textDim;
  const lower = s.toLowerCase();
  if (lower === 'approved' || lower === 'active') return C.green;
  if (lower === 'pending') return C.orange;
  if (lower === 'rejected') return C.red;
  return C.textMuted;
};

/* ================================================
   MAIN DASHBOARD COMPONENT
   ================================================ */
const CustomDashboard = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.getDashboard()
      .then((response) => {
        setData(response.data || {});
        setLoading(false);
      })
      .catch((fetchError) => {
        console.error('Dashboard fetch error:', fetchError);
        setError('Failed to load dashboard data.');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', backgroundColor: C.bg, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ width: 40, height: 40, border: `3px solid ${C.border}`, borderTopColor: C.gold, borderRadius: '50%', animation: 'spin 1s linear infinite', margin: '0 auto 16px' }} />
          <Text style={{ color: C.textMuted }}>Loading dashboard...</Text>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ minHeight: '100vh', backgroundColor: C.bg, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Box style={{ ...cardStyle(C.red), maxWidth: 400, textAlign: 'center' }}>
          <Icon icon="AlertTriangle" size={32} color={C.red} />
          <H5 style={{ color: C.red, margin: '16px 0 8px' }}>{error}</H5>
          <Text style={{ color: C.textMuted }}>Check the server logs for details.</Text>
        </Box>
      </div>
    );
  }

  const stats = data?.stats || {};
  const actionRequired = data?.actionRequired || {};
  const modsByPlatform = data?.modsByPlatform || [];
  const userGrowthData = data?.userGrowthData || [];
  const recentUsers = data?.recentUsers || [];
  const recentMods = data?.recentMods || [];

  // Prepare chart data
  const growthChartData = userGrowthData.map(d => ({ label: d.date, value: d.users }));

  const now = new Date();
  const greeting = now.getHours() < 12 ? 'Good morning' : now.getHours() < 18 ? 'Good afternoon' : 'Good evening';

  return (
    <div style={{ backgroundColor: C.bg, minHeight: '100vh', padding: 'clamp(16px, 3vw, 32px) clamp(14px, 3vw, 36px)', fontFamily: "'Poppins', sans-serif" }}>
      
      {/* ═══ HEADER ═══ */}
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '16px', paddingBottom: '24px', borderBottom: `1px solid ${C.border}`, marginBottom: '28px' }}>
        <div>
          <a href="/admin" style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', cursor: 'pointer' }}>
            <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
              <H2 style={{ margin: 0, display: 'inline-flex', alignItems: 'center', gap: '8px', fontFamily: "'Poppins', sans-serif" }}>
                <span style={{ color: C.gold, textShadow: `0 0 20px ${C.goldGlow}`, fontWeight: 800 }}>GPL</span>
                <span style={{ color: '#ffffff', textShadow: '0 0 15px rgba(255, 255, 255, 0.4)', fontWeight: 700 }}>Mods</span>
              </H2>
              <span style={{ color: '#ffd700', fontSize: '11px', fontWeight: 600, background: 'rgba(255, 215, 0, 0.12)', padding: '4px 10px', borderRadius: '20px', border: '1px solid rgba(255, 215, 0, 0.35)', fontFamily: "'Poppins', sans-serif", letterSpacing: '0.04em', textTransform: 'uppercase' }}>Admin Dashboard</span>
            </div>
          </a>
          <Text style={{ color: '#f1f5f9', marginTop: '8px', fontSize: '14px', fontWeight: 400, fontFamily: "'Poppins', sans-serif", lineHeight: 1.5 }}>
            {greeting}! Here's your platform overview for {now.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })}.
          </Text>
        </div>

        {/* ═══ ADMIN SUITE SHORTCUT BUTTONS ═══ */}
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '10px' }}>
          <a 
            href="/dashboard" 
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: C.gold, backgroundColor: C.goldDim, border: `1px solid ${C.gold}`, padding: '8px 14px', borderRadius: '8px', textDecoration: 'none', fontWeight: 600, fontSize: '13px', transition: 'all 0.2s', fontFamily: "'Poppins', sans-serif" }}
            onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(255,215,0,0.25)'; }}
            onMouseLeave={e => { e.currentTarget.style.backgroundColor = C.goldDim; }}
            title="Go Back To Dashboard"
          >
            <Icon icon="ArrowLeft" size={14} /> Go Back To Dashboard
          </a>

          <a 
            href="/admin/reports" 
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#ff6b6b', backgroundColor: 'rgba(229,57,53,0.12)', border: '1px solid rgba(229,57,53,0.3)', padding: '8px 14px', borderRadius: '8px', textDecoration: 'none', fontWeight: 600, fontSize: '13px', transition: 'all 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(229,57,53,0.25)'; }}
            onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'rgba(229,57,53,0.12)'; }}
            title="Moderation & Mod Reports Console"
          >
            <Icon icon="Flag" size={14} /> Reports
          </a>

          <a 
            href="/admin/support" 
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#64b5f6', backgroundColor: 'rgba(33,150,243,0.12)', border: '1px solid rgba(33,150,243,0.3)', padding: '8px 14px', borderRadius: '8px', textDecoration: 'none', fontWeight: 600, fontSize: '13px', transition: 'all 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(33,150,243,0.25)'; }}
            onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'rgba(33,150,243,0.12)'; }}
            title="Live Support & Inquiries Console"
          >
            <Icon icon="HelpCircle" size={14} /> Support
          </a>

          <a 
            href="/status" 
            target="_blank" 
            rel="noopener noreferrer" 
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#81c784', backgroundColor: 'rgba(67,160,71,0.12)', border: '1px solid rgba(67,160,71,0.3)', padding: '8px 14px', borderRadius: '8px', textDecoration: 'none', fontWeight: 600, fontSize: '13px', transition: 'all 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(67,160,71,0.25)'; }}
            onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'rgba(67,160,71,0.12)'; }}
            title="Live Server Health & Diagnostics"
          >
            <Icon icon="Activity" size={14} /> Status
          </a>

          <a 
            href="/admin/music" 
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#ba68c8', backgroundColor: 'rgba(186,104,200,0.12)', border: '1px solid rgba(186,104,200,0.3)', padding: '8px 14px', borderRadius: '8px', textDecoration: 'none', fontWeight: 600, fontSize: '13px', transition: 'all 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(186,104,200,0.25)'; }}
            onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'rgba(186,104,200,0.12)'; }}
            title="Music & Playlist Manager"
          >
            <Icon icon="Music" size={14} /> Music
          </a>

          <a 
            href="/home" 
            target="_blank" 
            rel="noopener noreferrer" 
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#ffffff', backgroundColor: C.surfaceAlt, border: `1px solid ${C.border}`, padding: '8px 14px', borderRadius: '8px', textDecoration: 'none', fontWeight: 600, fontSize: '13px', transition: 'all 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = C.gold; e.currentTarget.style.color = C.gold; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = '#ffffff'; }}
            title="Open Live Public Site"
          >
            <Icon icon="Globe" size={14} /> Live Site
          </a>
        </div>
      </div>

      {/* ═══ STAT CARDS ═══ */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', marginBottom: '24px' }}>
        <StatCard icon="Users" label="Total Users" value={(stats.totalUsers || 0).toLocaleString()} delta={stats.newUsersThisMonth} accentColor={C.blue} />
        <StatCard icon="Package" label="Total Mods" value={(stats.totalMods || 0).toLocaleString()} delta={stats.newModsThisMonth} accentColor={C.gold} />
        <StatCard icon="Download" label="Total Downloads" value={(stats.totalDownloads || 0).toLocaleString()} accentColor={C.green} />
        <StatCard icon="Eye" label="Total Views" value={(stats.totalViews || 0).toLocaleString()} accentColor={C.purple} />
      </div>

      {/* ═══ ACTION REQUIRED ═══ */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '14px', marginBottom: '32px' }}>
        <ActionCard icon="Flag" label="Pending Reports" count={actionRequired.pendingReports || 0} accentColor={C.red} resourceId="Report" />
        <ActionCard icon="CheckSquare" label="Pending Approvals" count={actionRequired.pendingApprovals || 0} accentColor={C.orange} resourceId="File" />
        <ActionCard icon="HelpCircle" label="Open Tickets" count={actionRequired.openTickets || 0} accentColor={C.blue} resourceId="SupportTicket" />
      </div>

      {/* ═══ CHARTS ROW ═══ */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '20px', marginBottom: '32px' }}>
        {/* User Growth Chart */}
        <Box style={{ ...cardStyle(), flex: '2 1 320px', minWidth: 0, width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '18px' }}>
            <Icon icon="Activity" color={C.gold} />
            <H5 style={{ color: C.text, margin: 0, fontFamily: "'Poppins', sans-serif" }}>User Growth</H5>
            <Badge style={{ marginLeft: '8px', backgroundColor: C.goldDim, color: C.gold, border: 'none', fontFamily: "'Poppins', sans-serif" }}>30 days</Badge>
          </div>
          {growthChartData.length > 0 ? (
            <AreaChart data={growthChartData} color={C.gold} width={500} height={170} />
          ) : (
            <div style={{ height: 160, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Text style={{ color: C.textDim, fontFamily: "'Poppins', sans-serif" }}>No user signups in the last 30 days.</Text>
            </div>
          )}
        </Box>

        {/* Platform Donut */}
        <Box style={{ ...cardStyle(), flex: '1 1 280px', minWidth: 0, width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '18px' }}>
            <Icon icon="PieChart" color={C.blue} />
            <H5 style={{ color: C.text, margin: 0, fontFamily: "'Poppins', sans-serif" }}>Mods by Platform</H5>
          </div>
          {modsByPlatform.length > 0 ? (
            <DonutChart data={modsByPlatform} size={180} />
          ) : (
            <div style={{ height: 160, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Text style={{ color: C.textDim, fontFamily: "'Poppins', sans-serif" }}>No platform data available.</Text>
            </div>
          )}
        </Box>
      </div>

      {/* ═══ RECENT ACTIVITY ROW ═══ */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '20px', marginBottom: '32px' }}>
        {/* Recent Users */}
        <Box style={{ ...cardStyle(), flex: '1 1 320px', minWidth: 0, width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '18px' }}>
            <Icon icon="Users" color={C.blue} />
            <H5 style={{ color: C.text, margin: 0, fontFamily: "'Poppins', sans-serif" }}>Recent Users</H5>
            <a href="/admin/resources/User" style={{ marginLeft: 'auto', color: C.gold, fontSize: '12px', textDecoration: 'none', fontWeight: 600, fontFamily: "'Poppins', sans-serif" }}>View All →</a>
          </div>
          {recentUsers.length > 0 ? (
            <div style={{ overflowX: 'auto', width: '100%', WebkitOverflowScrolling: 'touch' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '300px' }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    <th style={{ textAlign: 'left', padding: '8px 0', color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>Username</th>
                    <th style={{ textAlign: 'left', padding: '8px 0', color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>Role</th>
                    <th style={{ textAlign: 'right', padding: '8px 0', color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>Joined</th>
                  </tr>
                </thead>
                <tbody>
                  {recentUsers.map((u, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                      <td style={{ padding: '10px 0', color: C.text, fontSize: '13px', fontWeight: 500 }}>{u.username}</td>
                      <td style={{ padding: '10px 0' }}>
                        <span style={{ fontSize: '11px', padding: '3px 8px', borderRadius: '6px', backgroundColor: u.role === 'admin' ? `${C.gold}20` : `${C.blue}20`, color: u.role === 'admin' ? C.gold : C.blue, fontWeight: 600 }}>{u.role || 'user'}</span>
                      </td>
                      <td style={{ padding: '10px 0', color: C.textMuted, fontSize: '12px', textAlign: 'right' }}>{fmtDate(u.date)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Text style={{ color: C.textDim, textAlign: 'center', padding: '20px 0' }}>No recent users.</Text>
          )}
        </Box>

        {/* Recent Mods */}
        <Box style={{ ...cardStyle(), flex: '1 1 320px', minWidth: 0, width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '18px' }}>
            <Icon icon="Package" color={C.gold} />
            <H5 style={{ color: C.text, margin: 0, fontFamily: "'Poppins', sans-serif" }}>Recent Mods</H5>
            <a href="/admin/resources/File" style={{ marginLeft: 'auto', color: C.gold, fontSize: '12px', textDecoration: 'none', fontWeight: 600, fontFamily: "'Poppins', sans-serif" }}>View All →</a>
          </div>
          {recentMods.length > 0 ? (
            <div style={{ overflowX: 'auto', width: '100%', WebkitOverflowScrolling: 'touch' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '300px' }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    <th style={{ textAlign: 'left', padding: '8px 0', color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>Name</th>
                    <th style={{ textAlign: 'left', padding: '8px 0', color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>Platform</th>
                    <th style={{ textAlign: 'left', padding: '8px 0', color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>Status</th>
                    <th style={{ textAlign: 'right', padding: '8px 0', color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>Added</th>
                  </tr>
                </thead>
                <tbody>
                  {recentMods.map((m, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                      <td style={{ padding: '10px 0', color: C.text, fontSize: '13px', fontWeight: 500, maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.name}</td>
                      <td style={{ padding: '10px 0' }}>
                        <span style={{ fontSize: '11px', padding: '3px 8px', borderRadius: '6px', backgroundColor: `${C.blue}20`, color: C.blue, fontWeight: 600, textTransform: 'uppercase' }}>{m.category || '—'}</span>
                      </td>
                      <td style={{ padding: '10px 0' }}>
                        <span style={{ fontSize: '11px', padding: '3px 8px', borderRadius: '6px', backgroundColor: `${statusColor(m.status)}20`, color: statusColor(m.status), fontWeight: 600, textTransform: 'capitalize' }}>{m.status || '—'}</span>
                      </td>
                      <td style={{ padding: '10px 0', color: C.textMuted, fontSize: '12px', textAlign: 'right' }}>{fmtDate(m.date)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Text style={{ color: C.textDim, textAlign: 'center', padding: '20px 0' }}>No recent mods.</Text>
          )}
        </Box>
      </div>

      {/* ═══ FOOTER ═══ */}
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '14px', paddingTop: '20px', borderTop: `1px solid ${C.border}` }}>
        <a href="/admin" style={{ textDecoration: 'none' }}>
          <Text style={{ color: '#ffffff', fontSize: '13px', cursor: 'pointer', fontFamily: "'Poppins', sans-serif" }}>
            <span style={{ color: C.gold, fontWeight: 700 }}>GPL</span> <span style={{ color: '#ffffff', fontWeight: 600 }}>Mods</span> • Admin Panel v2.5
          </Text>
        </a>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          <a href="/admin/resources/User" style={{ color: '#ffffff', backgroundColor: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', padding: '5px 12px', borderRadius: '8px', fontSize: '12px', textDecoration: 'none', fontWeight: 500, fontFamily: "'Poppins', sans-serif" }}>Users</a>
          <a href="/admin/resources/File" style={{ color: '#ffffff', backgroundColor: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', padding: '5px 12px', borderRadius: '8px', fontSize: '12px', textDecoration: 'none', fontWeight: 500, fontFamily: "'Poppins', sans-serif" }}>Mods</a>
          <a href="/admin/resources/Report" style={{ color: '#ffffff', backgroundColor: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', padding: '5px 12px', borderRadius: '8px', fontSize: '12px', textDecoration: 'none', fontWeight: 500, fontFamily: "'Poppins', sans-serif" }}>Reports</a>
          <a href="/admin/resources/SupportTicket" style={{ color: '#ffffff', backgroundColor: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', padding: '5px 12px', borderRadius: '8px', fontSize: '12px', textDecoration: 'none', fontWeight: 500, fontFamily: "'Poppins', sans-serif" }}>Tickets</a>
          <a href="/admin/music" style={{ color: '#ffffff', backgroundColor: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', padding: '5px 12px', borderRadius: '8px', fontSize: '12px', textDecoration: 'none', fontWeight: 500, fontFamily: "'Poppins', sans-serif" }}>Music</a>
        </div>
      </div>
    </div>
  );
};

export default CustomDashboard;
