import React, { useState, useEffect } from 'react';
import { ApiClient } from 'adminjs';
import { Box, H2, Text, H5, Button, Icon } from '@adminjs/design-system'; 
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const api = new ApiClient();

// Colors for the Pie Chart to match your platform themes
const COLORS = ['#A4C639', '#FF9800', '#FFFFFF', '#0078D6', '#21759B']; 

const Dashboard = () => {
    const [data, setData] = useState({});
    const [loading, setLoading] = useState(true);
    const [theme, setTheme] = useState('dark');

    useEffect(() => {
        api.getPage({ pageName: 'Dashboard' }).then(res => {
            setData(res.data || {});
            setLoading(false);
        }).catch(err => {
            console.error("Dashboard data fetch error:", err);
            setLoading(false);
        });
        
        // Check current AdminJS theme (basic implementation)
        const currentTheme = document.body.getAttribute('data-theme') || 'dark';
        setTheme(currentTheme);
    }, []);

    const toggleTheme = () => {
        // AdminJS has a built-in theme switcher API, but it's complex to access from a custom component without Redux.
        // A simple visual toggle for demonstration (requires full page reload in AdminJS usually)
        alert("Theme toggling requires AdminJS Theme API integration. Defaulting to GPL Mods Premium Dark.");
    };

    if (loading) {
        return <Box p="xl" style={{ textAlign: 'center', color: '#c0c0c0' }}><Text>Loading telemetry...</Text></Box>;
    }

    const pieData = data.modsByPlatform || [];

    return (
        <Box style={{ padding: '40px', backgroundColor: 'transparent', minHeight: '100vh' }}>
            
            {/* Header Section */}
            <Box mb="xl" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '20px', borderBottom: '1px solid #333', paddingBottom: '20px' }}>
                <Box style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                    <Box>
                        <H2 style={{ margin: 0, color: '#fff' }}>Command <span style={{ color: '#FFD700' }}>Center</span></H2>
                        <Text style={{ color: '#c0c0c0' }}>Real-time statistics and telemetry for GPL Mods.</Text>
                    </Box>
                </Box>
                
                <Box style={{ display: 'flex', gap: '15px', alignItems: 'center' }}>
                    {/* Return to Site Link */}
                    <a href="/home" style={{ color: '#c0c0c0', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 'bold' }}>
                        <Icon icon="ArrowLeft" /> Back to Website
                    </a>
                    
                    <a href="/status" style={{ backgroundColor: 'transparent', color: '#FFD700', border: '2px solid #FFD700', padding: '8px 16px', borderRadius: '20px', textDecoration: 'none', fontWeight: 'bold', transition: 'all 0.3s ease' }}>
                        System Status
                    </a>
                </Box>
            </Box>

            {/* Clickable Stat Cards */}
            <Box flex flexDirection="row" flexWrap="wrap" style={{ gap: '20px', marginBottom: '40px' }}>
                
                {/* Users Card */}
                <a href="/admin/resources/User" style={{ textDecoration: 'none', flex: '1', minWidth: '200px' }}>
                    <Box p="lg" style={{ backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333', borderLeft: '4px solid #2196F3', transition: 'transform 0.2s', cursor: 'pointer' }} onMouseOver={e => e.currentTarget.style.transform = 'translateY(-5px)'} onMouseOut={e => e.currentTarget.style.transform = 'none'}>
                        <Text style={{ color: '#c0c0c0', textTransform: 'uppercase', fontSize: '12px', fontWeight: 'bold', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}><Icon icon="Users" /> Total Users</Text>
                        <H2 style={{ color: '#fff', margin: 0, display: 'flex', alignItems: 'baseline', gap: '10px' }}>
                            {data.stats?.totalUsers?.toLocaleString() || 0}
                        </H2>
                        {/* ✅ NEW: "This Month" Metric */}
                        <Text style={{ color: '#43a047', fontSize: '14px', marginTop: '5px', fontWeight: 'bold' }}>
                            <Icon icon="TrendUp" style={{ marginRight: '4px' }} /> 
                            +{data.stats?.newUsersThisMonth?.toLocaleString() || 0} this month
                        </Text>
                    </Box>
                </a>

                {/* Mods Card */}
                <a href="/admin/resources/File" style={{ textDecoration: 'none', flex: '1', minWidth: '200px' }}>
                    <Box p="lg" style={{ backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333', borderLeft: '4px solid #FFD700', transition: 'transform 0.2s', cursor: 'pointer' }} onMouseOver={e => e.currentTarget.style.transform = 'translateY(-5px)'} onMouseOut={e => e.currentTarget.style.transform = 'none'}>
                        <Text style={{ color: '#c0c0c0', textTransform: 'uppercase', fontSize: '12px', fontWeight: 'bold', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}><Icon icon="FileCode" /> Total Live Mods</Text>
                        <H2 style={{ color: '#fff', margin: 0 }}>
                            {data.stats?.totalMods?.toLocaleString() || 0}
                        </H2>
                        {/* ✅ NEW: "This Month" Metric */}
                        <Text style={{ color: '#FFD700', fontSize: '14px', marginTop: '5px', fontWeight: 'bold' }}>
                            <Icon icon="Plus" style={{ marginRight: '4px' }} /> 
                            +{data.stats?.newModsThisMonth?.toLocaleString() || 0} this month
                        </Text>
                    </Box>
                </a>

                {/* Downloads Card */}
                <Box p="lg" style={{ flex: '1', minWidth: '200px', backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333', borderLeft: '4px solid #43a047' }}>
                    <Text style={{ color: '#c0c0c0', textTransform: 'uppercase', fontSize: '12px', fontWeight: 'bold', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}><Icon icon="Download" /> Total Downloads</Text>
                    <H2 style={{ color: '#fff', margin: 0 }}>
                        {data.stats?.totalDownloads?.toLocaleString() || 0}
                    </H2>
                    {/* Note: Tracking exact downloads per month requires a separate historical DB collection. 
                        We keep this as a grand total for now. */}
                    <Text style={{ color: '#c0c0c0', fontSize: '12px', marginTop: '5px' }}>
                        All-time download count
                    </Text>
                </Box>

            </Box>
            {/* Charts Section */}
            <Box flex flexDirection="row" flexWrap="wrap" style={{ gap: '20px' }}>
                
                {/* Platform Distribution Pie Chart */}
                <Box p="xl" style={{ flex: '1', minWidth: '300px', backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333' }}>
                    <H5 style={{ color: '#fff', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}><Icon icon="ChartPieSlice" /> Mods by Platform</H5>
                    
                    <div style={{ width: '100%', height: 300 }}>
                        {pieData.length > 0 ? (
                            <ResponsiveContainer>
                                <PieChart>
                                    <Pie
                                        data={pieData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={100}
                                        paddingAngle={5}
                                        dataKey="value"
                                        stroke="none"
                                    >
                                        {pieData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #FFD700', borderRadius: '8px', color: '#fff' }} itemStyle={{ color: '#fff' }} />
                                    <Legend verticalAlign="bottom" height={36} wrapperStyle={{ color: '#c0c0c0' }} />
                                </PieChart>
                            </ResponsiveContainer>
                        ) : (
                            <Box flex alignItems="center" justifyContent="center" style={{ height: '100%', color: '#666' }}>
                                <Text>No platform data available.</Text>
                            </Box>
                        )}
                    </div>
                </Box>
                
                {/* Quick Actions Panel */}
                <Box p="xl" style={{ flex: '1', minWidth: '300px', backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333' }}>
                    <H5 style={{ color: '#fff', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}><Icon icon="Lightning" /> Quick Actions</H5>
                    
                    <Box style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                        <a href="/admin/resources/Report" style={{ textDecoration: 'none' }}>
                            <Button variant="primary" style={{ width: '100%', justifyContent: 'flex-start', gap: '10px' }}>
                                <Icon icon="Flag" /> Review Pending Reports
                            </Button>
                        </a>
                        <a href="/admin/resources/SupportTicket/actions/new" style={{ textDecoration: 'none' }}>
                            <Button variant="secondary" style={{ width: '100%', justifyContent: 'flex-start', gap: '10px', borderColor: '#333' }}>
                                <Icon icon="Ticket" /> Create Support Ticket
                            </Button>
                        </a>
                        <a href="/admin/resources/AutomatedCampaign/actions/new" style={{ textDecoration: 'none' }}>
                            <Button variant="secondary" style={{ width: '100%', justifyContent: 'flex-start', gap: '10px', borderColor: '#333' }}>
                                <Icon icon="Robot" /> Schedule Notification Blast
                            </Button>
                        </a>
                    </Box>
                </Box>

            </Box>

        </Box>
    );
};

export default Dashboard;