import React, { useState, useEffect } from 'react';
import { ApiClient } from 'adminjs';
import { Box, H2, Text, H5, Icon } from '@adminjs/design-system'; 
import { 
    LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    PieChart, Pie, Cell, Legend
} from 'recharts';

const api = new ApiClient();

// Colors for the Pie Chart
const COLORS = ['#A4C639', '#0078D6', '#21759B', '#FF9800', '#FFFFFF']; 

const Dashboard = () => {
    const [data, setData] = useState({
        stats: { totalUsers: 0, newUsersThisMonth: 0, totalMods: 0, newModsThisMonth: 0, totalDownloads: 0 },
        modsByPlatform: [],
        uploadChartData: []
    });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        // Fetch data from the backend handler
        api.getDashboard()
            .then((response) => {
                // Ensure we always have an object, even if the backend fails
                setData(response.data || {
                    stats: {}, modsByPlatform: [], uploadChartData: []
                });
                setLoading(false);
            })
            .catch((error) => {
                console.error("Dashboard fetch error:", error);
                setError("Failed to load telemetry data.");
                setLoading(false);
            });
    }, []);

    if (loading) {
        return (
            <Box p="xl" style={{ textAlign: 'center', color: '#c0c0c0', minHeight: '100vh', backgroundColor: '#0a0a0a' }}>
                <Text>Loading Real-Time Telemetry...</Text>
            </Box>
        );
    }

    if (error) {
        return (
            <Box p="xl" style={{ textAlign: 'center', color: '#e53935', minHeight: '100vh', backgroundColor: '#0a0a0a' }}>
                <H5>{error}</H5>
                <Text>Please check the server logs.</Text>
            </Box>
        );
    }

    // Safely extract data with fallbacks
    const stats = data.stats || {};
    const modsByPlatform = data.modsByPlatform || [];
    const uploadChartData = data.uploadChartData || [];

    return (
        <Box style={{ padding: '40px', backgroundColor: '#0a0a0a', minHeight: '100vh', fontFamily: 'Poppins, sans-serif' }}>
            
            {/* Header Section with Custom GPL Mods Branding */}
            <Box mb="xl" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #333', paddingBottom: '20px' }}>
                <Box>
                    <H2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span style={{ color: '#FFD700', textShadow: '0 0 15px rgba(255, 215, 0, 0.4)', fontWeight: 'bold' }}>GPL</span>
                        <span style={{ color: '#c0c0c0', fontWeight: 'bold' }}>Mods</span>
                        <span style={{ color: '#666', fontSize: '0.6em', fontWeight: 'normal', marginLeft: '10px' }}>Admin Telemetry</span>
                    </H2>
                    <Text style={{ color: '#888', marginTop: '5px' }}>Live overview of platform health and community growth.</Text>
                </Box>
                <a href="/home" target="_blank" rel="noopener noreferrer" style={{ color: '#FFD700', border: '1px solid #FFD700', padding: '8px 15px', borderRadius: '8px', textDecoration: 'none', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Icon icon="Globe" /> Go to Live Site
                </a>
            </Box>

            {/* --- STAT METRIC CARDS --- */}
            <Box flex flexDirection="row" flexWrap="wrap" style={{ gap: '20px', marginBottom: '40px' }}>
                
                {/* Users Card */}
                <Box p="lg" style={{ flex: '1', minWidth: '200px', backgroundColor: '#1a1a1a', borderRadius: '12px', borderLeft: '4px solid #2196F3', borderTop: '1px solid #333', borderRight: '1px solid #333', borderBottom: '1px solid #333' }}>
                    <Text style={{ color: '#c0c0c0', fontSize: '12px', fontWeight: 'bold', textTransform: 'uppercase' }}><Icon icon="Users" /> Total Users</Text>
                    <H2 style={{ color: '#fff', margin: '10px 0' }}>{stats.totalUsers?.toLocaleString() || 0}</H2>
                    <Text style={{ color: '#43a047', fontSize: '13px', fontWeight: 'bold' }}>
                        <Icon icon="TrendUp" /> +{stats.newUsersThisMonth?.toLocaleString() || 0} this month
                    </Text>
                </Box>

                {/* Mods Card */}
                <Box p="lg" style={{ flex: '1', minWidth: '200px', backgroundColor: '#1a1a1a', borderRadius: '12px', borderLeft: '4px solid #FFD700', borderTop: '1px solid #333', borderRight: '1px solid #333', borderBottom: '1px solid #333' }}>
                    <Text style={{ color: '#c0c0c0', fontSize: '12px', fontWeight: 'bold', textTransform: 'uppercase' }}><Icon icon="FileCode" /> Total Mods</Text>
                    <H2 style={{ color: '#fff', margin: '10px 0' }}>{stats.totalMods?.toLocaleString() || 0}</H2>
                    <Text style={{ color: '#FFD700', fontSize: '13px', fontWeight: 'bold' }}>
                        <Icon icon="Plus" /> +{stats.newModsThisMonth?.toLocaleString() || 0} this month
                    </Text>
                </Box>

                {/* Downloads Card */}
                <Box p="lg" style={{ flex: '1', minWidth: '200px', backgroundColor: '#1a1a1a', borderRadius: '12px', borderLeft: '4px solid #43a047', borderTop: '1px solid #333', borderRight: '1px solid #333', borderBottom: '1px solid #333' }}>
                    <Text style={{ color: '#c0c0c0', fontSize: '12px', fontWeight: 'bold', textTransform: 'uppercase' }}><Icon icon="Download" /> Total Downloads</Text>
                    <H2 style={{ color: '#fff', margin: '10px 0' }}>{stats.totalDownloads?.toLocaleString() || 0}</H2>
                    <Text style={{ color: '#888', fontSize: '13px' }}>Lifetime platform bandwidth</Text>
                </Box>
            </Box>

            {/* --- RECHARTS GRAPHICS SECTION --- */}
            <Box flex flexDirection="row" flexWrap="wrap" style={{ gap: '20px' }}>
                
                {/* LINE CHART: Recent Uploads */}
                <Box p="xl" style={{ flex: '2', minWidth: '400px', backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333' }}>
                    <H5 style={{ color: '#fff', marginBottom: '20px' }}><Icon icon="Activity" /> Upload Activity (Last 7 Days)</H5>
                    <div style={{ width: '100%', height: 300 }}>
                        {uploadChartData.length > 0 ? (
                            <ResponsiveContainer>
                                <LineChart data={uploadChartData} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                                    <XAxis dataKey="name" stroke="#888" tick={{ fill: '#c0c0c0' }} />
                                    <YAxis stroke="#888" allowDecimals={false} tick={{ fill: '#c0c0c0' }} />
                                    <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #FFD700', borderRadius: '8px' }} itemStyle={{ color: '#FFD700', fontWeight: 'bold' }} />
                                    <Line type="monotone" dataKey="Uploads" stroke="#FFD700" strokeWidth={4} dot={{ r: 6, fill: '#0a0a0a', stroke: '#FFD700', strokeWidth: 2 }} activeDot={{ r: 8 }} />
                                </LineChart>
                            </ResponsiveContainer>
                        ) : (
                            <Box flex alignItems="center" justifyContent="center" height="100%"><Text style={{ color: '#666' }}>No upload activity in the last 7 days.</Text></Box>
                        )}
                    </div>
                </Box>
                
                {/* PIE CHART: Platform Distribution */}
                <Box p="xl" style={{ flex: '1', minWidth: '300px', backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333' }}>
                    <H5 style={{ color: '#fff', marginBottom: '20px' }}><Icon icon="ChartPieSlice" /> Mods by Platform</H5>
                    <div style={{ width: '100%', height: 300 }}>
                        {modsByPlatform.length > 0 ? (
                            <ResponsiveContainer>
                                <PieChart>
                                    <Pie data={modsByPlatform} cx="50%" cy="45%" innerRadius={60} outerRadius={90} paddingAngle={5} dataKey="value" stroke="none">
                                        {modsByPlatform.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', borderRadius: '8px' }} itemStyle={{ color: '#fff' }} />
                                    <Legend verticalAlign="bottom" height={36} wrapperStyle={{ color: '#c0c0c0', fontSize: '12px' }} />
                                </PieChart>
                            </ResponsiveContainer>
                        ) : (
                            <Box flex alignItems="center" justifyContent="center" height="100%"><Text style={{ color: '#666' }}>No platform data available.</Text></Box>
                        )}
                    </div>
                </Box>

            </Box>
        </Box>
    );
};

export default Dashboard;