import React, { useState, useEffect } from 'react';
import { ApiClient } from 'adminjs';
import { Box, H2, Text, H5 } from '@adminjs/design-system'; 
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const api = new ApiClient();

const Dashboard = () => {
    const [data, setData] = useState({});
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Fetch the data from the handler we wrote in admin.js
        api.getPage({ pageName: 'Dashboard' }).then(res => {
            setData(res.data);
            setLoading(false);
        });
    }, []);

    if (loading) {
        return <Box p="xl" style={{ textAlign: 'center', color: '#c0c0c0' }}><Text>Loading telemetry...</Text></Box>;
    }

    // Process chart data for Recharts
    const chartData = data.chartData ? data.chartData.map(item => ({
        name: item._id.split('-').slice(1).join('/'), // Format date from YYYY-MM-DD to MM/DD
        Uploads: item.count
    })) : [];

    return (
        <Box style={{ padding: '40px', backgroundColor: '#0a0a0a', minHeight: '100vh' }}>
            
            {/* Header Section */}
            <Box mb="xl" style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                <img src="/images/logo.png" alt="Logo" style={{ height: '60px' }} onError={(e) => e.target.style.display='none'} />
                <Box>
                    <H2 style={{ margin: 0, color: '#fff' }}>Platform <span style={{ color: '#FFD700' }}>Overview</span></H2>
                    <Text style={{ color: '#c0c0c0' }}>Real-time statistics and telemetry for GPL Mods.</Text>
                </Box>
            </Box>

            {/* Top Stat Cards */}
            <Box flex flexDirection="row" flexWrap="wrap" style={{ gap: '20px', marginBottom: '40px' }}>
                
                {/* Stat Card 1 */}
                <Box p="lg" style={{ flex: '1', minWidth: '200px', backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333', borderLeft: '4px solid #2196F3' }}>
                    <Text style={{ color: '#c0c0c0', textTransform: 'uppercase', fontSize: '12px', fontWeight: 'bold', marginBottom: '10px' }}>Total Registered Users</Text>
                    <H2 style={{ color: '#fff', margin: 0 }}>{data.stats?.totalUsers || 0}</H2>
                </Box>

                {/* Stat Card 2 */}
                <Box p="lg" style={{ flex: '1', minWidth: '200px', backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333', borderLeft: '4px solid #FFD700' }}>
                    <Text style={{ color: '#c0c0c0', textTransform: 'uppercase', fontSize: '12px', fontWeight: 'bold', marginBottom: '10px' }}>Live Mods Database</Text>
                    <H2 style={{ color: '#fff', margin: 0 }}>{data.stats?.totalMods || 0}</H2>
                </Box>

                {/* Stat Card 3 */}
                <Box p="lg" style={{ flex: '1', minWidth: '200px', backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333', borderLeft: '4px solid #43a047' }}>
                    <Text style={{ color: '#c0c0c0', textTransform: 'uppercase', fontSize: '12px', fontWeight: 'bold', marginBottom: '10px' }}>Total All-Time Downloads</Text>
                    <H2 style={{ color: '#fff', margin: 0 }}>{data.stats?.totalDownloads?.toLocaleString() || 0}</H2>
                </Box>

            </Box>

            {/* Chart Section */}
            <Box p="xl" style={{ backgroundColor: '#1a1a1a', borderRadius: '12px', border: '1px solid #333' }}>
                <H5 style={{ color: '#fff', marginBottom: '20px' }}>Upload Activity (Last 7 Days)</H5>
                
                <div style={{ width: '100%', height: 400 }}>
                    {chartData.length > 0 ? (
                        <ResponsiveContainer>
                            <LineChart data={chartData} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                                <XAxis dataKey="name" stroke="#c0c0c0" />
                                <YAxis stroke="#c0c0c0" allowDecimals={false} />
                                <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #FFD700' }} />
                                <Line type="monotone" dataKey="Uploads" stroke="#FFD700" strokeWidth={3} dot={{ r: 6, fill: '#0a0a0a', stroke: '#FFD700', strokeWidth: 2 }} activeDot={{ r: 8 }} />
                            </LineChart>
                        </ResponsiveContainer>
                    ) : (
                        <Box flex alignItems="center" justifyContent="center" style={{ height: '100%', color: '#666' }}>
                            <Text>No upload activity in the last 7 days.</Text>
                        </Box>
                    )}
                </div>
            </Box>

        </Box>
    );
};

export default Dashboard;