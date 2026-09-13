(function (React, adminjs, designSystem) {
  'use strict';

  function _interopDefault (e) { return e && e.__esModule ? e : { default: e }; }

  var React__default = /*#__PURE__*/_interopDefault(React);

  const api$1 = new adminjs.ApiClient();

  /* ─── colour tokens ─── */
  const C = {
    bg: '#0a0a0a',
    surface: '#131313',
    surfaceAlt: '#1a1a1a',
    border: '#2a2a2a',
    borderHover: '#3a3a3a',
    gold: '#FFD700',
    goldDim: 'rgba(255,215,0,0.15)',
    goldGlow: 'rgba(255,215,0,0.35)',
    blue: '#2196F3',
    green: '#43a047',
    purple: '#9C27B0',
    red: '#e53935',
    orange: '#FF9800',
    text: '#ffffff',
    textMuted: '#999',
    textDim: '#666'
  };

  /* ─── platform chart colours ─── */
  const PLATFORM_COLORS = ['#A4C639', '#0078D6', '#21759B', '#FF9800', '#9C27B0', '#e53935', '#43a047', '#FFD700'];

  /* ─── reusable card style ─── */
  const cardStyle = accentColor => ({
    backgroundColor: C.surface,
    borderRadius: '16px',
    border: `1px solid ${C.border}`,
    borderLeft: accentColor ? `4px solid ${accentColor}` : `1px solid ${C.border}`,
    padding: '24px',
    transition: 'all 0.25s ease',
    cursor: 'default'
  });

  /* ─── Inline SVG Area Chart ─── */
  const AreaChart = ({
    data,
    width = 500,
    height = 200,
    color = C.gold
  }) => {
    if (!data || data.length === 0) return null;
    const maxVal = Math.max(...data.map(d => d.value), 1);
    const padX = 40;
    const padY = 20;
    const chartW = width - padX * 2;
    const chartH = height - padY * 2;
    const points = data.map((d, i) => ({
      x: padX + i / Math.max(data.length - 1, 1) * chartW,
      y: padY + chartH - d.value / maxVal * chartH
    }));
    const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x},${p.y}`).join(' ');
    const areaPath = `${linePath} L${points[points.length - 1].x},${padY + chartH} L${points[0].x},${padY + chartH} Z`;

    // Grid lines
    const gridLines = [0, 0.25, 0.5, 0.75, 1].map(pct => {
      const y = padY + chartH - pct * chartH;
      const label = Math.round(pct * maxVal);
      return {
        y,
        label
      };
    });
    return /*#__PURE__*/React__default.default.createElement("svg", {
      width: "100%",
      height: height,
      viewBox: `0 0 ${width} ${height}`,
      preserveAspectRatio: "xMidYMid meet"
    }, /*#__PURE__*/React__default.default.createElement("defs", null, /*#__PURE__*/React__default.default.createElement("linearGradient", {
      id: "areaFill",
      x1: "0",
      y1: "0",
      x2: "0",
      y2: "1"
    }, /*#__PURE__*/React__default.default.createElement("stop", {
      offset: "0%",
      stopColor: color,
      stopOpacity: "0.3"
    }), /*#__PURE__*/React__default.default.createElement("stop", {
      offset: "100%",
      stopColor: color,
      stopOpacity: "0.02"
    }))), gridLines.map((g, i) => /*#__PURE__*/React__default.default.createElement("g", {
      key: i
    }, /*#__PURE__*/React__default.default.createElement("line", {
      x1: padX,
      y1: g.y,
      x2: width - padX,
      y2: g.y,
      stroke: C.border,
      strokeWidth: "1",
      strokeDasharray: "4 4"
    }), /*#__PURE__*/React__default.default.createElement("text", {
      x: padX - 6,
      y: g.y + 4,
      fill: C.textDim,
      fontSize: "10",
      textAnchor: "end"
    }, g.label))), /*#__PURE__*/React__default.default.createElement("path", {
      d: areaPath,
      fill: "url(#areaFill)"
    }), /*#__PURE__*/React__default.default.createElement("path", {
      d: linePath,
      fill: "none",
      stroke: color,
      strokeWidth: "2.5",
      strokeLinejoin: "round",
      strokeLinecap: "round"
    }), points.map((p, i) => /*#__PURE__*/React__default.default.createElement("g", {
      key: i
    }, /*#__PURE__*/React__default.default.createElement("circle", {
      cx: p.x,
      cy: p.y,
      r: "4",
      fill: C.bg,
      stroke: color,
      strokeWidth: "2"
    }), /*#__PURE__*/React__default.default.createElement("text", {
      x: p.x,
      y: padY + chartH + 16,
      fill: C.textMuted,
      fontSize: "9",
      textAnchor: "middle"
    }, data[i].label))));
  };

  /* ─── Inline SVG Donut Chart ─── */
  const DonutChart = ({
    data,
    size = 200
  }) => {
    if (!data || data.length === 0) return null;
    const total = data.reduce((s, d) => s + d.value, 0);
    if (total === 0) return null;
    const cx = size / 2;
    const cy = size / 2;
    const outerR = size / 2 - 10;
    const innerR = outerR * 0.6;
    let cumAngle = -Math.PI / 2;
    const slices = data.map((d, i) => {
      const angle = d.value / total * Math.PI * 2;
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
      return {
        path,
        color,
        name: d.name,
        value: d.value,
        pct: Math.round(d.value / total * 100)
      };
    });
    return /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '24px',
        flexWrap: 'wrap',
        justifyContent: 'center'
      }
    }, /*#__PURE__*/React__default.default.createElement("svg", {
      width: size,
      height: size,
      viewBox: `0 0 ${size} ${size}`
    }, slices.map((s, i) => /*#__PURE__*/React__default.default.createElement("path", {
      key: i,
      d: s.path,
      fill: s.color,
      stroke: C.bg,
      strokeWidth: "2"
    }, /*#__PURE__*/React__default.default.createElement("title", null, s.name, ": ", s.value, " (", s.pct, "%)"))), /*#__PURE__*/React__default.default.createElement("text", {
      x: cx,
      y: cy - 6,
      fill: C.text,
      fontSize: "22",
      fontWeight: "bold",
      textAnchor: "middle"
    }, total), /*#__PURE__*/React__default.default.createElement("text", {
      x: cx,
      y: cy + 14,
      fill: C.textMuted,
      fontSize: "10",
      textAnchor: "middle"
    }, "TOTAL")), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        flexDirection: 'column',
        gap: '6px'
      }
    }, slices.map((s, i) => /*#__PURE__*/React__default.default.createElement("div", {
      key: i,
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        fontSize: '12px'
      }
    }, /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        width: 12,
        height: 12,
        borderRadius: '3px',
        backgroundColor: s.color,
        display: 'inline-block',
        flexShrink: 0
      }
    }), /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: C.text
      }
    }, s.name), /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: C.textDim,
        marginLeft: 'auto'
      }
    }, s.value, " (", s.pct, "%)")))));
  };

  /* ─── Stat Card ─── */
  const StatCard = ({
    icon,
    label,
    value,
    delta,
    deltaLabel,
    accentColor
  }) => /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
    style: {
      ...cardStyle(accentColor),
      flex: '1',
      minWidth: '220px'
    },
    onMouseEnter: e => {
      e.currentTarget.style.borderColor = accentColor || C.borderHover;
      e.currentTarget.style.transform = 'translateY(-2px)';
      e.currentTarget.style.boxShadow = `0 8px 24px rgba(0,0,0,0.4)`;
    },
    onMouseLeave: e => {
      e.currentTarget.style.borderColor = C.border;
      e.currentTarget.style.borderLeftColor = accentColor;
      e.currentTarget.style.transform = 'translateY(0)';
      e.currentTarget.style.boxShadow = 'none';
    }
  }, /*#__PURE__*/React__default.default.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      marginBottom: '14px'
    }
  }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
    icon: icon,
    color: accentColor
  }), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
    style: {
      color: C.textMuted,
      fontSize: '11px',
      fontWeight: 700,
      textTransform: 'uppercase',
      letterSpacing: '0.08em'
    }
  }, label)), /*#__PURE__*/React__default.default.createElement(designSystem.H2, {
    style: {
      color: C.text,
      margin: '0 0 8px 0',
      fontSize: '2.2rem'
    }
  }, value), delta !== undefined && /*#__PURE__*/React__default.default.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '6px'
    }
  }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
    icon: "ArrowUp",
    size: 14,
    color: C.green
  }), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
    style: {
      color: C.green,
      fontSize: '13px',
      fontWeight: 600
    }
  }, "+", delta, " ", deltaLabel || 'this month')));

  /* ─── Action Badge Card ─── */
  const ActionCard = ({
    icon,
    label,
    count,
    accentColor,
    resourceId
  }) => /*#__PURE__*/React__default.default.createElement("a", {
    href: `/admin/resources/${resourceId}`,
    style: {
      textDecoration: 'none',
      flex: '1',
      minWidth: '180px'
    }
  }, /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
    style: {
      ...cardStyle(accentColor),
      display: 'flex',
      alignItems: 'center',
      gap: '16px'
    },
    onMouseEnter: e => {
      e.currentTarget.style.borderColor = accentColor;
      e.currentTarget.style.transform = 'translateY(-2px)';
      e.currentTarget.style.boxShadow = `0 6px 20px rgba(0,0,0,0.3)`;
    },
    onMouseLeave: e => {
      e.currentTarget.style.borderColor = C.border;
      e.currentTarget.style.borderLeftColor = accentColor;
      e.currentTarget.style.transform = 'translateY(0)';
      e.currentTarget.style.boxShadow = 'none';
    }
  }, /*#__PURE__*/React__default.default.createElement("div", {
    style: {
      width: 44,
      height: 44,
      borderRadius: '12px',
      backgroundColor: `${accentColor}15`,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      flexShrink: 0
    }
  }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
    icon: icon,
    size: 22,
    color: accentColor
  })), /*#__PURE__*/React__default.default.createElement("div", null, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
    style: {
      color: C.textMuted,
      fontSize: '11px',
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.06em'
    }
  }, label), /*#__PURE__*/React__default.default.createElement(designSystem.H5, {
    style: {
      color: count > 0 ? accentColor : C.textDim,
      margin: '4px 0 0 0'
    }
  }, count)), /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
    icon: "ChevronRight",
    color: C.textDim,
    style: {
      marginLeft: 'auto'
    }
  })));

  /* ─── Format date nicely ─── */
  const fmtDate = d => {
    if (!d) return '—';
    const dt = new Date(d);
    return dt.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  /* ─── Status badge color ─── */
  const statusColor = s => {
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
    const [data, setData] = React.useState(null);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState(null);
    React.useEffect(() => {
      api$1.getDashboard().then(response => {
        setData(response.data || {});
        setLoading(false);
      }).catch(fetchError => {
        console.error('Dashboard fetch error:', fetchError);
        setError('Failed to load dashboard data.');
        setLoading(false);
      });
    }, []);
    if (loading) {
      return /*#__PURE__*/React__default.default.createElement("div", {
        style: {
          minHeight: '100vh',
          backgroundColor: C.bg,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }
      }, /*#__PURE__*/React__default.default.createElement("div", {
        style: {
          textAlign: 'center'
        }
      }, /*#__PURE__*/React__default.default.createElement("div", {
        style: {
          width: 40,
          height: 40,
          border: `3px solid ${C.border}`,
          borderTopColor: C.gold,
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          margin: '0 auto 16px'
        }
      }), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
        style: {
          color: C.textMuted
        }
      }, "Loading dashboard..."), /*#__PURE__*/React__default.default.createElement("style", null, `@keyframes spin { to { transform: rotate(360deg); } }`)));
    }
    if (error) {
      return /*#__PURE__*/React__default.default.createElement("div", {
        style: {
          minHeight: '100vh',
          backgroundColor: C.bg,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }
      }, /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
        style: {
          ...cardStyle(C.red),
          maxWidth: 400,
          textAlign: 'center'
        }
      }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
        icon: "AlertTriangle",
        size: 32,
        color: C.red
      }), /*#__PURE__*/React__default.default.createElement(designSystem.H5, {
        style: {
          color: C.red,
          margin: '16px 0 8px'
        }
      }, error), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
        style: {
          color: C.textMuted
        }
      }, "Check the server logs for details.")));
    }
    const stats = data?.stats || {};
    const actionRequired = data?.actionRequired || {};
    const modsByPlatform = data?.modsByPlatform || [];
    const userGrowthData = data?.userGrowthData || [];
    const recentUsers = data?.recentUsers || [];
    const recentMods = data?.recentMods || [];

    // Prepare chart data
    const growthChartData = userGrowthData.map(d => ({
      label: d.date,
      value: d.users
    }));
    const now = new Date();
    const greeting = now.getHours() < 12 ? 'Good morning' : now.getHours() < 18 ? 'Good afternoon' : 'Good evening';
    return /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        backgroundColor: C.bg,
        minHeight: '100vh',
        padding: '32px 40px',
        fontFamily: 'Inter, system-ui, -apple-system, sans-serif'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'flex-end',
        gap: '16px',
        paddingBottom: '24px',
        borderBottom: `1px solid ${C.border}`,
        marginBottom: '32px'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", null, /*#__PURE__*/React__default.default.createElement(designSystem.H2, {
      style: {
        margin: 0,
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }
    }, /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: C.gold,
        textShadow: `0 0 20px ${C.goldGlow}`,
        fontWeight: 800
      }
    }, "GPL"), /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: '#c0c0c0',
        fontWeight: 700
      }
    }, "Mods"), /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: C.textDim,
        fontSize: '0.5em',
        fontWeight: 400,
        marginLeft: '12px',
        background: C.surfaceAlt,
        padding: '4px 10px',
        borderRadius: '6px',
        border: `1px solid ${C.border}`
      }
    }, "Admin Dashboard")), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textMuted,
        marginTop: '6px'
      }
    }, greeting, "! Here's your platform overview for ", now.toLocaleDateString('en-US', {
      weekday: 'long',
      month: 'long',
      day: 'numeric',
      year: 'numeric'
    }), ".")), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/home",
      target: "_blank",
      rel: "noopener noreferrer",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        color: C.gold,
        border: `1px solid ${C.gold}`,
        padding: '10px 20px',
        borderRadius: '10px',
        textDecoration: 'none',
        fontWeight: 700,
        fontSize: '14px',
        transition: 'all 0.2s'
      },
      onMouseEnter: e => {
        e.currentTarget.style.backgroundColor = C.goldDim;
      },
      onMouseLeave: e => {
        e.currentTarget.style.backgroundColor = 'transparent';
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Globe"
    }), " View Live Site")), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '20px',
        marginBottom: '24px'
      }
    }, /*#__PURE__*/React__default.default.createElement(StatCard, {
      icon: "Users",
      label: "Total Users",
      value: (stats.totalUsers || 0).toLocaleString(),
      delta: stats.newUsersThisMonth,
      accentColor: C.blue
    }), /*#__PURE__*/React__default.default.createElement(StatCard, {
      icon: "Package",
      label: "Total Mods",
      value: (stats.totalMods || 0).toLocaleString(),
      delta: stats.newModsThisMonth,
      accentColor: C.gold
    }), /*#__PURE__*/React__default.default.createElement(StatCard, {
      icon: "Download",
      label: "Total Downloads",
      value: (stats.totalDownloads || 0).toLocaleString(),
      accentColor: C.green
    }), /*#__PURE__*/React__default.default.createElement(StatCard, {
      icon: "Eye",
      label: "Total Views",
      value: (stats.totalViews || 0).toLocaleString(),
      accentColor: C.purple
    })), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '16px',
        marginBottom: '32px'
      }
    }, /*#__PURE__*/React__default.default.createElement(ActionCard, {
      icon: "Flag",
      label: "Pending Reports",
      count: actionRequired.pendingReports || 0,
      accentColor: C.red,
      resourceId: "Report"
    }), /*#__PURE__*/React__default.default.createElement(ActionCard, {
      icon: "CheckSquare",
      label: "Pending Approvals",
      count: actionRequired.pendingApprovals || 0,
      accentColor: C.orange,
      resourceId: "File"
    }), /*#__PURE__*/React__default.default.createElement(ActionCard, {
      icon: "HelpCircle",
      label: "Open Tickets",
      count: actionRequired.openTickets || 0,
      accentColor: C.blue,
      resourceId: "SupportTicket"
    })), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '20px',
        marginBottom: '32px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      style: {
        ...cardStyle(),
        flex: '2',
        minWidth: '380px'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '20px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Activity",
      color: C.gold
    }), /*#__PURE__*/React__default.default.createElement(designSystem.H5, {
      style: {
        color: C.text,
        margin: 0
      }
    }, "User Growth"), /*#__PURE__*/React__default.default.createElement(designSystem.Badge, {
      style: {
        marginLeft: '8px',
        backgroundColor: C.goldDim,
        color: C.gold,
        border: 'none'
      }
    }, "30 days")), growthChartData.length > 0 ? /*#__PURE__*/React__default.default.createElement(AreaChart, {
      data: growthChartData,
      color: C.gold,
      width: 600,
      height: 220
    }) : /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        height: 200,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textDim
      }
    }, "No user signups in the last 30 days."))), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      style: {
        ...cardStyle(),
        flex: '1',
        minWidth: '300px'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '20px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "PieChart",
      color: C.blue
    }), /*#__PURE__*/React__default.default.createElement(designSystem.H5, {
      style: {
        color: C.text,
        margin: 0
      }
    }, "Mods by Platform")), modsByPlatform.length > 0 ? /*#__PURE__*/React__default.default.createElement(DonutChart, {
      data: modsByPlatform,
      size: 180
    }) : /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        height: 180,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textDim
      }
    }, "No platform data available.")))), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '20px',
        marginBottom: '32px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      style: {
        ...cardStyle(),
        flex: '1',
        minWidth: '340px'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '20px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Users",
      color: C.blue
    }), /*#__PURE__*/React__default.default.createElement(designSystem.H5, {
      style: {
        color: C.text,
        margin: 0
      }
    }, "Recent Users"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/User",
      style: {
        marginLeft: 'auto',
        color: C.gold,
        fontSize: '12px',
        textDecoration: 'none',
        fontWeight: 600
      }
    }, "View All \u2192")), recentUsers.length > 0 ? /*#__PURE__*/React__default.default.createElement("table", {
      style: {
        width: '100%',
        borderCollapse: 'collapse'
      }
    }, /*#__PURE__*/React__default.default.createElement("thead", null, /*#__PURE__*/React__default.default.createElement("tr", {
      style: {
        borderBottom: `1px solid ${C.border}`
      }
    }, /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'left',
        padding: '8px 0',
        color: C.textDim,
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Username"), /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'left',
        padding: '8px 0',
        color: C.textDim,
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Role"), /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'right',
        padding: '8px 0',
        color: C.textDim,
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Joined"))), /*#__PURE__*/React__default.default.createElement("tbody", null, recentUsers.map((u, i) => /*#__PURE__*/React__default.default.createElement("tr", {
      key: i,
      style: {
        borderBottom: `1px solid ${C.border}`
      }
    }, /*#__PURE__*/React__default.default.createElement("td", {
      style: {
        padding: '10px 0',
        color: C.text,
        fontSize: '13px',
        fontWeight: 500
      }
    }, u.username), /*#__PURE__*/React__default.default.createElement("td", {
      style: {
        padding: '10px 0'
      }
    }, /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        fontSize: '11px',
        padding: '3px 8px',
        borderRadius: '6px',
        backgroundColor: u.role === 'admin' ? `${C.gold}20` : `${C.blue}20`,
        color: u.role === 'admin' ? C.gold : C.blue,
        fontWeight: 600
      }
    }, u.role || 'user')), /*#__PURE__*/React__default.default.createElement("td", {
      style: {
        padding: '10px 0',
        color: C.textMuted,
        fontSize: '12px',
        textAlign: 'right'
      }
    }, fmtDate(u.date)))))) : /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textDim,
        textAlign: 'center',
        padding: '20px 0'
      }
    }, "No recent users.")), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      style: {
        ...cardStyle(),
        flex: '1',
        minWidth: '340px'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '20px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Package",
      color: C.gold
    }), /*#__PURE__*/React__default.default.createElement(designSystem.H5, {
      style: {
        color: C.text,
        margin: 0
      }
    }, "Recent Mods"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/File",
      style: {
        marginLeft: 'auto',
        color: C.gold,
        fontSize: '12px',
        textDecoration: 'none',
        fontWeight: 600
      }
    }, "View All \u2192")), recentMods.length > 0 ? /*#__PURE__*/React__default.default.createElement("table", {
      style: {
        width: '100%',
        borderCollapse: 'collapse'
      }
    }, /*#__PURE__*/React__default.default.createElement("thead", null, /*#__PURE__*/React__default.default.createElement("tr", {
      style: {
        borderBottom: `1px solid ${C.border}`
      }
    }, /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'left',
        padding: '8px 0',
        color: C.textDim,
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Name"), /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'left',
        padding: '8px 0',
        color: C.textDim,
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Platform"), /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'left',
        padding: '8px 0',
        color: C.textDim,
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Status"), /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'right',
        padding: '8px 0',
        color: C.textDim,
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Added"))), /*#__PURE__*/React__default.default.createElement("tbody", null, recentMods.map((m, i) => /*#__PURE__*/React__default.default.createElement("tr", {
      key: i,
      style: {
        borderBottom: `1px solid ${C.border}`
      }
    }, /*#__PURE__*/React__default.default.createElement("td", {
      style: {
        padding: '10px 0',
        color: C.text,
        fontSize: '13px',
        fontWeight: 500,
        maxWidth: '180px',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap'
      }
    }, m.name), /*#__PURE__*/React__default.default.createElement("td", {
      style: {
        padding: '10px 0'
      }
    }, /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        fontSize: '11px',
        padding: '3px 8px',
        borderRadius: '6px',
        backgroundColor: `${C.blue}20`,
        color: C.blue,
        fontWeight: 600,
        textTransform: 'uppercase'
      }
    }, m.category || '—')), /*#__PURE__*/React__default.default.createElement("td", {
      style: {
        padding: '10px 0'
      }
    }, /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        fontSize: '11px',
        padding: '3px 8px',
        borderRadius: '6px',
        backgroundColor: `${statusColor(m.status)}20`,
        color: statusColor(m.status),
        fontWeight: 600,
        textTransform: 'capitalize'
      }
    }, m.status || '—')), /*#__PURE__*/React__default.default.createElement("td", {
      style: {
        padding: '10px 0',
        color: C.textMuted,
        fontSize: '12px',
        textAlign: 'right'
      }
    }, fmtDate(m.date)))))) : /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textDim,
        textAlign: 'center',
        padding: '20px 0'
      }
    }, "No recent mods."))), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingTop: '20px',
        borderTop: `1px solid ${C.border}`
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textDim,
        fontSize: '12px'
      }
    }, /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: C.gold,
        fontWeight: 700
      }
    }, "GPL"), " ", /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: '#888'
      }
    }, "Mods"), " \u2022 Admin Panel v2.5"), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        gap: '16px'
      }
    }, /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/User",
      style: {
        color: C.textMuted,
        fontSize: '12px',
        textDecoration: 'none'
      }
    }, "Users"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/File",
      style: {
        color: C.textMuted,
        fontSize: '12px',
        textDecoration: 'none'
      }
    }, "Mods"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/Report",
      style: {
        color: C.textMuted,
        fontSize: '12px',
        textDecoration: 'none'
      }
    }, "Reports"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/SupportTicket",
      style: {
        color: C.textMuted,
        fontSize: '12px',
        textDecoration: 'none'
      }
    }, "Tickets"))));
  };

  const SidebarBranding = () => {
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      alignItems: "center",
      justifyContent: "center",
      p: "lg",
      style: {
        borderBottom: '1px solid #2a2a2a',
        backgroundColor: '#0a0a0a',
        padding: '22px 0',
        position: 'relative',
        overflow: 'hidden'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        position: 'absolute',
        bottom: 0,
        left: '50%',
        transform: 'translateX(-50%)',
        width: '60%',
        height: '1px',
        background: 'linear-gradient(90deg, transparent, rgba(255,215,0,0.5), transparent)'
      }
    }), /*#__PURE__*/React__default.default.createElement(designSystem.Link, {
      to: "/admin",
      style: {
        textDecoration: 'none',
        display: 'flex',
        alignItems: 'center',
        gap: '10px'
      }
    }, /*#__PURE__*/React__default.default.createElement("img", {
      src: "/images/logo.png",
      alt: "Logo",
      style: {
        height: '32px',
        width: 'auto',
        filter: 'drop-shadow(0 0 6px rgba(255,215,0,0.3))'
      },
      onError: e => e.target.style.display = 'none'
    }), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        fontSize: '22px',
        fontWeight: 'bold',
        fontFamily: 'Inter, system-ui, sans-serif',
        display: 'flex',
        alignItems: 'baseline',
        gap: '4px'
      }
    }, /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: '#FFD700',
        textShadow: '0 0 12px rgba(255, 215, 0, 0.4)'
      }
    }, "GPL"), /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: '#c0c0c0'
      }
    }, "Mods"), /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        fontSize: '9px',
        color: '#555',
        fontWeight: 600,
        marginLeft: '6px',
        letterSpacing: '0.05em'
      }
    }, "v2.5"))));
  };

  const ActionRedirect = props => {
    const {
      record,
      action
    } = props;
    const sendNotice = adminjs.useNotice();
    React.useEffect(() => {
      const url = record?.params?.redirectUrl;
      if (url) {
        setTimeout(() => {
          window.open(url, '_blank');
        }, 500);
      } else {
        sendNotice({
          message: 'Error: No redirect URL provided.',
          type: 'error'
        });
      }
    }, [record]);
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      p: "xxl"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Loader, null), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      mt: "lg",
      variant: "h4"
    }, "Redirecting..."));
  };

  const VariantBadge = props => {
    const {
      record,
      property
    } = props;
    const isVariant = record.params[property.name];
    if (isVariant === true || isVariant === 'true') {
      return /*#__PURE__*/React__default.default.createElement(designSystem.Badge, {
        variant: "primary",
        style: {
          backgroundColor: '#2196F3',
          color: '#fff',
          border: 'none'
        }
      }, "Variant");
    }
    return /*#__PURE__*/React__default.default.createElement(designSystem.Badge, {
      style: {
        backgroundColor: '#333',
        color: '#aaa',
        border: '1px solid #555'
      }
    }, "Master");
  };

  const AvatarCell = props => {
    const {
      record,
      property,
      where
    } = props;
    const key = record.params[property.name];
    const username = record.params.username || 'User';
    const [imageUrl, setImageUrl] = React.useState(null);
    const [loading, setLoading] = React.useState(true);
    const [hasError, setHasError] = React.useState(false);
    React.useEffect(() => {
      if (!key) {
        setLoading(false);
        return;
      }
      if (key.startsWith('http://') || key.startsWith('https://')) {
        setImageUrl(key);
        setLoading(false);
        return;
      }
      const fetchSignedUrl = async () => {
        try {
          const response = await fetch(`/api/admin/signed-url?key=${encodeURIComponent(key)}`);
          if (response.ok) {
            const data = await response.json();
            setImageUrl(data.url);
          } else {
            setHasError(true);
          }
        } catch (error) {
          console.error("Error fetching avatar URL:", error);
          setHasError(true);
        } finally {
          setLoading(false);
        }
      };
      fetchSignedUrl();
    }, [key]);
    const size = where === 'list' ? '32px' : '120px';
    if (loading) {
      return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
        style: {
          width: size,
          height: size,
          borderRadius: '50%',
          backgroundColor: '#333'
        }
      });
    }
    if (!imageUrl || hasError) {
      return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
        style: {
          width: size,
          height: size,
          borderRadius: '50%',
          backgroundColor: '#FFD700',
          color: '#0a0a0a',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 'bold',
          fontSize: where === 'list' ? '14px' : '48px',
          border: '2px solid #333'
        }
      }, username.charAt(0).toUpperCase());
    }
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, null, /*#__PURE__*/React__default.default.createElement("img", {
      src: imageUrl,
      alt: username,
      style: {
        width: size,
        height: size,
        borderRadius: '50%',
        objectFit: 'cover',
        border: '2px solid #FFD700'
      },
      onError: () => setHasError(true)
    }));
  };

  const ImagePreview = props => {
    const {
      record,
      property,
      where
    } = props;
    const value = record.params[property.name];
    const [imageUrl, setImageUrl] = React.useState(null);
    const [loading, setLoading] = React.useState(true);
    React.useEffect(() => {
      if (!value) {
        setLoading(false);
        return;
      }
      if (value.startsWith('http://') || value.startsWith('https://')) {
        setImageUrl(value);
        setLoading(false);
        return;
      }
      const fetchSignedUrl = async () => {
        try {
          const response = await fetch(`/api/admin/signed-url?key=${encodeURIComponent(value)}`);
          if (response.ok) {
            const data = await response.json();
            setImageUrl(data.url);
          } else {
            console.error("Failed to fetch signed URL.");
          }
        } catch (error) {
          console.error("Network error fetching signed URL:", error);
        } finally {
          setLoading(false);
        }
      };
      fetchSignedUrl();
    }, [value]);
    if (loading) return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      style: {
        color: '#FFD700',
        fontSize: '12px'
      }
    }, "Loading...");
    if (!imageUrl) return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      style: {
        color: '#888',
        fontSize: '12px'
      }
    }, "N/A");
    const size = where === 'list' ? '40px' : '150px';
    const radius = property.name === 'profileImageKey' ? '50%' : '8px';
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, null, /*#__PURE__*/React__default.default.createElement("img", {
      src: imageUrl,
      alt: "Preview",
      style: {
        width: size,
        height: size,
        borderRadius: radius,
        objectFit: 'cover',
        backgroundColor: '#1a1a1a',
        border: '1px solid #333'
      }
    }));
  };

  const api = new adminjs.ApiClient();
  const ManageVotes = props => {
    const {
      record,
      resource
    } = props;
    const addNotice = adminjs.useNotice();
    const [workingCount, setWorkingCount] = React.useState(record.params.workingVoteCount || 0);
    const [notWorkingCount, setNotWorkingCount] = React.useState(record.params.notWorkingVoteCount || 0);
    const [isLoading, setIsLoading] = React.useState(false);
    const handleSubmit = actionType => {
      if (actionType === 'reset' && !window.confirm("Are you sure you want to permanently delete all user votes for this mod?")) {
        return;
      }
      setIsLoading(true);
      api.resourceAction({
        resourceId: resource.id,
        actionName: 'manageVotes',
        recordId: record.id,
        method: 'post',
        data: {
          actionType: actionType,
          newWorkingCount: workingCount,
          newNotWorkingCount: notWorkingCount
        }
      }).then(response => {
        setIsLoading(false);
        if (response.data.notice) {
          addNotice(response.data.notice);
        }
        if (response.data.redirectUrl) {
          window.location.href = response.data.redirectUrl;
        }
      }).catch(error => {
        setIsLoading(false);
        addNotice({
          message: 'An error occurred while contacting the server.',
          type: 'error'
        });
      });
    };
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      variant: "white",
      p: "xl",
      style: {
        backgroundColor: '#1a1a1a',
        borderRadius: '8px',
        border: '1px solid #333'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.H3, {
      style: {
        color: '#FFD700',
        marginBottom: '20px'
      }
    }, "Manage Votes for: ", record.params.name), /*#__PURE__*/React__default.default.createElement(designSystem.NoticeBox, {
      style: {
        marginBottom: '30px'
      }
    }, /*#__PURE__*/React__default.default.createElement("strong", null, "Current Status:"), /*#__PURE__*/React__default.default.createElement("br", null), "Working Votes: ", /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: '#43a047',
        fontWeight: 'bold'
      }
    }, record.params.workingVoteCount || 0), /*#__PURE__*/React__default.default.createElement("br", null), "Not Working Votes: ", /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: '#e53935',
        fontWeight: 'bold'
      }
    }, record.params.notWorkingVoteCount || 0)), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      mb: "xxl",
      p: "lg",
      style: {
        border: '1px solid #444',
        borderRadius: '8px',
        backgroundColor: '#0a0a0a'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.H3, {
      style: {
        color: '#ffffff',
        fontSize: '1.2em'
      }
    }, "Option 1: Reset All Votes"), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#c0c0c0',
        marginBottom: '15px'
      }
    }, "This will wipe all existing user votes and reset both counts to 0. This is highly recommended when a major update is released that fixes a broken mod."), /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      variant: "danger",
      onClick: () => handleSubmit('reset'),
      disabled: isLoading
    }, isLoading ? 'Processing...' : 'Wipe & Reset Votes to 0')), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      p: "lg",
      style: {
        border: '1px solid #444',
        borderRadius: '8px',
        backgroundColor: '#0a0a0a'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.H3, {
      style: {
        color: '#ffffff',
        fontSize: '1.2em'
      }
    }, "Option 2: Manually Override Counts"), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#ffadad',
        marginBottom: '15px',
        fontSize: '0.9em'
      }
    }, "Warning: Manually setting numbers will clear the internal list of users who voted. Use this only if you need to artificially boost or reduce a score."), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      style: {
        gap: '20px',
        marginBottom: '20px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.FormGroup, {
      style: {
        flex: 1
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Label, {
      style: {
        color: '#c0c0c0'
      }
    }, "Force \"Working\" Count"), /*#__PURE__*/React__default.default.createElement(designSystem.Input, {
      type: "number",
      value: workingCount,
      onChange: e => setWorkingCount(e.target.value),
      style: {
        backgroundColor: '#1a1a1a',
        color: 'white',
        border: '1px solid #333'
      }
    })), /*#__PURE__*/React__default.default.createElement(designSystem.FormGroup, {
      style: {
        flex: 1
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Label, {
      style: {
        color: '#c0c0c0'
      }
    }, "Force \"Not Working\" Count"), /*#__PURE__*/React__default.default.createElement(designSystem.Input, {
      type: "number",
      value: notWorkingCount,
      onChange: e => setNotWorkingCount(e.target.value),
      style: {
        backgroundColor: '#1a1a1a',
        color: 'white',
        border: '1px solid #333'
      }
    }))), /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      variant: "primary",
      onClick: () => handleSubmit('override'),
      disabled: isLoading,
      style: {
        backgroundColor: '#FFD700',
        color: 'black',
        border: 'none'
      }
    }, isLoading ? 'Processing...' : 'Apply Manual Override')));
  };

  AdminJS.UserComponents = {};
  AdminJS.env.NODE_ENV = "production";
  AdminJS.UserComponents.Dashboard = CustomDashboard;
  AdminJS.UserComponents.SidebarBranding = SidebarBranding;
  AdminJS.UserComponents.ActionRedirect = ActionRedirect;
  AdminJS.UserComponents.VariantBadge = VariantBadge;
  AdminJS.UserComponents.AvatarCell = AvatarCell;
  AdminJS.UserComponents.ImagePreview = ImagePreview;
  AdminJS.UserComponents.ManageVotes = ManageVotes;

})(React, AdminJS, AdminJSDesignSystem);
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIiwic291cmNlcyI6WyIuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQuanN4IiwiLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nLmpzeCIsIi4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdC5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL1ZhcmlhbnRCYWRnZS5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL0F2YXRhckNlbGwuanN4IiwiLi4vY29tcG9uZW50cy9jZWxscy9JbWFnZVByZXZpZXcuanN4IiwiLi4vY29tcG9uZW50cy9hY3Rpb25zL01hbmFnZVZvdGVzLmpzeCIsImVudHJ5LmpzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQXBpQ2xpZW50IH0gZnJvbSAnYWRtaW5qcyc7XG5pbXBvcnQgeyBCb3gsIEgyLCBINSwgVGV4dCwgSWNvbiwgQmFkZ2UgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgYXBpID0gbmV3IEFwaUNsaWVudCgpO1xuXG4vKiDilIDilIDilIAgY29sb3VyIHRva2VucyDilIDilIDilIAgKi9cbmNvbnN0IEMgPSB7XG4gIGJnOiAnIzBhMGEwYScsIHN1cmZhY2U6ICcjMTMxMzEzJywgc3VyZmFjZUFsdDogJyMxYTFhMWEnLFxuICBib3JkZXI6ICcjMmEyYTJhJywgYm9yZGVySG92ZXI6ICcjM2EzYTNhJyxcbiAgZ29sZDogJyNGRkQ3MDAnLCBnb2xkRGltOiAncmdiYSgyNTUsMjE1LDAsMC4xNSknLCBnb2xkR2xvdzogJ3JnYmEoMjU1LDIxNSwwLDAuMzUpJyxcbiAgYmx1ZTogJyMyMTk2RjMnLCBncmVlbjogJyM0M2EwNDcnLCBwdXJwbGU6ICcjOUMyN0IwJywgcmVkOiAnI2U1MzkzNScsIG9yYW5nZTogJyNGRjk4MDAnLFxuICB0ZXh0OiAnI2ZmZmZmZicsIHRleHRNdXRlZDogJyM5OTknLCB0ZXh0RGltOiAnIzY2NicsXG59O1xuXG4vKiDilIDilIDilIAgcGxhdGZvcm0gY2hhcnQgY29sb3VycyDilIDilIDilIAgKi9cbmNvbnN0IFBMQVRGT1JNX0NPTE9SUyA9IFsnI0E0QzYzOScsICcjMDA3OEQ2JywgJyMyMTc1OUInLCAnI0ZGOTgwMCcsICcjOUMyN0IwJywgJyNlNTM5MzUnLCAnIzQzYTA0NycsICcjRkZENzAwJ107XG5cbi8qIOKUgOKUgOKUgCByZXVzYWJsZSBjYXJkIHN0eWxlIOKUgOKUgOKUgCAqL1xuY29uc3QgY2FyZFN0eWxlID0gKGFjY2VudENvbG9yKSA9PiAoe1xuICBiYWNrZ3JvdW5kQ29sb3I6IEMuc3VyZmFjZSxcbiAgYm9yZGVyUmFkaXVzOiAnMTZweCcsXG4gIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsXG4gIGJvcmRlckxlZnQ6IGFjY2VudENvbG9yID8gYDRweCBzb2xpZCAke2FjY2VudENvbG9yfWAgOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCxcbiAgcGFkZGluZzogJzI0cHgnLFxuICB0cmFuc2l0aW9uOiAnYWxsIDAuMjVzIGVhc2UnLFxuICBjdXJzb3I6ICdkZWZhdWx0Jyxcbn0pO1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBBcmVhIENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgQXJlYUNoYXJ0ID0gKHsgZGF0YSwgd2lkdGggPSA1MDAsIGhlaWdodCA9IDIwMCwgY29sb3IgPSBDLmdvbGQgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBtYXhWYWwgPSBNYXRoLm1heCguLi5kYXRhLm1hcChkID0+IGQudmFsdWUpLCAxKTtcbiAgY29uc3QgcGFkWCA9IDQwO1xuICBjb25zdCBwYWRZID0gMjA7XG4gIGNvbnN0IGNoYXJ0VyA9IHdpZHRoIC0gcGFkWCAqIDI7XG4gIGNvbnN0IGNoYXJ0SCA9IGhlaWdodCAtIHBhZFkgKiAyO1xuXG4gIGNvbnN0IHBvaW50cyA9IGRhdGEubWFwKChkLCBpKSA9PiAoe1xuICAgIHg6IHBhZFggKyAoaSAvIE1hdGgubWF4KGRhdGEubGVuZ3RoIC0gMSwgMSkpICogY2hhcnRXLFxuICAgIHk6IHBhZFkgKyBjaGFydEggLSAoZC52YWx1ZSAvIG1heFZhbCkgKiBjaGFydEgsXG4gIH0pKTtcblxuICBjb25zdCBsaW5lUGF0aCA9IHBvaW50cy5tYXAoKHAsIGkpID0+IGAke2kgPT09IDAgPyAnTScgOiAnTCd9JHtwLnh9LCR7cC55fWApLmpvaW4oJyAnKTtcbiAgY29uc3QgYXJlYVBhdGggPSBgJHtsaW5lUGF0aH0gTCR7cG9pbnRzW3BvaW50cy5sZW5ndGggLSAxXS54fSwke3BhZFkgKyBjaGFydEh9IEwke3BvaW50c1swXS54fSwke3BhZFkgKyBjaGFydEh9IFpgO1xuXG4gIC8vIEdyaWQgbGluZXNcbiAgY29uc3QgZ3JpZExpbmVzID0gWzAsIDAuMjUsIDAuNSwgMC43NSwgMV0ubWFwKHBjdCA9PiB7XG4gICAgY29uc3QgeSA9IHBhZFkgKyBjaGFydEggLSBwY3QgKiBjaGFydEg7XG4gICAgY29uc3QgbGFiZWwgPSBNYXRoLnJvdW5kKHBjdCAqIG1heFZhbCk7XG4gICAgcmV0dXJuIHsgeSwgbGFiZWwgfTtcbiAgfSk7XG5cbiAgcmV0dXJuIChcbiAgICA8c3ZnIHdpZHRoPVwiMTAwJVwiIGhlaWdodD17aGVpZ2h0fSB2aWV3Qm94PXtgMCAwICR7d2lkdGh9ICR7aGVpZ2h0fWB9IHByZXNlcnZlQXNwZWN0UmF0aW89XCJ4TWlkWU1pZCBtZWV0XCI+XG4gICAgICA8ZGVmcz5cbiAgICAgICAgPGxpbmVhckdyYWRpZW50IGlkPVwiYXJlYUZpbGxcIiB4MT1cIjBcIiB5MT1cIjBcIiB4Mj1cIjBcIiB5Mj1cIjFcIj5cbiAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIwJVwiIHN0b3BDb2xvcj17Y29sb3J9IHN0b3BPcGFjaXR5PVwiMC4zXCIgLz5cbiAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIxMDAlXCIgc3RvcENvbG9yPXtjb2xvcn0gc3RvcE9wYWNpdHk9XCIwLjAyXCIgLz5cbiAgICAgICAgPC9saW5lYXJHcmFkaWVudD5cbiAgICAgIDwvZGVmcz5cbiAgICAgIHsvKiBHcmlkICovfVxuICAgICAge2dyaWRMaW5lcy5tYXAoKGcsIGkpID0+IChcbiAgICAgICAgPGcga2V5PXtpfT5cbiAgICAgICAgICA8bGluZSB4MT17cGFkWH0geTE9e2cueX0geDI9e3dpZHRoIC0gcGFkWH0geTI9e2cueX0gc3Ryb2tlPXtDLmJvcmRlcn0gc3Ryb2tlV2lkdGg9XCIxXCIgc3Ryb2tlRGFzaGFycmF5PVwiNCA0XCIgLz5cbiAgICAgICAgICA8dGV4dCB4PXtwYWRYIC0gNn0geT17Zy55ICsgNH0gZmlsbD17Qy50ZXh0RGltfSBmb250U2l6ZT1cIjEwXCIgdGV4dEFuY2hvcj1cImVuZFwiPntnLmxhYmVsfTwvdGV4dD5cbiAgICAgICAgPC9nPlxuICAgICAgKSl9XG4gICAgICB7LyogQXJlYSBmaWxsICovfVxuICAgICAgPHBhdGggZD17YXJlYVBhdGh9IGZpbGw9XCJ1cmwoI2FyZWFGaWxsKVwiIC8+XG4gICAgICB7LyogTGluZSAqL31cbiAgICAgIDxwYXRoIGQ9e2xpbmVQYXRofSBmaWxsPVwibm9uZVwiIHN0cm9rZT17Y29sb3J9IHN0cm9rZVdpZHRoPVwiMi41XCIgc3Ryb2tlTGluZWpvaW49XCJyb3VuZFwiIHN0cm9rZUxpbmVjYXA9XCJyb3VuZFwiIC8+XG4gICAgICB7LyogRG90cyArIGxhYmVscyAqL31cbiAgICAgIHtwb2ludHMubWFwKChwLCBpKSA9PiAoXG4gICAgICAgIDxnIGtleT17aX0+XG4gICAgICAgICAgPGNpcmNsZSBjeD17cC54fSBjeT17cC55fSByPVwiNFwiIGZpbGw9e0MuYmd9IHN0cm9rZT17Y29sb3J9IHN0cm9rZVdpZHRoPVwiMlwiIC8+XG4gICAgICAgICAgPHRleHQgeD17cC54fSB5PXtwYWRZICsgY2hhcnRIICsgMTZ9IGZpbGw9e0MudGV4dE11dGVkfSBmb250U2l6ZT1cIjlcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e2RhdGFbaV0ubGFiZWx9PC90ZXh0PlxuICAgICAgICA8L2c+XG4gICAgICApKX1cbiAgICA8L3N2Zz5cbiAgKTtcbn07XG5cbi8qIOKUgOKUgOKUgCBJbmxpbmUgU1ZHIERvbnV0IENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgRG9udXRDaGFydCA9ICh7IGRhdGEsIHNpemUgPSAyMDAgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCB0b3RhbCA9IGRhdGEucmVkdWNlKChzLCBkKSA9PiBzICsgZC52YWx1ZSwgMCk7XG4gIGlmICh0b3RhbCA9PT0gMCkgcmV0dXJuIG51bGw7XG4gIGNvbnN0IGN4ID0gc2l6ZSAvIDI7XG4gIGNvbnN0IGN5ID0gc2l6ZSAvIDI7XG4gIGNvbnN0IG91dGVyUiA9IHNpemUgLyAyIC0gMTA7XG4gIGNvbnN0IGlubmVyUiA9IG91dGVyUiAqIDAuNjtcbiAgbGV0IGN1bUFuZ2xlID0gLU1hdGguUEkgLyAyO1xuXG4gIGNvbnN0IHNsaWNlcyA9IGRhdGEubWFwKChkLCBpKSA9PiB7XG4gICAgY29uc3QgYW5nbGUgPSAoZC52YWx1ZSAvIHRvdGFsKSAqIE1hdGguUEkgKiAyO1xuICAgIGNvbnN0IHN0YXJ0QW5nbGUgPSBjdW1BbmdsZTtcbiAgICBjdW1BbmdsZSArPSBhbmdsZTtcbiAgICBjb25zdCBlbmRBbmdsZSA9IGN1bUFuZ2xlO1xuXG4gICAgY29uc3QgeDEgPSBjeCArIG91dGVyUiAqIE1hdGguY29zKHN0YXJ0QW5nbGUpO1xuICAgIGNvbnN0IHkxID0gY3kgKyBvdXRlclIgKiBNYXRoLnNpbihzdGFydEFuZ2xlKTtcbiAgICBjb25zdCB4MiA9IGN4ICsgb3V0ZXJSICogTWF0aC5jb3MoZW5kQW5nbGUpO1xuICAgIGNvbnN0IHkyID0gY3kgKyBvdXRlclIgKiBNYXRoLnNpbihlbmRBbmdsZSk7XG4gICAgY29uc3QgaXgxID0gY3ggKyBpbm5lclIgKiBNYXRoLmNvcyhlbmRBbmdsZSk7XG4gICAgY29uc3QgaXkxID0gY3kgKyBpbm5lclIgKiBNYXRoLnNpbihlbmRBbmdsZSk7XG4gICAgY29uc3QgaXgyID0gY3ggKyBpbm5lclIgKiBNYXRoLmNvcyhzdGFydEFuZ2xlKTtcbiAgICBjb25zdCBpeTIgPSBjeSArIGlubmVyUiAqIE1hdGguc2luKHN0YXJ0QW5nbGUpO1xuICAgIGNvbnN0IGxhcmdlQXJjID0gYW5nbGUgPiBNYXRoLlBJID8gMSA6IDA7XG4gICAgY29uc3QgY29sb3IgPSBQTEFURk9STV9DT0xPUlNbaSAlIFBMQVRGT1JNX0NPTE9SUy5sZW5ndGhdO1xuXG4gICAgY29uc3QgcGF0aCA9IGBNJHt4MX0sJHt5MX0gQSR7b3V0ZXJSfSwke291dGVyUn0gMCAke2xhcmdlQXJjfSAxICR7eDJ9LCR7eTJ9IEwke2l4MX0sJHtpeTF9IEEke2lubmVyUn0sJHtpbm5lclJ9IDAgJHtsYXJnZUFyY30gMCAke2l4Mn0sJHtpeTJ9IFpgO1xuICAgIHJldHVybiB7IHBhdGgsIGNvbG9yLCBuYW1lOiBkLm5hbWUsIHZhbHVlOiBkLnZhbHVlLCBwY3Q6IE1hdGgucm91bmQoKGQudmFsdWUgLyB0b3RhbCkgKiAxMDApIH07XG4gIH0pO1xuXG4gIHJldHVybiAoXG4gICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcyNHB4JywgZmxleFdyYXA6ICd3cmFwJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInIH19PlxuICAgICAgPHN2ZyB3aWR0aD17c2l6ZX0gaGVpZ2h0PXtzaXplfSB2aWV3Qm94PXtgMCAwICR7c2l6ZX0gJHtzaXplfWB9PlxuICAgICAgICB7c2xpY2VzLm1hcCgocywgaSkgPT4gKFxuICAgICAgICAgIDxwYXRoIGtleT17aX0gZD17cy5wYXRofSBmaWxsPXtzLmNvbG9yfSBzdHJva2U9e0MuYmd9IHN0cm9rZVdpZHRoPVwiMlwiPlxuICAgICAgICAgICAgPHRpdGxlPntzLm5hbWV9OiB7cy52YWx1ZX0gKHtzLnBjdH0lKTwvdGl0bGU+XG4gICAgICAgICAgPC9wYXRoPlxuICAgICAgICApKX1cbiAgICAgICAgPHRleHQgeD17Y3h9IHk9e2N5IC0gNn0gZmlsbD17Qy50ZXh0fSBmb250U2l6ZT1cIjIyXCIgZm9udFdlaWdodD1cImJvbGRcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e3RvdGFsfTwvdGV4dD5cbiAgICAgICAgPHRleHQgeD17Y3h9IHk9e2N5ICsgMTR9IGZpbGw9e0MudGV4dE11dGVkfSBmb250U2l6ZT1cIjEwXCIgdGV4dEFuY2hvcj1cIm1pZGRsZVwiPlRPVEFMPC90ZXh0PlxuICAgICAgPC9zdmc+XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleERpcmVjdGlvbjogJ2NvbHVtbicsIGdhcDogJzZweCcgfX0+XG4gICAgICAgIHtzbGljZXMubWFwKChzLCBpKSA9PiAoXG4gICAgICAgICAgPGRpdiBrZXk9e2l9IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIGZvbnRTaXplOiAnMTJweCcgfX0+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyB3aWR0aDogMTIsIGhlaWdodDogMTIsIGJvcmRlclJhZGl1czogJzNweCcsIGJhY2tncm91bmRDb2xvcjogcy5jb2xvciwgZGlzcGxheTogJ2lubGluZS1ibG9jaycsIGZsZXhTaHJpbms6IDAgfX0gLz5cbiAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLnRleHQgfX0+e3MubmFtZX08L3NwYW4+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCBtYXJnaW5MZWZ0OiAnYXV0bycgfX0+e3MudmFsdWV9ICh7cy5wY3R9JSk8L3NwYW4+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICkpfVxuICAgICAgPC9kaXY+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG4vKiDilIDilIDilIAgU3RhdCBDYXJkIOKUgOKUgOKUgCAqL1xuY29uc3QgU3RhdENhcmQgPSAoeyBpY29uLCBsYWJlbCwgdmFsdWUsIGRlbHRhLCBkZWx0YUxhYmVsLCBhY2NlbnRDb2xvciB9KSA9PiAoXG4gIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKGFjY2VudENvbG9yKSwgZmxleDogJzEnLCBtaW5XaWR0aDogJzIyMHB4JyB9fVxuICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IGFjY2VudENvbG9yIHx8IEMuYm9yZGVySG92ZXI7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgtMnB4KSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSBgMCA4cHggMjRweCByZ2JhKDAsMCwwLDAuNClgOyB9fVxuICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuYm9yZGVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyTGVmdENvbG9yID0gYWNjZW50Q29sb3I7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgwKSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnbm9uZSc7IH19XG4gID5cbiAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE0cHgnIH19PlxuICAgICAgPEljb24gaWNvbj17aWNvbn0gY29sb3I9e2FjY2VudENvbG9yfSAvPlxuICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzExcHgnLCBmb250V2VpZ2h0OiA3MDAsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wOGVtJyB9fT57bGFiZWx9PC9UZXh0PlxuICAgIDwvZGl2PlxuICAgIDxIMiBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46ICcwIDAgOHB4IDAnLCBmb250U2l6ZTogJzIuMnJlbScgfX0+e3ZhbHVlfTwvSDI+XG4gICAge2RlbHRhICE9PSB1bmRlZmluZWQgJiYgKFxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnIH19PlxuICAgICAgICA8SWNvbiBpY29uPVwiQXJyb3dVcFwiIHNpemU9ezE0fSBjb2xvcj17Qy5ncmVlbn0gLz5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMuZ3JlZW4sIGZvbnRTaXplOiAnMTNweCcsIGZvbnRXZWlnaHQ6IDYwMCB9fT4re2RlbHRhfSB7ZGVsdGFMYWJlbCB8fCAndGhpcyBtb250aCd9PC9UZXh0PlxuICAgICAgPC9kaXY+XG4gICAgKX1cbiAgPC9Cb3g+XG4pO1xuXG4vKiDilIDilIDilIAgQWN0aW9uIEJhZGdlIENhcmQg4pSA4pSA4pSAICovXG5jb25zdCBBY3Rpb25DYXJkID0gKHsgaWNvbiwgbGFiZWwsIGNvdW50LCBhY2NlbnRDb2xvciwgcmVzb3VyY2VJZCB9KSA9PiAoXG4gIDxhIGhyZWY9e2AvYWRtaW4vcmVzb3VyY2VzLyR7cmVzb3VyY2VJZH1gfSBzdHlsZT17eyB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmbGV4OiAnMScsIG1pbldpZHRoOiAnMTgwcHgnIH19PlxuICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKGFjY2VudENvbG9yKSwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMTZweCcgfX1cbiAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoLTJweCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gYDAgNnB4IDIwcHggcmdiYSgwLDAsMCwwLjMpYDsgfX1cbiAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuYm9yZGVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyTGVmdENvbG9yID0gYWNjZW50Q29sb3I7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgwKSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnbm9uZSc7IH19XG4gICAgPlxuICAgICAgPGRpdiBzdHlsZT17eyB3aWR0aDogNDQsIGhlaWdodDogNDQsIGJvcmRlclJhZGl1czogJzEycHgnLCBiYWNrZ3JvdW5kQ29sb3I6IGAke2FjY2VudENvbG9yfTE1YCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLCBmbGV4U2hyaW5rOiAwIH19PlxuICAgICAgICA8SWNvbiBpY29uPXtpY29ufSBzaXplPXsyMn0gY29sb3I9e2FjY2VudENvbG9yfSAvPlxuICAgICAgPC9kaXY+XG4gICAgICA8ZGl2PlxuICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTFweCcsIGZvbnRXZWlnaHQ6IDYwMCwgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nIH19PntsYWJlbH08L1RleHQ+XG4gICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogY291bnQgPiAwID8gYWNjZW50Q29sb3IgOiBDLnRleHREaW0sIG1hcmdpbjogJzRweCAwIDAgMCcgfX0+e2NvdW50fTwvSDU+XG4gICAgICA8L2Rpdj5cbiAgICAgIDxJY29uIGljb249XCJDaGV2cm9uUmlnaHRcIiBjb2xvcj17Qy50ZXh0RGltfSBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnYXV0bycgfX0gLz5cbiAgICA8L0JveD5cbiAgPC9hPlxuKTtcblxuLyog4pSA4pSA4pSAIEZvcm1hdCBkYXRlIG5pY2VseSDilIDilIDilIAgKi9cbmNvbnN0IGZtdERhdGUgPSAoZCkgPT4ge1xuICBpZiAoIWQpIHJldHVybiAn4oCUJztcbiAgY29uc3QgZHQgPSBuZXcgRGF0ZShkKTtcbiAgcmV0dXJuIGR0LnRvTG9jYWxlRGF0ZVN0cmluZygnZW4tVVMnLCB7IG1vbnRoOiAnc2hvcnQnLCBkYXk6ICdudW1lcmljJywgeWVhcjogJ251bWVyaWMnIH0pO1xufTtcblxuLyog4pSA4pSA4pSAIFN0YXR1cyBiYWRnZSBjb2xvciDilIDilIDilIAgKi9cbmNvbnN0IHN0YXR1c0NvbG9yID0gKHMpID0+IHtcbiAgaWYgKCFzKSByZXR1cm4gQy50ZXh0RGltO1xuICBjb25zdCBsb3dlciA9IHMudG9Mb3dlckNhc2UoKTtcbiAgaWYgKGxvd2VyID09PSAnYXBwcm92ZWQnIHx8IGxvd2VyID09PSAnYWN0aXZlJykgcmV0dXJuIEMuZ3JlZW47XG4gIGlmIChsb3dlciA9PT0gJ3BlbmRpbmcnKSByZXR1cm4gQy5vcmFuZ2U7XG4gIGlmIChsb3dlciA9PT0gJ3JlamVjdGVkJykgcmV0dXJuIEMucmVkO1xuICByZXR1cm4gQy50ZXh0TXV0ZWQ7XG59O1xuXG4vKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbiAgIE1BSU4gREFTSEJPQVJEIENPTVBPTkVOVFxuICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovXG5jb25zdCBDdXN0b21EYXNoYm9hcmQgPSAoKSA9PiB7XG4gIGNvbnN0IFtkYXRhLCBzZXREYXRhXSA9IHVzZVN0YXRlKG51bGwpO1xuICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcbiAgY29uc3QgW2Vycm9yLCBzZXRFcnJvcl0gPSB1c2VTdGF0ZShudWxsKTtcblxuICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgIGFwaS5nZXREYXNoYm9hcmQoKVxuICAgICAgLnRoZW4oKHJlc3BvbnNlKSA9PiB7XG4gICAgICAgIHNldERhdGEocmVzcG9uc2UuZGF0YSB8fCB7fSk7XG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgfSlcbiAgICAgIC5jYXRjaCgoZmV0Y2hFcnJvcikgPT4ge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdEYXNoYm9hcmQgZmV0Y2ggZXJyb3I6JywgZmV0Y2hFcnJvcik7XG4gICAgICAgIHNldEVycm9yKCdGYWlsZWQgdG8gbG9hZCBkYXNoYm9hcmQgZGF0YS4nKTtcbiAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICB9KTtcbiAgfSwgW10pO1xuXG4gIGlmIChsb2FkaW5nKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgbWluSGVpZ2h0OiAnMTAwdmgnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgPGRpdiBzdHlsZT17eyB0ZXh0QWxpZ246ICdjZW50ZXInIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6IDQwLCBoZWlnaHQ6IDQwLCBib3JkZXI6IGAzcHggc29saWQgJHtDLmJvcmRlcn1gLCBib3JkZXJUb3BDb2xvcjogQy5nb2xkLCBib3JkZXJSYWRpdXM6ICc1MCUnLCBhbmltYXRpb246ICdzcGluIDFzIGxpbmVhciBpbmZpbml0ZScsIG1hcmdpbjogJzAgYXV0byAxNnB4JyB9fSAvPlxuICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCB9fT5Mb2FkaW5nIGRhc2hib2FyZC4uLjwvVGV4dD5cbiAgICAgICAgICA8c3R5bGU+e2BAa2V5ZnJhbWVzIHNwaW4geyB0byB7IHRyYW5zZm9ybTogcm90YXRlKDM2MGRlZyk7IH0gfWB9PC9zdHlsZT5cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L2Rpdj5cbiAgICApO1xuICB9XG5cbiAgaWYgKGVycm9yKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgbWluSGVpZ2h0OiAnMTAwdmgnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoQy5yZWQpLCBtYXhXaWR0aDogNDAwLCB0ZXh0QWxpZ246ICdjZW50ZXInIH19PlxuICAgICAgICAgIDxJY29uIGljb249XCJBbGVydFRyaWFuZ2xlXCIgc2l6ZT17MzJ9IGNvbG9yPXtDLnJlZH0gLz5cbiAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMucmVkLCBtYXJnaW46ICcxNnB4IDAgOHB4JyB9fT57ZXJyb3J9PC9INT5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQgfX0+Q2hlY2sgdGhlIHNlcnZlciBsb2dzIGZvciBkZXRhaWxzLjwvVGV4dD5cbiAgICAgICAgPC9Cb3g+XG4gICAgICA8L2Rpdj5cbiAgICApO1xuICB9XG5cbiAgY29uc3Qgc3RhdHMgPSBkYXRhPy5zdGF0cyB8fCB7fTtcbiAgY29uc3QgYWN0aW9uUmVxdWlyZWQgPSBkYXRhPy5hY3Rpb25SZXF1aXJlZCB8fCB7fTtcbiAgY29uc3QgbW9kc0J5UGxhdGZvcm0gPSBkYXRhPy5tb2RzQnlQbGF0Zm9ybSB8fCBbXTtcbiAgY29uc3QgdXNlckdyb3d0aERhdGEgPSBkYXRhPy51c2VyR3Jvd3RoRGF0YSB8fCBbXTtcbiAgY29uc3QgcmVjZW50VXNlcnMgPSBkYXRhPy5yZWNlbnRVc2VycyB8fCBbXTtcbiAgY29uc3QgcmVjZW50TW9kcyA9IGRhdGE/LnJlY2VudE1vZHMgfHwgW107XG5cbiAgLy8gUHJlcGFyZSBjaGFydCBkYXRhXG4gIGNvbnN0IGdyb3d0aENoYXJ0RGF0YSA9IHVzZXJHcm93dGhEYXRhLm1hcChkID0+ICh7IGxhYmVsOiBkLmRhdGUsIHZhbHVlOiBkLnVzZXJzIH0pKTtcblxuICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICBjb25zdCBncmVldGluZyA9IG5vdy5nZXRIb3VycygpIDwgMTIgPyAnR29vZCBtb3JuaW5nJyA6IG5vdy5nZXRIb3VycygpIDwgMTggPyAnR29vZCBhZnRlcm5vb24nIDogJ0dvb2QgZXZlbmluZyc7XG5cbiAgcmV0dXJuIChcbiAgICA8ZGl2IHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogQy5iZywgbWluSGVpZ2h0OiAnMTAwdmgnLCBwYWRkaW5nOiAnMzJweCA0MHB4JywgZm9udEZhbWlseTogJ0ludGVyLCBzeXN0ZW0tdWksIC1hcHBsZS1zeXN0ZW0sIHNhbnMtc2VyaWYnIH19PlxuICAgICAgXG4gICAgICB7Lyog4pWQ4pWQ4pWQIEhFQURFUiDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywganVzdGlmeUNvbnRlbnQ6ICdzcGFjZS1iZXR3ZWVuJywgYWxpZ25JdGVtczogJ2ZsZXgtZW5kJywgZ2FwOiAnMTZweCcsIHBhZGRpbmdCb3R0b206ICcyNHB4JywgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgbWFyZ2luQm90dG9tOiAnMzJweCcgfX0+XG4gICAgICAgIDxkaXY+XG4gICAgICAgICAgPEgyIHN0eWxlPXt7IG1hcmdpbjogMCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JyB9fT5cbiAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLmdvbGQsIHRleHRTaGFkb3c6IGAwIDAgMjBweCAke0MuZ29sZEdsb3d9YCwgZm9udFdlaWdodDogODAwIH19PkdQTDwvc3Bhbj5cbiAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcsIGZvbnRXZWlnaHQ6IDcwMCB9fT5Nb2RzPC9zcGFuPlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgZm9udFNpemU6ICcwLjVlbScsIGZvbnRXZWlnaHQ6IDQwMCwgbWFyZ2luTGVmdDogJzEycHgnLCBiYWNrZ3JvdW5kOiBDLnN1cmZhY2VBbHQsIHBhZGRpbmc6ICc0cHggMTBweCcsIGJvcmRlclJhZGl1czogJzZweCcsIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+QWRtaW4gRGFzaGJvYXJkPC9zcGFuPlxuICAgICAgICAgIDwvSDI+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBtYXJnaW5Ub3A6ICc2cHgnIH19PlxuICAgICAgICAgICAge2dyZWV0aW5nfSEgSGVyZSdzIHlvdXIgcGxhdGZvcm0gb3ZlcnZpZXcgZm9yIHtub3cudG9Mb2NhbGVEYXRlU3RyaW5nKCdlbi1VUycsIHsgd2Vla2RheTogJ2xvbmcnLCBtb250aDogJ2xvbmcnLCBkYXk6ICdudW1lcmljJywgeWVhcjogJ251bWVyaWMnIH0pfS5cbiAgICAgICAgICA8L1RleHQ+XG4gICAgICAgIDwvZGl2PlxuICAgICAgICA8YSBocmVmPVwiL2hvbWVcIiB0YXJnZXQ9XCJfYmxhbmtcIiByZWw9XCJub29wZW5lciBub3JlZmVycmVyXCIgXG4gICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIGNvbG9yOiBDLmdvbGQsIGJvcmRlcjogYDFweCBzb2xpZCAke0MuZ29sZH1gLCBwYWRkaW5nOiAnMTBweCAyMHB4JywgYm9yZGVyUmFkaXVzOiAnMTBweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDcwMCwgZm9udFNpemU6ICcxNHB4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSBDLmdvbGREaW07IH19XG4gICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICd0cmFuc3BhcmVudCc7IH19XG4gICAgICAgID5cbiAgICAgICAgICA8SWNvbiBpY29uPVwiR2xvYmVcIiAvPiBWaWV3IExpdmUgU2l0ZVxuICAgICAgICA8L2E+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBTVEFUIENBUkRTIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcyMHB4JywgbWFyZ2luQm90dG9tOiAnMjRweCcgfX0+XG4gICAgICAgIDxTdGF0Q2FyZCBpY29uPVwiVXNlcnNcIiBsYWJlbD1cIlRvdGFsIFVzZXJzXCIgdmFsdWU9eyhzdGF0cy50b3RhbFVzZXJzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGRlbHRhPXtzdGF0cy5uZXdVc2Vyc1RoaXNNb250aH0gYWNjZW50Q29sb3I9e0MuYmx1ZX0gLz5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJQYWNrYWdlXCIgbGFiZWw9XCJUb3RhbCBNb2RzXCIgdmFsdWU9eyhzdGF0cy50b3RhbE1vZHMgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gZGVsdGE9e3N0YXRzLm5ld01vZHNUaGlzTW9udGh9IGFjY2VudENvbG9yPXtDLmdvbGR9IC8+XG4gICAgICAgIDxTdGF0Q2FyZCBpY29uPVwiRG93bmxvYWRcIiBsYWJlbD1cIlRvdGFsIERvd25sb2Fkc1wiIHZhbHVlPXsoc3RhdHMudG90YWxEb3dubG9hZHMgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gYWNjZW50Q29sb3I9e0MuZ3JlZW59IC8+XG4gICAgICAgIDxTdGF0Q2FyZCBpY29uPVwiRXllXCIgbGFiZWw9XCJUb3RhbCBWaWV3c1wiIHZhbHVlPXsoc3RhdHMudG90YWxWaWV3cyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBhY2NlbnRDb2xvcj17Qy5wdXJwbGV9IC8+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBBQ1RJT04gUkVRVUlSRUQg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzE2cHgnLCBtYXJnaW5Cb3R0b206ICczMnB4JyB9fT5cbiAgICAgICAgPEFjdGlvbkNhcmQgaWNvbj1cIkZsYWdcIiBsYWJlbD1cIlBlbmRpbmcgUmVwb3J0c1wiIGNvdW50PXthY3Rpb25SZXF1aXJlZC5wZW5kaW5nUmVwb3J0cyB8fCAwfSBhY2NlbnRDb2xvcj17Qy5yZWR9IHJlc291cmNlSWQ9XCJSZXBvcnRcIiAvPlxuICAgICAgICA8QWN0aW9uQ2FyZCBpY29uPVwiQ2hlY2tTcXVhcmVcIiBsYWJlbD1cIlBlbmRpbmcgQXBwcm92YWxzXCIgY291bnQ9e2FjdGlvblJlcXVpcmVkLnBlbmRpbmdBcHByb3ZhbHMgfHwgMH0gYWNjZW50Q29sb3I9e0Mub3JhbmdlfSByZXNvdXJjZUlkPVwiRmlsZVwiIC8+XG4gICAgICAgIDxBY3Rpb25DYXJkIGljb249XCJIZWxwQ2lyY2xlXCIgbGFiZWw9XCJPcGVuIFRpY2tldHNcIiBjb3VudD17YWN0aW9uUmVxdWlyZWQub3BlblRpY2tldHMgfHwgMH0gYWNjZW50Q29sb3I9e0MuYmx1ZX0gcmVzb3VyY2VJZD1cIlN1cHBvcnRUaWNrZXRcIiAvPlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgQ0hBUlRTIFJPVyDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMjBweCcsIG1hcmdpbkJvdHRvbTogJzMycHgnIH19PlxuICAgICAgICB7LyogVXNlciBHcm93dGggQ2hhcnQgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcyJywgbWluV2lkdGg6ICczODBweCcgfX0+XG4gICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcyMHB4JyB9fT5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJBY3Rpdml0eVwiIGNvbG9yPXtDLmdvbGR9IC8+XG4gICAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAwIH19PlVzZXIgR3Jvd3RoPC9INT5cbiAgICAgICAgICAgIDxCYWRnZSBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnOHB4JywgYmFja2dyb3VuZENvbG9yOiBDLmdvbGREaW0sIGNvbG9yOiBDLmdvbGQsIGJvcmRlcjogJ25vbmUnIH19PjMwIGRheXM8L0JhZGdlPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIHtncm93dGhDaGFydERhdGEubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDxBcmVhQ2hhcnQgZGF0YT17Z3Jvd3RoQ2hhcnREYXRhfSBjb2xvcj17Qy5nb2xkfSB3aWR0aD17NjAwfSBoZWlnaHQ9ezIyMH0gLz5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBoZWlnaHQ6IDIwMCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInIH19PlxuICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltIH19Pk5vIHVzZXIgc2lnbnVwcyBpbiB0aGUgbGFzdCAzMCBkYXlzLjwvVGV4dD5cbiAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvQm94PlxuXG4gICAgICAgIHsvKiBQbGF0Zm9ybSBEb251dCAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzEnLCBtaW5XaWR0aDogJzMwMHB4JyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzIwcHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIlBpZUNoYXJ0XCIgY29sb3I9e0MuYmx1ZX0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAgfX0+TW9kcyBieSBQbGF0Zm9ybTwvSDU+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICAge21vZHNCeVBsYXRmb3JtLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8RG9udXRDaGFydCBkYXRhPXttb2RzQnlQbGF0Zm9ybX0gc2l6ZT17MTgwfSAvPlxuICAgICAgICAgICkgOiAoXG4gICAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGhlaWdodDogMTgwLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0gfX0+Tm8gcGxhdGZvcm0gZGF0YSBhdmFpbGFibGUuPC9UZXh0PlxuICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBSRUNFTlQgQUNUSVZJVFkgUk9XIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcyMHB4JywgbWFyZ2luQm90dG9tOiAnMzJweCcgfX0+XG4gICAgICAgIHsvKiBSZWNlbnQgVXNlcnMgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcxJywgbWluV2lkdGg6ICczNDBweCcgfX0+XG4gICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcyMHB4JyB9fT5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJVc2Vyc1wiIGNvbG9yPXtDLmJsdWV9IC8+XG4gICAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAwIH19PlJlY2VudCBVc2VyczwvSDU+XG4gICAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9Vc2VyXCIgc3R5bGU9e3sgbWFyZ2luTGVmdDogJ2F1dG8nLCBjb2xvcjogQy5nb2xkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAgfX0+VmlldyBBbGwg4oaSPC9hPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIHtyZWNlbnRVc2Vycy5sZW5ndGggPiAwID8gKFxuICAgICAgICAgICAgPHRhYmxlIHN0eWxlPXt7IHdpZHRoOiAnMTAwJScsIGJvcmRlckNvbGxhcHNlOiAnY29sbGFwc2UnIH19PlxuICAgICAgICAgICAgICA8dGhlYWQ+XG4gICAgICAgICAgICAgICAgPHRyIHN0eWxlPXt7IGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiBDLnRleHREaW0sIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PlVzZXJuYW1lPC90aD5cbiAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6IEMudGV4dERpbSwgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+Um9sZTwvdGg+XG4gICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAncmlnaHQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogQy50ZXh0RGltLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5Kb2luZWQ8L3RoPlxuICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgIDwvdGhlYWQ+XG4gICAgICAgICAgICAgIDx0Ym9keT5cbiAgICAgICAgICAgICAgICB7cmVjZW50VXNlcnMubWFwKCh1LCBpKSA9PiAoXG4gICAgICAgICAgICAgICAgICA8dHIga2V5PXtpfSBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHQsIGZvbnRTaXplOiAnMTNweCcsIGZvbnRXZWlnaHQ6IDUwMCB9fT57dS51c2VybmFtZX08L3RkPlxuICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICcxMXB4JywgcGFkZGluZzogJzNweCA4cHgnLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IHUucm9sZSA9PT0gJ2FkbWluJyA/IGAke0MuZ29sZH0yMGAgOiBgJHtDLmJsdWV9MjBgLCBjb2xvcjogdS5yb2xlID09PSAnYWRtaW4nID8gQy5nb2xkIDogQy5ibHVlLCBmb250V2VpZ2h0OiA2MDAgfX0+e3Uucm9sZSB8fCAndXNlcid9PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dEFsaWduOiAncmlnaHQnIH19PntmbXREYXRlKHUuZGF0ZSl9PC90ZD5cbiAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgKSl9XG4gICAgICAgICAgICAgIDwvdGJvZHk+XG4gICAgICAgICAgICA8L3RhYmxlPlxuICAgICAgICAgICkgOiAoXG4gICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCB0ZXh0QWxpZ246ICdjZW50ZXInLCBwYWRkaW5nOiAnMjBweCAwJyB9fT5ObyByZWNlbnQgdXNlcnMuPC9UZXh0PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvQm94PlxuXG4gICAgICAgIHsvKiBSZWNlbnQgTW9kcyAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzEnLCBtaW5XaWR0aDogJzM0MHB4JyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzIwcHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIlBhY2thZ2VcIiBjb2xvcj17Qy5nb2xkfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCB9fT5SZWNlbnQgTW9kczwvSDU+XG4gICAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9GaWxlXCIgc3R5bGU9e3sgbWFyZ2luTGVmdDogJ2F1dG8nLCBjb2xvcjogQy5nb2xkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAgfX0+VmlldyBBbGwg4oaSPC9hPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIHtyZWNlbnRNb2RzLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8dGFibGUgc3R5bGU9e3sgd2lkdGg6ICcxMDAlJywgYm9yZGVyQ29sbGFwc2U6ICdjb2xsYXBzZScgfX0+XG4gICAgICAgICAgICAgIDx0aGVhZD5cbiAgICAgICAgICAgICAgICA8dHIgc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6IEMudGV4dERpbSwgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+TmFtZTwvdGg+XG4gICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiBDLnRleHREaW0sIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PlBsYXRmb3JtPC90aD5cbiAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6IEMudGV4dERpbSwgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+U3RhdHVzPC90aD5cbiAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdyaWdodCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiBDLnRleHREaW0sIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PkFkZGVkPC90aD5cbiAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICA8L3RoZWFkPlxuICAgICAgICAgICAgICA8dGJvZHk+XG4gICAgICAgICAgICAgICAge3JlY2VudE1vZHMubWFwKChtLCBpKSA9PiAoXG4gICAgICAgICAgICAgICAgICA8dHIga2V5PXtpfSBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHQsIGZvbnRTaXplOiAnMTNweCcsIGZvbnRXZWlnaHQ6IDUwMCwgbWF4V2lkdGg6ICcxODBweCcsIG92ZXJmbG93OiAnaGlkZGVuJywgdGV4dE92ZXJmbG93OiAnZWxsaXBzaXMnLCB3aGl0ZVNwYWNlOiAnbm93cmFwJyB9fT57bS5uYW1lfTwvdGQ+XG4gICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzExcHgnLCBwYWRkaW5nOiAnM3B4IDhweCcsIGJvcmRlclJhZGl1czogJzZweCcsIGJhY2tncm91bmRDb2xvcjogYCR7Qy5ibHVlfTIwYCwgY29sb3I6IEMuYmx1ZSwgZm9udFdlaWdodDogNjAwLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyB9fT57bS5jYXRlZ29yeSB8fCAn4oCUJ308L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzExcHgnLCBwYWRkaW5nOiAnM3B4IDhweCcsIGJvcmRlclJhZGl1czogJzZweCcsIGJhY2tncm91bmRDb2xvcjogYCR7c3RhdHVzQ29sb3IobS5zdGF0dXMpfTIwYCwgY29sb3I6IHN0YXR1c0NvbG9yKG0uc3RhdHVzKSwgZm9udFdlaWdodDogNjAwLCB0ZXh0VHJhbnNmb3JtOiAnY2FwaXRhbGl6ZScgfX0+e20uc3RhdHVzIHx8ICfigJQnfTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnLCBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTJweCcsIHRleHRBbGlnbjogJ3JpZ2h0JyB9fT57Zm10RGF0ZShtLmRhdGUpfTwvdGQ+XG4gICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICkpfVxuICAgICAgICAgICAgICA8L3Rib2R5PlxuICAgICAgICAgICAgPC90YWJsZT5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgdGV4dEFsaWduOiAnY2VudGVyJywgcGFkZGluZzogJzIwcHggMCcgfX0+Tm8gcmVjZW50IG1vZHMuPC9UZXh0PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvQm94PlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgRk9PVEVSIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBqdXN0aWZ5Q29udGVudDogJ3NwYWNlLWJldHdlZW4nLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgcGFkZGluZ1RvcDogJzIwcHgnLCBib3JkZXJUb3A6IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCBmb250U2l6ZTogJzEycHgnIH19PlxuICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLmdvbGQsIGZvbnRXZWlnaHQ6IDcwMCB9fT5HUEw8L3NwYW4+IDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnIzg4OCcgfX0+TW9kczwvc3Bhbj4g4oCiIEFkbWluIFBhbmVsIHYyLjVcbiAgICAgICAgPC9UZXh0PlxuICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZ2FwOiAnMTZweCcgfX0+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvVXNlclwiIHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJyB9fT5Vc2VyczwvYT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9GaWxlXCIgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnIH19Pk1vZHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvUmVwb3J0XCIgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnIH19PlJlcG9ydHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvU3VwcG9ydFRpY2tldFwiIHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJyB9fT5UaWNrZXRzPC9hPlxuICAgICAgICA8L2Rpdj5cbiAgICAgIDwvZGl2PlxuICAgIDwvZGl2PlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgQ3VzdG9tRGFzaGJvYXJkO1xuIiwiaW1wb3J0IFJlYWN0IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCwgTGluayB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuXG5jb25zdCBTaWRlYmFyQnJhbmRpbmcgPSAoKSA9PiB7XG4gIHJldHVybiAoXG4gICAgPEJveCBcbiAgICAgIGZsZXggXG4gICAgICBhbGlnbkl0ZW1zPVwiY2VudGVyXCIgXG4gICAgICBqdXN0aWZ5Q29udGVudD1cImNlbnRlclwiIFxuICAgICAgcD1cImxnXCIgXG4gICAgICBzdHlsZT17eyBcbiAgICAgICAgYm9yZGVyQm90dG9tOiAnMXB4IHNvbGlkICMyYTJhMmEnLCBcbiAgICAgICAgYmFja2dyb3VuZENvbG9yOiAnIzBhMGEwYScsIFxuICAgICAgICBwYWRkaW5nOiAnMjJweCAwJyxcbiAgICAgICAgcG9zaXRpb246ICdyZWxhdGl2ZScsXG4gICAgICAgIG92ZXJmbG93OiAnaGlkZGVuJ1xuICAgICAgfX1cbiAgICA+XG4gICAgICB7LyogU3VidGxlIGdvbGQgZ2xvdyB1bmRlcmxpbmUgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7XG4gICAgICAgIHBvc2l0aW9uOiAnYWJzb2x1dGUnLFxuICAgICAgICBib3R0b206IDAsXG4gICAgICAgIGxlZnQ6ICc1MCUnLFxuICAgICAgICB0cmFuc2Zvcm06ICd0cmFuc2xhdGVYKC01MCUpJyxcbiAgICAgICAgd2lkdGg6ICc2MCUnLFxuICAgICAgICBoZWlnaHQ6ICcxcHgnLFxuICAgICAgICBiYWNrZ3JvdW5kOiAnbGluZWFyLWdyYWRpZW50KDkwZGVnLCB0cmFuc3BhcmVudCwgcmdiYSgyNTUsMjE1LDAsMC41KSwgdHJhbnNwYXJlbnQpJ1xuICAgICAgfX0gLz5cblxuICAgICAgPExpbmsgdG89XCIvYWRtaW5cIiBzdHlsZT17eyB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcxMHB4JyB9fT5cbiAgICAgICAgPGltZyBcbiAgICAgICAgICBzcmM9XCIvaW1hZ2VzL2xvZ28ucG5nXCIgXG4gICAgICAgICAgYWx0PVwiTG9nb1wiIFxuICAgICAgICAgIHN0eWxlPXt7IGhlaWdodDogJzMycHgnLCB3aWR0aDogJ2F1dG8nLCBmaWx0ZXI6ICdkcm9wLXNoYWRvdygwIDAgNnB4IHJnYmEoMjU1LDIxNSwwLDAuMykpJyB9fSBcbiAgICAgICAgICBvbkVycm9yPXsoZSkgPT4gZS50YXJnZXQuc3R5bGUuZGlzcGxheSA9ICdub25lJ31cbiAgICAgICAgLz5cbiAgICAgICAgPGRpdiBzdHlsZT17eyBmb250U2l6ZTogJzIycHgnLCBmb250V2VpZ2h0OiAnYm9sZCcsIGZvbnRGYW1pbHk6ICdJbnRlciwgc3lzdGVtLXVpLCBzYW5zLXNlcmlmJywgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnYmFzZWxpbmUnLCBnYXA6ICc0cHgnIH19PlxuICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI0ZGRDcwMCcsIHRleHRTaGFkb3c6ICcwIDAgMTJweCByZ2JhKDI1NSwgMjE1LCAwLCAwLjQpJyB9fT5HUEw8L3NwYW4+XG4gICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjYzBjMGMwJyB9fT5Nb2RzPC9zcGFuPlxuICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnOXB4JywgY29sb3I6ICcjNTU1JywgZm9udFdlaWdodDogNjAwLCBtYXJnaW5MZWZ0OiAnNnB4JywgbGV0dGVyU3BhY2luZzogJzAuMDVlbScgfX0+djIuNTwvc3Bhbj5cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L0xpbms+XG4gICAgPC9Cb3g+XG4gICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBTaWRlYmFyQnJhbmRpbmc7XG4iLCJpbXBvcnQgUmVhY3QsIHsgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94LCBUZXh0LCBMb2FkZXIgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcbmltcG9ydCB7IHVzZU5vdGljZSB9IGZyb20gJ2FkbWluanMnO1xuXG5jb25zdCBBY3Rpb25SZWRpcmVjdCA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkLCBhY3Rpb24gfSA9IHByb3BzO1xuICAgIGNvbnN0IHNlbmROb3RpY2UgPSB1c2VOb3RpY2UoKTtcblxuICAgIHVzZUVmZmVjdCgoKSA9PiB7XG4gICAgICAgIGNvbnN0IHVybCA9IHJlY29yZD8ucGFyYW1zPy5yZWRpcmVjdFVybDtcbiAgICAgICAgXG4gICAgICAgIGlmICh1cmwpIHtcbiAgICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICAgICAgICAgIHdpbmRvdy5vcGVuKHVybCwgJ19ibGFuaycpO1xuICAgICAgICAgICAgfSwgNTAwKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHNlbmROb3RpY2UoeyBtZXNzYWdlOiAnRXJyb3I6IE5vIHJlZGlyZWN0IFVSTCBwcm92aWRlZC4nLCB0eXBlOiAnZXJyb3InIH0pO1xuICAgICAgICB9XG4gICAgfSwgW3JlY29yZF0pO1xuXG4gICAgcmV0dXJuIChcbiAgICAgICAgPEJveCBmbGV4IGZsZXhEaXJlY3Rpb249XCJjb2x1bW5cIiBhbGlnbkl0ZW1zPVwiY2VudGVyXCIganVzdGlmeUNvbnRlbnQ9XCJjZW50ZXJcIiBwPVwieHhsXCI+XG4gICAgICAgICAgICA8TG9hZGVyIC8+XG4gICAgICAgICAgICA8VGV4dCBtdD1cImxnXCIgdmFyaWFudD1cImg0XCI+UmVkaXJlY3RpbmcuLi48L1RleHQ+XG4gICAgICAgIDwvQm94PlxuICAgICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBBY3Rpb25SZWRpcmVjdDtcbiIsImltcG9ydCBSZWFjdCBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCYWRnZSB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuXG5jb25zdCBWYXJpYW50QmFkZ2UgPSAocHJvcHMpID0+IHtcbiAgY29uc3QgeyByZWNvcmQsIHByb3BlcnR5IH0gPSBwcm9wcztcbiAgY29uc3QgaXNWYXJpYW50ID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcblxuICBpZiAoaXNWYXJpYW50ID09PSB0cnVlIHx8IGlzVmFyaWFudCA9PT0gJ3RydWUnKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxCYWRnZSB2YXJpYW50PVwicHJpbWFyeVwiIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMyMTk2RjMnLCBjb2xvcjogJyNmZmYnLCBib3JkZXI6ICdub25lJyB9fT5cbiAgICAgICAgVmFyaWFudFxuICAgICAgPC9CYWRnZT5cbiAgICApO1xuICB9XG5cbiAgcmV0dXJuIChcbiAgICA8QmFkZ2Ugc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzMzMycsIGNvbG9yOiAnI2FhYScsIGJvcmRlcjogJzFweCBzb2xpZCAjNTU1JyB9fT5cbiAgICAgIE1hc3RlclxuICAgIDwvQmFkZ2U+XG4gICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBWYXJpYW50QmFkZ2U7XG4iLCJpbXBvcnQgUmVhY3QsIHsgdXNlU3RhdGUsIHVzZUVmZmVjdCB9IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuXG5jb25zdCBBdmF0YXJDZWxsID0gKHByb3BzKSA9PiB7XG4gICAgY29uc3QgeyByZWNvcmQsIHByb3BlcnR5LCB3aGVyZSB9ID0gcHJvcHM7IFxuICAgIGNvbnN0IGtleSA9IHJlY29yZC5wYXJhbXNbcHJvcGVydHkubmFtZV07XG4gICAgY29uc3QgdXNlcm5hbWUgPSByZWNvcmQucGFyYW1zLnVzZXJuYW1lIHx8ICdVc2VyJztcblxuICAgIGNvbnN0IFtpbWFnZVVybCwgc2V0SW1hZ2VVcmxdID0gdXNlU3RhdGUobnVsbCk7XG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG4gICAgY29uc3QgW2hhc0Vycm9yLCBzZXRIYXNFcnJvcl0gPSB1c2VTdGF0ZShmYWxzZSk7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBpZiAoIWtleSkge1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoa2V5LnN0YXJ0c1dpdGgoJ2h0dHA6Ly8nKSB8fCBrZXkuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKSkge1xuICAgICAgICAgICAgc2V0SW1hZ2VVcmwoa2V5KTtcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZmV0Y2hTaWduZWRVcmwgPSBhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2goYC9hcGkvYWRtaW4vc2lnbmVkLXVybD9rZXk9JHtlbmNvZGVVUklDb21wb25lbnQoa2V5KX1gKTtcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgICAgICAgICAgc2V0SW1hZ2VVcmwoZGF0YS51cmwpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHNldEhhc0Vycm9yKHRydWUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIkVycm9yIGZldGNoaW5nIGF2YXRhciBVUkw6XCIsIGVycm9yKTtcbiAgICAgICAgICAgICAgICBzZXRIYXNFcnJvcih0cnVlKTtcbiAgICAgICAgICAgIH0gZmluYWxseSB7XG4gICAgICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG5cbiAgICAgICAgZmV0Y2hTaWduZWRVcmwoKTtcbiAgICB9LCBba2V5XSk7XG5cbiAgICBjb25zdCBzaXplID0gd2hlcmUgPT09ICdsaXN0JyA/ICczMnB4JyA6ICcxMjBweCc7XG5cbiAgICBpZiAobG9hZGluZykge1xuICAgICAgICByZXR1cm4gPEJveCBzdHlsZT17eyB3aWR0aDogc2l6ZSwgaGVpZ2h0OiBzaXplLCBib3JkZXJSYWRpdXM6ICc1MCUnLCBiYWNrZ3JvdW5kQ29sb3I6ICcjMzMzJyB9fSAvPjtcbiAgICB9XG5cbiAgICBpZiAoIWltYWdlVXJsIHx8IGhhc0Vycm9yKSB7XG4gICAgICAgIHJldHVybiAoXG4gICAgICAgICAgICA8Qm94IHN0eWxlPXt7IFxuICAgICAgICAgICAgICAgIHdpZHRoOiBzaXplLCBcbiAgICAgICAgICAgICAgICBoZWlnaHQ6IHNpemUsIFxuICAgICAgICAgICAgICAgIGJvcmRlclJhZGl1czogJzUwJScsIFxuICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJyNGRkQ3MDAnLFxuICAgICAgICAgICAgICAgIGNvbG9yOiAnIzBhMGEwYScsXG4gICAgICAgICAgICAgICAgZGlzcGxheTogJ2ZsZXgnLCBcbiAgICAgICAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJywgXG4gICAgICAgICAgICAgICAganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLFxuICAgICAgICAgICAgICAgIGZvbnRXZWlnaHQ6ICdib2xkJyxcbiAgICAgICAgICAgICAgICBmb250U2l6ZTogd2hlcmUgPT09ICdsaXN0JyA/ICcxNHB4JyA6ICc0OHB4JyxcbiAgICAgICAgICAgICAgICBib3JkZXI6ICcycHggc29saWQgIzMzMydcbiAgICAgICAgICAgIH19PlxuICAgICAgICAgICAgICAgIHt1c2VybmFtZS5jaGFyQXQoMCkudG9VcHBlckNhc2UoKX1cbiAgICAgICAgICAgIDwvQm94PlxuICAgICAgICApO1xuICAgIH1cblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3g+XG4gICAgICAgICAgICA8aW1nIFxuICAgICAgICAgICAgICAgIHNyYz17aW1hZ2VVcmx9IFxuICAgICAgICAgICAgICAgIGFsdD17dXNlcm5hbWV9XG4gICAgICAgICAgICAgICAgc3R5bGU9e3sgXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiAnNTAlJywgXG4gICAgICAgICAgICAgICAgICAgIG9iamVjdEZpdDogJ2NvdmVyJyxcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyOiAnMnB4IHNvbGlkICNGRkQ3MDAnXG4gICAgICAgICAgICAgICAgfX0gXG4gICAgICAgICAgICAgICAgb25FcnJvcj17KCkgPT4gc2V0SGFzRXJyb3IodHJ1ZSl9XG4gICAgICAgICAgICAvPlxuICAgICAgICA8L0JveD5cbiAgICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgQXZhdGFyQ2VsbDtcbiIsImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94IH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5cbmNvbnN0IEltYWdlUHJldmlldyA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSwgd2hlcmUgfSA9IHByb3BzOyBcbiAgICBjb25zdCB2YWx1ZSA9IHJlY29yZC5wYXJhbXNbcHJvcGVydHkubmFtZV07XG5cbiAgICBjb25zdCBbaW1hZ2VVcmwsIHNldEltYWdlVXJsXSA9IHVzZVN0YXRlKG51bGwpO1xuICAgIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IHVzZVN0YXRlKHRydWUpO1xuXG4gICAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICAgICAgaWYgKCF2YWx1ZSkge1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodmFsdWUuc3RhcnRzV2l0aCgnaHR0cDovLycpIHx8IHZhbHVlLnN0YXJ0c1dpdGgoJ2h0dHBzOi8vJykpIHtcbiAgICAgICAgICAgIHNldEltYWdlVXJsKHZhbHVlKTtcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZmV0Y2hTaWduZWRVcmwgPSBhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2goYC9hcGkvYWRtaW4vc2lnbmVkLXVybD9rZXk9JHtlbmNvZGVVUklDb21wb25lbnQodmFsdWUpfWApO1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZS5vaykge1xuICAgICAgICAgICAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzcG9uc2UuanNvbigpO1xuICAgICAgICAgICAgICAgICAgICBzZXRJbWFnZVVybChkYXRhLnVybCk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIkZhaWxlZCB0byBmZXRjaCBzaWduZWQgVVJMLlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJOZXR3b3JrIGVycm9yIGZldGNoaW5nIHNpZ25lZCBVUkw6XCIsIGVycm9yKTtcbiAgICAgICAgICAgIH0gZmluYWxseSB7XG4gICAgICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG5cbiAgICAgICAgZmV0Y2hTaWduZWRVcmwoKTtcbiAgICB9LCBbdmFsdWVdKTtcblxuICAgIGlmIChsb2FkaW5nKSByZXR1cm4gPEJveCBzdHlsZT17eyBjb2xvcjogJyNGRkQ3MDAnLCBmb250U2l6ZTogJzEycHgnIH19PkxvYWRpbmcuLi48L0JveD47XG4gICAgaWYgKCFpbWFnZVVybCkgcmV0dXJuIDxCb3ggc3R5bGU9e3sgY29sb3I6ICcjODg4JywgZm9udFNpemU6ICcxMnB4JyB9fT5OL0E8L0JveD47XG5cbiAgICBjb25zdCBzaXplID0gd2hlcmUgPT09ICdsaXN0JyA/ICc0MHB4JyA6ICcxNTBweCc7XG4gICAgY29uc3QgcmFkaXVzID0gcHJvcGVydHkubmFtZSA9PT0gJ3Byb2ZpbGVJbWFnZUtleScgPyAnNTAlJyA6ICc4cHgnO1xuXG4gICAgcmV0dXJuIChcbiAgICAgICAgPEJveD5cbiAgICAgICAgICAgIDxpbWcgXG4gICAgICAgICAgICAgICAgc3JjPXtpbWFnZVVybH0gXG4gICAgICAgICAgICAgICAgYWx0PVwiUHJldmlld1wiIFxuICAgICAgICAgICAgICAgIHN0eWxlPXt7IFxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGhlaWdodDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlclJhZGl1czogcmFkaXVzLFxuICAgICAgICAgICAgICAgICAgICBvYmplY3RGaXQ6ICdjb3ZlcicsXG4gICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnLFxuICAgICAgICAgICAgICAgICAgICBib3JkZXI6ICcxcHggc29saWQgIzMzMydcbiAgICAgICAgICAgICAgICB9fSBcbiAgICAgICAgICAgIC8+XG4gICAgICAgIDwvQm94PlxuICAgICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBJbWFnZVByZXZpZXc7XG4iLCJpbXBvcnQgUmVhY3QsIHsgdXNlU3RhdGUgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3gsIEJ1dHRvbiwgSDMsIFRleHQsIElucHV0LCBMYWJlbCwgRm9ybUdyb3VwLCBOb3RpY2VCb3ggfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcbmltcG9ydCB7IHVzZU5vdGljZSwgQXBpQ2xpZW50IH0gZnJvbSAnYWRtaW5qcyc7XG5cbmNvbnN0IGFwaSA9IG5ldyBBcGlDbGllbnQoKTtcblxuY29uc3QgTWFuYWdlVm90ZXMgPSAocHJvcHMpID0+IHtcbiAgY29uc3QgeyByZWNvcmQsIHJlc291cmNlIH0gPSBwcm9wcztcbiAgY29uc3QgYWRkTm90aWNlID0gdXNlTm90aWNlKCk7XG5cbiAgY29uc3QgW3dvcmtpbmdDb3VudCwgc2V0V29ya2luZ0NvdW50XSA9IHVzZVN0YXRlKHJlY29yZC5wYXJhbXMud29ya2luZ1ZvdGVDb3VudCB8fCAwKTtcbiAgY29uc3QgW25vdFdvcmtpbmdDb3VudCwgc2V0Tm90V29ya2luZ0NvdW50XSA9IHVzZVN0YXRlKHJlY29yZC5wYXJhbXMubm90V29ya2luZ1ZvdGVDb3VudCB8fCAwKTtcbiAgY29uc3QgW2lzTG9hZGluZywgc2V0SXNMb2FkaW5nXSA9IHVzZVN0YXRlKGZhbHNlKTtcblxuICBjb25zdCBoYW5kbGVTdWJtaXQgPSAoYWN0aW9uVHlwZSkgPT4ge1xuICAgIGlmIChhY3Rpb25UeXBlID09PSAncmVzZXQnICYmICF3aW5kb3cuY29uZmlybShcIkFyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byBwZXJtYW5lbnRseSBkZWxldGUgYWxsIHVzZXIgdm90ZXMgZm9yIHRoaXMgbW9kP1wiKSkge1xuICAgICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgc2V0SXNMb2FkaW5nKHRydWUpO1xuXG4gICAgYXBpLnJlc291cmNlQWN0aW9uKHtcbiAgICAgIHJlc291cmNlSWQ6IHJlc291cmNlLmlkLFxuICAgICAgYWN0aW9uTmFtZTogJ21hbmFnZVZvdGVzJyxcbiAgICAgIHJlY29yZElkOiByZWNvcmQuaWQsXG4gICAgICBtZXRob2Q6ICdwb3N0JyxcbiAgICAgIGRhdGE6IHtcbiAgICAgICAgYWN0aW9uVHlwZTogYWN0aW9uVHlwZSxcbiAgICAgICAgbmV3V29ya2luZ0NvdW50OiB3b3JraW5nQ291bnQsXG4gICAgICAgIG5ld05vdFdvcmtpbmdDb3VudDogbm90V29ya2luZ0NvdW50XG4gICAgICB9XG4gICAgfSkudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICBzZXRJc0xvYWRpbmcoZmFsc2UpO1xuICAgICAgaWYgKHJlc3BvbnNlLmRhdGEubm90aWNlKSB7XG4gICAgICAgIGFkZE5vdGljZShyZXNwb25zZS5kYXRhLm5vdGljZSk7XG4gICAgICB9XG4gICAgICBpZiAocmVzcG9uc2UuZGF0YS5yZWRpcmVjdFVybCkge1xuICAgICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSByZXNwb25zZS5kYXRhLnJlZGlyZWN0VXJsO1xuICAgICAgfVxuICAgIH0pLmNhdGNoKGVycm9yID0+IHtcbiAgICAgIHNldElzTG9hZGluZyhmYWxzZSk7XG4gICAgICBhZGROb3RpY2UoeyBtZXNzYWdlOiAnQW4gZXJyb3Igb2NjdXJyZWQgd2hpbGUgY29udGFjdGluZyB0aGUgc2VydmVyLicsIHR5cGU6ICdlcnJvcicgfSk7XG4gICAgfSk7XG4gIH07XG5cbiAgcmV0dXJuIChcbiAgICA8Qm94IHZhcmlhbnQ9XCJ3aGl0ZVwiIHA9XCJ4bFwiIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBib3JkZXI6ICcxcHggc29saWQgIzMzMycgfX0+XG4gICAgICBcbiAgICAgIDxIMyBzdHlsZT17eyBjb2xvcjogJyNGRkQ3MDAnLCBtYXJnaW5Cb3R0b206ICcyMHB4JyB9fT5NYW5hZ2UgVm90ZXMgZm9yOiB7cmVjb3JkLnBhcmFtcy5uYW1lfTwvSDM+XG4gICAgICBcbiAgICAgIDxOb3RpY2VCb3ggc3R5bGU9e3sgbWFyZ2luQm90dG9tOiAnMzBweCcgfX0+XG4gICAgICAgIDxzdHJvbmc+Q3VycmVudCBTdGF0dXM6PC9zdHJvbmc+PGJyLz5cbiAgICAgICAgV29ya2luZyBWb3RlczogPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjNDNhMDQ3JywgZm9udFdlaWdodDogJ2JvbGQnIH19PntyZWNvcmQucGFyYW1zLndvcmtpbmdWb3RlQ291bnQgfHwgMH08L3NwYW4+PGJyLz5cbiAgICAgICAgTm90IFdvcmtpbmcgVm90ZXM6IDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2U1MzkzNScsIGZvbnRXZWlnaHQ6ICdib2xkJyB9fT57cmVjb3JkLnBhcmFtcy5ub3RXb3JraW5nVm90ZUNvdW50IHx8IDB9PC9zcGFuPlxuICAgICAgPC9Ob3RpY2VCb3g+XG5cbiAgICAgIDxCb3ggbWI9XCJ4eGxcIiBwPVwibGdcIiBzdHlsZT17eyBib3JkZXI6ICcxcHggc29saWQgIzQ0NCcsIGJvcmRlclJhZGl1czogJzhweCcsIGJhY2tncm91bmRDb2xvcjogJyMwYTBhMGEnIH19PlxuICAgICAgICA8SDMgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgZm9udFNpemU6ICcxLjJlbScgfX0+T3B0aW9uIDE6IFJlc2V0IEFsbCBWb3RlczwvSDM+XG4gICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcsIG1hcmdpbkJvdHRvbTogJzE1cHgnIH19PlxuICAgICAgICAgIFRoaXMgd2lsbCB3aXBlIGFsbCBleGlzdGluZyB1c2VyIHZvdGVzIGFuZCByZXNldCBib3RoIGNvdW50cyB0byAwLiBUaGlzIGlzIGhpZ2hseSByZWNvbW1lbmRlZCB3aGVuIGEgbWFqb3IgdXBkYXRlIGlzIHJlbGVhc2VkIHRoYXQgZml4ZXMgYSBicm9rZW4gbW9kLlxuICAgICAgICA8L1RleHQ+XG4gICAgICAgIDxCdXR0b24gXG4gICAgICAgICAgICB2YXJpYW50PVwiZGFuZ2VyXCIgXG4gICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBoYW5kbGVTdWJtaXQoJ3Jlc2V0Jyl9IFxuICAgICAgICAgICAgZGlzYWJsZWQ9e2lzTG9hZGluZ31cbiAgICAgICAgPlxuICAgICAgICAgIHtpc0xvYWRpbmcgPyAnUHJvY2Vzc2luZy4uLicgOiAnV2lwZSAmIFJlc2V0IFZvdGVzIHRvIDAnfVxuICAgICAgICA8L0J1dHRvbj5cbiAgICAgIDwvQm94PlxuXG4gICAgICA8Qm94IHA9XCJsZ1wiIHN0eWxlPXt7IGJvcmRlcjogJzFweCBzb2xpZCAjNDQ0JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgYmFja2dyb3VuZENvbG9yOiAnIzBhMGEwYScgfX0+XG4gICAgICAgIDxIMyBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBmb250U2l6ZTogJzEuMmVtJyB9fT5PcHRpb24gMjogTWFudWFsbHkgT3ZlcnJpZGUgQ291bnRzPC9IMz5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjZmZhZGFkJywgbWFyZ2luQm90dG9tOiAnMTVweCcsIGZvbnRTaXplOiAnMC45ZW0nIH19PlxuICAgICAgICAgIFdhcm5pbmc6IE1hbnVhbGx5IHNldHRpbmcgbnVtYmVycyB3aWxsIGNsZWFyIHRoZSBpbnRlcm5hbCBsaXN0IG9mIHVzZXJzIHdobyB2b3RlZC4gVXNlIHRoaXMgb25seSBpZiB5b3UgbmVlZCB0byBhcnRpZmljaWFsbHkgYm9vc3Qgb3IgcmVkdWNlIGEgc2NvcmUuXG4gICAgICAgIDwvVGV4dD5cbiAgICAgICAgXG4gICAgICAgIDxCb3ggZmxleCBzdHlsZT17eyBnYXA6ICcyMHB4JywgbWFyZ2luQm90dG9tOiAnMjBweCcgfX0+XG4gICAgICAgICAgICA8Rm9ybUdyb3VwIHN0eWxlPXt7IGZsZXg6IDEgfX0+XG4gICAgICAgICAgICAgICAgPExhYmVsIHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcgfX0+Rm9yY2UgXCJXb3JraW5nXCIgQ291bnQ8L0xhYmVsPlxuICAgICAgICAgICAgICAgIDxJbnB1dCBcbiAgICAgICAgICAgICAgICAgICAgdHlwZT1cIm51bWJlclwiIFxuICAgICAgICAgICAgICAgICAgICB2YWx1ZT17d29ya2luZ0NvdW50fSBcbiAgICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKSA9PiBzZXRXb3JraW5nQ291bnQoZS50YXJnZXQudmFsdWUpfSBcbiAgICAgICAgICAgICAgICAgICAgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzFhMWExYScsIGNvbG9yOiAnd2hpdGUnLCBib3JkZXI6ICcxcHggc29saWQgIzMzMycgfX1cbiAgICAgICAgICAgICAgICAvPlxuICAgICAgICAgICAgPC9Gb3JtR3JvdXA+XG4gICAgICAgICAgICBcbiAgICAgICAgICAgIDxGb3JtR3JvdXAgc3R5bGU9e3sgZmxleDogMSB9fT5cbiAgICAgICAgICAgICAgICA8TGFiZWwgc3R5bGU9e3sgY29sb3I6ICcjYzBjMGMwJyB9fT5Gb3JjZSBcIk5vdCBXb3JraW5nXCIgQ291bnQ8L0xhYmVsPlxuICAgICAgICAgICAgICAgIDxJbnB1dCBcbiAgICAgICAgICAgICAgICAgICAgdHlwZT1cIm51bWJlclwiIFxuICAgICAgICAgICAgICAgICAgICB2YWx1ZT17bm90V29ya2luZ0NvdW50fSBcbiAgICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKSA9PiBzZXROb3RXb3JraW5nQ291bnQoZS50YXJnZXQudmFsdWUpfVxuICAgICAgICAgICAgICAgICAgICBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMWExYTFhJywgY29sb3I6ICd3aGl0ZScsIGJvcmRlcjogJzFweCBzb2xpZCAjMzMzJyB9fVxuICAgICAgICAgICAgICAgIC8+XG4gICAgICAgICAgICA8L0Zvcm1Hcm91cD5cbiAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgPEJ1dHRvbiBcbiAgICAgICAgICAgIHZhcmlhbnQ9XCJwcmltYXJ5XCIgXG4gICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBoYW5kbGVTdWJtaXQoJ292ZXJyaWRlJyl9IFxuICAgICAgICAgICAgZGlzYWJsZWQ9e2lzTG9hZGluZ31cbiAgICAgICAgICAgIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyNGRkQ3MDAnLCBjb2xvcjogJ2JsYWNrJywgYm9yZGVyOiAnbm9uZScgfX1cbiAgICAgICAgPlxuICAgICAgICAgIHtpc0xvYWRpbmcgPyAnUHJvY2Vzc2luZy4uLicgOiAnQXBwbHkgTWFudWFsIE92ZXJyaWRlJ31cbiAgICAgICAgPC9CdXR0b24+XG4gICAgICA8L0JveD5cblxuICAgIDwvQm94PlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgTWFuYWdlVm90ZXM7XG4iLCJBZG1pbkpTLlVzZXJDb21wb25lbnRzID0ge31cbkFkbWluSlMuZW52Lk5PREVfRU5WID0gXCJwcm9kdWN0aW9uXCJcbmltcG9ydCBEYXNoYm9hcmQgZnJvbSAnLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvQ3VzdG9tRGFzaGJvYXJkJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5EYXNoYm9hcmQgPSBEYXNoYm9hcmRcbmltcG9ydCBTaWRlYmFyQnJhbmRpbmcgZnJvbSAnLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5TaWRlYmFyQnJhbmRpbmcgPSBTaWRlYmFyQnJhbmRpbmdcbmltcG9ydCBBY3Rpb25SZWRpcmVjdCBmcm9tICcuLi9jb21wb25lbnRzL2FjdGlvbnMvQWN0aW9uUmVkaXJlY3QnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkFjdGlvblJlZGlyZWN0ID0gQWN0aW9uUmVkaXJlY3RcbmltcG9ydCBWYXJpYW50QmFkZ2UgZnJvbSAnLi4vY29tcG9uZW50cy9jZWxscy9WYXJpYW50QmFkZ2UnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLlZhcmlhbnRCYWRnZSA9IFZhcmlhbnRCYWRnZVxuaW1wb3J0IEF2YXRhckNlbGwgZnJvbSAnLi4vY29tcG9uZW50cy9jZWxscy9BdmF0YXJDZWxsJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5BdmF0YXJDZWxsID0gQXZhdGFyQ2VsbFxuaW1wb3J0IEltYWdlUHJldmlldyBmcm9tICcuLi9jb21wb25lbnRzL2NlbGxzL0ltYWdlUHJldmlldydcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuSW1hZ2VQcmV2aWV3ID0gSW1hZ2VQcmV2aWV3XG5pbXBvcnQgTWFuYWdlVm90ZXMgZnJvbSAnLi4vY29tcG9uZW50cy9hY3Rpb25zL01hbmFnZVZvdGVzJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5NYW5hZ2VWb3RlcyA9IE1hbmFnZVZvdGVzIl0sIm5hbWVzIjpbImFwaSIsIkFwaUNsaWVudCIsIkMiLCJiZyIsInN1cmZhY2UiLCJzdXJmYWNlQWx0IiwiYm9yZGVyIiwiYm9yZGVySG92ZXIiLCJnb2xkIiwiZ29sZERpbSIsImdvbGRHbG93IiwiYmx1ZSIsImdyZWVuIiwicHVycGxlIiwicmVkIiwib3JhbmdlIiwidGV4dCIsInRleHRNdXRlZCIsInRleHREaW0iLCJQTEFURk9STV9DT0xPUlMiLCJjYXJkU3R5bGUiLCJhY2NlbnRDb2xvciIsImJhY2tncm91bmRDb2xvciIsImJvcmRlclJhZGl1cyIsImJvcmRlckxlZnQiLCJwYWRkaW5nIiwidHJhbnNpdGlvbiIsImN1cnNvciIsIkFyZWFDaGFydCIsImRhdGEiLCJ3aWR0aCIsImhlaWdodCIsImNvbG9yIiwibGVuZ3RoIiwibWF4VmFsIiwiTWF0aCIsIm1heCIsIm1hcCIsImQiLCJ2YWx1ZSIsInBhZFgiLCJwYWRZIiwiY2hhcnRXIiwiY2hhcnRIIiwicG9pbnRzIiwiaSIsIngiLCJ5IiwibGluZVBhdGgiLCJwIiwiam9pbiIsImFyZWFQYXRoIiwiZ3JpZExpbmVzIiwicGN0IiwibGFiZWwiLCJyb3VuZCIsIlJlYWN0IiwiY3JlYXRlRWxlbWVudCIsInZpZXdCb3giLCJwcmVzZXJ2ZUFzcGVjdFJhdGlvIiwiaWQiLCJ4MSIsInkxIiwieDIiLCJ5MiIsIm9mZnNldCIsInN0b3BDb2xvciIsInN0b3BPcGFjaXR5IiwiZyIsImtleSIsInN0cm9rZSIsInN0cm9rZVdpZHRoIiwic3Ryb2tlRGFzaGFycmF5IiwiZmlsbCIsImZvbnRTaXplIiwidGV4dEFuY2hvciIsInN0cm9rZUxpbmVqb2luIiwic3Ryb2tlTGluZWNhcCIsImN4IiwiY3kiLCJyIiwiRG9udXRDaGFydCIsInNpemUiLCJ0b3RhbCIsInJlZHVjZSIsInMiLCJvdXRlclIiLCJpbm5lclIiLCJjdW1BbmdsZSIsIlBJIiwic2xpY2VzIiwiYW5nbGUiLCJzdGFydEFuZ2xlIiwiZW5kQW5nbGUiLCJjb3MiLCJzaW4iLCJpeDEiLCJpeTEiLCJpeDIiLCJpeTIiLCJsYXJnZUFyYyIsInBhdGgiLCJuYW1lIiwic3R5bGUiLCJkaXNwbGF5IiwiYWxpZ25JdGVtcyIsImdhcCIsImZsZXhXcmFwIiwianVzdGlmeUNvbnRlbnQiLCJmb250V2VpZ2h0IiwiZmxleERpcmVjdGlvbiIsImZsZXhTaHJpbmsiLCJtYXJnaW5MZWZ0IiwiU3RhdENhcmQiLCJpY29uIiwiZGVsdGEiLCJkZWx0YUxhYmVsIiwiQm94IiwiZmxleCIsIm1pbldpZHRoIiwib25Nb3VzZUVudGVyIiwiZSIsImN1cnJlbnRUYXJnZXQiLCJib3JkZXJDb2xvciIsInRyYW5zZm9ybSIsImJveFNoYWRvdyIsIm9uTW91c2VMZWF2ZSIsImJvcmRlckxlZnRDb2xvciIsIm1hcmdpbkJvdHRvbSIsIkljb24iLCJUZXh0IiwidGV4dFRyYW5zZm9ybSIsImxldHRlclNwYWNpbmciLCJIMiIsIm1hcmdpbiIsInVuZGVmaW5lZCIsIkFjdGlvbkNhcmQiLCJjb3VudCIsInJlc291cmNlSWQiLCJocmVmIiwidGV4dERlY29yYXRpb24iLCJINSIsImZtdERhdGUiLCJkdCIsIkRhdGUiLCJ0b0xvY2FsZURhdGVTdHJpbmciLCJtb250aCIsImRheSIsInllYXIiLCJzdGF0dXNDb2xvciIsImxvd2VyIiwidG9Mb3dlckNhc2UiLCJDdXN0b21EYXNoYm9hcmQiLCJzZXREYXRhIiwidXNlU3RhdGUiLCJsb2FkaW5nIiwic2V0TG9hZGluZyIsImVycm9yIiwic2V0RXJyb3IiLCJ1c2VFZmZlY3QiLCJnZXREYXNoYm9hcmQiLCJ0aGVuIiwicmVzcG9uc2UiLCJjYXRjaCIsImZldGNoRXJyb3IiLCJjb25zb2xlIiwibWluSGVpZ2h0IiwidGV4dEFsaWduIiwiYm9yZGVyVG9wQ29sb3IiLCJhbmltYXRpb24iLCJtYXhXaWR0aCIsInN0YXRzIiwiYWN0aW9uUmVxdWlyZWQiLCJtb2RzQnlQbGF0Zm9ybSIsInVzZXJHcm93dGhEYXRhIiwicmVjZW50VXNlcnMiLCJyZWNlbnRNb2RzIiwiZ3Jvd3RoQ2hhcnREYXRhIiwiZGF0ZSIsInVzZXJzIiwibm93IiwiZ3JlZXRpbmciLCJnZXRIb3VycyIsImZvbnRGYW1pbHkiLCJwYWRkaW5nQm90dG9tIiwiYm9yZGVyQm90dG9tIiwidGV4dFNoYWRvdyIsImJhY2tncm91bmQiLCJtYXJnaW5Ub3AiLCJ3ZWVrZGF5IiwidGFyZ2V0IiwicmVsIiwidG90YWxVc2VycyIsInRvTG9jYWxlU3RyaW5nIiwibmV3VXNlcnNUaGlzTW9udGgiLCJ0b3RhbE1vZHMiLCJuZXdNb2RzVGhpc01vbnRoIiwidG90YWxEb3dubG9hZHMiLCJ0b3RhbFZpZXdzIiwicGVuZGluZ1JlcG9ydHMiLCJwZW5kaW5nQXBwcm92YWxzIiwib3BlblRpY2tldHMiLCJCYWRnZSIsImJvcmRlckNvbGxhcHNlIiwidSIsInVzZXJuYW1lIiwicm9sZSIsIm0iLCJvdmVyZmxvdyIsInRleHRPdmVyZmxvdyIsIndoaXRlU3BhY2UiLCJjYXRlZ29yeSIsInN0YXR1cyIsInBhZGRpbmdUb3AiLCJib3JkZXJUb3AiLCJTaWRlYmFyQnJhbmRpbmciLCJwb3NpdGlvbiIsImJvdHRvbSIsImxlZnQiLCJMaW5rIiwidG8iLCJzcmMiLCJhbHQiLCJmaWx0ZXIiLCJvbkVycm9yIiwiQWN0aW9uUmVkaXJlY3QiLCJwcm9wcyIsInJlY29yZCIsImFjdGlvbiIsInNlbmROb3RpY2UiLCJ1c2VOb3RpY2UiLCJ1cmwiLCJwYXJhbXMiLCJyZWRpcmVjdFVybCIsInNldFRpbWVvdXQiLCJ3aW5kb3ciLCJvcGVuIiwibWVzc2FnZSIsInR5cGUiLCJMb2FkZXIiLCJtdCIsInZhcmlhbnQiLCJWYXJpYW50QmFkZ2UiLCJwcm9wZXJ0eSIsImlzVmFyaWFudCIsIkF2YXRhckNlbGwiLCJ3aGVyZSIsImltYWdlVXJsIiwic2V0SW1hZ2VVcmwiLCJoYXNFcnJvciIsInNldEhhc0Vycm9yIiwic3RhcnRzV2l0aCIsImZldGNoU2lnbmVkVXJsIiwiZmV0Y2giLCJlbmNvZGVVUklDb21wb25lbnQiLCJvayIsImpzb24iLCJjaGFyQXQiLCJ0b1VwcGVyQ2FzZSIsIm9iamVjdEZpdCIsIkltYWdlUHJldmlldyIsInJhZGl1cyIsIk1hbmFnZVZvdGVzIiwicmVzb3VyY2UiLCJhZGROb3RpY2UiLCJ3b3JraW5nQ291bnQiLCJzZXRXb3JraW5nQ291bnQiLCJ3b3JraW5nVm90ZUNvdW50Iiwibm90V29ya2luZ0NvdW50Iiwic2V0Tm90V29ya2luZ0NvdW50Iiwibm90V29ya2luZ1ZvdGVDb3VudCIsImlzTG9hZGluZyIsInNldElzTG9hZGluZyIsImhhbmRsZVN1Ym1pdCIsImFjdGlvblR5cGUiLCJjb25maXJtIiwicmVzb3VyY2VBY3Rpb24iLCJhY3Rpb25OYW1lIiwicmVjb3JkSWQiLCJtZXRob2QiLCJuZXdXb3JraW5nQ291bnQiLCJuZXdOb3RXb3JraW5nQ291bnQiLCJub3RpY2UiLCJsb2NhdGlvbiIsIkgzIiwiTm90aWNlQm94IiwibWIiLCJCdXR0b24iLCJvbkNsaWNrIiwiZGlzYWJsZWQiLCJGb3JtR3JvdXAiLCJMYWJlbCIsIklucHV0Iiwib25DaGFuZ2UiLCJBZG1pbkpTIiwiVXNlckNvbXBvbmVudHMiLCJlbnYiLCJOT0RFX0VOViIsIkRhc2hib2FyZCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztFQUlBLE1BQU1BLEtBQUcsR0FBRyxJQUFJQyxpQkFBUyxFQUFFOztFQUUzQjtFQUNBLE1BQU1DLENBQUMsR0FBRztFQUNSQyxFQUFBQSxFQUFFLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxPQUFPLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxVQUFVLEVBQUUsU0FBUztFQUN4REMsRUFBQUEsTUFBTSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsV0FBVyxFQUFFLFNBQVM7RUFDekNDLEVBQUFBLElBQUksRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE9BQU8sRUFBRSxzQkFBc0I7RUFBRUMsRUFBQUEsUUFBUSxFQUFF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
