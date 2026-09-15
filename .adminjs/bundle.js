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
        alignItems: 'center',
        gap: '16px',
        paddingBottom: '24px',
        borderBottom: `1px solid ${C.border}`,
        marginBottom: '28px'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", null, /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin",
      style: {
        textDecoration: 'none',
        display: 'inline-flex',
        alignItems: 'center',
        cursor: 'pointer'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.H2, {
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
    }, "Admin Dashboard"))), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textMuted,
        marginTop: '6px'
      }
    }, greeting, "! Here's your platform overview for ", now.toLocaleDateString('en-US', {
      weekday: 'long',
      month: 'long',
      day: 'numeric',
      year: 'numeric'
    }), ".")), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: '10px'
      }
    }, /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        color: C.gold,
        backgroundColor: C.goldDim,
        border: `1px solid ${C.gold}`,
        padding: '8px 14px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '13px',
        transition: 'all 0.2s'
      },
      onMouseEnter: e => {
        e.currentTarget.style.backgroundColor = 'rgba(255,215,0,0.25)';
      },
      onMouseLeave: e => {
        e.currentTarget.style.backgroundColor = C.goldDim;
      },
      title: "AdminJS Main Dashboard"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Home",
      size: 14
    }), " AdminJS"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/reports",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        color: '#ff6b6b',
        backgroundColor: 'rgba(229,57,53,0.12)',
        border: '1px solid rgba(229,57,53,0.3)',
        padding: '8px 14px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '13px',
        transition: 'all 0.2s'
      },
      onMouseEnter: e => {
        e.currentTarget.style.backgroundColor = 'rgba(229,57,53,0.25)';
      },
      onMouseLeave: e => {
        e.currentTarget.style.backgroundColor = 'rgba(229,57,53,0.12)';
      },
      title: "Moderation & Mod Reports Console"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Flag",
      size: 14
    }), " Reports"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/support",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        color: '#64b5f6',
        backgroundColor: 'rgba(33,150,243,0.12)',
        border: '1px solid rgba(33,150,243,0.3)',
        padding: '8px 14px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '13px',
        transition: 'all 0.2s'
      },
      onMouseEnter: e => {
        e.currentTarget.style.backgroundColor = 'rgba(33,150,243,0.25)';
      },
      onMouseLeave: e => {
        e.currentTarget.style.backgroundColor = 'rgba(33,150,243,0.12)';
      },
      title: "Live Support & Inquiries Console"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "HelpCircle",
      size: 14
    }), " Support"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/status",
      target: "_blank",
      rel: "noopener noreferrer",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        color: '#81c784',
        backgroundColor: 'rgba(67,160,71,0.12)',
        border: '1px solid rgba(67,160,71,0.3)',
        padding: '8px 14px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '13px',
        transition: 'all 0.2s'
      },
      onMouseEnter: e => {
        e.currentTarget.style.backgroundColor = 'rgba(67,160,71,0.25)';
      },
      onMouseLeave: e => {
        e.currentTarget.style.backgroundColor = 'rgba(67,160,71,0.12)';
      },
      title: "Live Server Health & Diagnostics"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Activity",
      size: 14
    }), " Status"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/music",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        color: '#ba68c8',
        backgroundColor: 'rgba(186,104,200,0.12)',
        border: '1px solid rgba(186,104,200,0.3)',
        padding: '8px 14px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '13px',
        transition: 'all 0.2s'
      },
      onMouseEnter: e => {
        e.currentTarget.style.backgroundColor = 'rgba(186,104,200,0.25)';
      },
      onMouseLeave: e => {
        e.currentTarget.style.backgroundColor = 'rgba(186,104,200,0.12)';
      },
      title: "Music & Playlist Manager"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Music",
      size: 14
    }), " Music"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/home",
      target: "_blank",
      rel: "noopener noreferrer",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        color: '#e0e0e0',
        backgroundColor: C.surfaceAlt,
        border: `1px solid ${C.border}`,
        padding: '8px 14px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '13px',
        transition: 'all 0.2s'
      },
      onMouseEnter: e => {
        e.currentTarget.style.borderColor = C.gold;
        e.currentTarget.style.color = C.gold;
      },
      onMouseLeave: e => {
        e.currentTarget.style.borderColor = C.border;
        e.currentTarget.style.color = '#e0e0e0';
      },
      title: "Open Live Public Site"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Globe",
      size: 14
    }), " Live Site"))), /*#__PURE__*/React__default.default.createElement("div", {
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
    }, /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin",
      style: {
        textDecoration: 'none'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textDim,
        fontSize: '12px',
        cursor: 'pointer'
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
    }, "Mods"), " \u2022 Admin Panel v2.5")), /*#__PURE__*/React__default.default.createElement("div", {
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
    }, "Tickets"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/music",
      style: {
        color: C.textMuted,
        fontSize: '12px',
        textDecoration: 'none'
      }
    }, "Music"))));
  };

  const SidebarBranding = () => {
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      p: "lg",
      style: {
        borderBottom: '1px solid #2a2a2a',
        backgroundColor: '#0a0a0a',
        padding: '20px 16px',
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
    }), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin",
      style: {
        textDecoration: 'none',
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        cursor: 'pointer',
        transition: 'opacity 0.2s ease'
      },
      onMouseEnter: e => {
        e.currentTarget.style.opacity = '0.85';
      },
      onMouseLeave: e => {
        e.currentTarget.style.opacity = '1';
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
    }, "v2.5"))), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin",
      style: {
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
      },
      onMouseEnter: e => {
        e.currentTarget.style.backgroundColor = 'rgba(255, 215, 0, 0.2)';
        e.currentTarget.style.boxShadow = '0 0 14px rgba(255,215,0,0.3)';
      },
      onMouseLeave: e => {
        e.currentTarget.style.backgroundColor = 'rgba(255, 215, 0, 0.08)';
        e.currentTarget.style.boxShadow = 'none';
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Home",
      size: 13,
      color: "#FFD700"
    }), /*#__PURE__*/React__default.default.createElement("span", null, "Dashboard")));
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIiwic291cmNlcyI6WyIuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQuanN4IiwiLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nLmpzeCIsIi4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdC5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL1ZhcmlhbnRCYWRnZS5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL0F2YXRhckNlbGwuanN4IiwiLi4vY29tcG9uZW50cy9jZWxscy9JbWFnZVByZXZpZXcuanN4IiwiLi4vY29tcG9uZW50cy9hY3Rpb25zL01hbmFnZVZvdGVzLmpzeCIsImVudHJ5LmpzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQXBpQ2xpZW50IH0gZnJvbSAnYWRtaW5qcyc7XG5pbXBvcnQgeyBCb3gsIEgyLCBINSwgVGV4dCwgSWNvbiwgQmFkZ2UgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgYXBpID0gbmV3IEFwaUNsaWVudCgpO1xuXG4vKiDilIDilIDilIAgY29sb3VyIHRva2VucyDilIDilIDilIAgKi9cbmNvbnN0IEMgPSB7XG4gIGJnOiAnIzBhMGEwYScsIHN1cmZhY2U6ICcjMTMxMzEzJywgc3VyZmFjZUFsdDogJyMxYTFhMWEnLFxuICBib3JkZXI6ICcjMmEyYTJhJywgYm9yZGVySG92ZXI6ICcjM2EzYTNhJyxcbiAgZ29sZDogJyNGRkQ3MDAnLCBnb2xkRGltOiAncmdiYSgyNTUsMjE1LDAsMC4xNSknLCBnb2xkR2xvdzogJ3JnYmEoMjU1LDIxNSwwLDAuMzUpJyxcbiAgYmx1ZTogJyMyMTk2RjMnLCBncmVlbjogJyM0M2EwNDcnLCBwdXJwbGU6ICcjOUMyN0IwJywgcmVkOiAnI2U1MzkzNScsIG9yYW5nZTogJyNGRjk4MDAnLFxuICB0ZXh0OiAnI2ZmZmZmZicsIHRleHRNdXRlZDogJyM5OTknLCB0ZXh0RGltOiAnIzY2NicsXG59O1xuXG4vKiDilIDilIDilIAgcGxhdGZvcm0gY2hhcnQgY29sb3VycyDilIDilIDilIAgKi9cbmNvbnN0IFBMQVRGT1JNX0NPTE9SUyA9IFsnI0E0QzYzOScsICcjMDA3OEQ2JywgJyMyMTc1OUInLCAnI0ZGOTgwMCcsICcjOUMyN0IwJywgJyNlNTM5MzUnLCAnIzQzYTA0NycsICcjRkZENzAwJ107XG5cbi8qIOKUgOKUgOKUgCByZXVzYWJsZSBjYXJkIHN0eWxlIOKUgOKUgOKUgCAqL1xuY29uc3QgY2FyZFN0eWxlID0gKGFjY2VudENvbG9yKSA9PiAoe1xuICBiYWNrZ3JvdW5kQ29sb3I6IEMuc3VyZmFjZSxcbiAgYm9yZGVyUmFkaXVzOiAnMTZweCcsXG4gIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsXG4gIGJvcmRlckxlZnQ6IGFjY2VudENvbG9yID8gYDRweCBzb2xpZCAke2FjY2VudENvbG9yfWAgOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCxcbiAgcGFkZGluZzogJzI0cHgnLFxuICB0cmFuc2l0aW9uOiAnYWxsIDAuMjVzIGVhc2UnLFxuICBjdXJzb3I6ICdkZWZhdWx0Jyxcbn0pO1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBBcmVhIENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgQXJlYUNoYXJ0ID0gKHsgZGF0YSwgd2lkdGggPSA1MDAsIGhlaWdodCA9IDIwMCwgY29sb3IgPSBDLmdvbGQgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBtYXhWYWwgPSBNYXRoLm1heCguLi5kYXRhLm1hcChkID0+IGQudmFsdWUpLCAxKTtcbiAgY29uc3QgcGFkWCA9IDQwO1xuICBjb25zdCBwYWRZID0gMjA7XG4gIGNvbnN0IGNoYXJ0VyA9IHdpZHRoIC0gcGFkWCAqIDI7XG4gIGNvbnN0IGNoYXJ0SCA9IGhlaWdodCAtIHBhZFkgKiAyO1xuXG4gIGNvbnN0IHBvaW50cyA9IGRhdGEubWFwKChkLCBpKSA9PiAoe1xuICAgIHg6IHBhZFggKyAoaSAvIE1hdGgubWF4KGRhdGEubGVuZ3RoIC0gMSwgMSkpICogY2hhcnRXLFxuICAgIHk6IHBhZFkgKyBjaGFydEggLSAoZC52YWx1ZSAvIG1heFZhbCkgKiBjaGFydEgsXG4gIH0pKTtcblxuICBjb25zdCBsaW5lUGF0aCA9IHBvaW50cy5tYXAoKHAsIGkpID0+IGAke2kgPT09IDAgPyAnTScgOiAnTCd9JHtwLnh9LCR7cC55fWApLmpvaW4oJyAnKTtcbiAgY29uc3QgYXJlYVBhdGggPSBgJHtsaW5lUGF0aH0gTCR7cG9pbnRzW3BvaW50cy5sZW5ndGggLSAxXS54fSwke3BhZFkgKyBjaGFydEh9IEwke3BvaW50c1swXS54fSwke3BhZFkgKyBjaGFydEh9IFpgO1xuXG4gIC8vIEdyaWQgbGluZXNcbiAgY29uc3QgZ3JpZExpbmVzID0gWzAsIDAuMjUsIDAuNSwgMC43NSwgMV0ubWFwKHBjdCA9PiB7XG4gICAgY29uc3QgeSA9IHBhZFkgKyBjaGFydEggLSBwY3QgKiBjaGFydEg7XG4gICAgY29uc3QgbGFiZWwgPSBNYXRoLnJvdW5kKHBjdCAqIG1heFZhbCk7XG4gICAgcmV0dXJuIHsgeSwgbGFiZWwgfTtcbiAgfSk7XG5cbiAgcmV0dXJuIChcbiAgICA8c3ZnIHdpZHRoPVwiMTAwJVwiIGhlaWdodD17aGVpZ2h0fSB2aWV3Qm94PXtgMCAwICR7d2lkdGh9ICR7aGVpZ2h0fWB9IHByZXNlcnZlQXNwZWN0UmF0aW89XCJ4TWlkWU1pZCBtZWV0XCI+XG4gICAgICA8ZGVmcz5cbiAgICAgICAgPGxpbmVhckdyYWRpZW50IGlkPVwiYXJlYUZpbGxcIiB4MT1cIjBcIiB5MT1cIjBcIiB4Mj1cIjBcIiB5Mj1cIjFcIj5cbiAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIwJVwiIHN0b3BDb2xvcj17Y29sb3J9IHN0b3BPcGFjaXR5PVwiMC4zXCIgLz5cbiAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIxMDAlXCIgc3RvcENvbG9yPXtjb2xvcn0gc3RvcE9wYWNpdHk9XCIwLjAyXCIgLz5cbiAgICAgICAgPC9saW5lYXJHcmFkaWVudD5cbiAgICAgIDwvZGVmcz5cbiAgICAgIHsvKiBHcmlkICovfVxuICAgICAge2dyaWRMaW5lcy5tYXAoKGcsIGkpID0+IChcbiAgICAgICAgPGcga2V5PXtpfT5cbiAgICAgICAgICA8bGluZSB4MT17cGFkWH0geTE9e2cueX0geDI9e3dpZHRoIC0gcGFkWH0geTI9e2cueX0gc3Ryb2tlPXtDLmJvcmRlcn0gc3Ryb2tlV2lkdGg9XCIxXCIgc3Ryb2tlRGFzaGFycmF5PVwiNCA0XCIgLz5cbiAgICAgICAgICA8dGV4dCB4PXtwYWRYIC0gNn0geT17Zy55ICsgNH0gZmlsbD17Qy50ZXh0RGltfSBmb250U2l6ZT1cIjEwXCIgdGV4dEFuY2hvcj1cImVuZFwiPntnLmxhYmVsfTwvdGV4dD5cbiAgICAgICAgPC9nPlxuICAgICAgKSl9XG4gICAgICB7LyogQXJlYSBmaWxsICovfVxuICAgICAgPHBhdGggZD17YXJlYVBhdGh9IGZpbGw9XCJ1cmwoI2FyZWFGaWxsKVwiIC8+XG4gICAgICB7LyogTGluZSAqL31cbiAgICAgIDxwYXRoIGQ9e2xpbmVQYXRofSBmaWxsPVwibm9uZVwiIHN0cm9rZT17Y29sb3J9IHN0cm9rZVdpZHRoPVwiMi41XCIgc3Ryb2tlTGluZWpvaW49XCJyb3VuZFwiIHN0cm9rZUxpbmVjYXA9XCJyb3VuZFwiIC8+XG4gICAgICB7LyogRG90cyArIGxhYmVscyAqL31cbiAgICAgIHtwb2ludHMubWFwKChwLCBpKSA9PiAoXG4gICAgICAgIDxnIGtleT17aX0+XG4gICAgICAgICAgPGNpcmNsZSBjeD17cC54fSBjeT17cC55fSByPVwiNFwiIGZpbGw9e0MuYmd9IHN0cm9rZT17Y29sb3J9IHN0cm9rZVdpZHRoPVwiMlwiIC8+XG4gICAgICAgICAgPHRleHQgeD17cC54fSB5PXtwYWRZICsgY2hhcnRIICsgMTZ9IGZpbGw9e0MudGV4dE11dGVkfSBmb250U2l6ZT1cIjlcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e2RhdGFbaV0ubGFiZWx9PC90ZXh0PlxuICAgICAgICA8L2c+XG4gICAgICApKX1cbiAgICA8L3N2Zz5cbiAgKTtcbn07XG5cbi8qIOKUgOKUgOKUgCBJbmxpbmUgU1ZHIERvbnV0IENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgRG9udXRDaGFydCA9ICh7IGRhdGEsIHNpemUgPSAyMDAgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCB0b3RhbCA9IGRhdGEucmVkdWNlKChzLCBkKSA9PiBzICsgZC52YWx1ZSwgMCk7XG4gIGlmICh0b3RhbCA9PT0gMCkgcmV0dXJuIG51bGw7XG4gIGNvbnN0IGN4ID0gc2l6ZSAvIDI7XG4gIGNvbnN0IGN5ID0gc2l6ZSAvIDI7XG4gIGNvbnN0IG91dGVyUiA9IHNpemUgLyAyIC0gMTA7XG4gIGNvbnN0IGlubmVyUiA9IG91dGVyUiAqIDAuNjtcbiAgbGV0IGN1bUFuZ2xlID0gLU1hdGguUEkgLyAyO1xuXG4gIGNvbnN0IHNsaWNlcyA9IGRhdGEubWFwKChkLCBpKSA9PiB7XG4gICAgY29uc3QgYW5nbGUgPSAoZC52YWx1ZSAvIHRvdGFsKSAqIE1hdGguUEkgKiAyO1xuICAgIGNvbnN0IHN0YXJ0QW5nbGUgPSBjdW1BbmdsZTtcbiAgICBjdW1BbmdsZSArPSBhbmdsZTtcbiAgICBjb25zdCBlbmRBbmdsZSA9IGN1bUFuZ2xlO1xuXG4gICAgY29uc3QgeDEgPSBjeCArIG91dGVyUiAqIE1hdGguY29zKHN0YXJ0QW5nbGUpO1xuICAgIGNvbnN0IHkxID0gY3kgKyBvdXRlclIgKiBNYXRoLnNpbihzdGFydEFuZ2xlKTtcbiAgICBjb25zdCB4MiA9IGN4ICsgb3V0ZXJSICogTWF0aC5jb3MoZW5kQW5nbGUpO1xuICAgIGNvbnN0IHkyID0gY3kgKyBvdXRlclIgKiBNYXRoLnNpbihlbmRBbmdsZSk7XG4gICAgY29uc3QgaXgxID0gY3ggKyBpbm5lclIgKiBNYXRoLmNvcyhlbmRBbmdsZSk7XG4gICAgY29uc3QgaXkxID0gY3kgKyBpbm5lclIgKiBNYXRoLnNpbihlbmRBbmdsZSk7XG4gICAgY29uc3QgaXgyID0gY3ggKyBpbm5lclIgKiBNYXRoLmNvcyhzdGFydEFuZ2xlKTtcbiAgICBjb25zdCBpeTIgPSBjeSArIGlubmVyUiAqIE1hdGguc2luKHN0YXJ0QW5nbGUpO1xuICAgIGNvbnN0IGxhcmdlQXJjID0gYW5nbGUgPiBNYXRoLlBJID8gMSA6IDA7XG4gICAgY29uc3QgY29sb3IgPSBQTEFURk9STV9DT0xPUlNbaSAlIFBMQVRGT1JNX0NPTE9SUy5sZW5ndGhdO1xuXG4gICAgY29uc3QgcGF0aCA9IGBNJHt4MX0sJHt5MX0gQSR7b3V0ZXJSfSwke291dGVyUn0gMCAke2xhcmdlQXJjfSAxICR7eDJ9LCR7eTJ9IEwke2l4MX0sJHtpeTF9IEEke2lubmVyUn0sJHtpbm5lclJ9IDAgJHtsYXJnZUFyY30gMCAke2l4Mn0sJHtpeTJ9IFpgO1xuICAgIHJldHVybiB7IHBhdGgsIGNvbG9yLCBuYW1lOiBkLm5hbWUsIHZhbHVlOiBkLnZhbHVlLCBwY3Q6IE1hdGgucm91bmQoKGQudmFsdWUgLyB0b3RhbCkgKiAxMDApIH07XG4gIH0pO1xuXG4gIHJldHVybiAoXG4gICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcyNHB4JywgZmxleFdyYXA6ICd3cmFwJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInIH19PlxuICAgICAgPHN2ZyB3aWR0aD17c2l6ZX0gaGVpZ2h0PXtzaXplfSB2aWV3Qm94PXtgMCAwICR7c2l6ZX0gJHtzaXplfWB9PlxuICAgICAgICB7c2xpY2VzLm1hcCgocywgaSkgPT4gKFxuICAgICAgICAgIDxwYXRoIGtleT17aX0gZD17cy5wYXRofSBmaWxsPXtzLmNvbG9yfSBzdHJva2U9e0MuYmd9IHN0cm9rZVdpZHRoPVwiMlwiPlxuICAgICAgICAgICAgPHRpdGxlPntzLm5hbWV9OiB7cy52YWx1ZX0gKHtzLnBjdH0lKTwvdGl0bGU+XG4gICAgICAgICAgPC9wYXRoPlxuICAgICAgICApKX1cbiAgICAgICAgPHRleHQgeD17Y3h9IHk9e2N5IC0gNn0gZmlsbD17Qy50ZXh0fSBmb250U2l6ZT1cIjIyXCIgZm9udFdlaWdodD1cImJvbGRcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e3RvdGFsfTwvdGV4dD5cbiAgICAgICAgPHRleHQgeD17Y3h9IHk9e2N5ICsgMTR9IGZpbGw9e0MudGV4dE11dGVkfSBmb250U2l6ZT1cIjEwXCIgdGV4dEFuY2hvcj1cIm1pZGRsZVwiPlRPVEFMPC90ZXh0PlxuICAgICAgPC9zdmc+XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleERpcmVjdGlvbjogJ2NvbHVtbicsIGdhcDogJzZweCcgfX0+XG4gICAgICAgIHtzbGljZXMubWFwKChzLCBpKSA9PiAoXG4gICAgICAgICAgPGRpdiBrZXk9e2l9IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIGZvbnRTaXplOiAnMTJweCcgfX0+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyB3aWR0aDogMTIsIGhlaWdodDogMTIsIGJvcmRlclJhZGl1czogJzNweCcsIGJhY2tncm91bmRDb2xvcjogcy5jb2xvciwgZGlzcGxheTogJ2lubGluZS1ibG9jaycsIGZsZXhTaHJpbms6IDAgfX0gLz5cbiAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLnRleHQgfX0+e3MubmFtZX08L3NwYW4+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCBtYXJnaW5MZWZ0OiAnYXV0bycgfX0+e3MudmFsdWV9ICh7cy5wY3R9JSk8L3NwYW4+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICkpfVxuICAgICAgPC9kaXY+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG4vKiDilIDilIDilIAgU3RhdCBDYXJkIOKUgOKUgOKUgCAqL1xuY29uc3QgU3RhdENhcmQgPSAoeyBpY29uLCBsYWJlbCwgdmFsdWUsIGRlbHRhLCBkZWx0YUxhYmVsLCBhY2NlbnRDb2xvciB9KSA9PiAoXG4gIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKGFjY2VudENvbG9yKSwgZmxleDogJzEnLCBtaW5XaWR0aDogJzIyMHB4JyB9fVxuICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IGFjY2VudENvbG9yIHx8IEMuYm9yZGVySG92ZXI7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgtMnB4KSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSBgMCA4cHggMjRweCByZ2JhKDAsMCwwLDAuNClgOyB9fVxuICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuYm9yZGVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyTGVmdENvbG9yID0gYWNjZW50Q29sb3I7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgwKSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnbm9uZSc7IH19XG4gID5cbiAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE0cHgnIH19PlxuICAgICAgPEljb24gaWNvbj17aWNvbn0gY29sb3I9e2FjY2VudENvbG9yfSAvPlxuICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzExcHgnLCBmb250V2VpZ2h0OiA3MDAsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wOGVtJyB9fT57bGFiZWx9PC9UZXh0PlxuICAgIDwvZGl2PlxuICAgIDxIMiBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46ICcwIDAgOHB4IDAnLCBmb250U2l6ZTogJzIuMnJlbScgfX0+e3ZhbHVlfTwvSDI+XG4gICAge2RlbHRhICE9PSB1bmRlZmluZWQgJiYgKFxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnIH19PlxuICAgICAgICA8SWNvbiBpY29uPVwiQXJyb3dVcFwiIHNpemU9ezE0fSBjb2xvcj17Qy5ncmVlbn0gLz5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMuZ3JlZW4sIGZvbnRTaXplOiAnMTNweCcsIGZvbnRXZWlnaHQ6IDYwMCB9fT4re2RlbHRhfSB7ZGVsdGFMYWJlbCB8fCAndGhpcyBtb250aCd9PC9UZXh0PlxuICAgICAgPC9kaXY+XG4gICAgKX1cbiAgPC9Cb3g+XG4pO1xuXG4vKiDilIDilIDilIAgQWN0aW9uIEJhZGdlIENhcmQg4pSA4pSA4pSAICovXG5jb25zdCBBY3Rpb25DYXJkID0gKHsgaWNvbiwgbGFiZWwsIGNvdW50LCBhY2NlbnRDb2xvciwgcmVzb3VyY2VJZCB9KSA9PiAoXG4gIDxhIGhyZWY9e2AvYWRtaW4vcmVzb3VyY2VzLyR7cmVzb3VyY2VJZH1gfSBzdHlsZT17eyB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmbGV4OiAnMScsIG1pbldpZHRoOiAnMTgwcHgnIH19PlxuICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKGFjY2VudENvbG9yKSwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMTZweCcgfX1cbiAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoLTJweCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gYDAgNnB4IDIwcHggcmdiYSgwLDAsMCwwLjMpYDsgfX1cbiAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuYm9yZGVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyTGVmdENvbG9yID0gYWNjZW50Q29sb3I7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgwKSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnbm9uZSc7IH19XG4gICAgPlxuICAgICAgPGRpdiBzdHlsZT17eyB3aWR0aDogNDQsIGhlaWdodDogNDQsIGJvcmRlclJhZGl1czogJzEycHgnLCBiYWNrZ3JvdW5kQ29sb3I6IGAke2FjY2VudENvbG9yfTE1YCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLCBmbGV4U2hyaW5rOiAwIH19PlxuICAgICAgICA8SWNvbiBpY29uPXtpY29ufSBzaXplPXsyMn0gY29sb3I9e2FjY2VudENvbG9yfSAvPlxuICAgICAgPC9kaXY+XG4gICAgICA8ZGl2PlxuICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTFweCcsIGZvbnRXZWlnaHQ6IDYwMCwgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nIH19PntsYWJlbH08L1RleHQ+XG4gICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogY291bnQgPiAwID8gYWNjZW50Q29sb3IgOiBDLnRleHREaW0sIG1hcmdpbjogJzRweCAwIDAgMCcgfX0+e2NvdW50fTwvSDU+XG4gICAgICA8L2Rpdj5cbiAgICAgIDxJY29uIGljb249XCJDaGV2cm9uUmlnaHRcIiBjb2xvcj17Qy50ZXh0RGltfSBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnYXV0bycgfX0gLz5cbiAgICA8L0JveD5cbiAgPC9hPlxuKTtcblxuLyog4pSA4pSA4pSAIEZvcm1hdCBkYXRlIG5pY2VseSDilIDilIDilIAgKi9cbmNvbnN0IGZtdERhdGUgPSAoZCkgPT4ge1xuICBpZiAoIWQpIHJldHVybiAn4oCUJztcbiAgY29uc3QgZHQgPSBuZXcgRGF0ZShkKTtcbiAgcmV0dXJuIGR0LnRvTG9jYWxlRGF0ZVN0cmluZygnZW4tVVMnLCB7IG1vbnRoOiAnc2hvcnQnLCBkYXk6ICdudW1lcmljJywgeWVhcjogJ251bWVyaWMnIH0pO1xufTtcblxuLyog4pSA4pSA4pSAIFN0YXR1cyBiYWRnZSBjb2xvciDilIDilIDilIAgKi9cbmNvbnN0IHN0YXR1c0NvbG9yID0gKHMpID0+IHtcbiAgaWYgKCFzKSByZXR1cm4gQy50ZXh0RGltO1xuICBjb25zdCBsb3dlciA9IHMudG9Mb3dlckNhc2UoKTtcbiAgaWYgKGxvd2VyID09PSAnYXBwcm92ZWQnIHx8IGxvd2VyID09PSAnYWN0aXZlJykgcmV0dXJuIEMuZ3JlZW47XG4gIGlmIChsb3dlciA9PT0gJ3BlbmRpbmcnKSByZXR1cm4gQy5vcmFuZ2U7XG4gIGlmIChsb3dlciA9PT0gJ3JlamVjdGVkJykgcmV0dXJuIEMucmVkO1xuICByZXR1cm4gQy50ZXh0TXV0ZWQ7XG59O1xuXG4vKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbiAgIE1BSU4gREFTSEJPQVJEIENPTVBPTkVOVFxuICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovXG5jb25zdCBDdXN0b21EYXNoYm9hcmQgPSAoKSA9PiB7XG4gIGNvbnN0IFtkYXRhLCBzZXREYXRhXSA9IHVzZVN0YXRlKG51bGwpO1xuICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcbiAgY29uc3QgW2Vycm9yLCBzZXRFcnJvcl0gPSB1c2VTdGF0ZShudWxsKTtcblxuICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgIGFwaS5nZXREYXNoYm9hcmQoKVxuICAgICAgLnRoZW4oKHJlc3BvbnNlKSA9PiB7XG4gICAgICAgIHNldERhdGEocmVzcG9uc2UuZGF0YSB8fCB7fSk7XG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgfSlcbiAgICAgIC5jYXRjaCgoZmV0Y2hFcnJvcikgPT4ge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdEYXNoYm9hcmQgZmV0Y2ggZXJyb3I6JywgZmV0Y2hFcnJvcik7XG4gICAgICAgIHNldEVycm9yKCdGYWlsZWQgdG8gbG9hZCBkYXNoYm9hcmQgZGF0YS4nKTtcbiAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICB9KTtcbiAgfSwgW10pO1xuXG4gIGlmIChsb2FkaW5nKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgbWluSGVpZ2h0OiAnMTAwdmgnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgPGRpdiBzdHlsZT17eyB0ZXh0QWxpZ246ICdjZW50ZXInIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6IDQwLCBoZWlnaHQ6IDQwLCBib3JkZXI6IGAzcHggc29saWQgJHtDLmJvcmRlcn1gLCBib3JkZXJUb3BDb2xvcjogQy5nb2xkLCBib3JkZXJSYWRpdXM6ICc1MCUnLCBhbmltYXRpb246ICdzcGluIDFzIGxpbmVhciBpbmZpbml0ZScsIG1hcmdpbjogJzAgYXV0byAxNnB4JyB9fSAvPlxuICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCB9fT5Mb2FkaW5nIGRhc2hib2FyZC4uLjwvVGV4dD5cbiAgICAgICAgICA8c3R5bGU+e2BAa2V5ZnJhbWVzIHNwaW4geyB0byB7IHRyYW5zZm9ybTogcm90YXRlKDM2MGRlZyk7IH0gfWB9PC9zdHlsZT5cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L2Rpdj5cbiAgICApO1xuICB9XG5cbiAgaWYgKGVycm9yKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgbWluSGVpZ2h0OiAnMTAwdmgnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoQy5yZWQpLCBtYXhXaWR0aDogNDAwLCB0ZXh0QWxpZ246ICdjZW50ZXInIH19PlxuICAgICAgICAgIDxJY29uIGljb249XCJBbGVydFRyaWFuZ2xlXCIgc2l6ZT17MzJ9IGNvbG9yPXtDLnJlZH0gLz5cbiAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMucmVkLCBtYXJnaW46ICcxNnB4IDAgOHB4JyB9fT57ZXJyb3J9PC9INT5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQgfX0+Q2hlY2sgdGhlIHNlcnZlciBsb2dzIGZvciBkZXRhaWxzLjwvVGV4dD5cbiAgICAgICAgPC9Cb3g+XG4gICAgICA8L2Rpdj5cbiAgICApO1xuICB9XG5cbiAgY29uc3Qgc3RhdHMgPSBkYXRhPy5zdGF0cyB8fCB7fTtcbiAgY29uc3QgYWN0aW9uUmVxdWlyZWQgPSBkYXRhPy5hY3Rpb25SZXF1aXJlZCB8fCB7fTtcbiAgY29uc3QgbW9kc0J5UGxhdGZvcm0gPSBkYXRhPy5tb2RzQnlQbGF0Zm9ybSB8fCBbXTtcbiAgY29uc3QgdXNlckdyb3d0aERhdGEgPSBkYXRhPy51c2VyR3Jvd3RoRGF0YSB8fCBbXTtcbiAgY29uc3QgcmVjZW50VXNlcnMgPSBkYXRhPy5yZWNlbnRVc2VycyB8fCBbXTtcbiAgY29uc3QgcmVjZW50TW9kcyA9IGRhdGE/LnJlY2VudE1vZHMgfHwgW107XG5cbiAgLy8gUHJlcGFyZSBjaGFydCBkYXRhXG4gIGNvbnN0IGdyb3d0aENoYXJ0RGF0YSA9IHVzZXJHcm93dGhEYXRhLm1hcChkID0+ICh7IGxhYmVsOiBkLmRhdGUsIHZhbHVlOiBkLnVzZXJzIH0pKTtcblxuICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICBjb25zdCBncmVldGluZyA9IG5vdy5nZXRIb3VycygpIDwgMTIgPyAnR29vZCBtb3JuaW5nJyA6IG5vdy5nZXRIb3VycygpIDwgMTggPyAnR29vZCBhZnRlcm5vb24nIDogJ0dvb2QgZXZlbmluZyc7XG5cbiAgcmV0dXJuIChcbiAgICA8ZGl2IHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogQy5iZywgbWluSGVpZ2h0OiAnMTAwdmgnLCBwYWRkaW5nOiAnMzJweCA0MHB4JywgZm9udEZhbWlseTogJ0ludGVyLCBzeXN0ZW0tdWksIC1hcHBsZS1zeXN0ZW0sIHNhbnMtc2VyaWYnIH19PlxuICAgICAgXG4gICAgICB7Lyog4pWQ4pWQ4pWQIEhFQURFUiDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywganVzdGlmeUNvbnRlbnQ6ICdzcGFjZS1iZXR3ZWVuJywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzE2cHgnLCBwYWRkaW5nQm90dG9tOiAnMjRweCcsIGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsIG1hcmdpbkJvdHRvbTogJzI4cHgnIH19PlxuICAgICAgICA8ZGl2PlxuICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW5cIiBzdHlsZT17eyB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgY3Vyc29yOiAncG9pbnRlcicgfX0+XG4gICAgICAgICAgICA8SDIgc3R5bGU9e3sgbWFyZ2luOiAwLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnIH19PlxuICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy5nb2xkLCB0ZXh0U2hhZG93OiBgMCAwIDIwcHggJHtDLmdvbGRHbG93fWAsIGZvbnRXZWlnaHQ6IDgwMCB9fT5HUEw8L3NwYW4+XG4gICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcsIGZvbnRXZWlnaHQ6IDcwMCB9fT5Nb2RzPC9zcGFuPlxuICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCBmb250U2l6ZTogJzAuNWVtJywgZm9udFdlaWdodDogNDAwLCBtYXJnaW5MZWZ0OiAnMTJweCcsIGJhY2tncm91bmQ6IEMuc3VyZmFjZUFsdCwgcGFkZGluZzogJzRweCAxMHB4JywgYm9yZGVyUmFkaXVzOiAnNnB4JywgYm9yZGVyOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5BZG1pbiBEYXNoYm9hcmQ8L3NwYW4+XG4gICAgICAgICAgICA8L0gyPlxuICAgICAgICAgIDwvYT5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQsIG1hcmdpblRvcDogJzZweCcgfX0+XG4gICAgICAgICAgICB7Z3JlZXRpbmd9ISBIZXJlJ3MgeW91ciBwbGF0Zm9ybSBvdmVydmlldyBmb3Ige25vdy50b0xvY2FsZURhdGVTdHJpbmcoJ2VuLVVTJywgeyB3ZWVrZGF5OiAnbG9uZycsIG1vbnRoOiAnbG9uZycsIGRheTogJ251bWVyaWMnLCB5ZWFyOiAnbnVtZXJpYycgfSl9LlxuICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgPC9kaXY+XG5cbiAgICAgICAgey8qIOKVkOKVkOKVkCBBRE1JTiBTVUlURSBTSE9SVENVVCBCVVRUT05TIOKVkOKVkOKVkCAqL31cbiAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcxMHB4JyB9fT5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvYWRtaW5cIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogQy5nb2xkLCBiYWNrZ3JvdW5kQ29sb3I6IEMuZ29sZERpbSwgYm9yZGVyOiBgMXB4IHNvbGlkICR7Qy5nb2xkfWAsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDI1NSwyMTUsMCwwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gQy5nb2xkRGltOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJBZG1pbkpTIE1haW4gRGFzaGJvYXJkXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiSG9tZVwiIHNpemU9ezE0fSAvPiBBZG1pbkpTXG4gICAgICAgICAgPC9hPlxuXG4gICAgICAgICAgPGEgXG4gICAgICAgICAgICBocmVmPVwiL2FkbWluL3JlcG9ydHNcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyNmZjZiNmInLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDIyOSw1Nyw1MywwLjEyKScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDIyOSw1Nyw1MywwLjMpJywgcGFkZGluZzogJzhweCAxNHB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEzcHgnLCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjI5LDU3LDUzLDAuMjUpJzsgfX1cbiAgICAgICAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyMjksNTcsNTMsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJNb2RlcmF0aW9uICYgTW9kIFJlcG9ydHMgQ29uc29sZVwiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkZsYWdcIiBzaXplPXsxNH0gLz4gUmVwb3J0c1xuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9hZG1pbi9zdXBwb3J0XCIgXG4gICAgICAgICAgICBzdHlsZT17eyBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JywgY29sb3I6ICcjNjRiNWY2JywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgzMywxNTAsMjQzLDAuMTIpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMzMsMTUwLDI0MywwLjMpJywgcGFkZGluZzogJzhweCAxNHB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEzcHgnLCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMzMsMTUwLDI0MywwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMzMsMTUwLDI0MywwLjEyKSc7IH19XG4gICAgICAgICAgICB0aXRsZT1cIkxpdmUgU3VwcG9ydCAmIElucXVpcmllcyBDb25zb2xlXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiSGVscENpcmNsZVwiIHNpemU9ezE0fSAvPiBTdXBwb3J0XG4gICAgICAgICAgPC9hPlxuXG4gICAgICAgICAgPGEgXG4gICAgICAgICAgICBocmVmPVwiL3N0YXR1c1wiIFxuICAgICAgICAgICAgdGFyZ2V0PVwiX2JsYW5rXCIgXG4gICAgICAgICAgICByZWw9XCJub29wZW5lciBub3JlZmVycmVyXCJcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyM4MWM3ODQnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDY3LDE2MCw3MSwwLjEyKScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDY3LDE2MCw3MSwwLjMpJywgcGFkZGluZzogJzhweCAxNHB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEzcHgnLCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoNjcsMTYwLDcxLDAuMjUpJzsgfX1cbiAgICAgICAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSg2NywxNjAsNzEsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJMaXZlIFNlcnZlciBIZWFsdGggJiBEaWFnbm9zdGljc1wiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkFjdGl2aXR5XCIgc2l6ZT17MTR9IC8+IFN0YXR1c1xuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9hZG1pbi9tdXNpY1wiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnI2JhNjhjOCcsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMTg2LDEwNCwyMDAsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgxODYsMTA0LDIwMCwwLjMpJywgcGFkZGluZzogJzhweCAxNHB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEzcHgnLCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMTg2LDEwNCwyMDAsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDE4NiwxMDQsMjAwLDAuMTIpJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiTXVzaWMgJiBQbGF5bGlzdCBNYW5hZ2VyXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiTXVzaWNcIiBzaXplPXsxNH0gLz4gTXVzaWNcbiAgICAgICAgICA8L2E+XG5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvaG9tZVwiIFxuICAgICAgICAgICAgdGFyZ2V0PVwiX2JsYW5rXCIgXG4gICAgICAgICAgICByZWw9XCJub29wZW5lciBub3JlZmVycmVyXCIgXG4gICAgICAgICAgICBzdHlsZT17eyBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JywgY29sb3I6ICcjZTBlMGUwJywgYmFja2dyb3VuZENvbG9yOiBDLnN1cmZhY2VBbHQsIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckNvbG9yID0gQy5nb2xkOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuY29sb3IgPSBDLmdvbGQ7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmNvbG9yID0gJyNlMGUwZTAnOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJPcGVuIExpdmUgUHVibGljIFNpdGVcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJHbG9iZVwiIHNpemU9ezE0fSAvPiBMaXZlIFNpdGVcbiAgICAgICAgICA8L2E+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgU1RBVCBDQVJEUyDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMjBweCcsIG1hcmdpbkJvdHRvbTogJzI0cHgnIH19PlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIlVzZXJzXCIgbGFiZWw9XCJUb3RhbCBVc2Vyc1wiIHZhbHVlPXsoc3RhdHMudG90YWxVc2VycyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBkZWx0YT17c3RhdHMubmV3VXNlcnNUaGlzTW9udGh9IGFjY2VudENvbG9yPXtDLmJsdWV9IC8+XG4gICAgICAgIDxTdGF0Q2FyZCBpY29uPVwiUGFja2FnZVwiIGxhYmVsPVwiVG90YWwgTW9kc1wiIHZhbHVlPXsoc3RhdHMudG90YWxNb2RzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGRlbHRhPXtzdGF0cy5uZXdNb2RzVGhpc01vbnRofSBhY2NlbnRDb2xvcj17Qy5nb2xkfSAvPlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIkRvd25sb2FkXCIgbGFiZWw9XCJUb3RhbCBEb3dubG9hZHNcIiB2YWx1ZT17KHN0YXRzLnRvdGFsRG93bmxvYWRzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGFjY2VudENvbG9yPXtDLmdyZWVufSAvPlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIkV5ZVwiIGxhYmVsPVwiVG90YWwgVmlld3NcIiB2YWx1ZT17KHN0YXRzLnRvdGFsVmlld3MgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gYWNjZW50Q29sb3I9e0MucHVycGxlfSAvPlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgQUNUSU9OIFJFUVVJUkVEIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcxNnB4JywgbWFyZ2luQm90dG9tOiAnMzJweCcgfX0+XG4gICAgICAgIDxBY3Rpb25DYXJkIGljb249XCJGbGFnXCIgbGFiZWw9XCJQZW5kaW5nIFJlcG9ydHNcIiBjb3VudD17YWN0aW9uUmVxdWlyZWQucGVuZGluZ1JlcG9ydHMgfHwgMH0gYWNjZW50Q29sb3I9e0MucmVkfSByZXNvdXJjZUlkPVwiUmVwb3J0XCIgLz5cbiAgICAgICAgPEFjdGlvbkNhcmQgaWNvbj1cIkNoZWNrU3F1YXJlXCIgbGFiZWw9XCJQZW5kaW5nIEFwcHJvdmFsc1wiIGNvdW50PXthY3Rpb25SZXF1aXJlZC5wZW5kaW5nQXBwcm92YWxzIHx8IDB9IGFjY2VudENvbG9yPXtDLm9yYW5nZX0gcmVzb3VyY2VJZD1cIkZpbGVcIiAvPlxuICAgICAgICA8QWN0aW9uQ2FyZCBpY29uPVwiSGVscENpcmNsZVwiIGxhYmVsPVwiT3BlbiBUaWNrZXRzXCIgY291bnQ9e2FjdGlvblJlcXVpcmVkLm9wZW5UaWNrZXRzIHx8IDB9IGFjY2VudENvbG9yPXtDLmJsdWV9IHJlc291cmNlSWQ9XCJTdXBwb3J0VGlja2V0XCIgLz5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIENIQVJUUyBST1cg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzIwcHgnLCBtYXJnaW5Cb3R0b206ICczMnB4JyB9fT5cbiAgICAgICAgey8qIFVzZXIgR3Jvd3RoIENoYXJ0ICovfVxuICAgICAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZSgpLCBmbGV4OiAnMicsIG1pbldpZHRoOiAnMzgwcHgnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMjBweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiQWN0aXZpdHlcIiBjb2xvcj17Qy5nb2xkfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCB9fT5Vc2VyIEdyb3d0aDwvSDU+XG4gICAgICAgICAgICA8QmFkZ2Ugc3R5bGU9e3sgbWFyZ2luTGVmdDogJzhweCcsIGJhY2tncm91bmRDb2xvcjogQy5nb2xkRGltLCBjb2xvcjogQy5nb2xkLCBib3JkZXI6ICdub25lJyB9fT4zMCBkYXlzPC9CYWRnZT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7Z3Jvd3RoQ2hhcnREYXRhLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8QXJlYUNoYXJ0IGRhdGE9e2dyb3d0aENoYXJ0RGF0YX0gY29sb3I9e0MuZ29sZH0gd2lkdGg9ezYwMH0gaGVpZ2h0PXsyMjB9IC8+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgaGVpZ2h0OiAyMDAsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSB9fT5ObyB1c2VyIHNpZ251cHMgaW4gdGhlIGxhc3QgMzAgZGF5cy48L1RleHQ+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cblxuICAgICAgICB7LyogUGxhdGZvcm0gRG9udXQgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcxJywgbWluV2lkdGg6ICczMDBweCcgfX0+XG4gICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcyMHB4JyB9fT5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJQaWVDaGFydFwiIGNvbG9yPXtDLmJsdWV9IC8+XG4gICAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAwIH19Pk1vZHMgYnkgUGxhdGZvcm08L0g1PlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIHttb2RzQnlQbGF0Zm9ybS5sZW5ndGggPiAwID8gKFxuICAgICAgICAgICAgPERvbnV0Q2hhcnQgZGF0YT17bW9kc0J5UGxhdGZvcm19IHNpemU9ezE4MH0gLz5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBoZWlnaHQ6IDE4MCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInIH19PlxuICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltIH19Pk5vIHBsYXRmb3JtIGRhdGEgYXZhaWxhYmxlLjwvVGV4dD5cbiAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvQm94PlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgUkVDRU5UIEFDVElWSVRZIFJPVyDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMjBweCcsIG1hcmdpbkJvdHRvbTogJzMycHgnIH19PlxuICAgICAgICB7LyogUmVjZW50IFVzZXJzICovfVxuICAgICAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZSgpLCBmbGV4OiAnMScsIG1pbldpZHRoOiAnMzQwcHgnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMjBweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiVXNlcnNcIiBjb2xvcj17Qy5ibHVlfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCB9fT5SZWNlbnQgVXNlcnM8L0g1PlxuICAgICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvVXNlclwiIHN0eWxlPXt7IG1hcmdpbkxlZnQ6ICdhdXRvJywgY29sb3I6IEMuZ29sZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwIH19PlZpZXcgQWxsIOKGkjwvYT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7cmVjZW50VXNlcnMubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDx0YWJsZSBzdHlsZT17eyB3aWR0aDogJzEwMCUnLCBib3JkZXJDb2xsYXBzZTogJ2NvbGxhcHNlJyB9fT5cbiAgICAgICAgICAgICAgPHRoZWFkPlxuICAgICAgICAgICAgICAgIDx0ciBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogQy50ZXh0RGltLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5Vc2VybmFtZTwvdGg+XG4gICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiBDLnRleHREaW0sIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PlJvbGU8L3RoPlxuICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ3JpZ2h0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6IEMudGV4dERpbSwgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+Sm9pbmVkPC90aD5cbiAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICA8L3RoZWFkPlxuICAgICAgICAgICAgICA8dGJvZHk+XG4gICAgICAgICAgICAgICAge3JlY2VudFVzZXJzLm1hcCgodSwgaSkgPT4gKFxuICAgICAgICAgICAgICAgICAgPHRyIGtleT17aX0gc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnLCBjb2xvcjogQy50ZXh0LCBmb250U2l6ZTogJzEzcHgnLCBmb250V2VpZ2h0OiA1MDAgfX0+e3UudXNlcm5hbWV9PC90ZD5cbiAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnMTFweCcsIHBhZGRpbmc6ICczcHggOHB4JywgYm9yZGVyUmFkaXVzOiAnNnB4JywgYmFja2dyb3VuZENvbG9yOiB1LnJvbGUgPT09ICdhZG1pbicgPyBgJHtDLmdvbGR9MjBgIDogYCR7Qy5ibHVlfTIwYCwgY29sb3I6IHUucm9sZSA9PT0gJ2FkbWluJyA/IEMuZ29sZCA6IEMuYmx1ZSwgZm9udFdlaWdodDogNjAwIH19Pnt1LnJvbGUgfHwgJ3VzZXInfTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnLCBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTJweCcsIHRleHRBbGlnbjogJ3JpZ2h0JyB9fT57Zm10RGF0ZSh1LmRhdGUpfTwvdGQ+XG4gICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICkpfVxuICAgICAgICAgICAgICA8L3Rib2R5PlxuICAgICAgICAgICAgPC90YWJsZT5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgdGV4dEFsaWduOiAnY2VudGVyJywgcGFkZGluZzogJzIwcHggMCcgfX0+Tm8gcmVjZW50IHVzZXJzLjwvVGV4dD5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cblxuICAgICAgICB7LyogUmVjZW50IE1vZHMgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcxJywgbWluV2lkdGg6ICczNDBweCcgfX0+XG4gICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcyMHB4JyB9fT5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJQYWNrYWdlXCIgY29sb3I9e0MuZ29sZH0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAgfX0+UmVjZW50IE1vZHM8L0g1PlxuICAgICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvRmlsZVwiIHN0eWxlPXt7IG1hcmdpbkxlZnQ6ICdhdXRvJywgY29sb3I6IEMuZ29sZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwIH19PlZpZXcgQWxsIOKGkjwvYT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7cmVjZW50TW9kcy5sZW5ndGggPiAwID8gKFxuICAgICAgICAgICAgPHRhYmxlIHN0eWxlPXt7IHdpZHRoOiAnMTAwJScsIGJvcmRlckNvbGxhcHNlOiAnY29sbGFwc2UnIH19PlxuICAgICAgICAgICAgICA8dGhlYWQ+XG4gICAgICAgICAgICAgICAgPHRyIHN0eWxlPXt7IGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiBDLnRleHREaW0sIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19Pk5hbWU8L3RoPlxuICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogQy50ZXh0RGltLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5QbGF0Zm9ybTwvdGg+XG4gICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiBDLnRleHREaW0sIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PlN0YXR1czwvdGg+XG4gICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAncmlnaHQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogQy50ZXh0RGltLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5BZGRlZDwvdGg+XG4gICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgPC90aGVhZD5cbiAgICAgICAgICAgICAgPHRib2R5PlxuICAgICAgICAgICAgICAgIHtyZWNlbnRNb2RzLm1hcCgobSwgaSkgPT4gKFxuICAgICAgICAgICAgICAgICAgPHRyIGtleT17aX0gc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnLCBjb2xvcjogQy50ZXh0LCBmb250U2l6ZTogJzEzcHgnLCBmb250V2VpZ2h0OiA1MDAsIG1heFdpZHRoOiAnMTgwcHgnLCBvdmVyZmxvdzogJ2hpZGRlbicsIHRleHRPdmVyZmxvdzogJ2VsbGlwc2lzJywgd2hpdGVTcGFjZTogJ25vd3JhcCcgfX0+e20ubmFtZX08L3RkPlxuICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICcxMXB4JywgcGFkZGluZzogJzNweCA4cHgnLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IGAke0MuYmx1ZX0yMGAsIGNvbG9yOiBDLmJsdWUsIGZvbnRXZWlnaHQ6IDYwMCwgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScgfX0+e20uY2F0ZWdvcnkgfHwgJ+KAlCd9PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICcxMXB4JywgcGFkZGluZzogJzNweCA4cHgnLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IGAke3N0YXR1c0NvbG9yKG0uc3RhdHVzKX0yMGAsIGNvbG9yOiBzdGF0dXNDb2xvcihtLnN0YXR1cyksIGZvbnRXZWlnaHQ6IDYwMCwgdGV4dFRyYW5zZm9ybTogJ2NhcGl0YWxpemUnIH19PnttLnN0YXR1cyB8fCAn4oCUJ308L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0QWxpZ246ICdyaWdodCcgfX0+e2ZtdERhdGUobS5kYXRlKX08L3RkPlxuICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICApKX1cbiAgICAgICAgICAgICAgPC90Ym9keT5cbiAgICAgICAgICAgIDwvdGFibGU+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0sIHRleHRBbGlnbjogJ2NlbnRlcicsIHBhZGRpbmc6ICcyMHB4IDAnIH19Pk5vIHJlY2VudCBtb2RzLjwvVGV4dD5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIEZPT1RFUiDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywganVzdGlmeUNvbnRlbnQ6ICdzcGFjZS1iZXR3ZWVuJywgYWxpZ25JdGVtczogJ2NlbnRlcicsIHBhZGRpbmdUb3A6ICcyMHB4JywgYm9yZGVyVG9wOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgPGEgaHJlZj1cIi9hZG1pblwiIHN0eWxlPXt7IHRleHREZWNvcmF0aW9uOiAnbm9uZScgfX0+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgZm9udFNpemU6ICcxMnB4JywgY3Vyc29yOiAncG9pbnRlcicgfX0+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy5nb2xkLCBmb250V2VpZ2h0OiA3MDAgfX0+R1BMPC9zcGFuPiA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyM4ODgnIH19Pk1vZHM8L3NwYW4+IOKAoiBBZG1pbiBQYW5lbCB2Mi41XG4gICAgICAgICAgPC9UZXh0PlxuICAgICAgICA8L2E+XG4gICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBnYXA6ICcxNnB4JyB9fT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9Vc2VyXCIgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnIH19PlVzZXJzPC9hPlxuICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL0ZpbGVcIiBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScgfX0+TW9kczwvYT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9SZXBvcnRcIiBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScgfX0+UmVwb3J0czwvYT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9TdXBwb3J0VGlja2V0XCIgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnIH19PlRpY2tldHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9tdXNpY1wiIHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJyB9fT5NdXNpYzwvYT5cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L2Rpdj5cbiAgICA8L2Rpdj5cbiAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEN1c3RvbURhc2hib2FyZDtcbiIsImltcG9ydCBSZWFjdCBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3gsIEljb24gfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgU2lkZWJhckJyYW5kaW5nID0gKCkgPT4ge1xuICByZXR1cm4gKFxuICAgIDxCb3ggXG4gICAgICBmbGV4IFxuICAgICAgZmxleERpcmVjdGlvbj1cImNvbHVtblwiXG4gICAgICBhbGlnbkl0ZW1zPVwiY2VudGVyXCIgXG4gICAgICBqdXN0aWZ5Q29udGVudD1cImNlbnRlclwiIFxuICAgICAgcD1cImxnXCIgXG4gICAgICBzdHlsZT17eyBcbiAgICAgICAgYm9yZGVyQm90dG9tOiAnMXB4IHNvbGlkICMyYTJhMmEnLCBcbiAgICAgICAgYmFja2dyb3VuZENvbG9yOiAnIzBhMGEwYScsIFxuICAgICAgICBwYWRkaW5nOiAnMjBweCAxNnB4JyxcbiAgICAgICAgcG9zaXRpb246ICdyZWxhdGl2ZScsXG4gICAgICAgIG92ZXJmbG93OiAnaGlkZGVuJ1xuICAgICAgfX1cbiAgICA+XG4gICAgICB7LyogU3VidGxlIGdvbGQgZ2xvdyB1bmRlcmxpbmUgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7XG4gICAgICAgIHBvc2l0aW9uOiAnYWJzb2x1dGUnLFxuICAgICAgICBib3R0b206IDAsXG4gICAgICAgIGxlZnQ6ICc1MCUnLFxuICAgICAgICB0cmFuc2Zvcm06ICd0cmFuc2xhdGVYKC01MCUpJyxcbiAgICAgICAgd2lkdGg6ICc2MCUnLFxuICAgICAgICBoZWlnaHQ6ICcxcHgnLFxuICAgICAgICBiYWNrZ3JvdW5kOiAnbGluZWFyLWdyYWRpZW50KDkwZGVnLCB0cmFuc3BhcmVudCwgcmdiYSgyNTUsMjE1LDAsMC41KSwgdHJhbnNwYXJlbnQpJ1xuICAgICAgfX0gLz5cblxuICAgICAgey8qIE1haW4gTG9nbyAmIFRpdGxlIExpbmsgKi99XG4gICAgICA8YSBcbiAgICAgICAgaHJlZj1cIi9hZG1pblwiIFxuICAgICAgICBzdHlsZT17eyBcbiAgICAgICAgICB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBcbiAgICAgICAgICBkaXNwbGF5OiAnZmxleCcsIFxuICAgICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInLCBcbiAgICAgICAgICBnYXA6ICcxMHB4JyxcbiAgICAgICAgICBjdXJzb3I6ICdwb2ludGVyJyxcbiAgICAgICAgICB0cmFuc2l0aW9uOiAnb3BhY2l0eSAwLjJzIGVhc2UnXG4gICAgICAgIH19XG4gICAgICAgIG9uTW91c2VFbnRlcj17KGUpID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLm9wYWNpdHkgPSAnMC44NSc7IH19XG4gICAgICAgIG9uTW91c2VMZWF2ZT17KGUpID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLm9wYWNpdHkgPSAnMSc7IH19XG4gICAgICA+XG4gICAgICAgIDxpbWcgXG4gICAgICAgICAgc3JjPVwiL2ltYWdlcy9sb2dvLnBuZ1wiIFxuICAgICAgICAgIGFsdD1cIkxvZ29cIiBcbiAgICAgICAgICBzdHlsZT17eyBoZWlnaHQ6ICczMnB4Jywgd2lkdGg6ICdhdXRvJywgZmlsdGVyOiAnZHJvcC1zaGFkb3coMCAwIDZweCByZ2JhKDI1NSwyMTUsMCwwLjMpKScgfX0gXG4gICAgICAgICAgb25FcnJvcj17KGUpID0+IGUudGFyZ2V0LnN0eWxlLmRpc3BsYXkgPSAnbm9uZSd9XG4gICAgICAgIC8+XG4gICAgICAgIDxkaXYgc3R5bGU9e3sgZm9udFNpemU6ICcyMnB4JywgZm9udFdlaWdodDogJ2JvbGQnLCBmb250RmFtaWx5OiAnSW50ZXIsIHN5c3RlbS11aSwgc2Fucy1zZXJpZicsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2Jhc2VsaW5lJywgZ2FwOiAnNHB4JyB9fT5cbiAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNGRkQ3MDAnLCB0ZXh0U2hhZG93OiAnMCAwIDEycHggcmdiYSgyNTUsIDIxNSwgMCwgMC40KScgfX0+R1BMPC9zcGFuPlxuICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcgfX0+TW9kczwvc3Bhbj5cbiAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzlweCcsIGNvbG9yOiAnIzU1NScsIGZvbnRXZWlnaHQ6IDYwMCwgbWFyZ2luTGVmdDogJzZweCcsIGxldHRlclNwYWNpbmc6ICcwLjA1ZW0nIH19PnYyLjU8L3NwYW4+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9hPlxuXG4gICAgICB7LyogUXVpY2sgRGFzaGJvYXJkIFNob3J0Y3V0IEJ1dHRvbiAqL31cbiAgICAgIDxhIFxuICAgICAgICBocmVmPVwiL2FkbWluXCIgXG4gICAgICAgIHN0eWxlPXt7XG4gICAgICAgICAgZGlzcGxheTogJ2ZsZXgnLFxuICAgICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInLFxuICAgICAgICAgIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyxcbiAgICAgICAgICBnYXA6ICc4cHgnLFxuICAgICAgICAgIG1hcmdpblRvcDogJzEycHgnLFxuICAgICAgICAgIHBhZGRpbmc6ICc2cHggMTZweCcsXG4gICAgICAgICAgd2lkdGg6ICc4NSUnLFxuICAgICAgICAgIGJvcmRlclJhZGl1czogJzhweCcsXG4gICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsIDIxNSwgMCwgMC4wOCknLFxuICAgICAgICAgIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwgMjE1LCAwLCAwLjI1KScsXG4gICAgICAgICAgY29sb3I6ICcjRkZENzAwJyxcbiAgICAgICAgICB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLFxuICAgICAgICAgIGZvbnRTaXplOiAnMTJweCcsXG4gICAgICAgICAgZm9udFdlaWdodDogNzAwLFxuICAgICAgICAgIGxldHRlclNwYWNpbmc6ICcwLjA0ZW0nLFxuICAgICAgICAgIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLFxuICAgICAgICAgIHRyYW5zaXRpb246ICdhbGwgMC4ycyBlYXNlJyxcbiAgICAgICAgICBjdXJzb3I6ICdwb2ludGVyJ1xuICAgICAgICB9fVxuICAgICAgICBvbk1vdXNlRW50ZXI9eyhlKSA9PiB7IFxuICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyNTUsIDIxNSwgMCwgMC4yKSc7IFxuICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnMCAwIDE0cHggcmdiYSgyNTUsMjE1LDAsMC4zKSc7IFxuICAgICAgICB9fVxuICAgICAgICBvbk1vdXNlTGVhdmU9eyhlKSA9PiB7IFxuICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyNTUsIDIxNSwgMCwgMC4wOCknOyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJ25vbmUnOyBcbiAgICAgICAgfX1cbiAgICAgID5cbiAgICAgICAgPEljb24gaWNvbj1cIkhvbWVcIiBzaXplPXsxM30gY29sb3I9XCIjRkZENzAwXCIgLz5cbiAgICAgICAgPHNwYW4+RGFzaGJvYXJkPC9zcGFuPlxuICAgICAgPC9hPlxuICAgIDwvQm94PlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgU2lkZWJhckJyYW5kaW5nO1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZUVmZmVjdCB9IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCwgVGV4dCwgTG9hZGVyIH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5pbXBvcnQgeyB1c2VOb3RpY2UgfSBmcm9tICdhZG1pbmpzJztcblxuY29uc3QgQWN0aW9uUmVkaXJlY3QgPSAocHJvcHMpID0+IHtcbiAgICBjb25zdCB7IHJlY29yZCwgYWN0aW9uIH0gPSBwcm9wcztcbiAgICBjb25zdCBzZW5kTm90aWNlID0gdXNlTm90aWNlKCk7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBjb25zdCB1cmwgPSByZWNvcmQ/LnBhcmFtcz8ucmVkaXJlY3RVcmw7XG4gICAgICAgIFxuICAgICAgICBpZiAodXJsKSB7XG4gICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgICAgICAgICB3aW5kb3cub3Blbih1cmwsICdfYmxhbmsnKTtcbiAgICAgICAgICAgIH0sIDUwMCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBzZW5kTm90aWNlKHsgbWVzc2FnZTogJ0Vycm9yOiBObyByZWRpcmVjdCBVUkwgcHJvdmlkZWQuJywgdHlwZTogJ2Vycm9yJyB9KTtcbiAgICAgICAgfVxuICAgIH0sIFtyZWNvcmRdKTtcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3ggZmxleCBmbGV4RGlyZWN0aW9uPVwiY29sdW1uXCIgYWxpZ25JdGVtcz1cImNlbnRlclwiIGp1c3RpZnlDb250ZW50PVwiY2VudGVyXCIgcD1cInh4bFwiPlxuICAgICAgICAgICAgPExvYWRlciAvPlxuICAgICAgICAgICAgPFRleHQgbXQ9XCJsZ1wiIHZhcmlhbnQ9XCJoNFwiPlJlZGlyZWN0aW5nLi4uPC9UZXh0PlxuICAgICAgICA8L0JveD5cbiAgICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgQWN0aW9uUmVkaXJlY3Q7XG4iLCJpbXBvcnQgUmVhY3QgZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQmFkZ2UgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgVmFyaWFudEJhZGdlID0gKHByb3BzKSA9PiB7XG4gIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSB9ID0gcHJvcHM7XG4gIGNvbnN0IGlzVmFyaWFudCA9IHJlY29yZC5wYXJhbXNbcHJvcGVydHkubmFtZV07XG5cbiAgaWYgKGlzVmFyaWFudCA9PT0gdHJ1ZSB8fCBpc1ZhcmlhbnQgPT09ICd0cnVlJykge1xuICAgIHJldHVybiAoXG4gICAgICA8QmFkZ2UgdmFyaWFudD1cInByaW1hcnlcIiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMjE5NkYzJywgY29sb3I6ICcjZmZmJywgYm9yZGVyOiAnbm9uZScgfX0+XG4gICAgICAgIFZhcmlhbnRcbiAgICAgIDwvQmFkZ2U+XG4gICAgKTtcbiAgfVxuXG4gIHJldHVybiAoXG4gICAgPEJhZGdlIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMzMzMnLCBjb2xvcjogJyNhYWEnLCBib3JkZXI6ICcxcHggc29saWQgIzU1NScgfX0+XG4gICAgICBNYXN0ZXJcbiAgICA8L0JhZGdlPlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgVmFyaWFudEJhZGdlO1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlLCB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3ggfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgQXZhdGFyQ2VsbCA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSwgd2hlcmUgfSA9IHByb3BzOyBcbiAgICBjb25zdCBrZXkgPSByZWNvcmQucGFyYW1zW3Byb3BlcnR5Lm5hbWVdO1xuICAgIGNvbnN0IHVzZXJuYW1lID0gcmVjb3JkLnBhcmFtcy51c2VybmFtZSB8fCAnVXNlcic7XG5cbiAgICBjb25zdCBbaW1hZ2VVcmwsIHNldEltYWdlVXJsXSA9IHVzZVN0YXRlKG51bGwpO1xuICAgIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IHVzZVN0YXRlKHRydWUpO1xuICAgIGNvbnN0IFtoYXNFcnJvciwgc2V0SGFzRXJyb3JdID0gdXNlU3RhdGUoZmFsc2UpO1xuXG4gICAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICAgICAgaWYgKCFrZXkpIHtcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGtleS5zdGFydHNXaXRoKCdodHRwOi8vJykgfHwga2V5LnN0YXJ0c1dpdGgoJ2h0dHBzOi8vJykpIHtcbiAgICAgICAgICAgIHNldEltYWdlVXJsKGtleSk7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGZldGNoU2lnbmVkVXJsID0gYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKGAvYXBpL2FkbWluL3NpZ25lZC11cmw/a2V5PSR7ZW5jb2RlVVJJQ29tcG9uZW50KGtleSl9YCk7XG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlLm9rKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICAgICAgICAgIHNldEltYWdlVXJsKGRhdGEudXJsKTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBzZXRIYXNFcnJvcih0cnVlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJFcnJvciBmZXRjaGluZyBhdmF0YXIgVVJMOlwiLCBlcnJvcik7XG4gICAgICAgICAgICAgICAgc2V0SGFzRXJyb3IodHJ1ZSk7XG4gICAgICAgICAgICB9IGZpbmFsbHkge1xuICAgICAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuXG4gICAgICAgIGZldGNoU2lnbmVkVXJsKCk7XG4gICAgfSwgW2tleV0pO1xuXG4gICAgY29uc3Qgc2l6ZSA9IHdoZXJlID09PSAnbGlzdCcgPyAnMzJweCcgOiAnMTIwcHgnO1xuXG4gICAgaWYgKGxvYWRpbmcpIHtcbiAgICAgICAgcmV0dXJuIDxCb3ggc3R5bGU9e3sgd2lkdGg6IHNpemUsIGhlaWdodDogc2l6ZSwgYm9yZGVyUmFkaXVzOiAnNTAlJywgYmFja2dyb3VuZENvbG9yOiAnIzMzMycgfX0gLz47XG4gICAgfVxuXG4gICAgaWYgKCFpbWFnZVVybCB8fCBoYXNFcnJvcikge1xuICAgICAgICByZXR1cm4gKFxuICAgICAgICAgICAgPEJveCBzdHlsZT17eyBcbiAgICAgICAgICAgICAgICB3aWR0aDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgaGVpZ2h0OiBzaXplLCBcbiAgICAgICAgICAgICAgICBib3JkZXJSYWRpdXM6ICc1MCUnLCBcbiAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICcjRkZENzAwJyxcbiAgICAgICAgICAgICAgICBjb2xvcjogJyMwYTBhMGEnLFxuICAgICAgICAgICAgICAgIGRpc3BsYXk6ICdmbGV4JywgXG4gICAgICAgICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcicsIFxuICAgICAgICAgICAgICAgIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyxcbiAgICAgICAgICAgICAgICBmb250V2VpZ2h0OiAnYm9sZCcsXG4gICAgICAgICAgICAgICAgZm9udFNpemU6IHdoZXJlID09PSAnbGlzdCcgPyAnMTRweCcgOiAnNDhweCcsXG4gICAgICAgICAgICAgICAgYm9yZGVyOiAnMnB4IHNvbGlkICMzMzMnXG4gICAgICAgICAgICB9fT5cbiAgICAgICAgICAgICAgICB7dXNlcm5hbWUuY2hhckF0KDApLnRvVXBwZXJDYXNlKCl9XG4gICAgICAgICAgICA8L0JveD5cbiAgICAgICAgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gKFxuICAgICAgICA8Qm94PlxuICAgICAgICAgICAgPGltZyBcbiAgICAgICAgICAgICAgICBzcmM9e2ltYWdlVXJsfSBcbiAgICAgICAgICAgICAgICBhbHQ9e3VzZXJuYW1lfVxuICAgICAgICAgICAgICAgIHN0eWxlPXt7IFxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGhlaWdodDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlclJhZGl1czogJzUwJScsIFxuICAgICAgICAgICAgICAgICAgICBvYmplY3RGaXQ6ICdjb3ZlcicsXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlcjogJzJweCBzb2xpZCAjRkZENzAwJ1xuICAgICAgICAgICAgICAgIH19IFxuICAgICAgICAgICAgICAgIG9uRXJyb3I9eygpID0+IHNldEhhc0Vycm9yKHRydWUpfVxuICAgICAgICAgICAgLz5cbiAgICAgICAgPC9Cb3g+XG4gICAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEF2YXRhckNlbGw7XG4iLCJpbXBvcnQgUmVhY3QsIHsgdXNlU3RhdGUsIHVzZUVmZmVjdCB9IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuXG5jb25zdCBJbWFnZVByZXZpZXcgPSAocHJvcHMpID0+IHtcbiAgICBjb25zdCB7IHJlY29yZCwgcHJvcGVydHksIHdoZXJlIH0gPSBwcm9wczsgXG4gICAgY29uc3QgdmFsdWUgPSByZWNvcmQucGFyYW1zW3Byb3BlcnR5Lm5hbWVdO1xuXG4gICAgY29uc3QgW2ltYWdlVXJsLCBzZXRJbWFnZVVybF0gPSB1c2VTdGF0ZShudWxsKTtcbiAgICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcblxuICAgIHVzZUVmZmVjdCgoKSA9PiB7XG4gICAgICAgIGlmICghdmFsdWUpIHtcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHZhbHVlLnN0YXJ0c1dpdGgoJ2h0dHA6Ly8nKSB8fCB2YWx1ZS5zdGFydHNXaXRoKCdodHRwczovLycpKSB7XG4gICAgICAgICAgICBzZXRJbWFnZVVybCh2YWx1ZSk7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGZldGNoU2lnbmVkVXJsID0gYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKGAvYXBpL2FkbWluL3NpZ25lZC11cmw/a2V5PSR7ZW5jb2RlVVJJQ29tcG9uZW50KHZhbHVlKX1gKTtcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgICAgICAgICAgc2V0SW1hZ2VVcmwoZGF0YS51cmwpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJGYWlsZWQgdG8gZmV0Y2ggc2lnbmVkIFVSTC5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiTmV0d29yayBlcnJvciBmZXRjaGluZyBzaWduZWQgVVJMOlwiLCBlcnJvcik7XG4gICAgICAgICAgICB9IGZpbmFsbHkge1xuICAgICAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuXG4gICAgICAgIGZldGNoU2lnbmVkVXJsKCk7XG4gICAgfSwgW3ZhbHVlXSk7XG5cbiAgICBpZiAobG9hZGluZykgcmV0dXJuIDxCb3ggc3R5bGU9e3sgY29sb3I6ICcjRkZENzAwJywgZm9udFNpemU6ICcxMnB4JyB9fT5Mb2FkaW5nLi4uPC9Cb3g+O1xuICAgIGlmICghaW1hZ2VVcmwpIHJldHVybiA8Qm94IHN0eWxlPXt7IGNvbG9yOiAnIzg4OCcsIGZvbnRTaXplOiAnMTJweCcgfX0+Ti9BPC9Cb3g+O1xuXG4gICAgY29uc3Qgc2l6ZSA9IHdoZXJlID09PSAnbGlzdCcgPyAnNDBweCcgOiAnMTUwcHgnO1xuICAgIGNvbnN0IHJhZGl1cyA9IHByb3BlcnR5Lm5hbWUgPT09ICdwcm9maWxlSW1hZ2VLZXknID8gJzUwJScgOiAnOHB4JztcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3g+XG4gICAgICAgICAgICA8aW1nIFxuICAgICAgICAgICAgICAgIHNyYz17aW1hZ2VVcmx9IFxuICAgICAgICAgICAgICAgIGFsdD1cIlByZXZpZXdcIiBcbiAgICAgICAgICAgICAgICBzdHlsZT17eyBcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IHNpemUsIFxuICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IHNpemUsIFxuICAgICAgICAgICAgICAgICAgICBib3JkZXJSYWRpdXM6IHJhZGl1cyxcbiAgICAgICAgICAgICAgICAgICAgb2JqZWN0Rml0OiAnY292ZXInLFxuICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICcjMWExYTFhJyxcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkICMzMzMnXG4gICAgICAgICAgICAgICAgfX0gXG4gICAgICAgICAgICAvPlxuICAgICAgICA8L0JveD5cbiAgICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgSW1hZ2VQcmV2aWV3O1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlIH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94LCBCdXR0b24sIEgzLCBUZXh0LCBJbnB1dCwgTGFiZWwsIEZvcm1Hcm91cCwgTm90aWNlQm94IH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5pbXBvcnQgeyB1c2VOb3RpY2UsIEFwaUNsaWVudCB9IGZyb20gJ2FkbWluanMnO1xuXG5jb25zdCBhcGkgPSBuZXcgQXBpQ2xpZW50KCk7XG5cbmNvbnN0IE1hbmFnZVZvdGVzID0gKHByb3BzKSA9PiB7XG4gIGNvbnN0IHsgcmVjb3JkLCByZXNvdXJjZSB9ID0gcHJvcHM7XG4gIGNvbnN0IGFkZE5vdGljZSA9IHVzZU5vdGljZSgpO1xuXG4gIGNvbnN0IFt3b3JraW5nQ291bnQsIHNldFdvcmtpbmdDb3VudF0gPSB1c2VTdGF0ZShyZWNvcmQucGFyYW1zLndvcmtpbmdWb3RlQ291bnQgfHwgMCk7XG4gIGNvbnN0IFtub3RXb3JraW5nQ291bnQsIHNldE5vdFdvcmtpbmdDb3VudF0gPSB1c2VTdGF0ZShyZWNvcmQucGFyYW1zLm5vdFdvcmtpbmdWb3RlQ291bnQgfHwgMCk7XG4gIGNvbnN0IFtpc0xvYWRpbmcsIHNldElzTG9hZGluZ10gPSB1c2VTdGF0ZShmYWxzZSk7XG5cbiAgY29uc3QgaGFuZGxlU3VibWl0ID0gKGFjdGlvblR5cGUpID0+IHtcbiAgICBpZiAoYWN0aW9uVHlwZSA9PT0gJ3Jlc2V0JyAmJiAhd2luZG93LmNvbmZpcm0oXCJBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gcGVybWFuZW50bHkgZGVsZXRlIGFsbCB1c2VyIHZvdGVzIGZvciB0aGlzIG1vZD9cIikpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHNldElzTG9hZGluZyh0cnVlKTtcblxuICAgIGFwaS5yZXNvdXJjZUFjdGlvbih7XG4gICAgICByZXNvdXJjZUlkOiByZXNvdXJjZS5pZCxcbiAgICAgIGFjdGlvbk5hbWU6ICdtYW5hZ2VWb3RlcycsXG4gICAgICByZWNvcmRJZDogcmVjb3JkLmlkLFxuICAgICAgbWV0aG9kOiAncG9zdCcsXG4gICAgICBkYXRhOiB7XG4gICAgICAgIGFjdGlvblR5cGU6IGFjdGlvblR5cGUsXG4gICAgICAgIG5ld1dvcmtpbmdDb3VudDogd29ya2luZ0NvdW50LFxuICAgICAgICBuZXdOb3RXb3JraW5nQ291bnQ6IG5vdFdvcmtpbmdDb3VudFxuICAgICAgfVxuICAgIH0pLnRoZW4ocmVzcG9uc2UgPT4ge1xuICAgICAgc2V0SXNMb2FkaW5nKGZhbHNlKTtcbiAgICAgIGlmIChyZXNwb25zZS5kYXRhLm5vdGljZSkge1xuICAgICAgICBhZGROb3RpY2UocmVzcG9uc2UuZGF0YS5ub3RpY2UpO1xuICAgICAgfVxuICAgICAgaWYgKHJlc3BvbnNlLmRhdGEucmVkaXJlY3RVcmwpIHtcbiAgICAgICAgIHdpbmRvdy5sb2NhdGlvbi5ocmVmID0gcmVzcG9uc2UuZGF0YS5yZWRpcmVjdFVybDtcbiAgICAgIH1cbiAgICB9KS5jYXRjaChlcnJvciA9PiB7XG4gICAgICBzZXRJc0xvYWRpbmcoZmFsc2UpO1xuICAgICAgYWRkTm90aWNlKHsgbWVzc2FnZTogJ0FuIGVycm9yIG9jY3VycmVkIHdoaWxlIGNvbnRhY3RpbmcgdGhlIHNlcnZlci4nLCB0eXBlOiAnZXJyb3InIH0pO1xuICAgIH0pO1xuICB9O1xuXG4gIHJldHVybiAoXG4gICAgPEJveCB2YXJpYW50PVwid2hpdGVcIiBwPVwieGxcIiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMWExYTFhJywgYm9yZGVyUmFkaXVzOiAnOHB4JywgYm9yZGVyOiAnMXB4IHNvbGlkICMzMzMnIH19PlxuICAgICAgXG4gICAgICA8SDMgc3R5bGU9e3sgY29sb3I6ICcjRkZENzAwJywgbWFyZ2luQm90dG9tOiAnMjBweCcgfX0+TWFuYWdlIFZvdGVzIGZvcjoge3JlY29yZC5wYXJhbXMubmFtZX08L0gzPlxuICAgICAgXG4gICAgICA8Tm90aWNlQm94IHN0eWxlPXt7IG1hcmdpbkJvdHRvbTogJzMwcHgnIH19PlxuICAgICAgICA8c3Ryb25nPkN1cnJlbnQgU3RhdHVzOjwvc3Ryb25nPjxici8+XG4gICAgICAgIFdvcmtpbmcgVm90ZXM6IDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnIzQzYTA0NycsIGZvbnRXZWlnaHQ6ICdib2xkJyB9fT57cmVjb3JkLnBhcmFtcy53b3JraW5nVm90ZUNvdW50IHx8IDB9PC9zcGFuPjxici8+XG4gICAgICAgIE5vdCBXb3JraW5nIFZvdGVzOiA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNlNTM5MzUnLCBmb250V2VpZ2h0OiAnYm9sZCcgfX0+e3JlY29yZC5wYXJhbXMubm90V29ya2luZ1ZvdGVDb3VudCB8fCAwfTwvc3Bhbj5cbiAgICAgIDwvTm90aWNlQm94PlxuXG4gICAgICA8Qm94IG1iPVwieHhsXCIgcD1cImxnXCIgc3R5bGU9e3sgYm9yZGVyOiAnMXB4IHNvbGlkICM0NDQnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBiYWNrZ3JvdW5kQ29sb3I6ICcjMGEwYTBhJyB9fT5cbiAgICAgICAgPEgzIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGZvbnRTaXplOiAnMS4yZW0nIH19Pk9wdGlvbiAxOiBSZXNldCBBbGwgVm90ZXM8L0gzPlxuICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNjMGMwYzAnLCBtYXJnaW5Cb3R0b206ICcxNXB4JyB9fT5cbiAgICAgICAgICBUaGlzIHdpbGwgd2lwZSBhbGwgZXhpc3RpbmcgdXNlciB2b3RlcyBhbmQgcmVzZXQgYm90aCBjb3VudHMgdG8gMC4gVGhpcyBpcyBoaWdobHkgcmVjb21tZW5kZWQgd2hlbiBhIG1ham9yIHVwZGF0ZSBpcyByZWxlYXNlZCB0aGF0IGZpeGVzIGEgYnJva2VuIG1vZC5cbiAgICAgICAgPC9UZXh0PlxuICAgICAgICA8QnV0dG9uIFxuICAgICAgICAgICAgdmFyaWFudD1cImRhbmdlclwiIFxuICAgICAgICAgICAgb25DbGljaz17KCkgPT4gaGFuZGxlU3VibWl0KCdyZXNldCcpfSBcbiAgICAgICAgICAgIGRpc2FibGVkPXtpc0xvYWRpbmd9XG4gICAgICAgID5cbiAgICAgICAgICB7aXNMb2FkaW5nID8gJ1Byb2Nlc3NpbmcuLi4nIDogJ1dpcGUgJiBSZXNldCBWb3RlcyB0byAwJ31cbiAgICAgICAgPC9CdXR0b24+XG4gICAgICA8L0JveD5cblxuICAgICAgPEJveCBwPVwibGdcIiBzdHlsZT17eyBib3JkZXI6ICcxcHggc29saWQgIzQ0NCcsIGJvcmRlclJhZGl1czogJzhweCcsIGJhY2tncm91bmRDb2xvcjogJyMwYTBhMGEnIH19PlxuICAgICAgICA8SDMgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgZm9udFNpemU6ICcxLjJlbScgfX0+T3B0aW9uIDI6IE1hbnVhbGx5IE92ZXJyaWRlIENvdW50czwvSDM+XG4gICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnI2ZmYWRhZCcsIG1hcmdpbkJvdHRvbTogJzE1cHgnLCBmb250U2l6ZTogJzAuOWVtJyB9fT5cbiAgICAgICAgICBXYXJuaW5nOiBNYW51YWxseSBzZXR0aW5nIG51bWJlcnMgd2lsbCBjbGVhciB0aGUgaW50ZXJuYWwgbGlzdCBvZiB1c2VycyB3aG8gdm90ZWQuIFVzZSB0aGlzIG9ubHkgaWYgeW91IG5lZWQgdG8gYXJ0aWZpY2lhbGx5IGJvb3N0IG9yIHJlZHVjZSBhIHNjb3JlLlxuICAgICAgICA8L1RleHQ+XG4gICAgICAgIFxuICAgICAgICA8Qm94IGZsZXggc3R5bGU9e3sgZ2FwOiAnMjBweCcsIG1hcmdpbkJvdHRvbTogJzIwcHgnIH19PlxuICAgICAgICAgICAgPEZvcm1Hcm91cCBzdHlsZT17eyBmbGV4OiAxIH19PlxuICAgICAgICAgICAgICAgIDxMYWJlbCBzdHlsZT17eyBjb2xvcjogJyNjMGMwYzAnIH19PkZvcmNlIFwiV29ya2luZ1wiIENvdW50PC9MYWJlbD5cbiAgICAgICAgICAgICAgICA8SW5wdXQgXG4gICAgICAgICAgICAgICAgICAgIHR5cGU9XCJudW1iZXJcIiBcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU9e3dvcmtpbmdDb3VudH0gXG4gICAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSkgPT4gc2V0V29ya2luZ0NvdW50KGUudGFyZ2V0LnZhbHVlKX0gXG4gICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnLCBjb2xvcjogJ3doaXRlJywgYm9yZGVyOiAnMXB4IHNvbGlkICMzMzMnIH19XG4gICAgICAgICAgICAgICAgLz5cbiAgICAgICAgICAgIDwvRm9ybUdyb3VwPlxuICAgICAgICAgICAgXG4gICAgICAgICAgICA8Rm9ybUdyb3VwIHN0eWxlPXt7IGZsZXg6IDEgfX0+XG4gICAgICAgICAgICAgICAgPExhYmVsIHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcgfX0+Rm9yY2UgXCJOb3QgV29ya2luZ1wiIENvdW50PC9MYWJlbD5cbiAgICAgICAgICAgICAgICA8SW5wdXQgXG4gICAgICAgICAgICAgICAgICAgIHR5cGU9XCJudW1iZXJcIiBcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU9e25vdFdvcmtpbmdDb3VudH0gXG4gICAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSkgPT4gc2V0Tm90V29ya2luZ0NvdW50KGUudGFyZ2V0LnZhbHVlKX1cbiAgICAgICAgICAgICAgICAgICAgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzFhMWExYScsIGNvbG9yOiAnd2hpdGUnLCBib3JkZXI6ICcxcHggc29saWQgIzMzMycgfX1cbiAgICAgICAgICAgICAgICAvPlxuICAgICAgICAgICAgPC9Gb3JtR3JvdXA+XG4gICAgICAgIDwvQm94PlxuXG4gICAgICAgIDxCdXR0b24gXG4gICAgICAgICAgICB2YXJpYW50PVwicHJpbWFyeVwiIFxuICAgICAgICAgICAgb25DbGljaz17KCkgPT4gaGFuZGxlU3VibWl0KCdvdmVycmlkZScpfSBcbiAgICAgICAgICAgIGRpc2FibGVkPXtpc0xvYWRpbmd9XG4gICAgICAgICAgICBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjRkZENzAwJywgY29sb3I6ICdibGFjaycsIGJvcmRlcjogJ25vbmUnIH19XG4gICAgICAgID5cbiAgICAgICAgICB7aXNMb2FkaW5nID8gJ1Byb2Nlc3NpbmcuLi4nIDogJ0FwcGx5IE1hbnVhbCBPdmVycmlkZSd9XG4gICAgICAgIDwvQnV0dG9uPlxuICAgICAgPC9Cb3g+XG5cbiAgICA8L0JveD5cbiAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IE1hbmFnZVZvdGVzO1xuIiwiQWRtaW5KUy5Vc2VyQ29tcG9uZW50cyA9IHt9XG5BZG1pbkpTLmVudi5OT0RFX0VOViA9IFwicHJvZHVjdGlvblwiXG5pbXBvcnQgRGFzaGJvYXJkIGZyb20gJy4uL2NvbXBvbmVudHMvZGFzaGJvYXJkL0N1c3RvbURhc2hib2FyZCdcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuRGFzaGJvYXJkID0gRGFzaGJvYXJkXG5pbXBvcnQgU2lkZWJhckJyYW5kaW5nIGZyb20gJy4uL2NvbXBvbmVudHMvZGFzaGJvYXJkL1NpZGViYXJCcmFuZGluZydcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuU2lkZWJhckJyYW5kaW5nID0gU2lkZWJhckJyYW5kaW5nXG5pbXBvcnQgQWN0aW9uUmVkaXJlY3QgZnJvbSAnLi4vY29tcG9uZW50cy9hY3Rpb25zL0FjdGlvblJlZGlyZWN0J1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5BY3Rpb25SZWRpcmVjdCA9IEFjdGlvblJlZGlyZWN0XG5pbXBvcnQgVmFyaWFudEJhZGdlIGZyb20gJy4uL2NvbXBvbmVudHMvY2VsbHMvVmFyaWFudEJhZGdlJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5WYXJpYW50QmFkZ2UgPSBWYXJpYW50QmFkZ2VcbmltcG9ydCBBdmF0YXJDZWxsIGZyb20gJy4uL2NvbXBvbmVudHMvY2VsbHMvQXZhdGFyQ2VsbCdcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuQXZhdGFyQ2VsbCA9IEF2YXRhckNlbGxcbmltcG9ydCBJbWFnZVByZXZpZXcgZnJvbSAnLi4vY29tcG9uZW50cy9jZWxscy9JbWFnZVByZXZpZXcnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkltYWdlUHJldmlldyA9IEltYWdlUHJldmlld1xuaW1wb3J0IE1hbmFnZVZvdGVzIGZyb20gJy4uL2NvbXBvbmVudHMvYWN0aW9ucy9NYW5hZ2VWb3RlcydcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuTWFuYWdlVm90ZXMgPSBNYW5hZ2VWb3RlcyJdLCJuYW1lcyI6WyJhcGkiLCJBcGlDbGllbnQiLCJDIiwiYmciLCJzdXJmYWNlIiwic3VyZmFjZUFsdCIsImJvcmRlciIsImJvcmRlckhvdmVyIiwiZ29sZCIsImdvbGREaW0iLCJnb2xkR2xvdyIsImJsdWUiLCJncmVlbiIsInB1cnBsZSIsInJlZCIsIm9yYW5nZSIsInRleHQiLCJ0ZXh0TXV0ZWQiLCJ0ZXh0RGltIiwiUExBVEZPUk1fQ09MT1JTIiwiY2FyZFN0eWxlIiwiYWNjZW50Q29sb3IiLCJiYWNrZ3JvdW5kQ29sb3IiLCJib3JkZXJSYWRpdXMiLCJib3JkZXJMZWZ0IiwicGFkZGluZyIsInRyYW5zaXRpb24iLCJjdXJzb3IiLCJBcmVhQ2hhcnQiLCJkYXRhIiwid2lkdGgiLCJoZWlnaHQiLCJjb2xvciIsImxlbmd0aCIsIm1heFZhbCIsIk1hdGgiLCJtYXgiLCJtYXAiLCJkIiwidmFsdWUiLCJwYWRYIiwicGFkWSIsImNoYXJ0VyIsImNoYXJ0SCIsInBvaW50cyIsImkiLCJ4IiwieSIsImxpbmVQYXRoIiwicCIsImpvaW4iLCJhcmVhUGF0aCIsImdyaWRMaW5lcyIsInBjdCIsImxhYmVsIiwicm91bmQiLCJSZWFjdCIsImNyZWF0ZUVsZW1lbnQiLCJ2aWV3Qm94IiwicHJlc2VydmVBc3BlY3RSYXRpbyIsImlkIiwieDEiLCJ5MSIsIngyIiwieTIiLCJvZmZzZXQiLCJzdG9wQ29sb3IiLCJzdG9wT3BhY2l0eSIsImciLCJrZXkiLCJzdHJva2UiLCJzdHJva2VXaWR0aCIsInN0cm9rZURhc2hhcnJheSIsImZpbGwiLCJmb250U2l6ZSIsInRleHRBbmNob3IiLCJzdHJva2VMaW5lam9pbiIsInN0cm9rZUxpbmVjYXAiLCJjeCIsImN5IiwiciIsIkRvbnV0Q2hhcnQiLCJzaXplIiwidG90YWwiLCJyZWR1Y2UiLCJzIiwib3V0ZXJSIiwiaW5uZXJSIiwiY3VtQW5nbGUiLCJQSSIsInNsaWNlcyIsImFuZ2xlIiwic3RhcnRBbmdsZSIsImVuZEFuZ2xlIiwiY29zIiwic2luIiwiaXgxIiwiaXkxIiwiaXgyIiwiaXkyIiwibGFyZ2VBcmMiLCJwYXRoIiwibmFtZSIsInN0eWxlIiwiZGlzcGxheSIsImFsaWduSXRlbXMiLCJnYXAiLCJmbGV4V3JhcCIsImp1c3RpZnlDb250ZW50IiwiZm9udFdlaWdodCIsImZsZXhEaXJlY3Rpb24iLCJmbGV4U2hyaW5rIiwibWFyZ2luTGVmdCIsIlN0YXRDYXJkIiwiaWNvbiIsImRlbHRhIiwiZGVsdGFMYWJlbCIsIkJveCIsImZsZXgiLCJtaW5XaWR0aCIsIm9uTW91c2VFbnRlciIsImUiLCJjdXJyZW50VGFyZ2V0IiwiYm9yZGVyQ29sb3IiLCJ0cmFuc2Zvcm0iLCJib3hTaGFkb3ciLCJvbk1vdXNlTGVhdmUiLCJib3JkZXJMZWZ0Q29sb3IiLCJtYXJnaW5Cb3R0b20iLCJJY29uIiwiVGV4dCIsInRleHRUcmFuc2Zvcm0iLCJsZXR0ZXJTcGFjaW5nIiwiSDIiLCJtYXJnaW4iLCJ1bmRlZmluZWQiLCJBY3Rpb25DYXJkIiwiY291bnQiLCJyZXNvdXJjZUlkIiwiaHJlZiIsInRleHREZWNvcmF0aW9uIiwiSDUiLCJmbXREYXRlIiwiZHQiLCJEYXRlIiwidG9Mb2NhbGVEYXRlU3RyaW5nIiwibW9udGgiLCJkYXkiLCJ5ZWFyIiwic3RhdHVzQ29sb3IiLCJsb3dlciIsInRvTG93ZXJDYXNlIiwiQ3VzdG9tRGFzaGJvYXJkIiwic2V0RGF0YSIsInVzZVN0YXRlIiwibG9hZGluZyIsInNldExvYWRpbmciLCJlcnJvciIsInNldEVycm9yIiwidXNlRWZmZWN0IiwiZ2V0RGFzaGJvYXJkIiwidGhlbiIsInJlc3BvbnNlIiwiY2F0Y2giLCJmZXRjaEVycm9yIiwiY29uc29sZSIsIm1pbkhlaWdodCIsInRleHRBbGlnbiIsImJvcmRlclRvcENvbG9yIiwiYW5pbWF0aW9uIiwibWF4V2lkdGgiLCJzdGF0cyIsImFjdGlvblJlcXVpcmVkIiwibW9kc0J5UGxhdGZvcm0iLCJ1c2VyR3Jvd3RoRGF0YSIsInJlY2VudFVzZXJzIiwicmVjZW50TW9kcyIsImdyb3d0aENoYXJ0RGF0YSIsImRhdGUiLCJ1c2VycyIsIm5vdyIsImdyZWV0aW5nIiwiZ2V0SG91cnMiLCJmb250RmFtaWx5IiwicGFkZGluZ0JvdHRvbSIsImJvcmRlckJvdHRvbSIsInRleHRTaGFkb3ciLCJiYWNrZ3JvdW5kIiwibWFyZ2luVG9wIiwid2Vla2RheSIsInRpdGxlIiwidGFyZ2V0IiwicmVsIiwidG90YWxVc2VycyIsInRvTG9jYWxlU3RyaW5nIiwibmV3VXNlcnNUaGlzTW9udGgiLCJ0b3RhbE1vZHMiLCJuZXdNb2RzVGhpc01vbnRoIiwidG90YWxEb3dubG9hZHMiLCJ0b3RhbFZpZXdzIiwicGVuZGluZ1JlcG9ydHMiLCJwZW5kaW5nQXBwcm92YWxzIiwib3BlblRpY2tldHMiLCJCYWRnZSIsImJvcmRlckNvbGxhcHNlIiwidSIsInVzZXJuYW1lIiwicm9sZSIsIm0iLCJvdmVyZmxvdyIsInRleHRPdmVyZmxvdyIsIndoaXRlU3BhY2UiLCJjYXRlZ29yeSIsInN0YXR1cyIsInBhZGRpbmdUb3AiLCJib3JkZXJUb3AiLCJTaWRlYmFyQnJhbmRpbmciLCJwb3NpdGlvbiIsImJvdHRvbSIsImxlZnQiLCJvcGFjaXR5Iiwic3JjIiwiYWx0IiwiZmlsdGVyIiwib25FcnJvciIsIkFjdGlvblJlZGlyZWN0IiwicHJvcHMiLCJyZWNvcmQiLCJhY3Rpb24iLCJzZW5kTm90aWNlIiwidXNlTm90aWNlIiwidXJsIiwicGFyYW1zIiwicmVkaXJlY3RVcmwiLCJzZXRUaW1lb3V0Iiwid2luZG93Iiwib3BlbiIsIm1lc3NhZ2UiLCJ0eXBlIiwiTG9hZGVyIiwibXQiLCJ2YXJpYW50IiwiVmFyaWFudEJhZGdlIiwicHJvcGVydHkiLCJpc1ZhcmlhbnQiLCJBdmF0YXJDZWxsIiwid2hlcmUiLCJpbWFnZVVybCIsInNldEltYWdlVXJsIiwiaGFzRXJyb3IiLCJzZXRIYXNFcnJvciIsInN0YXJ0c1dpdGgiLCJmZXRjaFNpZ25lZFVybCIsImZldGNoIiwiZW5jb2RlVVJJQ29tcG9uZW50Iiwib2siLCJqc29uIiwiY2hhckF0IiwidG9VcHBlckNhc2UiLCJvYmplY3RGaXQiLCJJbWFnZVByZXZpZXciLCJyYWRpdXMiLCJNYW5hZ2VWb3RlcyIsInJlc291cmNlIiwiYWRkTm90aWNlIiwid29ya2luZ0NvdW50Iiwic2V0V29ya2luZ0NvdW50Iiwid29ya2luZ1ZvdGVDb3VudCIsIm5vdFdvcmtpbmdDb3VudCIsInNldE5vdFdvcmtpbmdDb3VudCIsIm5vdFdvcmtpbmdWb3RlQ291bnQiLCJpc0xvYWRpbmciLCJzZXRJc0xvYWRpbmciLCJoYW5kbGVTdWJtaXQiLCJhY3Rpb25UeXBlIiwiY29uZmlybSIsInJlc291cmNlQWN0aW9uIiwiYWN0aW9uTmFtZSIsInJlY29yZElkIiwibWV0aG9kIiwibmV3V29ya2luZ0NvdW50IiwibmV3Tm90V29ya2luZ0NvdW50Iiwibm90aWNlIiwibG9jYXRpb24iLCJIMyIsIk5vdGljZUJveCIsIm1iIiwiQnV0dG9uIiwib25DbGljayIsImRpc2FibGVkIiwiRm9ybUdyb3VwIiwiTGFiZWwiLCJJbnB1dCIsIm9uQ2hhbmdlIiwiQWRtaW5KUyIsIlVzZXJDb21wb25lbnRzIiwiZW52IiwiTk9ERV9FTlYiLCJEYXNoYm9hcmQiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7RUFJQSxNQUFNQSxLQUFHLEdBQUcsSUFBSUMsaUJBQVMsRUFBRTs7RUFFM0I7RUFDQSxNQUFNQyxDQUFDLEdBQUc7RUFDUkMsRUFBQUEsRUFBRSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsT0FBTyxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsVUFBVSxFQUFFLFNBQVM7RUFDeERDLEVBQUFBLE1BQU0sRUFBRSxTQUFTO0VBQUVDLEVBQUFBLFdBQVcsRUFBRSxTQUFTO0VBQ3pDQyxFQUFBQSxJQUFJLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxPQUFPLEVBQUUsc0JBQXNCO0VBQUVDLEVBQUFBLFFBQVEsRUFBRSxzQkFBc0I7RUFDbEZDLEVBQUFBLElBQUksRUFBRSxTQUFTO0VBQUVDLEVBQUFBLEtBQUssRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE1BQU0sRUFBRSxTQUFTO0VBQUVDLEVBQUFBLEdBQUcsRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE1BQU0sRUFBRSxTQUFTO0VBQ3ZGQyxFQUFBQSxJQUFJLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxTQUFTLEVBQUUsTUFBTTtFQUFFQyxFQUFBQSxPQUFPLEVBQUU7RUFDL0MsQ0FBQzs7RUFFRDtFQUNBLE1BQU1DLGVBQWUsR0FBRyxDQUFDLFNBQVMsRUFBRSxTQUFTLEVBQUUsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLENBQUM7O0VBRWhIO0VBQ0EsTUFBTUMsU0FBUyxHQUFJQyxXQUFXLEtBQU07SUFDbENDLGVBQWUsRUFBRXBC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
