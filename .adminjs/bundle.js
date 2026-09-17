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
        fontFamily: "'Poppins', sans-serif"
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
        gap: '8px',
        fontFamily: "'Poppins', sans-serif"
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
        textShadow: '0 0 15px rgba(192, 192, 192, 0.6)',
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
        border: `1px solid ${C.border}`,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "Admin Dashboard"))), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textMuted,
        marginTop: '6px',
        fontFamily: "'Poppins', sans-serif"
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
      href: "/dashboard",
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
        transition: 'all 0.2s',
        fontFamily: "'Poppins', sans-serif"
      },
      onMouseEnter: e => {
        e.currentTarget.style.backgroundColor = 'rgba(255,215,0,0.25)';
      },
      onMouseLeave: e => {
        e.currentTarget.style.backgroundColor = C.goldDim;
      },
      title: "Go Back To Dashboard"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "ArrowLeft",
      size: 14
    }), " Go Back To Dashboard"), /*#__PURE__*/React__default.default.createElement("a", {
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
      src: "/images/team-logo.png",
      alt: "Logo",
      style: {
        height: '32px',
        width: '32px',
        objectFit: 'cover',
        borderRadius: '6px',
        filter: 'drop-shadow(0 0 6px rgba(255,215,0,0.3))'
      },
      onError: e => e.target.style.display = 'none'
    }), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        fontSize: '22px',
        fontWeight: 'bold',
        fontFamily: "'Poppins', sans-serif",
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
        color: '#c0c0c0',
        textShadow: '0 0 12px rgba(192, 192, 192, 0.5)'
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIiwic291cmNlcyI6WyIuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQuanN4IiwiLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nLmpzeCIsIi4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdC5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL1ZhcmlhbnRCYWRnZS5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL0F2YXRhckNlbGwuanN4IiwiLi4vY29tcG9uZW50cy9jZWxscy9JbWFnZVByZXZpZXcuanN4IiwiLi4vY29tcG9uZW50cy9hY3Rpb25zL01hbmFnZVZvdGVzLmpzeCIsImVudHJ5LmpzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQXBpQ2xpZW50IH0gZnJvbSAnYWRtaW5qcyc7XG5pbXBvcnQgeyBCb3gsIEgyLCBINSwgVGV4dCwgSWNvbiwgQmFkZ2UgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgYXBpID0gbmV3IEFwaUNsaWVudCgpO1xuXG4vKiDilIDilIDilIAgY29sb3VyIHRva2VucyDilIDilIDilIAgKi9cbmNvbnN0IEMgPSB7XG4gIGJnOiAnIzBhMGEwYScsIHN1cmZhY2U6ICcjMTMxMzEzJywgc3VyZmFjZUFsdDogJyMxYTFhMWEnLFxuICBib3JkZXI6ICcjMmEyYTJhJywgYm9yZGVySG92ZXI6ICcjM2EzYTNhJyxcbiAgZ29sZDogJyNGRkQ3MDAnLCBnb2xkRGltOiAncmdiYSgyNTUsMjE1LDAsMC4xNSknLCBnb2xkR2xvdzogJ3JnYmEoMjU1LDIxNSwwLDAuMzUpJyxcbiAgYmx1ZTogJyMyMTk2RjMnLCBncmVlbjogJyM0M2EwNDcnLCBwdXJwbGU6ICcjOUMyN0IwJywgcmVkOiAnI2U1MzkzNScsIG9yYW5nZTogJyNGRjk4MDAnLFxuICB0ZXh0OiAnI2ZmZmZmZicsIHRleHRNdXRlZDogJyM5OTknLCB0ZXh0RGltOiAnIzY2NicsXG59O1xuXG4vKiDilIDilIDilIAgcGxhdGZvcm0gY2hhcnQgY29sb3VycyDilIDilIDilIAgKi9cbmNvbnN0IFBMQVRGT1JNX0NPTE9SUyA9IFsnI0E0QzYzOScsICcjMDA3OEQ2JywgJyMyMTc1OUInLCAnI0ZGOTgwMCcsICcjOUMyN0IwJywgJyNlNTM5MzUnLCAnIzQzYTA0NycsICcjRkZENzAwJ107XG5cbi8qIOKUgOKUgOKUgCByZXVzYWJsZSBjYXJkIHN0eWxlIOKUgOKUgOKUgCAqL1xuY29uc3QgY2FyZFN0eWxlID0gKGFjY2VudENvbG9yKSA9PiAoe1xuICBiYWNrZ3JvdW5kQ29sb3I6IEMuc3VyZmFjZSxcbiAgYm9yZGVyUmFkaXVzOiAnMTZweCcsXG4gIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsXG4gIGJvcmRlckxlZnQ6IGFjY2VudENvbG9yID8gYDRweCBzb2xpZCAke2FjY2VudENvbG9yfWAgOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCxcbiAgcGFkZGluZzogJzI0cHgnLFxuICB0cmFuc2l0aW9uOiAnYWxsIDAuMjVzIGVhc2UnLFxuICBjdXJzb3I6ICdkZWZhdWx0Jyxcbn0pO1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBBcmVhIENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgQXJlYUNoYXJ0ID0gKHsgZGF0YSwgd2lkdGggPSA1MDAsIGhlaWdodCA9IDIwMCwgY29sb3IgPSBDLmdvbGQgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBtYXhWYWwgPSBNYXRoLm1heCguLi5kYXRhLm1hcChkID0+IGQudmFsdWUpLCAxKTtcbiAgY29uc3QgcGFkWCA9IDQwO1xuICBjb25zdCBwYWRZID0gMjA7XG4gIGNvbnN0IGNoYXJ0VyA9IHdpZHRoIC0gcGFkWCAqIDI7XG4gIGNvbnN0IGNoYXJ0SCA9IGhlaWdodCAtIHBhZFkgKiAyO1xuXG4gIGNvbnN0IHBvaW50cyA9IGRhdGEubWFwKChkLCBpKSA9PiAoe1xuICAgIHg6IHBhZFggKyAoaSAvIE1hdGgubWF4KGRhdGEubGVuZ3RoIC0gMSwgMSkpICogY2hhcnRXLFxuICAgIHk6IHBhZFkgKyBjaGFydEggLSAoZC52YWx1ZSAvIG1heFZhbCkgKiBjaGFydEgsXG4gIH0pKTtcblxuICBjb25zdCBsaW5lUGF0aCA9IHBvaW50cy5tYXAoKHAsIGkpID0+IGAke2kgPT09IDAgPyAnTScgOiAnTCd9JHtwLnh9LCR7cC55fWApLmpvaW4oJyAnKTtcbiAgY29uc3QgYXJlYVBhdGggPSBgJHtsaW5lUGF0aH0gTCR7cG9pbnRzW3BvaW50cy5sZW5ndGggLSAxXS54fSwke3BhZFkgKyBjaGFydEh9IEwke3BvaW50c1swXS54fSwke3BhZFkgKyBjaGFydEh9IFpgO1xuXG4gIC8vIEdyaWQgbGluZXNcbiAgY29uc3QgZ3JpZExpbmVzID0gWzAsIDAuMjUsIDAuNSwgMC43NSwgMV0ubWFwKHBjdCA9PiB7XG4gICAgY29uc3QgeSA9IHBhZFkgKyBjaGFydEggLSBwY3QgKiBjaGFydEg7XG4gICAgY29uc3QgbGFiZWwgPSBNYXRoLnJvdW5kKHBjdCAqIG1heFZhbCk7XG4gICAgcmV0dXJuIHsgeSwgbGFiZWwgfTtcbiAgfSk7XG5cbiAgcmV0dXJuIChcbiAgICA8c3ZnIHdpZHRoPVwiMTAwJVwiIGhlaWdodD17aGVpZ2h0fSB2aWV3Qm94PXtgMCAwICR7d2lkdGh9ICR7aGVpZ2h0fWB9IHByZXNlcnZlQXNwZWN0UmF0aW89XCJ4TWlkWU1pZCBtZWV0XCI+XG4gICAgICA8ZGVmcz5cbiAgICAgICAgPGxpbmVhckdyYWRpZW50IGlkPVwiYXJlYUZpbGxcIiB4MT1cIjBcIiB5MT1cIjBcIiB4Mj1cIjBcIiB5Mj1cIjFcIj5cbiAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIwJVwiIHN0b3BDb2xvcj17Y29sb3J9IHN0b3BPcGFjaXR5PVwiMC4zXCIgLz5cbiAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIxMDAlXCIgc3RvcENvbG9yPXtjb2xvcn0gc3RvcE9wYWNpdHk9XCIwLjAyXCIgLz5cbiAgICAgICAgPC9saW5lYXJHcmFkaWVudD5cbiAgICAgIDwvZGVmcz5cbiAgICAgIHsvKiBHcmlkICovfVxuICAgICAge2dyaWRMaW5lcy5tYXAoKGcsIGkpID0+IChcbiAgICAgICAgPGcga2V5PXtpfT5cbiAgICAgICAgICA8bGluZSB4MT17cGFkWH0geTE9e2cueX0geDI9e3dpZHRoIC0gcGFkWH0geTI9e2cueX0gc3Ryb2tlPXtDLmJvcmRlcn0gc3Ryb2tlV2lkdGg9XCIxXCIgc3Ryb2tlRGFzaGFycmF5PVwiNCA0XCIgLz5cbiAgICAgICAgICA8dGV4dCB4PXtwYWRYIC0gNn0geT17Zy55ICsgNH0gZmlsbD17Qy50ZXh0RGltfSBmb250U2l6ZT1cIjEwXCIgdGV4dEFuY2hvcj1cImVuZFwiPntnLmxhYmVsfTwvdGV4dD5cbiAgICAgICAgPC9nPlxuICAgICAgKSl9XG4gICAgICB7LyogQXJlYSBmaWxsICovfVxuICAgICAgPHBhdGggZD17YXJlYVBhdGh9IGZpbGw9XCJ1cmwoI2FyZWFGaWxsKVwiIC8+XG4gICAgICB7LyogTGluZSAqL31cbiAgICAgIDxwYXRoIGQ9e2xpbmVQYXRofSBmaWxsPVwibm9uZVwiIHN0cm9rZT17Y29sb3J9IHN0cm9rZVdpZHRoPVwiMi41XCIgc3Ryb2tlTGluZWpvaW49XCJyb3VuZFwiIHN0cm9rZUxpbmVjYXA9XCJyb3VuZFwiIC8+XG4gICAgICB7LyogRG90cyArIGxhYmVscyAqL31cbiAgICAgIHtwb2ludHMubWFwKChwLCBpKSA9PiAoXG4gICAgICAgIDxnIGtleT17aX0+XG4gICAgICAgICAgPGNpcmNsZSBjeD17cC54fSBjeT17cC55fSByPVwiNFwiIGZpbGw9e0MuYmd9IHN0cm9rZT17Y29sb3J9IHN0cm9rZVdpZHRoPVwiMlwiIC8+XG4gICAgICAgICAgPHRleHQgeD17cC54fSB5PXtwYWRZICsgY2hhcnRIICsgMTZ9IGZpbGw9e0MudGV4dE11dGVkfSBmb250U2l6ZT1cIjlcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e2RhdGFbaV0ubGFiZWx9PC90ZXh0PlxuICAgICAgICA8L2c+XG4gICAgICApKX1cbiAgICA8L3N2Zz5cbiAgKTtcbn07XG5cbi8qIOKUgOKUgOKUgCBJbmxpbmUgU1ZHIERvbnV0IENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgRG9udXRDaGFydCA9ICh7IGRhdGEsIHNpemUgPSAyMDAgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCB0b3RhbCA9IGRhdGEucmVkdWNlKChzLCBkKSA9PiBzICsgZC52YWx1ZSwgMCk7XG4gIGlmICh0b3RhbCA9PT0gMCkgcmV0dXJuIG51bGw7XG4gIGNvbnN0IGN4ID0gc2l6ZSAvIDI7XG4gIGNvbnN0IGN5ID0gc2l6ZSAvIDI7XG4gIGNvbnN0IG91dGVyUiA9IHNpemUgLyAyIC0gMTA7XG4gIGNvbnN0IGlubmVyUiA9IG91dGVyUiAqIDAuNjtcbiAgbGV0IGN1bUFuZ2xlID0gLU1hdGguUEkgLyAyO1xuXG4gIGNvbnN0IHNsaWNlcyA9IGRhdGEubWFwKChkLCBpKSA9PiB7XG4gICAgY29uc3QgYW5nbGUgPSAoZC52YWx1ZSAvIHRvdGFsKSAqIE1hdGguUEkgKiAyO1xuICAgIGNvbnN0IHN0YXJ0QW5nbGUgPSBjdW1BbmdsZTtcbiAgICBjdW1BbmdsZSArPSBhbmdsZTtcbiAgICBjb25zdCBlbmRBbmdsZSA9IGN1bUFuZ2xlO1xuXG4gICAgY29uc3QgeDEgPSBjeCArIG91dGVyUiAqIE1hdGguY29zKHN0YXJ0QW5nbGUpO1xuICAgIGNvbnN0IHkxID0gY3kgKyBvdXRlclIgKiBNYXRoLnNpbihzdGFydEFuZ2xlKTtcbiAgICBjb25zdCB4MiA9IGN4ICsgb3V0ZXJSICogTWF0aC5jb3MoZW5kQW5nbGUpO1xuICAgIGNvbnN0IHkyID0gY3kgKyBvdXRlclIgKiBNYXRoLnNpbihlbmRBbmdsZSk7XG4gICAgY29uc3QgaXgxID0gY3ggKyBpbm5lclIgKiBNYXRoLmNvcyhlbmRBbmdsZSk7XG4gICAgY29uc3QgaXkxID0gY3kgKyBpbm5lclIgKiBNYXRoLnNpbihlbmRBbmdsZSk7XG4gICAgY29uc3QgaXgyID0gY3ggKyBpbm5lclIgKiBNYXRoLmNvcyhzdGFydEFuZ2xlKTtcbiAgICBjb25zdCBpeTIgPSBjeSArIGlubmVyUiAqIE1hdGguc2luKHN0YXJ0QW5nbGUpO1xuICAgIGNvbnN0IGxhcmdlQXJjID0gYW5nbGUgPiBNYXRoLlBJID8gMSA6IDA7XG4gICAgY29uc3QgY29sb3IgPSBQTEFURk9STV9DT0xPUlNbaSAlIFBMQVRGT1JNX0NPTE9SUy5sZW5ndGhdO1xuXG4gICAgY29uc3QgcGF0aCA9IGBNJHt4MX0sJHt5MX0gQSR7b3V0ZXJSfSwke291dGVyUn0gMCAke2xhcmdlQXJjfSAxICR7eDJ9LCR7eTJ9IEwke2l4MX0sJHtpeTF9IEEke2lubmVyUn0sJHtpbm5lclJ9IDAgJHtsYXJnZUFyY30gMCAke2l4Mn0sJHtpeTJ9IFpgO1xuICAgIHJldHVybiB7IHBhdGgsIGNvbG9yLCBuYW1lOiBkLm5hbWUsIHZhbHVlOiBkLnZhbHVlLCBwY3Q6IE1hdGgucm91bmQoKGQudmFsdWUgLyB0b3RhbCkgKiAxMDApIH07XG4gIH0pO1xuXG4gIHJldHVybiAoXG4gICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcyNHB4JywgZmxleFdyYXA6ICd3cmFwJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInIH19PlxuICAgICAgPHN2ZyB3aWR0aD17c2l6ZX0gaGVpZ2h0PXtzaXplfSB2aWV3Qm94PXtgMCAwICR7c2l6ZX0gJHtzaXplfWB9PlxuICAgICAgICB7c2xpY2VzLm1hcCgocywgaSkgPT4gKFxuICAgICAgICAgIDxwYXRoIGtleT17aX0gZD17cy5wYXRofSBmaWxsPXtzLmNvbG9yfSBzdHJva2U9e0MuYmd9IHN0cm9rZVdpZHRoPVwiMlwiPlxuICAgICAgICAgICAgPHRpdGxlPntzLm5hbWV9OiB7cy52YWx1ZX0gKHtzLnBjdH0lKTwvdGl0bGU+XG4gICAgICAgICAgPC9wYXRoPlxuICAgICAgICApKX1cbiAgICAgICAgPHRleHQgeD17Y3h9IHk9e2N5IC0gNn0gZmlsbD17Qy50ZXh0fSBmb250U2l6ZT1cIjIyXCIgZm9udFdlaWdodD1cImJvbGRcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e3RvdGFsfTwvdGV4dD5cbiAgICAgICAgPHRleHQgeD17Y3h9IHk9e2N5ICsgMTR9IGZpbGw9e0MudGV4dE11dGVkfSBmb250U2l6ZT1cIjEwXCIgdGV4dEFuY2hvcj1cIm1pZGRsZVwiPlRPVEFMPC90ZXh0PlxuICAgICAgPC9zdmc+XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleERpcmVjdGlvbjogJ2NvbHVtbicsIGdhcDogJzZweCcgfX0+XG4gICAgICAgIHtzbGljZXMubWFwKChzLCBpKSA9PiAoXG4gICAgICAgICAgPGRpdiBrZXk9e2l9IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIGZvbnRTaXplOiAnMTJweCcgfX0+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyB3aWR0aDogMTIsIGhlaWdodDogMTIsIGJvcmRlclJhZGl1czogJzNweCcsIGJhY2tncm91bmRDb2xvcjogcy5jb2xvciwgZGlzcGxheTogJ2lubGluZS1ibG9jaycsIGZsZXhTaHJpbms6IDAgfX0gLz5cbiAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLnRleHQgfX0+e3MubmFtZX08L3NwYW4+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCBtYXJnaW5MZWZ0OiAnYXV0bycgfX0+e3MudmFsdWV9ICh7cy5wY3R9JSk8L3NwYW4+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICkpfVxuICAgICAgPC9kaXY+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG4vKiDilIDilIDilIAgU3RhdCBDYXJkIOKUgOKUgOKUgCAqL1xuY29uc3QgU3RhdENhcmQgPSAoeyBpY29uLCBsYWJlbCwgdmFsdWUsIGRlbHRhLCBkZWx0YUxhYmVsLCBhY2NlbnRDb2xvciB9KSA9PiAoXG4gIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKGFjY2VudENvbG9yKSwgZmxleDogJzEnLCBtaW5XaWR0aDogJzIyMHB4JyB9fVxuICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IGFjY2VudENvbG9yIHx8IEMuYm9yZGVySG92ZXI7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgtMnB4KSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSBgMCA4cHggMjRweCByZ2JhKDAsMCwwLDAuNClgOyB9fVxuICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuYm9yZGVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyTGVmdENvbG9yID0gYWNjZW50Q29sb3I7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgwKSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnbm9uZSc7IH19XG4gID5cbiAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE0cHgnIH19PlxuICAgICAgPEljb24gaWNvbj17aWNvbn0gY29sb3I9e2FjY2VudENvbG9yfSAvPlxuICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzExcHgnLCBmb250V2VpZ2h0OiA3MDAsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wOGVtJyB9fT57bGFiZWx9PC9UZXh0PlxuICAgIDwvZGl2PlxuICAgIDxIMiBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46ICcwIDAgOHB4IDAnLCBmb250U2l6ZTogJzIuMnJlbScgfX0+e3ZhbHVlfTwvSDI+XG4gICAge2RlbHRhICE9PSB1bmRlZmluZWQgJiYgKFxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnIH19PlxuICAgICAgICA8SWNvbiBpY29uPVwiQXJyb3dVcFwiIHNpemU9ezE0fSBjb2xvcj17Qy5ncmVlbn0gLz5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMuZ3JlZW4sIGZvbnRTaXplOiAnMTNweCcsIGZvbnRXZWlnaHQ6IDYwMCB9fT4re2RlbHRhfSB7ZGVsdGFMYWJlbCB8fCAndGhpcyBtb250aCd9PC9UZXh0PlxuICAgICAgPC9kaXY+XG4gICAgKX1cbiAgPC9Cb3g+XG4pO1xuXG4vKiDilIDilIDilIAgQWN0aW9uIEJhZGdlIENhcmQg4pSA4pSA4pSAICovXG5jb25zdCBBY3Rpb25DYXJkID0gKHsgaWNvbiwgbGFiZWwsIGNvdW50LCBhY2NlbnRDb2xvciwgcmVzb3VyY2VJZCB9KSA9PiAoXG4gIDxhIGhyZWY9e2AvYWRtaW4vcmVzb3VyY2VzLyR7cmVzb3VyY2VJZH1gfSBzdHlsZT17eyB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmbGV4OiAnMScsIG1pbldpZHRoOiAnMTgwcHgnIH19PlxuICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKGFjY2VudENvbG9yKSwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMTZweCcgfX1cbiAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoLTJweCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gYDAgNnB4IDIwcHggcmdiYSgwLDAsMCwwLjMpYDsgfX1cbiAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuYm9yZGVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyTGVmdENvbG9yID0gYWNjZW50Q29sb3I7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgwKSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnbm9uZSc7IH19XG4gICAgPlxuICAgICAgPGRpdiBzdHlsZT17eyB3aWR0aDogNDQsIGhlaWdodDogNDQsIGJvcmRlclJhZGl1czogJzEycHgnLCBiYWNrZ3JvdW5kQ29sb3I6IGAke2FjY2VudENvbG9yfTE1YCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLCBmbGV4U2hyaW5rOiAwIH19PlxuICAgICAgICA8SWNvbiBpY29uPXtpY29ufSBzaXplPXsyMn0gY29sb3I9e2FjY2VudENvbG9yfSAvPlxuICAgICAgPC9kaXY+XG4gICAgICA8ZGl2PlxuICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTFweCcsIGZvbnRXZWlnaHQ6IDYwMCwgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nIH19PntsYWJlbH08L1RleHQ+XG4gICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogY291bnQgPiAwID8gYWNjZW50Q29sb3IgOiBDLnRleHREaW0sIG1hcmdpbjogJzRweCAwIDAgMCcgfX0+e2NvdW50fTwvSDU+XG4gICAgICA8L2Rpdj5cbiAgICAgIDxJY29uIGljb249XCJDaGV2cm9uUmlnaHRcIiBjb2xvcj17Qy50ZXh0RGltfSBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnYXV0bycgfX0gLz5cbiAgICA8L0JveD5cbiAgPC9hPlxuKTtcblxuLyog4pSA4pSA4pSAIEZvcm1hdCBkYXRlIG5pY2VseSDilIDilIDilIAgKi9cbmNvbnN0IGZtdERhdGUgPSAoZCkgPT4ge1xuICBpZiAoIWQpIHJldHVybiAn4oCUJztcbiAgY29uc3QgZHQgPSBuZXcgRGF0ZShkKTtcbiAgcmV0dXJuIGR0LnRvTG9jYWxlRGF0ZVN0cmluZygnZW4tVVMnLCB7IG1vbnRoOiAnc2hvcnQnLCBkYXk6ICdudW1lcmljJywgeWVhcjogJ251bWVyaWMnIH0pO1xufTtcblxuLyog4pSA4pSA4pSAIFN0YXR1cyBiYWRnZSBjb2xvciDilIDilIDilIAgKi9cbmNvbnN0IHN0YXR1c0NvbG9yID0gKHMpID0+IHtcbiAgaWYgKCFzKSByZXR1cm4gQy50ZXh0RGltO1xuICBjb25zdCBsb3dlciA9IHMudG9Mb3dlckNhc2UoKTtcbiAgaWYgKGxvd2VyID09PSAnYXBwcm92ZWQnIHx8IGxvd2VyID09PSAnYWN0aXZlJykgcmV0dXJuIEMuZ3JlZW47XG4gIGlmIChsb3dlciA9PT0gJ3BlbmRpbmcnKSByZXR1cm4gQy5vcmFuZ2U7XG4gIGlmIChsb3dlciA9PT0gJ3JlamVjdGVkJykgcmV0dXJuIEMucmVkO1xuICByZXR1cm4gQy50ZXh0TXV0ZWQ7XG59O1xuXG4vKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbiAgIE1BSU4gREFTSEJPQVJEIENPTVBPTkVOVFxuICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovXG5jb25zdCBDdXN0b21EYXNoYm9hcmQgPSAoKSA9PiB7XG4gIGNvbnN0IFtkYXRhLCBzZXREYXRhXSA9IHVzZVN0YXRlKG51bGwpO1xuICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcbiAgY29uc3QgW2Vycm9yLCBzZXRFcnJvcl0gPSB1c2VTdGF0ZShudWxsKTtcblxuICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgIGFwaS5nZXREYXNoYm9hcmQoKVxuICAgICAgLnRoZW4oKHJlc3BvbnNlKSA9PiB7XG4gICAgICAgIHNldERhdGEocmVzcG9uc2UuZGF0YSB8fCB7fSk7XG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgfSlcbiAgICAgIC5jYXRjaCgoZmV0Y2hFcnJvcikgPT4ge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdEYXNoYm9hcmQgZmV0Y2ggZXJyb3I6JywgZmV0Y2hFcnJvcik7XG4gICAgICAgIHNldEVycm9yKCdGYWlsZWQgdG8gbG9hZCBkYXNoYm9hcmQgZGF0YS4nKTtcbiAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICB9KTtcbiAgfSwgW10pO1xuXG4gIGlmIChsb2FkaW5nKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgbWluSGVpZ2h0OiAnMTAwdmgnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgPGRpdiBzdHlsZT17eyB0ZXh0QWxpZ246ICdjZW50ZXInIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6IDQwLCBoZWlnaHQ6IDQwLCBib3JkZXI6IGAzcHggc29saWQgJHtDLmJvcmRlcn1gLCBib3JkZXJUb3BDb2xvcjogQy5nb2xkLCBib3JkZXJSYWRpdXM6ICc1MCUnLCBhbmltYXRpb246ICdzcGluIDFzIGxpbmVhciBpbmZpbml0ZScsIG1hcmdpbjogJzAgYXV0byAxNnB4JyB9fSAvPlxuICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCB9fT5Mb2FkaW5nIGRhc2hib2FyZC4uLjwvVGV4dD5cbiAgICAgICAgICA8c3R5bGU+e2BAa2V5ZnJhbWVzIHNwaW4geyB0byB7IHRyYW5zZm9ybTogcm90YXRlKDM2MGRlZyk7IH0gfWB9PC9zdHlsZT5cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L2Rpdj5cbiAgICApO1xuICB9XG5cbiAgaWYgKGVycm9yKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgbWluSGVpZ2h0OiAnMTAwdmgnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoQy5yZWQpLCBtYXhXaWR0aDogNDAwLCB0ZXh0QWxpZ246ICdjZW50ZXInIH19PlxuICAgICAgICAgIDxJY29uIGljb249XCJBbGVydFRyaWFuZ2xlXCIgc2l6ZT17MzJ9IGNvbG9yPXtDLnJlZH0gLz5cbiAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMucmVkLCBtYXJnaW46ICcxNnB4IDAgOHB4JyB9fT57ZXJyb3J9PC9INT5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQgfX0+Q2hlY2sgdGhlIHNlcnZlciBsb2dzIGZvciBkZXRhaWxzLjwvVGV4dD5cbiAgICAgICAgPC9Cb3g+XG4gICAgICA8L2Rpdj5cbiAgICApO1xuICB9XG5cbiAgY29uc3Qgc3RhdHMgPSBkYXRhPy5zdGF0cyB8fCB7fTtcbiAgY29uc3QgYWN0aW9uUmVxdWlyZWQgPSBkYXRhPy5hY3Rpb25SZXF1aXJlZCB8fCB7fTtcbiAgY29uc3QgbW9kc0J5UGxhdGZvcm0gPSBkYXRhPy5tb2RzQnlQbGF0Zm9ybSB8fCBbXTtcbiAgY29uc3QgdXNlckdyb3d0aERhdGEgPSBkYXRhPy51c2VyR3Jvd3RoRGF0YSB8fCBbXTtcbiAgY29uc3QgcmVjZW50VXNlcnMgPSBkYXRhPy5yZWNlbnRVc2VycyB8fCBbXTtcbiAgY29uc3QgcmVjZW50TW9kcyA9IGRhdGE/LnJlY2VudE1vZHMgfHwgW107XG5cbiAgLy8gUHJlcGFyZSBjaGFydCBkYXRhXG4gIGNvbnN0IGdyb3d0aENoYXJ0RGF0YSA9IHVzZXJHcm93dGhEYXRhLm1hcChkID0+ICh7IGxhYmVsOiBkLmRhdGUsIHZhbHVlOiBkLnVzZXJzIH0pKTtcblxuICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICBjb25zdCBncmVldGluZyA9IG5vdy5nZXRIb3VycygpIDwgMTIgPyAnR29vZCBtb3JuaW5nJyA6IG5vdy5nZXRIb3VycygpIDwgMTggPyAnR29vZCBhZnRlcm5vb24nIDogJ0dvb2QgZXZlbmluZyc7XG5cbiAgcmV0dXJuIChcbiAgICA8ZGl2IHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogQy5iZywgbWluSGVpZ2h0OiAnMTAwdmgnLCBwYWRkaW5nOiAnMzJweCA0MHB4JywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5cbiAgICAgIFxuICAgICAgey8qIOKVkOKVkOKVkCBIRUFERVIg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcxNnB4JywgcGFkZGluZ0JvdHRvbTogJzI0cHgnLCBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gLCBtYXJnaW5Cb3R0b206ICcyOHB4JyB9fT5cbiAgICAgICAgPGRpdj5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluXCIgc3R5bGU9e3sgdGV4dERlY29yYXRpb246ICdub25lJywgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGN1cnNvcjogJ3BvaW50ZXInIH19PlxuICAgICAgICAgICAgPEgyIHN0eWxlPXt7IG1hcmdpbjogMCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5cbiAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6IEMuZ29sZCwgdGV4dFNoYWRvdzogYDAgMCAyMHB4ICR7Qy5nb2xkR2xvd31gLCBmb250V2VpZ2h0OiA4MDAgfX0+R1BMPC9zcGFuPlxuICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNjMGMwYzAnLCB0ZXh0U2hhZG93OiAnMCAwIDE1cHggcmdiYSgxOTIsIDE5MiwgMTkyLCAwLjYpJywgZm9udFdlaWdodDogNzAwIH19Pk1vZHM8L3NwYW4+XG4gICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0sIGZvbnRTaXplOiAnMC41ZW0nLCBmb250V2VpZ2h0OiA0MDAsIG1hcmdpbkxlZnQ6ICcxMnB4JywgYmFja2dyb3VuZDogQy5zdXJmYWNlQWx0LCBwYWRkaW5nOiAnNHB4IDEwcHgnLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBib3JkZXI6IGAxcHggc29saWQgJHtDLmJvcmRlcn1gLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PkFkbWluIERhc2hib2FyZDwvc3Bhbj5cbiAgICAgICAgICAgIDwvSDI+XG4gICAgICAgICAgPC9hPlxuICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCwgbWFyZ2luVG9wOiAnNnB4JywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5cbiAgICAgICAgICAgIHtncmVldGluZ30hIEhlcmUncyB5b3VyIHBsYXRmb3JtIG92ZXJ2aWV3IGZvciB7bm93LnRvTG9jYWxlRGF0ZVN0cmluZygnZW4tVVMnLCB7IHdlZWtkYXk6ICdsb25nJywgbW9udGg6ICdsb25nJywgZGF5OiAnbnVtZXJpYycsIHllYXI6ICdudW1lcmljJyB9KX0uXG4gICAgICAgICAgPC9UZXh0PlxuICAgICAgICA8L2Rpdj5cblxuICAgICAgICB7Lyog4pWQ4pWQ4pWQIEFETUlOIFNVSVRFIFNIT1JUQ1VUIEJVVFRPTlMg4pWQ4pWQ4pWQICovfVxuICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzEwcHgnIH19PlxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9kYXNoYm9hcmRcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogQy5nb2xkLCBiYWNrZ3JvdW5kQ29sb3I6IEMuZ29sZERpbSwgYm9yZGVyOiBgMXB4IHNvbGlkICR7Qy5nb2xkfWAsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDI1NSwyMTUsMCwwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gQy5nb2xkRGltOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJHbyBCYWNrIFRvIERhc2hib2FyZFwiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkFycm93TGVmdFwiIHNpemU9ezE0fSAvPiBHbyBCYWNrIFRvIERhc2hib2FyZFxuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9hZG1pbi9yZXBvcnRzXCIgXG4gICAgICAgICAgICBzdHlsZT17eyBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JywgY29sb3I6ICcjZmY2YjZiJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyMjksNTcsNTMsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyMjksNTcsNTMsMC4zKScsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDIyOSw1Nyw1MywwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjI5LDU3LDUzLDAuMTIpJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiTW9kZXJhdGlvbiAmIE1vZCBSZXBvcnRzIENvbnNvbGVcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJGbGFnXCIgc2l6ZT17MTR9IC8+IFJlcG9ydHNcbiAgICAgICAgICA8L2E+XG5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvYWRtaW4vc3VwcG9ydFwiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnIzY0YjVmNicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMzMsMTUwLDI0MywwLjEyKScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDMzLDE1MCwyNDMsMC4zKScsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDMzLDE1MCwyNDMsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDMzLDE1MCwyNDMsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJMaXZlIFN1cHBvcnQgJiBJbnF1aXJpZXMgQ29uc29sZVwiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkhlbHBDaXJjbGVcIiBzaXplPXsxNH0gLz4gU3VwcG9ydFxuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9zdGF0dXNcIiBcbiAgICAgICAgICAgIHRhcmdldD1cIl9ibGFua1wiIFxuICAgICAgICAgICAgcmVsPVwibm9vcGVuZXIgbm9yZWZlcnJlclwiXG4gICAgICAgICAgICBzdHlsZT17eyBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JywgY29sb3I6ICcjODFjNzg0JywgYmFja2dyb3VuZENvbG9yOiAncmdiYSg2NywxNjAsNzEsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSg2NywxNjAsNzEsMC4zKScsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDY3LDE2MCw3MSwwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoNjcsMTYwLDcxLDAuMTIpJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiTGl2ZSBTZXJ2ZXIgSGVhbHRoICYgRGlhZ25vc3RpY3NcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJBY3Rpdml0eVwiIHNpemU9ezE0fSAvPiBTdGF0dXNcbiAgICAgICAgICA8L2E+XG5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvYWRtaW4vbXVzaWNcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyNiYTY4YzgnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDE4NiwxMDQsMjAwLDAuMTIpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMTg2LDEwNCwyMDAsMC4zKScsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDE4NiwxMDQsMjAwLDAuMjUpJzsgfX1cbiAgICAgICAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgxODYsMTA0LDIwMCwwLjEyKSc7IH19XG4gICAgICAgICAgICB0aXRsZT1cIk11c2ljICYgUGxheWxpc3QgTWFuYWdlclwiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIk11c2ljXCIgc2l6ZT17MTR9IC8+IE11c2ljXG4gICAgICAgICAgPC9hPlxuXG4gICAgICAgICAgPGEgXG4gICAgICAgICAgICBocmVmPVwiL2hvbWVcIiBcbiAgICAgICAgICAgIHRhcmdldD1cIl9ibGFua1wiIFxuICAgICAgICAgICAgcmVsPVwibm9vcGVuZXIgbm9yZWZlcnJlclwiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnI2UwZTBlMCcsIGJhY2tncm91bmRDb2xvcjogQy5zdXJmYWNlQWx0LCBib3JkZXI6IGAxcHggc29saWQgJHtDLmJvcmRlcn1gLCBwYWRkaW5nOiAnOHB4IDE0cHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTNweCcsIHRyYW5zaXRpb246ICdhbGwgMC4ycycgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuZ29sZDsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmNvbG9yID0gQy5nb2xkOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckNvbG9yID0gQy5ib3JkZXI7IGUuY3VycmVudFRhcmdldC5zdHlsZS5jb2xvciA9ICcjZTBlMGUwJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiT3BlbiBMaXZlIFB1YmxpYyBTaXRlXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiR2xvYmVcIiBzaXplPXsxNH0gLz4gTGl2ZSBTaXRlXG4gICAgICAgICAgPC9hPlxuICAgICAgICA8L2Rpdj5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIFNUQVQgQ0FSRFMg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzIwcHgnLCBtYXJnaW5Cb3R0b206ICcyNHB4JyB9fT5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJVc2Vyc1wiIGxhYmVsPVwiVG90YWwgVXNlcnNcIiB2YWx1ZT17KHN0YXRzLnRvdGFsVXNlcnMgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gZGVsdGE9e3N0YXRzLm5ld1VzZXJzVGhpc01vbnRofSBhY2NlbnRDb2xvcj17Qy5ibHVlfSAvPlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIlBhY2thZ2VcIiBsYWJlbD1cIlRvdGFsIE1vZHNcIiB2YWx1ZT17KHN0YXRzLnRvdGFsTW9kcyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBkZWx0YT17c3RhdHMubmV3TW9kc1RoaXNNb250aH0gYWNjZW50Q29sb3I9e0MuZ29sZH0gLz5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJEb3dubG9hZFwiIGxhYmVsPVwiVG90YWwgRG93bmxvYWRzXCIgdmFsdWU9eyhzdGF0cy50b3RhbERvd25sb2FkcyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBhY2NlbnRDb2xvcj17Qy5ncmVlbn0gLz5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJFeWVcIiBsYWJlbD1cIlRvdGFsIFZpZXdzXCIgdmFsdWU9eyhzdGF0cy50b3RhbFZpZXdzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGFjY2VudENvbG9yPXtDLnB1cnBsZX0gLz5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIEFDVElPTiBSRVFVSVJFRCDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMTZweCcsIG1hcmdpbkJvdHRvbTogJzMycHgnIH19PlxuICAgICAgICA8QWN0aW9uQ2FyZCBpY29uPVwiRmxhZ1wiIGxhYmVsPVwiUGVuZGluZyBSZXBvcnRzXCIgY291bnQ9e2FjdGlvblJlcXVpcmVkLnBlbmRpbmdSZXBvcnRzIHx8IDB9IGFjY2VudENvbG9yPXtDLnJlZH0gcmVzb3VyY2VJZD1cIlJlcG9ydFwiIC8+XG4gICAgICAgIDxBY3Rpb25DYXJkIGljb249XCJDaGVja1NxdWFyZVwiIGxhYmVsPVwiUGVuZGluZyBBcHByb3ZhbHNcIiBjb3VudD17YWN0aW9uUmVxdWlyZWQucGVuZGluZ0FwcHJvdmFscyB8fCAwfSBhY2NlbnRDb2xvcj17Qy5vcmFuZ2V9IHJlc291cmNlSWQ9XCJGaWxlXCIgLz5cbiAgICAgICAgPEFjdGlvbkNhcmQgaWNvbj1cIkhlbHBDaXJjbGVcIiBsYWJlbD1cIk9wZW4gVGlja2V0c1wiIGNvdW50PXthY3Rpb25SZXF1aXJlZC5vcGVuVGlja2V0cyB8fCAwfSBhY2NlbnRDb2xvcj17Qy5ibHVlfSByZXNvdXJjZUlkPVwiU3VwcG9ydFRpY2tldFwiIC8+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBDSEFSVFMgUk9XIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcyMHB4JywgbWFyZ2luQm90dG9tOiAnMzJweCcgfX0+XG4gICAgICAgIHsvKiBVc2VyIEdyb3d0aCBDaGFydCAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzInLCBtaW5XaWR0aDogJzM4MHB4JyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzIwcHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkFjdGl2aXR5XCIgY29sb3I9e0MuZ29sZH0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAgfX0+VXNlciBHcm93dGg8L0g1PlxuICAgICAgICAgICAgPEJhZGdlIHN0eWxlPXt7IG1hcmdpbkxlZnQ6ICc4cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuZ29sZERpbSwgY29sb3I6IEMuZ29sZCwgYm9yZGVyOiAnbm9uZScgfX0+MzAgZGF5czwvQmFkZ2U+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICAge2dyb3d0aENoYXJ0RGF0YS5sZW5ndGggPiAwID8gKFxuICAgICAgICAgICAgPEFyZWFDaGFydCBkYXRhPXtncm93dGhDaGFydERhdGF9IGNvbG9yPXtDLmdvbGR9IHdpZHRoPXs2MDB9IGhlaWdodD17MjIwfSAvPlxuICAgICAgICAgICkgOiAoXG4gICAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGhlaWdodDogMjAwLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0gfX0+Tm8gdXNlciBzaWdudXBzIGluIHRoZSBsYXN0IDMwIGRheXMuPC9UZXh0PlxuICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgey8qIFBsYXRmb3JtIERvbnV0ICovfVxuICAgICAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZSgpLCBmbGV4OiAnMScsIG1pbldpZHRoOiAnMzAwcHgnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMjBweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiUGllQ2hhcnRcIiBjb2xvcj17Qy5ibHVlfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCB9fT5Nb2RzIGJ5IFBsYXRmb3JtPC9INT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7bW9kc0J5UGxhdGZvcm0ubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDxEb251dENoYXJ0IGRhdGE9e21vZHNCeVBsYXRmb3JtfSBzaXplPXsxODB9IC8+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgaGVpZ2h0OiAxODAsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSB9fT5ObyBwbGF0Zm9ybSBkYXRhIGF2YWlsYWJsZS48L1RleHQ+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIFJFQ0VOVCBBQ1RJVklUWSBST1cg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzIwcHgnLCBtYXJnaW5Cb3R0b206ICczMnB4JyB9fT5cbiAgICAgICAgey8qIFJlY2VudCBVc2VycyAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzEnLCBtaW5XaWR0aDogJzM0MHB4JyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzIwcHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIlVzZXJzXCIgY29sb3I9e0MuYmx1ZX0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAgfX0+UmVjZW50IFVzZXJzPC9INT5cbiAgICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL1VzZXJcIiBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnYXV0bycsIGNvbG9yOiBDLmdvbGQsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5WaWV3IEFsbCDihpI8L2E+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICAge3JlY2VudFVzZXJzLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8dGFibGUgc3R5bGU9e3sgd2lkdGg6ICcxMDAlJywgYm9yZGVyQ29sbGFwc2U6ICdjb2xsYXBzZScgfX0+XG4gICAgICAgICAgICAgIDx0aGVhZD5cbiAgICAgICAgICAgICAgICA8dHIgc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6IEMudGV4dERpbSwgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+VXNlcm5hbWU8L3RoPlxuICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogQy50ZXh0RGltLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5Sb2xlPC90aD5cbiAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdyaWdodCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiBDLnRleHREaW0sIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PkpvaW5lZDwvdGg+XG4gICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgPC90aGVhZD5cbiAgICAgICAgICAgICAgPHRib2R5PlxuICAgICAgICAgICAgICAgIHtyZWNlbnRVc2Vycy5tYXAoKHUsIGkpID0+IChcbiAgICAgICAgICAgICAgICAgIDx0ciBrZXk9e2l9IHN0eWxlPXt7IGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dCwgZm9udFNpemU6ICcxM3B4JywgZm9udFdlaWdodDogNTAwIH19Pnt1LnVzZXJuYW1lfTwvdGQ+XG4gICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzExcHgnLCBwYWRkaW5nOiAnM3B4IDhweCcsIGJvcmRlclJhZGl1czogJzZweCcsIGJhY2tncm91bmRDb2xvcjogdS5yb2xlID09PSAnYWRtaW4nID8gYCR7Qy5nb2xkfTIwYCA6IGAke0MuYmx1ZX0yMGAsIGNvbG9yOiB1LnJvbGUgPT09ICdhZG1pbicgPyBDLmdvbGQgOiBDLmJsdWUsIGZvbnRXZWlnaHQ6IDYwMCB9fT57dS5yb2xlIHx8ICd1c2VyJ308L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0QWxpZ246ICdyaWdodCcgfX0+e2ZtdERhdGUodS5kYXRlKX08L3RkPlxuICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICApKX1cbiAgICAgICAgICAgICAgPC90Ym9keT5cbiAgICAgICAgICAgIDwvdGFibGU+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0sIHRleHRBbGlnbjogJ2NlbnRlcicsIHBhZGRpbmc6ICcyMHB4IDAnIH19Pk5vIHJlY2VudCB1c2Vycy48L1RleHQ+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgey8qIFJlY2VudCBNb2RzICovfVxuICAgICAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZSgpLCBmbGV4OiAnMScsIG1pbldpZHRoOiAnMzQwcHgnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMjBweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiUGFja2FnZVwiIGNvbG9yPXtDLmdvbGR9IC8+XG4gICAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAwIH19PlJlY2VudCBNb2RzPC9INT5cbiAgICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL0ZpbGVcIiBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnYXV0bycsIGNvbG9yOiBDLmdvbGQsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5WaWV3IEFsbCDihpI8L2E+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICAge3JlY2VudE1vZHMubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDx0YWJsZSBzdHlsZT17eyB3aWR0aDogJzEwMCUnLCBib3JkZXJDb2xsYXBzZTogJ2NvbGxhcHNlJyB9fT5cbiAgICAgICAgICAgICAgPHRoZWFkPlxuICAgICAgICAgICAgICAgIDx0ciBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogQy50ZXh0RGltLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5OYW1lPC90aD5cbiAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6IEMudGV4dERpbSwgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+UGxhdGZvcm08L3RoPlxuICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogQy50ZXh0RGltLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5TdGF0dXM8L3RoPlxuICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ3JpZ2h0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6IEMudGV4dERpbSwgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+QWRkZWQ8L3RoPlxuICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgIDwvdGhlYWQ+XG4gICAgICAgICAgICAgIDx0Ym9keT5cbiAgICAgICAgICAgICAgICB7cmVjZW50TW9kcy5tYXAoKG0sIGkpID0+IChcbiAgICAgICAgICAgICAgICAgIDx0ciBrZXk9e2l9IHN0eWxlPXt7IGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dCwgZm9udFNpemU6ICcxM3B4JywgZm9udFdlaWdodDogNTAwLCBtYXhXaWR0aDogJzE4MHB4Jywgb3ZlcmZsb3c6ICdoaWRkZW4nLCB0ZXh0T3ZlcmZsb3c6ICdlbGxpcHNpcycsIHdoaXRlU3BhY2U6ICdub3dyYXAnIH19PnttLm5hbWV9PC90ZD5cbiAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnMTFweCcsIHBhZGRpbmc6ICczcHggOHB4JywgYm9yZGVyUmFkaXVzOiAnNnB4JywgYmFja2dyb3VuZENvbG9yOiBgJHtDLmJsdWV9MjBgLCBjb2xvcjogQy5ibHVlLCBmb250V2VpZ2h0OiA2MDAsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnIH19PnttLmNhdGVnb3J5IHx8ICfigJQnfTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnMTFweCcsIHBhZGRpbmc6ICczcHggOHB4JywgYm9yZGVyUmFkaXVzOiAnNnB4JywgYmFja2dyb3VuZENvbG9yOiBgJHtzdGF0dXNDb2xvcihtLnN0YXR1cyl9MjBgLCBjb2xvcjogc3RhdHVzQ29sb3IobS5zdGF0dXMpLCBmb250V2VpZ2h0OiA2MDAsIHRleHRUcmFuc2Zvcm06ICdjYXBpdGFsaXplJyB9fT57bS5zdGF0dXMgfHwgJ+KAlCd9PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dEFsaWduOiAncmlnaHQnIH19PntmbXREYXRlKG0uZGF0ZSl9PC90ZD5cbiAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgKSl9XG4gICAgICAgICAgICAgIDwvdGJvZHk+XG4gICAgICAgICAgICA8L3RhYmxlPlxuICAgICAgICAgICkgOiAoXG4gICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCB0ZXh0QWxpZ246ICdjZW50ZXInLCBwYWRkaW5nOiAnMjBweCAwJyB9fT5ObyByZWNlbnQgbW9kcy48L1RleHQ+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBGT09URVIg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBwYWRkaW5nVG9wOiAnMjBweCcsIGJvcmRlclRvcDogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgIDxhIGhyZWY9XCIvYWRtaW5cIiBzdHlsZT17eyB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnIH19PlxuICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0sIGZvbnRTaXplOiAnMTJweCcsIGN1cnNvcjogJ3BvaW50ZXInIH19PlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6IEMuZ29sZCwgZm9udFdlaWdodDogNzAwIH19PkdQTDwvc3Bhbj4gPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjODg4JyB9fT5Nb2RzPC9zcGFuPiDigKIgQWRtaW4gUGFuZWwgdjIuNVxuICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgPC9hPlxuICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZ2FwOiAnMTZweCcgfX0+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvVXNlclwiIHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJyB9fT5Vc2VyczwvYT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9GaWxlXCIgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnIH19Pk1vZHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvUmVwb3J0XCIgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnIH19PlJlcG9ydHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvU3VwcG9ydFRpY2tldFwiIHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJyB9fT5UaWNrZXRzPC9hPlxuICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vbXVzaWNcIiBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScgfX0+TXVzaWM8L2E+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBDdXN0b21EYXNoYm9hcmQ7XG4iLCJpbXBvcnQgUmVhY3QgZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94LCBJY29uIH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5cbmNvbnN0IFNpZGViYXJCcmFuZGluZyA9ICgpID0+IHtcbiAgcmV0dXJuIChcbiAgICA8Qm94IFxuICAgICAgZmxleCBcbiAgICAgIGZsZXhEaXJlY3Rpb249XCJjb2x1bW5cIlxuICAgICAgYWxpZ25JdGVtcz1cImNlbnRlclwiIFxuICAgICAganVzdGlmeUNvbnRlbnQ9XCJjZW50ZXJcIiBcbiAgICAgIHA9XCJsZ1wiIFxuICAgICAgc3R5bGU9e3sgXG4gICAgICAgIGJvcmRlckJvdHRvbTogJzFweCBzb2xpZCAjMmEyYTJhJywgXG4gICAgICAgIGJhY2tncm91bmRDb2xvcjogJyMwYTBhMGEnLCBcbiAgICAgICAgcGFkZGluZzogJzIwcHggMTZweCcsXG4gICAgICAgIHBvc2l0aW9uOiAncmVsYXRpdmUnLFxuICAgICAgICBvdmVyZmxvdzogJ2hpZGRlbidcbiAgICAgIH19XG4gICAgPlxuICAgICAgey8qIFN1YnRsZSBnb2xkIGdsb3cgdW5kZXJsaW5lICovfVxuICAgICAgPGRpdiBzdHlsZT17e1xuICAgICAgICBwb3NpdGlvbjogJ2Fic29sdXRlJyxcbiAgICAgICAgYm90dG9tOiAwLFxuICAgICAgICBsZWZ0OiAnNTAlJyxcbiAgICAgICAgdHJhbnNmb3JtOiAndHJhbnNsYXRlWCgtNTAlKScsXG4gICAgICAgIHdpZHRoOiAnNjAlJyxcbiAgICAgICAgaGVpZ2h0OiAnMXB4JyxcbiAgICAgICAgYmFja2dyb3VuZDogJ2xpbmVhci1ncmFkaWVudCg5MGRlZywgdHJhbnNwYXJlbnQsIHJnYmEoMjU1LDIxNSwwLDAuNSksIHRyYW5zcGFyZW50KSdcbiAgICAgIH19IC8+XG5cbiAgICAgIHsvKiBNYWluIExvZ28gJiBUaXRsZSBMaW5rICovfVxuICAgICAgPGEgXG4gICAgICAgIGhyZWY9XCIvYWRtaW5cIiBcbiAgICAgICAgc3R5bGU9e3sgXG4gICAgICAgICAgdGV4dERlY29yYXRpb246ICdub25lJywgXG4gICAgICAgICAgZGlzcGxheTogJ2ZsZXgnLCBcbiAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJywgXG4gICAgICAgICAgZ2FwOiAnMTBweCcsXG4gICAgICAgICAgY3Vyc29yOiAncG9pbnRlcicsXG4gICAgICAgICAgdHJhbnNpdGlvbjogJ29wYWNpdHkgMC4ycyBlYXNlJ1xuICAgICAgICB9fVxuICAgICAgICBvbk1vdXNlRW50ZXI9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5vcGFjaXR5ID0gJzAuODUnOyB9fVxuICAgICAgICBvbk1vdXNlTGVhdmU9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5vcGFjaXR5ID0gJzEnOyB9fVxuICAgICAgPlxuICAgICAgICA8aW1nIFxuICAgICAgICAgIHNyYz1cIi9pbWFnZXMvdGVhbS1sb2dvLnBuZ1wiIFxuICAgICAgICAgIGFsdD1cIkxvZ29cIiBcbiAgICAgICAgICBzdHlsZT17eyBoZWlnaHQ6ICczMnB4Jywgd2lkdGg6ICczMnB4Jywgb2JqZWN0Rml0OiAnY292ZXInLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBmaWx0ZXI6ICdkcm9wLXNoYWRvdygwIDAgNnB4IHJnYmEoMjU1LDIxNSwwLDAuMykpJyB9fSBcbiAgICAgICAgICBvbkVycm9yPXsoZSkgPT4gZS50YXJnZXQuc3R5bGUuZGlzcGxheSA9ICdub25lJ31cbiAgICAgICAgLz5cbiAgICAgICAgPGRpdiBzdHlsZT17eyBmb250U2l6ZTogJzIycHgnLCBmb250V2VpZ2h0OiAnYm9sZCcsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2Jhc2VsaW5lJywgZ2FwOiAnNHB4JyB9fT5cbiAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNGRkQ3MDAnLCB0ZXh0U2hhZG93OiAnMCAwIDEycHggcmdiYSgyNTUsIDIxNSwgMCwgMC40KScgfX0+R1BMPC9zcGFuPlxuICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcsIHRleHRTaGFkb3c6ICcwIDAgMTJweCByZ2JhKDE5MiwgMTkyLCAxOTIsIDAuNSknIH19Pk1vZHM8L3NwYW4+XG4gICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICc5cHgnLCBjb2xvcjogJyM1NTUnLCBmb250V2VpZ2h0OiA2MDAsIG1hcmdpbkxlZnQ6ICc2cHgnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNWVtJyB9fT52Mi41PC9zcGFuPlxuICAgICAgICA8L2Rpdj5cbiAgICAgIDwvYT5cblxuICAgICAgey8qIFF1aWNrIERhc2hib2FyZCBTaG9ydGN1dCBCdXR0b24gKi99XG4gICAgICA8YSBcbiAgICAgICAgaHJlZj1cIi9hZG1pblwiIFxuICAgICAgICBzdHlsZT17e1xuICAgICAgICAgIGRpc3BsYXk6ICdmbGV4JyxcbiAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJyxcbiAgICAgICAgICBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicsXG4gICAgICAgICAgZ2FwOiAnOHB4JyxcbiAgICAgICAgICBtYXJnaW5Ub3A6ICcxMnB4JyxcbiAgICAgICAgICBwYWRkaW5nOiAnNnB4IDE2cHgnLFxuICAgICAgICAgIHdpZHRoOiAnODUlJyxcbiAgICAgICAgICBib3JkZXJSYWRpdXM6ICc4cHgnLFxuICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMDgpJyxcbiAgICAgICAgICBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsIDIxNSwgMCwgMC4yNSknLFxuICAgICAgICAgIGNvbG9yOiAnI0ZGRDcwMCcsXG4gICAgICAgICAgdGV4dERlY29yYXRpb246ICdub25lJyxcbiAgICAgICAgICBmb250U2l6ZTogJzEycHgnLFxuICAgICAgICAgIGZvbnRXZWlnaHQ6IDcwMCxcbiAgICAgICAgICBsZXR0ZXJTcGFjaW5nOiAnMC4wNGVtJyxcbiAgICAgICAgICB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyxcbiAgICAgICAgICB0cmFuc2l0aW9uOiAnYWxsIDAuMnMgZWFzZScsXG4gICAgICAgICAgY3Vyc29yOiAncG9pbnRlcidcbiAgICAgICAgfX1cbiAgICAgICAgb25Nb3VzZUVudGVyPXsoZSkgPT4geyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMiknOyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJzAgMCAxNHB4IHJnYmEoMjU1LDIxNSwwLDAuMyknOyBcbiAgICAgICAgfX1cbiAgICAgICAgb25Nb3VzZUxlYXZlPXsoZSkgPT4geyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMDgpJzsgXG4gICAgICAgICAgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJveFNoYWRvdyA9ICdub25lJzsgXG4gICAgICAgIH19XG4gICAgICA+XG4gICAgICAgIDxJY29uIGljb249XCJIb21lXCIgc2l6ZT17MTN9IGNvbG9yPVwiI0ZGRDcwMFwiIC8+XG4gICAgICAgIDxzcGFuPkRhc2hib2FyZDwvc3Bhbj5cbiAgICAgIDwvYT5cbiAgICA8L0JveD5cbiAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IFNpZGViYXJCcmFuZGluZztcbiIsImltcG9ydCBSZWFjdCwgeyB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3gsIFRleHQsIExvYWRlciB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuaW1wb3J0IHsgdXNlTm90aWNlIH0gZnJvbSAnYWRtaW5qcyc7XG5cbmNvbnN0IEFjdGlvblJlZGlyZWN0ID0gKHByb3BzKSA9PiB7XG4gICAgY29uc3QgeyByZWNvcmQsIGFjdGlvbiB9ID0gcHJvcHM7XG4gICAgY29uc3Qgc2VuZE5vdGljZSA9IHVzZU5vdGljZSgpO1xuXG4gICAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICAgICAgY29uc3QgdXJsID0gcmVjb3JkPy5wYXJhbXM/LnJlZGlyZWN0VXJsO1xuICAgICAgICBcbiAgICAgICAgaWYgKHVybCkge1xuICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgd2luZG93Lm9wZW4odXJsLCAnX2JsYW5rJyk7XG4gICAgICAgICAgICB9LCA1MDApO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgc2VuZE5vdGljZSh7IG1lc3NhZ2U6ICdFcnJvcjogTm8gcmVkaXJlY3QgVVJMIHByb3ZpZGVkLicsIHR5cGU6ICdlcnJvcicgfSk7XG4gICAgICAgIH1cbiAgICB9LCBbcmVjb3JkXSk7XG5cbiAgICByZXR1cm4gKFxuICAgICAgICA8Qm94IGZsZXggZmxleERpcmVjdGlvbj1cImNvbHVtblwiIGFsaWduSXRlbXM9XCJjZW50ZXJcIiBqdXN0aWZ5Q29udGVudD1cImNlbnRlclwiIHA9XCJ4eGxcIj5cbiAgICAgICAgICAgIDxMb2FkZXIgLz5cbiAgICAgICAgICAgIDxUZXh0IG10PVwibGdcIiB2YXJpYW50PVwiaDRcIj5SZWRpcmVjdGluZy4uLjwvVGV4dD5cbiAgICAgICAgPC9Cb3g+XG4gICAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEFjdGlvblJlZGlyZWN0O1xuIiwiaW1wb3J0IFJlYWN0IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJhZGdlIH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5cbmNvbnN0IFZhcmlhbnRCYWRnZSA9IChwcm9wcykgPT4ge1xuICBjb25zdCB7IHJlY29yZCwgcHJvcGVydHkgfSA9IHByb3BzO1xuICBjb25zdCBpc1ZhcmlhbnQgPSByZWNvcmQucGFyYW1zW3Byb3BlcnR5Lm5hbWVdO1xuXG4gIGlmIChpc1ZhcmlhbnQgPT09IHRydWUgfHwgaXNWYXJpYW50ID09PSAndHJ1ZScpIHtcbiAgICByZXR1cm4gKFxuICAgICAgPEJhZGdlIHZhcmlhbnQ9XCJwcmltYXJ5XCIgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzIxOTZGMycsIGNvbG9yOiAnI2ZmZicsIGJvcmRlcjogJ25vbmUnIH19PlxuICAgICAgICBWYXJpYW50XG4gICAgICA8L0JhZGdlPlxuICAgICk7XG4gIH1cblxuICByZXR1cm4gKFxuICAgIDxCYWRnZSBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMzMzJywgY29sb3I6ICcjYWFhJywgYm9yZGVyOiAnMXB4IHNvbGlkICM1NTUnIH19PlxuICAgICAgTWFzdGVyXG4gICAgPC9CYWRnZT5cbiAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IFZhcmlhbnRCYWRnZTtcbiIsImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94IH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5cbmNvbnN0IEF2YXRhckNlbGwgPSAocHJvcHMpID0+IHtcbiAgICBjb25zdCB7IHJlY29yZCwgcHJvcGVydHksIHdoZXJlIH0gPSBwcm9wczsgXG4gICAgY29uc3Qga2V5ID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcbiAgICBjb25zdCB1c2VybmFtZSA9IHJlY29yZC5wYXJhbXMudXNlcm5hbWUgfHwgJ1VzZXInO1xuXG4gICAgY29uc3QgW2ltYWdlVXJsLCBzZXRJbWFnZVVybF0gPSB1c2VTdGF0ZShudWxsKTtcbiAgICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcbiAgICBjb25zdCBbaGFzRXJyb3IsIHNldEhhc0Vycm9yXSA9IHVzZVN0YXRlKGZhbHNlKTtcblxuICAgIHVzZUVmZmVjdCgoKSA9PiB7XG4gICAgICAgIGlmICgha2V5KSB7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChrZXkuc3RhcnRzV2l0aCgnaHR0cDovLycpIHx8IGtleS5zdGFydHNXaXRoKCdodHRwczovLycpKSB7XG4gICAgICAgICAgICBzZXRJbWFnZVVybChrZXkpO1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBmZXRjaFNpZ25lZFVybCA9IGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChgL2FwaS9hZG1pbi9zaWduZWQtdXJsP2tleT0ke2VuY29kZVVSSUNvbXBvbmVudChrZXkpfWApO1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZS5vaykge1xuICAgICAgICAgICAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzcG9uc2UuanNvbigpO1xuICAgICAgICAgICAgICAgICAgICBzZXRJbWFnZVVybChkYXRhLnVybCk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgc2V0SGFzRXJyb3IodHJ1ZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiRXJyb3IgZmV0Y2hpbmcgYXZhdGFyIFVSTDpcIiwgZXJyb3IpO1xuICAgICAgICAgICAgICAgIHNldEhhc0Vycm9yKHRydWUpO1xuICAgICAgICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcblxuICAgICAgICBmZXRjaFNpZ25lZFVybCgpO1xuICAgIH0sIFtrZXldKTtcblxuICAgIGNvbnN0IHNpemUgPSB3aGVyZSA9PT0gJ2xpc3QnID8gJzMycHgnIDogJzEyMHB4JztcblxuICAgIGlmIChsb2FkaW5nKSB7XG4gICAgICAgIHJldHVybiA8Qm94IHN0eWxlPXt7IHdpZHRoOiBzaXplLCBoZWlnaHQ6IHNpemUsIGJvcmRlclJhZGl1czogJzUwJScsIGJhY2tncm91bmRDb2xvcjogJyMzMzMnIH19IC8+O1xuICAgIH1cblxuICAgIGlmICghaW1hZ2VVcmwgfHwgaGFzRXJyb3IpIHtcbiAgICAgICAgcmV0dXJuIChcbiAgICAgICAgICAgIDxCb3ggc3R5bGU9e3sgXG4gICAgICAgICAgICAgICAgd2lkdGg6IHNpemUsIFxuICAgICAgICAgICAgICAgIGhlaWdodDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiAnNTAlJywgXG4gICAgICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAnI0ZGRDcwMCcsXG4gICAgICAgICAgICAgICAgY29sb3I6ICcjMGEwYTBhJyxcbiAgICAgICAgICAgICAgICBkaXNwbGF5OiAnZmxleCcsIFxuICAgICAgICAgICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInLCBcbiAgICAgICAgICAgICAgICBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicsXG4gICAgICAgICAgICAgICAgZm9udFdlaWdodDogJ2JvbGQnLFxuICAgICAgICAgICAgICAgIGZvbnRTaXplOiB3aGVyZSA9PT0gJ2xpc3QnID8gJzE0cHgnIDogJzQ4cHgnLFxuICAgICAgICAgICAgICAgIGJvcmRlcjogJzJweCBzb2xpZCAjMzMzJ1xuICAgICAgICAgICAgfX0+XG4gICAgICAgICAgICAgICAge3VzZXJuYW1lLmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpfVxuICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIChcbiAgICAgICAgPEJveD5cbiAgICAgICAgICAgIDxpbWcgXG4gICAgICAgICAgICAgICAgc3JjPXtpbWFnZVVybH0gXG4gICAgICAgICAgICAgICAgYWx0PXt1c2VybmFtZX1cbiAgICAgICAgICAgICAgICBzdHlsZT17eyBcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IHNpemUsIFxuICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IHNpemUsIFxuICAgICAgICAgICAgICAgICAgICBib3JkZXJSYWRpdXM6ICc1MCUnLCBcbiAgICAgICAgICAgICAgICAgICAgb2JqZWN0Rml0OiAnY292ZXInLFxuICAgICAgICAgICAgICAgICAgICBib3JkZXI6ICcycHggc29saWQgI0ZGRDcwMCdcbiAgICAgICAgICAgICAgICB9fSBcbiAgICAgICAgICAgICAgICBvbkVycm9yPXsoKSA9PiBzZXRIYXNFcnJvcih0cnVlKX1cbiAgICAgICAgICAgIC8+XG4gICAgICAgIDwvQm94PlxuICAgICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBBdmF0YXJDZWxsO1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlLCB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3ggfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgSW1hZ2VQcmV2aWV3ID0gKHByb3BzKSA9PiB7XG4gICAgY29uc3QgeyByZWNvcmQsIHByb3BlcnR5LCB3aGVyZSB9ID0gcHJvcHM7IFxuICAgIGNvbnN0IHZhbHVlID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcblxuICAgIGNvbnN0IFtpbWFnZVVybCwgc2V0SW1hZ2VVcmxdID0gdXNlU3RhdGUobnVsbCk7XG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBpZiAoIXZhbHVlKSB7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh2YWx1ZS5zdGFydHNXaXRoKCdodHRwOi8vJykgfHwgdmFsdWUuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKSkge1xuICAgICAgICAgICAgc2V0SW1hZ2VVcmwodmFsdWUpO1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBmZXRjaFNpZ25lZFVybCA9IGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChgL2FwaS9hZG1pbi9zaWduZWQtdXJsP2tleT0ke2VuY29kZVVSSUNvbXBvbmVudCh2YWx1ZSl9YCk7XG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlLm9rKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICAgICAgICAgIHNldEltYWdlVXJsKGRhdGEudXJsKTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiRmFpbGVkIHRvIGZldGNoIHNpZ25lZCBVUkwuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIk5ldHdvcmsgZXJyb3IgZmV0Y2hpbmcgc2lnbmVkIFVSTDpcIiwgZXJyb3IpO1xuICAgICAgICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcblxuICAgICAgICBmZXRjaFNpZ25lZFVybCgpO1xuICAgIH0sIFt2YWx1ZV0pO1xuXG4gICAgaWYgKGxvYWRpbmcpIHJldHVybiA8Qm94IHN0eWxlPXt7IGNvbG9yOiAnI0ZGRDcwMCcsIGZvbnRTaXplOiAnMTJweCcgfX0+TG9hZGluZy4uLjwvQm94PjtcbiAgICBpZiAoIWltYWdlVXJsKSByZXR1cm4gPEJveCBzdHlsZT17eyBjb2xvcjogJyM4ODgnLCBmb250U2l6ZTogJzEycHgnIH19Pk4vQTwvQm94PjtcblxuICAgIGNvbnN0IHNpemUgPSB3aGVyZSA9PT0gJ2xpc3QnID8gJzQwcHgnIDogJzE1MHB4JztcbiAgICBjb25zdCByYWRpdXMgPSBwcm9wZXJ0eS5uYW1lID09PSAncHJvZmlsZUltYWdlS2V5JyA/ICc1MCUnIDogJzhweCc7XG5cbiAgICByZXR1cm4gKFxuICAgICAgICA8Qm94PlxuICAgICAgICAgICAgPGltZyBcbiAgICAgICAgICAgICAgICBzcmM9e2ltYWdlVXJsfSBcbiAgICAgICAgICAgICAgICBhbHQ9XCJQcmV2aWV3XCIgXG4gICAgICAgICAgICAgICAgc3R5bGU9e3sgXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiByYWRpdXMsXG4gICAgICAgICAgICAgICAgICAgIG9iamVjdEZpdDogJ2NvdmVyJyxcbiAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAnIzFhMWExYScsXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlcjogJzFweCBzb2xpZCAjMzMzJ1xuICAgICAgICAgICAgICAgIH19IFxuICAgICAgICAgICAgLz5cbiAgICAgICAgPC9Cb3g+XG4gICAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEltYWdlUHJldmlldztcbiIsImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSB9IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCwgQnV0dG9uLCBIMywgVGV4dCwgSW5wdXQsIExhYmVsLCBGb3JtR3JvdXAsIE5vdGljZUJveCB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuaW1wb3J0IHsgdXNlTm90aWNlLCBBcGlDbGllbnQgfSBmcm9tICdhZG1pbmpzJztcblxuY29uc3QgYXBpID0gbmV3IEFwaUNsaWVudCgpO1xuXG5jb25zdCBNYW5hZ2VWb3RlcyA9IChwcm9wcykgPT4ge1xuICBjb25zdCB7IHJlY29yZCwgcmVzb3VyY2UgfSA9IHByb3BzO1xuICBjb25zdCBhZGROb3RpY2UgPSB1c2VOb3RpY2UoKTtcblxuICBjb25zdCBbd29ya2luZ0NvdW50LCBzZXRXb3JraW5nQ291bnRdID0gdXNlU3RhdGUocmVjb3JkLnBhcmFtcy53b3JraW5nVm90ZUNvdW50IHx8IDApO1xuICBjb25zdCBbbm90V29ya2luZ0NvdW50LCBzZXROb3RXb3JraW5nQ291bnRdID0gdXNlU3RhdGUocmVjb3JkLnBhcmFtcy5ub3RXb3JraW5nVm90ZUNvdW50IHx8IDApO1xuICBjb25zdCBbaXNMb2FkaW5nLCBzZXRJc0xvYWRpbmddID0gdXNlU3RhdGUoZmFsc2UpO1xuXG4gIGNvbnN0IGhhbmRsZVN1Ym1pdCA9IChhY3Rpb25UeXBlKSA9PiB7XG4gICAgaWYgKGFjdGlvblR5cGUgPT09ICdyZXNldCcgJiYgIXdpbmRvdy5jb25maXJtKFwiQXJlIHlvdSBzdXJlIHlvdSB3YW50IHRvIHBlcm1hbmVudGx5IGRlbGV0ZSBhbGwgdXNlciB2b3RlcyBmb3IgdGhpcyBtb2Q/XCIpKSB7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBzZXRJc0xvYWRpbmcodHJ1ZSk7XG5cbiAgICBhcGkucmVzb3VyY2VBY3Rpb24oe1xuICAgICAgcmVzb3VyY2VJZDogcmVzb3VyY2UuaWQsXG4gICAgICBhY3Rpb25OYW1lOiAnbWFuYWdlVm90ZXMnLFxuICAgICAgcmVjb3JkSWQ6IHJlY29yZC5pZCxcbiAgICAgIG1ldGhvZDogJ3Bvc3QnLFxuICAgICAgZGF0YToge1xuICAgICAgICBhY3Rpb25UeXBlOiBhY3Rpb25UeXBlLFxuICAgICAgICBuZXdXb3JraW5nQ291bnQ6IHdvcmtpbmdDb3VudCxcbiAgICAgICAgbmV3Tm90V29ya2luZ0NvdW50OiBub3RXb3JraW5nQ291bnRcbiAgICAgIH1cbiAgICB9KS50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgIHNldElzTG9hZGluZyhmYWxzZSk7XG4gICAgICBpZiAocmVzcG9uc2UuZGF0YS5ub3RpY2UpIHtcbiAgICAgICAgYWRkTm90aWNlKHJlc3BvbnNlLmRhdGEubm90aWNlKTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXNwb25zZS5kYXRhLnJlZGlyZWN0VXJsKSB7XG4gICAgICAgICB3aW5kb3cubG9jYXRpb24uaHJlZiA9IHJlc3BvbnNlLmRhdGEucmVkaXJlY3RVcmw7XG4gICAgICB9XG4gICAgfSkuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgc2V0SXNMb2FkaW5nKGZhbHNlKTtcbiAgICAgIGFkZE5vdGljZSh7IG1lc3NhZ2U6ICdBbiBlcnJvciBvY2N1cnJlZCB3aGlsZSBjb250YWN0aW5nIHRoZSBzZXJ2ZXIuJywgdHlwZTogJ2Vycm9yJyB9KTtcbiAgICB9KTtcbiAgfTtcblxuICByZXR1cm4gKFxuICAgIDxCb3ggdmFyaWFudD1cIndoaXRlXCIgcD1cInhsXCIgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzFhMWExYScsIGJvcmRlclJhZGl1czogJzhweCcsIGJvcmRlcjogJzFweCBzb2xpZCAjMzMzJyB9fT5cbiAgICAgIFxuICAgICAgPEgzIHN0eWxlPXt7IGNvbG9yOiAnI0ZGRDcwMCcsIG1hcmdpbkJvdHRvbTogJzIwcHgnIH19Pk1hbmFnZSBWb3RlcyBmb3I6IHtyZWNvcmQucGFyYW1zLm5hbWV9PC9IMz5cbiAgICAgIFxuICAgICAgPE5vdGljZUJveCBzdHlsZT17eyBtYXJnaW5Cb3R0b206ICczMHB4JyB9fT5cbiAgICAgICAgPHN0cm9uZz5DdXJyZW50IFN0YXR1czo8L3N0cm9uZz48YnIvPlxuICAgICAgICBXb3JraW5nIFZvdGVzOiA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyM0M2EwNDcnLCBmb250V2VpZ2h0OiAnYm9sZCcgfX0+e3JlY29yZC5wYXJhbXMud29ya2luZ1ZvdGVDb3VudCB8fCAwfTwvc3Bhbj48YnIvPlxuICAgICAgICBOb3QgV29ya2luZyBWb3RlczogPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjZTUzOTM1JywgZm9udFdlaWdodDogJ2JvbGQnIH19PntyZWNvcmQucGFyYW1zLm5vdFdvcmtpbmdWb3RlQ291bnQgfHwgMH08L3NwYW4+XG4gICAgICA8L05vdGljZUJveD5cblxuICAgICAgPEJveCBtYj1cInh4bFwiIHA9XCJsZ1wiIHN0eWxlPXt7IGJvcmRlcjogJzFweCBzb2xpZCAjNDQ0JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgYmFja2dyb3VuZENvbG9yOiAnIzBhMGEwYScgfX0+XG4gICAgICAgIDxIMyBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBmb250U2l6ZTogJzEuMmVtJyB9fT5PcHRpb24gMTogUmVzZXQgQWxsIFZvdGVzPC9IMz5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjYzBjMGMwJywgbWFyZ2luQm90dG9tOiAnMTVweCcgfX0+XG4gICAgICAgICAgVGhpcyB3aWxsIHdpcGUgYWxsIGV4aXN0aW5nIHVzZXIgdm90ZXMgYW5kIHJlc2V0IGJvdGggY291bnRzIHRvIDAuIFRoaXMgaXMgaGlnaGx5IHJlY29tbWVuZGVkIHdoZW4gYSBtYWpvciB1cGRhdGUgaXMgcmVsZWFzZWQgdGhhdCBmaXhlcyBhIGJyb2tlbiBtb2QuXG4gICAgICAgIDwvVGV4dD5cbiAgICAgICAgPEJ1dHRvbiBcbiAgICAgICAgICAgIHZhcmlhbnQ9XCJkYW5nZXJcIiBcbiAgICAgICAgICAgIG9uQ2xpY2s9eygpID0+IGhhbmRsZVN1Ym1pdCgncmVzZXQnKX0gXG4gICAgICAgICAgICBkaXNhYmxlZD17aXNMb2FkaW5nfVxuICAgICAgICA+XG4gICAgICAgICAge2lzTG9hZGluZyA/ICdQcm9jZXNzaW5nLi4uJyA6ICdXaXBlICYgUmVzZXQgVm90ZXMgdG8gMCd9XG4gICAgICAgIDwvQnV0dG9uPlxuICAgICAgPC9Cb3g+XG5cbiAgICAgIDxCb3ggcD1cImxnXCIgc3R5bGU9e3sgYm9yZGVyOiAnMXB4IHNvbGlkICM0NDQnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBiYWNrZ3JvdW5kQ29sb3I6ICcjMGEwYTBhJyB9fT5cbiAgICAgICAgPEgzIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGZvbnRTaXplOiAnMS4yZW0nIH19Pk9wdGlvbiAyOiBNYW51YWxseSBPdmVycmlkZSBDb3VudHM8L0gzPlxuICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNmZmFkYWQnLCBtYXJnaW5Cb3R0b206ICcxNXB4JywgZm9udFNpemU6ICcwLjllbScgfX0+XG4gICAgICAgICAgV2FybmluZzogTWFudWFsbHkgc2V0dGluZyBudW1iZXJzIHdpbGwgY2xlYXIgdGhlIGludGVybmFsIGxpc3Qgb2YgdXNlcnMgd2hvIHZvdGVkLiBVc2UgdGhpcyBvbmx5IGlmIHlvdSBuZWVkIHRvIGFydGlmaWNpYWxseSBib29zdCBvciByZWR1Y2UgYSBzY29yZS5cbiAgICAgICAgPC9UZXh0PlxuICAgICAgICBcbiAgICAgICAgPEJveCBmbGV4IHN0eWxlPXt7IGdhcDogJzIwcHgnLCBtYXJnaW5Cb3R0b206ICcyMHB4JyB9fT5cbiAgICAgICAgICAgIDxGb3JtR3JvdXAgc3R5bGU9e3sgZmxleDogMSB9fT5cbiAgICAgICAgICAgICAgICA8TGFiZWwgc3R5bGU9e3sgY29sb3I6ICcjYzBjMGMwJyB9fT5Gb3JjZSBcIldvcmtpbmdcIiBDb3VudDwvTGFiZWw+XG4gICAgICAgICAgICAgICAgPElucHV0IFxuICAgICAgICAgICAgICAgICAgICB0eXBlPVwibnVtYmVyXCIgXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlPXt3b3JraW5nQ291bnR9IFxuICAgICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGUpID0+IHNldFdvcmtpbmdDb3VudChlLnRhcmdldC52YWx1ZSl9IFxuICAgICAgICAgICAgICAgICAgICBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMWExYTFhJywgY29sb3I6ICd3aGl0ZScsIGJvcmRlcjogJzFweCBzb2xpZCAjMzMzJyB9fVxuICAgICAgICAgICAgICAgIC8+XG4gICAgICAgICAgICA8L0Zvcm1Hcm91cD5cbiAgICAgICAgICAgIFxuICAgICAgICAgICAgPEZvcm1Hcm91cCBzdHlsZT17eyBmbGV4OiAxIH19PlxuICAgICAgICAgICAgICAgIDxMYWJlbCBzdHlsZT17eyBjb2xvcjogJyNjMGMwYzAnIH19PkZvcmNlIFwiTm90IFdvcmtpbmdcIiBDb3VudDwvTGFiZWw+XG4gICAgICAgICAgICAgICAgPElucHV0IFxuICAgICAgICAgICAgICAgICAgICB0eXBlPVwibnVtYmVyXCIgXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlPXtub3RXb3JraW5nQ291bnR9IFxuICAgICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGUpID0+IHNldE5vdFdvcmtpbmdDb3VudChlLnRhcmdldC52YWx1ZSl9XG4gICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnLCBjb2xvcjogJ3doaXRlJywgYm9yZGVyOiAnMXB4IHNvbGlkICMzMzMnIH19XG4gICAgICAgICAgICAgICAgLz5cbiAgICAgICAgICAgIDwvRm9ybUdyb3VwPlxuICAgICAgICA8L0JveD5cblxuICAgICAgICA8QnV0dG9uIFxuICAgICAgICAgICAgdmFyaWFudD1cInByaW1hcnlcIiBcbiAgICAgICAgICAgIG9uQ2xpY2s9eygpID0+IGhhbmRsZVN1Ym1pdCgnb3ZlcnJpZGUnKX0gXG4gICAgICAgICAgICBkaXNhYmxlZD17aXNMb2FkaW5nfVxuICAgICAgICAgICAgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnI0ZGRDcwMCcsIGNvbG9yOiAnYmxhY2snLCBib3JkZXI6ICdub25lJyB9fVxuICAgICAgICA+XG4gICAgICAgICAge2lzTG9hZGluZyA/ICdQcm9jZXNzaW5nLi4uJyA6ICdBcHBseSBNYW51YWwgT3ZlcnJpZGUnfVxuICAgICAgICA8L0J1dHRvbj5cbiAgICAgIDwvQm94PlxuXG4gICAgPC9Cb3g+XG4gICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBNYW5hZ2VWb3RlcztcbiIsIkFkbWluSlMuVXNlckNvbXBvbmVudHMgPSB7fVxuQWRtaW5KUy5lbnYuTk9ERV9FTlYgPSBcInByb2R1Y3Rpb25cIlxuaW1wb3J0IERhc2hib2FyZCBmcm9tICcuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkRhc2hib2FyZCA9IERhc2hib2FyZFxuaW1wb3J0IFNpZGViYXJCcmFuZGluZyBmcm9tICcuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9TaWRlYmFyQnJhbmRpbmcnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLlNpZGViYXJCcmFuZGluZyA9IFNpZGViYXJCcmFuZGluZ1xuaW1wb3J0IEFjdGlvblJlZGlyZWN0IGZyb20gJy4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdCdcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuQWN0aW9uUmVkaXJlY3QgPSBBY3Rpb25SZWRpcmVjdFxuaW1wb3J0IFZhcmlhbnRCYWRnZSBmcm9tICcuLi9jb21wb25lbnRzL2NlbGxzL1ZhcmlhbnRCYWRnZSdcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuVmFyaWFudEJhZGdlID0gVmFyaWFudEJhZGdlXG5pbXBvcnQgQXZhdGFyQ2VsbCBmcm9tICcuLi9jb21wb25lbnRzL2NlbGxzL0F2YXRhckNlbGwnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkF2YXRhckNlbGwgPSBBdmF0YXJDZWxsXG5pbXBvcnQgSW1hZ2VQcmV2aWV3IGZyb20gJy4uL2NvbXBvbmVudHMvY2VsbHMvSW1hZ2VQcmV2aWV3J1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5JbWFnZVByZXZpZXcgPSBJbWFnZVByZXZpZXdcbmltcG9ydCBNYW5hZ2VWb3RlcyBmcm9tICcuLi9jb21wb25lbnRzL2FjdGlvbnMvTWFuYWdlVm90ZXMnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLk1hbmFnZVZvdGVzID0gTWFuYWdlVm90ZXMiXSwibmFtZXMiOlsiYXBpIiwiQXBpQ2xpZW50IiwiQyIsImJnIiwic3VyZmFjZSIsInN1cmZhY2VBbHQiLCJib3JkZXIiLCJib3JkZXJIb3ZlciIsImdvbGQiLCJnb2xkRGltIiwiZ29sZEdsb3ciLCJibHVlIiwiZ3JlZW4iLCJwdXJwbGUiLCJyZWQiLCJvcmFuZ2UiLCJ0ZXh0IiwidGV4dE11dGVkIiwidGV4dERpbSIsIlBMQVRGT1JNX0NPTE9SUyIsImNhcmRTdHlsZSIsImFjY2VudENvbG9yIiwiYmFja2dyb3VuZENvbG9yIiwiYm9yZGVyUmFkaXVzIiwiYm9yZGVyTGVmdCIsInBhZGRpbmciLCJ0cmFuc2l0aW9uIiwiY3Vyc29yIiwiQXJlYUNoYXJ0IiwiZGF0YSIsIndpZHRoIiwiaGVpZ2h0IiwiY29sb3IiLCJsZW5ndGgiLCJtYXhWYWwiLCJNYXRoIiwibWF4IiwibWFwIiwiZCIsInZhbHVlIiwicGFkWCIsInBhZFkiLCJjaGFydFciLCJjaGFydEgiLCJwb2ludHMiLCJpIiwieCIsInkiLCJsaW5lUGF0aCIsInAiLCJqb2luIiwiYXJlYVBhdGgiLCJncmlkTGluZXMiLCJwY3QiLCJsYWJlbCIsInJvdW5kIiwiUmVhY3QiLCJjcmVhdGVFbGVtZW50Iiwidmlld0JveCIsInByZXNlcnZlQXNwZWN0UmF0aW8iLCJpZCIsIngxIiwieTEiLCJ4MiIsInkyIiwib2Zmc2V0Iiwic3RvcENvbG9yIiwic3RvcE9wYWNpdHkiLCJnIiwia2V5Iiwic3Ryb2tlIiwic3Ryb2tlV2lkdGgiLCJzdHJva2VEYXNoYXJyYXkiLCJmaWxsIiwiZm9udFNpemUiLCJ0ZXh0QW5jaG9yIiwic3Ryb2tlTGluZWpvaW4iLCJzdHJva2VMaW5lY2FwIiwiY3giLCJjeSIsInIiLCJEb251dENoYXJ0Iiwic2l6ZSIsInRvdGFsIiwicmVkdWNlIiwicyIsIm91dGVyUiIsImlubmVyUiIsImN1bUFuZ2xlIiwiUEkiLCJzbGljZXMiLCJhbmdsZSIsInN0YXJ0QW5nbGUiLCJlbmRBbmdsZSIsImNvcyIsInNpbiIsIml4MSIsIml5MSIsIml4MiIsIml5MiIsImxhcmdlQXJjIiwicGF0aCIsIm5hbWUiLCJzdHlsZSIsImRpc3BsYXkiLCJhbGlnbkl0ZW1zIiwiZ2FwIiwiZmxleFdyYXAiLCJqdXN0aWZ5Q29udGVudCIsImZvbnRXZWlnaHQiLCJmbGV4RGlyZWN0aW9uIiwiZmxleFNocmluayIsIm1hcmdpbkxlZnQiLCJTdGF0Q2FyZCIsImljb24iLCJkZWx0YSIsImRlbHRhTGFiZWwiLCJCb3giLCJmbGV4IiwibWluV2lkdGgiLCJvbk1vdXNlRW50ZXIiLCJlIiwiY3VycmVudFRhcmdldCIsImJvcmRlckNvbG9yIiwidHJhbnNmb3JtIiwiYm94U2hhZG93Iiwib25Nb3VzZUxlYXZlIiwiYm9yZGVyTGVmdENvbG9yIiwibWFyZ2luQm90dG9tIiwiSWNvbiIsIlRleHQiLCJ0ZXh0VHJhbnNmb3JtIiwibGV0dGVyU3BhY2luZyIsIkgyIiwibWFyZ2luIiwidW5kZWZpbmVkIiwiQWN0aW9uQ2FyZCIsImNvdW50IiwicmVzb3VyY2VJZCIsImhyZWYiLCJ0ZXh0RGVjb3JhdGlvbiIsIkg1IiwiZm10RGF0ZSIsImR0IiwiRGF0ZSIsInRvTG9jYWxlRGF0ZVN0cmluZyIsIm1vbnRoIiwiZGF5IiwieWVhciIsInN0YXR1c0NvbG9yIiwibG93ZXIiLCJ0b0xvd2VyQ2FzZSIsIkN1c3RvbURhc2hib2FyZCIsInNldERhdGEiLCJ1c2VTdGF0ZSIsImxvYWRpbmciLCJzZXRMb2FkaW5nIiwiZXJyb3IiLCJzZXRFcnJvciIsInVzZUVmZmVjdCIsImdldERhc2hib2FyZCIsInRoZW4iLCJyZXNwb25zZSIsImNhdGNoIiwiZmV0Y2hFcnJvciIsImNvbnNvbGUiLCJtaW5IZWlnaHQiLCJ0ZXh0QWxpZ24iLCJib3JkZXJUb3BDb2xvciIsImFuaW1hdGlvbiIsIm1heFdpZHRoIiwic3RhdHMiLCJhY3Rpb25SZXF1aXJlZCIsIm1vZHNCeVBsYXRmb3JtIiwidXNlckdyb3d0aERhdGEiLCJyZWNlbnRVc2VycyIsInJlY2VudE1vZHMiLCJncm93dGhDaGFydERhdGEiLCJkYXRlIiwidXNlcnMiLCJub3ciLCJncmVldGluZyIsImdldEhvdXJzIiwiZm9udEZhbWlseSIsInBhZGRpbmdCb3R0b20iLCJib3JkZXJCb3R0b20iLCJ0ZXh0U2hhZG93IiwiYmFja2dyb3VuZCIsIm1hcmdpblRvcCIsIndlZWtkYXkiLCJ0aXRsZSIsInRhcmdldCIsInJlbCIsInRvdGFsVXNlcnMiLCJ0b0xvY2FsZVN0cmluZyIsIm5ld1VzZXJzVGhpc01vbnRoIiwidG90YWxNb2RzIiwibmV3TW9kc1RoaXNNb250aCIsInRvdGFsRG93bmxvYWRzIiwidG90YWxWaWV3cyIsInBlbmRpbmdSZXBvcnRzIiwicGVuZGluZ0FwcHJvdmFscyIsIm9wZW5UaWNrZXRzIiwiQmFkZ2UiLCJib3JkZXJDb2xsYXBzZSIsInUiLCJ1c2VybmFtZSIsInJvbGUiLCJtIiwib3ZlcmZsb3ciLCJ0ZXh0T3ZlcmZsb3ciLCJ3aGl0ZVNwYWNlIiwiY2F0ZWdvcnkiLCJzdGF0dXMiLCJwYWRkaW5nVG9wIiwiYm9yZGVyVG9wIiwiU2lkZWJhckJyYW5kaW5nIiwicG9zaXRpb24iLCJib3R0b20iLCJsZWZ0Iiwib3BhY2l0eSIsInNyYyIsImFsdCIsIm9iamVjdEZpdCIsImZpbHRlciIsIm9uRXJyb3IiLCJBY3Rpb25SZWRpcmVjdCIsInByb3BzIiwicmVjb3JkIiwiYWN0aW9uIiwic2VuZE5vdGljZSIsInVzZU5vdGljZSIsInVybCIsInBhcmFtcyIsInJlZGlyZWN0VXJsIiwic2V0VGltZW91dCIsIndpbmRvdyIsIm9wZW4iLCJtZXNzYWdlIiwidHlwZSIsIkxvYWRlciIsIm10IiwidmFyaWFudCIsIlZhcmlhbnRCYWRnZSIsInByb3BlcnR5IiwiaXNWYXJpYW50IiwiQXZhdGFyQ2VsbCIsIndoZXJlIiwiaW1hZ2VVcmwiLCJzZXRJbWFnZVVybCIsImhhc0Vycm9yIiwic2V0SGFzRXJyb3IiLCJzdGFydHNXaXRoIiwiZmV0Y2hTaWduZWRVcmwiLCJmZXRjaCIsImVuY29kZVVSSUNvbXBvbmVudCIsIm9rIiwianNvbiIsImNoYXJBdCIsInRvVXBwZXJDYXNlIiwiSW1hZ2VQcmV2aWV3IiwicmFkaXVzIiwiTWFuYWdlVm90ZXMiLCJyZXNvdXJjZSIsImFkZE5vdGljZSIsIndvcmtpbmdDb3VudCIsInNldFdvcmtpbmdDb3VudCIsIndvcmtpbmdWb3RlQ291bnQiLCJub3RXb3JraW5nQ291bnQiLCJzZXROb3RXb3JraW5nQ291bnQiLCJub3RXb3JraW5nVm90ZUNvdW50IiwiaXNMb2FkaW5nIiwic2V0SXNMb2FkaW5nIiwiaGFuZGxlU3VibWl0IiwiYWN0aW9uVHlwZSIsImNvbmZpcm0iLCJyZXNvdXJjZUFjdGlvbiIsImFjdGlvbk5hbWUiLCJyZWNvcmRJZCIsIm1ldGhvZCIsIm5ld1dvcmtpbmdDb3VudCIsIm5ld05vdFdvcmtpbmdDb3VudCIsIm5vdGljZSIsImxvY2F0aW9uIiwiSDMiLCJOb3RpY2VCb3giLCJtYiIsIkJ1dHRvbiIsIm9uQ2xpY2siLCJkaXNhYmxlZCIsIkZvcm1Hcm91cCIsIkxhYmVsIiwiSW5wdXQiLCJvbkNoYW5nZSIsIkFkbWluSlMiLCJVc2VyQ29tcG9uZW50cyIsImVudiIsIk5PREVfRU5WIiwiRGFzaGJvYXJkIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0VBSUEsTUFBTUEsS0FBRyxHQUFHLElBQUlDLGlCQUFTLEVBQUU7O0VBRTNCO0VBQ0EsTUFBTUMsQ0FBQyxHQUFHO0VBQ1JDLEVBQUFBLEVBQUUsRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE9BQU8sRUFBRSxTQUFTO0VBQUVDLEVBQUFBLFVBQVUsRUFBRSxTQUFTO0VBQ3hEQyxFQUFBQSxNQUFNLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxXQUFXLEVBQUUsU0FBUztFQUN6Q0MsRUFBQUEsSUFBSSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsT0FBTyxFQUFFLHNCQUFzQjtFQUFFQyxFQUFBQSxRQUFRLEVBQUUsc0JBQXNCO0VBQ2xGQyxFQUFBQSxJQUFJLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxLQUFLLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxNQUFNLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxHQUFHLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxNQUFNLEVBQUUsU0FBUztFQUN2RkMsRUFBQUEsSUFBSSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsU0FBUyxFQUFFLE1BQU07RUFBRUMsRUFBQUEsT0FBTyxFQUFFO0VBQy9DLENBQUM7O0VBRUQ7RUFDQSxNQUFNQyxlQUFlLEdBQUcsQ0FBQyxTQUFTLEVBQUUsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsU0FBUyxDQUFDOztFQUVoSDtFQUNBLE1BQU1DLFNBQVMsR0FBSUMsV0FBVyxLQUFNO0lBQ2xDQyxlQUFlLEVBQUVwQixDQUFDLENBQUNFLE9BQU87RUFDMUJtQixFQUFBQSxZQUFZLEVBQUUsTUFBTTtFQUNwQmpCLEVBQUFBLE1BQU0sRUFBRSxDQUFBLFVBQUEsRUFBYUosQ0FBQyxDQUFDSSxNQUFNLENBQUEsQ0FBRTtJQUMvQmtCLFVBQVUsRUFBRUgsV0FBVyxHQUFHLENBQUEsVUFBQSxFQUFhQSxXQUFXLENBQUEsQ0FBRSxHQUFHLENBQUEsVUFBQSxFQUFhbkIsQ0FBQyxDQUFDSSxNQUFNLENBQUEsQ0FBRTtFQUM5RW1CLEVBQUFBLE9BQU8sRUFBRSxNQUFNO0VBQ2ZDLEVBQUFBLFVBQVUsRUFBRSxnQkFBZ0I7RUFDNUJDLEVBQUFBLE1BQU0sRUFBRTtFQUNWLENBQUMsQ0FBQzs7RUFFRjtFQUNBLE1BQU1DLFNBQVMsR0FBR0EsQ0FBQztJQUFFQyxJQUFJO0VBQUVDLEVBQUFBLEtBQUssR0FBRyxHQUFHO0VBQUVDLEVBQUFBLE1BQU0sR0FBRyxHQUFHO0lBQUVDLEtBQUssR0FBRzlCLENBQUMsQ0FBQ007RUFBSyxDQUFDLEtBQUs7SUFDekUsSUFBSSxDQUFDcUIsSUFBSSxJQUFJQSxJQUFJLENBQUNJLE1BQU0sS0FBSyxDQUFDLEVBQUUsT0FBTyxJQUFJO0VBQzNDLEVBQUEsTUFBTUMsTUFBTSxHQUFHQyxJQUFJLENBQUNDLEdBQUcsQ0FBQyxHQUFHUCxJQUFJLENBQUNRLEdBQUcsQ0FBQ0MsQ0FBQyxJQUFJQSxDQUFDLENBQUNDLEtBQUssQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUNyRCxNQUFNQyxJQUFJLEdBQUcsRUFBRTtJQUNmLE1BQU1DLElBQUksR0FBRyxFQUFFO0VBQ2YsRUFBQSxNQUFNQyxNQUFNLEdBQUdaLEtBQUssR0FBR1UsSUFBSSxHQUFHLENBQUM7RUFDL0IsRUFBQSxNQUFNRyxNQUFNLEdBQUdaLE1BQU0sR0FBR1UsSUFBSSxHQUFHLENBQUM7SUFFaEMsTUFBTUcsTUFBTSxHQUFHZixJQUFJLENBQUNRLEdBQUcsQ0FBQyxDQUFDQyxDQUFDLEVBQUVPLENBQUMsTUFBTTtFQUNqQ0MsSUFBQUEsQ0FBQyxFQUFFTixJQUFJLEdBQUlLLENBQUMsR0FBR1YsSUFBSSxDQUFDQyxHQUFHLENBQUNQLElBQUksQ0FBQ0ksTUFBTSxHQUFHLENBQUMsRUFBRSxDQUFDLENBQUMsR0FBSVMsTUFBTTtNQUNyREssQ0FBQyxFQUFFTixJQUFJLEdBQUdFLE1BQU0sR0FBSUwsQ0FBQyxDQUFDQyxLQUFLLEdBQUdMLE1BQU0sR0FBSVM7RUFDMUMsR0FBQyxDQUFDLENBQUM7RUFFSCxFQUFBLE1BQU1LLFFBQVEsR0FBR0osTUFBTSxDQUFDUCxHQUFHLENBQUMsQ0FBQ1ksQ0FBQyxFQUFFSixDQUFDLEtBQUssQ0FBQSxFQUFHQSxDQUFDLEtBQUssQ0FBQyxHQUFHLEdBQUcsR0FBRyxHQUFHLENBQUEsRUFBR0ksQ0FBQyxDQUFDSCxDQUFDLENBQUEsQ0FBQSxFQUFJRyxDQUFDLENBQUNGLENBQUMsRUFBRSxDQUFDLENBQUNHLElBQUksQ0FBQyxHQUFHLENBQUM7RUFDdEYsRUFBQSxNQUFNQyxRQUFRLEdBQUcsQ0FBQSxFQUFHSCxRQUFRLENBQUEsRUFBQSxFQUFLSixNQUFNLENBQUNBLE1BQU0sQ0FBQ1gsTUFBTSxHQUFHLENBQUMsQ0FBQyxDQUFDYSxDQUFDLENBQUEsQ0FBQSxFQUFJTCxJQUFJLEdBQUdFLE1BQU0sQ0FBQSxFQUFBLEVBQUtDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQ0UsQ0FBQyxDQUFBLENBQUEsRUFBSUwsSUFBSSxHQUFHRSxNQUFNLENBQUEsRUFBQSxDQUFJOztFQUVsSDtFQUNBLEVBQUEsTUFBTVMsU0FBUyxHQUFHLENBQUMsQ0FBQyxFQUFFLElBQUksRUFBRSxHQUFHLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQyxDQUFDZixHQUFHLENBQUNnQixHQUFHLElBQUk7TUFDbkQsTUFBTU4sQ0FBQyxHQUFHTixJQUFJLEdBQUdFLE1BQU0sR0FBR1UsR0FBRyxHQUFHVixNQUFNO01BQ3RDLE1BQU1XLEtBQUssR0FBR25CLElBQUksQ0FBQ29CLEtBQUssQ0FBQ0YsR0FBRyxHQUFHbkIsTUFBTSxDQUFDO01BQ3RDLE9BQU87UUFBRWEsQ0FBQztFQUFFTyxNQUFBQTtPQUFPO0VBQ3JCLEVBQUEsQ0FBQyxDQUFDO0lBRUYsb0JBQ0VFLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxLQUFBLEVBQUE7RUFBSzNCLElBQUFBLEtBQUssRUFBQyxNQUFNO0VBQUNDLElBQUFBLE1BQU0sRUFBRUEsTUFBTztFQUFDMkIsSUFBQUEsT0FBTyxFQUFFLENBQUEsSUFBQSxFQUFPNUIsS0FBSyxDQUFBLENBQUEsRUFBSUMsTUFBTSxDQUFBLENBQUc7RUFBQzRCLElBQUFBLG1CQUFtQixFQUFDO0VBQWUsR0FBQSxlQUN0R0gsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQSxJQUFBLGVBQ0VELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxnQkFBQSxFQUFBO0VBQWdCRyxJQUFBQSxFQUFFLEVBQUMsVUFBVTtFQUFDQyxJQUFBQSxFQUFFLEVBQUMsR0FBRztFQUFDQyxJQUFBQSxFQUFFLEVBQUMsR0FBRztFQUFDQyxJQUFBQSxFQUFFLEVBQUMsR0FBRztFQUFDQyxJQUFBQSxFQUFFLEVBQUM7S0FBRyxlQUN2RFIsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQTtFQUFNUSxJQUFBQSxNQUFNLEVBQUMsSUFBSTtFQUFDQyxJQUFBQSxTQUFTLEVBQUVsQyxLQUFNO0VBQUNtQyxJQUFBQSxXQUFXLEVBQUM7RUFBSyxHQUFFLENBQUMsZUFDeERYLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxNQUFBLEVBQUE7RUFBTVEsSUFBQUEsTUFBTSxFQUFDLE1BQU07RUFBQ0MsSUFBQUEsU0FBUyxFQUFFbEMsS0FBTTtFQUFDbUMsSUFBQUEsV0FBVyxFQUFDO0VBQU0sR0FBRSxDQUM1QyxDQUNaLENBQUMsRUFFTmYsU0FBUyxDQUFDZixHQUFHLENBQUMsQ0FBQytCLENBQUMsRUFBRXZCLENBQUMsa0JBQ2xCVyxzQkFBQSxDQUFBQyxhQUFBLENBQUEsR0FBQSxFQUFBO0VBQUdZLElBQUFBLEdBQUcsRUFBRXhCO0tBQUUsZUFDUlcsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQTtFQUFNSSxJQUFBQSxFQUFFLEVBQUVyQixJQUFLO01BQUNzQixFQUFFLEVBQUVNLENBQUMsQ0FBQ3JCLENBQUU7TUFBQ2dCLEVBQUUsRUFBRWpDLEtBQUssR0FBR1UsSUFBSztNQUFDd0IsRUFBRSxFQUFFSSxDQUFDLENBQUNyQixDQUFFO01BQUN1QixNQUFNLEVBQUVwRSxDQUFDLENBQUNJLE1BQU87RUFBQ2lFLElBQUFBLFdBQVcsRUFBQyxHQUFHO0VBQUNDLElBQUFBLGVBQWUsRUFBQztFQUFLLEdBQUUsQ0FBQyxlQUM5R2hCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxNQUFBLEVBQUE7TUFBTVgsQ0FBQyxFQUFFTixJQUFJLEdBQUcsQ0FBRTtFQUFDTyxJQUFBQSxDQUFDLEVBQUVxQixDQUFDLENBQUNyQixDQUFDLEdBQUcsQ0FBRTtNQUFDMEIsSUFBSSxFQUFFdkUsQ0FBQyxDQUFDZ0IsT0FBUTtFQUFDd0QsSUFBQUEsUUFBUSxFQUFDLElBQUk7RUFBQ0MsSUFBQUEsVUFBVSxFQUFDO0tBQUssRUFBRVAsQ0FBQyxDQUFDZCxLQUFZLENBQzdGLENBQ0osQ0FBQyxlQUVGRSxzQkFBQSxDQUFBQyxhQUFBLENBQUEsTUFBQSxFQUFBO0VBQU1uQixJQUFBQSxDQUFDLEVBQUVhLFFBQVM7RUFBQ3NCLElBQUFBLElBQUksRUFBQztFQUFnQixHQUFFLENBQUMsZUFFM0NqQixzQkFBQSxDQUFBQyxhQUFBLENBQUEsTUFBQSxFQUFBO0VBQU1uQixJQUFBQSxDQUFDLEVBQUVVLFFBQVM7RUFBQ3lCLElBQUFBLElBQUksRUFBQyxNQUFNO0VBQUNILElBQUFBLE1BQU0sRUFBRXRDLEtBQU07RUFBQ3VDLElBQUFBLFdBQVcsRUFBQyxLQUFLO0VBQUNLLElBQUFBLGNBQWMsRUFBQyxPQUFPO0VBQUNDLElBQUFBLGFBQWEsRUFBQztFQUFPLEdBQUUsQ0FBQyxFQUU5R2pDLE1BQU0sQ0FBQ1AsR0FBRyxDQUFDLENBQUNZLENBQUMsRUFBRUosQ0FBQyxrQkFDZlcsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEdBQUEsRUFBQTtFQUFHWSxJQUFBQSxHQUFHLEVBQUV4QjtLQUFFLGVBQ1JXLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxRQUFBLEVBQUE7TUFBUXFCLEVBQUUsRUFBRTdCLENBQUMsQ0FBQ0gsQ0FBRTtNQUFDaUMsRUFBRSxFQUFFOUIsQ0FBQyxDQUFDRixDQUFFO0VBQUNpQyxJQUFBQSxDQUFDLEVBQUMsR0FBRztNQUFDUCxJQUFJLEVBQUV2RSxDQUFDLENBQUNDLEVBQUc7RUFBQ21FLElBQUFBLE1BQU0sRUFBRXRDLEtBQU07RUFBQ3VDLElBQUFBLFdBQVcsRUFBQztFQUFHLEdBQUUsQ0FBQyxlQUM3RWYsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQTtNQUFNWCxDQUFDLEVBQUVHLENBQUMsQ0FBQ0gsQ0FBRTtFQUFDQyxJQUFBQSxDQUFDLEVBQUVOLElBQUksR0FBR0UsTUFBTSxHQUFHLEVBQUc7TUFBQzhCLElBQUksRUFBRXZFLENBQUMsQ0FBQ2UsU0FBVTtFQUFDeUQsSUFBQUEsUUFBUSxFQUFDLEdBQUc7RUFBQ0MsSUFBQUEsVUFBVSxFQUFDO0tBQVEsRUFBRTlDLElBQUksQ0FBQ2dCLENBQUMsQ0FBQyxDQUFDUyxLQUFZLENBQzdHLENBQ0osQ0FDRSxDQUFDO0VBRVYsQ0FBQzs7RUFFRDtFQUNBLE1BQU0yQixVQUFVLEdBQUdBLENBQUM7SUFBRXBELElBQUk7RUFBRXFELEVBQUFBLElBQUksR0FBRztFQUFJLENBQUMsS0FBSztJQUMzQyxJQUFJLENBQUNyRCxJQUFJLElBQUlBLElBQUksQ0FBQ0ksTUFBTSxLQUFLLENBQUMsRUFBRSxPQUFPLElBQUk7RUFDM0MsRUFBQSxNQUFNa0QsS0FBSyxHQUFHdEQsSUFBSSxDQUFDdUQsTUFBTSxDQUFDLENBQUNDLENBQUMsRUFBRS9DLENBQUMsS0FBSytDLENBQUMsR0FBRy9DLENBQUMsQ0FBQ0MsS0FBSyxFQUFFLENBQUMsQ0FBQztFQUNuRCxFQUFBLElBQUk0QyxLQUFLLEtBQUssQ0FBQyxFQUFFLE9BQU8sSUFBSTtFQUM1QixFQUFBLE1BQU1MLEVBQUUsR0FBR0ksSUFBSSxHQUFHLENBQUM7RUFDbkIsRUFBQSxNQUFNSCxFQUFFLEdBQUdHLElBQUksR0FBRyxDQUFDO0VBQ25CLEVBQUEsTUFBTUksTUFBTSxHQUFHSixJQUFJLEdBQUcsQ0FBQyxHQUFHLEVBQUU7RUFDNUIsRUFBQSxNQUFNSyxNQUFNLEdBQUdELE1BQU0sR0FBRyxHQUFHO0VBQzNCLEVBQUEsSUFBSUUsUUFBUSxHQUFHLENBQUNyRCxJQUFJLENBQUNzRCxFQUFFLEdBQUcsQ0FBQztJQUUzQixNQUFNQyxNQUFNLEdBQUc3RCxJQUFJLENBQUNRLEdBQUcsQ0FBQyxDQUFDQyxDQUFDLEVBQUVPLENBQUMsS0FBSztFQUNoQyxJQUFBLE1BQU04QyxLQUFLLEdBQUlyRCxDQUFDLENBQUNDLEtBQUssR0FBRzRDLEtBQUssR0FBSWhELElBQUksQ0FBQ3NELEVBQUUsR0FBRyxDQUFDO01BQzdDLE1BQU1HLFVBQVUsR0FBR0osUUFBUTtFQUMzQkEsSUFBQUEsUUFBUSxJQUFJRyxLQUFLO01BQ2pCLE1BQU1FLFFBQVEsR0FBR0wsUUFBUTtNQUV6QixNQUFNM0IsRUFBRSxHQUFHaUIsRUFBRSxHQUFHUSxNQUFNLEdBQUduRCxJQUFJLENBQUMyRCxHQUFHLENBQUNGLFVBQVUsQ0FBQztNQUM3QyxNQUFNOUIsRUFBRSxHQUFHaUIsRUFBRSxHQUFHTyxNQUFNLEdBQUduRCxJQUFJLENBQUM0RCxHQUFHLENBQUNILFVBQVUsQ0FBQztNQUM3QyxNQUFNN0IsRUFBRSxHQUFHZSxFQUFFLEdBQUdRLE1BQU0sR0FBR25ELElBQUksQ0FBQzJELEdBQUcsQ0FBQ0QsUUFBUSxDQUFDO01BQzNDLE1BQU03QixFQUFFLEdBQUdlLEVBQUUsR0FBR08sTUFBTSxHQUFHbkQsSUFBSSxDQUFDNEQsR0FBRyxDQUFDRixRQUFRLENBQUM7TUFDM0MsTUFBTUcsR0FBRyxHQUFHbEIsRUFBRSxHQUFHUyxNQUFNLEdBQUdwRCxJQUFJLENBQUMyRCxHQUFHLENBQUNELFFBQVEsQ0FBQztNQUM1QyxNQUFNSSxHQUFHLEdBQUdsQixFQUFFLEdBQUdRLE1BQU0sR0FBR3BELElBQUksQ0FBQzRELEdBQUcsQ0FBQ0YsUUFBUSxDQUFDO01BQzVDLE1BQU1LLEdBQUcsR0FBR3BCLEVBQUUsR0FBR1MsTUFBTSxHQUFHcEQsSUFBSSxDQUFDMkQsR0FBRyxDQUFDRixVQUFVLENBQUM7TUFDOUMsTUFBTU8sR0FBRyxHQUFHcEIsRUFBRSxHQUFHUSxNQUFNLEdBQUdwRCxJQUFJLENBQUM0RCxHQUFHLENBQUNILFVBQVUsQ0FBQztNQUM5QyxNQUFNUSxRQUFRLEdBQUdULEtBQUssR0FBR3hELElBQUksQ0FBQ3NELEVBQUUsR0FBRyxDQUFDLEdBQUcsQ0FBQztNQUN4QyxNQUFNekQsS0FBSyxHQUFHYixlQUFlLENBQUMwQixDQUFDLEdBQUcxQixlQUFlLENBQUNjLE1BQU0sQ0FBQztFQUV6RCxJQUFBLE1BQU1vRSxJQUFJLEdBQUcsQ0FBQSxDQUFBLEVBQUl4QyxFQUFFLENBQUEsQ0FBQSxFQUFJQyxFQUFFLENBQUEsRUFBQSxFQUFLd0IsTUFBTSxDQUFBLENBQUEsRUFBSUEsTUFBTSxDQUFBLEdBQUEsRUFBTWMsUUFBUSxNQUFNckMsRUFBRSxDQUFBLENBQUEsRUFBSUMsRUFBRSxDQUFBLEVBQUEsRUFBS2dDLEdBQUcsQ0FBQSxDQUFBLEVBQUlDLEdBQUcsQ0FBQSxFQUFBLEVBQUtWLE1BQU0sQ0FBQSxDQUFBLEVBQUlBLE1BQU0sQ0FBQSxHQUFBLEVBQU1hLFFBQVEsQ0FBQSxHQUFBLEVBQU1GLEdBQUcsQ0FBQSxDQUFBLEVBQUlDLEdBQUcsQ0FBQSxFQUFBLENBQUk7TUFDaEosT0FBTztRQUFFRSxJQUFJO1FBQUVyRSxLQUFLO1FBQUVzRSxJQUFJLEVBQUVoRSxDQUFDLENBQUNnRSxJQUFJO1FBQUUvRCxLQUFLLEVBQUVELENBQUMsQ0FBQ0MsS0FBSztRQUFFYyxHQUFHLEVBQUVsQixJQUFJLENBQUNvQixLQUFLLENBQUVqQixDQUFDLENBQUNDLEtBQUssR0FBRzRDLEtBQUssR0FBSSxHQUFHO09BQUc7RUFDaEcsRUFBQSxDQUFDLENBQUM7SUFFRixvQkFDRTNCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxLQUFBLEVBQUE7RUFBSzhDLElBQUFBLEtBQUssRUFBRTtFQUFFQyxNQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUFFQyxNQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFQyxNQUFBQSxHQUFHLEVBQUUsTUFBTTtFQUFFQyxNQUFBQSxRQUFRLEVBQUUsTUFBTTtFQUFFQyxNQUFBQSxjQUFjLEVBQUU7RUFBUztLQUFFLGVBQzdHcEQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQTtFQUFLM0IsSUFBQUEsS0FBSyxFQUFFb0QsSUFBSztFQUFDbkQsSUFBQUEsTUFBTSxFQUFFbUQsSUFBSztFQUFDeEIsSUFBQUEsT0FBTyxFQUFFLENBQUEsSUFBQSxFQUFPd0IsSUFBSSxDQUFBLENBQUEsRUFBSUEsSUFBSSxDQUFBO0tBQUcsRUFDNURRLE1BQU0sQ0FBQ3JELEdBQUcsQ0FBQyxDQUFDZ0QsQ0FBQyxFQUFFeEMsQ0FBQyxrQkFDZlcsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQTtFQUFNWSxJQUFBQSxHQUFHLEVBQUV4QixDQUFFO01BQUNQLENBQUMsRUFBRStDLENBQUMsQ0FBQ2dCLElBQUs7TUFBQzVCLElBQUksRUFBRVksQ0FBQyxDQUFDckQsS0FBTTtNQUFDc0MsTUFBTSxFQUFFcEUsQ0FBQyxDQUFDQyxFQUFHO0VBQUNvRSxJQUFBQSxXQUFXLEVBQUM7S0FBRyxlQUNuRWYsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE9BQUEsRUFBQSxJQUFBLEVBQVE0QixDQUFDLENBQUNpQixJQUFJLEVBQUMsSUFBRSxFQUFDakIsQ0FBQyxDQUFDOUMsS0FBSyxFQUFDLElBQUUsRUFBQzhDLENBQUMsQ0FBQ2hDLEdBQUcsRUFBQyxJQUFTLENBQ3hDLENBQ1AsQ0FBQyxlQUNGRyxzQkFBQSxDQUFBQyxhQUFBLENBQUEsTUFBQSxFQUFBO0VBQU1YLElBQUFBLENBQUMsRUFBRWdDLEVBQUc7TUFBQy9CLENBQUMsRUFBRWdDLEVBQUUsR0FBRyxDQUFFO01BQUNOLElBQUksRUFBRXZFLENBQUMsQ0FBQ2MsSUFBSztFQUFDMEQsSUFBQUEsUUFBUSxFQUFDLElBQUk7RUFBQ21DLElBQUFBLFVBQVUsRUFBQyxNQUFNO0VBQUNsQyxJQUFBQSxVQUFVLEVBQUM7RUFBUSxHQUFBLEVBQUVRLEtBQVksQ0FBQyxlQUN4RzNCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxNQUFBLEVBQUE7RUFBTVgsSUFBQUEsQ0FBQyxFQUFFZ0MsRUFBRztNQUFDL0IsQ0FBQyxFQUFFZ0MsRUFBRSxHQUFHLEVBQUc7TUFBQ04sSUFBSSxFQUFFdkUsQ0FBQyxDQUFDZSxTQUFVO0VBQUN5RCxJQUFBQSxRQUFRLEVBQUMsSUFBSTtFQUFDQyxJQUFBQSxVQUFVLEVBQUM7RUFBUSxHQUFBLEVBQUMsT0FBVyxDQUN0RixDQUFDLGVBQ05uQixzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRUMsTUFBQUEsT0FBTyxFQUFFLE1BQU07RUFBRU0sTUFBQUEsYUFBYSxFQUFFLFFBQVE7RUFBRUosTUFBQUEsR0FBRyxFQUFFO0VBQU07S0FBRSxFQUNsRWhCLE1BQU0sQ0FBQ3JELEdBQUcsQ0FBQyxDQUFDZ0QsQ0FBQyxFQUFFeEMsQ0FBQyxrQkFDZlcsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQTtFQUFLWSxJQUFBQSxHQUFHLEVBQUV4QixDQUFFO0VBQUMwRCxJQUFBQSxLQUFLLEVBQUU7RUFBRUMsTUFBQUEsT0FBTyxFQUFFLE1BQU07RUFBRUMsTUFBQUEsVUFBVSxFQUFFLFFBQVE7RUFBRUMsTUFBQUEsR0FBRyxFQUFFLEtBQUs7RUFBRWhDLE1BQUFBLFFBQVEsRUFBRTtFQUFPO0tBQUUsZUFDMUZsQixzQkFBQSxDQUFBQyxhQUFBLENBQUEsTUFBQSxFQUFBO0VBQU04QyxJQUFBQSxLQUFLLEVBQUU7RUFBRXpFLE1BQUFBLEtBQUssRUFBRSxFQUFFO0VBQUVDLE1BQUFBLE1BQU0sRUFBRSxFQUFFO0VBQUVSLE1BQUFBLFlBQVksRUFBRSxLQUFLO1FBQUVELGVBQWUsRUFBRStELENBQUMsQ0FBQ3JELEtBQUs7RUFBRXdFLE1BQUFBLE9BQU8sRUFBRSxjQUFjO0VBQUVPLE1BQUFBLFVBQVUsRUFBRTtFQUFFO0VBQUUsR0FBRSxDQUFDLGVBQ2pJdkQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQTtFQUFNOEMsSUFBQUEsS0FBSyxFQUFFO1FBQUV2RSxLQUFLLEVBQUU5QixDQUFDLENBQUNjO0VBQUs7RUFBRSxHQUFBLEVBQUVxRSxDQUFDLENBQUNpQixJQUFXLENBQUMsZUFDL0M5QyxzQkFBQSxDQUFBQyxhQUFBLENBQUEsTUFBQSxFQUFBO0VBQU04QyxJQUFBQSxLQUFLLEVBQUU7UUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2dCLE9BQU87RUFBRThGLE1BQUFBLFVBQVUsRUFBRTtFQUFPO0VBQUUsR0FBQSxFQUFFM0IsQ0FBQyxDQUFDOUMsS0FBSyxFQUFDLElBQUUsRUFBQzhDLENBQUMsQ0FBQ2hDLEdBQUcsRUFBQyxJQUFRLENBQzlFLENBQ04sQ0FDRSxDQUNGLENBQUM7RUFFVixDQUFDOztFQUVEO0VBQ0EsTUFBTTRELFFBQVEsR0FBR0EsQ0FBQztJQUFFQyxJQUFJO0lBQUU1RCxLQUFLO0lBQUVmLEtBQUs7SUFBRTRFLEtBQUs7SUFBRUMsVUFBVTtFQUFFL0YsRUFBQUE7RUFBWSxDQUFDLGtCQUN0RW1DLHNCQUFBLENBQUFDLGFBQUEsQ0FBQzRELGdCQUFHLEVBQUE7RUFBQ2QsRUFBQUEsS0FBSyxFQUFFO01BQUUsR0FBR25GLFNBQVMsQ0FBQ0MsV0FBVyxDQUFDO0VBQUVpRyxJQUFBQSxJQUFJLEVBQUUsR0FBRztFQUFFQyxJQUFBQSxRQUFRLEVBQUU7S0FBVTtJQUN0RUMsWUFBWSxFQUFFQyxDQUFDLElBQUk7TUFBRUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNvQixXQUFXLEdBQUd0RyxXQUFXLElBQUluQixDQUFDLENBQUNLLFdBQVc7RUFBRWtILElBQUFBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDcUIsU0FBUyxHQUFHLGtCQUFrQjtFQUFFSCxJQUFBQSxDQUFDLENBQUNDLGFBQWEsQ0FBQ25CLEtBQUssQ0FBQ3NCLFNBQVMsR0FBRyxDQUFBLDBCQUFBLENBQTRCO0lBQUUsQ0FBRTtJQUMvTUMsWUFBWSxFQUFFTCxDQUFDLElBQUk7TUFBRUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNvQixXQUFXLEdBQUd6SCxDQUFDLENBQUNJLE1BQU07RUFBRW1ILElBQUFBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDd0IsZUFBZSxHQUFHMUcsV0FBVztFQUFFb0csSUFBQUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNxQixTQUFTLEdBQUcsZUFBZTtFQUFFSCxJQUFBQSxDQUFDLENBQUNDLGFBQWEsQ0FBQ25CLEtBQUssQ0FBQ3NCLFNBQVMsR0FBRyxNQUFNO0VBQUUsRUFBQTtFQUFFLENBQUEsZUFFdk5yRSxzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxFQUFBQSxLQUFLLEVBQUU7RUFBRUMsSUFBQUEsT0FBTyxFQUFFLE1BQU07RUFBRUMsSUFBQUEsVUFBVSxFQUFFLFFBQVE7RUFBRUMsSUFBQUEsR0FBRyxFQUFFLEtBQUs7RUFBRXNCLElBQUFBLFlBQVksRUFBRTtFQUFPO0VBQUUsQ0FBQSxlQUN0RnhFLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3dFLGlCQUFJLEVBQUE7RUFBQ2YsRUFBQUEsSUFBSSxFQUFFQSxJQUFLO0VBQUNsRixFQUFBQSxLQUFLLEVBQUVYO0VBQVksQ0FBRSxDQUFDLGVBQ3hDbUMsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDeUUsaUJBQUksRUFBQTtFQUFDM0IsRUFBQUEsS0FBSyxFQUFFO01BQUV2RSxLQUFLLEVBQUU5QixDQUFDLENBQUNlLFNBQVM7RUFBRXlELElBQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUVtQyxJQUFBQSxVQUFVLEVBQUUsR0FBRztFQUFFc0IsSUFBQUEsYUFBYSxFQUFFLFdBQVc7RUFBRUMsSUFBQUEsYUFBYSxFQUFFO0VBQVM7RUFBRSxDQUFBLEVBQUU5RSxLQUFZLENBQ3ZJLENBQUMsZUFDTkUsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDNEUsZUFBRSxFQUFBO0VBQUM5QixFQUFBQSxLQUFLLEVBQUU7TUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2MsSUFBSTtFQUFFc0gsSUFBQUEsTUFBTSxFQUFFLFdBQVc7RUFBRTVELElBQUFBLFFBQVEsRUFBRTtFQUFTO0VBQUUsQ0FBQSxFQUFFbkMsS0FBVSxDQUFDLEVBQ2xGNEUsS0FBSyxLQUFLb0IsU0FBUyxpQkFDbEIvRSxzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxFQUFBQSxLQUFLLEVBQUU7RUFBRUMsSUFBQUEsT0FBTyxFQUFFLE1BQU07RUFBRUMsSUFBQUEsVUFBVSxFQUFFLFFBQVE7RUFBRUMsSUFBQUEsR0FBRyxFQUFFO0VBQU07RUFBRSxDQUFBLGVBQ2hFbEQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDd0UsaUJBQUksRUFBQTtFQUFDZixFQUFBQSxJQUFJLEVBQUMsU0FBUztFQUFDaEMsRUFBQUEsSUFBSSxFQUFFLEVBQUc7SUFBQ2xELEtBQUssRUFBRTlCLENBQUMsQ0FBQ1U7RUFBTSxDQUFFLENBQUMsZUFDakQ0QyxzQkFBQSxDQUFBQyxhQUFBLENBQUN5RSxpQkFBSSxFQUFBO0VBQUMzQixFQUFBQSxLQUFLLEVBQUU7TUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ1UsS0FBSztFQUFFOEQsSUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRW1DLElBQUFBLFVBQVUsRUFBRTtFQUFJO0VBQUUsQ0FBQSxFQUFDLEdBQUMsRUFBQ00sS0FBSyxFQUFDLEdBQUMsRUFBQ0MsVUFBVSxJQUFJLFlBQW1CLENBQzVHLENBRUosQ0FDTjs7RUFFRDtFQUNBLE1BQU1vQixVQUFVLEdBQUdBLENBQUM7SUFBRXRCLElBQUk7SUFBRTVELEtBQUs7SUFBRW1GLEtBQUs7SUFBRXBILFdBQVc7RUFBRXFILEVBQUFBO0VBQVcsQ0FBQyxrQkFDakVsRixzQkFBQSxDQUFBQyxhQUFBLENBQUEsR0FBQSxFQUFBO0lBQUdrRixJQUFJLEVBQUUsQ0FBQSxpQkFBQSxFQUFvQkQsVUFBVSxDQUFBLENBQUc7RUFBQ25DLEVBQUFBLEtBQUssRUFBRTtFQUFFcUMsSUFBQUEsY0FBYyxFQUFFLE1BQU07RUFBRXRCLElBQUFBLElBQUksRUFBRSxHQUFHO0VBQUVDLElBQUFBLFFBQVEsRUFBRTtFQUFRO0VBQUUsQ0FBQSxlQUN6Ry9ELHNCQUFBLENBQUFDLGFBQUEsQ0FBQzRELGdCQUFHLEVBQUE7RUFBQ2QsRUFBQUEsS0FBSyxFQUFFO01BQUUsR0FBR25GLFNBQVMsQ0FBQ0MsV0FBVyxDQUFDO0VBQUVtRixJQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUFFQyxJQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFQyxJQUFBQSxHQUFHLEVBQUU7S0FBUztJQUM1RmMsWUFBWSxFQUFFQyxDQUFDLElBQUk7RUFBRUEsSUFBQUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNvQixXQUFXLEdBQUd0RyxXQUFXO0VBQUVvRyxJQUFBQSxDQUFDLENBQUNDLGFBQWEsQ0FBQ25CLEtBQUssQ0FBQ3FCLFNBQVMsR0FBRyxrQkFBa0I7RUFBRUgsSUFBQUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNzQixTQUFTLEdBQUcsQ0FBQSwwQkFBQSxDQUE0QjtJQUFFLENBQUU7SUFDOUxDLFlBQVksRUFBRUwsQ0FBQyxJQUFJO01BQUVBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDb0IsV0FBVyxHQUFHekgsQ0FBQyxDQUFDSSxNQUFNO0VBQUVtSCxJQUFBQSxDQUFDLENBQUNDLGFBQWEsQ0FBQ25CLEtBQUssQ0FBQ3dCLGVBQWUsR0FBRzFHLFdBQVc7RUFBRW9HLElBQUFBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDcUIsU0FBUyxHQUFHLGVBQWU7RUFBRUgsSUFBQUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNzQixTQUFTLEdBQUcsTUFBTTtFQUFFLEVBQUE7RUFBRSxDQUFBLGVBRXZOckUsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQTtFQUFLOEMsRUFBQUEsS0FBSyxFQUFFO0VBQUV6RSxJQUFBQSxLQUFLLEVBQUUsRUFBRTtFQUFFQyxJQUFBQSxNQUFNLEVBQUUsRUFBRTtFQUFFUixJQUFBQSxZQUFZLEVBQUUsTUFBTTtNQUFFRCxlQUFlLEVBQUUsQ0FBQSxFQUFHRCxXQUFXLENBQUEsRUFBQSxDQUFJO0VBQUVtRixJQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUFFQyxJQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFRyxJQUFBQSxjQUFjLEVBQUUsUUFBUTtFQUFFRyxJQUFBQSxVQUFVLEVBQUU7RUFBRTtFQUFFLENBQUEsZUFDL0t2RCxzQkFBQSxDQUFBQyxhQUFBLENBQUN3RSxpQkFBSSxFQUFBO0VBQUNmLEVBQUFBLElBQUksRUFBRUEsSUFBSztFQUFDaEMsRUFBQUEsSUFBSSxFQUFFLEVBQUc7RUFBQ2xELEVBQUFBLEtBQUssRUFBRVg7RUFBWSxDQUFFLENBQzlDLENBQUMsZUFDTm1DLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxLQUFBLEVBQUEsSUFBQSxlQUNFRCxzQkFBQSxDQUFBQyxhQUFBLENBQUN5RSxpQkFBSSxFQUFBO0VBQUMzQixFQUFBQSxLQUFLLEVBQUU7TUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2UsU0FBUztFQUFFeUQsSUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRW1DLElBQUFBLFVBQVUsRUFBRSxHQUFHO0VBQUVzQixJQUFBQSxhQUFhLEVBQUUsV0FBVztFQUFFQyxJQUFBQSxhQUFhLEVBQUU7RUFBUztFQUFFLENBQUEsRUFBRTlFLEtBQVksQ0FBQyxlQUMzSUUsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDb0YsZUFBRSxFQUFBO0VBQUN0QyxFQUFBQSxLQUFLLEVBQUU7TUFBRXZFLEtBQUssRUFBRXlHLEtBQUssR0FBRyxDQUFDLEdBQUdwSCxXQUFXLEdBQUduQixDQUFDLENBQUNnQixPQUFPO0VBQUVvSCxJQUFBQSxNQUFNLEVBQUU7RUFBWTtFQUFFLENBQUEsRUFBRUcsS0FBVSxDQUN4RixDQUFDLGVBQ05qRixzQkFBQSxDQUFBQyxhQUFBLENBQUN3RSxpQkFBSSxFQUFBO0VBQUNmLEVBQUFBLElBQUksRUFBQyxjQUFjO0lBQUNsRixLQUFLLEVBQUU5QixDQUFDLENBQUNnQixPQUFRO0VBQUNxRixFQUFBQSxLQUFLLEVBQUU7RUFBRVMsSUFBQUEsVUFBVSxFQUFFO0VBQU87RUFBRSxDQUFFLENBQ3pFLENBQ0osQ0FDSjs7RUFFRDtFQUNBLE1BQU04QixPQUFPLEdBQUl4RyxDQUFDLElBQUs7RUFDckIsRUFBQSxJQUFJLENBQUNBLENBQUMsRUFBRSxPQUFPLEdBQUc7RUFDbEIsRUFBQSxNQUFNeUcsRUFBRSxHQUFHLElBQUlDLElBQUksQ0FBQzFHLENBQUMsQ0FBQztFQUN0QixFQUFBLE9BQU95RyxFQUFFLENBQUNFLGtCQUFrQixDQUFDLE9BQU8sRUFBRTtFQUFFQyxJQUFBQSxLQUFLLEVBQUUsT0FBTztFQUFFQyxJQUFBQSxHQUFHLEVBQUUsU0FBUztFQUFFQyxJQUFBQSxJQUFJLEVBQUU7RUFBVSxHQUFDLENBQUM7RUFDNUYsQ0FBQzs7RUFFRDtFQUNBLE1BQU1DLFdBQVcsR0FBSWhFLENBQUMsSUFBSztFQUN6QixFQUFBLElBQUksQ0FBQ0EsQ0FBQyxFQUFFLE9BQU9uRixDQUFDLENBQUNnQixPQUFPO0VBQ3hCLEVBQUEsTUFBTW9JLEtBQUssR0FBR2pFLENBQUMsQ0FBQ2tFLFdBQVcsRUFBRTtJQUM3QixJQUFJRCxLQUFLLEtBQUssVUFBVSxJQUFJQSxLQUFLLEtBQUssUUFBUSxFQUFFLE9BQU9wSixDQUFDLENBQUNVLEtBQUs7RUFDOUQsRUFBQSxJQUFJMEksS0FBSyxLQUFLLFNBQVMsRUFBRSxPQUFPcEosQ0FBQyxDQUFDYSxNQUFNO0VBQ3hDLEVBQUEsSUFBSXVJLEtBQUssS0FBSyxVQUFVLEVBQUUsT0FBT3BKLENBQUMsQ0FBQ1ksR0FBRztJQUN0QyxPQUFPWixDQUFDLENBQUNlLFNBQVM7RUFDcEIsQ0FBQzs7RUFFRDtFQUNBO0VBQ0E7RUFDQSxNQUFNdUksZUFBZSxHQUFHQSxNQUFNO0lBQzVCLE1BQU0sQ0FBQzNILElBQUksRUFBRTRILE9BQU8sQ0FBQyxHQUFHQyxjQUFRLENBQUMsSUFBSSxDQUFDO0lBQ3RDLE1BQU0sQ0FBQ0MsT0FBTyxFQUFFQyxVQUFVLENBQUMsR0FBR0YsY0FBUSxDQUFDLElBQUksQ0FBQztJQUM1QyxNQUFNLENBQUNHLEtBQUssRUFBRUMsUUFBUSxDQUFDLEdBQUdKLGNBQVEsQ0FBQyxJQUFJLENBQUM7RUFFeENLLEVBQUFBLGVBQVMsQ0FBQyxNQUFNO01BQ2QvSixLQUFHLENBQUNnSyxZQUFZLEVBQUUsQ0FDZkMsSUFBSSxDQUFFQyxRQUFRLElBQUs7RUFDbEJULE1BQUFBLE9BQU8sQ0FBQ1MsUUFBUSxDQUFDckksSUFBSSxJQUFJLEVBQUUsQ0FBQztRQUM1QitILFVBQVUsQ0FBQyxLQUFLLENBQUM7RUFDbkIsSUFBQSxDQUFDLENBQUMsQ0FDRE8sS0FBSyxDQUFFQyxVQUFVLElBQUs7RUFDckJDLE1BQUFBLE9BQU8sQ0FBQ1IsS0FBSyxDQUFDLHdCQUF3QixFQUFFTyxVQUFVLENBQUM7UUFDbkROLFFBQVEsQ0FBQyxnQ0FBZ0MsQ0FBQztRQUMxQ0YsVUFBVSxDQUFDLEtBQUssQ0FBQztFQUNuQixJQUFBLENBQUMsQ0FBQztJQUNOLENBQUMsRUFBRSxFQUFFLENBQUM7RUFFTixFQUFBLElBQUlELE9BQU8sRUFBRTtNQUNYLG9CQUNFbkcsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQTtFQUFLOEMsTUFBQUEsS0FBSyxFQUFFO0VBQUUrRCxRQUFBQSxTQUFTLEVBQUUsT0FBTztVQUFFaEosZUFBZSxFQUFFcEIsQ0FBQyxDQUFDQyxFQUFFO0VBQUVxRyxRQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUFFQyxRQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFRyxRQUFBQSxjQUFjLEVBQUU7RUFBUztPQUFFLGVBQ3pIcEQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQTtFQUFLOEMsTUFBQUEsS0FBSyxFQUFFO0VBQUVnRSxRQUFBQSxTQUFTLEVBQUU7RUFBUztPQUFFLGVBQ2xDL0csc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQTtFQUFLOEMsTUFBQUEsS0FBSyxFQUFFO0VBQUV6RSxRQUFBQSxLQUFLLEVBQUUsRUFBRTtFQUFFQyxRQUFBQSxNQUFNLEVBQUUsRUFBRTtFQUFFekIsUUFBQUEsTUFBTSxFQUFFLENBQUEsVUFBQSxFQUFhSixDQUFDLENBQUNJLE1BQU0sQ0FBQSxDQUFFO1VBQUVrSyxjQUFjLEVBQUV0SyxDQUFDLENBQUNNLElBQUk7RUFBRWUsUUFBQUEsWUFBWSxFQUFFLEtBQUs7RUFBRWtKLFFBQUFBLFNBQVMsRUFBRSx5QkFBeUI7RUFBRW5DLFFBQUFBLE1BQU0sRUFBRTtFQUFjO0VBQUUsS0FBRSxDQUFDLGVBQ3BMOUUsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDeUUsaUJBQUksRUFBQTtFQUFDM0IsTUFBQUEsS0FBSyxFQUFFO1VBQUV2RSxLQUFLLEVBQUU5QixDQUFDLENBQUNlO0VBQVU7T0FBRSxFQUFDLHNCQUEwQixDQUFDLGVBQ2hFdUMsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE9BQUEsRUFBQSxJQUFBLEVBQVEsQ0FBQSxxREFBQSxDQUErRCxDQUNwRSxDQUNGLENBQUM7RUFFVixFQUFBO0VBRUEsRUFBQSxJQUFJb0csS0FBSyxFQUFFO01BQ1Qsb0JBQ0VyRyxzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxNQUFBQSxLQUFLLEVBQUU7RUFBRStELFFBQUFBLFNBQVMsRUFBRSxPQUFPO1VBQUVoSixlQUFlLEVBQUVwQixDQUFDLENBQUNDLEVBQUU7RUFBRXFHLFFBQUFBLE9BQU8sRUFBRSxNQUFNO0VBQUVDLFFBQUFBLFVBQVUsRUFBRSxRQUFRO0VBQUVHLFFBQUFBLGNBQWMsRUFBRTtFQUFTO0VBQUUsS0FBQSxlQUN6SHBELHNCQUFBLENBQUFDLGFBQUEsQ0FBQzRELGdCQUFHLEVBQUE7RUFBQ2QsTUFBQUEsS0FBSyxFQUFFO0VBQUUsUUFBQSxHQUFHbkYsU0FBUyxDQUFDbEIsQ0FBQyxDQUFDWSxHQUFHLENBQUM7RUFBRTRKLFFBQUFBLFFBQVEsRUFBRSxHQUFHO0VBQUVILFFBQUFBLFNBQVMsRUFBRTtFQUFTO0VBQUUsS0FBQSxlQUN0RS9HLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3dFLGlCQUFJLEVBQUE7RUFBQ2YsTUFBQUEsSUFBSSxFQUFDLGVBQWU7RUFBQ2hDLE1BQUFBLElBQUksRUFBRSxFQUFHO1FBQUNsRCxLQUFLLEVBQUU5QixDQUFDLENBQUNZO0VBQUksS0FBRSxDQUFDLGVBQ3JEMEMsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDb0YsZUFBRSxFQUFBO0VBQUN0QyxNQUFBQSxLQUFLLEVBQUU7VUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ1ksR0FBRztFQUFFd0gsUUFBQUEsTUFBTSxFQUFFO0VBQWE7RUFBRSxLQUFBLEVBQUV1QixLQUFVLENBQUMsZUFDL0RyRyxzQkFBQSxDQUFBQyxhQUFBLENBQUN5RSxpQkFBSSxFQUFBO0VBQUMzQixNQUFBQSxLQUFLLEVBQUU7VUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2U7RUFBVTtPQUFFLEVBQUMsb0NBQXdDLENBQzFFLENBQ0YsQ0FBQztFQUVWLEVBQUE7RUFFQSxFQUFBLE1BQU0wSixLQUFLLEdBQUc5SSxJQUFJLEVBQUU4SSxLQUFLLElBQUksRUFBRTtFQUMvQixFQUFBLE1BQU1DLGNBQWMsR0FBRy9JLElBQUksRUFBRStJLGNBQWMsSUFBSSxFQUFFO0VBQ2pELEVBQUEsTUFBTUMsY0FBYyxHQUFHaEosSUFBSSxFQUFFZ0osY0FBYyxJQUFJLEVBQUU7RUFDakQsRUFBQSxNQUFNQyxjQUFjLEdBQUdqSixJQUFJLEVBQUVpSixjQUFjLElBQUksRUFBRTtFQUNqRCxFQUFBLE1BQU1DLFdBQVcsR0FBR2xKLElBQUksRUFBRWtKLFdBQVcsSUFBSSxFQUFFO0VBQzNDLEVBQUEsTUFBTUMsVUFBVSxHQUFHbkosSUFBSSxFQUFFbUosVUFBVSxJQUFJLEVBQUU7O0VBRXpDO0VBQ0EsRUFBQSxNQUFNQyxlQUFlLEdBQUdILGNBQWMsQ0FBQ3pJLEdBQUcsQ0FBQ0MsQ0FBQyxLQUFLO01BQUVnQixLQUFLLEVBQUVoQixDQUFDLENBQUM0SSxJQUFJO01BQUUzSSxLQUFLLEVBQUVELENBQUMsQ0FBQzZJO0VBQU0sR0FBQyxDQUFDLENBQUM7RUFFcEYsRUFBQSxNQUFNQyxHQUFHLEdBQUcsSUFBSXBDLElBQUksRUFBRTtJQUN0QixNQUFNcUMsUUFBUSxHQUFHRCxHQUFHLENBQUNFLFFBQVEsRUFBRSxHQUFHLEVBQUUsR0FBRyxjQUFjLEdBQUdGLEdBQUcsQ0FBQ0UsUUFBUSxFQUFFLEdBQUcsRUFBRSxHQUFHLGdCQUFnQixHQUFHLGNBQWM7SUFFL0csb0JBQ0U5SCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxJQUFBQSxLQUFLLEVBQUU7UUFBRWpGLGVBQWUsRUFBRXBCLENBQUMsQ0FBQ0MsRUFBRTtFQUFFbUssTUFBQUEsU0FBUyxFQUFFLE9BQU87RUFBRTdJLE1BQUFBLE9BQU8sRUFBRSxXQUFXO0VBQUU4SixNQUFBQSxVQUFVLEVBQUU7RUFBd0I7S0FBRSxlQUduSC9ILHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxLQUFBLEVBQUE7RUFBSzhDLElBQUFBLEtBQUssRUFBRTtFQUFFQyxNQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUFFRyxNQUFBQSxRQUFRLEVBQUUsTUFBTTtFQUFFQyxNQUFBQSxjQUFjLEVBQUUsZUFBZTtFQUFFSCxNQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFQyxNQUFBQSxHQUFHLEVBQUUsTUFBTTtFQUFFOEUsTUFBQUEsYUFBYSxFQUFFLE1BQU07RUFBRUMsTUFBQUEsWUFBWSxFQUFFLENBQUEsVUFBQSxFQUFhdkwsQ0FBQyxDQUFDSSxNQUFNLENBQUEsQ0FBRTtFQUFFMEgsTUFBQUEsWUFBWSxFQUFFO0VBQU87RUFBRSxHQUFBLGVBQ3hNeEUsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQSxJQUFBLGVBQ0VELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxHQUFBLEVBQUE7RUFBR2tGLElBQUFBLElBQUksRUFBQyxRQUFRO0VBQUNwQyxJQUFBQSxLQUFLLEVBQUU7RUFBRXFDLE1BQUFBLGNBQWMsRUFBRSxNQUFNO0VBQUVwQyxNQUFBQSxPQUFPLEVBQUUsYUFBYTtFQUFFQyxNQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFOUUsTUFBQUEsTUFBTSxFQUFFO0VBQVU7RUFBRSxHQUFBLGVBQ2xINkIsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDNEUsZUFBRSxFQUFBO0VBQUM5QixJQUFBQSxLQUFLLEVBQUU7RUFBRStCLE1BQUFBLE1BQU0sRUFBRSxDQUFDO0VBQUU5QixNQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUFFQyxNQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFQyxNQUFBQSxHQUFHLEVBQUUsS0FBSztFQUFFNkUsTUFBQUEsVUFBVSxFQUFFO0VBQXdCO0tBQUUsZUFDL0cvSCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsTUFBQSxFQUFBO0VBQU04QyxJQUFBQSxLQUFLLEVBQUU7UUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ00sSUFBSTtFQUFFa0wsTUFBQUEsVUFBVSxFQUFFLENBQUEsU0FBQSxFQUFZeEwsQ0FBQyxDQUFDUSxRQUFRLENBQUEsQ0FBRTtFQUFFbUcsTUFBQUEsVUFBVSxFQUFFO0VBQUk7RUFBRSxHQUFBLEVBQUMsS0FBUyxDQUFDLGVBQ2pHckQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQTtFQUFNOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUV2RSxNQUFBQSxLQUFLLEVBQUUsU0FBUztFQUFFMEosTUFBQUEsVUFBVSxFQUFFLG1DQUFtQztFQUFFN0UsTUFBQUEsVUFBVSxFQUFFO0VBQUk7RUFBRSxHQUFBLEVBQUMsTUFBVSxDQUFDLGVBQ2hIckQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQTtFQUFNOEMsSUFBQUEsS0FBSyxFQUFFO1FBQUV2RSxLQUFLLEVBQUU5QixDQUFDLENBQUNnQixPQUFPO0VBQUV3RCxNQUFBQSxRQUFRLEVBQUUsT0FBTztFQUFFbUMsTUFBQUEsVUFBVSxFQUFFLEdBQUc7RUFBRUcsTUFBQUEsVUFBVSxFQUFFLE1BQU07UUFBRTJFLFVBQVUsRUFBRXpMLENBQUMsQ0FBQ0csVUFBVTtFQUFFb0IsTUFBQUEsT0FBTyxFQUFFLFVBQVU7RUFBRUYsTUFBQUEsWUFBWSxFQUFFLEtBQUs7RUFBRWpCLE1BQUFBLE1BQU0sRUFBRSxDQUFBLFVBQUEsRUFBYUosQ0FBQyxDQUFDSSxNQUFNLENBQUEsQ0FBRTtFQUFFaUwsTUFBQUEsVUFBVSxFQUFFO0VBQXdCO0tBQUUsRUFBQyxpQkFBcUIsQ0FDeFAsQ0FDSCxDQUFDLGVBQ0ovSCxzQkFBQSxDQUFBQyxhQUFBLENBQUN5RSxpQkFBSSxFQUFBO0VBQUMzQixJQUFBQSxLQUFLLEVBQUU7UUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2UsU0FBUztFQUFFMkssTUFBQUEsU0FBUyxFQUFFLEtBQUs7RUFBRUwsTUFBQUEsVUFBVSxFQUFFO0VBQXdCO0tBQUUsRUFDeEZGLFFBQVEsRUFBQyxzQ0FBb0MsRUFBQ0QsR0FBRyxDQUFDbkMsa0JBQWtCLENBQUMsT0FBTyxFQUFFO0VBQUU0QyxJQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUFFM0MsSUFBQUEsS0FBSyxFQUFFLE1BQU07RUFBRUMsSUFBQUEsR0FBRyxFQUFFLFNBQVM7RUFBRUMsSUFBQUEsSUFBSSxFQUFFO0tBQVcsQ0FBQyxFQUFDLEdBQ2hKLENBQ0gsQ0FBQyxlQUdONUYsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQTtFQUFLOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUVDLE1BQUFBLE9BQU8sRUFBRSxNQUFNO0VBQUVHLE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUVGLE1BQUFBLFVBQVUsRUFBRSxRQUFRO0VBQUVDLE1BQUFBLEdBQUcsRUFBRTtFQUFPO0tBQUUsZUFDbkZsRCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsR0FBQSxFQUFBO0VBQ0VrRixJQUFBQSxJQUFJLEVBQUMsWUFBWTtFQUNqQnBDLElBQUFBLEtBQUssRUFBRTtFQUFFQyxNQUFBQSxPQUFPLEVBQUUsYUFBYTtFQUFFQyxNQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFQyxNQUFBQSxHQUFHLEVBQUUsS0FBSztRQUFFMUUsS0FBSyxFQUFFOUIsQ0FBQyxDQUFDTSxJQUFJO1FBQUVjLGVBQWUsRUFBRXBCLENBQUMsQ0FBQ08sT0FBTztFQUFFSCxNQUFBQSxNQUFNLEVBQUUsQ0FBQSxVQUFBLEVBQWFKLENBQUMsQ0FBQ00sSUFBSSxDQUFBLENBQUU7RUFBRWlCLE1BQUFBLE9BQU8sRUFBRSxVQUFVO0VBQUVGLE1BQUFBLFlBQVksRUFBRSxLQUFLO0VBQUVxSCxNQUFBQSxjQUFjLEVBQUUsTUFBTTtFQUFFL0IsTUFBQUEsVUFBVSxFQUFFLEdBQUc7RUFBRW5DLE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUVoRCxNQUFBQSxVQUFVLEVBQUUsVUFBVTtFQUFFNkosTUFBQUEsVUFBVSxFQUFFO09BQTBCO01BQ2hUL0QsWUFBWSxFQUFFQyxDQUFDLElBQUk7RUFBRUEsTUFBQUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNqRixlQUFlLEdBQUcsc0JBQXNCO01BQUUsQ0FBRTtNQUN2RndHLFlBQVksRUFBRUwsQ0FBQyxJQUFJO1FBQUVBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDakYsZUFBZSxHQUFHcEIsQ0FBQyxDQUFDTyxPQUFPO01BQUUsQ0FBRTtFQUMxRXFMLElBQUFBLEtBQUssRUFBQztFQUFzQixHQUFBLGVBRTVCdEksc0JBQUEsQ0FBQUMsYUFBQSxDQUFDd0UsaUJBQUksRUFBQTtFQUFDZixJQUFBQSxJQUFJLEVBQUMsV0FBVztFQUFDaEMsSUFBQUEsSUFBSSxFQUFFO0VBQUcsR0FBRSxDQUFDLEVBQUEsdUJBQ2xDLENBQUMsZUFFSjFCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxHQUFBLEVBQUE7RUFDRWtGLElBQUFBLElBQUksRUFBQyxnQkFBZ0I7RUFDckJwQyxJQUFBQSxLQUFLLEVBQUU7RUFBRUMsTUFBQUEsT0FBTyxFQUFFLGFBQWE7RUFBRUMsTUFBQUEsVUFBVSxFQUFFLFFBQVE7RUFBRUMsTUFBQUEsR0FBRyxFQUFFLEtBQUs7RUFBRTFFLE1BQUFBLEtBQUssRUFBRSxTQUFTO0VBQUVWLE1BQUFBLGVBQWUsRUFBRSxzQkFBc0I7RUFBRWhCLE1BQUFBLE1BQU0sRUFBRSwrQkFBK0I7RUFBRW1CLE1BQUFBLE9BQU8sRUFBRSxVQUFVO0VBQUVGLE1BQUFBLFlBQVksRUFBRSxLQUFLO0VBQUVxSCxNQUFBQSxjQUFjLEVBQUUsTUFBTTtFQUFFL0IsTUFBQUEsVUFBVSxFQUFFLEdBQUc7RUFBRW5DLE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUVoRCxNQUFBQSxVQUFVLEVBQUU7T0FBYTtNQUNyUzhGLFlBQVksRUFBRUMsQ0FBQyxJQUFJO0VBQUVBLE1BQUFBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDakYsZUFBZSxHQUFHLHNCQUFzQjtNQUFFLENBQUU7TUFDdkZ3RyxZQUFZLEVBQUVMLENBQUMsSUFBSTtFQUFFQSxNQUFBQSxDQUFDLENBQUNDLGFBQWEsQ0FBQ25CLEtBQUssQ0FBQ2pGLGVBQWUsR0FBRyxzQkFBc0I7TUFBRSxDQUFFO0VBQ3ZGd0ssSUFBQUEsS0FBSyxFQUFDO0VBQWtDLEdBQUEsZUFFeEN0SSxzQkFBQSxDQUFBQyxhQUFBLENBQUN3RSxpQkFBSSxFQUFBO0VBQUNmLElBQUFBLElBQUksRUFBQyxNQUFNO0VBQUNoQyxJQUFBQSxJQUFJLEVBQUU7RUFBRyxHQUFFLENBQUMsRUFBQSxVQUM3QixDQUFDLGVBRUoxQixzQkFBQSxDQUFBQyxhQUFBLENBQUEsR0FBQSxFQUFBO0VBQ0VrRixJQUFBQSxJQUFJLEVBQUMsZ0JBQWdCO0VBQ3JCcEMsSUFBQUEsS0FBSyxFQUFFO0VBQUVDLE1BQUFBLE9BQU8sRUFBRSxhQUFhO0VBQUVDLE1BQUFBLFVBQVUsRUFBRSxRQUFRO0VBQUVDLE1BQUFBLEdBQUcsRUFBRSxLQUFLO0VBQUUxRSxNQUFBQSxLQUFLLEVBQUUsU0FBUztFQUFFVixNQUFBQSxlQUFlLEVBQUUsdUJBQXVCO0VBQUVoQixNQUFBQSxNQUFNLEVBQUUsZ0NBQWdDO0VBQUVtQixNQUFBQSxPQUFPLEVBQUUsVUFBVTtFQUFFRixNQUFBQSxZQUFZLEVBQUUsS0FBSztFQUFFcUgsTUFBQUEsY0FBYyxFQUFFLE1BQU07RUFBRS9CLE1BQUFBLFVBQVUsRUFBRSxHQUFHO0VBQUVuQyxNQUFBQSxRQUFRLEVBQUUsTUFBTTtFQUFFaEQsTUFBQUEsVUFBVSxFQUFFO09BQWE7TUFDdlM4RixZQUFZLEVBQUVDLENBQUMsSUFBSTtFQUFFQSxNQUFBQSxDQUFDLENBQUNDLGFBQWEsQ0FBQ25CLEtBQUssQ0FBQ2pGLGVBQWUsR0FBRyx1QkFBdUI7TUFBRSxDQUFFO01BQ3hGd0csWUFBWSxFQUFFTCxDQUFDLElBQUk7RUFBRUEsTUFBQUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNqRixlQUFlLEdBQUcsdUJBQXVCO01BQUUsQ0FBRTtFQUN4RndLLElBQUFBLEtBQUssRUFBQztFQUFrQyxHQUFBLGVBRXhDdEksc0JBQUEsQ0FBQUMsYUFBQSxDQUFDd0UsaUJBQUksRUFBQTtFQUFDZixJQUFBQSxJQUFJLEVBQUMsWUFBWTtFQUFDaEMsSUFBQUEsSUFBSSxFQUFFO0VBQUcsR0FBRSxDQUFDLEVBQUEsVUFDbkMsQ0FBQyxlQUVKMUIsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEdBQUEsRUFBQTtFQUNFa0YsSUFBQUEsSUFBSSxFQUFDLFNBQVM7RUFDZG9ELElBQUFBLE1BQU0sRUFBQyxRQUFRO0VBQ2ZDLElBQUFBLEdBQUcsRUFBQyxxQkFBcUI7RUFDekJ6RixJQUFBQSxLQUFLLEVBQUU7RUFBRUMsTUFBQUEsT0FBTyxFQUFFLGFBQWE7RUFBRUMsTUFBQUEsVUFBVSxFQUFFLFFBQVE7RUFBRUMsTUFBQUEsR0FBRyxFQUFFLEtBQUs7RUFBRTFFLE1BQUFBLEtBQUssRUFBRSxTQUFTO0VBQUVWLE1BQUFBLGVBQWUsRUFBRSxzQkFBc0I7RUFBRWhCLE1BQUFBLE1BQU0sRUFBRSwrQkFBK0I7RUFBRW1CLE1BQUFBLE9BQU8sRUFBRSxVQUFVO0VBQUVGLE1BQUFBLFlBQVksRUFBRSxLQUFLO0VBQUVxSCxNQUFBQSxjQUFjLEVBQUUsTUFBTTtFQUFFL0IsTUFBQUEsVUFBVSxFQUFFLEdBQUc7RUFBRW5DLE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUVoRCxNQUFBQSxVQUFVLEVBQUU7T0FBYTtNQUNyUzhGLFlBQVksRUFBRUMsQ0FBQyxJQUFJO0VBQUVBLE1BQUFBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDakYsZUFBZSxHQUFHLHNCQUFzQjtNQUFFLENBQUU7TUFDdkZ3RyxZQUFZLEVBQUVMLENBQUMsSUFBSTtFQUFFQSxNQUFBQSxDQUFDLENBQUNDLGFBQWEsQ0FBQ25CLEtBQUssQ0FBQ2pGLGVBQWUsR0FBRyxzQkFBc0I7TUFBRSxDQUFFO0VBQ3ZGd0ssSUFBQUEsS0FBSyxFQUFDO0VBQWtDLEdBQUEsZUFFeEN0SSxzQkFBQSxDQUFBQyxhQUFBLENBQUN3RSxpQkFBSSxFQUFBO0VBQUNmLElBQUFBLElBQUksRUFBQyxVQUFVO0VBQUNoQyxJQUFBQSxJQUFJLEVBQUU7RUFBRyxHQUFFLENBQUMsRUFBQSxTQUNqQyxDQUFDLGVBRUoxQixzQkFBQSxDQUFBQyxhQUFBLENBQUEsR0FBQSxFQUFBO0VBQ0VrRixJQUFBQSxJQUFJLEVBQUMsY0FBYztFQUNuQnBDLElBQUFBLEtBQUssRUFBRTtFQUFFQyxNQUFBQSxPQUFPLEVBQUUsYUFBYTtFQUFFQyxNQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFQyxNQUFBQSxHQUFHLEVBQUUsS0FBSztFQUFFMUUsTUFBQUEsS0FBSyxFQUFFLFNBQVM7RUFBRVYsTUFBQUEsZUFBZSxFQUFFLHdCQUF3QjtFQUFFaEIsTUFBQUEsTUFBTSxFQUFFLGlDQUFpQztFQUFFbUIsTUFBQUEsT0FBTyxFQUFFLFVBQVU7RUFBRUYsTUFBQUEsWUFBWSxFQUFFLEtBQUs7RUFBRXFILE1BQUFBLGNBQWMsRUFBRSxNQUFNO0VBQUUvQixNQUFBQSxVQUFVLEVBQUUsR0FBRztFQUFFbkMsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRWhELE1BQUFBLFVBQVUsRUFBRTtPQUFhO01BQ3pTOEYsWUFBWSxFQUFFQyxDQUFDLElBQUk7RUFBRUEsTUFBQUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNqRixlQUFlLEdBQUcsd0JBQXdCO01BQUUsQ0FBRTtNQUN6RndHLFlBQVksRUFBRUwsQ0FBQyxJQUFJO0VBQUVBLE1BQUFBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDakYsZUFBZSxHQUFHLHdCQUF3QjtNQUFFLENBQUU7RUFDekZ3SyxJQUFBQSxLQUFLLEVBQUM7RUFBMEIsR0FBQSxlQUVoQ3RJLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3dFLGlCQUFJLEVBQUE7RUFBQ2YsSUFBQUEsSUFBSSxFQUFDLE9BQU87RUFBQ2hDLElBQUFBLElBQUksRUFBRTtFQUFHLEdBQUUsQ0FBQyxFQUFBLFFBQzlCLENBQUMsZUFFSjFCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxHQUFBLEVBQUE7RUFDRWtGLElBQUFBLElBQUksRUFBQyxPQUFPO0VBQ1pvRCxJQUFBQSxNQUFNLEVBQUMsUUFBUTtFQUNmQyxJQUFBQSxHQUFHLEVBQUMscUJBQXFCO0VBQ3pCekYsSUFBQUEsS0FBSyxFQUFFO0VBQUVDLE1BQUFBLE9BQU8sRUFBRSxhQUFhO0VBQUVDLE1BQUFBLFVBQVUsRUFBRSxRQUFRO0VBQUVDLE1BQUFBLEdBQUcsRUFBRSxLQUFLO0VBQUUxRSxNQUFBQSxLQUFLLEVBQUUsU0FBUztRQUFFVixlQUFlLEVBQUVwQixDQUFDLENBQUNHLFVBQVU7RUFBRUMsTUFBQUEsTUFBTSxFQUFFLENBQUEsVUFBQSxFQUFhSixDQUFDLENBQUNJLE1BQU0sQ0FBQSxDQUFFO0VBQUVtQixNQUFBQSxPQUFPLEVBQUUsVUFBVTtFQUFFRixNQUFBQSxZQUFZLEVBQUUsS0FBSztFQUFFcUgsTUFBQUEsY0FBYyxFQUFFLE1BQU07RUFBRS9CLE1BQUFBLFVBQVUsRUFBRSxHQUFHO0VBQUVuQyxNQUFBQSxRQUFRLEVBQUUsTUFBTTtFQUFFaEQsTUFBQUEsVUFBVSxFQUFFO09BQWE7TUFDblI4RixZQUFZLEVBQUVDLENBQUMsSUFBSTtRQUFFQSxDQUFDLENBQUNDLGFBQWEsQ0FBQ25CLEtBQUssQ0FBQ29CLFdBQVcsR0FBR3pILENBQUMsQ0FBQ00sSUFBSTtRQUFFaUgsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUN2RSxLQUFLLEdBQUc5QixDQUFDLENBQUNNLElBQUk7TUFBRSxDQUFFO01BQ3pHc0gsWUFBWSxFQUFFTCxDQUFDLElBQUk7UUFBRUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNvQixXQUFXLEdBQUd6SCxDQUFDLENBQUNJLE1BQU07RUFBRW1ILE1BQUFBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDdkUsS0FBSyxHQUFHLFNBQVM7TUFBRSxDQUFFO0VBQzlHOEosSUFBQUEsS0FBSyxFQUFDO0VBQXVCLEdBQUEsZUFFN0J0SSxzQkFBQSxDQUFBQyxhQUFBLENBQUN3RSxpQkFBSSxFQUFBO0VBQUNmLElBQUFBLElBQUksRUFBQyxPQUFPO0VBQUNoQyxJQUFBQSxJQUFJLEVBQUU7S0FBSyxDQUFDLGNBQzlCLENBQ0EsQ0FDRixDQUFDLGVBR04xQixzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRUMsTUFBQUEsT0FBTyxFQUFFLE1BQU07RUFBRUcsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRUQsTUFBQUEsR0FBRyxFQUFFLE1BQU07RUFBRXNCLE1BQUFBLFlBQVksRUFBRTtFQUFPO0VBQUUsR0FBQSxlQUNuRnhFLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3dELFFBQVEsRUFBQTtFQUFDQyxJQUFBQSxJQUFJLEVBQUMsT0FBTztFQUFDNUQsSUFBQUEsS0FBSyxFQUFDLGFBQWE7TUFBQ2YsS0FBSyxFQUFFLENBQUNvSSxLQUFLLENBQUNzQixVQUFVLElBQUksQ0FBQyxFQUFFQyxjQUFjLEVBQUc7TUFBQy9FLEtBQUssRUFBRXdELEtBQUssQ0FBQ3dCLGlCQUFrQjtNQUFDOUssV0FBVyxFQUFFbkIsQ0FBQyxDQUFDUztFQUFLLEdBQUUsQ0FBQyxlQUNuSjZDLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3dELFFBQVEsRUFBQTtFQUFDQyxJQUFBQSxJQUFJLEVBQUMsU0FBUztFQUFDNUQsSUFBQUEsS0FBSyxFQUFDLFlBQVk7TUFBQ2YsS0FBSyxFQUFFLENBQUNvSSxLQUFLLENBQUN5QixTQUFTLElBQUksQ0FBQyxFQUFFRixjQUFjLEVBQUc7TUFBQy9FLEtBQUssRUFBRXdELEtBQUssQ0FBQzBCLGdCQUFpQjtNQUFDaEwsV0FBVyxFQUFFbkIsQ0FBQyxDQUFDTTtFQUFLLEdBQUUsQ0FBQyxlQUNsSmdELHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3dELFFBQVEsRUFBQTtFQUFDQyxJQUFBQSxJQUFJLEVBQUMsVUFBVTtFQUFDNUQsSUFBQUEsS0FBSyxFQUFDLGlCQUFpQjtNQUFDZixLQUFLLEVBQUUsQ0FBQ29JLEtBQUssQ0FBQzJCLGNBQWMsSUFBSSxDQUFDLEVBQUVKLGNBQWMsRUFBRztNQUFDN0ssV0FBVyxFQUFFbkIsQ0FBQyxDQUFDVTtFQUFNLEdBQUUsQ0FBQyxlQUMvSDRDLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3dELFFBQVEsRUFBQTtFQUFDQyxJQUFBQSxJQUFJLEVBQUMsS0FBSztFQUFDNUQsSUFBQUEsS0FBSyxFQUFDLGFBQWE7TUFBQ2YsS0FBSyxFQUFFLENBQUNvSSxLQUFLLENBQUM0QixVQUFVLElBQUksQ0FBQyxFQUFFTCxjQUFjLEVBQUc7TUFBQzdLLFdBQVcsRUFBRW5CLENBQUMsQ0FBQ1c7RUFBTyxHQUFFLENBQy9HLENBQUMsZUFHTjJDLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxLQUFBLEVBQUE7RUFBSzhDLElBQUFBLEtBQUssRUFBRTtFQUFFQyxNQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUFFRyxNQUFBQSxRQUFRLEVBQUUsTUFBTTtFQUFFRCxNQUFBQSxHQUFHLEVBQUUsTUFBTTtFQUFFc0IsTUFBQUEsWUFBWSxFQUFFO0VBQU87RUFBRSxHQUFBLGVBQ25GeEUsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDK0UsVUFBVSxFQUFBO0VBQUN0QixJQUFBQSxJQUFJLEVBQUMsTUFBTTtFQUFDNUQsSUFBQUEsS0FBSyxFQUFDLGlCQUFpQjtFQUFDbUYsSUFBQUEsS0FBSyxFQUFFbUMsY0FBYyxDQUFDNEIsY0FBYyxJQUFJLENBQUU7TUFBQ25MLFdBQVcsRUFBRW5CLENBQUMsQ0FBQ1ksR0FBSTtFQUFDNEgsSUFBQUEsVUFBVSxFQUFDO0VBQVEsR0FBRSxDQUFDLGVBQ3JJbEYsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDK0UsVUFBVSxFQUFBO0VBQUN0QixJQUFBQSxJQUFJLEVBQUMsYUFBYTtFQUFDNUQsSUFBQUEsS0FBSyxFQUFDLG1CQUFtQjtFQUFDbUYsSUFBQUEsS0FBSyxFQUFFbUMsY0FBYyxDQUFDNkIsZ0JBQWdCLElBQUksQ0FBRTtNQUFDcEwsV0FBVyxFQUFFbkIsQ0FBQyxDQUFDYSxNQUFPO0VBQUMySCxJQUFBQSxVQUFVLEVBQUM7RUFBTSxHQUFFLENBQUMsZUFDakpsRixzQkFBQSxDQUFBQyxhQUFBLENBQUMrRSxVQUFVLEVBQUE7RUFBQ3RCLElBQUFBLElBQUksRUFBQyxZQUFZO0VBQUM1RCxJQUFBQSxLQUFLLEVBQUMsY0FBYztFQUFDbUYsSUFBQUEsS0FBSyxFQUFFbUMsY0FBYyxDQUFDOEIsV0FBVyxJQUFJLENBQUU7TUFBQ3JMLFdBQVcsRUFBRW5CLENBQUMsQ0FBQ1MsSUFBSztFQUFDK0gsSUFBQUEsVUFBVSxFQUFDO0VBQWUsR0FBRSxDQUN6SSxDQUFDLGVBR05sRixzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRUMsTUFBQUEsT0FBTyxFQUFFLE1BQU07RUFBRUcsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRUQsTUFBQUEsR0FBRyxFQUFFLE1BQU07RUFBRXNCLE1BQUFBLFlBQVksRUFBRTtFQUFPO0VBQUUsR0FBQSxlQUVuRnhFLHNCQUFBLENBQUFDLGFBQUEsQ0FBQzRELGdCQUFHLEVBQUE7RUFBQ2QsSUFBQUEsS0FBSyxFQUFFO1FBQUUsR0FBR25GLFNBQVMsRUFBRTtFQUFFa0csTUFBQUEsSUFBSSxFQUFFLEdBQUc7RUFBRUMsTUFBQUEsUUFBUSxFQUFFO0VBQVE7S0FBRSxlQUMzRC9ELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxLQUFBLEVBQUE7RUFBSzhDLElBQUFBLEtBQUssRUFBRTtFQUFFQyxNQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUFFQyxNQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFQyxNQUFBQSxHQUFHLEVBQUUsS0FBSztFQUFFc0IsTUFBQUEsWUFBWSxFQUFFO0VBQU87RUFBRSxHQUFBLGVBQ3RGeEUsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDd0UsaUJBQUksRUFBQTtFQUFDZixJQUFBQSxJQUFJLEVBQUMsVUFBVTtNQUFDbEYsS0FBSyxFQUFFOUIsQ0FBQyxDQUFDTTtFQUFLLEdBQUUsQ0FBQyxlQUN2Q2dELHNCQUFBLENBQUFDLGFBQUEsQ0FBQ29GLGVBQUUsRUFBQTtFQUFDdEMsSUFBQUEsS0FBSyxFQUFFO1FBQUV2RSxLQUFLLEVBQUU5QixDQUFDLENBQUNjLElBQUk7RUFBRXNILE1BQUFBLE1BQU0sRUFBRTtFQUFFO0VBQUUsR0FBQSxFQUFDLGFBQWUsQ0FBQyxlQUN6RDlFLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ2tKLGtCQUFLLEVBQUE7RUFBQ3BHLElBQUFBLEtBQUssRUFBRTtFQUFFUyxNQUFBQSxVQUFVLEVBQUUsS0FBSztRQUFFMUYsZUFBZSxFQUFFcEIsQ0FBQyxDQUFDTyxPQUFPO1FBQUV1QixLQUFLLEVBQUU5QixDQUFDLENBQUNNLElBQUk7RUFBRUYsTUFBQUEsTUFBTSxFQUFFO0VBQU87RUFBRSxHQUFBLEVBQUMsU0FBYyxDQUMzRyxDQUFDLEVBQ0wySyxlQUFlLENBQUNoSixNQUFNLEdBQUcsQ0FBQyxnQkFDekJ1QixzQkFBQSxDQUFBQyxhQUFBLENBQUM3QixTQUFTLEVBQUE7RUFBQ0MsSUFBQUEsSUFBSSxFQUFFb0osZUFBZ0I7TUFBQ2pKLEtBQUssRUFBRTlCLENBQUMsQ0FBQ00sSUFBSztFQUFDc0IsSUFBQUEsS0FBSyxFQUFFLEdBQUk7RUFBQ0MsSUFBQUEsTUFBTSxFQUFFO0VBQUksR0FBRSxDQUFDLGdCQUU1RXlCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxLQUFBLEVBQUE7RUFBSzhDLElBQUFBLEtBQUssRUFBRTtFQUFFeEUsTUFBQUEsTUFBTSxFQUFFLEdBQUc7RUFBRXlFLE1BQUFBLE9BQU8sRUFBRSxNQUFNO0VBQUVDLE1BQUFBLFVBQVUsRUFBRSxRQUFRO0VBQUVHLE1BQUFBLGNBQWMsRUFBRTtFQUFTO0VBQUUsR0FBQSxlQUMzRnBELHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3lFLGlCQUFJLEVBQUE7RUFBQzNCLElBQUFBLEtBQUssRUFBRTtRQUFFdkUsS0FBSyxFQUFFOUIsQ0FBQyxDQUFDZ0I7RUFBUTtLQUFFLEVBQUMsc0NBQTBDLENBQzFFLENBRUosQ0FBQyxlQUdOc0Msc0JBQUEsQ0FBQUMsYUFBQSxDQUFDNEQsZ0JBQUcsRUFBQTtFQUFDZCxJQUFBQSxLQUFLLEVBQUU7UUFBRSxHQUFHbkYsU0FBUyxFQUFFO0VBQUVrRyxNQUFBQSxJQUFJLEVBQUUsR0FBRztFQUFFQyxNQUFBQSxRQUFRLEVBQUU7RUFBUTtLQUFFLGVBQzNEL0Qsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQTtFQUFLOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUVDLE1BQUFBLE9BQU8sRUFBRSxNQUFNO0VBQUVDLE1BQUFBLFVBQVUsRUFBRSxRQUFRO0VBQUVDLE1BQUFBLEdBQUcsRUFBRSxLQUFLO0VBQUVzQixNQUFBQSxZQUFZLEVBQUU7RUFBTztFQUFFLEdBQUEsZUFDdEZ4RSxzQkFBQSxDQUFBQyxhQUFBLENBQUN3RSxpQkFBSSxFQUFBO0VBQUNmLElBQUFBLElBQUksRUFBQyxVQUFVO01BQUNsRixLQUFLLEVBQUU5QixDQUFDLENBQUNTO0VBQUssR0FBRSxDQUFDLGVBQ3ZDNkMsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDb0YsZUFBRSxFQUFBO0VBQUN0QyxJQUFBQSxLQUFLLEVBQUU7UUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2MsSUFBSTtFQUFFc0gsTUFBQUEsTUFBTSxFQUFFO0VBQUU7RUFBRSxHQUFBLEVBQUMsa0JBQW9CLENBQzFELENBQUMsRUFDTHVDLGNBQWMsQ0FBQzVJLE1BQU0sR0FBRyxDQUFDLGdCQUN4QnVCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3dCLFVBQVUsRUFBQTtFQUFDcEQsSUFBQUEsSUFBSSxFQUFFZ0osY0FBZTtFQUFDM0YsSUFBQUEsSUFBSSxFQUFFO0VBQUksR0FBRSxDQUFDLGdCQUUvQzFCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxLQUFBLEVBQUE7RUFBSzhDLElBQUFBLEtBQUssRUFBRTtFQUFFeEUsTUFBQUEsTUFBTSxFQUFFLEdBQUc7RUFBRXlFLE1BQUFBLE9BQU8sRUFBRSxNQUFNO0VBQUVDLE1BQUFBLFVBQVUsRUFBRSxRQUFRO0VBQUVHLE1BQUFBLGNBQWMsRUFBRTtFQUFTO0VBQUUsR0FBQSxlQUMzRnBELHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3lFLGlCQUFJLEVBQUE7RUFBQzNCLElBQUFBLEtBQUssRUFBRTtRQUFFdkUsS0FBSyxFQUFFOUIsQ0FBQyxDQUFDZ0I7RUFBUTtLQUFFLEVBQUMsNkJBQWlDLENBQ2pFLENBRUosQ0FDRixDQUFDLGVBR05zQyxzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRUMsTUFBQUEsT0FBTyxFQUFFLE1BQU07RUFBRUcsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRUQsTUFBQUEsR0FBRyxFQUFFLE1BQU07RUFBRXNCLE1BQUFBLFlBQVksRUFBRTtFQUFPO0VBQUUsR0FBQSxlQUVuRnhFLHNCQUFBLENBQUFDLGFBQUEsQ0FBQzRELGdCQUFHLEVBQUE7RUFBQ2QsSUFBQUEsS0FBSyxFQUFFO1FBQUUsR0FBR25GLFNBQVMsRUFBRTtFQUFFa0csTUFBQUEsSUFBSSxFQUFFLEdBQUc7RUFBRUMsTUFBQUEsUUFBUSxFQUFFO0VBQVE7S0FBRSxlQUMzRC9ELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxLQUFBLEVBQUE7RUFBSzhDLElBQUFBLEtBQUssRUFBRTtFQUFFQyxNQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUFFQyxNQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUFFQyxNQUFBQSxHQUFHLEVBQUUsS0FBSztFQUFFc0IsTUFBQUEsWUFBWSxFQUFFO0VBQU87RUFBRSxHQUFBLGVBQ3RGeEUsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDd0UsaUJBQUksRUFBQTtFQUFDZixJQUFBQSxJQUFJLEVBQUMsT0FBTztNQUFDbEYsS0FBSyxFQUFFOUIsQ0FBQyxDQUFDUztFQUFLLEdBQUUsQ0FBQyxlQUNwQzZDLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ29GLGVBQUUsRUFBQTtFQUFDdEMsSUFBQUEsS0FBSyxFQUFFO1FBQUV2RSxLQUFLLEVBQUU5QixDQUFDLENBQUNjLElBQUk7RUFBRXNILE1BQUFBLE1BQU0sRUFBRTtFQUFFO0VBQUUsR0FBQSxFQUFDLGNBQWdCLENBQUMsZUFDMUQ5RSxzQkFBQSxDQUFBQyxhQUFBLENBQUEsR0FBQSxFQUFBO0VBQUdrRixJQUFBQSxJQUFJLEVBQUMsdUJBQXVCO0VBQUNwQyxJQUFBQSxLQUFLLEVBQUU7RUFBRVMsTUFBQUEsVUFBVSxFQUFFLE1BQU07UUFBRWhGLEtBQUssRUFBRTlCLENBQUMsQ0FBQ00sSUFBSTtFQUFFa0UsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRWtFLE1BQUFBLGNBQWMsRUFBRSxNQUFNO0VBQUUvQixNQUFBQSxVQUFVLEVBQUU7RUFBSTtFQUFFLEdBQUEsRUFBQyxpQkFBYSxDQUNuSixDQUFDLEVBQ0xrRSxXQUFXLENBQUM5SSxNQUFNLEdBQUcsQ0FBQyxnQkFDckJ1QixzQkFBQSxDQUFBQyxhQUFBLENBQUEsT0FBQSxFQUFBO0VBQU84QyxJQUFBQSxLQUFLLEVBQUU7RUFBRXpFLE1BQUFBLEtBQUssRUFBRSxNQUFNO0VBQUU4SyxNQUFBQSxjQUFjLEVBQUU7RUFBVztFQUFFLEdBQUEsZUFDMURwSixzQkFBQSxDQUFBQyxhQUFBLENBQUEsT0FBQSxFQUFBLElBQUEsZUFDRUQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLElBQUEsRUFBQTtFQUFJOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUVrRixNQUFBQSxZQUFZLEVBQUUsQ0FBQSxVQUFBLEVBQWF2TCxDQUFDLENBQUNJLE1BQU0sQ0FBQTtFQUFHO0tBQUUsZUFDbkRrRCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsSUFBQSxFQUFBO0VBQUk4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRWdFLE1BQUFBLFNBQVMsRUFBRSxNQUFNO0VBQUU5SSxNQUFBQSxPQUFPLEVBQUUsT0FBTztRQUFFTyxLQUFLLEVBQUU5QixDQUFDLENBQUNnQixPQUFPO0VBQUV3RCxNQUFBQSxRQUFRLEVBQUUsTUFBTTtFQUFFeUQsTUFBQUEsYUFBYSxFQUFFLFdBQVc7RUFBRUMsTUFBQUEsYUFBYSxFQUFFLFFBQVE7RUFBRXZCLE1BQUFBLFVBQVUsRUFBRTtFQUFJO0VBQUUsR0FBQSxFQUFDLFVBQVksQ0FBQyxlQUMzS3JELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxJQUFBLEVBQUE7RUFBSThDLElBQUFBLEtBQUssRUFBRTtFQUFFZ0UsTUFBQUEsU0FBUyxFQUFFLE1BQU07RUFBRTlJLE1BQUFBLE9BQU8sRUFBRSxPQUFPO1FBQUVPLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2dCLE9BQU87RUFBRXdELE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUV5RCxNQUFBQSxhQUFhLEVBQUUsV0FBVztFQUFFQyxNQUFBQSxhQUFhLEVBQUUsUUFBUTtFQUFFdkIsTUFBQUEsVUFBVSxFQUFFO0VBQUk7RUFBRSxHQUFBLEVBQUMsTUFBUSxDQUFDLGVBQ3ZLckQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLElBQUEsRUFBQTtFQUFJOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUVnRSxNQUFBQSxTQUFTLEVBQUUsT0FBTztFQUFFOUksTUFBQUEsT0FBTyxFQUFFLE9BQU87UUFBRU8sS0FBSyxFQUFFOUIsQ0FBQyxDQUFDZ0IsT0FBTztFQUFFd0QsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRXlELE1BQUFBLGFBQWEsRUFBRSxXQUFXO0VBQUVDLE1BQUFBLGFBQWEsRUFBRSxRQUFRO0VBQUV2QixNQUFBQSxVQUFVLEVBQUU7RUFBSTtLQUFFLEVBQUMsUUFBVSxDQUN2SyxDQUNDLENBQUMsZUFDUnJELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxPQUFBLEVBQUEsSUFBQSxFQUNHc0gsV0FBVyxDQUFDMUksR0FBRyxDQUFDLENBQUN3SyxDQUFDLEVBQUVoSyxDQUFDLGtCQUNwQlcsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLElBQUEsRUFBQTtFQUFJWSxJQUFBQSxHQUFHLEVBQUV4QixDQUFFO0VBQUMwRCxJQUFBQSxLQUFLLEVBQUU7RUFBRWtGLE1BQUFBLFlBQVksRUFBRSxDQUFBLFVBQUEsRUFBYXZMLENBQUMsQ0FBQ0ksTUFBTSxDQUFBO0VBQUc7S0FBRSxlQUMzRGtELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxJQUFBLEVBQUE7RUFBSThDLElBQUFBLEtBQUssRUFBRTtFQUFFOUUsTUFBQUEsT0FBTyxFQUFFLFFBQVE7UUFBRU8sS0FBSyxFQUFFOUIsQ0FBQyxDQUFDYyxJQUFJO0VBQUUwRCxNQUFBQSxRQUFRLEVBQUUsTUFBTTtFQUFFbUMsTUFBQUEsVUFBVSxFQUFFO0VBQUk7RUFBRSxHQUFBLEVBQUVnRyxDQUFDLENBQUNDLFFBQWEsQ0FBQyxlQUNyR3RKLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxJQUFBLEVBQUE7RUFBSThDLElBQUFBLEtBQUssRUFBRTtFQUFFOUUsTUFBQUEsT0FBTyxFQUFFO0VBQVM7S0FBRSxlQUMvQitCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxNQUFBLEVBQUE7RUFBTThDLElBQUFBLEtBQUssRUFBRTtFQUFFN0IsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRWpELE1BQUFBLE9BQU8sRUFBRSxTQUFTO0VBQUVGLE1BQUFBLFlBQVksRUFBRSxLQUFLO0VBQUVELE1BQUFBLGVBQWUsRUFBRXVMLENBQUMsQ0FBQ0UsSUFBSSxLQUFLLE9BQU8sR0FBRyxDQUFBLEVBQUc3TSxDQUFDLENBQUNNLElBQUksQ0FBQSxFQUFBLENBQUksR0FBRyxHQUFHTixDQUFDLENBQUNTLElBQUksQ0FBQSxFQUFBLENBQUk7RUFBRXFCLE1BQUFBLEtBQUssRUFBRTZLLENBQUMsQ0FBQ0UsSUFBSSxLQUFLLE9BQU8sR0FBRzdNLENBQUMsQ0FBQ00sSUFBSSxHQUFHTixDQUFDLENBQUNTLElBQUk7RUFBRWtHLE1BQUFBLFVBQVUsRUFBRTtFQUFJO0tBQUUsRUFBRWdHLENBQUMsQ0FBQ0UsSUFBSSxJQUFJLE1BQWEsQ0FDck8sQ0FBQyxlQUNMdkosc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLElBQUEsRUFBQTtFQUFJOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUU5RSxNQUFBQSxPQUFPLEVBQUUsUUFBUTtRQUFFTyxLQUFLLEVBQUU5QixDQUFDLENBQUNlLFNBQVM7RUFBRXlELE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUU2RixNQUFBQSxTQUFTLEVBQUU7RUFBUTtFQUFFLEdBQUEsRUFBRXpCLE9BQU8sQ0FBQytELENBQUMsQ0FBQzNCLElBQUksQ0FBTSxDQUMvRyxDQUNMLENBQ0ksQ0FDRixDQUFDLGdCQUVSMUgsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDeUUsaUJBQUksRUFBQTtFQUFDM0IsSUFBQUEsS0FBSyxFQUFFO1FBQUV2RSxLQUFLLEVBQUU5QixDQUFDLENBQUNnQixPQUFPO0VBQUVxSixNQUFBQSxTQUFTLEVBQUUsUUFBUTtFQUFFOUksTUFBQUEsT0FBTyxFQUFFO0VBQVM7S0FBRSxFQUFDLGtCQUFzQixDQUVoRyxDQUFDLGVBR04rQixzQkFBQSxDQUFBQyxhQUFBLENBQUM0RCxnQkFBRyxFQUFBO0VBQUNkLElBQUFBLEtBQUssRUFBRTtRQUFFLEdBQUduRixTQUFTLEVBQUU7RUFBRWtHLE1BQUFBLElBQUksRUFBRSxHQUFHO0VBQUVDLE1BQUFBLFFBQVEsRUFBRTtFQUFRO0tBQUUsZUFDM0QvRCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRUMsTUFBQUEsT0FBTyxFQUFFLE1BQU07RUFBRUMsTUFBQUEsVUFBVSxFQUFFLFFBQVE7RUFBRUMsTUFBQUEsR0FBRyxFQUFFLEtBQUs7RUFBRXNCLE1BQUFBLFlBQVksRUFBRTtFQUFPO0VBQUUsR0FBQSxlQUN0RnhFLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3dFLGlCQUFJLEVBQUE7RUFBQ2YsSUFBQUEsSUFBSSxFQUFDLFNBQVM7TUFBQ2xGLEtBQUssRUFBRTlCLENBQUMsQ0FBQ007RUFBSyxHQUFFLENBQUMsZUFDdENnRCxzQkFBQSxDQUFBQyxhQUFBLENBQUNvRixlQUFFLEVBQUE7RUFBQ3RDLElBQUFBLEtBQUssRUFBRTtRQUFFdkUsS0FBSyxFQUFFOUIsQ0FBQyxDQUFDYyxJQUFJO0VBQUVzSCxNQUFBQSxNQUFNLEVBQUU7RUFBRTtFQUFFLEdBQUEsRUFBQyxhQUFlLENBQUMsZUFDekQ5RSxzQkFBQSxDQUFBQyxhQUFBLENBQUEsR0FBQSxFQUFBO0VBQUdrRixJQUFBQSxJQUFJLEVBQUMsdUJBQXVCO0VBQUNwQyxJQUFBQSxLQUFLLEVBQUU7RUFBRVMsTUFBQUEsVUFBVSxFQUFFLE1BQU07UUFBRWhGLEtBQUssRUFBRTlCLENBQUMsQ0FBQ00sSUFBSTtFQUFFa0UsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRWtFLE1BQUFBLGNBQWMsRUFBRSxNQUFNO0VBQUUvQixNQUFBQSxVQUFVLEVBQUU7RUFBSTtFQUFFLEdBQUEsRUFBQyxpQkFBYSxDQUNuSixDQUFDLEVBQ0xtRSxVQUFVLENBQUMvSSxNQUFNLEdBQUcsQ0FBQyxnQkFDcEJ1QixzQkFBQSxDQUFBQyxhQUFBLENBQUEsT0FBQSxFQUFBO0VBQU84QyxJQUFBQSxLQUFLLEVBQUU7RUFBRXpFLE1BQUFBLEtBQUssRUFBRSxNQUFNO0VBQUU4SyxNQUFBQSxjQUFjLEVBQUU7RUFBVztFQUFFLEdBQUEsZUFDMURwSixzQkFBQSxDQUFBQyxhQUFBLENBQUEsT0FBQSxFQUFBLElBQUEsZUFDRUQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLElBQUEsRUFBQTtFQUFJOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUVrRixNQUFBQSxZQUFZLEVBQUUsQ0FBQSxVQUFBLEVBQWF2TCxDQUFDLENBQUNJLE1BQU0sQ0FBQTtFQUFHO0tBQUUsZUFDbkRrRCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsSUFBQSxFQUFBO0VBQUk4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRWdFLE1BQUFBLFNBQVMsRUFBRSxNQUFNO0VBQUU5SSxNQUFBQSxPQUFPLEVBQUUsT0FBTztRQUFFTyxLQUFLLEVBQUU5QixDQUFDLENBQUNnQixPQUFPO0VBQUV3RCxNQUFBQSxRQUFRLEVBQUUsTUFBTTtFQUFFeUQsTUFBQUEsYUFBYSxFQUFFLFdBQVc7RUFBRUMsTUFBQUEsYUFBYSxFQUFFLFFBQVE7RUFBRXZCLE1BQUFBLFVBQVUsRUFBRTtFQUFJO0VBQUUsR0FBQSxFQUFDLE1BQVEsQ0FBQyxlQUN2S3JELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxJQUFBLEVBQUE7RUFBSThDLElBQUFBLEtBQUssRUFBRTtFQUFFZ0UsTUFBQUEsU0FBUyxFQUFFLE1BQU07RUFBRTlJLE1BQUFBLE9BQU8sRUFBRSxPQUFPO1FBQUVPLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2dCLE9BQU87RUFBRXdELE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUV5RCxNQUFBQSxhQUFhLEVBQUUsV0FBVztFQUFFQyxNQUFBQSxhQUFhLEVBQUUsUUFBUTtFQUFFdkIsTUFBQUEsVUFBVSxFQUFFO0VBQUk7RUFBRSxHQUFBLEVBQUMsVUFBWSxDQUFDLGVBQzNLckQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLElBQUEsRUFBQTtFQUFJOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUVnRSxNQUFBQSxTQUFTLEVBQUUsTUFBTTtFQUFFOUksTUFBQUEsT0FBTyxFQUFFLE9BQU87UUFBRU8sS0FBSyxFQUFFOUIsQ0FBQyxDQUFDZ0IsT0FBTztFQUFFd0QsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRXlELE1BQUFBLGFBQWEsRUFBRSxXQUFXO0VBQUVDLE1BQUFBLGFBQWEsRUFBRSxRQUFRO0VBQUV2QixNQUFBQSxVQUFVLEVBQUU7RUFBSTtFQUFFLEdBQUEsRUFBQyxRQUFVLENBQUMsZUFDektyRCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsSUFBQSxFQUFBO0VBQUk4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRWdFLE1BQUFBLFNBQVMsRUFBRSxPQUFPO0VBQUU5SSxNQUFBQSxPQUFPLEVBQUUsT0FBTztRQUFFTyxLQUFLLEVBQUU5QixDQUFDLENBQUNnQixPQUFPO0VBQUV3RCxNQUFBQSxRQUFRLEVBQUUsTUFBTTtFQUFFeUQsTUFBQUEsYUFBYSxFQUFFLFdBQVc7RUFBRUMsTUFBQUEsYUFBYSxFQUFFLFFBQVE7RUFBRXZCLE1BQUFBLFVBQVUsRUFBRTtFQUFJO0tBQUUsRUFBQyxPQUFTLENBQ3RLLENBQ0MsQ0FBQyxlQUNSckQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE9BQUEsRUFBQSxJQUFBLEVBQ0d1SCxVQUFVLENBQUMzSSxHQUFHLENBQUMsQ0FBQzJLLENBQUMsRUFBRW5LLENBQUMsa0JBQ25CVyxzQkFBQSxDQUFBQyxhQUFBLENBQUEsSUFBQSxFQUFBO0VBQUlZLElBQUFBLEdBQUcsRUFBRXhCLENBQUU7RUFBQzBELElBQUFBLEtBQUssRUFBRTtFQUFFa0YsTUFBQUEsWUFBWSxFQUFFLENBQUEsVUFBQSxFQUFhdkwsQ0FBQyxDQUFDSSxNQUFNLENBQUE7RUFBRztLQUFFLGVBQzNEa0Qsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLElBQUEsRUFBQTtFQUFJOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUU5RSxNQUFBQSxPQUFPLEVBQUUsUUFBUTtRQUFFTyxLQUFLLEVBQUU5QixDQUFDLENBQUNjLElBQUk7RUFBRTBELE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUVtQyxNQUFBQSxVQUFVLEVBQUUsR0FBRztFQUFFNkQsTUFBQUEsUUFBUSxFQUFFLE9BQU87RUFBRXVDLE1BQUFBLFFBQVEsRUFBRSxRQUFRO0VBQUVDLE1BQUFBLFlBQVksRUFBRSxVQUFVO0VBQUVDLE1BQUFBLFVBQVUsRUFBRTtFQUFTO0VBQUUsR0FBQSxFQUFFSCxDQUFDLENBQUMxRyxJQUFTLENBQUMsZUFDeEw5QyxzQkFBQSxDQUFBQyxhQUFBLENBQUEsSUFBQSxFQUFBO0VBQUk4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRTlFLE1BQUFBLE9BQU8sRUFBRTtFQUFTO0tBQUUsZUFDL0IrQixzQkFBQSxDQUFBQyxhQUFBLENBQUEsTUFBQSxFQUFBO0VBQU04QyxJQUFBQSxLQUFLLEVBQUU7RUFBRTdCLE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUVqRCxNQUFBQSxPQUFPLEVBQUUsU0FBUztFQUFFRixNQUFBQSxZQUFZLEVBQUUsS0FBSztFQUFFRCxNQUFBQSxlQUFlLEVBQUUsQ0FBQSxFQUFHcEIsQ0FBQyxDQUFDUyxJQUFJLENBQUEsRUFBQSxDQUFJO1FBQUVxQixLQUFLLEVBQUU5QixDQUFDLENBQUNTLElBQUk7RUFBRWtHLE1BQUFBLFVBQVUsRUFBRSxHQUFHO0VBQUVzQixNQUFBQSxhQUFhLEVBQUU7RUFBWTtLQUFFLEVBQUU2RSxDQUFDLENBQUNJLFFBQVEsSUFBSSxHQUFVLENBQy9MLENBQUMsZUFDTDVKLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxJQUFBLEVBQUE7RUFBSThDLElBQUFBLEtBQUssRUFBRTtFQUFFOUUsTUFBQUEsT0FBTyxFQUFFO0VBQVM7S0FBRSxlQUMvQitCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxNQUFBLEVBQUE7RUFBTThDLElBQUFBLEtBQUssRUFBRTtFQUFFN0IsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRWpELE1BQUFBLE9BQU8sRUFBRSxTQUFTO0VBQUVGLE1BQUFBLFlBQVksRUFBRSxLQUFLO1FBQUVELGVBQWUsRUFBRSxHQUFHK0gsV0FBVyxDQUFDMkQsQ0FBQyxDQUFDSyxNQUFNLENBQUMsQ0FBQSxFQUFBLENBQUk7RUFBRXJMLE1BQUFBLEtBQUssRUFBRXFILFdBQVcsQ0FBQzJELENBQUMsQ0FBQ0ssTUFBTSxDQUFDO0VBQUV4RyxNQUFBQSxVQUFVLEVBQUUsR0FBRztFQUFFc0IsTUFBQUEsYUFBYSxFQUFFO0VBQWE7S0FBRSxFQUFFNkUsQ0FBQyxDQUFDSyxNQUFNLElBQUksR0FBVSxDQUM1TixDQUFDLGVBQ0w3SixzQkFBQSxDQUFBQyxhQUFBLENBQUEsSUFBQSxFQUFBO0VBQUk4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRTlFLE1BQUFBLE9BQU8sRUFBRSxRQUFRO1FBQUVPLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2UsU0FBUztFQUFFeUQsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRTZGLE1BQUFBLFNBQVMsRUFBRTtFQUFRO0VBQUUsR0FBQSxFQUFFekIsT0FBTyxDQUFDa0UsQ0FBQyxDQUFDOUIsSUFBSSxDQUFNLENBQy9HLENBQ0wsQ0FDSSxDQUNGLENBQUMsZ0JBRVIxSCxzQkFBQSxDQUFBQyxhQUFBLENBQUN5RSxpQkFBSSxFQUFBO0VBQUMzQixJQUFBQSxLQUFLLEVBQUU7UUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2dCLE9BQU87RUFBRXFKLE1BQUFBLFNBQVMsRUFBRSxRQUFRO0VBQUU5SSxNQUFBQSxPQUFPLEVBQUU7RUFBUztFQUFFLEdBQUEsRUFBQyxpQkFBcUIsQ0FFL0YsQ0FDRixDQUFDLGVBR04rQixzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRUMsTUFBQUEsT0FBTyxFQUFFLE1BQU07RUFBRUksTUFBQUEsY0FBYyxFQUFFLGVBQWU7RUFBRUgsTUFBQUEsVUFBVSxFQUFFLFFBQVE7RUFBRTZHLE1BQUFBLFVBQVUsRUFBRSxNQUFNO0VBQUVDLE1BQUFBLFNBQVMsRUFBRSxDQUFBLFVBQUEsRUFBYXJOLENBQUMsQ0FBQ0ksTUFBTSxDQUFBO0VBQUc7S0FBRSxlQUM3SWtELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxHQUFBLEVBQUE7RUFBR2tGLElBQUFBLElBQUksRUFBQyxRQUFRO0VBQUNwQyxJQUFBQSxLQUFLLEVBQUU7RUFBRXFDLE1BQUFBLGNBQWMsRUFBRTtFQUFPO0VBQUUsR0FBQSxlQUNqRHBGLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3lFLGlCQUFJLEVBQUE7RUFBQzNCLElBQUFBLEtBQUssRUFBRTtRQUFFdkUsS0FBSyxFQUFFOUIsQ0FBQyxDQUFDZ0IsT0FBTztFQUFFd0QsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRS9DLE1BQUFBLE1BQU0sRUFBRTtFQUFVO0tBQUUsZUFDckU2QixzQkFBQSxDQUFBQyxhQUFBLENBQUEsTUFBQSxFQUFBO0VBQU04QyxJQUFBQSxLQUFLLEVBQUU7UUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ00sSUFBSTtFQUFFcUcsTUFBQUEsVUFBVSxFQUFFO0VBQUk7RUFBRSxHQUFBLEVBQUMsS0FBUyxDQUFDLEVBQUEsR0FBQyxlQUFBckQsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQTtFQUFNOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUV2RSxNQUFBQSxLQUFLLEVBQUU7RUFBTztLQUFFLEVBQUMsTUFBVSxDQUFDLEVBQUEsMEJBQ25HLENBQ0wsQ0FBQyxlQUNKd0Isc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQTtFQUFLOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUVDLE1BQUFBLE9BQU8sRUFBRSxNQUFNO0VBQUVFLE1BQUFBLEdBQUcsRUFBRTtFQUFPO0tBQUUsZUFDM0NsRCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsR0FBQSxFQUFBO0VBQUdrRixJQUFBQSxJQUFJLEVBQUMsdUJBQXVCO0VBQUNwQyxJQUFBQSxLQUFLLEVBQUU7UUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2UsU0FBUztFQUFFeUQsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRWtFLE1BQUFBLGNBQWMsRUFBRTtFQUFPO0VBQUUsR0FBQSxFQUFDLE9BQVEsQ0FBQyxlQUNsSHBGLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxHQUFBLEVBQUE7RUFBR2tGLElBQUFBLElBQUksRUFBQyx1QkFBdUI7RUFBQ3BDLElBQUFBLEtBQUssRUFBRTtRQUFFdkUsS0FBSyxFQUFFOUIsQ0FBQyxDQUFDZSxTQUFTO0VBQUV5RCxNQUFBQSxRQUFRLEVBQUUsTUFBTTtFQUFFa0UsTUFBQUEsY0FBYyxFQUFFO0VBQU87RUFBRSxHQUFBLEVBQUMsTUFBTyxDQUFDLGVBQ2pIcEYsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEdBQUEsRUFBQTtFQUFHa0YsSUFBQUEsSUFBSSxFQUFDLHlCQUF5QjtFQUFDcEMsSUFBQUEsS0FBSyxFQUFFO1FBQUV2RSxLQUFLLEVBQUU5QixDQUFDLENBQUNlLFNBQVM7RUFBRXlELE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUVrRSxNQUFBQSxjQUFjLEVBQUU7RUFBTztFQUFFLEdBQUEsRUFBQyxTQUFVLENBQUMsZUFDdEhwRixzQkFBQSxDQUFBQyxhQUFBLENBQUEsR0FBQSxFQUFBO0VBQUdrRixJQUFBQSxJQUFJLEVBQUMsZ0NBQWdDO0VBQUNwQyxJQUFBQSxLQUFLLEVBQUU7UUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2UsU0FBUztFQUFFeUQsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRWtFLE1BQUFBLGNBQWMsRUFBRTtFQUFPO0VBQUUsR0FBQSxFQUFDLFNBQVUsQ0FBQyxlQUM3SHBGLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxHQUFBLEVBQUE7RUFBR2tGLElBQUFBLElBQUksRUFBQyxjQUFjO0VBQUNwQyxJQUFBQSxLQUFLLEVBQUU7UUFBRXZFLEtBQUssRUFBRTlCLENBQUMsQ0FBQ2UsU0FBUztFQUFFeUQsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFBRWtFLE1BQUFBLGNBQWMsRUFBRTtFQUFPO0VBQUUsR0FBQSxFQUFDLE9BQVEsQ0FDckcsQ0FDRixDQUNGLENBQUM7RUFFVixDQUFDOztFQzNkRCxNQUFNNEUsZUFBZSxHQUFHQSxNQUFNO0VBQzVCLEVBQUEsb0JBQ0VoSyxzQkFBQSxDQUFBQyxhQUFBLENBQUM0RCxnQkFBRyxFQUFBO01BQ0ZDLElBQUksRUFBQSxJQUFBO0VBQ0pSLElBQUFBLGFBQWEsRUFBQyxRQUFRO0VBQ3RCTCxJQUFBQSxVQUFVLEVBQUMsUUFBUTtFQUNuQkcsSUFBQUEsY0FBYyxFQUFDLFFBQVE7RUFDdkIzRCxJQUFBQSxDQUFDLEVBQUMsSUFBSTtFQUNOc0QsSUFBQUEsS0FBSyxFQUFFO0VBQ0xrRixNQUFBQSxZQUFZLEVBQUUsbUJBQW1CO0VBQ2pDbkssTUFBQUEsZUFBZSxFQUFFLFNBQVM7RUFDMUJHLE1BQUFBLE9BQU8sRUFBRSxXQUFXO0VBQ3BCZ00sTUFBQUEsUUFBUSxFQUFFLFVBQVU7RUFDcEJSLE1BQUFBLFFBQVEsRUFBRTtFQUNaO0tBQUUsZUFHRnpKLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxLQUFBLEVBQUE7RUFBSzhDLElBQUFBLEtBQUssRUFBRTtFQUNWa0gsTUFBQUEsUUFBUSxFQUFFLFVBQVU7RUFDcEJDLE1BQUFBLE1BQU0sRUFBRSxDQUFDO0VBQ1RDLE1BQUFBLElBQUksRUFBRSxLQUFLO0VBQ1gvRixNQUFBQSxTQUFTLEVBQUUsa0JBQWtCO0VBQzdCOUYsTUFBQUEsS0FBSyxFQUFFLEtBQUs7RUFDWkMsTUFBQUEsTUFBTSxFQUFFLEtBQUs7RUFDYjRKLE1BQUFBLFVBQVUsRUFBRTtFQUNkO0VBQUUsR0FBRSxDQUFDLGVBR0xuSSxzQkFBQSxDQUFBQyxhQUFBLENBQUEsR0FBQSxFQUFBO0VBQ0VrRixJQUFBQSxJQUFJLEVBQUMsUUFBUTtFQUNicEMsSUFBQUEsS0FBSyxFQUFFO0VBQ0xxQyxNQUFBQSxjQUFjLEVBQUUsTUFBTTtFQUN0QnBDLE1BQUFBLE9BQU8sRUFBRSxNQUFNO0VBQ2ZDLE1BQUFBLFVBQVUsRUFBRSxRQUFRO0VBQ3BCQyxNQUFBQSxHQUFHLEVBQUUsTUFBTTtFQUNYL0UsTUFBQUEsTUFBTSxFQUFFLFNBQVM7RUFDakJELE1BQUFBLFVBQVUsRUFBRTtPQUNaO01BQ0Y4RixZQUFZLEVBQUdDLENBQUMsSUFBSztFQUFFQSxNQUFBQSxDQUFDLENBQUNDLGFBQWEsQ0FBQ25CLEtBQUssQ0FBQ3FILE9BQU8sR0FBRyxNQUFNO01BQUUsQ0FBRTtNQUNqRTlGLFlBQVksRUFBR0wsQ0FBQyxJQUFLO0VBQUVBLE1BQUFBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDcUgsT0FBTyxHQUFHLEdBQUc7RUFBRSxJQUFBO0tBQUUsZUFFOURwSyxzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQ0VvSyxJQUFBQSxHQUFHLEVBQUMsdUJBQXVCO0VBQzNCQyxJQUFBQSxHQUFHLEVBQUMsTUFBTTtFQUNWdkgsSUFBQUEsS0FBSyxFQUFFO0VBQUV4RSxNQUFBQSxNQUFNLEVBQUUsTUFBTTtFQUFFRCxNQUFBQSxLQUFLLEVBQUUsTUFBTTtFQUFFaU0sTUFBQUEsU0FBUyxFQUFFLE9BQU87RUFBRXhNLE1BQUFBLFlBQVksRUFBRSxLQUFLO0VBQUV5TSxNQUFBQSxNQUFNLEVBQUU7T0FBNkM7TUFDdElDLE9BQU8sRUFBR3hHLENBQUMsSUFBS0EsQ0FBQyxDQUFDc0UsTUFBTSxDQUFDeEYsS0FBSyxDQUFDQyxPQUFPLEdBQUc7RUFBTyxHQUNqRCxDQUFDLGVBQ0ZoRCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQUs4QyxJQUFBQSxLQUFLLEVBQUU7RUFBRTdCLE1BQUFBLFFBQVEsRUFBRSxNQUFNO0VBQUVtQyxNQUFBQSxVQUFVLEVBQUUsTUFBTTtFQUFFMEUsTUFBQUEsVUFBVSxFQUFFLHVCQUF1QjtFQUFFL0UsTUFBQUEsT0FBTyxFQUFFLE1BQU07RUFBRUMsTUFBQUEsVUFBVSxFQUFFLFVBQVU7RUFBRUMsTUFBQUEsR0FBRyxFQUFFO0VBQU07S0FBRSxlQUM3SWxELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxNQUFBLEVBQUE7RUFBTThDLElBQUFBLEtBQUssRUFBRTtFQUFFdkUsTUFBQUEsS0FBSyxFQUFFLFNBQVM7RUFBRTBKLE1BQUFBLFVBQVUsRUFBRTtFQUFrQztFQUFFLEdBQUEsRUFBQyxLQUFTLENBQUMsZUFDNUZsSSxzQkFBQSxDQUFBQyxhQUFBLENBQUEsTUFBQSxFQUFBO0VBQU04QyxJQUFBQSxLQUFLLEVBQUU7RUFBRXZFLE1BQUFBLEtBQUssRUFBRSxTQUFTO0VBQUUwSixNQUFBQSxVQUFVLEVBQUU7RUFBb0M7RUFBRSxHQUFBLEVBQUMsTUFBVSxDQUFDLGVBQy9GbEksc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQTtFQUFNOEMsSUFBQUEsS0FBSyxFQUFFO0VBQUU3QixNQUFBQSxRQUFRLEVBQUUsS0FBSztFQUFFMUMsTUFBQUEsS0FBSyxFQUFFLE1BQU07RUFBRTZFLE1BQUFBLFVBQVUsRUFBRSxHQUFHO0VBQUVHLE1BQUFBLFVBQVUsRUFBRSxLQUFLO0VBQUVvQixNQUFBQSxhQUFhLEVBQUU7RUFBUztFQUFFLEdBQUEsRUFBQyxNQUFVLENBQ3JILENBQ0osQ0FBQyxlQUdKNUUsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEdBQUEsRUFBQTtFQUNFa0YsSUFBQUEsSUFBSSxFQUFDLFFBQVE7RUFDYnBDLElBQUFBLEtBQUssRUFBRTtFQUNMQyxNQUFBQSxPQUFPLEVBQUUsTUFBTTtFQUNmQyxNQUFBQSxVQUFVLEVBQUUsUUFBUTtFQUNwQkcsTUFBQUEsY0FBYyxFQUFFLFFBQVE7RUFDeEJGLE1BQUFBLEdBQUcsRUFBRSxLQUFLO0VBQ1ZrRixNQUFBQSxTQUFTLEVBQUUsTUFBTTtFQUNqQm5LLE1BQUFBLE9BQU8sRUFBRSxVQUFVO0VBQ25CSyxNQUFBQSxLQUFLLEVBQUUsS0FBSztFQUNaUCxNQUFBQSxZQUFZLEVBQUUsS0FBSztFQUNuQkQsTUFBQUEsZUFBZSxFQUFFLHlCQUF5QjtFQUMxQ2hCLE1BQUFBLE1BQU0sRUFBRSxtQ0FBbUM7RUFDM0MwQixNQUFBQSxLQUFLLEVBQUUsU0FBUztFQUNoQjRHLE1BQUFBLGNBQWMsRUFBRSxNQUFNO0VBQ3RCbEUsTUFBQUEsUUFBUSxFQUFFLE1BQU07RUFDaEJtQyxNQUFBQSxVQUFVLEVBQUUsR0FBRztFQUNmdUIsTUFBQUEsYUFBYSxFQUFFLFFBQVE7RUFDdkJELE1BQUFBLGFBQWEsRUFBRSxXQUFXO0VBQzFCekcsTUFBQUEsVUFBVSxFQUFFLGVBQWU7RUFDM0JDLE1BQUFBLE1BQU0sRUFBRTtPQUNSO01BQ0Y2RixZQUFZLEVBQUdDLENBQUMsSUFBSztFQUNuQkEsTUFBQUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNqRixlQUFlLEdBQUcsd0JBQXdCO0VBQ2hFbUcsTUFBQUEsQ0FBQyxDQUFDQyxhQUFhLENBQUNuQixLQUFLLENBQUNzQixTQUFTLEdBQUcsOEJBQThCO01BQ2xFLENBQUU7TUFDRkMsWUFBWSxFQUFHTCxDQUFDLElBQUs7RUFDbkJBLE1BQUFBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDakYsZUFBZSxHQUFHLHlCQUF5QjtFQUNqRW1HLE1BQUFBLENBQUMsQ0FBQ0MsYUFBYSxDQUFDbkIsS0FBSyxDQUFDc0IsU0FBUyxHQUFHLE1BQU07RUFDMUMsSUFBQTtFQUFFLEdBQUEsZUFFRnJFLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3dFLGlCQUFJLEVBQUE7RUFBQ2YsSUFBQUEsSUFBSSxFQUFDLE1BQU07RUFBQ2hDLElBQUFBLElBQUksRUFBRSxFQUFHO0VBQUNsRCxJQUFBQSxLQUFLLEVBQUM7S0FBVyxDQUFDLGVBQzlDd0Isc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLE1BQUEsRUFBQSxJQUFBLEVBQU0sV0FBZSxDQUNwQixDQUNBLENBQUM7RUFFVixDQUFDOztFQzFGRCxNQUFNeUssY0FBYyxHQUFJQyxLQUFLLElBQUs7SUFDOUIsTUFBTTtNQUFFQyxNQUFNO0VBQUVDLElBQUFBO0VBQU8sR0FBQyxHQUFHRixLQUFLO0VBQ2hDLEVBQUEsTUFBTUcsVUFBVSxHQUFHQyxpQkFBUyxFQUFFO0VBRTlCeEUsRUFBQUEsZUFBUyxDQUFDLE1BQU07RUFDWixJQUFBLE1BQU15RSxHQUFHLEdBQUdKLE1BQU0sRUFBRUssTUFBTSxFQUFFQyxXQUFXO0VBRXZDLElBQUEsSUFBSUYsR0FBRyxFQUFFO0VBQ0xHLE1BQUFBLFVBQVUsQ0FBQyxNQUFNO0VBQ2JDLFFBQUFBLE1BQU0sQ0FBQ0MsSUFBSSxDQUFDTCxHQUFHLEVBQUUsUUFBUSxDQUFDO1FBQzlCLENBQUMsRUFBRSxHQUFHLENBQUM7RUFDWCxJQUFBLENBQUMsTUFBTTtFQUNIRixNQUFBQSxVQUFVLENBQUM7RUFBRVEsUUFBQUEsT0FBTyxFQUFFLGtDQUFrQztFQUFFQyxRQUFBQSxJQUFJLEVBQUU7RUFBUSxPQUFDLENBQUM7RUFDOUUsSUFBQTtFQUNKLEVBQUEsQ0FBQyxFQUFFLENBQUNYLE1BQU0sQ0FBQyxDQUFDO0VBRVosRUFBQSxvQkFDSTVLLHNCQUFBLENBQUFDLGFBQUEsQ0FBQzRELGdCQUFHLEVBQUE7TUFBQ0MsSUFBSSxFQUFBLElBQUE7RUFBQ1IsSUFBQUEsYUFBYSxFQUFDLFFBQVE7RUFBQ0wsSUFBQUEsVUFBVSxFQUFDLFFBQVE7RUFBQ0csSUFBQUEsY0FBYyxFQUFDLFFBQVE7RUFBQzNELElBQUFBLENBQUMsRUFBQztFQUFLLEdBQUEsZUFDaEZPLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3VMLG1CQUFNLEVBQUEsSUFBRSxDQUFDLGVBQ1Z4TCxzQkFBQSxDQUFBQyxhQUFBLENBQUN5RSxpQkFBSSxFQUFBO0VBQUMrRyxJQUFBQSxFQUFFLEVBQUMsSUFBSTtFQUFDQyxJQUFBQSxPQUFPLEVBQUM7S0FBSSxFQUFDLGdCQUFvQixDQUM5QyxDQUFDO0VBRWQsQ0FBQzs7RUN2QkQsTUFBTUMsWUFBWSxHQUFJaEIsS0FBSyxJQUFLO0lBQzlCLE1BQU07TUFBRUMsTUFBTTtFQUFFZ0IsSUFBQUE7RUFBUyxHQUFDLEdBQUdqQixLQUFLO0lBQ2xDLE1BQU1rQixTQUFTLEdBQUdqQixNQUFNLENBQUNLLE1BQU0sQ0FBQ1csUUFBUSxDQUFDOUksSUFBSSxDQUFDO0VBRTlDLEVBQUEsSUFBSStJLFNBQVMsS0FBSyxJQUFJLElBQUlBLFNBQVMsS0FBSyxNQUFNLEVBQUU7RUFDOUMsSUFBQSxvQkFDRTdMLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ2tKLGtCQUFLLEVBQUE7RUFBQ3VDLE1BQUFBLE9BQU8sRUFBQyxTQUFTO0VBQUMzSSxNQUFBQSxLQUFLLEVBQUU7RUFBRWpGLFFBQUFBLGVBQWUsRUFBRSxTQUFTO0VBQUVVLFFBQUFBLEtBQUssRUFBRSxNQUFNO0VBQUUxQixRQUFBQSxNQUFNLEVBQUU7RUFBTztFQUFFLEtBQUEsRUFBQyxTQUV4RixDQUFDO0VBRVosRUFBQTtFQUVBLEVBQUEsb0JBQ0VrRCxzQkFBQSxDQUFBQyxhQUFBLENBQUNrSixrQkFBSyxFQUFBO0VBQUNwRyxJQUFBQSxLQUFLLEVBQUU7RUFBRWpGLE1BQUFBLGVBQWUsRUFBRSxNQUFNO0VBQUVVLE1BQUFBLEtBQUssRUFBRSxNQUFNO0VBQUUxQixNQUFBQSxNQUFNLEVBQUU7RUFBaUI7RUFBRSxHQUFBLEVBQUMsUUFFN0UsQ0FBQztFQUVaLENBQUM7O0VDakJELE1BQU1nUCxVQUFVLEdBQUluQixLQUFLLElBQUs7SUFDMUIsTUFBTTtNQUFFQyxNQUFNO01BQUVnQixRQUFRO0VBQUVHLElBQUFBO0VBQU0sR0FBQyxHQUFHcEIsS0FBSztJQUN6QyxNQUFNOUosR0FBRyxHQUFHK0osTUFBTSxDQUFDSyxNQUFNLENBQUNXLFFBQVEsQ0FBQzlJLElBQUksQ0FBQztJQUN4QyxNQUFNd0csUUFBUSxHQUFHc0IsTUFBTSxDQUFDSyxNQUFNLENBQUMzQixRQUFRLElBQUksTUFBTTtJQUVqRCxNQUFNLENBQUMwQyxRQUFRLEVBQUVDLFdBQVcsQ0FBQyxHQUFHL0YsY0FBUSxDQUFDLElBQUksQ0FBQztJQUM5QyxNQUFNLENBQUNDLE9BQU8sRUFBRUMsVUFBVSxDQUFDLEdBQUdGLGNBQVEsQ0FBQyxJQUFJLENBQUM7SUFDNUMsTUFBTSxDQUFDZ0csUUFBUSxFQUFFQyxXQUFXLENBQUMsR0FBR2pHLGNBQVEsQ0FBQyxLQUFLLENBQUM7RUFFL0NLLEVBQUFBLGVBQVMsQ0FBQyxNQUFNO01BQ1osSUFBSSxDQUFDMUYsR0FBRyxFQUFFO1FBQ051RixVQUFVLENBQUMsS0FBSyxDQUFDO0VBQ2pCLE1BQUE7RUFDSixJQUFBO0VBRUEsSUFBQSxJQUFJdkYsR0FBRyxDQUFDdUwsVUFBVSxDQUFDLFNBQVMsQ0FBQyxJQUFJdkwsR0FBRyxDQUFDdUwsVUFBVSxDQUFDLFVBQVUsQ0FBQyxFQUFFO1FBQ3pESCxXQUFXLENBQUNwTCxHQUFHLENBQUM7UUFDaEJ1RixVQUFVLENBQUMsS0FBSyxDQUFDO0VBQ2pCLE1BQUE7RUFDSixJQUFBO0VBRUEsSUFBQSxNQUFNaUcsY0FBYyxHQUFHLFlBQVk7UUFDL0IsSUFBSTtVQUNBLE1BQU0zRixRQUFRLEdBQUcsTUFBTTRGLEtBQUssQ0FBQyxDQUFBLDBCQUFBLEVBQTZCQyxrQkFBa0IsQ0FBQzFMLEdBQUcsQ0FBQyxDQUFBLENBQUUsQ0FBQztVQUNwRixJQUFJNkYsUUFBUSxDQUFDOEYsRUFBRSxFQUFFO0VBQ2IsVUFBQSxNQUFNbk8sSUFBSSxHQUFHLE1BQU1xSSxRQUFRLENBQUMrRixJQUFJLEVBQUU7RUFDbENSLFVBQUFBLFdBQVcsQ0FBQzVOLElBQUksQ0FBQzJNLEdBQUcsQ0FBQztFQUN6QixRQUFBLENBQUMsTUFBTTtZQUNIbUIsV0FBVyxDQUFDLElBQUksQ0FBQztFQUNyQixRQUFBO1FBQ0osQ0FBQyxDQUFDLE9BQU85RixLQUFLLEVBQUU7RUFDWlEsUUFBQUEsT0FBTyxDQUFDUixLQUFLLENBQUMsNEJBQTRCLEVBQUVBLEtBQUssQ0FBQztVQUNsRDhGLFdBQVcsQ0FBQyxJQUFJLENBQUM7RUFDckIsTUFBQSxDQUFDLFNBQVM7VUFDTi9GLFVBQVUsQ0FBQyxLQUFLLENBQUM7RUFDckIsTUFBQTtNQUNKLENBQUM7RUFFRGlHLElBQUFBLGNBQWMsRUFBRTtFQUNwQixFQUFBLENBQUMsRUFBRSxDQUFDeEwsR0FBRyxDQUFDLENBQUM7SUFFVCxNQUFNYSxJQUFJLEdBQUdxSyxLQUFLLEtBQUssTUFBTSxHQUFHLE1BQU0sR0FBRyxPQUFPO0VBRWhELEVBQUEsSUFBSTVGLE9BQU8sRUFBRTtFQUNULElBQUEsb0JBQU9uRyxzQkFBQSxDQUFBQyxhQUFBLENBQUM0RCxnQkFBRyxFQUFBO0VBQUNkLE1BQUFBLEtBQUssRUFBRTtFQUFFekUsUUFBQUEsS0FBSyxFQUFFb0QsSUFBSTtFQUFFbkQsUUFBQUEsTUFBTSxFQUFFbUQsSUFBSTtFQUFFM0QsUUFBQUEsWUFBWSxFQUFFLEtBQUs7RUFBRUQsUUFBQUEsZUFBZSxFQUFFO0VBQU87RUFBRSxLQUFFLENBQUM7RUFDdEcsRUFBQTtFQUVBLEVBQUEsSUFBSSxDQUFDa08sUUFBUSxJQUFJRSxRQUFRLEVBQUU7RUFDdkIsSUFBQSxvQkFDSWxNLHNCQUFBLENBQUFDLGFBQUEsQ0FBQzRELGdCQUFHLEVBQUE7RUFBQ2QsTUFBQUEsS0FBSyxFQUFFO0VBQ1J6RSxRQUFBQSxLQUFLLEVBQUVvRCxJQUFJO0VBQ1huRCxRQUFBQSxNQUFNLEVBQUVtRCxJQUFJO0VBQ1ozRCxRQUFBQSxZQUFZLEVBQUUsS0FBSztFQUNuQkQsUUFBQUEsZUFBZSxFQUFFLFNBQVM7RUFDMUJVLFFBQUFBLEtBQUssRUFBRSxTQUFTO0VBQ2hCd0UsUUFBQUEsT0FBTyxFQUFFLE1BQU07RUFDZkMsUUFBQUEsVUFBVSxFQUFFLFFBQVE7RUFDcEJHLFFBQUFBLGNBQWMsRUFBRSxRQUFRO0VBQ3hCQyxRQUFBQSxVQUFVLEVBQUUsTUFBTTtFQUNsQm5DLFFBQUFBLFFBQVEsRUFBRTZLLEtBQUssS0FBSyxNQUFNLEdBQUcsTUFBTSxHQUFHLE1BQU07RUFDNUNqUCxRQUFBQSxNQUFNLEVBQUU7RUFDWjtPQUFFLEVBQ0d3TSxRQUFRLENBQUNvRCxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUNDLFdBQVcsRUFDOUIsQ0FBQztFQUVkLEVBQUE7SUFFQSxvQkFDSTNNLHNCQUFBLENBQUFDLGFBQUEsQ0FBQzRELGdCQUFHLEVBQUEsSUFBQSxlQUNBN0Qsc0JBQUEsQ0FBQUMsYUFBQSxDQUFBLEtBQUEsRUFBQTtFQUNJb0ssSUFBQUEsR0FBRyxFQUFFMkIsUUFBUztFQUNkMUIsSUFBQUEsR0FBRyxFQUFFaEIsUUFBUztFQUNkdkcsSUFBQUEsS0FBSyxFQUFFO0VBQ0h6RSxNQUFBQSxLQUFLLEVBQUVvRCxJQUFJO0VBQ1huRCxNQUFBQSxNQUFNLEVBQUVtRCxJQUFJO0VBQ1ozRCxNQUFBQSxZQUFZLEVBQUUsS0FBSztFQUNuQndNLE1BQUFBLFNBQVMsRUFBRSxPQUFPO0VBQ2xCek4sTUFBQUEsTUFBTSxFQUFFO09BQ1Y7RUFDRjJOLElBQUFBLE9BQU8sRUFBRUEsTUFBTTBCLFdBQVcsQ0FBQyxJQUFJO0VBQUUsR0FDcEMsQ0FDQSxDQUFDO0VBRWQsQ0FBQzs7RUNuRkQsTUFBTVMsWUFBWSxHQUFJakMsS0FBSyxJQUFLO0lBQzVCLE1BQU07TUFBRUMsTUFBTTtNQUFFZ0IsUUFBUTtFQUFFRyxJQUFBQTtFQUFNLEdBQUMsR0FBR3BCLEtBQUs7SUFDekMsTUFBTTVMLEtBQUssR0FBRzZMLE1BQU0sQ0FBQ0ssTUFBTSxDQUFDVyxRQUFRLENBQUM5SSxJQUFJLENBQUM7SUFFMUMsTUFBTSxDQUFDa0osUUFBUSxFQUFFQyxXQUFXLENBQUMsR0FBRy9GLGNBQVEsQ0FBQyxJQUFJLENBQUM7SUFDOUMsTUFBTSxDQUFDQyxPQUFPLEVBQUVDLFVBQVUsQ0FBQyxHQUFHRixjQUFRLENBQUMsSUFBSSxDQUFDO0VBRTVDSyxFQUFBQSxlQUFTLENBQUMsTUFBTTtNQUNaLElBQUksQ0FBQ3hILEtBQUssRUFBRTtRQUNScUgsVUFBVSxDQUFDLEtBQUssQ0FBQztFQUNqQixNQUFBO0VBQ0osSUFBQTtFQUVBLElBQUEsSUFBSXJILEtBQUssQ0FBQ3FOLFVBQVUsQ0FBQyxTQUFTLENBQUMsSUFBSXJOLEtBQUssQ0FBQ3FOLFVBQVUsQ0FBQyxVQUFVLENBQUMsRUFBRTtRQUM3REgsV0FBVyxDQUFDbE4sS0FBSyxDQUFDO1FBQ2xCcUgsVUFBVSxDQUFDLEtBQUssQ0FBQztFQUNqQixNQUFBO0VBQ0osSUFBQTtFQUVBLElBQUEsTUFBTWlHLGNBQWMsR0FBRyxZQUFZO1FBQy9CLElBQUk7VUFDQSxNQUFNM0YsUUFBUSxHQUFHLE1BQU00RixLQUFLLENBQUMsQ0FBQSwwQkFBQSxFQUE2QkMsa0JBQWtCLENBQUN4TixLQUFLLENBQUMsQ0FBQSxDQUFFLENBQUM7VUFDdEYsSUFBSTJILFFBQVEsQ0FBQzhGLEVBQUUsRUFBRTtFQUNiLFVBQUEsTUFBTW5PLElBQUksR0FBRyxNQUFNcUksUUFBUSxDQUFDK0YsSUFBSSxFQUFFO0VBQ2xDUixVQUFBQSxXQUFXLENBQUM1TixJQUFJLENBQUMyTSxHQUFHLENBQUM7RUFDekIsUUFBQSxDQUFDLE1BQU07RUFDSG5FLFVBQUFBLE9BQU8sQ0FBQ1IsS0FBSyxDQUFDLDZCQUE2QixDQUFDO0VBQ2hELFFBQUE7UUFDSixDQUFDLENBQUMsT0FBT0EsS0FBSyxFQUFFO0VBQ1pRLFFBQUFBLE9BQU8sQ0FBQ1IsS0FBSyxDQUFDLG9DQUFvQyxFQUFFQSxLQUFLLENBQUM7RUFDOUQsTUFBQSxDQUFDLFNBQVM7VUFDTkQsVUFBVSxDQUFDLEtBQUssQ0FBQztFQUNyQixNQUFBO01BQ0osQ0FBQztFQUVEaUcsSUFBQUEsY0FBYyxFQUFFO0VBQ3BCLEVBQUEsQ0FBQyxFQUFFLENBQUN0TixLQUFLLENBQUMsQ0FBQztFQUVYLEVBQUEsSUFBSW9ILE9BQU8sRUFBRSxvQkFBT25HLHNCQUFBLENBQUFDLGFBQUEsQ0FBQzRELGdCQUFHLEVBQUE7RUFBQ2QsSUFBQUEsS0FBSyxFQUFFO0VBQUV2RSxNQUFBQSxLQUFLLEVBQUUsU0FBUztFQUFFMEMsTUFBQUEsUUFBUSxFQUFFO0VBQU87RUFBRSxHQUFBLEVBQUMsWUFBZSxDQUFDO0lBQ3hGLElBQUksQ0FBQzhLLFFBQVEsRUFBRSxvQkFBT2hNLHNCQUFBLENBQUFDLGFBQUEsQ0FBQzRELGdCQUFHLEVBQUE7RUFBQ2QsSUFBQUEsS0FBSyxFQUFFO0VBQUV2RSxNQUFBQSxLQUFLLEVBQUUsTUFBTTtFQUFFMEMsTUFBQUEsUUFBUSxFQUFFO0VBQU87RUFBRSxHQUFBLEVBQUMsS0FBUSxDQUFDO0lBRWhGLE1BQU1RLElBQUksR0FBR3FLLEtBQUssS0FBSyxNQUFNLEdBQUcsTUFBTSxHQUFHLE9BQU87SUFDaEQsTUFBTWMsTUFBTSxHQUFHakIsUUFBUSxDQUFDOUksSUFBSSxLQUFLLGlCQUFpQixHQUFHLEtBQUssR0FBRyxLQUFLO0lBRWxFLG9CQUNJOUMsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDNEQsZ0JBQUcsRUFBQSxJQUFBLGVBQ0E3RCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsS0FBQSxFQUFBO0VBQ0lvSyxJQUFBQSxHQUFHLEVBQUUyQixRQUFTO0VBQ2QxQixJQUFBQSxHQUFHLEVBQUMsU0FBUztFQUNidkgsSUFBQUEsS0FBSyxFQUFFO0VBQ0h6RSxNQUFBQSxLQUFLLEVBQUVvRCxJQUFJO0VBQ1huRCxNQUFBQSxNQUFNLEVBQUVtRCxJQUFJO0VBQ1ozRCxNQUFBQSxZQUFZLEVBQUU4TyxNQUFNO0VBQ3BCdEMsTUFBQUEsU0FBUyxFQUFFLE9BQU87RUFDbEJ6TSxNQUFBQSxlQUFlLEVBQUUsU0FBUztFQUMxQmhCLE1BQUFBLE1BQU0sRUFBRTtFQUNaO0VBQUUsR0FDTCxDQUNBLENBQUM7RUFFZCxDQUFDOztFQzNERCxNQUFNTixHQUFHLEdBQUcsSUFBSUMsaUJBQVMsRUFBRTtFQUUzQixNQUFNcVEsV0FBVyxHQUFJbkMsS0FBSyxJQUFLO0lBQzdCLE1BQU07TUFBRUMsTUFBTTtFQUFFbUMsSUFBQUE7RUFBUyxHQUFDLEdBQUdwQyxLQUFLO0VBQ2xDLEVBQUEsTUFBTXFDLFNBQVMsR0FBR2pDLGlCQUFTLEVBQUU7RUFFN0IsRUFBQSxNQUFNLENBQUNrQyxZQUFZLEVBQUVDLGVBQWUsQ0FBQyxHQUFHaEgsY0FBUSxDQUFDMEUsTUFBTSxDQUFDSyxNQUFNLENBQUNrQyxnQkFBZ0IsSUFBSSxDQUFDLENBQUM7RUFDckYsRUFBQSxNQUFNLENBQUNDLGVBQWUsRUFBRUMsa0JBQWtCLENBQUMsR0FBR25ILGNBQVEsQ0FBQzBFLE1BQU0sQ0FBQ0ssTUFBTSxDQUFDcUMsbUJBQW1CLElBQUksQ0FBQyxDQUFDO0lBQzlGLE1BQU0sQ0FBQ0MsU0FBUyxFQUFFQyxZQUFZLENBQUMsR0FBR3RILGNBQVEsQ0FBQyxLQUFLLENBQUM7SUFFakQsTUFBTXVILFlBQVksR0FBSUMsVUFBVSxJQUFLO01BQ25DLElBQUlBLFVBQVUsS0FBSyxPQUFPLElBQUksQ0FBQ3RDLE1BQU0sQ0FBQ3VDLE9BQU8sQ0FBQywwRUFBMEUsQ0FBQyxFQUFFO0VBQ3ZILE1BQUE7RUFDSixJQUFBO01BRUFILFlBQVksQ0FBQyxJQUFJLENBQUM7TUFFbEJoUixHQUFHLENBQUNvUixjQUFjLENBQUM7UUFDakIxSSxVQUFVLEVBQUU2SCxRQUFRLENBQUMzTSxFQUFFO0VBQ3ZCeU4sTUFBQUEsVUFBVSxFQUFFLGFBQWE7UUFDekJDLFFBQVEsRUFBRWxELE1BQU0sQ0FBQ3hLLEVBQUU7RUFDbkIyTixNQUFBQSxNQUFNLEVBQUUsTUFBTTtFQUNkMVAsTUFBQUEsSUFBSSxFQUFFO0VBQ0pxUCxRQUFBQSxVQUFVLEVBQUVBLFVBQVU7RUFDdEJNLFFBQUFBLGVBQWUsRUFBRWYsWUFBWTtFQUM3QmdCLFFBQUFBLGtCQUFrQixFQUFFYjtFQUN0QjtFQUNGLEtBQUMsQ0FBQyxDQUFDM0csSUFBSSxDQUFDQyxRQUFRLElBQUk7UUFDbEI4RyxZQUFZLENBQUMsS0FBSyxDQUFDO0VBQ25CLE1BQUEsSUFBSTlHLFFBQVEsQ0FBQ3JJLElBQUksQ0FBQzZQLE1BQU0sRUFBRTtFQUN4QmxCLFFBQUFBLFNBQVMsQ0FBQ3RHLFFBQVEsQ0FBQ3JJLElBQUksQ0FBQzZQLE1BQU0sQ0FBQztFQUNqQyxNQUFBO0VBQ0EsTUFBQSxJQUFJeEgsUUFBUSxDQUFDckksSUFBSSxDQUFDNk0sV0FBVyxFQUFFO1VBQzVCRSxNQUFNLENBQUMrQyxRQUFRLENBQUNoSixJQUFJLEdBQUd1QixRQUFRLENBQUNySSxJQUFJLENBQUM2TSxXQUFXO0VBQ25ELE1BQUE7RUFDRixJQUFBLENBQUMsQ0FBQyxDQUFDdkUsS0FBSyxDQUFDTixLQUFLLElBQUk7UUFDaEJtSCxZQUFZLENBQUMsS0FBSyxDQUFDO0VBQ25CUixNQUFBQSxTQUFTLENBQUM7RUFBRTFCLFFBQUFBLE9BQU8sRUFBRSxnREFBZ0Q7RUFBRUMsUUFBQUEsSUFBSSxFQUFFO0VBQVEsT0FBQyxDQUFDO0VBQ3pGLElBQUEsQ0FBQyxDQUFDO0lBQ0osQ0FBQztFQUVELEVBQUEsb0JBQ0V2TCxzQkFBQSxDQUFBQyxhQUFBLENBQUM0RCxnQkFBRyxFQUFBO0VBQUM2SCxJQUFBQSxPQUFPLEVBQUMsT0FBTztFQUFDak0sSUFBQUEsQ0FBQyxFQUFDLElBQUk7RUFBQ3NELElBQUFBLEtBQUssRUFBRTtFQUFFakYsTUFBQUEsZUFBZSxFQUFFLFNBQVM7RUFBRUMsTUFBQUEsWUFBWSxFQUFFLEtBQUs7RUFBRWpCLE1BQUFBLE1BQU0sRUFBRTtFQUFpQjtFQUFFLEdBQUEsZUFFL0drRCxzQkFBQSxDQUFBQyxhQUFBLENBQUNtTyxlQUFFLEVBQUE7RUFBQ3JMLElBQUFBLEtBQUssRUFBRTtFQUFFdkUsTUFBQUEsS0FBSyxFQUFFLFNBQVM7RUFBRWdHLE1BQUFBLFlBQVksRUFBRTtFQUFPO0VBQUUsR0FBQSxFQUFDLG9CQUFrQixFQUFDb0csTUFBTSxDQUFDSyxNQUFNLENBQUNuSSxJQUFTLENBQUMsZUFFbEc5QyxzQkFBQSxDQUFBQyxhQUFBLENBQUNvTyxzQkFBUyxFQUFBO0VBQUN0TCxJQUFBQSxLQUFLLEVBQUU7RUFBRXlCLE1BQUFBLFlBQVksRUFBRTtFQUFPO0VBQUUsR0FBQSxlQUN6Q3hFLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxRQUFBLEVBQUEsSUFBQSxFQUFRLGlCQUF1QixDQUFDLGVBQUFELHNCQUFBLENBQUFDLGFBQUEsV0FBSSxDQUFDLEVBQUEsaUJBQ3RCLGVBQUFELHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxNQUFBLEVBQUE7RUFBTThDLElBQUFBLEtBQUssRUFBRTtFQUFFdkUsTUFBQUEsS0FBSyxFQUFFLFNBQVM7RUFBRTZFLE1BQUFBLFVBQVUsRUFBRTtFQUFPO0VBQUUsR0FBQSxFQUFFdUgsTUFBTSxDQUFDSyxNQUFNLENBQUNrQyxnQkFBZ0IsSUFBSSxDQUFRLENBQUMsZUFBQW5OLHNCQUFBLENBQUFDLGFBQUEsQ0FBQSxJQUFBLEVBQUEsSUFBSSxDQUFDLHVCQUNwRyxlQUFBRCxzQkFBQSxDQUFBQyxhQUFBLENBQUEsTUFBQSxFQUFBO0VBQU04QyxJQUFBQSxLQUFLLEVBQUU7RUFBRXZFLE1BQUFBLEtBQUssRUFBRSxTQUFTO0VBQUU2RSxNQUFBQSxVQUFVLEVBQUU7RUFBTztFQUFFLEdBQUEsRUFBRXVILE1BQU0sQ0FBQ0ssTUFBTSxDQUFDcUMsbUJBQW1CLElBQUksQ0FBUSxDQUMvRyxDQUFDLGVBRVp0TixzQkFBQSxDQUFBQyxhQUFBLENBQUM0RCxnQkFBRyxFQUFBO0VBQUN5SyxJQUFBQSxFQUFFLEVBQUMsS0FBSztFQUFDN08sSUFBQUEsQ0FBQyxFQUFDLElBQUk7RUFBQ3NELElBQUFBLEtBQUssRUFBRTtFQUFFakcsTUFBQUEsTUFBTSxFQUFFLGdCQUFnQjtFQUFFaUIsTUFBQUEsWUFBWSxFQUFFLEtBQUs7RUFBRUQsTUFBQUEsZUFBZSxFQUFFO0VBQVU7RUFBRSxHQUFBLGVBQ3hHa0Msc0JBQUEsQ0FBQUMsYUFBQSxDQUFDbU8sZUFBRSxFQUFBO0VBQUNyTCxJQUFBQSxLQUFLLEVBQUU7RUFBRXZFLE1BQUFBLEtBQUssRUFBRSxTQUFTO0VBQUUwQyxNQUFBQSxRQUFRLEVBQUU7RUFBUTtFQUFFLEdBQUEsRUFBQywyQkFBNkIsQ0FBQyxlQUNsRmxCLHNCQUFBLENBQUFDLGFBQUEsQ0FBQ3lFLGlCQUFJLEVBQUE7RUFBQzNCLElBQUFBLEtBQUssRUFBRTtFQUFFdkUsTUFBQUEsS0FBSyxFQUFFLFNBQVM7RUFBRWdHLE1BQUFBLFlBQVksRUFBRTtFQUFPO0VBQUUsR0FBQSxFQUFDLHdKQUVuRCxDQUFDLGVBQ1B4RSxzQkFBQSxDQUFBQyxhQUFBLENBQUNzTyxtQkFBTSxFQUFBO0VBQ0g3QyxJQUFBQSxPQUFPLEVBQUMsUUFBUTtFQUNoQjhDLElBQUFBLE9BQU8sRUFBRUEsTUFBTWYsWUFBWSxDQUFDLE9BQU8sQ0FBRTtFQUNyQ2dCLElBQUFBLFFBQVEsRUFBRWxCO0VBQVUsR0FBQSxFQUVyQkEsU0FBUyxHQUFHLGVBQWUsR0FBRyx5QkFDekIsQ0FDTCxDQUFDLGVBRU52TixzQkFBQSxDQUFBQyxhQUFBLENBQUM0RCxnQkFBRyxFQUFBO0VBQUNwRSxJQUFBQSxDQUFDLEVBQUMsSUFBSTtFQUFDc0QsSUFBQUEsS0FBSyxFQUFFO0VBQUVqRyxNQUFBQSxNQUFNLEVBQUUsZ0JBQWdCO0VBQUVpQixNQUFBQSxZQUFZLEVBQUUsS0FBSztFQUFFRCxNQUFBQSxlQUFlLEVBQUU7RUFBVTtFQUFFLEdBQUEsZUFDL0ZrQyxzQkFBQSxDQUFBQyxhQUFBLENBQUNtTyxlQUFFLEVBQUE7RUFBQ3JMLElBQUFBLEtBQUssRUFBRTtFQUFFdkUsTUFBQUEsS0FBSyxFQUFFLFNBQVM7RUFBRTBDLE1BQUFBLFFBQVEsRUFBRTtFQUFRO0VBQUUsR0FBQSxFQUFDLG9DQUFzQyxDQUFDLGVBQzNGbEIsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDeUUsaUJBQUksRUFBQTtFQUFDM0IsSUFBQUEsS0FBSyxFQUFFO0VBQUV2RSxNQUFBQSxLQUFLLEVBQUUsU0FBUztFQUFFZ0csTUFBQUEsWUFBWSxFQUFFLE1BQU07RUFBRXRELE1BQUFBLFFBQVEsRUFBRTtFQUFRO0VBQUUsR0FBQSxFQUFDLHVKQUV0RSxDQUFDLGVBRVBsQixzQkFBQSxDQUFBQyxhQUFBLENBQUM0RCxnQkFBRyxFQUFBO01BQUNDLElBQUksRUFBQSxJQUFBO0VBQUNmLElBQUFBLEtBQUssRUFBRTtFQUFFRyxNQUFBQSxHQUFHLEVBQUUsTUFBTTtFQUFFc0IsTUFBQUEsWUFBWSxFQUFFO0VBQU87RUFBRSxHQUFBLGVBQ25EeEUsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDeU8sc0JBQVMsRUFBQTtFQUFDM0wsSUFBQUEsS0FBSyxFQUFFO0VBQUVlLE1BQUFBLElBQUksRUFBRTtFQUFFO0VBQUUsR0FBQSxlQUMxQjlELHNCQUFBLENBQUFDLGFBQUEsQ0FBQzBPLGtCQUFLLEVBQUE7RUFBQzVMLElBQUFBLEtBQUssRUFBRTtFQUFFdkUsTUFBQUEsS0FBSyxFQUFFO0VBQVU7RUFBRSxHQUFBLEVBQUMseUJBQTRCLENBQUMsZUFDakV3QixzQkFBQSxDQUFBQyxhQUFBLENBQUMyTyxrQkFBSyxFQUFBO0VBQ0ZyRCxJQUFBQSxJQUFJLEVBQUMsUUFBUTtFQUNieE0sSUFBQUEsS0FBSyxFQUFFa08sWUFBYTtNQUNwQjRCLFFBQVEsRUFBRzVLLENBQUMsSUFBS2lKLGVBQWUsQ0FBQ2pKLENBQUMsQ0FBQ3NFLE1BQU0sQ0FBQ3hKLEtBQUssQ0FBRTtFQUNqRGdFLElBQUFBLEtBQUssRUFBRTtFQUFFakYsTUFBQUEsZUFBZSxFQUFFLFNBQVM7RUFBRVUsTUFBQUEsS0FBSyxFQUFFLE9BQU87RUFBRTFCLE1BQUFBLE1BQU0sRUFBRTtFQUFpQjtFQUFFLEdBQ25GLENBQ00sQ0FBQyxlQUVaa0Qsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDeU8sc0JBQVMsRUFBQTtFQUFDM0wsSUFBQUEsS0FBSyxFQUFFO0VBQUVlLE1BQUFBLElBQUksRUFBRTtFQUFFO0VBQUUsR0FBQSxlQUMxQjlELHNCQUFBLENBQUFDLGFBQUEsQ0FBQzBPLGtCQUFLLEVBQUE7RUFBQzVMLElBQUFBLEtBQUssRUFBRTtFQUFFdkUsTUFBQUEsS0FBSyxFQUFFO0VBQVU7RUFBRSxHQUFBLEVBQUMsNkJBQWdDLENBQUMsZUFDckV3QixzQkFBQSxDQUFBQyxhQUFBLENBQUMyTyxrQkFBSyxFQUFBO0VBQ0ZyRCxJQUFBQSxJQUFJLEVBQUMsUUFBUTtFQUNieE0sSUFBQUEsS0FBSyxFQUFFcU8sZUFBZ0I7TUFDdkJ5QixRQUFRLEVBQUc1SyxDQUFDLElBQUtvSixrQkFBa0IsQ0FBQ3BKLENBQUMsQ0FBQ3NFLE1BQU0sQ0FBQ3hKLEtBQUssQ0FBRTtFQUNwRGdFLElBQUFBLEtBQUssRUFBRTtFQUFFakYsTUFBQUEsZUFBZSxFQUFFLFNBQVM7RUFBRVUsTUFBQUEsS0FBSyxFQUFFLE9BQU87RUFBRTFCLE1BQUFBLE1BQU0sRUFBRTtFQUFpQjtLQUNqRixDQUNNLENBQ1YsQ0FBQyxlQUVOa0Qsc0JBQUEsQ0FBQUMsYUFBQSxDQUFDc08sbUJBQU0sRUFBQTtFQUNIN0MsSUFBQUEsT0FBTyxFQUFDLFNBQVM7RUFDakI4QyxJQUFBQSxPQUFPLEVBQUVBLE1BQU1mLFlBQVksQ0FBQyxVQUFVLENBQUU7RUFDeENnQixJQUFBQSxRQUFRLEVBQUVsQixTQUFVO0VBQ3BCeEssSUFBQUEsS0FBSyxFQUFFO0VBQUVqRixNQUFBQSxlQUFlLEVBQUUsU0FBUztFQUFFVSxNQUFBQSxLQUFLLEVBQUUsT0FBTztFQUFFMUIsTUFBQUEsTUFBTSxFQUFFO0VBQU87RUFBRSxHQUFBLEVBRXZFeVEsU0FBUyxHQUFHLGVBQWUsR0FBRyx1QkFDekIsQ0FDTCxDQUVGLENBQUM7RUFFVixDQUFDOztFQzlHRHVCLE9BQU8sQ0FBQ0MsY0FBYyxHQUFHLEVBQUU7RUFDM0JELE9BQU8sQ0FBQ0UsR0FBRyxDQUFDQyxRQUFRLEdBQUcsWUFBWTtFQUVuQ0gsT0FBTyxDQUFDQyxjQUFjLENBQUNHLFNBQVMsR0FBR0EsZUFBUztFQUU1Q0osT0FBTyxDQUFDQyxjQUFjLENBQUMvRSxlQUFlLEdBQUdBLGVBQWU7RUFFeEQ4RSxPQUFPLENBQUNDLGNBQWMsQ0FBQ3JFLGNBQWMsR0FBR0EsY0FBYztFQUV0RG9FLE9BQU8sQ0FBQ0MsY0FBYyxDQUFDcEQsWUFBWSxHQUFHQSxZQUFZO0VBRWxEbUQsT0FBTyxDQUFDQyxjQUFjLENBQUNqRCxVQUFVLEdBQUdBLFVBQVU7RUFFOUNnRCxPQUFPLENBQUNDLGNBQWMsQ0FBQ25DLFlBQVksR0FBR0EsWUFBWTtFQUVsRGtDLE9BQU8sQ0FBQ0MsY0FBYyxDQUFDakMsV0FBVyxHQUFHQSxXQUFXOzs7Ozs7In0=
