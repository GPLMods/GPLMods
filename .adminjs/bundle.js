(function (React, adminjs, designSystem) {
  'use strict';

  function _interopDefault (e) { return e && e.__esModule ? e : { default: e }; }

  var React__default = /*#__PURE__*/_interopDefault(React);

  const api = new adminjs.ApiClient();

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
    textMuted: '#e2e8f0',
    textDim: '#cbd5e1'
  };

  /* ─── platform chart colours ─── */
  const PLATFORM_COLORS = ['#A4C639', '#0078D6', '#21759B', '#FF9800', '#9C27B0', '#e53935', '#43a047', '#FFD700'];

  /* ─── reusable card style ─── */
  const cardStyle = accentColor => ({
    backgroundColor: C.surface,
    borderRadius: '16px',
    border: `1px solid ${C.border}`,
    borderLeft: accentColor ? `4px solid ${accentColor}` : `1px solid ${C.border}`,
    padding: 'clamp(16px, 2.5vw, 24px)',
    transition: 'all 0.25s ease',
    cursor: 'default',
    boxSizing: 'border-box'
  });

  /* ─── Inline SVG Area Chart ─── */
  const AreaChart = ({
    data,
    width = 500,
    height = 170,
    color = C.gold
  }) => {
    if (!data || data.length === 0) return null;
    const maxVal = Math.max(...data.map(d => d.value), 1);
    const padX = 35;
    const padY = 16;
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
    const step = data.length > 8 ? Math.ceil(data.length / 5) : 1;
    return /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        width: '100%',
        overflow: 'hidden'
      }
    }, /*#__PURE__*/React__default.default.createElement("svg", {
      width: "100%",
      height: height,
      viewBox: `0 0 ${width} ${height}`,
      preserveAspectRatio: "none",
      style: {
        display: 'block',
        maxWidth: '100%'
      }
    }, /*#__PURE__*/React__default.default.createElement("defs", null, /*#__PURE__*/React__default.default.createElement("linearGradient", {
      id: "areaFill",
      x1: "0",
      y1: "0",
      x2: "0",
      y2: "1"
    }, /*#__PURE__*/React__default.default.createElement("stop", {
      offset: "0%",
      stopColor: color,
      stopOpacity: "0.35"
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
      strokeDasharray: "3 3"
    }), /*#__PURE__*/React__default.default.createElement("text", {
      x: padX - 6,
      y: g.y + 4,
      fill: "#94a3b8",
      fontSize: "9",
      fontFamily: "'Poppins', sans-serif",
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
    }), points.map((p, i) => {
      const showLabel = i === 0 || i === data.length - 1 || i % step === 0;
      return /*#__PURE__*/React__default.default.createElement("g", {
        key: i
      }, /*#__PURE__*/React__default.default.createElement("circle", {
        cx: p.x,
        cy: p.y,
        r: "3",
        fill: C.bg,
        stroke: color,
        strokeWidth: "2"
      }), showLabel && /*#__PURE__*/React__default.default.createElement("text", {
        x: p.x,
        y: padY + chartH + 14,
        fill: "#cbd5e1",
        fontSize: "9",
        fontFamily: "'Poppins', sans-serif",
        textAnchor: "middle"
      }, data[i].label));
    })));
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
      api.getDashboard().then(response => {
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
        padding: 'clamp(16px, 3vw, 32px) clamp(14px, 3vw, 36px)',
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
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '10px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.H2, {
      style: {
        margin: 0,
        display: 'inline-flex',
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
        color: '#ffffff',
        textShadow: '0 0 15px rgba(255, 255, 255, 0.4)',
        fontWeight: 700
      }
    }, "Mods")), /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: '#ffd700',
        fontSize: '11px',
        fontWeight: 600,
        background: 'rgba(255, 215, 0, 0.12)',
        padding: '4px 10px',
        borderRadius: '20px',
        border: '1px solid rgba(255, 215, 0, 0.35)',
        fontFamily: "'Poppins', sans-serif",
        letterSpacing: '0.04em',
        textTransform: 'uppercase'
      }
    }, "Admin Dashboard"))), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#f1f5f9',
        marginTop: '8px',
        fontSize: '14px',
        fontWeight: 400,
        fontFamily: "'Poppins', sans-serif",
        lineHeight: 1.5
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
        color: '#ffffff',
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
        e.currentTarget.style.color = '#ffffff';
      },
      title: "Open Live Public Site"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Globe",
      size: 14
    }), " Live Site"))), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '16px',
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
        gap: '14px',
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
        flex: '2 1 320px',
        minWidth: 0,
        width: '100%'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '18px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Activity",
      color: C.gold
    }), /*#__PURE__*/React__default.default.createElement(designSystem.H5, {
      style: {
        color: C.text,
        margin: 0,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "User Growth"), /*#__PURE__*/React__default.default.createElement(designSystem.Badge, {
      style: {
        marginLeft: '8px',
        backgroundColor: C.goldDim,
        color: C.gold,
        border: 'none',
        fontFamily: "'Poppins', sans-serif"
      }
    }, "30 days")), growthChartData.length > 0 ? /*#__PURE__*/React__default.default.createElement(AreaChart, {
      data: growthChartData,
      color: C.gold,
      width: 500,
      height: 170
    }) : /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        height: 160,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textDim,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "No user signups in the last 30 days."))), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      style: {
        ...cardStyle(),
        flex: '1 1 280px',
        minWidth: 0,
        width: '100%'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '18px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "PieChart",
      color: C.blue
    }), /*#__PURE__*/React__default.default.createElement(designSystem.H5, {
      style: {
        color: C.text,
        margin: 0,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "Mods by Platform")), modsByPlatform.length > 0 ? /*#__PURE__*/React__default.default.createElement(DonutChart, {
      data: modsByPlatform,
      size: 180
    }) : /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        height: 160,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textDim,
        fontFamily: "'Poppins', sans-serif"
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
        flex: '1 1 320px',
        minWidth: 0,
        width: '100%'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '18px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Users",
      color: C.blue
    }), /*#__PURE__*/React__default.default.createElement(designSystem.H5, {
      style: {
        color: C.text,
        margin: 0,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "Recent Users"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/User",
      style: {
        marginLeft: 'auto',
        color: C.gold,
        fontSize: '12px',
        textDecoration: 'none',
        fontWeight: 600,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "View All \u2192")), recentUsers.length > 0 ? /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        overflowX: 'auto',
        width: '100%',
        WebkitOverflowScrolling: 'touch'
      }
    }, /*#__PURE__*/React__default.default.createElement("table", {
      style: {
        width: '100%',
        borderCollapse: 'collapse',
        minWidth: '300px'
      }
    }, /*#__PURE__*/React__default.default.createElement("thead", null, /*#__PURE__*/React__default.default.createElement("tr", {
      style: {
        borderBottom: `1px solid ${C.border}`
      }
    }, /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'left',
        padding: '8px 0',
        color: '#94a3b8',
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Username"), /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'left',
        padding: '8px 0',
        color: '#94a3b8',
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Role"), /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'right',
        padding: '8px 0',
        color: '#94a3b8',
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
    }, fmtDate(u.date))))))) : /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textDim,
        textAlign: 'center',
        padding: '20px 0'
      }
    }, "No recent users.")), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      style: {
        ...cardStyle(),
        flex: '1 1 320px',
        minWidth: 0,
        width: '100%'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '18px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Package",
      color: C.gold
    }), /*#__PURE__*/React__default.default.createElement(designSystem.H5, {
      style: {
        color: C.text,
        margin: 0,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "Recent Mods"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/File",
      style: {
        marginLeft: 'auto',
        color: C.gold,
        fontSize: '12px',
        textDecoration: 'none',
        fontWeight: 600,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "View All \u2192")), recentMods.length > 0 ? /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        overflowX: 'auto',
        width: '100%',
        WebkitOverflowScrolling: 'touch'
      }
    }, /*#__PURE__*/React__default.default.createElement("table", {
      style: {
        width: '100%',
        borderCollapse: 'collapse',
        minWidth: '300px'
      }
    }, /*#__PURE__*/React__default.default.createElement("thead", null, /*#__PURE__*/React__default.default.createElement("tr", {
      style: {
        borderBottom: `1px solid ${C.border}`
      }
    }, /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'left',
        padding: '8px 0',
        color: '#94a3b8',
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Name"), /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'left',
        padding: '8px 0',
        color: '#94a3b8',
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Platform"), /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'left',
        padding: '8px 0',
        color: '#94a3b8',
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        fontWeight: 600
      }
    }, "Status"), /*#__PURE__*/React__default.default.createElement("th", {
      style: {
        textAlign: 'right',
        padding: '8px 0',
        color: '#94a3b8',
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
    }, fmtDate(m.date))))))) : /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: C.textDim,
        textAlign: 'center',
        padding: '20px 0'
      }
    }, "No recent mods."))), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '14px',
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
        color: '#ffffff',
        fontSize: '13px',
        cursor: 'pointer',
        fontFamily: "'Poppins', sans-serif"
      }
    }, /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: C.gold,
        fontWeight: 700
      }
    }, "GPL"), " ", /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: '#ffffff',
        fontWeight: 600
      }
    }, "Mods"), " \u2022 Admin Panel v2.5")), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '8px'
      }
    }, /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/User",
      style: {
        color: '#ffffff',
        backgroundColor: 'rgba(255,255,255,0.06)',
        border: '1px solid rgba(255,255,255,0.1)',
        padding: '5px 12px',
        borderRadius: '8px',
        fontSize: '12px',
        textDecoration: 'none',
        fontWeight: 500,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "Users"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/File",
      style: {
        color: '#ffffff',
        backgroundColor: 'rgba(255,255,255,0.06)',
        border: '1px solid rgba(255,255,255,0.1)',
        padding: '5px 12px',
        borderRadius: '8px',
        fontSize: '12px',
        textDecoration: 'none',
        fontWeight: 500,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "Mods"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/Report",
      style: {
        color: '#ffffff',
        backgroundColor: 'rgba(255,255,255,0.06)',
        border: '1px solid rgba(255,255,255,0.1)',
        padding: '5px 12px',
        borderRadius: '8px',
        fontSize: '12px',
        textDecoration: 'none',
        fontWeight: 500,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "Reports"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/resources/SupportTicket",
      style: {
        color: '#ffffff',
        backgroundColor: 'rgba(255,255,255,0.06)',
        border: '1px solid rgba(255,255,255,0.1)',
        padding: '5px 12px',
        borderRadius: '8px',
        fontSize: '12px',
        textDecoration: 'none',
        fontWeight: 500,
        fontFamily: "'Poppins', sans-serif"
      }
    }, "Tickets"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/music",
      style: {
        color: '#ffffff',
        backgroundColor: 'rgba(255,255,255,0.06)',
        border: '1px solid rgba(255,255,255,0.1)',
        padding: '5px 12px',
        borderRadius: '8px',
        fontSize: '12px',
        textDecoration: 'none',
        fontWeight: 500,
        fontFamily: "'Poppins', sans-serif"
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
    if (!record || !record.params || !property) return null;
    const isVariant = record.params[property.name];
    if (isVariant === true || isVariant === 'true') {
      return /*#__PURE__*/React__default.default.createElement("span", {
        className: "admin-custom-chip",
        "data-badge-val": "variant-child",
        style: {
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '3px 10px',
          borderRadius: '20px',
          fontSize: '11px',
          fontWeight: 700,
          letterSpacing: '0.06em',
          textTransform: 'uppercase',
          background: 'linear-gradient(145deg, rgba(186, 104, 200, 0.22) 0%, rgba(65, 25, 75, 0.25) 100%)',
          color: '#ce93d8',
          border: '1px solid rgba(186, 104, 200, 0.6)',
          boxShadow: 'inset 0 1.5px 2px rgba(255, 255, 255, 0.2), inset 0 -1.5px 2px rgba(0, 0, 0, 0.8), 0 0 10px rgba(186, 104, 200, 0.25)',
          textShadow: '0 0 6px rgba(206, 147, 216, 0.4)',
          fontFamily: "'Poppins', sans-serif"
        }
      }, "Variant");
    }
    return /*#__PURE__*/React__default.default.createElement("span", {
      className: "admin-custom-chip",
      "data-badge-val": "variant-master",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: '3px 10px',
        borderRadius: '20px',
        fontSize: '11px',
        fontWeight: 700,
        letterSpacing: '0.06em',
        textTransform: 'uppercase',
        background: 'linear-gradient(145deg, rgba(255, 215, 0, 0.22) 0%, rgba(90, 70, 15, 0.25) 100%)',
        color: '#FFD700',
        border: '1px solid rgba(255, 215, 0, 0.65)',
        boxShadow: 'inset 0 1.5px 2px rgba(255, 255, 255, 0.22), inset 0 -1.5px 2px rgba(0, 0, 0, 0.8), 0 0 10px rgba(255, 215, 0, 0.25)',
        textShadow: '0 0 6px rgba(255, 215, 0, 0.4)',
        fontFamily: "'Poppins', sans-serif"
      }
    }, "Master");
  };

  const AvatarCell = props => {
    const {
      record,
      property,
      where
    } = props;
    if (!record || !record.params || !property) return null;
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
    const defaultAvatar = '/images/default-avatar.png';
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, null, /*#__PURE__*/React__default.default.createElement("img", {
      src: !imageUrl || hasError ? defaultAvatar : imageUrl,
      alt: username,
      style: {
        width: size,
        height: size,
        borderRadius: '50%',
        objectFit: 'cover',
        border: '2px solid #FFD700',
        backgroundColor: '#1a1a1a'
      },
      onError: e => {
        if (e.currentTarget.src !== defaultAvatar) {
          e.currentTarget.src = defaultAvatar;
        }
      }
    }));
  };

  const ImagePreview = props => {
    const {
      record,
      property,
      where
    } = props;
    if (!record || !record.params || !property) return null;
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
    const isAvatar = property.name === 'profileImageKey' || property.name === 'cardAvatarUrl' || property.name === 'avatar';
    const defaultImage = isAvatar ? '/images/default-avatar.png' : '/images/default-app-icon.png';
    const displayUrl = imageUrl || defaultImage;
    const size = where === 'list' ? '40px' : '150px';
    const radius = isAvatar ? '50%' : '8px';
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, null, /*#__PURE__*/React__default.default.createElement("img", {
      src: displayUrl,
      alt: "Preview",
      style: {
        width: size,
        height: size,
        borderRadius: radius,
        objectFit: 'cover',
        backgroundColor: '#1a1a1a',
        border: '1px solid #333'
      },
      onError: e => {
        if (e.currentTarget.src !== defaultImage) {
          e.currentTarget.src = defaultImage;
        }
      }
    }));
  };

  AdminJS.UserComponents = {};
  AdminJS.env.NODE_ENV = "production";
  AdminJS.UserComponents.Dashboard = CustomDashboard;
  AdminJS.UserComponents.SidebarBranding = SidebarBranding;
  AdminJS.UserComponents.ActionRedirect = ActionRedirect;
  AdminJS.UserComponents.VariantBadge = VariantBadge;
  AdminJS.UserComponents.AvatarCell = AvatarCell;
  AdminJS.UserComponents.ImagePreview = ImagePreview;

})(React, AdminJS, AdminJSDesignSystem);
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIiwic291cmNlcyI6WyIuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQuanN4IiwiLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nLmpzeCIsIi4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdC5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL1ZhcmlhbnRCYWRnZS5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL0F2YXRhckNlbGwuanN4IiwiLi4vY29tcG9uZW50cy9jZWxscy9JbWFnZVByZXZpZXcuanN4IiwiZW50cnkuanMiXSwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlLCB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBBcGlDbGllbnQgfSBmcm9tICdhZG1pbmpzJztcbmltcG9ydCB7IEJveCwgSDIsIEg1LCBUZXh0LCBJY29uLCBCYWRnZSB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuXG5jb25zdCBhcGkgPSBuZXcgQXBpQ2xpZW50KCk7XG5cbi8qIOKUgOKUgOKUgCBjb2xvdXIgdG9rZW5zIOKUgOKUgOKUgCAqL1xuY29uc3QgQyA9IHtcbiAgYmc6ICcjMGEwYTBhJywgc3VyZmFjZTogJyMxMzEzMTMnLCBzdXJmYWNlQWx0OiAnIzFhMWExYScsXG4gIGJvcmRlcjogJyMyYTJhMmEnLCBib3JkZXJIb3ZlcjogJyMzYTNhM2EnLFxuICBnb2xkOiAnI0ZGRDcwMCcsIGdvbGREaW06ICdyZ2JhKDI1NSwyMTUsMCwwLjE1KScsIGdvbGRHbG93OiAncmdiYSgyNTUsMjE1LDAsMC4zNSknLFxuICBibHVlOiAnIzIxOTZGMycsIGdyZWVuOiAnIzQzYTA0NycsIHB1cnBsZTogJyM5QzI3QjAnLCByZWQ6ICcjZTUzOTM1Jywgb3JhbmdlOiAnI0ZGOTgwMCcsXG4gIHRleHQ6ICcjZmZmZmZmJywgdGV4dE11dGVkOiAnI2UyZThmMCcsIHRleHREaW06ICcjY2JkNWUxJyxcbn07XG5cbi8qIOKUgOKUgOKUgCBwbGF0Zm9ybSBjaGFydCBjb2xvdXJzIOKUgOKUgOKUgCAqL1xuY29uc3QgUExBVEZPUk1fQ09MT1JTID0gWycjQTRDNjM5JywgJyMwMDc4RDYnLCAnIzIxNzU5QicsICcjRkY5ODAwJywgJyM5QzI3QjAnLCAnI2U1MzkzNScsICcjNDNhMDQ3JywgJyNGRkQ3MDAnXTtcblxuLyog4pSA4pSA4pSAIHJldXNhYmxlIGNhcmQgc3R5bGUg4pSA4pSA4pSAICovXG5jb25zdCBjYXJkU3R5bGUgPSAoYWNjZW50Q29sb3IpID0+ICh7XG4gIGJhY2tncm91bmRDb2xvcjogQy5zdXJmYWNlLFxuICBib3JkZXJSYWRpdXM6ICcxNnB4JyxcbiAgYm9yZGVyOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCxcbiAgYm9yZGVyTGVmdDogYWNjZW50Q29sb3IgPyBgNHB4IHNvbGlkICR7YWNjZW50Q29sb3J9YCA6IGAxcHggc29saWQgJHtDLmJvcmRlcn1gLFxuICBwYWRkaW5nOiAnY2xhbXAoMTZweCwgMi41dncsIDI0cHgpJyxcbiAgdHJhbnNpdGlvbjogJ2FsbCAwLjI1cyBlYXNlJyxcbiAgY3Vyc29yOiAnZGVmYXVsdCcsXG4gIGJveFNpemluZzogJ2JvcmRlci1ib3gnLFxufSk7XG5cbi8qIOKUgOKUgOKUgCBJbmxpbmUgU1ZHIEFyZWEgQ2hhcnQg4pSA4pSA4pSAICovXG5jb25zdCBBcmVhQ2hhcnQgPSAoeyBkYXRhLCB3aWR0aCA9IDUwMCwgaGVpZ2h0ID0gMTcwLCBjb2xvciA9IEMuZ29sZCB9KSA9PiB7XG4gIGlmICghZGF0YSB8fCBkYXRhLmxlbmd0aCA9PT0gMCkgcmV0dXJuIG51bGw7XG4gIGNvbnN0IG1heFZhbCA9IE1hdGgubWF4KC4uLmRhdGEubWFwKGQgPT4gZC52YWx1ZSksIDEpO1xuICBjb25zdCBwYWRYID0gMzU7XG4gIGNvbnN0IHBhZFkgPSAxNjtcbiAgY29uc3QgY2hhcnRXID0gd2lkdGggLSBwYWRYICogMjtcbiAgY29uc3QgY2hhcnRIID0gaGVpZ2h0IC0gcGFkWSAqIDI7XG5cbiAgY29uc3QgcG9pbnRzID0gZGF0YS5tYXAoKGQsIGkpID0+ICh7XG4gICAgeDogcGFkWCArIChpIC8gTWF0aC5tYXgoZGF0YS5sZW5ndGggLSAxLCAxKSkgKiBjaGFydFcsXG4gICAgeTogcGFkWSArIGNoYXJ0SCAtIChkLnZhbHVlIC8gbWF4VmFsKSAqIGNoYXJ0SCxcbiAgfSkpO1xuXG4gIGNvbnN0IGxpbmVQYXRoID0gcG9pbnRzLm1hcCgocCwgaSkgPT4gYCR7aSA9PT0gMCA/ICdNJyA6ICdMJ30ke3AueH0sJHtwLnl9YCkuam9pbignICcpO1xuICBjb25zdCBhcmVhUGF0aCA9IGAke2xpbmVQYXRofSBMJHtwb2ludHNbcG9pbnRzLmxlbmd0aCAtIDFdLnh9LCR7cGFkWSArIGNoYXJ0SH0gTCR7cG9pbnRzWzBdLnh9LCR7cGFkWSArIGNoYXJ0SH0gWmA7XG5cbiAgLy8gR3JpZCBsaW5lc1xuICBjb25zdCBncmlkTGluZXMgPSBbMCwgMC4yNSwgMC41LCAwLjc1LCAxXS5tYXAocGN0ID0+IHtcbiAgICBjb25zdCB5ID0gcGFkWSArIGNoYXJ0SCAtIHBjdCAqIGNoYXJ0SDtcbiAgICBjb25zdCBsYWJlbCA9IE1hdGgucm91bmQocGN0ICogbWF4VmFsKTtcbiAgICByZXR1cm4geyB5LCBsYWJlbCB9O1xuICB9KTtcblxuICBjb25zdCBzdGVwID0gZGF0YS5sZW5ndGggPiA4ID8gTWF0aC5jZWlsKGRhdGEubGVuZ3RoIC8gNSkgOiAxO1xuXG4gIHJldHVybiAoXG4gICAgPGRpdiBzdHlsZT17eyB3aWR0aDogJzEwMCUnLCBvdmVyZmxvdzogJ2hpZGRlbicgfX0+XG4gICAgICA8c3ZnIHdpZHRoPVwiMTAwJVwiIGhlaWdodD17aGVpZ2h0fSB2aWV3Qm94PXtgMCAwICR7d2lkdGh9ICR7aGVpZ2h0fWB9IHByZXNlcnZlQXNwZWN0UmF0aW89XCJub25lXCIgc3R5bGU9e3sgZGlzcGxheTogJ2Jsb2NrJywgbWF4V2lkdGg6ICcxMDAlJyB9fT5cbiAgICAgICAgPGRlZnM+XG4gICAgICAgICAgPGxpbmVhckdyYWRpZW50IGlkPVwiYXJlYUZpbGxcIiB4MT1cIjBcIiB5MT1cIjBcIiB4Mj1cIjBcIiB5Mj1cIjFcIj5cbiAgICAgICAgICAgIDxzdG9wIG9mZnNldD1cIjAlXCIgc3RvcENvbG9yPXtjb2xvcn0gc3RvcE9wYWNpdHk9XCIwLjM1XCIgLz5cbiAgICAgICAgICAgIDxzdG9wIG9mZnNldD1cIjEwMCVcIiBzdG9wQ29sb3I9e2NvbG9yfSBzdG9wT3BhY2l0eT1cIjAuMDJcIiAvPlxuICAgICAgICAgIDwvbGluZWFyR3JhZGllbnQ+XG4gICAgICAgIDwvZGVmcz5cbiAgICAgICAgey8qIEdyaWQgKi99XG4gICAgICAgIHtncmlkTGluZXMubWFwKChnLCBpKSA9PiAoXG4gICAgICAgICAgPGcga2V5PXtpfT5cbiAgICAgICAgICAgIDxsaW5lIHgxPXtwYWRYfSB5MT17Zy55fSB4Mj17d2lkdGggLSBwYWRYfSB5Mj17Zy55fSBzdHJva2U9e0MuYm9yZGVyfSBzdHJva2VXaWR0aD1cIjFcIiBzdHJva2VEYXNoYXJyYXk9XCIzIDNcIiAvPlxuICAgICAgICAgICAgPHRleHQgeD17cGFkWCAtIDZ9IHk9e2cueSArIDR9IGZpbGw9XCIjOTRhM2I4XCIgZm9udFNpemU9XCI5XCIgZm9udEZhbWlseT1cIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIHRleHRBbmNob3I9XCJlbmRcIj57Zy5sYWJlbH08L3RleHQ+XG4gICAgICAgICAgPC9nPlxuICAgICAgICApKX1cbiAgICAgICAgey8qIEFyZWEgZmlsbCAqL31cbiAgICAgICAgPHBhdGggZD17YXJlYVBhdGh9IGZpbGw9XCJ1cmwoI2FyZWFGaWxsKVwiIC8+XG4gICAgICAgIHsvKiBMaW5lICovfVxuICAgICAgICA8cGF0aCBkPXtsaW5lUGF0aH0gZmlsbD1cIm5vbmVcIiBzdHJva2U9e2NvbG9yfSBzdHJva2VXaWR0aD1cIjIuNVwiIHN0cm9rZUxpbmVqb2luPVwicm91bmRcIiBzdHJva2VMaW5lY2FwPVwicm91bmRcIiAvPlxuICAgICAgICB7LyogRG90cyArIGxhYmVscyAqL31cbiAgICAgICAge3BvaW50cy5tYXAoKHAsIGkpID0+IHtcbiAgICAgICAgICBjb25zdCBzaG93TGFiZWwgPSAoaSA9PT0gMCB8fCBpID09PSBkYXRhLmxlbmd0aCAtIDEgfHwgaSAlIHN0ZXAgPT09IDApO1xuICAgICAgICAgIHJldHVybiAoXG4gICAgICAgICAgICA8ZyBrZXk9e2l9PlxuICAgICAgICAgICAgICA8Y2lyY2xlIGN4PXtwLnh9IGN5PXtwLnl9IHI9XCIzXCIgZmlsbD17Qy5iZ30gc3Ryb2tlPXtjb2xvcn0gc3Ryb2tlV2lkdGg9XCIyXCIgLz5cbiAgICAgICAgICAgICAge3Nob3dMYWJlbCAmJiAoXG4gICAgICAgICAgICAgICAgPHRleHQgeD17cC54fSB5PXtwYWRZICsgY2hhcnRIICsgMTR9IGZpbGw9XCIjY2JkNWUxXCIgZm9udFNpemU9XCI5XCIgZm9udEZhbWlseT1cIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIHRleHRBbmNob3I9XCJtaWRkbGVcIj57ZGF0YVtpXS5sYWJlbH08L3RleHQ+XG4gICAgICAgICAgICAgICl9XG4gICAgICAgICAgICA8L2c+XG4gICAgICAgICAgKTtcbiAgICAgICAgfSl9XG4gICAgICA8L3N2Zz5cbiAgICA8L2Rpdj5cbiAgKTtcbn07XG5cbi8qIOKUgOKUgOKUgCBJbmxpbmUgU1ZHIERvbnV0IENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgRG9udXRDaGFydCA9ICh7IGRhdGEsIHNpemUgPSAyMDAgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCB0b3RhbCA9IGRhdGEucmVkdWNlKChzLCBkKSA9PiBzICsgZC52YWx1ZSwgMCk7XG4gIGlmICh0b3RhbCA9PT0gMCkgcmV0dXJuIG51bGw7XG4gIGNvbnN0IGN4ID0gc2l6ZSAvIDI7XG4gIGNvbnN0IGN5ID0gc2l6ZSAvIDI7XG4gIGNvbnN0IG91dGVyUiA9IHNpemUgLyAyIC0gMTA7XG4gIGNvbnN0IGlubmVyUiA9IG91dGVyUiAqIDAuNjtcbiAgbGV0IGN1bUFuZ2xlID0gLU1hdGguUEkgLyAyO1xuXG4gIGNvbnN0IHNsaWNlcyA9IGRhdGEubWFwKChkLCBpKSA9PiB7XG4gICAgY29uc3QgYW5nbGUgPSAoZC52YWx1ZSAvIHRvdGFsKSAqIE1hdGguUEkgKiAyO1xuICAgIGNvbnN0IHN0YXJ0QW5nbGUgPSBjdW1BbmdsZTtcbiAgICBjdW1BbmdsZSArPSBhbmdsZTtcbiAgICBjb25zdCBlbmRBbmdsZSA9IGN1bUFuZ2xlO1xuXG4gICAgY29uc3QgeDEgPSBjeCArIG91dGVyUiAqIE1hdGguY29zKHN0YXJ0QW5nbGUpO1xuICAgIGNvbnN0IHkxID0gY3kgKyBvdXRlclIgKiBNYXRoLnNpbihzdGFydEFuZ2xlKTtcbiAgICBjb25zdCB4MiA9IGN4ICsgb3V0ZXJSICogTWF0aC5jb3MoZW5kQW5nbGUpO1xuICAgIGNvbnN0IHkyID0gY3kgKyBvdXRlclIgKiBNYXRoLnNpbihlbmRBbmdsZSk7XG4gICAgY29uc3QgaXgxID0gY3ggKyBpbm5lclIgKiBNYXRoLmNvcyhlbmRBbmdsZSk7XG4gICAgY29uc3QgaXkxID0gY3kgKyBpbm5lclIgKiBNYXRoLnNpbihlbmRBbmdsZSk7XG4gICAgY29uc3QgaXgyID0gY3ggKyBpbm5lclIgKiBNYXRoLmNvcyhzdGFydEFuZ2xlKTtcbiAgICBjb25zdCBpeTIgPSBjeSArIGlubmVyUiAqIE1hdGguc2luKHN0YXJ0QW5nbGUpO1xuICAgIGNvbnN0IGxhcmdlQXJjID0gYW5nbGUgPiBNYXRoLlBJID8gMSA6IDA7XG4gICAgY29uc3QgY29sb3IgPSBQTEFURk9STV9DT0xPUlNbaSAlIFBMQVRGT1JNX0NPTE9SUy5sZW5ndGhdO1xuXG4gICAgY29uc3QgcGF0aCA9IGBNJHt4MX0sJHt5MX0gQSR7b3V0ZXJSfSwke291dGVyUn0gMCAke2xhcmdlQXJjfSAxICR7eDJ9LCR7eTJ9IEwke2l4MX0sJHtpeTF9IEEke2lubmVyUn0sJHtpbm5lclJ9IDAgJHtsYXJnZUFyY30gMCAke2l4Mn0sJHtpeTJ9IFpgO1xuICAgIHJldHVybiB7IHBhdGgsIGNvbG9yLCBuYW1lOiBkLm5hbWUsIHZhbHVlOiBkLnZhbHVlLCBwY3Q6IE1hdGgucm91bmQoKGQudmFsdWUgLyB0b3RhbCkgKiAxMDApIH07XG4gIH0pO1xuXG4gIHJldHVybiAoXG4gICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcyNHB4JywgZmxleFdyYXA6ICd3cmFwJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInIH19PlxuICAgICAgPHN2ZyB3aWR0aD17c2l6ZX0gaGVpZ2h0PXtzaXplfSB2aWV3Qm94PXtgMCAwICR7c2l6ZX0gJHtzaXplfWB9PlxuICAgICAgICB7c2xpY2VzLm1hcCgocywgaSkgPT4gKFxuICAgICAgICAgIDxwYXRoIGtleT17aX0gZD17cy5wYXRofSBmaWxsPXtzLmNvbG9yfSBzdHJva2U9e0MuYmd9IHN0cm9rZVdpZHRoPVwiMlwiPlxuICAgICAgICAgICAgPHRpdGxlPntzLm5hbWV9OiB7cy52YWx1ZX0gKHtzLnBjdH0lKTwvdGl0bGU+XG4gICAgICAgICAgPC9wYXRoPlxuICAgICAgICApKX1cbiAgICAgICAgPHRleHQgeD17Y3h9IHk9e2N5IC0gNn0gZmlsbD17Qy50ZXh0fSBmb250U2l6ZT1cIjIyXCIgZm9udFdlaWdodD1cImJvbGRcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e3RvdGFsfTwvdGV4dD5cbiAgICAgICAgPHRleHQgeD17Y3h9IHk9e2N5ICsgMTR9IGZpbGw9e0MudGV4dE11dGVkfSBmb250U2l6ZT1cIjEwXCIgdGV4dEFuY2hvcj1cIm1pZGRsZVwiPlRPVEFMPC90ZXh0PlxuICAgICAgPC9zdmc+XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleERpcmVjdGlvbjogJ2NvbHVtbicsIGdhcDogJzZweCcgfX0+XG4gICAgICAgIHtzbGljZXMubWFwKChzLCBpKSA9PiAoXG4gICAgICAgICAgPGRpdiBrZXk9e2l9IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIGZvbnRTaXplOiAnMTJweCcgfX0+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyB3aWR0aDogMTIsIGhlaWdodDogMTIsIGJvcmRlclJhZGl1czogJzNweCcsIGJhY2tncm91bmRDb2xvcjogcy5jb2xvciwgZGlzcGxheTogJ2lubGluZS1ibG9jaycsIGZsZXhTaHJpbms6IDAgfX0gLz5cbiAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLnRleHQgfX0+e3MubmFtZX08L3NwYW4+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCBtYXJnaW5MZWZ0OiAnYXV0bycgfX0+e3MudmFsdWV9ICh7cy5wY3R9JSk8L3NwYW4+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICkpfVxuICAgICAgPC9kaXY+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG4vKiDilIDilIDilIAgU3RhdCBDYXJkIOKUgOKUgOKUgCAqL1xuY29uc3QgU3RhdENhcmQgPSAoeyBpY29uLCBsYWJlbCwgdmFsdWUsIGRlbHRhLCBkZWx0YUxhYmVsLCBhY2NlbnRDb2xvciB9KSA9PiAoXG4gIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKGFjY2VudENvbG9yKSwgZmxleDogJzEnLCBtaW5XaWR0aDogJzIyMHB4JyB9fVxuICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IGFjY2VudENvbG9yIHx8IEMuYm9yZGVySG92ZXI7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgtMnB4KSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSBgMCA4cHggMjRweCByZ2JhKDAsMCwwLDAuNClgOyB9fVxuICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuYm9yZGVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyTGVmdENvbG9yID0gYWNjZW50Q29sb3I7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgwKSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnbm9uZSc7IH19XG4gID5cbiAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE0cHgnIH19PlxuICAgICAgPEljb24gaWNvbj17aWNvbn0gY29sb3I9e2FjY2VudENvbG9yfSAvPlxuICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzExcHgnLCBmb250V2VpZ2h0OiA3MDAsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wOGVtJyB9fT57bGFiZWx9PC9UZXh0PlxuICAgIDwvZGl2PlxuICAgIDxIMiBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46ICcwIDAgOHB4IDAnLCBmb250U2l6ZTogJzIuMnJlbScgfX0+e3ZhbHVlfTwvSDI+XG4gICAge2RlbHRhICE9PSB1bmRlZmluZWQgJiYgKFxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnIH19PlxuICAgICAgICA8SWNvbiBpY29uPVwiQXJyb3dVcFwiIHNpemU9ezE0fSBjb2xvcj17Qy5ncmVlbn0gLz5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMuZ3JlZW4sIGZvbnRTaXplOiAnMTNweCcsIGZvbnRXZWlnaHQ6IDYwMCB9fT4re2RlbHRhfSB7ZGVsdGFMYWJlbCB8fCAndGhpcyBtb250aCd9PC9UZXh0PlxuICAgICAgPC9kaXY+XG4gICAgKX1cbiAgPC9Cb3g+XG4pO1xuXG4vKiDilIDilIDilIAgQWN0aW9uIEJhZGdlIENhcmQg4pSA4pSA4pSAICovXG5jb25zdCBBY3Rpb25DYXJkID0gKHsgaWNvbiwgbGFiZWwsIGNvdW50LCBhY2NlbnRDb2xvciwgcmVzb3VyY2VJZCB9KSA9PiAoXG4gIDxhIGhyZWY9e2AvYWRtaW4vcmVzb3VyY2VzLyR7cmVzb3VyY2VJZH1gfSBzdHlsZT17eyB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmbGV4OiAnMScsIG1pbldpZHRoOiAnMTgwcHgnIH19PlxuICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKGFjY2VudENvbG9yKSwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMTZweCcgfX1cbiAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoLTJweCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gYDAgNnB4IDIwcHggcmdiYSgwLDAsMCwwLjMpYDsgfX1cbiAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuYm9yZGVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyTGVmdENvbG9yID0gYWNjZW50Q29sb3I7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAndHJhbnNsYXRlWSgwKSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnbm9uZSc7IH19XG4gICAgPlxuICAgICAgPGRpdiBzdHlsZT17eyB3aWR0aDogNDQsIGhlaWdodDogNDQsIGJvcmRlclJhZGl1czogJzEycHgnLCBiYWNrZ3JvdW5kQ29sb3I6IGAke2FjY2VudENvbG9yfTE1YCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLCBmbGV4U2hyaW5rOiAwIH19PlxuICAgICAgICA8SWNvbiBpY29uPXtpY29ufSBzaXplPXsyMn0gY29sb3I9e2FjY2VudENvbG9yfSAvPlxuICAgICAgPC9kaXY+XG4gICAgICA8ZGl2PlxuICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTFweCcsIGZvbnRXZWlnaHQ6IDYwMCwgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nIH19PntsYWJlbH08L1RleHQ+XG4gICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogY291bnQgPiAwID8gYWNjZW50Q29sb3IgOiBDLnRleHREaW0sIG1hcmdpbjogJzRweCAwIDAgMCcgfX0+e2NvdW50fTwvSDU+XG4gICAgICA8L2Rpdj5cbiAgICAgIDxJY29uIGljb249XCJDaGV2cm9uUmlnaHRcIiBjb2xvcj17Qy50ZXh0RGltfSBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnYXV0bycgfX0gLz5cbiAgICA8L0JveD5cbiAgPC9hPlxuKTtcblxuLyog4pSA4pSA4pSAIEZvcm1hdCBkYXRlIG5pY2VseSDilIDilIDilIAgKi9cbmNvbnN0IGZtdERhdGUgPSAoZCkgPT4ge1xuICBpZiAoIWQpIHJldHVybiAn4oCUJztcbiAgY29uc3QgZHQgPSBuZXcgRGF0ZShkKTtcbiAgcmV0dXJuIGR0LnRvTG9jYWxlRGF0ZVN0cmluZygnZW4tVVMnLCB7IG1vbnRoOiAnc2hvcnQnLCBkYXk6ICdudW1lcmljJywgeWVhcjogJ251bWVyaWMnIH0pO1xufTtcblxuLyog4pSA4pSA4pSAIFN0YXR1cyBiYWRnZSBjb2xvciDilIDilIDilIAgKi9cbmNvbnN0IHN0YXR1c0NvbG9yID0gKHMpID0+IHtcbiAgaWYgKCFzKSByZXR1cm4gQy50ZXh0RGltO1xuICBjb25zdCBsb3dlciA9IHMudG9Mb3dlckNhc2UoKTtcbiAgaWYgKGxvd2VyID09PSAnYXBwcm92ZWQnIHx8IGxvd2VyID09PSAnYWN0aXZlJykgcmV0dXJuIEMuZ3JlZW47XG4gIGlmIChsb3dlciA9PT0gJ3BlbmRpbmcnKSByZXR1cm4gQy5vcmFuZ2U7XG4gIGlmIChsb3dlciA9PT0gJ3JlamVjdGVkJykgcmV0dXJuIEMucmVkO1xuICByZXR1cm4gQy50ZXh0TXV0ZWQ7XG59O1xuXG4vKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbiAgIE1BSU4gREFTSEJPQVJEIENPTVBPTkVOVFxuICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovXG5jb25zdCBDdXN0b21EYXNoYm9hcmQgPSAoKSA9PiB7XG4gIGNvbnN0IFtkYXRhLCBzZXREYXRhXSA9IHVzZVN0YXRlKG51bGwpO1xuICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcbiAgY29uc3QgW2Vycm9yLCBzZXRFcnJvcl0gPSB1c2VTdGF0ZShudWxsKTtcblxuICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgIGFwaS5nZXREYXNoYm9hcmQoKVxuICAgICAgLnRoZW4oKHJlc3BvbnNlKSA9PiB7XG4gICAgICAgIHNldERhdGEocmVzcG9uc2UuZGF0YSB8fCB7fSk7XG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgfSlcbiAgICAgIC5jYXRjaCgoZmV0Y2hFcnJvcikgPT4ge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdEYXNoYm9hcmQgZmV0Y2ggZXJyb3I6JywgZmV0Y2hFcnJvcik7XG4gICAgICAgIHNldEVycm9yKCdGYWlsZWQgdG8gbG9hZCBkYXNoYm9hcmQgZGF0YS4nKTtcbiAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICB9KTtcbiAgfSwgW10pO1xuXG4gIGlmIChsb2FkaW5nKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgbWluSGVpZ2h0OiAnMTAwdmgnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgPGRpdiBzdHlsZT17eyB0ZXh0QWxpZ246ICdjZW50ZXInIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6IDQwLCBoZWlnaHQ6IDQwLCBib3JkZXI6IGAzcHggc29saWQgJHtDLmJvcmRlcn1gLCBib3JkZXJUb3BDb2xvcjogQy5nb2xkLCBib3JkZXJSYWRpdXM6ICc1MCUnLCBhbmltYXRpb246ICdzcGluIDFzIGxpbmVhciBpbmZpbml0ZScsIG1hcmdpbjogJzAgYXV0byAxNnB4JyB9fSAvPlxuICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCB9fT5Mb2FkaW5nIGRhc2hib2FyZC4uLjwvVGV4dD5cbiAgICAgICAgICA8c3R5bGU+e2BAa2V5ZnJhbWVzIHNwaW4geyB0byB7IHRyYW5zZm9ybTogcm90YXRlKDM2MGRlZyk7IH0gfWB9PC9zdHlsZT5cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L2Rpdj5cbiAgICApO1xuICB9XG5cbiAgaWYgKGVycm9yKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgbWluSGVpZ2h0OiAnMTAwdmgnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoQy5yZWQpLCBtYXhXaWR0aDogNDAwLCB0ZXh0QWxpZ246ICdjZW50ZXInIH19PlxuICAgICAgICAgIDxJY29uIGljb249XCJBbGVydFRyaWFuZ2xlXCIgc2l6ZT17MzJ9IGNvbG9yPXtDLnJlZH0gLz5cbiAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMucmVkLCBtYXJnaW46ICcxNnB4IDAgOHB4JyB9fT57ZXJyb3J9PC9INT5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQgfX0+Q2hlY2sgdGhlIHNlcnZlciBsb2dzIGZvciBkZXRhaWxzLjwvVGV4dD5cbiAgICAgICAgPC9Cb3g+XG4gICAgICA8L2Rpdj5cbiAgICApO1xuICB9XG5cbiAgY29uc3Qgc3RhdHMgPSBkYXRhPy5zdGF0cyB8fCB7fTtcbiAgY29uc3QgYWN0aW9uUmVxdWlyZWQgPSBkYXRhPy5hY3Rpb25SZXF1aXJlZCB8fCB7fTtcbiAgY29uc3QgbW9kc0J5UGxhdGZvcm0gPSBkYXRhPy5tb2RzQnlQbGF0Zm9ybSB8fCBbXTtcbiAgY29uc3QgdXNlckdyb3d0aERhdGEgPSBkYXRhPy51c2VyR3Jvd3RoRGF0YSB8fCBbXTtcbiAgY29uc3QgcmVjZW50VXNlcnMgPSBkYXRhPy5yZWNlbnRVc2VycyB8fCBbXTtcbiAgY29uc3QgcmVjZW50TW9kcyA9IGRhdGE/LnJlY2VudE1vZHMgfHwgW107XG5cbiAgLy8gUHJlcGFyZSBjaGFydCBkYXRhXG4gIGNvbnN0IGdyb3d0aENoYXJ0RGF0YSA9IHVzZXJHcm93dGhEYXRhLm1hcChkID0+ICh7IGxhYmVsOiBkLmRhdGUsIHZhbHVlOiBkLnVzZXJzIH0pKTtcblxuICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICBjb25zdCBncmVldGluZyA9IG5vdy5nZXRIb3VycygpIDwgMTIgPyAnR29vZCBtb3JuaW5nJyA6IG5vdy5nZXRIb3VycygpIDwgMTggPyAnR29vZCBhZnRlcm5vb24nIDogJ0dvb2QgZXZlbmluZyc7XG5cbiAgcmV0dXJuIChcbiAgICA8ZGl2IHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogQy5iZywgbWluSGVpZ2h0OiAnMTAwdmgnLCBwYWRkaW5nOiAnY2xhbXAoMTZweCwgM3Z3LCAzMnB4KSBjbGFtcCgxNHB4LCAzdncsIDM2cHgpJywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5cbiAgICAgIFxuICAgICAgey8qIOKVkOKVkOKVkCBIRUFERVIg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcxNnB4JywgcGFkZGluZ0JvdHRvbTogJzI0cHgnLCBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gLCBtYXJnaW5Cb3R0b206ICcyOHB4JyB9fT5cbiAgICAgICAgPGRpdj5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluXCIgc3R5bGU9e3sgdGV4dERlY29yYXRpb246ICdub25lJywgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGN1cnNvcjogJ3BvaW50ZXInIH19PlxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcxMHB4JyB9fT5cbiAgICAgICAgICAgICAgPEgyIHN0eWxlPXt7IG1hcmdpbjogMCwgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+XG4gICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6IEMuZ29sZCwgdGV4dFNoYWRvdzogYDAgMCAyMHB4ICR7Qy5nb2xkR2xvd31gLCBmb250V2VpZ2h0OiA4MDAgfX0+R1BMPC9zcGFuPlxuICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIHRleHRTaGFkb3c6ICcwIDAgMTVweCByZ2JhKDI1NSwgMjU1LCAyNTUsIDAuNCknLCBmb250V2VpZ2h0OiA3MDAgfX0+TW9kczwvc3Bhbj5cbiAgICAgICAgICAgICAgPC9IMj5cbiAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjZmZkNzAwJywgZm9udFNpemU6ICcxMXB4JywgZm9udFdlaWdodDogNjAwLCBiYWNrZ3JvdW5kOiAncmdiYSgyNTUsIDIxNSwgMCwgMC4xMiknLCBwYWRkaW5nOiAnNHB4IDEwcHgnLCBib3JkZXJSYWRpdXM6ICcyMHB4JywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LCAyMTUsIDAsIDAuMzUpJywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiwgbGV0dGVyU3BhY2luZzogJzAuMDRlbScsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnIH19PkFkbWluIERhc2hib2FyZDwvc3Bhbj5cbiAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIDwvYT5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNmMWY1ZjknLCBtYXJnaW5Ub3A6ICc4cHgnLCBmb250U2l6ZTogJzE0cHgnLCBmb250V2VpZ2h0OiA0MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIsIGxpbmVIZWlnaHQ6IDEuNSB9fT5cbiAgICAgICAgICAgIHtncmVldGluZ30hIEhlcmUncyB5b3VyIHBsYXRmb3JtIG92ZXJ2aWV3IGZvciB7bm93LnRvTG9jYWxlRGF0ZVN0cmluZygnZW4tVVMnLCB7IHdlZWtkYXk6ICdsb25nJywgbW9udGg6ICdsb25nJywgZGF5OiAnbnVtZXJpYycsIHllYXI6ICdudW1lcmljJyB9KX0uXG4gICAgICAgICAgPC9UZXh0PlxuICAgICAgICA8L2Rpdj5cblxuICAgICAgICB7Lyog4pWQ4pWQ4pWQIEFETUlOIFNVSVRFIFNIT1JUQ1VUIEJVVFRPTlMg4pWQ4pWQ4pWQICovfVxuICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzEwcHgnIH19PlxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9kYXNoYm9hcmRcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogQy5nb2xkLCBiYWNrZ3JvdW5kQ29sb3I6IEMuZ29sZERpbSwgYm9yZGVyOiBgMXB4IHNvbGlkICR7Qy5nb2xkfWAsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDI1NSwyMTUsMCwwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gQy5nb2xkRGltOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJHbyBCYWNrIFRvIERhc2hib2FyZFwiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkFycm93TGVmdFwiIHNpemU9ezE0fSAvPiBHbyBCYWNrIFRvIERhc2hib2FyZFxuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9hZG1pbi9yZXBvcnRzXCIgXG4gICAgICAgICAgICBzdHlsZT17eyBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JywgY29sb3I6ICcjZmY2YjZiJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyMjksNTcsNTMsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyMjksNTcsNTMsMC4zKScsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDIyOSw1Nyw1MywwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjI5LDU3LDUzLDAuMTIpJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiTW9kZXJhdGlvbiAmIE1vZCBSZXBvcnRzIENvbnNvbGVcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJGbGFnXCIgc2l6ZT17MTR9IC8+IFJlcG9ydHNcbiAgICAgICAgICA8L2E+XG5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvYWRtaW4vc3VwcG9ydFwiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnIzY0YjVmNicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMzMsMTUwLDI0MywwLjEyKScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDMzLDE1MCwyNDMsMC4zKScsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDMzLDE1MCwyNDMsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDMzLDE1MCwyNDMsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJMaXZlIFN1cHBvcnQgJiBJbnF1aXJpZXMgQ29uc29sZVwiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkhlbHBDaXJjbGVcIiBzaXplPXsxNH0gLz4gU3VwcG9ydFxuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9zdGF0dXNcIiBcbiAgICAgICAgICAgIHRhcmdldD1cIl9ibGFua1wiIFxuICAgICAgICAgICAgcmVsPVwibm9vcGVuZXIgbm9yZWZlcnJlclwiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnIzgxYzc4NCcsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoNjcsMTYwLDcxLDAuMTIpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoNjcsMTYwLDcxLDAuMyknLCBwYWRkaW5nOiAnOHB4IDE0cHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTNweCcsIHRyYW5zaXRpb246ICdhbGwgMC4ycycgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSg2NywxNjAsNzEsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDY3LDE2MCw3MSwwLjEyKSc7IH19XG4gICAgICAgICAgICB0aXRsZT1cIkxpdmUgU2VydmVyIEhlYWx0aCAmIERpYWdub3N0aWNzXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiQWN0aXZpdHlcIiBzaXplPXsxNH0gLz4gU3RhdHVzXG4gICAgICAgICAgPC9hPlxuXG4gICAgICAgICAgPGEgXG4gICAgICAgICAgICBocmVmPVwiL2FkbWluL211c2ljXCIgXG4gICAgICAgICAgICBzdHlsZT17eyBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JywgY29sb3I6ICcjYmE2OGM4JywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgxODYsMTA0LDIwMCwwLjEyKScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDE4NiwxMDQsMjAwLDAuMyknLCBwYWRkaW5nOiAnOHB4IDE0cHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTNweCcsIHRyYW5zaXRpb246ICdhbGwgMC4ycycgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgxODYsMTA0LDIwMCwwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMTg2LDEwNCwyMDAsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJNdXNpYyAmIFBsYXlsaXN0IE1hbmFnZXJcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJNdXNpY1wiIHNpemU9ezE0fSAvPiBNdXNpY1xuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9ob21lXCIgXG4gICAgICAgICAgICB0YXJnZXQ9XCJfYmxhbmtcIiBcbiAgICAgICAgICAgIHJlbD1cIm5vb3BlbmVyIG5vcmVmZXJyZXJcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyNmZmZmZmYnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuc3VyZmFjZUFsdCwgYm9yZGVyOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgcGFkZGluZzogJzhweCAxNHB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEzcHgnLCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmdvbGQ7IGUuY3VycmVudFRhcmdldC5zdHlsZS5jb2xvciA9IEMuZ29sZDsgfX1cbiAgICAgICAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuYm9yZGVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuY29sb3IgPSAnI2ZmZmZmZic7IH19XG4gICAgICAgICAgICB0aXRsZT1cIk9wZW4gTGl2ZSBQdWJsaWMgU2l0ZVwiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkdsb2JlXCIgc2l6ZT17MTR9IC8+IExpdmUgU2l0ZVxuICAgICAgICAgIDwvYT5cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBTVEFUIENBUkRTIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcxNnB4JywgbWFyZ2luQm90dG9tOiAnMjRweCcgfX0+XG4gICAgICAgIDxTdGF0Q2FyZCBpY29uPVwiVXNlcnNcIiBsYWJlbD1cIlRvdGFsIFVzZXJzXCIgdmFsdWU9eyhzdGF0cy50b3RhbFVzZXJzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGRlbHRhPXtzdGF0cy5uZXdVc2Vyc1RoaXNNb250aH0gYWNjZW50Q29sb3I9e0MuYmx1ZX0gLz5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJQYWNrYWdlXCIgbGFiZWw9XCJUb3RhbCBNb2RzXCIgdmFsdWU9eyhzdGF0cy50b3RhbE1vZHMgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gZGVsdGE9e3N0YXRzLm5ld01vZHNUaGlzTW9udGh9IGFjY2VudENvbG9yPXtDLmdvbGR9IC8+XG4gICAgICAgIDxTdGF0Q2FyZCBpY29uPVwiRG93bmxvYWRcIiBsYWJlbD1cIlRvdGFsIERvd25sb2Fkc1wiIHZhbHVlPXsoc3RhdHMudG90YWxEb3dubG9hZHMgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gYWNjZW50Q29sb3I9e0MuZ3JlZW59IC8+XG4gICAgICAgIDxTdGF0Q2FyZCBpY29uPVwiRXllXCIgbGFiZWw9XCJUb3RhbCBWaWV3c1wiIHZhbHVlPXsoc3RhdHMudG90YWxWaWV3cyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBhY2NlbnRDb2xvcj17Qy5wdXJwbGV9IC8+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBBQ1RJT04gUkVRVUlSRUQg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzE0cHgnLCBtYXJnaW5Cb3R0b206ICczMnB4JyB9fT5cbiAgICAgICAgPEFjdGlvbkNhcmQgaWNvbj1cIkZsYWdcIiBsYWJlbD1cIlBlbmRpbmcgUmVwb3J0c1wiIGNvdW50PXthY3Rpb25SZXF1aXJlZC5wZW5kaW5nUmVwb3J0cyB8fCAwfSBhY2NlbnRDb2xvcj17Qy5yZWR9IHJlc291cmNlSWQ9XCJSZXBvcnRcIiAvPlxuICAgICAgICA8QWN0aW9uQ2FyZCBpY29uPVwiQ2hlY2tTcXVhcmVcIiBsYWJlbD1cIlBlbmRpbmcgQXBwcm92YWxzXCIgY291bnQ9e2FjdGlvblJlcXVpcmVkLnBlbmRpbmdBcHByb3ZhbHMgfHwgMH0gYWNjZW50Q29sb3I9e0Mub3JhbmdlfSByZXNvdXJjZUlkPVwiRmlsZVwiIC8+XG4gICAgICAgIDxBY3Rpb25DYXJkIGljb249XCJIZWxwQ2lyY2xlXCIgbGFiZWw9XCJPcGVuIFRpY2tldHNcIiBjb3VudD17YWN0aW9uUmVxdWlyZWQub3BlblRpY2tldHMgfHwgMH0gYWNjZW50Q29sb3I9e0MuYmx1ZX0gcmVzb3VyY2VJZD1cIlN1cHBvcnRUaWNrZXRcIiAvPlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgQ0hBUlRTIFJPVyDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMjBweCcsIG1hcmdpbkJvdHRvbTogJzMycHgnIH19PlxuICAgICAgICB7LyogVXNlciBHcm93dGggQ2hhcnQgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcyIDEgMzIwcHgnLCBtaW5XaWR0aDogMCwgd2lkdGg6ICcxMDAlJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE4cHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkFjdGl2aXR5XCIgY29sb3I9e0MuZ29sZH0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+VXNlciBHcm93dGg8L0g1PlxuICAgICAgICAgICAgPEJhZGdlIHN0eWxlPXt7IG1hcmdpbkxlZnQ6ICc4cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuZ29sZERpbSwgY29sb3I6IEMuZ29sZCwgYm9yZGVyOiAnbm9uZScsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+MzAgZGF5czwvQmFkZ2U+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICAge2dyb3d0aENoYXJ0RGF0YS5sZW5ndGggPiAwID8gKFxuICAgICAgICAgICAgPEFyZWFDaGFydCBkYXRhPXtncm93dGhDaGFydERhdGF9IGNvbG9yPXtDLmdvbGR9IHdpZHRoPXs1MDB9IGhlaWdodD17MTcwfSAvPlxuICAgICAgICAgICkgOiAoXG4gICAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGhlaWdodDogMTYwLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0sIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+Tm8gdXNlciBzaWdudXBzIGluIHRoZSBsYXN0IDMwIGRheXMuPC9UZXh0PlxuICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgey8qIFBsYXRmb3JtIERvbnV0ICovfVxuICAgICAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZSgpLCBmbGV4OiAnMSAxIDI4MHB4JywgbWluV2lkdGg6IDAsIHdpZHRoOiAnMTAwJScgfX0+XG4gICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcxOHB4JyB9fT5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJQaWVDaGFydFwiIGNvbG9yPXtDLmJsdWV9IC8+XG4gICAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19Pk1vZHMgYnkgUGxhdGZvcm08L0g1PlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIHttb2RzQnlQbGF0Zm9ybS5sZW5ndGggPiAwID8gKFxuICAgICAgICAgICAgPERvbnV0Q2hhcnQgZGF0YT17bW9kc0J5UGxhdGZvcm19IHNpemU9ezE4MH0gLz5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBoZWlnaHQ6IDE2MCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInIH19PlxuICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19Pk5vIHBsYXRmb3JtIGRhdGEgYXZhaWxhYmxlLjwvVGV4dD5cbiAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvQm94PlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgUkVDRU5UIEFDVElWSVRZIFJPVyDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMjBweCcsIG1hcmdpbkJvdHRvbTogJzMycHgnIH19PlxuICAgICAgICB7LyogUmVjZW50IFVzZXJzICovfVxuICAgICAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZSgpLCBmbGV4OiAnMSAxIDMyMHB4JywgbWluV2lkdGg6IDAsIHdpZHRoOiAnMTAwJScgfX0+XG4gICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcxOHB4JyB9fT5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJVc2Vyc1wiIGNvbG9yPXtDLmJsdWV9IC8+XG4gICAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlJlY2VudCBVc2VyczwvSDU+XG4gICAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9Vc2VyXCIgc3R5bGU9e3sgbWFyZ2luTGVmdDogJ2F1dG8nLCBjb2xvcjogQy5nb2xkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+VmlldyBBbGwg4oaSPC9hPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIHtyZWNlbnRVc2Vycy5sZW5ndGggPiAwID8gKFxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBvdmVyZmxvd1g6ICdhdXRvJywgd2lkdGg6ICcxMDAlJywgV2Via2l0T3ZlcmZsb3dTY3JvbGxpbmc6ICd0b3VjaCcgfX0+XG4gICAgICAgICAgICAgIDx0YWJsZSBzdHlsZT17eyB3aWR0aDogJzEwMCUnLCBib3JkZXJDb2xsYXBzZTogJ2NvbGxhcHNlJywgbWluV2lkdGg6ICczMDBweCcgfX0+XG4gICAgICAgICAgICAgICAgPHRoZWFkPlxuICAgICAgICAgICAgICAgICAgPHRyIHN0eWxlPXt7IGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+VXNlcm5hbWU8L3RoPlxuICAgICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PlJvbGU8L3RoPlxuICAgICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAncmlnaHQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5Kb2luZWQ8L3RoPlxuICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICA8L3RoZWFkPlxuICAgICAgICAgICAgICAgIDx0Ym9keT5cbiAgICAgICAgICAgICAgICAgIHtyZWNlbnRVc2Vycy5tYXAoKHUsIGkpID0+IChcbiAgICAgICAgICAgICAgICAgICAgPHRyIGtleT17aX0gc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHQsIGZvbnRTaXplOiAnMTNweCcsIGZvbnRXZWlnaHQ6IDUwMCB9fT57dS51c2VybmFtZX08L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnMTFweCcsIHBhZGRpbmc6ICczcHggOHB4JywgYm9yZGVyUmFkaXVzOiAnNnB4JywgYmFja2dyb3VuZENvbG9yOiB1LnJvbGUgPT09ICdhZG1pbicgPyBgJHtDLmdvbGR9MjBgIDogYCR7Qy5ibHVlfTIwYCwgY29sb3I6IHUucm9sZSA9PT0gJ2FkbWluJyA/IEMuZ29sZCA6IEMuYmx1ZSwgZm9udFdlaWdodDogNjAwIH19Pnt1LnJvbGUgfHwgJ3VzZXInfTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0QWxpZ246ICdyaWdodCcgfX0+e2ZtdERhdGUodS5kYXRlKX08L3RkPlxuICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgKSl9XG4gICAgICAgICAgICAgICAgPC90Ym9keT5cbiAgICAgICAgICAgICAgPC90YWJsZT5cbiAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICkgOiAoXG4gICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCB0ZXh0QWxpZ246ICdjZW50ZXInLCBwYWRkaW5nOiAnMjBweCAwJyB9fT5ObyByZWNlbnQgdXNlcnMuPC9UZXh0PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvQm94PlxuXG4gICAgICAgIHsvKiBSZWNlbnQgTW9kcyAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzEgMSAzMjBweCcsIG1pbldpZHRoOiAwLCB3aWR0aDogJzEwMCUnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMThweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiUGFja2FnZVwiIGNvbG9yPXtDLmdvbGR9IC8+XG4gICAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlJlY2VudCBNb2RzPC9INT5cbiAgICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL0ZpbGVcIiBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnYXV0bycsIGNvbG9yOiBDLmdvbGQsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5WaWV3IEFsbCDihpI8L2E+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICAge3JlY2VudE1vZHMubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgb3ZlcmZsb3dYOiAnYXV0bycsIHdpZHRoOiAnMTAwJScsIFdlYmtpdE92ZXJmbG93U2Nyb2xsaW5nOiAndG91Y2gnIH19PlxuICAgICAgICAgICAgICA8dGFibGUgc3R5bGU9e3sgd2lkdGg6ICcxMDAlJywgYm9yZGVyQ29sbGFwc2U6ICdjb2xsYXBzZScsIG1pbldpZHRoOiAnMzAwcHgnIH19PlxuICAgICAgICAgICAgICAgIDx0aGVhZD5cbiAgICAgICAgICAgICAgICAgIDx0ciBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19Pk5hbWU8L3RoPlxuICAgICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PlBsYXRmb3JtPC90aD5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5TdGF0dXM8L3RoPlxuICAgICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAncmlnaHQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5BZGRlZDwvdGg+XG4gICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgIDwvdGhlYWQ+XG4gICAgICAgICAgICAgICAgPHRib2R5PlxuICAgICAgICAgICAgICAgICAge3JlY2VudE1vZHMubWFwKChtLCBpKSA9PiAoXG4gICAgICAgICAgICAgICAgICAgIDx0ciBrZXk9e2l9IHN0eWxlPXt7IGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnLCBjb2xvcjogQy50ZXh0LCBmb250U2l6ZTogJzEzcHgnLCBmb250V2VpZ2h0OiA1MDAsIG1heFdpZHRoOiAnMTgwcHgnLCBvdmVyZmxvdzogJ2hpZGRlbicsIHRleHRPdmVyZmxvdzogJ2VsbGlwc2lzJywgd2hpdGVTcGFjZTogJ25vd3JhcCcgfX0+e20ubmFtZX08L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnMTFweCcsIHBhZGRpbmc6ICczcHggOHB4JywgYm9yZGVyUmFkaXVzOiAnNnB4JywgYmFja2dyb3VuZENvbG9yOiBgJHtDLmJsdWV9MjBgLCBjb2xvcjogQy5ibHVlLCBmb250V2VpZ2h0OiA2MDAsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnIH19PnttLmNhdGVnb3J5IHx8ICfigJQnfTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnMTFweCcsIHBhZGRpbmc6ICczcHggOHB4JywgYm9yZGVyUmFkaXVzOiAnNnB4JywgYmFja2dyb3VuZENvbG9yOiBgJHtzdGF0dXNDb2xvcihtLnN0YXR1cyl9MjBgLCBjb2xvcjogc3RhdHVzQ29sb3IobS5zdGF0dXMpLCBmb250V2VpZ2h0OiA2MDAsIHRleHRUcmFuc2Zvcm06ICdjYXBpdGFsaXplJyB9fT57bS5zdGF0dXMgfHwgJ+KAlCd9PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnLCBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTJweCcsIHRleHRBbGlnbjogJ3JpZ2h0JyB9fT57Zm10RGF0ZShtLmRhdGUpfTwvdGQ+XG4gICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICApKX1cbiAgICAgICAgICAgICAgICA8L3Rib2R5PlxuICAgICAgICAgICAgICA8L3RhYmxlPlxuICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0sIHRleHRBbGlnbjogJ2NlbnRlcicsIHBhZGRpbmc6ICcyMHB4IDAnIH19Pk5vIHJlY2VudCBtb2RzLjwvVGV4dD5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIEZPT1RFUiDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywganVzdGlmeUNvbnRlbnQ6ICdzcGFjZS1iZXR3ZWVuJywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzE0cHgnLCBwYWRkaW5nVG9wOiAnMjBweCcsIGJvcmRlclRvcDogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgIDxhIGhyZWY9XCIvYWRtaW5cIiBzdHlsZT17eyB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnIH19PlxuICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGZvbnRTaXplOiAnMTNweCcsIGN1cnNvcjogJ3BvaW50ZXInLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6IEMuZ29sZCwgZm9udFdlaWdodDogNzAwIH19PkdQTDwvc3Bhbj4gPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgZm9udFdlaWdodDogNjAwIH19Pk1vZHM8L3NwYW4+IOKAoiBBZG1pbiBQYW5lbCB2Mi41XG4gICAgICAgICAgPC9UZXh0PlxuICAgICAgICA8L2E+XG4gICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICc4cHgnIH19PlxuICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL1VzZXJcIiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuMDYpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4xKScsIHBhZGRpbmc6ICc1cHggMTJweCcsIGJvcmRlclJhZGl1czogJzhweCcsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDUwMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5Vc2VyczwvYT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9GaWxlXCIgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjA2KScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSknLCBwYWRkaW5nOiAnNXB4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA1MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+TW9kczwvYT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9SZXBvcnRcIiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuMDYpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4xKScsIHBhZGRpbmc6ICc1cHggMTJweCcsIGJvcmRlclJhZGl1czogJzhweCcsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDUwMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5SZXBvcnRzPC9hPlxuICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL1N1cHBvcnRUaWNrZXRcIiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuMDYpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4xKScsIHBhZGRpbmc6ICc1cHggMTJweCcsIGJvcmRlclJhZGl1czogJzhweCcsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDUwMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5UaWNrZXRzPC9hPlxuICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vbXVzaWNcIiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuMDYpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4xKScsIHBhZGRpbmc6ICc1cHggMTJweCcsIGJvcmRlclJhZGl1czogJzhweCcsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDUwMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5NdXNpYzwvYT5cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L2Rpdj5cbiAgICA8L2Rpdj5cbiAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEN1c3RvbURhc2hib2FyZDtcbiIsImltcG9ydCBSZWFjdCBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3gsIEljb24gfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgU2lkZWJhckJyYW5kaW5nID0gKCkgPT4ge1xuICByZXR1cm4gKFxuICAgIDxCb3ggXG4gICAgICBmbGV4IFxuICAgICAgZmxleERpcmVjdGlvbj1cImNvbHVtblwiXG4gICAgICBhbGlnbkl0ZW1zPVwiY2VudGVyXCIgXG4gICAgICBqdXN0aWZ5Q29udGVudD1cImNlbnRlclwiIFxuICAgICAgcD1cImxnXCIgXG4gICAgICBzdHlsZT17eyBcbiAgICAgICAgYm9yZGVyQm90dG9tOiAnMXB4IHNvbGlkICMyYTJhMmEnLCBcbiAgICAgICAgYmFja2dyb3VuZENvbG9yOiAnIzBhMGEwYScsIFxuICAgICAgICBwYWRkaW5nOiAnMjBweCAxNnB4JyxcbiAgICAgICAgcG9zaXRpb246ICdyZWxhdGl2ZScsXG4gICAgICAgIG92ZXJmbG93OiAnaGlkZGVuJ1xuICAgICAgfX1cbiAgICA+XG4gICAgICB7LyogU3VidGxlIGdvbGQgZ2xvdyB1bmRlcmxpbmUgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7XG4gICAgICAgIHBvc2l0aW9uOiAnYWJzb2x1dGUnLFxuICAgICAgICBib3R0b206IDAsXG4gICAgICAgIGxlZnQ6ICc1MCUnLFxuICAgICAgICB0cmFuc2Zvcm06ICd0cmFuc2xhdGVYKC01MCUpJyxcbiAgICAgICAgd2lkdGg6ICc2MCUnLFxuICAgICAgICBoZWlnaHQ6ICcxcHgnLFxuICAgICAgICBiYWNrZ3JvdW5kOiAnbGluZWFyLWdyYWRpZW50KDkwZGVnLCB0cmFuc3BhcmVudCwgcmdiYSgyNTUsMjE1LDAsMC41KSwgdHJhbnNwYXJlbnQpJ1xuICAgICAgfX0gLz5cblxuICAgICAgey8qIE1haW4gTG9nbyAmIFRpdGxlIExpbmsgKi99XG4gICAgICA8YSBcbiAgICAgICAgaHJlZj1cIi9hZG1pblwiIFxuICAgICAgICBzdHlsZT17eyBcbiAgICAgICAgICB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBcbiAgICAgICAgICBkaXNwbGF5OiAnZmxleCcsIFxuICAgICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInLCBcbiAgICAgICAgICBnYXA6ICcxMHB4JyxcbiAgICAgICAgICBjdXJzb3I6ICdwb2ludGVyJyxcbiAgICAgICAgICB0cmFuc2l0aW9uOiAnb3BhY2l0eSAwLjJzIGVhc2UnXG4gICAgICAgIH19XG4gICAgICAgIG9uTW91c2VFbnRlcj17KGUpID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLm9wYWNpdHkgPSAnMC44NSc7IH19XG4gICAgICAgIG9uTW91c2VMZWF2ZT17KGUpID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLm9wYWNpdHkgPSAnMSc7IH19XG4gICAgICA+XG4gICAgICAgIDxpbWcgXG4gICAgICAgICAgc3JjPVwiL2ltYWdlcy90ZWFtLWxvZ28ucG5nXCIgXG4gICAgICAgICAgYWx0PVwiTG9nb1wiIFxuICAgICAgICAgIHN0eWxlPXt7IGhlaWdodDogJzMycHgnLCB3aWR0aDogJzMycHgnLCBvYmplY3RGaXQ6ICdjb3ZlcicsIGJvcmRlclJhZGl1czogJzZweCcsIGZpbHRlcjogJ2Ryb3Atc2hhZG93KDAgMCA2cHggcmdiYSgyNTUsMjE1LDAsMC4zKSknIH19IFxuICAgICAgICAgIG9uRXJyb3I9eyhlKSA9PiBlLnRhcmdldC5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnfVxuICAgICAgICAvPlxuICAgICAgICA8ZGl2IHN0eWxlPXt7IGZvbnRTaXplOiAnMjJweCcsIGZvbnRXZWlnaHQ6ICdib2xkJywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnYmFzZWxpbmUnLCBnYXA6ICc0cHgnIH19PlxuICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI0ZGRDcwMCcsIHRleHRTaGFkb3c6ICcwIDAgMTJweCByZ2JhKDI1NSwgMjE1LCAwLCAwLjQpJyB9fT5HUEw8L3NwYW4+XG4gICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjYzBjMGMwJywgdGV4dFNoYWRvdzogJzAgMCAxMnB4IHJnYmEoMTkyLCAxOTIsIDE5MiwgMC41KScgfX0+TW9kczwvc3Bhbj5cbiAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzlweCcsIGNvbG9yOiAnIzU1NScsIGZvbnRXZWlnaHQ6IDYwMCwgbWFyZ2luTGVmdDogJzZweCcsIGxldHRlclNwYWNpbmc6ICcwLjA1ZW0nIH19PnYyLjU8L3NwYW4+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9hPlxuXG4gICAgICB7LyogUXVpY2sgRGFzaGJvYXJkIFNob3J0Y3V0IEJ1dHRvbiAqL31cbiAgICAgIDxhIFxuICAgICAgICBocmVmPVwiL2FkbWluXCIgXG4gICAgICAgIHN0eWxlPXt7XG4gICAgICAgICAgZGlzcGxheTogJ2ZsZXgnLFxuICAgICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInLFxuICAgICAgICAgIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyxcbiAgICAgICAgICBnYXA6ICc4cHgnLFxuICAgICAgICAgIG1hcmdpblRvcDogJzEycHgnLFxuICAgICAgICAgIHBhZGRpbmc6ICc2cHggMTZweCcsXG4gICAgICAgICAgd2lkdGg6ICc4NSUnLFxuICAgICAgICAgIGJvcmRlclJhZGl1czogJzhweCcsXG4gICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsIDIxNSwgMCwgMC4wOCknLFxuICAgICAgICAgIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwgMjE1LCAwLCAwLjI1KScsXG4gICAgICAgICAgY29sb3I6ICcjRkZENzAwJyxcbiAgICAgICAgICB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLFxuICAgICAgICAgIGZvbnRTaXplOiAnMTJweCcsXG4gICAgICAgICAgZm9udFdlaWdodDogNzAwLFxuICAgICAgICAgIGxldHRlclNwYWNpbmc6ICcwLjA0ZW0nLFxuICAgICAgICAgIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLFxuICAgICAgICAgIHRyYW5zaXRpb246ICdhbGwgMC4ycyBlYXNlJyxcbiAgICAgICAgICBjdXJzb3I6ICdwb2ludGVyJ1xuICAgICAgICB9fVxuICAgICAgICBvbk1vdXNlRW50ZXI9eyhlKSA9PiB7IFxuICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyNTUsIDIxNSwgMCwgMC4yKSc7IFxuICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnMCAwIDE0cHggcmdiYSgyNTUsMjE1LDAsMC4zKSc7IFxuICAgICAgICB9fVxuICAgICAgICBvbk1vdXNlTGVhdmU9eyhlKSA9PiB7IFxuICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyNTUsIDIxNSwgMCwgMC4wOCknOyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJ25vbmUnOyBcbiAgICAgICAgfX1cbiAgICAgID5cbiAgICAgICAgPEljb24gaWNvbj1cIkhvbWVcIiBzaXplPXsxM30gY29sb3I9XCIjRkZENzAwXCIgLz5cbiAgICAgICAgPHNwYW4+RGFzaGJvYXJkPC9zcGFuPlxuICAgICAgPC9hPlxuICAgIDwvQm94PlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgU2lkZWJhckJyYW5kaW5nO1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZUVmZmVjdCB9IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCwgVGV4dCwgTG9hZGVyIH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5pbXBvcnQgeyB1c2VOb3RpY2UgfSBmcm9tICdhZG1pbmpzJztcblxuY29uc3QgQWN0aW9uUmVkaXJlY3QgPSAocHJvcHMpID0+IHtcbiAgICBjb25zdCB7IHJlY29yZCwgYWN0aW9uIH0gPSBwcm9wcztcbiAgICBjb25zdCBzZW5kTm90aWNlID0gdXNlTm90aWNlKCk7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBjb25zdCB1cmwgPSByZWNvcmQ/LnBhcmFtcz8ucmVkaXJlY3RVcmw7XG4gICAgICAgIFxuICAgICAgICBpZiAodXJsKSB7XG4gICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgICAgICAgICB3aW5kb3cub3Blbih1cmwsICdfYmxhbmsnKTtcbiAgICAgICAgICAgIH0sIDUwMCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBzZW5kTm90aWNlKHsgbWVzc2FnZTogJ0Vycm9yOiBObyByZWRpcmVjdCBVUkwgcHJvdmlkZWQuJywgdHlwZTogJ2Vycm9yJyB9KTtcbiAgICAgICAgfVxuICAgIH0sIFtyZWNvcmRdKTtcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3ggZmxleCBmbGV4RGlyZWN0aW9uPVwiY29sdW1uXCIgYWxpZ25JdGVtcz1cImNlbnRlclwiIGp1c3RpZnlDb250ZW50PVwiY2VudGVyXCIgcD1cInh4bFwiPlxuICAgICAgICAgICAgPExvYWRlciAvPlxuICAgICAgICAgICAgPFRleHQgbXQ9XCJsZ1wiIHZhcmlhbnQ9XCJoNFwiPlJlZGlyZWN0aW5nLi4uPC9UZXh0PlxuICAgICAgICA8L0JveD5cbiAgICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgQWN0aW9uUmVkaXJlY3Q7XG4iLCJpbXBvcnQgUmVhY3QgZnJvbSAncmVhY3QnO1xuXG5jb25zdCBWYXJpYW50QmFkZ2UgPSAocHJvcHMpID0+IHtcbiAgY29uc3QgeyByZWNvcmQsIHByb3BlcnR5IH0gPSBwcm9wcztcbiAgaWYgKCFyZWNvcmQgfHwgIXJlY29yZC5wYXJhbXMgfHwgIXByb3BlcnR5KSByZXR1cm4gbnVsbDtcbiAgY29uc3QgaXNWYXJpYW50ID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcblxuICBpZiAoaXNWYXJpYW50ID09PSB0cnVlIHx8IGlzVmFyaWFudCA9PT0gJ3RydWUnKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxzcGFuXG4gICAgICAgIGNsYXNzTmFtZT1cImFkbWluLWN1c3RvbS1jaGlwXCJcbiAgICAgICAgZGF0YS1iYWRnZS12YWw9XCJ2YXJpYW50LWNoaWxkXCJcbiAgICAgICAgc3R5bGU9e3tcbiAgICAgICAgICBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLFxuICAgICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInLFxuICAgICAgICAgIGdhcDogJzZweCcsXG4gICAgICAgICAgcGFkZGluZzogJzNweCAxMHB4JyxcbiAgICAgICAgICBib3JkZXJSYWRpdXM6ICcyMHB4JyxcbiAgICAgICAgICBmb250U2l6ZTogJzExcHgnLFxuICAgICAgICAgIGZvbnRXZWlnaHQ6IDcwMCxcbiAgICAgICAgICBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJyxcbiAgICAgICAgICB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyxcbiAgICAgICAgICBiYWNrZ3JvdW5kOiAnbGluZWFyLWdyYWRpZW50KDE0NWRlZywgcmdiYSgxODYsIDEwNCwgMjAwLCAwLjIyKSAwJSwgcmdiYSg2NSwgMjUsIDc1LCAwLjI1KSAxMDAlKScsXG4gICAgICAgICAgY29sb3I6ICcjY2U5M2Q4JyxcbiAgICAgICAgICBib3JkZXI6ICcxcHggc29saWQgcmdiYSgxODYsIDEwNCwgMjAwLCAwLjYpJyxcbiAgICAgICAgICBib3hTaGFkb3c6ICdpbnNldCAwIDEuNXB4IDJweCByZ2JhKDI1NSwgMjU1LCAyNTUsIDAuMiksIGluc2V0IDAgLTEuNXB4IDJweCByZ2JhKDAsIDAsIDAsIDAuOCksIDAgMCAxMHB4IHJnYmEoMTg2LCAxMDQsIDIwMCwgMC4yNSknLFxuICAgICAgICAgIHRleHRTaGFkb3c6ICcwIDAgNnB4IHJnYmEoMjA2LCAxNDcsIDIxNiwgMC40KScsXG4gICAgICAgICAgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIlxuICAgICAgICB9fVxuICAgICAgPlxuICAgICAgICBWYXJpYW50XG4gICAgICA8L3NwYW4+XG4gICAgKTtcbiAgfVxuXG4gIHJldHVybiAoXG4gICAgPHNwYW5cbiAgICAgIGNsYXNzTmFtZT1cImFkbWluLWN1c3RvbS1jaGlwXCJcbiAgICAgIGRhdGEtYmFkZ2UtdmFsPVwidmFyaWFudC1tYXN0ZXJcIlxuICAgICAgc3R5bGU9e3tcbiAgICAgICAgZGlzcGxheTogJ2lubGluZS1mbGV4JyxcbiAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcicsXG4gICAgICAgIGdhcDogJzZweCcsXG4gICAgICAgIHBhZGRpbmc6ICczcHggMTBweCcsXG4gICAgICAgIGJvcmRlclJhZGl1czogJzIwcHgnLFxuICAgICAgICBmb250U2l6ZTogJzExcHgnLFxuICAgICAgICBmb250V2VpZ2h0OiA3MDAsXG4gICAgICAgIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLFxuICAgICAgICB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyxcbiAgICAgICAgYmFja2dyb3VuZDogJ2xpbmVhci1ncmFkaWVudCgxNDVkZWcsIHJnYmEoMjU1LCAyMTUsIDAsIDAuMjIpIDAlLCByZ2JhKDkwLCA3MCwgMTUsIDAuMjUpIDEwMCUpJyxcbiAgICAgICAgY29sb3I6ICcjRkZENzAwJyxcbiAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LCAyMTUsIDAsIDAuNjUpJyxcbiAgICAgICAgYm94U2hhZG93OiAnaW5zZXQgMCAxLjVweCAycHggcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjIyKSwgaW5zZXQgMCAtMS41cHggMnB4IHJnYmEoMCwgMCwgMCwgMC44KSwgMCAwIDEwcHggcmdiYSgyNTUsIDIxNSwgMCwgMC4yNSknLFxuICAgICAgICB0ZXh0U2hhZG93OiAnMCAwIDZweCByZ2JhKDI1NSwgMjE1LCAwLCAwLjQpJyxcbiAgICAgICAgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIlxuICAgICAgfX1cbiAgICA+XG4gICAgICBNYXN0ZXJcbiAgICA8L3NwYW4+XG4gICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBWYXJpYW50QmFkZ2U7XG4iLCJpbXBvcnQgUmVhY3QsIHsgdXNlU3RhdGUsIHVzZUVmZmVjdCB9IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuXG5jb25zdCBBdmF0YXJDZWxsID0gKHByb3BzKSA9PiB7XG4gICAgY29uc3QgeyByZWNvcmQsIHByb3BlcnR5LCB3aGVyZSB9ID0gcHJvcHM7IFxuICAgIGlmICghcmVjb3JkIHx8ICFyZWNvcmQucGFyYW1zIHx8ICFwcm9wZXJ0eSkgcmV0dXJuIG51bGw7XG4gICAgY29uc3Qga2V5ID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcbiAgICBjb25zdCB1c2VybmFtZSA9IHJlY29yZC5wYXJhbXMudXNlcm5hbWUgfHwgJ1VzZXInO1xuXG4gICAgY29uc3QgW2ltYWdlVXJsLCBzZXRJbWFnZVVybF0gPSB1c2VTdGF0ZShudWxsKTtcbiAgICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcbiAgICBjb25zdCBbaGFzRXJyb3IsIHNldEhhc0Vycm9yXSA9IHVzZVN0YXRlKGZhbHNlKTtcblxuICAgIHVzZUVmZmVjdCgoKSA9PiB7XG4gICAgICAgIGlmICgha2V5KSB7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChrZXkuc3RhcnRzV2l0aCgnaHR0cDovLycpIHx8IGtleS5zdGFydHNXaXRoKCdodHRwczovLycpKSB7XG4gICAgICAgICAgICBzZXRJbWFnZVVybChrZXkpO1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBmZXRjaFNpZ25lZFVybCA9IGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChgL2FwaS9hZG1pbi9zaWduZWQtdXJsP2tleT0ke2VuY29kZVVSSUNvbXBvbmVudChrZXkpfWApO1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZS5vaykge1xuICAgICAgICAgICAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzcG9uc2UuanNvbigpO1xuICAgICAgICAgICAgICAgICAgICBzZXRJbWFnZVVybChkYXRhLnVybCk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgc2V0SGFzRXJyb3IodHJ1ZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiRXJyb3IgZmV0Y2hpbmcgYXZhdGFyIFVSTDpcIiwgZXJyb3IpO1xuICAgICAgICAgICAgICAgIHNldEhhc0Vycm9yKHRydWUpO1xuICAgICAgICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcblxuICAgICAgICBmZXRjaFNpZ25lZFVybCgpO1xuICAgIH0sIFtrZXldKTtcblxuICAgIGNvbnN0IHNpemUgPSB3aGVyZSA9PT0gJ2xpc3QnID8gJzMycHgnIDogJzEyMHB4JztcblxuICAgIGlmIChsb2FkaW5nKSB7XG4gICAgICAgIHJldHVybiA8Qm94IHN0eWxlPXt7IHdpZHRoOiBzaXplLCBoZWlnaHQ6IHNpemUsIGJvcmRlclJhZGl1czogJzUwJScsIGJhY2tncm91bmRDb2xvcjogJyMzMzMnIH19IC8+O1xuICAgIH1cblxuICAgIGNvbnN0IGRlZmF1bHRBdmF0YXIgPSAnL2ltYWdlcy9kZWZhdWx0LWF2YXRhci5wbmcnO1xuXG4gICAgcmV0dXJuIChcbiAgICAgICAgPEJveD5cbiAgICAgICAgICAgIDxpbWcgXG4gICAgICAgICAgICAgICAgc3JjPXsoIWltYWdlVXJsIHx8IGhhc0Vycm9yKSA/IGRlZmF1bHRBdmF0YXIgOiBpbWFnZVVybH0gXG4gICAgICAgICAgICAgICAgYWx0PXt1c2VybmFtZX1cbiAgICAgICAgICAgICAgICBzdHlsZT17eyBcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IHNpemUsIFxuICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IHNpemUsIFxuICAgICAgICAgICAgICAgICAgICBib3JkZXJSYWRpdXM6ICc1MCUnLCBcbiAgICAgICAgICAgICAgICAgICAgb2JqZWN0Rml0OiAnY292ZXInLFxuICAgICAgICAgICAgICAgICAgICBib3JkZXI6ICcycHggc29saWQgI0ZGRDcwMCcsXG4gICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnXG4gICAgICAgICAgICAgICAgfX0gXG4gICAgICAgICAgICAgICAgb25FcnJvcj17KGUpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGUuY3VycmVudFRhcmdldC5zcmMgIT09IGRlZmF1bHRBdmF0YXIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zcmMgPSBkZWZhdWx0QXZhdGFyO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfX1cbiAgICAgICAgICAgIC8+XG4gICAgICAgIDwvQm94PlxuICAgICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBBdmF0YXJDZWxsO1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlLCB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3ggfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgSW1hZ2VQcmV2aWV3ID0gKHByb3BzKSA9PiB7XG4gICAgY29uc3QgeyByZWNvcmQsIHByb3BlcnR5LCB3aGVyZSB9ID0gcHJvcHM7IFxuICAgIGlmICghcmVjb3JkIHx8ICFyZWNvcmQucGFyYW1zIHx8ICFwcm9wZXJ0eSkgcmV0dXJuIG51bGw7XG4gICAgY29uc3QgdmFsdWUgPSByZWNvcmQucGFyYW1zW3Byb3BlcnR5Lm5hbWVdO1xuXG4gICAgY29uc3QgW2ltYWdlVXJsLCBzZXRJbWFnZVVybF0gPSB1c2VTdGF0ZShudWxsKTtcbiAgICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcblxuICAgIHVzZUVmZmVjdCgoKSA9PiB7XG4gICAgICAgIGlmICghdmFsdWUpIHtcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHZhbHVlLnN0YXJ0c1dpdGgoJ2h0dHA6Ly8nKSB8fCB2YWx1ZS5zdGFydHNXaXRoKCdodHRwczovLycpKSB7XG4gICAgICAgICAgICBzZXRJbWFnZVVybCh2YWx1ZSk7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGZldGNoU2lnbmVkVXJsID0gYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKGAvYXBpL2FkbWluL3NpZ25lZC11cmw/a2V5PSR7ZW5jb2RlVVJJQ29tcG9uZW50KHZhbHVlKX1gKTtcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgICAgICAgICAgc2V0SW1hZ2VVcmwoZGF0YS51cmwpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJGYWlsZWQgdG8gZmV0Y2ggc2lnbmVkIFVSTC5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiTmV0d29yayBlcnJvciBmZXRjaGluZyBzaWduZWQgVVJMOlwiLCBlcnJvcik7XG4gICAgICAgICAgICB9IGZpbmFsbHkge1xuICAgICAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuXG4gICAgICAgIGZldGNoU2lnbmVkVXJsKCk7XG4gICAgfSwgW3ZhbHVlXSk7XG5cbiAgICBpZiAobG9hZGluZykgcmV0dXJuIDxCb3ggc3R5bGU9e3sgY29sb3I6ICcjRkZENzAwJywgZm9udFNpemU6ICcxMnB4JyB9fT5Mb2FkaW5nLi4uPC9Cb3g+O1xuXG4gICAgY29uc3QgaXNBdmF0YXIgPSBwcm9wZXJ0eS5uYW1lID09PSAncHJvZmlsZUltYWdlS2V5JyB8fCBwcm9wZXJ0eS5uYW1lID09PSAnY2FyZEF2YXRhclVybCcgfHwgcHJvcGVydHkubmFtZSA9PT0gJ2F2YXRhcic7XG4gICAgY29uc3QgZGVmYXVsdEltYWdlID0gaXNBdmF0YXIgPyAnL2ltYWdlcy9kZWZhdWx0LWF2YXRhci5wbmcnIDogJy9pbWFnZXMvZGVmYXVsdC1hcHAtaWNvbi5wbmcnO1xuICAgIGNvbnN0IGRpc3BsYXlVcmwgPSBpbWFnZVVybCB8fCBkZWZhdWx0SW1hZ2U7XG5cbiAgICBjb25zdCBzaXplID0gd2hlcmUgPT09ICdsaXN0JyA/ICc0MHB4JyA6ICcxNTBweCc7XG4gICAgY29uc3QgcmFkaXVzID0gaXNBdmF0YXIgPyAnNTAlJyA6ICc4cHgnO1xuXG4gICAgcmV0dXJuIChcbiAgICAgICAgPEJveD5cbiAgICAgICAgICAgIDxpbWcgXG4gICAgICAgICAgICAgICAgc3JjPXtkaXNwbGF5VXJsfSBcbiAgICAgICAgICAgICAgICBhbHQ9XCJQcmV2aWV3XCIgXG4gICAgICAgICAgICAgICAgc3R5bGU9e3sgXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiByYWRpdXMsXG4gICAgICAgICAgICAgICAgICAgIG9iamVjdEZpdDogJ2NvdmVyJyxcbiAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAnIzFhMWExYScsXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlcjogJzFweCBzb2xpZCAjMzMzJ1xuICAgICAgICAgICAgICAgIH19IFxuICAgICAgICAgICAgICAgIG9uRXJyb3I9eyhlKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChlLmN1cnJlbnRUYXJnZXQuc3JjICE9PSBkZWZhdWx0SW1hZ2UpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zcmMgPSBkZWZhdWx0SW1hZ2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9fVxuICAgICAgICAgICAgLz5cbiAgICAgICAgPC9Cb3g+XG4gICAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEltYWdlUHJldmlldztcbiIsIkFkbWluSlMuVXNlckNvbXBvbmVudHMgPSB7fVxuQWRtaW5KUy5lbnYuTk9ERV9FTlYgPSBcInByb2R1Y3Rpb25cIlxuaW1wb3J0IERhc2hib2FyZCBmcm9tICcuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkRhc2hib2FyZCA9IERhc2hib2FyZFxuaW1wb3J0IFNpZGViYXJCcmFuZGluZyBmcm9tICcuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9TaWRlYmFyQnJhbmRpbmcnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLlNpZGViYXJCcmFuZGluZyA9IFNpZGViYXJCcmFuZGluZ1xuaW1wb3J0IEFjdGlvblJlZGlyZWN0IGZyb20gJy4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdCdcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuQWN0aW9uUmVkaXJlY3QgPSBBY3Rpb25SZWRpcmVjdFxuaW1wb3J0IFZhcmlhbnRCYWRnZSBmcm9tICcuLi9jb21wb25lbnRzL2NlbGxzL1ZhcmlhbnRCYWRnZSdcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuVmFyaWFudEJhZGdlID0gVmFyaWFudEJhZGdlXG5pbXBvcnQgQXZhdGFyQ2VsbCBmcm9tICcuLi9jb21wb25lbnRzL2NlbGxzL0F2YXRhckNlbGwnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkF2YXRhckNlbGwgPSBBdmF0YXJDZWxsXG5pbXBvcnQgSW1hZ2VQcmV2aWV3IGZyb20gJy4uL2NvbXBvbmVudHMvY2VsbHMvSW1hZ2VQcmV2aWV3J1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5JbWFnZVByZXZpZXcgPSBJbWFnZVByZXZpZXciXSwibmFtZXMiOlsiYXBpIiwiQXBpQ2xpZW50IiwiQyIsImJnIiwic3VyZmFjZSIsInN1cmZhY2VBbHQiLCJib3JkZXIiLCJib3JkZXJIb3ZlciIsImdvbGQiLCJnb2xkRGltIiwiZ29sZEdsb3ciLCJibHVlIiwiZ3JlZW4iLCJwdXJwbGUiLCJyZWQiLCJvcmFuZ2UiLCJ0ZXh0IiwidGV4dE11dGVkIiwidGV4dERpbSIsIlBMQVRGT1JNX0NPTE9SUyIsImNhcmRTdHlsZSIsImFjY2VudENvbG9yIiwiYmFja2dyb3VuZENvbG9yIiwiYm9yZGVyUmFkaXVzIiwiYm9yZGVyTGVmdCIsInBhZGRpbmciLCJ0cmFuc2l0aW9uIiwiY3Vyc29yIiwiYm94U2l6aW5nIiwiQXJlYUNoYXJ0IiwiZGF0YSIsIndpZHRoIiwiaGVpZ2h0IiwiY29sb3IiLCJsZW5ndGgiLCJtYXhWYWwiLCJNYXRoIiwibWF4IiwibWFwIiwiZCIsInZhbHVlIiwicGFkWCIsInBhZFkiLCJjaGFydFciLCJjaGFydEgiLCJwb2ludHMiLCJpIiwieCIsInkiLCJsaW5lUGF0aCIsInAiLCJqb2luIiwiYXJlYVBhdGgiLCJncmlkTGluZXMiLCJwY3QiLCJsYWJlbCIsInJvdW5kIiwic3RlcCIsImNlaWwiLCJSZWFjdCIsImNyZWF0ZUVsZW1lbnQiLCJzdHlsZSIsIm92ZXJmbG93Iiwidmlld0JveCIsInByZXNlcnZlQXNwZWN0UmF0aW8iLCJkaXNwbGF5IiwibWF4V2lkdGgiLCJpZCIsIngxIiwieTEiLCJ4MiIsInkyIiwib2Zmc2V0Iiwic3RvcENvbG9yIiwic3RvcE9wYWNpdHkiLCJnIiwia2V5Iiwic3Ryb2tlIiwic3Ryb2tlV2lkdGgiLCJzdHJva2VEYXNoYXJyYXkiLCJmaWxsIiwiZm9udFNpemUiLCJmb250RmFtaWx5IiwidGV4dEFuY2hvciIsInN0cm9rZUxpbmVqb2luIiwic3Ryb2tlTGluZWNhcCIsInNob3dMYWJlbCIsImN4IiwiY3kiLCJyIiwiRG9udXRDaGFydCIsInNpemUiLCJ0b3RhbCIsInJlZHVjZSIsInMiLCJvdXRlclIiLCJpbm5lclIiLCJjdW1BbmdsZSIsIlBJIiwic2xpY2VzIiwiYW5nbGUiLCJzdGFydEFuZ2xlIiwiZW5kQW5nbGUiLCJjb3MiLCJzaW4iLCJpeDEiLCJpeTEiLCJpeDIiLCJpeTIiLCJsYXJnZUFyYyIsInBhdGgiLCJuYW1lIiwiYWxpZ25JdGVtcyIsImdhcCIsImZsZXhXcmFwIiwianVzdGlmeUNvbnRlbnQiLCJmb250V2VpZ2h0IiwiZmxleERpcmVjdGlvbiIsImZsZXhTaHJpbmsiLCJtYXJnaW5MZWZ0IiwiU3RhdENhcmQiLCJpY29uIiwiZGVsdGEiLCJkZWx0YUxhYmVsIiwiQm94IiwiZmxleCIsIm1pbldpZHRoIiwib25Nb3VzZUVudGVyIiwiZSIsImN1cnJlbnRUYXJnZXQiLCJib3JkZXJDb2xvciIsInRyYW5zZm9ybSIsImJveFNoYWRvdyIsIm9uTW91c2VMZWF2ZSIsImJvcmRlckxlZnRDb2xvciIsIm1hcmdpbkJvdHRvbSIsIkljb24iLCJUZXh0IiwidGV4dFRyYW5zZm9ybSIsImxldHRlclNwYWNpbmciLCJIMiIsIm1hcmdpbiIsInVuZGVmaW5lZCIsIkFjdGlvbkNhcmQiLCJjb3VudCIsInJlc291cmNlSWQiLCJocmVmIiwidGV4dERlY29yYXRpb24iLCJINSIsImZtdERhdGUiLCJkdCIsIkRhdGUiLCJ0b0xvY2FsZURhdGVTdHJpbmciLCJtb250aCIsImRheSIsInllYXIiLCJzdGF0dXNDb2xvciIsImxvd2VyIiwidG9Mb3dlckNhc2UiLCJDdXN0b21EYXNoYm9hcmQiLCJzZXREYXRhIiwidXNlU3RhdGUiLCJsb2FkaW5nIiwic2V0TG9hZGluZyIsImVycm9yIiwic2V0RXJyb3IiLCJ1c2VFZmZlY3QiLCJnZXREYXNoYm9hcmQiLCJ0aGVuIiwicmVzcG9uc2UiLCJjYXRjaCIsImZldGNoRXJyb3IiLCJjb25zb2xlIiwibWluSGVpZ2h0IiwidGV4dEFsaWduIiwiYm9yZGVyVG9wQ29sb3IiLCJhbmltYXRpb24iLCJzdGF0cyIsImFjdGlvblJlcXVpcmVkIiwibW9kc0J5UGxhdGZvcm0iLCJ1c2VyR3Jvd3RoRGF0YSIsInJlY2VudFVzZXJzIiwicmVjZW50TW9kcyIsImdyb3d0aENoYXJ0RGF0YSIsImRhdGUiLCJ1c2VycyIsIm5vdyIsImdyZWV0aW5nIiwiZ2V0SG91cnMiLCJwYWRkaW5nQm90dG9tIiwiYm9yZGVyQm90dG9tIiwidGV4dFNoYWRvdyIsImJhY2tncm91bmQiLCJtYXJnaW5Ub3AiLCJsaW5lSGVpZ2h0Iiwid2Vla2RheSIsInRpdGxlIiwidGFyZ2V0IiwicmVsIiwidG90YWxVc2VycyIsInRvTG9jYWxlU3RyaW5nIiwibmV3VXNlcnNUaGlzTW9udGgiLCJ0b3RhbE1vZHMiLCJuZXdNb2RzVGhpc01vbnRoIiwidG90YWxEb3dubG9hZHMiLCJ0b3RhbFZpZXdzIiwicGVuZGluZ1JlcG9ydHMiLCJwZW5kaW5nQXBwcm92YWxzIiwib3BlblRpY2tldHMiLCJCYWRnZSIsIm92ZXJmbG93WCIsIldlYmtpdE92ZXJmbG93U2Nyb2xsaW5nIiwiYm9yZGVyQ29sbGFwc2UiLCJ1IiwidXNlcm5hbWUiLCJyb2xlIiwibSIsInRleHRPdmVyZmxvdyIsIndoaXRlU3BhY2UiLCJjYXRlZ29yeSIsInN0YXR1cyIsInBhZGRpbmdUb3AiLCJib3JkZXJUb3AiLCJTaWRlYmFyQnJhbmRpbmciLCJwb3NpdGlvbiIsImJvdHRvbSIsImxlZnQiLCJvcGFjaXR5Iiwic3JjIiwiYWx0Iiwib2JqZWN0Rml0IiwiZmlsdGVyIiwib25FcnJvciIsIkFjdGlvblJlZGlyZWN0IiwicHJvcHMiLCJyZWNvcmQiLCJhY3Rpb24iLCJzZW5kTm90aWNlIiwidXNlTm90aWNlIiwidXJsIiwicGFyYW1zIiwicmVkaXJlY3RVcmwiLCJzZXRUaW1lb3V0Iiwid2luZG93Iiwib3BlbiIsIm1lc3NhZ2UiLCJ0eXBlIiwiTG9hZGVyIiwibXQiLCJ2YXJpYW50IiwiVmFyaWFudEJhZGdlIiwicHJvcGVydHkiLCJpc1ZhcmlhbnQiLCJjbGFzc05hbWUiLCJBdmF0YXJDZWxsIiwid2hlcmUiLCJpbWFnZVVybCIsInNldEltYWdlVXJsIiwiaGFzRXJyb3IiLCJzZXRIYXNFcnJvciIsInN0YXJ0c1dpdGgiLCJmZXRjaFNpZ25lZFVybCIsImZldGNoIiwiZW5jb2RlVVJJQ29tcG9uZW50Iiwib2siLCJqc29uIiwiZGVmYXVsdEF2YXRhciIsIkltYWdlUHJldmlldyIsImlzQXZhdGFyIiwiZGVmYXVsdEltYWdlIiwiZGlzcGxheVVybCIsInJhZGl1cyIsIkFkbWluSlMiLCJVc2VyQ29tcG9uZW50cyIsImVudiIsIk5PREVfRU5WIiwiRGFzaGJvYXJkIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0VBSUEsTUFBTUEsR0FBRyxHQUFHLElBQUlDLGlCQUFTLEVBQUU7O0VBRTNCO0VBQ0EsTUFBTUMsQ0FBQyxHQUFHO0VBQ1JDLEVBQUFBLEVBQUUsRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE9BQU8sRUFBRSxTQUFTO0VBQUVDLEVBQUFBLFVBQVUsRUFBRSxTQUFTO0VBQ3hEQyxFQUFBQSxNQUFNLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxXQUFXLEVBQUUsU0FBUztFQUN6Q0MsRUFBQUEsSUFBSSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsT0FBTyxFQUFFLHNCQUFzQjtFQUFFQyxFQUFBQSxRQUFRLEVBQUUsc0JBQXNCO0VBQ2xGQyxFQUFBQSxJQUFJLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxLQUFLLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxNQUFNLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxHQUFHLEVBQUUs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
