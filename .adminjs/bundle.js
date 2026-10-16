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
        gap: '8px',
        maxWidth: '100%',
        marginTop: '6px'
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
        padding: '7px 12px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '12px',
        lineHeight: 1.4,
        transition: 'all 0.2s',
        fontFamily: "'Poppins', sans-serif",
        flexShrink: 0
      },
      onMouseEnter: e => {
        e.currentTarget.style.backgroundColor = 'rgba(255,215,0,0.25)';
      },
      onMouseLeave: e => {
        e.currentTarget.style.backgroundColor = C.goldDim;
      },
      title: "Go Back To User Dashboard"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "ArrowLeft",
      size: 13
    }), " Dashboard"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/reports",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        color: '#ff6b6b',
        backgroundColor: 'rgba(229,57,53,0.12)',
        border: '1px solid rgba(229,57,53,0.3)',
        padding: '7px 12px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '12px',
        lineHeight: 1.4,
        transition: 'all 0.2s',
        flexShrink: 0
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
      size: 13
    }), " Reports"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/support",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        color: '#64b5f6',
        backgroundColor: 'rgba(33,150,243,0.12)',
        border: '1px solid rgba(33,150,243,0.3)',
        padding: '7px 12px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '12px',
        lineHeight: 1.4,
        transition: 'all 0.2s',
        flexShrink: 0
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
      size: 13
    }), " Support"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/status",
      target: "_blank",
      rel: "noopener noreferrer",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        color: '#81c784',
        backgroundColor: 'rgba(67,160,71,0.12)',
        border: '1px solid rgba(67,160,71,0.3)',
        padding: '7px 12px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '12px',
        lineHeight: 1.4,
        transition: 'all 0.2s',
        flexShrink: 0
      },
      onMouseEnter: e => {
        e.currentTarget.style.backgroundColor = 'rgba(67,160,71,0.25)';
      },
      onMouseLeave: e => {
        e.currentTarget.style.backgroundColor = 'rgba(67,160,71,0.12)';
      },
      title: "Live Server Diagnostics & Health"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Activity",
      size: 13
    }), " Diagnostics"), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/admin/music",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        color: '#ba68c8',
        backgroundColor: 'rgba(186,104,200,0.12)',
        border: '1px solid rgba(186,104,200,0.3)',
        padding: '7px 12px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '12px',
        lineHeight: 1.4,
        transition: 'all 0.2s',
        flexShrink: 0
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
      size: 13
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
        padding: '7px 12px',
        borderRadius: '8px',
        textDecoration: 'none',
        fontWeight: 600,
        fontSize: '12px',
        lineHeight: 1.4,
        transition: 'all 0.2s',
        flexShrink: 0
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
      size: 13
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
      record
    } = props;
    const sendNotice = adminjs.useNotice();
    const url = record?.params?.redirectUrl;
    React.useEffect(() => {
      if (!url) {
        sendNotice({
          message: 'Error: No redirect URL provided.',
          type: 'error'
        });
        return;
      }

      // Internal admin navigation: Redirect in the SAME tab so user is not stuck on spinner
      if (url.startsWith('/admin')) {
        window.location.href = url;
      } else {
        // External or frontend route: open in new tab, and restore previous history in admin tab
        window.open(url, '_blank');
        setTimeout(() => {
          if (window.history.length > 1) {
            window.history.back();
          } else if (record?.params?._id) {
            window.location.href = `/admin/resources/File/records/${record.params._id}/show`;
          }
        }, 600);
      }
    }, [record, url]);
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      p: "xxl"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Loader, null), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      mt: "lg",
      variant: "h4"
    }, "Redirecting..."), url && /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      mt: "md"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      size: "sm",
      variant: "primary",
      onClick: () => {
        window.location.href = url;
      },
      style: {
        cursor: 'pointer'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "ExternalLink",
      style: {
        marginRight: '6px'
      }
    }), "Click here if not redirected automatically")));
  };

  const DownloadInspector = props => {
    const {
      record
    } = props;
    const sendNotice = adminjs.useNotice();
    const [copied, setCopied] = React.useState(false);
    if (!record || !record.params) {
      return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
        p: "xl",
        textAlign: "center"
      }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
        variant: "h4"
      }, "No record data found."));
    }
    const fileId = record.params._id || record.id;
    const fileName = record.params.name || 'Mod File';
    const fileVersion = record.params.version || '1.0';
    const fileSize = record.params.fileSize || 'N/A';
    const externalUrl = record.params.externalDownloadUrl || '';
    const fileKey = record.params.fileKey || '';
    const directUrl = record.params.directDownloadUrl || '';
    const isMultiPart = record.params.isMultiPart === true || record.params.isMultiPart === 'true';

    // The primary valid download endpoint generated by the server
    const primaryDownloadUrl = `${window.location.origin}/download-file/${fileId}`;
    const handleCopy = urlToCopy => {
      if (!urlToCopy) return;
      navigator.clipboard.writeText(urlToCopy).then(() => {
        setCopied(true);
        sendNotice({
          message: 'Download URL copied to clipboard!',
          type: 'success'
        });
        setTimeout(() => setCopied(false), 3000);
      }).catch(() => {
        sendNotice({
          message: 'Failed to copy URL to clipboard.',
          type: 'error'
        });
      });
    };
    const handleStartDownload = targetUrl => {
      sendNotice({
        message: 'Initiating file download in new tab...',
        type: 'info'
      });
      window.open(targetUrl || primaryDownloadUrl, '_blank');
    };
    const handleBack = () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = `/admin/resources/File/records/${fileId}/show`;
      }
    };
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      p: "xxl",
      style: {
        maxWidth: '820px',
        margin: '0 auto',
        fontFamily: "'Poppins', sans-serif"
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      p: "xl",
      style: {
        backgroundColor: '#161924',
        border: '1px solid rgba(255, 215, 0, 0.35)',
        borderRadius: '16px',
        boxShadow: '0 12px 35px rgba(0, 0, 0, 0.65)'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      justifyContent: "space-between",
      alignItems: "center",
      mb: "xl"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Box, null, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      variant: "h3",
      style: {
        color: '#FFD700',
        margin: 0,
        fontWeight: 700
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Download",
      style: {
        marginRight: '10px'
      }
    }), "Download Inspector"), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#aaa',
        fontSize: '13px',
        marginTop: '4px'
      }
    }, "Inspect, verify, copy or test download URLs safely without unwanted downloads")), /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      variant: "light",
      size: "sm",
      onClick: handleBack,
      style: {
        cursor: 'pointer'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "ArrowLeft",
      style: {
        marginRight: '6px'
      }
    }), "Back to Mod")), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      p: "lg",
      mb: "xl",
      style: {
        backgroundColor: '#0e1017',
        borderRadius: '10px',
        border: '1px solid rgba(255, 255, 255, 0.08)'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      justifyContent: "space-between",
      alignItems: "center",
      flexWrap: "wrap",
      style: {
        gap: '10px'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", null, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#fff',
        fontSize: '16px',
        fontWeight: 600
      }
    }, fileName), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#888',
        fontSize: '12px'
      }
    }, "ID: ", fileId)), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      style: {
        gap: '8px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Badge, {
      variant: "primary",
      style: {
        backgroundColor: '#2a2f45',
        color: '#c0c6e0'
      }
    }, "v", fileVersion), /*#__PURE__*/React__default.default.createElement(designSystem.Badge, {
      variant: "info",
      style: {
        backgroundColor: '#1d3557',
        color: '#64b5f6'
      }
    }, "Size: ", fileSize), isMultiPart && /*#__PURE__*/React__default.default.createElement(designSystem.Badge, {
      variant: "warning",
      style: {
        backgroundColor: '#4a3800',
        color: '#ffd54f'
      }
    }, "Multi-Part File")))), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      mb: "xl"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#FFD700',
        fontWeight: 600,
        fontSize: '13px',
        textTransform: 'uppercase',
        letterSpacing: '0.5px',
        marginBottom: '8px'
      }
    }, "Primary Verified Download Route:"), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      p: "md",
      style: {
        backgroundColor: '#0b0c10',
        border: '1px solid #333',
        borderRadius: '8px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#00e5ff',
        fontFamily: 'monospace',
        fontSize: '13px',
        wordBreak: 'break-all'
      }
    }, primaryDownloadUrl), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      style: {
        gap: '8px',
        flexShrink: 0
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      size: "sm",
      variant: "secondary",
      onClick: () => handleCopy(primaryDownloadUrl),
      style: {
        cursor: 'pointer',
        background: copied ? '#2ecc71' : undefined
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: copied ? 'Check' : 'Copy',
      style: {
        marginRight: '6px'
      }
    }), copied ? 'Copied' : 'Copy URL'), /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      size: "sm",
      variant: "primary",
      onClick: () => handleStartDownload(primaryDownloadUrl),
      style: {
        backgroundColor: '#FFD700',
        color: '#000',
        fontWeight: 600,
        cursor: 'pointer'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "ExternalLink",
      style: {
        marginRight: '6px'
      }
    }), "Test Download")))), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      mb: "lg"
    }, externalUrl && /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      mb: "md"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#bbb',
        fontSize: '12px',
        fontWeight: 600,
        marginBottom: '4px'
      }
    }, "External Cloud Mirror URL:"), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      p: "sm",
      style: {
        backgroundColor: '#0b0c10',
        border: '1px solid #222',
        borderRadius: '6px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#ccc',
        fontSize: '12px',
        fontFamily: 'monospace',
        wordBreak: 'break-all'
      }
    }, externalUrl), /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      size: "sm",
      variant: "text",
      onClick: () => handleCopy(externalUrl),
      style: {
        cursor: 'pointer',
        color: '#FFD700'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Copy"
    })))), fileKey && /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      mb: "md"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#bbb',
        fontSize: '12px',
        fontWeight: 600,
        marginBottom: '4px'
      }
    }, "Backblaze B2 Storage Key:"), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      p: "sm",
      style: {
        backgroundColor: '#0b0c10',
        border: '1px solid #222',
        borderRadius: '6px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#aaa',
        fontSize: '12px',
        fontFamily: 'monospace',
        wordBreak: 'break-all'
      }
    }, fileKey), /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      size: "sm",
      variant: "text",
      onClick: () => handleCopy(fileKey),
      style: {
        cursor: 'pointer',
        color: '#FFD700'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Copy"
    })))), directUrl && /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      mb: "md"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#bbb',
        fontSize: '12px',
        fontWeight: 600,
        marginBottom: '4px'
      }
    }, "Direct CDN / Cloudflare Passthrough:"), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      p: "sm",
      style: {
        backgroundColor: '#0b0c10',
        border: '1px solid #222',
        borderRadius: '6px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#2ecc71',
        fontSize: '12px',
        fontFamily: 'monospace',
        wordBreak: 'break-all'
      }
    }, directUrl), /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      size: "sm",
      variant: "text",
      onClick: () => handleCopy(directUrl),
      style: {
        cursor: 'pointer',
        color: '#FFD700'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Copy"
    }))))), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      justifyContent: "flex-end",
      style: {
        gap: '10px'
      },
      mt: "xl",
      pt: "lg",
      borderTop: "1px solid rgba(255, 255, 255, 0.08)"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      variant: "light",
      onClick: handleBack,
      style: {
        cursor: 'pointer'
      }
    }, "Done"), /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      variant: "primary",
      onClick: () => handleStartDownload(primaryDownloadUrl),
      style: {
        backgroundColor: '#FFD700',
        color: '#000',
        fontWeight: 600,
        cursor: 'pointer'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Download",
      style: {
        marginRight: '6px'
      }
    }), "Launch Download"))));
  };

  const VariantBadge = props => {
    const {
      record,
      property
    } = props;
    if (!record || !record.params || !property) return null;
    const isVariant = record.params[property.name];
    const isVar = isVariant === true || isVariant === 'true';
    const masterId = record.params.masterFile;
    const recordId = record.params._id || record.id;
    const handleClick = e => {
      e.preventDefault();
      e.stopPropagation();
      if (isVar && masterId) {
        window.location.href = `/admin/resources/File/records/${masterId}/show`;
      } else {
        window.location.href = `/admin/resources/File?filters.masterFile=${recordId}`;
      }
    };
    if (isVar) {
      return /*#__PURE__*/React__default.default.createElement("a", {
        href: masterId ? `/admin/resources/File/records/${masterId}/show` : '#',
        onClick: handleClick,
        title: masterId ? `Click to view Master App (${masterId})` : 'Variant Mod',
        className: "admin-custom-chip",
        "data-badge-val": "variant-child",
        style: {
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '4px 11px',
          borderRadius: '20px',
          fontSize: '11px',
          fontWeight: 700,
          letterSpacing: '0.06em',
          textTransform: 'uppercase',
          background: 'linear-gradient(145deg, rgba(186, 104, 200, 0.28) 0%, rgba(65, 25, 75, 0.35) 100%)',
          color: '#e1bee7',
          border: '1px solid rgba(186, 104, 200, 0.7)',
          boxShadow: 'inset 0 1.5px 2px rgba(255, 255, 255, 0.2), 0 0 10px rgba(186, 104, 200, 0.3)',
          textShadow: '0 0 6px rgba(206, 147, 216, 0.4)',
          fontFamily: "'Poppins', sans-serif",
          textDecoration: 'none',
          cursor: 'pointer',
          transition: 'all 0.2s ease'
        },
        onMouseEnter: e => {
          e.currentTarget.style.transform = 'scale(1.05)';
          e.currentTarget.style.borderColor = '#ce93d8';
        },
        onMouseLeave: e => {
          e.currentTarget.style.transform = 'scale(1)';
          e.currentTarget.style.borderColor = 'rgba(186, 104, 200, 0.7)';
        }
      }, /*#__PURE__*/React__default.default.createElement("span", {
        style: {
          fontSize: '10px'
        }
      }, "\u26A1"), " Variant");
    }
    return /*#__PURE__*/React__default.default.createElement("a", {
      href: `/admin/resources/File?filters.masterFile=${recordId}`,
      onClick: handleClick,
      title: "Click to view all Variants of this Master Mod",
      className: "admin-custom-chip",
      "data-badge-val": "variant-master",
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: '4px 11px',
        borderRadius: '20px',
        fontSize: '11px',
        fontWeight: 700,
        letterSpacing: '0.06em',
        textTransform: 'uppercase',
        background: 'linear-gradient(145deg, rgba(255, 215, 0, 0.25) 0%, rgba(90, 70, 15, 0.3) 100%)',
        color: '#FFD700',
        border: '1px solid rgba(255, 215, 0, 0.75)',
        boxShadow: 'inset 0 1.5px 2px rgba(255, 255, 255, 0.22), 0 0 10px rgba(255, 215, 0, 0.3)',
        textShadow: '0 0 6px rgba(255, 215, 0, 0.4)',
        fontFamily: "'Poppins', sans-serif",
        textDecoration: 'none',
        cursor: 'pointer',
        transition: 'all 0.2s ease'
      },
      onMouseEnter: e => {
        e.currentTarget.style.transform = 'scale(1.05)';
        e.currentTarget.style.borderColor = '#fff';
      },
      onMouseLeave: e => {
        e.currentTarget.style.transform = 'scale(1)';
        e.currentTarget.style.borderColor = 'rgba(255, 215, 0, 0.75)';
      }
    }, /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        fontSize: '10px'
      }
    }, "\uD83D\uDC51"), " Master");
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
  AdminJS.UserComponents.DownloadInspector = DownloadInspector;
  AdminJS.UserComponents.VariantBadge = VariantBadge;
  AdminJS.UserComponents.AvatarCell = AvatarCell;
  AdminJS.UserComponents.ImagePreview = ImagePreview;

})(React, AdminJS, AdminJSDesignSystem);
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIiwic291cmNlcyI6WyIuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQuanN4IiwiLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nLmpzeCIsIi4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdC5qc3giLCIuLi9jb21wb25lbnRzL2FjdGlvbnMvRG93bmxvYWRJbnNwZWN0b3IuanN4IiwiLi4vY29tcG9uZW50cy9jZWxscy9WYXJpYW50QmFkZ2UuanN4IiwiLi4vY29tcG9uZW50cy9jZWxscy9BdmF0YXJDZWxsLmpzeCIsIi4uL2NvbXBvbmVudHMvY2VsbHMvSW1hZ2VQcmV2aWV3LmpzeCIsImVudHJ5LmpzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQXBpQ2xpZW50IH0gZnJvbSAnYWRtaW5qcyc7XG5pbXBvcnQgeyBCb3gsIEgyLCBINSwgVGV4dCwgSWNvbiwgQmFkZ2UgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgYXBpID0gbmV3IEFwaUNsaWVudCgpO1xuXG4vKiDilIDilIDilIAgY29sb3VyIHRva2VucyDilIDilIDilIAgKi9cbmNvbnN0IEMgPSB7XG4gIGJnOiAnIzBhMGEwYScsIHN1cmZhY2U6ICcjMTMxMzEzJywgc3VyZmFjZUFsdDogJyMxYTFhMWEnLFxuICBib3JkZXI6ICcjMmEyYTJhJywgYm9yZGVySG92ZXI6ICcjM2EzYTNhJyxcbiAgZ29sZDogJyNGRkQ3MDAnLCBnb2xkRGltOiAncmdiYSgyNTUsMjE1LDAsMC4xNSknLCBnb2xkR2xvdzogJ3JnYmEoMjU1LDIxNSwwLDAuMzUpJyxcbiAgYmx1ZTogJyMyMTk2RjMnLCBncmVlbjogJyM0M2EwNDcnLCBwdXJwbGU6ICcjOUMyN0IwJywgcmVkOiAnI2U1MzkzNScsIG9yYW5nZTogJyNGRjk4MDAnLFxuICB0ZXh0OiAnI2ZmZmZmZicsIHRleHRNdXRlZDogJyNlMmU4ZjAnLCB0ZXh0RGltOiAnI2NiZDVlMScsXG59O1xuXG4vKiDilIDilIDilIAgcGxhdGZvcm0gY2hhcnQgY29sb3VycyDilIDilIDilIAgKi9cbmNvbnN0IFBMQVRGT1JNX0NPTE9SUyA9IFsnI0E0QzYzOScsICcjMDA3OEQ2JywgJyMyMTc1OUInLCAnI0ZGOTgwMCcsICcjOUMyN0IwJywgJyNlNTM5MzUnLCAnIzQzYTA0NycsICcjRkZENzAwJ107XG5cbi8qIOKUgOKUgOKUgCByZXVzYWJsZSBjYXJkIHN0eWxlIOKUgOKUgOKUgCAqL1xuY29uc3QgY2FyZFN0eWxlID0gKGFjY2VudENvbG9yKSA9PiAoe1xuICBiYWNrZ3JvdW5kQ29sb3I6IEMuc3VyZmFjZSxcbiAgYm9yZGVyUmFkaXVzOiAnMTZweCcsXG4gIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsXG4gIGJvcmRlckxlZnQ6IGFjY2VudENvbG9yID8gYDRweCBzb2xpZCAke2FjY2VudENvbG9yfWAgOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCxcbiAgcGFkZGluZzogJ2NsYW1wKDE2cHgsIDIuNXZ3LCAyNHB4KScsXG4gIHRyYW5zaXRpb246ICdhbGwgMC4yNXMgZWFzZScsXG4gIGN1cnNvcjogJ2RlZmF1bHQnLFxuICBib3hTaXppbmc6ICdib3JkZXItYm94Jyxcbn0pO1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBBcmVhIENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgQXJlYUNoYXJ0ID0gKHsgZGF0YSwgd2lkdGggPSA1MDAsIGhlaWdodCA9IDE3MCwgY29sb3IgPSBDLmdvbGQgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBtYXhWYWwgPSBNYXRoLm1heCguLi5kYXRhLm1hcChkID0+IGQudmFsdWUpLCAxKTtcbiAgY29uc3QgcGFkWCA9IDM1O1xuICBjb25zdCBwYWRZID0gMTY7XG4gIGNvbnN0IGNoYXJ0VyA9IHdpZHRoIC0gcGFkWCAqIDI7XG4gIGNvbnN0IGNoYXJ0SCA9IGhlaWdodCAtIHBhZFkgKiAyO1xuXG4gIGNvbnN0IHBvaW50cyA9IGRhdGEubWFwKChkLCBpKSA9PiAoe1xuICAgIHg6IHBhZFggKyAoaSAvIE1hdGgubWF4KGRhdGEubGVuZ3RoIC0gMSwgMSkpICogY2hhcnRXLFxuICAgIHk6IHBhZFkgKyBjaGFydEggLSAoZC52YWx1ZSAvIG1heFZhbCkgKiBjaGFydEgsXG4gIH0pKTtcblxuICBjb25zdCBsaW5lUGF0aCA9IHBvaW50cy5tYXAoKHAsIGkpID0+IGAke2kgPT09IDAgPyAnTScgOiAnTCd9JHtwLnh9LCR7cC55fWApLmpvaW4oJyAnKTtcbiAgY29uc3QgYXJlYVBhdGggPSBgJHtsaW5lUGF0aH0gTCR7cG9pbnRzW3BvaW50cy5sZW5ndGggLSAxXS54fSwke3BhZFkgKyBjaGFydEh9IEwke3BvaW50c1swXS54fSwke3BhZFkgKyBjaGFydEh9IFpgO1xuXG4gIC8vIEdyaWQgbGluZXNcbiAgY29uc3QgZ3JpZExpbmVzID0gWzAsIDAuMjUsIDAuNSwgMC43NSwgMV0ubWFwKHBjdCA9PiB7XG4gICAgY29uc3QgeSA9IHBhZFkgKyBjaGFydEggLSBwY3QgKiBjaGFydEg7XG4gICAgY29uc3QgbGFiZWwgPSBNYXRoLnJvdW5kKHBjdCAqIG1heFZhbCk7XG4gICAgcmV0dXJuIHsgeSwgbGFiZWwgfTtcbiAgfSk7XG5cbiAgY29uc3Qgc3RlcCA9IGRhdGEubGVuZ3RoID4gOCA/IE1hdGguY2VpbChkYXRhLmxlbmd0aCAvIDUpIDogMTtcblxuICByZXR1cm4gKFxuICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6ICcxMDAlJywgb3ZlcmZsb3c6ICdoaWRkZW4nIH19PlxuICAgICAgPHN2ZyB3aWR0aD1cIjEwMCVcIiBoZWlnaHQ9e2hlaWdodH0gdmlld0JveD17YDAgMCAke3dpZHRofSAke2hlaWdodH1gfSBwcmVzZXJ2ZUFzcGVjdFJhdGlvPVwibm9uZVwiIHN0eWxlPXt7IGRpc3BsYXk6ICdibG9jaycsIG1heFdpZHRoOiAnMTAwJScgfX0+XG4gICAgICAgIDxkZWZzPlxuICAgICAgICAgIDxsaW5lYXJHcmFkaWVudCBpZD1cImFyZWFGaWxsXCIgeDE9XCIwXCIgeTE9XCIwXCIgeDI9XCIwXCIgeTI9XCIxXCI+XG4gICAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIwJVwiIHN0b3BDb2xvcj17Y29sb3J9IHN0b3BPcGFjaXR5PVwiMC4zNVwiIC8+XG4gICAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIxMDAlXCIgc3RvcENvbG9yPXtjb2xvcn0gc3RvcE9wYWNpdHk9XCIwLjAyXCIgLz5cbiAgICAgICAgICA8L2xpbmVhckdyYWRpZW50PlxuICAgICAgICA8L2RlZnM+XG4gICAgICAgIHsvKiBHcmlkICovfVxuICAgICAgICB7Z3JpZExpbmVzLm1hcCgoZywgaSkgPT4gKFxuICAgICAgICAgIDxnIGtleT17aX0+XG4gICAgICAgICAgICA8bGluZSB4MT17cGFkWH0geTE9e2cueX0geDI9e3dpZHRoIC0gcGFkWH0geTI9e2cueX0gc3Ryb2tlPXtDLmJvcmRlcn0gc3Ryb2tlV2lkdGg9XCIxXCIgc3Ryb2tlRGFzaGFycmF5PVwiMyAzXCIgLz5cbiAgICAgICAgICAgIDx0ZXh0IHg9e3BhZFggLSA2fSB5PXtnLnkgKyA0fSBmaWxsPVwiIzk0YTNiOFwiIGZvbnRTaXplPVwiOVwiIGZvbnRGYW1pbHk9XCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB0ZXh0QW5jaG9yPVwiZW5kXCI+e2cubGFiZWx9PC90ZXh0PlxuICAgICAgICAgIDwvZz5cbiAgICAgICAgKSl9XG4gICAgICAgIHsvKiBBcmVhIGZpbGwgKi99XG4gICAgICAgIDxwYXRoIGQ9e2FyZWFQYXRofSBmaWxsPVwidXJsKCNhcmVhRmlsbClcIiAvPlxuICAgICAgICB7LyogTGluZSAqL31cbiAgICAgICAgPHBhdGggZD17bGluZVBhdGh9IGZpbGw9XCJub25lXCIgc3Ryb2tlPXtjb2xvcn0gc3Ryb2tlV2lkdGg9XCIyLjVcIiBzdHJva2VMaW5lam9pbj1cInJvdW5kXCIgc3Ryb2tlTGluZWNhcD1cInJvdW5kXCIgLz5cbiAgICAgICAgey8qIERvdHMgKyBsYWJlbHMgKi99XG4gICAgICAgIHtwb2ludHMubWFwKChwLCBpKSA9PiB7XG4gICAgICAgICAgY29uc3Qgc2hvd0xhYmVsID0gKGkgPT09IDAgfHwgaSA9PT0gZGF0YS5sZW5ndGggLSAxIHx8IGkgJSBzdGVwID09PSAwKTtcbiAgICAgICAgICByZXR1cm4gKFxuICAgICAgICAgICAgPGcga2V5PXtpfT5cbiAgICAgICAgICAgICAgPGNpcmNsZSBjeD17cC54fSBjeT17cC55fSByPVwiM1wiIGZpbGw9e0MuYmd9IHN0cm9rZT17Y29sb3J9IHN0cm9rZVdpZHRoPVwiMlwiIC8+XG4gICAgICAgICAgICAgIHtzaG93TGFiZWwgJiYgKFxuICAgICAgICAgICAgICAgIDx0ZXh0IHg9e3AueH0geT17cGFkWSArIGNoYXJ0SCArIDE0fSBmaWxsPVwiI2NiZDVlMVwiIGZvbnRTaXplPVwiOVwiIGZvbnRGYW1pbHk9XCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e2RhdGFbaV0ubGFiZWx9PC90ZXh0PlxuICAgICAgICAgICAgICApfVxuICAgICAgICAgICAgPC9nPlxuICAgICAgICAgICk7XG4gICAgICAgIH0pfVxuICAgICAgPC9zdmc+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBEb251dCBDaGFydCDilIDilIDilIAgKi9cbmNvbnN0IERvbnV0Q2hhcnQgPSAoeyBkYXRhLCBzaXplID0gMjAwIH0pID0+IHtcbiAgaWYgKCFkYXRhIHx8IGRhdGEubGVuZ3RoID09PSAwKSByZXR1cm4gbnVsbDtcbiAgY29uc3QgdG90YWwgPSBkYXRhLnJlZHVjZSgocywgZCkgPT4gcyArIGQudmFsdWUsIDApO1xuICBpZiAodG90YWwgPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBjeCA9IHNpemUgLyAyO1xuICBjb25zdCBjeSA9IHNpemUgLyAyO1xuICBjb25zdCBvdXRlclIgPSBzaXplIC8gMiAtIDEwO1xuICBjb25zdCBpbm5lclIgPSBvdXRlclIgKiAwLjY7XG4gIGxldCBjdW1BbmdsZSA9IC1NYXRoLlBJIC8gMjtcblxuICBjb25zdCBzbGljZXMgPSBkYXRhLm1hcCgoZCwgaSkgPT4ge1xuICAgIGNvbnN0IGFuZ2xlID0gKGQudmFsdWUgLyB0b3RhbCkgKiBNYXRoLlBJICogMjtcbiAgICBjb25zdCBzdGFydEFuZ2xlID0gY3VtQW5nbGU7XG4gICAgY3VtQW5nbGUgKz0gYW5nbGU7XG4gICAgY29uc3QgZW5kQW5nbGUgPSBjdW1BbmdsZTtcblxuICAgIGNvbnN0IHgxID0gY3ggKyBvdXRlclIgKiBNYXRoLmNvcyhzdGFydEFuZ2xlKTtcbiAgICBjb25zdCB5MSA9IGN5ICsgb3V0ZXJSICogTWF0aC5zaW4oc3RhcnRBbmdsZSk7XG4gICAgY29uc3QgeDIgPSBjeCArIG91dGVyUiAqIE1hdGguY29zKGVuZEFuZ2xlKTtcbiAgICBjb25zdCB5MiA9IGN5ICsgb3V0ZXJSICogTWF0aC5zaW4oZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl4MSA9IGN4ICsgaW5uZXJSICogTWF0aC5jb3MoZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl5MSA9IGN5ICsgaW5uZXJSICogTWF0aC5zaW4oZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl4MiA9IGN4ICsgaW5uZXJSICogTWF0aC5jb3Moc3RhcnRBbmdsZSk7XG4gICAgY29uc3QgaXkyID0gY3kgKyBpbm5lclIgKiBNYXRoLnNpbihzdGFydEFuZ2xlKTtcbiAgICBjb25zdCBsYXJnZUFyYyA9IGFuZ2xlID4gTWF0aC5QSSA/IDEgOiAwO1xuICAgIGNvbnN0IGNvbG9yID0gUExBVEZPUk1fQ09MT1JTW2kgJSBQTEFURk9STV9DT0xPUlMubGVuZ3RoXTtcblxuICAgIGNvbnN0IHBhdGggPSBgTSR7eDF9LCR7eTF9IEEke291dGVyUn0sJHtvdXRlclJ9IDAgJHtsYXJnZUFyY30gMSAke3gyfSwke3kyfSBMJHtpeDF9LCR7aXkxfSBBJHtpbm5lclJ9LCR7aW5uZXJSfSAwICR7bGFyZ2VBcmN9IDAgJHtpeDJ9LCR7aXkyfSBaYDtcbiAgICByZXR1cm4geyBwYXRoLCBjb2xvciwgbmFtZTogZC5uYW1lLCB2YWx1ZTogZC52YWx1ZSwgcGN0OiBNYXRoLnJvdW5kKChkLnZhbHVlIC8gdG90YWwpICogMTAwKSB9O1xuICB9KTtcblxuICByZXR1cm4gKFxuICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMjRweCcsIGZsZXhXcmFwOiAnd3JhcCcsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgIDxzdmcgd2lkdGg9e3NpemV9IGhlaWdodD17c2l6ZX0gdmlld0JveD17YDAgMCAke3NpemV9ICR7c2l6ZX1gfT5cbiAgICAgICAge3NsaWNlcy5tYXAoKHMsIGkpID0+IChcbiAgICAgICAgICA8cGF0aCBrZXk9e2l9IGQ9e3MucGF0aH0gZmlsbD17cy5jb2xvcn0gc3Ryb2tlPXtDLmJnfSBzdHJva2VXaWR0aD1cIjJcIj5cbiAgICAgICAgICAgIDx0aXRsZT57cy5uYW1lfToge3MudmFsdWV9ICh7cy5wY3R9JSk8L3RpdGxlPlxuICAgICAgICAgIDwvcGF0aD5cbiAgICAgICAgKSl9XG4gICAgICAgIDx0ZXh0IHg9e2N4fSB5PXtjeSAtIDZ9IGZpbGw9e0MudGV4dH0gZm9udFNpemU9XCIyMlwiIGZvbnRXZWlnaHQ9XCJib2xkXCIgdGV4dEFuY2hvcj1cIm1pZGRsZVwiPnt0b3RhbH08L3RleHQ+XG4gICAgICAgIDx0ZXh0IHg9e2N4fSB5PXtjeSArIDE0fSBmaWxsPXtDLnRleHRNdXRlZH0gZm9udFNpemU9XCIxMFwiIHRleHRBbmNob3I9XCJtaWRkbGVcIj5UT1RBTDwvdGV4dD5cbiAgICAgIDwvc3ZnPlxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhEaXJlY3Rpb246ICdjb2x1bW4nLCBnYXA6ICc2cHgnIH19PlxuICAgICAgICB7c2xpY2VzLm1hcCgocywgaSkgPT4gKFxuICAgICAgICAgIDxkaXYga2V5PXtpfSBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnIH19PlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgd2lkdGg6IDEyLCBoZWlnaHQ6IDEyLCBib3JkZXJSYWRpdXM6ICczcHgnLCBiYWNrZ3JvdW5kQ29sb3I6IHMuY29sb3IsIGRpc3BsYXk6ICdpbmxpbmUtYmxvY2snLCBmbGV4U2hyaW5rOiAwIH19IC8+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy50ZXh0IH19PntzLm5hbWV9PC9zcGFuPlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgbWFyZ2luTGVmdDogJ2F1dG8nIH19PntzLnZhbHVlfSAoe3MucGN0fSUpPC9zcGFuPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICApKX1cbiAgICAgIDwvZGl2PlxuICAgIDwvZGl2PlxuICApO1xufTtcblxuLyog4pSA4pSA4pSAIFN0YXQgQ2FyZCDilIDilIDilIAgKi9cbmNvbnN0IFN0YXRDYXJkID0gKHsgaWNvbiwgbGFiZWwsIHZhbHVlLCBkZWx0YSwgZGVsdGFMYWJlbCwgYWNjZW50Q29sb3IgfSkgPT4gKFxuICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZShhY2NlbnRDb2xvciksIGZsZXg6ICcxJywgbWluV2lkdGg6ICcyMjBweCcgfX1cbiAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBhY2NlbnRDb2xvciB8fCBDLmJvcmRlckhvdmVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoLTJweCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gYDAgOHB4IDI0cHggcmdiYSgwLDAsMCwwLjQpYDsgfX1cbiAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckxlZnRDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoMCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJ25vbmUnOyB9fVxuICA+XG4gICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcxNHB4JyB9fT5cbiAgICAgIDxJY29uIGljb249e2ljb259IGNvbG9yPXthY2NlbnRDb2xvcn0gLz5cbiAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMXB4JywgZm9udFdlaWdodDogNzAwLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDhlbScgfX0+e2xhYmVsfTwvVGV4dD5cbiAgICA8L2Rpdj5cbiAgICA8SDIgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAnMCAwIDhweCAwJywgZm9udFNpemU6ICcyLjJyZW0nIH19Pnt2YWx1ZX08L0gyPlxuICAgIHtkZWx0YSAhPT0gdW5kZWZpbmVkICYmIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JyB9fT5cbiAgICAgICAgPEljb24gaWNvbj1cIkFycm93VXBcIiBzaXplPXsxNH0gY29sb3I9e0MuZ3JlZW59IC8+XG4gICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLmdyZWVuLCBmb250U2l6ZTogJzEzcHgnLCBmb250V2VpZ2h0OiA2MDAgfX0+K3tkZWx0YX0ge2RlbHRhTGFiZWwgfHwgJ3RoaXMgbW9udGgnfTwvVGV4dD5cbiAgICAgIDwvZGl2PlxuICAgICl9XG4gIDwvQm94PlxuKTtcblxuLyog4pSA4pSA4pSAIEFjdGlvbiBCYWRnZSBDYXJkIOKUgOKUgOKUgCAqL1xuY29uc3QgQWN0aW9uQ2FyZCA9ICh7IGljb24sIGxhYmVsLCBjb3VudCwgYWNjZW50Q29sb3IsIHJlc291cmNlSWQgfSkgPT4gKFxuICA8YSBocmVmPXtgL2FkbWluL3Jlc291cmNlcy8ke3Jlc291cmNlSWR9YH0gc3R5bGU9e3sgdGV4dERlY29yYXRpb246ICdub25lJywgZmxleDogJzEnLCBtaW5XaWR0aDogJzE4MHB4JyB9fT5cbiAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZShhY2NlbnRDb2xvciksIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzE2cHgnIH19XG4gICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBhY2NlbnRDb2xvcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLnRyYW5zZm9ybSA9ICd0cmFuc2xhdGVZKC0ycHgpJzsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJveFNoYWRvdyA9IGAwIDZweCAyMHB4IHJnYmEoMCwwLDAsMC4zKWA7IH19XG4gICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckxlZnRDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoMCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJ25vbmUnOyB9fVxuICAgID5cbiAgICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6IDQ0LCBoZWlnaHQ6IDQ0LCBib3JkZXJSYWRpdXM6ICcxMnB4JywgYmFja2dyb3VuZENvbG9yOiBgJHthY2NlbnRDb2xvcn0xNWAsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJywgZmxleFNocmluazogMCB9fT5cbiAgICAgICAgPEljb24gaWNvbj17aWNvbn0gc2l6ZT17MjJ9IGNvbG9yPXthY2NlbnRDb2xvcn0gLz5cbiAgICAgIDwvZGl2PlxuICAgICAgPGRpdj5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzExcHgnLCBmb250V2VpZ2h0OiA2MDAsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJyB9fT57bGFiZWx9PC9UZXh0PlxuICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IGNvdW50ID4gMCA/IGFjY2VudENvbG9yIDogQy50ZXh0RGltLCBtYXJnaW46ICc0cHggMCAwIDAnIH19Pntjb3VudH08L0g1PlxuICAgICAgPC9kaXY+XG4gICAgICA8SWNvbiBpY29uPVwiQ2hldnJvblJpZ2h0XCIgY29sb3I9e0MudGV4dERpbX0gc3R5bGU9e3sgbWFyZ2luTGVmdDogJ2F1dG8nIH19IC8+XG4gICAgPC9Cb3g+XG4gIDwvYT5cbik7XG5cbi8qIOKUgOKUgOKUgCBGb3JtYXQgZGF0ZSBuaWNlbHkg4pSA4pSA4pSAICovXG5jb25zdCBmbXREYXRlID0gKGQpID0+IHtcbiAgaWYgKCFkKSByZXR1cm4gJ+KAlCc7XG4gIGNvbnN0IGR0ID0gbmV3IERhdGUoZCk7XG4gIHJldHVybiBkdC50b0xvY2FsZURhdGVTdHJpbmcoJ2VuLVVTJywgeyBtb250aDogJ3Nob3J0JywgZGF5OiAnbnVtZXJpYycsIHllYXI6ICdudW1lcmljJyB9KTtcbn07XG5cbi8qIOKUgOKUgOKUgCBTdGF0dXMgYmFkZ2UgY29sb3Ig4pSA4pSA4pSAICovXG5jb25zdCBzdGF0dXNDb2xvciA9IChzKSA9PiB7XG4gIGlmICghcykgcmV0dXJuIEMudGV4dERpbTtcbiAgY29uc3QgbG93ZXIgPSBzLnRvTG93ZXJDYXNlKCk7XG4gIGlmIChsb3dlciA9PT0gJ2FwcHJvdmVkJyB8fCBsb3dlciA9PT0gJ2FjdGl2ZScpIHJldHVybiBDLmdyZWVuO1xuICBpZiAobG93ZXIgPT09ICdwZW5kaW5nJykgcmV0dXJuIEMub3JhbmdlO1xuICBpZiAobG93ZXIgPT09ICdyZWplY3RlZCcpIHJldHVybiBDLnJlZDtcbiAgcmV0dXJuIEMudGV4dE11dGVkO1xufTtcblxuLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4gICBNQUlOIERBU0hCT0FSRCBDT01QT05FTlRcbiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqL1xuY29uc3QgQ3VzdG9tRGFzaGJvYXJkID0gKCkgPT4ge1xuICBjb25zdCBbZGF0YSwgc2V0RGF0YV0gPSB1c2VTdGF0ZShudWxsKTtcbiAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG4gIGNvbnN0IFtlcnJvciwgc2V0RXJyb3JdID0gdXNlU3RhdGUobnVsbCk7XG5cbiAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICBhcGkuZ2V0RGFzaGJvYXJkKClcbiAgICAgIC50aGVuKChyZXNwb25zZSkgPT4ge1xuICAgICAgICBzZXREYXRhKHJlc3BvbnNlLmRhdGEgfHwge30pO1xuICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goKGZldGNoRXJyb3IpID0+IHtcbiAgICAgICAgY29uc29sZS5lcnJvcignRGFzaGJvYXJkIGZldGNoIGVycm9yOicsIGZldGNoRXJyb3IpO1xuICAgICAgICBzZXRFcnJvcignRmFpbGVkIHRvIGxvYWQgZGFzaGJvYXJkIGRhdGEuJyk7XG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgfSk7XG4gIH0sIFtdKTtcblxuICBpZiAobG9hZGluZykge1xuICAgIHJldHVybiAoXG4gICAgICA8ZGl2IHN0eWxlPXt7IG1pbkhlaWdodDogJzEwMHZoJywgYmFja2dyb3VuZENvbG9yOiBDLmJnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgIDxkaXYgc3R5bGU9e3sgdGV4dEFsaWduOiAnY2VudGVyJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IHdpZHRoOiA0MCwgaGVpZ2h0OiA0MCwgYm9yZGVyOiBgM3B4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgYm9yZGVyVG9wQ29sb3I6IEMuZ29sZCwgYm9yZGVyUmFkaXVzOiAnNTAlJywgYW5pbWF0aW9uOiAnc3BpbiAxcyBsaW5lYXIgaW5maW5pdGUnLCBtYXJnaW46ICcwIGF1dG8gMTZweCcgfX0gLz5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQgfX0+TG9hZGluZyBkYXNoYm9hcmQuLi48L1RleHQ+XG4gICAgICAgICAgPHN0eWxlPntgQGtleWZyYW1lcyBzcGluIHsgdG8geyB0cmFuc2Zvcm06IHJvdGF0ZSgzNjBkZWcpOyB9IH1gfTwvc3R5bGU+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG4gICAgKTtcbiAgfVxuXG4gIGlmIChlcnJvcikge1xuICAgIHJldHVybiAoXG4gICAgICA8ZGl2IHN0eWxlPXt7IG1pbkhlaWdodDogJzEwMHZoJywgYmFja2dyb3VuZENvbG9yOiBDLmJnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKEMucmVkKSwgbWF4V2lkdGg6IDQwMCwgdGV4dEFsaWduOiAnY2VudGVyJyB9fT5cbiAgICAgICAgICA8SWNvbiBpY29uPVwiQWxlcnRUcmlhbmdsZVwiIHNpemU9ezMyfSBjb2xvcj17Qy5yZWR9IC8+XG4gICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnJlZCwgbWFyZ2luOiAnMTZweCAwIDhweCcgfX0+e2Vycm9yfTwvSDU+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkIH19PkNoZWNrIHRoZSBzZXJ2ZXIgbG9ncyBmb3IgZGV0YWlscy48L1RleHQ+XG4gICAgICAgIDwvQm94PlxuICAgICAgPC9kaXY+XG4gICAgKTtcbiAgfVxuXG4gIGNvbnN0IHN0YXRzID0gZGF0YT8uc3RhdHMgfHwge307XG4gIGNvbnN0IGFjdGlvblJlcXVpcmVkID0gZGF0YT8uYWN0aW9uUmVxdWlyZWQgfHwge307XG4gIGNvbnN0IG1vZHNCeVBsYXRmb3JtID0gZGF0YT8ubW9kc0J5UGxhdGZvcm0gfHwgW107XG4gIGNvbnN0IHVzZXJHcm93dGhEYXRhID0gZGF0YT8udXNlckdyb3d0aERhdGEgfHwgW107XG4gIGNvbnN0IHJlY2VudFVzZXJzID0gZGF0YT8ucmVjZW50VXNlcnMgfHwgW107XG4gIGNvbnN0IHJlY2VudE1vZHMgPSBkYXRhPy5yZWNlbnRNb2RzIHx8IFtdO1xuXG4gIC8vIFByZXBhcmUgY2hhcnQgZGF0YVxuICBjb25zdCBncm93dGhDaGFydERhdGEgPSB1c2VyR3Jvd3RoRGF0YS5tYXAoZCA9PiAoeyBsYWJlbDogZC5kYXRlLCB2YWx1ZTogZC51c2VycyB9KSk7XG5cbiAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgY29uc3QgZ3JlZXRpbmcgPSBub3cuZ2V0SG91cnMoKSA8IDEyID8gJ0dvb2QgbW9ybmluZycgOiBub3cuZ2V0SG91cnMoKSA8IDE4ID8gJ0dvb2QgYWZ0ZXJub29uJyA6ICdHb29kIGV2ZW5pbmcnO1xuXG4gIHJldHVybiAoXG4gICAgPGRpdiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIG1pbkhlaWdodDogJzEwMHZoJywgcGFkZGluZzogJ2NsYW1wKDE2cHgsIDN2dywgMzJweCkgY2xhbXAoMTRweCwgM3Z3LCAzNnB4KScsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+XG4gICAgICBcbiAgICAgIHsvKiDilZDilZDilZAgSEVBREVSIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBqdXN0aWZ5Q29udGVudDogJ3NwYWNlLWJldHdlZW4nLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMTZweCcsIHBhZGRpbmdCb3R0b206ICcyNHB4JywgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgbWFyZ2luQm90dG9tOiAnMjhweCcgfX0+XG4gICAgICAgIDxkaXY+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pblwiIHN0eWxlPXt7IHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBjdXJzb3I6ICdwb2ludGVyJyB9fT5cbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMTBweCcgfX0+XG4gICAgICAgICAgICAgIDxIMiBzdHlsZT17eyBtYXJnaW46IDAsIGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlxuICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLmdvbGQsIHRleHRTaGFkb3c6IGAwIDAgMjBweCAke0MuZ29sZEdsb3d9YCwgZm9udFdlaWdodDogODAwIH19PkdQTDwvc3Bhbj5cbiAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCB0ZXh0U2hhZG93OiAnMCAwIDE1cHggcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjQpJywgZm9udFdlaWdodDogNzAwIH19Pk1vZHM8L3NwYW4+XG4gICAgICAgICAgICAgIDwvSDI+XG4gICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZDcwMCcsIGZvbnRTaXplOiAnMTFweCcsIGZvbnRXZWlnaHQ6IDYwMCwgYmFja2dyb3VuZDogJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMTIpJywgcGFkZGluZzogJzRweCAxMHB4JywgYm9yZGVyUmFkaXVzOiAnMjBweCcsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwgMjE1LCAwLCAwLjM1KScsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIsIGxldHRlclNwYWNpbmc6ICcwLjA0ZW0nLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyB9fT5BZG1pbiBEYXNoYm9hcmQ8L3NwYW4+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICA8L2E+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjZjFmNWY5JywgbWFyZ2luVG9wOiAnOHB4JywgZm9udFNpemU6ICcxNHB4JywgZm9udFdlaWdodDogNDAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiLCBsaW5lSGVpZ2h0OiAxLjUgfX0+XG4gICAgICAgICAgICB7Z3JlZXRpbmd9ISBIZXJlJ3MgeW91ciBwbGF0Zm9ybSBvdmVydmlldyBmb3Ige25vdy50b0xvY2FsZURhdGVTdHJpbmcoJ2VuLVVTJywgeyB3ZWVrZGF5OiAnbG9uZycsIG1vbnRoOiAnbG9uZycsIGRheTogJ251bWVyaWMnLCB5ZWFyOiAnbnVtZXJpYycgfSl9LlxuICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgPC9kaXY+XG5cbiAgICAgICAgey8qIOKVkOKVkOKVkCBBRE1JTiBTVUlURSBTSE9SVENVVCBCVVRUT05TIOKVkOKVkOKVkCAqL31cbiAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXhXaWR0aDogJzEwMCUnLCBtYXJnaW5Ub3A6ICc2cHgnIH19PlxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9kYXNoYm9hcmRcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogQy5nb2xkLCBiYWNrZ3JvdW5kQ29sb3I6IEMuZ29sZERpbSwgYm9yZGVyOiBgMXB4IHNvbGlkICR7Qy5nb2xkfWAsIHBhZGRpbmc6ICc3cHggMTJweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxMnB4JywgbGluZUhlaWdodDogMS40LCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiLCBmbGV4U2hyaW5rOiAwIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjU1LDIxNSwwLDAuMjUpJzsgfX1cbiAgICAgICAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSBDLmdvbGREaW07IH19XG4gICAgICAgICAgICB0aXRsZT1cIkdvIEJhY2sgVG8gVXNlciBEYXNoYm9hcmRcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJBcnJvd0xlZnRcIiBzaXplPXsxM30gLz4gRGFzaGJvYXJkXG4gICAgICAgICAgPC9hPlxuXG4gICAgICAgICAgPGEgXG4gICAgICAgICAgICBocmVmPVwiL2FkbWluL3JlcG9ydHNcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyNmZjZiNmInLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDIyOSw1Nyw1MywwLjEyKScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDIyOSw1Nyw1MywwLjMpJywgcGFkZGluZzogJzdweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEycHgnLCBsaW5lSGVpZ2h0OiAxLjQsIHRyYW5zaXRpb246ICdhbGwgMC4ycycsIGZsZXhTaHJpbms6IDAgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyMjksNTcsNTMsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDIyOSw1Nyw1MywwLjEyKSc7IH19XG4gICAgICAgICAgICB0aXRsZT1cIk1vZGVyYXRpb24gJiBNb2QgUmVwb3J0cyBDb25zb2xlXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiRmxhZ1wiIHNpemU9ezEzfSAvPiBSZXBvcnRzXG4gICAgICAgICAgPC9hPlxuXG4gICAgICAgICAgPGEgXG4gICAgICAgICAgICBocmVmPVwiL2FkbWluL3N1cHBvcnRcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyM2NGI1ZjYnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDMzLDE1MCwyNDMsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgzMywxNTAsMjQzLDAuMyknLCBwYWRkaW5nOiAnN3B4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTJweCcsIGxpbmVIZWlnaHQ6IDEuNCwgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJywgZmxleFNocmluazogMCB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDMzLDE1MCwyNDMsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDMzLDE1MCwyNDMsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJMaXZlIFN1cHBvcnQgJiBJbnF1aXJpZXMgQ29uc29sZVwiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkhlbHBDaXJjbGVcIiBzaXplPXsxM30gLz4gU3VwcG9ydFxuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9hZG1pbi9zdGF0dXNcIiBcbiAgICAgICAgICAgIHRhcmdldD1cIl9ibGFua1wiIFxuICAgICAgICAgICAgcmVsPVwibm9vcGVuZXIgbm9yZWZlcnJlclwiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnIzgxYzc4NCcsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoNjcsMTYwLDcxLDAuMTIpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoNjcsMTYwLDcxLDAuMyknLCBwYWRkaW5nOiAnN3B4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTJweCcsIGxpbmVIZWlnaHQ6IDEuNCwgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJywgZmxleFNocmluazogMCB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDY3LDE2MCw3MSwwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoNjcsMTYwLDcxLDAuMTIpJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiTGl2ZSBTZXJ2ZXIgRGlhZ25vc3RpY3MgJiBIZWFsdGhcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJBY3Rpdml0eVwiIHNpemU9ezEzfSAvPiBEaWFnbm9zdGljc1xuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9hZG1pbi9tdXNpY1wiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnI2JhNjhjOCcsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMTg2LDEwNCwyMDAsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgxODYsMTA0LDIwMCwwLjMpJywgcGFkZGluZzogJzdweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEycHgnLCBsaW5lSGVpZ2h0OiAxLjQsIHRyYW5zaXRpb246ICdhbGwgMC4ycycsIGZsZXhTaHJpbms6IDAgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgxODYsMTA0LDIwMCwwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMTg2LDEwNCwyMDAsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJNdXNpYyAmIFBsYXlsaXN0IE1hbmFnZXJcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJNdXNpY1wiIHNpemU9ezEzfSAvPiBNdXNpY1xuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9ob21lXCIgXG4gICAgICAgICAgICB0YXJnZXQ9XCJfYmxhbmtcIiBcbiAgICAgICAgICAgIHJlbD1cIm5vb3BlbmVyIG5vcmVmZXJyZXJcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyNmZmZmZmYnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuc3VyZmFjZUFsdCwgYm9yZGVyOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgcGFkZGluZzogJzdweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEycHgnLCBsaW5lSGVpZ2h0OiAxLjQsIHRyYW5zaXRpb246ICdhbGwgMC4ycycsIGZsZXhTaHJpbms6IDAgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuZ29sZDsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmNvbG9yID0gQy5nb2xkOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckNvbG9yID0gQy5ib3JkZXI7IGUuY3VycmVudFRhcmdldC5zdHlsZS5jb2xvciA9ICcjZmZmZmZmJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiT3BlbiBMaXZlIFB1YmxpYyBTaXRlXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiR2xvYmVcIiBzaXplPXsxM30gLz4gTGl2ZSBTaXRlXG4gICAgICAgICAgPC9hPlxuICAgICAgICA8L2Rpdj5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIFNUQVQgQ0FSRFMg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzE2cHgnLCBtYXJnaW5Cb3R0b206ICcyNHB4JyB9fT5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJVc2Vyc1wiIGxhYmVsPVwiVG90YWwgVXNlcnNcIiB2YWx1ZT17KHN0YXRzLnRvdGFsVXNlcnMgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gZGVsdGE9e3N0YXRzLm5ld1VzZXJzVGhpc01vbnRofSBhY2NlbnRDb2xvcj17Qy5ibHVlfSAvPlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIlBhY2thZ2VcIiBsYWJlbD1cIlRvdGFsIE1vZHNcIiB2YWx1ZT17KHN0YXRzLnRvdGFsTW9kcyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBkZWx0YT17c3RhdHMubmV3TW9kc1RoaXNNb250aH0gYWNjZW50Q29sb3I9e0MuZ29sZH0gLz5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJEb3dubG9hZFwiIGxhYmVsPVwiVG90YWwgRG93bmxvYWRzXCIgdmFsdWU9eyhzdGF0cy50b3RhbERvd25sb2FkcyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBhY2NlbnRDb2xvcj17Qy5ncmVlbn0gLz5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJFeWVcIiBsYWJlbD1cIlRvdGFsIFZpZXdzXCIgdmFsdWU9eyhzdGF0cy50b3RhbFZpZXdzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGFjY2VudENvbG9yPXtDLnB1cnBsZX0gLz5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIEFDVElPTiBSRVFVSVJFRCDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMTRweCcsIG1hcmdpbkJvdHRvbTogJzMycHgnIH19PlxuICAgICAgICA8QWN0aW9uQ2FyZCBpY29uPVwiRmxhZ1wiIGxhYmVsPVwiUGVuZGluZyBSZXBvcnRzXCIgY291bnQ9e2FjdGlvblJlcXVpcmVkLnBlbmRpbmdSZXBvcnRzIHx8IDB9IGFjY2VudENvbG9yPXtDLnJlZH0gcmVzb3VyY2VJZD1cIlJlcG9ydFwiIC8+XG4gICAgICAgIDxBY3Rpb25DYXJkIGljb249XCJDaGVja1NxdWFyZVwiIGxhYmVsPVwiUGVuZGluZyBBcHByb3ZhbHNcIiBjb3VudD17YWN0aW9uUmVxdWlyZWQucGVuZGluZ0FwcHJvdmFscyB8fCAwfSBhY2NlbnRDb2xvcj17Qy5vcmFuZ2V9IHJlc291cmNlSWQ9XCJGaWxlXCIgLz5cbiAgICAgICAgPEFjdGlvbkNhcmQgaWNvbj1cIkhlbHBDaXJjbGVcIiBsYWJlbD1cIk9wZW4gVGlja2V0c1wiIGNvdW50PXthY3Rpb25SZXF1aXJlZC5vcGVuVGlja2V0cyB8fCAwfSBhY2NlbnRDb2xvcj17Qy5ibHVlfSByZXNvdXJjZUlkPVwiU3VwcG9ydFRpY2tldFwiIC8+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBDSEFSVFMgUk9XIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcyMHB4JywgbWFyZ2luQm90dG9tOiAnMzJweCcgfX0+XG4gICAgICAgIHsvKiBVc2VyIEdyb3d0aCBDaGFydCAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzIgMSAzMjBweCcsIG1pbldpZHRoOiAwLCB3aWR0aDogJzEwMCUnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMThweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiQWN0aXZpdHlcIiBjb2xvcj17Qy5nb2xkfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5Vc2VyIEdyb3d0aDwvSDU+XG4gICAgICAgICAgICA8QmFkZ2Ugc3R5bGU9e3sgbWFyZ2luTGVmdDogJzhweCcsIGJhY2tncm91bmRDb2xvcjogQy5nb2xkRGltLCBjb2xvcjogQy5nb2xkLCBib3JkZXI6ICdub25lJywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT4zMCBkYXlzPC9CYWRnZT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7Z3Jvd3RoQ2hhcnREYXRhLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8QXJlYUNoYXJ0IGRhdGE9e2dyb3d0aENoYXJ0RGF0YX0gY29sb3I9e0MuZ29sZH0gd2lkdGg9ezUwMH0gaGVpZ2h0PXsxNzB9IC8+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgaGVpZ2h0OiAxNjAsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5ObyB1c2VyIHNpZ251cHMgaW4gdGhlIGxhc3QgMzAgZGF5cy48L1RleHQ+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cblxuICAgICAgICB7LyogUGxhdGZvcm0gRG9udXQgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcxIDEgMjgwcHgnLCBtaW5XaWR0aDogMCwgd2lkdGg6ICcxMDAlJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE4cHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIlBpZUNoYXJ0XCIgY29sb3I9e0MuYmx1ZX0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+TW9kcyBieSBQbGF0Zm9ybTwvSDU+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICAge21vZHNCeVBsYXRmb3JtLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8RG9udXRDaGFydCBkYXRhPXttb2RzQnlQbGF0Zm9ybX0gc2l6ZT17MTgwfSAvPlxuICAgICAgICAgICkgOiAoXG4gICAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGhlaWdodDogMTYwLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0sIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+Tm8gcGxhdGZvcm0gZGF0YSBhdmFpbGFibGUuPC9UZXh0PlxuICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBSRUNFTlQgQUNUSVZJVFkgUk9XIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcyMHB4JywgbWFyZ2luQm90dG9tOiAnMzJweCcgfX0+XG4gICAgICAgIHsvKiBSZWNlbnQgVXNlcnMgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcxIDEgMzIwcHgnLCBtaW5XaWR0aDogMCwgd2lkdGg6ICcxMDAlJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE4cHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIlVzZXJzXCIgY29sb3I9e0MuYmx1ZX0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+UmVjZW50IFVzZXJzPC9INT5cbiAgICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL1VzZXJcIiBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnYXV0bycsIGNvbG9yOiBDLmdvbGQsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5WaWV3IEFsbCDihpI8L2E+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICAge3JlY2VudFVzZXJzLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8ZGl2IHN0eWxlPXt7IG92ZXJmbG93WDogJ2F1dG8nLCB3aWR0aDogJzEwMCUnLCBXZWJraXRPdmVyZmxvd1Njcm9sbGluZzogJ3RvdWNoJyB9fT5cbiAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPXt7IHdpZHRoOiAnMTAwJScsIGJvcmRlckNvbGxhcHNlOiAnY29sbGFwc2UnLCBtaW5XaWR0aDogJzMwMHB4JyB9fT5cbiAgICAgICAgICAgICAgICA8dGhlYWQ+XG4gICAgICAgICAgICAgICAgICA8dHIgc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5Vc2VybmFtZTwvdGg+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+Um9sZTwvdGg+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdyaWdodCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PkpvaW5lZDwvdGg+XG4gICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgIDwvdGhlYWQ+XG4gICAgICAgICAgICAgICAgPHRib2R5PlxuICAgICAgICAgICAgICAgICAge3JlY2VudFVzZXJzLm1hcCgodSwgaSkgPT4gKFxuICAgICAgICAgICAgICAgICAgICA8dHIga2V5PXtpfSBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dCwgZm9udFNpemU6ICcxM3B4JywgZm9udFdlaWdodDogNTAwIH19Pnt1LnVzZXJuYW1lfTwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICcxMXB4JywgcGFkZGluZzogJzNweCA4cHgnLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IHUucm9sZSA9PT0gJ2FkbWluJyA/IGAke0MuZ29sZH0yMGAgOiBgJHtDLmJsdWV9MjBgLCBjb2xvcjogdS5yb2xlID09PSAnYWRtaW4nID8gQy5nb2xkIDogQy5ibHVlLCBmb250V2VpZ2h0OiA2MDAgfX0+e3Uucm9sZSB8fCAndXNlcid9PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnLCBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTJweCcsIHRleHRBbGlnbjogJ3JpZ2h0JyB9fT57Zm10RGF0ZSh1LmRhdGUpfTwvdGQ+XG4gICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICApKX1cbiAgICAgICAgICAgICAgICA8L3Rib2R5PlxuICAgICAgICAgICAgICA8L3RhYmxlPlxuICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0sIHRleHRBbGlnbjogJ2NlbnRlcicsIHBhZGRpbmc6ICcyMHB4IDAnIH19Pk5vIHJlY2VudCB1c2Vycy48L1RleHQ+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgey8qIFJlY2VudCBNb2RzICovfVxuICAgICAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZSgpLCBmbGV4OiAnMSAxIDMyMHB4JywgbWluV2lkdGg6IDAsIHdpZHRoOiAnMTAwJScgfX0+XG4gICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcxOHB4JyB9fT5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJQYWNrYWdlXCIgY29sb3I9e0MuZ29sZH0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+UmVjZW50IE1vZHM8L0g1PlxuICAgICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvRmlsZVwiIHN0eWxlPXt7IG1hcmdpbkxlZnQ6ICdhdXRvJywgY29sb3I6IEMuZ29sZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlZpZXcgQWxsIOKGkjwvYT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7cmVjZW50TW9kcy5sZW5ndGggPiAwID8gKFxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBvdmVyZmxvd1g6ICdhdXRvJywgd2lkdGg6ICcxMDAlJywgV2Via2l0T3ZlcmZsb3dTY3JvbGxpbmc6ICd0b3VjaCcgfX0+XG4gICAgICAgICAgICAgIDx0YWJsZSBzdHlsZT17eyB3aWR0aDogJzEwMCUnLCBib3JkZXJDb2xsYXBzZTogJ2NvbGxhcHNlJywgbWluV2lkdGg6ICczMDBweCcgfX0+XG4gICAgICAgICAgICAgICAgPHRoZWFkPlxuICAgICAgICAgICAgICAgICAgPHRyIHN0eWxlPXt7IGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+TmFtZTwvdGg+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+UGxhdGZvcm08L3RoPlxuICAgICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PlN0YXR1czwvdGg+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdyaWdodCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PkFkZGVkPC90aD5cbiAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgPC90aGVhZD5cbiAgICAgICAgICAgICAgICA8dGJvZHk+XG4gICAgICAgICAgICAgICAgICB7cmVjZW50TW9kcy5tYXAoKG0sIGkpID0+IChcbiAgICAgICAgICAgICAgICAgICAgPHRyIGtleT17aX0gc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHQsIGZvbnRTaXplOiAnMTNweCcsIGZvbnRXZWlnaHQ6IDUwMCwgbWF4V2lkdGg6ICcxODBweCcsIG92ZXJmbG93OiAnaGlkZGVuJywgdGV4dE92ZXJmbG93OiAnZWxsaXBzaXMnLCB3aGl0ZVNwYWNlOiAnbm93cmFwJyB9fT57bS5uYW1lfTwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICcxMXB4JywgcGFkZGluZzogJzNweCA4cHgnLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IGAke0MuYmx1ZX0yMGAsIGNvbG9yOiBDLmJsdWUsIGZvbnRXZWlnaHQ6IDYwMCwgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScgfX0+e20uY2F0ZWdvcnkgfHwgJ+KAlCd9PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICcxMXB4JywgcGFkZGluZzogJzNweCA4cHgnLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IGAke3N0YXR1c0NvbG9yKG0uc3RhdHVzKX0yMGAsIGNvbG9yOiBzdGF0dXNDb2xvcihtLnN0YXR1cyksIGZvbnRXZWlnaHQ6IDYwMCwgdGV4dFRyYW5zZm9ybTogJ2NhcGl0YWxpemUnIH19PnttLnN0YXR1cyB8fCAn4oCUJ308L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dEFsaWduOiAncmlnaHQnIH19PntmbXREYXRlKG0uZGF0ZSl9PC90ZD5cbiAgICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICAgICkpfVxuICAgICAgICAgICAgICAgIDwvdGJvZHk+XG4gICAgICAgICAgICAgIDwvdGFibGU+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgdGV4dEFsaWduOiAnY2VudGVyJywgcGFkZGluZzogJzIwcHggMCcgfX0+Tm8gcmVjZW50IG1vZHMuPC9UZXh0PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvQm94PlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgRk9PVEVSIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBqdXN0aWZ5Q29udGVudDogJ3NwYWNlLWJldHdlZW4nLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMTRweCcsIHBhZGRpbmdUb3A6ICcyMHB4JywgYm9yZGVyVG9wOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgPGEgaHJlZj1cIi9hZG1pblwiIHN0eWxlPXt7IHRleHREZWNvcmF0aW9uOiAnbm9uZScgfX0+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgZm9udFNpemU6ICcxM3B4JywgY3Vyc29yOiAncG9pbnRlcicsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy5nb2xkLCBmb250V2VpZ2h0OiA3MDAgfX0+R1BMPC9zcGFuPiA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBmb250V2VpZ2h0OiA2MDAgfX0+TW9kczwvc3Bhbj4g4oCiIEFkbWluIFBhbmVsIHYyLjVcbiAgICAgICAgICA8L1RleHQ+XG4gICAgICAgIDwvYT5cbiAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzhweCcgfX0+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvVXNlclwiIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC4wNiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpJywgcGFkZGluZzogJzVweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNTAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlVzZXJzPC9hPlxuICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL0ZpbGVcIiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuMDYpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4xKScsIHBhZGRpbmc6ICc1cHggMTJweCcsIGJvcmRlclJhZGl1czogJzhweCcsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDUwMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5Nb2RzPC9hPlxuICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL1JlcG9ydFwiIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC4wNiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpJywgcGFkZGluZzogJzVweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNTAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlJlcG9ydHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvU3VwcG9ydFRpY2tldFwiIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC4wNiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpJywgcGFkZGluZzogJzVweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNTAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlRpY2tldHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9tdXNpY1wiIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC4wNiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpJywgcGFkZGluZzogJzVweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNTAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19Pk11c2ljPC9hPlxuICAgICAgICA8L2Rpdj5cbiAgICAgIDwvZGl2PlxuICAgIDwvZGl2PlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgQ3VzdG9tRGFzaGJvYXJkO1xuIiwiaW1wb3J0IFJlYWN0IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCwgSWNvbiB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuXG5jb25zdCBTaWRlYmFyQnJhbmRpbmcgPSAoKSA9PiB7XG4gIHJldHVybiAoXG4gICAgPEJveCBcbiAgICAgIGZsZXggXG4gICAgICBmbGV4RGlyZWN0aW9uPVwiY29sdW1uXCJcbiAgICAgIGFsaWduSXRlbXM9XCJjZW50ZXJcIiBcbiAgICAgIGp1c3RpZnlDb250ZW50PVwiY2VudGVyXCIgXG4gICAgICBwPVwibGdcIiBcbiAgICAgIHN0eWxlPXt7IFxuICAgICAgICBib3JkZXJCb3R0b206ICcxcHggc29saWQgIzJhMmEyYScsIFxuICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICcjMGEwYTBhJywgXG4gICAgICAgIHBhZGRpbmc6ICcyMHB4IDE2cHgnLFxuICAgICAgICBwb3NpdGlvbjogJ3JlbGF0aXZlJyxcbiAgICAgICAgb3ZlcmZsb3c6ICdoaWRkZW4nXG4gICAgICB9fVxuICAgID5cbiAgICAgIHsvKiBTdWJ0bGUgZ29sZCBnbG93IHVuZGVybGluZSAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3tcbiAgICAgICAgcG9zaXRpb246ICdhYnNvbHV0ZScsXG4gICAgICAgIGJvdHRvbTogMCxcbiAgICAgICAgbGVmdDogJzUwJScsXG4gICAgICAgIHRyYW5zZm9ybTogJ3RyYW5zbGF0ZVgoLTUwJSknLFxuICAgICAgICB3aWR0aDogJzYwJScsXG4gICAgICAgIGhlaWdodDogJzFweCcsXG4gICAgICAgIGJhY2tncm91bmQ6ICdsaW5lYXItZ3JhZGllbnQoOTBkZWcsIHRyYW5zcGFyZW50LCByZ2JhKDI1NSwyMTUsMCwwLjUpLCB0cmFuc3BhcmVudCknXG4gICAgICB9fSAvPlxuXG4gICAgICB7LyogTWFpbiBMb2dvICYgVGl0bGUgTGluayAqL31cbiAgICAgIDxhIFxuICAgICAgICBocmVmPVwiL2FkbWluXCIgXG4gICAgICAgIHN0eWxlPXt7IFxuICAgICAgICAgIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIFxuICAgICAgICAgIGRpc3BsYXk6ICdmbGV4JywgXG4gICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcicsIFxuICAgICAgICAgIGdhcDogJzEwcHgnLFxuICAgICAgICAgIGN1cnNvcjogJ3BvaW50ZXInLFxuICAgICAgICAgIHRyYW5zaXRpb246ICdvcGFjaXR5IDAuMnMgZWFzZSdcbiAgICAgICAgfX1cbiAgICAgICAgb25Nb3VzZUVudGVyPXsoZSkgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUub3BhY2l0eSA9ICcwLjg1JzsgfX1cbiAgICAgICAgb25Nb3VzZUxlYXZlPXsoZSkgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUub3BhY2l0eSA9ICcxJzsgfX1cbiAgICAgID5cbiAgICAgICAgPGltZyBcbiAgICAgICAgICBzcmM9XCIvaW1hZ2VzL3RlYW0tbG9nby5wbmdcIiBcbiAgICAgICAgICBhbHQ9XCJMb2dvXCIgXG4gICAgICAgICAgc3R5bGU9e3sgaGVpZ2h0OiAnMzJweCcsIHdpZHRoOiAnMzJweCcsIG9iamVjdEZpdDogJ2NvdmVyJywgYm9yZGVyUmFkaXVzOiAnNnB4JywgZmlsdGVyOiAnZHJvcC1zaGFkb3coMCAwIDZweCByZ2JhKDI1NSwyMTUsMCwwLjMpKScgfX0gXG4gICAgICAgICAgb25FcnJvcj17KGUpID0+IGUudGFyZ2V0LnN0eWxlLmRpc3BsYXkgPSAnbm9uZSd9XG4gICAgICAgIC8+XG4gICAgICAgIDxkaXYgc3R5bGU9e3sgZm9udFNpemU6ICcyMnB4JywgZm9udFdlaWdodDogJ2JvbGQnLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdiYXNlbGluZScsIGdhcDogJzRweCcgfX0+XG4gICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjRkZENzAwJywgdGV4dFNoYWRvdzogJzAgMCAxMnB4IHJnYmEoMjU1LCAyMTUsIDAsIDAuNCknIH19PkdQTDwvc3Bhbj5cbiAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNjMGMwYzAnLCB0ZXh0U2hhZG93OiAnMCAwIDEycHggcmdiYSgxOTIsIDE5MiwgMTkyLCAwLjUpJyB9fT5Nb2RzPC9zcGFuPlxuICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnOXB4JywgY29sb3I6ICcjNTU1JywgZm9udFdlaWdodDogNjAwLCBtYXJnaW5MZWZ0OiAnNnB4JywgbGV0dGVyU3BhY2luZzogJzAuMDVlbScgfX0+djIuNTwvc3Bhbj5cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L2E+XG5cbiAgICAgIHsvKiBRdWljayBEYXNoYm9hcmQgU2hvcnRjdXQgQnV0dG9uICovfVxuICAgICAgPGEgXG4gICAgICAgIGhyZWY9XCIvYWRtaW5cIiBcbiAgICAgICAgc3R5bGU9e3tcbiAgICAgICAgICBkaXNwbGF5OiAnZmxleCcsXG4gICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcicsXG4gICAgICAgICAganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLFxuICAgICAgICAgIGdhcDogJzhweCcsXG4gICAgICAgICAgbWFyZ2luVG9wOiAnMTJweCcsXG4gICAgICAgICAgcGFkZGluZzogJzZweCAxNnB4JyxcbiAgICAgICAgICB3aWR0aDogJzg1JScsXG4gICAgICAgICAgYm9yZGVyUmFkaXVzOiAnOHB4JyxcbiAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwgMjE1LCAwLCAwLjA4KScsXG4gICAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LCAyMTUsIDAsIDAuMjUpJyxcbiAgICAgICAgICBjb2xvcjogJyNGRkQ3MDAnLFxuICAgICAgICAgIHRleHREZWNvcmF0aW9uOiAnbm9uZScsXG4gICAgICAgICAgZm9udFNpemU6ICcxMnB4JyxcbiAgICAgICAgICBmb250V2VpZ2h0OiA3MDAsXG4gICAgICAgICAgbGV0dGVyU3BhY2luZzogJzAuMDRlbScsXG4gICAgICAgICAgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsXG4gICAgICAgICAgdHJhbnNpdGlvbjogJ2FsbCAwLjJzIGVhc2UnLFxuICAgICAgICAgIGN1cnNvcjogJ3BvaW50ZXInXG4gICAgICAgIH19XG4gICAgICAgIG9uTW91c2VFbnRlcj17KGUpID0+IHsgXG4gICAgICAgICAgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDI1NSwgMjE1LCAwLCAwLjIpJzsgXG4gICAgICAgICAgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJveFNoYWRvdyA9ICcwIDAgMTRweCByZ2JhKDI1NSwyMTUsMCwwLjMpJzsgXG4gICAgICAgIH19XG4gICAgICAgIG9uTW91c2VMZWF2ZT17KGUpID0+IHsgXG4gICAgICAgICAgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDI1NSwgMjE1LCAwLCAwLjA4KSc7IFxuICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnbm9uZSc7IFxuICAgICAgICB9fVxuICAgICAgPlxuICAgICAgICA8SWNvbiBpY29uPVwiSG9tZVwiIHNpemU9ezEzfSBjb2xvcj1cIiNGRkQ3MDBcIiAvPlxuICAgICAgICA8c3Bhbj5EYXNoYm9hcmQ8L3NwYW4+XG4gICAgICA8L2E+XG4gICAgPC9Cb3g+XG4gICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBTaWRlYmFyQnJhbmRpbmc7XG4iLCJpbXBvcnQgUmVhY3QsIHsgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94LCBUZXh0LCBMb2FkZXIsIEJ1dHRvbiwgSWNvbiB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuaW1wb3J0IHsgdXNlTm90aWNlIH0gZnJvbSAnYWRtaW5qcyc7XG5cbmNvbnN0IEFjdGlvblJlZGlyZWN0ID0gKHByb3BzKSA9PiB7XG4gICAgY29uc3QgeyByZWNvcmQgfSA9IHByb3BzO1xuICAgIGNvbnN0IHNlbmROb3RpY2UgPSB1c2VOb3RpY2UoKTtcbiAgICBjb25zdCB1cmwgPSByZWNvcmQ/LnBhcmFtcz8ucmVkaXJlY3RVcmw7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBpZiAoIXVybCkge1xuICAgICAgICAgICAgc2VuZE5vdGljZSh7IG1lc3NhZ2U6ICdFcnJvcjogTm8gcmVkaXJlY3QgVVJMIHByb3ZpZGVkLicsIHR5cGU6ICdlcnJvcicgfSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBJbnRlcm5hbCBhZG1pbiBuYXZpZ2F0aW9uOiBSZWRpcmVjdCBpbiB0aGUgU0FNRSB0YWIgc28gdXNlciBpcyBub3Qgc3R1Y2sgb24gc3Bpbm5lclxuICAgICAgICBpZiAodXJsLnN0YXJ0c1dpdGgoJy9hZG1pbicpKSB7XG4gICAgICAgICAgICB3aW5kb3cubG9jYXRpb24uaHJlZiA9IHVybDtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vIEV4dGVybmFsIG9yIGZyb250ZW5kIHJvdXRlOiBvcGVuIGluIG5ldyB0YWIsIGFuZCByZXN0b3JlIHByZXZpb3VzIGhpc3RvcnkgaW4gYWRtaW4gdGFiXG4gICAgICAgICAgICB3aW5kb3cub3Blbih1cmwsICdfYmxhbmsnKTtcbiAgICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICAgICAgICAgIGlmICh3aW5kb3cuaGlzdG9yeS5sZW5ndGggPiAxKSB7XG4gICAgICAgICAgICAgICAgICAgIHdpbmRvdy5oaXN0b3J5LmJhY2soKTtcbiAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKHJlY29yZD8ucGFyYW1zPy5faWQpIHtcbiAgICAgICAgICAgICAgICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSBgL2FkbWluL3Jlc291cmNlcy9GaWxlL3JlY29yZHMvJHtyZWNvcmQucGFyYW1zLl9pZH0vc2hvd2A7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSwgNjAwKTtcbiAgICAgICAgfVxuICAgIH0sIFtyZWNvcmQsIHVybF0pO1xuXG4gICAgcmV0dXJuIChcbiAgICAgICAgPEJveCBmbGV4IGZsZXhEaXJlY3Rpb249XCJjb2x1bW5cIiBhbGlnbkl0ZW1zPVwiY2VudGVyXCIganVzdGlmeUNvbnRlbnQ9XCJjZW50ZXJcIiBwPVwieHhsXCI+XG4gICAgICAgICAgICA8TG9hZGVyIC8+XG4gICAgICAgICAgICA8VGV4dCBtdD1cImxnXCIgdmFyaWFudD1cImg0XCI+UmVkaXJlY3RpbmcuLi48L1RleHQ+XG4gICAgICAgICAgICB7dXJsICYmIChcbiAgICAgICAgICAgICAgICA8Qm94IG10PVwibWRcIj5cbiAgICAgICAgICAgICAgICAgICAgPEJ1dHRvblxuICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZT1cInNtXCJcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhcmlhbnQ9XCJwcmltYXJ5XCJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpID0+IHsgd2luZG93LmxvY2F0aW9uLmhyZWYgPSB1cmw7IH19XG4gICAgICAgICAgICAgICAgICAgICAgICBzdHlsZT17eyBjdXJzb3I6ICdwb2ludGVyJyB9fVxuICAgICAgICAgICAgICAgICAgICA+XG4gICAgICAgICAgICAgICAgICAgICAgICA8SWNvbiBpY29uPVwiRXh0ZXJuYWxMaW5rXCIgc3R5bGU9e3sgbWFyZ2luUmlnaHQ6ICc2cHgnIH19IC8+XG4gICAgICAgICAgICAgICAgICAgICAgICBDbGljayBoZXJlIGlmIG5vdCByZWRpcmVjdGVkIGF1dG9tYXRpY2FsbHlcbiAgICAgICAgICAgICAgICAgICAgPC9CdXR0b24+XG4gICAgICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cbiAgICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgQWN0aW9uUmVkaXJlY3Q7XG4iLCJpbXBvcnQgUmVhY3QsIHsgdXNlU3RhdGUgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3gsIFRleHQsIEJ1dHRvbiwgSWNvbiwgQmFkZ2UgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcbmltcG9ydCB7IHVzZU5vdGljZSB9IGZyb20gJ2FkbWluanMnO1xuXG5jb25zdCBEb3dubG9hZEluc3BlY3RvciA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkIH0gPSBwcm9wcztcbiAgICBjb25zdCBzZW5kTm90aWNlID0gdXNlTm90aWNlKCk7XG4gICAgY29uc3QgW2NvcGllZCwgc2V0Q29waWVkXSA9IHVzZVN0YXRlKGZhbHNlKTtcblxuICAgIGlmICghcmVjb3JkIHx8ICFyZWNvcmQucGFyYW1zKSB7XG4gICAgICAgIHJldHVybiAoXG4gICAgICAgICAgICA8Qm94IHA9XCJ4bFwiIHRleHRBbGlnbj1cImNlbnRlclwiPlxuICAgICAgICAgICAgICAgIDxUZXh0IHZhcmlhbnQ9XCJoNFwiPk5vIHJlY29yZCBkYXRhIGZvdW5kLjwvVGV4dD5cbiAgICAgICAgICAgIDwvQm94PlxuICAgICAgICApO1xuICAgIH1cblxuICAgIGNvbnN0IGZpbGVJZCA9IHJlY29yZC5wYXJhbXMuX2lkIHx8IHJlY29yZC5pZDtcbiAgICBjb25zdCBmaWxlTmFtZSA9IHJlY29yZC5wYXJhbXMubmFtZSB8fCAnTW9kIEZpbGUnO1xuICAgIGNvbnN0IGZpbGVWZXJzaW9uID0gcmVjb3JkLnBhcmFtcy52ZXJzaW9uIHx8ICcxLjAnO1xuICAgIGNvbnN0IGZpbGVTaXplID0gcmVjb3JkLnBhcmFtcy5maWxlU2l6ZSB8fCAnTi9BJztcbiAgICBjb25zdCBleHRlcm5hbFVybCA9IHJlY29yZC5wYXJhbXMuZXh0ZXJuYWxEb3dubG9hZFVybCB8fCAnJztcbiAgICBjb25zdCBmaWxlS2V5ID0gcmVjb3JkLnBhcmFtcy5maWxlS2V5IHx8ICcnO1xuICAgIGNvbnN0IGRpcmVjdFVybCA9IHJlY29yZC5wYXJhbXMuZGlyZWN0RG93bmxvYWRVcmwgfHwgJyc7XG4gICAgY29uc3QgaXNNdWx0aVBhcnQgPSByZWNvcmQucGFyYW1zLmlzTXVsdGlQYXJ0ID09PSB0cnVlIHx8IHJlY29yZC5wYXJhbXMuaXNNdWx0aVBhcnQgPT09ICd0cnVlJztcblxuICAgIC8vIFRoZSBwcmltYXJ5IHZhbGlkIGRvd25sb2FkIGVuZHBvaW50IGdlbmVyYXRlZCBieSB0aGUgc2VydmVyXG4gICAgY29uc3QgcHJpbWFyeURvd25sb2FkVXJsID0gYCR7d2luZG93LmxvY2F0aW9uLm9yaWdpbn0vZG93bmxvYWQtZmlsZS8ke2ZpbGVJZH1gO1xuXG4gICAgY29uc3QgaGFuZGxlQ29weSA9ICh1cmxUb0NvcHkpID0+IHtcbiAgICAgICAgaWYgKCF1cmxUb0NvcHkpIHJldHVybjtcbiAgICAgICAgbmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQodXJsVG9Db3B5KS50aGVuKCgpID0+IHtcbiAgICAgICAgICAgIHNldENvcGllZCh0cnVlKTtcbiAgICAgICAgICAgIHNlbmROb3RpY2UoeyBtZXNzYWdlOiAnRG93bmxvYWQgVVJMIGNvcGllZCB0byBjbGlwYm9hcmQhJywgdHlwZTogJ3N1Y2Nlc3MnIH0pO1xuICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRDb3BpZWQoZmFsc2UpLCAzMDAwKTtcbiAgICAgICAgfSkuY2F0Y2goKCkgPT4ge1xuICAgICAgICAgICAgc2VuZE5vdGljZSh7IG1lc3NhZ2U6ICdGYWlsZWQgdG8gY29weSBVUkwgdG8gY2xpcGJvYXJkLicsIHR5cGU6ICdlcnJvcicgfSk7XG4gICAgICAgIH0pO1xuICAgIH07XG5cbiAgICBjb25zdCBoYW5kbGVTdGFydERvd25sb2FkID0gKHRhcmdldFVybCkgPT4ge1xuICAgICAgICBzZW5kTm90aWNlKHsgbWVzc2FnZTogJ0luaXRpYXRpbmcgZmlsZSBkb3dubG9hZCBpbiBuZXcgdGFiLi4uJywgdHlwZTogJ2luZm8nIH0pO1xuICAgICAgICB3aW5kb3cub3Blbih0YXJnZXRVcmwgfHwgcHJpbWFyeURvd25sb2FkVXJsLCAnX2JsYW5rJyk7XG4gICAgfTtcblxuICAgIGNvbnN0IGhhbmRsZUJhY2sgPSAoKSA9PiB7XG4gICAgICAgIGlmICh3aW5kb3cuaGlzdG9yeS5sZW5ndGggPiAxKSB7XG4gICAgICAgICAgICB3aW5kb3cuaGlzdG9yeS5iYWNrKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB3aW5kb3cubG9jYXRpb24uaHJlZiA9IGAvYWRtaW4vcmVzb3VyY2VzL0ZpbGUvcmVjb3Jkcy8ke2ZpbGVJZH0vc2hvd2A7XG4gICAgICAgIH1cbiAgICB9O1xuXG4gICAgcmV0dXJuIChcbiAgICAgICAgPEJveCBwPVwieHhsXCIgc3R5bGU9e3sgbWF4V2lkdGg6ICc4MjBweCcsIG1hcmdpbjogJzAgYXV0bycsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+XG4gICAgICAgICAgICA8Qm94XG4gICAgICAgICAgICAgICAgcD1cInhsXCJcbiAgICAgICAgICAgICAgICBzdHlsZT17e1xuICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICcjMTYxOTI0JyxcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LCAyMTUsIDAsIDAuMzUpJyxcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiAnMTZweCcsXG4gICAgICAgICAgICAgICAgICAgIGJveFNoYWRvdzogJzAgMTJweCAzNXB4IHJnYmEoMCwgMCwgMCwgMC42NSknXG4gICAgICAgICAgICAgICAgfX1cbiAgICAgICAgICAgID5cbiAgICAgICAgICAgICAgICB7LyogSGVhZGVyICovfVxuICAgICAgICAgICAgICAgIDxCb3ggZmxleCBqdXN0aWZ5Q29udGVudD1cInNwYWNlLWJldHdlZW5cIiBhbGlnbkl0ZW1zPVwiY2VudGVyXCIgbWI9XCJ4bFwiPlxuICAgICAgICAgICAgICAgICAgICA8Qm94PlxuICAgICAgICAgICAgICAgICAgICAgICAgPFRleHQgdmFyaWFudD1cImgzXCIgc3R5bGU9e3sgY29sb3I6ICcjRkZENzAwJywgbWFyZ2luOiAwLCBmb250V2VpZ2h0OiA3MDAgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPEljb24gaWNvbj1cIkRvd25sb2FkXCIgc3R5bGU9e3sgbWFyZ2luUmlnaHQ6ICcxMHB4JyB9fSAvPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIERvd25sb2FkIEluc3BlY3RvclxuICAgICAgICAgICAgICAgICAgICAgICAgPC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjYWFhJywgZm9udFNpemU6ICcxM3B4JywgbWFyZ2luVG9wOiAnNHB4JyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBJbnNwZWN0LCB2ZXJpZnksIGNvcHkgb3IgdGVzdCBkb3dubG9hZCBVUkxzIHNhZmVseSB3aXRob3V0IHVud2FudGVkIGRvd25sb2Fkc1xuICAgICAgICAgICAgICAgICAgICAgICAgPC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICA8L0JveD5cbiAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiB2YXJpYW50PVwibGlnaHRcIiBzaXplPVwic21cIiBvbkNsaWNrPXtoYW5kbGVCYWNrfSBzdHlsZT17eyBjdXJzb3I6ICdwb2ludGVyJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxJY29uIGljb249XCJBcnJvd0xlZnRcIiBzdHlsZT17eyBtYXJnaW5SaWdodDogJzZweCcgfX0gLz5cbiAgICAgICAgICAgICAgICAgICAgICAgIEJhY2sgdG8gTW9kXG4gICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxuICAgICAgICAgICAgICAgIDwvQm94PlxuXG4gICAgICAgICAgICAgICAgey8qIE1vZCBNZXRhIFNuYXBzaG90ICovfVxuICAgICAgICAgICAgICAgIDxCb3hcbiAgICAgICAgICAgICAgICAgICAgcD1cImxnXCJcbiAgICAgICAgICAgICAgICAgICAgbWI9XCJ4bFwiXG4gICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7XG4gICAgICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICcjMGUxMDE3JyxcbiAgICAgICAgICAgICAgICAgICAgICAgIGJvcmRlclJhZGl1czogJzEwcHgnLFxuICAgICAgICAgICAgICAgICAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LCAyNTUsIDI1NSwgMC4wOCknXG4gICAgICAgICAgICAgICAgICAgIH19XG4gICAgICAgICAgICAgICAgPlxuICAgICAgICAgICAgICAgICAgICA8Qm94IGZsZXgganVzdGlmeUNvbnRlbnQ9XCJzcGFjZS1iZXR3ZWVuXCIgYWxpZ25JdGVtcz1cImNlbnRlclwiIGZsZXhXcmFwPVwid3JhcFwiIHN0eWxlPXt7IGdhcDogJzEwcHgnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNmZmYnLCBmb250U2l6ZTogJzE2cHgnLCBmb250V2VpZ2h0OiA2MDAgfX0+e2ZpbGVOYW1lfTwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyM4ODgnLCBmb250U2l6ZTogJzEycHgnIH19PklEOiB7ZmlsZUlkfTwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgPEJveCBmbGV4IHN0eWxlPXt7IGdhcDogJzhweCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPEJhZGdlIHZhcmlhbnQ9XCJwcmltYXJ5XCIgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzJhMmY0NScsIGNvbG9yOiAnI2MwYzZlMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZ7ZmlsZVZlcnNpb259XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9CYWRnZT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8QmFkZ2UgdmFyaWFudD1cImluZm9cIiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMWQzNTU3JywgY29sb3I6ICcjNjRiNWY2JyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgU2l6ZToge2ZpbGVTaXplfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQmFkZ2U+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge2lzTXVsdGlQYXJ0ICYmIChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEJhZGdlIHZhcmlhbnQ9XCJ3YXJuaW5nXCIgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzRhMzgwMCcsIGNvbG9yOiAnI2ZmZDU0ZicgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBNdWx0aS1QYXJ0IEZpbGVcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9CYWRnZT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICApfVxuICAgICAgICAgICAgICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgIDwvQm94PlxuXG4gICAgICAgICAgICAgICAgey8qIFByaW1hcnkgVmFsaWQgVVJMIEJveCAqL31cbiAgICAgICAgICAgICAgICA8Qm94IG1iPVwieGxcIj5cbiAgICAgICAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjRkZENzAwJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEzcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuNXB4JywgbWFyZ2luQm90dG9tOiAnOHB4JyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgIFByaW1hcnkgVmVyaWZpZWQgRG93bmxvYWQgUm91dGU6XG4gICAgICAgICAgICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgPEJveFxuICAgICAgICAgICAgICAgICAgICAgICAgcD1cIm1kXCJcbiAgICAgICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAnIzBiMGMxMCcsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkICMzMzMnLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJvcmRlclJhZGl1czogJzhweCcsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogJ2ZsZXgnLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZ2FwOiAnMTJweCdcbiAgICAgICAgICAgICAgICAgICAgICAgIH19XG4gICAgICAgICAgICAgICAgICAgID5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnIzAwZTVmZicsIGZvbnRGYW1pbHk6ICdtb25vc3BhY2UnLCBmb250U2l6ZTogJzEzcHgnLCB3b3JkQnJlYWs6ICdicmVhay1hbGwnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtwcmltYXJ5RG93bmxvYWRVcmx9XG4gICAgICAgICAgICAgICAgICAgICAgICA8L1RleHQ+XG4gICAgICAgICAgICAgICAgICAgICAgICA8Qm94IGZsZXggc3R5bGU9e3sgZ2FwOiAnOHB4JywgZmxleFNocmluazogMCB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8QnV0dG9uXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNpemU9XCJzbVwiXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhcmlhbnQ9XCJzZWNvbmRhcnlcIlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBoYW5kbGVDb3B5KHByaW1hcnlEb3dubG9hZFVybCl9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7IGN1cnNvcjogJ3BvaW50ZXInLCBiYWNrZ3JvdW5kOiBjb3BpZWQgPyAnIzJlY2M3MScgOiB1bmRlZmluZWQgfX1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxJY29uIGljb249e2NvcGllZCA/ICdDaGVjaycgOiAnQ29weSd9IHN0eWxlPXt7IG1hcmdpblJpZ2h0OiAnNnB4JyB9fSAvPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7Y29waWVkID8gJ0NvcGllZCcgOiAnQ29weSBVUkwnfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxCdXR0b25cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZT1cInNtXCJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyaWFudD1cInByaW1hcnlcIlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBoYW5kbGVTdGFydERvd25sb2FkKHByaW1hcnlEb3dubG9hZFVybCl9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyNGRkQ3MDAnLCBjb2xvcjogJyMwMDAnLCBmb250V2VpZ2h0OiA2MDAsIGN1cnNvcjogJ3BvaW50ZXInIH19XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8SWNvbiBpY29uPVwiRXh0ZXJuYWxMaW5rXCIgc3R5bGU9e3sgbWFyZ2luUmlnaHQ6ICc2cHgnIH19IC8+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRlc3QgRG93bmxvYWRcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L0J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgICAgICA8L0JveD5cbiAgICAgICAgICAgICAgICA8L0JveD5cblxuICAgICAgICAgICAgICAgIHsvKiBBZGRpdGlvbmFsIEVuZHBvaW50cyAmIENsb3VkIFN0b3JhZ2UgSW5mbyAqL31cbiAgICAgICAgICAgICAgICA8Qm94IG1iPVwibGdcIj5cbiAgICAgICAgICAgICAgICAgICAge2V4dGVybmFsVXJsICYmIChcbiAgICAgICAgICAgICAgICAgICAgICAgIDxCb3ggbWI9XCJtZFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnI2JiYicsIGZvbnRTaXplOiAnMTJweCcsIGZvbnRXZWlnaHQ6IDYwMCwgbWFyZ2luQm90dG9tOiAnNHB4JyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRXh0ZXJuYWwgQ2xvdWQgTWlycm9yIFVSTDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L1RleHQ+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPEJveCBwPVwic21cIiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMGIwYzEwJywgYm9yZGVyOiAnMXB4IHNvbGlkICMyMjInLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBkaXNwbGF5OiAnZmxleCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIGFsaWduSXRlbXM6ICdjZW50ZXInIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNjY2MnLCBmb250U2l6ZTogJzEycHgnLCBmb250RmFtaWx5OiAnbW9ub3NwYWNlJywgd29yZEJyZWFrOiAnYnJlYWstYWxsJyB9fT57ZXh0ZXJuYWxVcmx9PC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8QnV0dG9uIHNpemU9XCJzbVwiIHZhcmlhbnQ9XCJ0ZXh0XCIgb25DbGljaz17KCkgPT4gaGFuZGxlQ29weShleHRlcm5hbFVybCl9IHN0eWxlPXt7IGN1cnNvcjogJ3BvaW50ZXInLCBjb2xvcjogJyNGRkQ3MDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEljb24gaWNvbj1cIkNvcHlcIiAvPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L0J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L0JveD5cbiAgICAgICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgICAgICApfVxuXG4gICAgICAgICAgICAgICAgICAgIHtmaWxlS2V5ICYmIChcbiAgICAgICAgICAgICAgICAgICAgICAgIDxCb3ggbWI9XCJtZFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnI2JiYicsIGZvbnRTaXplOiAnMTJweCcsIGZvbnRXZWlnaHQ6IDYwMCwgbWFyZ2luQm90dG9tOiAnNHB4JyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQmFja2JsYXplIEIyIFN0b3JhZ2UgS2V5OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8Qm94IHA9XCJzbVwiIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMwYjBjMTAnLCBib3JkZXI6ICcxcHggc29saWQgIzIyMicsIGJvcmRlclJhZGl1czogJzZweCcsIGRpc3BsYXk6ICdmbGV4JywganVzdGlmeUNvbnRlbnQ6ICdzcGFjZS1iZXR3ZWVuJywgYWxpZ25JdGVtczogJ2NlbnRlcicgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnI2FhYScsIGZvbnRTaXplOiAnMTJweCcsIGZvbnRGYW1pbHk6ICdtb25vc3BhY2UnLCB3b3JkQnJlYWs6ICdicmVhay1hbGwnIH19PntmaWxlS2V5fTwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBzaXplPVwic21cIiB2YXJpYW50PVwidGV4dFwiIG9uQ2xpY2s9eygpID0+IGhhbmRsZUNvcHkoZmlsZUtleSl9IHN0eWxlPXt7IGN1cnNvcjogJ3BvaW50ZXInLCBjb2xvcjogJyNGRkQ3MDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEljb24gaWNvbj1cIkNvcHlcIiAvPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L0J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L0JveD5cbiAgICAgICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgICAgICApfVxuXG4gICAgICAgICAgICAgICAgICAgIHtkaXJlY3RVcmwgJiYgKFxuICAgICAgICAgICAgICAgICAgICAgICAgPEJveCBtYj1cIm1kXCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjYmJiJywgZm9udFNpemU6ICcxMnB4JywgZm9udFdlaWdodDogNjAwLCBtYXJnaW5Cb3R0b206ICc0cHgnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBEaXJlY3QgQ0ROIC8gQ2xvdWRmbGFyZSBQYXNzdGhyb3VnaDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L1RleHQ+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPEJveCBwPVwic21cIiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMGIwYzEwJywgYm9yZGVyOiAnMXB4IHNvbGlkICMyMjInLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBkaXNwbGF5OiAnZmxleCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIGFsaWduSXRlbXM6ICdjZW50ZXInIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyMyZWNjNzEnLCBmb250U2l6ZTogJzEycHgnLCBmb250RmFtaWx5OiAnbW9ub3NwYWNlJywgd29yZEJyZWFrOiAnYnJlYWstYWxsJyB9fT57ZGlyZWN0VXJsfTwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBzaXplPVwic21cIiB2YXJpYW50PVwidGV4dFwiIG9uQ2xpY2s9eygpID0+IGhhbmRsZUNvcHkoZGlyZWN0VXJsKX0gc3R5bGU9e3sgY3Vyc29yOiAncG9pbnRlcicsIGNvbG9yOiAnI0ZGRDcwMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8SWNvbiBpY29uPVwiQ29weVwiIC8+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICAgICAgICAgICAgICl9XG4gICAgICAgICAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgICAgICAgICB7LyogRm9vdGVyIEJ1dHRvbnMgKi99XG4gICAgICAgICAgICAgICAgPEJveCBmbGV4IGp1c3RpZnlDb250ZW50PVwiZmxleC1lbmRcIiBzdHlsZT17eyBnYXA6ICcxMHB4JyB9fSBtdD1cInhsXCIgcHQ9XCJsZ1wiIGJvcmRlclRvcD1cIjFweCBzb2xpZCByZ2JhKDI1NSwgMjU1LCAyNTUsIDAuMDgpXCI+XG4gICAgICAgICAgICAgICAgICAgIDxCdXR0b24gdmFyaWFudD1cImxpZ2h0XCIgb25DbGljaz17aGFuZGxlQmFja30gc3R5bGU9e3sgY3Vyc29yOiAncG9pbnRlcicgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICBEb25lXG4gICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICA8QnV0dG9uXG4gICAgICAgICAgICAgICAgICAgICAgICB2YXJpYW50PVwicHJpbWFyeVwiXG4gICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBoYW5kbGVTdGFydERvd25sb2FkKHByaW1hcnlEb3dubG9hZFVybCl9XG4gICAgICAgICAgICAgICAgICAgICAgICBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjRkZENzAwJywgY29sb3I6ICcjMDAwJywgZm9udFdlaWdodDogNjAwLCBjdXJzb3I6ICdwb2ludGVyJyB9fVxuICAgICAgICAgICAgICAgICAgICA+XG4gICAgICAgICAgICAgICAgICAgICAgICA8SWNvbiBpY29uPVwiRG93bmxvYWRcIiBzdHlsZT17eyBtYXJnaW5SaWdodDogJzZweCcgfX0gLz5cbiAgICAgICAgICAgICAgICAgICAgICAgIExhdW5jaCBEb3dubG9hZFxuICAgICAgICAgICAgICAgICAgICA8L0J1dHRvbj5cbiAgICAgICAgICAgICAgICA8L0JveD5cbiAgICAgICAgICAgIDwvQm94PlxuICAgICAgICA8L0JveD5cbiAgICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgRG93bmxvYWRJbnNwZWN0b3I7XG4iLCJpbXBvcnQgUmVhY3QgZnJvbSAncmVhY3QnO1xuXG5jb25zdCBWYXJpYW50QmFkZ2UgPSAocHJvcHMpID0+IHtcbiAgY29uc3QgeyByZWNvcmQsIHByb3BlcnR5IH0gPSBwcm9wcztcbiAgaWYgKCFyZWNvcmQgfHwgIXJlY29yZC5wYXJhbXMgfHwgIXByb3BlcnR5KSByZXR1cm4gbnVsbDtcbiAgY29uc3QgaXNWYXJpYW50ID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcbiAgY29uc3QgaXNWYXIgPSBpc1ZhcmlhbnQgPT09IHRydWUgfHwgaXNWYXJpYW50ID09PSAndHJ1ZSc7XG4gIGNvbnN0IG1hc3RlcklkID0gcmVjb3JkLnBhcmFtcy5tYXN0ZXJGaWxlO1xuICBjb25zdCByZWNvcmRJZCA9IHJlY29yZC5wYXJhbXMuX2lkIHx8IHJlY29yZC5pZDtcblxuICBjb25zdCBoYW5kbGVDbGljayA9IChlKSA9PiB7XG4gICAgZS5wcmV2ZW50RGVmYXVsdCgpO1xuICAgIGUuc3RvcFByb3BhZ2F0aW9uKCk7XG4gICAgaWYgKGlzVmFyICYmIG1hc3RlcklkKSB7XG4gICAgICB3aW5kb3cubG9jYXRpb24uaHJlZiA9IGAvYWRtaW4vcmVzb3VyY2VzL0ZpbGUvcmVjb3Jkcy8ke21hc3RlcklkfS9zaG93YDtcbiAgICB9IGVsc2Uge1xuICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSBgL2FkbWluL3Jlc291cmNlcy9GaWxlP2ZpbHRlcnMubWFzdGVyRmlsZT0ke3JlY29yZElkfWA7XG4gICAgfVxuICB9O1xuXG4gIGlmIChpc1Zhcikge1xuICAgIHJldHVybiAoXG4gICAgICA8YVxuICAgICAgICBocmVmPXttYXN0ZXJJZCA/IGAvYWRtaW4vcmVzb3VyY2VzL0ZpbGUvcmVjb3Jkcy8ke21hc3RlcklkfS9zaG93YCA6ICcjJ31cbiAgICAgICAgb25DbGljaz17aGFuZGxlQ2xpY2t9XG4gICAgICAgIHRpdGxlPXttYXN0ZXJJZCA/IGBDbGljayB0byB2aWV3IE1hc3RlciBBcHAgKCR7bWFzdGVySWR9KWAgOiAnVmFyaWFudCBNb2QnfVxuICAgICAgICBjbGFzc05hbWU9XCJhZG1pbi1jdXN0b20tY2hpcFwiXG4gICAgICAgIGRhdGEtYmFkZ2UtdmFsPVwidmFyaWFudC1jaGlsZFwiXG4gICAgICAgIHN0eWxlPXt7XG4gICAgICAgICAgZGlzcGxheTogJ2lubGluZS1mbGV4JyxcbiAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJyxcbiAgICAgICAgICBnYXA6ICc2cHgnLFxuICAgICAgICAgIHBhZGRpbmc6ICc0cHggMTFweCcsXG4gICAgICAgICAgYm9yZGVyUmFkaXVzOiAnMjBweCcsXG4gICAgICAgICAgZm9udFNpemU6ICcxMXB4JyxcbiAgICAgICAgICBmb250V2VpZ2h0OiA3MDAsXG4gICAgICAgICAgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsXG4gICAgICAgICAgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsXG4gICAgICAgICAgYmFja2dyb3VuZDogJ2xpbmVhci1ncmFkaWVudCgxNDVkZWcsIHJnYmEoMTg2LCAxMDQsIDIwMCwgMC4yOCkgMCUsIHJnYmEoNjUsIDI1LCA3NSwgMC4zNSkgMTAwJSknLFxuICAgICAgICAgIGNvbG9yOiAnI2UxYmVlNycsXG4gICAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMTg2LCAxMDQsIDIwMCwgMC43KScsXG4gICAgICAgICAgYm94U2hhZG93OiAnaW5zZXQgMCAxLjVweCAycHggcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjIpLCAwIDAgMTBweCByZ2JhKDE4NiwgMTA0LCAyMDAsIDAuMyknLFxuICAgICAgICAgIHRleHRTaGFkb3c6ICcwIDAgNnB4IHJnYmEoMjA2LCAxNDcsIDIxNiwgMC40KScsXG4gICAgICAgICAgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIixcbiAgICAgICAgICB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLFxuICAgICAgICAgIGN1cnNvcjogJ3BvaW50ZXInLFxuICAgICAgICAgIHRyYW5zaXRpb246ICdhbGwgMC4ycyBlYXNlJ1xuICAgICAgICB9fVxuICAgICAgICBvbk1vdXNlRW50ZXI9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAnc2NhbGUoMS4wNSknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSAnI2NlOTNkOCc7IH19XG4gICAgICAgIG9uTW91c2VMZWF2ZT17KGUpID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLnRyYW5zZm9ybSA9ICdzY2FsZSgxKSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9ICdyZ2JhKDE4NiwgMTA0LCAyMDAsIDAuNyknOyB9fVxuICAgICAgPlxuICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzEwcHgnIH19PuKaoTwvc3Bhbj4gVmFyaWFudFxuICAgICAgPC9hPlxuICAgICk7XG4gIH1cblxuICByZXR1cm4gKFxuICAgIDxhXG4gICAgICBocmVmPXtgL2FkbWluL3Jlc291cmNlcy9GaWxlP2ZpbHRlcnMubWFzdGVyRmlsZT0ke3JlY29yZElkfWB9XG4gICAgICBvbkNsaWNrPXtoYW5kbGVDbGlja31cbiAgICAgIHRpdGxlPVwiQ2xpY2sgdG8gdmlldyBhbGwgVmFyaWFudHMgb2YgdGhpcyBNYXN0ZXIgTW9kXCJcbiAgICAgIGNsYXNzTmFtZT1cImFkbWluLWN1c3RvbS1jaGlwXCJcbiAgICAgIGRhdGEtYmFkZ2UtdmFsPVwidmFyaWFudC1tYXN0ZXJcIlxuICAgICAgc3R5bGU9e3tcbiAgICAgICAgZGlzcGxheTogJ2lubGluZS1mbGV4JyxcbiAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcicsXG4gICAgICAgIGdhcDogJzZweCcsXG4gICAgICAgIHBhZGRpbmc6ICc0cHggMTFweCcsXG4gICAgICAgIGJvcmRlclJhZGl1czogJzIwcHgnLFxuICAgICAgICBmb250U2l6ZTogJzExcHgnLFxuICAgICAgICBmb250V2VpZ2h0OiA3MDAsXG4gICAgICAgIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLFxuICAgICAgICB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyxcbiAgICAgICAgYmFja2dyb3VuZDogJ2xpbmVhci1ncmFkaWVudCgxNDVkZWcsIHJnYmEoMjU1LCAyMTUsIDAsIDAuMjUpIDAlLCByZ2JhKDkwLCA3MCwgMTUsIDAuMykgMTAwJSknLFxuICAgICAgICBjb2xvcjogJyNGRkQ3MDAnLFxuICAgICAgICBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsIDIxNSwgMCwgMC43NSknLFxuICAgICAgICBib3hTaGFkb3c6ICdpbnNldCAwIDEuNXB4IDJweCByZ2JhKDI1NSwgMjU1LCAyNTUsIDAuMjIpLCAwIDAgMTBweCByZ2JhKDI1NSwgMjE1LCAwLCAwLjMpJyxcbiAgICAgICAgdGV4dFNoYWRvdzogJzAgMCA2cHggcmdiYSgyNTUsIDIxNSwgMCwgMC40KScsXG4gICAgICAgIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIsXG4gICAgICAgIHRleHREZWNvcmF0aW9uOiAnbm9uZScsXG4gICAgICAgIGN1cnNvcjogJ3BvaW50ZXInLFxuICAgICAgICB0cmFuc2l0aW9uOiAnYWxsIDAuMnMgZWFzZSdcbiAgICAgIH19XG4gICAgICBvbk1vdXNlRW50ZXI9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAnc2NhbGUoMS4wNSknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSAnI2ZmZic7IH19XG4gICAgICBvbk1vdXNlTGVhdmU9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAnc2NhbGUoMSknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSAncmdiYSgyNTUsIDIxNSwgMCwgMC43NSknOyB9fVxuICAgID5cbiAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnMTBweCcgfX0+8J+RkTwvc3Bhbj4gTWFzdGVyXG4gICAgPC9hPlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgVmFyaWFudEJhZGdlO1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlLCB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3ggfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgQXZhdGFyQ2VsbCA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSwgd2hlcmUgfSA9IHByb3BzOyBcbiAgICBpZiAoIXJlY29yZCB8fCAhcmVjb3JkLnBhcmFtcyB8fCAhcHJvcGVydHkpIHJldHVybiBudWxsO1xuICAgIGNvbnN0IGtleSA9IHJlY29yZC5wYXJhbXNbcHJvcGVydHkubmFtZV07XG4gICAgY29uc3QgdXNlcm5hbWUgPSByZWNvcmQucGFyYW1zLnVzZXJuYW1lIHx8ICdVc2VyJztcblxuICAgIGNvbnN0IFtpbWFnZVVybCwgc2V0SW1hZ2VVcmxdID0gdXNlU3RhdGUobnVsbCk7XG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG4gICAgY29uc3QgW2hhc0Vycm9yLCBzZXRIYXNFcnJvcl0gPSB1c2VTdGF0ZShmYWxzZSk7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBpZiAoIWtleSkge1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoa2V5LnN0YXJ0c1dpdGgoJ2h0dHA6Ly8nKSB8fCBrZXkuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKSkge1xuICAgICAgICAgICAgc2V0SW1hZ2VVcmwoa2V5KTtcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZmV0Y2hTaWduZWRVcmwgPSBhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2goYC9hcGkvYWRtaW4vc2lnbmVkLXVybD9rZXk9JHtlbmNvZGVVUklDb21wb25lbnQoa2V5KX1gKTtcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgICAgICAgICAgc2V0SW1hZ2VVcmwoZGF0YS51cmwpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHNldEhhc0Vycm9yKHRydWUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIkVycm9yIGZldGNoaW5nIGF2YXRhciBVUkw6XCIsIGVycm9yKTtcbiAgICAgICAgICAgICAgICBzZXRIYXNFcnJvcih0cnVlKTtcbiAgICAgICAgICAgIH0gZmluYWxseSB7XG4gICAgICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG5cbiAgICAgICAgZmV0Y2hTaWduZWRVcmwoKTtcbiAgICB9LCBba2V5XSk7XG5cbiAgICBjb25zdCBzaXplID0gd2hlcmUgPT09ICdsaXN0JyA/ICczMnB4JyA6ICcxMjBweCc7XG5cbiAgICBpZiAobG9hZGluZykge1xuICAgICAgICByZXR1cm4gPEJveCBzdHlsZT17eyB3aWR0aDogc2l6ZSwgaGVpZ2h0OiBzaXplLCBib3JkZXJSYWRpdXM6ICc1MCUnLCBiYWNrZ3JvdW5kQ29sb3I6ICcjMzMzJyB9fSAvPjtcbiAgICB9XG5cbiAgICBjb25zdCBkZWZhdWx0QXZhdGFyID0gJy9pbWFnZXMvZGVmYXVsdC1hdmF0YXIucG5nJztcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3g+XG4gICAgICAgICAgICA8aW1nIFxuICAgICAgICAgICAgICAgIHNyYz17KCFpbWFnZVVybCB8fCBoYXNFcnJvcikgPyBkZWZhdWx0QXZhdGFyIDogaW1hZ2VVcmx9IFxuICAgICAgICAgICAgICAgIGFsdD17dXNlcm5hbWV9XG4gICAgICAgICAgICAgICAgc3R5bGU9e3sgXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiAnNTAlJywgXG4gICAgICAgICAgICAgICAgICAgIG9iamVjdEZpdDogJ2NvdmVyJyxcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyOiAnMnB4IHNvbGlkICNGRkQ3MDAnLFxuICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICcjMWExYTFhJ1xuICAgICAgICAgICAgICAgIH19IFxuICAgICAgICAgICAgICAgIG9uRXJyb3I9eyhlKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChlLmN1cnJlbnRUYXJnZXQuc3JjICE9PSBkZWZhdWx0QXZhdGFyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3JjID0gZGVmYXVsdEF2YXRhcjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH19XG4gICAgICAgICAgICAvPlxuICAgICAgICA8L0JveD5cbiAgICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgQXZhdGFyQ2VsbDtcbiIsImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94IH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5cbmNvbnN0IEltYWdlUHJldmlldyA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSwgd2hlcmUgfSA9IHByb3BzOyBcbiAgICBpZiAoIXJlY29yZCB8fCAhcmVjb3JkLnBhcmFtcyB8fCAhcHJvcGVydHkpIHJldHVybiBudWxsO1xuICAgIGNvbnN0IHZhbHVlID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcblxuICAgIGNvbnN0IFtpbWFnZVVybCwgc2V0SW1hZ2VVcmxdID0gdXNlU3RhdGUobnVsbCk7XG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBpZiAoIXZhbHVlKSB7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh2YWx1ZS5zdGFydHNXaXRoKCdodHRwOi8vJykgfHwgdmFsdWUuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKSkge1xuICAgICAgICAgICAgc2V0SW1hZ2VVcmwodmFsdWUpO1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBmZXRjaFNpZ25lZFVybCA9IGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChgL2FwaS9hZG1pbi9zaWduZWQtdXJsP2tleT0ke2VuY29kZVVSSUNvbXBvbmVudCh2YWx1ZSl9YCk7XG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlLm9rKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICAgICAgICAgIHNldEltYWdlVXJsKGRhdGEudXJsKTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiRmFpbGVkIHRvIGZldGNoIHNpZ25lZCBVUkwuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIk5ldHdvcmsgZXJyb3IgZmV0Y2hpbmcgc2lnbmVkIFVSTDpcIiwgZXJyb3IpO1xuICAgICAgICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcblxuICAgICAgICBmZXRjaFNpZ25lZFVybCgpO1xuICAgIH0sIFt2YWx1ZV0pO1xuXG4gICAgaWYgKGxvYWRpbmcpIHJldHVybiA8Qm94IHN0eWxlPXt7IGNvbG9yOiAnI0ZGRDcwMCcsIGZvbnRTaXplOiAnMTJweCcgfX0+TG9hZGluZy4uLjwvQm94PjtcblxuICAgIGNvbnN0IGlzQXZhdGFyID0gcHJvcGVydHkubmFtZSA9PT0gJ3Byb2ZpbGVJbWFnZUtleScgfHwgcHJvcGVydHkubmFtZSA9PT0gJ2NhcmRBdmF0YXJVcmwnIHx8IHByb3BlcnR5Lm5hbWUgPT09ICdhdmF0YXInO1xuICAgIGNvbnN0IGRlZmF1bHRJbWFnZSA9IGlzQXZhdGFyID8gJy9pbWFnZXMvZGVmYXVsdC1hdmF0YXIucG5nJyA6ICcvaW1hZ2VzL2RlZmF1bHQtYXBwLWljb24ucG5nJztcbiAgICBjb25zdCBkaXNwbGF5VXJsID0gaW1hZ2VVcmwgfHwgZGVmYXVsdEltYWdlO1xuXG4gICAgY29uc3Qgc2l6ZSA9IHdoZXJlID09PSAnbGlzdCcgPyAnNDBweCcgOiAnMTUwcHgnO1xuICAgIGNvbnN0IHJhZGl1cyA9IGlzQXZhdGFyID8gJzUwJScgOiAnOHB4JztcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3g+XG4gICAgICAgICAgICA8aW1nIFxuICAgICAgICAgICAgICAgIHNyYz17ZGlzcGxheVVybH0gXG4gICAgICAgICAgICAgICAgYWx0PVwiUHJldmlld1wiIFxuICAgICAgICAgICAgICAgIHN0eWxlPXt7IFxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGhlaWdodDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlclJhZGl1czogcmFkaXVzLFxuICAgICAgICAgICAgICAgICAgICBvYmplY3RGaXQ6ICdjb3ZlcicsXG4gICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnLFxuICAgICAgICAgICAgICAgICAgICBib3JkZXI6ICcxcHggc29saWQgIzMzMydcbiAgICAgICAgICAgICAgICB9fSBcbiAgICAgICAgICAgICAgICBvbkVycm9yPXsoZSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZS5jdXJyZW50VGFyZ2V0LnNyYyAhPT0gZGVmYXVsdEltYWdlKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3JjID0gZGVmYXVsdEltYWdlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfX1cbiAgICAgICAgICAgIC8+XG4gICAgICAgIDwvQm94PlxuICAgICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBJbWFnZVByZXZpZXc7XG4iLCJBZG1pbkpTLlVzZXJDb21wb25lbnRzID0ge31cbkFkbWluSlMuZW52Lk5PREVfRU5WID0gXCJwcm9kdWN0aW9uXCJcbmltcG9ydCBEYXNoYm9hcmQgZnJvbSAnLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvQ3VzdG9tRGFzaGJvYXJkJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5EYXNoYm9hcmQgPSBEYXNoYm9hcmRcbmltcG9ydCBTaWRlYmFyQnJhbmRpbmcgZnJvbSAnLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5TaWRlYmFyQnJhbmRpbmcgPSBTaWRlYmFyQnJhbmRpbmdcbmltcG9ydCBBY3Rpb25SZWRpcmVjdCBmcm9tICcuLi9jb21wb25lbnRzL2FjdGlvbnMvQWN0aW9uUmVkaXJlY3QnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkFjdGlvblJlZGlyZWN0ID0gQWN0aW9uUmVkaXJlY3RcbmltcG9ydCBEb3dubG9hZEluc3BlY3RvciBmcm9tICcuLi9jb21wb25lbnRzL2FjdGlvbnMvRG93bmxvYWRJbnNwZWN0b3InXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkRvd25sb2FkSW5zcGVjdG9yID0gRG93bmxvYWRJbnNwZWN0b3JcbmltcG9ydCBWYXJpYW50QmFkZ2UgZnJvbSAnLi4vY29tcG9uZW50cy9jZWxscy9WYXJpYW50QmFkZ2UnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLlZhcmlhbnRCYWRnZSA9IFZhcmlhbnRCYWRnZVxuaW1wb3J0IEF2YXRhckNlbGwgZnJvbSAnLi4vY29tcG9uZW50cy9jZWxscy9BdmF0YXJDZWxsJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5BdmF0YXJDZWxsID0gQXZhdGFyQ2VsbFxuaW1wb3J0IEltYWdlUHJldmlldyBmcm9tICcuLi9jb21wb25lbnRzL2NlbGxzL0ltYWdlUHJldmlldydcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuSW1hZ2VQcmV2aWV3ID0gSW1hZ2VQcmV2aWV3Il0sIm5hbWVzIjpbImFwaSIsIkFwaUNsaWVudCIsIkMiLCJiZyIsInN1cmZhY2UiLCJzdXJmYWNlQWx0IiwiYm9yZGVyIiwiYm9yZGVySG92ZXIiLCJnb2xkIiwiZ29sZERpbSIsImdvbGRHbG93IiwiYmx1ZSIsImdyZWVuIiwicHVycGxlIiwicmVkIiwib3JhbmdlIiwidGV4dCIsInRleHRNdXRlZCIsInRleHREaW0iLCJQTEFURk9STV9DT0xPUlMiLCJjYXJkU3R5bGUiLCJhY2NlbnRDb2xvciIsImJhY2tncm91bmRDb2xvciIsImJvcmRlclJhZGl1cyIsImJvcmRlckxlZnQiLCJwYWRkaW5nIiwidHJhbnNpdGlvbiIsImN1cnNvciIsImJveFNpemluZyIsIkFyZWFDaGFydCIsImRhdGEiLCJ3aWR0aCIsImhlaWdodCIsImNvbG9yIiwibGVuZ3RoIiwibWF4VmFsIiwiTWF0aCIsIm1heCIsIm1hcCIsImQiLCJ2YWx1ZSIsInBhZFgiLCJwYWRZIiwiY2hhcnRXIiwiY2hhcnRIIiwicG9pbnRzIiwiaSIsIngiLCJ5IiwibGluZVBhdGgiLCJwIiwiam9pbiIsImFyZWFQYXRoIiwiZ3JpZExpbmVzIiwicGN0IiwibGFiZWwiLCJyb3VuZCIsInN0ZXAiLCJjZWlsIiwiUmVhY3QiLCJjcmVhdGVFbGVtZW50Iiwic3R5bGUiLCJvdmVyZmxvdyIsInZpZXdCb3giLCJwcmVzZXJ2ZUFzcGVjdFJhdGlvIiwiZGlzcGxheSIsIm1heFdpZHRoIiwiaWQiLCJ4MSIsInkxIiwieDIiLCJ5MiIsIm9mZnNldCIsInN0b3BDb2xvciIsInN0b3BPcGFjaXR5IiwiZyIsImtleSIsInN0cm9rZSIsInN0cm9rZVdpZHRoIiwic3Ryb2tlRGFzaGFycmF5IiwiZmlsbCIsImZvbnRTaXplIiwiZm9udEZhbWlseSIsInRleHRBbmNob3IiLCJzdHJva2VMaW5lam9pbiIsInN0cm9rZUxpbmVjYXAiLCJzaG93TGFiZWwiLCJjeCIsImN5IiwiciIsIkRvbnV0Q2hhcnQiLCJzaXplIiwidG90YWwiLCJyZWR1Y2UiLCJzIiwib3V0ZXJSIiwiaW5uZXJSIiwiY3VtQW5nbGUiLCJQSSIsInNsaWNlcyIsImFuZ2xlIiwic3RhcnRBbmdsZSIsImVuZEFuZ2xlIiwiY29zIiwic2luIiwiaXgxIiwiaXkxIiwiaXgyIiwiaXkyIiwibGFyZ2VBcmMiLCJwYXRoIiwibmFtZSIsImFsaWduSXRlbXMiLCJnYXAiLCJmbGV4V3JhcCIsImp1c3RpZnlDb250ZW50IiwiZm9udFdlaWdodCIsImZsZXhEaXJlY3Rpb24iLCJmbGV4U2hyaW5rIiwibWFyZ2luTGVmdCIsIlN0YXRDYXJkIiwiaWNvbiIsImRlbHRhIiwiZGVsdGFMYWJlbCIsIkJveCIsImZsZXgiLCJtaW5XaWR0aCIsIm9uTW91c2VFbnRlciIsImUiLCJjdXJyZW50VGFyZ2V0IiwiYm9yZGVyQ29sb3IiLCJ0cmFuc2Zvcm0iLCJib3hTaGFkb3ciLCJvbk1vdXNlTGVhdmUiLCJib3JkZXJMZWZ0Q29sb3IiLCJtYXJnaW5Cb3R0b20iLCJJY29uIiwiVGV4dCIsInRleHRUcmFuc2Zvcm0iLCJsZXR0ZXJTcGFjaW5nIiwiSDIiLCJtYXJnaW4iLCJ1bmRlZmluZWQiLCJBY3Rpb25DYXJkIiwiY291bnQiLCJyZXNvdXJjZUlkIiwiaHJlZiIsInRleHREZWNvcmF0aW9uIiwiSDUiLCJmbXREYXRlIiwiZHQiLCJEYXRlIiwidG9Mb2NhbGVEYXRlU3RyaW5nIiwibW9udGgiLCJkYXkiLCJ5ZWFyIiwic3RhdHVzQ29sb3IiLCJsb3dlciIsInRvTG93ZXJDYXNlIiwiQ3VzdG9tRGFzaGJvYXJkIiwic2V0RGF0YSIsInVzZVN0YXRlIiwibG9hZGluZyIsInNldExvYWRpbmciLCJlcnJvciIsInNldEVycm9yIiwidXNlRWZmZWN0IiwiZ2V0RGFzaGJvYXJkIiwidGhlbiIsInJlc3BvbnNlIiwiY2F0Y2giLCJmZXRjaEVycm9yIiwiY29uc29sZSIsIm1pbkhlaWdodCIsInRleHRBbGlnbiIsImJvcmRlclRvcENvbG9yIiwiYW5pbWF0aW9uIiwic3RhdHMiLCJhY3Rpb25SZXF1aXJlZCIsIm1vZHNCeVBsYXRmb3JtIiwidXNlckdyb3d0aERhdGEiLCJyZWNlbnRVc2VycyIsInJlY2VudE1vZHMiLCJncm93dGhDaGFydERhdGEiLCJkYXRlIiwidXNlcnMiLCJub3ciLCJncmVldGluZyIsImdldEhvdXJzIiwicGFkZGluZ0JvdHRvbSIsImJvcmRlckJvdHRvbSIsInRleHRTaGFkb3ciLCJiYWNrZ3JvdW5kIiwibWFyZ2luVG9wIiwibGluZUhlaWdodCIsIndlZWtkYXkiLCJ0aXRsZSIsInRhcmdldCIsInJlbCIsInRvdGFsVXNlcnMiLCJ0b0xvY2FsZVN0cmluZyIsIm5ld1VzZXJzVGhpc01vbnRoIiwidG90YWxNb2RzIiwibmV3TW9kc1RoaXNNb250aCIsInRvdGFsRG93bmxvYWRzIiwidG90YWxWaWV3cyIsInBlbmRpbmdSZXBvcnRzIiwicGVuZGluZ0FwcHJvdmFscyIsIm9wZW5UaWNrZXRzIiwiQmFkZ2UiLCJvdmVyZmxvd1giLCJXZWJraXRPdmVyZmxvd1Njcm9sbGluZyIsImJvcmRlckNvbGxhcHNlIiwidSIsInVzZXJuYW1lIiwicm9sZSIsIm0iLCJ0ZXh0T3ZlcmZsb3ciLCJ3aGl0ZVNwYWNlIiwiY2F0ZWdvcnkiLCJzdGF0dXMiLCJwYWRkaW5nVG9wIiwiYm9yZGVyVG9wIiwiU2lkZWJhckJyYW5kaW5nIiwicG9zaXRpb24iLCJib3R0b20iLCJsZWZ0Iiwib3BhY2l0eSIsInNyYyIsImFsdCIsIm9iamVjdEZpdCIsImZpbHRlciIsIm9uRXJyb3IiLCJBY3Rpb25SZWRpcmVjdCIsInByb3BzIiwicmVjb3JkIiwic2VuZE5vdGljZSIsInVzZU5vdGljZSIsInVybCIsInBhcmFtcyIsInJlZGlyZWN0VXJsIiwibWVzc2FnZSIsInR5cGUiLCJzdGFydHNXaXRoIiwid2luZG93IiwibG9jYXRpb24iLCJvcGVuIiwic2V0VGltZW91dCIsImhpc3RvcnkiLCJiYWNrIiwiX2lkIiwiTG9hZGVyIiwibXQiLCJ2YXJpYW50IiwiQnV0dG9uIiwib25DbGljayIsIm1hcmdpblJpZ2h0IiwiRG93bmxvYWRJbnNwZWN0b3IiLCJjb3BpZWQiLCJzZXRDb3BpZWQiLCJmaWxlSWQiLCJmaWxlTmFtZSIsImZpbGVWZXJzaW9uIiwidmVyc2lvbiIsImZpbGVTaXplIiwiZXh0ZXJuYWxVcmwiLCJleHRlcm5hbERvd25sb2FkVXJsIiwiZmlsZUtleSIsImRpcmVjdFVybCIsImRpcmVjdERvd25sb2FkVXJsIiwiaXNNdWx0aVBhcnQiLCJwcmltYXJ5RG93bmxvYWRVcmwiLCJvcmlnaW4iLCJoYW5kbGVDb3B5IiwidXJsVG9Db3B5IiwibmF2aWdhdG9yIiwiY2xpcGJvYXJkIiwid3JpdGVUZXh0IiwiaGFuZGxlU3RhcnREb3dubG9hZCIsInRhcmdldFVybCIsImhhbmRsZUJhY2siLCJtYiIsIndvcmRCcmVhayIsInB0IiwiVmFyaWFudEJhZGdlIiwicHJvcGVydHkiLCJpc1ZhcmlhbnQiLCJpc1ZhciIsIm1hc3RlcklkIiwibWFzdGVyRmlsZSIsInJlY29yZElkIiwiaGFuZGxlQ2xpY2siLCJwcmV2ZW50RGVmYXVsdCIsInN0b3BQcm9wYWdhdGlvbiIsImNsYXNzTmFtZSIsIkF2YXRhckNlbGwiLCJ3aGVyZSIsImltYWdlVXJsIiwic2V0SW1hZ2VVcmwiLCJoYXNFcnJvciIsInNldEhhc0Vycm9yIiwiZmV0Y2hTaWduZWRVcmwiLCJmZXRjaCIsImVuY29kZVVSSUNvbXBvbmVudCIsIm9rIiwianNvbiIsImRlZmF1bHRBdmF0YXIiLCJJbWFnZVByZXZpZXciLCJpc0F2YXRhciIsImRlZmF1bHRJbWFnZSIsImRpc3BsYXlVcmwiLCJyYWRpdXMiLCJBZG1pbkpTIiwiVXNlckNvbXBvbmVudHMiLCJlbnYiLCJOT0RFX0VOViIsIkRhc2hib2FyZCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztFQUlBLE1BQU1BLEdBQUcsR0FBRyxJQUFJQyxpQkFBUyxFQUFFOztFQUUzQjtFQUNBLE1BQU1DLENBQUMsR0FBRztFQUNSQyxFQUFBQSxFQUFFLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxPQUFPLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxVQUFVLEVBQUUsU0FBUztFQUN4REMsRUFBQUEsTUFBTSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsV0FBVyxFQUFFLFNBQVM7RUFDekNDLEVBQUFBLElBQUksRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE9BQU8sRUFBRSxzQkFBc0I7RUFBRUMsRUFBQUEsUUFBUSxFQUFFLHNCQUFzQjtFQUNsRkMsRUFBQUEsSUFBSSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsS0FBSyxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsTUFBTSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsR0FBRyxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsTUFBTSxFQUFFLFNBQVM7RUFDdkZDLEVBQUFBLElBQUksRUFBRSxTQUFTO0VBQUVDLEVBQUFBLFNBQVMsRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE9BQU8sRUFBRTtFQUNsRCxDQUFDOztFQUVEO0VBQ0EsTUFBTUMsZUFBZSxHQUFHLENBQUMsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsU0FBUyxFQUFFLFNB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
