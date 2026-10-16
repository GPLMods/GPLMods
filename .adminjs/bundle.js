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
      record,
      action
    } = props;
    const sendNotice = adminjs.useNotice();
    let url = record?.params?.redirectUrl;
    if (!url && record && record.params) {
      const actionName = action?.name;
      const recId = record.params._id || record.id;
      const isVar = record.params.isVariant === true || record.params.isVariant === 'true';
      const masterId = record.params.masterFile;
      if (actionName === 'viewVariants' || !actionName && (isVar || masterId)) {
        if (isVar && masterId) {
          url = `/admin/resources/File/records/${masterId}/show`;
        } else if (recId) {
          url = `/admin/resources/File?filters.masterFile=${recId}`;
        }
      } else if (actionName === 'viewOnSite' && recId) {
        url = `/mods/${recId}`;
      } else if (actionName === 'viewVirusTotal') {
        const vtHash = record.params.virusTotalId || '';
        const vtAnalysis = record.params.virusTotalAnalysisId || '';
        if (vtHash.length === 64) url = `https://www.virustotal.com/gui/file/${vtHash}`;else if (vtAnalysis) url = `https://www.virustotal.com/gui/file-analysis/${vtAnalysis}`;else if (vtHash) url = `https://www.virustotal.com/gui/file-analysis/${vtHash}`;else url = `https://www.virustotal.com/`;
      }
    }
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
    const [verifying, setVerifying] = React.useState(false);
    const [verificationResult, setVerificationResult] = React.useState(null);
    const [showDownloadConfirm, setShowDownloadConfirm] = React.useState(false);
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

    // Safely test/verify the download endpoint without triggering browser file download
    const handleVerifyEndpoint = async () => {
      setVerifying(true);
      setVerificationResult(null);
      try {
        // Using fetch with HEAD or abort controller to check status code without consuming body
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 6000);
        const response = await fetch(primaryDownloadUrl, {
          method: 'GET',
          signal: controller.signal,
          headers: {
            'Range': 'bytes=0-0'
          } // Only request 1 byte so file is never downloaded
        });
        clearTimeout(timeoutId);
        const isOk = response.status >= 200 && response.status < 400;
        const contentType = response.headers.get('content-type') || 'application/octet-stream';
        const contentLength = response.headers.get('content-length') || fileSize;
        setVerificationResult({
          status: response.status,
          statusText: response.statusText || (isOk ? 'OK' : 'Error'),
          isOk,
          contentType,
          contentLength,
          timestamp: new Date().toLocaleTimeString()
        });
        if (isOk) {
          sendNotice({
            message: `✓ Download route verified! HTTP ${response.status} (Valid & Reachable)`,
            type: 'success'
          });
        } else {
          sendNotice({
            message: `⚠️ Download route returned HTTP ${response.status}`,
            type: 'alert'
          });
        }
      } catch (err) {
        setVerificationResult({
          status: 'Error',
          statusText: err.name === 'AbortError' ? 'Timeout (Server responding slowly)' : err.message,
          isOk: false,
          timestamp: new Date().toLocaleTimeString()
        });
        sendNotice({
          message: `Verification check: ${err.message}`,
          type: 'error'
        });
      } finally {
        setVerifying(false);
      }
    };
    const handleConfirmDownload = () => {
      setShowDownloadConfirm(false);
      sendNotice({
        message: 'Initiating file download to your device...',
        type: 'info'
      });
      window.open(primaryDownloadUrl, '_blank');
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
        maxWidth: '840px',
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
    }), "Download Inspector & URL Validator"), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
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
      onClick: handleVerifyEndpoint,
      disabled: verifying,
      style: {
        backgroundColor: '#00c853',
        color: '#fff',
        fontWeight: 600,
        cursor: 'pointer'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: verifying ? 'Loader' : 'CheckCircle',
      style: {
        marginRight: '6px'
      }
    }), verifying ? 'Testing...' : 'Test Validity (Safe)'))), verificationResult && /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      mt: "md",
      p: "md",
      style: {
        backgroundColor: verificationResult.isOk ? 'rgba(0, 200, 83, 0.12)' : 'rgba(231, 76, 60, 0.15)',
        border: `1px solid ${verificationResult.isOk ? 'rgba(0, 200, 83, 0.4)' : 'rgba(231, 76, 60, 0.4)'}`,
        borderRadius: '8px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      justifyContent: "space-between",
      alignItems: "center"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: verificationResult.isOk ? '#2ecc71' : '#e74c3c',
        fontWeight: 600,
        fontSize: '13px'
      }
    }, verificationResult.isOk ? '✓ Route Verified Active & Healthy' : '⚠️ Verification Issue Detected'), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#888',
        fontSize: '11px'
      }
    }, "Tested at ", verificationResult.timestamp)), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#ccc',
        fontSize: '12px',
        marginTop: '4px'
      }
    }, "HTTP Status: ", /*#__PURE__*/React__default.default.createElement("strong", null, verificationResult.status, " ", verificationResult.statusText), " \u2022 Content-Type: ", /*#__PURE__*/React__default.default.createElement("strong", null, verificationResult.contentType), " \u2022 Safe Test (no local download triggered)"))), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
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
    }))))), showDownloadConfirm && /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      p: "lg",
      mb: "lg",
      style: {
        backgroundColor: 'rgba(255, 193, 7, 0.1)',
        border: '1.5px solid #ffc107',
        borderRadius: '10px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#ffd54f',
        fontWeight: 700,
        fontSize: '14px',
        marginBottom: '6px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "AlertTriangle",
      style: {
        marginRight: '6px'
      }
    }), "Confirm Real Download"), /*#__PURE__*/React__default.default.createElement(designSystem.Text, {
      style: {
        color: '#eee',
        fontSize: '13px',
        marginBottom: '12px'
      }
    }, "You are about to start downloading the actual mod file (", fileName, ", ", fileSize, ") directly onto your computer. Are you sure?"), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      style: {
        gap: '10px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      size: "sm",
      variant: "primary",
      onClick: handleConfirmDownload,
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
    }), "Yes, Download File to PC"), /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      size: "sm",
      variant: "light",
      onClick: () => setShowDownloadConfirm(false),
      style: {
        cursor: 'pointer'
      }
    }, "Cancel"))), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      justifyContent: "space-between",
      alignItems: "center",
      mt: "xl",
      pt: "lg",
      borderTop: "1px solid rgba(255, 255, 255, 0.08)"
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      variant: "text",
      onClick: () => window.open(`/mods/${fileId}`, '_blank'),
      style: {
        color: '#64b5f6',
        cursor: 'pointer'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "ExternalLink",
      style: {
        marginRight: '6px'
      }
    }), "View Public Mod Page"), /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      style: {
        gap: '10px'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      variant: "light",
      onClick: handleBack,
      style: {
        cursor: 'pointer'
      }
    }, "Done"), /*#__PURE__*/React__default.default.createElement(designSystem.Button, {
      variant: "secondary",
      onClick: () => setShowDownloadConfirm(true),
      style: {
        cursor: 'pointer',
        borderColor: '#FFD700',
        color: '#FFD700'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Icon, {
      icon: "Download",
      style: {
        marginRight: '6px'
      }
    }), "Download to Local Device...")))));
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIiwic291cmNlcyI6WyIuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQuanN4IiwiLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nLmpzeCIsIi4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdC5qc3giLCIuLi9jb21wb25lbnRzL2FjdGlvbnMvRG93bmxvYWRJbnNwZWN0b3IuanN4IiwiLi4vY29tcG9uZW50cy9jZWxscy9WYXJpYW50QmFkZ2UuanN4IiwiLi4vY29tcG9uZW50cy9jZWxscy9BdmF0YXJDZWxsLmpzeCIsIi4uL2NvbXBvbmVudHMvY2VsbHMvSW1hZ2VQcmV2aWV3LmpzeCIsImVudHJ5LmpzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQXBpQ2xpZW50IH0gZnJvbSAnYWRtaW5qcyc7XG5pbXBvcnQgeyBCb3gsIEgyLCBINSwgVGV4dCwgSWNvbiwgQmFkZ2UgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgYXBpID0gbmV3IEFwaUNsaWVudCgpO1xuXG4vKiDilIDilIDilIAgY29sb3VyIHRva2VucyDilIDilIDilIAgKi9cbmNvbnN0IEMgPSB7XG4gIGJnOiAnIzBhMGEwYScsIHN1cmZhY2U6ICcjMTMxMzEzJywgc3VyZmFjZUFsdDogJyMxYTFhMWEnLFxuICBib3JkZXI6ICcjMmEyYTJhJywgYm9yZGVySG92ZXI6ICcjM2EzYTNhJyxcbiAgZ29sZDogJyNGRkQ3MDAnLCBnb2xkRGltOiAncmdiYSgyNTUsMjE1LDAsMC4xNSknLCBnb2xkR2xvdzogJ3JnYmEoMjU1LDIxNSwwLDAuMzUpJyxcbiAgYmx1ZTogJyMyMTk2RjMnLCBncmVlbjogJyM0M2EwNDcnLCBwdXJwbGU6ICcjOUMyN0IwJywgcmVkOiAnI2U1MzkzNScsIG9yYW5nZTogJyNGRjk4MDAnLFxuICB0ZXh0OiAnI2ZmZmZmZicsIHRleHRNdXRlZDogJyNlMmU4ZjAnLCB0ZXh0RGltOiAnI2NiZDVlMScsXG59O1xuXG4vKiDilIDilIDilIAgcGxhdGZvcm0gY2hhcnQgY29sb3VycyDilIDilIDilIAgKi9cbmNvbnN0IFBMQVRGT1JNX0NPTE9SUyA9IFsnI0E0QzYzOScsICcjMDA3OEQ2JywgJyMyMTc1OUInLCAnI0ZGOTgwMCcsICcjOUMyN0IwJywgJyNlNTM5MzUnLCAnIzQzYTA0NycsICcjRkZENzAwJ107XG5cbi8qIOKUgOKUgOKUgCByZXVzYWJsZSBjYXJkIHN0eWxlIOKUgOKUgOKUgCAqL1xuY29uc3QgY2FyZFN0eWxlID0gKGFjY2VudENvbG9yKSA9PiAoe1xuICBiYWNrZ3JvdW5kQ29sb3I6IEMuc3VyZmFjZSxcbiAgYm9yZGVyUmFkaXVzOiAnMTZweCcsXG4gIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsXG4gIGJvcmRlckxlZnQ6IGFjY2VudENvbG9yID8gYDRweCBzb2xpZCAke2FjY2VudENvbG9yfWAgOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCxcbiAgcGFkZGluZzogJ2NsYW1wKDE2cHgsIDIuNXZ3LCAyNHB4KScsXG4gIHRyYW5zaXRpb246ICdhbGwgMC4yNXMgZWFzZScsXG4gIGN1cnNvcjogJ2RlZmF1bHQnLFxuICBib3hTaXppbmc6ICdib3JkZXItYm94Jyxcbn0pO1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBBcmVhIENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgQXJlYUNoYXJ0ID0gKHsgZGF0YSwgd2lkdGggPSA1MDAsIGhlaWdodCA9IDE3MCwgY29sb3IgPSBDLmdvbGQgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBtYXhWYWwgPSBNYXRoLm1heCguLi5kYXRhLm1hcChkID0+IGQudmFsdWUpLCAxKTtcbiAgY29uc3QgcGFkWCA9IDM1O1xuICBjb25zdCBwYWRZID0gMTY7XG4gIGNvbnN0IGNoYXJ0VyA9IHdpZHRoIC0gcGFkWCAqIDI7XG4gIGNvbnN0IGNoYXJ0SCA9IGhlaWdodCAtIHBhZFkgKiAyO1xuXG4gIGNvbnN0IHBvaW50cyA9IGRhdGEubWFwKChkLCBpKSA9PiAoe1xuICAgIHg6IHBhZFggKyAoaSAvIE1hdGgubWF4KGRhdGEubGVuZ3RoIC0gMSwgMSkpICogY2hhcnRXLFxuICAgIHk6IHBhZFkgKyBjaGFydEggLSAoZC52YWx1ZSAvIG1heFZhbCkgKiBjaGFydEgsXG4gIH0pKTtcblxuICBjb25zdCBsaW5lUGF0aCA9IHBvaW50cy5tYXAoKHAsIGkpID0+IGAke2kgPT09IDAgPyAnTScgOiAnTCd9JHtwLnh9LCR7cC55fWApLmpvaW4oJyAnKTtcbiAgY29uc3QgYXJlYVBhdGggPSBgJHtsaW5lUGF0aH0gTCR7cG9pbnRzW3BvaW50cy5sZW5ndGggLSAxXS54fSwke3BhZFkgKyBjaGFydEh9IEwke3BvaW50c1swXS54fSwke3BhZFkgKyBjaGFydEh9IFpgO1xuXG4gIC8vIEdyaWQgbGluZXNcbiAgY29uc3QgZ3JpZExpbmVzID0gWzAsIDAuMjUsIDAuNSwgMC43NSwgMV0ubWFwKHBjdCA9PiB7XG4gICAgY29uc3QgeSA9IHBhZFkgKyBjaGFydEggLSBwY3QgKiBjaGFydEg7XG4gICAgY29uc3QgbGFiZWwgPSBNYXRoLnJvdW5kKHBjdCAqIG1heFZhbCk7XG4gICAgcmV0dXJuIHsgeSwgbGFiZWwgfTtcbiAgfSk7XG5cbiAgY29uc3Qgc3RlcCA9IGRhdGEubGVuZ3RoID4gOCA/IE1hdGguY2VpbChkYXRhLmxlbmd0aCAvIDUpIDogMTtcblxuICByZXR1cm4gKFxuICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6ICcxMDAlJywgb3ZlcmZsb3c6ICdoaWRkZW4nIH19PlxuICAgICAgPHN2ZyB3aWR0aD1cIjEwMCVcIiBoZWlnaHQ9e2hlaWdodH0gdmlld0JveD17YDAgMCAke3dpZHRofSAke2hlaWdodH1gfSBwcmVzZXJ2ZUFzcGVjdFJhdGlvPVwibm9uZVwiIHN0eWxlPXt7IGRpc3BsYXk6ICdibG9jaycsIG1heFdpZHRoOiAnMTAwJScgfX0+XG4gICAgICAgIDxkZWZzPlxuICAgICAgICAgIDxsaW5lYXJHcmFkaWVudCBpZD1cImFyZWFGaWxsXCIgeDE9XCIwXCIgeTE9XCIwXCIgeDI9XCIwXCIgeTI9XCIxXCI+XG4gICAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIwJVwiIHN0b3BDb2xvcj17Y29sb3J9IHN0b3BPcGFjaXR5PVwiMC4zNVwiIC8+XG4gICAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIxMDAlXCIgc3RvcENvbG9yPXtjb2xvcn0gc3RvcE9wYWNpdHk9XCIwLjAyXCIgLz5cbiAgICAgICAgICA8L2xpbmVhckdyYWRpZW50PlxuICAgICAgICA8L2RlZnM+XG4gICAgICAgIHsvKiBHcmlkICovfVxuICAgICAgICB7Z3JpZExpbmVzLm1hcCgoZywgaSkgPT4gKFxuICAgICAgICAgIDxnIGtleT17aX0+XG4gICAgICAgICAgICA8bGluZSB4MT17cGFkWH0geTE9e2cueX0geDI9e3dpZHRoIC0gcGFkWH0geTI9e2cueX0gc3Ryb2tlPXtDLmJvcmRlcn0gc3Ryb2tlV2lkdGg9XCIxXCIgc3Ryb2tlRGFzaGFycmF5PVwiMyAzXCIgLz5cbiAgICAgICAgICAgIDx0ZXh0IHg9e3BhZFggLSA2fSB5PXtnLnkgKyA0fSBmaWxsPVwiIzk0YTNiOFwiIGZvbnRTaXplPVwiOVwiIGZvbnRGYW1pbHk9XCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB0ZXh0QW5jaG9yPVwiZW5kXCI+e2cubGFiZWx9PC90ZXh0PlxuICAgICAgICAgIDwvZz5cbiAgICAgICAgKSl9XG4gICAgICAgIHsvKiBBcmVhIGZpbGwgKi99XG4gICAgICAgIDxwYXRoIGQ9e2FyZWFQYXRofSBmaWxsPVwidXJsKCNhcmVhRmlsbClcIiAvPlxuICAgICAgICB7LyogTGluZSAqL31cbiAgICAgICAgPHBhdGggZD17bGluZVBhdGh9IGZpbGw9XCJub25lXCIgc3Ryb2tlPXtjb2xvcn0gc3Ryb2tlV2lkdGg9XCIyLjVcIiBzdHJva2VMaW5lam9pbj1cInJvdW5kXCIgc3Ryb2tlTGluZWNhcD1cInJvdW5kXCIgLz5cbiAgICAgICAgey8qIERvdHMgKyBsYWJlbHMgKi99XG4gICAgICAgIHtwb2ludHMubWFwKChwLCBpKSA9PiB7XG4gICAgICAgICAgY29uc3Qgc2hvd0xhYmVsID0gKGkgPT09IDAgfHwgaSA9PT0gZGF0YS5sZW5ndGggLSAxIHx8IGkgJSBzdGVwID09PSAwKTtcbiAgICAgICAgICByZXR1cm4gKFxuICAgICAgICAgICAgPGcga2V5PXtpfT5cbiAgICAgICAgICAgICAgPGNpcmNsZSBjeD17cC54fSBjeT17cC55fSByPVwiM1wiIGZpbGw9e0MuYmd9IHN0cm9rZT17Y29sb3J9IHN0cm9rZVdpZHRoPVwiMlwiIC8+XG4gICAgICAgICAgICAgIHtzaG93TGFiZWwgJiYgKFxuICAgICAgICAgICAgICAgIDx0ZXh0IHg9e3AueH0geT17cGFkWSArIGNoYXJ0SCArIDE0fSBmaWxsPVwiI2NiZDVlMVwiIGZvbnRTaXplPVwiOVwiIGZvbnRGYW1pbHk9XCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e2RhdGFbaV0ubGFiZWx9PC90ZXh0PlxuICAgICAgICAgICAgICApfVxuICAgICAgICAgICAgPC9nPlxuICAgICAgICAgICk7XG4gICAgICAgIH0pfVxuICAgICAgPC9zdmc+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBEb251dCBDaGFydCDilIDilIDilIAgKi9cbmNvbnN0IERvbnV0Q2hhcnQgPSAoeyBkYXRhLCBzaXplID0gMjAwIH0pID0+IHtcbiAgaWYgKCFkYXRhIHx8IGRhdGEubGVuZ3RoID09PSAwKSByZXR1cm4gbnVsbDtcbiAgY29uc3QgdG90YWwgPSBkYXRhLnJlZHVjZSgocywgZCkgPT4gcyArIGQudmFsdWUsIDApO1xuICBpZiAodG90YWwgPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBjeCA9IHNpemUgLyAyO1xuICBjb25zdCBjeSA9IHNpemUgLyAyO1xuICBjb25zdCBvdXRlclIgPSBzaXplIC8gMiAtIDEwO1xuICBjb25zdCBpbm5lclIgPSBvdXRlclIgKiAwLjY7XG4gIGxldCBjdW1BbmdsZSA9IC1NYXRoLlBJIC8gMjtcblxuICBjb25zdCBzbGljZXMgPSBkYXRhLm1hcCgoZCwgaSkgPT4ge1xuICAgIGNvbnN0IGFuZ2xlID0gKGQudmFsdWUgLyB0b3RhbCkgKiBNYXRoLlBJICogMjtcbiAgICBjb25zdCBzdGFydEFuZ2xlID0gY3VtQW5nbGU7XG4gICAgY3VtQW5nbGUgKz0gYW5nbGU7XG4gICAgY29uc3QgZW5kQW5nbGUgPSBjdW1BbmdsZTtcblxuICAgIGNvbnN0IHgxID0gY3ggKyBvdXRlclIgKiBNYXRoLmNvcyhzdGFydEFuZ2xlKTtcbiAgICBjb25zdCB5MSA9IGN5ICsgb3V0ZXJSICogTWF0aC5zaW4oc3RhcnRBbmdsZSk7XG4gICAgY29uc3QgeDIgPSBjeCArIG91dGVyUiAqIE1hdGguY29zKGVuZEFuZ2xlKTtcbiAgICBjb25zdCB5MiA9IGN5ICsgb3V0ZXJSICogTWF0aC5zaW4oZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl4MSA9IGN4ICsgaW5uZXJSICogTWF0aC5jb3MoZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl5MSA9IGN5ICsgaW5uZXJSICogTWF0aC5zaW4oZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl4MiA9IGN4ICsgaW5uZXJSICogTWF0aC5jb3Moc3RhcnRBbmdsZSk7XG4gICAgY29uc3QgaXkyID0gY3kgKyBpbm5lclIgKiBNYXRoLnNpbihzdGFydEFuZ2xlKTtcbiAgICBjb25zdCBsYXJnZUFyYyA9IGFuZ2xlID4gTWF0aC5QSSA/IDEgOiAwO1xuICAgIGNvbnN0IGNvbG9yID0gUExBVEZPUk1fQ09MT1JTW2kgJSBQTEFURk9STV9DT0xPUlMubGVuZ3RoXTtcblxuICAgIGNvbnN0IHBhdGggPSBgTSR7eDF9LCR7eTF9IEEke291dGVyUn0sJHtvdXRlclJ9IDAgJHtsYXJnZUFyY30gMSAke3gyfSwke3kyfSBMJHtpeDF9LCR7aXkxfSBBJHtpbm5lclJ9LCR7aW5uZXJSfSAwICR7bGFyZ2VBcmN9IDAgJHtpeDJ9LCR7aXkyfSBaYDtcbiAgICByZXR1cm4geyBwYXRoLCBjb2xvciwgbmFtZTogZC5uYW1lLCB2YWx1ZTogZC52YWx1ZSwgcGN0OiBNYXRoLnJvdW5kKChkLnZhbHVlIC8gdG90YWwpICogMTAwKSB9O1xuICB9KTtcblxuICByZXR1cm4gKFxuICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMjRweCcsIGZsZXhXcmFwOiAnd3JhcCcsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgIDxzdmcgd2lkdGg9e3NpemV9IGhlaWdodD17c2l6ZX0gdmlld0JveD17YDAgMCAke3NpemV9ICR7c2l6ZX1gfT5cbiAgICAgICAge3NsaWNlcy5tYXAoKHMsIGkpID0+IChcbiAgICAgICAgICA8cGF0aCBrZXk9e2l9IGQ9e3MucGF0aH0gZmlsbD17cy5jb2xvcn0gc3Ryb2tlPXtDLmJnfSBzdHJva2VXaWR0aD1cIjJcIj5cbiAgICAgICAgICAgIDx0aXRsZT57cy5uYW1lfToge3MudmFsdWV9ICh7cy5wY3R9JSk8L3RpdGxlPlxuICAgICAgICAgIDwvcGF0aD5cbiAgICAgICAgKSl9XG4gICAgICAgIDx0ZXh0IHg9e2N4fSB5PXtjeSAtIDZ9IGZpbGw9e0MudGV4dH0gZm9udFNpemU9XCIyMlwiIGZvbnRXZWlnaHQ9XCJib2xkXCIgdGV4dEFuY2hvcj1cIm1pZGRsZVwiPnt0b3RhbH08L3RleHQ+XG4gICAgICAgIDx0ZXh0IHg9e2N4fSB5PXtjeSArIDE0fSBmaWxsPXtDLnRleHRNdXRlZH0gZm9udFNpemU9XCIxMFwiIHRleHRBbmNob3I9XCJtaWRkbGVcIj5UT1RBTDwvdGV4dD5cbiAgICAgIDwvc3ZnPlxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhEaXJlY3Rpb246ICdjb2x1bW4nLCBnYXA6ICc2cHgnIH19PlxuICAgICAgICB7c2xpY2VzLm1hcCgocywgaSkgPT4gKFxuICAgICAgICAgIDxkaXYga2V5PXtpfSBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnIH19PlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgd2lkdGg6IDEyLCBoZWlnaHQ6IDEyLCBib3JkZXJSYWRpdXM6ICczcHgnLCBiYWNrZ3JvdW5kQ29sb3I6IHMuY29sb3IsIGRpc3BsYXk6ICdpbmxpbmUtYmxvY2snLCBmbGV4U2hyaW5rOiAwIH19IC8+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy50ZXh0IH19PntzLm5hbWV9PC9zcGFuPlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgbWFyZ2luTGVmdDogJ2F1dG8nIH19PntzLnZhbHVlfSAoe3MucGN0fSUpPC9zcGFuPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICApKX1cbiAgICAgIDwvZGl2PlxuICAgIDwvZGl2PlxuICApO1xufTtcblxuLyog4pSA4pSA4pSAIFN0YXQgQ2FyZCDilIDilIDilIAgKi9cbmNvbnN0IFN0YXRDYXJkID0gKHsgaWNvbiwgbGFiZWwsIHZhbHVlLCBkZWx0YSwgZGVsdGFMYWJlbCwgYWNjZW50Q29sb3IgfSkgPT4gKFxuICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZShhY2NlbnRDb2xvciksIGZsZXg6ICcxJywgbWluV2lkdGg6ICcyMjBweCcgfX1cbiAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBhY2NlbnRDb2xvciB8fCBDLmJvcmRlckhvdmVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoLTJweCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gYDAgOHB4IDI0cHggcmdiYSgwLDAsMCwwLjQpYDsgfX1cbiAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckxlZnRDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoMCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJ25vbmUnOyB9fVxuICA+XG4gICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcxNHB4JyB9fT5cbiAgICAgIDxJY29uIGljb249e2ljb259IGNvbG9yPXthY2NlbnRDb2xvcn0gLz5cbiAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMXB4JywgZm9udFdlaWdodDogNzAwLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDhlbScgfX0+e2xhYmVsfTwvVGV4dD5cbiAgICA8L2Rpdj5cbiAgICA8SDIgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAnMCAwIDhweCAwJywgZm9udFNpemU6ICcyLjJyZW0nIH19Pnt2YWx1ZX08L0gyPlxuICAgIHtkZWx0YSAhPT0gdW5kZWZpbmVkICYmIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JyB9fT5cbiAgICAgICAgPEljb24gaWNvbj1cIkFycm93VXBcIiBzaXplPXsxNH0gY29sb3I9e0MuZ3JlZW59IC8+XG4gICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLmdyZWVuLCBmb250U2l6ZTogJzEzcHgnLCBmb250V2VpZ2h0OiA2MDAgfX0+K3tkZWx0YX0ge2RlbHRhTGFiZWwgfHwgJ3RoaXMgbW9udGgnfTwvVGV4dD5cbiAgICAgIDwvZGl2PlxuICAgICl9XG4gIDwvQm94PlxuKTtcblxuLyog4pSA4pSA4pSAIEFjdGlvbiBCYWRnZSBDYXJkIOKUgOKUgOKUgCAqL1xuY29uc3QgQWN0aW9uQ2FyZCA9ICh7IGljb24sIGxhYmVsLCBjb3VudCwgYWNjZW50Q29sb3IsIHJlc291cmNlSWQgfSkgPT4gKFxuICA8YSBocmVmPXtgL2FkbWluL3Jlc291cmNlcy8ke3Jlc291cmNlSWR9YH0gc3R5bGU9e3sgdGV4dERlY29yYXRpb246ICdub25lJywgZmxleDogJzEnLCBtaW5XaWR0aDogJzE4MHB4JyB9fT5cbiAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZShhY2NlbnRDb2xvciksIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzE2cHgnIH19XG4gICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBhY2NlbnRDb2xvcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLnRyYW5zZm9ybSA9ICd0cmFuc2xhdGVZKC0ycHgpJzsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJveFNoYWRvdyA9IGAwIDZweCAyMHB4IHJnYmEoMCwwLDAsMC4zKWA7IH19XG4gICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckxlZnRDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoMCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJ25vbmUnOyB9fVxuICAgID5cbiAgICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6IDQ0LCBoZWlnaHQ6IDQ0LCBib3JkZXJSYWRpdXM6ICcxMnB4JywgYmFja2dyb3VuZENvbG9yOiBgJHthY2NlbnRDb2xvcn0xNWAsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJywgZmxleFNocmluazogMCB9fT5cbiAgICAgICAgPEljb24gaWNvbj17aWNvbn0gc2l6ZT17MjJ9IGNvbG9yPXthY2NlbnRDb2xvcn0gLz5cbiAgICAgIDwvZGl2PlxuICAgICAgPGRpdj5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzExcHgnLCBmb250V2VpZ2h0OiA2MDAsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJyB9fT57bGFiZWx9PC9UZXh0PlxuICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IGNvdW50ID4gMCA/IGFjY2VudENvbG9yIDogQy50ZXh0RGltLCBtYXJnaW46ICc0cHggMCAwIDAnIH19Pntjb3VudH08L0g1PlxuICAgICAgPC9kaXY+XG4gICAgICA8SWNvbiBpY29uPVwiQ2hldnJvblJpZ2h0XCIgY29sb3I9e0MudGV4dERpbX0gc3R5bGU9e3sgbWFyZ2luTGVmdDogJ2F1dG8nIH19IC8+XG4gICAgPC9Cb3g+XG4gIDwvYT5cbik7XG5cbi8qIOKUgOKUgOKUgCBGb3JtYXQgZGF0ZSBuaWNlbHkg4pSA4pSA4pSAICovXG5jb25zdCBmbXREYXRlID0gKGQpID0+IHtcbiAgaWYgKCFkKSByZXR1cm4gJ+KAlCc7XG4gIGNvbnN0IGR0ID0gbmV3IERhdGUoZCk7XG4gIHJldHVybiBkdC50b0xvY2FsZURhdGVTdHJpbmcoJ2VuLVVTJywgeyBtb250aDogJ3Nob3J0JywgZGF5OiAnbnVtZXJpYycsIHllYXI6ICdudW1lcmljJyB9KTtcbn07XG5cbi8qIOKUgOKUgOKUgCBTdGF0dXMgYmFkZ2UgY29sb3Ig4pSA4pSA4pSAICovXG5jb25zdCBzdGF0dXNDb2xvciA9IChzKSA9PiB7XG4gIGlmICghcykgcmV0dXJuIEMudGV4dERpbTtcbiAgY29uc3QgbG93ZXIgPSBzLnRvTG93ZXJDYXNlKCk7XG4gIGlmIChsb3dlciA9PT0gJ2FwcHJvdmVkJyB8fCBsb3dlciA9PT0gJ2FjdGl2ZScpIHJldHVybiBDLmdyZWVuO1xuICBpZiAobG93ZXIgPT09ICdwZW5kaW5nJykgcmV0dXJuIEMub3JhbmdlO1xuICBpZiAobG93ZXIgPT09ICdyZWplY3RlZCcpIHJldHVybiBDLnJlZDtcbiAgcmV0dXJuIEMudGV4dE11dGVkO1xufTtcblxuLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4gICBNQUlOIERBU0hCT0FSRCBDT01QT05FTlRcbiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqL1xuY29uc3QgQ3VzdG9tRGFzaGJvYXJkID0gKCkgPT4ge1xuICBjb25zdCBbZGF0YSwgc2V0RGF0YV0gPSB1c2VTdGF0ZShudWxsKTtcbiAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG4gIGNvbnN0IFtlcnJvciwgc2V0RXJyb3JdID0gdXNlU3RhdGUobnVsbCk7XG5cbiAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICBhcGkuZ2V0RGFzaGJvYXJkKClcbiAgICAgIC50aGVuKChyZXNwb25zZSkgPT4ge1xuICAgICAgICBzZXREYXRhKHJlc3BvbnNlLmRhdGEgfHwge30pO1xuICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goKGZldGNoRXJyb3IpID0+IHtcbiAgICAgICAgY29uc29sZS5lcnJvcignRGFzaGJvYXJkIGZldGNoIGVycm9yOicsIGZldGNoRXJyb3IpO1xuICAgICAgICBzZXRFcnJvcignRmFpbGVkIHRvIGxvYWQgZGFzaGJvYXJkIGRhdGEuJyk7XG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgfSk7XG4gIH0sIFtdKTtcblxuICBpZiAobG9hZGluZykge1xuICAgIHJldHVybiAoXG4gICAgICA8ZGl2IHN0eWxlPXt7IG1pbkhlaWdodDogJzEwMHZoJywgYmFja2dyb3VuZENvbG9yOiBDLmJnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgIDxkaXYgc3R5bGU9e3sgdGV4dEFsaWduOiAnY2VudGVyJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IHdpZHRoOiA0MCwgaGVpZ2h0OiA0MCwgYm9yZGVyOiBgM3B4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgYm9yZGVyVG9wQ29sb3I6IEMuZ29sZCwgYm9yZGVyUmFkaXVzOiAnNTAlJywgYW5pbWF0aW9uOiAnc3BpbiAxcyBsaW5lYXIgaW5maW5pdGUnLCBtYXJnaW46ICcwIGF1dG8gMTZweCcgfX0gLz5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQgfX0+TG9hZGluZyBkYXNoYm9hcmQuLi48L1RleHQ+XG4gICAgICAgICAgPHN0eWxlPntgQGtleWZyYW1lcyBzcGluIHsgdG8geyB0cmFuc2Zvcm06IHJvdGF0ZSgzNjBkZWcpOyB9IH1gfTwvc3R5bGU+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG4gICAgKTtcbiAgfVxuXG4gIGlmIChlcnJvcikge1xuICAgIHJldHVybiAoXG4gICAgICA8ZGl2IHN0eWxlPXt7IG1pbkhlaWdodDogJzEwMHZoJywgYmFja2dyb3VuZENvbG9yOiBDLmJnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKEMucmVkKSwgbWF4V2lkdGg6IDQwMCwgdGV4dEFsaWduOiAnY2VudGVyJyB9fT5cbiAgICAgICAgICA8SWNvbiBpY29uPVwiQWxlcnRUcmlhbmdsZVwiIHNpemU9ezMyfSBjb2xvcj17Qy5yZWR9IC8+XG4gICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnJlZCwgbWFyZ2luOiAnMTZweCAwIDhweCcgfX0+e2Vycm9yfTwvSDU+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkIH19PkNoZWNrIHRoZSBzZXJ2ZXIgbG9ncyBmb3IgZGV0YWlscy48L1RleHQ+XG4gICAgICAgIDwvQm94PlxuICAgICAgPC9kaXY+XG4gICAgKTtcbiAgfVxuXG4gIGNvbnN0IHN0YXRzID0gZGF0YT8uc3RhdHMgfHwge307XG4gIGNvbnN0IGFjdGlvblJlcXVpcmVkID0gZGF0YT8uYWN0aW9uUmVxdWlyZWQgfHwge307XG4gIGNvbnN0IG1vZHNCeVBsYXRmb3JtID0gZGF0YT8ubW9kc0J5UGxhdGZvcm0gfHwgW107XG4gIGNvbnN0IHVzZXJHcm93dGhEYXRhID0gZGF0YT8udXNlckdyb3d0aERhdGEgfHwgW107XG4gIGNvbnN0IHJlY2VudFVzZXJzID0gZGF0YT8ucmVjZW50VXNlcnMgfHwgW107XG4gIGNvbnN0IHJlY2VudE1vZHMgPSBkYXRhPy5yZWNlbnRNb2RzIHx8IFtdO1xuXG4gIC8vIFByZXBhcmUgY2hhcnQgZGF0YVxuICBjb25zdCBncm93dGhDaGFydERhdGEgPSB1c2VyR3Jvd3RoRGF0YS5tYXAoZCA9PiAoeyBsYWJlbDogZC5kYXRlLCB2YWx1ZTogZC51c2VycyB9KSk7XG5cbiAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgY29uc3QgZ3JlZXRpbmcgPSBub3cuZ2V0SG91cnMoKSA8IDEyID8gJ0dvb2QgbW9ybmluZycgOiBub3cuZ2V0SG91cnMoKSA8IDE4ID8gJ0dvb2QgYWZ0ZXJub29uJyA6ICdHb29kIGV2ZW5pbmcnO1xuXG4gIHJldHVybiAoXG4gICAgPGRpdiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIG1pbkhlaWdodDogJzEwMHZoJywgcGFkZGluZzogJ2NsYW1wKDE2cHgsIDN2dywgMzJweCkgY2xhbXAoMTRweCwgM3Z3LCAzNnB4KScsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+XG4gICAgICBcbiAgICAgIHsvKiDilZDilZDilZAgSEVBREVSIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBqdXN0aWZ5Q29udGVudDogJ3NwYWNlLWJldHdlZW4nLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMTZweCcsIHBhZGRpbmdCb3R0b206ICcyNHB4JywgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgbWFyZ2luQm90dG9tOiAnMjhweCcgfX0+XG4gICAgICAgIDxkaXY+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pblwiIHN0eWxlPXt7IHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBjdXJzb3I6ICdwb2ludGVyJyB9fT5cbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMTBweCcgfX0+XG4gICAgICAgICAgICAgIDxIMiBzdHlsZT17eyBtYXJnaW46IDAsIGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlxuICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLmdvbGQsIHRleHRTaGFkb3c6IGAwIDAgMjBweCAke0MuZ29sZEdsb3d9YCwgZm9udFdlaWdodDogODAwIH19PkdQTDwvc3Bhbj5cbiAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCB0ZXh0U2hhZG93OiAnMCAwIDE1cHggcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjQpJywgZm9udFdlaWdodDogNzAwIH19Pk1vZHM8L3NwYW4+XG4gICAgICAgICAgICAgIDwvSDI+XG4gICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZDcwMCcsIGZvbnRTaXplOiAnMTFweCcsIGZvbnRXZWlnaHQ6IDYwMCwgYmFja2dyb3VuZDogJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMTIpJywgcGFkZGluZzogJzRweCAxMHB4JywgYm9yZGVyUmFkaXVzOiAnMjBweCcsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwgMjE1LCAwLCAwLjM1KScsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIsIGxldHRlclNwYWNpbmc6ICcwLjA0ZW0nLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyB9fT5BZG1pbiBEYXNoYm9hcmQ8L3NwYW4+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICA8L2E+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjZjFmNWY5JywgbWFyZ2luVG9wOiAnOHB4JywgZm9udFNpemU6ICcxNHB4JywgZm9udFdlaWdodDogNDAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiLCBsaW5lSGVpZ2h0OiAxLjUgfX0+XG4gICAgICAgICAgICB7Z3JlZXRpbmd9ISBIZXJlJ3MgeW91ciBwbGF0Zm9ybSBvdmVydmlldyBmb3Ige25vdy50b0xvY2FsZURhdGVTdHJpbmcoJ2VuLVVTJywgeyB3ZWVrZGF5OiAnbG9uZycsIG1vbnRoOiAnbG9uZycsIGRheTogJ251bWVyaWMnLCB5ZWFyOiAnbnVtZXJpYycgfSl9LlxuICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgPC9kaXY+XG5cbiAgICAgICAgey8qIOKVkOKVkOKVkCBBRE1JTiBTVUlURSBTSE9SVENVVCBCVVRUT05TIOKVkOKVkOKVkCAqL31cbiAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXhXaWR0aDogJzEwMCUnLCBtYXJnaW5Ub3A6ICc2cHgnIH19PlxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9kYXNoYm9hcmRcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogQy5nb2xkLCBiYWNrZ3JvdW5kQ29sb3I6IEMuZ29sZERpbSwgYm9yZGVyOiBgMXB4IHNvbGlkICR7Qy5nb2xkfWAsIHBhZGRpbmc6ICc3cHggMTJweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxMnB4JywgbGluZUhlaWdodDogMS40LCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiLCBmbGV4U2hyaW5rOiAwIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjU1LDIxNSwwLDAuMjUpJzsgfX1cbiAgICAgICAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSBDLmdvbGREaW07IH19XG4gICAgICAgICAgICB0aXRsZT1cIkdvIEJhY2sgVG8gVXNlciBEYXNoYm9hcmRcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJBcnJvd0xlZnRcIiBzaXplPXsxM30gLz4gRGFzaGJvYXJkXG4gICAgICAgICAgPC9hPlxuXG4gICAgICAgICAgPGEgXG4gICAgICAgICAgICBocmVmPVwiL2FkbWluL3JlcG9ydHNcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyNmZjZiNmInLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDIyOSw1Nyw1MywwLjEyKScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDIyOSw1Nyw1MywwLjMpJywgcGFkZGluZzogJzdweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEycHgnLCBsaW5lSGVpZ2h0OiAxLjQsIHRyYW5zaXRpb246ICdhbGwgMC4ycycsIGZsZXhTaHJpbms6IDAgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyMjksNTcsNTMsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDIyOSw1Nyw1MywwLjEyKSc7IH19XG4gICAgICAgICAgICB0aXRsZT1cIk1vZGVyYXRpb24gJiBNb2QgUmVwb3J0cyBDb25zb2xlXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiRmxhZ1wiIHNpemU9ezEzfSAvPiBSZXBvcnRzXG4gICAgICAgICAgPC9hPlxuXG4gICAgICAgICAgPGEgXG4gICAgICAgICAgICBocmVmPVwiL2FkbWluL3N1cHBvcnRcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyM2NGI1ZjYnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDMzLDE1MCwyNDMsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgzMywxNTAsMjQzLDAuMyknLCBwYWRkaW5nOiAnN3B4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTJweCcsIGxpbmVIZWlnaHQ6IDEuNCwgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJywgZmxleFNocmluazogMCB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDMzLDE1MCwyNDMsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDMzLDE1MCwyNDMsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJMaXZlIFN1cHBvcnQgJiBJbnF1aXJpZXMgQ29uc29sZVwiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkhlbHBDaXJjbGVcIiBzaXplPXsxM30gLz4gU3VwcG9ydFxuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9hZG1pbi9zdGF0dXNcIiBcbiAgICAgICAgICAgIHRhcmdldD1cIl9ibGFua1wiIFxuICAgICAgICAgICAgcmVsPVwibm9vcGVuZXIgbm9yZWZlcnJlclwiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnIzgxYzc4NCcsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoNjcsMTYwLDcxLDAuMTIpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoNjcsMTYwLDcxLDAuMyknLCBwYWRkaW5nOiAnN3B4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTJweCcsIGxpbmVIZWlnaHQ6IDEuNCwgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJywgZmxleFNocmluazogMCB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDY3LDE2MCw3MSwwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoNjcsMTYwLDcxLDAuMTIpJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiTGl2ZSBTZXJ2ZXIgRGlhZ25vc3RpY3MgJiBIZWFsdGhcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJBY3Rpdml0eVwiIHNpemU9ezEzfSAvPiBEaWFnbm9zdGljc1xuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9hZG1pbi9tdXNpY1wiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnI2JhNjhjOCcsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMTg2LDEwNCwyMDAsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgxODYsMTA0LDIwMCwwLjMpJywgcGFkZGluZzogJzdweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEycHgnLCBsaW5lSGVpZ2h0OiAxLjQsIHRyYW5zaXRpb246ICdhbGwgMC4ycycsIGZsZXhTaHJpbms6IDAgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgxODYsMTA0LDIwMCwwLjI1KSc7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMTg2LDEwNCwyMDAsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJNdXNpYyAmIFBsYXlsaXN0IE1hbmFnZXJcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJNdXNpY1wiIHNpemU9ezEzfSAvPiBNdXNpY1xuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9ob21lXCIgXG4gICAgICAgICAgICB0YXJnZXQ9XCJfYmxhbmtcIiBcbiAgICAgICAgICAgIHJlbD1cIm5vb3BlbmVyIG5vcmVmZXJyZXJcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyNmZmZmZmYnLCBiYWNrZ3JvdW5kQ29sb3I6IEMuc3VyZmFjZUFsdCwgYm9yZGVyOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgcGFkZGluZzogJzdweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEycHgnLCBsaW5lSGVpZ2h0OiAxLjQsIHRyYW5zaXRpb246ICdhbGwgMC4ycycsIGZsZXhTaHJpbms6IDAgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9IEMuZ29sZDsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmNvbG9yID0gQy5nb2xkOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckNvbG9yID0gQy5ib3JkZXI7IGUuY3VycmVudFRhcmdldC5zdHlsZS5jb2xvciA9ICcjZmZmZmZmJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiT3BlbiBMaXZlIFB1YmxpYyBTaXRlXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiR2xvYmVcIiBzaXplPXsxM30gLz4gTGl2ZSBTaXRlXG4gICAgICAgICAgPC9hPlxuICAgICAgICA8L2Rpdj5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIFNUQVQgQ0FSRFMg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzE2cHgnLCBtYXJnaW5Cb3R0b206ICcyNHB4JyB9fT5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJVc2Vyc1wiIGxhYmVsPVwiVG90YWwgVXNlcnNcIiB2YWx1ZT17KHN0YXRzLnRvdGFsVXNlcnMgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gZGVsdGE9e3N0YXRzLm5ld1VzZXJzVGhpc01vbnRofSBhY2NlbnRDb2xvcj17Qy5ibHVlfSAvPlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIlBhY2thZ2VcIiBsYWJlbD1cIlRvdGFsIE1vZHNcIiB2YWx1ZT17KHN0YXRzLnRvdGFsTW9kcyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBkZWx0YT17c3RhdHMubmV3TW9kc1RoaXNNb250aH0gYWNjZW50Q29sb3I9e0MuZ29sZH0gLz5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJEb3dubG9hZFwiIGxhYmVsPVwiVG90YWwgRG93bmxvYWRzXCIgdmFsdWU9eyhzdGF0cy50b3RhbERvd25sb2FkcyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBhY2NlbnRDb2xvcj17Qy5ncmVlbn0gLz5cbiAgICAgICAgPFN0YXRDYXJkIGljb249XCJFeWVcIiBsYWJlbD1cIlRvdGFsIFZpZXdzXCIgdmFsdWU9eyhzdGF0cy50b3RhbFZpZXdzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGFjY2VudENvbG9yPXtDLnB1cnBsZX0gLz5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIEFDVElPTiBSRVFVSVJFRCDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMTRweCcsIG1hcmdpbkJvdHRvbTogJzMycHgnIH19PlxuICAgICAgICA8QWN0aW9uQ2FyZCBpY29uPVwiRmxhZ1wiIGxhYmVsPVwiUGVuZGluZyBSZXBvcnRzXCIgY291bnQ9e2FjdGlvblJlcXVpcmVkLnBlbmRpbmdSZXBvcnRzIHx8IDB9IGFjY2VudENvbG9yPXtDLnJlZH0gcmVzb3VyY2VJZD1cIlJlcG9ydFwiIC8+XG4gICAgICAgIDxBY3Rpb25DYXJkIGljb249XCJDaGVja1NxdWFyZVwiIGxhYmVsPVwiUGVuZGluZyBBcHByb3ZhbHNcIiBjb3VudD17YWN0aW9uUmVxdWlyZWQucGVuZGluZ0FwcHJvdmFscyB8fCAwfSBhY2NlbnRDb2xvcj17Qy5vcmFuZ2V9IHJlc291cmNlSWQ9XCJGaWxlXCIgLz5cbiAgICAgICAgPEFjdGlvbkNhcmQgaWNvbj1cIkhlbHBDaXJjbGVcIiBsYWJlbD1cIk9wZW4gVGlja2V0c1wiIGNvdW50PXthY3Rpb25SZXF1aXJlZC5vcGVuVGlja2V0cyB8fCAwfSBhY2NlbnRDb2xvcj17Qy5ibHVlfSByZXNvdXJjZUlkPVwiU3VwcG9ydFRpY2tldFwiIC8+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBDSEFSVFMgUk9XIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcyMHB4JywgbWFyZ2luQm90dG9tOiAnMzJweCcgfX0+XG4gICAgICAgIHsvKiBVc2VyIEdyb3d0aCBDaGFydCAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzIgMSAzMjBweCcsIG1pbldpZHRoOiAwLCB3aWR0aDogJzEwMCUnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMThweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiQWN0aXZpdHlcIiBjb2xvcj17Qy5nb2xkfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5Vc2VyIEdyb3d0aDwvSDU+XG4gICAgICAgICAgICA8QmFkZ2Ugc3R5bGU9e3sgbWFyZ2luTGVmdDogJzhweCcsIGJhY2tncm91bmRDb2xvcjogQy5nb2xkRGltLCBjb2xvcjogQy5nb2xkLCBib3JkZXI6ICdub25lJywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT4zMCBkYXlzPC9CYWRnZT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7Z3Jvd3RoQ2hhcnREYXRhLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8QXJlYUNoYXJ0IGRhdGE9e2dyb3d0aENoYXJ0RGF0YX0gY29sb3I9e0MuZ29sZH0gd2lkdGg9ezUwMH0gaGVpZ2h0PXsxNzB9IC8+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgaGVpZ2h0OiAxNjAsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5ObyB1c2VyIHNpZ251cHMgaW4gdGhlIGxhc3QgMzAgZGF5cy48L1RleHQ+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cblxuICAgICAgICB7LyogUGxhdGZvcm0gRG9udXQgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcxIDEgMjgwcHgnLCBtaW5XaWR0aDogMCwgd2lkdGg6ICcxMDAlJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE4cHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIlBpZUNoYXJ0XCIgY29sb3I9e0MuYmx1ZX0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+TW9kcyBieSBQbGF0Zm9ybTwvSDU+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICAge21vZHNCeVBsYXRmb3JtLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8RG9udXRDaGFydCBkYXRhPXttb2RzQnlQbGF0Zm9ybX0gc2l6ZT17MTgwfSAvPlxuICAgICAgICAgICkgOiAoXG4gICAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGhlaWdodDogMTYwLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0sIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+Tm8gcGxhdGZvcm0gZGF0YSBhdmFpbGFibGUuPC9UZXh0PlxuICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBSRUNFTlQgQUNUSVZJVFkgUk9XIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcyMHB4JywgbWFyZ2luQm90dG9tOiAnMzJweCcgfX0+XG4gICAgICAgIHsvKiBSZWNlbnQgVXNlcnMgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcxIDEgMzIwcHgnLCBtaW5XaWR0aDogMCwgd2lkdGg6ICcxMDAlJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE4cHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIlVzZXJzXCIgY29sb3I9e0MuYmx1ZX0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+UmVjZW50IFVzZXJzPC9INT5cbiAgICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL1VzZXJcIiBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnYXV0bycsIGNvbG9yOiBDLmdvbGQsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5WaWV3IEFsbCDihpI8L2E+XG4gICAgICAgICAgPC9kaXY+XG4gICAgICAgICAge3JlY2VudFVzZXJzLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8ZGl2IHN0eWxlPXt7IG92ZXJmbG93WDogJ2F1dG8nLCB3aWR0aDogJzEwMCUnLCBXZWJraXRPdmVyZmxvd1Njcm9sbGluZzogJ3RvdWNoJyB9fT5cbiAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPXt7IHdpZHRoOiAnMTAwJScsIGJvcmRlckNvbGxhcHNlOiAnY29sbGFwc2UnLCBtaW5XaWR0aDogJzMwMHB4JyB9fT5cbiAgICAgICAgICAgICAgICA8dGhlYWQ+XG4gICAgICAgICAgICAgICAgICA8dHIgc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5Vc2VybmFtZTwvdGg+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+Um9sZTwvdGg+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdyaWdodCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PkpvaW5lZDwvdGg+XG4gICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgIDwvdGhlYWQ+XG4gICAgICAgICAgICAgICAgPHRib2R5PlxuICAgICAgICAgICAgICAgICAge3JlY2VudFVzZXJzLm1hcCgodSwgaSkgPT4gKFxuICAgICAgICAgICAgICAgICAgICA8dHIga2V5PXtpfSBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dCwgZm9udFNpemU6ICcxM3B4JywgZm9udFdlaWdodDogNTAwIH19Pnt1LnVzZXJuYW1lfTwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICcxMXB4JywgcGFkZGluZzogJzNweCA4cHgnLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IHUucm9sZSA9PT0gJ2FkbWluJyA/IGAke0MuZ29sZH0yMGAgOiBgJHtDLmJsdWV9MjBgLCBjb2xvcjogdS5yb2xlID09PSAnYWRtaW4nID8gQy5nb2xkIDogQy5ibHVlLCBmb250V2VpZ2h0OiA2MDAgfX0+e3Uucm9sZSB8fCAndXNlcid9PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnLCBjb2xvcjogQy50ZXh0TXV0ZWQsIGZvbnRTaXplOiAnMTJweCcsIHRleHRBbGlnbjogJ3JpZ2h0JyB9fT57Zm10RGF0ZSh1LmRhdGUpfTwvdGQ+XG4gICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICApKX1cbiAgICAgICAgICAgICAgICA8L3Rib2R5PlxuICAgICAgICAgICAgICA8L3RhYmxlPlxuICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHREaW0sIHRleHRBbGlnbjogJ2NlbnRlcicsIHBhZGRpbmc6ICcyMHB4IDAnIH19Pk5vIHJlY2VudCB1c2Vycy48L1RleHQ+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgey8qIFJlY2VudCBNb2RzICovfVxuICAgICAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZSgpLCBmbGV4OiAnMSAxIDMyMHB4JywgbWluV2lkdGg6IDAsIHdpZHRoOiAnMTAwJScgfX0+XG4gICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcxOHB4JyB9fT5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJQYWNrYWdlXCIgY29sb3I9e0MuZ29sZH0gLz5cbiAgICAgICAgICAgIDxINSBzdHlsZT17eyBjb2xvcjogQy50ZXh0LCBtYXJnaW46IDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+UmVjZW50IE1vZHM8L0g1PlxuICAgICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvRmlsZVwiIHN0eWxlPXt7IG1hcmdpbkxlZnQ6ICdhdXRvJywgY29sb3I6IEMuZ29sZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlZpZXcgQWxsIOKGkjwvYT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7cmVjZW50TW9kcy5sZW5ndGggPiAwID8gKFxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBvdmVyZmxvd1g6ICdhdXRvJywgd2lkdGg6ICcxMDAlJywgV2Via2l0T3ZlcmZsb3dTY3JvbGxpbmc6ICd0b3VjaCcgfX0+XG4gICAgICAgICAgICAgIDx0YWJsZSBzdHlsZT17eyB3aWR0aDogJzEwMCUnLCBib3JkZXJDb2xsYXBzZTogJ2NvbGxhcHNlJywgbWluV2lkdGg6ICczMDBweCcgfX0+XG4gICAgICAgICAgICAgICAgPHRoZWFkPlxuICAgICAgICAgICAgICAgICAgPHRyIHN0eWxlPXt7IGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+TmFtZTwvdGg+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+UGxhdGZvcm08L3RoPlxuICAgICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PlN0YXR1czwvdGg+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdyaWdodCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PkFkZGVkPC90aD5cbiAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgPC90aGVhZD5cbiAgICAgICAgICAgICAgICA8dGJvZHk+XG4gICAgICAgICAgICAgICAgICB7cmVjZW50TW9kcy5tYXAoKG0sIGkpID0+IChcbiAgICAgICAgICAgICAgICAgICAgPHRyIGtleT17aX0gc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHQsIGZvbnRTaXplOiAnMTNweCcsIGZvbnRXZWlnaHQ6IDUwMCwgbWF4V2lkdGg6ICcxODBweCcsIG92ZXJmbG93OiAnaGlkZGVuJywgdGV4dE92ZXJmbG93OiAnZWxsaXBzaXMnLCB3aGl0ZVNwYWNlOiAnbm93cmFwJyB9fT57bS5uYW1lfTwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICcxMXB4JywgcGFkZGluZzogJzNweCA4cHgnLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IGAke0MuYmx1ZX0yMGAsIGNvbG9yOiBDLmJsdWUsIGZvbnRXZWlnaHQ6IDYwMCwgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScgfX0+e20uY2F0ZWdvcnkgfHwgJ+KAlCd9PC9zcGFuPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICcxMXB4JywgcGFkZGluZzogJzNweCA4cHgnLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBiYWNrZ3JvdW5kQ29sb3I6IGAke3N0YXR1c0NvbG9yKG0uc3RhdHVzKX0yMGAsIGNvbG9yOiBzdGF0dXNDb2xvcihtLnN0YXR1cyksIGZvbnRXZWlnaHQ6IDYwMCwgdGV4dFRyYW5zZm9ybTogJ2NhcGl0YWxpemUnIH19PnttLnN0YXR1cyB8fCAn4oCUJ308L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dEFsaWduOiAncmlnaHQnIH19PntmbXREYXRlKG0uZGF0ZSl9PC90ZD5cbiAgICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICAgICkpfVxuICAgICAgICAgICAgICAgIDwvdGJvZHk+XG4gICAgICAgICAgICAgIDwvdGFibGU+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgdGV4dEFsaWduOiAnY2VudGVyJywgcGFkZGluZzogJzIwcHggMCcgfX0+Tm8gcmVjZW50IG1vZHMuPC9UZXh0PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvQm94PlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgRk9PVEVSIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBqdXN0aWZ5Q29udGVudDogJ3NwYWNlLWJldHdlZW4nLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMTRweCcsIHBhZGRpbmdUb3A6ICcyMHB4JywgYm9yZGVyVG9wOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgPGEgaHJlZj1cIi9hZG1pblwiIHN0eWxlPXt7IHRleHREZWNvcmF0aW9uOiAnbm9uZScgfX0+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgZm9udFNpemU6ICcxM3B4JywgY3Vyc29yOiAncG9pbnRlcicsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy5nb2xkLCBmb250V2VpZ2h0OiA3MDAgfX0+R1BMPC9zcGFuPiA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBmb250V2VpZ2h0OiA2MDAgfX0+TW9kczwvc3Bhbj4g4oCiIEFkbWluIFBhbmVsIHYyLjVcbiAgICAgICAgICA8L1RleHQ+XG4gICAgICAgIDwvYT5cbiAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzhweCcgfX0+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvVXNlclwiIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC4wNiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpJywgcGFkZGluZzogJzVweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNTAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlVzZXJzPC9hPlxuICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL0ZpbGVcIiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuMDYpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4xKScsIHBhZGRpbmc6ICc1cHggMTJweCcsIGJvcmRlclJhZGl1czogJzhweCcsIGZvbnRTaXplOiAnMTJweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDUwMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5Nb2RzPC9hPlxuICAgICAgICAgIDxhIGhyZWY9XCIvYWRtaW4vcmVzb3VyY2VzL1JlcG9ydFwiIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC4wNiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpJywgcGFkZGluZzogJzVweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNTAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlJlcG9ydHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvU3VwcG9ydFRpY2tldFwiIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC4wNiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpJywgcGFkZGluZzogJzVweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNTAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlRpY2tldHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9tdXNpY1wiIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC4wNiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpJywgcGFkZGluZzogJzVweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNTAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19Pk11c2ljPC9hPlxuICAgICAgICA8L2Rpdj5cbiAgICAgIDwvZGl2PlxuICAgIDwvZGl2PlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgQ3VzdG9tRGFzaGJvYXJkO1xuIiwiaW1wb3J0IFJlYWN0IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCwgSWNvbiB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuXG5jb25zdCBTaWRlYmFyQnJhbmRpbmcgPSAoKSA9PiB7XG4gIHJldHVybiAoXG4gICAgPEJveCBcbiAgICAgIGZsZXggXG4gICAgICBmbGV4RGlyZWN0aW9uPVwiY29sdW1uXCJcbiAgICAgIGFsaWduSXRlbXM9XCJjZW50ZXJcIiBcbiAgICAgIGp1c3RpZnlDb250ZW50PVwiY2VudGVyXCIgXG4gICAgICBwPVwibGdcIiBcbiAgICAgIHN0eWxlPXt7IFxuICAgICAgICBib3JkZXJCb3R0b206ICcxcHggc29saWQgIzJhMmEyYScsIFxuICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICcjMGEwYTBhJywgXG4gICAgICAgIHBhZGRpbmc6ICcyMHB4IDE2cHgnLFxuICAgICAgICBwb3NpdGlvbjogJ3JlbGF0aXZlJyxcbiAgICAgICAgb3ZlcmZsb3c6ICdoaWRkZW4nXG4gICAgICB9fVxuICAgID5cbiAgICAgIHsvKiBTdWJ0bGUgZ29sZCBnbG93IHVuZGVybGluZSAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3tcbiAgICAgICAgcG9zaXRpb246ICdhYnNvbHV0ZScsXG4gICAgICAgIGJvdHRvbTogMCxcbiAgICAgICAgbGVmdDogJzUwJScsXG4gICAgICAgIHRyYW5zZm9ybTogJ3RyYW5zbGF0ZVgoLTUwJSknLFxuICAgICAgICB3aWR0aDogJzYwJScsXG4gICAgICAgIGhlaWdodDogJzFweCcsXG4gICAgICAgIGJhY2tncm91bmQ6ICdsaW5lYXItZ3JhZGllbnQoOTBkZWcsIHRyYW5zcGFyZW50LCByZ2JhKDI1NSwyMTUsMCwwLjUpLCB0cmFuc3BhcmVudCknXG4gICAgICB9fSAvPlxuXG4gICAgICB7LyogTWFpbiBMb2dvICYgVGl0bGUgTGluayAqL31cbiAgICAgIDxhIFxuICAgICAgICBocmVmPVwiL2FkbWluXCIgXG4gICAgICAgIHN0eWxlPXt7IFxuICAgICAgICAgIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIFxuICAgICAgICAgIGRpc3BsYXk6ICdmbGV4JywgXG4gICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcicsIFxuICAgICAgICAgIGdhcDogJzEwcHgnLFxuICAgICAgICAgIGN1cnNvcjogJ3BvaW50ZXInLFxuICAgICAgICAgIHRyYW5zaXRpb246ICdvcGFjaXR5IDAuMnMgZWFzZSdcbiAgICAgICAgfX1cbiAgICAgICAgb25Nb3VzZUVudGVyPXsoZSkgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUub3BhY2l0eSA9ICcwLjg1JzsgfX1cbiAgICAgICAgb25Nb3VzZUxlYXZlPXsoZSkgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUub3BhY2l0eSA9ICcxJzsgfX1cbiAgICAgID5cbiAgICAgICAgPGltZyBcbiAgICAgICAgICBzcmM9XCIvaW1hZ2VzL3RlYW0tbG9nby5wbmdcIiBcbiAgICAgICAgICBhbHQ9XCJMb2dvXCIgXG4gICAgICAgICAgc3R5bGU9e3sgaGVpZ2h0OiAnMzJweCcsIHdpZHRoOiAnMzJweCcsIG9iamVjdEZpdDogJ2NvdmVyJywgYm9yZGVyUmFkaXVzOiAnNnB4JywgZmlsdGVyOiAnZHJvcC1zaGFkb3coMCAwIDZweCByZ2JhKDI1NSwyMTUsMCwwLjMpKScgfX0gXG4gICAgICAgICAgb25FcnJvcj17KGUpID0+IGUudGFyZ2V0LnN0eWxlLmRpc3BsYXkgPSAnbm9uZSd9XG4gICAgICAgIC8+XG4gICAgICAgIDxkaXYgc3R5bGU9e3sgZm9udFNpemU6ICcyMnB4JywgZm9udFdlaWdodDogJ2JvbGQnLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdiYXNlbGluZScsIGdhcDogJzRweCcgfX0+XG4gICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjRkZENzAwJywgdGV4dFNoYWRvdzogJzAgMCAxMnB4IHJnYmEoMjU1LCAyMTUsIDAsIDAuNCknIH19PkdQTDwvc3Bhbj5cbiAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNjMGMwYzAnLCB0ZXh0U2hhZG93OiAnMCAwIDEycHggcmdiYSgxOTIsIDE5MiwgMTkyLCAwLjUpJyB9fT5Nb2RzPC9zcGFuPlxuICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnOXB4JywgY29sb3I6ICcjNTU1JywgZm9udFdlaWdodDogNjAwLCBtYXJnaW5MZWZ0OiAnNnB4JywgbGV0dGVyU3BhY2luZzogJzAuMDVlbScgfX0+djIuNTwvc3Bhbj5cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L2E+XG5cbiAgICAgIHsvKiBRdWljayBEYXNoYm9hcmQgU2hvcnRjdXQgQnV0dG9uICovfVxuICAgICAgPGEgXG4gICAgICAgIGhyZWY9XCIvYWRtaW5cIiBcbiAgICAgICAgc3R5bGU9e3tcbiAgICAgICAgICBkaXNwbGF5OiAnZmxleCcsXG4gICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcicsXG4gICAgICAgICAganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLFxuICAgICAgICAgIGdhcDogJzhweCcsXG4gICAgICAgICAgbWFyZ2luVG9wOiAnMTJweCcsXG4gICAgICAgICAgcGFkZGluZzogJzZweCAxNnB4JyxcbiAgICAgICAgICB3aWR0aDogJzg1JScsXG4gICAgICAgICAgYm9yZGVyUmFkaXVzOiAnOHB4JyxcbiAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwgMjE1LCAwLCAwLjA4KScsXG4gICAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjU1LCAyMTUsIDAsIDAuMjUpJyxcbiAgICAgICAgICBjb2xvcjogJyNGRkQ3MDAnLFxuICAgICAgICAgIHRleHREZWNvcmF0aW9uOiAnbm9uZScsXG4gICAgICAgICAgZm9udFNpemU6ICcxMnB4JyxcbiAgICAgICAgICBmb250V2VpZ2h0OiA3MDAsXG4gICAgICAgICAgbGV0dGVyU3BhY2luZzogJzAuMDRlbScsXG4gICAgICAgICAgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsXG4gICAgICAgICAgdHJhbnNpdGlvbjogJ2FsbCAwLjJzIGVhc2UnLFxuICAgICAgICAgIGN1cnNvcjogJ3BvaW50ZXInXG4gICAgICAgIH19XG4gICAgICAgIG9uTW91c2VFbnRlcj17KGUpID0+IHsgXG4gICAgICAgICAgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDI1NSwgMjE1LCAwLCAwLjIpJzsgXG4gICAgICAgICAgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJveFNoYWRvdyA9ICcwIDAgMTRweCByZ2JhKDI1NSwyMTUsMCwwLjMpJzsgXG4gICAgICAgIH19XG4gICAgICAgIG9uTW91c2VMZWF2ZT17KGUpID0+IHsgXG4gICAgICAgICAgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDI1NSwgMjE1LCAwLCAwLjA4KSc7IFxuICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3hTaGFkb3cgPSAnbm9uZSc7IFxuICAgICAgICB9fVxuICAgICAgPlxuICAgICAgICA8SWNvbiBpY29uPVwiSG9tZVwiIHNpemU9ezEzfSBjb2xvcj1cIiNGRkQ3MDBcIiAvPlxuICAgICAgICA8c3Bhbj5EYXNoYm9hcmQ8L3NwYW4+XG4gICAgICA8L2E+XG4gICAgPC9Cb3g+XG4gICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBTaWRlYmFyQnJhbmRpbmc7XG4iLCJpbXBvcnQgUmVhY3QsIHsgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94LCBUZXh0LCBMb2FkZXIsIEJ1dHRvbiwgSWNvbiB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuaW1wb3J0IHsgdXNlTm90aWNlIH0gZnJvbSAnYWRtaW5qcyc7XG5cbmNvbnN0IEFjdGlvblJlZGlyZWN0ID0gKHByb3BzKSA9PiB7XG4gICAgY29uc3QgeyByZWNvcmQsIGFjdGlvbiB9ID0gcHJvcHM7XG4gICAgY29uc3Qgc2VuZE5vdGljZSA9IHVzZU5vdGljZSgpO1xuICAgIGxldCB1cmwgPSByZWNvcmQ/LnBhcmFtcz8ucmVkaXJlY3RVcmw7XG5cbiAgICBpZiAoIXVybCAmJiByZWNvcmQgJiYgcmVjb3JkLnBhcmFtcykge1xuICAgICAgICBjb25zdCBhY3Rpb25OYW1lID0gYWN0aW9uPy5uYW1lO1xuICAgICAgICBjb25zdCByZWNJZCA9IHJlY29yZC5wYXJhbXMuX2lkIHx8IHJlY29yZC5pZDtcbiAgICAgICAgY29uc3QgaXNWYXIgPSByZWNvcmQucGFyYW1zLmlzVmFyaWFudCA9PT0gdHJ1ZSB8fCByZWNvcmQucGFyYW1zLmlzVmFyaWFudCA9PT0gJ3RydWUnO1xuICAgICAgICBjb25zdCBtYXN0ZXJJZCA9IHJlY29yZC5wYXJhbXMubWFzdGVyRmlsZTtcblxuICAgICAgICBpZiAoYWN0aW9uTmFtZSA9PT0gJ3ZpZXdWYXJpYW50cycgfHwgKCFhY3Rpb25OYW1lICYmIChpc1ZhciB8fCBtYXN0ZXJJZCkpKSB7XG4gICAgICAgICAgICBpZiAoaXNWYXIgJiYgbWFzdGVySWQpIHtcbiAgICAgICAgICAgICAgICB1cmwgPSBgL2FkbWluL3Jlc291cmNlcy9GaWxlL3JlY29yZHMvJHttYXN0ZXJJZH0vc2hvd2A7XG4gICAgICAgICAgICB9IGVsc2UgaWYgKHJlY0lkKSB7XG4gICAgICAgICAgICAgICAgdXJsID0gYC9hZG1pbi9yZXNvdXJjZXMvRmlsZT9maWx0ZXJzLm1hc3RlckZpbGU9JHtyZWNJZH1gO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGVsc2UgaWYgKGFjdGlvbk5hbWUgPT09ICd2aWV3T25TaXRlJyAmJiByZWNJZCkge1xuICAgICAgICAgICAgdXJsID0gYC9tb2RzLyR7cmVjSWR9YDtcbiAgICAgICAgfSBlbHNlIGlmIChhY3Rpb25OYW1lID09PSAndmlld1ZpcnVzVG90YWwnKSB7XG4gICAgICAgICAgICBjb25zdCB2dEhhc2ggPSByZWNvcmQucGFyYW1zLnZpcnVzVG90YWxJZCB8fCAnJztcbiAgICAgICAgICAgIGNvbnN0IHZ0QW5hbHlzaXMgPSByZWNvcmQucGFyYW1zLnZpcnVzVG90YWxBbmFseXNpc0lkIHx8ICcnO1xuICAgICAgICAgICAgaWYgKHZ0SGFzaC5sZW5ndGggPT09IDY0KSB1cmwgPSBgaHR0cHM6Ly93d3cudmlydXN0b3RhbC5jb20vZ3VpL2ZpbGUvJHt2dEhhc2h9YDtcbiAgICAgICAgICAgIGVsc2UgaWYgKHZ0QW5hbHlzaXMpIHVybCA9IGBodHRwczovL3d3dy52aXJ1c3RvdGFsLmNvbS9ndWkvZmlsZS1hbmFseXNpcy8ke3Z0QW5hbHlzaXN9YDtcbiAgICAgICAgICAgIGVsc2UgaWYgKHZ0SGFzaCkgdXJsID0gYGh0dHBzOi8vd3d3LnZpcnVzdG90YWwuY29tL2d1aS9maWxlLWFuYWx5c2lzLyR7dnRIYXNofWA7XG4gICAgICAgICAgICBlbHNlIHVybCA9IGBodHRwczovL3d3dy52aXJ1c3RvdGFsLmNvbS9gO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICAgICAgaWYgKCF1cmwpIHtcbiAgICAgICAgICAgIHNlbmROb3RpY2UoeyBtZXNzYWdlOiAnRXJyb3I6IE5vIHJlZGlyZWN0IFVSTCBwcm92aWRlZC4nLCB0eXBlOiAnZXJyb3InIH0pO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gSW50ZXJuYWwgYWRtaW4gbmF2aWdhdGlvbjogUmVkaXJlY3QgaW4gdGhlIFNBTUUgdGFiIHNvIHVzZXIgaXMgbm90IHN0dWNrIG9uIHNwaW5uZXJcbiAgICAgICAgaWYgKHVybC5zdGFydHNXaXRoKCcvYWRtaW4nKSkge1xuICAgICAgICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSB1cmw7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAvLyBFeHRlcm5hbCBvciBmcm9udGVuZCByb3V0ZTogb3BlbiBpbiBuZXcgdGFiLCBhbmQgcmVzdG9yZSBwcmV2aW91cyBoaXN0b3J5IGluIGFkbWluIHRhYlxuICAgICAgICAgICAgd2luZG93Lm9wZW4odXJsLCAnX2JsYW5rJyk7XG4gICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgICAgICAgICBpZiAod2luZG93Lmhpc3RvcnkubGVuZ3RoID4gMSkge1xuICAgICAgICAgICAgICAgICAgICB3aW5kb3cuaGlzdG9yeS5iYWNrKCk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIGlmIChyZWNvcmQ/LnBhcmFtcz8uX2lkKSB7XG4gICAgICAgICAgICAgICAgICAgIHdpbmRvdy5sb2NhdGlvbi5ocmVmID0gYC9hZG1pbi9yZXNvdXJjZXMvRmlsZS9yZWNvcmRzLyR7cmVjb3JkLnBhcmFtcy5faWR9L3Nob3dgO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0sIDYwMCk7XG4gICAgICAgIH1cbiAgICB9LCBbcmVjb3JkLCB1cmxdKTtcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3ggZmxleCBmbGV4RGlyZWN0aW9uPVwiY29sdW1uXCIgYWxpZ25JdGVtcz1cImNlbnRlclwiIGp1c3RpZnlDb250ZW50PVwiY2VudGVyXCIgcD1cInh4bFwiPlxuICAgICAgICAgICAgPExvYWRlciAvPlxuICAgICAgICAgICAgPFRleHQgbXQ9XCJsZ1wiIHZhcmlhbnQ9XCJoNFwiPlJlZGlyZWN0aW5nLi4uPC9UZXh0PlxuICAgICAgICAgICAge3VybCAmJiAoXG4gICAgICAgICAgICAgICAgPEJveCBtdD1cIm1kXCI+XG4gICAgICAgICAgICAgICAgICAgIDxCdXR0b25cbiAgICAgICAgICAgICAgICAgICAgICAgIHNpemU9XCJzbVwiXG4gICAgICAgICAgICAgICAgICAgICAgICB2YXJpYW50PVwicHJpbWFyeVwiXG4gICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiB7IHdpbmRvdy5sb2NhdGlvbi5ocmVmID0gdXJsOyB9fVxuICAgICAgICAgICAgICAgICAgICAgICAgc3R5bGU9e3sgY3Vyc29yOiAncG9pbnRlcicgfX1cbiAgICAgICAgICAgICAgICAgICAgPlxuICAgICAgICAgICAgICAgICAgICAgICAgPEljb24gaWNvbj1cIkV4dGVybmFsTGlua1wiIHN0eWxlPXt7IG1hcmdpblJpZ2h0OiAnNnB4JyB9fSAvPlxuICAgICAgICAgICAgICAgICAgICAgICAgQ2xpY2sgaGVyZSBpZiBub3QgcmVkaXJlY3RlZCBhdXRvbWF0aWNhbGx5XG4gICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxuICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG4gICAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEFjdGlvblJlZGlyZWN0O1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlIH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94LCBUZXh0LCBCdXR0b24sIEljb24sIEJhZGdlIH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5pbXBvcnQgeyB1c2VOb3RpY2UgfSBmcm9tICdhZG1pbmpzJztcblxuY29uc3QgRG93bmxvYWRJbnNwZWN0b3IgPSAocHJvcHMpID0+IHtcbiAgICBjb25zdCB7IHJlY29yZCB9ID0gcHJvcHM7XG4gICAgY29uc3Qgc2VuZE5vdGljZSA9IHVzZU5vdGljZSgpO1xuICAgIGNvbnN0IFtjb3BpZWQsIHNldENvcGllZF0gPSB1c2VTdGF0ZShmYWxzZSk7XG4gICAgY29uc3QgW3ZlcmlmeWluZywgc2V0VmVyaWZ5aW5nXSA9IHVzZVN0YXRlKGZhbHNlKTtcbiAgICBjb25zdCBbdmVyaWZpY2F0aW9uUmVzdWx0LCBzZXRWZXJpZmljYXRpb25SZXN1bHRdID0gdXNlU3RhdGUobnVsbCk7XG4gICAgY29uc3QgW3Nob3dEb3dubG9hZENvbmZpcm0sIHNldFNob3dEb3dubG9hZENvbmZpcm1dID0gdXNlU3RhdGUoZmFsc2UpO1xuXG4gICAgaWYgKCFyZWNvcmQgfHwgIXJlY29yZC5wYXJhbXMpIHtcbiAgICAgICAgcmV0dXJuIChcbiAgICAgICAgICAgIDxCb3ggcD1cInhsXCIgdGV4dEFsaWduPVwiY2VudGVyXCI+XG4gICAgICAgICAgICAgICAgPFRleHQgdmFyaWFudD1cImg0XCI+Tm8gcmVjb3JkIGRhdGEgZm91bmQuPC9UZXh0PlxuICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICk7XG4gICAgfVxuXG4gICAgY29uc3QgZmlsZUlkID0gcmVjb3JkLnBhcmFtcy5faWQgfHwgcmVjb3JkLmlkO1xuICAgIGNvbnN0IGZpbGVOYW1lID0gcmVjb3JkLnBhcmFtcy5uYW1lIHx8ICdNb2QgRmlsZSc7XG4gICAgY29uc3QgZmlsZVZlcnNpb24gPSByZWNvcmQucGFyYW1zLnZlcnNpb24gfHwgJzEuMCc7XG4gICAgY29uc3QgZmlsZVNpemUgPSByZWNvcmQucGFyYW1zLmZpbGVTaXplIHx8ICdOL0EnO1xuICAgIGNvbnN0IGV4dGVybmFsVXJsID0gcmVjb3JkLnBhcmFtcy5leHRlcm5hbERvd25sb2FkVXJsIHx8ICcnO1xuICAgIGNvbnN0IGZpbGVLZXkgPSByZWNvcmQucGFyYW1zLmZpbGVLZXkgfHwgJyc7XG4gICAgY29uc3QgZGlyZWN0VXJsID0gcmVjb3JkLnBhcmFtcy5kaXJlY3REb3dubG9hZFVybCB8fCAnJztcbiAgICBjb25zdCBpc011bHRpUGFydCA9IHJlY29yZC5wYXJhbXMuaXNNdWx0aVBhcnQgPT09IHRydWUgfHwgcmVjb3JkLnBhcmFtcy5pc011bHRpUGFydCA9PT0gJ3RydWUnO1xuXG4gICAgLy8gVGhlIHByaW1hcnkgdmFsaWQgZG93bmxvYWQgZW5kcG9pbnQgZ2VuZXJhdGVkIGJ5IHRoZSBzZXJ2ZXJcbiAgICBjb25zdCBwcmltYXJ5RG93bmxvYWRVcmwgPSBgJHt3aW5kb3cubG9jYXRpb24ub3JpZ2lufS9kb3dubG9hZC1maWxlLyR7ZmlsZUlkfWA7XG5cbiAgICBjb25zdCBoYW5kbGVDb3B5ID0gKHVybFRvQ29weSkgPT4ge1xuICAgICAgICBpZiAoIXVybFRvQ29weSkgcmV0dXJuO1xuICAgICAgICBuYXZpZ2F0b3IuY2xpcGJvYXJkLndyaXRlVGV4dCh1cmxUb0NvcHkpLnRoZW4oKCkgPT4ge1xuICAgICAgICAgICAgc2V0Q29waWVkKHRydWUpO1xuICAgICAgICAgICAgc2VuZE5vdGljZSh7IG1lc3NhZ2U6ICdEb3dubG9hZCBVUkwgY29waWVkIHRvIGNsaXBib2FyZCEnLCB0eXBlOiAnc3VjY2VzcycgfSk7XG4gICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldENvcGllZChmYWxzZSksIDMwMDApO1xuICAgICAgICB9KS5jYXRjaCgoKSA9PiB7XG4gICAgICAgICAgICBzZW5kTm90aWNlKHsgbWVzc2FnZTogJ0ZhaWxlZCB0byBjb3B5IFVSTCB0byBjbGlwYm9hcmQuJywgdHlwZTogJ2Vycm9yJyB9KTtcbiAgICAgICAgfSk7XG4gICAgfTtcblxuICAgIC8vIFNhZmVseSB0ZXN0L3ZlcmlmeSB0aGUgZG93bmxvYWQgZW5kcG9pbnQgd2l0aG91dCB0cmlnZ2VyaW5nIGJyb3dzZXIgZmlsZSBkb3dubG9hZFxuICAgIGNvbnN0IGhhbmRsZVZlcmlmeUVuZHBvaW50ID0gYXN5bmMgKCkgPT4ge1xuICAgICAgICBzZXRWZXJpZnlpbmcodHJ1ZSk7XG4gICAgICAgIHNldFZlcmlmaWNhdGlvblJlc3VsdChudWxsKTtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIC8vIFVzaW5nIGZldGNoIHdpdGggSEVBRCBvciBhYm9ydCBjb250cm9sbGVyIHRvIGNoZWNrIHN0YXR1cyBjb2RlIHdpdGhvdXQgY29uc3VtaW5nIGJvZHlcbiAgICAgICAgICAgIGNvbnN0IGNvbnRyb2xsZXIgPSBuZXcgQWJvcnRDb250cm9sbGVyKCk7XG4gICAgICAgICAgICBjb25zdCB0aW1lb3V0SWQgPSBzZXRUaW1lb3V0KCgpID0+IGNvbnRyb2xsZXIuYWJvcnQoKSwgNjAwMCk7XG4gICAgICAgICAgICBcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2gocHJpbWFyeURvd25sb2FkVXJsLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICAgICAgICBzaWduYWw6IGNvbnRyb2xsZXIuc2lnbmFsLFxuICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgJ1JhbmdlJzogJ2J5dGVzPTAtMCcgfSAvLyBPbmx5IHJlcXVlc3QgMSBieXRlIHNvIGZpbGUgaXMgbmV2ZXIgZG93bmxvYWRlZFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBjbGVhclRpbWVvdXQodGltZW91dElkKTtcblxuICAgICAgICAgICAgY29uc3QgaXNPayA9IHJlc3BvbnNlLnN0YXR1cyA+PSAyMDAgJiYgcmVzcG9uc2Uuc3RhdHVzIDwgNDAwO1xuICAgICAgICAgICAgY29uc3QgY29udGVudFR5cGUgPSByZXNwb25zZS5oZWFkZXJzLmdldCgnY29udGVudC10eXBlJykgfHwgJ2FwcGxpY2F0aW9uL29jdGV0LXN0cmVhbSc7XG4gICAgICAgICAgICBjb25zdCBjb250ZW50TGVuZ3RoID0gcmVzcG9uc2UuaGVhZGVycy5nZXQoJ2NvbnRlbnQtbGVuZ3RoJykgfHwgZmlsZVNpemU7XG5cbiAgICAgICAgICAgIHNldFZlcmlmaWNhdGlvblJlc3VsdCh7XG4gICAgICAgICAgICAgICAgc3RhdHVzOiByZXNwb25zZS5zdGF0dXMsXG4gICAgICAgICAgICAgICAgc3RhdHVzVGV4dDogcmVzcG9uc2Uuc3RhdHVzVGV4dCB8fCAoaXNPayA/ICdPSycgOiAnRXJyb3InKSxcbiAgICAgICAgICAgICAgICBpc09rLFxuICAgICAgICAgICAgICAgIGNvbnRlbnRUeXBlLFxuICAgICAgICAgICAgICAgIGNvbnRlbnRMZW5ndGgsXG4gICAgICAgICAgICAgICAgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvTG9jYWxlVGltZVN0cmluZygpXG4gICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgaWYgKGlzT2spIHtcbiAgICAgICAgICAgICAgICBzZW5kTm90aWNlKHsgbWVzc2FnZTogYOKckyBEb3dubG9hZCByb3V0ZSB2ZXJpZmllZCEgSFRUUCAke3Jlc3BvbnNlLnN0YXR1c30gKFZhbGlkICYgUmVhY2hhYmxlKWAsIHR5cGU6ICdzdWNjZXNzJyB9KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgc2VuZE5vdGljZSh7IG1lc3NhZ2U6IGDimqDvuI8gRG93bmxvYWQgcm91dGUgcmV0dXJuZWQgSFRUUCAke3Jlc3BvbnNlLnN0YXR1c31gLCB0eXBlOiAnYWxlcnQnIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgICAgIHNldFZlcmlmaWNhdGlvblJlc3VsdCh7XG4gICAgICAgICAgICAgICAgc3RhdHVzOiAnRXJyb3InLFxuICAgICAgICAgICAgICAgIHN0YXR1c1RleHQ6IGVyci5uYW1lID09PSAnQWJvcnRFcnJvcicgPyAnVGltZW91dCAoU2VydmVyIHJlc3BvbmRpbmcgc2xvd2x5KScgOiBlcnIubWVzc2FnZSxcbiAgICAgICAgICAgICAgICBpc09rOiBmYWxzZSxcbiAgICAgICAgICAgICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCkudG9Mb2NhbGVUaW1lU3RyaW5nKClcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgc2VuZE5vdGljZSh7IG1lc3NhZ2U6IGBWZXJpZmljYXRpb24gY2hlY2s6ICR7ZXJyLm1lc3NhZ2V9YCwgdHlwZTogJ2Vycm9yJyB9KTtcbiAgICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgICAgIHNldFZlcmlmeWluZyhmYWxzZSk7XG4gICAgICAgIH1cbiAgICB9O1xuXG4gICAgY29uc3QgaGFuZGxlQ29uZmlybURvd25sb2FkID0gKCkgPT4ge1xuICAgICAgICBzZXRTaG93RG93bmxvYWRDb25maXJtKGZhbHNlKTtcbiAgICAgICAgc2VuZE5vdGljZSh7IG1lc3NhZ2U6ICdJbml0aWF0aW5nIGZpbGUgZG93bmxvYWQgdG8geW91ciBkZXZpY2UuLi4nLCB0eXBlOiAnaW5mbycgfSk7XG4gICAgICAgIHdpbmRvdy5vcGVuKHByaW1hcnlEb3dubG9hZFVybCwgJ19ibGFuaycpO1xuICAgIH07XG5cbiAgICBjb25zdCBoYW5kbGVCYWNrID0gKCkgPT4ge1xuICAgICAgICBpZiAod2luZG93Lmhpc3RvcnkubGVuZ3RoID4gMSkge1xuICAgICAgICAgICAgd2luZG93Lmhpc3RvcnkuYmFjaygpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSBgL2FkbWluL3Jlc291cmNlcy9GaWxlL3JlY29yZHMvJHtmaWxlSWR9L3Nob3dgO1xuICAgICAgICB9XG4gICAgfTtcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3ggcD1cInh4bFwiIHN0eWxlPXt7IG1heFdpZHRoOiAnODQwcHgnLCBtYXJnaW46ICcwIGF1dG8nLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlxuICAgICAgICAgICAgPEJveFxuICAgICAgICAgICAgICAgIHA9XCJ4bFwiXG4gICAgICAgICAgICAgICAgc3R5bGU9e3tcbiAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAnIzE2MTkyNCcsXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwgMjE1LCAwLCAwLjM1KScsXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlclJhZGl1czogJzE2cHgnLFxuICAgICAgICAgICAgICAgICAgICBib3hTaGFkb3c6ICcwIDEycHggMzVweCByZ2JhKDAsIDAsIDAsIDAuNjUpJ1xuICAgICAgICAgICAgICAgIH19XG4gICAgICAgICAgICA+XG4gICAgICAgICAgICAgICAgey8qIEhlYWRlciAqL31cbiAgICAgICAgICAgICAgICA8Qm94IGZsZXgganVzdGlmeUNvbnRlbnQ9XCJzcGFjZS1iZXR3ZWVuXCIgYWxpZ25JdGVtcz1cImNlbnRlclwiIG1iPVwieGxcIj5cbiAgICAgICAgICAgICAgICAgICAgPEJveD5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxUZXh0IHZhcmlhbnQ9XCJoM1wiIHN0eWxlPXt7IGNvbG9yOiAnI0ZGRDcwMCcsIG1hcmdpbjogMCwgZm9udFdlaWdodDogNzAwIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxJY29uIGljb249XCJEb3dubG9hZFwiIHN0eWxlPXt7IG1hcmdpblJpZ2h0OiAnMTBweCcgfX0gLz5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBEb3dubG9hZCBJbnNwZWN0b3IgJiBVUkwgVmFsaWRhdG9yXG4gICAgICAgICAgICAgICAgICAgICAgICA8L1RleHQ+XG4gICAgICAgICAgICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNhYWEnLCBmb250U2l6ZTogJzEzcHgnLCBtYXJnaW5Ub3A6ICc0cHgnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEluc3BlY3QsIHZlcmlmeSwgY29weSBvciB0ZXN0IGRvd25sb2FkIFVSTHMgc2FmZWx5IHdpdGhvdXQgdW53YW50ZWQgZG93bmxvYWRzXG4gICAgICAgICAgICAgICAgICAgICAgICA8L1RleHQ+XG4gICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgICAgICA8QnV0dG9uIHZhcmlhbnQ9XCJsaWdodFwiIHNpemU9XCJzbVwiIG9uQ2xpY2s9e2hhbmRsZUJhY2t9IHN0eWxlPXt7IGN1cnNvcjogJ3BvaW50ZXInIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgPEljb24gaWNvbj1cIkFycm93TGVmdFwiIHN0eWxlPXt7IG1hcmdpblJpZ2h0OiAnNnB4JyB9fSAvPlxuICAgICAgICAgICAgICAgICAgICAgICAgQmFjayB0byBNb2RcbiAgICAgICAgICAgICAgICAgICAgPC9CdXR0b24+XG4gICAgICAgICAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgICAgICAgICB7LyogTW9kIE1ldGEgU25hcHNob3QgKi99XG4gICAgICAgICAgICAgICAgPEJveFxuICAgICAgICAgICAgICAgICAgICBwPVwibGdcIlxuICAgICAgICAgICAgICAgICAgICBtYj1cInhsXCJcbiAgICAgICAgICAgICAgICAgICAgc3R5bGU9e3tcbiAgICAgICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJyMwZTEwMTcnLFxuICAgICAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiAnMTBweCcsXG4gICAgICAgICAgICAgICAgICAgICAgICBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjA4KSdcbiAgICAgICAgICAgICAgICAgICAgfX1cbiAgICAgICAgICAgICAgICA+XG4gICAgICAgICAgICAgICAgICAgIDxCb3ggZmxleCBqdXN0aWZ5Q29udGVudD1cInNwYWNlLWJldHdlZW5cIiBhbGlnbkl0ZW1zPVwiY2VudGVyXCIgZmxleFdyYXA9XCJ3cmFwXCIgc3R5bGU9e3sgZ2FwOiAnMTBweCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnI2ZmZicsIGZvbnRTaXplOiAnMTZweCcsIGZvbnRXZWlnaHQ6IDYwMCB9fT57ZmlsZU5hbWV9PC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnIzg4OCcsIGZvbnRTaXplOiAnMTJweCcgfX0+SUQ6IHtmaWxlSWR9PC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgICAgICAgICAgICAgICA8Qm94IGZsZXggc3R5bGU9e3sgZ2FwOiAnOHB4JyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8QmFkZ2UgdmFyaWFudD1cInByaW1hcnlcIiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMmEyZjQ1JywgY29sb3I6ICcjYzBjNmUwJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdntmaWxlVmVyc2lvbn1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L0JhZGdlPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxCYWRnZSB2YXJpYW50PVwiaW5mb1wiIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMxZDM1NTcnLCBjb2xvcjogJyM2NGI1ZjYnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBTaXplOiB7ZmlsZVNpemV9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9CYWRnZT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7aXNNdWx0aVBhcnQgJiYgKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8QmFkZ2UgdmFyaWFudD1cIndhcm5pbmdcIiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjNGEzODAwJywgY29sb3I6ICcjZmZkNTRmJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIE11bHRpLVBhcnQgRmlsZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L0JhZGdlPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICl9XG4gICAgICAgICAgICAgICAgICAgICAgICA8L0JveD5cbiAgICAgICAgICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgICAgICAgICB7LyogUHJpbWFyeSBWYWxpZCBVUkwgQm94ICovfVxuICAgICAgICAgICAgICAgIDxCb3ggbWI9XCJ4bFwiPlxuICAgICAgICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNGRkQ3MDAnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTNweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC41cHgnLCBtYXJnaW5Cb3R0b206ICc4cHgnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgUHJpbWFyeSBWZXJpZmllZCBEb3dubG9hZCBSb3V0ZTpcbiAgICAgICAgICAgICAgICAgICAgPC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICA8Qm94XG4gICAgICAgICAgICAgICAgICAgICAgICBwPVwibWRcIlxuICAgICAgICAgICAgICAgICAgICAgICAgc3R5bGU9e3tcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICcjMGIwYzEwJyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBib3JkZXI6ICcxcHggc29saWQgIzMzMycsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiAnOHB4JyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkaXNwbGF5OiAnZmxleCcsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcicsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAganVzdGlmeUNvbnRlbnQ6ICdzcGFjZS1iZXR3ZWVuJyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBnYXA6ICcxMnB4J1xuICAgICAgICAgICAgICAgICAgICAgICAgfX1cbiAgICAgICAgICAgICAgICAgICAgPlxuICAgICAgICAgICAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjMDBlNWZmJywgZm9udEZhbWlseTogJ21vbm9zcGFjZScsIGZvbnRTaXplOiAnMTNweCcsIHdvcmRCcmVhazogJ2JyZWFrLWFsbCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge3ByaW1hcnlEb3dubG9hZFVybH1cbiAgICAgICAgICAgICAgICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxCb3ggZmxleCBzdHlsZT17eyBnYXA6ICc4cHgnLCBmbGV4U2hyaW5rOiAwIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxCdXR0b25cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZT1cInNtXCJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyaWFudD1cInNlY29uZGFyeVwiXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpID0+IGhhbmRsZUNvcHkocHJpbWFyeURvd25sb2FkVXJsKX1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3R5bGU9e3sgY3Vyc29yOiAncG9pbnRlcicsIGJhY2tncm91bmQ6IGNvcGllZCA/ICcjMmVjYzcxJyA6IHVuZGVmaW5lZCB9fVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgID5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEljb24gaWNvbj17Y29waWVkID8gJ0NoZWNrJyA6ICdDb3B5J30gc3R5bGU9e3sgbWFyZ2luUmlnaHQ6ICc2cHgnIH19IC8+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtjb3BpZWQgPyAnQ29waWVkJyA6ICdDb3B5IFVSTCd9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9CdXR0b24+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplPVwic21cIlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXJpYW50PVwicHJpbWFyeVwiXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9e2hhbmRsZVZlcmlmeUVuZHBvaW50fVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkaXNhYmxlZD17dmVyaWZ5aW5nfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMDBjODUzJywgY29sb3I6ICcjZmZmJywgZm9udFdlaWdodDogNjAwLCBjdXJzb3I6ICdwb2ludGVyJyB9fVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgID5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEljb24gaWNvbj17dmVyaWZ5aW5nID8gJ0xvYWRlcicgOiAnQ2hlY2tDaXJjbGUnfSBzdHlsZT17eyBtYXJnaW5SaWdodDogJzZweCcgfX0gLz5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge3ZlcmlmeWluZyA/ICdUZXN0aW5nLi4uJyA6ICdUZXN0IFZhbGlkaXR5IChTYWZlKSd9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9CdXR0b24+XG4gICAgICAgICAgICAgICAgICAgICAgICA8L0JveD5cbiAgICAgICAgICAgICAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgICAgICAgICAgICAgey8qIFZlcmlmaWNhdGlvbiBSZXN1bHQgRmVlZGJhY2sgQ2FyZCAqL31cbiAgICAgICAgICAgICAgICAgICAge3ZlcmlmaWNhdGlvblJlc3VsdCAmJiAoXG4gICAgICAgICAgICAgICAgICAgICAgICA8Qm94XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbXQ9XCJtZFwiXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcD1cIm1kXCJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHlsZT17e1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6IHZlcmlmaWNhdGlvblJlc3VsdC5pc09rID8gJ3JnYmEoMCwgMjAwLCA4MywgMC4xMiknIDogJ3JnYmEoMjMxLCA3NiwgNjAsIDAuMTUpJyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYm9yZGVyOiBgMXB4IHNvbGlkICR7dmVyaWZpY2F0aW9uUmVzdWx0LmlzT2sgPyAncmdiYSgwLCAyMDAsIDgzLCAwLjQpJyA6ICdyZ2JhKDIzMSwgNzYsIDYwLCAwLjQpJ31gLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBib3JkZXJSYWRpdXM6ICc4cHgnXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfX1cbiAgICAgICAgICAgICAgICAgICAgICAgID5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8Qm94IGZsZXgganVzdGlmeUNvbnRlbnQ9XCJzcGFjZS1iZXR3ZWVuXCIgYWxpZ25JdGVtcz1cImNlbnRlclwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogdmVyaWZpY2F0aW9uUmVzdWx0LmlzT2sgPyAnIzJlY2M3MScgOiAnI2U3NGMzYycsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHt2ZXJpZmljYXRpb25SZXN1bHQuaXNPayA/ICfinJMgUm91dGUgVmVyaWZpZWQgQWN0aXZlICYgSGVhbHRoeScgOiAn4pqg77iPIFZlcmlmaWNhdGlvbiBJc3N1ZSBEZXRlY3RlZCd9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjODg4JywgZm9udFNpemU6ICcxMXB4JyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRlc3RlZCBhdCB7dmVyaWZpY2F0aW9uUmVzdWx0LnRpbWVzdGFtcH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnI2NjYycsIGZvbnRTaXplOiAnMTJweCcsIG1hcmdpblRvcDogJzRweCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEhUVFAgU3RhdHVzOiA8c3Ryb25nPnt2ZXJpZmljYXRpb25SZXN1bHQuc3RhdHVzfSB7dmVyaWZpY2F0aW9uUmVzdWx0LnN0YXR1c1RleHR9PC9zdHJvbmc+ICZidWxsOyBDb250ZW50LVR5cGU6IDxzdHJvbmc+e3ZlcmlmaWNhdGlvblJlc3VsdC5jb250ZW50VHlwZX08L3N0cm9uZz4gJmJ1bGw7IFNhZmUgVGVzdCAobm8gbG9jYWwgZG93bmxvYWQgdHJpZ2dlcmVkKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgICAgICApfVxuICAgICAgICAgICAgICAgIDwvQm94PlxuXG4gICAgICAgICAgICAgICAgey8qIEFkZGl0aW9uYWwgRW5kcG9pbnRzICYgQ2xvdWQgU3RvcmFnZSBJbmZvICovfVxuICAgICAgICAgICAgICAgIDxCb3ggbWI9XCJsZ1wiPlxuICAgICAgICAgICAgICAgICAgICB7ZXh0ZXJuYWxVcmwgJiYgKFxuICAgICAgICAgICAgICAgICAgICAgICAgPEJveCBtYj1cIm1kXCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjYmJiJywgZm9udFNpemU6ICcxMnB4JywgZm9udFdlaWdodDogNjAwLCBtYXJnaW5Cb3R0b206ICc0cHgnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBFeHRlcm5hbCBDbG91ZCBNaXJyb3IgVVJMOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8Qm94IHA9XCJzbVwiIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMwYjBjMTAnLCBib3JkZXI6ICcxcHggc29saWQgIzIyMicsIGJvcmRlclJhZGl1czogJzZweCcsIGRpc3BsYXk6ICdmbGV4JywganVzdGlmeUNvbnRlbnQ6ICdzcGFjZS1iZXR3ZWVuJywgYWxpZ25JdGVtczogJ2NlbnRlcicgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnI2NjYycsIGZvbnRTaXplOiAnMTJweCcsIGZvbnRGYW1pbHk6ICdtb25vc3BhY2UnLCB3b3JkQnJlYWs6ICdicmVhay1hbGwnIH19PntleHRlcm5hbFVybH08L1RleHQ+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxCdXR0b24gc2l6ZT1cInNtXCIgdmFyaWFudD1cInRleHRcIiBvbkNsaWNrPXsoKSA9PiBoYW5kbGVDb3B5KGV4dGVybmFsVXJsKX0gc3R5bGU9e3sgY3Vyc29yOiAncG9pbnRlcicsIGNvbG9yOiAnI0ZGRDcwMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8SWNvbiBpY29uPVwiQ29weVwiIC8+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICAgICAgICAgICAgICl9XG5cbiAgICAgICAgICAgICAgICAgICAge2ZpbGVLZXkgJiYgKFxuICAgICAgICAgICAgICAgICAgICAgICAgPEJveCBtYj1cIm1kXCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjYmJiJywgZm9udFNpemU6ICcxMnB4JywgZm9udFdlaWdodDogNjAwLCBtYXJnaW5Cb3R0b206ICc0cHgnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBCYWNrYmxhemUgQjIgU3RvcmFnZSBLZXk6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxCb3ggcD1cInNtXCIgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzBiMGMxMCcsIGJvcmRlcjogJzFweCBzb2xpZCAjMjIyJywgYm9yZGVyUmFkaXVzOiAnNnB4JywgZGlzcGxheTogJ2ZsZXgnLCBqdXN0aWZ5Q29udGVudDogJ3NwYWNlLWJldHdlZW4nLCBhbGlnbkl0ZW1zOiAnY2VudGVyJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjYWFhJywgZm9udFNpemU6ICcxMnB4JywgZm9udEZhbWlseTogJ21vbm9zcGFjZScsIHdvcmRCcmVhazogJ2JyZWFrLWFsbCcgfX0+e2ZpbGVLZXl9PC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8QnV0dG9uIHNpemU9XCJzbVwiIHZhcmlhbnQ9XCJ0ZXh0XCIgb25DbGljaz17KCkgPT4gaGFuZGxlQ29weShmaWxlS2V5KX0gc3R5bGU9e3sgY3Vyc29yOiAncG9pbnRlcicsIGNvbG9yOiAnI0ZGRDcwMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8SWNvbiBpY29uPVwiQ29weVwiIC8+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICAgICAgICAgICAgICl9XG5cbiAgICAgICAgICAgICAgICAgICAge2RpcmVjdFVybCAmJiAoXG4gICAgICAgICAgICAgICAgICAgICAgICA8Qm94IG1iPVwibWRcIj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNiYmInLCBmb250U2l6ZTogJzEycHgnLCBmb250V2VpZ2h0OiA2MDAsIG1hcmdpbkJvdHRvbTogJzRweCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIERpcmVjdCBDRE4gLyBDbG91ZGZsYXJlIFBhc3N0aHJvdWdoOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8Qm94IHA9XCJzbVwiIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMwYjBjMTAnLCBib3JkZXI6ICcxcHggc29saWQgIzIyMicsIGJvcmRlclJhZGl1czogJzZweCcsIGRpc3BsYXk6ICdmbGV4JywganVzdGlmeUNvbnRlbnQ6ICdzcGFjZS1iZXR3ZWVuJywgYWxpZ25JdGVtczogJ2NlbnRlcicgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnIzJlY2M3MScsIGZvbnRTaXplOiAnMTJweCcsIGZvbnRGYW1pbHk6ICdtb25vc3BhY2UnLCB3b3JkQnJlYWs6ICdicmVhay1hbGwnIH19PntkaXJlY3RVcmx9PC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8QnV0dG9uIHNpemU9XCJzbVwiIHZhcmlhbnQ9XCJ0ZXh0XCIgb25DbGljaz17KCkgPT4gaGFuZGxlQ29weShkaXJlY3RVcmwpfSBzdHlsZT17eyBjdXJzb3I6ICdwb2ludGVyJywgY29sb3I6ICcjRkZENzAwJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxJY29uIGljb249XCJDb3B5XCIgLz5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9CdXR0b24+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICAgICAgICAgICAgICAgICA8L0JveD5cbiAgICAgICAgICAgICAgICAgICAgKX1cbiAgICAgICAgICAgICAgICA8L0JveD5cblxuICAgICAgICAgICAgICAgIHsvKiBFeHBsaWNpdCBEb3dubG9hZCBDb25maXJtYXRpb24gTW9kYWwgLyBDYXJkICovfVxuICAgICAgICAgICAgICAgIHtzaG93RG93bmxvYWRDb25maXJtICYmIChcbiAgICAgICAgICAgICAgICAgICAgPEJveFxuICAgICAgICAgICAgICAgICAgICAgICAgcD1cImxnXCJcbiAgICAgICAgICAgICAgICAgICAgICAgIG1iPVwibGdcIlxuICAgICAgICAgICAgICAgICAgICAgICAgc3R5bGU9e3tcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwgMTkzLCA3LCAwLjEpJyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBib3JkZXI6ICcxLjVweCBzb2xpZCAjZmZjMTA3JyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBib3JkZXJSYWRpdXM6ICcxMHB4J1xuICAgICAgICAgICAgICAgICAgICAgICAgfX1cbiAgICAgICAgICAgICAgICAgICAgPlxuICAgICAgICAgICAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjZmZkNTRmJywgZm9udFdlaWdodDogNzAwLCBmb250U2l6ZTogJzE0cHgnLCBtYXJnaW5Cb3R0b206ICc2cHgnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxJY29uIGljb249XCJBbGVydFRyaWFuZ2xlXCIgc3R5bGU9e3sgbWFyZ2luUmlnaHQ6ICc2cHgnIH19IC8+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29uZmlybSBSZWFsIERvd25sb2FkXG4gICAgICAgICAgICAgICAgICAgICAgICA8L1RleHQ+XG4gICAgICAgICAgICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNlZWUnLCBmb250U2l6ZTogJzEzcHgnLCBtYXJnaW5Cb3R0b206ICcxMnB4JyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBZb3UgYXJlIGFib3V0IHRvIHN0YXJ0IGRvd25sb2FkaW5nIHRoZSBhY3R1YWwgbW9kIGZpbGUgKHtmaWxlTmFtZX0sIHtmaWxlU2l6ZX0pIGRpcmVjdGx5IG9udG8geW91ciBjb21wdXRlci4gQXJlIHlvdSBzdXJlP1xuICAgICAgICAgICAgICAgICAgICAgICAgPC9UZXh0PlxuICAgICAgICAgICAgICAgICAgICAgICAgPEJveCBmbGV4IHN0eWxlPXt7IGdhcDogJzEwcHgnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxCdXR0b25cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZT1cInNtXCJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyaWFudD1cInByaW1hcnlcIlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXtoYW5kbGVDb25maXJtRG93bmxvYWR9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyNGRkQ3MDAnLCBjb2xvcjogJyMwMDAnLCBmb250V2VpZ2h0OiA2MDAsIGN1cnNvcjogJ3BvaW50ZXInIH19XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8SWNvbiBpY29uPVwiRG93bmxvYWRcIiBzdHlsZT17eyBtYXJnaW5SaWdodDogJzZweCcgfX0gLz5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgWWVzLCBEb3dubG9hZCBGaWxlIHRvIFBDXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9CdXR0b24+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplPVwic21cIlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXJpYW50PVwibGlnaHRcIlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBzZXRTaG93RG93bmxvYWRDb25maXJtKGZhbHNlKX1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3R5bGU9e3sgY3Vyc29yOiAncG9pbnRlcicgfX1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENhbmNlbFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxuICAgICAgICAgICAgICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICAgICAgICAgICAgIDwvQm94PlxuICAgICAgICAgICAgICAgICl9XG5cbiAgICAgICAgICAgICAgICB7LyogRm9vdGVyIEJ1dHRvbnMgKi99XG4gICAgICAgICAgICAgICAgPEJveCBmbGV4IGp1c3RpZnlDb250ZW50PVwic3BhY2UtYmV0d2VlblwiIGFsaWduSXRlbXM9XCJjZW50ZXJcIiBtdD1cInhsXCIgcHQ9XCJsZ1wiIGJvcmRlclRvcD1cIjFweCBzb2xpZCByZ2JhKDI1NSwgMjU1LCAyNTUsIDAuMDgpXCI+XG4gICAgICAgICAgICAgICAgICAgIDxCdXR0b25cbiAgICAgICAgICAgICAgICAgICAgICAgIHZhcmlhbnQ9XCJ0ZXh0XCJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpID0+IHdpbmRvdy5vcGVuKGAvbW9kcy8ke2ZpbGVJZH1gLCAnX2JsYW5rJyl9XG4gICAgICAgICAgICAgICAgICAgICAgICBzdHlsZT17eyBjb2xvcjogJyM2NGI1ZjYnLCBjdXJzb3I6ICdwb2ludGVyJyB9fVxuICAgICAgICAgICAgICAgICAgICA+XG4gICAgICAgICAgICAgICAgICAgICAgICA8SWNvbiBpY29uPVwiRXh0ZXJuYWxMaW5rXCIgc3R5bGU9e3sgbWFyZ2luUmlnaHQ6ICc2cHgnIH19IC8+XG4gICAgICAgICAgICAgICAgICAgICAgICBWaWV3IFB1YmxpYyBNb2QgUGFnZVxuICAgICAgICAgICAgICAgICAgICA8L0J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgPEJveCBmbGV4IHN0eWxlPXt7IGdhcDogJzEwcHgnIH19PlxuICAgICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiB2YXJpYW50PVwibGlnaHRcIiBvbkNsaWNrPXtoYW5kbGVCYWNrfSBzdHlsZT17eyBjdXJzb3I6ICdwb2ludGVyJyB9fT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBEb25lXG4gICAgICAgICAgICAgICAgICAgICAgICA8L0J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDxCdXR0b25cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXJpYW50PVwic2Vjb25kYXJ5XCJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBzZXRTaG93RG93bmxvYWRDb25maXJtKHRydWUpfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7IGN1cnNvcjogJ3BvaW50ZXInLCBib3JkZXJDb2xvcjogJyNGRkQ3MDAnLCBjb2xvcjogJyNGRkQ3MDAnIH19XG4gICAgICAgICAgICAgICAgICAgICAgICA+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPEljb24gaWNvbj1cIkRvd25sb2FkXCIgc3R5bGU9e3sgbWFyZ2luUmlnaHQ6ICc2cHgnIH19IC8+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgRG93bmxvYWQgdG8gTG9jYWwgRGV2aWNlLi4uXG4gICAgICAgICAgICAgICAgICAgICAgICA8L0J1dHRvbj5cbiAgICAgICAgICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICAgICAgICAgPC9Cb3g+XG4gICAgICAgICAgICA8L0JveD5cbiAgICAgICAgPC9Cb3g+XG4gICAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IERvd25sb2FkSW5zcGVjdG9yO1xuXG4iLCJpbXBvcnQgUmVhY3QgZnJvbSAncmVhY3QnO1xuXG5jb25zdCBWYXJpYW50QmFkZ2UgPSAocHJvcHMpID0+IHtcbiAgY29uc3QgeyByZWNvcmQsIHByb3BlcnR5IH0gPSBwcm9wcztcbiAgaWYgKCFyZWNvcmQgfHwgIXJlY29yZC5wYXJhbXMgfHwgIXByb3BlcnR5KSByZXR1cm4gbnVsbDtcbiAgY29uc3QgaXNWYXJpYW50ID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcbiAgY29uc3QgaXNWYXIgPSBpc1ZhcmlhbnQgPT09IHRydWUgfHwgaXNWYXJpYW50ID09PSAndHJ1ZSc7XG4gIGNvbnN0IG1hc3RlcklkID0gcmVjb3JkLnBhcmFtcy5tYXN0ZXJGaWxlO1xuICBjb25zdCByZWNvcmRJZCA9IHJlY29yZC5wYXJhbXMuX2lkIHx8IHJlY29yZC5pZDtcblxuICBjb25zdCBoYW5kbGVDbGljayA9IChlKSA9PiB7XG4gICAgZS5wcmV2ZW50RGVmYXVsdCgpO1xuICAgIGUuc3RvcFByb3BhZ2F0aW9uKCk7XG4gICAgaWYgKGlzVmFyICYmIG1hc3RlcklkKSB7XG4gICAgICB3aW5kb3cubG9jYXRpb24uaHJlZiA9IGAvYWRtaW4vcmVzb3VyY2VzL0ZpbGUvcmVjb3Jkcy8ke21hc3RlcklkfS9zaG93YDtcbiAgICB9IGVsc2Uge1xuICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSBgL2FkbWluL3Jlc291cmNlcy9GaWxlP2ZpbHRlcnMubWFzdGVyRmlsZT0ke3JlY29yZElkfWA7XG4gICAgfVxuICB9O1xuXG4gIGlmIChpc1Zhcikge1xuICAgIHJldHVybiAoXG4gICAgICA8YVxuICAgICAgICBocmVmPXttYXN0ZXJJZCA/IGAvYWRtaW4vcmVzb3VyY2VzL0ZpbGUvcmVjb3Jkcy8ke21hc3RlcklkfS9zaG93YCA6ICcjJ31cbiAgICAgICAgb25DbGljaz17aGFuZGxlQ2xpY2t9XG4gICAgICAgIHRpdGxlPXttYXN0ZXJJZCA/IGBDbGljayB0byB2aWV3IE1hc3RlciBBcHAgKCR7bWFzdGVySWR9KWAgOiAnVmFyaWFudCBNb2QnfVxuICAgICAgICBjbGFzc05hbWU9XCJhZG1pbi1jdXN0b20tY2hpcFwiXG4gICAgICAgIGRhdGEtYmFkZ2UtdmFsPVwidmFyaWFudC1jaGlsZFwiXG4gICAgICAgIHN0eWxlPXt7XG4gICAgICAgICAgZGlzcGxheTogJ2lubGluZS1mbGV4JyxcbiAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJyxcbiAgICAgICAgICBnYXA6ICc2cHgnLFxuICAgICAgICAgIHBhZGRpbmc6ICc0cHggMTFweCcsXG4gICAgICAgICAgYm9yZGVyUmFkaXVzOiAnMjBweCcsXG4gICAgICAgICAgZm9udFNpemU6ICcxMXB4JyxcbiAgICAgICAgICBmb250V2VpZ2h0OiA3MDAsXG4gICAgICAgICAgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsXG4gICAgICAgICAgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsXG4gICAgICAgICAgYmFja2dyb3VuZDogJ2xpbmVhci1ncmFkaWVudCgxNDVkZWcsIHJnYmEoMTg2LCAxMDQsIDIwMCwgMC4yOCkgMCUsIHJnYmEoNjUsIDI1LCA3NSwgMC4zNSkgMTAwJSknLFxuICAgICAgICAgIGNvbG9yOiAnI2UxYmVlNycsXG4gICAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMTg2LCAxMDQsIDIwMCwgMC43KScsXG4gICAgICAgICAgYm94U2hhZG93OiAnaW5zZXQgMCAxLjVweCAycHggcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjIpLCAwIDAgMTBweCByZ2JhKDE4NiwgMTA0LCAyMDAsIDAuMyknLFxuICAgICAgICAgIHRleHRTaGFkb3c6ICcwIDAgNnB4IHJnYmEoMjA2LCAxNDcsIDIxNiwgMC40KScsXG4gICAgICAgICAgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIixcbiAgICAgICAgICB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLFxuICAgICAgICAgIGN1cnNvcjogJ3BvaW50ZXInLFxuICAgICAgICAgIHRyYW5zaXRpb246ICdhbGwgMC4ycyBlYXNlJ1xuICAgICAgICB9fVxuICAgICAgICBvbk1vdXNlRW50ZXI9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAnc2NhbGUoMS4wNSknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSAnI2NlOTNkOCc7IH19XG4gICAgICAgIG9uTW91c2VMZWF2ZT17KGUpID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLnRyYW5zZm9ybSA9ICdzY2FsZSgxKSc7IGUuY3VycmVudFRhcmdldC5zdHlsZS5ib3JkZXJDb2xvciA9ICdyZ2JhKDE4NiwgMTA0LCAyMDAsIDAuNyknOyB9fVxuICAgICAgPlxuICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzEwcHgnIH19PuKaoTwvc3Bhbj4gVmFyaWFudFxuICAgICAgPC9hPlxuICAgICk7XG4gIH1cblxuICByZXR1cm4gKFxuICAgIDxhXG4gICAgICBocmVmPXtgL2FkbWluL3Jlc291cmNlcy9GaWxlP2ZpbHRlcnMubWFzdGVyRmlsZT0ke3JlY29yZElkfWB9XG4gICAgICBvbkNsaWNrPXtoYW5kbGVDbGlja31cbiAgICAgIHRpdGxlPVwiQ2xpY2sgdG8gdmlldyBhbGwgVmFyaWFudHMgb2YgdGhpcyBNYXN0ZXIgTW9kXCJcbiAgICAgIGNsYXNzTmFtZT1cImFkbWluLWN1c3RvbS1jaGlwXCJcbiAgICAgIGRhdGEtYmFkZ2UtdmFsPVwidmFyaWFudC1tYXN0ZXJcIlxuICAgICAgc3R5bGU9e3tcbiAgICAgICAgZGlzcGxheTogJ2lubGluZS1mbGV4JyxcbiAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcicsXG4gICAgICAgIGdhcDogJzZweCcsXG4gICAgICAgIHBhZGRpbmc6ICc0cHggMTFweCcsXG4gICAgICAgIGJvcmRlclJhZGl1czogJzIwcHgnLFxuICAgICAgICBmb250U2l6ZTogJzExcHgnLFxuICAgICAgICBmb250V2VpZ2h0OiA3MDAsXG4gICAgICAgIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLFxuICAgICAgICB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyxcbiAgICAgICAgYmFja2dyb3VuZDogJ2xpbmVhci1ncmFkaWVudCgxNDVkZWcsIHJnYmEoMjU1LCAyMTUsIDAsIDAuMjUpIDAlLCByZ2JhKDkwLCA3MCwgMTUsIDAuMykgMTAwJSknLFxuICAgICAgICBjb2xvcjogJyNGRkQ3MDAnLFxuICAgICAgICBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsIDIxNSwgMCwgMC43NSknLFxuICAgICAgICBib3hTaGFkb3c6ICdpbnNldCAwIDEuNXB4IDJweCByZ2JhKDI1NSwgMjU1LCAyNTUsIDAuMjIpLCAwIDAgMTBweCByZ2JhKDI1NSwgMjE1LCAwLCAwLjMpJyxcbiAgICAgICAgdGV4dFNoYWRvdzogJzAgMCA2cHggcmdiYSgyNTUsIDIxNSwgMCwgMC40KScsXG4gICAgICAgIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIsXG4gICAgICAgIHRleHREZWNvcmF0aW9uOiAnbm9uZScsXG4gICAgICAgIGN1cnNvcjogJ3BvaW50ZXInLFxuICAgICAgICB0cmFuc2l0aW9uOiAnYWxsIDAuMnMgZWFzZSdcbiAgICAgIH19XG4gICAgICBvbk1vdXNlRW50ZXI9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAnc2NhbGUoMS4wNSknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSAnI2ZmZic7IH19XG4gICAgICBvbk1vdXNlTGVhdmU9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS50cmFuc2Zvcm0gPSAnc2NhbGUoMSknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSAncmdiYSgyNTUsIDIxNSwgMCwgMC43NSknOyB9fVxuICAgID5cbiAgICAgIDxzcGFuIHN0eWxlPXt7IGZvbnRTaXplOiAnMTBweCcgfX0+8J+RkTwvc3Bhbj4gTWFzdGVyXG4gICAgPC9hPlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgVmFyaWFudEJhZGdlO1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlLCB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3ggfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgQXZhdGFyQ2VsbCA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSwgd2hlcmUgfSA9IHByb3BzOyBcbiAgICBpZiAoIXJlY29yZCB8fCAhcmVjb3JkLnBhcmFtcyB8fCAhcHJvcGVydHkpIHJldHVybiBudWxsO1xuICAgIGNvbnN0IGtleSA9IHJlY29yZC5wYXJhbXNbcHJvcGVydHkubmFtZV07XG4gICAgY29uc3QgdXNlcm5hbWUgPSByZWNvcmQucGFyYW1zLnVzZXJuYW1lIHx8ICdVc2VyJztcblxuICAgIGNvbnN0IFtpbWFnZVVybCwgc2V0SW1hZ2VVcmxdID0gdXNlU3RhdGUobnVsbCk7XG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG4gICAgY29uc3QgW2hhc0Vycm9yLCBzZXRIYXNFcnJvcl0gPSB1c2VTdGF0ZShmYWxzZSk7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBpZiAoIWtleSkge1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoa2V5LnN0YXJ0c1dpdGgoJ2h0dHA6Ly8nKSB8fCBrZXkuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKSkge1xuICAgICAgICAgICAgc2V0SW1hZ2VVcmwoa2V5KTtcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZmV0Y2hTaWduZWRVcmwgPSBhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2goYC9hcGkvYWRtaW4vc2lnbmVkLXVybD9rZXk9JHtlbmNvZGVVUklDb21wb25lbnQoa2V5KX1gKTtcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgICAgICAgICAgc2V0SW1hZ2VVcmwoZGF0YS51cmwpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHNldEhhc0Vycm9yKHRydWUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIkVycm9yIGZldGNoaW5nIGF2YXRhciBVUkw6XCIsIGVycm9yKTtcbiAgICAgICAgICAgICAgICBzZXRIYXNFcnJvcih0cnVlKTtcbiAgICAgICAgICAgIH0gZmluYWxseSB7XG4gICAgICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG5cbiAgICAgICAgZmV0Y2hTaWduZWRVcmwoKTtcbiAgICB9LCBba2V5XSk7XG5cbiAgICBjb25zdCBzaXplID0gd2hlcmUgPT09ICdsaXN0JyA/ICczMnB4JyA6ICcxMjBweCc7XG5cbiAgICBpZiAobG9hZGluZykge1xuICAgICAgICByZXR1cm4gPEJveCBzdHlsZT17eyB3aWR0aDogc2l6ZSwgaGVpZ2h0OiBzaXplLCBib3JkZXJSYWRpdXM6ICc1MCUnLCBiYWNrZ3JvdW5kQ29sb3I6ICcjMzMzJyB9fSAvPjtcbiAgICB9XG5cbiAgICBjb25zdCBkZWZhdWx0QXZhdGFyID0gJy9pbWFnZXMvZGVmYXVsdC1hdmF0YXIucG5nJztcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3g+XG4gICAgICAgICAgICA8aW1nIFxuICAgICAgICAgICAgICAgIHNyYz17KCFpbWFnZVVybCB8fCBoYXNFcnJvcikgPyBkZWZhdWx0QXZhdGFyIDogaW1hZ2VVcmx9IFxuICAgICAgICAgICAgICAgIGFsdD17dXNlcm5hbWV9XG4gICAgICAgICAgICAgICAgc3R5bGU9e3sgXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiAnNTAlJywgXG4gICAgICAgICAgICAgICAgICAgIG9iamVjdEZpdDogJ2NvdmVyJyxcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyOiAnMnB4IHNvbGlkICNGRkQ3MDAnLFxuICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICcjMWExYTFhJ1xuICAgICAgICAgICAgICAgIH19IFxuICAgICAgICAgICAgICAgIG9uRXJyb3I9eyhlKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChlLmN1cnJlbnRUYXJnZXQuc3JjICE9PSBkZWZhdWx0QXZhdGFyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3JjID0gZGVmYXVsdEF2YXRhcjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH19XG4gICAgICAgICAgICAvPlxuICAgICAgICA8L0JveD5cbiAgICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgQXZhdGFyQ2VsbDtcbiIsImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94IH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5cbmNvbnN0IEltYWdlUHJldmlldyA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSwgd2hlcmUgfSA9IHByb3BzOyBcbiAgICBpZiAoIXJlY29yZCB8fCAhcmVjb3JkLnBhcmFtcyB8fCAhcHJvcGVydHkpIHJldHVybiBudWxsO1xuICAgIGNvbnN0IHZhbHVlID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcblxuICAgIGNvbnN0IFtpbWFnZVVybCwgc2V0SW1hZ2VVcmxdID0gdXNlU3RhdGUobnVsbCk7XG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBpZiAoIXZhbHVlKSB7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh2YWx1ZS5zdGFydHNXaXRoKCdodHRwOi8vJykgfHwgdmFsdWUuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKSkge1xuICAgICAgICAgICAgc2V0SW1hZ2VVcmwodmFsdWUpO1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBmZXRjaFNpZ25lZFVybCA9IGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChgL2FwaS9hZG1pbi9zaWduZWQtdXJsP2tleT0ke2VuY29kZVVSSUNvbXBvbmVudCh2YWx1ZSl9YCk7XG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlLm9rKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICAgICAgICAgIHNldEltYWdlVXJsKGRhdGEudXJsKTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiRmFpbGVkIHRvIGZldGNoIHNpZ25lZCBVUkwuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIk5ldHdvcmsgZXJyb3IgZmV0Y2hpbmcgc2lnbmVkIFVSTDpcIiwgZXJyb3IpO1xuICAgICAgICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcblxuICAgICAgICBmZXRjaFNpZ25lZFVybCgpO1xuICAgIH0sIFt2YWx1ZV0pO1xuXG4gICAgaWYgKGxvYWRpbmcpIHJldHVybiA8Qm94IHN0eWxlPXt7IGNvbG9yOiAnI0ZGRDcwMCcsIGZvbnRTaXplOiAnMTJweCcgfX0+TG9hZGluZy4uLjwvQm94PjtcblxuICAgIGNvbnN0IGlzQXZhdGFyID0gcHJvcGVydHkubmFtZSA9PT0gJ3Byb2ZpbGVJbWFnZUtleScgfHwgcHJvcGVydHkubmFtZSA9PT0gJ2NhcmRBdmF0YXJVcmwnIHx8IHByb3BlcnR5Lm5hbWUgPT09ICdhdmF0YXInO1xuICAgIGNvbnN0IGRlZmF1bHRJbWFnZSA9IGlzQXZhdGFyID8gJy9pbWFnZXMvZGVmYXVsdC1hdmF0YXIucG5nJyA6ICcvaW1hZ2VzL2RlZmF1bHQtYXBwLWljb24ucG5nJztcbiAgICBjb25zdCBkaXNwbGF5VXJsID0gaW1hZ2VVcmwgfHwgZGVmYXVsdEltYWdlO1xuXG4gICAgY29uc3Qgc2l6ZSA9IHdoZXJlID09PSAnbGlzdCcgPyAnNDBweCcgOiAnMTUwcHgnO1xuICAgIGNvbnN0IHJhZGl1cyA9IGlzQXZhdGFyID8gJzUwJScgOiAnOHB4JztcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3g+XG4gICAgICAgICAgICA8aW1nIFxuICAgICAgICAgICAgICAgIHNyYz17ZGlzcGxheVVybH0gXG4gICAgICAgICAgICAgICAgYWx0PVwiUHJldmlld1wiIFxuICAgICAgICAgICAgICAgIHN0eWxlPXt7IFxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGhlaWdodDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlclJhZGl1czogcmFkaXVzLFxuICAgICAgICAgICAgICAgICAgICBvYmplY3RGaXQ6ICdjb3ZlcicsXG4gICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnLFxuICAgICAgICAgICAgICAgICAgICBib3JkZXI6ICcxcHggc29saWQgIzMzMydcbiAgICAgICAgICAgICAgICB9fSBcbiAgICAgICAgICAgICAgICBvbkVycm9yPXsoZSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZS5jdXJyZW50VGFyZ2V0LnNyYyAhPT0gZGVmYXVsdEltYWdlKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3JjID0gZGVmYXVsdEltYWdlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfX1cbiAgICAgICAgICAgIC8+XG4gICAgICAgIDwvQm94PlxuICAgICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBJbWFnZVByZXZpZXc7XG4iLCJBZG1pbkpTLlVzZXJDb21wb25lbnRzID0ge31cbkFkbWluSlMuZW52Lk5PREVfRU5WID0gXCJwcm9kdWN0aW9uXCJcbmltcG9ydCBEYXNoYm9hcmQgZnJvbSAnLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvQ3VzdG9tRGFzaGJvYXJkJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5EYXNoYm9hcmQgPSBEYXNoYm9hcmRcbmltcG9ydCBTaWRlYmFyQnJhbmRpbmcgZnJvbSAnLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5TaWRlYmFyQnJhbmRpbmcgPSBTaWRlYmFyQnJhbmRpbmdcbmltcG9ydCBBY3Rpb25SZWRpcmVjdCBmcm9tICcuLi9jb21wb25lbnRzL2FjdGlvbnMvQWN0aW9uUmVkaXJlY3QnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkFjdGlvblJlZGlyZWN0ID0gQWN0aW9uUmVkaXJlY3RcbmltcG9ydCBEb3dubG9hZEluc3BlY3RvciBmcm9tICcuLi9jb21wb25lbnRzL2FjdGlvbnMvRG93bmxvYWRJbnNwZWN0b3InXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkRvd25sb2FkSW5zcGVjdG9yID0gRG93bmxvYWRJbnNwZWN0b3JcbmltcG9ydCBWYXJpYW50QmFkZ2UgZnJvbSAnLi4vY29tcG9uZW50cy9jZWxscy9WYXJpYW50QmFkZ2UnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLlZhcmlhbnRCYWRnZSA9IFZhcmlhbnRCYWRnZVxuaW1wb3J0IEF2YXRhckNlbGwgZnJvbSAnLi4vY29tcG9uZW50cy9jZWxscy9BdmF0YXJDZWxsJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5BdmF0YXJDZWxsID0gQXZhdGFyQ2VsbFxuaW1wb3J0IEltYWdlUHJldmlldyBmcm9tICcuLi9jb21wb25lbnRzL2NlbGxzL0ltYWdlUHJldmlldydcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuSW1hZ2VQcmV2aWV3ID0gSW1hZ2VQcmV2aWV3Il0sIm5hbWVzIjpbImFwaSIsIkFwaUNsaWVudCIsIkMiLCJiZyIsInN1cmZhY2UiLCJzdXJmYWNlQWx0IiwiYm9yZGVyIiwiYm9yZGVySG92ZXIiLCJnb2xkIiwiZ29sZERpbSIsImdvbGRHbG93IiwiYmx1ZSIsImdyZWVuIiwicHVycGxlIiwicmVkIiwib3JhbmdlIiwidGV4dCIsInRleHRNdXRlZCIsInRleHREaW0iLCJQTEFURk9STV9DT0xPUlMiLCJjYXJkU3R5bGUiLCJhY2NlbnRDb2xvciIsImJhY2tncm91bmRDb2xvciIsImJvcmRlclJhZGl1cyIsImJvcmRlckxlZnQiLCJwYWRkaW5nIiwidHJhbnNpdGlvbiIsImN1cnNvciIsImJveFNpemluZyIsIkFyZWFDaGFydCIsImRhdGEiLCJ3aWR0aCIsImhlaWdodCIsImNvbG9yIiwibGVuZ3RoIiwibWF4VmFsIiwiTWF0aCIsIm1heCIsIm1hcCIsImQiLCJ2YWx1ZSIsInBhZFgiLCJwYWRZIiwiY2hhcnRXIiwiY2hhcnRIIiwicG9pbnRzIiwiaSIsIngiLCJ5IiwibGluZVBhdGgiLCJwIiwiam9pbiIsImFyZWFQYXRoIiwiZ3JpZExpbmVzIiwicGN0IiwibGFiZWwiLCJyb3VuZCIsInN0ZXAiLCJjZWlsIiwiUmVhY3QiLCJjcmVhdGVFbGVtZW50Iiwic3R5bGUiLCJvdmVyZmxvdyIsInZpZXdCb3giLCJwcmVzZXJ2ZUFzcGVjdFJhdGlvIiwiZGlzcGxheSIsIm1heFdpZHRoIiwiaWQiLCJ4MSIsInkxIiwieDIiLCJ5MiIsIm9mZnNldCIsInN0b3BDb2xvciIsInN0b3BPcGFjaXR5IiwiZyIsImtleSIsInN0cm9rZSIsInN0cm9rZVdpZHRoIiwic3Ryb2tlRGFzaGFycmF5IiwiZmlsbCIsImZvbnRTaXplIiwiZm9udEZhbWlseSIsInRleHRBbmNob3IiLCJzdHJva2VMaW5lam9pbiIsInN0cm9rZUxpbmVjYXAiLCJzaG93TGFiZWwiLCJjeCIsImN5IiwiciIsIkRvbnV0Q2hhcnQiLCJzaXplIiwidG90YWwiLCJyZWR1Y2UiLCJzIiwib3V0ZXJSIiwiaW5uZXJSIiwiY3VtQW5nbGUiLCJQSSIsInNsaWNlcyIsImFuZ2xlIiwic3RhcnRBbmdsZSIsImVuZEFuZ2xlIiwiY29zIiwic2luIiwiaXgxIiwiaXkxIiwiaXgyIiwiaXkyIiwibGFyZ2VBcmMiLCJwYXRoIiwibmFtZSIsImFsaWduSXRlbXMiLCJnYXAiLCJmbGV4V3JhcCIsImp1c3RpZnlDb250ZW50IiwiZm9udFdlaWdodCIsImZsZXhEaXJlY3Rpb24iLCJmbGV4U2hyaW5rIiwibWFyZ2luTGVmdCIsIlN0YXRDYXJkIiwiaWNvbiIsImRlbHRhIiwiZGVsdGFMYWJlbCIsIkJveCIsImZsZXgiLCJtaW5XaWR0aCIsIm9uTW91c2VFbnRlciIsImUiLCJjdXJyZW50VGFyZ2V0IiwiYm9yZGVyQ29sb3IiLCJ0cmFuc2Zvcm0iLCJib3hTaGFkb3ciLCJvbk1vdXNlTGVhdmUiLCJib3JkZXJMZWZ0Q29sb3IiLCJtYXJnaW5Cb3R0b20iLCJJY29uIiwiVGV4dCIsInRleHRUcmFuc2Zvcm0iLCJsZXR0ZXJTcGFjaW5nIiwiSDIiLCJtYXJnaW4iLCJ1bmRlZmluZWQiLCJBY3Rpb25DYXJkIiwiY291bnQiLCJyZXNvdXJjZUlkIiwiaHJlZiIsInRleHREZWNvcmF0aW9uIiwiSDUiLCJmbXREYXRlIiwiZHQiLCJEYXRlIiwidG9Mb2NhbGVEYXRlU3RyaW5nIiwibW9udGgiLCJkYXkiLCJ5ZWFyIiwic3RhdHVzQ29sb3IiLCJsb3dlciIsInRvTG93ZXJDYXNlIiwiQ3VzdG9tRGFzaGJvYXJkIiwic2V0RGF0YSIsInVzZVN0YXRlIiwibG9hZGluZyIsInNldExvYWRpbmciLCJlcnJvciIsInNldEVycm9yIiwidXNlRWZmZWN0IiwiZ2V0RGFzaGJvYXJkIiwidGhlbiIsInJlc3BvbnNlIiwiY2F0Y2giLCJmZXRjaEVycm9yIiwiY29uc29sZSIsIm1pbkhlaWdodCIsInRleHRBbGlnbiIsImJvcmRlclRvcENvbG9yIiwiYW5pbWF0aW9uIiwic3RhdHMiLCJhY3Rpb25SZXF1aXJlZCIsIm1vZHNCeVBsYXRmb3JtIiwidXNlckdyb3d0aERhdGEiLCJyZWNlbnRVc2VycyIsInJlY2VudE1vZHMiLCJncm93dGhDaGFydERhdGEiLCJkYXRlIiwidXNlcnMiLCJub3ciLCJncmVldGluZyIsImdldEhvdXJzIiwicGFkZGluZ0JvdHRvbSIsImJvcmRlckJvdHRvbSIsInRleHRTaGFkb3ciLCJiYWNrZ3JvdW5kIiwibWFyZ2luVG9wIiwibGluZUhlaWdodCIsIndlZWtkYXkiLCJ0aXRsZSIsInRhcmdldCIsInJlbCIsInRvdGFsVXNlcnMiLCJ0b0xvY2FsZVN0cmluZyIsIm5ld1VzZXJzVGhpc01vbnRoIiwidG90YWxNb2RzIiwibmV3TW9kc1RoaXNNb250aCIsInRvdGFsRG93bmxvYWRzIiwidG90YWxWaWV3cyIsInBlbmRpbmdSZXBvcnRzIiwicGVuZGluZ0FwcHJvdmFscyIsIm9wZW5UaWNrZXRzIiwiQmFkZ2UiLCJvdmVyZmxvd1giLCJXZWJraXRPdmVyZmxvd1Njcm9sbGluZyIsImJvcmRlckNvbGxhcHNlIiwidSIsInVzZXJuYW1lIiwicm9sZSIsIm0iLCJ0ZXh0T3ZlcmZsb3ciLCJ3aGl0ZVNwYWNlIiwiY2F0ZWdvcnkiLCJzdGF0dXMiLCJwYWRkaW5nVG9wIiwiYm9yZGVyVG9wIiwiU2lkZWJhckJyYW5kaW5nIiwicG9zaXRpb24iLCJib3R0b20iLCJsZWZ0Iiwib3BhY2l0eSIsInNyYyIsImFsdCIsIm9iamVjdEZpdCIsImZpbHRlciIsIm9uRXJyb3IiLCJBY3Rpb25SZWRpcmVjdCIsInByb3BzIiwicmVjb3JkIiwiYWN0aW9uIiwic2VuZE5vdGljZSIsInVzZU5vdGljZSIsInVybCIsInBhcmFtcyIsInJlZGlyZWN0VXJsIiwiYWN0aW9uTmFtZSIsInJlY0lkIiwiX2lkIiwiaXNWYXIiLCJpc1ZhcmlhbnQiLCJtYXN0ZXJJZCIsIm1hc3RlckZpbGUiLCJ2dEhhc2giLCJ2aXJ1c1RvdGFsSWQiLCJ2dEFuYWx5c2lzIiwidmlydXNUb3RhbEFuYWx5c2lzSWQiLCJtZXNzYWdlIiwidHlwZSIsInN0YXJ0c1dpdGgiLCJ3aW5kb3ciLCJsb2NhdGlvbiIsIm9wZW4iLCJzZXRUaW1lb3V0IiwiaGlzdG9yeSIsImJhY2siLCJMb2FkZXIiLCJtdCIsInZhcmlhbnQiLCJCdXR0b24iLCJvbkNsaWNrIiwibWFyZ2luUmlnaHQiLCJEb3dubG9hZEluc3BlY3RvciIsImNvcGllZCIsInNldENvcGllZCIsInZlcmlmeWluZyIsInNldFZlcmlmeWluZyIsInZlcmlmaWNhdGlvblJlc3VsdCIsInNldFZlcmlmaWNhdGlvblJlc3VsdCIsInNob3dEb3dubG9hZENvbmZpcm0iLCJzZXRTaG93RG93bmxvYWRDb25maXJtIiwiZmlsZUlkIiwiZmlsZU5hbWUiLCJmaWxlVmVyc2lvbiIsInZlcnNpb24iLCJmaWxlU2l6ZSIsImV4dGVybmFsVXJsIiwiZXh0ZXJuYWxEb3dubG9hZFVybCIsImZpbGVLZXkiLCJkaXJlY3RVcmwiLCJkaXJlY3REb3dubG9hZFVybCIsImlzTXVsdGlQYXJ0IiwicHJpbWFyeURvd25sb2FkVXJsIiwib3JpZ2luIiwiaGFuZGxlQ29weSIsInVybFRvQ29weSIsIm5hdmlnYXRvciIsImNsaXBib2FyZCIsIndyaXRlVGV4dCIsImhhbmRsZVZlcmlmeUVuZHBvaW50IiwiY29udHJvbGxlciIsIkFib3J0Q29udHJvbGxlciIsInRpbWVvdXRJZCIsImFib3J0IiwiZmV0Y2giLCJtZXRob2QiLCJzaWduYWwiLCJoZWFkZXJzIiwiY2xlYXJUaW1lb3V0IiwiaXNPayIsImNvbnRlbnRUeXBlIiwiZ2V0IiwiY29udGVudExlbmd0aCIsInN0YXR1c1RleHQiLCJ0aW1lc3RhbXAiLCJ0b0xvY2FsZVRpbWVTdHJpbmciLCJlcnIiLCJoYW5kbGVDb25maXJtRG93bmxvYWQiLCJoYW5kbGVCYWNrIiwibWIiLCJ3b3JkQnJlYWsiLCJkaXNhYmxlZCIsInB0IiwiVmFyaWFudEJhZGdlIiwicHJvcGVydHkiLCJyZWNvcmRJZCIsImhhbmRsZUNsaWNrIiwicHJldmVudERlZmF1bHQiLCJzdG9wUHJvcGFnYXRpb24iLCJjbGFzc05hbWUiLCJBdmF0YXJDZWxsIiwid2hlcmUiLCJpbWFnZVVybCIsInNldEltYWdlVXJsIiwiaGFzRXJyb3IiLCJzZXRIYXNFcnJvciIsImZldGNoU2lnbmVkVXJsIiwiZW5jb2RlVVJJQ29tcG9uZW50Iiwib2siLCJqc29uIiwiZGVmYXVsdEF2YXRhciIsIkltYWdlUHJldmlldyIsImlzQXZhdGFyIiwiZGVmYXVsdEltYWdlIiwiZGlzcGxheVVybCIsInJhZGl1cyIsIkFkbWluSlMiLCJVc2VyQ29tcG9uZW50cyIsImVudiIsIk5PREVfRU5WIiwiRGFzaGJvYXJkIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0VBSUEsTUFBTUEsR0FBRyxHQUFHLElBQUlDLGlCQUFTLEVBQUU7O0VBRTNCO0VBQ0EsTUFBTUMsQ0FBQyxHQUFHO0VBQ1JDLEVBQUFBLEVBQUUsRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE9BQU8sRUFBRSxTQUFTO0VBQUVDLEVBQUFBLFVBQVUsRUFBRSxTQUFTO0VBQ3hEQyxFQUFBQSxNQUFNLEVBQUUsU0FBUztF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
