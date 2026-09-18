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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIiwic291cmNlcyI6WyIuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQuanN4IiwiLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nLmpzeCIsIi4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdC5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL1ZhcmlhbnRCYWRnZS5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL0F2YXRhckNlbGwuanN4IiwiLi4vY29tcG9uZW50cy9jZWxscy9JbWFnZVByZXZpZXcuanN4IiwiLi4vY29tcG9uZW50cy9hY3Rpb25zL01hbmFnZVZvdGVzLmpzeCIsImVudHJ5LmpzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQXBpQ2xpZW50IH0gZnJvbSAnYWRtaW5qcyc7XG5pbXBvcnQgeyBCb3gsIEgyLCBINSwgVGV4dCwgSWNvbiwgQmFkZ2UgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgYXBpID0gbmV3IEFwaUNsaWVudCgpO1xuXG4vKiDilIDilIDilIAgY29sb3VyIHRva2VucyDilIDilIDilIAgKi9cbmNvbnN0IEMgPSB7XG4gIGJnOiAnIzBhMGEwYScsIHN1cmZhY2U6ICcjMTMxMzEzJywgc3VyZmFjZUFsdDogJyMxYTFhMWEnLFxuICBib3JkZXI6ICcjMmEyYTJhJywgYm9yZGVySG92ZXI6ICcjM2EzYTNhJyxcbiAgZ29sZDogJyNGRkQ3MDAnLCBnb2xkRGltOiAncmdiYSgyNTUsMjE1LDAsMC4xNSknLCBnb2xkR2xvdzogJ3JnYmEoMjU1LDIxNSwwLDAuMzUpJyxcbiAgYmx1ZTogJyMyMTk2RjMnLCBncmVlbjogJyM0M2EwNDcnLCBwdXJwbGU6ICcjOUMyN0IwJywgcmVkOiAnI2U1MzkzNScsIG9yYW5nZTogJyNGRjk4MDAnLFxuICB0ZXh0OiAnI2ZmZmZmZicsIHRleHRNdXRlZDogJyNlMmU4ZjAnLCB0ZXh0RGltOiAnI2NiZDVlMScsXG59O1xuXG4vKiDilIDilIDilIAgcGxhdGZvcm0gY2hhcnQgY29sb3VycyDilIDilIDilIAgKi9cbmNvbnN0IFBMQVRGT1JNX0NPTE9SUyA9IFsnI0E0QzYzOScsICcjMDA3OEQ2JywgJyMyMTc1OUInLCAnI0ZGOTgwMCcsICcjOUMyN0IwJywgJyNlNTM5MzUnLCAnIzQzYTA0NycsICcjRkZENzAwJ107XG5cbi8qIOKUgOKUgOKUgCByZXVzYWJsZSBjYXJkIHN0eWxlIOKUgOKUgOKUgCAqL1xuY29uc3QgY2FyZFN0eWxlID0gKGFjY2VudENvbG9yKSA9PiAoe1xuICBiYWNrZ3JvdW5kQ29sb3I6IEMuc3VyZmFjZSxcbiAgYm9yZGVyUmFkaXVzOiAnMTZweCcsXG4gIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsXG4gIGJvcmRlckxlZnQ6IGFjY2VudENvbG9yID8gYDRweCBzb2xpZCAke2FjY2VudENvbG9yfWAgOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCxcbiAgcGFkZGluZzogJ2NsYW1wKDE2cHgsIDIuNXZ3LCAyNHB4KScsXG4gIHRyYW5zaXRpb246ICdhbGwgMC4yNXMgZWFzZScsXG4gIGN1cnNvcjogJ2RlZmF1bHQnLFxuICBib3hTaXppbmc6ICdib3JkZXItYm94Jyxcbn0pO1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBBcmVhIENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgQXJlYUNoYXJ0ID0gKHsgZGF0YSwgd2lkdGggPSA1MDAsIGhlaWdodCA9IDE3MCwgY29sb3IgPSBDLmdvbGQgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBtYXhWYWwgPSBNYXRoLm1heCguLi5kYXRhLm1hcChkID0+IGQudmFsdWUpLCAxKTtcbiAgY29uc3QgcGFkWCA9IDM1O1xuICBjb25zdCBwYWRZID0gMTY7XG4gIGNvbnN0IGNoYXJ0VyA9IHdpZHRoIC0gcGFkWCAqIDI7XG4gIGNvbnN0IGNoYXJ0SCA9IGhlaWdodCAtIHBhZFkgKiAyO1xuXG4gIGNvbnN0IHBvaW50cyA9IGRhdGEubWFwKChkLCBpKSA9PiAoe1xuICAgIHg6IHBhZFggKyAoaSAvIE1hdGgubWF4KGRhdGEubGVuZ3RoIC0gMSwgMSkpICogY2hhcnRXLFxuICAgIHk6IHBhZFkgKyBjaGFydEggLSAoZC52YWx1ZSAvIG1heFZhbCkgKiBjaGFydEgsXG4gIH0pKTtcblxuICBjb25zdCBsaW5lUGF0aCA9IHBvaW50cy5tYXAoKHAsIGkpID0+IGAke2kgPT09IDAgPyAnTScgOiAnTCd9JHtwLnh9LCR7cC55fWApLmpvaW4oJyAnKTtcbiAgY29uc3QgYXJlYVBhdGggPSBgJHtsaW5lUGF0aH0gTCR7cG9pbnRzW3BvaW50cy5sZW5ndGggLSAxXS54fSwke3BhZFkgKyBjaGFydEh9IEwke3BvaW50c1swXS54fSwke3BhZFkgKyBjaGFydEh9IFpgO1xuXG4gIC8vIEdyaWQgbGluZXNcbiAgY29uc3QgZ3JpZExpbmVzID0gWzAsIDAuMjUsIDAuNSwgMC43NSwgMV0ubWFwKHBjdCA9PiB7XG4gICAgY29uc3QgeSA9IHBhZFkgKyBjaGFydEggLSBwY3QgKiBjaGFydEg7XG4gICAgY29uc3QgbGFiZWwgPSBNYXRoLnJvdW5kKHBjdCAqIG1heFZhbCk7XG4gICAgcmV0dXJuIHsgeSwgbGFiZWwgfTtcbiAgfSk7XG5cbiAgY29uc3Qgc3RlcCA9IGRhdGEubGVuZ3RoID4gOCA/IE1hdGguY2VpbChkYXRhLmxlbmd0aCAvIDUpIDogMTtcblxuICByZXR1cm4gKFxuICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6ICcxMDAlJywgb3ZlcmZsb3c6ICdoaWRkZW4nIH19PlxuICAgICAgPHN2ZyB3aWR0aD1cIjEwMCVcIiBoZWlnaHQ9e2hlaWdodH0gdmlld0JveD17YDAgMCAke3dpZHRofSAke2hlaWdodH1gfSBwcmVzZXJ2ZUFzcGVjdFJhdGlvPVwibm9uZVwiIHN0eWxlPXt7IGRpc3BsYXk6ICdibG9jaycsIG1heFdpZHRoOiAnMTAwJScgfX0+XG4gICAgICAgIDxkZWZzPlxuICAgICAgICAgIDxsaW5lYXJHcmFkaWVudCBpZD1cImFyZWFGaWxsXCIgeDE9XCIwXCIgeTE9XCIwXCIgeDI9XCIwXCIgeTI9XCIxXCI+XG4gICAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIwJVwiIHN0b3BDb2xvcj17Y29sb3J9IHN0b3BPcGFjaXR5PVwiMC4zNVwiIC8+XG4gICAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIxMDAlXCIgc3RvcENvbG9yPXtjb2xvcn0gc3RvcE9wYWNpdHk9XCIwLjAyXCIgLz5cbiAgICAgICAgICA8L2xpbmVhckdyYWRpZW50PlxuICAgICAgICA8L2RlZnM+XG4gICAgICAgIHsvKiBHcmlkICovfVxuICAgICAgICB7Z3JpZExpbmVzLm1hcCgoZywgaSkgPT4gKFxuICAgICAgICAgIDxnIGtleT17aX0+XG4gICAgICAgICAgICA8bGluZSB4MT17cGFkWH0geTE9e2cueX0geDI9e3dpZHRoIC0gcGFkWH0geTI9e2cueX0gc3Ryb2tlPXtDLmJvcmRlcn0gc3Ryb2tlV2lkdGg9XCIxXCIgc3Ryb2tlRGFzaGFycmF5PVwiMyAzXCIgLz5cbiAgICAgICAgICAgIDx0ZXh0IHg9e3BhZFggLSA2fSB5PXtnLnkgKyA0fSBmaWxsPVwiIzk0YTNiOFwiIGZvbnRTaXplPVwiOVwiIGZvbnRGYW1pbHk9XCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB0ZXh0QW5jaG9yPVwiZW5kXCI+e2cubGFiZWx9PC90ZXh0PlxuICAgICAgICAgIDwvZz5cbiAgICAgICAgKSl9XG4gICAgICAgIHsvKiBBcmVhIGZpbGwgKi99XG4gICAgICAgIDxwYXRoIGQ9e2FyZWFQYXRofSBmaWxsPVwidXJsKCNhcmVhRmlsbClcIiAvPlxuICAgICAgICB7LyogTGluZSAqL31cbiAgICAgICAgPHBhdGggZD17bGluZVBhdGh9IGZpbGw9XCJub25lXCIgc3Ryb2tlPXtjb2xvcn0gc3Ryb2tlV2lkdGg9XCIyLjVcIiBzdHJva2VMaW5lam9pbj1cInJvdW5kXCIgc3Ryb2tlTGluZWNhcD1cInJvdW5kXCIgLz5cbiAgICAgICAgey8qIERvdHMgKyBsYWJlbHMgKi99XG4gICAgICAgIHtwb2ludHMubWFwKChwLCBpKSA9PiB7XG4gICAgICAgICAgY29uc3Qgc2hvd0xhYmVsID0gKGkgPT09IDAgfHwgaSA9PT0gZGF0YS5sZW5ndGggLSAxIHx8IGkgJSBzdGVwID09PSAwKTtcbiAgICAgICAgICByZXR1cm4gKFxuICAgICAgICAgICAgPGcga2V5PXtpfT5cbiAgICAgICAgICAgICAgPGNpcmNsZSBjeD17cC54fSBjeT17cC55fSByPVwiM1wiIGZpbGw9e0MuYmd9IHN0cm9rZT17Y29sb3J9IHN0cm9rZVdpZHRoPVwiMlwiIC8+XG4gICAgICAgICAgICAgIHtzaG93TGFiZWwgJiYgKFxuICAgICAgICAgICAgICAgIDx0ZXh0IHg9e3AueH0geT17cGFkWSArIGNoYXJ0SCArIDE0fSBmaWxsPVwiI2NiZDVlMVwiIGZvbnRTaXplPVwiOVwiIGZvbnRGYW1pbHk9XCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e2RhdGFbaV0ubGFiZWx9PC90ZXh0PlxuICAgICAgICAgICAgICApfVxuICAgICAgICAgICAgPC9nPlxuICAgICAgICAgICk7XG4gICAgICAgIH0pfVxuICAgICAgPC9zdmc+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBEb251dCBDaGFydCDilIDilIDilIAgKi9cbmNvbnN0IERvbnV0Q2hhcnQgPSAoeyBkYXRhLCBzaXplID0gMjAwIH0pID0+IHtcbiAgaWYgKCFkYXRhIHx8IGRhdGEubGVuZ3RoID09PSAwKSByZXR1cm4gbnVsbDtcbiAgY29uc3QgdG90YWwgPSBkYXRhLnJlZHVjZSgocywgZCkgPT4gcyArIGQudmFsdWUsIDApO1xuICBpZiAodG90YWwgPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBjeCA9IHNpemUgLyAyO1xuICBjb25zdCBjeSA9IHNpemUgLyAyO1xuICBjb25zdCBvdXRlclIgPSBzaXplIC8gMiAtIDEwO1xuICBjb25zdCBpbm5lclIgPSBvdXRlclIgKiAwLjY7XG4gIGxldCBjdW1BbmdsZSA9IC1NYXRoLlBJIC8gMjtcblxuICBjb25zdCBzbGljZXMgPSBkYXRhLm1hcCgoZCwgaSkgPT4ge1xuICAgIGNvbnN0IGFuZ2xlID0gKGQudmFsdWUgLyB0b3RhbCkgKiBNYXRoLlBJICogMjtcbiAgICBjb25zdCBzdGFydEFuZ2xlID0gY3VtQW5nbGU7XG4gICAgY3VtQW5nbGUgKz0gYW5nbGU7XG4gICAgY29uc3QgZW5kQW5nbGUgPSBjdW1BbmdsZTtcblxuICAgIGNvbnN0IHgxID0gY3ggKyBvdXRlclIgKiBNYXRoLmNvcyhzdGFydEFuZ2xlKTtcbiAgICBjb25zdCB5MSA9IGN5ICsgb3V0ZXJSICogTWF0aC5zaW4oc3RhcnRBbmdsZSk7XG4gICAgY29uc3QgeDIgPSBjeCArIG91dGVyUiAqIE1hdGguY29zKGVuZEFuZ2xlKTtcbiAgICBjb25zdCB5MiA9IGN5ICsgb3V0ZXJSICogTWF0aC5zaW4oZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl4MSA9IGN4ICsgaW5uZXJSICogTWF0aC5jb3MoZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl5MSA9IGN5ICsgaW5uZXJSICogTWF0aC5zaW4oZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl4MiA9IGN4ICsgaW5uZXJSICogTWF0aC5jb3Moc3RhcnRBbmdsZSk7XG4gICAgY29uc3QgaXkyID0gY3kgKyBpbm5lclIgKiBNYXRoLnNpbihzdGFydEFuZ2xlKTtcbiAgICBjb25zdCBsYXJnZUFyYyA9IGFuZ2xlID4gTWF0aC5QSSA/IDEgOiAwO1xuICAgIGNvbnN0IGNvbG9yID0gUExBVEZPUk1fQ09MT1JTW2kgJSBQTEFURk9STV9DT0xPUlMubGVuZ3RoXTtcblxuICAgIGNvbnN0IHBhdGggPSBgTSR7eDF9LCR7eTF9IEEke291dGVyUn0sJHtvdXRlclJ9IDAgJHtsYXJnZUFyY30gMSAke3gyfSwke3kyfSBMJHtpeDF9LCR7aXkxfSBBJHtpbm5lclJ9LCR7aW5uZXJSfSAwICR7bGFyZ2VBcmN9IDAgJHtpeDJ9LCR7aXkyfSBaYDtcbiAgICByZXR1cm4geyBwYXRoLCBjb2xvciwgbmFtZTogZC5uYW1lLCB2YWx1ZTogZC52YWx1ZSwgcGN0OiBNYXRoLnJvdW5kKChkLnZhbHVlIC8gdG90YWwpICogMTAwKSB9O1xuICB9KTtcblxuICByZXR1cm4gKFxuICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMjRweCcsIGZsZXhXcmFwOiAnd3JhcCcsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgIDxzdmcgd2lkdGg9e3NpemV9IGhlaWdodD17c2l6ZX0gdmlld0JveD17YDAgMCAke3NpemV9ICR7c2l6ZX1gfT5cbiAgICAgICAge3NsaWNlcy5tYXAoKHMsIGkpID0+IChcbiAgICAgICAgICA8cGF0aCBrZXk9e2l9IGQ9e3MucGF0aH0gZmlsbD17cy5jb2xvcn0gc3Ryb2tlPXtDLmJnfSBzdHJva2VXaWR0aD1cIjJcIj5cbiAgICAgICAgICAgIDx0aXRsZT57cy5uYW1lfToge3MudmFsdWV9ICh7cy5wY3R9JSk8L3RpdGxlPlxuICAgICAgICAgIDwvcGF0aD5cbiAgICAgICAgKSl9XG4gICAgICAgIDx0ZXh0IHg9e2N4fSB5PXtjeSAtIDZ9IGZpbGw9e0MudGV4dH0gZm9udFNpemU9XCIyMlwiIGZvbnRXZWlnaHQ9XCJib2xkXCIgdGV4dEFuY2hvcj1cIm1pZGRsZVwiPnt0b3RhbH08L3RleHQ+XG4gICAgICAgIDx0ZXh0IHg9e2N4fSB5PXtjeSArIDE0fSBmaWxsPXtDLnRleHRNdXRlZH0gZm9udFNpemU9XCIxMFwiIHRleHRBbmNob3I9XCJtaWRkbGVcIj5UT1RBTDwvdGV4dD5cbiAgICAgIDwvc3ZnPlxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhEaXJlY3Rpb246ICdjb2x1bW4nLCBnYXA6ICc2cHgnIH19PlxuICAgICAgICB7c2xpY2VzLm1hcCgocywgaSkgPT4gKFxuICAgICAgICAgIDxkaXYga2V5PXtpfSBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnIH19PlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgd2lkdGg6IDEyLCBoZWlnaHQ6IDEyLCBib3JkZXJSYWRpdXM6ICczcHgnLCBiYWNrZ3JvdW5kQ29sb3I6IHMuY29sb3IsIGRpc3BsYXk6ICdpbmxpbmUtYmxvY2snLCBmbGV4U2hyaW5rOiAwIH19IC8+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy50ZXh0IH19PntzLm5hbWV9PC9zcGFuPlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgbWFyZ2luTGVmdDogJ2F1dG8nIH19PntzLnZhbHVlfSAoe3MucGN0fSUpPC9zcGFuPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICApKX1cbiAgICAgIDwvZGl2PlxuICAgIDwvZGl2PlxuICApO1xufTtcblxuLyog4pSA4pSA4pSAIFN0YXQgQ2FyZCDilIDilIDilIAgKi9cbmNvbnN0IFN0YXRDYXJkID0gKHsgaWNvbiwgbGFiZWwsIHZhbHVlLCBkZWx0YSwgZGVsdGFMYWJlbCwgYWNjZW50Q29sb3IgfSkgPT4gKFxuICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZShhY2NlbnRDb2xvciksIGZsZXg6ICcxJywgbWluV2lkdGg6ICcyMjBweCcgfX1cbiAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBhY2NlbnRDb2xvciB8fCBDLmJvcmRlckhvdmVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoLTJweCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gYDAgOHB4IDI0cHggcmdiYSgwLDAsMCwwLjQpYDsgfX1cbiAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckxlZnRDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoMCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJ25vbmUnOyB9fVxuICA+XG4gICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcxNHB4JyB9fT5cbiAgICAgIDxJY29uIGljb249e2ljb259IGNvbG9yPXthY2NlbnRDb2xvcn0gLz5cbiAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMXB4JywgZm9udFdlaWdodDogNzAwLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDhlbScgfX0+e2xhYmVsfTwvVGV4dD5cbiAgICA8L2Rpdj5cbiAgICA8SDIgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAnMCAwIDhweCAwJywgZm9udFNpemU6ICcyLjJyZW0nIH19Pnt2YWx1ZX08L0gyPlxuICAgIHtkZWx0YSAhPT0gdW5kZWZpbmVkICYmIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JyB9fT5cbiAgICAgICAgPEljb24gaWNvbj1cIkFycm93VXBcIiBzaXplPXsxNH0gY29sb3I9e0MuZ3JlZW59IC8+XG4gICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLmdyZWVuLCBmb250U2l6ZTogJzEzcHgnLCBmb250V2VpZ2h0OiA2MDAgfX0+K3tkZWx0YX0ge2RlbHRhTGFiZWwgfHwgJ3RoaXMgbW9udGgnfTwvVGV4dD5cbiAgICAgIDwvZGl2PlxuICAgICl9XG4gIDwvQm94PlxuKTtcblxuLyog4pSA4pSA4pSAIEFjdGlvbiBCYWRnZSBDYXJkIOKUgOKUgOKUgCAqL1xuY29uc3QgQWN0aW9uQ2FyZCA9ICh7IGljb24sIGxhYmVsLCBjb3VudCwgYWNjZW50Q29sb3IsIHJlc291cmNlSWQgfSkgPT4gKFxuICA8YSBocmVmPXtgL2FkbWluL3Jlc291cmNlcy8ke3Jlc291cmNlSWR9YH0gc3R5bGU9e3sgdGV4dERlY29yYXRpb246ICdub25lJywgZmxleDogJzEnLCBtaW5XaWR0aDogJzE4MHB4JyB9fT5cbiAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZShhY2NlbnRDb2xvciksIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzE2cHgnIH19XG4gICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBhY2NlbnRDb2xvcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLnRyYW5zZm9ybSA9ICd0cmFuc2xhdGVZKC0ycHgpJzsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJveFNoYWRvdyA9IGAwIDZweCAyMHB4IHJnYmEoMCwwLDAsMC4zKWA7IH19XG4gICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckxlZnRDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoMCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJ25vbmUnOyB9fVxuICAgID5cbiAgICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6IDQ0LCBoZWlnaHQ6IDQ0LCBib3JkZXJSYWRpdXM6ICcxMnB4JywgYmFja2dyb3VuZENvbG9yOiBgJHthY2NlbnRDb2xvcn0xNWAsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJywgZmxleFNocmluazogMCB9fT5cbiAgICAgICAgPEljb24gaWNvbj17aWNvbn0gc2l6ZT17MjJ9IGNvbG9yPXthY2NlbnRDb2xvcn0gLz5cbiAgICAgIDwvZGl2PlxuICAgICAgPGRpdj5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzExcHgnLCBmb250V2VpZ2h0OiA2MDAsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJyB9fT57bGFiZWx9PC9UZXh0PlxuICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IGNvdW50ID4gMCA/IGFjY2VudENvbG9yIDogQy50ZXh0RGltLCBtYXJnaW46ICc0cHggMCAwIDAnIH19Pntjb3VudH08L0g1PlxuICAgICAgPC9kaXY+XG4gICAgICA8SWNvbiBpY29uPVwiQ2hldnJvblJpZ2h0XCIgY29sb3I9e0MudGV4dERpbX0gc3R5bGU9e3sgbWFyZ2luTGVmdDogJ2F1dG8nIH19IC8+XG4gICAgPC9Cb3g+XG4gIDwvYT5cbik7XG5cbi8qIOKUgOKUgOKUgCBGb3JtYXQgZGF0ZSBuaWNlbHkg4pSA4pSA4pSAICovXG5jb25zdCBmbXREYXRlID0gKGQpID0+IHtcbiAgaWYgKCFkKSByZXR1cm4gJ+KAlCc7XG4gIGNvbnN0IGR0ID0gbmV3IERhdGUoZCk7XG4gIHJldHVybiBkdC50b0xvY2FsZURhdGVTdHJpbmcoJ2VuLVVTJywgeyBtb250aDogJ3Nob3J0JywgZGF5OiAnbnVtZXJpYycsIHllYXI6ICdudW1lcmljJyB9KTtcbn07XG5cbi8qIOKUgOKUgOKUgCBTdGF0dXMgYmFkZ2UgY29sb3Ig4pSA4pSA4pSAICovXG5jb25zdCBzdGF0dXNDb2xvciA9IChzKSA9PiB7XG4gIGlmICghcykgcmV0dXJuIEMudGV4dERpbTtcbiAgY29uc3QgbG93ZXIgPSBzLnRvTG93ZXJDYXNlKCk7XG4gIGlmIChsb3dlciA9PT0gJ2FwcHJvdmVkJyB8fCBsb3dlciA9PT0gJ2FjdGl2ZScpIHJldHVybiBDLmdyZWVuO1xuICBpZiAobG93ZXIgPT09ICdwZW5kaW5nJykgcmV0dXJuIEMub3JhbmdlO1xuICBpZiAobG93ZXIgPT09ICdyZWplY3RlZCcpIHJldHVybiBDLnJlZDtcbiAgcmV0dXJuIEMudGV4dE11dGVkO1xufTtcblxuLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4gICBNQUlOIERBU0hCT0FSRCBDT01QT05FTlRcbiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqL1xuY29uc3QgQ3VzdG9tRGFzaGJvYXJkID0gKCkgPT4ge1xuICBjb25zdCBbZGF0YSwgc2V0RGF0YV0gPSB1c2VTdGF0ZShudWxsKTtcbiAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG4gIGNvbnN0IFtlcnJvciwgc2V0RXJyb3JdID0gdXNlU3RhdGUobnVsbCk7XG5cbiAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICBhcGkuZ2V0RGFzaGJvYXJkKClcbiAgICAgIC50aGVuKChyZXNwb25zZSkgPT4ge1xuICAgICAgICBzZXREYXRhKHJlc3BvbnNlLmRhdGEgfHwge30pO1xuICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goKGZldGNoRXJyb3IpID0+IHtcbiAgICAgICAgY29uc29sZS5lcnJvcignRGFzaGJvYXJkIGZldGNoIGVycm9yOicsIGZldGNoRXJyb3IpO1xuICAgICAgICBzZXRFcnJvcignRmFpbGVkIHRvIGxvYWQgZGFzaGJvYXJkIGRhdGEuJyk7XG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgfSk7XG4gIH0sIFtdKTtcblxuICBpZiAobG9hZGluZykge1xuICAgIHJldHVybiAoXG4gICAgICA8ZGl2IHN0eWxlPXt7IG1pbkhlaWdodDogJzEwMHZoJywgYmFja2dyb3VuZENvbG9yOiBDLmJnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgIDxkaXYgc3R5bGU9e3sgdGV4dEFsaWduOiAnY2VudGVyJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IHdpZHRoOiA0MCwgaGVpZ2h0OiA0MCwgYm9yZGVyOiBgM3B4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgYm9yZGVyVG9wQ29sb3I6IEMuZ29sZCwgYm9yZGVyUmFkaXVzOiAnNTAlJywgYW5pbWF0aW9uOiAnc3BpbiAxcyBsaW5lYXIgaW5maW5pdGUnLCBtYXJnaW46ICcwIGF1dG8gMTZweCcgfX0gLz5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQgfX0+TG9hZGluZyBkYXNoYm9hcmQuLi48L1RleHQ+XG4gICAgICAgICAgPHN0eWxlPntgQGtleWZyYW1lcyBzcGluIHsgdG8geyB0cmFuc2Zvcm06IHJvdGF0ZSgzNjBkZWcpOyB9IH1gfTwvc3R5bGU+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG4gICAgKTtcbiAgfVxuXG4gIGlmIChlcnJvcikge1xuICAgIHJldHVybiAoXG4gICAgICA8ZGl2IHN0eWxlPXt7IG1pbkhlaWdodDogJzEwMHZoJywgYmFja2dyb3VuZENvbG9yOiBDLmJnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKEMucmVkKSwgbWF4V2lkdGg6IDQwMCwgdGV4dEFsaWduOiAnY2VudGVyJyB9fT5cbiAgICAgICAgICA8SWNvbiBpY29uPVwiQWxlcnRUcmlhbmdsZVwiIHNpemU9ezMyfSBjb2xvcj17Qy5yZWR9IC8+XG4gICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnJlZCwgbWFyZ2luOiAnMTZweCAwIDhweCcgfX0+e2Vycm9yfTwvSDU+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkIH19PkNoZWNrIHRoZSBzZXJ2ZXIgbG9ncyBmb3IgZGV0YWlscy48L1RleHQ+XG4gICAgICAgIDwvQm94PlxuICAgICAgPC9kaXY+XG4gICAgKTtcbiAgfVxuXG4gIGNvbnN0IHN0YXRzID0gZGF0YT8uc3RhdHMgfHwge307XG4gIGNvbnN0IGFjdGlvblJlcXVpcmVkID0gZGF0YT8uYWN0aW9uUmVxdWlyZWQgfHwge307XG4gIGNvbnN0IG1vZHNCeVBsYXRmb3JtID0gZGF0YT8ubW9kc0J5UGxhdGZvcm0gfHwgW107XG4gIGNvbnN0IHVzZXJHcm93dGhEYXRhID0gZGF0YT8udXNlckdyb3d0aERhdGEgfHwgW107XG4gIGNvbnN0IHJlY2VudFVzZXJzID0gZGF0YT8ucmVjZW50VXNlcnMgfHwgW107XG4gIGNvbnN0IHJlY2VudE1vZHMgPSBkYXRhPy5yZWNlbnRNb2RzIHx8IFtdO1xuXG4gIC8vIFByZXBhcmUgY2hhcnQgZGF0YVxuICBjb25zdCBncm93dGhDaGFydERhdGEgPSB1c2VyR3Jvd3RoRGF0YS5tYXAoZCA9PiAoeyBsYWJlbDogZC5kYXRlLCB2YWx1ZTogZC51c2VycyB9KSk7XG5cbiAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgY29uc3QgZ3JlZXRpbmcgPSBub3cuZ2V0SG91cnMoKSA8IDEyID8gJ0dvb2QgbW9ybmluZycgOiBub3cuZ2V0SG91cnMoKSA8IDE4ID8gJ0dvb2QgYWZ0ZXJub29uJyA6ICdHb29kIGV2ZW5pbmcnO1xuXG4gIHJldHVybiAoXG4gICAgPGRpdiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIG1pbkhlaWdodDogJzEwMHZoJywgcGFkZGluZzogJ2NsYW1wKDE2cHgsIDN2dywgMzJweCkgY2xhbXAoMTRweCwgM3Z3LCAzNnB4KScsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+XG4gICAgICBcbiAgICAgIHsvKiDilZDilZDilZAgSEVBREVSIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBqdXN0aWZ5Q29udGVudDogJ3NwYWNlLWJldHdlZW4nLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMTZweCcsIHBhZGRpbmdCb3R0b206ICcyNHB4JywgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgbWFyZ2luQm90dG9tOiAnMjhweCcgfX0+XG4gICAgICAgIDxkaXY+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pblwiIHN0eWxlPXt7IHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBjdXJzb3I6ICdwb2ludGVyJyB9fT5cbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMTBweCcgfX0+XG4gICAgICAgICAgICAgIDxIMiBzdHlsZT17eyBtYXJnaW46IDAsIGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlxuICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLmdvbGQsIHRleHRTaGFkb3c6IGAwIDAgMjBweCAke0MuZ29sZEdsb3d9YCwgZm9udFdlaWdodDogODAwIH19PkdQTDwvc3Bhbj5cbiAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCB0ZXh0U2hhZG93OiAnMCAwIDE1cHggcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjQpJywgZm9udFdlaWdodDogNzAwIH19Pk1vZHM8L3NwYW4+XG4gICAgICAgICAgICAgIDwvSDI+XG4gICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZDcwMCcsIGZvbnRTaXplOiAnMTFweCcsIGZvbnRXZWlnaHQ6IDYwMCwgYmFja2dyb3VuZDogJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMTIpJywgcGFkZGluZzogJzRweCAxMHB4JywgYm9yZGVyUmFkaXVzOiAnMjBweCcsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwgMjE1LCAwLCAwLjM1KScsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIsIGxldHRlclNwYWNpbmc6ICcwLjA0ZW0nLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyB9fT5BZG1pbiBEYXNoYm9hcmQ8L3NwYW4+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICA8L2E+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjZjFmNWY5JywgbWFyZ2luVG9wOiAnOHB4JywgZm9udFNpemU6ICcxNHB4JywgZm9udFdlaWdodDogNDAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiLCBsaW5lSGVpZ2h0OiAxLjUgfX0+XG4gICAgICAgICAgICB7Z3JlZXRpbmd9ISBIZXJlJ3MgeW91ciBwbGF0Zm9ybSBvdmVydmlldyBmb3Ige25vdy50b0xvY2FsZURhdGVTdHJpbmcoJ2VuLVVTJywgeyB3ZWVrZGF5OiAnbG9uZycsIG1vbnRoOiAnbG9uZycsIGRheTogJ251bWVyaWMnLCB5ZWFyOiAnbnVtZXJpYycgfSl9LlxuICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgPC9kaXY+XG5cbiAgICAgICAgey8qIOKVkOKVkOKVkCBBRE1JTiBTVUlURSBTSE9SVENVVCBCVVRUT05TIOKVkOKVkOKVkCAqL31cbiAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcxMHB4JyB9fT5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvZGFzaGJvYXJkXCIgXG4gICAgICAgICAgICBzdHlsZT17eyBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JywgY29sb3I6IEMuZ29sZCwgYmFja2dyb3VuZENvbG9yOiBDLmdvbGREaW0sIGJvcmRlcjogYDFweCBzb2xpZCAke0MuZ29sZH1gLCBwYWRkaW5nOiAnOHB4IDE0cHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTNweCcsIHRyYW5zaXRpb246ICdhbGwgMC4ycycsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyNTUsMjE1LDAsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9IEMuZ29sZERpbTsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiR28gQmFjayBUbyBEYXNoYm9hcmRcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJBcnJvd0xlZnRcIiBzaXplPXsxNH0gLz4gR28gQmFjayBUbyBEYXNoYm9hcmRcbiAgICAgICAgICA8L2E+XG5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvYWRtaW4vcmVwb3J0c1wiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnI2ZmNmI2YicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjI5LDU3LDUzLDAuMTIpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjI5LDU3LDUzLDAuMyknLCBwYWRkaW5nOiAnOHB4IDE0cHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTNweCcsIHRyYW5zaXRpb246ICdhbGwgMC4ycycgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyMjksNTcsNTMsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDIyOSw1Nyw1MywwLjEyKSc7IH19XG4gICAgICAgICAgICB0aXRsZT1cIk1vZGVyYXRpb24gJiBNb2QgUmVwb3J0cyBDb25zb2xlXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiRmxhZ1wiIHNpemU9ezE0fSAvPiBSZXBvcnRzXG4gICAgICAgICAgPC9hPlxuXG4gICAgICAgICAgPGEgXG4gICAgICAgICAgICBocmVmPVwiL2FkbWluL3N1cHBvcnRcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyM2NGI1ZjYnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDMzLDE1MCwyNDMsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgzMywxNTAsMjQzLDAuMyknLCBwYWRkaW5nOiAnOHB4IDE0cHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTNweCcsIHRyYW5zaXRpb246ICdhbGwgMC4ycycgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgzMywxNTAsMjQzLDAuMjUpJzsgfX1cbiAgICAgICAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgzMywxNTAsMjQzLDAuMTIpJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiTGl2ZSBTdXBwb3J0ICYgSW5xdWlyaWVzIENvbnNvbGVcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJIZWxwQ2lyY2xlXCIgc2l6ZT17MTR9IC8+IFN1cHBvcnRcbiAgICAgICAgICA8L2E+XG5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvc3RhdHVzXCIgXG4gICAgICAgICAgICB0YXJnZXQ9XCJfYmxhbmtcIiBcbiAgICAgICAgICAgIHJlbD1cIm5vb3BlbmVyIG5vcmVmZXJyZXJcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyM4MWM3ODQnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDY3LDE2MCw3MSwwLjEyKScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDY3LDE2MCw3MSwwLjMpJywgcGFkZGluZzogJzhweCAxNHB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEzcHgnLCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoNjcsMTYwLDcxLDAuMjUpJzsgfX1cbiAgICAgICAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSg2NywxNjAsNzEsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJMaXZlIFNlcnZlciBIZWFsdGggJiBEaWFnbm9zdGljc1wiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkFjdGl2aXR5XCIgc2l6ZT17MTR9IC8+IFN0YXR1c1xuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9hZG1pbi9tdXNpY1wiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnI2JhNjhjOCcsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMTg2LDEwNCwyMDAsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgxODYsMTA0LDIwMCwwLjMpJywgcGFkZGluZzogJzhweCAxNHB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEzcHgnLCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMTg2LDEwNCwyMDAsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDE4NiwxMDQsMjAwLDAuMTIpJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiTXVzaWMgJiBQbGF5bGlzdCBNYW5hZ2VyXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiTXVzaWNcIiBzaXplPXsxNH0gLz4gTXVzaWNcbiAgICAgICAgICA8L2E+XG5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvaG9tZVwiIFxuICAgICAgICAgICAgdGFyZ2V0PVwiX2JsYW5rXCIgXG4gICAgICAgICAgICByZWw9XCJub29wZW5lciBub3JlZmVycmVyXCIgXG4gICAgICAgICAgICBzdHlsZT17eyBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JywgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiBDLnN1cmZhY2VBbHQsIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckNvbG9yID0gQy5nb2xkOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuY29sb3IgPSBDLmdvbGQ7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmNvbG9yID0gJyNmZmZmZmYnOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJPcGVuIExpdmUgUHVibGljIFNpdGVcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJHbG9iZVwiIHNpemU9ezE0fSAvPiBMaXZlIFNpdGVcbiAgICAgICAgICA8L2E+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgU1RBVCBDQVJEUyDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMTZweCcsIG1hcmdpbkJvdHRvbTogJzI0cHgnIH19PlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIlVzZXJzXCIgbGFiZWw9XCJUb3RhbCBVc2Vyc1wiIHZhbHVlPXsoc3RhdHMudG90YWxVc2VycyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBkZWx0YT17c3RhdHMubmV3VXNlcnNUaGlzTW9udGh9IGFjY2VudENvbG9yPXtDLmJsdWV9IC8+XG4gICAgICAgIDxTdGF0Q2FyZCBpY29uPVwiUGFja2FnZVwiIGxhYmVsPVwiVG90YWwgTW9kc1wiIHZhbHVlPXsoc3RhdHMudG90YWxNb2RzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGRlbHRhPXtzdGF0cy5uZXdNb2RzVGhpc01vbnRofSBhY2NlbnRDb2xvcj17Qy5nb2xkfSAvPlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIkRvd25sb2FkXCIgbGFiZWw9XCJUb3RhbCBEb3dubG9hZHNcIiB2YWx1ZT17KHN0YXRzLnRvdGFsRG93bmxvYWRzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGFjY2VudENvbG9yPXtDLmdyZWVufSAvPlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIkV5ZVwiIGxhYmVsPVwiVG90YWwgVmlld3NcIiB2YWx1ZT17KHN0YXRzLnRvdGFsVmlld3MgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gYWNjZW50Q29sb3I9e0MucHVycGxlfSAvPlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgQUNUSU9OIFJFUVVJUkVEIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcxNHB4JywgbWFyZ2luQm90dG9tOiAnMzJweCcgfX0+XG4gICAgICAgIDxBY3Rpb25DYXJkIGljb249XCJGbGFnXCIgbGFiZWw9XCJQZW5kaW5nIFJlcG9ydHNcIiBjb3VudD17YWN0aW9uUmVxdWlyZWQucGVuZGluZ1JlcG9ydHMgfHwgMH0gYWNjZW50Q29sb3I9e0MucmVkfSByZXNvdXJjZUlkPVwiUmVwb3J0XCIgLz5cbiAgICAgICAgPEFjdGlvbkNhcmQgaWNvbj1cIkNoZWNrU3F1YXJlXCIgbGFiZWw9XCJQZW5kaW5nIEFwcHJvdmFsc1wiIGNvdW50PXthY3Rpb25SZXF1aXJlZC5wZW5kaW5nQXBwcm92YWxzIHx8IDB9IGFjY2VudENvbG9yPXtDLm9yYW5nZX0gcmVzb3VyY2VJZD1cIkZpbGVcIiAvPlxuICAgICAgICA8QWN0aW9uQ2FyZCBpY29uPVwiSGVscENpcmNsZVwiIGxhYmVsPVwiT3BlbiBUaWNrZXRzXCIgY291bnQ9e2FjdGlvblJlcXVpcmVkLm9wZW5UaWNrZXRzIHx8IDB9IGFjY2VudENvbG9yPXtDLmJsdWV9IHJlc291cmNlSWQ9XCJTdXBwb3J0VGlja2V0XCIgLz5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIENIQVJUUyBST1cg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzIwcHgnLCBtYXJnaW5Cb3R0b206ICczMnB4JyB9fT5cbiAgICAgICAgey8qIFVzZXIgR3Jvd3RoIENoYXJ0ICovfVxuICAgICAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZSgpLCBmbGV4OiAnMiAxIDMyMHB4JywgbWluV2lkdGg6IDAsIHdpZHRoOiAnMTAwJScgfX0+XG4gICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcxOHB4JyB9fT5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJBY3Rpdml0eVwiIGNvbG9yPXtDLmdvbGR9IC8+XG4gICAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlVzZXIgR3Jvd3RoPC9INT5cbiAgICAgICAgICAgIDxCYWRnZSBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnOHB4JywgYmFja2dyb3VuZENvbG9yOiBDLmdvbGREaW0sIGNvbG9yOiBDLmdvbGQsIGJvcmRlcjogJ25vbmUnLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PjMwIGRheXM8L0JhZGdlPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIHtncm93dGhDaGFydERhdGEubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDxBcmVhQ2hhcnQgZGF0YT17Z3Jvd3RoQ2hhcnREYXRhfSBjb2xvcj17Qy5nb2xkfSB3aWR0aD17NTAwfSBoZWlnaHQ9ezE3MH0gLz5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBoZWlnaHQ6IDE2MCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInIH19PlxuICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19Pk5vIHVzZXIgc2lnbnVwcyBpbiB0aGUgbGFzdCAzMCBkYXlzLjwvVGV4dD5cbiAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvQm94PlxuXG4gICAgICAgIHsvKiBQbGF0Zm9ybSBEb251dCAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzEgMSAyODBweCcsIG1pbldpZHRoOiAwLCB3aWR0aDogJzEwMCUnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMThweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiUGllQ2hhcnRcIiBjb2xvcj17Qy5ibHVlfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5Nb2RzIGJ5IFBsYXRmb3JtPC9INT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7bW9kc0J5UGxhdGZvcm0ubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDxEb251dENoYXJ0IGRhdGE9e21vZHNCeVBsYXRmb3JtfSBzaXplPXsxODB9IC8+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgaGVpZ2h0OiAxNjAsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5ObyBwbGF0Zm9ybSBkYXRhIGF2YWlsYWJsZS48L1RleHQ+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIFJFQ0VOVCBBQ1RJVklUWSBST1cg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzIwcHgnLCBtYXJnaW5Cb3R0b206ICczMnB4JyB9fT5cbiAgICAgICAgey8qIFJlY2VudCBVc2VycyAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzEgMSAzMjBweCcsIG1pbldpZHRoOiAwLCB3aWR0aDogJzEwMCUnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMThweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiVXNlcnNcIiBjb2xvcj17Qy5ibHVlfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5SZWNlbnQgVXNlcnM8L0g1PlxuICAgICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvVXNlclwiIHN0eWxlPXt7IG1hcmdpbkxlZnQ6ICdhdXRvJywgY29sb3I6IEMuZ29sZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlZpZXcgQWxsIOKGkjwvYT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7cmVjZW50VXNlcnMubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgb3ZlcmZsb3dYOiAnYXV0bycsIHdpZHRoOiAnMTAwJScsIFdlYmtpdE92ZXJmbG93U2Nyb2xsaW5nOiAndG91Y2gnIH19PlxuICAgICAgICAgICAgICA8dGFibGUgc3R5bGU9e3sgd2lkdGg6ICcxMDAlJywgYm9yZGVyQ29sbGFwc2U6ICdjb2xsYXBzZScsIG1pbldpZHRoOiAnMzAwcHgnIH19PlxuICAgICAgICAgICAgICAgIDx0aGVhZD5cbiAgICAgICAgICAgICAgICAgIDx0ciBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PlVzZXJuYW1lPC90aD5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5Sb2xlPC90aD5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ3JpZ2h0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+Sm9pbmVkPC90aD5cbiAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgPC90aGVhZD5cbiAgICAgICAgICAgICAgICA8dGJvZHk+XG4gICAgICAgICAgICAgICAgICB7cmVjZW50VXNlcnMubWFwKCh1LCBpKSA9PiAoXG4gICAgICAgICAgICAgICAgICAgIDx0ciBrZXk9e2l9IHN0eWxlPXt7IGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnLCBjb2xvcjogQy50ZXh0LCBmb250U2l6ZTogJzEzcHgnLCBmb250V2VpZ2h0OiA1MDAgfX0+e3UudXNlcm5hbWV9PC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzExcHgnLCBwYWRkaW5nOiAnM3B4IDhweCcsIGJvcmRlclJhZGl1czogJzZweCcsIGJhY2tncm91bmRDb2xvcjogdS5yb2xlID09PSAnYWRtaW4nID8gYCR7Qy5nb2xkfTIwYCA6IGAke0MuYmx1ZX0yMGAsIGNvbG9yOiB1LnJvbGUgPT09ICdhZG1pbicgPyBDLmdvbGQgOiBDLmJsdWUsIGZvbnRXZWlnaHQ6IDYwMCB9fT57dS5yb2xlIHx8ICd1c2VyJ308L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dEFsaWduOiAncmlnaHQnIH19PntmbXREYXRlKHUuZGF0ZSl9PC90ZD5cbiAgICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICAgICkpfVxuICAgICAgICAgICAgICAgIDwvdGJvZHk+XG4gICAgICAgICAgICAgIDwvdGFibGU+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgdGV4dEFsaWduOiAnY2VudGVyJywgcGFkZGluZzogJzIwcHggMCcgfX0+Tm8gcmVjZW50IHVzZXJzLjwvVGV4dD5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cblxuICAgICAgICB7LyogUmVjZW50IE1vZHMgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcxIDEgMzIwcHgnLCBtaW5XaWR0aDogMCwgd2lkdGg6ICcxMDAlJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE4cHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIlBhY2thZ2VcIiBjb2xvcj17Qy5nb2xkfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5SZWNlbnQgTW9kczwvSDU+XG4gICAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9GaWxlXCIgc3R5bGU9e3sgbWFyZ2luTGVmdDogJ2F1dG8nLCBjb2xvcjogQy5nb2xkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+VmlldyBBbGwg4oaSPC9hPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIHtyZWNlbnRNb2RzLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8ZGl2IHN0eWxlPXt7IG92ZXJmbG93WDogJ2F1dG8nLCB3aWR0aDogJzEwMCUnLCBXZWJraXRPdmVyZmxvd1Njcm9sbGluZzogJ3RvdWNoJyB9fT5cbiAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPXt7IHdpZHRoOiAnMTAwJScsIGJvcmRlckNvbGxhcHNlOiAnY29sbGFwc2UnLCBtaW5XaWR0aDogJzMwMHB4JyB9fT5cbiAgICAgICAgICAgICAgICA8dGhlYWQ+XG4gICAgICAgICAgICAgICAgICA8dHIgc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5OYW1lPC90aD5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5QbGF0Zm9ybTwvdGg+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+U3RhdHVzPC90aD5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ3JpZ2h0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+QWRkZWQ8L3RoPlxuICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICA8L3RoZWFkPlxuICAgICAgICAgICAgICAgIDx0Ym9keT5cbiAgICAgICAgICAgICAgICAgIHtyZWNlbnRNb2RzLm1hcCgobSwgaSkgPT4gKFxuICAgICAgICAgICAgICAgICAgICA8dHIga2V5PXtpfSBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dCwgZm9udFNpemU6ICcxM3B4JywgZm9udFdlaWdodDogNTAwLCBtYXhXaWR0aDogJzE4MHB4Jywgb3ZlcmZsb3c6ICdoaWRkZW4nLCB0ZXh0T3ZlcmZsb3c6ICdlbGxpcHNpcycsIHdoaXRlU3BhY2U6ICdub3dyYXAnIH19PnttLm5hbWV9PC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzExcHgnLCBwYWRkaW5nOiAnM3B4IDhweCcsIGJvcmRlclJhZGl1czogJzZweCcsIGJhY2tncm91bmRDb2xvcjogYCR7Qy5ibHVlfTIwYCwgY29sb3I6IEMuYmx1ZSwgZm9udFdlaWdodDogNjAwLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyB9fT57bS5jYXRlZ29yeSB8fCAn4oCUJ308L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzExcHgnLCBwYWRkaW5nOiAnM3B4IDhweCcsIGJvcmRlclJhZGl1czogJzZweCcsIGJhY2tncm91bmRDb2xvcjogYCR7c3RhdHVzQ29sb3IobS5zdGF0dXMpfTIwYCwgY29sb3I6IHN0YXR1c0NvbG9yKG0uc3RhdHVzKSwgZm9udFdlaWdodDogNjAwLCB0ZXh0VHJhbnNmb3JtOiAnY2FwaXRhbGl6ZScgfX0+e20uc3RhdHVzIHx8ICfigJQnfTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0QWxpZ246ICdyaWdodCcgfX0+e2ZtdERhdGUobS5kYXRlKX08L3RkPlxuICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgKSl9XG4gICAgICAgICAgICAgICAgPC90Ym9keT5cbiAgICAgICAgICAgICAgPC90YWJsZT5cbiAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICkgOiAoXG4gICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCB0ZXh0QWxpZ246ICdjZW50ZXInLCBwYWRkaW5nOiAnMjBweCAwJyB9fT5ObyByZWNlbnQgbW9kcy48L1RleHQ+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBGT09URVIg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcxNHB4JywgcGFkZGluZ1RvcDogJzIwcHgnLCBib3JkZXJUb3A6IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICA8YSBocmVmPVwiL2FkbWluXCIgc3R5bGU9e3sgdGV4dERlY29yYXRpb246ICdub25lJyB9fT5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBmb250U2l6ZTogJzEzcHgnLCBjdXJzb3I6ICdwb2ludGVyJywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5cbiAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLmdvbGQsIGZvbnRXZWlnaHQ6IDcwMCB9fT5HUEw8L3NwYW4+IDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGZvbnRXZWlnaHQ6IDYwMCB9fT5Nb2RzPC9zcGFuPiDigKIgQWRtaW4gUGFuZWwgdjIuNVxuICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgPC9hPlxuICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnOHB4JyB9fT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9Vc2VyXCIgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjA2KScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSknLCBwYWRkaW5nOiAnNXB4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA1MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+VXNlcnM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvRmlsZVwiIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC4wNiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpJywgcGFkZGluZzogJzVweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNTAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19Pk1vZHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvUmVwb3J0XCIgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjA2KScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSknLCBwYWRkaW5nOiAnNXB4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA1MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+UmVwb3J0czwvYT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9TdXBwb3J0VGlja2V0XCIgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjA2KScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSknLCBwYWRkaW5nOiAnNXB4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA1MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+VGlja2V0czwvYT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL211c2ljXCIgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjA2KScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSknLCBwYWRkaW5nOiAnNXB4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA1MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+TXVzaWM8L2E+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBDdXN0b21EYXNoYm9hcmQ7XG4iLCJpbXBvcnQgUmVhY3QgZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94LCBJY29uIH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5cbmNvbnN0IFNpZGViYXJCcmFuZGluZyA9ICgpID0+IHtcbiAgcmV0dXJuIChcbiAgICA8Qm94IFxuICAgICAgZmxleCBcbiAgICAgIGZsZXhEaXJlY3Rpb249XCJjb2x1bW5cIlxuICAgICAgYWxpZ25JdGVtcz1cImNlbnRlclwiIFxuICAgICAganVzdGlmeUNvbnRlbnQ9XCJjZW50ZXJcIiBcbiAgICAgIHA9XCJsZ1wiIFxuICAgICAgc3R5bGU9e3sgXG4gICAgICAgIGJvcmRlckJvdHRvbTogJzFweCBzb2xpZCAjMmEyYTJhJywgXG4gICAgICAgIGJhY2tncm91bmRDb2xvcjogJyMwYTBhMGEnLCBcbiAgICAgICAgcGFkZGluZzogJzIwcHggMTZweCcsXG4gICAgICAgIHBvc2l0aW9uOiAncmVsYXRpdmUnLFxuICAgICAgICBvdmVyZmxvdzogJ2hpZGRlbidcbiAgICAgIH19XG4gICAgPlxuICAgICAgey8qIFN1YnRsZSBnb2xkIGdsb3cgdW5kZXJsaW5lICovfVxuICAgICAgPGRpdiBzdHlsZT17e1xuICAgICAgICBwb3NpdGlvbjogJ2Fic29sdXRlJyxcbiAgICAgICAgYm90dG9tOiAwLFxuICAgICAgICBsZWZ0OiAnNTAlJyxcbiAgICAgICAgdHJhbnNmb3JtOiAndHJhbnNsYXRlWCgtNTAlKScsXG4gICAgICAgIHdpZHRoOiAnNjAlJyxcbiAgICAgICAgaGVpZ2h0OiAnMXB4JyxcbiAgICAgICAgYmFja2dyb3VuZDogJ2xpbmVhci1ncmFkaWVudCg5MGRlZywgdHJhbnNwYXJlbnQsIHJnYmEoMjU1LDIxNSwwLDAuNSksIHRyYW5zcGFyZW50KSdcbiAgICAgIH19IC8+XG5cbiAgICAgIHsvKiBNYWluIExvZ28gJiBUaXRsZSBMaW5rICovfVxuICAgICAgPGEgXG4gICAgICAgIGhyZWY9XCIvYWRtaW5cIiBcbiAgICAgICAgc3R5bGU9e3sgXG4gICAgICAgICAgdGV4dERlY29yYXRpb246ICdub25lJywgXG4gICAgICAgICAgZGlzcGxheTogJ2ZsZXgnLCBcbiAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJywgXG4gICAgICAgICAgZ2FwOiAnMTBweCcsXG4gICAgICAgICAgY3Vyc29yOiAncG9pbnRlcicsXG4gICAgICAgICAgdHJhbnNpdGlvbjogJ29wYWNpdHkgMC4ycyBlYXNlJ1xuICAgICAgICB9fVxuICAgICAgICBvbk1vdXNlRW50ZXI9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5vcGFjaXR5ID0gJzAuODUnOyB9fVxuICAgICAgICBvbk1vdXNlTGVhdmU9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5vcGFjaXR5ID0gJzEnOyB9fVxuICAgICAgPlxuICAgICAgICA8aW1nIFxuICAgICAgICAgIHNyYz1cIi9pbWFnZXMvdGVhbS1sb2dvLnBuZ1wiIFxuICAgICAgICAgIGFsdD1cIkxvZ29cIiBcbiAgICAgICAgICBzdHlsZT17eyBoZWlnaHQ6ICczMnB4Jywgd2lkdGg6ICczMnB4Jywgb2JqZWN0Rml0OiAnY292ZXInLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBmaWx0ZXI6ICdkcm9wLXNoYWRvdygwIDAgNnB4IHJnYmEoMjU1LDIxNSwwLDAuMykpJyB9fSBcbiAgICAgICAgICBvbkVycm9yPXsoZSkgPT4gZS50YXJnZXQuc3R5bGUuZGlzcGxheSA9ICdub25lJ31cbiAgICAgICAgLz5cbiAgICAgICAgPGRpdiBzdHlsZT17eyBmb250U2l6ZTogJzIycHgnLCBmb250V2VpZ2h0OiAnYm9sZCcsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2Jhc2VsaW5lJywgZ2FwOiAnNHB4JyB9fT5cbiAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNGRkQ3MDAnLCB0ZXh0U2hhZG93OiAnMCAwIDEycHggcmdiYSgyNTUsIDIxNSwgMCwgMC40KScgfX0+R1BMPC9zcGFuPlxuICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcsIHRleHRTaGFkb3c6ICcwIDAgMTJweCByZ2JhKDE5MiwgMTkyLCAxOTIsIDAuNSknIH19Pk1vZHM8L3NwYW4+XG4gICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICc5cHgnLCBjb2xvcjogJyM1NTUnLCBmb250V2VpZ2h0OiA2MDAsIG1hcmdpbkxlZnQ6ICc2cHgnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNWVtJyB9fT52Mi41PC9zcGFuPlxuICAgICAgICA8L2Rpdj5cbiAgICAgIDwvYT5cblxuICAgICAgey8qIFF1aWNrIERhc2hib2FyZCBTaG9ydGN1dCBCdXR0b24gKi99XG4gICAgICA8YSBcbiAgICAgICAgaHJlZj1cIi9hZG1pblwiIFxuICAgICAgICBzdHlsZT17e1xuICAgICAgICAgIGRpc3BsYXk6ICdmbGV4JyxcbiAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJyxcbiAgICAgICAgICBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicsXG4gICAgICAgICAgZ2FwOiAnOHB4JyxcbiAgICAgICAgICBtYXJnaW5Ub3A6ICcxMnB4JyxcbiAgICAgICAgICBwYWRkaW5nOiAnNnB4IDE2cHgnLFxuICAgICAgICAgIHdpZHRoOiAnODUlJyxcbiAgICAgICAgICBib3JkZXJSYWRpdXM6ICc4cHgnLFxuICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMDgpJyxcbiAgICAgICAgICBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsIDIxNSwgMCwgMC4yNSknLFxuICAgICAgICAgIGNvbG9yOiAnI0ZGRDcwMCcsXG4gICAgICAgICAgdGV4dERlY29yYXRpb246ICdub25lJyxcbiAgICAgICAgICBmb250U2l6ZTogJzEycHgnLFxuICAgICAgICAgIGZvbnRXZWlnaHQ6IDcwMCxcbiAgICAgICAgICBsZXR0ZXJTcGFjaW5nOiAnMC4wNGVtJyxcbiAgICAgICAgICB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyxcbiAgICAgICAgICB0cmFuc2l0aW9uOiAnYWxsIDAuMnMgZWFzZScsXG4gICAgICAgICAgY3Vyc29yOiAncG9pbnRlcidcbiAgICAgICAgfX1cbiAgICAgICAgb25Nb3VzZUVudGVyPXsoZSkgPT4geyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMiknOyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJzAgMCAxNHB4IHJnYmEoMjU1LDIxNSwwLDAuMyknOyBcbiAgICAgICAgfX1cbiAgICAgICAgb25Nb3VzZUxlYXZlPXsoZSkgPT4geyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMDgpJzsgXG4gICAgICAgICAgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJveFNoYWRvdyA9ICdub25lJzsgXG4gICAgICAgIH19XG4gICAgICA+XG4gICAgICAgIDxJY29uIGljb249XCJIb21lXCIgc2l6ZT17MTN9IGNvbG9yPVwiI0ZGRDcwMFwiIC8+XG4gICAgICAgIDxzcGFuPkRhc2hib2FyZDwvc3Bhbj5cbiAgICAgIDwvYT5cbiAgICA8L0JveD5cbiAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IFNpZGViYXJCcmFuZGluZztcbiIsImltcG9ydCBSZWFjdCwgeyB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3gsIFRleHQsIExvYWRlciB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuaW1wb3J0IHsgdXNlTm90aWNlIH0gZnJvbSAnYWRtaW5qcyc7XG5cbmNvbnN0IEFjdGlvblJlZGlyZWN0ID0gKHByb3BzKSA9PiB7XG4gICAgY29uc3QgeyByZWNvcmQsIGFjdGlvbiB9ID0gcHJvcHM7XG4gICAgY29uc3Qgc2VuZE5vdGljZSA9IHVzZU5vdGljZSgpO1xuXG4gICAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICAgICAgY29uc3QgdXJsID0gcmVjb3JkPy5wYXJhbXM/LnJlZGlyZWN0VXJsO1xuICAgICAgICBcbiAgICAgICAgaWYgKHVybCkge1xuICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgd2luZG93Lm9wZW4odXJsLCAnX2JsYW5rJyk7XG4gICAgICAgICAgICB9LCA1MDApO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgc2VuZE5vdGljZSh7IG1lc3NhZ2U6ICdFcnJvcjogTm8gcmVkaXJlY3QgVVJMIHByb3ZpZGVkLicsIHR5cGU6ICdlcnJvcicgfSk7XG4gICAgICAgIH1cbiAgICB9LCBbcmVjb3JkXSk7XG5cbiAgICByZXR1cm4gKFxuICAgICAgICA8Qm94IGZsZXggZmxleERpcmVjdGlvbj1cImNvbHVtblwiIGFsaWduSXRlbXM9XCJjZW50ZXJcIiBqdXN0aWZ5Q29udGVudD1cImNlbnRlclwiIHA9XCJ4eGxcIj5cbiAgICAgICAgICAgIDxMb2FkZXIgLz5cbiAgICAgICAgICAgIDxUZXh0IG10PVwibGdcIiB2YXJpYW50PVwiaDRcIj5SZWRpcmVjdGluZy4uLjwvVGV4dD5cbiAgICAgICAgPC9Cb3g+XG4gICAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEFjdGlvblJlZGlyZWN0O1xuIiwiaW1wb3J0IFJlYWN0IGZyb20gJ3JlYWN0JztcblxuY29uc3QgVmFyaWFudEJhZGdlID0gKHByb3BzKSA9PiB7XG4gIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSB9ID0gcHJvcHM7XG4gIGlmICghcmVjb3JkIHx8ICFyZWNvcmQucGFyYW1zIHx8ICFwcm9wZXJ0eSkgcmV0dXJuIG51bGw7XG4gIGNvbnN0IGlzVmFyaWFudCA9IHJlY29yZC5wYXJhbXNbcHJvcGVydHkubmFtZV07XG5cbiAgaWYgKGlzVmFyaWFudCA9PT0gdHJ1ZSB8fCBpc1ZhcmlhbnQgPT09ICd0cnVlJykge1xuICAgIHJldHVybiAoXG4gICAgICA8c3BhblxuICAgICAgICBjbGFzc05hbWU9XCJhZG1pbi1jdXN0b20tY2hpcFwiXG4gICAgICAgIGRhdGEtYmFkZ2UtdmFsPVwidmFyaWFudC1jaGlsZFwiXG4gICAgICAgIHN0eWxlPXt7XG4gICAgICAgICAgZGlzcGxheTogJ2lubGluZS1mbGV4JyxcbiAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJyxcbiAgICAgICAgICBnYXA6ICc2cHgnLFxuICAgICAgICAgIHBhZGRpbmc6ICczcHggMTBweCcsXG4gICAgICAgICAgYm9yZGVyUmFkaXVzOiAnMjBweCcsXG4gICAgICAgICAgZm9udFNpemU6ICcxMXB4JyxcbiAgICAgICAgICBmb250V2VpZ2h0OiA3MDAsXG4gICAgICAgICAgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsXG4gICAgICAgICAgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsXG4gICAgICAgICAgYmFja2dyb3VuZDogJ2xpbmVhci1ncmFkaWVudCgxNDVkZWcsIHJnYmEoMTg2LCAxMDQsIDIwMCwgMC4yMikgMCUsIHJnYmEoNjUsIDI1LCA3NSwgMC4yNSkgMTAwJSknLFxuICAgICAgICAgIGNvbG9yOiAnI2NlOTNkOCcsXG4gICAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMTg2LCAxMDQsIDIwMCwgMC42KScsXG4gICAgICAgICAgYm94U2hhZG93OiAnaW5zZXQgMCAxLjVweCAycHggcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjIpLCBpbnNldCAwIC0xLjVweCAycHggcmdiYSgwLCAwLCAwLCAwLjgpLCAwIDAgMTBweCByZ2JhKDE4NiwgMTA0LCAyMDAsIDAuMjUpJyxcbiAgICAgICAgICB0ZXh0U2hhZG93OiAnMCAwIDZweCByZ2JhKDIwNiwgMTQ3LCAyMTYsIDAuNCknLFxuICAgICAgICAgIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCJcbiAgICAgICAgfX1cbiAgICAgID5cbiAgICAgICAgVmFyaWFudFxuICAgICAgPC9zcGFuPlxuICAgICk7XG4gIH1cblxuICByZXR1cm4gKFxuICAgIDxzcGFuXG4gICAgICBjbGFzc05hbWU9XCJhZG1pbi1jdXN0b20tY2hpcFwiXG4gICAgICBkYXRhLWJhZGdlLXZhbD1cInZhcmlhbnQtbWFzdGVyXCJcbiAgICAgIHN0eWxlPXt7XG4gICAgICAgIGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsXG4gICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInLFxuICAgICAgICBnYXA6ICc2cHgnLFxuICAgICAgICBwYWRkaW5nOiAnM3B4IDEwcHgnLFxuICAgICAgICBib3JkZXJSYWRpdXM6ICcyMHB4JyxcbiAgICAgICAgZm9udFNpemU6ICcxMXB4JyxcbiAgICAgICAgZm9udFdlaWdodDogNzAwLFxuICAgICAgICBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJyxcbiAgICAgICAgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsXG4gICAgICAgIGJhY2tncm91bmQ6ICdsaW5lYXItZ3JhZGllbnQoMTQ1ZGVnLCByZ2JhKDI1NSwgMjE1LCAwLCAwLjIyKSAwJSwgcmdiYSg5MCwgNzAsIDE1LCAwLjI1KSAxMDAlKScsXG4gICAgICAgIGNvbG9yOiAnI0ZGRDcwMCcsXG4gICAgICAgIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwgMjE1LCAwLCAwLjY1KScsXG4gICAgICAgIGJveFNoYWRvdzogJ2luc2V0IDAgMS41cHggMnB4IHJnYmEoMjU1LCAyNTUsIDI1NSwgMC4yMiksIGluc2V0IDAgLTEuNXB4IDJweCByZ2JhKDAsIDAsIDAsIDAuOCksIDAgMCAxMHB4IHJnYmEoMjU1LCAyMTUsIDAsIDAuMjUpJyxcbiAgICAgICAgdGV4dFNoYWRvdzogJzAgMCA2cHggcmdiYSgyNTUsIDIxNSwgMCwgMC40KScsXG4gICAgICAgIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCJcbiAgICAgIH19XG4gICAgPlxuICAgICAgTWFzdGVyXG4gICAgPC9zcGFuPlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgVmFyaWFudEJhZGdlO1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlLCB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3ggfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgQXZhdGFyQ2VsbCA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSwgd2hlcmUgfSA9IHByb3BzOyBcbiAgICBpZiAoIXJlY29yZCB8fCAhcmVjb3JkLnBhcmFtcyB8fCAhcHJvcGVydHkpIHJldHVybiBudWxsO1xuICAgIGNvbnN0IGtleSA9IHJlY29yZC5wYXJhbXNbcHJvcGVydHkubmFtZV07XG4gICAgY29uc3QgdXNlcm5hbWUgPSByZWNvcmQucGFyYW1zLnVzZXJuYW1lIHx8ICdVc2VyJztcblxuICAgIGNvbnN0IFtpbWFnZVVybCwgc2V0SW1hZ2VVcmxdID0gdXNlU3RhdGUobnVsbCk7XG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG4gICAgY29uc3QgW2hhc0Vycm9yLCBzZXRIYXNFcnJvcl0gPSB1c2VTdGF0ZShmYWxzZSk7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBpZiAoIWtleSkge1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoa2V5LnN0YXJ0c1dpdGgoJ2h0dHA6Ly8nKSB8fCBrZXkuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKSkge1xuICAgICAgICAgICAgc2V0SW1hZ2VVcmwoa2V5KTtcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZmV0Y2hTaWduZWRVcmwgPSBhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2goYC9hcGkvYWRtaW4vc2lnbmVkLXVybD9rZXk9JHtlbmNvZGVVUklDb21wb25lbnQoa2V5KX1gKTtcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgICAgICAgICAgc2V0SW1hZ2VVcmwoZGF0YS51cmwpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHNldEhhc0Vycm9yKHRydWUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIkVycm9yIGZldGNoaW5nIGF2YXRhciBVUkw6XCIsIGVycm9yKTtcbiAgICAgICAgICAgICAgICBzZXRIYXNFcnJvcih0cnVlKTtcbiAgICAgICAgICAgIH0gZmluYWxseSB7XG4gICAgICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG5cbiAgICAgICAgZmV0Y2hTaWduZWRVcmwoKTtcbiAgICB9LCBba2V5XSk7XG5cbiAgICBjb25zdCBzaXplID0gd2hlcmUgPT09ICdsaXN0JyA/ICczMnB4JyA6ICcxMjBweCc7XG5cbiAgICBpZiAobG9hZGluZykge1xuICAgICAgICByZXR1cm4gPEJveCBzdHlsZT17eyB3aWR0aDogc2l6ZSwgaGVpZ2h0OiBzaXplLCBib3JkZXJSYWRpdXM6ICc1MCUnLCBiYWNrZ3JvdW5kQ29sb3I6ICcjMzMzJyB9fSAvPjtcbiAgICB9XG5cbiAgICBjb25zdCBkZWZhdWx0QXZhdGFyID0gJy9pbWFnZXMvZGVmYXVsdC1hdmF0YXIucG5nJztcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3g+XG4gICAgICAgICAgICA8aW1nIFxuICAgICAgICAgICAgICAgIHNyYz17KCFpbWFnZVVybCB8fCBoYXNFcnJvcikgPyBkZWZhdWx0QXZhdGFyIDogaW1hZ2VVcmx9IFxuICAgICAgICAgICAgICAgIGFsdD17dXNlcm5hbWV9XG4gICAgICAgICAgICAgICAgc3R5bGU9e3sgXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiAnNTAlJywgXG4gICAgICAgICAgICAgICAgICAgIG9iamVjdEZpdDogJ2NvdmVyJyxcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyOiAnMnB4IHNvbGlkICNGRkQ3MDAnLFxuICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICcjMWExYTFhJ1xuICAgICAgICAgICAgICAgIH19IFxuICAgICAgICAgICAgICAgIG9uRXJyb3I9eyhlKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChlLmN1cnJlbnRUYXJnZXQuc3JjICE9PSBkZWZhdWx0QXZhdGFyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3JjID0gZGVmYXVsdEF2YXRhcjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH19XG4gICAgICAgICAgICAvPlxuICAgICAgICA8L0JveD5cbiAgICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgQXZhdGFyQ2VsbDtcbiIsImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94IH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5cbmNvbnN0IEltYWdlUHJldmlldyA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSwgd2hlcmUgfSA9IHByb3BzOyBcbiAgICBpZiAoIXJlY29yZCB8fCAhcmVjb3JkLnBhcmFtcyB8fCAhcHJvcGVydHkpIHJldHVybiBudWxsO1xuICAgIGNvbnN0IHZhbHVlID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcblxuICAgIGNvbnN0IFtpbWFnZVVybCwgc2V0SW1hZ2VVcmxdID0gdXNlU3RhdGUobnVsbCk7XG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG5cbiAgICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgICAgICBpZiAoIXZhbHVlKSB7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh2YWx1ZS5zdGFydHNXaXRoKCdodHRwOi8vJykgfHwgdmFsdWUuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKSkge1xuICAgICAgICAgICAgc2V0SW1hZ2VVcmwodmFsdWUpO1xuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBmZXRjaFNpZ25lZFVybCA9IGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChgL2FwaS9hZG1pbi9zaWduZWQtdXJsP2tleT0ke2VuY29kZVVSSUNvbXBvbmVudCh2YWx1ZSl9YCk7XG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlLm9rKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICAgICAgICAgIHNldEltYWdlVXJsKGRhdGEudXJsKTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiRmFpbGVkIHRvIGZldGNoIHNpZ25lZCBVUkwuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIk5ldHdvcmsgZXJyb3IgZmV0Y2hpbmcgc2lnbmVkIFVSTDpcIiwgZXJyb3IpO1xuICAgICAgICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcblxuICAgICAgICBmZXRjaFNpZ25lZFVybCgpO1xuICAgIH0sIFt2YWx1ZV0pO1xuXG4gICAgaWYgKGxvYWRpbmcpIHJldHVybiA8Qm94IHN0eWxlPXt7IGNvbG9yOiAnI0ZGRDcwMCcsIGZvbnRTaXplOiAnMTJweCcgfX0+TG9hZGluZy4uLjwvQm94PjtcblxuICAgIGNvbnN0IGlzQXZhdGFyID0gcHJvcGVydHkubmFtZSA9PT0gJ3Byb2ZpbGVJbWFnZUtleScgfHwgcHJvcGVydHkubmFtZSA9PT0gJ2NhcmRBdmF0YXJVcmwnIHx8IHByb3BlcnR5Lm5hbWUgPT09ICdhdmF0YXInO1xuICAgIGNvbnN0IGRlZmF1bHRJbWFnZSA9IGlzQXZhdGFyID8gJy9pbWFnZXMvZGVmYXVsdC1hdmF0YXIucG5nJyA6ICcvaW1hZ2VzL2RlZmF1bHQtYXBwLWljb24ucG5nJztcbiAgICBjb25zdCBkaXNwbGF5VXJsID0gaW1hZ2VVcmwgfHwgZGVmYXVsdEltYWdlO1xuXG4gICAgY29uc3Qgc2l6ZSA9IHdoZXJlID09PSAnbGlzdCcgPyAnNDBweCcgOiAnMTUwcHgnO1xuICAgIGNvbnN0IHJhZGl1cyA9IGlzQXZhdGFyID8gJzUwJScgOiAnOHB4JztcblxuICAgIHJldHVybiAoXG4gICAgICAgIDxCb3g+XG4gICAgICAgICAgICA8aW1nIFxuICAgICAgICAgICAgICAgIHNyYz17ZGlzcGxheVVybH0gXG4gICAgICAgICAgICAgICAgYWx0PVwiUHJldmlld1wiIFxuICAgICAgICAgICAgICAgIHN0eWxlPXt7IFxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGhlaWdodDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlclJhZGl1czogcmFkaXVzLFxuICAgICAgICAgICAgICAgICAgICBvYmplY3RGaXQ6ICdjb3ZlcicsXG4gICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnLFxuICAgICAgICAgICAgICAgICAgICBib3JkZXI6ICcxcHggc29saWQgIzMzMydcbiAgICAgICAgICAgICAgICB9fSBcbiAgICAgICAgICAgICAgICBvbkVycm9yPXsoZSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZS5jdXJyZW50VGFyZ2V0LnNyYyAhPT0gZGVmYXVsdEltYWdlKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3JjID0gZGVmYXVsdEltYWdlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfX1cbiAgICAgICAgICAgIC8+XG4gICAgICAgIDwvQm94PlxuICAgICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBJbWFnZVByZXZpZXc7XG4iLCJpbXBvcnQgUmVhY3QsIHsgdXNlU3RhdGUgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3gsIEJ1dHRvbiwgSDMsIFRleHQsIElucHV0LCBMYWJlbCwgRm9ybUdyb3VwLCBOb3RpY2VCb3ggfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcbmltcG9ydCB7IHVzZU5vdGljZSwgQXBpQ2xpZW50IH0gZnJvbSAnYWRtaW5qcyc7XG5cbmNvbnN0IGFwaSA9IG5ldyBBcGlDbGllbnQoKTtcblxuY29uc3QgTWFuYWdlVm90ZXMgPSAocHJvcHMpID0+IHtcbiAgY29uc3QgeyByZWNvcmQsIHJlc291cmNlIH0gPSBwcm9wcztcbiAgY29uc3QgYWRkTm90aWNlID0gdXNlTm90aWNlKCk7XG5cbiAgY29uc3QgW3dvcmtpbmdDb3VudCwgc2V0V29ya2luZ0NvdW50XSA9IHVzZVN0YXRlKHJlY29yZC5wYXJhbXMud29ya2luZ1ZvdGVDb3VudCB8fCAwKTtcbiAgY29uc3QgW25vdFdvcmtpbmdDb3VudCwgc2V0Tm90V29ya2luZ0NvdW50XSA9IHVzZVN0YXRlKHJlY29yZC5wYXJhbXMubm90V29ya2luZ1ZvdGVDb3VudCB8fCAwKTtcbiAgY29uc3QgW2lzTG9hZGluZywgc2V0SXNMb2FkaW5nXSA9IHVzZVN0YXRlKGZhbHNlKTtcblxuICBjb25zdCBoYW5kbGVTdWJtaXQgPSAoYWN0aW9uVHlwZSkgPT4ge1xuICAgIGlmIChhY3Rpb25UeXBlID09PSAncmVzZXQnICYmICF3aW5kb3cuY29uZmlybShcIkFyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byBwZXJtYW5lbnRseSBkZWxldGUgYWxsIHVzZXIgdm90ZXMgZm9yIHRoaXMgbW9kP1wiKSkge1xuICAgICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgc2V0SXNMb2FkaW5nKHRydWUpO1xuXG4gICAgYXBpLnJlc291cmNlQWN0aW9uKHtcbiAgICAgIHJlc291cmNlSWQ6IHJlc291cmNlLmlkLFxuICAgICAgYWN0aW9uTmFtZTogJ21hbmFnZVZvdGVzJyxcbiAgICAgIHJlY29yZElkOiByZWNvcmQuaWQsXG4gICAgICBtZXRob2Q6ICdwb3N0JyxcbiAgICAgIGRhdGE6IHtcbiAgICAgICAgYWN0aW9uVHlwZTogYWN0aW9uVHlwZSxcbiAgICAgICAgbmV3V29ya2luZ0NvdW50OiB3b3JraW5nQ291bnQsXG4gICAgICAgIG5ld05vdFdvcmtpbmdDb3VudDogbm90V29ya2luZ0NvdW50XG4gICAgICB9XG4gICAgfSkudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICBzZXRJc0xvYWRpbmcoZmFsc2UpO1xuICAgICAgaWYgKHJlc3BvbnNlLmRhdGEubm90aWNlKSB7XG4gICAgICAgIGFkZE5vdGljZShyZXNwb25zZS5kYXRhLm5vdGljZSk7XG4gICAgICB9XG4gICAgICBpZiAocmVzcG9uc2UuZGF0YS5yZWRpcmVjdFVybCkge1xuICAgICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSByZXNwb25zZS5kYXRhLnJlZGlyZWN0VXJsO1xuICAgICAgfVxuICAgIH0pLmNhdGNoKGVycm9yID0+IHtcbiAgICAgIHNldElzTG9hZGluZyhmYWxzZSk7XG4gICAgICBhZGROb3RpY2UoeyBtZXNzYWdlOiAnQW4gZXJyb3Igb2NjdXJyZWQgd2hpbGUgY29udGFjdGluZyB0aGUgc2VydmVyLicsIHR5cGU6ICdlcnJvcicgfSk7XG4gICAgfSk7XG4gIH07XG5cbiAgcmV0dXJuIChcbiAgICA8Qm94IHZhcmlhbnQ9XCJ3aGl0ZVwiIHA9XCJ4bFwiIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBib3JkZXI6ICcxcHggc29saWQgIzMzMycgfX0+XG4gICAgICBcbiAgICAgIDxIMyBzdHlsZT17eyBjb2xvcjogJyNGRkQ3MDAnLCBtYXJnaW5Cb3R0b206ICcyMHB4JyB9fT5NYW5hZ2UgVm90ZXMgZm9yOiB7cmVjb3JkLnBhcmFtcy5uYW1lfTwvSDM+XG4gICAgICBcbiAgICAgIDxOb3RpY2VCb3ggc3R5bGU9e3sgbWFyZ2luQm90dG9tOiAnMzBweCcgfX0+XG4gICAgICAgIDxzdHJvbmc+Q3VycmVudCBTdGF0dXM6PC9zdHJvbmc+PGJyLz5cbiAgICAgICAgV29ya2luZyBWb3RlczogPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjNDNhMDQ3JywgZm9udFdlaWdodDogJ2JvbGQnIH19PntyZWNvcmQucGFyYW1zLndvcmtpbmdWb3RlQ291bnQgfHwgMH08L3NwYW4+PGJyLz5cbiAgICAgICAgTm90IFdvcmtpbmcgVm90ZXM6IDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2U1MzkzNScsIGZvbnRXZWlnaHQ6ICdib2xkJyB9fT57cmVjb3JkLnBhcmFtcy5ub3RXb3JraW5nVm90ZUNvdW50IHx8IDB9PC9zcGFuPlxuICAgICAgPC9Ob3RpY2VCb3g+XG5cbiAgICAgIDxCb3ggbWI9XCJ4eGxcIiBwPVwibGdcIiBzdHlsZT17eyBib3JkZXI6ICcxcHggc29saWQgIzQ0NCcsIGJvcmRlclJhZGl1czogJzhweCcsIGJhY2tncm91bmRDb2xvcjogJyMwYTBhMGEnIH19PlxuICAgICAgICA8SDMgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgZm9udFNpemU6ICcxLjJlbScgfX0+T3B0aW9uIDE6IFJlc2V0IEFsbCBWb3RlczwvSDM+XG4gICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcsIG1hcmdpbkJvdHRvbTogJzE1cHgnIH19PlxuICAgICAgICAgIFRoaXMgd2lsbCB3aXBlIGFsbCBleGlzdGluZyB1c2VyIHZvdGVzIGFuZCByZXNldCBib3RoIGNvdW50cyB0byAwLiBUaGlzIGlzIGhpZ2hseSByZWNvbW1lbmRlZCB3aGVuIGEgbWFqb3IgdXBkYXRlIGlzIHJlbGVhc2VkIHRoYXQgZml4ZXMgYSBicm9rZW4gbW9kLlxuICAgICAgICA8L1RleHQ+XG4gICAgICAgIDxCdXR0b24gXG4gICAgICAgICAgICB2YXJpYW50PVwiZGFuZ2VyXCIgXG4gICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBoYW5kbGVTdWJtaXQoJ3Jlc2V0Jyl9IFxuICAgICAgICAgICAgZGlzYWJsZWQ9e2lzTG9hZGluZ31cbiAgICAgICAgPlxuICAgICAgICAgIHtpc0xvYWRpbmcgPyAnUHJvY2Vzc2luZy4uLicgOiAnV2lwZSAmIFJlc2V0IFZvdGVzIHRvIDAnfVxuICAgICAgICA8L0J1dHRvbj5cbiAgICAgIDwvQm94PlxuXG4gICAgICA8Qm94IHA9XCJsZ1wiIHN0eWxlPXt7IGJvcmRlcjogJzFweCBzb2xpZCAjNDQ0JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgYmFja2dyb3VuZENvbG9yOiAnIzBhMGEwYScgfX0+XG4gICAgICAgIDxIMyBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBmb250U2l6ZTogJzEuMmVtJyB9fT5PcHRpb24gMjogTWFudWFsbHkgT3ZlcnJpZGUgQ291bnRzPC9IMz5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjZmZhZGFkJywgbWFyZ2luQm90dG9tOiAnMTVweCcsIGZvbnRTaXplOiAnMC45ZW0nIH19PlxuICAgICAgICAgIFdhcm5pbmc6IE1hbnVhbGx5IHNldHRpbmcgbnVtYmVycyB3aWxsIGNsZWFyIHRoZSBpbnRlcm5hbCBsaXN0IG9mIHVzZXJzIHdobyB2b3RlZC4gVXNlIHRoaXMgb25seSBpZiB5b3UgbmVlZCB0byBhcnRpZmljaWFsbHkgYm9vc3Qgb3IgcmVkdWNlIGEgc2NvcmUuXG4gICAgICAgIDwvVGV4dD5cbiAgICAgICAgXG4gICAgICAgIDxCb3ggZmxleCBzdHlsZT17eyBnYXA6ICcyMHB4JywgbWFyZ2luQm90dG9tOiAnMjBweCcgfX0+XG4gICAgICAgICAgICA8Rm9ybUdyb3VwIHN0eWxlPXt7IGZsZXg6IDEgfX0+XG4gICAgICAgICAgICAgICAgPExhYmVsIHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcgfX0+Rm9yY2UgXCJXb3JraW5nXCIgQ291bnQ8L0xhYmVsPlxuICAgICAgICAgICAgICAgIDxJbnB1dCBcbiAgICAgICAgICAgICAgICAgICAgdHlwZT1cIm51bWJlclwiIFxuICAgICAgICAgICAgICAgICAgICB2YWx1ZT17d29ya2luZ0NvdW50fSBcbiAgICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKSA9PiBzZXRXb3JraW5nQ291bnQoZS50YXJnZXQudmFsdWUpfSBcbiAgICAgICAgICAgICAgICAgICAgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzFhMWExYScsIGNvbG9yOiAnd2hpdGUnLCBib3JkZXI6ICcxcHggc29saWQgIzMzMycgfX1cbiAgICAgICAgICAgICAgICAvPlxuICAgICAgICAgICAgPC9Gb3JtR3JvdXA+XG4gICAgICAgICAgICBcbiAgICAgICAgICAgIDxGb3JtR3JvdXAgc3R5bGU9e3sgZmxleDogMSB9fT5cbiAgICAgICAgICAgICAgICA8TGFiZWwgc3R5bGU9e3sgY29sb3I6ICcjYzBjMGMwJyB9fT5Gb3JjZSBcIk5vdCBXb3JraW5nXCIgQ291bnQ8L0xhYmVsPlxuICAgICAgICAgICAgICAgIDxJbnB1dCBcbiAgICAgICAgICAgICAgICAgICAgdHlwZT1cIm51bWJlclwiIFxuICAgICAgICAgICAgICAgICAgICB2YWx1ZT17bm90V29ya2luZ0NvdW50fSBcbiAgICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKSA9PiBzZXROb3RXb3JraW5nQ291bnQoZS50YXJnZXQudmFsdWUpfVxuICAgICAgICAgICAgICAgICAgICBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMWExYTFhJywgY29sb3I6ICd3aGl0ZScsIGJvcmRlcjogJzFweCBzb2xpZCAjMzMzJyB9fVxuICAgICAgICAgICAgICAgIC8+XG4gICAgICAgICAgICA8L0Zvcm1Hcm91cD5cbiAgICAgICAgPC9Cb3g+XG5cbiAgICAgICAgPEJ1dHRvbiBcbiAgICAgICAgICAgIHZhcmlhbnQ9XCJwcmltYXJ5XCIgXG4gICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBoYW5kbGVTdWJtaXQoJ292ZXJyaWRlJyl9IFxuICAgICAgICAgICAgZGlzYWJsZWQ9e2lzTG9hZGluZ31cbiAgICAgICAgICAgIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyNGRkQ3MDAnLCBjb2xvcjogJ2JsYWNrJywgYm9yZGVyOiAnbm9uZScgfX1cbiAgICAgICAgPlxuICAgICAgICAgIHtpc0xvYWRpbmcgPyAnUHJvY2Vzc2luZy4uLicgOiAnQXBwbHkgTWFudWFsIE92ZXJyaWRlJ31cbiAgICAgICAgPC9CdXR0b24+XG4gICAgICA8L0JveD5cblxuICAgIDwvQm94PlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgTWFuYWdlVm90ZXM7XG4iLCJBZG1pbkpTLlVzZXJDb21wb25lbnRzID0ge31cbkFkbWluSlMuZW52Lk5PREVfRU5WID0gXCJwcm9kdWN0aW9uXCJcbmltcG9ydCBEYXNoYm9hcmQgZnJvbSAnLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvQ3VzdG9tRGFzaGJvYXJkJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5EYXNoYm9hcmQgPSBEYXNoYm9hcmRcbmltcG9ydCBTaWRlYmFyQnJhbmRpbmcgZnJvbSAnLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5TaWRlYmFyQnJhbmRpbmcgPSBTaWRlYmFyQnJhbmRpbmdcbmltcG9ydCBBY3Rpb25SZWRpcmVjdCBmcm9tICcuLi9jb21wb25lbnRzL2FjdGlvbnMvQWN0aW9uUmVkaXJlY3QnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkFjdGlvblJlZGlyZWN0ID0gQWN0aW9uUmVkaXJlY3RcbmltcG9ydCBWYXJpYW50QmFkZ2UgZnJvbSAnLi4vY29tcG9uZW50cy9jZWxscy9WYXJpYW50QmFkZ2UnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLlZhcmlhbnRCYWRnZSA9IFZhcmlhbnRCYWRnZVxuaW1wb3J0IEF2YXRhckNlbGwgZnJvbSAnLi4vY29tcG9uZW50cy9jZWxscy9BdmF0YXJDZWxsJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5BdmF0YXJDZWxsID0gQXZhdGFyQ2VsbFxuaW1wb3J0IEltYWdlUHJldmlldyBmcm9tICcuLi9jb21wb25lbnRzL2NlbGxzL0ltYWdlUHJldmlldydcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuSW1hZ2VQcmV2aWV3ID0gSW1hZ2VQcmV2aWV3XG5pbXBvcnQgTWFuYWdlVm90ZXMgZnJvbSAnLi4vY29tcG9uZW50cy9hY3Rpb25zL01hbmFnZVZvdGVzJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5NYW5hZ2VWb3RlcyA9IE1hbmFnZVZvdGVzIl0sIm5hbWVzIjpbImFwaSIsIkFwaUNsaWVudCIsIkMiLCJiZyIsInN1cmZhY2UiLCJzdXJmYWNlQWx0IiwiYm9yZGVyIiwiYm9yZGVySG92ZXIiLCJnb2xkIiwiZ29sZERpbSIsImdvbGRHbG93IiwiYmx1ZSIsImdyZWVuIiwicHVycGxlIiwicmVkIiwib3JhbmdlIiwidGV4dCIsInRleHRNdXRlZCIsInRleHREaW0iLCJQTEFURk9STV9DT0xPUlMiLCJjYXJkU3R5bGUiLCJhY2NlbnRDb2xvciIsImJhY2tncm91bmRDb2xvciIsImJvcmRlclJhZGl1cyIsImJvcmRlckxlZnQiLCJwYWRkaW5nIiwidHJhbnNpdGlvbiIsImN1cnNvciIsImJveFNpemluZyIsIkFyZWFDaGFydCIsImRhdGEiLCJ3aWR0aCIsImhlaWdodCIsImNvbG9yIiwibGVuZ3RoIiwibWF4VmFsIiwiTWF0aCIsIm1heCIsIm1hcCIsImQiLCJ2YWx1ZSIsInBhZFgiLCJwYWRZIiwiY2hhcnRXIiwiY2hhcnRIIiwicG9pbnRzIiwiaSIsIngiLCJ5IiwibGluZVBhdGgiLCJwIiwiam9pbiIsImFyZWFQYXRoIiwiZ3JpZExpbmVzIiwicGN0IiwibGFiZWwiLCJyb3VuZCIsInN0ZXAiLCJjZWlsIiwiUmVhY3QiLCJjcmVhdGVFbGVtZW50Iiwic3R5bGUiLCJvdmVyZmxvdyIsInZpZXdCb3giLCJwcmVzZXJ2ZUFzcGVjdFJhdGlvIiwiZGlzcGxheSIsIm1heFdpZHRoIiwiaWQiLCJ4MSIsInkxIiwieDIiLCJ5MiIsIm9mZnNldCIsInN0b3BDb2xvciIsInN0b3BPcGFjaXR5IiwiZyIsImtleSIsInN0cm9rZSIsInN0cm9rZVdpZHRoIiwic3Ryb2tlRGFzaGFycmF5IiwiZmlsbCIsImZvbnRTaXplIiwiZm9udEZhbWlseSIsInRleHRBbmNob3IiLCJzdHJva2VMaW5lam9pbiIsInN0cm9rZUxpbmVjYXAiLCJzaG93TGFiZWwiLCJjeCIsImN5IiwiciIsIkRvbnV0Q2hhcnQiLCJzaXplIiwidG90YWwiLCJyZWR1Y2UiLCJzIiwib3V0ZXJSIiwiaW5uZXJSIiwiY3VtQW5nbGUiLCJQSSIsInNsaWNlcyIsImFuZ2xlIiwic3RhcnRBbmdsZSIsImVuZEFuZ2xlIiwiY29zIiwic2luIiwiaXgxIiwiaXkxIiwiaXgyIiwiaXkyIiwibGFyZ2VBcmMiLCJwYXRoIiwibmFtZSIsImFsaWduSXRlbXMiLCJnYXAiLCJmbGV4V3JhcCIsImp1c3RpZnlDb250ZW50IiwiZm9udFdlaWdodCIsImZsZXhEaXJlY3Rpb24iLCJmbGV4U2hyaW5rIiwibWFyZ2luTGVmdCIsIlN0YXRDYXJkIiwiaWNvbiIsImRlbHRhIiwiZGVsdGFMYWJlbCIsIkJveCIsImZsZXgiLCJtaW5XaWR0aCIsIm9uTW91c2VFbnRlciIsImUiLCJjdXJyZW50VGFyZ2V0IiwiYm9yZGVyQ29sb3IiLCJ0cmFuc2Zvcm0iLCJib3hTaGFkb3ciLCJvbk1vdXNlTGVhdmUiLCJib3JkZXJMZWZ0Q29sb3IiLCJtYXJnaW5Cb3R0b20iLCJJY29uIiwiVGV4dCIsInRleHRUcmFuc2Zvcm0iLCJsZXR0ZXJTcGFjaW5nIiwiSDIiLCJtYXJnaW4iLCJ1bmRlZmluZWQiLCJBY3Rpb25DYXJkIiwiY291bnQiLCJyZXNvdXJjZUlkIiwiaHJlZiIsInRleHREZWNvcmF0aW9uIiwiSDUiLCJmbXREYXRlIiwiZHQiLCJEYXRlIiwidG9Mb2NhbGVEYXRlU3RyaW5nIiwibW9udGgiLCJkYXkiLCJ5ZWFyIiwic3RhdHVzQ29sb3IiLCJsb3dlciIsInRvTG93ZXJDYXNlIiwiQ3VzdG9tRGFzaGJvYXJkIiwic2V0RGF0YSIsInVzZVN0YXRlIiwibG9hZGluZyIsInNldExvYWRpbmciLCJlcnJvciIsInNldEVycm9yIiwidXNlRWZmZWN0IiwiZ2V0RGFzaGJvYXJkIiwidGhlbiIsInJlc3BvbnNlIiwiY2F0Y2giLCJmZXRjaEVycm9yIiwiY29uc29sZSIsIm1pbkhlaWdodCIsInRleHRBbGlnbiIsImJvcmRlclRvcENvbG9yIiwiYW5pbWF0aW9uIiwic3RhdHMiLCJhY3Rpb25SZXF1aXJlZCIsIm1vZHNCeVBsYXRmb3JtIiwidXNlckdyb3d0aERhdGEiLCJyZWNlbnRVc2VycyIsInJlY2VudE1vZHMiLCJncm93dGhDaGFydERhdGEiLCJkYXRlIiwidXNlcnMiLCJub3ciLCJncmVldGluZyIsImdldEhvdXJzIiwicGFkZGluZ0JvdHRvbSIsImJvcmRlckJvdHRvbSIsInRleHRTaGFkb3ciLCJiYWNrZ3JvdW5kIiwibWFyZ2luVG9wIiwibGluZUhlaWdodCIsIndlZWtkYXkiLCJ0aXRsZSIsInRhcmdldCIsInJlbCIsInRvdGFsVXNlcnMiLCJ0b0xvY2FsZVN0cmluZyIsIm5ld1VzZXJzVGhpc01vbnRoIiwidG90YWxNb2RzIiwibmV3TW9kc1RoaXNNb250aCIsInRvdGFsRG93bmxvYWRzIiwidG90YWxWaWV3cyIsInBlbmRpbmdSZXBvcnRzIiwicGVuZGluZ0FwcHJvdmFscyIsIm9wZW5UaWNrZXRzIiwiQmFkZ2UiLCJvdmVyZmxvd1giLCJXZWJraXRPdmVyZmxvd1Njcm9sbGluZyIsImJvcmRlckNvbGxhcHNlIiwidSIsInVzZXJuYW1lIiwicm9sZSIsIm0iLCJ0ZXh0T3ZlcmZsb3ciLCJ3aGl0ZVNwYWNlIiwiY2F0ZWdvcnkiLCJzdGF0dXMiLCJwYWRkaW5nVG9wIiwiYm9yZGVyVG9wIiwiU2lkZWJhckJyYW5kaW5nIiwicG9zaXRpb24iLCJib3R0b20iLCJsZWZ0Iiwib3BhY2l0eSIsInNyYyIsImFsdCIsIm9iamVjdEZpdCIsImZpbHRlciIsIm9uRXJyb3IiLCJBY3Rpb25SZWRpcmVjdCIsInByb3BzIiwicmVjb3JkIiwiYWN0aW9uIiwic2VuZE5vdGljZSIsInVzZU5vdGljZSIsInVybCIsInBhcmFtcyIsInJlZGlyZWN0VXJsIiwic2V0VGltZW91dCIsIndpbmRvdyIsIm9wZW4iLCJtZXNzYWdlIiwidHlwZSIsIkxvYWRlciIsIm10IiwidmFyaWFudCIsIlZhcmlhbnRCYWRnZSIsInByb3BlcnR5IiwiaXNWYXJpYW50IiwiY2xhc3NOYW1lIiwiQXZhdGFyQ2VsbCIsIndoZXJlIiwiaW1hZ2VVcmwiLCJzZXRJbWFnZVVybCIsImhhc0Vycm9yIiwic2V0SGFzRXJyb3IiLCJzdGFydHNXaXRoIiwiZmV0Y2hTaWduZWRVcmwiLCJmZXRjaCIsImVuY29kZVVSSUNvbXBvbmVudCIsIm9rIiwianNvbiIsImRlZmF1bHRBdmF0YXIiLCJJbWFnZVByZXZpZXciLCJpc0F2YXRhciIsImRlZmF1bHRJbWFnZSIsImRpc3BsYXlVcmwiLCJyYWRpdXMiLCJNYW5hZ2VWb3RlcyIsInJlc291cmNlIiwiYWRkTm90aWNlIiwid29ya2luZ0NvdW50Iiwic2V0V29ya2luZ0NvdW50Iiwid29ya2luZ1ZvdGVDb3VudCIsIm5vdFdvcmtpbmdDb3VudCIsInNldE5vdFdvcmtpbmdDb3VudCIsIm5vdFdvcmtpbmdWb3RlQ291bnQiLCJpc0xvYWRpbmciLCJzZXRJc0xvYWRpbmciLCJoYW5kbGVTdWJtaXQiLCJhY3Rpb25UeXBlIiwiY29uZmlybSIsInJlc291cmNlQWN0aW9uIiwiYWN0aW9uTmFtZSIsInJlY29yZElkIiwibWV0aG9kIiwibmV3V29ya2luZ0NvdW50IiwibmV3Tm90V29ya2luZ0NvdW50Iiwibm90aWNlIiwibG9jYXRpb24iLCJIMyIsIk5vdGljZUJveCIsIm1iIiwiQnV0dG9uIiwib25DbGljayIsImRpc2FibGVkIiwiRm9ybUdyb3VwIiwiTGFiZWwiLCJJbnB1dCIsIm9uQ2hhbmdlIiwiQWRtaW5KUyIsIlVzZXJDb21wb25lbnRzIiwiZW52IiwiTk9ERV9FTlYiLCJEYXNoYm9hcmQiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7RUFJQSxNQUFNQSxLQUFHLEdBQUcsSUFBSUMsaUJBQVMsRUFBRTs7RUFFM0I7RUFDQSxNQUFNQyxDQUFDLEdBQUc7RUFDUkMsRUFBQUEsRUFBRSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsT0FBTyxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsVUFBVSxFQUFFLFNBQVM7RUFDeERDLEVBQUFBLE1BQU0sRUFBRSxTQUFTO0VBQUVDLEVBQUFBLFdBQVcsRUFBRSxTQUFTO0VBQ3pDQyxFQUFBQSxJQUFJLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxPQUFPLEVBQUUsc0JBQXNCO0VBQUVDLEVBQUFBLFFBQVEsRUFBRSxzQkFBc0I7RUFDbEZDLEVBQUFBLElBQUksRUFBRSxTQUFTO0VBQUVDLEVBQUFBLEtBQUssRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE1BQU0sRUFBRSxTQUFTO0VBQUVDLEVBQUFBLEdBQUcsRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE1BQU0sRUFBRSxTQUFTO0VBQ3ZGQyxFQUFBQSxJQUFJLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxTQUFTLEVBQUUs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
