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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIiwic291cmNlcyI6WyIuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQuanN4IiwiLi4vY29tcG9uZW50cy9kYXNoYm9hcmQvU2lkZWJhckJyYW5kaW5nLmpzeCIsIi4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdC5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL1ZhcmlhbnRCYWRnZS5qc3giLCIuLi9jb21wb25lbnRzL2NlbGxzL0F2YXRhckNlbGwuanN4IiwiLi4vY29tcG9uZW50cy9jZWxscy9JbWFnZVByZXZpZXcuanN4IiwiLi4vY29tcG9uZW50cy9hY3Rpb25zL01hbmFnZVZvdGVzLmpzeCIsImVudHJ5LmpzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQXBpQ2xpZW50IH0gZnJvbSAnYWRtaW5qcyc7XG5pbXBvcnQgeyBCb3gsIEgyLCBINSwgVGV4dCwgSWNvbiwgQmFkZ2UgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgYXBpID0gbmV3IEFwaUNsaWVudCgpO1xuXG4vKiDilIDilIDilIAgY29sb3VyIHRva2VucyDilIDilIDilIAgKi9cbmNvbnN0IEMgPSB7XG4gIGJnOiAnIzBhMGEwYScsIHN1cmZhY2U6ICcjMTMxMzEzJywgc3VyZmFjZUFsdDogJyMxYTFhMWEnLFxuICBib3JkZXI6ICcjMmEyYTJhJywgYm9yZGVySG92ZXI6ICcjM2EzYTNhJyxcbiAgZ29sZDogJyNGRkQ3MDAnLCBnb2xkRGltOiAncmdiYSgyNTUsMjE1LDAsMC4xNSknLCBnb2xkR2xvdzogJ3JnYmEoMjU1LDIxNSwwLDAuMzUpJyxcbiAgYmx1ZTogJyMyMTk2RjMnLCBncmVlbjogJyM0M2EwNDcnLCBwdXJwbGU6ICcjOUMyN0IwJywgcmVkOiAnI2U1MzkzNScsIG9yYW5nZTogJyNGRjk4MDAnLFxuICB0ZXh0OiAnI2ZmZmZmZicsIHRleHRNdXRlZDogJyNlMmU4ZjAnLCB0ZXh0RGltOiAnI2NiZDVlMScsXG59O1xuXG4vKiDilIDilIDilIAgcGxhdGZvcm0gY2hhcnQgY29sb3VycyDilIDilIDilIAgKi9cbmNvbnN0IFBMQVRGT1JNX0NPTE9SUyA9IFsnI0E0QzYzOScsICcjMDA3OEQ2JywgJyMyMTc1OUInLCAnI0ZGOTgwMCcsICcjOUMyN0IwJywgJyNlNTM5MzUnLCAnIzQzYTA0NycsICcjRkZENzAwJ107XG5cbi8qIOKUgOKUgOKUgCByZXVzYWJsZSBjYXJkIHN0eWxlIOKUgOKUgOKUgCAqL1xuY29uc3QgY2FyZFN0eWxlID0gKGFjY2VudENvbG9yKSA9PiAoe1xuICBiYWNrZ3JvdW5kQ29sb3I6IEMuc3VyZmFjZSxcbiAgYm9yZGVyUmFkaXVzOiAnMTZweCcsXG4gIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsXG4gIGJvcmRlckxlZnQ6IGFjY2VudENvbG9yID8gYDRweCBzb2xpZCAke2FjY2VudENvbG9yfWAgOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCxcbiAgcGFkZGluZzogJ2NsYW1wKDE2cHgsIDIuNXZ3LCAyNHB4KScsXG4gIHRyYW5zaXRpb246ICdhbGwgMC4yNXMgZWFzZScsXG4gIGN1cnNvcjogJ2RlZmF1bHQnLFxuICBib3hTaXppbmc6ICdib3JkZXItYm94Jyxcbn0pO1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBBcmVhIENoYXJ0IOKUgOKUgOKUgCAqL1xuY29uc3QgQXJlYUNoYXJ0ID0gKHsgZGF0YSwgd2lkdGggPSA1MDAsIGhlaWdodCA9IDE3MCwgY29sb3IgPSBDLmdvbGQgfSkgPT4ge1xuICBpZiAoIWRhdGEgfHwgZGF0YS5sZW5ndGggPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBtYXhWYWwgPSBNYXRoLm1heCguLi5kYXRhLm1hcChkID0+IGQudmFsdWUpLCAxKTtcbiAgY29uc3QgcGFkWCA9IDM1O1xuICBjb25zdCBwYWRZID0gMTY7XG4gIGNvbnN0IGNoYXJ0VyA9IHdpZHRoIC0gcGFkWCAqIDI7XG4gIGNvbnN0IGNoYXJ0SCA9IGhlaWdodCAtIHBhZFkgKiAyO1xuXG4gIGNvbnN0IHBvaW50cyA9IGRhdGEubWFwKChkLCBpKSA9PiAoe1xuICAgIHg6IHBhZFggKyAoaSAvIE1hdGgubWF4KGRhdGEubGVuZ3RoIC0gMSwgMSkpICogY2hhcnRXLFxuICAgIHk6IHBhZFkgKyBjaGFydEggLSAoZC52YWx1ZSAvIG1heFZhbCkgKiBjaGFydEgsXG4gIH0pKTtcblxuICBjb25zdCBsaW5lUGF0aCA9IHBvaW50cy5tYXAoKHAsIGkpID0+IGAke2kgPT09IDAgPyAnTScgOiAnTCd9JHtwLnh9LCR7cC55fWApLmpvaW4oJyAnKTtcbiAgY29uc3QgYXJlYVBhdGggPSBgJHtsaW5lUGF0aH0gTCR7cG9pbnRzW3BvaW50cy5sZW5ndGggLSAxXS54fSwke3BhZFkgKyBjaGFydEh9IEwke3BvaW50c1swXS54fSwke3BhZFkgKyBjaGFydEh9IFpgO1xuXG4gIC8vIEdyaWQgbGluZXNcbiAgY29uc3QgZ3JpZExpbmVzID0gWzAsIDAuMjUsIDAuNSwgMC43NSwgMV0ubWFwKHBjdCA9PiB7XG4gICAgY29uc3QgeSA9IHBhZFkgKyBjaGFydEggLSBwY3QgKiBjaGFydEg7XG4gICAgY29uc3QgbGFiZWwgPSBNYXRoLnJvdW5kKHBjdCAqIG1heFZhbCk7XG4gICAgcmV0dXJuIHsgeSwgbGFiZWwgfTtcbiAgfSk7XG5cbiAgY29uc3Qgc3RlcCA9IGRhdGEubGVuZ3RoID4gOCA/IE1hdGguY2VpbChkYXRhLmxlbmd0aCAvIDUpIDogMTtcblxuICByZXR1cm4gKFxuICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6ICcxMDAlJywgb3ZlcmZsb3c6ICdoaWRkZW4nIH19PlxuICAgICAgPHN2ZyB3aWR0aD1cIjEwMCVcIiBoZWlnaHQ9e2hlaWdodH0gdmlld0JveD17YDAgMCAke3dpZHRofSAke2hlaWdodH1gfSBwcmVzZXJ2ZUFzcGVjdFJhdGlvPVwibm9uZVwiIHN0eWxlPXt7IGRpc3BsYXk6ICdibG9jaycsIG1heFdpZHRoOiAnMTAwJScgfX0+XG4gICAgICAgIDxkZWZzPlxuICAgICAgICAgIDxsaW5lYXJHcmFkaWVudCBpZD1cImFyZWFGaWxsXCIgeDE9XCIwXCIgeTE9XCIwXCIgeDI9XCIwXCIgeTI9XCIxXCI+XG4gICAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIwJVwiIHN0b3BDb2xvcj17Y29sb3J9IHN0b3BPcGFjaXR5PVwiMC4zNVwiIC8+XG4gICAgICAgICAgICA8c3RvcCBvZmZzZXQ9XCIxMDAlXCIgc3RvcENvbG9yPXtjb2xvcn0gc3RvcE9wYWNpdHk9XCIwLjAyXCIgLz5cbiAgICAgICAgICA8L2xpbmVhckdyYWRpZW50PlxuICAgICAgICA8L2RlZnM+XG4gICAgICAgIHsvKiBHcmlkICovfVxuICAgICAgICB7Z3JpZExpbmVzLm1hcCgoZywgaSkgPT4gKFxuICAgICAgICAgIDxnIGtleT17aX0+XG4gICAgICAgICAgICA8bGluZSB4MT17cGFkWH0geTE9e2cueX0geDI9e3dpZHRoIC0gcGFkWH0geTI9e2cueX0gc3Ryb2tlPXtDLmJvcmRlcn0gc3Ryb2tlV2lkdGg9XCIxXCIgc3Ryb2tlRGFzaGFycmF5PVwiMyAzXCIgLz5cbiAgICAgICAgICAgIDx0ZXh0IHg9e3BhZFggLSA2fSB5PXtnLnkgKyA0fSBmaWxsPVwiIzk0YTNiOFwiIGZvbnRTaXplPVwiOVwiIGZvbnRGYW1pbHk9XCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB0ZXh0QW5jaG9yPVwiZW5kXCI+e2cubGFiZWx9PC90ZXh0PlxuICAgICAgICAgIDwvZz5cbiAgICAgICAgKSl9XG4gICAgICAgIHsvKiBBcmVhIGZpbGwgKi99XG4gICAgICAgIDxwYXRoIGQ9e2FyZWFQYXRofSBmaWxsPVwidXJsKCNhcmVhRmlsbClcIiAvPlxuICAgICAgICB7LyogTGluZSAqL31cbiAgICAgICAgPHBhdGggZD17bGluZVBhdGh9IGZpbGw9XCJub25lXCIgc3Ryb2tlPXtjb2xvcn0gc3Ryb2tlV2lkdGg9XCIyLjVcIiBzdHJva2VMaW5lam9pbj1cInJvdW5kXCIgc3Ryb2tlTGluZWNhcD1cInJvdW5kXCIgLz5cbiAgICAgICAgey8qIERvdHMgKyBsYWJlbHMgKi99XG4gICAgICAgIHtwb2ludHMubWFwKChwLCBpKSA9PiB7XG4gICAgICAgICAgY29uc3Qgc2hvd0xhYmVsID0gKGkgPT09IDAgfHwgaSA9PT0gZGF0YS5sZW5ndGggLSAxIHx8IGkgJSBzdGVwID09PSAwKTtcbiAgICAgICAgICByZXR1cm4gKFxuICAgICAgICAgICAgPGcga2V5PXtpfT5cbiAgICAgICAgICAgICAgPGNpcmNsZSBjeD17cC54fSBjeT17cC55fSByPVwiM1wiIGZpbGw9e0MuYmd9IHN0cm9rZT17Y29sb3J9IHN0cm9rZVdpZHRoPVwiMlwiIC8+XG4gICAgICAgICAgICAgIHtzaG93TGFiZWwgJiYgKFxuICAgICAgICAgICAgICAgIDx0ZXh0IHg9e3AueH0geT17cGFkWSArIGNoYXJ0SCArIDE0fSBmaWxsPVwiI2NiZDVlMVwiIGZvbnRTaXplPVwiOVwiIGZvbnRGYW1pbHk9XCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB0ZXh0QW5jaG9yPVwibWlkZGxlXCI+e2RhdGFbaV0ubGFiZWx9PC90ZXh0PlxuICAgICAgICAgICAgICApfVxuICAgICAgICAgICAgPC9nPlxuICAgICAgICAgICk7XG4gICAgICAgIH0pfVxuICAgICAgPC9zdmc+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG4vKiDilIDilIDilIAgSW5saW5lIFNWRyBEb251dCBDaGFydCDilIDilIDilIAgKi9cbmNvbnN0IERvbnV0Q2hhcnQgPSAoeyBkYXRhLCBzaXplID0gMjAwIH0pID0+IHtcbiAgaWYgKCFkYXRhIHx8IGRhdGEubGVuZ3RoID09PSAwKSByZXR1cm4gbnVsbDtcbiAgY29uc3QgdG90YWwgPSBkYXRhLnJlZHVjZSgocywgZCkgPT4gcyArIGQudmFsdWUsIDApO1xuICBpZiAodG90YWwgPT09IDApIHJldHVybiBudWxsO1xuICBjb25zdCBjeCA9IHNpemUgLyAyO1xuICBjb25zdCBjeSA9IHNpemUgLyAyO1xuICBjb25zdCBvdXRlclIgPSBzaXplIC8gMiAtIDEwO1xuICBjb25zdCBpbm5lclIgPSBvdXRlclIgKiAwLjY7XG4gIGxldCBjdW1BbmdsZSA9IC1NYXRoLlBJIC8gMjtcblxuICBjb25zdCBzbGljZXMgPSBkYXRhLm1hcCgoZCwgaSkgPT4ge1xuICAgIGNvbnN0IGFuZ2xlID0gKGQudmFsdWUgLyB0b3RhbCkgKiBNYXRoLlBJICogMjtcbiAgICBjb25zdCBzdGFydEFuZ2xlID0gY3VtQW5nbGU7XG4gICAgY3VtQW5nbGUgKz0gYW5nbGU7XG4gICAgY29uc3QgZW5kQW5nbGUgPSBjdW1BbmdsZTtcblxuICAgIGNvbnN0IHgxID0gY3ggKyBvdXRlclIgKiBNYXRoLmNvcyhzdGFydEFuZ2xlKTtcbiAgICBjb25zdCB5MSA9IGN5ICsgb3V0ZXJSICogTWF0aC5zaW4oc3RhcnRBbmdsZSk7XG4gICAgY29uc3QgeDIgPSBjeCArIG91dGVyUiAqIE1hdGguY29zKGVuZEFuZ2xlKTtcbiAgICBjb25zdCB5MiA9IGN5ICsgb3V0ZXJSICogTWF0aC5zaW4oZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl4MSA9IGN4ICsgaW5uZXJSICogTWF0aC5jb3MoZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl5MSA9IGN5ICsgaW5uZXJSICogTWF0aC5zaW4oZW5kQW5nbGUpO1xuICAgIGNvbnN0IGl4MiA9IGN4ICsgaW5uZXJSICogTWF0aC5jb3Moc3RhcnRBbmdsZSk7XG4gICAgY29uc3QgaXkyID0gY3kgKyBpbm5lclIgKiBNYXRoLnNpbihzdGFydEFuZ2xlKTtcbiAgICBjb25zdCBsYXJnZUFyYyA9IGFuZ2xlID4gTWF0aC5QSSA/IDEgOiAwO1xuICAgIGNvbnN0IGNvbG9yID0gUExBVEZPUk1fQ09MT1JTW2kgJSBQTEFURk9STV9DT0xPUlMubGVuZ3RoXTtcblxuICAgIGNvbnN0IHBhdGggPSBgTSR7eDF9LCR7eTF9IEEke291dGVyUn0sJHtvdXRlclJ9IDAgJHtsYXJnZUFyY30gMSAke3gyfSwke3kyfSBMJHtpeDF9LCR7aXkxfSBBJHtpbm5lclJ9LCR7aW5uZXJSfSAwICR7bGFyZ2VBcmN9IDAgJHtpeDJ9LCR7aXkyfSBaYDtcbiAgICByZXR1cm4geyBwYXRoLCBjb2xvciwgbmFtZTogZC5uYW1lLCB2YWx1ZTogZC52YWx1ZSwgcGN0OiBNYXRoLnJvdW5kKChkLnZhbHVlIC8gdG90YWwpICogMTAwKSB9O1xuICB9KTtcblxuICByZXR1cm4gKFxuICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMjRweCcsIGZsZXhXcmFwOiAnd3JhcCcsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgIDxzdmcgd2lkdGg9e3NpemV9IGhlaWdodD17c2l6ZX0gdmlld0JveD17YDAgMCAke3NpemV9ICR7c2l6ZX1gfT5cbiAgICAgICAge3NsaWNlcy5tYXAoKHMsIGkpID0+IChcbiAgICAgICAgICA8cGF0aCBrZXk9e2l9IGQ9e3MucGF0aH0gZmlsbD17cy5jb2xvcn0gc3Ryb2tlPXtDLmJnfSBzdHJva2VXaWR0aD1cIjJcIj5cbiAgICAgICAgICAgIDx0aXRsZT57cy5uYW1lfToge3MudmFsdWV9ICh7cy5wY3R9JSk8L3RpdGxlPlxuICAgICAgICAgIDwvcGF0aD5cbiAgICAgICAgKSl9XG4gICAgICAgIDx0ZXh0IHg9e2N4fSB5PXtjeSAtIDZ9IGZpbGw9e0MudGV4dH0gZm9udFNpemU9XCIyMlwiIGZvbnRXZWlnaHQ9XCJib2xkXCIgdGV4dEFuY2hvcj1cIm1pZGRsZVwiPnt0b3RhbH08L3RleHQ+XG4gICAgICAgIDx0ZXh0IHg9e2N4fSB5PXtjeSArIDE0fSBmaWxsPXtDLnRleHRNdXRlZH0gZm9udFNpemU9XCIxMFwiIHRleHRBbmNob3I9XCJtaWRkbGVcIj5UT1RBTDwvdGV4dD5cbiAgICAgIDwvc3ZnPlxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhEaXJlY3Rpb246ICdjb2x1bW4nLCBnYXA6ICc2cHgnIH19PlxuICAgICAgICB7c2xpY2VzLm1hcCgocywgaSkgPT4gKFxuICAgICAgICAgIDxkaXYga2V5PXtpfSBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnIH19PlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgd2lkdGg6IDEyLCBoZWlnaHQ6IDEyLCBib3JkZXJSYWRpdXM6ICczcHgnLCBiYWNrZ3JvdW5kQ29sb3I6IHMuY29sb3IsIGRpc3BsYXk6ICdpbmxpbmUtYmxvY2snLCBmbGV4U2hyaW5rOiAwIH19IC8+XG4gICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogQy50ZXh0IH19PntzLm5hbWV9PC9zcGFuPlxuICAgICAgICAgICAgPHNwYW4gc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgbWFyZ2luTGVmdDogJ2F1dG8nIH19PntzLnZhbHVlfSAoe3MucGN0fSUpPC9zcGFuPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICApKX1cbiAgICAgIDwvZGl2PlxuICAgIDwvZGl2PlxuICApO1xufTtcblxuLyog4pSA4pSA4pSAIFN0YXQgQ2FyZCDilIDilIDilIAgKi9cbmNvbnN0IFN0YXRDYXJkID0gKHsgaWNvbiwgbGFiZWwsIHZhbHVlLCBkZWx0YSwgZGVsdGFMYWJlbCwgYWNjZW50Q29sb3IgfSkgPT4gKFxuICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZShhY2NlbnRDb2xvciksIGZsZXg6ICcxJywgbWluV2lkdGg6ICcyMjBweCcgfX1cbiAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBhY2NlbnRDb2xvciB8fCBDLmJvcmRlckhvdmVyOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoLTJweCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gYDAgOHB4IDI0cHggcmdiYSgwLDAsMCwwLjQpYDsgfX1cbiAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckxlZnRDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoMCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJ25vbmUnOyB9fVxuICA+XG4gICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcxNHB4JyB9fT5cbiAgICAgIDxJY29uIGljb249e2ljb259IGNvbG9yPXthY2NlbnRDb2xvcn0gLz5cbiAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMXB4JywgZm9udFdlaWdodDogNzAwLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDhlbScgfX0+e2xhYmVsfTwvVGV4dD5cbiAgICA8L2Rpdj5cbiAgICA8SDIgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAnMCAwIDhweCAwJywgZm9udFNpemU6ICcyLjJyZW0nIH19Pnt2YWx1ZX08L0gyPlxuICAgIHtkZWx0YSAhPT0gdW5kZWZpbmVkICYmIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JyB9fT5cbiAgICAgICAgPEljb24gaWNvbj1cIkFycm93VXBcIiBzaXplPXsxNH0gY29sb3I9e0MuZ3JlZW59IC8+XG4gICAgICAgIDxUZXh0IHN0eWxlPXt7IGNvbG9yOiBDLmdyZWVuLCBmb250U2l6ZTogJzEzcHgnLCBmb250V2VpZ2h0OiA2MDAgfX0+K3tkZWx0YX0ge2RlbHRhTGFiZWwgfHwgJ3RoaXMgbW9udGgnfTwvVGV4dD5cbiAgICAgIDwvZGl2PlxuICAgICl9XG4gIDwvQm94PlxuKTtcblxuLyog4pSA4pSA4pSAIEFjdGlvbiBCYWRnZSBDYXJkIOKUgOKUgOKUgCAqL1xuY29uc3QgQWN0aW9uQ2FyZCA9ICh7IGljb24sIGxhYmVsLCBjb3VudCwgYWNjZW50Q29sb3IsIHJlc291cmNlSWQgfSkgPT4gKFxuICA8YSBocmVmPXtgL2FkbWluL3Jlc291cmNlcy8ke3Jlc291cmNlSWR9YH0gc3R5bGU9e3sgdGV4dERlY29yYXRpb246ICdub25lJywgZmxleDogJzEnLCBtaW5XaWR0aDogJzE4MHB4JyB9fT5cbiAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZShhY2NlbnRDb2xvciksIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzE2cHgnIH19XG4gICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBhY2NlbnRDb2xvcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLnRyYW5zZm9ybSA9ICd0cmFuc2xhdGVZKC0ycHgpJzsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJveFNoYWRvdyA9IGAwIDZweCAyMHB4IHJnYmEoMCwwLDAsMC4zKWA7IH19XG4gICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckxlZnRDb2xvciA9IGFjY2VudENvbG9yOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUudHJhbnNmb3JtID0gJ3RyYW5zbGF0ZVkoMCknOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJ25vbmUnOyB9fVxuICAgID5cbiAgICAgIDxkaXYgc3R5bGU9e3sgd2lkdGg6IDQ0LCBoZWlnaHQ6IDQ0LCBib3JkZXJSYWRpdXM6ICcxMnB4JywgYmFja2dyb3VuZENvbG9yOiBgJHthY2NlbnRDb2xvcn0xNWAsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJywgZmxleFNocmluazogMCB9fT5cbiAgICAgICAgPEljb24gaWNvbj17aWNvbn0gc2l6ZT17MjJ9IGNvbG9yPXthY2NlbnRDb2xvcn0gLz5cbiAgICAgIDwvZGl2PlxuICAgICAgPGRpdj5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzExcHgnLCBmb250V2VpZ2h0OiA2MDAsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJyB9fT57bGFiZWx9PC9UZXh0PlxuICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IGNvdW50ID4gMCA/IGFjY2VudENvbG9yIDogQy50ZXh0RGltLCBtYXJnaW46ICc0cHggMCAwIDAnIH19Pntjb3VudH08L0g1PlxuICAgICAgPC9kaXY+XG4gICAgICA8SWNvbiBpY29uPVwiQ2hldnJvblJpZ2h0XCIgY29sb3I9e0MudGV4dERpbX0gc3R5bGU9e3sgbWFyZ2luTGVmdDogJ2F1dG8nIH19IC8+XG4gICAgPC9Cb3g+XG4gIDwvYT5cbik7XG5cbi8qIOKUgOKUgOKUgCBGb3JtYXQgZGF0ZSBuaWNlbHkg4pSA4pSA4pSAICovXG5jb25zdCBmbXREYXRlID0gKGQpID0+IHtcbiAgaWYgKCFkKSByZXR1cm4gJ+KAlCc7XG4gIGNvbnN0IGR0ID0gbmV3IERhdGUoZCk7XG4gIHJldHVybiBkdC50b0xvY2FsZURhdGVTdHJpbmcoJ2VuLVVTJywgeyBtb250aDogJ3Nob3J0JywgZGF5OiAnbnVtZXJpYycsIHllYXI6ICdudW1lcmljJyB9KTtcbn07XG5cbi8qIOKUgOKUgOKUgCBTdGF0dXMgYmFkZ2UgY29sb3Ig4pSA4pSA4pSAICovXG5jb25zdCBzdGF0dXNDb2xvciA9IChzKSA9PiB7XG4gIGlmICghcykgcmV0dXJuIEMudGV4dERpbTtcbiAgY29uc3QgbG93ZXIgPSBzLnRvTG93ZXJDYXNlKCk7XG4gIGlmIChsb3dlciA9PT0gJ2FwcHJvdmVkJyB8fCBsb3dlciA9PT0gJ2FjdGl2ZScpIHJldHVybiBDLmdyZWVuO1xuICBpZiAobG93ZXIgPT09ICdwZW5kaW5nJykgcmV0dXJuIEMub3JhbmdlO1xuICBpZiAobG93ZXIgPT09ICdyZWplY3RlZCcpIHJldHVybiBDLnJlZDtcbiAgcmV0dXJuIEMudGV4dE11dGVkO1xufTtcblxuLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4gICBNQUlOIERBU0hCT0FSRCBDT01QT05FTlRcbiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqL1xuY29uc3QgQ3VzdG9tRGFzaGJvYXJkID0gKCkgPT4ge1xuICBjb25zdCBbZGF0YSwgc2V0RGF0YV0gPSB1c2VTdGF0ZShudWxsKTtcbiAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gdXNlU3RhdGUodHJ1ZSk7XG4gIGNvbnN0IFtlcnJvciwgc2V0RXJyb3JdID0gdXNlU3RhdGUobnVsbCk7XG5cbiAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICBhcGkuZ2V0RGFzaGJvYXJkKClcbiAgICAgIC50aGVuKChyZXNwb25zZSkgPT4ge1xuICAgICAgICBzZXREYXRhKHJlc3BvbnNlLmRhdGEgfHwge30pO1xuICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goKGZldGNoRXJyb3IpID0+IHtcbiAgICAgICAgY29uc29sZS5lcnJvcignRGFzaGJvYXJkIGZldGNoIGVycm9yOicsIGZldGNoRXJyb3IpO1xuICAgICAgICBzZXRFcnJvcignRmFpbGVkIHRvIGxvYWQgZGFzaGJvYXJkIGRhdGEuJyk7XG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgfSk7XG4gIH0sIFtdKTtcblxuICBpZiAobG9hZGluZykge1xuICAgIHJldHVybiAoXG4gICAgICA8ZGl2IHN0eWxlPXt7IG1pbkhlaWdodDogJzEwMHZoJywgYmFja2dyb3VuZENvbG9yOiBDLmJnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgIDxkaXYgc3R5bGU9e3sgdGV4dEFsaWduOiAnY2VudGVyJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IHdpZHRoOiA0MCwgaGVpZ2h0OiA0MCwgYm9yZGVyOiBgM3B4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgYm9yZGVyVG9wQ29sb3I6IEMuZ29sZCwgYm9yZGVyUmFkaXVzOiAnNTAlJywgYW5pbWF0aW9uOiAnc3BpbiAxcyBsaW5lYXIgaW5maW5pdGUnLCBtYXJnaW46ICcwIGF1dG8gMTZweCcgfX0gLz5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0TXV0ZWQgfX0+TG9hZGluZyBkYXNoYm9hcmQuLi48L1RleHQ+XG4gICAgICAgICAgPHN0eWxlPntgQGtleWZyYW1lcyBzcGluIHsgdG8geyB0cmFuc2Zvcm06IHJvdGF0ZSgzNjBkZWcpOyB9IH1gfTwvc3R5bGU+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG4gICAgKTtcbiAgfVxuXG4gIGlmIChlcnJvcikge1xuICAgIHJldHVybiAoXG4gICAgICA8ZGl2IHN0eWxlPXt7IG1pbkhlaWdodDogJzEwMHZoJywgYmFja2dyb3VuZENvbG9yOiBDLmJnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKEMucmVkKSwgbWF4V2lkdGg6IDQwMCwgdGV4dEFsaWduOiAnY2VudGVyJyB9fT5cbiAgICAgICAgICA8SWNvbiBpY29uPVwiQWxlcnRUcmlhbmdsZVwiIHNpemU9ezMyfSBjb2xvcj17Qy5yZWR9IC8+XG4gICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnJlZCwgbWFyZ2luOiAnMTZweCAwIDhweCcgfX0+e2Vycm9yfTwvSDU+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dE11dGVkIH19PkNoZWNrIHRoZSBzZXJ2ZXIgbG9ncyBmb3IgZGV0YWlscy48L1RleHQ+XG4gICAgICAgIDwvQm94PlxuICAgICAgPC9kaXY+XG4gICAgKTtcbiAgfVxuXG4gIGNvbnN0IHN0YXRzID0gZGF0YT8uc3RhdHMgfHwge307XG4gIGNvbnN0IGFjdGlvblJlcXVpcmVkID0gZGF0YT8uYWN0aW9uUmVxdWlyZWQgfHwge307XG4gIGNvbnN0IG1vZHNCeVBsYXRmb3JtID0gZGF0YT8ubW9kc0J5UGxhdGZvcm0gfHwgW107XG4gIGNvbnN0IHVzZXJHcm93dGhEYXRhID0gZGF0YT8udXNlckdyb3d0aERhdGEgfHwgW107XG4gIGNvbnN0IHJlY2VudFVzZXJzID0gZGF0YT8ucmVjZW50VXNlcnMgfHwgW107XG4gIGNvbnN0IHJlY2VudE1vZHMgPSBkYXRhPy5yZWNlbnRNb2RzIHx8IFtdO1xuXG4gIC8vIFByZXBhcmUgY2hhcnQgZGF0YVxuICBjb25zdCBncm93dGhDaGFydERhdGEgPSB1c2VyR3Jvd3RoRGF0YS5tYXAoZCA9PiAoeyBsYWJlbDogZC5kYXRlLCB2YWx1ZTogZC51c2VycyB9KSk7XG5cbiAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgY29uc3QgZ3JlZXRpbmcgPSBub3cuZ2V0SG91cnMoKSA8IDEyID8gJ0dvb2QgbW9ybmluZycgOiBub3cuZ2V0SG91cnMoKSA8IDE4ID8gJ0dvb2QgYWZ0ZXJub29uJyA6ICdHb29kIGV2ZW5pbmcnO1xuXG4gIHJldHVybiAoXG4gICAgPGRpdiBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6IEMuYmcsIG1pbkhlaWdodDogJzEwMHZoJywgcGFkZGluZzogJ2NsYW1wKDE2cHgsIDN2dywgMzJweCkgY2xhbXAoMTRweCwgM3Z3LCAzNnB4KScsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+XG4gICAgICBcbiAgICAgIHsvKiDilZDilZDilZAgSEVBREVSIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBqdXN0aWZ5Q29udGVudDogJ3NwYWNlLWJldHdlZW4nLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnMTZweCcsIHBhZGRpbmdCb3R0b206ICcyNHB4JywgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCwgbWFyZ2luQm90dG9tOiAnMjhweCcgfX0+XG4gICAgICAgIDxkaXY+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pblwiIHN0eWxlPXt7IHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBjdXJzb3I6ICdwb2ludGVyJyB9fT5cbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMTBweCcgfX0+XG4gICAgICAgICAgICAgIDxIMiBzdHlsZT17eyBtYXJnaW46IDAsIGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlxuICAgICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLmdvbGQsIHRleHRTaGFkb3c6IGAwIDAgMjBweCAke0MuZ29sZEdsb3d9YCwgZm9udFdlaWdodDogODAwIH19PkdQTDwvc3Bhbj5cbiAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCB0ZXh0U2hhZG93OiAnMCAwIDE1cHggcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjQpJywgZm9udFdlaWdodDogNzAwIH19Pk1vZHM8L3NwYW4+XG4gICAgICAgICAgICAgIDwvSDI+XG4gICAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZDcwMCcsIGZvbnRTaXplOiAnMTFweCcsIGZvbnRXZWlnaHQ6IDYwMCwgYmFja2dyb3VuZDogJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMTIpJywgcGFkZGluZzogJzRweCAxMHB4JywgYm9yZGVyUmFkaXVzOiAnMjBweCcsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwgMjE1LCAwLCAwLjM1KScsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIsIGxldHRlclNwYWNpbmc6ICcwLjA0ZW0nLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyB9fT5BZG1pbiBEYXNoYm9hcmQ8L3NwYW4+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICA8L2E+XG4gICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjZjFmNWY5JywgbWFyZ2luVG9wOiAnOHB4JywgZm9udFNpemU6ICcxNHB4JywgZm9udFdlaWdodDogNDAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiLCBsaW5lSGVpZ2h0OiAxLjUgfX0+XG4gICAgICAgICAgICB7Z3JlZXRpbmd9ISBIZXJlJ3MgeW91ciBwbGF0Zm9ybSBvdmVydmlldyBmb3Ige25vdy50b0xvY2FsZURhdGVTdHJpbmcoJ2VuLVVTJywgeyB3ZWVrZGF5OiAnbG9uZycsIG1vbnRoOiAnbG9uZycsIGRheTogJ251bWVyaWMnLCB5ZWFyOiAnbnVtZXJpYycgfSl9LlxuICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgPC9kaXY+XG5cbiAgICAgICAgey8qIOKVkOKVkOKVkCBBRE1JTiBTVUlURSBTSE9SVENVVCBCVVRUT05TIOKVkOKVkOKVkCAqL31cbiAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcxMHB4JyB9fT5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvZGFzaGJvYXJkXCIgXG4gICAgICAgICAgICBzdHlsZT17eyBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JywgY29sb3I6IEMuZ29sZCwgYmFja2dyb3VuZENvbG9yOiBDLmdvbGREaW0sIGJvcmRlcjogYDFweCBzb2xpZCAke0MuZ29sZH1gLCBwYWRkaW5nOiAnOHB4IDE0cHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTNweCcsIHRyYW5zaXRpb246ICdhbGwgMC4ycycsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyNTUsMjE1LDAsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9IEMuZ29sZERpbTsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiR28gQmFjayBUbyBEYXNoYm9hcmRcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJBcnJvd0xlZnRcIiBzaXplPXsxNH0gLz4gR28gQmFjayBUbyBEYXNoYm9hcmRcbiAgICAgICAgICA8L2E+XG5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvYWRtaW4vcmVwb3J0c1wiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnI2ZmNmI2YicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjI5LDU3LDUzLDAuMTIpJywgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMjI5LDU3LDUzLDAuMyknLCBwYWRkaW5nOiAnOHB4IDE0cHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTNweCcsIHRyYW5zaXRpb246ICdhbGwgMC4ycycgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgyMjksNTcsNTMsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDIyOSw1Nyw1MywwLjEyKSc7IH19XG4gICAgICAgICAgICB0aXRsZT1cIk1vZGVyYXRpb24gJiBNb2QgUmVwb3J0cyBDb25zb2xlXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiRmxhZ1wiIHNpemU9ezE0fSAvPiBSZXBvcnRzXG4gICAgICAgICAgPC9hPlxuXG4gICAgICAgICAgPGEgXG4gICAgICAgICAgICBocmVmPVwiL2FkbWluL3N1cHBvcnRcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyM2NGI1ZjYnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDMzLDE1MCwyNDMsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgzMywxNTAsMjQzLDAuMyknLCBwYWRkaW5nOiAnOHB4IDE0cHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRTaXplOiAnMTNweCcsIHRyYW5zaXRpb246ICdhbGwgMC4ycycgfX1cbiAgICAgICAgICAgIG9uTW91c2VFbnRlcj17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgzMywxNTAsMjQzLDAuMjUpJzsgfX1cbiAgICAgICAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSgzMywxNTAsMjQzLDAuMTIpJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiTGl2ZSBTdXBwb3J0ICYgSW5xdWlyaWVzIENvbnNvbGVcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJIZWxwQ2lyY2xlXCIgc2l6ZT17MTR9IC8+IFN1cHBvcnRcbiAgICAgICAgICA8L2E+XG5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvc3RhdHVzXCIgXG4gICAgICAgICAgICB0YXJnZXQ9XCJfYmxhbmtcIiBcbiAgICAgICAgICAgIHJlbD1cIm5vb3BlbmVyIG5vcmVmZXJyZXJcIiBcbiAgICAgICAgICAgIHN0eWxlPXt7IGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc2cHgnLCBjb2xvcjogJyM4MWM3ODQnLCBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDY3LDE2MCw3MSwwLjEyKScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDY3LDE2MCw3MSwwLjMpJywgcGFkZGluZzogJzhweCAxNHB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEzcHgnLCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoNjcsMTYwLDcxLDAuMjUpJzsgfX1cbiAgICAgICAgICAgIG9uTW91c2VMZWF2ZT17ZSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3IgPSAncmdiYSg2NywxNjAsNzEsMC4xMiknOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJMaXZlIFNlcnZlciBIZWFsdGggJiBEaWFnbm9zdGljc1wiXG4gICAgICAgICAgPlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIkFjdGl2aXR5XCIgc2l6ZT17MTR9IC8+IFN0YXR1c1xuICAgICAgICAgIDwvYT5cblxuICAgICAgICAgIDxhIFxuICAgICAgICAgICAgaHJlZj1cIi9hZG1pbi9tdXNpY1wiIFxuICAgICAgICAgICAgc3R5bGU9e3sgZGlzcGxheTogJ2lubGluZS1mbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzZweCcsIGNvbG9yOiAnI2JhNjhjOCcsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMTg2LDEwNCwyMDAsMC4xMiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgxODYsMTA0LDIwMCwwLjMpJywgcGFkZGluZzogJzhweCAxNHB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250U2l6ZTogJzEzcHgnLCB0cmFuc2l0aW9uOiAnYWxsIDAuMnMnIH19XG4gICAgICAgICAgICBvbk1vdXNlRW50ZXI9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMTg2LDEwNCwyMDAsMC4yNSknOyB9fVxuICAgICAgICAgICAgb25Nb3VzZUxlYXZlPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJhY2tncm91bmRDb2xvciA9ICdyZ2JhKDE4NiwxMDQsMjAwLDAuMTIpJzsgfX1cbiAgICAgICAgICAgIHRpdGxlPVwiTXVzaWMgJiBQbGF5bGlzdCBNYW5hZ2VyXCJcbiAgICAgICAgICA+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiTXVzaWNcIiBzaXplPXsxNH0gLz4gTXVzaWNcbiAgICAgICAgICA8L2E+XG5cbiAgICAgICAgICA8YSBcbiAgICAgICAgICAgIGhyZWY9XCIvaG9tZVwiIFxuICAgICAgICAgICAgdGFyZ2V0PVwiX2JsYW5rXCIgXG4gICAgICAgICAgICByZWw9XCJub29wZW5lciBub3JlZmVycmVyXCIgXG4gICAgICAgICAgICBzdHlsZT17eyBkaXNwbGF5OiAnaW5saW5lLWZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnNnB4JywgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiBDLnN1cmZhY2VBbHQsIGJvcmRlcjogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAsIHBhZGRpbmc6ICc4cHggMTRweCcsIGJvcmRlclJhZGl1czogJzhweCcsIHRleHREZWNvcmF0aW9uOiAnbm9uZScsIGZvbnRXZWlnaHQ6IDYwMCwgZm9udFNpemU6ICcxM3B4JywgdHJhbnNpdGlvbjogJ2FsbCAwLjJzJyB9fVxuICAgICAgICAgICAgb25Nb3VzZUVudGVyPXtlID0+IHsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJvcmRlckNvbG9yID0gQy5nb2xkOyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuY29sb3IgPSBDLmdvbGQ7IH19XG4gICAgICAgICAgICBvbk1vdXNlTGVhdmU9e2UgPT4geyBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm9yZGVyQ29sb3IgPSBDLmJvcmRlcjsgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmNvbG9yID0gJyNmZmZmZmYnOyB9fVxuICAgICAgICAgICAgdGl0bGU9XCJPcGVuIExpdmUgUHVibGljIFNpdGVcIlxuICAgICAgICAgID5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJHbG9iZVwiIHNpemU9ezE0fSAvPiBMaXZlIFNpdGVcbiAgICAgICAgICA8L2E+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgU1RBVCBDQVJEUyDilZDilZDilZAgKi99XG4gICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnMTZweCcsIG1hcmdpbkJvdHRvbTogJzI0cHgnIH19PlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIlVzZXJzXCIgbGFiZWw9XCJUb3RhbCBVc2Vyc1wiIHZhbHVlPXsoc3RhdHMudG90YWxVc2VycyB8fCAwKS50b0xvY2FsZVN0cmluZygpfSBkZWx0YT17c3RhdHMubmV3VXNlcnNUaGlzTW9udGh9IGFjY2VudENvbG9yPXtDLmJsdWV9IC8+XG4gICAgICAgIDxTdGF0Q2FyZCBpY29uPVwiUGFja2FnZVwiIGxhYmVsPVwiVG90YWwgTW9kc1wiIHZhbHVlPXsoc3RhdHMudG90YWxNb2RzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGRlbHRhPXtzdGF0cy5uZXdNb2RzVGhpc01vbnRofSBhY2NlbnRDb2xvcj17Qy5nb2xkfSAvPlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIkRvd25sb2FkXCIgbGFiZWw9XCJUb3RhbCBEb3dubG9hZHNcIiB2YWx1ZT17KHN0YXRzLnRvdGFsRG93bmxvYWRzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IGFjY2VudENvbG9yPXtDLmdyZWVufSAvPlxuICAgICAgICA8U3RhdENhcmQgaWNvbj1cIkV5ZVwiIGxhYmVsPVwiVG90YWwgVmlld3NcIiB2YWx1ZT17KHN0YXRzLnRvdGFsVmlld3MgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gYWNjZW50Q29sb3I9e0MucHVycGxlfSAvPlxuICAgICAgPC9kaXY+XG5cbiAgICAgIHsvKiDilZDilZDilZAgQUNUSU9OIFJFUVVJUkVEIOKVkOKVkOKVkCAqL31cbiAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBmbGV4V3JhcDogJ3dyYXAnLCBnYXA6ICcxNHB4JywgbWFyZ2luQm90dG9tOiAnMzJweCcgfX0+XG4gICAgICAgIDxBY3Rpb25DYXJkIGljb249XCJGbGFnXCIgbGFiZWw9XCJQZW5kaW5nIFJlcG9ydHNcIiBjb3VudD17YWN0aW9uUmVxdWlyZWQucGVuZGluZ1JlcG9ydHMgfHwgMH0gYWNjZW50Q29sb3I9e0MucmVkfSByZXNvdXJjZUlkPVwiUmVwb3J0XCIgLz5cbiAgICAgICAgPEFjdGlvbkNhcmQgaWNvbj1cIkNoZWNrU3F1YXJlXCIgbGFiZWw9XCJQZW5kaW5nIEFwcHJvdmFsc1wiIGNvdW50PXthY3Rpb25SZXF1aXJlZC5wZW5kaW5nQXBwcm92YWxzIHx8IDB9IGFjY2VudENvbG9yPXtDLm9yYW5nZX0gcmVzb3VyY2VJZD1cIkZpbGVcIiAvPlxuICAgICAgICA8QWN0aW9uQ2FyZCBpY29uPVwiSGVscENpcmNsZVwiIGxhYmVsPVwiT3BlbiBUaWNrZXRzXCIgY291bnQ9e2FjdGlvblJlcXVpcmVkLm9wZW5UaWNrZXRzIHx8IDB9IGFjY2VudENvbG9yPXtDLmJsdWV9IHJlc291cmNlSWQ9XCJTdXBwb3J0VGlja2V0XCIgLz5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIENIQVJUUyBST1cg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzIwcHgnLCBtYXJnaW5Cb3R0b206ICczMnB4JyB9fT5cbiAgICAgICAgey8qIFVzZXIgR3Jvd3RoIENoYXJ0ICovfVxuICAgICAgICA8Qm94IHN0eWxlPXt7IC4uLmNhcmRTdHlsZSgpLCBmbGV4OiAnMiAxIDMyMHB4JywgbWluV2lkdGg6IDAsIHdpZHRoOiAnMTAwJScgfX0+XG4gICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICc4cHgnLCBtYXJnaW5Cb3R0b206ICcxOHB4JyB9fT5cbiAgICAgICAgICAgIDxJY29uIGljb249XCJBY3Rpdml0eVwiIGNvbG9yPXtDLmdvbGR9IC8+XG4gICAgICAgICAgICA8SDUgc3R5bGU9e3sgY29sb3I6IEMudGV4dCwgbWFyZ2luOiAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlVzZXIgR3Jvd3RoPC9INT5cbiAgICAgICAgICAgIDxCYWRnZSBzdHlsZT17eyBtYXJnaW5MZWZ0OiAnOHB4JywgYmFja2dyb3VuZENvbG9yOiBDLmdvbGREaW0sIGNvbG9yOiBDLmdvbGQsIGJvcmRlcjogJ25vbmUnLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PjMwIGRheXM8L0JhZGdlPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIHtncm93dGhDaGFydERhdGEubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDxBcmVhQ2hhcnQgZGF0YT17Z3Jvd3RoQ2hhcnREYXRhfSBjb2xvcj17Qy5nb2xkfSB3aWR0aD17NTAwfSBoZWlnaHQ9ezE3MH0gLz5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBoZWlnaHQ6IDE2MCwgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInIH19PlxuICAgICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19Pk5vIHVzZXIgc2lnbnVwcyBpbiB0aGUgbGFzdCAzMCBkYXlzLjwvVGV4dD5cbiAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvQm94PlxuXG4gICAgICAgIHsvKiBQbGF0Zm9ybSBEb251dCAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzEgMSAyODBweCcsIG1pbldpZHRoOiAwLCB3aWR0aDogJzEwMCUnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMThweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiUGllQ2hhcnRcIiBjb2xvcj17Qy5ibHVlfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5Nb2RzIGJ5IFBsYXRmb3JtPC9INT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7bW9kc0J5UGxhdGZvcm0ubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDxEb251dENoYXJ0IGRhdGE9e21vZHNCeVBsYXRmb3JtfSBzaXplPXsxODB9IC8+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgaGVpZ2h0OiAxNjAsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5ObyBwbGF0Zm9ybSBkYXRhIGF2YWlsYWJsZS48L1RleHQ+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7Lyog4pWQ4pWQ4pWQIFJFQ0VOVCBBQ1RJVklUWSBST1cg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGdhcDogJzIwcHgnLCBtYXJnaW5Cb3R0b206ICczMnB4JyB9fT5cbiAgICAgICAgey8qIFJlY2VudCBVc2VycyAqL31cbiAgICAgICAgPEJveCBzdHlsZT17eyAuLi5jYXJkU3R5bGUoKSwgZmxleDogJzEgMSAzMjBweCcsIG1pbldpZHRoOiAwLCB3aWR0aDogJzEwMCUnIH19PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywgZ2FwOiAnOHB4JywgbWFyZ2luQm90dG9tOiAnMThweCcgfX0+XG4gICAgICAgICAgICA8SWNvbiBpY29uPVwiVXNlcnNcIiBjb2xvcj17Qy5ibHVlfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5SZWNlbnQgVXNlcnM8L0g1PlxuICAgICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvVXNlclwiIHN0eWxlPXt7IG1hcmdpbkxlZnQ6ICdhdXRvJywgY29sb3I6IEMuZ29sZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNjAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19PlZpZXcgQWxsIOKGkjwvYT5cbiAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICB7cmVjZW50VXNlcnMubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgb3ZlcmZsb3dYOiAnYXV0bycsIHdpZHRoOiAnMTAwJScsIFdlYmtpdE92ZXJmbG93U2Nyb2xsaW5nOiAndG91Y2gnIH19PlxuICAgICAgICAgICAgICA8dGFibGUgc3R5bGU9e3sgd2lkdGg6ICcxMDAlJywgYm9yZGVyQ29sbGFwc2U6ICdjb2xsYXBzZScsIG1pbldpZHRoOiAnMzAwcHgnIH19PlxuICAgICAgICAgICAgICAgIDx0aGVhZD5cbiAgICAgICAgICAgICAgICAgIDx0ciBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgICA8dGggc3R5bGU9e3sgdGV4dEFsaWduOiAnbGVmdCcsIHBhZGRpbmc6ICc4cHggMCcsIGNvbG9yOiAnIzk0YTNiOCcsIGZvbnRTaXplOiAnMTFweCcsIHRleHRUcmFuc2Zvcm06ICd1cHBlcmNhc2UnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJywgZm9udFdlaWdodDogNjAwIH19PlVzZXJuYW1lPC90aD5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5Sb2xlPC90aD5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ3JpZ2h0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+Sm9pbmVkPC90aD5cbiAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgPC90aGVhZD5cbiAgICAgICAgICAgICAgICA8dGJvZHk+XG4gICAgICAgICAgICAgICAgICB7cmVjZW50VXNlcnMubWFwKCh1LCBpKSA9PiAoXG4gICAgICAgICAgICAgICAgICAgIDx0ciBrZXk9e2l9IHN0eWxlPXt7IGJvcmRlckJvdHRvbTogYDFweCBzb2xpZCAke0MuYm9yZGVyfWAgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPXt7IHBhZGRpbmc6ICcxMHB4IDAnLCBjb2xvcjogQy50ZXh0LCBmb250U2l6ZTogJzEzcHgnLCBmb250V2VpZ2h0OiA1MDAgfX0+e3UudXNlcm5hbWV9PC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzExcHgnLCBwYWRkaW5nOiAnM3B4IDhweCcsIGJvcmRlclJhZGl1czogJzZweCcsIGJhY2tncm91bmRDb2xvcjogdS5yb2xlID09PSAnYWRtaW4nID8gYCR7Qy5nb2xkfTIwYCA6IGAke0MuYmx1ZX0yMGAsIGNvbG9yOiB1LnJvbGUgPT09ICdhZG1pbicgPyBDLmdvbGQgOiBDLmJsdWUsIGZvbnRXZWlnaHQ6IDYwMCB9fT57dS5yb2xlIHx8ICd1c2VyJ308L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcsIGNvbG9yOiBDLnRleHRNdXRlZCwgZm9udFNpemU6ICcxMnB4JywgdGV4dEFsaWduOiAncmlnaHQnIH19PntmbXREYXRlKHUuZGF0ZSl9PC90ZD5cbiAgICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICAgICkpfVxuICAgICAgICAgICAgICAgIDwvdGJvZHk+XG4gICAgICAgICAgICAgIDwvdGFibGU+XG4gICAgICAgICAgICA8L2Rpdj5cbiAgICAgICAgICApIDogKFxuICAgICAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6IEMudGV4dERpbSwgdGV4dEFsaWduOiAnY2VudGVyJywgcGFkZGluZzogJzIwcHggMCcgfX0+Tm8gcmVjZW50IHVzZXJzLjwvVGV4dD5cbiAgICAgICAgICApfVxuICAgICAgICA8L0JveD5cblxuICAgICAgICB7LyogUmVjZW50IE1vZHMgKi99XG4gICAgICAgIDxCb3ggc3R5bGU9e3sgLi4uY2FyZFN0eWxlKCksIGZsZXg6ICcxIDEgMzIwcHgnLCBtaW5XaWR0aDogMCwgd2lkdGg6ICcxMDAlJyB9fT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGdhcDogJzhweCcsIG1hcmdpbkJvdHRvbTogJzE4cHgnIH19PlxuICAgICAgICAgICAgPEljb24gaWNvbj1cIlBhY2thZ2VcIiBjb2xvcj17Qy5nb2xkfSAvPlxuICAgICAgICAgICAgPEg1IHN0eWxlPXt7IGNvbG9yOiBDLnRleHQsIG1hcmdpbjogMCwgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5SZWNlbnQgTW9kczwvSDU+XG4gICAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9GaWxlXCIgc3R5bGU9e3sgbWFyZ2luTGVmdDogJ2F1dG8nLCBjb2xvcjogQy5nb2xkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA2MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+VmlldyBBbGwg4oaSPC9hPlxuICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgIHtyZWNlbnRNb2RzLmxlbmd0aCA+IDAgPyAoXG4gICAgICAgICAgICA8ZGl2IHN0eWxlPXt7IG92ZXJmbG93WDogJ2F1dG8nLCB3aWR0aDogJzEwMCUnLCBXZWJraXRPdmVyZmxvd1Njcm9sbGluZzogJ3RvdWNoJyB9fT5cbiAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPXt7IHdpZHRoOiAnMTAwJScsIGJvcmRlckNvbGxhcHNlOiAnY29sbGFwc2UnLCBtaW5XaWR0aDogJzMwMHB4JyB9fT5cbiAgICAgICAgICAgICAgICA8dGhlYWQ+XG4gICAgICAgICAgICAgICAgICA8dHIgc3R5bGU9e3sgYm9yZGVyQm90dG9tOiBgMXB4IHNvbGlkICR7Qy5ib3JkZXJ9YCB9fT5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5OYW1lPC90aD5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ2xlZnQnLCBwYWRkaW5nOiAnOHB4IDAnLCBjb2xvcjogJyM5NGEzYjgnLCBmb250U2l6ZTogJzExcHgnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsIGZvbnRXZWlnaHQ6IDYwMCB9fT5QbGF0Zm9ybTwvdGg+XG4gICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT17eyB0ZXh0QWxpZ246ICdsZWZ0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+U3RhdHVzPC90aD5cbiAgICAgICAgICAgICAgICAgICAgPHRoIHN0eWxlPXt7IHRleHRBbGlnbjogJ3JpZ2h0JywgcGFkZGluZzogJzhweCAwJywgY29sb3I6ICcjOTRhM2I4JywgZm9udFNpemU6ICcxMXB4JywgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsIGxldHRlclNwYWNpbmc6ICcwLjA2ZW0nLCBmb250V2VpZ2h0OiA2MDAgfX0+QWRkZWQ8L3RoPlxuICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICA8L3RoZWFkPlxuICAgICAgICAgICAgICAgIDx0Ym9keT5cbiAgICAgICAgICAgICAgICAgIHtyZWNlbnRNb2RzLm1hcCgobSwgaSkgPT4gKFxuICAgICAgICAgICAgICAgICAgICA8dHIga2V5PXtpfSBzdHlsZT17eyBib3JkZXJCb3R0b206IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dCwgZm9udFNpemU6ICcxM3B4JywgZm9udFdlaWdodDogNTAwLCBtYXhXaWR0aDogJzE4MHB4Jywgb3ZlcmZsb3c6ICdoaWRkZW4nLCB0ZXh0T3ZlcmZsb3c6ICdlbGxpcHNpcycsIHdoaXRlU3BhY2U6ICdub3dyYXAnIH19PnttLm5hbWV9PC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzExcHgnLCBwYWRkaW5nOiAnM3B4IDhweCcsIGJvcmRlclJhZGl1czogJzZweCcsIGJhY2tncm91bmRDb2xvcjogYCR7Qy5ibHVlfTIwYCwgY29sb3I6IEMuYmx1ZSwgZm9udFdlaWdodDogNjAwLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyB9fT57bS5jYXRlZ29yeSB8fCAn4oCUJ308L3NwYW4+XG4gICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9e3sgcGFkZGluZzogJzEwcHggMCcgfX0+XG4gICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT17eyBmb250U2l6ZTogJzExcHgnLCBwYWRkaW5nOiAnM3B4IDhweCcsIGJvcmRlclJhZGl1czogJzZweCcsIGJhY2tncm91bmRDb2xvcjogYCR7c3RhdHVzQ29sb3IobS5zdGF0dXMpfTIwYCwgY29sb3I6IHN0YXR1c0NvbG9yKG0uc3RhdHVzKSwgZm9udFdlaWdodDogNjAwLCB0ZXh0VHJhbnNmb3JtOiAnY2FwaXRhbGl6ZScgfX0+e20uc3RhdHVzIHx8ICfigJQnfTwvc3Bhbj5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT17eyBwYWRkaW5nOiAnMTBweCAwJywgY29sb3I6IEMudGV4dE11dGVkLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0QWxpZ246ICdyaWdodCcgfX0+e2ZtdERhdGUobS5kYXRlKX08L3RkPlxuICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgKSl9XG4gICAgICAgICAgICAgICAgPC90Ym9keT5cbiAgICAgICAgICAgICAgPC90YWJsZT5cbiAgICAgICAgICAgIDwvZGl2PlxuICAgICAgICAgICkgOiAoXG4gICAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogQy50ZXh0RGltLCB0ZXh0QWxpZ246ICdjZW50ZXInLCBwYWRkaW5nOiAnMjBweCAwJyB9fT5ObyByZWNlbnQgbW9kcy48L1RleHQ+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9Cb3g+XG4gICAgICA8L2Rpdj5cblxuICAgICAgey8qIOKVkOKVkOKVkCBGT09URVIg4pWQ4pWQ4pWQICovfVxuICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGZsZXhXcmFwOiAnd3JhcCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcxNHB4JywgcGFkZGluZ1RvcDogJzIwcHgnLCBib3JkZXJUb3A6IGAxcHggc29saWQgJHtDLmJvcmRlcn1gIH19PlxuICAgICAgICA8YSBocmVmPVwiL2FkbWluXCIgc3R5bGU9e3sgdGV4dERlY29yYXRpb246ICdub25lJyB9fT5cbiAgICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBmb250U2l6ZTogJzEzcHgnLCBjdXJzb3I6ICdwb2ludGVyJywgZm9udEZhbWlseTogXCInUG9wcGlucycsIHNhbnMtc2VyaWZcIiB9fT5cbiAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiBDLmdvbGQsIGZvbnRXZWlnaHQ6IDcwMCB9fT5HUEw8L3NwYW4+IDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGZvbnRXZWlnaHQ6IDYwMCB9fT5Nb2RzPC9zcGFuPiDigKIgQWRtaW4gUGFuZWwgdjIuNVxuICAgICAgICAgIDwvVGV4dD5cbiAgICAgICAgPC9hPlxuICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywgZmxleFdyYXA6ICd3cmFwJywgZ2FwOiAnOHB4JyB9fT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9Vc2VyXCIgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjA2KScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSknLCBwYWRkaW5nOiAnNXB4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA1MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+VXNlcnM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvRmlsZVwiIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC4wNiknLCBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpJywgcGFkZGluZzogJzVweCAxMnB4JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgZm9udFNpemU6ICcxMnB4JywgdGV4dERlY29yYXRpb246ICdub25lJywgZm9udFdlaWdodDogNTAwLCBmb250RmFtaWx5OiBcIidQb3BwaW5zJywgc2Fucy1zZXJpZlwiIH19Pk1vZHM8L2E+XG4gICAgICAgICAgPGEgaHJlZj1cIi9hZG1pbi9yZXNvdXJjZXMvUmVwb3J0XCIgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjA2KScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSknLCBwYWRkaW5nOiAnNXB4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA1MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+UmVwb3J0czwvYT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL3Jlc291cmNlcy9TdXBwb3J0VGlja2V0XCIgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjA2KScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSknLCBwYWRkaW5nOiAnNXB4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA1MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+VGlja2V0czwvYT5cbiAgICAgICAgICA8YSBocmVmPVwiL2FkbWluL211c2ljXCIgc3R5bGU9e3sgY29sb3I6ICcjZmZmZmZmJywgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjA2KScsIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMSknLCBwYWRkaW5nOiAnNXB4IDEycHgnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBmb250U2l6ZTogJzEycHgnLCB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBmb250V2VpZ2h0OiA1MDAsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIgfX0+TXVzaWM8L2E+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG4gICAgPC9kaXY+XG4gICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBDdXN0b21EYXNoYm9hcmQ7XG4iLCJpbXBvcnQgUmVhY3QgZnJvbSAncmVhY3QnO1xuaW1wb3J0IHsgQm94LCBJY29uIH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XG5cbmNvbnN0IFNpZGViYXJCcmFuZGluZyA9ICgpID0+IHtcbiAgcmV0dXJuIChcbiAgICA8Qm94IFxuICAgICAgZmxleCBcbiAgICAgIGZsZXhEaXJlY3Rpb249XCJjb2x1bW5cIlxuICAgICAgYWxpZ25JdGVtcz1cImNlbnRlclwiIFxuICAgICAganVzdGlmeUNvbnRlbnQ9XCJjZW50ZXJcIiBcbiAgICAgIHA9XCJsZ1wiIFxuICAgICAgc3R5bGU9e3sgXG4gICAgICAgIGJvcmRlckJvdHRvbTogJzFweCBzb2xpZCAjMmEyYTJhJywgXG4gICAgICAgIGJhY2tncm91bmRDb2xvcjogJyMwYTBhMGEnLCBcbiAgICAgICAgcGFkZGluZzogJzIwcHggMTZweCcsXG4gICAgICAgIHBvc2l0aW9uOiAncmVsYXRpdmUnLFxuICAgICAgICBvdmVyZmxvdzogJ2hpZGRlbidcbiAgICAgIH19XG4gICAgPlxuICAgICAgey8qIFN1YnRsZSBnb2xkIGdsb3cgdW5kZXJsaW5lICovfVxuICAgICAgPGRpdiBzdHlsZT17e1xuICAgICAgICBwb3NpdGlvbjogJ2Fic29sdXRlJyxcbiAgICAgICAgYm90dG9tOiAwLFxuICAgICAgICBsZWZ0OiAnNTAlJyxcbiAgICAgICAgdHJhbnNmb3JtOiAndHJhbnNsYXRlWCgtNTAlKScsXG4gICAgICAgIHdpZHRoOiAnNjAlJyxcbiAgICAgICAgaGVpZ2h0OiAnMXB4JyxcbiAgICAgICAgYmFja2dyb3VuZDogJ2xpbmVhci1ncmFkaWVudCg5MGRlZywgdHJhbnNwYXJlbnQsIHJnYmEoMjU1LDIxNSwwLDAuNSksIHRyYW5zcGFyZW50KSdcbiAgICAgIH19IC8+XG5cbiAgICAgIHsvKiBNYWluIExvZ28gJiBUaXRsZSBMaW5rICovfVxuICAgICAgPGEgXG4gICAgICAgIGhyZWY9XCIvYWRtaW5cIiBcbiAgICAgICAgc3R5bGU9e3sgXG4gICAgICAgICAgdGV4dERlY29yYXRpb246ICdub25lJywgXG4gICAgICAgICAgZGlzcGxheTogJ2ZsZXgnLCBcbiAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJywgXG4gICAgICAgICAgZ2FwOiAnMTBweCcsXG4gICAgICAgICAgY3Vyc29yOiAncG9pbnRlcicsXG4gICAgICAgICAgdHJhbnNpdGlvbjogJ29wYWNpdHkgMC4ycyBlYXNlJ1xuICAgICAgICB9fVxuICAgICAgICBvbk1vdXNlRW50ZXI9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5vcGFjaXR5ID0gJzAuODUnOyB9fVxuICAgICAgICBvbk1vdXNlTGVhdmU9eyhlKSA9PiB7IGUuY3VycmVudFRhcmdldC5zdHlsZS5vcGFjaXR5ID0gJzEnOyB9fVxuICAgICAgPlxuICAgICAgICA8aW1nIFxuICAgICAgICAgIHNyYz1cIi9pbWFnZXMvdGVhbS1sb2dvLnBuZ1wiIFxuICAgICAgICAgIGFsdD1cIkxvZ29cIiBcbiAgICAgICAgICBzdHlsZT17eyBoZWlnaHQ6ICczMnB4Jywgd2lkdGg6ICczMnB4Jywgb2JqZWN0Rml0OiAnY292ZXInLCBib3JkZXJSYWRpdXM6ICc2cHgnLCBmaWx0ZXI6ICdkcm9wLXNoYWRvdygwIDAgNnB4IHJnYmEoMjU1LDIxNSwwLDAuMykpJyB9fSBcbiAgICAgICAgICBvbkVycm9yPXsoZSkgPT4gZS50YXJnZXQuc3R5bGUuZGlzcGxheSA9ICdub25lJ31cbiAgICAgICAgLz5cbiAgICAgICAgPGRpdiBzdHlsZT17eyBmb250U2l6ZTogJzIycHgnLCBmb250V2VpZ2h0OiAnYm9sZCcsIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCIsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2Jhc2VsaW5lJywgZ2FwOiAnNHB4JyB9fT5cbiAgICAgICAgICA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyNGRkQ3MDAnLCB0ZXh0U2hhZG93OiAnMCAwIDEycHggcmdiYSgyNTUsIDIxNSwgMCwgMC40KScgfX0+R1BMPC9zcGFuPlxuICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcsIHRleHRTaGFkb3c6ICcwIDAgMTJweCByZ2JhKDE5MiwgMTkyLCAxOTIsIDAuNSknIH19Pk1vZHM8L3NwYW4+XG4gICAgICAgICAgPHNwYW4gc3R5bGU9e3sgZm9udFNpemU6ICc5cHgnLCBjb2xvcjogJyM1NTUnLCBmb250V2VpZ2h0OiA2MDAsIG1hcmdpbkxlZnQ6ICc2cHgnLCBsZXR0ZXJTcGFjaW5nOiAnMC4wNWVtJyB9fT52Mi41PC9zcGFuPlxuICAgICAgICA8L2Rpdj5cbiAgICAgIDwvYT5cblxuICAgICAgey8qIFF1aWNrIERhc2hib2FyZCBTaG9ydGN1dCBCdXR0b24gKi99XG4gICAgICA8YSBcbiAgICAgICAgaHJlZj1cIi9hZG1pblwiIFxuICAgICAgICBzdHlsZT17e1xuICAgICAgICAgIGRpc3BsYXk6ICdmbGV4JyxcbiAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJyxcbiAgICAgICAgICBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicsXG4gICAgICAgICAgZ2FwOiAnOHB4JyxcbiAgICAgICAgICBtYXJnaW5Ub3A6ICcxMnB4JyxcbiAgICAgICAgICBwYWRkaW5nOiAnNnB4IDE2cHgnLFxuICAgICAgICAgIHdpZHRoOiAnODUlJyxcbiAgICAgICAgICBib3JkZXJSYWRpdXM6ICc4cHgnLFxuICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMDgpJyxcbiAgICAgICAgICBib3JkZXI6ICcxcHggc29saWQgcmdiYSgyNTUsIDIxNSwgMCwgMC4yNSknLFxuICAgICAgICAgIGNvbG9yOiAnI0ZGRDcwMCcsXG4gICAgICAgICAgdGV4dERlY29yYXRpb246ICdub25lJyxcbiAgICAgICAgICBmb250U2l6ZTogJzEycHgnLFxuICAgICAgICAgIGZvbnRXZWlnaHQ6IDcwMCxcbiAgICAgICAgICBsZXR0ZXJTcGFjaW5nOiAnMC4wNGVtJyxcbiAgICAgICAgICB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJyxcbiAgICAgICAgICB0cmFuc2l0aW9uOiAnYWxsIDAuMnMgZWFzZScsXG4gICAgICAgICAgY3Vyc29yOiAncG9pbnRlcidcbiAgICAgICAgfX1cbiAgICAgICAgb25Nb3VzZUVudGVyPXsoZSkgPT4geyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMiknOyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYm94U2hhZG93ID0gJzAgMCAxNHB4IHJnYmEoMjU1LDIxNSwwLDAuMyknOyBcbiAgICAgICAgfX1cbiAgICAgICAgb25Nb3VzZUxlYXZlPXsoZSkgPT4geyBcbiAgICAgICAgICBlLmN1cnJlbnRUYXJnZXQuc3R5bGUuYmFja2dyb3VuZENvbG9yID0gJ3JnYmEoMjU1LCAyMTUsIDAsIDAuMDgpJzsgXG4gICAgICAgICAgZS5jdXJyZW50VGFyZ2V0LnN0eWxlLmJveFNoYWRvdyA9ICdub25lJzsgXG4gICAgICAgIH19XG4gICAgICA+XG4gICAgICAgIDxJY29uIGljb249XCJIb21lXCIgc2l6ZT17MTN9IGNvbG9yPVwiI0ZGRDcwMFwiIC8+XG4gICAgICAgIDxzcGFuPkRhc2hib2FyZDwvc3Bhbj5cbiAgICAgIDwvYT5cbiAgICA8L0JveD5cbiAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IFNpZGViYXJCcmFuZGluZztcbiIsImltcG9ydCBSZWFjdCwgeyB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3gsIFRleHQsIExvYWRlciB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuaW1wb3J0IHsgdXNlTm90aWNlIH0gZnJvbSAnYWRtaW5qcyc7XG5cbmNvbnN0IEFjdGlvblJlZGlyZWN0ID0gKHByb3BzKSA9PiB7XG4gICAgY29uc3QgeyByZWNvcmQsIGFjdGlvbiB9ID0gcHJvcHM7XG4gICAgY29uc3Qgc2VuZE5vdGljZSA9IHVzZU5vdGljZSgpO1xuXG4gICAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICAgICAgY29uc3QgdXJsID0gcmVjb3JkPy5wYXJhbXM/LnJlZGlyZWN0VXJsO1xuICAgICAgICBcbiAgICAgICAgaWYgKHVybCkge1xuICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgd2luZG93Lm9wZW4odXJsLCAnX2JsYW5rJyk7XG4gICAgICAgICAgICB9LCA1MDApO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgc2VuZE5vdGljZSh7IG1lc3NhZ2U6ICdFcnJvcjogTm8gcmVkaXJlY3QgVVJMIHByb3ZpZGVkLicsIHR5cGU6ICdlcnJvcicgfSk7XG4gICAgICAgIH1cbiAgICB9LCBbcmVjb3JkXSk7XG5cbiAgICByZXR1cm4gKFxuICAgICAgICA8Qm94IGZsZXggZmxleERpcmVjdGlvbj1cImNvbHVtblwiIGFsaWduSXRlbXM9XCJjZW50ZXJcIiBqdXN0aWZ5Q29udGVudD1cImNlbnRlclwiIHA9XCJ4eGxcIj5cbiAgICAgICAgICAgIDxMb2FkZXIgLz5cbiAgICAgICAgICAgIDxUZXh0IG10PVwibGdcIiB2YXJpYW50PVwiaDRcIj5SZWRpcmVjdGluZy4uLjwvVGV4dD5cbiAgICAgICAgPC9Cb3g+XG4gICAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEFjdGlvblJlZGlyZWN0O1xuIiwiaW1wb3J0IFJlYWN0IGZyb20gJ3JlYWN0JztcblxuY29uc3QgVmFyaWFudEJhZGdlID0gKHByb3BzKSA9PiB7XG4gIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSB9ID0gcHJvcHM7XG4gIGNvbnN0IGlzVmFyaWFudCA9IHJlY29yZC5wYXJhbXNbcHJvcGVydHkubmFtZV07XG5cbiAgaWYgKGlzVmFyaWFudCA9PT0gdHJ1ZSB8fCBpc1ZhcmlhbnQgPT09ICd0cnVlJykge1xuICAgIHJldHVybiAoXG4gICAgICA8c3BhblxuICAgICAgICBjbGFzc05hbWU9XCJhZG1pbi1jdXN0b20tY2hpcFwiXG4gICAgICAgIGRhdGEtYmFkZ2UtdmFsPVwidmFyaWFudC1jaGlsZFwiXG4gICAgICAgIHN0eWxlPXt7XG4gICAgICAgICAgZGlzcGxheTogJ2lubGluZS1mbGV4JyxcbiAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJyxcbiAgICAgICAgICBnYXA6ICc2cHgnLFxuICAgICAgICAgIHBhZGRpbmc6ICczcHggMTBweCcsXG4gICAgICAgICAgYm9yZGVyUmFkaXVzOiAnMjBweCcsXG4gICAgICAgICAgZm9udFNpemU6ICcxMXB4JyxcbiAgICAgICAgICBmb250V2VpZ2h0OiA3MDAsXG4gICAgICAgICAgbGV0dGVyU3BhY2luZzogJzAuMDZlbScsXG4gICAgICAgICAgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsXG4gICAgICAgICAgYmFja2dyb3VuZDogJ2xpbmVhci1ncmFkaWVudCgxNDVkZWcsIHJnYmEoMTg2LCAxMDQsIDIwMCwgMC4yMikgMCUsIHJnYmEoNjUsIDI1LCA3NSwgMC4yNSkgMTAwJSknLFxuICAgICAgICAgIGNvbG9yOiAnI2NlOTNkOCcsXG4gICAgICAgICAgYm9yZGVyOiAnMXB4IHNvbGlkIHJnYmEoMTg2LCAxMDQsIDIwMCwgMC42KScsXG4gICAgICAgICAgYm94U2hhZG93OiAnaW5zZXQgMCAxLjVweCAycHggcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjIpLCBpbnNldCAwIC0xLjVweCAycHggcmdiYSgwLCAwLCAwLCAwLjgpLCAwIDAgMTBweCByZ2JhKDE4NiwgMTA0LCAyMDAsIDAuMjUpJyxcbiAgICAgICAgICB0ZXh0U2hhZG93OiAnMCAwIDZweCByZ2JhKDIwNiwgMTQ3LCAyMTYsIDAuNCknLFxuICAgICAgICAgIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCJcbiAgICAgICAgfX1cbiAgICAgID5cbiAgICAgICAgVmFyaWFudFxuICAgICAgPC9zcGFuPlxuICAgICk7XG4gIH1cblxuICByZXR1cm4gKFxuICAgIDxzcGFuXG4gICAgICBjbGFzc05hbWU9XCJhZG1pbi1jdXN0b20tY2hpcFwiXG4gICAgICBkYXRhLWJhZGdlLXZhbD1cInZhcmlhbnQtbWFzdGVyXCJcbiAgICAgIHN0eWxlPXt7XG4gICAgICAgIGRpc3BsYXk6ICdpbmxpbmUtZmxleCcsXG4gICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInLFxuICAgICAgICBnYXA6ICc2cHgnLFxuICAgICAgICBwYWRkaW5nOiAnM3B4IDEwcHgnLFxuICAgICAgICBib3JkZXJSYWRpdXM6ICcyMHB4JyxcbiAgICAgICAgZm9udFNpemU6ICcxMXB4JyxcbiAgICAgICAgZm9udFdlaWdodDogNzAwLFxuICAgICAgICBsZXR0ZXJTcGFjaW5nOiAnMC4wNmVtJyxcbiAgICAgICAgdGV4dFRyYW5zZm9ybTogJ3VwcGVyY2FzZScsXG4gICAgICAgIGJhY2tncm91bmQ6ICdsaW5lYXItZ3JhZGllbnQoMTQ1ZGVnLCByZ2JhKDI1NSwgMjE1LCAwLCAwLjIyKSAwJSwgcmdiYSg5MCwgNzAsIDE1LCAwLjI1KSAxMDAlKScsXG4gICAgICAgIGNvbG9yOiAnI0ZGRDcwMCcsXG4gICAgICAgIGJvcmRlcjogJzFweCBzb2xpZCByZ2JhKDI1NSwgMjE1LCAwLCAwLjY1KScsXG4gICAgICAgIGJveFNoYWRvdzogJ2luc2V0IDAgMS41cHggMnB4IHJnYmEoMjU1LCAyNTUsIDI1NSwgMC4yMiksIGluc2V0IDAgLTEuNXB4IDJweCByZ2JhKDAsIDAsIDAsIDAuOCksIDAgMCAxMHB4IHJnYmEoMjU1LCAyMTUsIDAsIDAuMjUpJyxcbiAgICAgICAgdGV4dFNoYWRvdzogJzAgMCA2cHggcmdiYSgyNTUsIDIxNSwgMCwgMC40KScsXG4gICAgICAgIGZvbnRGYW1pbHk6IFwiJ1BvcHBpbnMnLCBzYW5zLXNlcmlmXCJcbiAgICAgIH19XG4gICAgPlxuICAgICAgTWFzdGVyXG4gICAgPC9zcGFuPlxuICApO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgVmFyaWFudEJhZGdlO1xuIiwiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlLCB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgeyBCb3ggfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcblxuY29uc3QgQXZhdGFyQ2VsbCA9IChwcm9wcykgPT4ge1xuICAgIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSwgd2hlcmUgfSA9IHByb3BzOyBcbiAgICBjb25zdCBrZXkgPSByZWNvcmQucGFyYW1zW3Byb3BlcnR5Lm5hbWVdO1xuICAgIGNvbnN0IHVzZXJuYW1lID0gcmVjb3JkLnBhcmFtcy51c2VybmFtZSB8fCAnVXNlcic7XG5cbiAgICBjb25zdCBbaW1hZ2VVcmwsIHNldEltYWdlVXJsXSA9IHVzZVN0YXRlKG51bGwpO1xuICAgIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IHVzZVN0YXRlKHRydWUpO1xuICAgIGNvbnN0IFtoYXNFcnJvciwgc2V0SGFzRXJyb3JdID0gdXNlU3RhdGUoZmFsc2UpO1xuXG4gICAgdXNlRWZmZWN0KCgpID0+IHtcbiAgICAgICAgaWYgKCFrZXkpIHtcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGtleS5zdGFydHNXaXRoKCdodHRwOi8vJykgfHwga2V5LnN0YXJ0c1dpdGgoJ2h0dHBzOi8vJykpIHtcbiAgICAgICAgICAgIHNldEltYWdlVXJsKGtleSk7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGZldGNoU2lnbmVkVXJsID0gYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKGAvYXBpL2FkbWluL3NpZ25lZC11cmw/a2V5PSR7ZW5jb2RlVVJJQ29tcG9uZW50KGtleSl9YCk7XG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlLm9rKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICAgICAgICAgIHNldEltYWdlVXJsKGRhdGEudXJsKTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBzZXRIYXNFcnJvcih0cnVlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJFcnJvciBmZXRjaGluZyBhdmF0YXIgVVJMOlwiLCBlcnJvcik7XG4gICAgICAgICAgICAgICAgc2V0SGFzRXJyb3IodHJ1ZSk7XG4gICAgICAgICAgICB9IGZpbmFsbHkge1xuICAgICAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuXG4gICAgICAgIGZldGNoU2lnbmVkVXJsKCk7XG4gICAgfSwgW2tleV0pO1xuXG4gICAgY29uc3Qgc2l6ZSA9IHdoZXJlID09PSAnbGlzdCcgPyAnMzJweCcgOiAnMTIwcHgnO1xuXG4gICAgaWYgKGxvYWRpbmcpIHtcbiAgICAgICAgcmV0dXJuIDxCb3ggc3R5bGU9e3sgd2lkdGg6IHNpemUsIGhlaWdodDogc2l6ZSwgYm9yZGVyUmFkaXVzOiAnNTAlJywgYmFja2dyb3VuZENvbG9yOiAnIzMzMycgfX0gLz47XG4gICAgfVxuXG4gICAgY29uc3QgZGVmYXVsdEF2YXRhciA9ICcvaW1hZ2VzL2RlZmF1bHQtYXZhdGFyLnBuZyc7XG5cbiAgICByZXR1cm4gKFxuICAgICAgICA8Qm94PlxuICAgICAgICAgICAgPGltZyBcbiAgICAgICAgICAgICAgICBzcmM9eyghaW1hZ2VVcmwgfHwgaGFzRXJyb3IpID8gZGVmYXVsdEF2YXRhciA6IGltYWdlVXJsfSBcbiAgICAgICAgICAgICAgICBhbHQ9e3VzZXJuYW1lfVxuICAgICAgICAgICAgICAgIHN0eWxlPXt7IFxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGhlaWdodDogc2l6ZSwgXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlclJhZGl1czogJzUwJScsIFxuICAgICAgICAgICAgICAgICAgICBvYmplY3RGaXQ6ICdjb3ZlcicsXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlcjogJzJweCBzb2xpZCAjRkZENzAwJyxcbiAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAnIzFhMWExYSdcbiAgICAgICAgICAgICAgICB9fSBcbiAgICAgICAgICAgICAgICBvbkVycm9yPXsoZSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZS5jdXJyZW50VGFyZ2V0LnNyYyAhPT0gZGVmYXVsdEF2YXRhcikge1xuICAgICAgICAgICAgICAgICAgICAgICAgZS5jdXJyZW50VGFyZ2V0LnNyYyA9IGRlZmF1bHRBdmF0YXI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9fVxuICAgICAgICAgICAgLz5cbiAgICAgICAgPC9Cb3g+XG4gICAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEF2YXRhckNlbGw7XG4iLCJpbXBvcnQgUmVhY3QsIHsgdXNlU3RhdGUsIHVzZUVmZmVjdCB9IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuXG5jb25zdCBJbWFnZVByZXZpZXcgPSAocHJvcHMpID0+IHtcbiAgICBjb25zdCB7IHJlY29yZCwgcHJvcGVydHksIHdoZXJlIH0gPSBwcm9wczsgXG4gICAgY29uc3QgdmFsdWUgPSByZWNvcmQucGFyYW1zW3Byb3BlcnR5Lm5hbWVdO1xuXG4gICAgY29uc3QgW2ltYWdlVXJsLCBzZXRJbWFnZVVybF0gPSB1c2VTdGF0ZShudWxsKTtcbiAgICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcblxuICAgIHVzZUVmZmVjdCgoKSA9PiB7XG4gICAgICAgIGlmICghdmFsdWUpIHtcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHZhbHVlLnN0YXJ0c1dpdGgoJ2h0dHA6Ly8nKSB8fCB2YWx1ZS5zdGFydHNXaXRoKCdodHRwczovLycpKSB7XG4gICAgICAgICAgICBzZXRJbWFnZVVybCh2YWx1ZSk7XG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGZldGNoU2lnbmVkVXJsID0gYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKGAvYXBpL2FkbWluL3NpZ25lZC11cmw/a2V5PSR7ZW5jb2RlVVJJQ29tcG9uZW50KHZhbHVlKX1gKTtcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgICAgICAgICAgc2V0SW1hZ2VVcmwoZGF0YS51cmwpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJGYWlsZWQgdG8gZmV0Y2ggc2lnbmVkIFVSTC5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiTmV0d29yayBlcnJvciBmZXRjaGluZyBzaWduZWQgVVJMOlwiLCBlcnJvcik7XG4gICAgICAgICAgICB9IGZpbmFsbHkge1xuICAgICAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuXG4gICAgICAgIGZldGNoU2lnbmVkVXJsKCk7XG4gICAgfSwgW3ZhbHVlXSk7XG5cbiAgICBpZiAobG9hZGluZykgcmV0dXJuIDxCb3ggc3R5bGU9e3sgY29sb3I6ICcjRkZENzAwJywgZm9udFNpemU6ICcxMnB4JyB9fT5Mb2FkaW5nLi4uPC9Cb3g+O1xuXG4gICAgY29uc3QgaXNBdmF0YXIgPSBwcm9wZXJ0eS5uYW1lID09PSAncHJvZmlsZUltYWdlS2V5JyB8fCBwcm9wZXJ0eS5uYW1lID09PSAnY2FyZEF2YXRhclVybCcgfHwgcHJvcGVydHkubmFtZSA9PT0gJ2F2YXRhcic7XG4gICAgY29uc3QgZGVmYXVsdEltYWdlID0gaXNBdmF0YXIgPyAnL2ltYWdlcy9kZWZhdWx0LWF2YXRhci5wbmcnIDogJy9pbWFnZXMvZGVmYXVsdC1hcHAtaWNvbi5wbmcnO1xuICAgIGNvbnN0IGRpc3BsYXlVcmwgPSBpbWFnZVVybCB8fCBkZWZhdWx0SW1hZ2U7XG5cbiAgICBjb25zdCBzaXplID0gd2hlcmUgPT09ICdsaXN0JyA/ICc0MHB4JyA6ICcxNTBweCc7XG4gICAgY29uc3QgcmFkaXVzID0gaXNBdmF0YXIgPyAnNTAlJyA6ICc4cHgnO1xuXG4gICAgcmV0dXJuIChcbiAgICAgICAgPEJveD5cbiAgICAgICAgICAgIDxpbWcgXG4gICAgICAgICAgICAgICAgc3JjPXtkaXNwbGF5VXJsfSBcbiAgICAgICAgICAgICAgICBhbHQ9XCJQcmV2aWV3XCIgXG4gICAgICAgICAgICAgICAgc3R5bGU9e3sgXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiBzaXplLCBcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiByYWRpdXMsXG4gICAgICAgICAgICAgICAgICAgIG9iamVjdEZpdDogJ2NvdmVyJyxcbiAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAnIzFhMWExYScsXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlcjogJzFweCBzb2xpZCAjMzMzJ1xuICAgICAgICAgICAgICAgIH19IFxuICAgICAgICAgICAgICAgIG9uRXJyb3I9eyhlKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChlLmN1cnJlbnRUYXJnZXQuc3JjICE9PSBkZWZhdWx0SW1hZ2UpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGUuY3VycmVudFRhcmdldC5zcmMgPSBkZWZhdWx0SW1hZ2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9fVxuICAgICAgICAgICAgLz5cbiAgICAgICAgPC9Cb3g+XG4gICAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IEltYWdlUHJldmlldztcbiIsImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSB9IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEJveCwgQnV0dG9uLCBIMywgVGV4dCwgSW5wdXQsIExhYmVsLCBGb3JtR3JvdXAsIE5vdGljZUJveCB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xuaW1wb3J0IHsgdXNlTm90aWNlLCBBcGlDbGllbnQgfSBmcm9tICdhZG1pbmpzJztcblxuY29uc3QgYXBpID0gbmV3IEFwaUNsaWVudCgpO1xuXG5jb25zdCBNYW5hZ2VWb3RlcyA9IChwcm9wcykgPT4ge1xuICBjb25zdCB7IHJlY29yZCwgcmVzb3VyY2UgfSA9IHByb3BzO1xuICBjb25zdCBhZGROb3RpY2UgPSB1c2VOb3RpY2UoKTtcblxuICBjb25zdCBbd29ya2luZ0NvdW50LCBzZXRXb3JraW5nQ291bnRdID0gdXNlU3RhdGUocmVjb3JkLnBhcmFtcy53b3JraW5nVm90ZUNvdW50IHx8IDApO1xuICBjb25zdCBbbm90V29ya2luZ0NvdW50LCBzZXROb3RXb3JraW5nQ291bnRdID0gdXNlU3RhdGUocmVjb3JkLnBhcmFtcy5ub3RXb3JraW5nVm90ZUNvdW50IHx8IDApO1xuICBjb25zdCBbaXNMb2FkaW5nLCBzZXRJc0xvYWRpbmddID0gdXNlU3RhdGUoZmFsc2UpO1xuXG4gIGNvbnN0IGhhbmRsZVN1Ym1pdCA9IChhY3Rpb25UeXBlKSA9PiB7XG4gICAgaWYgKGFjdGlvblR5cGUgPT09ICdyZXNldCcgJiYgIXdpbmRvdy5jb25maXJtKFwiQXJlIHlvdSBzdXJlIHlvdSB3YW50IHRvIHBlcm1hbmVudGx5IGRlbGV0ZSBhbGwgdXNlciB2b3RlcyBmb3IgdGhpcyBtb2Q/XCIpKSB7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBzZXRJc0xvYWRpbmcodHJ1ZSk7XG5cbiAgICBhcGkucmVzb3VyY2VBY3Rpb24oe1xuICAgICAgcmVzb3VyY2VJZDogcmVzb3VyY2UuaWQsXG4gICAgICBhY3Rpb25OYW1lOiAnbWFuYWdlVm90ZXMnLFxuICAgICAgcmVjb3JkSWQ6IHJlY29yZC5pZCxcbiAgICAgIG1ldGhvZDogJ3Bvc3QnLFxuICAgICAgZGF0YToge1xuICAgICAgICBhY3Rpb25UeXBlOiBhY3Rpb25UeXBlLFxuICAgICAgICBuZXdXb3JraW5nQ291bnQ6IHdvcmtpbmdDb3VudCxcbiAgICAgICAgbmV3Tm90V29ya2luZ0NvdW50OiBub3RXb3JraW5nQ291bnRcbiAgICAgIH1cbiAgICB9KS50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgIHNldElzTG9hZGluZyhmYWxzZSk7XG4gICAgICBpZiAocmVzcG9uc2UuZGF0YS5ub3RpY2UpIHtcbiAgICAgICAgYWRkTm90aWNlKHJlc3BvbnNlLmRhdGEubm90aWNlKTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXNwb25zZS5kYXRhLnJlZGlyZWN0VXJsKSB7XG4gICAgICAgICB3aW5kb3cubG9jYXRpb24uaHJlZiA9IHJlc3BvbnNlLmRhdGEucmVkaXJlY3RVcmw7XG4gICAgICB9XG4gICAgfSkuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgc2V0SXNMb2FkaW5nKGZhbHNlKTtcbiAgICAgIGFkZE5vdGljZSh7IG1lc3NhZ2U6ICdBbiBlcnJvciBvY2N1cnJlZCB3aGlsZSBjb250YWN0aW5nIHRoZSBzZXJ2ZXIuJywgdHlwZTogJ2Vycm9yJyB9KTtcbiAgICB9KTtcbiAgfTtcblxuICByZXR1cm4gKFxuICAgIDxCb3ggdmFyaWFudD1cIndoaXRlXCIgcD1cInhsXCIgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzFhMWExYScsIGJvcmRlclJhZGl1czogJzhweCcsIGJvcmRlcjogJzFweCBzb2xpZCAjMzMzJyB9fT5cbiAgICAgIFxuICAgICAgPEgzIHN0eWxlPXt7IGNvbG9yOiAnI0ZGRDcwMCcsIG1hcmdpbkJvdHRvbTogJzIwcHgnIH19Pk1hbmFnZSBWb3RlcyBmb3I6IHtyZWNvcmQucGFyYW1zLm5hbWV9PC9IMz5cbiAgICAgIFxuICAgICAgPE5vdGljZUJveCBzdHlsZT17eyBtYXJnaW5Cb3R0b206ICczMHB4JyB9fT5cbiAgICAgICAgPHN0cm9uZz5DdXJyZW50IFN0YXR1czo8L3N0cm9uZz48YnIvPlxuICAgICAgICBXb3JraW5nIFZvdGVzOiA8c3BhbiBzdHlsZT17eyBjb2xvcjogJyM0M2EwNDcnLCBmb250V2VpZ2h0OiAnYm9sZCcgfX0+e3JlY29yZC5wYXJhbXMud29ya2luZ1ZvdGVDb3VudCB8fCAwfTwvc3Bhbj48YnIvPlxuICAgICAgICBOb3QgV29ya2luZyBWb3RlczogPHNwYW4gc3R5bGU9e3sgY29sb3I6ICcjZTUzOTM1JywgZm9udFdlaWdodDogJ2JvbGQnIH19PntyZWNvcmQucGFyYW1zLm5vdFdvcmtpbmdWb3RlQ291bnQgfHwgMH08L3NwYW4+XG4gICAgICA8L05vdGljZUJveD5cblxuICAgICAgPEJveCBtYj1cInh4bFwiIHA9XCJsZ1wiIHN0eWxlPXt7IGJvcmRlcjogJzFweCBzb2xpZCAjNDQ0JywgYm9yZGVyUmFkaXVzOiAnOHB4JywgYmFja2dyb3VuZENvbG9yOiAnIzBhMGEwYScgfX0+XG4gICAgICAgIDxIMyBzdHlsZT17eyBjb2xvcjogJyNmZmZmZmYnLCBmb250U2l6ZTogJzEuMmVtJyB9fT5PcHRpb24gMTogUmVzZXQgQWxsIFZvdGVzPC9IMz5cbiAgICAgICAgPFRleHQgc3R5bGU9e3sgY29sb3I6ICcjYzBjMGMwJywgbWFyZ2luQm90dG9tOiAnMTVweCcgfX0+XG4gICAgICAgICAgVGhpcyB3aWxsIHdpcGUgYWxsIGV4aXN0aW5nIHVzZXIgdm90ZXMgYW5kIHJlc2V0IGJvdGggY291bnRzIHRvIDAuIFRoaXMgaXMgaGlnaGx5IHJlY29tbWVuZGVkIHdoZW4gYSBtYWpvciB1cGRhdGUgaXMgcmVsZWFzZWQgdGhhdCBmaXhlcyBhIGJyb2tlbiBtb2QuXG4gICAgICAgIDwvVGV4dD5cbiAgICAgICAgPEJ1dHRvbiBcbiAgICAgICAgICAgIHZhcmlhbnQ9XCJkYW5nZXJcIiBcbiAgICAgICAgICAgIG9uQ2xpY2s9eygpID0+IGhhbmRsZVN1Ym1pdCgncmVzZXQnKX0gXG4gICAgICAgICAgICBkaXNhYmxlZD17aXNMb2FkaW5nfVxuICAgICAgICA+XG4gICAgICAgICAge2lzTG9hZGluZyA/ICdQcm9jZXNzaW5nLi4uJyA6ICdXaXBlICYgUmVzZXQgVm90ZXMgdG8gMCd9XG4gICAgICAgIDwvQnV0dG9uPlxuICAgICAgPC9Cb3g+XG5cbiAgICAgIDxCb3ggcD1cImxnXCIgc3R5bGU9e3sgYm9yZGVyOiAnMXB4IHNvbGlkICM0NDQnLCBib3JkZXJSYWRpdXM6ICc4cHgnLCBiYWNrZ3JvdW5kQ29sb3I6ICcjMGEwYTBhJyB9fT5cbiAgICAgICAgPEgzIHN0eWxlPXt7IGNvbG9yOiAnI2ZmZmZmZicsIGZvbnRTaXplOiAnMS4yZW0nIH19Pk9wdGlvbiAyOiBNYW51YWxseSBPdmVycmlkZSBDb3VudHM8L0gzPlxuICAgICAgICA8VGV4dCBzdHlsZT17eyBjb2xvcjogJyNmZmFkYWQnLCBtYXJnaW5Cb3R0b206ICcxNXB4JywgZm9udFNpemU6ICcwLjllbScgfX0+XG4gICAgICAgICAgV2FybmluZzogTWFudWFsbHkgc2V0dGluZyBudW1iZXJzIHdpbGwgY2xlYXIgdGhlIGludGVybmFsIGxpc3Qgb2YgdXNlcnMgd2hvIHZvdGVkLiBVc2UgdGhpcyBvbmx5IGlmIHlvdSBuZWVkIHRvIGFydGlmaWNpYWxseSBib29zdCBvciByZWR1Y2UgYSBzY29yZS5cbiAgICAgICAgPC9UZXh0PlxuICAgICAgICBcbiAgICAgICAgPEJveCBmbGV4IHN0eWxlPXt7IGdhcDogJzIwcHgnLCBtYXJnaW5Cb3R0b206ICcyMHB4JyB9fT5cbiAgICAgICAgICAgIDxGb3JtR3JvdXAgc3R5bGU9e3sgZmxleDogMSB9fT5cbiAgICAgICAgICAgICAgICA8TGFiZWwgc3R5bGU9e3sgY29sb3I6ICcjYzBjMGMwJyB9fT5Gb3JjZSBcIldvcmtpbmdcIiBDb3VudDwvTGFiZWw+XG4gICAgICAgICAgICAgICAgPElucHV0IFxuICAgICAgICAgICAgICAgICAgICB0eXBlPVwibnVtYmVyXCIgXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlPXt3b3JraW5nQ291bnR9IFxuICAgICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGUpID0+IHNldFdvcmtpbmdDb3VudChlLnRhcmdldC52YWx1ZSl9IFxuICAgICAgICAgICAgICAgICAgICBzdHlsZT17eyBiYWNrZ3JvdW5kQ29sb3I6ICcjMWExYTFhJywgY29sb3I6ICd3aGl0ZScsIGJvcmRlcjogJzFweCBzb2xpZCAjMzMzJyB9fVxuICAgICAgICAgICAgICAgIC8+XG4gICAgICAgICAgICA8L0Zvcm1Hcm91cD5cbiAgICAgICAgICAgIFxuICAgICAgICAgICAgPEZvcm1Hcm91cCBzdHlsZT17eyBmbGV4OiAxIH19PlxuICAgICAgICAgICAgICAgIDxMYWJlbCBzdHlsZT17eyBjb2xvcjogJyNjMGMwYzAnIH19PkZvcmNlIFwiTm90IFdvcmtpbmdcIiBDb3VudDwvTGFiZWw+XG4gICAgICAgICAgICAgICAgPElucHV0IFxuICAgICAgICAgICAgICAgICAgICB0eXBlPVwibnVtYmVyXCIgXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlPXtub3RXb3JraW5nQ291bnR9IFxuICAgICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGUpID0+IHNldE5vdFdvcmtpbmdDb3VudChlLnRhcmdldC52YWx1ZSl9XG4gICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnLCBjb2xvcjogJ3doaXRlJywgYm9yZGVyOiAnMXB4IHNvbGlkICMzMzMnIH19XG4gICAgICAgICAgICAgICAgLz5cbiAgICAgICAgICAgIDwvRm9ybUdyb3VwPlxuICAgICAgICA8L0JveD5cblxuICAgICAgICA8QnV0dG9uIFxuICAgICAgICAgICAgdmFyaWFudD1cInByaW1hcnlcIiBcbiAgICAgICAgICAgIG9uQ2xpY2s9eygpID0+IGhhbmRsZVN1Ym1pdCgnb3ZlcnJpZGUnKX0gXG4gICAgICAgICAgICBkaXNhYmxlZD17aXNMb2FkaW5nfVxuICAgICAgICAgICAgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnI0ZGRDcwMCcsIGNvbG9yOiAnYmxhY2snLCBib3JkZXI6ICdub25lJyB9fVxuICAgICAgICA+XG4gICAgICAgICAge2lzTG9hZGluZyA/ICdQcm9jZXNzaW5nLi4uJyA6ICdBcHBseSBNYW51YWwgT3ZlcnJpZGUnfVxuICAgICAgICA8L0J1dHRvbj5cbiAgICAgIDwvQm94PlxuXG4gICAgPC9Cb3g+XG4gICk7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBNYW5hZ2VWb3RlcztcbiIsIkFkbWluSlMuVXNlckNvbXBvbmVudHMgPSB7fVxuQWRtaW5KUy5lbnYuTk9ERV9FTlYgPSBcInByb2R1Y3Rpb25cIlxuaW1wb3J0IERhc2hib2FyZCBmcm9tICcuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9DdXN0b21EYXNoYm9hcmQnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkRhc2hib2FyZCA9IERhc2hib2FyZFxuaW1wb3J0IFNpZGViYXJCcmFuZGluZyBmcm9tICcuLi9jb21wb25lbnRzL2Rhc2hib2FyZC9TaWRlYmFyQnJhbmRpbmcnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLlNpZGViYXJCcmFuZGluZyA9IFNpZGViYXJCcmFuZGluZ1xuaW1wb3J0IEFjdGlvblJlZGlyZWN0IGZyb20gJy4uL2NvbXBvbmVudHMvYWN0aW9ucy9BY3Rpb25SZWRpcmVjdCdcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuQWN0aW9uUmVkaXJlY3QgPSBBY3Rpb25SZWRpcmVjdFxuaW1wb3J0IFZhcmlhbnRCYWRnZSBmcm9tICcuLi9jb21wb25lbnRzL2NlbGxzL1ZhcmlhbnRCYWRnZSdcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuVmFyaWFudEJhZGdlID0gVmFyaWFudEJhZGdlXG5pbXBvcnQgQXZhdGFyQ2VsbCBmcm9tICcuLi9jb21wb25lbnRzL2NlbGxzL0F2YXRhckNlbGwnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkF2YXRhckNlbGwgPSBBdmF0YXJDZWxsXG5pbXBvcnQgSW1hZ2VQcmV2aWV3IGZyb20gJy4uL2NvbXBvbmVudHMvY2VsbHMvSW1hZ2VQcmV2aWV3J1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5JbWFnZVByZXZpZXcgPSBJbWFnZVByZXZpZXdcbmltcG9ydCBNYW5hZ2VWb3RlcyBmcm9tICcuLi9jb21wb25lbnRzL2FjdGlvbnMvTWFuYWdlVm90ZXMnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLk1hbmFnZVZvdGVzID0gTWFuYWdlVm90ZXMiXSwibmFtZXMiOlsiYXBpIiwiQXBpQ2xpZW50IiwiQyIsImJnIiwic3VyZmFjZSIsInN1cmZhY2VBbHQiLCJib3JkZXIiLCJib3JkZXJIb3ZlciIsImdvbGQiLCJnb2xkRGltIiwiZ29sZEdsb3ciLCJibHVlIiwiZ3JlZW4iLCJwdXJwbGUiLCJyZWQiLCJvcmFuZ2UiLCJ0ZXh0IiwidGV4dE11dGVkIiwidGV4dERpbSIsIlBMQVRGT1JNX0NPTE9SUyIsImNhcmRTdHlsZSIsImFjY2VudENvbG9yIiwiYmFja2dyb3VuZENvbG9yIiwiYm9yZGVyUmFkaXVzIiwiYm9yZGVyTGVmdCIsInBhZGRpbmciLCJ0cmFuc2l0aW9uIiwiY3Vyc29yIiwiYm94U2l6aW5nIiwiQXJlYUNoYXJ0IiwiZGF0YSIsIndpZHRoIiwiaGVpZ2h0IiwiY29sb3IiLCJsZW5ndGgiLCJtYXhWYWwiLCJNYXRoIiwibWF4IiwibWFwIiwiZCIsInZhbHVlIiwicGFkWCIsInBhZFkiLCJjaGFydFciLCJjaGFydEgiLCJwb2ludHMiLCJpIiwieCIsInkiLCJsaW5lUGF0aCIsInAiLCJqb2luIiwiYXJlYVBhdGgiLCJncmlkTGluZXMiLCJwY3QiLCJsYWJlbCIsInJvdW5kIiwic3RlcCIsImNlaWwiLCJSZWFjdCIsImNyZWF0ZUVsZW1lbnQiLCJzdHlsZSIsIm92ZXJmbG93Iiwidmlld0JveCIsInByZXNlcnZlQXNwZWN0UmF0aW8iLCJkaXNwbGF5IiwibWF4V2lkdGgiLCJpZCIsIngxIiwieTEiLCJ4MiIsInkyIiwib2Zmc2V0Iiwic3RvcENvbG9yIiwic3RvcE9wYWNpdHkiLCJnIiwia2V5Iiwic3Ryb2tlIiwic3Ryb2tlV2lkdGgiLCJzdHJva2VEYXNoYXJyYXkiLCJmaWxsIiwiZm9udFNpemUiLCJmb250RmFtaWx5IiwidGV4dEFuY2hvciIsInN0cm9rZUxpbmVqb2luIiwic3Ryb2tlTGluZWNhcCIsInNob3dMYWJlbCIsImN4IiwiY3kiLCJyIiwiRG9udXRDaGFydCIsInNpemUiLCJ0b3RhbCIsInJlZHVjZSIsInMiLCJvdXRlclIiLCJpbm5lclIiLCJjdW1BbmdsZSIsIlBJIiwic2xpY2VzIiwiYW5nbGUiLCJzdGFydEFuZ2xlIiwiZW5kQW5nbGUiLCJjb3MiLCJzaW4iLCJpeDEiLCJpeTEiLCJpeDIiLCJpeTIiLCJsYXJnZUFyYyIsInBhdGgiLCJuYW1lIiwiYWxpZ25JdGVtcyIsImdhcCIsImZsZXhXcmFwIiwianVzdGlmeUNvbnRlbnQiLCJmb250V2VpZ2h0IiwiZmxleERpcmVjdGlvbiIsImZsZXhTaHJpbmsiLCJtYXJnaW5MZWZ0IiwiU3RhdENhcmQiLCJpY29uIiwiZGVsdGEiLCJkZWx0YUxhYmVsIiwiQm94IiwiZmxleCIsIm1pbldpZHRoIiwib25Nb3VzZUVudGVyIiwiZSIsImN1cnJlbnRUYXJnZXQiLCJib3JkZXJDb2xvciIsInRyYW5zZm9ybSIsImJveFNoYWRvdyIsIm9uTW91c2VMZWF2ZSIsImJvcmRlckxlZnRDb2xvciIsIm1hcmdpbkJvdHRvbSIsIkljb24iLCJUZXh0IiwidGV4dFRyYW5zZm9ybSIsImxldHRlclNwYWNpbmciLCJIMiIsIm1hcmdpbiIsInVuZGVmaW5lZCIsIkFjdGlvbkNhcmQiLCJjb3VudCIsInJlc291cmNlSWQiLCJocmVmIiwidGV4dERlY29yYXRpb24iLCJINSIsImZtdERhdGUiLCJkdCIsIkRhdGUiLCJ0b0xvY2FsZURhdGVTdHJpbmciLCJtb250aCIsImRheSIsInllYXIiLCJzdGF0dXNDb2xvciIsImxvd2VyIiwidG9Mb3dlckNhc2UiLCJDdXN0b21EYXNoYm9hcmQiLCJzZXREYXRhIiwidXNlU3RhdGUiLCJsb2FkaW5nIiwic2V0TG9hZGluZyIsImVycm9yIiwic2V0RXJyb3IiLCJ1c2VFZmZlY3QiLCJnZXREYXNoYm9hcmQiLCJ0aGVuIiwicmVzcG9uc2UiLCJjYXRjaCIsImZldGNoRXJyb3IiLCJjb25zb2xlIiwibWluSGVpZ2h0IiwidGV4dEFsaWduIiwiYm9yZGVyVG9wQ29sb3IiLCJhbmltYXRpb24iLCJzdGF0cyIsImFjdGlvblJlcXVpcmVkIiwibW9kc0J5UGxhdGZvcm0iLCJ1c2VyR3Jvd3RoRGF0YSIsInJlY2VudFVzZXJzIiwicmVjZW50TW9kcyIsImdyb3d0aENoYXJ0RGF0YSIsImRhdGUiLCJ1c2VycyIsIm5vdyIsImdyZWV0aW5nIiwiZ2V0SG91cnMiLCJwYWRkaW5nQm90dG9tIiwiYm9yZGVyQm90dG9tIiwidGV4dFNoYWRvdyIsImJhY2tncm91bmQiLCJtYXJnaW5Ub3AiLCJsaW5lSGVpZ2h0Iiwid2Vla2RheSIsInRpdGxlIiwidGFyZ2V0IiwicmVsIiwidG90YWxVc2VycyIsInRvTG9jYWxlU3RyaW5nIiwibmV3VXNlcnNUaGlzTW9udGgiLCJ0b3RhbE1vZHMiLCJuZXdNb2RzVGhpc01vbnRoIiwidG90YWxEb3dubG9hZHMiLCJ0b3RhbFZpZXdzIiwicGVuZGluZ1JlcG9ydHMiLCJwZW5kaW5nQXBwcm92YWxzIiwib3BlblRpY2tldHMiLCJCYWRnZSIsIm92ZXJmbG93WCIsIldlYmtpdE92ZXJmbG93U2Nyb2xsaW5nIiwiYm9yZGVyQ29sbGFwc2UiLCJ1IiwidXNlcm5hbWUiLCJyb2xlIiwibSIsInRleHRPdmVyZmxvdyIsIndoaXRlU3BhY2UiLCJjYXRlZ29yeSIsInN0YXR1cyIsInBhZGRpbmdUb3AiLCJib3JkZXJUb3AiLCJTaWRlYmFyQnJhbmRpbmciLCJwb3NpdGlvbiIsImJvdHRvbSIsImxlZnQiLCJvcGFjaXR5Iiwic3JjIiwiYWx0Iiwib2JqZWN0Rml0IiwiZmlsdGVyIiwib25FcnJvciIsIkFjdGlvblJlZGlyZWN0IiwicHJvcHMiLCJyZWNvcmQiLCJhY3Rpb24iLCJzZW5kTm90aWNlIiwidXNlTm90aWNlIiwidXJsIiwicGFyYW1zIiwicmVkaXJlY3RVcmwiLCJzZXRUaW1lb3V0Iiwid2luZG93Iiwib3BlbiIsIm1lc3NhZ2UiLCJ0eXBlIiwiTG9hZGVyIiwibXQiLCJ2YXJpYW50IiwiVmFyaWFudEJhZGdlIiwicHJvcGVydHkiLCJpc1ZhcmlhbnQiLCJjbGFzc05hbWUiLCJBdmF0YXJDZWxsIiwid2hlcmUiLCJpbWFnZVVybCIsInNldEltYWdlVXJsIiwiaGFzRXJyb3IiLCJzZXRIYXNFcnJvciIsInN0YXJ0c1dpdGgiLCJmZXRjaFNpZ25lZFVybCIsImZldGNoIiwiZW5jb2RlVVJJQ29tcG9uZW50Iiwib2siLCJqc29uIiwiZGVmYXVsdEF2YXRhciIsIkltYWdlUHJldmlldyIsImlzQXZhdGFyIiwiZGVmYXVsdEltYWdlIiwiZGlzcGxheVVybCIsInJhZGl1cyIsIk1hbmFnZVZvdGVzIiwicmVzb3VyY2UiLCJhZGROb3RpY2UiLCJ3b3JraW5nQ291bnQiLCJzZXRXb3JraW5nQ291bnQiLCJ3b3JraW5nVm90ZUNvdW50Iiwibm90V29ya2luZ0NvdW50Iiwic2V0Tm90V29ya2luZ0NvdW50Iiwibm90V29ya2luZ1ZvdGVDb3VudCIsImlzTG9hZGluZyIsInNldElzTG9hZGluZyIsImhhbmRsZVN1Ym1pdCIsImFjdGlvblR5cGUiLCJjb25maXJtIiwicmVzb3VyY2VBY3Rpb24iLCJhY3Rpb25OYW1lIiwicmVjb3JkSWQiLCJtZXRob2QiLCJuZXdXb3JraW5nQ291bnQiLCJuZXdOb3RXb3JraW5nQ291bnQiLCJub3RpY2UiLCJsb2NhdGlvbiIsIkgzIiwiTm90aWNlQm94IiwibWIiLCJCdXR0b24iLCJvbkNsaWNrIiwiZGlzYWJsZWQiLCJGb3JtR3JvdXAiLCJMYWJlbCIsIklucHV0Iiwib25DaGFuZ2UiLCJBZG1pbkpTIiwiVXNlckNvbXBvbmVudHMiLCJlbnYiLCJOT0RFX0VOViIsIkRhc2hib2FyZCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztFQUlBLE1BQU1BLEtBQUcsR0FBRyxJQUFJQyxpQkFBUyxFQUFFOztFQUUzQjtFQUNBLE1BQU1DLENBQUMsR0FBRztFQUNSQyxFQUFBQSxFQUFFLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxPQUFPLEVBQUUsU0FBUztFQUFFQyxFQUFBQSxVQUFVLEVBQUUsU0FBUztFQUN4REMsRUFBQUEsTUFBTSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsV0FBVyxFQUFFLFNBQVM7RUFDekNDLEVBQUFBLElBQUksRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE9BQU8sRUFBRSxzQkFBc0I7RUFBRUMsRUFBQUEsUUFBUSxFQUFFLHNCQUFzQjtFQUNsRkMsRUFBQUEsSUFBSSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsS0FBSyxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsTUFBTSxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsR0FBRyxFQUFFLFNBQVM7RUFBRUMsRUFBQUEsTUFBTSxFQUFFLFNBQVM7RUFDdkZDLEVBQUFBLElBQUksRUFBRSxTQUFTO0VBQUVDLEVBQUFBLFNBQVMsRUFBRSxTQUFTO0VBQUVDLEVBQUFBLE9BQU8sRUFBRTtFQUNsRCxDQUFDOztFQUVEO0VBQ0EsTUFBTUMsZUFBZSxHQUFHLENBQUMsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsU0FBUyxFQUFFLFNBQVMsQ0FBQzs7RUFFaEg7RUFDQSxNQUFNQyxTQUFTLEdBQUlDLFdBQVcs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
