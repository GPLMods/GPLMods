(function (React, adminjs, designSystem) {
  'use strict';

  function _interopDefault (e) { return e && e.__esModule ? e : { default: e }; }

  var React__default = /*#__PURE__*/_interopDefault(React);

  const api = new adminjs.ApiClient();
  const section = {
    maxWidth: '1120px',
    margin: '0 auto',
    padding: '28px',
    color: '#f5f5f5',
    fontFamily: 'Inter, system-ui, sans-serif'
  };
  const header = {
    display: 'flex',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    gap: '14px',
    alignItems: 'flex-end',
    paddingBottom: '20px',
    borderBottom: '1px solid #333'
  };
  const title = {
    margin: 0,
    fontSize: '2rem',
    color: '#fff'
  };
  const subtitle = {
    margin: '8px 0 0',
    color: '#aaa',
    maxWidth: '720px'
  };
  const linkButton = {
    display: 'inline-block',
    color: '#ffd700',
    border: '1px solid #ffd700',
    borderRadius: '10px',
    padding: '10px 16px',
    textDecoration: 'none',
    fontWeight: 700
  };
  const grid = {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
    gap: '18px',
    marginTop: '30px'
  };
  const card = {
    background: '#121212',
    border: '1px solid #2d2d2d',
    borderRadius: '16px',
    padding: '22px',
    minHeight: '140px'
  };
  const label = {
    fontSize: '0.8rem',
    color: '#9d9d9d',
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    marginBottom: '14px'
  };
  const value = {
    fontSize: '2.4rem',
    color: '#fff',
    margin: 0
  };
  const note = {
    fontSize: '0.95rem',
    color: '#b0b0b0',
    marginTop: '12px'
  };
  const empty = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '140px',
    color: '#777'
  };
  const Dashboard = () => {
    const [data, setData] = React.useState({
      stats: {},
      modsByPlatform: [],
      uploadChartData: []
    });
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState(null);
    React.useEffect(() => {
      api.getDashboard().then(response => {
        setData(response.data || {
          stats: {},
          modsByPlatform: [],
          uploadChartData: []
        });
        setLoading(false);
      }).catch(fetchError => {
        console.error('Dashboard fetch error:', fetchError);
        setError('Failed to load telemetry data.');
        setLoading(false);
      });
    }, []);
    const stats = data.stats || {};
    if (loading) {
      return /*#__PURE__*/React__default.default.createElement("div", {
        style: {
          ...section,
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }
      }, /*#__PURE__*/React__default.default.createElement("p", {
        style: {
          color: '#ccc'
        }
      }, "Loading real-time telemetry\u2026"));
    }
    if (error) {
      return /*#__PURE__*/React__default.default.createElement("div", {
        style: {
          ...section,
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }
      }, /*#__PURE__*/React__default.default.createElement("p", {
        style: {
          color: '#f06464'
        }
      }, error));
    }
    return /*#__PURE__*/React__default.default.createElement("div", {
      style: section
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: header
    }, /*#__PURE__*/React__default.default.createElement("div", null, /*#__PURE__*/React__default.default.createElement("h1", {
      style: title
    }, "GPL Mods Admin Dashboard"), /*#__PURE__*/React__default.default.createElement("p", {
      style: subtitle
    }, "A clean, compatible admin overview with core platform metrics.")), /*#__PURE__*/React__default.default.createElement("a", {
      href: "/home",
      target: "_blank",
      rel: "noopener noreferrer",
      style: linkButton
    }, "View live site")), /*#__PURE__*/React__default.default.createElement("div", {
      style: grid
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: card
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: label
    }, "Total Users"), /*#__PURE__*/React__default.default.createElement("p", {
      style: value
    }, (stats.totalUsers || 0).toLocaleString()), /*#__PURE__*/React__default.default.createElement("div", {
      style: note
    }, (stats.newUsersThisMonth || 0).toLocaleString(), " new users this month")), /*#__PURE__*/React__default.default.createElement("div", {
      style: card
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: label
    }, "Total Mods"), /*#__PURE__*/React__default.default.createElement("p", {
      style: value
    }, (stats.totalMods || 0).toLocaleString()), /*#__PURE__*/React__default.default.createElement("div", {
      style: note
    }, (stats.newModsThisMonth || 0).toLocaleString(), " new mods this month")), /*#__PURE__*/React__default.default.createElement("div", {
      style: card
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: label
    }, "Total Downloads"), /*#__PURE__*/React__default.default.createElement("p", {
      style: value
    }, (stats.totalDownloads || 0).toLocaleString()), /*#__PURE__*/React__default.default.createElement("div", {
      style: note
    }, "Lifetime downloads across the platform")), /*#__PURE__*/React__default.default.createElement("div", {
      style: card
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: label
    }, "Total Views"), /*#__PURE__*/React__default.default.createElement("p", {
      style: value
    }, (stats.totalViews || 0).toLocaleString()), /*#__PURE__*/React__default.default.createElement("div", {
      style: note
    }, "All-time global views across the platform"))), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        ...grid,
        marginTop: '24px'
      }
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: card
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: label
    }, "Upload Activity"), Array.isArray(data.uploadChartData) && data.uploadChartData.length > 0 ? /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        color: '#ccc'
      }
    }, /*#__PURE__*/React__default.default.createElement("p", {
      style: {
        margin: 0
      }
    }, "Showing recent activity for the last 7 days."), /*#__PURE__*/React__default.default.createElement("pre", {
      style: {
        color: '#ddd',
        marginTop: '14px',
        whiteSpace: 'pre-wrap'
      }
    }, JSON.stringify(data.uploadChartData, null, 2))) : /*#__PURE__*/React__default.default.createElement("div", {
      style: empty
    }, "No upload activity this week.")), /*#__PURE__*/React__default.default.createElement("div", {
      style: card
    }, /*#__PURE__*/React__default.default.createElement("div", {
      style: label
    }, "Mods by Platform"), Array.isArray(data.modsByPlatform) && data.modsByPlatform.length > 0 ? /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        color: '#ccc'
      }
    }, /*#__PURE__*/React__default.default.createElement("p", {
      style: {
        margin: 0
      }
    }, "Platform distribution data is available."), /*#__PURE__*/React__default.default.createElement("pre", {
      style: {
        color: '#ddd',
        marginTop: '14px',
        whiteSpace: 'pre-wrap'
      }
    }, JSON.stringify(data.modsByPlatform, null, 2))) : /*#__PURE__*/React__default.default.createElement("div", {
      style: empty
    }, "No platform distribution data available."))));
  };

  const SidebarBranding = () => {
    return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
      flex: true,
      alignItems: "center",
      justifyContent: "center",
      p: "lg",
      style: {
        borderBottom: '1px solid #333',
        backgroundColor: '#0a0a0a',
        padding: '20px 0'
      }
    }, /*#__PURE__*/React__default.default.createElement(designSystem.Link, {
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
        height: '35px',
        width: 'auto'
      },
      onError: e => e.target.style.display = 'none'
    }), /*#__PURE__*/React__default.default.createElement("div", {
      style: {
        fontSize: '24px',
        fontWeight: 'bold',
        fontFamily: 'Poppins, sans-serif'
      }
    }, /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: '#FFD700',
        textShadow: '0 0 10px rgba(255, 215, 0, 0.4)'
      }
    }, "GPL"), /*#__PURE__*/React__default.default.createElement("span", {
      style: {
        color: '#c0c0c0',
        marginLeft: '5px'
      }
    }, "Mods"))));
  };

  const ActionRedirect = props => {
    const {
      record,
      action
    } = props;
    const sendNotice = adminjs.useNotice();
    React.useEffect(() => {
      // We defined redirectUrl in our handler in admin.js
      const url = record?.params?.redirectUrl;
      if (url) {
        // Give a tiny delay so the user sees the notice
        setTimeout(() => {
          window.open(url, '_blank'); // Open in a new tab is usually best for these actions
          // Or use window.location.href = url; to stay in the same tab
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

    // If it's false, it's a Master file
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
    const key = record.params[property.name]; // This is the profileImageKey
    const username = record.params.username || 'User';
    const [imageUrl, setImageUrl] = React.useState(null);
    const [loading, setLoading] = React.useState(true);
    const [hasError, setHasError] = React.useState(false);
    React.useEffect(() => {
      if (!key) {
        setLoading(false);
        return;
      }

      // If it's a standard web URL, use it directly
      if (key.startsWith('http://') || key.startsWith('https://')) {
        setImageUrl(key);
        setLoading(false);
        return;
      }

      // Otherwise, fetch the signed URL securely
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

    // Set size based on whether we are looking at the table list or the detail view
    const size = where === 'list' ? '32px' : '120px';

    // 1. Loading State
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

    // 2. Fallback State (No image, or image failed to load)
    if (!imageUrl || hasError) {
      return /*#__PURE__*/React__default.default.createElement(designSystem.Box, {
        style: {
          width: size,
          height: size,
          borderRadius: '50%',
          backgroundColor: '#FFD700',
          // GPL Gold
          color: '#0a0a0a',
          // GPL Black
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 'bold',
          fontSize: where === 'list' ? '14px' : '48px',
          border: '2px solid #333'
        }
      }, username.charAt(0).toUpperCase());
    }

    // 3. Success State (Image loaded)
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
      onError: () => setHasError(true) // Instantly switch to initials if the image breaks!
    }));
  };

  const ImagePreview = props => {
    // We extract 'where' to know if we are in the 'list' view or 'show' view
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

    // --- SMART STYLING LOGIC ---

    // 1. Determine Size: Small in the table list, large in the details page
    const size = where === 'list' ? '40px' : '150px';

    // 2. Determine Shape: Circular for user avatars, rounded square for mod icons
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

  AdminJS.UserComponents = {};
  AdminJS.env.NODE_ENV = "production";
  AdminJS.UserComponents.Dashboard = Dashboard;
  AdminJS.UserComponents.SidebarBranding = SidebarBranding;
  AdminJS.UserComponents.ActionRedirect = ActionRedirect;
  AdminJS.UserComponents.VariantBadge = VariantBadge;
  AdminJS.UserComponents.AvatarCell = AvatarCell;
  AdminJS.UserComponents.ImagePreview = ImagePreview;

})(React, AdminJS, AdminJSDesignSystem);
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYnVuZGxlLmpzIiwic291cmNlcyI6WyIuLi9jb21wb25lbnRzL0N1c3RvbURhc2hib2FyZC5qc3giLCIuLi9jb21wb25lbnRzL1NpZGViYXJCcmFuZGluZy5qc3giLCIuLi9jb21wb25lbnRzL0FjdGlvblJlZGlyZWN0LmpzeCIsIi4uL2NvbXBvbmVudHMvVmFyaWFudEJhZGdlLmpzeCIsIi4uL2NvbXBvbmVudHMvQXZhdGFyQ2VsbC5qc3giLCIuLi9jb21wb25lbnRzL0ltYWdlUHJldmlldy5qc3giLCJlbnRyeS5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgUmVhY3QsIHsgdXNlU3RhdGUsIHVzZUVmZmVjdCB9IGZyb20gJ3JlYWN0JztcbmltcG9ydCB7IEFwaUNsaWVudCB9IGZyb20gJ2FkbWluanMnO1xuXG5jb25zdCBhcGkgPSBuZXcgQXBpQ2xpZW50KCk7XG5cbmNvbnN0IHNlY3Rpb24gPSB7XG4gIG1heFdpZHRoOiAnMTEyMHB4JyxcbiAgbWFyZ2luOiAnMCBhdXRvJyxcbiAgcGFkZGluZzogJzI4cHgnLFxuICBjb2xvcjogJyNmNWY1ZjUnLFxuICBmb250RmFtaWx5OiAnSW50ZXIsIHN5c3RlbS11aSwgc2Fucy1zZXJpZicsXG59O1xuY29uc3QgaGVhZGVyID0ge1xuICBkaXNwbGF5OiAnZmxleCcsXG4gIGZsZXhXcmFwOiAnd3JhcCcsXG4gIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsXG4gIGdhcDogJzE0cHgnLFxuICBhbGlnbkl0ZW1zOiAnZmxleC1lbmQnLFxuICBwYWRkaW5nQm90dG9tOiAnMjBweCcsXG4gIGJvcmRlckJvdHRvbTogJzFweCBzb2xpZCAjMzMzJyxcbn07XG5jb25zdCB0aXRsZSA9IHsgbWFyZ2luOiAwLCBmb250U2l6ZTogJzJyZW0nLCBjb2xvcjogJyNmZmYnIH07XG5jb25zdCBzdWJ0aXRsZSA9IHsgbWFyZ2luOiAnOHB4IDAgMCcsIGNvbG9yOiAnI2FhYScsIG1heFdpZHRoOiAnNzIwcHgnIH07XG5jb25zdCBsaW5rQnV0dG9uID0ge1xuICBkaXNwbGF5OiAnaW5saW5lLWJsb2NrJyxcbiAgY29sb3I6ICcjZmZkNzAwJyxcbiAgYm9yZGVyOiAnMXB4IHNvbGlkICNmZmQ3MDAnLFxuICBib3JkZXJSYWRpdXM6ICcxMHB4JyxcbiAgcGFkZGluZzogJzEwcHggMTZweCcsXG4gIHRleHREZWNvcmF0aW9uOiAnbm9uZScsXG4gIGZvbnRXZWlnaHQ6IDcwMCxcbn07XG5jb25zdCBncmlkID0ge1xuICBkaXNwbGF5OiAnZ3JpZCcsXG4gIGdyaWRUZW1wbGF0ZUNvbHVtbnM6ICdyZXBlYXQoYXV0by1maXQsIG1pbm1heCgyNjBweCwgMWZyKSknLFxuICBnYXA6ICcxOHB4JyxcbiAgbWFyZ2luVG9wOiAnMzBweCcsXG59O1xuY29uc3QgY2FyZCA9IHtcbiAgYmFja2dyb3VuZDogJyMxMjEyMTInLFxuICBib3JkZXI6ICcxcHggc29saWQgIzJkMmQyZCcsXG4gIGJvcmRlclJhZGl1czogJzE2cHgnLFxuICBwYWRkaW5nOiAnMjJweCcsXG4gIG1pbkhlaWdodDogJzE0MHB4Jyxcbn07XG5jb25zdCBsYWJlbCA9IHsgZm9udFNpemU6ICcwLjhyZW0nLCBjb2xvcjogJyM5ZDlkOWQnLCB0ZXh0VHJhbnNmb3JtOiAndXBwZXJjYXNlJywgbGV0dGVyU3BhY2luZzogJzAuMDhlbScsIG1hcmdpbkJvdHRvbTogJzE0cHgnIH07XG5jb25zdCB2YWx1ZSA9IHsgZm9udFNpemU6ICcyLjRyZW0nLCBjb2xvcjogJyNmZmYnLCBtYXJnaW46IDAgfTtcbmNvbnN0IG5vdGUgPSB7IGZvbnRTaXplOiAnMC45NXJlbScsIGNvbG9yOiAnI2IwYjBiMCcsIG1hcmdpblRvcDogJzEycHgnIH07XG5jb25zdCBlbXB0eSA9IHsgZGlzcGxheTogJ2ZsZXgnLCBhbGlnbkl0ZW1zOiAnY2VudGVyJywganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLCBtaW5IZWlnaHQ6ICcxNDBweCcsIGNvbG9yOiAnIzc3NycgfTtcblxuY29uc3QgRGFzaGJvYXJkID0gKCkgPT4ge1xuICBjb25zdCBbZGF0YSwgc2V0RGF0YV0gPSB1c2VTdGF0ZSh7IHN0YXRzOiB7fSwgbW9kc0J5UGxhdGZvcm06IFtdLCB1cGxvYWRDaGFydERhdGE6IFtdIH0pO1xuICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcbiAgY29uc3QgW2Vycm9yLCBzZXRFcnJvcl0gPSB1c2VTdGF0ZShudWxsKTtcblxuICB1c2VFZmZlY3QoKCkgPT4ge1xuICAgIGFwaS5nZXREYXNoYm9hcmQoKVxuICAgICAgLnRoZW4oKHJlc3BvbnNlKSA9PiB7XG4gICAgICAgIHNldERhdGEocmVzcG9uc2UuZGF0YSB8fCB7IHN0YXRzOiB7fSwgbW9kc0J5UGxhdGZvcm06IFtdLCB1cGxvYWRDaGFydERhdGE6IFtdIH0pO1xuICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goKGZldGNoRXJyb3IpID0+IHtcbiAgICAgICAgY29uc29sZS5lcnJvcignRGFzaGJvYXJkIGZldGNoIGVycm9yOicsIGZldGNoRXJyb3IpO1xuICAgICAgICBzZXRFcnJvcignRmFpbGVkIHRvIGxvYWQgdGVsZW1ldHJ5IGRhdGEuJyk7XG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xuICAgICAgfSk7XG4gIH0sIFtdKTtcblxuICBjb25zdCBzdGF0cyA9IGRhdGEuc3RhdHMgfHwge307XG5cbiAgaWYgKGxvYWRpbmcpIHtcbiAgICByZXR1cm4gKFxuICAgICAgPGRpdiBzdHlsZT17eyAuLi5zZWN0aW9uLCBtaW5IZWlnaHQ6ICcxMDB2aCcsIGRpc3BsYXk6ICdmbGV4JywgYWxpZ25JdGVtczogJ2NlbnRlcicsIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyB9fT5cbiAgICAgICAgPHAgc3R5bGU9e3sgY29sb3I6ICcjY2NjJyB9fT5Mb2FkaW5nIHJlYWwtdGltZSB0ZWxlbWV0cnnigKY8L3A+XG4gICAgICA8L2Rpdj5cbiAgICApO1xuICB9XG5cbiAgaWYgKGVycm9yKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIDxkaXYgc3R5bGU9e3sgLi4uc2VjdGlvbiwgbWluSGVpZ2h0OiAnMTAwdmgnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicgfX0+XG4gICAgICAgIDxwIHN0eWxlPXt7IGNvbG9yOiAnI2YwNjQ2NCcgfX0+e2Vycm9yfTwvcD5cbiAgICAgIDwvZGl2PlxuICAgICk7XG4gIH1cblxuICByZXR1cm4gKFxuICAgIDxkaXYgc3R5bGU9e3NlY3Rpb259PlxuICAgICAgPGRpdiBzdHlsZT17aGVhZGVyfT5cbiAgICAgICAgPGRpdj5cbiAgICAgICAgICA8aDEgc3R5bGU9e3RpdGxlfT5HUEwgTW9kcyBBZG1pbiBEYXNoYm9hcmQ8L2gxPlxuICAgICAgICAgIDxwIHN0eWxlPXtzdWJ0aXRsZX0+QSBjbGVhbiwgY29tcGF0aWJsZSBhZG1pbiBvdmVydmlldyB3aXRoIGNvcmUgcGxhdGZvcm0gbWV0cmljcy48L3A+XG4gICAgICAgIDwvZGl2PlxuICAgICAgICA8YSBocmVmPVwiL2hvbWVcIiB0YXJnZXQ9XCJfYmxhbmtcIiByZWw9XCJub29wZW5lciBub3JlZmVycmVyXCIgc3R5bGU9e2xpbmtCdXR0b259PlxuICAgICAgICAgIFZpZXcgbGl2ZSBzaXRlXG4gICAgICAgIDwvYT5cbiAgICAgIDwvZGl2PlxuXG4gICAgICB7LyogLS0tIFNUQVRTIEdSSUQgLS0tICovfVxuICAgICAgPGRpdiBzdHlsZT17Z3JpZH0+XG4gICAgICAgIDxkaXYgc3R5bGU9e2NhcmR9PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e2xhYmVsfT5Ub3RhbCBVc2VyczwvZGl2PlxuICAgICAgICAgIDxwIHN0eWxlPXt2YWx1ZX0+eyhzdGF0cy50b3RhbFVzZXJzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9PC9wPlxuICAgICAgICAgIDxkaXYgc3R5bGU9e25vdGV9Pnsoc3RhdHMubmV3VXNlcnNUaGlzTW9udGggfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX0gbmV3IHVzZXJzIHRoaXMgbW9udGg8L2Rpdj5cbiAgICAgICAgPC9kaXY+XG4gICAgICAgIFxuICAgICAgICA8ZGl2IHN0eWxlPXtjYXJkfT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXtsYWJlbH0+VG90YWwgTW9kczwvZGl2PlxuICAgICAgICAgIDxwIHN0eWxlPXt2YWx1ZX0+eyhzdGF0cy50b3RhbE1vZHMgfHwgMCkudG9Mb2NhbGVTdHJpbmcoKX08L3A+XG4gICAgICAgICAgPGRpdiBzdHlsZT17bm90ZX0+eyhzdGF0cy5uZXdNb2RzVGhpc01vbnRoIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9IG5ldyBtb2RzIHRoaXMgbW9udGg8L2Rpdj5cbiAgICAgICAgPC9kaXY+XG4gICAgICAgIFxuICAgICAgICA8ZGl2IHN0eWxlPXtjYXJkfT5cbiAgICAgICAgICA8ZGl2IHN0eWxlPXtsYWJlbH0+VG90YWwgRG93bmxvYWRzPC9kaXY+XG4gICAgICAgICAgPHAgc3R5bGU9e3ZhbHVlfT57KHN0YXRzLnRvdGFsRG93bmxvYWRzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9PC9wPlxuICAgICAgICAgIDxkaXYgc3R5bGU9e25vdGV9PkxpZmV0aW1lIGRvd25sb2FkcyBhY3Jvc3MgdGhlIHBsYXRmb3JtPC9kaXY+XG4gICAgICAgIDwvZGl2PlxuXG4gICAgICAgIHsvKiDinIUgTkVXOiBUT1RBTCBWSUVXUyBDQVJEIEFEREVEIEhFUkUgKi99XG4gICAgICAgIDxkaXYgc3R5bGU9e2NhcmR9PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e2xhYmVsfT5Ub3RhbCBWaWV3czwvZGl2PlxuICAgICAgICAgIDxwIHN0eWxlPXt2YWx1ZX0+eyhzdGF0cy50b3RhbFZpZXdzIHx8IDApLnRvTG9jYWxlU3RyaW5nKCl9PC9wPlxuICAgICAgICAgIDxkaXYgc3R5bGU9e25vdGV9PkFsbC10aW1lIGdsb2JhbCB2aWV3cyBhY3Jvc3MgdGhlIHBsYXRmb3JtPC9kaXY+XG4gICAgICAgIDwvZGl2PlxuICAgICAgPC9kaXY+XG5cbiAgICAgIDxkaXYgc3R5bGU9e3sgLi4uZ3JpZCwgbWFyZ2luVG9wOiAnMjRweCcgfX0+XG4gICAgICAgIDxkaXYgc3R5bGU9e2NhcmR9PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e2xhYmVsfT5VcGxvYWQgQWN0aXZpdHk8L2Rpdj5cbiAgICAgICAgICB7QXJyYXkuaXNBcnJheShkYXRhLnVwbG9hZENoYXJ0RGF0YSkgJiYgZGF0YS51cGxvYWRDaGFydERhdGEubGVuZ3RoID4gMCA/IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgY29sb3I6ICcjY2NjJyB9fT5cbiAgICAgICAgICAgICAgPHAgc3R5bGU9e3sgbWFyZ2luOiAwIH19PlNob3dpbmcgcmVjZW50IGFjdGl2aXR5IGZvciB0aGUgbGFzdCA3IGRheXMuPC9wPlxuICAgICAgICAgICAgICA8cHJlIHN0eWxlPXt7IGNvbG9yOiAnI2RkZCcsIG1hcmdpblRvcDogJzE0cHgnLCB3aGl0ZVNwYWNlOiAncHJlLXdyYXAnIH19PlxuICAgICAgICAgICAgICAgIHtKU09OLnN0cmluZ2lmeShkYXRhLnVwbG9hZENoYXJ0RGF0YSwgbnVsbCwgMil9XG4gICAgICAgICAgICAgIDwvcHJlPlxuICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e2VtcHR5fT5ObyB1cGxvYWQgYWN0aXZpdHkgdGhpcyB3ZWVrLjwvZGl2PlxuICAgICAgICAgICl9XG4gICAgICAgIDwvZGl2PlxuXG4gICAgICAgIDxkaXYgc3R5bGU9e2NhcmR9PlxuICAgICAgICAgIDxkaXYgc3R5bGU9e2xhYmVsfT5Nb2RzIGJ5IFBsYXRmb3JtPC9kaXY+XG4gICAgICAgICAge0FycmF5LmlzQXJyYXkoZGF0YS5tb2RzQnlQbGF0Zm9ybSkgJiYgZGF0YS5tb2RzQnlQbGF0Zm9ybS5sZW5ndGggPiAwID8gKFxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBjb2xvcjogJyNjY2MnIH19PlxuICAgICAgICAgICAgICA8cCBzdHlsZT17eyBtYXJnaW46IDAgfX0+UGxhdGZvcm0gZGlzdHJpYnV0aW9uIGRhdGEgaXMgYXZhaWxhYmxlLjwvcD5cbiAgICAgICAgICAgICAgPHByZSBzdHlsZT17eyBjb2xvcjogJyNkZGQnLCBtYXJnaW5Ub3A6ICcxNHB4Jywgd2hpdGVTcGFjZTogJ3ByZS13cmFwJyB9fT5cbiAgICAgICAgICAgICAgICB7SlNPTi5zdHJpbmdpZnkoZGF0YS5tb2RzQnlQbGF0Zm9ybSwgbnVsbCwgMil9XG4gICAgICAgICAgICAgIDwvcHJlPlxuICAgICAgICAgICAgPC9kaXY+XG4gICAgICAgICAgKSA6IChcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e2VtcHR5fT5ObyBwbGF0Zm9ybSBkaXN0cmlidXRpb24gZGF0YSBhdmFpbGFibGUuPC9kaXY+XG4gICAgICAgICAgKX1cbiAgICAgICAgPC9kaXY+XG4gICAgICA8L2Rpdj5cbiAgICA8L2Rpdj5cbiAgKTtcbn07XG5cbmV4cG9ydCBkZWZhdWx0IERhc2hib2FyZDsiLCJpbXBvcnQgUmVhY3QgZnJvbSAncmVhY3QnO1xyXG5pbXBvcnQgeyBCb3gsIExpbmsgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcclxuXHJcbmNvbnN0IFNpZGViYXJCcmFuZGluZyA9ICgpID0+IHtcclxuICByZXR1cm4gKFxyXG4gICAgPEJveCBcclxuICAgICAgZmxleCBcclxuICAgICAgYWxpZ25JdGVtcz1cImNlbnRlclwiIFxyXG4gICAgICBqdXN0aWZ5Q29udGVudD1cImNlbnRlclwiIFxyXG4gICAgICBwPVwibGdcIiBcclxuICAgICAgc3R5bGU9e3sgYm9yZGVyQm90dG9tOiAnMXB4IHNvbGlkICMzMzMnLCBiYWNrZ3JvdW5kQ29sb3I6ICcjMGEwYTBhJywgcGFkZGluZzogJzIwcHggMCcgfX1cclxuICAgID5cclxuICAgICAgPExpbmsgdG89XCIvYWRtaW5cIiBzdHlsZT17eyB0ZXh0RGVjb3JhdGlvbjogJ25vbmUnLCBkaXNwbGF5OiAnZmxleCcsIGFsaWduSXRlbXM6ICdjZW50ZXInLCBnYXA6ICcxMHB4JyB9fT5cclxuICAgICAgICBcclxuICAgICAgICB7LyogT3B0aW9uYWwgTG9nbyBJY29uICovfVxyXG4gICAgICAgIDxpbWcgXHJcbiAgICAgICAgICBzcmM9XCIvaW1hZ2VzL2xvZ28ucG5nXCIgXHJcbiAgICAgICAgICBhbHQ9XCJMb2dvXCIgXHJcbiAgICAgICAgICBzdHlsZT17eyBoZWlnaHQ6ICczNXB4Jywgd2lkdGg6ICdhdXRvJyB9fSBcclxuICAgICAgICAgIG9uRXJyb3I9eyhlKSA9PiBlLnRhcmdldC5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnfVxyXG4gICAgICAgIC8+XHJcbiAgICAgICAgXHJcbiAgICAgICAgey8qIFRoZSBDdXN0b20gQ29sb3JlZCBUZXh0ICovfVxyXG4gICAgICAgIDxkaXYgc3R5bGU9e3sgZm9udFNpemU6ICcyNHB4JywgZm9udFdlaWdodDogJ2JvbGQnLCBmb250RmFtaWx5OiAnUG9wcGlucywgc2Fucy1zZXJpZicgfX0+XHJcbiAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI0ZGRDcwMCcsIHRleHRTaGFkb3c6ICcwIDAgMTBweCByZ2JhKDI1NSwgMjE1LCAwLCAwLjQpJyB9fT5HUEw8L3NwYW4+XHJcbiAgICAgICAgICAgIDxzcGFuIHN0eWxlPXt7IGNvbG9yOiAnI2MwYzBjMCcsIG1hcmdpbkxlZnQ6ICc1cHgnIH19Pk1vZHM8L3NwYW4+XHJcbiAgICAgICAgPC9kaXY+XHJcblxyXG4gICAgICA8L0xpbms+XHJcbiAgICA8L0JveD5cclxuICApO1xyXG59O1xyXG5cclxuZXhwb3J0IGRlZmF1bHQgU2lkZWJhckJyYW5kaW5nOyIsImltcG9ydCBSZWFjdCwgeyB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XHJcbmltcG9ydCB7IEJveCwgVGV4dCwgTG9hZGVyIH0gZnJvbSAnQGFkbWluanMvZGVzaWduLXN5c3RlbSc7XHJcbmltcG9ydCB7IHVzZU5vdGljZSB9IGZyb20gJ2FkbWluanMnO1xyXG5cclxuY29uc3QgQWN0aW9uUmVkaXJlY3QgPSAocHJvcHMpID0+IHtcclxuICAgIGNvbnN0IHsgcmVjb3JkLCBhY3Rpb24gfSA9IHByb3BzO1xyXG4gICAgY29uc3Qgc2VuZE5vdGljZSA9IHVzZU5vdGljZSgpO1xyXG5cclxuICAgIHVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgICAgLy8gV2UgZGVmaW5lZCByZWRpcmVjdFVybCBpbiBvdXIgaGFuZGxlciBpbiBhZG1pbi5qc1xyXG4gICAgICAgIGNvbnN0IHVybCA9IHJlY29yZD8ucGFyYW1zPy5yZWRpcmVjdFVybDtcclxuICAgICAgICBcclxuICAgICAgICBpZiAodXJsKSB7XHJcbiAgICAgICAgICAgIC8vIEdpdmUgYSB0aW55IGRlbGF5IHNvIHRoZSB1c2VyIHNlZXMgdGhlIG5vdGljZVxyXG4gICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHtcclxuICAgICAgICAgICAgICAgIHdpbmRvdy5vcGVuKHVybCwgJ19ibGFuaycpOyAvLyBPcGVuIGluIGEgbmV3IHRhYiBpcyB1c3VhbGx5IGJlc3QgZm9yIHRoZXNlIGFjdGlvbnNcclxuICAgICAgICAgICAgICAgIC8vIE9yIHVzZSB3aW5kb3cubG9jYXRpb24uaHJlZiA9IHVybDsgdG8gc3RheSBpbiB0aGUgc2FtZSB0YWJcclxuICAgICAgICAgICAgfSwgNTAwKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICBzZW5kTm90aWNlKHsgbWVzc2FnZTogJ0Vycm9yOiBObyByZWRpcmVjdCBVUkwgcHJvdmlkZWQuJywgdHlwZTogJ2Vycm9yJyB9KTtcclxuICAgICAgICB9XHJcbiAgICB9LCBbcmVjb3JkXSk7XHJcblxyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8Qm94IGZsZXggZmxleERpcmVjdGlvbj1cImNvbHVtblwiIGFsaWduSXRlbXM9XCJjZW50ZXJcIiBqdXN0aWZ5Q29udGVudD1cImNlbnRlclwiIHA9XCJ4eGxcIj5cclxuICAgICAgICAgICAgPExvYWRlciAvPlxyXG4gICAgICAgICAgICA8VGV4dCBtdD1cImxnXCIgdmFyaWFudD1cImg0XCI+UmVkaXJlY3RpbmcuLi48L1RleHQ+XHJcbiAgICAgICAgPC9Cb3g+XHJcbiAgICApO1xyXG59O1xyXG5cclxuZXhwb3J0IGRlZmF1bHQgQWN0aW9uUmVkaXJlY3Q7IiwiaW1wb3J0IFJlYWN0IGZyb20gJ3JlYWN0JztcclxuaW1wb3J0IHsgQmFkZ2UgfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcclxuXHJcbmNvbnN0IFZhcmlhbnRCYWRnZSA9IChwcm9wcykgPT4ge1xyXG4gIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSB9ID0gcHJvcHM7XHJcbiAgY29uc3QgaXNWYXJpYW50ID0gcmVjb3JkLnBhcmFtc1twcm9wZXJ0eS5uYW1lXTtcclxuXHJcbiAgaWYgKGlzVmFyaWFudCA9PT0gdHJ1ZSB8fCBpc1ZhcmlhbnQgPT09ICd0cnVlJykge1xyXG4gICAgcmV0dXJuIChcclxuICAgICAgPEJhZGdlIHZhcmlhbnQ9XCJwcmltYXJ5XCIgc3R5bGU9e3sgYmFja2dyb3VuZENvbG9yOiAnIzIxOTZGMycsIGNvbG9yOiAnI2ZmZicsIGJvcmRlcjogJ25vbmUnIH19PlxyXG4gICAgICAgIFZhcmlhbnRcclxuICAgICAgPC9CYWRnZT5cclxuICAgICk7XHJcbiAgfVxyXG5cclxuICAvLyBJZiBpdCdzIGZhbHNlLCBpdCdzIGEgTWFzdGVyIGZpbGVcclxuICByZXR1cm4gKFxyXG4gICAgPEJhZGdlIHN0eWxlPXt7IGJhY2tncm91bmRDb2xvcjogJyMzMzMnLCBjb2xvcjogJyNhYWEnLCBib3JkZXI6ICcxcHggc29saWQgIzU1NScgfX0+XHJcbiAgICAgIE1hc3RlclxyXG4gICAgPC9CYWRnZT5cclxuICApO1xyXG59O1xyXG5cclxuZXhwb3J0IGRlZmF1bHQgVmFyaWFudEJhZGdlOyIsImltcG9ydCBSZWFjdCwgeyB1c2VTdGF0ZSwgdXNlRWZmZWN0IH0gZnJvbSAncmVhY3QnO1xyXG5pbXBvcnQgeyBCb3ggfSBmcm9tICdAYWRtaW5qcy9kZXNpZ24tc3lzdGVtJztcclxuXHJcbmNvbnN0IEF2YXRhckNlbGwgPSAocHJvcHMpID0+IHtcclxuICAgIGNvbnN0IHsgcmVjb3JkLCBwcm9wZXJ0eSwgd2hlcmUgfSA9IHByb3BzOyBcclxuICAgIGNvbnN0IGtleSA9IHJlY29yZC5wYXJhbXNbcHJvcGVydHkubmFtZV07IC8vIFRoaXMgaXMgdGhlIHByb2ZpbGVJbWFnZUtleVxyXG4gICAgY29uc3QgdXNlcm5hbWUgPSByZWNvcmQucGFyYW1zLnVzZXJuYW1lIHx8ICdVc2VyJztcclxuXHJcbiAgICBjb25zdFtpbWFnZVVybCwgc2V0SW1hZ2VVcmxdID0gdXNlU3RhdGUobnVsbCk7XHJcbiAgICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSB1c2VTdGF0ZSh0cnVlKTtcclxuICAgIGNvbnN0W2hhc0Vycm9yLCBzZXRIYXNFcnJvcl0gPSB1c2VTdGF0ZShmYWxzZSk7XHJcblxyXG4gICAgdXNlRWZmZWN0KCgpID0+IHtcclxuICAgICAgICBpZiAoIWtleSkge1xyXG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgLy8gSWYgaXQncyBhIHN0YW5kYXJkIHdlYiBVUkwsIHVzZSBpdCBkaXJlY3RseVxyXG4gICAgICAgIGlmIChrZXkuc3RhcnRzV2l0aCgnaHR0cDovLycpIHx8IGtleS5zdGFydHNXaXRoKCdodHRwczovLycpKSB7XHJcbiAgICAgICAgICAgIHNldEltYWdlVXJsKGtleSk7XHJcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICAvLyBPdGhlcndpc2UsIGZldGNoIHRoZSBzaWduZWQgVVJMIHNlY3VyZWx5XHJcbiAgICAgICAgY29uc3QgZmV0Y2hTaWduZWRVcmwgPSBhc3luYyAoKSA9PiB7XHJcbiAgICAgICAgICAgIHRyeSB7XHJcbiAgICAgICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKGAvYXBpL2FkbWluL3NpZ25lZC11cmw/a2V5PSR7ZW5jb2RlVVJJQ29tcG9uZW50KGtleSl9YCk7XHJcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHtcclxuICAgICAgICAgICAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzcG9uc2UuanNvbigpO1xyXG4gICAgICAgICAgICAgICAgICAgIHNldEltYWdlVXJsKGRhdGEudXJsKTtcclxuICAgICAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICAgICAgc2V0SGFzRXJyb3IodHJ1ZSk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XHJcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiRXJyb3IgZmV0Y2hpbmcgYXZhdGFyIFVSTDpcIiwgZXJyb3IpO1xyXG4gICAgICAgICAgICAgICAgc2V0SGFzRXJyb3IodHJ1ZSk7XHJcbiAgICAgICAgICAgIH0gZmluYWxseSB7XHJcbiAgICAgICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH07XHJcblxyXG4gICAgICAgIGZldGNoU2lnbmVkVXJsKCk7XHJcbiAgICB9LCBba2V5XSk7XHJcblxyXG4gICAgLy8gU2V0IHNpemUgYmFzZWQgb24gd2hldGhlciB3ZSBhcmUgbG9va2luZyBhdCB0aGUgdGFibGUgbGlzdCBvciB0aGUgZGV0YWlsIHZpZXdcclxuICAgIGNvbnN0IHNpemUgPSB3aGVyZSA9PT0gJ2xpc3QnID8gJzMycHgnIDogJzEyMHB4JztcclxuXHJcbiAgICAvLyAxLiBMb2FkaW5nIFN0YXRlXHJcbiAgICBpZiAobG9hZGluZykge1xyXG4gICAgICAgIHJldHVybiA8Qm94IHN0eWxlPXt7IHdpZHRoOiBzaXplLCBoZWlnaHQ6IHNpemUsIGJvcmRlclJhZGl1czogJzUwJScsIGJhY2tncm91bmRDb2xvcjogJyMzMzMnIH19IC8+O1xyXG4gICAgfVxyXG5cclxuICAgIC8vIDIuIEZhbGxiYWNrIFN0YXRlIChObyBpbWFnZSwgb3IgaW1hZ2UgZmFpbGVkIHRvIGxvYWQpXHJcbiAgICBpZiAoIWltYWdlVXJsIHx8IGhhc0Vycm9yKSB7XHJcbiAgICAgICAgcmV0dXJuIChcclxuICAgICAgICAgICAgPEJveCBzdHlsZT17eyBcclxuICAgICAgICAgICAgICAgIHdpZHRoOiBzaXplLCBcclxuICAgICAgICAgICAgICAgIGhlaWdodDogc2l6ZSwgXHJcbiAgICAgICAgICAgICAgICBib3JkZXJSYWRpdXM6ICc1MCUnLCBcclxuICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJyNGRkQ3MDAnLCAvLyBHUEwgR29sZFxyXG4gICAgICAgICAgICAgICAgY29sb3I6ICcjMGEwYTBhJywgICAgICAgICAgLy8gR1BMIEJsYWNrXHJcbiAgICAgICAgICAgICAgICBkaXNwbGF5OiAnZmxleCcsIFxyXG4gICAgICAgICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcicsIFxyXG4gICAgICAgICAgICAgICAganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLFxyXG4gICAgICAgICAgICAgICAgZm9udFdlaWdodDogJ2JvbGQnLFxyXG4gICAgICAgICAgICAgICAgZm9udFNpemU6IHdoZXJlID09PSAnbGlzdCcgPyAnMTRweCcgOiAnNDhweCcsXHJcbiAgICAgICAgICAgICAgICBib3JkZXI6ICcycHggc29saWQgIzMzMydcclxuICAgICAgICAgICAgfX0+XHJcbiAgICAgICAgICAgICAgICB7dXNlcm5hbWUuY2hhckF0KDApLnRvVXBwZXJDYXNlKCl9XHJcbiAgICAgICAgICAgIDwvQm94PlxyXG4gICAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gMy4gU3VjY2VzcyBTdGF0ZSAoSW1hZ2UgbG9hZGVkKVxyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8Qm94PlxyXG4gICAgICAgICAgICA8aW1nIFxyXG4gICAgICAgICAgICAgICAgc3JjPXtpbWFnZVVybH0gXHJcbiAgICAgICAgICAgICAgICBhbHQ9e3VzZXJuYW1lfVxyXG4gICAgICAgICAgICAgICAgc3R5bGU9e3sgXHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IHNpemUsIFxyXG4gICAgICAgICAgICAgICAgICAgIGhlaWdodDogc2l6ZSwgXHJcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiAnNTAlJywgXHJcbiAgICAgICAgICAgICAgICAgICAgb2JqZWN0Rml0OiAnY292ZXInLFxyXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlcjogJzJweCBzb2xpZCAjRkZENzAwJ1xyXG4gICAgICAgICAgICAgICAgfX0gXHJcbiAgICAgICAgICAgICAgICBvbkVycm9yPXsoKSA9PiBzZXRIYXNFcnJvcih0cnVlKX0gLy8gSW5zdGFudGx5IHN3aXRjaCB0byBpbml0aWFscyBpZiB0aGUgaW1hZ2UgYnJlYWtzIVxyXG4gICAgICAgICAgICAvPlxyXG4gICAgICAgIDwvQm94PlxyXG4gICAgKTtcclxufTtcclxuXHJcbmV4cG9ydCBkZWZhdWx0IEF2YXRhckNlbGw7IiwiaW1wb3J0IFJlYWN0LCB7IHVzZVN0YXRlLCB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XHJcbmltcG9ydCB7IEJveCB9IGZyb20gJ0BhZG1pbmpzL2Rlc2lnbi1zeXN0ZW0nO1xyXG5cclxuY29uc3QgSW1hZ2VQcmV2aWV3ID0gKHByb3BzKSA9PiB7XHJcbiAgICAvLyBXZSBleHRyYWN0ICd3aGVyZScgdG8ga25vdyBpZiB3ZSBhcmUgaW4gdGhlICdsaXN0JyB2aWV3IG9yICdzaG93JyB2aWV3XHJcbiAgICBjb25zdCB7IHJlY29yZCwgcHJvcGVydHksIHdoZXJlIH0gPSBwcm9wczsgXHJcbiAgICBjb25zdCB2YWx1ZSA9IHJlY29yZC5wYXJhbXNbcHJvcGVydHkubmFtZV07XHJcblxyXG4gICAgY29uc3QgW2ltYWdlVXJsLCBzZXRJbWFnZVVybF0gPSB1c2VTdGF0ZShudWxsKTtcclxuICAgIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IHVzZVN0YXRlKHRydWUpO1xyXG5cclxuICAgIHVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgICAgaWYgKCF2YWx1ZSkge1xyXG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKHZhbHVlLnN0YXJ0c1dpdGgoJ2h0dHA6Ly8nKSB8fCB2YWx1ZS5zdGFydHNXaXRoKCdodHRwczovLycpKSB7XHJcbiAgICAgICAgICAgIHNldEltYWdlVXJsKHZhbHVlKTtcclxuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IGZldGNoU2lnbmVkVXJsID0gYXN5bmMgKCkgPT4ge1xyXG4gICAgICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChgL2FwaS9hZG1pbi9zaWduZWQtdXJsP2tleT0ke2VuY29kZVVSSUNvbXBvbmVudCh2YWx1ZSl9YCk7XHJcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub2spIHtcclxuICAgICAgICAgICAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzcG9uc2UuanNvbigpO1xyXG4gICAgICAgICAgICAgICAgICAgIHNldEltYWdlVXJsKGRhdGEudXJsKTtcclxuICAgICAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIkZhaWxlZCB0byBmZXRjaCBzaWduZWQgVVJMLlwiKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcclxuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJOZXR3b3JrIGVycm9yIGZldGNoaW5nIHNpZ25lZCBVUkw6XCIsIGVycm9yKTtcclxuICAgICAgICAgICAgfSBmaW5hbGx5IHtcclxuICAgICAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfTtcclxuXHJcbiAgICAgICAgZmV0Y2hTaWduZWRVcmwoKTtcclxuICAgIH0sIFt2YWx1ZV0pO1xyXG5cclxuICAgIGlmIChsb2FkaW5nKSByZXR1cm4gPEJveCBzdHlsZT17eyBjb2xvcjogJyNGRkQ3MDAnLCBmb250U2l6ZTogJzEycHgnIH19PkxvYWRpbmcuLi48L0JveD47XHJcbiAgICBpZiAoIWltYWdlVXJsKSByZXR1cm4gPEJveCBzdHlsZT17eyBjb2xvcjogJyM4ODgnLCBmb250U2l6ZTogJzEycHgnIH19Pk4vQTwvQm94PjtcclxuXHJcbiAgICAvLyAtLS0gU01BUlQgU1RZTElORyBMT0dJQyAtLS1cclxuICAgIFxyXG4gICAgLy8gMS4gRGV0ZXJtaW5lIFNpemU6IFNtYWxsIGluIHRoZSB0YWJsZSBsaXN0LCBsYXJnZSBpbiB0aGUgZGV0YWlscyBwYWdlXHJcbiAgICBjb25zdCBzaXplID0gd2hlcmUgPT09ICdsaXN0JyA/ICc0MHB4JyA6ICcxNTBweCc7XHJcbiAgICBcclxuICAgIC8vIDIuIERldGVybWluZSBTaGFwZTogQ2lyY3VsYXIgZm9yIHVzZXIgYXZhdGFycywgcm91bmRlZCBzcXVhcmUgZm9yIG1vZCBpY29uc1xyXG4gICAgY29uc3QgcmFkaXVzID0gcHJvcGVydHkubmFtZSA9PT0gJ3Byb2ZpbGVJbWFnZUtleScgPyAnNTAlJyA6ICc4cHgnO1xyXG5cclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPEJveD5cclxuICAgICAgICAgICAgPGltZyBcclxuICAgICAgICAgICAgICAgIHNyYz17aW1hZ2VVcmx9IFxyXG4gICAgICAgICAgICAgICAgYWx0PVwiUHJldmlld1wiIFxyXG4gICAgICAgICAgICAgICAgc3R5bGU9e3sgXHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IHNpemUsIFxyXG4gICAgICAgICAgICAgICAgICAgIGhlaWdodDogc2l6ZSwgXHJcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyUmFkaXVzOiByYWRpdXMsXHJcbiAgICAgICAgICAgICAgICAgICAgb2JqZWN0Rml0OiAnY292ZXInLFxyXG4gICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogJyMxYTFhMWEnLFxyXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlcjogJzFweCBzb2xpZCAjMzMzJ1xyXG4gICAgICAgICAgICAgICAgfX0gXHJcbiAgICAgICAgICAgIC8+XHJcbiAgICAgICAgPC9Cb3g+XHJcbiAgICApO1xyXG59O1xyXG5cclxuZXhwb3J0IGRlZmF1bHQgSW1hZ2VQcmV2aWV3OyIsIkFkbWluSlMuVXNlckNvbXBvbmVudHMgPSB7fVxuQWRtaW5KUy5lbnYuTk9ERV9FTlYgPSBcInByb2R1Y3Rpb25cIlxuaW1wb3J0IERhc2hib2FyZCBmcm9tICcuLi9jb21wb25lbnRzL0N1c3RvbURhc2hib2FyZCdcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuRGFzaGJvYXJkID0gRGFzaGJvYXJkXG5pbXBvcnQgU2lkZWJhckJyYW5kaW5nIGZyb20gJy4uL2NvbXBvbmVudHMvU2lkZWJhckJyYW5kaW5nJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5TaWRlYmFyQnJhbmRpbmcgPSBTaWRlYmFyQnJhbmRpbmdcbmltcG9ydCBBY3Rpb25SZWRpcmVjdCBmcm9tICcuLi9jb21wb25lbnRzL0FjdGlvblJlZGlyZWN0J1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5BY3Rpb25SZWRpcmVjdCA9IEFjdGlvblJlZGlyZWN0XG5pbXBvcnQgVmFyaWFudEJhZGdlIGZyb20gJy4uL2NvbXBvbmVudHMvVmFyaWFudEJhZGdlJ1xuQWRtaW5KUy5Vc2VyQ29tcG9uZW50cy5WYXJpYW50QmFkZ2UgPSBWYXJpYW50QmFkZ2VcbmltcG9ydCBBdmF0YXJDZWxsIGZyb20gJy4uL2NvbXBvbmVudHMvQXZhdGFyQ2VsbCdcbkFkbWluSlMuVXNlckNvbXBvbmVudHMuQXZhdGFyQ2VsbCA9IEF2YXRhckNlbGxcbmltcG9ydCBJbWFnZVByZXZpZXcgZnJvbSAnLi4vY29tcG9uZW50cy9JbWFnZVByZXZpZXcnXG5BZG1pbkpTLlVzZXJDb21wb25lbnRzLkltYWdlUHJldmlldyA9IEltYWdlUHJldmlldyJdLCJuYW1lcyI6WyJhcGkiLCJBcGlDbGllbnQiLCJzZWN0aW9uIiwibWF4V2lkdGgiLCJtYXJnaW4iLCJwYWRkaW5nIiwiY29sb3IiLCJmb250RmFtaWx5IiwiaGVhZGVyIiwiZGlzcGxheSIsImZsZXhXcmFwIiwianVzdGlmeUNvbnRlbnQiLCJnYXAiLCJhbGlnbkl0ZW1zIiwicGFkZGluZ0JvdHRvbSIsImJvcmRlckJvdHRvbSIsInRpdGxlIiwiZm9udFNpemUiLCJzdWJ0aXRsZSIsImxpbmtCdXR0b24iLCJib3JkZXIiLCJib3JkZXJSYWRpdXMiLCJ0ZXh0RGVjb3JhdGlvbiIsImZvbnRXZWlnaHQiLCJncmlkIiwiZ3JpZFRlbXBsYXRlQ29sdW1ucyIsIm1hcmdpblRvcCIsImNhcmQiLCJiYWNrZ3JvdW5kIiwibWluSGVpZ2h0IiwibGFiZWwiLCJ0ZXh0VHJhbnNmb3JtIiwibGV0dGVyU3BhY2luZyIsIm1hcmdpbkJvdHRvbSIsInZhbHVlIiwibm90ZSIsImVtcHR5IiwiRGFzaGJvYXJkIiwiZGF0YSIsInNldERhdGEiLCJ1c2VTdGF0ZSIsInN0YXRzIiwibW9kc0J5UGxhdGZvcm0iLCJ1cGxvYWRDaGFydERhdGEiLCJsb2FkaW5nIiwic2V0TG9hZGluZyIsImVycm9yIiwic2V0RXJyb3IiLCJ1c2VFZmZlY3QiLCJnZXREYXNoYm9hcmQiLCJ0aGVuIiwicmVzcG9uc2UiLCJjYXRjaCIsImZldGNoRXJyb3IiLCJjb25zb2xlIiwiUmVhY3QiLCJjcmVhdGVFbGVtZW50Iiwic3R5bGUiLCJocmVmIiwidGFyZ2V0IiwicmVsIiwidG90YWxVc2VycyIsInRvTG9jYWxlU3RyaW5nIiwibmV3VXNlcnNUaGlzTW9udGgiLCJ0b3RhbE1vZHMiLCJuZXdNb2RzVGhpc01vbnRoIiwidG90YWxEb3dubG9hZHMiLCJ0b3RhbFZpZXdzIiwiQXJyYXkiLCJpc0FycmF5IiwibGVuZ3RoIiwid2hpdGVTcGFjZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJTaWRlYmFyQnJhbmRpbmciLCJCb3giLCJmbGV4IiwicCIsImJhY2tncm91bmRDb2xvciIsIkxpbmsiLCJ0byIsInNyYyIsImFsdCIsImhlaWdodCIsIndpZHRoIiwib25FcnJvciIsImUiLCJ0ZXh0U2hhZG93IiwibWFyZ2luTGVmdCIsIkFjdGlvblJlZGlyZWN0IiwicHJvcHMiLCJyZWNvcmQiLCJhY3Rpb24iLCJzZW5kTm90aWNlIiwidXNlTm90aWNlIiwidXJsIiwicGFyYW1zIiwicmVkaXJlY3RVcmwiLCJzZXRUaW1lb3V0Iiwid2luZG93Iiwib3BlbiIsIm1lc3NhZ2UiLCJ0eXBlIiwiZmxleERpcmVjdGlvbiIsIkxvYWRlciIsIlRleHQiLCJtdCIsInZhcmlhbnQiLCJWYXJpYW50QmFkZ2UiLCJwcm9wZXJ0eSIsImlzVmFyaWFudCIsIm5hbWUiLCJCYWRnZSIsIkF2YXRhckNlbGwiLCJ3aGVyZSIsImtleSIsInVzZXJuYW1lIiwiaW1hZ2VVcmwiLCJzZXRJbWFnZVVybCIsImhhc0Vycm9yIiwic2V0SGFzRXJyb3IiLCJzdGFydHNXaXRoIiwiZmV0Y2hTaWduZWRVcmwiLCJmZXRjaCIsImVuY29kZVVSSUNvbXBvbmVudCIsIm9rIiwianNvbiIsInNpemUiLCJjaGFyQXQiLCJ0b1VwcGVyQ2FzZSIsIm9iamVjdEZpdCIsIkltYWdlUHJldmlldyIsInJhZGl1cyIsIkFkbWluSlMiLCJVc2VyQ29tcG9uZW50cyIsImVudiIsIk5PREVfRU5WIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0VBR0EsTUFBTUEsR0FBRyxHQUFHLElBQUlDLGlCQUFTLEVBQUU7RUFFM0IsTUFBTUMsT0FB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
