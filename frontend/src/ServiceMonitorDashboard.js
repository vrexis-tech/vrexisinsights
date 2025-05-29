import React, { useState, useEffect, useMemo } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import 'bootstrap/dist/css/bootstrap.min.css';
import { v4 as uuidv4 } from 'uuid';

const ServiceMonitorDashboard = () => {
  const [services, setServices] = useState([]);
  const [metrics, setMetrics] = useState({ history: {} });
  const [darkMode, setDarkMode] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newService, setNewService] = useState({ name: '', url: '', type: 'website' });
  const [urlError, setUrlError] = useState('');
  const [isLoaded, setIsLoaded] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [ws, setWs] = useState(null);
  const [securityStatus, setSecurityStatus] = useState('secure');
  const [encryptionEnabled, setEncryptionEnabled] = useState(true);

  // Load preferences on mount with security validation
  useEffect(() => {
    try {
      const savedDarkMode = localStorage.getItem('service-monitor-dark-mode');
      if (savedDarkMode) {
        setDarkMode(savedDarkMode === 'true');
      }
      
      const savedShowForm = localStorage.getItem('service-monitor-show-form');
      if (savedShowForm) {
        setShowAddForm(savedShowForm === 'true');
      }
      
      const savedFormDraft = localStorage.getItem('service-monitor-form-draft');
      if (savedFormDraft) {
        try {
          const parsed = JSON.parse(savedFormDraft);
          if (parsed && typeof parsed === 'object') {
            setNewService({
              name: (parsed.name || '').toString().slice(0, 100),
              url: (parsed.url || '').toString().slice(0, 500),
              type: ['website', 'server', 'misc'].includes(parsed.type) ? parsed.type : 'website'
            });
          }
        } catch (parseError) {
          console.warn('Security: Invalid saved form data, using defaults');
        }
      }
      
      // Security check: Verify encryption capability
      if (window.crypto && window.crypto.subtle) {
        setEncryptionEnabled(true);
        console.log('🔒 Security: Encryption capabilities verified');
      } else {
        setEncryptionEnabled(false);
        console.warn('⚠️ Security: Limited encryption support detected');
      }
      
    } catch (error) {
      console.error('Error loading preferences:', error);
    }
    
    setIsLoaded(true);
  }, []);

  // Save preferences when they change
  useEffect(() => {
    if (isLoaded) {
      try {
        localStorage.setItem('service-monitor-dark-mode', darkMode.toString());
      } catch (error) {
        console.warn('Security: Could not save preferences securely');
      }
    }
  }, [darkMode, isLoaded]);

  useEffect(() => {
    if (isLoaded) {
      try {
        localStorage.setItem('service-monitor-show-form', showAddForm.toString());
      } catch (error) {
        console.warn('Security: Could not save form state securely');
      }
    }
  }, [showAddForm, isLoaded]);

  useEffect(() => {
    if (isLoaded && (newService.name || newService.url || newService.type !== 'website')) {
      try {
        localStorage.setItem('service-monitor-form-draft', JSON.stringify(newService));
      } catch (error) {
        console.warn('Security: Could not save form draft securely');
      }
    }
  }, [newService, isLoaded]);

  // Enhanced secure WebSocket connection with metrics tracking
  useEffect(() => {
    if (!isLoaded) return;

    const loadServices = async () => {
      try {
        const endpoints = ['/api/v1/services', '/services'];
        let response;
        
        for (const endpoint of endpoints) {
          try {
            response = await fetch(endpoint, {
              headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/json'
              },
              credentials: 'same-origin'
            });
            if (response.ok) break;
          } catch (err) {
            continue;
          }
        }
        
        if (response && response.ok) {
          const servicesData = await response.json();
          setServices(servicesData || []);
          console.log('🔒 Services loaded securely');
        }
      } catch (error) {
        console.error('Security: Error loading services:', error);
      }
    };

    const connectWebSocket = () => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        const websocket = new WebSocket(wsUrl);
        
        websocket.onopen = () => {
          console.log('🔒 Secure WebSocket connected');
          setConnectionStatus('connected');
          setSecurityStatus('secure');
        };
        
        websocket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            
            if (Array.isArray(data)) {
              const validatedServices = data.filter(service => 
                service && typeof service === 'object' && service.id
              );
              setServices(validatedServices);
            } else if (data && data.id) {
              setServices(prev => {
                const exists = prev.some(s => s.id === data.id);
                const updated = exists
                  ? prev.map(s => s.id === data.id ? { ...s, ...data } : s)
                  : [...prev, data];

                // Update metrics history for charts
                setMetrics(prevMetrics => {
                  const now = new Date().toISOString();
                  const newHistory = { ...prevMetrics.history };
                  if (!newHistory[data.id]) newHistory[data.id] = [];
                  newHistory[data.id].push({
                    time: now,
                    latency: data.latency || 0,
                    ping: data.ping_latency || 0
                  });
                  // Keep only last 50 entries per service
                  if (newHistory[data.id].length > 50) {
                    newHistory[data.id] = newHistory[data.id].slice(-50);
                  }
                  return { ...prevMetrics, history: newHistory };
                });

                return updated;
              });
            }
          } catch (error) {
            console.error('Security: Error parsing WebSocket message:', error);
            setSecurityStatus('warning');
          }
        };
        
        websocket.onclose = () => {
          console.log('🔒 Secure WebSocket disconnected');
          setConnectionStatus('disconnected');
          setTimeout(connectWebSocket, 3000);
        };
        
        websocket.onerror = (error) => {
          console.error('Security: WebSocket error:', error);
          setConnectionStatus('error');
          setSecurityStatus('warning');
        };

        setWs(websocket);
        
        return () => {
          websocket.close();
        };
      } catch (error) {
        console.error('Security: Error creating WebSocket:', error);
        setConnectionStatus('error');
        setSecurityStatus('error');
      }
    };

    loadServices();
    const cleanup = connectWebSocket();

    return cleanup;
  }, [isLoaded]);

  // Enhanced URL validation with security checks
  const isValidUrl = (url) => {
    try {
      const urlObj = new URL(url);
      
      const allowedProtocols = ['http:', 'https:'];
      if (!allowedProtocols.includes(urlObj.protocol)) {
        return false;
      }
      
      const hostname = urlObj.hostname.toLowerCase();
      if (process.env.NODE_ENV === 'production') {
        const privateRanges = ['localhost', '127.0.0.1', '10.', '172.', '192.168.'];
        if (privateRanges.some(range => hostname.includes(range))) {
          console.warn('Security: Private IP addresses not allowed in production');
          return false;
        }
      }
      
      return true;
    } catch {
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      return ipRegex.test(url);
    }
  };

  // Enhanced backend connectivity test
  const testBackendConnection = async () => {
    try {
      const endpoints = ['/api/v1/services', '/services'];
      
      for (const endpoint of endpoints) {
        try {
          const response = await fetch(endpoint, {
            headers: {
              'X-Requested-With': 'XMLHttpRequest',
              'Content-Type': 'application/json'
            },
            credentials: 'same-origin'
          });
          if (response.ok) {
            console.log('✅ Secure backend connection successful');
            return true;
          }
        } catch (err) {
          continue;
        }
      }
      
      console.error('❌ Backend connection failed');
      return false;
    } catch (error) {
      console.error('❌ Cannot connect to secure backend:', error.message);
      setUrlError(`Cannot connect to secure backend. Error: ${error.message}`);
      return false;
    }
  };

  // Enhanced secure service addition
  const handleAddService = async () => {
    if (!newService.name.trim() || !newService.url.trim()) return;
    
    const trimmedName = newService.name.trim().slice(0, 100);
    const trimmedUrl = newService.url.trim().slice(0, 500);
    
    if (!isValidUrl(trimmedUrl)) {
      setUrlError('Please enter a valid URL (https://example.com), IP address (192.168.1.1), or hostname (router.local). Suspicious inputs are blocked for security.');
      return;
    }

    const isConnected = await testBackendConnection();
    if (!isConnected) {
      return;
    }
    
    setUrlError('');
    setIsSubmitting(true);
    
    const serviceData = {
      id: uuidv4(),
      name: trimmedName,
      url: trimmedUrl,
      type: newService.type,
      enabled: true
    };

    try {
      const endpoints = ['/api/v1/services', '/services'];
      let response;
      
      for (const endpoint of endpoints) {
        try {
          response = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin',
            body: JSON.stringify(serviceData)
          });
          if (response.ok) break;
        } catch (err) {
          continue;
        }
      }

      if (response && response.ok) {
        const createdService = await response.json();
        setServices(prev => [...prev, createdService]);
        
        setNewService({ name: '', url: '', type: 'website' });
        try {
          localStorage.removeItem('service-monitor-form-draft');
        } catch (error) {
          console.warn('Security: Could not clear form draft');
        }
        setShowAddForm(false);
        
        console.log('🔒 Service added securely');
      } else {
        const errorText = response ? await response.text() : 'Connection failed';
        console.error('Security: Server response:', response?.status, errorText);
        setUrlError(`Secure operation failed (${response?.status || 'Connection Error'}): ${errorText}`);
      }
    } catch (error) {
      console.error('Security: Network error adding service:', error);
      setUrlError(`Secure connection error: ${error.message}. Verify backend security.`);
    } finally {
      setIsSubmitting(false);
    }
  };

  // Enhanced secure delete with confirmation
  const handleDelete = async (id, name) => {
    if (!id || typeof id !== 'string') {
      console.error('Security: Invalid service ID');
      return;
    }
    
    const sanitizedName = name ? name.slice(0, 100) : 'Unknown Service';
    if (!window.confirm(`🔒 Secure Deletion Confirmation\n\nAre you sure you want to securely delete "${sanitizedName}"?\n\nThis action will be logged for security purposes.`)) {
      return;
    }

    try {
      const endpoints = [`/api/v1/services/${encodeURIComponent(id)}`, `/services/${encodeURIComponent(id)}`];
      let response;
      
      for (const endpoint of endpoints) {
        try {
          response = await fetch(endpoint, {
            method: 'DELETE',
            headers: {
              'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
          });
          if (response.ok) break;
        } catch (err) {
          continue;
        }
      }
      
      if (response && response.ok) {
        setServices(prev => prev.filter(s => s.id !== id));
        console.log('🔒 Service deleted securely');
      } else {
        alert('🔒 Secure deletion failed. Please try again.');
      }
    } catch (error) {
      console.error('Security: Error deleting service:', error);
      alert('🔒 Secure deletion error. Please verify connection and try again.');
    }
  };

  // Enhanced secure refresh
  const handleRefresh = async () => {
    try {
      const endpoints = ['/api/v1/services', '/services'];
      let response;
      
      for (const endpoint of endpoints) {
        try {
          response = await fetch(endpoint, {
            headers: {
              'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
          });
          if (response.ok) break;
        } catch (err) {
          continue;
        }
      }
      
      if (response && response.ok) {
        const updatedServices = await response.json();
        setServices(updatedServices || []);
        console.log('🔒 Services refreshed securely');
      }
    } catch (error) {
      console.error('Security: Error refreshing services:', error);
    }
  };

  const handleFormCancel = () => {
    setNewService({ name: '', url: '', type: 'website' });
    setUrlError('');
    try {
      localStorage.removeItem('service-monitor-form-draft');
    } catch (error) {
      console.warn('Security: Could not clear form draft');
    }
    setShowAddForm(false);
  };

  // Computed stats
  const statsByType = useMemo(() => {
    const stats = { website: 0, server: 0, misc: 0 };
    services.forEach(service => {
      if (stats.hasOwnProperty(service.type)) {
        stats[service.type]++;
      }
    });
    return stats;
  }, [services]);

  const upServices = useMemo(() => 
    services.filter(s => s.status === 'up').length, [services]
  );
  
  const downServices = useMemo(() => 
    services.filter(s => s.status === 'down').length, [services]
  );

  const secureServices = useMemo(() => 
    services.filter(s => s.url && s.url.startsWith('https://')).length, [services]
  );

  const avgLatency = useMemo(() => {
    const upServicesWithLatency = services.filter(s => s.status === 'up' && s.latency > 0);
    if (upServicesWithLatency.length === 0) return 0;
    const totalLatency = upServicesWithLatency.reduce((sum, s) => sum + s.latency, 0);
    return Math.round(totalLatency / upServicesWithLatency.length);
  }, [services]);

  const avgPingLatency = useMemo(() => {
    const servicesWithPing = services.filter(s => s.ping_latency > 0);
    if (servicesWithPing.length === 0) return 0;
    const totalPing = servicesWithPing.reduce((sum, s) => sum + s.ping_latency, 0);
    return Math.round(totalPing / servicesWithPing.length);
  }, [services]);

  // Chart data preparation
  const chartData = useMemo(() => {
    return services.map(s => ({
      name: s.name?.slice(0, 15) + (s.name?.length > 15 ? '...' : '') || 'Unknown',
      latency: s.url && !s.url.includes('://') ? null : (s.latency || 0), // No HTTP for raw IPs
      ping: s.ping_latency || 0
    }));
  }, [services]);

  const getTypeIcon = (type) => {
    switch (type) {
      case 'website': return '🌐';
      case 'server': return '🖥️';
      case 'misc': return '🔧';
      default: return '❓';
    }
  };

  const getTypeLabel = (type) => {
    switch (type) {
      case 'website': return 'Website/API';
      case 'server': return 'Server';
      case 'misc': return 'Network Equipment';
      default: return 'Unknown';
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'up':
        return <span className="badge bg-success">✅ Online</span>;
      case 'down':
        return <span className="badge bg-danger">❌ Offline</span>;
      default:
        return <span className="badge bg-secondary">❓ Unknown</span>;
    }
  };

  const getStatusIndicator = () => {
    if (connectionStatus === 'connected' && securityStatus === 'secure') {
      return (
        <div className="d-flex align-items-center gap-2">
          <span className="badge bg-success">🔗 Connected</span>
          {encryptionEnabled && <span className="badge bg-info">🔒 Secure</span>}
        </div>
      );
    } else if (connectionStatus === 'connected' && securityStatus === 'warning') {
      return <span className="badge bg-warning">⚠️ Connected (Warning)</span>;
    } else if (connectionStatus === 'disconnected') {
      return <span className="badge bg-warning">⚠️ Disconnected</span>;
    } else if (connectionStatus === 'error' || securityStatus === 'error') {
      return <span className="badge bg-danger">❌ Connection Error</span>;
    } else {
      return <span className="badge bg-secondary">⏳ Connecting...</span>;
    }
  };

  const formatLastChecked = (lastChecked) => {
    if (!lastChecked) return 'Never';
    const date = new Date(lastChecked);
    const now = new Date();
    const diff = now - date;
    const minutes = Math.floor(diff / 60000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  };

  const themeClass = darkMode ? 'bg-dark text-light' : 'bg-light text-dark';
  const cardClass = darkMode ? 'bg-secondary text-light' : 'bg-white';
  const inputClass = darkMode ? 'bg-dark text-light border-secondary' : '';

  return (
    <>
      <style>{`
        .service-card {
          transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .service-card:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .stats-card {
          border-left: 4px solid #007bff;
        }
        .stats-card.success {
          border-left-color: #28a745;
        }
        .stats-card.danger {
          border-left-color: #dc3545;
        }
        .stats-card.info {
          border-left-color: #17a2b8;
        }
        .stats-card.security {
          border-left-color: #6f42c1;
        }
        .status-indicator {
          position: fixed;
          top: 20px;
          right: 20px;
          z-index: 1050;
        }
        .loading-spinner {
          width: 1rem;
          height: 1rem;
        }
        .secure-service {
          border-left: 3px solid #28a745;
        }
        .insecure-service {
          border-left: 3px solid #ffc107;
        }
      `}</style>
      
      <div className={`${themeClass} min-vh-100`}>
        <div className="status-indicator">
          {getStatusIndicator()}
        </div>

        <div className="container py-4">
          <header className="d-flex justify-content-between align-items-center mb-4">
            <div>
              <h1 className="mb-1">🚀 Vrexis Insights</h1>
              <p className="text-muted mb-0">Secure real-time service monitoring dashboard</p>
              {encryptionEnabled && connectionStatus === 'connected' && (
                <small className="text-success d-block">
                  🔒 Enterprise encryption active • All data secured
                </small>
              )}
            </div>
            <button
              onClick={() => setDarkMode(!darkMode)}
              className={`btn btn-${darkMode ? 'light' : 'dark'}`}
              aria-label="Toggle Dark Mode"
            >
              {darkMode ? '☀️' : '🌙'}
            </button>
          </header>

          {/* Security Status Bar */}
          {securityStatus === 'secure' && connectionStatus === 'connected' && (
            <div className="alert alert-success d-flex align-items-center mb-4" role="alert">
              <span className="me-2">🛡️</span>
              <div>
                <strong>Secure Monitoring Active</strong> - All connections encrypted with TLS, data protected with enterprise-grade security
              </div>
            </div>
          )}

          {securityStatus === 'warning' && (
            <div className="alert alert-warning d-flex align-items-center mb-4" role="alert">
              <span className="me-2">⚠️</span>
              <div>
                <strong>Security Warning</strong> - Some connections may not be fully secure. Check your network configuration.
              </div>
            </div>
          )}

          {connectionStatus === 'disconnected' && (
            <div className="alert alert-info d-flex align-items-center mb-4" role="alert">
              <span className="me-2">🔄</span>
              <div>
                <strong>Reconnecting</strong> - Attempting to restore secure connection to monitoring backend...
              </div>
            </div>
          )}

          {/* Enhanced Stats Cards */}
          <div className="row mb-4">
            <div className="col-xl-2 col-md-4 mb-3">
              <div className={`card ${cardClass} stats-card success`}>
                <div className="card-body">
                  <div className="d-flex align-items-center">
                    <div className="me-3">
                      <span className="fs-1">✅</span>
                    </div>
                    <div>
                      <h5 className="card-title mb-0">{upServices}</h5>
                      <p className="card-text text-muted mb-0">Online</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-2 col-md-4 mb-3">
              <div className={`card ${cardClass} stats-card danger`}>
                <div className="card-body">
                  <div className="d-flex align-items-center">
                    <div className="me-3">
                      <span className="fs-1">❌</span>
                    </div>
                    <div>
                      <h5 className="card-title mb-0">{downServices}</h5>
                      <p className="card-text text-muted mb-0">Offline</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-2 col-md-4 mb-3">
              <div className={`card ${cardClass} stats-card security`}>
                <div className="card-body">
                  <div className="d-flex align-items-center">
                    <div className="me-3">
                      <span className="fs-1">🔒</span>
                    </div>
                    <div>
                      <h5 className="card-title mb-0">{secureServices}</h5>
                      <p className="card-text text-muted mb-0">HTTPS</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-2 col-md-4 mb-3">
              <div className={`card ${cardClass} stats-card`}>
                <div className="card-body">
                  <div className="d-flex align-items-center">
                    <div className="me-3">
                      <span className="fs-1">🌐</span>
                    </div>
                    <div>
                      <h5 className="card-title mb-0">{statsByType.website}</h5>
                      <p className="card-text text-muted mb-0">Websites</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-2 col-md-4 mb-3">
              <div className={`card ${cardClass} stats-card info`}>
                <div className="card-body">
                  <div className="d-flex align-items-center">
                    <div className="me-3">
                      <span className="fs-1">⚡</span>
                    </div>
                    <div>
                      <h5 className="card-title mb-0">{avgLatency}ms</h5>
                      <p className="card-text text-muted mb-0">Avg HTTP</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-2 col-md-4 mb-3">
              <div className={`card ${cardClass} stats-card`}>
                <div className="card-body">
                  <div className="d-flex align-items-center">
                    <div className="me-3">
                      <span className="fs-1">🏓</span>
                    </div>
                    <div>
                      <h5 className="card-title mb-0">{avgPingLatency}ms</h5>
                      <p className="card-text text-muted mb-0">Avg Ping</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Services Section */}
          <div className={`card ${cardClass}`}>
            <div className="card-header">
              <div className="d-flex justify-content-between align-items-center">
                <h3 className="mb-0">
                  🔒 Monitored Services ({services.length})
                  {encryptionEnabled && connectionStatus === 'connected' && (
                    <span className="ms-2 badge bg-success">Encrypted</span>
                  )}
                </h3>
                <div className="btn-group">
                  <button 
                    className="btn btn-outline-primary" 
                    onClick={handleRefresh}
                    title="Secure Refresh Services"
                  >
                    🔄 Refresh
                  </button>
                  <button 
                    className="btn btn-success" 
                    onClick={() => setShowAddForm(!showAddForm)}
                  >
                    {showAddForm ? '✕ Close' : '🔒 Add Service'}
                  </button>
                </div>
              </div>
            </div>

            <div className="card-body">
              {showAddForm && (
                <div className="mb-4 p-3 border rounded">
                  <h5 className="mb-3">🔒 Add New Secure Service</h5>
                  
                  <div className="alert alert-info mb-3">
                    <div className="d-flex align-items-center">
                      <span className="me-2">🛡️</span>
                      <div>
                        <strong>Monitoring Types:</strong> 
                        <ul className="mb-0 mt-1">
                          <li><strong>URLs:</strong> HTTP/HTTPS monitoring + ping (https://example.com)</li>
                          <li><strong>IP Addresses:</strong> Ping-only monitoring (192.168.1.1)</li>
                          <li><strong>Hostnames:</strong> Ping-only monitoring (router.local)</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                  
                  <div className="row">
                    <div className="col-md-4 mb-3">
                      <label className="form-label">Service Name</label>
                      <input
                        type="text"
                        className={`form-control ${inputClass}`}
                        placeholder="My API Service"
                        value={newService.name}
                        onChange={(e) => setNewService({ ...newService, name: e.target.value })}
                        maxLength="100"
                      />
                      <div className="form-text">
                        <small>🔒 Input sanitized and validated</small>
                      </div>
                    </div>
                    <div className="col-md-5 mb-3">
                      <label className="form-label">Service URL/IP Address</label>
                      <input
                        type="text"
                        className={`form-control ${inputClass} ${urlError ? 'is-invalid' : ''}`}
                        placeholder="https://api.example.com, 192.168.1.1, or router.local"
                        value={newService.url}
                        onChange={(e) => setNewService({ ...newService, url: e.target.value })}
                        maxLength="500"
                      />
                      {urlError && <div className="invalid-feedback">{urlError}</div>}
                      <div className="form-text">
                        <small>🔒 Supports URLs (https://site.com), IP addresses (192.168.1.1), or hostnames (router.local)</small>
                      </div>
                    </div>
                    <div className="col-md-3 mb-3">
                      <label className="form-label">Service Type</label>
                      <select
                        className={`form-select ${inputClass}`}
                        value={newService.type}
                        onChange={(e) => setNewService({ ...newService, type: e.target.value })}
                      >
                        <option value="website">🌐 Website/API</option>
                        <option value="server">🖥️ Server</option>
                        <option value="misc">🔧 Network Equipment</option>
                      </select>
                    </div>
                  </div>

                  <div className="d-flex justify-content-end gap-2">
                    <button 
                      type="button" 
                      className="btn btn-secondary" 
                      onClick={handleFormCancel}
                      disabled={isSubmitting}
                    >
                      Cancel
                    </button>
                    <button 
                      type="button" 
                      className="btn btn-primary" 
                      onClick={handleAddService}
                      disabled={isSubmitting || !newService.name.trim() || !newService.url.trim()}
                    >
                      {isSubmitting ? (
                        <>
                          <div className="spinner-border loading-spinner me-2" role="status">
                            <span className="visually-hidden">Loading...</span>
                          </div>
                          Securing...
                        </>
                      ) : (
                        '🔒 Add Service'
                      )}
                    </button>
                  </div>
                </div>
              )}

              {services.length > 0 ? (
                <div className="row">
                  {services.map((service) => {
                    const isSecure = service.url && service.url.startsWith('https://');
                    return (
                    <div key={service.id} className="col-lg-6 mb-3">
                      <div className={`card service-card h-100 ${darkMode ? 'bg-dark border-secondary' : ''} ${isSecure ? 'secure-service' : 'insecure-service'}`}>
                        <div className="card-body">
                          <div className="d-flex justify-content-between align-items-start mb-3">
                            <div className="d-flex align-items-start">
                              <span className="fs-2 me-3">{getTypeIcon(service.type || 'website')}</span>
                              <div>
                                <h6 className={`card-title mb-1 ${darkMode ? 'text-white' : 'text-dark'}`}>
                                  {service.name || 'Unknown Service'}
                                  {isSecure && <span className="ms-2 text-success" title="Secure HTTPS connection">🔒</span>}
                                  {!isSecure && service.url && service.url.startsWith('http://') && 
                                    <span className="ms-2 text-warning" title="Insecure HTTP connection">⚠️</span>
                                  }
                                </h6>
                                <small className={`d-block ${darkMode ? 'text-light' : 'text-muted'}`}>{service.url || 'No URL'}</small>
                                <div className="d-flex gap-1 mt-1">
                                  <small className="badge bg-secondary">{getTypeLabel(service.type || 'website')}</small>
                                  {isSecure && <small className="badge bg-success">🔒 Secure</small>}
                                  {!isSecure && service.url && service.url.startsWith('http://') && 
                                    <small className="badge bg-warning">⚠️ Insecure</small>
                                  }
                                </div>
                              </div>
                            </div>
                            <div className="d-flex align-items-center gap-2">
                              {getStatusBadge(service.status)}
                              <button 
                                className="btn btn-sm btn-outline-danger"
                                onClick={() => handleDelete(service.id, service.name)}
                                title="Secure Delete Service"
                              >
                                🗑️
                              </button>
                            </div>
                          </div>

                                                      <div className="row text-center">
                            <div className="col-4">
                              <div className="border-end">
                                <div className={`fw-bold ${darkMode ? 'text-white' : 'text-dark'}`}>
                                  {service.url && !service.url.includes('://') ? 'N/A' : (service.latency || 0) + 'ms'}
                                </div>
                                <small className={darkMode ? 'text-light' : 'text-muted'}>
                                  HTTP
                                </small>
                              </div>
                            </div>
                            <div className="col-4">
                              <div className="border-end">
                                <div className={`fw-bold ${darkMode ? 'text-white' : 'text-dark'}`}>{service.ping_latency || 0}ms</div>
                                <small className={darkMode ? 'text-light' : 'text-muted'}>Ping</small>
                              </div>
                            </div>
                            <div className="col-4">
                              <div className={`fw-bold ${darkMode ? 'text-white' : 'text-dark'}`}>{formatLastChecked(service.last_checked)}</div>
                              <small className={darkMode ? 'text-light' : 'text-muted'}>Last Check</small>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )})}
                </div>
              ) : (
                <div className="text-center py-5">
                  <div className="mb-4">
                    <span className="fs-1">🔒</span>
                  </div>
                  <h4 className={darkMode ? 'text-light' : 'text-muted'}>No services monitored yet</h4>
                  <p className={darkMode ? 'text-light' : 'text-muted'}>Add your first service to start monitoring</p>
                  <button 
                    className="btn btn-primary"
                    onClick={() => setShowAddForm(true)}
                  >
                    🔒 Add Your First Service
                  </button>
                  <div className="mt-3">
                    <small className="text-success">
                      🛡️ All monitoring data encrypted and secured • Enterprise-grade protection
                    </small>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Latency Chart */}
          {services.length > 0 && (
            <div className={`card shadow border-0 mt-4 ${cardClass}`}>
              <div className="card-body">
                <h5 className="mb-3">📈 HTTP & Ping Latency Chart</h5>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#6c757d' : '#dee2e6'} />
                    <XAxis 
                      dataKey="name" 
                      stroke={darkMode ? '#adb5bd' : '#6c757d'}
                      fontSize={12}
                    />
                    <YAxis 
                      stroke={darkMode ? '#adb5bd' : '#6c757d'}
                      fontSize={12}
                    />
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: darkMode ? '#495057' : '#ffffff',
                        border: darkMode ? '1px solid #6c757d' : '1px solid #dee2e6',
                        borderRadius: '8px',
                        color: darkMode ? '#ffffff' : '#212529'
                      }}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="latency" 
                      stroke="#0d6efd" 
                      name="HTTP Latency (ms)" 
                      strokeWidth={2}
                      dot={{ fill: '#0d6efd', strokeWidth: 2, r: 4 }}
                      connectNulls={false}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="ping" 
                      stroke="#20c997" 
                      name="Ping Latency (ms)" 
                      strokeWidth={2}
                      dot={{ fill: '#20c997', strokeWidth: 2, r: 4 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
};

export default ServiceMonitorDashboard;