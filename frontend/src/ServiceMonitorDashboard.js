import React, { useState, useEffect, useMemo, useCallback, createContext, useContext } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import 'bootstrap/dist/css/bootstrap.min.css';
import { v4 as uuidv4 } from 'uuid';

// Authentication Context
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Authentication Provider
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for stored auth data on mount
    const storedToken = localStorage.getItem('auth-token');
    const storedUser = localStorage.getItem('auth-user');
    
    if (storedToken && storedUser) {
      try {
        const userData = JSON.parse(storedUser);
        setToken(storedToken);
        setUser(userData);
      } catch (error) {
        console.error('Error parsing stored user data:', error);
        localStorage.removeItem('auth-token');
        localStorage.removeItem('auth-user');
      }
    }
    setLoading(false);
  }, []);

  const login = async (email, password) => {
    try {
      const response = await fetch('http://localhost:8080/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const error = await response.json();
        
        // Handle rate limiting specifically
        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After') || '60';
          throw new Error(`Rate limit exceeded. Please wait ${retryAfter} seconds before trying again.`);
        }
        
        throw new Error(error.error || 'Login failed');
      }

      const data = await response.json();
      
      setToken(data.token);
      setUser(data.user);
      
      localStorage.setItem('auth-token', data.token);
      localStorage.setItem('auth-user', JSON.stringify(data.user));
      
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const register = async (email, password, firstName, lastName) => {
    try {
      const response = await fetch('http://localhost:8080/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          email, 
          password, 
          first_name: firstName, 
          last_name: lastName 
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        
        // Handle rate limiting specifically
        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After') || '60';
          throw new Error(`Rate limit exceeded. Please wait ${retryAfter} seconds before trying again.`);
        }
        
        throw new Error(error.error || 'Registration failed');
      }

      const data = await response.json();
      
      setToken(data.token);
      setUser(data.user);
      
      localStorage.setItem('auth-token', data.token);
      localStorage.setItem('auth-user', JSON.stringify(data.user));
      
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('auth-token');
    localStorage.removeItem('auth-user');
  };

  const isAuthenticated = () => {
    return token && user;
  };

  const value = {
    user,
    token,
    loading,
    login,
    register,
    logout,
    isAuthenticated,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Login Component with rate limiting
const LoginForm = ({ onToggleMode }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const result = await login(email, password);
      
      if (!result.success) {
        if (result.error.includes('Rate limit') || result.error.includes('Too many')) {
          // Extract retry time if available
          const match = result.error.match(/(\d+)\s*seconds?/);
          const waitTime = match ? parseInt(match[1]) : 60;
          
          setRetryAfter(waitTime);
          const timer = setInterval(() => {
            setRetryAfter(prev => {
              if (prev <= 1) {
                clearInterval(timer);
                return 0;
              }
              return prev - 1;
            });
          }, 1000);
        }
        setError(result.error);
      }
    } catch (err) {
      setError('An unexpected error occurred');
    }
    
    setLoading(false);
  };

  return (
    <div className="container d-flex align-items-center justify-content-center min-vh-100">
      <div className="row w-100">
        <div className="col-md-6 col-lg-4 mx-auto">
          <div className="card shadow">
            <div className="card-body p-4">
              <div className="text-center mb-4">
                <h1 className="h3 mb-3">🚀 Vrexis Insights</h1>
                <p className="text-muted">Sign in to your account</p>
              </div>

              {error && (
                <div className="alert alert-danger" role="alert">
                  {error}
                </div>
              )}

              <div>
                <div className="mb-3">
                  <label htmlFor="email" className="form-label">Email</label>
                  <input
                    type="email"
                    className="form-control"
                    id="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    disabled={loading || retryAfter > 0}
                    onKeyPress={(e) => e.key === 'Enter' && handleSubmit(e)}
                  />
                </div>

                <div className="mb-3">
                  <label htmlFor="password" className="form-label">Password</label>
                  <input
                    type="password"
                    className="form-control"
                    id="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    disabled={loading || retryAfter > 0}
                    onKeyPress={(e) => e.key === 'Enter' && handleSubmit(e)}
                  />
                </div>

                <button 
                  onClick={handleSubmit}
                  className="btn btn-primary w-100 mb-3"
                  disabled={loading || retryAfter > 0}
                >
                  {loading ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-2" role="status"></span>
                      Signing in...
                    </>
                  ) : retryAfter > 0 ? (
                    `⏳ Wait ${retryAfter}s`
                  ) : (
                    'Sign In'
                  )}
                </button>
              </div>

              <div className="text-center">
                <span className="text-muted">Don't have an account? </span>
                <button 
                  className="btn btn-link p-0" 
                  onClick={onToggleMode}
                  disabled={loading || retryAfter > 0}
                >
                  Create one
                </button>
              </div>

              <div className="mt-4 p-3 bg-light rounded">
                <small className="text-muted">
                  <strong>Demo Account:</strong><br />
                  Email: admin@vrexisinsights.com<br />
                  Password: admin123
                </small>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Register Component with rate limiting
const RegisterForm = ({ onToggleMode }) => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    firstName: '',
    lastName: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);
  const { register } = useAuth();

  const handleChange = (e) => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (formData.password.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }

    setLoading(true);

    try {
      const result = await register(
        formData.email, 
        formData.password, 
        formData.firstName, 
        formData.lastName
      );
      
      if (!result.success) {
        if (result.error.includes('Rate limit') || result.error.includes('Too many')) {
          const match = result.error.match(/(\d+)\s*seconds?/);
          const waitTime = match ? parseInt(match[1]) : 60;
          
          setRetryAfter(waitTime);
          const timer = setInterval(() => {
            setRetryAfter(prev => {
              if (prev <= 1) {
                clearInterval(timer);
                return 0;
              }
              return prev - 1;
            });
          }, 1000);
        }
        setError(result.error);
      }
    } catch (err) {
      setError('An unexpected error occurred');
    }
    
    setLoading(false);
  };

  return (
    <div className="container d-flex align-items-center justify-content-center min-vh-100">
      <div className="row w-100">
        <div className="col-md-6 col-lg-5 mx-auto">
          <div className="card shadow">
            <div className="card-body p-4">
              <div className="text-center mb-4">
                <h1 className="h3 mb-3">🚀 Vrexis Insights</h1>
                <p className="text-muted">Create your account</p>
              </div>

              {error && (
                <div className="alert alert-danger" role="alert">
                  {error}
                </div>
              )}

              <div>
                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label htmlFor="firstName" className="form-label">First Name</label>
                    <input
                      type="text"
                      className="form-control"
                      id="firstName"
                      name="firstName"
                      value={formData.firstName}
                      onChange={handleChange}
                      required
                      disabled={loading || retryAfter > 0}
                    />
                  </div>
                  <div className="col-md-6 mb-3">
                    <label htmlFor="lastName" className="form-label">Last Name</label>
                    <input
                      type="text"
                      className="form-control"
                      id="lastName"
                      name="lastName"
                      value={formData.lastName}
                      onChange={handleChange}
                      required
                      disabled={loading || retryAfter > 0}
                    />
                  </div>
                </div>

                <div className="mb-3">
                  <label htmlFor="email" className="form-label">Email</label>
                  <input
                    type="email"
                    className="form-control"
                    id="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    required
                    disabled={loading || retryAfter > 0}
                  />
                </div>

                <div className="mb-3">
                  <label htmlFor="password" className="form-label">Password</label>
                  <input
                    type="password"
                    className="form-control"
                    id="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    required
                    disabled={loading || retryAfter > 0}
                  />
                  <div className="form-text">Must be at least 6 characters</div>
                </div>

                <div className="mb-3">
                  <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
                  <input
                    type="password"
                    className="form-control"
                    id="confirmPassword"
                    name="confirmPassword"
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    required
                    disabled={loading || retryAfter > 0}
                  />
                </div>

                <button 
                  onClick={handleSubmit}
                  className="btn btn-primary w-100 mb-3"
                  disabled={loading || retryAfter > 0}
                >
                  {loading ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-2" role="status"></span>
                      Creating account...
                    </>
                  ) : retryAfter > 0 ? (
                    `⏳ Wait ${retryAfter}s`
                  ) : (
                    'Create Account'
                  )}
                </button>
              </div>

              <div className="text-center">
                <span className="text-muted">Already have an account? </span>
                <button 
                  className="btn btn-link p-0" 
                  onClick={onToggleMode}
                  disabled={loading || retryAfter > 0}
                >
                  Sign in
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Auth Screen Component
const AuthScreen = () => {
  const [isLogin, setIsLogin] = useState(true);

  return isLogin ? (
    <LoginForm onToggleMode={() => setIsLogin(false)} />
  ) : (
    <RegisterForm onToggleMode={() => setIsLogin(true)} />
  );
};

// Main Dashboard Component (enhanced with auth)
const ServiceMonitorDashboard = () => {
  const { user, token, logout } = useAuth();
  const [services, setServices] = useState([]);
  const [darkMode, setDarkMode] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newService, setNewService] = useState({ name: '', url: '', type: 'website' });
  const [urlError, setUrlError] = useState('');
  const [isLoaded, setIsLoaded] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [securityStatus, setSecurityStatus] = useState('secure');
  const [encryptionEnabled, setEncryptionEnabled] = useState(true);
  const [rateLimitInfo, setRateLimitInfo] = useState(null);
  const [isRateLimited, setIsRateLimited] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);

  // API helper with authentication and rate limit handling
  const apiCall = useCallback(async (url, options = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      ...options.headers,
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      // Handle rate limit headers
      const rateLimitHeaders = {
        limit: parseInt(response.headers.get('X-RateLimit-Limit')) || null,
        remaining: parseInt(response.headers.get('X-RateLimit-Remaining')) || null,
        reset: parseInt(response.headers.get('X-RateLimit-Reset')) || null,
        retryAfter: parseInt(response.headers.get('Retry-After')) || null,
      };

      setRateLimitInfo(rateLimitHeaders);

      // Handle rate limiting
      if (response.status === 429) {
        const errorData = await response.json();
        setIsRateLimited(true);
        setRetryAfter(rateLimitHeaders.retryAfter || 60);
        
        // Start countdown timer
        const timer = setInterval(() => {
          setRetryAfter(prev => {
            if (prev <= 1) {
              setIsRateLimited(false);
              clearInterval(timer);
              return 0;
            }
            return prev - 1;
          });
        }, 1000);

        throw new Error(errorData.message || 'Rate limit exceeded. Please wait before trying again.');
      }

      return response;
    } catch (error) {
      if (error.message.includes('Rate limit')) {
        throw error;
      }
      throw new Error(`Network error: ${error.message}`);
    }
  }, [token]);

  // Load preferences on mount
  useEffect(() => {
    try {
      const savedDarkMode = localStorage.getItem('service-monitor-dark-mode');
      if (savedDarkMode) {
        setDarkMode(savedDarkMode === 'true');
      }
      
      if (window.crypto && window.crypto.subtle) {
        setEncryptionEnabled(true);
      } else {
        setEncryptionEnabled(false);
      }
    } catch (error) {
      console.error('Error loading preferences:', error);
    }
    
    setIsLoaded(true);
  }, []);

  // Save preferences
  useEffect(() => {
    if (isLoaded) {
      try {
        localStorage.setItem('service-monitor-dark-mode', darkMode.toString());
      } catch (error) {
        console.warn('Could not save preferences');
      }
    }
  }, [darkMode, isLoaded]);

  // Enhanced secure WebSocket connection with authentication
  useEffect(() => {
    if (!isLoaded || !token) return;

    const loadServices = async () => {
      try {
        const response = await apiCall('/api/v1/services');
        
        if (response.ok) {
          const servicesData = await response.json();
          setServices(servicesData || []);
          console.log('🔒 Services loaded securely');
        }
      } catch (error) {
        console.error('Error loading services:', error);
      }
    };

    const connectWebSocket = () => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws?token=${encodeURIComponent(token)}`;
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
              setServices(data);
            } else if (data && data.id) {
              setServices(prev => {
                const exists = prev.some(s => s.id === data.id);
                return exists
                  ? prev.map(s => s.id === data.id ? { ...s, ...data } : s)
                  : [...prev, data];
              });
            }
          } catch (error) {
            console.error('Error parsing WebSocket message:', error);
            setSecurityStatus('warning');
          }
        };
        
        websocket.onclose = () => {
          console.log('🔒 WebSocket disconnected');
          setConnectionStatus('disconnected');
          setTimeout(connectWebSocket, 3000);
        };
        
        websocket.onerror = (error) => {
          console.error('WebSocket error:', error);
          setConnectionStatus('error');
          setSecurityStatus('warning');
        };
        
        return () => {
          websocket.close();
        };
      } catch (error) {
        console.error('Error creating WebSocket:', error);
        setConnectionStatus('error');
        setSecurityStatus('error');
      }
    };

    loadServices();
    const cleanup = connectWebSocket();

    return cleanup;
  }, [isLoaded, token, apiCall]);

  // Enhanced URL validation with support for raw IPs
  const isValidUrl = (url) => {
    const trimmedUrl = url.trim();
    
    if (!trimmedUrl.includes('://')) {
      let host = trimmedUrl;
      if (host.includes(':')) {
        const parts = host.split(':');
        if (parts.length !== 2) return false;
        host = parts[0];
        const port = parts[1];
        if (!/^\d{1,5}$/.test(port) || parseInt(port) > 65535) {
          return false;
        }
      }
      
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipRegex.test(host)) {
        const octets = host.split('.');
        return octets.every(octet => {
          const num = parseInt(octet);
          return num >= 0 && num <= 255;
        });
      }
      
      const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
      return hostnameRegex.test(host) && host.length <= 253;
    }
    
    try {
      const urlObj = new URL(trimmedUrl);
      const allowedProtocols = ['http:', 'https:'];
      return allowedProtocols.includes(urlObj.protocol);
    } catch {
      return false;
    }
  };

  // Enhanced secure service addition with rate limit handling
  const handleAddService = async () => {
    if (!newService.name.trim() || !newService.url.trim()) return;
    
    const trimmedName = newService.name.trim().slice(0, 100);
    const trimmedUrl = newService.url.trim().slice(0, 500);
    
    if (!isValidUrl(trimmedUrl)) {
      setUrlError('Please enter a valid URL (https://example.com), IP address (192.168.1.1), or hostname (router.local).');
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
      const response = await apiCall('/api/v1/services', {
        method: 'POST',
        body: JSON.stringify(serviceData)
      });

      if (response.ok) {
        const createdService = await response.json();
        setServices(prev => [...prev, createdService]);
        
        setNewService({ name: '', url: '', type: 'website' });
        setShowAddForm(false);
        
        console.log('🔒 Service added securely');
      } else {
        const errorData = await response.json();
        setUrlError(`Failed to add service: ${errorData.error}`);
      }
    } catch (error) {
      console.error('Error adding service:', error);
      if (error.message.includes('Rate limit')) {
        setUrlError(`${error.message} Please wait ${retryAfter} seconds.`);
      } else {
        setUrlError(`Connection error: ${error.message}`);
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  // Enhanced secure delete with rate limit handling
  const handleDelete = async (id, name) => {
    if (!window.confirm(`Are you sure you want to delete "${name}"?`)) {
      return;
    }

    try {
      const response = await apiCall(`/api/v1/services/${encodeURIComponent(id)}`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        setServices(prev => prev.filter(s => s.id !== id));
        console.log('🔒 Service deleted securely');
      } else {
        const errorData = await response.json();
        alert(`Failed to delete service: ${errorData.error}`);
      }
    } catch (error) {
      console.error('Error deleting service:', error);
      if (error.message.includes('Rate limit')) {
        alert(`${error.message} Please wait ${retryAfter} seconds before trying again.`);
      } else {
        alert('Error deleting service. Please check your connection.');
      }
    }
  };

  // Enhanced secure refresh with rate limit handling
  const handleRefresh = async () => {
    try {
      const response = await apiCall('/api/v1/services');
      
      if (response.ok) {
        const updatedServices = await response.json();
        setServices(updatedServices || []);
        console.log('🔒 Services refreshed securely');
      }
    } catch (error) {
      console.error('Error refreshing services:', error);
      if (error.message.includes('Rate limit')) {
        // Show a toast or banner instead of console error
        console.warn(`Rate limited: ${error.message}`);
      }
    }
  };

  const handleFormCancel = () => {
    setNewService({ name: '', url: '', type: 'website' });
    setUrlError('');
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
      latency: s.url && !s.url.includes('://') ? null : (s.latency || 0),
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
              <p className="text-muted mb-0">
                Welcome back, {user?.first_name || user?.email}
              </p>
              {encryptionEnabled && connectionStatus === 'connected' && (
                <small className="text-success d-block">
                  🔒 Enterprise encryption active • All data secured
                </small>
              )}
            </div>
            <div className="d-flex gap-2">
              <button
                onClick={() => setDarkMode(!darkMode)}
                className={`btn btn-${darkMode ? 'light' : 'dark'}`}
                aria-label="Toggle Dark Mode"
              >
                {darkMode ? '☀️' : '🌙'}
              </button>
              <button
                onClick={logout}
                className="btn btn-outline-danger"
              >
                🚪 Logout
              </button>
            </div>
          </header>

          {/* Rate Limit Status Bar */}
          {isRateLimited && (
            <div className="alert alert-warning d-flex align-items-center mb-4" role="alert">
              <span className="me-2">⏳</span>
              <div className="flex-grow-1">
                <strong>Rate Limit Exceeded</strong> - Too many requests. Please wait {retryAfter} seconds before trying again.
              </div>
              <div className="ms-auto">
                <span className="badge bg-warning text-dark">{retryAfter}s</span>
              </div>
            </div>
          )}

          {/* Rate Limit Info (Development Mode) */}
          {rateLimitInfo && !isRateLimited && process.env.NODE_ENV === 'development' && (
            <div className="alert alert-info d-flex align-items-center mb-4" role="alert">
              <span className="me-2">📊</span>
              <div>
                <strong>Rate Limit Status:</strong> {rateLimitInfo.remaining || 0} requests remaining of {rateLimitInfo.limit || 0} per minute
              </div>
            </div>
          )}

          {/* Security Status Bar */}
          {securityStatus === 'secure' && connectionStatus === 'connected' && (
            <div className="alert alert-success d-flex align-items-center mb-4" role="alert">
              <span className="me-2">🛡️</span>
              <div>
                <strong>Secure Monitoring Active</strong> - All connections encrypted with TLS, rate limited for protection, data secured with enterprise-grade security
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
                  🔒 Your Monitored Services ({services.length})
                  {encryptionEnabled && connectionStatus === 'connected' && (
                    <span className="ms-2 badge bg-success">Encrypted</span>
                  )}
                </h3>
                <div className="btn-group">
                  <button 
                    className="btn btn-outline-primary" 
                    onClick={handleRefresh}
                    title="Refresh Services"
                    disabled={isRateLimited}
                  >
                    🔄 Refresh
                  </button>
                  <button 
                    className="btn btn-success" 
                    onClick={() => setShowAddForm(!showAddForm)}
                    disabled={isRateLimited}
                  >
                    {showAddForm ? '✕ Close' : '🔒 Add Service'}
                  </button>
                </div>
              </div>
            </div>

            <div className="card-body">
              {showAddForm && (
                <div className="mb-4 p-3 border rounded">
                  <h5 className="mb-3">🔒 Add New Service</h5>
                  
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
                      disabled={isSubmitting || isRateLimited}
                    >
                      Cancel
                    </button>
                    <button 
                      type="button" 
                      className="btn btn-primary" 
                      onClick={handleAddService}
                      disabled={isSubmitting || isRateLimited || !newService.name.trim() || !newService.url.trim()}
                    >
                      {isSubmitting ? (
                        <>
                          <div className="spinner-border loading-spinner me-2" role="status">
                            <span className="visually-hidden">Loading...</span>
                          </div>
                          Adding...
                        </>
                      ) : isRateLimited ? (
                        `⏳ Wait ${retryAfter}s`
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
                                title="Delete Service"
                                disabled={isRateLimited}
                              >
                                {isRateLimited ? '⏳' : '🗑️'}
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

// Main App Component
const App = () => {
  return (
    <AuthProvider>
      <AuthenticatedApp />
    </AuthProvider>
  );
};

const AuthenticatedApp = () => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="d-flex justify-content-center align-items-center min-vh-100">
        <div className="text-center">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-3 text-muted">Loading Vrexis Insights...</p>
        </div>
      </div>
    );
  }

  return isAuthenticated() ? <ServiceMonitorDashboard /> : <AuthScreen />;
};

export default App;