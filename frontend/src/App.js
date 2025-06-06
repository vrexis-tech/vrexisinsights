import React, { useState, useEffect, useMemo, useCallback, createContext, useContext } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import { v4 as uuidv4 } from 'uuid';
import './App.css'; // Import our custom styles

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
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div className="bg-white rounded-lg shadow-lg p-8 fade-in">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-blue-600 mb-2 text-shadow">Vrexis Insights</h1>
            <p className="text-gray-600">Sign in to your account</p>
          </div>

          {error && (
            <div className="alert alert-danger">
              <span className="mr-2">⚠️</span>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                Email
              </label>
              <input
                type="email"
                id="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={loading || retryAfter > 0}
                className="form-input"
                placeholder="Enter your email"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <input
                type="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={loading || retryAfter > 0}
                className="form-input"
                placeholder="Enter your password"
              />
            </div>

            <button 
              type="submit"
              className="btn-primary w-full flex justify-center items-center"
              disabled={loading || retryAfter > 0}
            >
              {loading ? (
                <>
                  <svg className="loading-spinner mr-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Signing in...
                </>
              ) : retryAfter > 0 ? (
                `⏳ Wait ${retryAfter}s`
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          <div className="text-center mt-6">
            <span className="text-gray-600">Don't have an account? </span>
            <button 
              className="text-blue-600 hover:text-blue-500 font-medium transition-colors"
              onClick={onToggleMode}
              disabled={loading || retryAfter > 0}
            >
              Create one
            </button>
          </div>

          <div className="mt-6 p-4 bg-gray-50 rounded-lg">
            <p className="text-sm text-gray-600">
              <strong>Demo Account:</strong><br />
              Email: admin@vrexisinsights.com<br />
              Password: admin123
            </p>
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
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div className="bg-white rounded-lg shadow-lg p-8 fade-in">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2 text-shadow">🚀 Vrexis Insights</h1>
            <p className="text-gray-600">Create your account</p>
          </div>

          {error && (
            <div className="alert alert-danger">
              <span className="mr-2">⚠️</span>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="firstName" className="block text-sm font-medium text-gray-700 mb-1">
                  First Name
                </label>
                <input
                  type="text"
                  id="firstName"
                  name="firstName"
                  value={formData.firstName}
                  onChange={handleChange}
                  required
                  disabled={loading || retryAfter > 0}
                  className="form-input"
                  placeholder="John"
                />
              </div>
              <div>
                <label htmlFor="lastName" className="block text-sm font-medium text-gray-700 mb-1">
                  Last Name
                </label>
                <input
                  type="text"
                  id="lastName"
                  name="lastName"
                  value={formData.lastName}
                  onChange={handleChange}
                  required
                  disabled={loading || retryAfter > 0}
                  className="form-input"
                  placeholder="Doe"
                />
              </div>
            </div>

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                Email
              </label>
              <input
                type="email"
                id="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                required
                disabled={loading || retryAfter > 0}
                className="form-input"
                placeholder="john@example.com"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <input
                type="password"
                id="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                required
                disabled={loading || retryAfter > 0}
                className="form-input"
                placeholder="••••••••"
              />
              <p className="text-sm text-gray-500 mt-1">Must be at least 6 characters</p>
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-1">
                Confirm Password
              </label>
              <input
                type="password"
                id="confirmPassword"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                required
                disabled={loading || retryAfter > 0}
                className="form-input"
                placeholder="••••••••"
              />
            </div>

            <button 
              type="submit"
              className="btn-primary w-full flex justify-center items-center"
              disabled={loading || retryAfter > 0}
            >
              {loading ? (
                <>
                  <svg className="loading-spinner mr-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Creating account...
                </>
              ) : retryAfter > 0 ? (
                `⏳ Wait ${retryAfter}s`
              ) : (
                'Create Account'
              )}
            </button>
          </form>

          <div className="text-center mt-6">
            <span className="text-gray-600">Already have an account? </span>
            <button 
              className="text-blue-600 hover:text-blue-500 font-medium transition-colors"
              onClick={onToggleMode}
              disabled={loading || retryAfter > 0}
            >
              Sign in
            </button>
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
  const [services, setServices] = useState([
    // Sample data for demo
    {
      id: '1',
      name: 'Main Website',
      url: 'https://example.com',
      type: 'website',
      status: 'up',
      latency: 45,
      ping_latency: 12,
      last_checked: new Date().toISOString()
    },
    {
      id: '2',
      name: 'API Server',
      url: 'https://api.example.com',
      type: 'server',
      status: 'up',
      latency: 89,
      ping_latency: 8,
      last_checked: new Date().toISOString()
    },
    {
      id: '3',
      name: 'Database Server',
      url: '192.168.1.100',
      type: 'server',
      status: 'down',
      latency: 0,
      ping_latency: 0,
      last_checked: new Date(Date.now() - 300000).toISOString()
    }
  ]);
  const [darkMode, setDarkMode] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newService, setNewService] = useState({ name: '', url: '', type: 'website' });
  const [urlError, setUrlError] = useState('');
  const [isLoaded, setIsLoaded] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('connected'); // Demo status
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [securityStatus, setSecurityStatus] = useState('secure');
  const [encryptionEnabled, setEncryptionEnabled] = useState(true);
  const [rateLimitInfo, setRateLimitInfo] = useState(null);
  const [isRateLimited, setIsRateLimited] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);

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

  // Enhanced secure service addition
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
      enabled: true,
      status: 'up', // Demo status
      latency: Math.floor(Math.random() * 100) + 20,
      ping_latency: Math.floor(Math.random() * 50) + 5,
      last_checked: new Date().toISOString()
    };

    // Simulate API call
    setTimeout(() => {
      setServices(prev => [...prev, serviceData]);
      setNewService({ name: '', url: '', type: 'website' });
      setShowAddForm(false);
      setIsSubmitting(false);
      console.log('🔒 Service added securely');
    }, 1000);
  };

  // Enhanced secure delete
  const handleDelete = async (id, name) => {
    if (!window.confirm(`Are you sure you want to delete "${name}"?`)) {
      return;
    }

    setServices(prev => prev.filter(s => s.id !== id));
    console.log('🔒 Service deleted securely');
  };

  // Enhanced secure refresh
  const handleRefresh = async () => {
    // Simulate refresh with random latency updates
    setServices(prev => prev.map(service => ({
      ...service,
      latency: service.status === 'up' ? Math.floor(Math.random() * 100) + 20 : 0,
      ping_latency: service.status === 'up' ? Math.floor(Math.random() * 50) + 5 : 0,
      last_checked: new Date().toISOString()
    })));
    console.log('🔒 Services refreshed securely');
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
        return <span className="badge badge-success">✅ Online</span>;
      case 'down':
        return <span className="badge badge-danger">❌ Offline</span>;
      default:
        return <span className="badge badge-gray">❓ Unknown</span>;
    }
  };

  const getStatusIndicator = () => {
    if (connectionStatus === 'connected' && securityStatus === 'secure') {
      return (
        <div className="flex items-center gap-2">
          <span className="badge badge-success">🔗 Connected</span>
          {encryptionEnabled && <span className="badge badge-info">🔒 Secure</span>}
        </div>
      );
    } else if (connectionStatus === 'connected' && securityStatus === 'warning') {
      return <span className="badge badge-warning">⚠️ Connected (Warning)</span>;
    } else if (connectionStatus === 'disconnected') {
      return <span className="badge badge-warning">⚠️ Disconnected</span>;
    } else if (connectionStatus === 'error' || securityStatus === 'error') {
      return <span className="badge badge-danger">❌ Connection Error</span>;
    } else {
      return <span className="badge badge-gray">⏳ Connecting...</span>;
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

  return (
    <div className={`min-h-screen ${darkMode ? 'bg-gray-900 text-white' : 'bg-gray-50 text-gray-900'}`}>
      {/* Status Indicator */}
      <div className="status-indicator">
        {getStatusIndicator()}
      </div>

      <div className="max-w-6xl mx-auto py-8 px-4">
        {/* Header */}
        <header className="flex justify-between items-center mb-8 fade-in">
          <div>
            <h1 className="text-4xl font-bold mb-2 text-shadow">🚀 Vrexis Insights</h1>
            <p className={`${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
              Welcome back, {user?.first_name || user?.email}
            </p>
            {encryptionEnabled && connectionStatus === 'connected' && (
              <p className="text-green-600 text-sm mt-1">
                🔒 Enterprise encryption active • All data secured
              </p>
            )}
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => setDarkMode(!darkMode)}
              className={`px-4 py-2 rounded-lg border transition-colors ${
                darkMode 
                  ? 'bg-white text-gray-900 border-white hover:bg-gray-100' 
                  : 'bg-gray-900 text-white border-gray-900 hover:bg-gray-800'
              }`}
            >
              {darkMode ? '☀️' : '🌙'}
            </button>
            <button
              onClick={logout}
              className="btn-danger"
            >
              🚪 Logout
            </button>
          </div>
        </header>

        {/* Rate Limit Status Bar */}
        {isRateLimited && (
          <div className="alert alert-warning flex justify-between items-center">
            <div className="flex items-center">
              <span className="mr-2">⏳</span>
              <div>
                <strong>Rate Limit Exceeded</strong> - Too many requests. Please wait {retryAfter} seconds before trying again.
              </div>
            </div>
            <span className="badge badge-warning">{retryAfter}s</span>
          </div>
        )}

        {/* Security Status Bar */}
        {securityStatus === 'secure' && connectionStatus === 'connected' && (
          <div className="alert alert-success">
            <span className="mr-2">🛡️</span>
            <div>
              <strong>Secure Monitoring Active</strong> - All connections encrypted with TLS, rate limited for protection, data secured with enterprise-grade security
            </div>
          </div>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
          <div className={`${darkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-lg p-6 stats-card stats-card-success fade-in`}>
            <div className="flex items-center">
              <div className="mr-4">
                <span className="text-4xl">✅</span>
              </div>
              <div>
                <h3 className="text-2xl font-bold">{upServices}</h3>
                <p className={`${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Online</p>
              </div>
            </div>
          </div>

          <div className={`${darkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-lg p-6 stats-card stats-card-danger fade-in`}>
            <div className="flex items-center">
              <div className="mr-4">
                <span className="text-4xl">❌</span>
              </div>
              <div>
                <h3 className="text-2xl font-bold">{downServices}</h3>
                <p className={`${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Offline</p>
              </div>
            </div>
          </div>

          <div className={`${darkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-lg p-6 stats-card stats-card-security fade-in`}>
            <div className="flex items-center">
              <div className="mr-4">
                <span className="text-4xl">🔒</span>
              </div>
              <div>
                <h3 className="text-2xl font-bold">{secureServices}</h3>
                <p className={`${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>HTTPS</p>
              </div>
            </div>
          </div>

          <div className={`${darkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-lg p-6 stats-card stats-card-info fade-in`}>
            <div className="flex items-center">
              <div className="mr-4">
                <span className="text-4xl">🌐</span>
              </div>
              <div>
                <h3 className="text-2xl font-bold">{statsByType.website}</h3>
                <p className={`${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Websites</p>
              </div>
            </div>
          </div>

          <div className={`${darkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-lg p-6 stats-card stats-card-info fade-in`}>
            <div className="flex items-center">
              <div className="mr-4">
                <span className="text-4xl">⚡</span>
              </div>
              <div>
                <h3 className="text-2xl font-bold">{avgLatency}ms</h3>
                <p className={`${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Avg HTTP</p>
              </div>
            </div>
          </div>

          <div className={`${darkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-lg p-6 stats-card stats-card-info fade-in`}>
            <div className="flex items-center">
              <div className="mr-4">
                <span className="text-4xl">🏓</span>
              </div>
              <div>
                <h3 className="text-2xl font-bold">{avgPingLatency}ms</h3>
                <p className={`${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Avg Ping</p>
              </div>
            </div>
          </div>
        </div>

        {/* Services Section */}
        <div className={`${darkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-lg fade-in`}>
          <div className="p-6 border-b border-gray-200">
            <div className="flex justify-between items-center">
              <h3 className="text-xl font-bold flex items-center">
                🔒 Your Monitored Services ({services.length})
                {encryptionEnabled && connectionStatus === 'connected' && (
                  <span className="ml-2 badge badge-success">Encrypted</span>
                )}
              </h3>
              <div className="flex gap-2">
                <button 
                  className="btn-secondary"
                  onClick={handleRefresh}
                  disabled={isRateLimited}
                >
                  🔄 Refresh
                </button>
                <button 
                  className="btn-primary"
                  onClick={() => setShowAddForm(!showAddForm)}
                  disabled={isRateLimited}
                >
                  {showAddForm ? '✕ Close' : '🔒 Add Service'}
                </button>
              </div>
            </div>
          </div>

          <div className="p-6">
            {showAddForm && (
              <div className="mb-6 p-4 border border-gray-200 rounded-lg fade-in">
                <h5 className="text-lg font-semibold mb-4">🔒 Add New Service</h5>
                
                <div className="alert alert-info mb-4">
                  <div className="flex items-start">
                    <span className="mr-2 mt-0.5">🛡️</span>
                    <div>
                      <strong>Monitoring Types:</strong> 
                      <ul className="mt-2 ml-4 list-disc">
                        <li><strong>URLs:</strong> HTTP/HTTPS monitoring + ping (https://example.com)</li>
                        <li><strong>IP Addresses:</strong> Ping-only monitoring (192.168.1.1)</li>
                        <li><strong>Hostnames:</strong> Ping-only monitoring (router.local)</li>
                      </ul>
                    </div>
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Service Name</label>
                    <input
                      type="text"
                      className={`form-input ${darkMode ? 'form-input-dark' : ''}`}
                      placeholder="My API Service"
                      value={newService.name}
                      onChange={(e) => setNewService({ ...newService, name: e.target.value })}
                      maxLength="100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Service URL/IP Address</label>
                    <input
                      type="text"
                      className={`form-input ${urlError ? 'border-red-500' : ''} ${darkMode ? 'form-input-dark' : ''}`}
                      placeholder="https://api.example.com, 192.168.1.1, or router.local"
                      value={newService.url}
                      onChange={(e) => setNewService({ ...newService, url: e.target.value })}
                      maxLength="500"
                    />
                    {urlError && <p className="text-red-500 text-sm mt-1">{urlError}</p>}
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Service Type</label>
                    <select
                      className={`form-input ${darkMode ? 'form-input-dark' : ''}`}
                      value={newService.type}
                      onChange={(e) => setNewService({ ...newService, type: e.target.value })}
                    >
                      <option value="website">🌐 Website/API</option>
                      <option value="server">🖥️ Server</option>
                      <option value="misc">🔧 Network Equipment</option>
                    </select>
                  </div>
                </div>

                <div className="flex justify-end gap-2 mt-4">
                  <button 
                    type="button" 
                    className="btn-secondary"
                    onClick={handleFormCancel}
                    disabled={isSubmitting || isRateLimited}
                  >
                    Cancel
                  </button>
                  <button 
                    type="button" 
                    className="btn-primary flex items-center"
                    onClick={handleAddService}
                    disabled={isSubmitting || isRateLimited || !newService.name.trim() || !newService.url.trim()}
                  >
                    {isSubmitting ? (
                      <>
                        <svg className="loading-spinner mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
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
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {services.map((service) => {
                  const isSecure = service.url && service.url.startsWith('https://');
                  return (
                    <div key={service.id} className={`${darkMode ? 'bg-gray-700' : 'bg-gray-50'} rounded-lg p-6 service-card ${
                      isSecure ? 'secure-service' : 'insecure-service'
                    }`}>
                      <div className="flex justify-between items-start mb-4">
                        <div className="flex items-start">
                          <span className="text-3xl mr-3">{getTypeIcon(service.type || 'website')}</span>
                          <div>
                            <h6 className="font-semibold text-lg flex items-center">
                              {service.name || 'Unknown Service'}
                              {isSecure && <span className="ml-2 text-green-500" title="Secure HTTPS connection">🔒</span>}
                              {!isSecure && service.url && service.url.startsWith('http://') && 
                                <span className="ml-2 text-yellow-500" title="Insecure HTTP connection">⚠️</span>
                              }
                            </h6>
                            <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{service.url || 'No URL'}</p>
                            <div className="flex gap-2 mt-2">
                              <span className="badge badge-gray">
                                {getTypeLabel(service.type || 'website')}
                              </span>
                              {isSecure && <span className="badge badge-success">🔒 Secure</span>}
                              {!isSecure && service.url && service.url.startsWith('http://') && 
                                <span className="badge badge-warning">⚠️ Insecure</span>
                              }
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {getStatusBadge(service.status)}
                          <button 
                            className="p-2 text-red-500 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-50"
                            onClick={() => handleDelete(service.id, service.name)}
                            title="Delete Service"
                            disabled={isRateLimited}
                          >
                            {isRateLimited ? '⏳' : '🗑️'}
                          </button>
                        </div>
                      </div>

                      <div className="grid grid-cols-3 gap-4 text-center">
                        <div className="border-r border-gray-300 pr-4">
                          <div className="text-xl font-bold">
                            {service.url && !service.url.includes('://') ? 'N/A' : (service.latency || 0) + 'ms'}
                          </div>
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>HTTP</p>
                        </div>
                        <div className="border-r border-gray-300 pr-4">
                          <div className="text-xl font-bold">{service.ping_latency || 0}ms</div>
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Ping</p>
                        </div>
                        <div>
                          <div className="text-xl font-bold">{formatLastChecked(service.last_checked)}</div>
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Last Check</p>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-12">
                <div className="mb-4">
                  <span className="text-6xl">🔒</span>
                </div>
                <h4 className={`text-xl font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                  No services monitored yet
                </h4>
                <p className={`mb-4 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Add your first service to start monitoring
                </p>
                <button 
                  className="btn-primary"
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
          <div className={`${darkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-lg mt-8 fade-in`}>
            <div className="p-6">
              <h5 className="text-xl font-semibold mb-4">📈 HTTP & Ping Latency Chart</h5>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#6B7280' : '#E5E7EB'} />
                  <XAxis 
                    dataKey="name" 
                    stroke={darkMode ? '#9CA3AF' : '#6B7280'}
                    fontSize={12}
                  />
                  <YAxis 
                    stroke={darkMode ? '#9CA3AF' : '#6B7280'}
                    fontSize={12}
                  />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: darkMode ? '#374151' : '#FFFFFF',
                      border: darkMode ? '1px solid #6B7280' : '1px solid #E5E7EB',
                      borderRadius: '8px',
                      color: darkMode ? '#FFFFFF' : '#111827'
                    }}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="latency" 
                    stroke="#3B82F6" 
                    name="HTTP Latency (ms)" 
                    strokeWidth={2}
                    dot={{ fill: '#3B82F6', strokeWidth: 2, r: 4 }}
                    connectNulls={false}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="ping" 
                    stroke="#10B981" 
                    name="Ping Latency (ms)" 
                    strokeWidth={2}
                    dot={{ fill: '#10B981', strokeWidth: 2, r: 4 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </div>
    </div>
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
      <div className="min-h-screen flex justify-center items-center bg-gray-50">
        <div className="text-center fade-in">
          <svg className="w-12 h-12 text-blue-500 mx-auto mb-4 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <p className="text-gray-600">Loading Vrexis Insights...</p>
        </div>
      </div>
    );
  }

  return isAuthenticated() ? <ServiceMonitorDashboard /> : <AuthScreen />;
};

export default App;