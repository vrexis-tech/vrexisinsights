import React, { useState, useEffect, useMemo, useCallback, createContext, useContext } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';

import { 
  Activity, 
  Server, 
  Globe, 
  Wifi, 
  WifiOff, 
  Plus, 
  Search, 
  RotateCcw, 
  Trash2, 
  Settings, 
  User, 
  LogOut, 
  Moon, 
  Sun, 
  BarChart3, 
  Shield, 
  Clock, 
  AlertCircle, 
  CheckCircle, 
  Info, 
  Zap,
  MoreVertical,
  Eye,
  Lock,
  Unlock,
  TrendingUp,
  AlertTriangle
} from 'lucide-react';
import { v4 as uuidv4 } from 'uuid';

// Import our API integration
import apiService from './apiService';
import { useServices } from './useServices';

// Mock logo for demo
const vrexisLogo = "data:image/svg+xml,%3Csvg width='100' height='100' xmlns='http://www.w3.org/2000/svg'%3E%3Ccircle cx='50' cy='50' r='40' fill='%234F46E5'/%3E%3Ctext x='50' y='55' font-family='Arial' font-size='20' fill='white' text-anchor='middle'%3EV%3C/text%3E%3C/svg%3E";

// Authentication Context
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Authentication Provider - Updated with real API
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for stored auth data on mount
    const storedToken = sessionStorage.getItem('auth-token');
    const storedUser = sessionStorage.getItem('auth-user');
    const storedRefreshToken = sessionStorage.getItem('refresh-token');
    
    if (storedToken && storedUser) {
      try {
        const userData = JSON.parse(storedUser);
        setToken(storedToken);
        setUser(userData);
        
        // Set tokens in API service
        apiService.setTokens(storedToken, storedRefreshToken);
      } catch (error) {
        console.error('Error parsing stored user data:', error);
        sessionStorage.removeItem('auth-token');
        sessionStorage.removeItem('auth-user');
        sessionStorage.removeItem('refresh-token');
      }
    }
    setLoading(false);
  }, []);

  const login = async (email, password) => {
    try {
      console.log('Attempting login with API service...');
      const data = await apiService.login(email, password);
      console.log('Login response:', data);
      
      // Handle different response formats from your Go backend
      const accessToken = data.access_token || data.token;
      const refreshToken = data.refresh_token;
      const userData = data.user;
      
      if (!accessToken) {
        throw new Error('No access token received from server');
      }
      
      setToken(accessToken);
      setUser(userData);
      
      // Set tokens in API service
      apiService.setTokens(accessToken, refreshToken);
      
      sessionStorage.setItem('auth-token', accessToken);
      sessionStorage.setItem('auth-user', JSON.stringify(userData));
      if (refreshToken) {
        sessionStorage.setItem('refresh-token', refreshToken);
      }
      
      return { success: true };
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, error: error.message };
    }
  };

  const register = async (email, password, firstName, lastName) => {
    try {
      console.log('Attempting registration with API service...');
      const data = await apiService.register(email, password, firstName, lastName);
      console.log('Registration response:', data);
      
      // Handle different response formats from your Go backend
      const accessToken = data.access_token || data.token;
      const refreshToken = data.refresh_token;
      const userData = data.user;
      
      if (!accessToken) {
        throw new Error('No access token received from server');
      }
      
      setToken(accessToken);
      setUser(userData);
      
      // Set tokens in API service
      apiService.setTokens(accessToken, refreshToken);
      
      sessionStorage.setItem('auth-token', accessToken);
      sessionStorage.setItem('auth-user', JSON.stringify(userData));
      if (refreshToken) {
        sessionStorage.setItem('refresh-token', refreshToken);
      }
      
      return { success: true };
    } catch (error) {
      console.error('Registration error:', error);
      return { success: false, error: error.message };
    }
  };

  const logout = async () => {
    try {
      // Call API logout endpoint
      await apiService.logout();
    } catch (error) {
      console.error('Logout API call failed:', error);
    } finally {
      // Always clear local auth state
      setToken(null);
      setUser(null);
      sessionStorage.removeItem('auth-token');
      sessionStorage.removeItem('auth-user');
      sessionStorage.removeItem('refresh-token');
    }
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

// Modern Login Form
const LoginForm = ({ onToggleMode }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);
  const { login } = useAuth();

  const handleSubmit = async () => {
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
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl overflow-hidden">
          <div className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-gray-700 dark:to-gray-600 p-6 text-center">
            <div className="w-20 h-20 mx-auto mb-4 rounded-full bg-white shadow-lg flex items-center justify-center">
              <img src={vrexisLogo} alt="VREXIS" className="w-12 h-12 object-contain" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white tracking-widest">VREXIS</h1>
            <p className="text-sm font-medium text-blue-600 dark:text-blue-400 tracking-wider">INSIGHTS</p>
          </div>
          
          <div className="p-6">
            <p className="text-gray-600 dark:text-gray-400 text-center mb-6">Sign in to your account</p>

            {error && (
              <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <div className="flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-red-700 dark:text-red-400 text-sm">{error}</span>
                </div>
              </div>
            )}

            <div className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Email
                </label>
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  disabled={loading || retryAfter > 0}
                  className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                  placeholder="Enter your email"
                />
              </div>

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Password
                </label>
                <input
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  disabled={loading || retryAfter > 0}
                  className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                  placeholder="Enter your password"
                />
              </div>

              <button 
                onClick={handleSubmit}
                disabled={loading || retryAfter > 0}
                className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-500 via-blue-600 to-blue-700 text-white rounded-lg hover:from-blue-600 hover:via-blue-700 hover:to-blue-800 transition-all font-medium shadow-lg hover:shadow-xl transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    Signing in...
                  </>
                ) : retryAfter > 0 ? (
                  <>
                    <Clock className="w-4 h-4" />
                    Wait {retryAfter}s
                  </>
                ) : (
                  'Sign In'
                )}
              </button>
            </div>

            <div className="mt-6 text-center">
              <span className="text-gray-600 dark:text-gray-400">Don't have an account? </span>
              <button 
                onClick={onToggleMode}
                disabled={loading || retryAfter > 0}
                className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 font-medium"
              >
                Create one
              </button>
            </div>

            <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
              <div className="text-sm text-blue-700 dark:text-blue-400">
                <div className="font-medium mb-1">Test Account:</div>
                <div>Email: admin@vrexisinsights.com</div>
                <div>Password: TestPass123!</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Modern Register Form
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

  const handleSubmit = async () => {
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters');
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
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl overflow-hidden">
          <div className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-gray-700 dark:to-gray-600 p-6 text-center">
            <div className="w-20 h-20 mx-auto mb-4 rounded-full bg-white shadow-lg flex items-center justify-center">
              <img src={vrexisLogo} alt="VREXIS" className="w-12 h-12 object-contain" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white tracking-widest">VREXIS</h1>
            <p className="text-sm font-medium text-blue-600 dark:text-blue-400 tracking-wider">INSIGHTS</p>
          </div>
          
          <div className="p-6">
            <p className="text-gray-600 dark:text-gray-400 text-center mb-6">Create your account</p>

            {error && (
              <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <div className="flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-red-700 dark:text-red-400 text-sm">{error}</span>
                </div>
              </div>
            )}

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label htmlFor="firstName" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
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
                    className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                  />
                </div>
                <div>
                  <label htmlFor="lastName" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
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
                    className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                  />
                </div>
              </div>

              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
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
                  className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                />
              </div>

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
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
                  className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Must be at least 8 characters</p>
              </div>

              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
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
                  className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                />
              </div>

              <button 
                onClick={handleSubmit}
                disabled={loading || retryAfter > 0}
                className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-500 via-blue-600 to-blue-700 text-white rounded-lg hover:from-blue-600 hover:via-blue-700 hover:to-blue-800 transition-all font-medium shadow-lg hover:shadow-xl transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    Creating account...
                  </>
                ) : retryAfter > 0 ? (
                  <>
                    <Clock className="w-4 h-4" />
                    Wait {retryAfter}s
                  </>
                ) : (
                  'Create Account'
                )}
              </button>
            </div>

            <div className="mt-6 text-center">
              <span className="text-gray-600 dark:text-gray-400">Already have an account? </span>
              <button 
                onClick={onToggleMode}
                disabled={loading || retryAfter > 0}
                className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 font-medium"
              >
                Sign in
              </button>
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

// Main Insights Dashboard - Updated with real API integration
const ServiceMonitorDashboard = () => {
  const { user, token, logout } = useAuth();
  
  // REAL API integration - replaces all mock data
  const {
    services,
    loading: servicesLoading,
    error: servicesError,
    lastUpdated,
    connectionStatus,
    stats,
    addService: addServiceApi,
    deleteService: deleteServiceApi,
    refreshServices: refreshServicesApi,
    refetch: refetchServices
  } = useServices(token);

  // UI state only - with dark mode persistence
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('vrexis-dark-mode');
    return saved ? JSON.parse(saved) : false;
  });
  const [showAddForm, setShowAddForm] = useState(false);
  const [newService, setNewService] = useState({ name: '', url: '', type: 'website' });
  const [urlError, setUrlError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  // Save dark mode preference whenever it changes
  useEffect(() => {
    localStorage.setItem('vrexis-dark-mode', JSON.stringify(darkMode));
  }, [darkMode]);

  // Extract stats from useServices hook
  const { upServices, downServices, secureServices, statsByType, avgLatency, avgPingLatency } = stats;

  // Filter services based on search query (MOVE BEFORE EARLY RETURNS)
  const filteredServices = useMemo(() => {
    if (!searchQuery.trim()) return services;
    
    const query = searchQuery.toLowerCase();
    return services.filter(service => 
      service.name?.toLowerCase().includes(query) ||
      service.url?.toLowerCase().includes(query) ||
      service.type?.toLowerCase().includes(query)
    );
  }, [services, searchQuery]);

  // Chart data preparation (MOVE BEFORE EARLY RETURNS)
  const chartData = useMemo(() => {
    return filteredServices.map(s => ({
      name: s.name?.slice(0, 15) + (s.name?.length > 15 ? '...' : '') || 'Unknown',
      latency: s.url && !s.url.includes('://') ? null : (s.latency || 0),
      ping: s.ping_latency || 0
    }));
  }, [filteredServices]);

  // Show loading state
  if (servicesLoading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600 dark:text-gray-400">Loading services...</p>
        </div>
      </div>
    );
  }

  // Show error state (only if no services and there's an error)
  if (servicesError && services.length === 0) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center max-w-md">
          <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
            Connection Error
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            {servicesError}
          </p>
          <button 
            onClick={refetchServices}
            className="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  // Enhanced URL validation
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

  // Real API service handlers
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
      name: trimmedName,
      url: trimmedUrl,
      type: newService.type,
      enabled: true
    };

    try {
      const result = await addServiceApi(serviceData);
      
      if (result.success) {
        setNewService({ name: '', url: '', type: 'website' });
        setShowAddForm(false);
      } else {
        setUrlError(result.error || 'Failed to add service');
      }
    } catch (error) {
      console.error('Error adding service:', error);
      setUrlError('Failed to add service');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (id, name) => {
    if (!window.confirm(`Are you sure you want to delete "${name}"?`)) {
      return;
    }

    try {
      const result = await deleteServiceApi(id);
      if (!result.success) {
        alert('Failed to delete service: ' + result.error);
      }
    } catch (error) {
      console.error('Error deleting service:', error);
      alert('Failed to delete service');
    }
  };

  const handleRefresh = async () => {
    try {
      await refreshServicesApi();
    } catch (error) {
      console.error('Error refreshing services:', error);
    }
  };

  const handleFormCancel = () => {
    setNewService({ name: '', url: '', type: 'website' });
    setUrlError('');
    setShowAddForm(false);
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'website': return <Globe className="w-5 h-5" />;
      case 'server': return <Server className="w-5 h-5" />;
      case 'misc': return <Settings className="w-5 h-5" />;
      default: return <Activity className="w-5 h-5" />;
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
        return (
          <div className="flex items-center gap-1 px-2 py-1 bg-green-100 text-green-700 rounded-full text-xs dark:bg-green-900/20 dark:text-green-400">
            <CheckCircle className="w-3 h-3" />
            Online
          </div>
        );
      case 'down':
        return (
          <div className="flex items-center gap-1 px-2 py-1 bg-red-100 text-red-700 rounded-full text-xs dark:bg-red-900/20 dark:text-red-400">
            <AlertTriangle className="w-3 h-3" />
            Offline
          </div>
        );
      default:
        return (
          <div className="flex items-center gap-1 px-2 py-1 bg-gray-100 text-gray-700 rounded-full text-xs dark:bg-gray-800 dark:text-gray-400">
            <AlertCircle className="w-3 h-3" />
            Unknown
          </div>
        );
    }
  };

  // Updated status indicator with real connection status
  const getStatusIndicator = () => {
    if (connectionStatus === 'connected') {
      return (
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 px-3 py-1.5 bg-green-100 text-green-700 rounded-full text-sm dark:bg-green-900/20 dark:text-green-400 font-medium shadow-sm">
            <Wifi className="w-4 h-4" />
            Connected
            {lastUpdated && (
              <span className="text-xs opacity-75 ml-1">
                • {lastUpdated.toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>
      );
    } else if (connectionStatus === 'connecting') {
      return (
        <div className="flex items-center gap-1 px-3 py-1.5 bg-yellow-100 text-yellow-700 rounded-full text-sm dark:bg-yellow-900/20 dark:text-yellow-400 font-medium shadow-sm">
          <div className="w-4 h-4 border-2 border-yellow-600 border-t-transparent rounded-full animate-spin"></div>
          Connecting...
        </div>
      );
    } else {
      return (
        <div className="flex items-center gap-1 px-3 py-1.5 bg-red-100 text-red-700 rounded-full text-sm dark:bg-red-900/20 dark:text-red-400 font-medium shadow-sm">
          <WifiOff className="w-4 h-4" />
          Disconnected
        </div>
      );
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
    <div className={`min-h-screen ${darkMode ? 'dark bg-gray-900' : 'bg-gray-50'}`}>
      {/* Sidebar */}
      <div className={`fixed left-0 top-0 h-full ${sidebarOpen ? 'w-80' : 'w-16'} ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border-r transition-all duration-300 z-40 overflow-hidden`}>
        <div className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-400 via-blue-500 to-blue-800 rounded-xl flex items-center justify-center shadow-lg">
              <Activity className="w-6 h-6 text-white" />
            </div>
            {sidebarOpen && (
              <div className="flex-1">
                <h1 className={`text-2xl font-bold tracking-widest ${darkMode ? 'text-white' : 'text-gray-900'}`}>VREXIS</h1>
                <p className={`text-sm font-medium tracking-wider ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>INSIGHTS</p>
              </div>
            )}
          </div>
        </div>

        {sidebarOpen && (
          <div className="px-4 mb-6">
            <div className={`p-4 rounded-xl ${darkMode ? 'bg-gradient-to-r from-gray-700 to-gray-600' : 'bg-gradient-to-r from-blue-50 to-purple-50'} border ${darkMode ? 'border-gray-600' : 'border-blue-100'}`}>
              <div className="flex items-center justify-between mb-3">
                <span className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Service Status</span>
                <Info className={`w-4 h-4 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`} />
              </div>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>Online Services</span>
                  <span className={`font-medium ${darkMode ? 'text-green-400' : 'text-green-600'}`}>{upServices}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>Offline Services</span>
                  <span className={`font-medium ${darkMode ? 'text-red-400' : 'text-red-600'}`}>{downServices}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>Avg Latency</span>
                  <span className={`font-medium ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>{avgLatency}ms</span>
                </div>
              </div>
            </div>
          </div>
        )}

        <nav className="px-2">
          <div className="space-y-1">
            <button 
              className={`w-full flex items-center gap-3 px-3 py-3 rounded-xl transition-all bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300 shadow-sm`}
            >
              <div className="p-2 rounded-lg bg-blue-200 dark:bg-blue-800">
                <BarChart3 className="w-4 h-4" />
              </div>
              {sidebarOpen && (
                <div className="flex-1 text-left">
                  <div className="font-medium">Dashboard</div>
                  <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                    Monitor all services
                  </div>
                </div>
              )}
            </button>
          </div>
        </nav>
      </div>

      {/* Main Content */}
      <div className={`${sidebarOpen ? 'ml-80' : 'ml-16'} transition-all duration-300`}>
        {/* Header */}
        <header className={`${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border-b px-6 py-4`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <button 
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className={`p-2 rounded-lg ${darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100'}`}
              >
                <MoreVertical className={`w-5 h-5 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`} />
              </button>
              
              <div>
                <h2 className={`text-xl font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  Service Monitor Dashboard
                </h2>
                <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Welcome back, {user?.first_name || user?.email}
                </p>
              </div>
            </div>

            {/* Status Indicator in Header */}
            <div className="flex items-center gap-4">
              {getStatusIndicator()}
              
              <div className="relative">
                <Search className={`absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                <input
                  type="text"
                  placeholder="Search services..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className={`pl-10 pr-4 py-2 w-64 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'} focus:ring-2 focus:ring-blue-500 focus:border-transparent`}
                />
              </div>
              
              <button 
                onClick={() => setDarkMode(!darkMode)}
                className={`p-2 rounded-lg ${darkMode ? 'text-gray-300 hover:bg-gray-700' : 'text-gray-600 hover:bg-gray-100'}`}
              >
                {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
              </button>
              
              <button 
                onClick={logout}
                className={`p-2 rounded-lg ${darkMode ? 'text-gray-300 hover:bg-gray-700' : 'text-gray-600 hover:bg-gray-100'}`}
                title="Logout"
              >
                <LogOut className="w-5 h-5" />
              </button>
            </div>
          </div>
        </header>

        {/* Content Area */}
        <main className="p-6">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-6 mb-8">
            <div className={`p-6 rounded-2xl ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-lg border ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Online</p>
                  <p className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{upServices}</p>
                </div>
                <div className="w-12 h-12 bg-gradient-to-r from-green-500 to-green-600 rounded-xl flex items-center justify-center">
                  <CheckCircle className="w-6 h-6 text-white" />
                </div>
              </div>
            </div>

            <div className={`p-6 rounded-2xl ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-lg border ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Offline</p>
                  <p className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{downServices}</p>
                </div>
                <div className="w-12 h-12 bg-gradient-to-r from-red-500 to-red-600 rounded-xl flex items-center justify-center">
                  <AlertTriangle className="w-6 h-6 text-white" />
                </div>
              </div>
            </div>

            <div className={`p-6 rounded-2xl ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-lg border ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Secure</p>
                  <p className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{secureServices}</p>
                </div>
                <div className="w-12 h-12 bg-gradient-to-r from-blue-500 to-blue-600 rounded-xl flex items-center justify-center">
                  <Shield className="w-6 h-6 text-white" />
                </div>
              </div>
            </div>

            <div className={`p-6 rounded-2xl ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-lg border ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Websites</p>
                  <p className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{statsByType.website}</p>
                </div>
                <div className="w-12 h-12 bg-gradient-to-r from-purple-500 to-purple-600 rounded-xl flex items-center justify-center">
                  <Globe className="w-6 h-6 text-white" />
                </div>
              </div>
            </div>

            <div className={`p-6 rounded-2xl ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-lg border ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Avg HTTP</p>
                  <p className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{avgLatency}ms</p>
                </div>
                <div className="w-12 h-12 bg-gradient-to-r from-yellow-500 to-yellow-600 rounded-xl flex items-center justify-center">
                  <Zap className="w-6 h-6 text-white" />
                </div>
              </div>
            </div>

            <div className={`p-6 rounded-2xl ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-lg border ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Avg Ping</p>
                  <p className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{avgPingLatency}ms</p>
                </div>
                <div className="w-12 h-12 bg-gradient-to-r from-indigo-500 to-indigo-600 rounded-xl flex items-center justify-center">
                  <TrendingUp className="w-6 h-6 text-white" />
                </div>
              </div>
            </div>
          </div>

          {/* Services Section */}
          <div className={`rounded-2xl ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-lg border ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                    Monitored Services ({services.length})
                  </h3>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    Real-time monitoring of your critical services
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <button 
                    onClick={handleRefresh}
                    className={`flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-all`}
                  >
                    <RotateCcw className="w-4 h-4" />
                    Refresh
                  </button>
                  <button 
                    onClick={() => setShowAddForm(!showAddForm)}
                    className={`flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-500 via-blue-600 to-blue-700 text-white rounded-lg hover:from-blue-600 hover:via-blue-700 hover:to-blue-800 transition-all shadow-lg hover:shadow-xl transform hover:scale-105`}
                  >
                    <Plus className="w-4 h-4" />
                    {showAddForm ? 'Close' : 'Add Service'}
                  </button>
                </div>
              </div>
            </div>

            <div className="p-6">
              {showAddForm && (
                <div className={`mb-6 p-6 rounded-xl border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-200'}`}>
                  <h4 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Add New Service</h4>
                  
                  <div className={`mb-4 p-4 rounded-lg ${darkMode ? 'bg-blue-900/20 border-blue-800' : 'bg-blue-50 border-blue-200'} border`}>
                    <div className="flex items-start gap-3">
                      <Info className="w-5 h-5 text-blue-600 dark:text-blue-400 mt-0.5" />
                      <div>
                        <h5 className={`font-medium mb-2 ${darkMode ? 'text-blue-400' : 'text-blue-800'}`}>Monitoring Types:</h5>
                        <ul className={`space-y-1 text-sm ${darkMode ? 'text-blue-300' : 'text-blue-700'}`}>
                          <li><strong>URLs:</strong> HTTP/HTTPS monitoring + ping (https://example.com)</li>
                          <li><strong>IP Addresses:</strong> Ping-only monitoring (192.168.1.1)</li>
                          <li><strong>Hostnames:</strong> Ping-only monitoring (router.local)</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                    <div>
                      <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                        Service Name
                      </label>
                      <input
                        type="text"
                        placeholder="My API Service"
                        value={newService.name}
                        onChange={(e) => setNewService({ ...newService, name: e.target.value })}
                        maxLength="100"
                        className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${darkMode ? 'bg-gray-800 border-gray-600 text-white placeholder-gray-400' : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'}`}
                      />
                    </div>
                    
                    <div>
                      <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                        Service URL/IP Address
                      </label>
                      <input
                        type="text"
                        placeholder="https://api.example.com or 192.168.1.1"
                        value={newService.url}
                        onChange={(e) => setNewService({ ...newService, url: e.target.value })}
                        maxLength="500"
                        className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${urlError ? 'border-red-500' : darkMode ? 'border-gray-600' : 'border-gray-300'} ${darkMode ? 'bg-gray-800 text-white placeholder-gray-400' : 'bg-white text-gray-900 placeholder-gray-500'}`}
                      />
                      {urlError && (
                        <p className="text-red-500 text-sm mt-1">{urlError}</p>
                      )}
                    </div>
                    
                    <div>
                      <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                        Service Type
                      </label>
                      <select
                        value={newService.type}
                        onChange={(e) => setNewService({ ...newService, type: e.target.value })}
                        className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${darkMode ? 'bg-gray-800 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900'}`}
                      >
                        <option value="website">Website/API</option>
                        <option value="server">Server</option>
                        <option value="misc">Network Equipment</option>
                      </select>
                    </div>
                  </div>

                  <div className="flex justify-end gap-3">
                    <button 
                      onClick={handleFormCancel}
                      disabled={isSubmitting}
                      className={`px-6 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-all ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}
                    >
                      Cancel
                    </button>
                    <button 
                      onClick={handleAddService}
                      disabled={isSubmitting || !newService.name.trim() || !newService.url.trim()}
                      className="flex items-center gap-2 px-6 py-2 bg-gradient-to-r from-blue-500 via-blue-600 to-blue-700 text-white rounded-lg hover:from-blue-600 hover:via-blue-700 hover:to-blue-800 transition-all shadow-lg hover:shadow-xl transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                    >
                      {isSubmitting ? (
                        <>
                          <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                          Adding...
                        </>
                      ) : (
                        <>
                          <Plus className="w-4 h-4" />
                          Add Service
                        </>
                      )}
                    </button>
                  </div>
                </div>
              )}

              {filteredServices.length > 0 ? (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {filteredServices.map((service) => {
                    const isSecure = service.url && service.url.startsWith('https://');
                    return (
                      <div 
                        key={service.id}
                        className={`group p-6 rounded-xl border ${darkMode ? 'bg-gray-700 border-gray-600 hover:border-gray-500' : 'bg-white border-gray-200 hover:border-gray-300'} hover:shadow-xl transition-all cursor-pointer transform hover:scale-105`}
                      >
                        <div className="flex items-start justify-between mb-4">
                          <div className="flex items-start gap-3">
                            <div className="w-12 h-12 bg-gradient-to-br from-blue-400 via-blue-500 to-blue-800 rounded-xl flex items-center justify-center shadow-lg group-hover:shadow-xl transition-shadow">
                              {getTypeIcon(service.type || 'website')}
                            </div>
                            <div>
                              <h4 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'} flex items-center gap-2`}>
                                {service.name || 'Unknown Service'}
                                {isSecure && <Lock className="w-4 h-4 text-green-500" title="Secure HTTPS connection" />}
                                {!isSecure && service.url && service.url.startsWith('http://') && 
                                  <Unlock className="w-4 h-4 text-yellow-500" title="Insecure HTTP connection" />
                                }
                              </h4>
                              <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'} mb-2`}>
                                {service.url || 'No URL'}
                              </p>
                              <div className="flex items-center gap-2">
                                <span className={`px-2 py-1 text-xs rounded-full ${darkMode ? 'bg-gray-600 text-gray-300' : 'bg-gray-100 text-gray-700'}`}>
                                  {getTypeLabel(service.type || 'website')}
                                </span>
                                {isSecure && (
                                  <span className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded-full dark:bg-green-900/20 dark:text-green-400">
                                    Secure
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {getStatusBadge(service.status)}
                            <button 
                              onClick={() => handleDelete(service.id, service.name)}
                              className={`p-2 rounded-lg ${darkMode ? 'hover:bg-gray-600' : 'hover:bg-gray-100'} opacity-0 group-hover:opacity-100 transition-opacity`}
                              title="Delete Service"
                            >
                              <Trash2 className="w-4 h-4 text-red-500" />
                            </button>
                          </div>
                        </div>

                        <div className="grid grid-cols-3 gap-4 text-center">
                          <div className={`border-r ${darkMode ? 'border-gray-600' : 'border-gray-200'}`}>
                            <div className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                              {service.url && !service.url.includes('://') ? 'N/A' : (service.latency || 0) + 'ms'}
                            </div>
                            <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>HTTP</div>
                          </div>
                          <div className={`border-r ${darkMode ? 'border-gray-600' : 'border-gray-200'}`}>
                            <div className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                              {service.ping_latency || 0}ms
                            </div>
                            <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Ping</div>
                          </div>
                          <div>
                            <div className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                              {formatLastChecked(service.last_checked)}
                            </div>
                            <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Last Check</div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="text-center py-12">
                  <div className="w-24 h-24 mx-auto mb-6 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center">
                    <Activity className="w-12 h-12 text-gray-500 dark:text-gray-400" />
                  </div>
                  <h4 className={`text-xl font-semibold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                    No services monitored yet
                  </h4>
                  <p className={`mb-6 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    Add your first service to start monitoring
                  </p>
                  <button 
                    onClick={() => setShowAddForm(true)}
                    className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-500 via-blue-600 to-blue-700 text-white rounded-lg hover:from-blue-600 hover:via-blue-700 hover:to-blue-800 transition-all shadow-lg hover:shadow-xl transform hover:scale-105 mx-auto"
                  >
                    <Plus className="w-4 h-4" />
                    Add Your First Service
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Latency Chart */}
          {filteredServices.length > 0 && (
            <div className={`mt-8 rounded-2xl ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-lg border ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
              <div className="p-6">
                <h4 className={`text-lg font-semibold mb-6 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  HTTP & Ping Latency Chart
                </h4>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#374151' : '#e5e7eb'} />
                    <XAxis 
                      dataKey="name" 
                      stroke={darkMode ? '#9ca3af' : '#6b7280'}
                      fontSize={12}
                    />
                    <YAxis 
                      stroke={darkMode ? '#9ca3af' : '#6b7280'}
                      fontSize={12}
                    />
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: darkMode ? '#374151' : '#ffffff',
                        border: darkMode ? '1px solid #6b7280' : '1px solid #e5e7eb',
                        borderRadius: '8px',
                        color: darkMode ? '#ffffff' : '#111827'
                      }}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="latency" 
                      stroke="#3b82f6" 
                      name="HTTP Latency (ms)" 
                      strokeWidth={3}
                      dot={{ fill: '#3b82f6', strokeWidth: 2, r: 6 }}
                      connectNulls={false}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="ping" 
                      stroke="#10b981" 
                      name="Ping Latency (ms)" 
                      strokeWidth={3}
                      dot={{ fill: '#10b981', strokeWidth: 2, r: 6 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </main>
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
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600 dark:text-gray-400">Loading VREXIS Insights...</p>
        </div>
      </div>
    );
  }

  return isAuthenticated() ? <ServiceMonitorDashboard /> : <AuthScreen />;
};

export default App;