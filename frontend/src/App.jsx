import React, { useState, useEffect, createContext, useContext } from 'react';
import { 
  CheckCircle, 
  AlertCircle, 
  Monitor, 
  TrendingUp, 
  Bell, 
  RefreshCw, 
  Trash2, 
  Plus, 
  BarChart3,
  AlertTriangle,
  Clock,
  X,
  Settings,
  Mail,
  MailOff,
  Save
} from 'lucide-react';

// API Configuration
const API_BASE_URL = 'http://localhost:8080';

// API Helper Functions
const apiCall = async (endpoint, options = {}) => {
  const token = localStorage.getItem('token');
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options.headers,
    },
    ...options,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Network error' }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }

  return response.json();
};

const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    return token && savedUser ? JSON.parse(savedUser) : null;
  });

  const login = async (email, password) => {
    try {
      const response = await apiCall('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      
      setUser(response.user);
      localStorage.setItem('token', response.token);
      localStorage.setItem('user', JSON.stringify(response.user));
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const register = async (first_name, last_name, email, password) => {
    try {
      const response = await apiCall('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ first_name, last_name, email, password }),
      });
      
      setUser(response.user);
      localStorage.setItem('token', response.token);
      localStorage.setItem('user', JSON.stringify(response.user));
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const updateEmailNotifications = async (emailNotifications) => {
    try {
      const response = await apiCall('/api/v1/user/email-notifications', {
        method: 'PUT',
        body: JSON.stringify({ email_notifications: emailNotifications }),
      });
      
      setUser(response);
      localStorage.setItem('user', JSON.stringify(response));
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, register, updateEmailNotifications }}>
      {children}
    </AuthContext.Provider>
  );
};

const SettingsModal = ({ isOpen, onClose }) => {
  const { user, updateEmailNotifications } = useAuth();
  const [emailNotifications, setEmailNotifications] = useState(user?.email_notifications || false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    if (user) {
      setEmailNotifications(user.email_notifications || false);
    }
  }, [user]);

  const handleSave = async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    const result = await updateEmailNotifications(emailNotifications);
    
    if (result.success) {
      setSuccess('Settings updated successfully!');
      setTimeout(() => setSuccess(''), 3000);
    } else {
      setError(result.error);
    }
    
    setLoading(false);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-md">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-white">Settings</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && (
          <div className="bg-red-900 border border-red-600 text-red-200 px-4 py-3 rounded-lg text-sm mb-4">
            {error}
          </div>
        )}

        {success && (
          <div className="bg-green-900 border border-green-600 text-green-200 px-4 py-3 rounded-lg text-sm mb-4">
            {success}
          </div>
        )}

        <div className="space-y-6">
          {/* User Info */}
          <div className="bg-slate-900 rounded-lg p-4">
            <h3 className="text-slate-300 text-sm font-medium mb-2">Account Information</h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">Name</span>
                <span className="text-white">{user?.first_name} {user?.last_name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Email</span>
                <span className="text-white">{user?.email}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Plan</span>
                <span className="text-purple-400">Free Tier</span>
              </div>
            </div>
          </div>

          {/* Email Notifications */}
          <div className="space-y-4">
            <h3 className="text-slate-300 text-sm font-medium">Notification Preferences</h3>
            
            <div className="flex items-center justify-between p-4 bg-slate-900 rounded-lg">
              <div className="flex items-center gap-3">
                {emailNotifications ? (
                  <Mail className="w-5 h-5 text-green-400" />
                ) : (
                  <MailOff className="w-5 h-5 text-slate-500" />
                )}
                <div>
                  <p className="text-white font-medium">Email Notifications</p>
                  <p className="text-slate-400 text-sm">
                    Get notified when your services go down or come back up
                  </p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={emailNotifications}
                  onChange={(e) => setEmailNotifications(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
              </label>
            </div>

            {emailNotifications && (
              <div className="bg-purple-900/20 border border-purple-600/30 rounded-lg p-3">
                <p className="text-purple-200 text-sm">
                  ✉️ You'll receive email alerts when your services go down or are restored.
                </p>
              </div>
            )}
          </div>

          {/* Plan Information */}
          <div className="bg-slate-900 rounded-lg p-4">
            <h3 className="text-slate-300 text-sm font-medium mb-2">Free Tier Includes</h3>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-slate-300">Monitor up to 5 services</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-slate-300">Real-time dashboard</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-slate-300">Email notifications</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-slate-300">24-hour data retention</span>
              </div>
            </div>
          </div>
        </div>

        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 text-slate-300 hover:text-white border border-slate-600 hover:border-slate-500 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={loading}
            className="flex-1 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {loading ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>
    </div>
  );
};

const Sidebar = ({ activeTab, setActiveTab, services, onDeleteService }) => {
  const { user, logout } = useAuth();
  const [showSettings, setShowSettings] = useState(false);
  
  const getStatusIcon = (status) => {
    switch (status) {
      case 'up': return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'down': return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'checking': return <Clock className="w-4 h-4 text-yellow-400" />;
      default: return <AlertCircle className="w-4 h-4 text-gray-400" />;
    }
  };

  const getUptimePercentage = (status) => {
    switch (status) {
      case 'up': return (Math.random() * 2 + 98).toFixed(1);
      case 'down': return (Math.random() * 20 + 80).toFixed(1);
      default: return '--';
    }
  };

  const alertCount = services.filter(s => s.status === 'down').length;
  const servicesUp = services.filter(s => s.status === 'up').length;
  const avgUptime = services.length > 0 ? (servicesUp / services.length * 100).toFixed(1) : 0;
  const avgResponse = services.length > 0 ? Math.round(services.reduce((acc, s) => acc + (s.latency || 0), 0) / services.length) : 0;

  return (
    <>
      <div className="w-80 bg-slate-900 border-r border-slate-800 flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-8 h-8 bg-purple-600 rounded-lg flex items-center justify-center">
              <Monitor className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-white font-semibold">VREXIS Insights</h1>
              <p className="text-slate-400 text-sm">Service monitoring dashboard</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            <span className="text-green-400">Free Tier</span>
            {user?.email_notifications && (
              <>
                <div className="w-2 h-2 bg-purple-400 rounded-full ml-2"></div>
                <span className="text-purple-400 flex items-center gap-1">
                  <Mail className="w-3 h-3" />
                  Alerts ON
                </span>
              </>
            )}
          </div>
        </div>

        {/* Navigation */}
        <div className="flex-1 p-4">
          <nav className="space-y-2 mb-8">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left transition-colors ${
                activeTab === 'dashboard'
                  ? 'bg-purple-600 text-white'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <BarChart3 className="w-5 h-5" />
              Dashboard
            </button>
            
            <button
              onClick={() => setActiveTab('services')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left transition-colors ${
                activeTab === 'services'
                  ? 'bg-purple-600 text-white'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Monitor className="w-5 h-5" />
              All Services
            </button>
            
            <button
              onClick={() => setActiveTab('alerts')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left transition-colors ${
                activeTab === 'alerts'
                  ? 'bg-purple-600 text-white'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Bell className="w-5 h-5" />
              Alerts
              {alertCount > 0 && (
                <span className="ml-auto bg-red-500 text-white text-xs w-5 h-5 rounded-full flex items-center justify-center">
                  {alertCount}
                </span>
              )}
            </button>
          </nav>

          {/* Your Services */}
          <div className="mb-8">
            <h3 className="text-slate-400 text-sm font-medium mb-3 uppercase tracking-wide">Your Services</h3>
            <div className="space-y-2">
              {services.slice(0, 5).map((service) => (
                <div key={service.id} className="group flex items-center gap-3 p-2 rounded-lg hover:bg-slate-800 transition-colors">
                  {getStatusIcon(service.status)}
                  <div className="flex-1 min-w-0">
                    <p className="text-slate-300 text-sm font-medium truncate">{service.name}</p>
                    <p className="text-slate-500 text-xs">{getUptimePercentage(service.status)}% uptime</p>
                  </div>
                  <button
                    onClick={() => onDeleteService(service.id)}
                    className="opacity-0 group-hover:opacity-100 text-slate-400 hover:text-red-400 transition-all"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* System Status */}
          <div className="bg-slate-800 rounded-lg p-4">
            <h3 className="text-slate-400 text-sm font-medium mb-3">System Status</h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">Services Up</span>
                <span className="text-white">{servicesUp}/{services.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Avg Uptime</span>
                <span className="text-purple-400">{avgUptime}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Avg Response</span>
                <span className="text-slate-300">{avgResponse}ms</span>
              </div>
            </div>
          </div>
        </div>

        {/* User Menu */}
        <div className="p-4 border-t border-slate-800">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-8 h-8 bg-purple-600 rounded-full flex items-center justify-center text-white text-sm font-medium">
              {user?.first_name?.[0]}{user?.last_name?.[0]}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-slate-300 text-sm font-medium">{user?.first_name} {user?.last_name}</p>
              <p className="text-slate-500 text-xs truncate">{user?.email}</p>
            </div>
            <button 
              onClick={() => setShowSettings(true)}
              className="text-slate-400 hover:text-white"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>
          <button
            onClick={logout}
            className="w-full px-3 py-2 text-sm text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            Sign out
          </button>
        </div>
      </div>

      <SettingsModal isOpen={showSettings} onClose={() => setShowSettings(false)} />
    </>
  );
};

const StatsCard = ({ title, value, icon: Icon, color = "blue", change }) => (
  <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
    <div className="flex items-center justify-between mb-4">
      <h3 className="text-slate-400 text-sm font-medium">{title}</h3>
      <Icon className={`w-6 h-6 text-${color}-400`} />
    </div>
    <div className="flex items-end justify-between">
      <div>
        <p className="text-3xl font-bold text-white mb-1">{value}</p>
        {change && (
          <p className="text-slate-400 text-sm">{change}</p>
        )}
      </div>
    </div>
  </div>
);

const ServiceOverview = ({ services, onDeleteService }) => {
  const getStatusIndicator = (status) => {
    switch (status) {
      case 'up':
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      case 'down':
        return <AlertTriangle className="w-5 h-5 text-red-400" />;
      case 'checking':
        return <Clock className="w-5 h-5 text-yellow-400" />;
      default:
        return <AlertCircle className="w-5 h-5 text-gray-400" />;
    }
  };

  const getServiceType = (service) => {
    // Use the actual service type from the database
    switch (service.type) {
      case 'website': return { name: 'website', icon: '🌐' };
      case 'server': return { name: 'server', icon: '🖥️' };
      case 'iot': return { name: 'iot', icon: '📱' };
      default: return { name: 'website', icon: '🌐' };
    }
  };

  const getUptimePercentage = (status) => {
    switch (status) {
      case 'up': return (Math.random() * 2 + 98).toFixed(1);
      case 'down': return (Math.random() * 20 + 85).toFixed(1);
      case 'checking': return '--';
      default: return '--';
    }
  };

  return (
    <div className="space-y-4">
      {services.length === 0 ? (
        <div className="text-center py-12">
          <Monitor className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-300 mb-2">No services configured</h3>
          <p className="text-slate-500">Add your first service to start monitoring</p>
        </div>
      ) : (
        services.map((service) => (
          <div key={service.id} className="group bg-slate-800 border border-slate-700 rounded-xl p-6 hover:border-slate-600 transition-colors">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                {getStatusIndicator(service.status)}
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="text-lg font-semibold text-white">{service.name}</h3>
                    <span className="px-2 py-1 bg-slate-700 text-slate-300 text-xs rounded-full flex items-center gap-1">
                      <span>{getServiceType(service).icon}</span>
                      {getServiceType(service).name}
                    </span>
                  </div>
                  <p className="text-slate-400 text-sm">{service.url}</p>
                </div>
              </div>
              <div className="flex items-center gap-6">
                <div className="text-right">
                  <p className="text-2xl font-bold text-white">{getUptimePercentage(service.status)}%</p>
                  <p className="text-slate-400 text-sm">
                    {service.latency > 0 ? `${service.latency}ms avg` : '0ms avg'}
                  </p>
                </div>
                <button
                  onClick={() => onDeleteService(service.id)}
                  className="opacity-0 group-hover:opacity-100 text-slate-400 hover:text-red-400 transition-all p-2 hover:bg-slate-700 rounded-lg"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  );
};

const AddServiceModal = ({ isOpen, onClose, onAdd, isLoading }) => {
  const [formData, setFormData] = useState({ 
    name: '', 
    address: '', 
    type: 'website',
    port: ''
  });

  const serviceTypes = [
    {
      id: 'website',
      name: 'Website',
      description: 'Monitor web applications and websites',
      icon: '🌐',
      placeholder: 'https://example.com',
      supportsPorts: false
    },
    {
      id: 'server',
      name: 'Server',
      description: 'Monitor servers and APIs via HTTP/HTTPS',
      icon: '🖥️',
      placeholder: '192.168.1.100 or server.local',
      supportsPorts: true
    },
    {
      id: 'iot',
      name: 'IoT Device',
      description: 'Monitor IoT devices on local network',
      icon: '📱',
      placeholder: '192.168.1.50 or device.local',
      supportsPorts: true
    }
  ];

  const selectedType = serviceTypes.find(t => t.id === formData.type);

  const validateAddress = () => {
    const { address, type } = formData;
    if (!address.trim()) return false;

    if (type === 'website') {
      // Must be a valid URL for websites
      return address.startsWith('http://') || address.startsWith('https://');
    } else {
      // For servers and IoT, accept IP addresses or hostnames
      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
      
      return ipRegex.test(address) || hostnameRegex.test(address);
    }
  };

  const handleSubmit = async () => {
    if (!formData.name.trim() || !validateAddress()) return;
    
    let finalAddress = formData.address.trim();
    
    // For non-website types, add protocol and port if needed
    if (formData.type !== 'website') {
      if (!finalAddress.startsWith('http://') && !finalAddress.startsWith('https://')) {
        finalAddress = 'http://' + finalAddress;
      }
      if (formData.port && !finalAddress.includes(':')) {
        finalAddress += ':' + formData.port;
      }
    }
    
    const success = await onAdd(formData.name.trim(), finalAddress, formData.type);
    if (success) {
      setFormData({ name: '', address: '', type: 'website', port: '' });
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-lg">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-white">Add New Service</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <div className="space-y-6">
          {/* Service Type Selection */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-3">Service Type</label>
            <div className="grid grid-cols-1 gap-3">
              {serviceTypes.map((type) => (
                <label
                  key={type.id}
                  className={`relative flex items-center p-4 border-2 rounded-lg cursor-pointer transition-colors ${
                    formData.type === type.id
                      ? 'border-purple-500 bg-purple-500/10'
                      : 'border-slate-600 hover:border-slate-500'
                  }`}
                >
                  <input
                    type="radio"
                    name="serviceType"
                    value={type.id}
                    checked={formData.type === type.id}
                    onChange={(e) => setFormData({ ...formData, type: e.target.value, port: '' })}
                    className="sr-only"
                  />
                  <div className="flex items-center gap-3 flex-1">
                    <span className="text-2xl">{type.icon}</span>
                    <div>
                      <div className="font-medium text-white">{type.name}</div>
                      <div className="text-sm text-slate-400">{type.description}</div>
                    </div>
                  </div>
                  {formData.type === type.id && (
                    <CheckCircle className="w-5 h-5 text-purple-400" />
                  )}
                </label>
              ))}
            </div>
          </div>

          {/* Service Details */}
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Service Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder={`e.g., ${selectedType?.name === 'Website' ? 'Main Website' : selectedType?.name === 'Server' ? 'Production Server' : 'Smart Thermostat'}`}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-purple-500"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                {formData.type === 'website' ? 'Website URL' : 'IP Address or Hostname'}
              </label>
              <input
                type="text"
                value={formData.address}
                onChange={(e) => setFormData({ ...formData, address: e.target.value })}
                placeholder={selectedType?.placeholder}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-purple-500"
              />
              {formData.type !== 'website' && (
                <p className="text-xs text-slate-400 mt-1">
                  Enter IP address (192.168.1.100) or hostname (server.local)
                </p>
              )}
            </div>

            {/* Port field for servers and IoT devices */}
            {selectedType?.supportsPorts && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Port (Optional)</label>
                <input
                  type="number"
                  value={formData.port}
                  onChange={(e) => setFormData({ ...formData, port: e.target.value })}
                  placeholder="80, 443, 8080, etc."
                  min="1"
                  max="65535"
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-purple-500"
                />
                <p className="text-xs text-slate-400 mt-1">
                  Default: 80 for HTTP, 443 for HTTPS
                </p>
              </div>
            )}
          </div>

          {/* Preview */}
          {formData.name && formData.address && (
            <div className="bg-slate-900 border border-slate-600 rounded-lg p-3">
              <p className="text-xs text-slate-400 mb-1">Preview:</p>
              <p className="text-white font-medium">{formData.name}</p>
              <p className="text-slate-300 text-sm">
                {formData.type === 'website' 
                  ? formData.address 
                  : `${formData.address}${formData.port ? ':' + formData.port : ''}`
                }
              </p>
            </div>
          )}
        </div>
        
        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 text-slate-300 hover:text-white border border-slate-600 hover:border-slate-500 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={isLoading || !formData.name.trim() || !validateAddress()}
            className="flex-1 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
          >
            {isLoading ? 'Adding...' : 'Add Service'}
          </button>
        </div>
      </div>
    </div>
  );
};

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [services, setServices] = useState([]);
  const [stats, setStats] = useState({
    total_services: 0,
    services_up: 0,
    services_down: 0,
    avg_uptime: 0,
    avg_latency: 0
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [addingService, setAddingService] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  const fetchServices = async () => {
    try {
      const data = await apiCall('/api/v1/services');
      setServices(data || []);
      setError('');
    } catch (err) {
      setError('Failed to fetch services: ' + err.message);
      console.error('Error fetching services:', err);
    }
  };

  const fetchStats = async () => {
    try {
      const data = await apiCall('/api/v1/services/stats');
      setStats(data);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Error fetching stats:', err);
    }
  };

  const handleAddService = async (name, address, type) => {
    setAddingService(true);
    try {
      const created = await apiCall('/api/v1/services', {
        method: 'POST',
        body: JSON.stringify({ name, url: address, type }),
      });
      
      setServices(prev => [created, ...prev]);
      setError('');
      await fetchStats();
      return true;
    } catch (err) {
      setError(err.message);
      return false;
    } finally {
      setAddingService(false);
    }
  };

  const handleDeleteService = async (serviceId) => {
    if (!confirm('Are you sure you want to delete this service?')) return;

    try {
      await apiCall(`/api/v1/services/${serviceId}`, { method: 'DELETE' });
      setServices(prev => prev.filter(s => s.id !== serviceId));
      setError('');
      await fetchStats();
    } catch (err) {
      setError('Failed to delete service: ' + err.message);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await Promise.all([fetchServices(), fetchStats()]);
    setRefreshing(false);
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([fetchServices(), fetchStats()]);
      setLoading(false);
    };

    loadData();

    const interval = setInterval(() => {
      fetchServices();
      fetchStats();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  const formatTime = (date) => {
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit',
      hour12: true 
    });
  };

  const alertCount = services.filter(s => s.status === 'down').length;

  return (
    <div className="min-h-screen bg-slate-950 text-white flex">
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        services={services}
        onDeleteService={handleDeleteService}
      />
      
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <header className="bg-slate-900 border-b border-slate-800 px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white capitalize">{activeTab}</h1>
              <p className="text-slate-400 text-sm">Last updated: {formatTime(lastUpdated)}</p>
            </div>
            <div className="flex items-center gap-3">
              {activeTab === 'services' && (
                <button
                  onClick={() => setShowAddModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  Add Service
                </button>
              )}
              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-white rounded-lg transition-colors"
              >
                <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="flex-1 p-8">
          {error && (
            <div className="bg-red-900 border border-red-600 text-red-200 px-4 py-3 rounded-lg mb-6">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-5 h-5" />
                {error}
              </div>
            </div>
          )}

          {activeTab === 'dashboard' && (
            <div className="space-y-8">
              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatsCard
                  title="Total Services"
                  value={stats.total_services}
                  icon={Monitor}
                  color="blue"
                />
                <StatsCard
                  title="Services Up"
                  value={stats.services_up}
                  icon={CheckCircle}
                  color="green"
                />
                <StatsCard
                  title="Avg Uptime"
                  value={`${stats.avg_uptime.toFixed(1)}%`}
                  icon={TrendingUp}
                  color="purple"
                />
                <StatsCard
                  title="Active Alerts"
                  value={alertCount}
                  icon={Bell}
                  color="yellow"
                />
              </div>

              {/* Services Overview */}
              <div>
                <h2 className="text-xl font-semibold text-white mb-6">Services Overview</h2>
                <ServiceOverview services={services} onDeleteService={handleDeleteService} />
              </div>
            </div>
          )}

          {activeTab === 'services' && (
            <div>
              <ServiceOverview services={services} onDeleteService={handleDeleteService} />
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="space-y-6">
              {alertCount === 0 ? (
                <div className="text-center py-12">
                  <Bell className="w-12 h-12 text-slate-600 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-slate-300 mb-2">No active alerts</h3>
                  <p className="text-slate-500">All services are running normally</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {services.filter(s => s.status === 'down').map((service) => (
                    <div key={service.id} className="bg-red-900 border border-red-600 rounded-xl p-6">
                      <div className="flex items-center gap-4">
                        <AlertTriangle className="w-6 h-6 text-red-400" />
                        <div>
                          <h3 className="text-lg font-semibold text-white">{service.name} is down</h3>
                          <p className="text-red-200">{service.url}</p>
                          <p className="text-red-300 text-sm mt-1">
                            Last checked: {service.last_checked ? new Date(service.last_checked).toLocaleString() : 'Never'}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </main>
      </div>

      <AddServiceModal
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        onAdd={handleAddService}
        isLoading={addingService}
      />
    </div>
  );
};

const AuthScreen = () => {
  const { login, register } = useAuth();
  const [isRegister, setIsRegister] = useState(false);
  const [form, setForm] = useState({ first_name: '', last_name: '', email: '', password: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async () => {
    setLoading(true);
    setError('');

    if (!form.email.trim() || !form.password.trim()) {
      setError('Email and password are required');
      setLoading(false);
      return;
    }

    if (isRegister && (!form.first_name.trim() || !form.last_name.trim())) {
      setError('First name and last name are required');
      setLoading(false);
      return;
    }

    const result = isRegister 
      ? await register(form.first_name, form.last_name, form.email, form.password)
      : await login(form.email, form.password);

    if (!result.success) {
      setError(result.error);
    }
    setLoading(false);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSubmit();
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 text-white">
      <div className="bg-slate-900 border border-slate-800 p-8 rounded-xl shadow-xl w-full max-w-md">
        <div className="text-center mb-8">
          <div className="w-12 h-12 bg-purple-600 rounded-xl flex items-center justify-center mx-auto mb-4">
            <Monitor className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white mb-2">VREXIS Insights</h1>
          <p className="text-slate-400">{isRegister ? 'Create your account' : 'Sign in to continue'}</p>
        </div>

        {error && (
          <div className="bg-red-900 border border-red-600 text-red-200 px-4 py-3 rounded-lg text-sm mb-6">
            {error}
          </div>
        )}

        <div className="space-y-4">
          {isRegister && (
            <div className="grid grid-cols-2 gap-3">
              <input 
                type="text" 
                placeholder="First name" 
                value={form.first_name} 
                onChange={e => setForm({ ...form, first_name: e.target.value })} 
                onKeyPress={handleKeyPress}
                className="px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-purple-500"
              />
              <input 
                type="text" 
                placeholder="Last name" 
                value={form.last_name} 
                onChange={e => setForm({ ...form, last_name: e.target.value })} 
                onKeyPress={handleKeyPress}
                className="px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-purple-500"
              />
            </div>
          )}

          <input 
            type="email" 
            placeholder="Email" 
            value={form.email} 
            onChange={e => setForm({ ...form, email: e.target.value })} 
            onKeyPress={handleKeyPress}
            className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-purple-500"
          />
          
          <input 
            type="password" 
            placeholder="Password" 
            value={form.password} 
            onChange={e => setForm({ ...form, password: e.target.value })} 
            onKeyPress={handleKeyPress}
            className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-purple-500"
          />

          <button 
            onClick={handleSubmit}
            disabled={loading}
            className="w-full px-4 py-3 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors font-medium"
          >
            {loading ? 'Please wait...' : (isRegister ? 'Create Account' : 'Sign In')}
          </button>
        </div>

        <p className="text-sm text-slate-400 text-center mt-6">
          {isRegister ? 'Already have an account?' : 'New to VREXIS Insights?'}{' '}
          <button 
            className="text-purple-400 hover:text-purple-300 underline" 
            onClick={() => {
              setIsRegister(!isRegister);
              setError('');
              setForm({ first_name: '', last_name: '', email: '', password: '' });
            }}
          >
            {isRegister ? 'Sign in' : 'Create account'}
          </button>
        </p>
      </div>
    </div>
  );
};

const App = () => {
  const { user } = useAuth();
  return user ? <Dashboard /> : <AuthScreen />;
};

export default () => (
  <AuthProvider>
    <App />
  </AuthProvider>
);