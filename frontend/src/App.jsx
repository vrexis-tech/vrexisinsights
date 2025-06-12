import React, { useState, useEffect, createContext, useContext } from 'react';
import './App.css';
import { CheckCircle, AlertCircle, Monitor, TrendingUp, Bell, RefreshCw, Trash2, Plus, Edit3 } from 'lucide-react';

const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => JSON.parse(localStorage.getItem('user')));
  const [users, setUsers] = useState(() => JSON.parse(localStorage.getItem('users')) || []);

  const login = (email, password) => {
    const found = users.find(u => u.email === email && u.password === password);
    if (found) {
      setUser(found);
      localStorage.setItem('user', JSON.stringify(found));
      return true;
    }
    return false;
  };

  const register = (name, email, password) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email) || password.length < 8 || users.find(u => u.email === email)) return false;
    const newUser = { name, email, password, role: users.length === 0 ? 'admin' : 'user' };
    const updatedUsers = [...users, newUser];
    setUsers(updatedUsers);
    localStorage.setItem('users', JSON.stringify(updatedUsers));
    setUser(newUser);
    localStorage.setItem('user', JSON.stringify(newUser));
    return true;
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('user');
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, register }}>
      {children}
    </AuthContext.Provider>
  );
};

const DashboardStats = ({ services }) => {
  const upCount = services.filter(s => s.status === 'up').length;
  const avgUptime = `${(upCount / services.length * 100).toFixed(1)}%`;
  const avgLatency = `${Math.floor(Math.random() * 100) + 50}ms`;
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      <div className="bg-gray-800 p-4 rounded-lg shadow flex items-center gap-4">
        <Monitor className="text-blue-400" />
        <div>
          <p className="text-sm text-gray-400">Total Services</p>
          <p className="text-xl font-semibold">{services.length}</p>
        </div>
      </div>
      <div className="bg-gray-800 p-4 rounded-lg shadow flex items-center gap-4">
        <CheckCircle className="text-green-400" />
        <div>
          <p className="text-sm text-gray-400">Services Up</p>
          <p className="text-xl font-semibold">{upCount}</p>
        </div>
      </div>
      <div className="bg-gray-800 p-4 rounded-lg shadow flex items-center gap-4">
        <TrendingUp className="text-purple-400" />
        <div>
          <p className="text-sm text-gray-400">Avg Uptime</p>
          <p className="text-xl font-semibold">{avgUptime}</p>
        </div>
      </div>
      <div className="bg-gray-800 p-4 rounded-lg shadow flex items-center gap-4">
        <Bell className="text-yellow-400" />
        <div>
          <p className="text-sm text-gray-400">Avg Latency</p>
          <p className="text-xl font-semibold">{avgLatency}</p>
        </div>
      </div>
    </div>
  );
};

const Dashboard = () => {
  const { user, logout } = useAuth();
  const [services, setServices] = useState(() => JSON.parse(localStorage.getItem('services')) || []);
  const [newService, setNewService] = useState({ name: '', url: '' });
  const isPersonalTier = user.role === 'user' && services.length >= 5;

  const handleAdd = () => {
    if (!newService.name || !newService.url || isPersonalTier) return;
    const updated = [...services, { ...newService, id: Date.now(), status: 'checking' }];
    setServices(updated);
    localStorage.setItem('services', JSON.stringify(updated));
    setNewService({ name: '', url: '' });
  };

  useEffect(() => {
    const checkStatus = async () => {
      const updated = await Promise.all(
        services.map(async service => {
          try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 3000);

            await fetch(service.url.startsWith('http') ? service.url : `http://${service.url}`, {
              method: 'GET',
              signal: controller.signal,
              mode: 'no-cors'
            });

            clearTimeout(timeout);
            return { ...service, status: 'up' };
          } catch {
            return { ...service, status: 'down' };
          }
        })
      );
      setServices(updated);
      localStorage.setItem('services', JSON.stringify(updated));
    };
    checkStatus();
    const interval = setInterval(checkStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">🔒 Vrexis Insights - Personal</h1>
        <button onClick={logout} className="btn-danger">Logout</button>
      </div>
      <DashboardStats services={services} />
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
        {services.map(service => (
          <div key={service.id} className="bg-gray-800 p-4 rounded-lg shadow">
            <div className="flex justify-between items-center">
              <div>
                <h2 className="text-lg font-semibold">{service.name}</h2>
                <p className="text-sm text-gray-400">{service.url}</p>
              </div>
              <span className={`badge ${service.status === 'up' ? 'badge-success' : 'badge-danger'}`}>{service.status.toUpperCase()}</span>
            </div>
          </div>
        ))}
      </div>
      <div className="bg-gray-800 p-4 rounded-lg shadow">
        <h2 className="text-lg font-semibold mb-2">Add New Service</h2>
        <div className="flex flex-col sm:flex-row gap-2">
          <input type="text" className="form-input" placeholder="Name" value={newService.name} onChange={e => setNewService({ ...newService, name: e.target.value })} />
          <input type="text" className="form-input" placeholder="URL or IP" value={newService.url} onChange={e => setNewService({ ...newService, url: e.target.value })} />
          <button onClick={handleAdd} className="btn-primary" disabled={isPersonalTier}>Add</button>
        </div>
        {isPersonalTier && <p className="text-red-400 mt-2 text-sm">Personal tier allows up to 5 services.</p>}
      </div>
    </div>
  );
};

const AuthScreen = () => {
  const { login, register } = useAuth();
  const [isRegister, setIsRegister] = useState(false);
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const handleSubmit = (e) => {
    e.preventDefault();
    const success = isRegister ? register(form.name, form.email, form.password) : login(form.email, form.password);
    if (!success) alert('Failed to authenticate. Check credentials or try registering.');
  };
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 text-white">
      <form onSubmit={handleSubmit} className="bg-gray-800 p-8 rounded-lg shadow-md space-y-4 w-full max-w-sm">
        <h1 className="text-xl font-bold">{isRegister ? 'Create Account' : 'Sign In'}</h1>
        {isRegister && (
          <input type="text" className="form-input" placeholder="Name" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
        )}
        <input type="email" className="form-input" placeholder="Email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} required />
        <input type="password" className="form-input" placeholder="Password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} required />
        <button type="submit" className="btn-primary w-full">{isRegister ? 'Register' : 'Login'}</button>
        <p className="text-sm text-gray-400 text-center">
          {isRegister ? 'Already have an account?' : 'New here?'}{' '}
          <button type="button" className="text-blue-400 underline" onClick={() => setIsRegister(!isRegister)}>
            {isRegister ? 'Sign in' : 'Create one'}
          </button>
        </p>
      </form>
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
