// useAlerts.js - React hook for alert management
import { useState, useEffect, useCallback, useMemo } from 'react';
import alertService from './alertService';

export const useAlerts = (token) => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  // Fetch alerts from API
  const fetchAlerts = useCallback(async () => {
    if (!token) {
      setLoading(false);
      return;
    }

    try {
      setError(null);
      setLoading(true);
      
      const alertsData = await alertService.getAlerts();
      setAlerts(alertsData);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  // Create a new alert
  const createAlert = useCallback(async (alertData) => {
    try {
      const newAlert = await alertService.createAlert(alertData);
      setAlerts(prev => [...prev, newAlert]);
      return { success: true, alert: newAlert };
    } catch (err) {
      console.error('Failed to create alert:', err);
      return { success: false, error: err.message };
    }
  }, []);

  // Update an existing alert
  const updateAlert = useCallback(async (alertId, updates) => {
    try {
      const updatedAlert = await alertService.updateAlert(alertId, updates);
      setAlerts(prev => prev.map(alert => 
        alert.id === alertId ? updatedAlert : alert
      ));
      return { success: true, alert: updatedAlert };
    } catch (err) {
      console.error('Failed to update alert:', err);
      return { success: false, error: err.message };
    }
  }, []);

  // Delete an alert
  const deleteAlert = useCallback(async (alertId) => {
    try {
      await alertService.deleteAlert(alertId);
      setAlerts(prev => prev.filter(alert => alert.id !== alertId));
      return { success: true };
    } catch (err) {
      console.error('Failed to delete alert:', err);
      return { success: false, error: err.message };
    }
  }, []);

  // Toggle alert enabled/disabled
  const toggleAlert = useCallback(async (alertId, enabled) => {
    try {
      const updatedAlert = await alertService.toggleAlert(alertId, enabled);
      setAlerts(prev => prev.map(alert => 
        alert.id === alertId ? updatedAlert : alert
      ));
      return { success: true, alert: updatedAlert };
    } catch (err) {
      console.error('Failed to toggle alert:', err);
      return { success: false, error: err.message };
    }
  }, []);

  // Test an alert
  const testAlert = useCallback(async (alertId) => {
    try {
      await alertService.testAlert(alertId);
      return { success: true };
    } catch (err) {
      console.error('Failed to test alert:', err);
      return { success: false, error: err.message };
    }
  }, []);

  // Get alert trigger history
  const getAlertTriggerHistory = useCallback(async (alertId, limit = 50) => {
    try {
      return await alertService.getAlertTriggerHistory(alertId, limit);
    } catch (err) {
      console.error('Failed to fetch alert trigger history:', err);
      throw err;
    }
  }, []);

  // Refresh alerts
  const refreshAlerts = useCallback(async () => {
    await fetchAlerts();
  }, [fetchAlerts]);

  // Initialize alerts on mount
  useEffect(() => {
    if (token) {
      fetchAlerts();
    }
  }, [token, fetchAlerts]);

  // Computed alert statistics
  const alertStats = useMemo(() => {
    const total = alerts.length;
    const enabled = alerts.filter(a => a.enabled).length;
    const disabled = total - enabled;
    const critical = alerts.filter(a => a.severity === 'critical').length;
    const warning = alerts.filter(a => a.severity === 'warning').length;
    const info = alerts.filter(a => a.severity === 'info').length;
    
    // Recent triggers (last 24 hours)
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentTriggers = alerts.filter(a => 
      a.last_triggered && new Date(a.last_triggered) > oneDayAgo
    ).length;

    // Most triggered alert
    const mostTriggered = alerts.reduce((max, alert) => 
      alert.trigger_count > (max?.trigger_count || 0) ? alert : max, null
    );

    return {
      total,
      enabled,
      disabled,
      critical,
      warning,
      info,
      recentTriggers,
      mostTriggered
    };
  }, [alerts]);

  return {
    alerts,
    loading,
    error,
    lastUpdated,
    alertStats,
    createAlert,
    updateAlert,
    deleteAlert,
    toggleAlert,
    testAlert,
    getAlertTriggerHistory,
    refreshAlerts,
    refetch: fetchAlerts
  };
};

export const useNotificationSettings = (token) => {
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch notification settings
  const fetchSettings = useCallback(async () => {
    if (!token) {
      setLoading(false);
      return;
    }

    try {
      setError(null);
      setLoading(true);
      
      const settingsData = await alertService.getNotificationSettings();
      setSettings(settingsData);
    } catch (err) {
      console.error('Failed to fetch notification settings:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  // Update notification settings
  const updateSettings = useCallback(async (updates) => {
    try {
      const updatedSettings = await alertService.updateNotificationSettings(updates);
      setSettings(updatedSettings);
      return { success: true, settings: updatedSettings };
    } catch (err) {
      console.error('Failed to update notification settings:', err);
      return { success: false, error: err.message };
    }
  }, []);

  // Initialize settings on mount
  useEffect(() => {
    if (token) {
      fetchSettings();
    }
  }, [token, fetchSettings]);

  return {
    settings,
    loading,
    error,
    updateSettings,
    refreshSettings: fetchSettings
  };
};

// Hook for alert filtering and sorting
export const useAlertFilters = (alerts) => {
  const [filters, setFilters] = useState({
    search: '',
    enabled: 'all', // 'all', 'enabled', 'disabled'
    severity: 'all', // 'all', 'info', 'warning', 'critical'
    sortBy: 'created', // 'created', 'name', 'severity', 'lastTriggered'
    sortOrder: 'desc' // 'asc', 'desc'
  });

  // Apply filters and sorting
  const filteredAlerts = useMemo(() => {
    let filtered = [...alerts];

    // Search filter
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      filtered = filtered.filter(alert =>
        alert.name.toLowerCase().includes(searchLower) ||
        alert.description.toLowerCase().includes(searchLower)
      );
    }

    // Enabled filter
    if (filters.enabled !== 'all') {
      filtered = filtered.filter(alert =>
        filters.enabled === 'enabled' ? alert.enabled : !alert.enabled
      );
    }

    // Severity filter
    if (filters.severity !== 'all') {
      filtered = filtered.filter(alert => alert.severity === filters.severity);
    }

    // Sorting
    filtered.sort((a, b) => {
      let aVal, bVal;

      switch (filters.sortBy) {
        case 'name':
          aVal = a.name.toLowerCase();
          bVal = b.name.toLowerCase();
          break;
        case 'severity':
          const severityOrder = { critical: 3, warning: 2, info: 1 };
          aVal = severityOrder[a.severity] || 0;
          bVal = severityOrder[b.severity] || 0;
          break;
        case 'lastTriggered':
          aVal = a.last_triggered ? new Date(a.last_triggered).getTime() : 0;
          bVal = b.last_triggered ? new Date(b.last_triggered).getTime() : 0;
          break;
        case 'created':
        default:
          aVal = new Date(a.created).getTime();
          bVal = new Date(b.created).getTime();
          break;
      }

      if (filters.sortOrder === 'asc') {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });

    return filtered;
  }, [alerts, filters]);

  const updateFilters = useCallback((newFilters) => {
    setFilters(prev => ({ ...prev, ...newFilters }));
  }, []);

  const resetFilters = useCallback(() => {
    setFilters({
      search: '',
      enabled: 'all',
      severity: 'all',
      sortBy: 'created',
      sortOrder: 'desc'
    });
  }, []);

  return {
    filters,
    filteredAlerts,
    updateFilters,
    resetFilters
  };
};

export default useAlerts;