// useServices.js - React hook for real-time service monitoring

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import apiService from './apiService';

export const useServices = (token) => {
  const [services, setServices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const pollCleanupRef = useRef(null);

  // Initialize API service with token
  useEffect(() => {
    if (token) {
      console.log('Setting API token');
      apiService.setTokens(token);
    }
  }, [token]);

  // Fetch services from API
  const fetchServices = useCallback(async () => {
    if (!token) {
      console.log('No token available, skipping fetch');
      setLoading(false);
      return;
    }

    try {
      setError(null);
      setConnectionStatus('connecting');
      
      console.log('Fetching services from backend...');
      const data = await apiService.getServices();
      console.log('Backend response:', data);
      
      // Handle different possible response formats from your Go backend
      let servicesArray = [];
      if (Array.isArray(data)) {
        servicesArray = data;
      } else if (data.services && Array.isArray(data.services)) {
        servicesArray = data.services;
      } else if (data.data && Array.isArray(data.data)) {
        servicesArray = data.data;
      } else if (data.message && !data.services) {
        // Backend might return {"message": "No services found"} for empty results
        console.log('No services found:', data.message);
        servicesArray = [];
      } else {
        console.warn('Unexpected services response format:', data);
        servicesArray = [];
      }
      
      setServices(servicesArray);
      setLastUpdated(new Date());
      setConnectionStatus('connected');
      console.log(`Loaded ${servicesArray.length} services`);
    } catch (err) {
      console.error('Failed to fetch services:', err);
      setError(err.message);
      setConnectionStatus('disconnected');
      
      // If we get specific authentication errors, don't show fallback data
      if (err.message.includes('Session expired') || err.message.includes('401')) {
        setServices([]);
        throw err; // Re-throw auth errors so they can be handled upstream
      }
      
      // Only use fallback for network/server errors
      if (err.message.includes('fetch') || err.message.includes('Network')) {
        console.log('Using fallback mock data due to network error');
        setServices([
          { 
            id: '1', 
            name: 'Demo Website (Offline)', 
            url: 'https://example.com', 
            type: 'website', 
            status: 'down', 
            latency: 0, 
            ping_latency: 0, 
            last_checked: new Date().toISOString(),
            enabled: true
          },
          { 
            id: '2', 
            name: 'Demo API (Network Error)', 
            url: 'https://api.example.com', 
            type: 'server', 
            status: 'down', 
            latency: 0, 
            ping_latency: 0, 
            last_checked: new Date().toISOString(),
            enabled: true
          }
        ]);
      }
    } finally {
      setLoading(false);
    }
  }, [token]);

  // Add new service
  const addService = useCallback(async (serviceData) => {
    try {
      console.log('Adding service via API:', serviceData);
      const newService = await apiService.addService(serviceData);
      
      // Add to local state
      setServices(prev => [...prev, newService]);
      return { success: true, service: newService };
    } catch (err) {
      console.error('Failed to add service:', err);
      return { success: false, error: err.message };
    }
  }, []);

  // Delete service
  const deleteService = useCallback(async (serviceId) => {
    try {
      console.log('Deleting service via API:', serviceId);
      await apiService.deleteService(serviceId);
      
      // Remove from local state
      setServices(prev => prev.filter(s => s.id !== serviceId));
      return { success: true };
    } catch (err) {
      console.error('Failed to delete service:', err);
      return { success: false, error: err.message };
    }
  }, []);

  // Update service
  const updateService = useCallback(async (serviceId, serviceData) => {
    try {
      console.log('Updating service via API:', serviceId, serviceData);
      const updatedService = await apiService.updateService(serviceId, serviceData);
      
      // Update in local state
      setServices(prev => prev.map(service => 
        service.id === serviceId ? updatedService : service
      ));
      return { success: true, service: updatedService };
    } catch (err) {
      console.error('Failed to update service:', err);
      return { success: false, error: err.message };
    }
  }, []);

  // Refresh all services (just re-fetch since backend doesn't have a refresh endpoint)
  const refreshServices = useCallback(async () => {
    try {
      console.log('Refreshing services...');
      await fetchServices();
      return { success: true };
    } catch (err) {
      console.error('Failed to refresh services:', err);
      return { success: false, error: err.message };
    }
  }, [fetchServices]);

  // Setup real-time updates with polling
  const startPolling = useCallback((interval = 30000) => {
    if (pollCleanupRef.current) {
      pollCleanupRef.current();
    }

    console.log(`Starting polling every ${interval}ms`);

    const poll = async () => {
      if (!token) return;
      
      try {
        const data = await apiService.getServices();
        
        // Handle response format
        let servicesArray = [];
        if (Array.isArray(data)) {
          servicesArray = data;
        } else if (data.services && Array.isArray(data.services)) {
          servicesArray = data.services;
        } else if (data.data && Array.isArray(data.data)) {
          servicesArray = data.data;
        }
        
        setServices(servicesArray);
        setLastUpdated(new Date());
        setConnectionStatus('connected');
      } catch (err) {
        console.error('Polling error:', err);
        setConnectionStatus('disconnected');
      }
    };

    // Start polling
    const pollInterval = setInterval(poll, interval);
    pollCleanupRef.current = () => {
      console.log('Stopping polling');
      clearInterval(pollInterval);
    };

    return pollCleanupRef.current;
  }, [token]);


  // Initialize data fetching and real-time updates
  useEffect(() => {
    if (!token) {
      console.log('No token, clearing services and stopping loading');
      setServices([]);
      setLoading(false);
      setConnectionStatus('disconnected');
      return;
    }

    console.log('Initializing services with token');
    
    // Initial fetch
    fetchServices();

    // Start polling for updates
    setTimeout(() => {
      startPolling();
    }, 1000);

    // Cleanup function
    return () => {
      console.log('Cleaning up services hook');
      if (pollCleanupRef.current) {
        pollCleanupRef.current();
      }
    };
  }, [token, fetchServices, startPolling]);

  // Computed statistics
  const stats = useMemo(() => {
    const upServices = services.filter(s => s.status === 'up').length;
    const downServices = services.filter(s => s.status === 'down').length;
    const secureServices = services.filter(s => s.url?.startsWith('https://')).length;
    
    const statsByType = services.reduce((acc, service) => {
      const type = service.type || 'website';
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, { website: 0, server: 0, misc: 0 });

    const upServicesWithLatency = services.filter(s => s.status === 'up' && s.latency > 0);
    const avgLatency = upServicesWithLatency.length > 0 
      ? Math.round(upServicesWithLatency.reduce((sum, s) => sum + s.latency, 0) / upServicesWithLatency.length)
      : 0;

    const servicesWithPing = services.filter(s => s.ping_latency > 0);
    const avgPingLatency = servicesWithPing.length > 0
      ? Math.round(servicesWithPing.reduce((sum, s) => sum + s.ping_latency, 0) / servicesWithPing.length)
      : 0;

    return {
      upServices,
      downServices,
      secureServices,
      totalServices: services.length,
      statsByType,
      avgLatency,
      avgPingLatency
    };
  }, [services]);

  return {
    services,
    loading,
    error,
    lastUpdated,
    connectionStatus,
    stats,
    addService,
    deleteService,
    updateService,
    refreshServices,
    refetch: fetchServices
  };
};

export default useServices;