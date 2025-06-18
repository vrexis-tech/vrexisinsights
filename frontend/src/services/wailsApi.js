// frontend/src/services/wailsApi.js
// This replaces your HTTP API calls with direct Wails context calls

import { 
  GetServices, 
  AddService, 
  DeleteService, 
  GetServiceStats,
  IsDesktopMode,
  GetAPIEndpoint 
} from '../../wailsjs/go/main/App'

import { useState, useEffect, useCallback } from 'react'

// Service Management
export const apiService = {
  // Get all services
  async getServices() {
    try {
      const services = await GetServices()
      return { data: services, error: null }
    } catch (error) {
      console.error('Failed to fetch services:', error)
      return { data: [], error: error.message }
    }
  },

  // Add a new service
  async addService(serviceData) {
    try {
      const { name, url, type = 'website' } = serviceData
      const service = await AddService(name, url, type)
      return { data: service, error: null }
    } catch (error) {
      console.error('Failed to add service:', error)
      return { data: null, error: error.message }
    }
  },

  // Delete a service
  async deleteService(serviceId) {
    try {
      await DeleteService(serviceId)
      return { success: true, error: null }
    } catch (error) {
      console.error('Failed to delete service:', error)
      return { success: false, error: error.message }
    }
  },

  // Get service statistics
  async getServiceStats() {
    try {
      const stats = await GetServiceStats()
      return { data: stats, error: null }
    } catch (error) {
      console.error('Failed to fetch service stats:', error)
      return { 
        data: {
          total_services: 0,
          services_up: 0,
          services_down: 0,
          avg_uptime: 0,
          avg_latency: 0
        }, 
        error: error.message 
      }
    }
  },

  // Check if running in desktop mode
  async isDesktopMode() {
    try {
      return await IsDesktopMode()
    } catch (error) {
      console.error('Failed to check desktop mode:', error)
      return true // Default to desktop mode
    }
  },

  // Get API endpoint (for any legacy HTTP calls if needed)
  async getAPIEndpoint() {
    try {
      return await GetAPIEndpoint()
    } catch (error) {
      console.error('Failed to get API endpoint:', error)
      return 'http://127.0.0.1:8080'
    }
  }
}

// React Hook for Services
export const useServices = () => {
  const [services, setServices] = useState([])
  const [stats, setStats] = useState({
    total_services: 0,
    services_up: 0,
    services_down: 0,
    avg_uptime: 0,
    avg_latency: 0
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Fetch services
  const fetchServices = useCallback(async () => {
    setLoading(true)
    setError(null)
    
    const result = await apiService.getServices()
    if (result.error) {
      setError(result.error)
    } else {
      setServices(result.data)
    }
    
    setLoading(false)
  }, [])

  // Fetch statistics
  const fetchStats = useCallback(async () => {
    const result = await apiService.getServiceStats()
    if (result.error) {
      console.error('Stats error:', result.error)
    } else {
      setStats(result.data)
    }
  }, [])

  // Add service
  const addService = useCallback(async (serviceData) => {
    const result = await apiService.addService(serviceData)
    if (result.error) {
      setError(result.error)
      return { success: false, error: result.error }
    } else {
      // Refresh services list
      await fetchServices()
      await fetchStats()
      return { success: true, data: result.data }
    }
  }, [fetchServices, fetchStats])

  // Delete service
  const deleteService = useCallback(async (serviceId) => {
    const result = await apiService.deleteService(serviceId)
    if (result.error) {
      setError(result.error)
      return { success: false, error: result.error }
    } else {
      // Refresh services list
      await fetchServices()
      await fetchStats()
      return { success: true }
    }
  }, [fetchServices, fetchStats])

  // Initial load
  useEffect(() => {
    fetchServices()
    fetchStats()
  }, [fetchServices, fetchStats])

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      fetchServices()
      fetchStats()
    }, 30000)

    return () => clearInterval(interval)
  }, [fetchServices, fetchStats])

  return {
    services,
    stats,
    loading,
    error,
    addService,
    deleteService,
    refreshServices: fetchServices,
    refreshStats: fetchStats
  }
}