// frontend/src/App.jsx
// Updated to use a unified apiService for web and desktop modes

import React, { useState, useEffect } from 'react'
import { 
  Activity, 
  Server, 
  Globe, 
  Smartphone, 
  Plus, 
  Settings,
  Mail,
  MailX,
  Save,
  Laptop,
  Trash2
} from 'lucide-react'

// Import the unified API service
import apiService from './apiService'

// Custom hook to use apiService
function useServices() {
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
  const fetchServices = async () => {
    try {
      setError(null)
      const data = await apiService.getServices()
      setServices(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error('Failed to fetch services:', err)
      setError(err.message)
      setServices([])
    }
  }

  // Fetch stats
  const fetchStats = async () => {
    try {
      const data = await apiService.getServiceStats()
      setStats(data || {
        total_services: 0,
        services_up: 0,
        services_down: 0,
        avg_uptime: 0,
        avg_latency: 0
      })
    } catch (err) {
      console.error('Failed to fetch stats:', err)
    }
  }

  // Add service
  const addService = async (serviceData) => {
    try {
      await apiService.addService(serviceData)
      await fetchServices()
      await fetchStats()
      return { success: true }
    } catch (err) {
      console.error('Failed to add service:', err)
      return { success: false, error: err.message }
    }
  }

  // Delete service
  const deleteService = async (serviceId) => {
    try {
      await apiService.deleteService(serviceId)
      await fetchServices()
      await fetchStats()
      return { success: true }
    } catch (err) {
      console.error('Failed to delete service:', err)
      return { success: false, error: err.message }
    }
  }

  // Initial load
  useEffect(() => {
    const loadData = async () => {
      setLoading(true)
      await Promise.all([fetchServices(), fetchStats()])
      setLoading(false)
    }
    
    loadData()

    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      fetchServices()
      fetchStats()
    }, 30000)

    return () => clearInterval(interval)
  }, [])

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

function App() {
  const { 
    services, 
    stats, 
    loading, 
    error, 
    addService, 
    deleteService 
  } = useServices()

  const [showAddForm, setShowAddForm] = useState(false)
  const [formData, setFormData] = useState({
    name: '',
    url: '',
    type: 'website'
  })

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    const result = await addService(formData)
    
    if (result.success) {
      // Reset form and close modal
      setFormData({ name: '', url: '', type: 'website' })
      setShowAddForm(false)
    } else {
      alert(`Failed to add service: ${result.error}`)
    }
  }

  const handleDelete = async (serviceId) => {
    if (window.confirm('Are you sure you want to delete this service?')) {
      const result = await deleteService(serviceId)
      
      if (!result.success) {
        alert(`Failed to delete service: ${result.error}`)
      }
    }
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'up': return 'text-green-500'
      case 'down': return 'text-red-500'
      case 'checking': return 'text-yellow-500'
      default: return 'text-gray-500'
    }
  }

  const getTypeIcon = (type) => {
    switch (type) {
      case 'server': return <Server className="w-5 h-5" />
      case 'iot': return <Smartphone className="w-5 h-5" />
      default: return <Globe className="w-5 h-5" />
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading Vrexis Insights...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Activity className="w-8 h-8 text-blue-500" />
            <div>
              <h1 className="text-xl font-bold">Vrexis Insights</h1>
              <p className="text-sm text-gray-400 flex items-center">
                <Laptop className="w-4 h-4 mr-1" />
                Desktop Edition
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowAddForm(true)}
            className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>Add Service</span>
          </button>
        </div>
      </header>

      {/* Stats Dashboard */}
      <div className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-8">
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-sm font-medium text-gray-400">Total Services</h3>
            <p className="text-2xl font-bold">{stats.total_services}</p>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-sm font-medium text-gray-400">Services Up</h3>
            <p className="text-2xl font-bold text-green-500">{stats.services_up}</p>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-sm font-medium text-gray-400">Services Down</h3>
            <p className="text-2xl font-bold text-red-500">{stats.services_down}</p>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-sm font-medium text-gray-400">Avg Uptime</h3>
            <p className="text-2xl font-bold">{stats.avg_uptime.toFixed(1)}%</p>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-sm font-medium text-gray-400">Avg Latency</h3>
            <p className="text-2xl font-bold">{stats.avg_latency}ms</p>
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-600/20 border border-red-600 text-red-400 p-4 rounded-lg mb-6">
            Error: {error}
          </div>
        )}

        {/* Services List */}
        <div className="space-y-4">
          <h2 className="text-xl font-bold">Services</h2>
          
          {services.length === 0 ? (
            <div className="bg-gray-800 p-8 rounded-lg text-center">
              <Server className="w-12 h-12 mx-auto text-gray-500 mb-4" />
              <p className="text-gray-400">No services configured yet</p>
              <button
                onClick={() => setShowAddForm(true)}
                className="mt-4 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg"
              >
                Add Your First Service
              </button>
            </div>
          ) : (
            <div className="grid gap-4">
              {services.map((service) => (
                <div key={service.id} className="bg-gray-800 p-4 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {getTypeIcon(service.type)}
                      <div>
                        <h3 className="font-medium">{service.name}</h3>
                        <p className="text-sm text-gray-400">{service.url}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <p className={`font-medium ${getStatusColor(service.status)}`}>
                          {service.status.toUpperCase()}
                        </p>
                        <p className="text-sm text-gray-400">
                          {service.latency}ms
                        </p>
                      </div>
                      <button
                        onClick={() => handleDelete(service.id)}
                        className="text-red-400 hover:text-red-300 p-2"
                        title="Delete Service"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Add Service Modal */}
      {showAddForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold mb-4">Add New Service</h2>
            
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Service Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2"
                  placeholder="My Website"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-1">URL</label>
                <input
                  type="text"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2"
                  placeholder="https://example.com or 192.168.1.100"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-1">Service Type</label>
                <select
                  value={formData.type}
                  onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2"
                >
                  <option value="website">Website</option>
                  <option value="server">Server</option>
                  <option value="iot">IoT Device</option>
                </select>
              </div>
              
              <div className="flex space-x-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowAddForm(false)}
                  className="flex-1 bg-gray-600 hover:bg-gray-700 py-2 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 hover:bg-blue-700 py-2 rounded-lg"
                >
                  Add Service
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default App