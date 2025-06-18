// desktopApiService.js - API service that works for both web and desktop modes

class DesktopApiService {
  constructor() {
    this.isDesktop = window.go !== undefined;
    this.baseURL = this.isDesktop ? null : 'http://localhost:8080';
    
    if (this.isDesktop) {
      console.log('🖥️  Running in desktop mode with Wails');
    } else {
      console.log('🌐 Running in web mode');
    }
  }

  // Check if we're running in desktop mode
  isDesktopMode() {
    return this.isDesktop;
  }

  // Get API endpoint (for web mode or debugging)
  async getAPIEndpoint() {
    if (this.isDesktop && window.go?.main?.App?.GetAPIEndpoint) {
      try {
        return await window.go.main.App.GetAPIEndpoint();
      } catch (error) {
        console.error('Failed to get API endpoint from desktop:', error);
        return 'http://localhost:8080';
      }
    }
    return this.baseURL;
  }

  // =============================================================================
  // SERVICES API
  // =============================================================================

  async getServices() {
    if (this.isDesktop && window.go?.main?.App?.GetServices) {
      try {
        console.log('📱 Fetching services via Wails...');
        const services = await window.go.main.App.GetServices();
        console.log('✅ Desktop API returned:', services);
        return services || [];
      } catch (error) {
        console.error('Desktop API error:', error);
        // Fallback to HTTP API
        return this.makeHttpRequest('/api/v1/services');
      }
    }
    
    // Web mode - use HTTP API
    return this.makeHttpRequest('/api/v1/services');
  }

  async addService(serviceData) {
    if (this.isDesktop && window.go?.main?.App?.AddService) {
      try {
        console.log('📱 Adding service via Wails:', serviceData);
        const service = await window.go.main.App.AddService(
          serviceData.name, 
          serviceData.url, 
          serviceData.type || 'website'
        );
        console.log('✅ Service added via desktop API:', service);
        return service;
      } catch (error) {
        console.error('Desktop API error:', error);
        throw new Error(error.message || 'Failed to add service');
      }
    }
    
    // Web mode - use HTTP API
    return this.makeHttpRequest('/api/v1/services', {
      method: 'POST',
      body: JSON.stringify(serviceData)
    });
  }

  async deleteService(serviceId) {
    if (this.isDesktop && window.go?.main?.App?.DeleteService) {
      try {
        console.log('📱 Deleting service via Wails:', serviceId);
        await window.go.main.App.DeleteService(serviceId);
        console.log('✅ Service deleted via desktop API');
        return { success: true };
      } catch (error) {
        console.error('Desktop API error:', error);
        throw new Error(error.message || 'Failed to delete service');
      }
    }
    
    // Web mode - use HTTP API
    await this.makeHttpRequest(`/api/v1/services/${serviceId}`, {
      method: 'DELETE'
    });
    return { success: true };
  }

  async getServiceStats() {
    if (this.isDesktop && window.go?.main?.App?.GetServiceStats) {
      try {
        console.log('📱 Fetching service stats via Wails...');
        const stats = await window.go.main.App.GetServiceStats();
        console.log('✅ Desktop API returned stats:', stats);
        return stats;
      } catch (error) {
        console.error('Desktop API error:', error);
        // Fallback to HTTP API
        return this.makeHttpRequest('/api/v1/services/stats');
      }
    }
    
    // Web mode - use HTTP API
    return this.makeHttpRequest('/api/v1/services/stats');
  }

  // =============================================================================
  // AUTHENTICATION (Web mode only - desktop doesn't need auth)
  // =============================================================================

  async login(email, password) {
    if (this.isDesktop) {
      // Desktop mode - create a mock auth response
      console.log('🖥️  Desktop mode - skipping authentication');
      return {
        token: 'desktop-mode-token',
        user: {
          id: 'desktop-user',
          email: 'desktop@user.local',
          first_name: 'Desktop',
          last_name: 'User',
          email_notifications: false
        }
      };
    }
    
    // Web mode - use HTTP API
    return this.makeHttpRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
  }

  async register(email, password, firstName, lastName) {
    if (this.isDesktop) {
      // Desktop mode - create a mock auth response
      console.log('🖥️  Desktop mode - skipping registration');
      return {
        token: 'desktop-mode-token',
        user: {
          id: 'desktop-user',
          email: 'desktop@user.local',
          first_name: firstName || 'Desktop',
          last_name: lastName || 'User',
          email_notifications: false
        }
      };
    }
    
    // Web mode - use HTTP API
    return this.makeHttpRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ 
        email, 
        password, 
        first_name: firstName, 
        last_name: lastName 
      })
    });
  }

  async updateEmailNotifications(enabled) {
    if (this.isDesktop) {
      // Desktop mode - just return success (could save to local storage)
      console.log('🖥️  Desktop mode - email notifications setting saved locally');
      localStorage.setItem('desktop-email-notifications', enabled.toString());
      return {
        id: 'desktop-user',
        email: 'desktop@user.local',
        first_name: 'Desktop',
        last_name: 'User',
        email_notifications: enabled
      };
    }
    
    // Web mode - use HTTP API
    return this.makeHttpRequest('/api/v1/user/email-notifications', {
      method: 'PUT',
      body: JSON.stringify({ email_notifications: enabled })
    });
  }

  // =============================================================================
  // HTTP API HELPERS (for web mode and fallback)
  // =============================================================================

  async makeHttpRequest(endpoint, options = {}) {
    const token = localStorage.getItem('token');
    const apiBase = await this.getAPIEndpoint();
    const url = `${apiBase}${endpoint}`;
    
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
      ...options,
    };

    try {
      console.log(`🌐 HTTP API: ${options.method || 'GET'} ${url}`);
      const response = await fetch(url, config);
      
      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Network error' }));
        throw new Error(error.error || `HTTP ${response.status}`);
      }

      const data = await response.json();
      console.log('✅ HTTP API success:', data);
      return data;
    } catch (error) {
      console.error(`❌ HTTP API error: ${endpoint}`, error);
      throw error;
    }
  }

  // =============================================================================
  // UTILITY METHODS
  // =============================================================================

  async getHealth() {
    try {
      const endpoint = await this.getAPIEndpoint();
      const response = await fetch(`${endpoint}/health`);
      return response.json();
    } catch (error) {
      console.error('Health check failed:', error);
      return { status: 'unhealthy', error: error.message };
    }
  }

  // Real-time updates using polling (works for both modes)
  async startPolling(callback, interval = 30000) {
    console.log(`🔄 Starting polling every ${interval}ms`);
    
    const poll = async () => {
      try {
        const services = await this.getServices();
        const stats = await this.getServiceStats();
        callback({ services, stats, error: null });
      } catch (error) {
        console.error('Polling error:', error);
        callback({ services: [], stats: null, error: error.message });
      }
    };

    // Initial poll
    await poll();

    // Set up interval polling
    const pollInterval = setInterval(poll, interval);
    
    // Return cleanup function
    return () => {
      console.log('🛑 Stopping polling');
      clearInterval(pollInterval);
    };
  }

  // Desktop app info
  async getAppInfo() {
    if (this.isDesktop) {
      return {
        mode: 'desktop',
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        apiEndpoint: await this.getAPIEndpoint()
      };
    } else {
      return {
        mode: 'web',
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        apiEndpoint: this.baseURL
      };
    }
  }
}

// Create singleton instance
const desktopApiService = new DesktopApiService();
export default desktopApiService;