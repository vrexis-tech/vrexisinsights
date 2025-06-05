// apiService.js - Complete API integration for VREXIS Insights backend

class ApiService {
  constructor(baseURL = 'http://localhost:8080') {
    this.baseURL = baseURL;
    this.accessToken = null;
    this.refreshToken = null;
    this.refreshPromise = null;
  }

  setTokens(accessToken, refreshToken = null) {
    this.accessToken = accessToken;
    if (refreshToken) {
      this.refreshToken = refreshToken;
    }
  }

  getToken() {
    return this.accessToken;
  }

  async makeRequest(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(this.accessToken && { 'Authorization': `Bearer ${this.accessToken}` }),
        ...options.headers,
      },
      ...options,
    };

    try {
      console.log(`Making API request: ${options.method || 'GET'} ${url}`);
      const response = await fetch(url, config);
      
      // Handle token refresh for 401 errors
      if (response.status === 401 && this.accessToken && endpoint !== '/auth/refresh') {
        console.log('Got 401, attempting token refresh...');
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          // Retry the original request with new token
          config.headers.Authorization = `Bearer ${this.accessToken}`;
          return await fetch(url, config);
        } else {
          // Refresh failed, clear auth and redirect to login
          this.clearAuth();
          throw new Error('Session expired. Please login again.');
        }
      }

      // Handle rate limiting
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After') || '60';
        throw new Error(`Rate limit exceeded. Please wait ${retryAfter} seconds before trying again.`);
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.error('API Error:', response.status, errorData);
        throw new Error(errorData.error || errorData.message || `HTTP ${response.status}`);
      }

      console.log(`API request successful: ${endpoint}`);
      return response;
    } catch (error) {
      console.error(`API Request failed: ${endpoint}`, error);
      throw error;
    }
  }

  async refreshAccessToken() {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    if (!this.refreshToken) {
      console.log('No refresh token available');
      return false;
    }

    this.refreshPromise = this.makeRequest('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: this.refreshToken }),
    }).then(async (response) => {
      const data = await response.json();
      console.log('Token refresh successful');
      
      this.setTokens(data.access_token || data.token, data.refresh_token || this.refreshToken);
      
      // Update stored tokens
      sessionStorage.setItem('auth-token', this.accessToken);
      if (data.refresh_token) {
        sessionStorage.setItem('refresh-token', data.refresh_token);
      }
      
      return true;
    }).catch((error) => {
      console.error('Token refresh failed:', error);
      this.clearAuth();
      return false;
    }).finally(() => {
      this.refreshPromise = null;
    });

    return this.refreshPromise;
  }

  clearAuth() {
    this.accessToken = null;
    this.refreshToken = null;
    sessionStorage.removeItem('auth-token');
    sessionStorage.removeItem('refresh-token');
    sessionStorage.removeItem('auth-user');
  }

  // Authentication endpoints
  async register(email, password, firstName, lastName) {
    console.log('Attempting registration for:', email);
    const response = await this.makeRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ 
        email, 
        password, 
        first_name: firstName, 
        last_name: lastName 
      }),
    });
    return response.json();
  }

  async login(email, password) {
    console.log('Attempting login for:', email);
    const response = await this.makeRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    return response.json();
  }

  async logout() {
    try {
      await this.makeRequest('/auth/logout', {
        method: 'POST',
      });
    } catch (error) {
      console.error('Logout API call failed:', error);
      // Still clear local auth data even if API call fails
    } finally {
      this.clearAuth();
    }
  }

  // Services endpoints - matching your backend routes exactly
  async getServices() {
    console.log('Fetching services...');
    const response = await this.makeRequest('/api/v1/services');
    return response.json();
  }

  async addService(serviceData) {
    console.log('Adding service:', serviceData);
    const response = await this.makeRequest('/api/v1/services', {
      method: 'POST',
      body: JSON.stringify(serviceData),
    });
    return response.json();
  }

  async updateService(serviceId, serviceData) {
    console.log('Updating service:', serviceId);
    const response = await this.makeRequest(`/api/v1/services/${encodeURIComponent(serviceId)}`, {
      method: 'PUT',
      body: JSON.stringify(serviceData),
    });
    return response.json();
  }

  async deleteService(serviceId) {
    console.log('Deleting service:', serviceId);
    const response = await this.makeRequest(`/api/v1/services/${encodeURIComponent(serviceId)}`, {
      method: 'DELETE',
    });
    return response.json();
  }

  // Additional endpoints
  async getProfile() {
    const response = await this.makeRequest('/api/v1/profile');
    return response.json();
  }

  async getSecurityStatus() {
    const response = await this.makeRequest('/api/v1/security/status');
    return response.json();
  }

  async getHealth() {
    const response = await this.makeRequest('/health');
    return response.json();
  }

  // Real-time updates using polling
  async pollServices(callback, interval = 30000) {
    const poll = async () => {
      try {
        const data = await this.getServices();
        callback(data);
      } catch (error) {
        console.error('Polling error:', error);
        callback({ error: error.message });
      }
    };

    // Initial poll
    await poll();

    // Set up interval polling
    const pollInterval = setInterval(poll, interval);
    
    // Return cleanup function
    return () => {
      console.log('Stopping services polling');
      clearInterval(pollInterval);
    };
  }

  // WebSocket connection using your backend's /ws endpoint
  connectWebSocket(onMessage, onError) {
    const wsURL = this.baseURL.replace('http://localhost:8080', 'ws://localhost:8080') + '/ws';
    console.log('Connecting to WebSocket:', wsURL);
    
    const ws = new WebSocket(wsURL);

    ws.onopen = () => {
      console.log('WebSocket connected to:', wsURL);
      // Send auth token if available
      if (this.accessToken) {
        ws.send(JSON.stringify({ type: 'auth', token: this.accessToken }));
      }
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        console.log('WebSocket message received:', data);
        onMessage(data);
      } catch (error) {
        console.error('WebSocket message error:', error);
        // If it's not JSON, maybe it's a simple message
        onMessage({ type: 'raw', data: event.data });
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      onError?.(error);
    };

    ws.onclose = (event) => {
      console.log('WebSocket disconnected:', event.code, event.reason);
      // Attempt to reconnect after delay (only if it wasn't a manual close)
      if (event.code !== 1000) {
        setTimeout(() => {
          console.log('Attempting WebSocket reconnection...');
          this.connectWebSocket(onMessage, onError);
        }, 5000);
      }
    };

    return ws;
  }
}

// Create singleton instance
const apiService = new ApiService();

export default apiService;