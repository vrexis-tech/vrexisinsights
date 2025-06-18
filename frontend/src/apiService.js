// desktopApiService.js - Fixed API service that works for both web and desktop modes

class DesktopApiService {
  constructor() {
    this.isDesktop = window.go !== undefined;
    // FIXED: Ensure baseURL is never null
    this.baseURL = this.isDesktop
      ? "http://127.0.0.1:8080"
      : "http://127.0.0.1:8080";

    if (this.isDesktop) {
      console.log("🖥️  Running in desktop mode with Wails");
    } else {
      console.log("🌐 Running in web mode, baseURL:", this.baseURL);
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
        const endpoint = await window.go.main.App.GetAPIEndpoint();
        console.log("📱 Got API endpoint from desktop:", endpoint);
        return endpoint;
      } catch (error) {
        console.error("Failed to get API endpoint from desktop:", error);
        return this.baseURL;
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
        console.log("📱 Fetching services via Wails...");
        const services = await window.go.main.App.GetServices();
        console.log("✅ Desktop API returned:", services);
        return services || [];
      } catch (error) {
        console.error("Desktop API error:", error);
        // Fallback to HTTP API
        return this.makeHttpRequest("/api/v1/services");
      }
    }

    // Web mode - use HTTP API
    console.log("🌐 Fetching services via HTTP API...");
    return this.makeHttpRequest("/api/v1/services");
  }

  async addService(serviceData) {
    if (this.isDesktop && window.go?.main?.App?.AddService) {
      try {
        console.log("📱 Adding service via Wails:", serviceData);
        const service = await window.go.main.App.AddService(
          serviceData.name,
          serviceData.url,
          serviceData.type || "website"
        );
        console.log("✅ Service added via desktop API:", service);
        return service;
      } catch (error) {
        console.error("Desktop API error:", error);
        throw new Error(error.message || "Failed to add service");
      }
    }

    // Web mode - use HTTP API
    console.log("🌐 Adding service via HTTP API:", serviceData);
    return this.makeHttpRequest("/api/v1/services", {
      method: "POST",
      body: JSON.stringify(serviceData),
    });
  }

  async deleteService(serviceId) {
    if (this.isDesktop && window.go?.main?.App?.DeleteService) {
      try {
        console.log("📱 Deleting service via Wails:", serviceId);
        await window.go.main.App.DeleteService(serviceId);
        console.log("✅ Service deleted via desktop API");
        return { success: true };
      } catch (error) {
        console.error("Desktop API error:", error);
        throw new Error(error.message || "Failed to delete service");
      }
    }

    // Web mode - use HTTP API
    console.log("🌐 Deleting service via HTTP API:", serviceId);
    await this.makeHttpRequest(`/api/v1/services/${serviceId}`, {
      method: "DELETE",
    });
    return { success: true };
  }

  async getServiceStats() {
    if (this.isDesktop && window.go?.main?.App?.GetServiceStats) {
      try {
        console.log("📱 Fetching service stats via Wails...");
        const stats = await window.go.main.App.GetServiceStats();
        console.log("✅ Desktop API returned stats:", stats);
        return stats;
      } catch (error) {
        console.error("Desktop API error:", error);
        // Fallback to HTTP API
        return this.makeHttpRequest("/api/v1/services/stats");
      }
    }

    // Web mode - use HTTP API
    console.log("🌐 Fetching stats via HTTP API...");
    return this.makeHttpRequest("/api/v1/services/stats");
  }

  // =============================================================================
  // AUTHENTICATION (Web mode only - desktop doesn't need auth)
  // =============================================================================

  async login(email, password) {
    if (this.isDesktop) {
      // Desktop mode - create a mock auth response
      console.log("🖥️  Desktop mode - skipping authentication");
      return {
        token: "desktop-mode-token",
        user: {
          id: "desktop-user",
          email: "desktop@user.local",
          first_name: "Desktop",
          last_name: "User",
          email_notifications: false,
        },
      };
    }

    // Web mode - use HTTP API
    return this.makeHttpRequest("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  }

  async register(email, password, firstName, lastName) {
    if (this.isDesktop) {
      // Desktop mode - create a mock auth response
      console.log("🖥️  Desktop mode - skipping registration");
      return {
        token: "desktop-mode-token",
        user: {
          id: "desktop-user",
          email: "desktop@user.local",
          first_name: firstName || "Desktop",
          last_name: lastName || "User",
          email_notifications: false,
        },
      };
    }

    // Web mode - use HTTP API
    return this.makeHttpRequest("/auth/register", {
      method: "POST",
      body: JSON.stringify({
        email,
        password,
        first_name: firstName,
        last_name: lastName,
      }),
    });
  }

  // =============================================================================
  // HTTP API HELPERS (for web mode and fallback)
  // =============================================================================

  async makeHttpRequest(endpoint, options = {}) {
    // FIXED: Always use a valid base URL
    const apiBase = await this.getAPIEndpoint();
    const url = `${apiBase}${endpoint}`;

    console.log(`🌐 Making HTTP request: ${options.method || "GET"} ${url}`);

    const config = {
      headers: {
        "Content-Type": "application/json",
        // REMOVED: Don't require auth tokens in desktop mode
        // The desktop app should handle auth internally
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);

      console.log(`📡 Response status: ${response.status}`);

      if (!response.ok) {
        const error = await response.json().catch(() => ({
          error: `HTTP ${response.status} ${response.statusText}`,
        }));
        throw new Error(error.error || `HTTP ${response.status}`);
      }

      const data = await response.json();
      console.log("✅ HTTP API success:", data);
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
      console.error("Health check failed:", error);
      return { status: "unhealthy", error: error.message };
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
        console.error("Polling error:", error);
        callback({ services: [], stats: null, error: error.message });
      }
    };

    // Initial poll
    await poll();

    // Set up interval polling
    const pollInterval = setInterval(poll, interval);

    // Return cleanup function
    return () => {
      console.log("🛑 Stopping polling");
      clearInterval(pollInterval);
    };
  }

  // Desktop app info
  async getAppInfo() {
    const apiEndpoint = await this.getAPIEndpoint();

    if (this.isDesktop) {
      return {
        mode: "desktop",
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        apiEndpoint,
      };
    } else {
      return {
        mode: "web",
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        apiEndpoint,
      };
    }
  }
}

// Create singleton instance
const desktopApiService = new DesktopApiService();
export default desktopApiService;
