package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AlertEngine handles alert evaluation and notifications
type AlertEngine struct {
	alertStore        *AlertStore
	serviceStore      *ServiceStore
	notificationStore *NotificationStore
	config            AlertConfig
	ticker            *time.Ticker
	done              chan bool
}

// NewAlertEngine creates a new alert engine
func NewAlertEngine(alertStore *AlertStore, serviceStore *ServiceStore, notificationStore *NotificationStore, config AlertConfig) *AlertEngine {
	return &AlertEngine{
		alertStore:        alertStore,
		serviceStore:      serviceStore,
		notificationStore: notificationStore,
		config:            config,
		done:              make(chan bool),
	}
}

// Start begins the alert evaluation loop
func (ae *AlertEngine) Start(ctx context.Context) {
	log.Println("🚨 Starting alert engine...")

	// Run immediately on start
	ae.EvaluateAlerts()

	// Then run at configured interval
	ae.ticker = time.NewTicker(ae.config.EvaluationInterval)

	for {
		select {
		case <-ctx.Done():
			ae.Stop()
			return
		case <-ae.done:
			return
		case <-ae.ticker.C:
			ae.EvaluateAlerts()
		}
	}
}

// Stop stops the alert engine
func (ae *AlertEngine) Stop() {
	if ae.ticker != nil {
		ae.ticker.Stop()
	}

	select {
	case ae.done <- true:
	default:
	}

	log.Println("🛑 Alert engine stopped")
}

// EvaluateAlerts evaluates all enabled alerts against current service states
func (ae *AlertEngine) EvaluateAlerts() {
	alerts, err := ae.alertStore.GetEnabledAlerts()
	if err != nil {
		log.Printf("Error fetching enabled alerts: %v", err)
		return
	}

	log.Printf("📊 Evaluating %d enabled alerts...", len(alerts))

	for _, alert := range alerts {
		ae.evaluateAlert(&alert)
	}
}

// evaluateAlert evaluates a single alert
func (ae *AlertEngine) evaluateAlert(alert *Alert) {
	// Check cooldown period
	if alert.LastTriggered != nil {
		cooldownEnd := alert.LastTriggered.Add(time.Duration(alert.Cooldown) * time.Minute)
		if time.Now().Before(cooldownEnd) {
			return // Still in cooldown period
		}
	}

	// Get services for this alert
	services, err := ae.getServicesForAlert(alert)
	if err != nil {
		log.Printf("Error getting services for alert %s: %v", alert.ID, err)
		return
	}

	if len(services) == 0 {
		log.Printf("No services found for alert %s", alert.ID)
		return
	}

	// Evaluate based on condition type
	switch alert.Condition {
	case "status":
		ae.evaluateStatusCondition(alert, services)
	case "latency":
		ae.evaluateLatencyCondition(alert, services)
	case "ping_latency":
		ae.evaluatePingLatencyCondition(alert, services)
	case "multiple_down":
		ae.evaluateMultipleDownCondition(alert, services)
	default:
		log.Printf("Unknown alert condition: %s for alert %s", alert.Condition, alert.ID)
	}
}

// getServicesForAlert retrieves services associated with an alert using proper ServiceStore
func (ae *AlertEngine) getServicesForAlert(alert *Alert) ([]Service, error) {
	var services []Service

	for _, serviceID := range alert.ServiceIDs {
		service, err := ae.serviceStore.GetServiceByID(serviceID, alert.UserID)
		if err != nil {
			log.Printf("Error fetching service %s for alert %s: %v", serviceID, alert.ID, err)
			continue
		}
		if service != nil {
			services = append(services, *service)
		}
	}

	return services, nil
}

// evaluateStatusCondition evaluates status-based conditions
func (ae *AlertEngine) evaluateStatusCondition(alert *Alert, services []Service) {
	targetStatus := alert.Value

	for _, service := range services {
		shouldTrigger := false

		switch alert.Operator {
		case "equals":
			shouldTrigger = service.Status == targetStatus
		case "not_equals":
			shouldTrigger = service.Status != targetStatus
		default:
			log.Printf("Invalid operator %s for status condition in alert %s", alert.Operator, alert.ID)
			continue
		}

		if shouldTrigger {
			message := fmt.Sprintf("Service '%s' status is %s", service.Name, service.Status)
			ae.triggerAlert(alert, &service, message)
			return // Only trigger once per evaluation
		}
	}
}

// evaluateLatencyCondition evaluates HTTP latency-based conditions
func (ae *AlertEngine) evaluateLatencyCondition(alert *Alert, services []Service) {
	threshold, err := strconv.ParseFloat(alert.Value, 64)
	if err != nil {
		log.Printf("Invalid latency threshold for alert %s: %s", alert.ID, alert.Value)
		return
	}

	for _, service := range services {
		// Skip if service doesn't have HTTP monitoring (e.g., IP addresses)
		if service.Latency == nil {
			continue
		}

		latency := float64(*service.Latency)
		shouldTrigger := false

		switch alert.Operator {
		case "greater_than":
			shouldTrigger = latency > threshold
		case "less_than":
			shouldTrigger = latency < threshold
		case "greater_equal":
			shouldTrigger = latency >= threshold
		case "less_equal":
			shouldTrigger = latency <= threshold
		case "equals":
			shouldTrigger = latency == threshold
		case "not_equals":
			shouldTrigger = latency != threshold
		default:
			log.Printf("Invalid operator %s for latency condition in alert %s", alert.Operator, alert.ID)
			continue
		}

		if shouldTrigger {
			message := fmt.Sprintf("Service '%s' latency is %.0fms (threshold: %.0fms)",
				service.Name, latency, threshold)
			ae.triggerAlert(alert, &service, message)
			return // Only trigger once per evaluation
		}
	}
}

// evaluatePingLatencyCondition evaluates ping latency-based conditions
func (ae *AlertEngine) evaluatePingLatencyCondition(alert *Alert, services []Service) {
	threshold, err := strconv.ParseFloat(alert.Value, 64)
	if err != nil {
		log.Printf("Invalid ping latency threshold for alert %s: %s", alert.ID, alert.Value)
		return
	}

	for _, service := range services {
		// Skip if service doesn't have ping monitoring
		if service.PingLatency == nil {
			continue
		}

		pingLatency := float64(*service.PingLatency)
		shouldTrigger := false

		switch alert.Operator {
		case "greater_than":
			shouldTrigger = pingLatency > threshold
		case "less_than":
			shouldTrigger = pingLatency < threshold
		case "greater_equal":
			shouldTrigger = pingLatency >= threshold
		case "less_equal":
			shouldTrigger = pingLatency <= threshold
		case "equals":
			shouldTrigger = pingLatency == threshold
		case "not_equals":
			shouldTrigger = pingLatency != threshold
		default:
			log.Printf("Invalid operator %s for ping latency condition in alert %s", alert.Operator, alert.ID)
			continue
		}

		if shouldTrigger {
			message := fmt.Sprintf("Service '%s' ping latency is %.0fms (threshold: %.0fms)",
				service.Name, pingLatency, threshold)
			ae.triggerAlert(alert, &service, message)
			return // Only trigger once per evaluation
		}
	}
}

// evaluateMultipleDownCondition evaluates multiple services down condition
func (ae *AlertEngine) evaluateMultipleDownCondition(alert *Alert, services []Service) {
	threshold, err := strconv.Atoi(alert.Value)
	if err != nil {
		log.Printf("Invalid multiple down threshold for alert %s: %s", alert.ID, alert.Value)
		return
	}

	downCount := 0
	var downServices []string

	for _, service := range services {
		if service.Status == "down" {
			downCount++
			downServices = append(downServices, service.Name)
		}
	}

	shouldTrigger := false
	switch alert.Operator {
	case "greater_than":
		shouldTrigger = downCount > threshold
	case "greater_equal":
		shouldTrigger = downCount >= threshold
	case "equals":
		shouldTrigger = downCount == threshold
	case "less_than":
		shouldTrigger = downCount < threshold
	case "less_equal":
		shouldTrigger = downCount <= threshold
	default:
		log.Printf("Invalid operator %s for multiple down condition in alert %s", alert.Operator, alert.ID)
		return
	}

	if shouldTrigger {
		message := fmt.Sprintf("%d services are down: %s", downCount, strings.Join(downServices, ", "))
		ae.triggerAlert(alert, nil, message)
	}
}

// triggerAlert triggers an alert and sends notifications
func (ae *AlertEngine) triggerAlert(alert *Alert, service *Service, message string) {
	log.Printf("🚨 Triggering alert %s: %s", alert.ID, message)

	// Update alert trigger count and timestamp
	if err := ae.alertStore.UpdateAlertTrigger(alert.ID); err != nil {
		log.Printf("Error updating alert trigger for alert %s: %v", alert.ID, err)
	}

	// Log the trigger event
	trigger := &AlertTrigger{
		AlertID:  alert.ID,
		Message:  message,
		Severity: alert.Severity,
	}

	if service != nil {
		trigger.ServiceID = service.ID
	}

	if err := ae.alertStore.CreateAlertTrigger(trigger); err != nil {
		log.Printf("Error creating alert trigger log for alert %s: %v", alert.ID, err)
	}

	// Send notifications
	ae.sendNotifications(alert, message)
}

// sendNotifications sends notifications through configured channels
func (ae *AlertEngine) sendNotifications(alert *Alert, message string) {
	// Get user's notification settings
	settings, err := ae.notificationStore.GetNotificationSettings(alert.UserID)
	if err != nil {
		log.Printf("Error fetching notification settings for user %s: %v", alert.UserID, err)
		return
	}

	// Send notifications for each enabled channel
	for _, channel := range alert.Notifications {
		switch channel {
		case "email":
			if ae.config.EnableEmailNotifications && settings.EmailEnabled && settings.EmailAddress != "" {
				ae.sendEmailNotification(settings.EmailAddress, alert, message)
			}
		case "slack":
			if ae.config.EnableSlackNotifications && settings.SlackEnabled && settings.SlackWebhook != "" {
				ae.sendSlackNotification(settings.SlackWebhook, settings.SlackChannel, alert, message)
			}
		case "webhook":
			if ae.config.EnableWebhookNotifications && settings.WebhookEnabled && settings.WebhookURL != "" {
				ae.sendWebhookNotification(settings.WebhookURL, settings.WebhookMethod, alert, message)
			}
		case "sms":
			if ae.config.EnableSMSNotifications && settings.SMSEnabled && settings.SMSNumber != "" {
				ae.sendSMSNotification(settings.SMSNumber, alert, message)
			}
		default:
			log.Printf("Unknown notification channel: %s", channel)
		}
	}
}

// sendEmailNotification sends an email notification
func (ae *AlertEngine) sendEmailNotification(email string, alert *Alert, message string) {
	// TODO: Implement with actual email service (SendGrid, AWS SES, SMTP, etc.)
	log.Printf("📧 Email notification sent to %s: [%s] %s - %s",
		email, strings.ToUpper(alert.Severity), alert.Name, message)

	// Example implementation with SendGrid:
	/*
		import "github.com/sendgrid/sendgrid-go"
		import "github.com/sendgrid/sendgrid-go/helpers/mail"

		from := mail.NewEmail("VREXIS Insights", "noreply@vrexisinsights.com")
		to := mail.NewEmail("", email)
		subject := fmt.Sprintf("[VREXIS Alert] %s - %s", strings.ToUpper(alert.Severity), alert.Name)
		content := mail.NewContent("text/html", fmt.Sprintf(`
			<h2>Alert Triggered</h2>
			<p><strong>Alert:</strong> %s</p>
			<p><strong>Severity:</strong> %s</p>
			<p><strong>Message:</strong> %s</p>
			<p><strong>Time:</strong> %s</p>
		`, alert.Name, alert.Severity, message, time.Now().Format(time.RFC3339)))

		m := mail.NewV3MailInit(from, subject, to, content)
		client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))

		if response, err := client.Send(m); err != nil {
			log.Printf("Email send error: %v", err)
		} else {
			log.Printf("Email sent successfully, status: %d", response.StatusCode)
		}
	*/
}

// sendSlackNotification sends a Slack notification
func (ae *AlertEngine) sendSlackNotification(webhookURL, channel string, alert *Alert, message string) {
	color := "warning"
	emoji := "⚠️"

	switch alert.Severity {
	case "critical":
		color = "danger"
		emoji = "🚨"
	case "info":
		color = "good"
		emoji = "ℹ️"
	}

	payload := map[string]interface{}{
		"channel": channel,
		"attachments": []map[string]interface{}{
			{
				"color":      color,
				"title":      fmt.Sprintf("%s %s Alert", emoji, strings.Title(alert.Severity)),
				"title_link": fmt.Sprintf("https://vrexisinsights.com/alerts/%s", alert.ID),
				"text":       fmt.Sprintf("*%s*\n%s", alert.Name, message),
				"fields": []map[string]interface{}{
					{
						"title": "Severity",
						"value": strings.ToUpper(alert.Severity),
						"short": true,
					},
					{
						"title": "Condition",
						"value": fmt.Sprintf("%s %s %s", alert.Condition, alert.Operator, alert.Value),
						"short": true,
					},
				},
				"footer": "VREXIS Insights",
				"ts":     time.Now().Unix(),
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling Slack payload: %v", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error sending Slack notification: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Slack notification failed with status: %d", resp.StatusCode)
	} else {
		log.Printf("💬 Slack notification sent successfully to %s", channel)
	}
}

// sendWebhookNotification sends a webhook notification
func (ae *AlertEngine) sendWebhookNotification(webhookURL, method string, alert *Alert, message string) {
	payload := map[string]interface{}{
		"alert_id":    alert.ID,
		"alert_name":  alert.Name,
		"severity":    alert.Severity,
		"message":     message,
		"timestamp":   time.Now().Unix(),
		"condition":   alert.Condition,
		"operator":    alert.Operator,
		"value":       alert.Value,
		"service_ids": alert.ServiceIDs,
		"user_id":     alert.UserID,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling webhook payload: %v", err)
		return
	}

	req, err := http.NewRequest(method, webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating webhook request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VREXIS-Insights/1.0")
	req.Header.Set("X-VREXIS-Alert-ID", alert.ID)
	req.Header.Set("X-VREXIS-Severity", alert.Severity)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending webhook notification: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("🔗 Webhook notification sent successfully to %s", webhookURL)
	} else {
		log.Printf("Webhook notification failed with status: %d", resp.StatusCode)
	}
}

// sendSMSNotification sends an SMS notification
func (ae *AlertEngine) sendSMSNotification(phoneNumber string, alert *Alert, message string) {
	// TODO: Implement with Twilio or similar SMS service
	log.Printf("📱 SMS notification sent to %s: [%s] %s - %s",
		phoneNumber, strings.ToUpper(alert.Severity), alert.Name, message)

	// Example implementation with Twilio:
	/*
		import "github.com/twilio/twilio-go"
		import openapi "github.com/twilio/twilio-go/rest/api/v2010"

		client := twilio.NewRestClientWithParams(twilio.ClientParams{
			Username: os.Getenv("TWILIO_ACCOUNT_SID"),
			Password: os.Getenv("TWILIO_AUTH_TOKEN"),
		})

		params := &openapi.CreateMessageParams{}
		params.SetTo(phoneNumber)
		params.SetFrom(os.Getenv("TWILIO_PHONE_NUMBER"))
		params.SetBody(fmt.Sprintf("[VREXIS] %s: %s", alert.Name, message))

		if resp, err := client.Api.CreateMessage(params); err != nil {
			log.Printf("Error sending SMS: %v", err)
		} else {
			log.Printf("SMS sent successfully, SID: %s", *resp.Sid)
		}
	*/
}

// TestAlert manually triggers an alert for testing purposes
func (ae *AlertEngine) TestAlert(alertID, userID string) error {
	alert, err := ae.alertStore.GetAlertByID(alertID, userID)
	if err != nil {
		return fmt.Errorf("failed to get alert: %w", err)
	}

	message := "Test alert triggered manually"
	ae.triggerAlert(alert, nil, message)

	return nil
}

// GetAlertStats returns statistics about alert triggering
func (ae *AlertEngine) GetAlertStats() map[string]interface{} {
	// This could be expanded to include more detailed metrics
	return map[string]interface{}{
		"evaluation_interval": ae.config.EvaluationInterval.String(),
		"email_enabled":       ae.config.EnableEmailNotifications,
		"slack_enabled":       ae.config.EnableSlackNotifications,
		"sms_enabled":         ae.config.EnableSMSNotifications,
		"webhook_enabled":     ae.config.EnableWebhookNotifications,
		"max_notifications":   ae.config.MaxNotificationsPerHour,
	}
}
