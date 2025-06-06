// stores.go - Alert-related stores only (UserStore and ServiceStore are in user_service_stores.go)

package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// AlertStore handles alert data operations
type AlertStore struct {
	db      *sql.DB
	monitor *SecurityMonitor
}

// NotificationStore handles notification settings data operations
type NotificationStore struct {
	db      *sql.DB
	monitor *SecurityMonitor
}

// NewAlertStore creates a new alert store
func NewAlertStore(db *sql.DB, monitor *SecurityMonitor) (*AlertStore, error) {
	return &AlertStore{
		db:      db,
		monitor: monitor,
	}, nil
}

// NewNotificationStore creates a new notification store
func NewNotificationStore(db *sql.DB, monitor *SecurityMonitor) (*NotificationStore, error) {
	return &NotificationStore{
		db:      db,
		monitor: monitor,
	}, nil
}

// Alert CRUD operations

// GetAlertsByUserID retrieves all alerts for a specific user
func (s *AlertStore) GetAlertsByUserID(userID string) ([]Alert, error) {
	query := `
		SELECT id, user_id, name, description, service_ids, condition, operator, 
		       value, enabled, notifications, cooldown, severity, created, 
		       last_triggered, trigger_count
		FROM alerts 
		WHERE user_id = ? 
		ORDER BY created DESC
	`

	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var alert Alert
		var serviceIDsJSON, notificationsJSON string
		var lastTriggered sql.NullTime

		err := rows.Scan(
			&alert.ID, &alert.UserID, &alert.Name, &alert.Description,
			&serviceIDsJSON, &alert.Condition, &alert.Operator, &alert.Value,
			&alert.Enabled, &notificationsJSON, &alert.Cooldown, &alert.Severity,
			&alert.Created, &lastTriggered, &alert.TriggerCount,
		)
		if err != nil {
			return nil, err
		}

		// Parse JSON fields
		if err := json.Unmarshal([]byte(serviceIDsJSON), &alert.ServiceIDs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(notificationsJSON), &alert.Notifications); err != nil {
			return nil, err
		}

		if lastTriggered.Valid {
			alert.LastTriggered = &lastTriggered.Time
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// GetAlertByID retrieves a specific alert by ID
func (s *AlertStore) GetAlertByID(alertID, userID string) (*Alert, error) {
	query := `
		SELECT id, user_id, name, description, service_ids, condition, operator, 
		       value, enabled, notifications, cooldown, severity, created, 
		       last_triggered, trigger_count
		FROM alerts 
		WHERE id = ? AND user_id = ?
	`

	var alert Alert
	var serviceIDsJSON, notificationsJSON string
	var lastTriggered sql.NullTime

	err := s.db.QueryRow(query, alertID, userID).Scan(
		&alert.ID, &alert.UserID, &alert.Name, &alert.Description,
		&serviceIDsJSON, &alert.Condition, &alert.Operator, &alert.Value,
		&alert.Enabled, &notificationsJSON, &alert.Cooldown, &alert.Severity,
		&alert.Created, &lastTriggered, &alert.TriggerCount,
	)
	if err != nil {
		return nil, err
	}

	// Parse JSON fields
	if err := json.Unmarshal([]byte(serviceIDsJSON), &alert.ServiceIDs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(notificationsJSON), &alert.Notifications); err != nil {
		return nil, err
	}

	if lastTriggered.Valid {
		alert.LastTriggered = &lastTriggered.Time
	}

	return &alert, nil
}

// CreateAlert creates a new alert
func (s *AlertStore) CreateAlert(alert *Alert) error {
	// Generate ID if not provided
	if alert.ID == "" {
		alert.ID = generateID("alert")
	}

	// Marshal JSON fields
	serviceIDsJSON, err := json.Marshal(alert.ServiceIDs)
	if err != nil {
		return err
	}
	notificationsJSON, err := json.Marshal(alert.Notifications)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO alerts (id, user_id, name, description, service_ids, condition, 
		                   operator, value, enabled, notifications, cooldown, severity)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.Exec(query,
		alert.ID, alert.UserID, alert.Name, alert.Description, string(serviceIDsJSON),
		alert.Condition, alert.Operator, alert.Value, alert.Enabled,
		string(notificationsJSON), alert.Cooldown, alert.Severity,
	)
	if err != nil {
		return err
	}

	alert.Created = time.Now()
	return nil
}

// UpdateAlert updates an existing alert
func (s *AlertStore) UpdateAlert(alert *Alert) error {
	// Marshal JSON fields
	serviceIDsJSON, err := json.Marshal(alert.ServiceIDs)
	if err != nil {
		return err
	}
	notificationsJSON, err := json.Marshal(alert.Notifications)
	if err != nil {
		return err
	}

	query := `
		UPDATE alerts 
		SET name = ?, description = ?, service_ids = ?, condition = ?, 
		    operator = ?, value = ?, enabled = ?, notifications = ?, 
		    cooldown = ?, severity = ?
		WHERE id = ? AND user_id = ?
	`

	_, err = s.db.Exec(query,
		alert.Name, alert.Description, string(serviceIDsJSON), alert.Condition,
		alert.Operator, alert.Value, alert.Enabled, string(notificationsJSON),
		alert.Cooldown, alert.Severity, alert.ID, alert.UserID,
	)

	return err
}

// DeleteAlert deletes an alert
func (s *AlertStore) DeleteAlert(alertID, userID string) error {
	query := `DELETE FROM alerts WHERE id = ? AND user_id = ?`
	_, err := s.db.Exec(query, alertID, userID)
	return err
}

// UpdateAlertTrigger updates the trigger count and last triggered time
func (s *AlertStore) UpdateAlertTrigger(alertID string) error {
	query := `
		UPDATE alerts 
		SET trigger_count = trigger_count + 1, last_triggered = CURRENT_TIMESTAMP
		WHERE id = ?
	`
	_, err := s.db.Exec(query, alertID)
	return err
}

// GetEnabledAlerts retrieves all enabled alerts (for monitoring)
func (s *AlertStore) GetEnabledAlerts() ([]Alert, error) {
	query := `
		SELECT id, user_id, name, description, service_ids, condition, operator, 
		       value, enabled, notifications, cooldown, severity, created, 
		       last_triggered, trigger_count
		FROM alerts 
		WHERE enabled = 1
		ORDER BY severity DESC, created ASC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var alert Alert
		var serviceIDsJSON, notificationsJSON string
		var lastTriggered sql.NullTime

		err := rows.Scan(
			&alert.ID, &alert.UserID, &alert.Name, &alert.Description,
			&serviceIDsJSON, &alert.Condition, &alert.Operator, &alert.Value,
			&alert.Enabled, &notificationsJSON, &alert.Cooldown, &alert.Severity,
			&alert.Created, &lastTriggered, &alert.TriggerCount,
		)
		if err != nil {
			return nil, err
		}

		// Parse JSON fields
		if err := json.Unmarshal([]byte(serviceIDsJSON), &alert.ServiceIDs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(notificationsJSON), &alert.Notifications); err != nil {
			return nil, err
		}

		if lastTriggered.Valid {
			alert.LastTriggered = &lastTriggered.Time
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// Alert trigger operations

// CreateAlertTrigger logs an alert trigger event
func (s *AlertStore) CreateAlertTrigger(trigger *AlertTrigger) error {
	if trigger.ID == "" {
		trigger.ID = generateID("trigger")
	}

	query := `
		INSERT INTO alert_triggers (id, alert_id, service_id, message, severity)
		VALUES (?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query, trigger.ID, trigger.AlertID, trigger.ServiceID, trigger.Message, trigger.Severity)
	if err != nil {
		return err
	}

	trigger.Triggered = time.Now()
	return nil
}

// GetAlertTriggerHistory retrieves trigger history for an alert
func (s *AlertStore) GetAlertTriggerHistory(alertID string, limit int) ([]AlertTrigger, error) {
	query := `
		SELECT id, alert_id, service_id, message, severity, triggered, resolved
		FROM alert_triggers 
		WHERE alert_id = ?
		ORDER BY triggered DESC
		LIMIT ?
	`

	rows, err := s.db.Query(query, alertID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var triggers []AlertTrigger
	for rows.Next() {
		var trigger AlertTrigger
		var serviceID sql.NullString
		var resolved sql.NullTime

		err := rows.Scan(
			&trigger.ID, &trigger.AlertID, &serviceID, &trigger.Message,
			&trigger.Severity, &trigger.Triggered, &resolved,
		)
		if err != nil {
			return nil, err
		}

		if serviceID.Valid {
			trigger.ServiceID = serviceID.String
		}

		if resolved.Valid {
			trigger.Resolved = &resolved.Time
		}

		triggers = append(triggers, trigger)
	}

	return triggers, nil
}

// Notification settings operations

// GetNotificationSettings retrieves notification settings for a user
func (s *NotificationStore) GetNotificationSettings(userID string) (*NotificationSettings, error) {
	query := `
		SELECT id, user_id, email_enabled, email_address, email_verified,
		       sms_enabled, sms_number, sms_verified, slack_enabled, 
		       slack_webhook, slack_channel, webhook_enabled, webhook_url, 
		       webhook_method, updated
		FROM notification_settings 
		WHERE user_id = ?
	`

	var settings NotificationSettings
	err := s.db.QueryRow(query, userID).Scan(
		&settings.ID, &settings.UserID, &settings.EmailEnabled, &settings.EmailAddress,
		&settings.EmailVerified, &settings.SMSEnabled, &settings.SMSNumber,
		&settings.SMSVerified, &settings.SlackEnabled, &settings.SlackWebhook,
		&settings.SlackChannel, &settings.WebhookEnabled, &settings.WebhookURL,
		&settings.WebhookMethod, &settings.Updated,
	)

	if err == sql.ErrNoRows {
		// Create default settings if none exist
		return s.CreateDefaultNotificationSettings(userID)
	}

	if err != nil {
		return nil, err
	}

	return &settings, nil
}

// CreateDefaultNotificationSettings creates default notification settings for a new user
func (s *NotificationStore) CreateDefaultNotificationSettings(userID string) (*NotificationSettings, error) {
	settings := &NotificationSettings{
		ID:             generateID("settings"),
		UserID:         userID,
		EmailEnabled:   true,
		EmailAddress:   "", // Will be populated from user email
		EmailVerified:  false,
		SMSEnabled:     false,
		SlackEnabled:   false,
		WebhookEnabled: false,
		WebhookMethod:  "POST",
		Updated:        time.Now(),
	}

	query := `
		INSERT INTO notification_settings (id, user_id, email_enabled, email_address, 
		                                  email_verified, sms_enabled, sms_number, 
		                                  sms_verified, slack_enabled, slack_webhook, 
		                                  slack_channel, webhook_enabled, webhook_url, 
		                                  webhook_method)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query,
		settings.ID, settings.UserID, settings.EmailEnabled, settings.EmailAddress,
		settings.EmailVerified, settings.SMSEnabled, settings.SMSNumber,
		settings.SMSVerified, settings.SlackEnabled, settings.SlackWebhook,
		settings.SlackChannel, settings.WebhookEnabled, settings.WebhookURL,
		settings.WebhookMethod,
	)
	if err != nil {
		return nil, err
	}

	return settings, nil
}

// UpdateNotificationSettings updates notification settings for a user
func (s *NotificationStore) UpdateNotificationSettings(userID string, settings *UpdateNotificationSettingsRequest) error {
	query := `
		UPDATE notification_settings 
		SET email_enabled = ?, email_address = ?, sms_enabled = ?, sms_number = ?,
		    slack_enabled = ?, slack_webhook = ?, slack_channel = ?,
		    webhook_enabled = ?, webhook_url = ?, webhook_method = ?,
		    updated = CURRENT_TIMESTAMP
		WHERE user_id = ?
	`

	_, err := s.db.Exec(query,
		settings.EmailEnabled, settings.EmailAddress, settings.SMSEnabled,
		settings.SMSNumber, settings.SlackEnabled, settings.SlackWebhook,
		settings.SlackChannel, settings.WebhookEnabled, settings.WebhookURL,
		settings.WebhookMethod, userID,
	)

	return err
}

// Utility function to generate unique IDs
func generateID(prefix string) string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(bytes))
}

// Demo data initialization functions

func (s *AlertStore) CreateDemoAlert(alert *Alert) error {
	return s.CreateAlert(alert)
}

func (s *NotificationStore) CreateDemoNotificationSettings(settings *NotificationSettings) error {
	query := `
		INSERT OR REPLACE INTO notification_settings 
		(id, user_id, email_enabled, email_address, email_verified, 
		 sms_enabled, sms_number, sms_verified, slack_enabled, 
		 slack_webhook, slack_channel, webhook_enabled, webhook_url, 
		 webhook_method, updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query,
		settings.ID, settings.UserID, settings.EmailEnabled, settings.EmailAddress,
		settings.EmailVerified, settings.SMSEnabled, settings.SMSNumber,
		settings.SMSVerified, settings.SlackEnabled, settings.SlackWebhook,
		settings.SlackChannel, settings.WebhookEnabled, settings.WebhookURL,
		settings.WebhookMethod, settings.Updated,
	)

	return err
}
