package stripe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/brandon/cotex-backend/internal/database"
	"github.com/brandon/cotex-backend/internal/logger"
	"github.com/rs/zerolog"
	"github.com/stripe/stripe-go/v78"
	"github.com/stripe/stripe-go/v78/checkout/session"
	"github.com/stripe/stripe-go/v78/customer"
	"github.com/stripe/stripe-go/v78/webhook"
)

// Service handles Stripe operations
type Service struct {
	db            database.Store
	webhookSecret string
	priceID       string
	log           zerolog.Logger
}

// NewService creates a new Stripe service
func NewService(db database.Store, webhookSecret, priceID string) *Service {
	return &Service{
		db:            db,
		webhookSecret: webhookSecret,
		priceID:       priceID,
		log:           logger.Logger(map[string]interface{}{"component": "stripe"}),
	}
}

// CreateCheckoutSession creates a Stripe checkout session for upgrading to pro
func (s *Service) CreateCheckoutSession(userID, userEmail string) (*stripe.CheckoutSession, error) {
	// Get or create Stripe customer
	customer, err := s.getOrCreateCustomer(userID, userEmail)
	if err != nil {
		s.log.Error().Err(err).Str("user_id", userID).Msg("Failed to get or create Stripe customer")
		return nil, fmt.Errorf("failed to get or create customer: %w", err)
	}

	// Create checkout session with subscription mode
	params := &stripe.CheckoutSessionParams{
		Customer: stripe.String(customer.ID),
		PaymentMethodTypes: stripe.StringSlice([]string{
			"card",
		}),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(s.priceID),
				Quantity: stripe.Int64(1),
			},
		},
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)), // Subscription mode
		SuccessURL: stripe.String("https://cotex-md.netlify.app/"),
		CancelURL:  stripe.String("https://cotex-md.netlify.app/download"),
		Metadata: map[string]string{
			"user_id": userID,
		},
	}

	session, err := session.New(params)
	if err != nil {
		s.log.Error().Err(err).Str("user_id", userID).Msg("Failed to create checkout session")
		return nil, fmt.Errorf("failed to create checkout session: %w", err)
	}

	s.log.Info().
		Str("user_id", userID).
		Str("session_id", session.ID).
		Msg("Created checkout session")

	return session, nil
}

// HandleWebhook processes Stripe webhook events
func (s *Service) HandleWebhook(r *http.Request) error {
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to read webhook payload")
		return fmt.Errorf("failed to read payload: %w", err)
	}

	signature := r.Header.Get("Stripe-Signature")
	if signature == "" {
		s.log.Error().Msg("Missing Stripe-Signature header")
		return fmt.Errorf("missing signature")
	}

	event, err := webhook.ConstructEventWithOptions(payload, signature, s.webhookSecret, webhook.ConstructEventOptions{
		IgnoreAPIVersionMismatch: true,
	})
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to construct webhook event")
		return fmt.Errorf("failed to construct webhook event: %w", err)
	}

	s.log.Info().
		Str("event_type", string(event.Type)).
		Str("event_id", event.ID).
		Msg("Processing Stripe webhook event")

	// Log shape information for debugging
	s.logShapeInfo(event)

	switch event.Type {
	case "checkout.session.completed":
		return s.handleCheckoutSessionCompleted(event)
	case "checkout.session.async_payment_succeeded":
		return s.handleCheckoutSessionAsyncPaymentSucceeded(event)
	case "checkout.session.async_payment_failed":
		return s.handleCheckoutSessionAsyncPaymentFailed(event)
	case "checkout.session.expired":
		return s.handleCheckoutSessionExpired(event)
	case "customer.subscription.updated":
		return s.handleSubscriptionUpdated(event)
	case "customer.subscription.deleted":
		return s.handleSubscriptionDeleted(event)
	default:
		s.log.Info().
			Str("event_type", string(event.Type)).
			Msg("Unhandled event type")
	}

	return nil
}

// handleCheckoutSessionCompleted processes successful checkout sessions
func (s *Service) handleCheckoutSessionCompleted(event stripe.Event) error {
	var cs stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &cs); err != nil {
		return fmt.Errorf("failed to unmarshal session: %w", err)
	}

	userID := cs.Metadata["user_id"]
	if userID == "" {
		return fmt.Errorf("no user_id in session metadata")
	}

	// ----- Get customer ID safely -----
	customerID := ""
	if cs.Customer != nil && cs.Customer.ID != "" {
		customerID = cs.Customer.ID
	}
	if customerID == "" {
		// Basil guarantees a customer on a successful sub flow, so log loudly
		s.log.Error().Interface("session", cs).Msg("Missing customer id on checkout.session.completed")
		return fmt.Errorf("missing customer id")
	}

	// ----- Get subscription ID safely -----
	subscriptionID := ""
	if cs.Subscription != nil && cs.Subscription.ID != "" {
		subscriptionID = cs.Subscription.ID
	}

	// Mark user as pro
	if err := s.db.UpdateUserSubscription(userID, database.ProTier); err != nil {
		return fmt.Errorf("failed to upgrade user: %w", err)
	}

	// Save Stripe info
	if err := s.db.UpdateUserStripeInfo(userID, customerID, subscriptionID, "active"); err != nil {
		return fmt.Errorf("failed to save Stripe info: %w", err)
	}

	s.log.Info().
		Str("user_id", userID).
		Str("session_id", cs.ID).
		Str("customer_id", customerID).
		Str("subscription_id", subscriptionID).
		Msg("Successfully upgraded user to pro")
	return nil
}

// handleSubscriptionUpdated processes subscription updates
func (s *Service) handleSubscriptionUpdated(event stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return fmt.Errorf("failed to unmarshal subscription: %w", err)
	}

	userID := sub.Metadata["user_id"]
	if userID == "" {
		s.log.Error().Str("subscription_id", sub.ID).Msg("No user_id in subscription metadata")
		return fmt.Errorf("no user_id in subscription metadata")
	}

	// ----- Get customer ID safely -----
	customerID := ""
	if sub.Customer != nil && sub.Customer.ID != "" {
		customerID = sub.Customer.ID
	}

	// Update user subscription status based on subscription status
	switch sub.Status {
	case stripe.SubscriptionStatusActive:
		if err := s.db.UpdateUserSubscription(userID, database.ProTier); err != nil {
			s.log.Error().
				Err(err).
				Str("user_id", userID).
				Str("subscription_id", sub.ID).
				Msg("Failed to upgrade user to pro")
			return fmt.Errorf("failed to upgrade user: %w", err)
		}
		// Update Stripe status
		if err := s.db.UpdateUserStripeInfo(userID, customerID, sub.ID, "active"); err != nil {
			s.log.Error().
				Err(err).
				Str("user_id", userID).
				Str("subscription_id", sub.ID).
				Msg("Failed to update Stripe status")
		}
	case stripe.SubscriptionStatusCanceled, stripe.SubscriptionStatusUnpaid, stripe.SubscriptionStatusPastDue:
		if err := s.db.UpdateUserSubscription(userID, database.FreeTier); err != nil {
			s.log.Error().
				Err(err).
				Str("user_id", userID).
				Str("subscription_id", sub.ID).
				Msg("Failed to downgrade user to free")
			return fmt.Errorf("failed to downgrade user: %w", err)
		}
		// Update Stripe status
		if err := s.db.UpdateUserStripeInfo(userID, customerID, sub.ID, string(sub.Status)); err != nil {
			s.log.Error().
				Err(err).
				Str("user_id", userID).
				Str("subscription_id", sub.ID).
				Msg("Failed to update Stripe status")
		}
	}

	s.log.Info().
		Str("user_id", userID).
		Str("subscription_id", sub.ID).
		Str("status", string(sub.Status)).
		Msg("Updated user subscription status")

	return nil
}

// handleSubscriptionDeleted processes subscription cancellations
func (s *Service) handleSubscriptionDeleted(event stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return fmt.Errorf("failed to unmarshal subscription: %w", err)
	}

	userID := sub.Metadata["user_id"]
	if userID == "" {
		s.log.Error().Str("subscription_id", sub.ID).Msg("No user_id in subscription metadata")
		return fmt.Errorf("no user_id in subscription metadata")
	}

	// ----- Get customer ID safely -----
	customerID := ""
	if sub.Customer != nil && sub.Customer.ID != "" {
		customerID = sub.Customer.ID
	}

	// Downgrade user to free
	if err := s.db.UpdateUserSubscription(userID, database.FreeTier); err != nil {
		s.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("subscription_id", sub.ID).
			Msg("Failed to downgrade user to free")
		return fmt.Errorf("failed to downgrade user: %w", err)
	}

	// Update Stripe status
	if err := s.db.UpdateUserStripeInfo(userID, customerID, sub.ID, "canceled"); err != nil {
		s.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("subscription_id", sub.ID).
			Msg("Failed to update Stripe status")
	}

	s.log.Info().
		Str("user_id", userID).
		Str("subscription_id", sub.ID).
		Msg("Successfully downgraded user to free")

	return nil
}

// handleCheckoutSessionAsyncPaymentSucceeded processes successful async payments
func (s *Service) handleCheckoutSessionAsyncPaymentSucceeded(event stripe.Event) error {
	var cs stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &cs); err != nil {
		return fmt.Errorf("failed to unmarshal session: %w", err)
	}

	userID := cs.Metadata["user_id"]
	if userID == "" {
		s.log.Error().Str("session_id", cs.ID).Msg("No user_id in session metadata")
		return fmt.Errorf("no user_id in session metadata")
	}

	// ----- Get customer ID safely -----
	customerID := ""
	if cs.Customer != nil && cs.Customer.ID != "" {
		customerID = cs.Customer.ID
	}

	// ----- Get subscription ID safely -----
	subscriptionID := ""
	if cs.Subscription != nil && cs.Subscription.ID != "" {
		subscriptionID = cs.Subscription.ID
	}

	// Ensure user is marked as pro (in case they weren't already)
	if err := s.db.UpdateUserSubscription(userID, database.ProTier); err != nil {
		s.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("session_id", cs.ID).
			Msg("Failed to upgrade user to pro after async payment success")
		return fmt.Errorf("failed to upgrade user: %w", err)
	}

	// Update Stripe status to active
	if err := s.db.UpdateUserStripeInfo(userID, customerID, subscriptionID, "active"); err != nil {
		s.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("session_id", cs.ID).
			Msg("Failed to update Stripe status after async payment success")
	}

	s.log.Info().
		Str("user_id", userID).
		Str("session_id", cs.ID).
		Msg("Async payment succeeded, user confirmed as pro")

	return nil
}

// handleCheckoutSessionAsyncPaymentFailed processes failed async payments
func (s *Service) handleCheckoutSessionAsyncPaymentFailed(event stripe.Event) error {
	var cs stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &cs); err != nil {
		return fmt.Errorf("failed to unmarshal session: %w", err)
	}

	userID := cs.Metadata["user_id"]
	if userID == "" {
		s.log.Error().Str("session_id", cs.ID).Msg("No user_id in session metadata")
		return fmt.Errorf("no user_id in session metadata")
	}

	// ----- Get customer ID safely -----
	customerID := ""
	if cs.Customer != nil && cs.Customer.ID != "" {
		customerID = cs.Customer.ID
	}

	// ----- Get subscription ID safely -----
	subscriptionID := ""
	if cs.Subscription != nil && cs.Subscription.ID != "" {
		subscriptionID = cs.Subscription.ID
	}

	// Downgrade user to free since payment failed
	if err := s.db.UpdateUserSubscription(userID, database.FreeTier); err != nil {
		s.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("session_id", cs.ID).
			Msg("Failed to downgrade user to free after async payment failure")
		return fmt.Errorf("failed to downgrade user: %w", err)
	}

	// Update Stripe status to failed
	if err := s.db.UpdateUserStripeInfo(userID, customerID, subscriptionID, "failed"); err != nil {
		s.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("session_id", cs.ID).
			Msg("Failed to update Stripe status after async payment failure")
	}

	s.log.Info().
		Str("user_id", userID).
		Str("session_id", cs.ID).
		Msg("Async payment failed, user downgraded to free")

	return nil
}

// handleCheckoutSessionExpired processes expired checkout sessions
func (s *Service) handleCheckoutSessionExpired(event stripe.Event) error {
	var session stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
		return fmt.Errorf("failed to unmarshal session: %w", err)
	}

	userID := session.Metadata["user_id"]
	if userID == "" {
		s.log.Error().Str("session_id", session.ID).Msg("No user_id in session metadata")
		return fmt.Errorf("no user_id in session metadata")
	}

	// Log the expired session - no action needed as user never completed payment
	s.log.Info().
		Str("user_id", userID).
		Str("session_id", session.ID).
		Msg("Checkout session expired - no action taken")

	return nil
}

// getOrCreateCustomer finds an existing customer or creates a new one
func (s *Service) getOrCreateCustomer(userID, userEmail string) (*stripe.Customer, error) {
	// First, try to find existing customer by email
	params := &stripe.CustomerListParams{}
	params.Filters.AddFilter("email", "", userEmail)
	params.Limit = stripe.Int64(1)

	iter := customer.List(params)

	// Check if we found any customers
	if iter.Next() {
		existingCustomer := iter.Customer()
		s.log.Info().
			Str("user_id", userID).
			Str("customer_id", existingCustomer.ID).
			Str("email", userEmail).
			Msg("Found existing Stripe customer")
		return existingCustomer, nil
	}

	// Check for errors
	if err := iter.Err(); err != nil {
		s.log.Error().Err(err).Str("user_id", userID).Str("email", userEmail).Msg("Failed to search for existing customer")
		return nil, fmt.Errorf("failed to search for existing customer: %w", err)
	}

	// Create new customer if not found
	customerParams := &stripe.CustomerParams{
		Email: stripe.String(userEmail),
		Metadata: map[string]string{
			"user_id": userID,
		},
	}

	newCustomer, err := customer.New(customerParams)
	if err != nil {
		s.log.Error().Err(err).Str("user_id", userID).Str("email", userEmail).Msg("Failed to create new Stripe customer")
		return nil, fmt.Errorf("failed to create new customer: %w", err)
	}

	s.log.Info().
		Str("user_id", userID).
		Str("customer_id", newCustomer.ID).
		Str("email", userEmail).
		Msg("Created new Stripe customer")

	return newCustomer, nil
}

// logShapeInfo logs shape information for debugging webhook events
func (s *Service) logShapeInfo(event stripe.Event) {
	switch event.Type {
	case "checkout.session.completed", "checkout.session.async_payment_succeeded", "checkout.session.async_payment_failed":
		var cs stripe.CheckoutSession
		if err := json.Unmarshal(event.Data.Raw, &cs); err == nil {
			customerID := ""
			if cs.Customer != nil {
				customerID = cs.Customer.ID
			}
			subscriptionID := ""
			if cs.Subscription != nil {
				subscriptionID = cs.Subscription.ID
			}
			s.log.Debug().
				Str("event_type", string(event.Type)).
				Str("session_id", cs.ID).
				Str("customer_id", customerID).
				Str("subscription_id", subscriptionID).
				Bool("has_customer_object", cs.Customer != nil).
				Bool("has_subscription_object", cs.Subscription != nil).
				Msg("Checkout session shape info")
		}
	case "customer.subscription.updated", "customer.subscription.deleted":
		var sub stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &sub); err == nil {
			customerID := ""
			if sub.Customer != nil {
				customerID = sub.Customer.ID
			}
			s.log.Debug().
				Str("event_type", string(event.Type)).
				Str("subscription_id", sub.ID).
				Str("customer_id", customerID).
				Bool("has_customer_object", sub.Customer != nil).
				Msg("Subscription shape info")
		}
	}
}
