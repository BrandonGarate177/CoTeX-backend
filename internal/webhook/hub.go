// Package webhook provides functionality for WebSocket communication
package webhook

import (
	"sync"
)

// Hub maintains the set of active clients and broadcasts messages to the clients
type Hub struct {
	// Registered clients by user ID
	clientsByUser map[string]map[*Client]bool

	// Inbound messages from the clients
	broadcast chan *Message

	// Register requests from the clients
	register chan *Client

	// Unregister requests from clients
	unregister chan *Client

	// Mutex for thread-safe map operations
	mu sync.RWMutex
}

// NewHub creates a new Hub instance
func NewHub() *Hub {
	return &Hub{
		broadcast:     make(chan *Message),
		register:      make(chan *Client),
		unregister:    make(chan *Client),
		clientsByUser: make(map[string]map[*Client]bool),
		mu:            sync.RWMutex{},
	}
}

// Run starts the hub
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			// Initialize user's client map if it doesn't exist
			if _, ok := h.clientsByUser[client.UserID]; !ok {
				h.clientsByUser[client.UserID] = make(map[*Client]bool)
			}
			// Add the client to the user's map
			h.clientsByUser[client.UserID][client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			// Remove client from the user's map if it exists
			if clients, ok := h.clientsByUser[client.UserID]; ok {
				if _, ok := clients[client]; ok {
					delete(clients, client)
					close(client.send)

					// If this was the last client for this user, clean up
					if len(clients) == 0 {
						delete(h.clientsByUser, client.UserID)
					}
				}
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			// If targetUserID is specified, send only to that user's clients
			// Otherwise, broadcast to all clients (only used for admin/system messages)
			h.mu.RLock()

			if message.TargetUserID != "" {
				// User-specific broadcast
				if clients, ok := h.clientsByUser[message.TargetUserID]; ok {
					for client := range clients {
						select {
						case client.send <- message:
						default:
							close(client.send)
							delete(clients, client)

							// If this was the last client for this user, clean up
							if len(clients) == 0 {
								delete(h.clientsByUser, message.TargetUserID)
							}
						}
					}
				}
			} else {
				// System-wide broadcast (admin only)
				for userID, clients := range h.clientsByUser {
					for client := range clients {
						select {
						case client.send <- message:
						default:
							close(client.send)
							delete(clients, client)

							// If this was the last client for this user, clean up
							if len(clients) == 0 {
								delete(h.clientsByUser, userID)
							}
						}
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}

// BroadcastToUser sends a message to a specific user's clients
func (h *Hub) BroadcastToUser(userID string, message *Message) {
	message.TargetUserID = userID
	h.broadcast <- message
}

// BroadcastToAll sends a message to all connected clients (admin only)
func (h *Hub) BroadcastToAll(message *Message) {
	h.broadcast <- message
}
