// Package webhook provides WebSocket communication functionality
package webhook

import (
	"net/http"
	"time"

	"github.com/brandon/cotex-backend/internal/logger"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 512 * 1024 // 512KB
)

// WebSocketUpgrader configures the WebSocket upgrader with proper security settings
type WebSocketUpgrader struct {
	upgrader websocket.Upgrader
	log      zerolog.Logger
}

// NewWebSocketUpgrader creates a new WebSocket upgrader with the specified allowed origins
func NewWebSocketUpgrader(allowedOrigins []string) *WebSocketUpgrader {
	return &WebSocketUpgrader{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")

				// Support wildcard allow-list
				wildcardAllowed := false
				for _, allowed := range allowedOrigins {
					if allowed == "*" {
						wildcardAllowed = true
						break
					}
				}

				// If origin header is missing, allow if wildcard is enabled
				if origin == "" {
					return wildcardAllowed
				}

				// Check if origin is in the allowed list or wildcard enabled
				if wildcardAllowed {
					return true
				}
				for _, allowed := range allowedOrigins {
					if origin == allowed {
						return true
					}
				}
				return false
			},
		},
		log: logger.Logger(map[string]interface{}{"component": "websocket"}),
	}
}

// Client is a middleman between the websocket connection and the hub
type Client struct {
	// The WebSocket hub
	hub *Hub

	// The WebSocket connection
	conn *websocket.Conn

	// Buffered channel of outbound messages
	send chan *Message

	// User ID associated with this connection
	UserID string

	// Logger instance with user context
	log zerolog.Logger
}

// readPump pumps messages from the websocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
		c.log.Debug().Msg("WebSocket connection closed")
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		var message Message
		err := c.conn.ReadJSON(&message)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.log.Error().Err(err).Msg("Unexpected WebSocket error")
			}
			break
		}

		// Set the message sender
		message.UserID = c.UserID

		c.log.Debug().
			Str("message_type", string(message.Type)).
			Msg("Received WebSocket message")

		// Only forward messages to the hub if needed
		// Most communication is one-way (server -> client)
		if message.Type == MessageTypeClientEvent {
			c.hub.broadcast <- &message
		}
	}
}

// writePump pumps messages from the hub to the websocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			err := c.conn.WriteJSON(message)
			if err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ServeWs handles websocket requests from clients
func (wu *WebSocketUpgrader) ServeWs(hub *Hub, w http.ResponseWriter, r *http.Request, userID string) {
	conn, err := wu.upgrader.Upgrade(w, r, nil)
	if err != nil {
		wu.log.Error().Err(err).Str("user_id", userID).Msg("Failed to upgrade WebSocket connection")
		return
	}

	// Create a client-specific logger
	clientLog := logger.WithUserID(userID)
	clientLog.Info().Msg("WebSocket connection established")

	// Create a new client with the user ID
	client := &Client{
		hub:    hub,
		conn:   conn,
		send:   make(chan *Message, 256),
		UserID: userID,
		log:    clientLog,
	}

	// Register the client with the hub
	client.hub.register <- client

	// Start the client's read and write pumps in separate goroutines
	go client.writePump()
	go client.readPump()
}
