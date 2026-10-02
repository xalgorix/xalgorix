package web

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Reject cross-site WebSocket connections to prevent CSWSH attacks.
		// Allow if no Origin header (direct connection) or Origin matches Host.
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		// Parse origin and compare scheme+host with request Host
		if u, err := url.Parse(origin); err == nil {
			return u.Host == r.Host
		}
		return false
	},
	ReadBufferSize:  8192,
	WriteBufferSize: 32768,
}

const (
	// WebSocket keepalive settings
	wsPingInterval   = 30 * time.Second
	wsPongWait       = 60 * time.Second
	wsWriteWait      = 10 * time.Second
	wsMaxMessageSize = 8192 // max incoming message from client
	wsMaxClients     = 50
	wsSendBufSize    = 512 // buffered channel size per client
)

// wsClient wraps a WebSocket connection with a buffered send channel.
//
// Concurrency: instanceID is mutated by readPump (subscribe/unsubscribe)
// and read by broadcastToInstance / broadcastDashboard from other
// goroutines. ALL reads and writes MUST hold server.mu (RLock for reads,
// Lock for writes). The lock also guards iteration over server.clients,
// so an atomic.Pointer would be redundant and would split the invariant
// into two synchronization mechanisms.
type wsClient struct {
	conn       *websocket.Conn
	send       chan []byte
	server     *Server
	instanceID string // GUARDED BY server.mu — see struct doc.

	// authenticated is true when the WebSocket upgrade carried a valid
	// session cookie (or auth is disabled and the connection is from
	// loopback). Privileged scan-request fields like Model/APIKey/APIBase
	// are only honored for authenticated connections — otherwise a
	// client could pivot the LLM to an attacker-controlled endpoint.
	authenticated bool
	fromLoopback  bool
}

// writePump drains the send channel and writes to the WebSocket.
// Also handles periodic ping messages for keepalive.
func (c *wsClient) writePump() {
	ticker := time.NewTicker(wsPingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
		c.server.removeClient(c)
	}()

	for {
		select {
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if !ok {
				// Server closed the channel — send close frame
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump reads messages from the WebSocket (scan requests).
// Also sets up pong handler for keepalive.
func (c *wsClient) readPump() {
	defer func() {
		c.server.removeClient(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(wsMaxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
		return nil
	})

	// Single decode path. The previous "fast path" tried to detect
	// subscribe/unsubscribe via byte prefix, but it was order-dependent on
	// JSON field layout and would fall through unexpectedly. The combined
	// struct below handles all three message shapes in one Unmarshal.
	type wsInbound struct {
		Subscribe   string `json:"subscribe,omitempty"`
		Unsubscribe bool   `json:"unsubscribe,omitempty"`
		ScanRequest
	}

	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		var in wsInbound
		if err := json.Unmarshal(msg, &in); err != nil {
			continue
		}

		// Subscribe / unsubscribe to per-instance broadcasts.
		if in.Subscribe != "" {
			c.server.mu.Lock()
			c.instanceID = in.Subscribe
			c.server.mu.Unlock()
			continue
		}
		if in.Unsubscribe {
			c.server.mu.Lock()
			c.instanceID = ""
			c.server.mu.Unlock()
			continue
		}

		// Scan request.
		if len(in.Targets) == 0 {
			continue
		}
		normalizeScanRequestActivity(&in.ScanRequest)

		// Only authenticated (or loopback-when-auth-off) clients may override
		// LLM provider settings — otherwise an attacker could repoint the
		// agent's brain to an endpoint that returns crafted tool calls.
		scanCfg := *c.server.cfg // shallow copy
		if c.authenticated {
			if in.Model != "" {
				scanCfg.LLM = in.Model
			}
			if in.APIKey != "" {
				scanCfg.APIKey = in.APIKey
			}
			if in.APIBase != "" {
				scanCfg.APIBase = in.APIBase
			}
		} else if in.Model != "" || in.APIKey != "" || in.APIBase != "" {
			log.Printf("[ws] dropping LLM-provider overrides from unauthenticated client %s", c.conn.RemoteAddr())
		}

		go c.server.runMultiScan(in.ScanRequest, &scanCfg)
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Enforce max client limit
	s.mu.RLock()
	numClients := len(s.clients)
	s.mu.RUnlock()
	if numClients >= wsMaxClients {
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}

	// Capture authentication state at upgrade time. authMiddleware has
	// already validated the cookie for us when auth is configured —
	// reaching this handler proves the cookie was valid. When auth is
	// off, only loopback clients get the "authenticated" capability so
	// the agent's brain can't be repointed from off-box.
	ip := clientIP(r)
	loopback := ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
	authed := false
	if authConfigured(s.cfg) {
		// authMiddleware accepted this request, so the session is valid.
		authed = true
	} else {
		authed = loopback
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	client := &wsClient{
		conn:          conn,
		send:          make(chan []byte, wsSendBufSize),
		server:        s,
		authenticated: authed,
		fromLoopback:  loopback,
	}

	s.mu.Lock()
	s.clients[client] = true
	s.mu.Unlock()

	// Start write pump in a goroutine
	go client.writePump()
	// Read pump runs in this goroutine (blocks until disconnect)
	client.readPump()
}

// removeClient safely removes a client from the server's client set.
func (s *Server) removeClient(c *wsClient) {
	s.mu.Lock()
	if _, ok := s.clients[c]; ok {
		delete(s.clients, c)
		close(c.send)
	}
	s.mu.Unlock()
}

func (s *Server) broadcast(evt WSEvent) {
	evt = withEventTimestamp(evt)
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		select {
		case client.send <- data:
			// queued successfully
		default:
			// client send buffer full — drop the client
			log.Printf("WebSocket client send buffer full, dropping client")
			go func(c *wsClient) {
				s.removeClient(c)
				c.conn.Close()
			}(client)
		}
	}
}

// broadcastToInstance sends an event to clients subscribed to a specific instance
// and to dashboard clients without an instance subscription.
// Buffers events into the instance for replay.
func (s *Server) broadcastToInstance(instanceID string, evt WSEvent) {
	evt = withEventTimestamp(evt)
	if evt.InstanceID == "" {
		evt.InstanceID = instanceID
	}
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	// Buffer event into instance for replay (cap at 500)
	s.instancesMu.RLock()
	if inst, ok := s.instances[instanceID]; ok {
		inst.mu.Lock()
		if len(inst.events) < 500 {
			inst.events = append(inst.events, evt)
		} else {
			// Keep last 400, drop oldest
			inst.events = append(inst.events[100:], evt)
		}
		// Also buffer vulns
		if len(evt.Vulns) > 0 {
			for _, vuln := range evt.Vulns {
				applySummaryReplacement(&inst.Vulns, &vuln, metadataBool(evt.ResultMeta, "upgraded"))
				appendVulnSummaryUnique(&inst.Vulns, vuln)
			}
		}
		if evt.CurrentPhase > 0 {
			inst.CurrentPhase = evt.CurrentPhase
		}
		inst.mu.Unlock()
	}
	s.instancesMu.RUnlock()

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		if client.instanceID == "" || client.instanceID == instanceID {
			select {
			case client.send <- data:
			default:
				go func(c *wsClient) {
					s.removeClient(c)
					c.conn.Close()
				}(client)
			}
		}
	}
}

// notifyInstanceListeners delivers an event that is already present in the
// coherent instance snapshot. Unlike broadcastToInstance it never buffers the
// event again, preventing exact-stop retries from duplicating replay history.
func (s *Server) notifyInstanceListeners(instanceID string, evt WSEvent) {
	evt = withEventTimestamp(evt)
	if evt.InstanceID == "" {
		evt.InstanceID = instanceID
	}
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for client := range s.clients {
		if client.instanceID == "" || client.instanceID == instanceID {
			select {
			case client.send <- data:
			default:
				go func(c *wsClient) {
					s.removeClient(c)
					c.conn.Close()
				}(client)
			}
		}
	}
}

// broadcastDashboard sends an event only to dashboard clients (no instance subscription).
func (s *Server) broadcastDashboard(evt WSEvent) {
	evt = withEventTimestamp(evt)
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		if client.instanceID == "" {
			select {
			case client.send <- data:
			default:
				go func(c *wsClient) {
					s.removeClient(c)
					c.conn.Close()
				}(client)
			}
		}
	}
}

func withEventTimestamp(evt WSEvent) WSEvent {
	if strings.TrimSpace(evt.Timestamp) == "" {
		evt.Timestamp = time.Now().Format(time.RFC3339)
	}
	return evt
}
