package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"agentide/core"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// EventType classifies the kind of message sent to the dashboard.
type EventType string

const (
	EventFingerprint       EventType = "fingerprint"
	EventDiscovery         EventType = "discovery"
	EventPassiveAlert      EventType = "passive_alert"
	EventTamper            EventType = "tamper_event" // Agent was killed and recovered
	EventModuleStart       EventType = "module_start"
	EventModuleResult      EventType = "module_result"
	EventAssessmentDone    EventType = "assessment_done"
	EventHeartbeat         EventType = "heartbeat"
	EventPreScanResult     EventType = "pre_scan_result"  // Sent before assessment: list of discovered agents
	EventAssessmentReady   EventType = "assessment_ready" // Sent after vendor disabled, assessment is starting
	EventReportStatus      EventType = "report_status"
	EventPreflightResult   EventType = "preflight_result"
	EventAssessmentResumed EventType = "assessment_resumed" // Agent was killed and resumed from checkpoint
	EventAssessmentAborted EventType = "assessment_aborted" // Auto-resume gave up after kill cap — operator must relaunch
	EventAssessmentStopped EventType = "assessment_stopped" // Operator requested a graceful stop
)

// Event is the standard envelope sent over the WebSocket connection.
type Event struct {
	Type      EventType   `json:"type"`
	AgentID   string      `json:"agent_id"` // Hostname of the endpoint
	Timestamp string      `json:"timestamp"`
	Payload   interface{} `json:"payload"`
}

// Client manages a persistent, auto-reconnecting WebSocket connection
// to the AgentIde Central Dashboard.
type Client struct {
	urls       []string
	agentID    string
	agentToken string
	certPin    string
	logger     *core.Logger
	conn       *websocket.Conn
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	queue      chan Event
	connected  bool
	// CommandCh receives parsed commands from the dashboard (e.g. start_assessment).
	CommandCh chan map[string]interface{}
	// lastFingerprint is the most recent fingerprint payload. It is re-sent on
	// every (re)connect because the dashboard only offers a self-update in
	// response to a fingerprint message — sending it once at startup means a
	// newly published build is never offered after a reconnect.
	lastFingerprint interface{}
}

// NewClient builds a client that tries each dashboard URL in order until one
// connects, then keeps reconnecting with exponential backoff. Listing several
// comma-separated addresses (for example a host-only IP plus the Wi-Fi IP)
// lets a single install survive network changes. The token is appended to each
// URL, and the /agent path is added automatically when missing.
func NewClient(dashboardURL, agentID, agentToken, certPin string, logger *core.Logger) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		urls:       parseDashboardURLs(dashboardURL, agentToken, agentID),
		agentID:    agentID,
		agentToken: agentToken,
		certPin:    certPin,
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
		queue:      make(chan Event, 256),
		CommandCh:  make(chan map[string]interface{}, 16),
	}
}

// parseDashboardURLs turns a comma-separated list of dashboard addresses into
// ready-to-dial WebSocket URLs. Each address has the /agent path appended when
// missing, and the auth token plus the agent's identity attached as query
// parameters. The agent_id lets the dashboard register the socket at connect
// time so commands (restart, update, assessment) can be routed to a
// reconnecting agent before it has re-sent its fingerprint.
func parseDashboardURLs(raw, token, agentID string) []string {
	var urls []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.HasSuffix(part, "/agent") {
			part = strings.TrimRight(part, "/") + "/agent"
		}
		q := neturl.Values{}
		if token != "" {
			q.Set("token", token)
		}
		if agentID != "" {
			q.Set("agent_id", agentID)
		}
		if len(q) > 0 {
			part += "?" + q.Encode()
		}
		urls = append(urls, part)
	}
	return urls
}

// redactURL strips the query string so auth tokens are never written to logs.
func redactURL(raw string) string {
	if i := strings.Index(raw, "?"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// Connect establishes the WebSocket connection and starts the send loop.
// It returns immediately — reconnection is handled automatically in the background.
func (c *Client) Connect() {
	go c.connectLoop()
	go c.sendLoop()
}

// Disconnect gracefully closes the connection and stops all goroutines.
func (c *Client) Disconnect() {
	c.cancel()
	c.mu.Lock()
	if c.conn != nil {
		_ = c.conn.Close(websocket.StatusNormalClosure, "AgentIde shutting down")
	}
	c.mu.Unlock()
}

// Send enqueues an event to be sent to the dashboard.
// It is non-blocking — events are buffered and sent asynchronously.
// If the dashboard is not connected, events are held in the buffer
// and flushed when the connection is restored.
func (c *Client) Send(eventType EventType, payload interface{}) {
	ev := Event{
		Type:      eventType,
		AgentID:   c.agentID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Payload:   payload,
	}
	select {
	case c.queue <- ev:
	default:
		// Buffer full — drop oldest event and try again
		select {
		case <-c.queue:
		default:
		}
		c.queue <- ev
	}
}

// IsConnected returns true if the client currently has an active connection.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// connectLoop maintains a persistent connection with exponential backoff.
// Each round it tries the configured dashboard URLs in order and keeps the
// first one that connects, so a single install can survive subnet changes.
func (c *Client) connectLoop() {
	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	// A connection shorter than this is treated as a flap rather than a
	// healthy session, and triggers the backoff above.
	const flapThreshold = 15 * time.Second

	// Allow self-signed certificates for POC/internal deployments. When a cert
	// pin is configured, the peer certificate's SPKI SHA-256 must match instead
	// of trusting everything.
	tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	if c.certPin != "" {
		tlsConfig.VerifyPeerCertificate = verifyPinnedCertificate(c.certPin)
	}
	opts := &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		var conn *websocket.Conn
		var lastErr error
		for _, url := range c.urls {
			select {
			case <-c.ctx.Done():
				return
			default:
			}

			c.logger.Info("Transport: connecting to dashboard", map[string]interface{}{
				"url": redactURL(url),
			})
			dialed, _, err := websocket.Dial(c.ctx, url, opts)
			if err != nil {
				lastErr = err
				c.logger.Warn("Transport: connection attempt failed", map[string]interface{}{
					"url":   redactURL(url),
					"error": err.Error(),
				})
				continue
			}
			conn = dialed
			break
		}

		if conn == nil {
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()

			fields := map[string]interface{}{"backoff": backoff.String()}
			if lastErr != nil {
				fields["error"] = lastErr.Error()
			}
			c.logger.Warn("Transport: all dashboard addresses unreachable, retrying", fields)

			select {
			case <-c.ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		c.mu.Lock()
		c.conn = conn
		c.connected = true
		c.mu.Unlock()

		connectedAt := time.Now()
		c.logger.Info("Transport: connected to dashboard — agent is reporting", nil)

		// Re-announce the endpoint on every connect. The dashboard replies to a
		// fingerprint with an update command when it has a newer build, so a
		// reconnect after a long uptime is how an agent picks up a release that
		// was published while it was already running.
		c.mu.Lock()
		fp := c.lastFingerprint
		c.mu.Unlock()
		if fp != nil {
			c.Send(EventFingerprint, fp)
		}

		// Block until connection drops
		c.readLoop(conn)

		c.mu.Lock()
		c.connected = false
		c.conn = nil
		c.mu.Unlock()

		c.logger.Warn("Transport: connection lost, reconnecting...", map[string]interface{}{
			"connected_for": time.Since(connectedAt).Truncate(time.Millisecond).String(),
		})

		// Flap backoff. A connection that drops almost immediately means the
		// dashboard is rejecting us repeatedly — most often because a second
		// process for this host is registered under the same agent_id, and each
		// registration evicts the other's socket. Re-dialing instantly turns
		// that into a livelock: both agents evict each other forever, hammering
		// the dashboard hundreds of times a second and never settling on a
		// usable socket. Backing off lets the last registration win and stay.
		if time.Since(connectedAt) < flapThreshold {
			c.logger.Warn("Transport: connection dropped immediately, backing off", map[string]interface{}{
				"backoff": backoff.String(),
			})
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// A connection that stayed up long enough is genuinely healthy, so the
		// next failure starts from the base delay again.
		backoff = 2 * time.Second
	}
}

// WaitForConnection blocks until the client reports a live connection or the
// timeout elapses. It lets callers (e.g. -check and install-time diagnostics)
// confirm the dashboard is actually reachable before declaring success.
func WaitForConnection(s Sender, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.IsConnected() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return s.IsConnected()
}

// readLoop reads incoming messages from the dashboard and dispatches commands.
func (c *Client) readLoop(conn *websocket.Conn) {
	for {
		var raw map[string]interface{}
		if err := wsjson.Read(c.ctx, conn, &raw); err != nil {
			return // Connection closed or context cancelled
		}
		msgType, _ := raw["type"].(string)
		c.logger.Debug("Transport: received command from dashboard", map[string]interface{}{
			"type": msgType,
		})
		// Forward all dashboard commands to the command channel (non-blocking)
		select {
		case c.CommandCh <- raw:
		default:
			c.logger.Warn("Transport: command channel full, dropping command", nil)
		}
	}
}

// sendLoop drains the event queue and sends events to the dashboard.
func (c *Client) sendLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case ev := <-c.queue:
			c.mu.Lock()
			conn := c.conn
			connected := c.connected
			c.mu.Unlock()

			if !connected || conn == nil {
				// Re-queue the event (best-effort) and wait briefly
				select {
				case c.queue <- ev:
				default:
				}
				time.Sleep(500 * time.Millisecond)
				continue
			}

			if err := wsjson.Write(c.ctx, conn, ev); err != nil {
				c.logger.Warn("Transport: send failed", map[string]interface{}{
					"error": err.Error(),
					"type":  string(ev.Type),
				})
				// Re-queue for retry
				select {
				case c.queue <- ev:
				default:
				}
			}
		}
	}
}

// verifyPinnedCertificate returns a verification callback that accepts
// only certificates whose SubjectPublicKeyInfo SHA-256 matches pin
// (hex-encoded). Used instead of full chain verification for POC
// deployments that want MITM protection without a PKI.
func verifyPinnedCertificate(pin string) func([][]byte, [][]*x509.Certificate) error {
	want := strings.ToLower(strings.TrimSpace(pin))
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no peer certificate presented")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer certificate: %w", err)
		}
		spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		got := hex.EncodeToString(spki[:])
		if got != want {
			return fmt.Errorf("certificate pin mismatch: expected %s, got %s", want, got)
		}
		return nil
	}
}

// startHeartbeat sends a heartbeat ping to the dashboard every 30 seconds.
// This lets the dashboard know the agent is alive even when no tests are running.
func (c *Client) StartHeartbeat() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.Send(EventHeartbeat, map[string]interface{}{
					"status": "alive",
				})
			}
		}
	}()
}

// SendFingerprint is a convenience method to send the endpoint fingerprint on startup.
// The payload is remembered and replayed on every reconnect, because the
// dashboard only advertises a self-update in response to a fingerprint.
func (c *Client) SendFingerprint(fp interface{}) {
	c.mu.Lock()
	c.lastFingerprint = fp
	c.mu.Unlock()
	c.Send(EventFingerprint, fp)
}

// SendDiscovery sends the list of discovered security agents to the dashboard.
func (c *Client) SendDiscovery(agents interface{}) {
	c.Send(EventDiscovery, agents)
}

// SendPassiveAlert notifies the dashboard that a new agent installation was detected.
func (c *Client) SendPassiveAlert(details interface{}) {
	c.Send(EventPassiveAlert, details)
}

// SendModuleResult sends a single test result to the dashboard in real-time.
func (c *Client) SendModuleResult(result interface{}) {
	c.Send(EventModuleResult, result)
}

// SendAssessmentDone notifies the dashboard the assessment is complete and includes the final summary.
func (c *Client) SendAssessmentDone(summary interface{}) {
	c.Send(EventAssessmentDone, summary)
}

// SendTamperEvent reports that the agent was externally killed and has recovered.
// This is key assessment data — it shows what the EDR was able to block/remove.
func (c *Client) SendTamperEvent(event interface{}) {
	c.Send(EventTamper, event)
}

// NoopClient is a transport client that does nothing — used when no dashboard URL is configured.
// This allows the agent to run in standalone CLI mode without any dashboard.
type NoopClient struct{}

func NewNoopClient() *NoopClient { return &NoopClient{} }

func (n *NoopClient) Connect()                         {}
func (n *NoopClient) Disconnect()                      {}
func (n *NoopClient) IsConnected() bool                { return false }
func (n *NoopClient) StartHeartbeat()                  {}
func (n *NoopClient) Send(_ EventType, _ interface{})  {}
func (n *NoopClient) SendFingerprint(_ interface{})    {}
func (n *NoopClient) SendDiscovery(_ interface{})      {}
func (n *NoopClient) SendPassiveAlert(_ interface{})   {}
func (n *NoopClient) SendTamperEvent(_ interface{})    {}
func (n *NoopClient) SendModuleResult(_ interface{})   {}
func (n *NoopClient) SendAssessmentDone(_ interface{}) {}
func (n *NoopClient) Commands() <-chan map[string]interface{} {
	return make(chan map[string]interface{}) // never receives anything
}

// Commands returns the read-only channel of incoming dashboard commands.
func (c *Client) Commands() <-chan map[string]interface{} {
	return c.CommandCh
}

// Sender is the interface both Client and NoopClient satisfy.
// This lets main.go use either transparently.
type Sender interface {
	Connect()
	Disconnect()
	IsConnected() bool
	StartHeartbeat()
	Send(EventType, interface{})
	SendFingerprint(interface{})
	SendDiscovery(interface{})
	SendPassiveAlert(interface{})
	SendTamperEvent(interface{})
	SendModuleResult(interface{})
	SendAssessmentDone(interface{})
	Commands() <-chan map[string]interface{}
}

// NewSender returns a real Client if a dashboard URL is configured,
// or a NoopClient if no URL is set (standalone mode).
func NewSender(dashboardURL, agentID, agentToken, certPin string, logger *core.Logger) Sender {
	if dashboardURL == "" {
		fmt.Println("[TRANSPORT] No dashboard URL configured — running in standalone mode")
		return NewNoopClient()
	}
	return NewClient(dashboardURL, agentID, agentToken, certPin, logger)
}
