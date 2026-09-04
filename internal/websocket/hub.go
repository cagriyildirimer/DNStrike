package websocket

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type Hub struct{ 
	upgrader websocket.Upgrader
	clients  map[string]map[*websocket.Conn]bool
	mu       sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[string]map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024, CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		return err == nil && u.Host == r.Host
	}}}
}
func (h *Hub) Serve(c *gin.Context) {
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	h.mu.Lock()
	if h.clients[c.Param("id")] == nil {
		h.clients[c.Param("id")] = make(map[*websocket.Conn]bool)
	}
	h.clients[c.Param("id")][conn] = true
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients[c.Param("id")], conn)
		h.mu.Unlock()
		conn.Close()
	}()

	_ = conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(70 * time.Second)) })
	_ = conn.WriteJSON(gin.H{"type": "connected", "test_id": c.Param("id"), "timestamp": time.Now().UTC()})
	
	// Read loop to process client disconnects
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-ticker.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				return
			}
		}
	}
}

func (h *Hub) Broadcast(testID string, message []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	for conn := range h.clients[testID] {
		_ = conn.WriteMessage(websocket.TextMessage, message)
	}
}
