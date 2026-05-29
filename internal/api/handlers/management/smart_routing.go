package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetSmartRoutingStatus returns the current smart-routing quota monitor state.
func (h *Handler) GetSmartRoutingStatus(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler unavailable"})
		return
	}

	h.mu.Lock()
	manager := h.authManager
	h.mu.Unlock()
	if manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	c.JSON(http.StatusOK, manager.SmartRoutingStatus())
}

// PostSmartRoutingProbe sends a manual probe to all available smart-routing auths.
func (h *Handler) PostSmartRoutingProbe(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler unavailable"})
		return
	}

	h.mu.Lock()
	manager := h.authManager
	h.mu.Unlock()
	if manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	c.JSON(http.StatusOK, manager.ProbeSmartRouting(c.Request.Context()))
}
