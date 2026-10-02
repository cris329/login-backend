// Publica las rutas /api/v1 y permite las peticiones del frontend.
package router

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/cris329/login/controller"
)

// New arma el servidor. origin es el único front permitido, por ejemplo http://localhost:5500.
func New(handler controller.Handler, origin string) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	_ = engine.SetTrustedProxies(nil)
	engine.Use(gin.Recovery(), cors(origin))
	// /api/v1 es la ruta oficial. La otra queda porque la pantalla abierta aún la usa.
	routes(engine.Group("/api/v1"), handler)
	routes(engine, handler)
	return engine
}

func routes(group gin.IRoutes, handler controller.Handler) {
	group.POST("/registro", handler.Register)
	group.POST("/login", handler.Login)
	group.POST("/recuperar", handler.Recover)
	group.POST("/recuperar/codigo", handler.Reset)
	group.POST("/sesion", handler.Renew)
}

// cors acepta solo el origen del front. Cualquier otro se rechaza.
func cors(origin string) gin.HandlerFunc {
	origin = strings.TrimSpace(origin)
	return func(c *gin.Context) {
		if origin == "" || c.GetHeader("Origin") != origin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "origen no permitido"})
			return
		}
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Vary", "Origin")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
