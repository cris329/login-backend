// Traduce el JSON del navegador a una llamada del servicio y responde en español.
package controller

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/cris329/login/model"
	"github.com/cris329/login/repository"
	"github.com/cris329/login/service"
)

// Handler une cada ruta con App.
type Handler struct{ App service.App }

// Register crea la cuenta. Responde ok cuando quedó guardada.
func (h Handler) Register(c *gin.Context) {
	var body model.Register
	if !bind(c, &body, http.StatusBadRequest, "solicitud invalida") {
		return
	}
	if err := h.App.Register(c.Request.Context(), body); err != nil {
		write(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"ok": true})
}

// Login devuelve el token cifrado. No devuelve nombre, correo ni identificación.
func (h Handler) Login(c *gin.Context) {
	var body model.Login
	if !bind(c, &body, http.StatusBadRequest, "solicitud invalida") {
		return
	}
	token, err := h.App.Login(c.Request.Context(), body)
	sendToken(c, token, err)
}

// Recover envía el código y el tiempo de espera para pedir otro.
func (h Handler) Recover(c *gin.Context) {
	var body model.Recover
	if !bind(c, &body, http.StatusBadRequest, "no se pudo enviar el codigo") {
		return
	}
	wait, err := h.App.Recover(c.Request.Context(), body)
	if err != nil {
		write(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"ok": true, "wait": wait})
}

// Reset guarda la contraseña nueva si el código sigue vigente.
func (h Handler) Reset(c *gin.Context) {
	var body model.Reset
	if !bind(c, &body, http.StatusUnauthorized, "codigo invalido") {
		return
	}
	if err := h.App.Reset(c.Request.Context(), body); err != nil {
		write(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Renew renueva el token mientras la pantalla de sesión sigue abierta.
func (h Handler) Renew(c *gin.Context) {
	token, err := h.App.Renew(c.Request.Context(), c.GetHeader("Authorization"))
	sendToken(c, token, err)
}

func bind(c *gin.Context, body any, status int, message string) bool {
	if c.ShouldBindJSON(body) == nil {
		return true
	}
	c.AbortWithStatusJSON(status, gin.H{"error": message})
	return false
}

func sendToken(c *gin.Context, token string, err error) {
	if err != nil {
		write(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// write elige el estado HTTP según el error que devolvió el servicio.
func write(c *gin.Context, err error) {
	var wait service.WaitError
	if errors.As(err, &wait) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": wait.Error(), "wait": wait.Seconds})
		return
	}
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, service.ErrCredentials), errors.Is(err, service.ErrCode), errors.Is(err, service.ErrCodeGone), errors.Is(err, service.ErrPassword), errors.Is(err, service.ErrSession):
		status = http.StatusUnauthorized
	case errors.Is(err, repository.ErrIDTaken):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "esa identificacion ya esta registrada"})
		return
	case errors.Is(err, service.ErrInternal):
		status = http.StatusInternalServerError
	case errors.Is(err, service.ErrTwilio):
		status = http.StatusServiceUnavailable
	case errors.Is(err, service.ErrMailConfig), errors.Is(err, service.ErrDeliver):
		status = http.StatusBadGateway
	}
	c.AbortWithStatusJSON(status, gin.H{"error": err.Error()})
}
