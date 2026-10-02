// Cifra el token y envía el código. El login está en service.go.
// El token no muestra datos en jwt.io. El correo sale por Brevo y el SMS por Twilio.
package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var (
	ErrNotConfigured = errors.New("canal no configurado")
	ErrMailRejected  = errors.New("el correo rechazo el envio")
	ErrSMSRejected   = errors.New("twilio rechazo el sms")
	ErrExpired       = errors.New("codigo vencido")
	verifySIDExpr    = regexp.MustCompile(`VA[0-9a-fA-F]{32}`)
	verifyMu         sync.Mutex
	verifySID        string
)

// Issuer guarda la clave de 32 bytes y los minutos de inactividad.
type Issuer struct {
	key []byte
	ttl time.Duration
}

func NewToken(key []byte, ttl time.Duration) *Issuer {
	return &Issuer{key: append([]byte(nil), key...), ttl: ttl}
}

func (i *Issuer) Idle() time.Duration { return i.ttl }

// Issue crea el token. Solo mete el id, la hora y el vencimiento.
func (i *Issuer) Issue(userID string) (string, error) {
	now := time.Now()
	payload, err := json.Marshal(map[string]any{"sub": userID, "iat": now.Unix(), "exp": now.Add(i.ttl).Unix()})
	if err != nil {
		return "", err
	}
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: i.key}, (&jose.EncrypterOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	object, err := enc.Encrypt(payload)
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}

// Read abre el token y devuelve el id. Si venció, falla.
func (i *Issuer) Read(compact string) (string, error) {
	object, err := jose.ParseEncrypted(compact, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return "", err
	}
	raw, err := object.Decrypt(i.key)
	if err != nil {
		return "", err
	}
	var claims struct {
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Sub == "" || time.Now().Unix() >= claims.Exp {
		return "", errors.New("token vencido")
	}
	return claims.Sub, nil
}

// Sender tiene los datos de Brevo y de Twilio. Salen del .env, no del código.
type Sender struct {
	From, User, Password, Host, Port, APIKey string
	TwilioSID, TwilioToken, TwilioFrom       string
	Minutes                                  int
}

func NewDigits() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// Digest guarda una huella del código de correo. El número no queda en la base.
func Digest(key []byte, userID, digits string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(userID + digits))
	return hex.EncodeToString(mac.Sum(nil))
}

func Matches(key []byte, userID, digits, digest string) bool {
	expected, err := hex.DecodeString(digest)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(userID + digits))
	return hmac.Equal(mac.Sum(nil), expected)
}

// Send manda el código. El correo guarda los 6 dígitos. El SMS lo arma Twilio.
func (s Sender) Send(ctx context.Context, method, phone, correo, digits string) (string, error) {
	if method == "sms" {
		return "", s.sms(ctx, phone)
	}
	text := "Codigo " + digits + ". Tarda cerca de 1 minuto y caduca 5 minutos despues."
	if err := s.mail(correo, text); err != nil {
		return "", err
	}
	return digits, nil
}

// to es el correo de la cuenta. From es el remitente verificado en Brevo.
// Brevo cambia ese remitente, en la bandeja, por la dirección @brevosend.com.
// Si hay BREVO_API_KEY sale por HTTPS. Si no, usa SMTP en el puerto 2525.
func (s Sender) mail(to, text string) error {
	if s.Password == "" || s.From == "" || to == "" {
		return ErrNotConfigured
	}
	if s.APIKey != "" {
		return s.mailAPI(to, text)
	}
	return s.mailSMTP(to, text)
}

func (s Sender) mailAPI(to, text string) error {
	payload, err := json.Marshal(map[string]any{
		"sender":      map[string]string{"name": "Login", "email": s.From},
		"to":          []map[string]string{{"email": to}},
		"subject":     "Codigo de acceso",
		"textContent": text,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.brevo.com/v3/smtp/email", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("api-key", s.APIKey)
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 400))
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: %s", ErrMailRejected, brevoCode(string(raw), `"message":"`))
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("brevo %d %s", res.StatusCode, brevoCode(string(raw), `"code":"`))
	}
	return nil
}

func brevoCode(raw, mark string) string {
	start := strings.Index(raw, mark)
	if start < 0 {
		return ""
	}
	rest := raw[start+len(mark):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func (s Sender) mailSMTP(to, text string) error {
	host := s.Host
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", net.JoinHostPort(host, "2525"))
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()
	if err = client.StartTLS(&tls.Config{ServerName: host}); err != nil {
		return err
	}
	user := s.User
	if user == "" {
		user = s.From
	}
	if err = client.Auth(smtp.PlainAuth("", user, s.Password, host)); err != nil {
		if strings.Contains(err.Error(), "535") || strings.Contains(err.Error(), "BadCredentials") {
			return ErrMailRejected
		}
		return err
	}
	msg := "From: Login <" + s.From + ">\r\nReply-To: " + s.From + "\r\nTo: " + to +
		"\r\nSubject: Codigo de acceso\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + text
	if err = client.Mail(s.From); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err = w.Write([]byte(msg)); err != nil {
		return err
	}
	return w.Close()
}

func (s Sender) sms(ctx context.Context, phone string) error {
	id, err := s.verifyService(ctx)
	if err != nil {
		return err
	}
	_, status, err := s.call(ctx, http.MethodPost, verifyURL(id, "/Verifications"), url.Values{"To": {e164(phone)}, "Channel": {"sms"}})
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("%w %d", ErrSMSRejected, status)
	}
	return nil
}

// Check prueba el código contra el servicio de Twilio que lo envió.
func (s Sender) Check(ctx context.Context, phone, digits string) error {
	ids, err := s.serviceIDs(ctx)
	if err != nil {
		return err
	}
	form := url.Values{"To": {e164(phone)}, "Code": {digits}}
	pending := false
	expired := false
	for _, id := range ids {
		raw, status, err := s.call(ctx, http.MethodPost, verifyURL(id, "/VerificationCheck"), form)
		if err != nil {
			return err
		}
		if strings.Contains(raw, `"approved"`) {
			return nil
		}
		lower := strings.ToLower(raw)
		if strings.Contains(lower, "expired") {
			expired = true
			continue
		}
		if status < 300 {
			pending = true
		}
	}
	if pending || !expired {
		return ErrSMSRejected
	}
	return ErrExpired
}

func (s Sender) verifyService(ctx context.Context) (string, error) {
	ids, err := s.serviceIDs(ctx)
	if err != nil || len(ids) > 0 {
		if len(ids) == 0 {
			return "", err
		}
		return ids[0], nil
	}
	raw, status, err := s.call(ctx, http.MethodPost, "https://verify.twilio.com/v2/Services", url.Values{"FriendlyName": {"Login"}})
	if err != nil {
		return "", err
	}
	found := verifySIDExpr.FindString(raw)
	if status >= 300 || found == "" {
		return "", ErrSMSRejected
	}
	verifyMu.Lock()
	verifySID = found
	verifyMu.Unlock()
	return found, nil
}

func (s Sender) serviceIDs(ctx context.Context) ([]string, error) {
	if s.TwilioSID == "" || s.TwilioToken == "" {
		return nil, ErrNotConfigured
	}
	verifyMu.Lock()
	defer verifyMu.Unlock()
	if verifySID != "" {
		return []string{verifySID}, nil
	}
	raw, status, err := s.call(ctx, http.MethodGet, "https://verify.twilio.com/v2/Services?PageSize=20", nil)
	if err != nil || status >= 300 {
		return nil, ErrSMSRejected
	}
	return verifySIDExpr.FindAllString(raw, -1), nil
}

func (s Sender) call(ctx context.Context, method, endpoint string, form url.Values) (string, int, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return "", 0, err
	}
	req.SetBasicAuth(s.TwilioSID, s.TwilioToken)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", 0, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 20000))
	return string(raw), res.StatusCode, nil
}

func verifyURL(id, path string) string {
	return "https://verify.twilio.com/v2/Services/" + url.PathEscape(id) + path
}

func e164(phone string) string {
	if strings.HasPrefix(phone, "+") {
		return phone
	}
	if len(phone) == 10 {
		return "+57" + phone
	}
	return "+" + phone
}
