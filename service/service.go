// Reglas del login. Este es el archivo que hay que leer.
// Register crea la cuenta. Login entrega el token si la contraseña coincide.
// Recover manda un solo código. Reset cambia la clave. Renew alarga la sesión.
package service

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/cris329/login/model"
	"github.com/cris329/login/repository"
)

var (
	ErrBadInput    = errors.New("revisa los datos obligatorios")
	ErrCredentials = errors.New("credenciales invalidas")
	ErrInternal    = errors.New("error interno")
	ErrSend        = errors.New("no se pudo enviar el codigo")
	ErrDeliver     = errors.New("no se pudo enviar el codigo")
	ErrTwilio      = errors.New("falta configurar Twilio para el SMS")
	ErrMailConfig  = errors.New("no se pudo enviar el correo")
	ErrCode        = errors.New("codigo invalido")
	ErrCodeGone    = errors.New("el codigo vencio")
	ErrPassword    = errors.New("la contraseña debe tener 8 caracteres, una mayúscula, una minúscula, un número y un signo")
	ErrSession     = errors.New("la sesion vencio")
	namePattern    = regexp.MustCompile(`^[\p{L} ]{2,40}$`)
	idPattern      = regexp.MustCompile(`^\d{5,15}$`)
	phonePattern   = regexp.MustCompile(`^\d{7,15}$`)
	correoPattern  = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
	codeDigits     = regexp.MustCompile(`\d{6}`)
)

// WaitError avisa que el código anterior sigue vivo. Seconds es la espera.
type WaitError struct{ Seconds int }

func (e WaitError) Error() string { return "espera para enviar otro codigo" }

// App junta la base, el token y el canal que envía el código.
type App struct {
	DB     *sql.DB
	Tokens *Issuer
	Codes  Sender
	Key    []byte
}

// Register guarda la cuenta.
// Pide nombre, apellido, identificación y contraseña. Celular y correo pueden ir vacíos.
// La contraseña se cifra con bcrypt: en la base no queda el texto.
func (a App) Register(ctx context.Context, body model.Register) error {
	first, last, identification, phone, correo, password, err := clean(body)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return ErrInternal
	}
	err = repository.Create(ctx, a.DB, first, last, identification, phone, correo, string(hash))
	if errors.Is(err, repository.ErrIDTaken) {
		return err
	}
	if err != nil {
		return ErrInternal
	}
	return nil
}

// Login compara la contraseña cifrada.
// Si coincide, el token lleva solo el id numérico. Si no, responde credenciales inválidas.
func (a App) Login(ctx context.Context, body model.Login) (string, error) {
	identification := strings.TrimSpace(body.Identification)
	if !idPattern.MatchString(identification) || len(body.Password) < 8 || len(body.Password) > 72 {
		return "", ErrCredentials
	}
	account, err := repository.Find(ctx, a.DB, identification)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(account.Hash), []byte(body.Password)) != nil {
		return "", ErrCredentials
	}
	signed, err := a.Tokens.Issue(account.ID)
	if err != nil || repository.StartSession(ctx, a.DB, account.ID, signed) != nil {
		return "", ErrCredentials
	}
	return signed, nil
}

// Recover envía el código al celular o al correo guardados.
// Mientras ese código no venza no se envía otro, así no se pisan en la base.
func (a App) Recover(ctx context.Context, body model.Recover) (int, error) {
	identification := strings.TrimSpace(body.Identification)
	method := strings.TrimSpace(body.Method)
	if !idPattern.MatchString(identification) || (method != "sms" && method != "correo") {
		return 0, ErrSend
	}
	account, err := repository.Find(ctx, a.DB, identification)
	if err != nil || (method == "sms" && account.Phone == "") || (method == "correo" && account.Correo == "") {
		return 0, ErrSend
	}
	left, err := repository.CodeWait(ctx, a.DB, account.ID)
	if err != nil {
		return 0, ErrSend
	}
	if left > 0 {
		return left, WaitError{Seconds: left}
	}
	digits, err := NewDigits()
	if err != nil {
		return 0, ErrSend
	}
	sent, err := a.Codes.Send(ctx, method, account.Phone, account.Correo, digits)
	if err != nil {
		slog.Error("envio del codigo", "error", err.Error())
		return 0, sendErr(err, method)
	}
	if sent != "" {
		digits = sent
	}
	stored := digits
	if method == "sms" {
		stored = "verify"
	}
	if repository.SaveCode(ctx, a.DB, account.ID, stored, a.Codes.Minutes+1, method) != nil {
		return 0, ErrSend
	}
	wait, _ := repository.CodeWait(ctx, a.DB, account.ID)
	return wait, nil
}

// Reset cambia la contraseña.
// Acepta los 6 dígitos aunque al pegarlos quede un punto. La clave nueva pide 8 caracteres.
func (a App) Reset(ctx context.Context, body model.Reset) error {
	identification := strings.TrimSpace(body.Identification)
	digits := codeDigits.FindString(body.Code)
	if !idPattern.MatchString(identification) || digits == "" {
		return ErrCode
	}
	if !strongPassword(body.Password) {
		return ErrPassword
	}
	account, err := repository.Find(ctx, a.DB, identification)
	if err != nil {
		return ErrCode
	}
	stored, _, err := repository.TakeCode(ctx, a.DB, account.ID)
	if errors.Is(err, repository.ErrCodeExpired) {
		repository.DeleteCode(ctx, a.DB, account.ID)
		return ErrCodeGone
	}
	if err != nil {
		return ErrCode
	}
	if stored == "verify" {
		err = a.Codes.Check(ctx, account.Phone, digits)
		if errors.Is(err, ErrExpired) {
			return ErrCodeGone
		}
		if err != nil {
			repository.FailCode(ctx, a.DB, account.ID)
			return ErrCode
		}
	} else if stored != digits {
		repository.FailCode(ctx, a.DB, account.ID)
		return ErrCode
	} else if repository.HashCode(ctx, a.DB, account.ID, Digest(a.Key, account.ID, digits)) != nil {
		return ErrCode
	}
	secret, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil || repository.UpdatePassword(ctx, a.DB, account.ID, string(secret)) != nil {
		return ErrCode
	}
	if stored == "verify" {
		repository.DeleteCode(ctx, a.DB, account.ID)
	}
	return nil
}

// Renew da un token nuevo si la persona sigue usando la pantalla.
// Si deja la app, a los minutos de JWT_TTL_MINUTES la sesión muere.
func (a App) Renew(ctx context.Context, header string) (string, error) {
	current := bearer(header)
	userID, err := a.Tokens.Read(current)
	if err != nil {
		return "", ErrSession
	}
	signed, err := a.Tokens.Issue(userID)
	if err != nil || repository.RenewSession(ctx, a.DB, userID, a.Tokens.Idle(), current, signed) != nil {
		return "", ErrSession
	}
	return signed, nil
}

func sendErr(err error, method string) error {
	if errors.Is(err, ErrNotConfigured) && method == "sms" {
		return ErrTwilio
	}
	if errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrMailRejected) {
		return ErrMailConfig
	}
	return ErrDeliver
}

func bearer(header string) string {
	value := strings.TrimSpace(header)
	if len(value) > 7 && strings.EqualFold(value[:7], "bearer ") {
		return strings.TrimSpace(value[7:])
	}
	return ""
}

func clean(body model.Register) (string, string, string, string, string, string, error) {
	first := strings.Join(strings.Fields(body.FirstName), " ")
	last := strings.Join(strings.Fields(body.LastName), " ")
	identification := onlyDigits(body.Identification)
	phone := onlyDigits(body.Phone)
	if strings.HasPrefix(phone, "57") && len(phone) > 10 {
		phone = phone[len(phone)-10:]
	}
	correo := strings.ToLower(strings.TrimSpace(body.Correo))
	switch {
	case !namePattern.MatchString(first):
		return "", "", "", "", "", "", errors.New("el primer nombre debe tener solo letras")
	case !namePattern.MatchString(last):
		return "", "", "", "", "", "", errors.New("el primer apellido debe tener solo letras")
	case !idPattern.MatchString(identification):
		return "", "", "", "", "", "", errors.New("la identificacion debe tener entre 5 y 15 numeros")
	case phone == "" && correo == "":
		return "", "", "", "", "", "", errors.New("coloca un celular o un correo para recuperar la cuenta")
	case phone != "" && !phonePattern.MatchString(phone):
		return "", "", "", "", "", "", errors.New("el celular debe tener solo numeros")
	case correo != "" && !correoPattern.MatchString(correo):
		return "", "", "", "", "", "", errors.New("el correo debe incluir un @ y un dominio")
	case !strongPassword(body.Password):
		return "", "", "", "", "", "", ErrPassword
	}
	return first, last, identification, phone, correo, body.Password, nil
}

func strongPassword(password string) bool {
	if len(password) < 8 || len(password) > 72 {
		return false
	}
	var upper, lower, digit, sign bool
	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			sign = true
		}
	}
	return upper && lower && digit && sign
}

func onlyDigits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
