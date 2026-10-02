// Consultas a PostgreSQL. Aquí no hay reglas de login, solo SQL.
package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cris329/login/model"
)

var (
	ErrNotFound    = errors.New("no encontrado")
	ErrIDTaken     = errors.New("identificacion registrada")
	ErrCodeExpired = errors.New("codigo vencido")
)

// Create guarda la cuenta. La contraseña ya llega cifrada.
func Create(ctx context.Context, conn *sql.DB, first, last, identification, phone, correo, hash string) error {
	_, err := conn.ExecContext(ctx, `
		INSERT INTO users (first_name, last_name, identification, phone, correo, password_hash)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		first, last, identification, phone, correo, hash)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrIDTaken
	}
	return err
}

// Find busca por número de identificación.
func Find(ctx context.Context, conn *sql.DB, identification string) (model.Account, error) {
	var account model.Account
	err := conn.QueryRowContext(ctx, `
		SELECT id::text, password_hash, phone, correo FROM users WHERE identification = $1`,
		identification).Scan(&account.ID, &account.Hash, &account.Phone, &account.Correo)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Account{}, ErrNotFound
	}
	return account, err
}

// UpdatePassword reemplaza el hash después de un código válido.
func UpdatePassword(ctx context.Context, conn *sql.DB, userID, hash string) error {
	_, err := conn.ExecContext(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, userID, hash)
	return err
}

// SaveCode deja un solo código por persona. El tiempo lo cuenta Postgres.
func SaveCode(ctx context.Context, conn *sql.DB, userID, hash string, minutes int, channel string) error {
	_, err := conn.ExecContext(ctx, `
		INSERT INTO login_codes (user_id, code_hash, expires_at, attempts, channel, sent_at)
		VALUES ($1, $2, now() + make_interval(mins => $3), 0, $4, now())
		ON CONFLICT (user_id) DO UPDATE
		SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at,
			attempts = 0, channel = EXCLUDED.channel, sent_at = now()`,
		userID, hash, minutes, channel)
	return err
}

// CodeWait dice cuántos segundos faltan para poder pedir otro código.
func CodeWait(ctx context.Context, conn *sql.DB, userID string) (int, error) {
	var left int
	err := conn.QueryRowContext(ctx, `
		SELECT GREATEST(0, CEIL(EXTRACT(EPOCH FROM (expires_at - now())))::int)
		FROM login_codes WHERE user_id = $1`, userID).Scan(&left)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return left, err
}

// TakeCode lee el código vigente. Cinco fallos o el vencimiento lo invalidan.
func TakeCode(ctx context.Context, conn *sql.DB, userID string) (string, string, error) {
	var hash, channel string
	var live bool
	var attempts int
	err := conn.QueryRowContext(ctx, `
		SELECT code_hash, channel, expires_at > now(), attempts FROM login_codes WHERE user_id = $1`, userID).
		Scan(&hash, &channel, &live, &attempts)
	if errors.Is(err, sql.ErrNoRows) || attempts >= 5 {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	if !live {
		return hash, channel, ErrCodeExpired
	}
	return hash, channel, nil
}

// FailCode suma un intento fallido.
func FailCode(ctx context.Context, conn *sql.DB, userID string) {
	_, _ = conn.ExecContext(ctx, `UPDATE login_codes SET attempts = attempts + 1 WHERE user_id = $1`, userID)
}

// HashCode cambia el texto plano por la huella. El tiempo queda en cero para poder pedir otro.
func HashCode(ctx context.Context, conn *sql.DB, userID, hash string) error {
	_, err := conn.ExecContext(ctx, `UPDATE login_codes SET code_hash = $2, expires_at = now() WHERE user_id = $1`, userID, hash)
	return err
}

// DeleteCode borra el código cuando ya venció.
func DeleteCode(ctx context.Context, conn *sql.DB, userID string) {
	_, _ = conn.ExecContext(ctx, `DELETE FROM login_codes WHERE user_id = $1`, userID)
}

// StartSession guarda el token cifrado de esa persona.
func StartSession(ctx context.Context, conn *sql.DB, userID, token string) error {
	_, err := conn.ExecContext(ctx, `
		INSERT INTO sessions (user_id, last_seen, token) VALUES ($1, now(), $2)
		ON CONFLICT (user_id) DO UPDATE SET last_seen = now(), token = EXCLUDED.token`, userID, token)
	return err
}

// RenewSession cambia el token guardado solo si el anterior sigue vigente.
func RenewSession(ctx context.Context, conn *sql.DB, userID string, idle time.Duration, current, next string) error {
	res, err := conn.ExecContext(ctx, `
		UPDATE sessions SET last_seen = now(), token = $4
		WHERE user_id = $1 AND token = $3 AND last_seen > now() - make_interval(secs => $2)`,
		userID, int(idle.Seconds()), current, next)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
