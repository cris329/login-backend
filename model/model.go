// Datos que viajan entre el formulario, la base y las respuestas.
package model

// Account es la persona ya guardada. ID es el entero de la tabla.
type Account struct {
	ID     string
	Hash   string
	Phone  string
	Correo string
}

// Register llega de POST /api/v1/registro.
type Register struct {
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	Identification string `json:"identification"`
	Phone          string `json:"phone"`
	Correo         string `json:"correo"`
	Password       string `json:"password"`
}

// Login llega de POST /api/v1/login.
type Login struct {
	Identification string `json:"identification"`
	Password       string `json:"password"`
}

// Recover pide el código por sms o por correo.
type Recover struct {
	Identification string `json:"identification"`
	Method         string `json:"method"`
}

// Reset cambia la contraseña cuando el código coincide.
type Reset struct {
	Identification string `json:"identification"`
	Code           string `json:"code"`
	Password       string `json:"password"`
}
