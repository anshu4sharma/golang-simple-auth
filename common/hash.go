// passwords.go
package common

import (
	"golang.org/x/crypto/bcrypt"
	"os"
	"strconv"
)

func HashPassword(password string) (string, error) {
	saltRoundStr := os.Getenv("SALT_ROUND")
	saltRound, err := strconv.Atoi(saltRoundStr)
	if err != nil {
		panic("Failed to parse SALT_ROUND")
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), saltRound)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// func main() {
//     password := "secret"
//     hash, _ := HashPassword(password) // ignore error for the sake of simplicity

//     fmt.Println("Password:", password)
//     fmt.Println("Hash:    ", hash)

//     match := CheckPasswordHash(password, hash)
//     fmt.Println("Match:   ", match)
// }
