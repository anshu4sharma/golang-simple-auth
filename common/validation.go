package common

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

// ValidateEmptyFields checks if any of the fields in the given map are empty.
func ValidateEmptyFields(data map[string]string) bool {
	for _, value := range data {
		fmt.Println(value)
		if value == "" {
			return true
		}
	}
	return false
}

// RespondWithBadRequest sends a bad request response with the given message.
func RespondWithBadRequest(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
		"error": message,
	})
}
