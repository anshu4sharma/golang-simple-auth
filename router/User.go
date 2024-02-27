package router

import (
	"golang-simple-auth/common"
	"golang-simple-auth/models"
	"os"
	"time"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	// "go.mongodb.org/mongo-driver/mongo"
	// "go.mongodb.org/mongo-driver/bson/primitive"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/golang-jwt/jwt/v5"
)

func AddUserGroup(app *fiber.App) {
	userGroup := app.Group("/user")

	userGroup.Post("/login", login)
	userGroup.Post("/signup", signup)

	//   // JWT Middleware
	app.Use(jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(os.Getenv("JWT_SECRET"))},
	}))
	userGroup.Get("/info", getUserInfo)
}

type createDTO struct {
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
}

func getUserInfo(c *fiber.Ctx) error {
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	email := claims["email"].(string)
	id := claims["id"].(string)
	return c.SendString("Welcome " + email + " & your id is " + id)
}

func login(c *fiber.Ctx) error {
	// validate the body
	b := new(createDTO)
	if err := c.BodyParser(b); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid body",
		})
	}
	coll := common.GetDBCollection("users")
	user := models.User{}
	err := coll.FindOne(c.Context(), bson.M{"email": b.Email, "password": b.Password}).Decode(&user)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "User not found !",
			"message": err.Error(),
		})
	}
	// Create the Claims
	claims := jwt.MapClaims{
		"email": user.Email,
		"id":    user.ID,
		"exp":   time.Now().Add(time.Hour * 72).Unix(),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	return c.JSON(fiber.Map{"token": t})

}

func signup(c *fiber.Ctx) error {
	// validate the body
	b := new(createDTO)
	if err := c.BodyParser(b); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid body",
		})
	}

	// create User
	coll := common.GetDBCollection("users")
	user := models.User{}
	errExist := coll.FindOne(c.Context(), bson.M{"email": b.Email}).Decode(&user)
	if errExist == nil {
        // User with the same email already exists
        return c.Status(409).JSON(fiber.Map{
            "error":   "User already exists",
            "message": "A user with the same email already exists",
        })
    }
	result, err := coll.InsertOne(c.Context(), b)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to create User",
			"message": err.Error(),
		})
	}

	// return the book
	return c.Status(201).JSON(fiber.Map{
		"result": result,
	})
}
