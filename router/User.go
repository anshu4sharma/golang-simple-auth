package router

import (
	"fmt"
	"golang-simple-auth/common"
	"golang-simple-auth/models"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"

	// "github.com/gofiber/fiber/v2/middleware/logger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	// "go.mongodb.org/mongo-driver/mongo"
	// "go.mongodb.org/mongo-driver/bson/primitive"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/golang-jwt/jwt/v5"
)

func AddUserGroup(app *fiber.App) {
	userGroup := app.Group("/user")

	userGroup.Post("/login", login)
	userGroup.Post("/signup", signup)
	userGroup.Post("/forgot-password", forgotPassword)
	userGroup.Post("/reset-password/:id/:token", resetPassword)

	userGroup.Get("/info", jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(os.Getenv("JWT_SECRET"))},
	}), getUserInfo)
}

type createDTO struct {
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
}

type TEMAIL struct {
	Email string `json:"email" bson:"email"`
}

type TPASSWORD struct {
	Password string `json:"password" bson:"password"`
}

func getUserInfo(c *fiber.Ctx) error {
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	email := claims["email"].(string)
	id := claims["id"].(string)
	return c.SendString("Welcome " + email + " & your id is " + id)
}

// Define a method in createDTO to check if any fields are empty
func (b *createDTO) IsEmpty() bool {
	return b.Email == "" || b.Password == ""
}

func login(c *fiber.Ctx) error {
	// validate the body
	b := new(createDTO)
	if err := c.BodyParser(b); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid body",
		})
	}
	// Check if any of the fields in b are empty
	if common.ValidateEmptyFields(map[string]string{"Email": b.Email, "Password": b.Password}) {
		return common.RespondWithBadRequest(c, "Empty fields in request body")
	}
	// if common.ValidateEmptyFields(map[string]string{"field1": b.Email, "field2": b.Password}) {
	// 	return common.RespondWithBadRequest(c, "Empty fields in request body")
	// }

	// if b.IsEmpty() {
	// 	return c.Status(400).JSON(fiber.Map{
	// 		"error": "Empty fields in request body",
	// 	})
	// }

	coll := common.GetDBCollection("users")
	user := models.User{}
	err := coll.FindOne(c.Context(), bson.M{"email": b.Email}).Decode(&user)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "User not found !",
		})
	}

	match := common.CheckPasswordHash(b.Password, user.Password)

	if !match {
		return common.RespondWithBadRequest(c, "Invalid Credentials !")
	}

	// Create the Claims
	claims := jwt.MapClaims{
		"email": user.Email,
		"id":    user.ID,
		"exp":   time.Now().Add(time.Minute * 60).Unix(),
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
	// if the user pass any othervalue except the email or password they will not be parsed
	if common.ValidateEmptyFields(map[string]string{"Email": b.Email, "Password": b.Password}) {
		return common.RespondWithBadRequest(c, "Empty fields in request body")
	}
	// create User
	coll := common.GetDBCollection("users")
	user := models.User{}
	errExist := coll.FindOne(c.Context(), bson.M{"email": b.Email}).Decode(&user)
	if errExist == nil {
		// User with the same email already exists
		return c.Status(409).JSON(fiber.Map{
			"error": "User already exists",
		})
	}

	hashedPassword, err := common.HashPassword(b.Password)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to Signup",
			"message": err.Error(),
		})
	}

	b.Password = hashedPassword

	result, err := coll.InsertOne(c.Context(), b)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to Signup",
			"message": err.Error(),
		})
	}

	// return the book
	return c.Status(201).JSON(fiber.Map{
		"result": result,
	})
}

func forgotPassword(c *fiber.Ctx) error {
	// validate the body
	b := new(TEMAIL)
	if err := c.BodyParser(b); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid body",
		})
	}
	if common.ValidateEmptyFields(map[string]string{"Email": b.Email}) {
		return common.RespondWithBadRequest(c, "Empty fields in request body")
	}

	coll := common.GetDBCollection("users")
	user := models.User{}
	err := coll.FindOne(c.Context(), bson.M{"email": b.Email}).Decode(&user)
	fmt.Println(err, b.Email)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "User not found !",
		})
	}

	// Create the Claims
	claims := jwt.MapClaims{
		"email": user.Email,
		"id":    user.ID,
		"exp":   time.Now().Add(time.Minute * 60).Unix(),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	tokenstring, err := token.SignedString([]byte(os.Getenv("JWT_SECRET") + user.Password))

	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to Generate Reset Password Link",
		})
	}

	baseUrl := "http://localhost:3000"
	userID := user.ID
	link := fmt.Sprintf("%s/user/reset-password/%s/%s", baseUrl, userID.Hex(), tokenstring)
	fmt.Println(link)

	return c.JSON(fiber.Map{"link": link, "message": "Reset password link has been generated !"})
}
func resetPassword(c *fiber.Ctx) error {
	// Retrieve the ID and token parameters from the URL
	id := c.Params("id")
	tokenString := c.Params("token")

	b := new(TPASSWORD)

	if err := c.BodyParser(b); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid body",
		})
	}

	if common.ValidateEmptyFields(map[string]string{"Password": b.Password}) {
		return common.RespondWithBadRequest(c, "Empty fields in request body")
	}
	
	coll := common.GetDBCollection("users")
	user := models.User{}

	objectId, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Failed to fetch the user !",
		})
	}

	errExist := coll.FindOne(c.Context(), bson.M{"_id": objectId}).Decode(&user)

	if errExist != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "User not Found !",
		})
	}

	_, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET") + user.Password), nil
	})

	// claims, ok := token.Claims.(jwt.MapClaims)

	// fmt.Println(claims, ok)

	fmt.Println(err, "err")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Token is expired or invalid token !",
		})
	}

	hashedPassword, err := common.HashPassword(b.Password)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to Signup",
			"message": err.Error(),
		})
	}

	// Update the user's password
	update := bson.M{"$set": bson.M{"password": hashedPassword}}
	_, err = coll.UpdateOne(c.Context(), bson.M{"_id": objectId}, update)

	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Failed to Reset Password !",
		})
	}

	// For now, let's just return a placeholder response
	return c.JSON(fiber.Map{
		"message": "Your password has been successfully reset !",
	})
}
