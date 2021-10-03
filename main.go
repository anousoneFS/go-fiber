package main

// this is gofiber basic

import (
	"fmt"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	jwtware "github.com/gofiber/jwt/v2"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const(
	host = "localhost"
	port = 5432
	username = ""
	password = ""
	dbname = ""
)
var db *sqlx.DB
const jwtSecret = "infinitus"

func main(){
	psqlconn := fmt.Sprintf(
		"host=%v port=%v user=%v password=%v dbname=%v sslmode=disable", host, port, username, password, dbname) 
	var err error
	db, err = sqlx.Open("postgres", psqlconn)
	if err != nil {
		panic(err)
	}
	// defer db.Close()

	app := fiber.New()
	app.Use("/hello", jwtware.New(jwtware.Config{
		SigningMethod: "HS256",
		SigningKey: []byte(jwtSecret),
		SuccessHandler: func(c *fiber.Ctx) error {
			return c.Next()
		},
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			return fiber.ErrUnauthorized
		},
	}))
	app.Post("/signup", Signup)
	app.Post("/login", Login)
	app.Get("/hello", Hello)
	app.Listen(":8000")
}

func Signup(c *fiber.Ctx) error {
	request := SignupRequest{}
	err := c.BodyParser(&request)
	if err != nil {
		return err
	}
	fmt.Println("1")
	if request.Username == "" || request.Password == "" {
		return fiber.ErrUnprocessableEntity
	}
	fmt.Println("2")
	password, err := bcrypt.GenerateFromPassword([]byte(request.Password), 10)
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}
	fmt.Println("3")
	query := "INSERT INTO user_signup (username, password) VALUES ($1, $2) RETURNING id"
	lastinsertid := 0
	err = db.QueryRow(query,request.Username,string(password)).Scan(&lastinsertid)
	if err != nil {
		fmt.Printf("error = %v", err)
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	user := User{
		Id: int(lastinsertid),
		Username: request.Username,
		Password: string(password),
	}

	return c.Status(fiber.StatusCreated).JSON(user)
}

func Login(c *fiber.Ctx) error {
	request := LoginRequest{}
	err := c.BodyParser(&request)
	if err != nil {
		return err
	}
	if request.Username == "" || request.Password == "" {
		return fiber.ErrUnprocessableEntity
	}

	user := User{}
	query := "SELECT id, username, password FROM user_signup WHERE username=$1"
	err = db.Get(&user, query, request.Username)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Incorrect username or password")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Incorrect password")
	}

	claims := jwt.StandardClaims{
		Issuer: strconv.Itoa(user.Id),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := jwtToken.SignedString([]byte(jwtSecret))
	if err != nil {
		fmt.Println(err)
		return fiber.ErrInternalServerError
	}

	return c.JSON(fiber.Map{"jwtToken": token})
}

func Hello(c *fiber.Ctx) error {
	return c.SendString("hi this is home page")
}

type User struct {
	Id int `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Password string `db:"password" json:"password"`
}

type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Fiber(){
	app := fiber.New(fiber.Config {
		Prefork: false,  // set to false for run one port
		CaseSensitive: false, // if set true home != Home
		StrictRouting: false, // if set true /home != /home/
	})

	app.Use(requestid.New()) // X-Request-Id: a9b45ddb-ecc0-4b9b-b26b-bd74d006467a

	app.Use(cors.New( cors.Config {
			AllowOrigins: "*",
			AllowMethods: "GET,POST",
			AllowHeaders: "*",
	}))

	// MIddleware
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("name_local", "myname local")
		fmt.Println("begin")
		err := c.Next()
		fmt.Println("end")
		return err
	})

	// set time zone for laos location
	// app.Use(logger.New()) //? declare after Middleware( middleware > route > log > middleware)

	// GET
	app.Get("/hello", func(c *fiber.Ctx) error {
		fmt.Println("hello")
		return c.SendString("GET: Hello World")	
	})

	// POST
	app.Post("/hello", func(c *fiber.Ctx) error{
		return c.SendString("POST: Hello World")	
	})

	// Parameters Optional
	app.Get("/hello/:name/:surname", func(c *fiber.Ctx) error{
		name := c.Params("name")
		surname := c.Params("surname")
		return c.SendString("name: " + name + " " + surname)	
	})

	// Parameters Int
	app.Get("/hello/:id", func(c *fiber.Ctx) error{
		id, err := c.ParamsInt("id")
		if err != nil {
			return fiber.ErrBadRequest
		}
		return c.SendString(fmt.Sprintf("ID: %v", id))	
	})

	// Query
	app.Get("/query", func(c *fiber.Ctx) error {
		name := c.Query("name")
		surname := c.Query("surname")
		return c.SendString("name: " + name + " surname: " + surname)
	})

	// Query Parser
	app.Get("/query2", func(c *fiber.Ctx) error {
		person := Person{}
		c.QueryParser(&person)
		return c.JSON(person)
	})

	// WildCard
	app.Get("/wildcard/*", func(c *fiber.Ctx) error {
		wildcard := c.Params("*")
		return c.SendString(wildcard)
	})

	// Static file
	app.Static("/", "./wwwroot")

	// NewError
	app.Get("/error", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusNotFound, "content not found")
	})

	// Group
	v1 := app.Group("/v1", func(c *fiber.Ctx) error {
		c.Set("version", "v1")
		return c.Next()
	})
	v1.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("hello v1")
	})

	v2 := app.Group("/v2", func(c *fiber.Ctx) error {
		c.Set("version", "v2")
		return c.Next()
	})
	v2.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("hello v2")
	})


	// Mount
	userApp := fiber.New() // create new instance
	userApp.Get("/login", func(c *fiber.Ctx) error {
		return c.SendString("this is login page")
	})
	app.Mount("/user", userApp)

	// Server
	app.Server().MaxConnsPerIP = 1 //? one ip per one connection
	app.Get("/server", func(c *fiber.Ctx) error {
		time.Sleep(time.Second * 20)
		return c.SendString("server process")
	})

	// Enviroments
	app.Get("/env", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"BaseURL": c.BaseURL(),
			"Hostname": c.Hostname(),
			"IP": c.IP(),
			"IPs": c.IPs(),
			"OriginalURL": c.OriginalURL(),
			"Path": c.Path(),
			"Protocol": c.Protocol(),
			"Subdomains": c.Subdomains(),
		})
	})
	
	// Body
	app.Post("/body", func(c *fiber.Ctx) error {
		fmt.Printf("is json: %v\n", c.Is("json")) // check if body is json
		// fmt.Println(string(c.Body())) // access body content from request
		person := Person{}
		err := c.BodyParser(&person)
		if err != nil {
			return err
		}
		fmt.Println(person)
		return nil
	})

	app.Listen(":8000")
}

type Person struct {
	Id int `json:"id"`
	Name string `json:"name"`
}