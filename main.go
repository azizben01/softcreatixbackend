package main

import (
	"ben/benaziz/backend/database"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"os"
	"strings"

	//"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

func main() {
	router := gin.Default()
	database.ConnectDatabase()

	// Add CORS middleware
	router.Use(cors.New(cors.Config{                                
		AllowOrigins:     []string{"http://localhost:3000", "https://userinterface-gkco.vercel.app"},
		AllowMethods:     []string{"POST", "GET", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// routers
	router.POST("/services", requestService)
	router.GET("/requestlist", requestList)
	router.PUT("/markAsCompleted/:id/complete", markAsCompleted)
	router.DELETE("/deleteRequest/:id", deleteRequest) // New endpoint
	router.POST("/createadmin", CreateAdmin)
	router.POST("/adminlogin", AdminLogin)
	router.POST("/submitcontact", submitContactForm)
	router.GET("/messagelist", MessageList)
	router.DELETE("/deletecustomermessage/:id", DeleteCustomerMessage)
	router.POST("/requestpasswordreset", RequestPasswordReset)
	//getTokenJSON()


	db := &database.Database{DB: database.DB}
	db.InitDatabase()
	router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{
			"message": "Working fine",
		})
	})
	// err := router.Run(":2020")
	// if err != nil {
	// 	panic(err)
	// }

port := os.Getenv("SERVER_PORT")
if port == "" {
    port = "8080"  // Fallback for local development
}
 router.Run(":" + port)
}


type service struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Phonenumber string `json:"phonenumber"`
	Services    string `json:"services"`
	Description string `json:"description"`
	IsDeleted   bool   `json:"is_deleted"`
	ID          int    `json:"id"`
	Status      string `json:"status"`

}

func requestService(context *gin.Context) {
	var req service
	if err := context.ShouldBindJSON(&req); err != nil {
		fmt.Println("this is the input:", req)
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	_, err := database.DB.Exec("INSERT INTO services (name, email, phonenumber, services, description) VALUES ($1, $2, $3, $4, $5)", req.Name, req.Email, req.Phonenumber, req.Services, req.Description)
	if err != nil {
		fmt.Println("Database error during insert: ", err)
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create a new user"})
		return
	}
	context.JSON(http.StatusOK, gin.H{"message": "Request successfully sent"})
}

func requestList(context *gin.Context) {
	var reqlist []service
	rows, err := database.DB.Query("SELECT * FROM services WHERE is_deleted = FALSE") // Filter out deleted rows

	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve service list"})
		return
	}
	for rows.Next() {
		var list service
		err := rows.Scan(&list.Name, &list.Email, &list.Phonenumber, &list.Services, &list.Description, &list.IsDeleted, &list.Status,  &list.ID)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "error processing service request list"})
			fmt.Println(err)
			return
		}
		reqlist = append(reqlist, list)
	}
	context.JSON(http.StatusOK, reqlist)
}

func markAsCompleted(context *gin.Context) {
	id := context.Param("id")
	_, err := database.DB.Exec("UPDATE services SET status = $1 WHERE id = $2", "completed", id)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark request as completed"})
		return
	}
	context.JSON(http.StatusOK, gin.H{"message": "Request marked as completed"})
}

func deleteRequest(context *gin.Context) {
	id := context.Param("id")
	_, err := database.DB.Exec("UPDATE services SET is_deleted = TRUE WHERE id = $1", id) // Set is_deleted to true
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark request as deleted"})
		return
	}
	context.JSON(http.StatusOK, gin.H{"message": "Request marked as deleted"})
}


// Below are the functions related to admin
type Admin struct {
	Adminid          string     `json:"adminid"`
	Email            string     `json:"email"`
	Firstname        string     `json:"firstname"`
	Lastname         string     `json:"lastname"`
	Phonenumber      string     `json:"phonenumber"`
	Password         string     `json:"password"`
	Status           string     `json:"status"`
	ResetToken       *string    `json:"resetToken"` // Pointer to string to handle NULL
	ResetTokenExpiry *time.Time `json:"resetTokenExpiry"`
}
// function for registering admin
func CreateAdmin(context *gin.Context) {
	var req Admin
	
	if err := context.ShouldBindJSON(&req); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "bad input to register"})
		return
	}
	fmt.Println("This is the new admin:", &req)

	// Generate bcrypt hash from the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		context.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	req.Password = string(hashedPassword)

	// Insert the hashed password into the database
	_, err = database.DB.Exec("INSERT INTO admin (email, firstname, lastname, phonenumber, password, status) VALUES ($1, $2, $3, $4, $5, $6)",
		req.Email, req.Firstname, req.Lastname, req.Phonenumber, req.Password, req.Status)

	if err != nil {
		fmt.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create a new administrator"})
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"message": "New administrator created successfully",
	})
}


// function to log admin in

func AdminLogin(context *gin.Context) {
	var login Admin 
	err := context.ShouldBindJSON(&login)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error":"Invalid input for login"})
		return
	}

	var storeAdmin Admin
	err = database.DB.QueryRow("SELECT adminid, email, firstname, lastname, phonenumber, password, status FROM admin WHERE email=$1", login.Email).
	Scan(&storeAdmin.Adminid, &storeAdmin.Email,&storeAdmin.Firstname, &storeAdmin.Lastname, &storeAdmin.Phonenumber,&storeAdmin.Password, &storeAdmin.Status)

	if err != nil {
		if err == sql.ErrNoRows {
			context.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email"})
		} else {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			fmt.Println("error from the database:", err)
		}
		return
	}

	// Compare hashed password with the one provided
	err = bcrypt.CompareHashAndPassword([]byte(storeAdmin.Password), []byte(login.Password))
	if err != nil {
		// Passwords do not match
		fmt.Println("Password mismatch or error comparing hash:", err)
		context.JSON(http.StatusUnauthorized, gin.H{"error": "wrong password"})
		return
	}
	
	context.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"adminId": storeAdmin.Adminid,
		"email": storeAdmin.Email,
		"status": storeAdmin.Status,
	})
}

type Message struct {
	Name    		string `json:"name"`
	Email   		string `json:"email"`
	Message 		string `json:"message"`
	Created_at 		*time.Time `json:"created_at"`
	Id 				int 	`json:"is"`
	Is_deleted		bool     `json:"is_deleted"`
}
func submitContactForm(context *gin.Context) {
    var contact Message

    if err := context.ShouldBindJSON(&contact); err != nil {
        context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    _, err := database.DB.Exec("INSERT INTO contact (name, email, message) VALUES ($1, $2, $3)",
        contact.Name, contact.Email, contact.Message)
    if err != nil {
        context.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save contact message"})
		fmt.Println("could not save message:",err)
        return
    }

    context.JSON(http.StatusOK, gin.H{"message": "Contact message successfully sent"})
}


func MessageList(context *gin.Context) {
	//var reqlist []service
	var message [] Message
	rows, err := database.DB.Query("SELECT * FROM contact") // Filter out deleted rows

	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "failed to customer message list"})
		return
	}
	for rows.Next() {
		var list Message
		err := rows.Scan(&list.Name, &list.Email, &list.Message, &list.Created_at, &list.Id, &list.Is_deleted)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "error processing customer message list"})
			fmt.Println(err)
			return
		}
		message = append(message, list)
	}
	context.JSON(http.StatusOK, message)
}


func DeleteCustomerMessage(context *gin.Context) {
	id := context.Param("id")
	_, err := database.DB.Exec("UPDATE contact SET is_deleted = TRUE WHERE id = $1", id) // Set is_deleted to true
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark customer message as deleted"})
		return
	}
	context.JSON(http.StatusOK, gin.H{"message": "customer message marked as deleted"})
}


// Generate token then send mail
func getTokenJSON() {
	ctx := context.Background()
	b, err := os.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(b, gmail.GmailSendScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)

	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Unable to retrieve Gmail client: %v", err)
	}

	user := "me"
	r, err := srv.Users.Labels.List(user).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve labels: %v", err)
	}
	if len(r.Labels) == 0 {
		fmt.Println("No labels found.")
		return
	}
	
	fmt.Println("Labels:")
	for _, l := range r.Labels {
		fmt.Printf("- %s\n", l.Name)
	}
}

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
	// The file token.json stores the user's access and refresh tokens, and is
	// created automatically when the authorization flow completes for the first
	// time.
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}
// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)
	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func sendResetEmail(userEmail string, code string) error {
	b, err := os.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}
	config, err := google.ConfigFromJSON(b, gmail.GmailSendScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)
	ctx := context.Background()

	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Unable to retrieve Gmail client: %v", err)
	}

	var message gmail.Message
	subject := "Password Reset Request"
	body := fmt.Sprintf("You requested a password reset. Use the code below to reset your password:\n\n%s", code) // Email body with the numeric code

	msg := []byte("From: 'me'\r\n" +
		"To: " + userEmail + "\r\n" +
		"Subject: " + subject + "\r\n\r\n" +
		body)

	message.Raw = base64.URLEncoding.EncodeToString(msg)

	_, err = srv.Users.Messages.Send("me", &message).Do()
	if err != nil {
		return fmt.Errorf("Unable to send email: %v", err)
	}

	fmt.Println("Email sent successfully!")
	return nil
}

// generate random 6 digits code
func generateResetCode() (string, error) {
	// Generate a random 6-digit code
	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	return code, nil
}


// // function for requesting the password reset code via email
// func RequestPasswordReset(ctx *gin.Context) {
// 	fmt.Println("RequestPasswordReset function called")
// 	var req struct {
// 		Email string `json:"email"`
// 	}

// 	if err := ctx.ShouldBindJSON(&req); err != nil {
// 		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
// 		return
// 	}
// 	// Normalize the email to lowercase
// 	req.Email = strings.ToLower(req.Email)

// 	//var employee Employees
// 	var administrator Admin
// 	err := database.DB.QueryRow("SELECT adminid, email FROM admin WHERE email = $1", req.Email).Scan(&administrator.Adminid, &administrator.Email)
// 	if err != nil {
// 		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Email not found"})
// 		return
// 	} else {
// 		fmt.Println("email is existing")
// 	}

// 	// Generate the reset code
// 	code, err := generateResetCode()
// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset code"})
// 		return
// 	}

// 	// Store the token in the database with an expiry time
// 	expiry := time.Now().Add(1 * time.Hour).UTC()

// 	_, err = database.DB.Exec("UPDATE admin SET resettoken = $1, resettokenexpiry = $2 WHERE email = $3", code, expiry, req.Email)

// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store reset token"})
// 		return
// 	}
// 	// Send the password reset email
// 	fmt.Println("Sending email to:", administrator.Email)
// 	err = sendResetEmail(administrator.Email, code)
// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send password reset email"})
// 		return
// 	}

// 	ctx.JSON(http.StatusOK, gin.H{"message": "Password reset email sent"})
// }

func RequestPasswordReset(ctx *gin.Context) {
    fmt.Println("RequestPasswordReset function called")

    var req struct {
        Email string `json:"email"`
    }

    if err := ctx.ShouldBindJSON(&req); err != nil {
        fmt.Println("Invalid input:", err)
        ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }
    req.Email = strings.ToLower(req.Email)

    var administrator Admin
    err := database.DB.QueryRow("SELECT adminid, email FROM admin WHERE email = $1", req.Email).Scan(&administrator.Adminid, &administrator.Email)
    if err != nil {
        fmt.Println("Email not found in database:", err)
        ctx.JSON(http.StatusBadRequest, gin.H{"error": "Email not found"})
        return
    }
    fmt.Println("Email exists in database:", administrator.Email)

    code, err := generateResetCode()
    if err != nil {
        fmt.Println("Error generating reset code:", err)
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset code"})
        return
    }
    fmt.Println("Generated reset code:", code)

    expiry := time.Now().Add(1 * time.Hour).UTC()
    _, err = database.DB.Exec("UPDATE admin SET resettoken = $1, resettokenexpiry = $2 WHERE email = $3", code, expiry, req.Email)
    if err != nil {
        fmt.Println("Failed to store reset token:", err)
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store reset token"})
        return
    }

    fmt.Println("Attempting to send email to:", administrator.Email)
    err = sendResetEmail(administrator.Email, code)
    if err != nil {
        fmt.Println("Failed to send password reset email:", err)
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send password reset email"})
        return
    }

    fmt.Println("Password reset email sent successfully")
    ctx.JSON(http.StatusOK, gin.H{"message": "Password reset email sent"})
}
