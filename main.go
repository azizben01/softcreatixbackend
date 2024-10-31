package main

import (
	"ben/benaziz/backend/database"
	"database/sql"

	//"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	router := gin.Default()
	database.ConnectDatabase()

	// Add CORS middleware
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "https://userinterface-gkco.vercel.app/"},
		AllowMethods:     []string{"POST", "GET", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// routers
	router.POST("/services", requestService)
	router.GET("/requestlist", requestList)
	router.PUT("/markAsCompleted/:id/complete", markAsCompleted)
	router.DELETE("/services/:id", deleteRequest) // New endpoint
	router.POST("/createadmin", CreateAdmin)
	router.POST("/adminlogin", AdminLogin)


	db := &database.Database{DB: database.DB}
	db.InitDatabase()
	router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{
			"message": "Working fine",
		})
	})
	err := router.Run(":2020")
	if err != nil {
		panic(err)
	}
}

type service struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Phonenumber string `json:"phonenumber"`
	Services    string `json:"services"`
	Description string `json:"description"`
	Status      string `json:"status"`
	ID          int    `json:"id"`
	IsDeleted   bool   `json:"is_deleted"`
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
		err := rows.Scan(&list.Name, &list.Email, &list.Phonenumber, &list.Services, &list.Description, &list.IsDeleted, &list.ID, &list.Status, )
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