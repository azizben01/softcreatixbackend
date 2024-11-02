package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type Database struct {
	DB *sql.DB
}

var DB *sql.DB

func ConnectDatabase() {
	// err := godotenv.Load()
	// if err != nil {
	// 	fmt.Println("error has occured in .env file, please check.")
	// }

	 // Load .env file only if not in production (e.g., when ENVIRONMENT is not "production")
	 if os.Getenv("ENVIRONMENT") != "production" {
        err := godotenv.Load()
        if err != nil {
            fmt.Println("Error loading .env file")
        }
    }
	host := os.Getenv("HOST")
	port, _ := strconv.Atoi(os.Getenv("DB_PORT"))
	user := os.Getenv("USER")
	password := os.Getenv("PASSWORD")
	dbname := os.Getenv("DB_NAME")

	// fmt.Println("host:", host)
	// fmt.Println(port)
	// fmt.Println(user)
	// fmt.Println("dbname:", dbname)
	// fmt.Println("password:", password)
	

	psqlSetup := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=require", host, port, user, password, dbname)

	db, errSql := sql.Open("postgres", psqlSetup) // establishes a connection with the database and this connection is stored in the local variable db.

	if errSql != nil {
		fmt.Println("There was an error when trying to connect to database", errSql)
		panic(errSql)
	} else {
		DB = db //DB: global varialble declared. db: local variable declared
		fmt.Println("Successfully connected to the database")
	}
}

func (database *Database) InitDatabase() {
	tableQueries := GetTableQueries()
	for _, query := range tableQueries {
		_, err := database.DB.Exec(query)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// key = value
