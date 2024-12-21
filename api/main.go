package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type user struct{
	Username string `json:"username"`
	Email string `json:"email"`
	Password string `json:"password"`
	Age string `json"age"`
	Gender string `json:"gender"`
}

var (
	mongoURI       = "mongodb+srv://muhammadabdullahgohar572:ilove1382005@cluster0.kxsr5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
	client         *mongo.Client
	usersCollection *mongo.Collection
)

func init() {
	// Initialize MongoDB connection once
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}
	usersCollection = client.Database("test").Collection("users")
	log.Println("Connected to MongoDB")
}

func sigup(w http.ResponseWriter, r *http.Request) {
	
var User user


if err :=json.NewDecoder(r.Body).Decode(&User);err !=nil{
	http.Error(w,"Invalid request body",http.StatusBadRequest)
	return
}

var existingUser user

err :=usersCollection.FindOne(context.TODO(),map[string]string{"email":User.Email}).Decode(&existingUser)

if err == nil {
	http.Error(w,"User already exists",http.StatusBadRequest)
    return
}

hashpassword,err :=bcrypt.GenerateFromPassword([]byte(User.Password),bcrypt.DefaultCost)
	

if  err !=nil {
	http.Error(w,"Probelm hashpassowrd",http.StatusBadRequest)
return
}

User.Password = string(hashpassword)

_,err =usersCollection.InsertOne(context.TODO(),User)

if err!= nil {
    http.Error(w,"Error inserting user",http.StatusInternalServerError)
    return
}



w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(User)

}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "hello go from vercel !!!!",
	})
}

// Exported Handler function
func Handler(w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()
	router.HandleFunc("/", helloHandler).Methods("GET")
	router.HandleFunc("/sigup",sigup).Methods("POST")


	// Apply CORS middleware
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}).Handler(router)

	// Serve the request
	corsHandler.ServeHTTP(w, r)
}

 
