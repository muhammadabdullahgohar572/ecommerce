package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
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

type Claims struct {
	Username string `json:"username"`
	Email string `json:"email"`
	Password string `json:"password"`
	Age string `json"age"`
	Gender string `json:"gender"`
	jwt.StandardClaims
}
var (
	mongoURI       = "mongodb+srv://muhammadabdullahgohar572:ilove1382005@cluster0.kxsr5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
	client         *mongo.Client
	usersCollection *mongo.Collection
	jwtSecret = []byte("abdullah")
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

func signup(w http.ResponseWriter, r *http.Request) {
	
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

func login(w http.ResponseWriter, r *http.Request) {


	var Loginuser user
	if err :=json.NewDecoder(r.Body).Decode(&Loginuser);err !=nil {
		http.Error(w,"Invalid request body",http.StatusBadRequest)
		return
	}

	var existingUser user
	err:=usersCollection.FindOne(context.TODO(),map[string]string{"email":Loginuser.Email}).Decode(&existingUser)
 
if err!= nil {
    http.Error(w,"User not found",http.StatusNotFound)
    return
}

// Compare password
if err := bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(Loginuser.Password)); err != nil {
	http.Error(w, "Invalid password", http.StatusUnauthorized)
	return
}

// Now create the token
expireAtTime := time.Now().Add(20 * time.Hour)
claims := &Claims{
	Username: existingUser.Username,
	Email:    existingUser.Email,
	Password: existingUser.Password,
	Age:      existingUser.Age,
	Gender:   existingUser.Gender,
	StandardClaims: jwt.StandardClaims{
		ExpiresAt: expireAtTime.Unix(),
	},
}

token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

tokenString, err := token.SignedString(jwtSecret)
if err != nil {
	http.Error(w, "Error creating token", http.StatusInternalServerError)
	return
}

w.WriteHeader(http.StatusOK)
json.NewEncoder(w).Encode(map[string]string{"token": tokenString})



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
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")

	
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

 
