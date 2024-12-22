package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// Structs for different data models
type user struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Age      string `json:"age"`
	Gender   string `json:"gender"`
}

type contactUs struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	Message     string `json:"message"`
}

type order struct {
	CarType        string `json:"car_type"`
	PickupLocation string `json:"pickup_location"`
	DropoffLocation string `json:"dropoff_location"`
	PickupDate     string `json:"pickup_date"`
	PickupTime     string `json:"pickup_time"`
	DropoffTime    string `json:"dropoff_time"`
}

type Claims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.StandardClaims
}

// MongoDB client and JWT secret
var (
	mongoURI        = "mongodb+srv://muhammadabdullahgohar572:ilove1382005@cluster0.kxsr5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
	jwtSecret       = []byte("abdullah")
	client          *mongo.Client
	usersCollection *mongo.Collection
	contactUsCollection *mongo.Collection
	ordersCollection *mongo.Collection
)

// Initialize MongoDB connection
func init() {
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}
	db := client.Database("test")
	usersCollection = db.Collection("users")
	contactUsCollection = db.Collection("contact_us")
	ordersCollection = db.Collection("orders")
	log.Println("Connected to MongoDB")
}

// Signup API
func signup(w http.ResponseWriter, r *http.Request) {
	var User user

	if err := json.NewDecoder(r.Body).Decode(&User); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var existingUser user
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": User.Email}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	hashpassword, err := bcrypt.GenerateFromPassword([]byte(User.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Problem hashing password", http.StatusInternalServerError)
		return
	}
	User.Password = string(hashpassword)

	_, err = usersCollection.InsertOne(context.TODO(), User)
	if err != nil {
		http.Error(w, "Error inserting user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(User)
}

// Login API
func login(w http.ResponseWriter, r *http.Request) {
	var Loginuser user
	if err := json.NewDecoder(r.Body).Decode(&Loginuser); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var existingUser user
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": Loginuser.Email}).Decode(&existingUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(Loginuser.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	expireAt := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: existingUser.Username,
		Email:    existingUser.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expireAt.Unix(),
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

// Decode Token API
func decodeToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
		return
	}

	token, err := jwt.ParseWithClaims(authHeader, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		http.Error(w, "Could not parse claims", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(claims)
}

// Contact Us API
func contactUsHandler(w http.ResponseWriter, r *http.Request) {
	var contact contactUs
	if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	_, err := contactUsCollection.InsertOne(context.TODO(), contact)
	if err != nil {
		http.Error(w, "Error saving contact", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Contact saved successfully"})
}

// Order Booking API
func orderBooking(w http.ResponseWriter, r *http.Request) {
	var Order order
	if err := json.NewDecoder(r.Body).Decode(&Order); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	_, err := ordersCollection.InsertOne(context.TODO(), Order)
	if err != nil {
		http.Error(w, "Error saving order", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Order booked successfully"})
}

// Main function to set up routes and start the server
func Handler(w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/decode", decodeToken).Methods("GET")
	router.HandleFunc("/contactus", contactUsHandler).Methods("POST")
	router.HandleFunc("/orderbooking", orderBooking).Methods("POST")

	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(router)

	corsHandler.ServeHTTP(w, r)
}
