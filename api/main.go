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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// User struct to represent the user data
type user struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Age      string `json:"age"`
	Gender   string `json:"gender"`
}

type Contactus struct {
	Name         string `json:"name"`
	Email        string `json:"email"`
	Phone_Number string `json:"phone_number"`
	Message      string `json:"message"`
}

// Claims struct represents JWT token claims
type Claims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Age      string `json:"age"`
	Gender   string `json:"gender"`
	jwt.StandardClaims
}

// MongoDB client and JWT secret
var (
	mongoURI        = "mongodb+srv://muhammadabdullahgohar572:ilove1382005@cluster0.kxsr5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
	jwtSecret       = []byte("abdullah")
	client          *mongo.Client
	usersCollection *mongo.Collection
)

type Booking struct {
	CarType         string    `json:"car_type"`
	PickupLocation  string    `json:"pickup_location"`
	DropoffLocation string    `json:"dropoff_location"`
	PickupDate      string    `json:"pickup_date"`
	PickupTime      string    `json:"pickup_time"`
	DropoffTime     string    `json:"dropoff_time"`
	BookingID       string    `json:"booking_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// Initialize MongoDB connection
func init() {
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

	// Decode the request body into the User struct
	if err := json.NewDecoder(r.Body).Decode(&User); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if the user already exists in the database
	var existingUser user
	err := usersCollection.FindOne(context.TODO(), map[string]string{"email": User.Email}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashpassword, err := bcrypt.GenerateFromPassword([]byte(User.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Problem hashing password", http.StatusBadRequest)
		return
	}
	User.Password = string(hashpassword)

	// Insert the new user into the MongoDB database
	_, err = usersCollection.InsertOne(context.TODO(), User)
	if err != nil {
		http.Error(w, "Error inserting user", http.StatusInternalServerError)
		return
	}

	// Respond with the created user's data
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(User) // Return the User struct, not Booking
}

// Login function
func login(w http.ResponseWriter, r *http.Request) {
	var Loginuser user
	if err := json.NewDecoder(r.Body).Decode(&Loginuser); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Find the user by email
	var existingUser user
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": Loginuser.Email}).Decode(&existingUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Compare the password with the stored hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(Loginuser.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Create JWT token
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

func contactus(w http.ResponseWriter, r *http.Request) {

	var contactus Contactus
	if err := json.NewDecoder(r.Body).Decode(&contactus); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	contactCollection := client.Database("test").Collection("contactus")
	
	_, err := contactCollection.InsertOne(context.TODO(), contactus)
	if err != nil {
		http.Error(w, "Error inserting contactus", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(contactus)
}

// Booking handler
func BookingD(w http.ResponseWriter, r *http.Request) {
    var booking Booking

    // Decode the JSON request
    if err := json.NewDecoder(r.Body).Decode(&booking); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate required fields
    if booking.CarType == "" || booking.PickupLocation == "" || booking.DropoffLocation == "" {
        http.Error(w, "All fields are required", http.StatusBadRequest)
        return
    }

    // Set the CreatedAt timestamp
    booking.CreatedAt = time.Now()

    // Insert booking into MongoDB
    bookingCollection := client.Database("test").Collection("booking")
    _, err := bookingCollection.InsertOne(context.TODO(), booking)
    if err != nil {
        http.Error(w, "Error inserting booking", http.StatusInternalServerError)
        return
    }

    // Respond with the created booking data
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status": "success",
        "data":   booking,
    })
}


// HelloHandler function
func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Hello, Go from Vercel!",
	})
}
func decodeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r) // Extract URL parameters
	tokenString, exists := vars["token"]
	if !exists || tokenString == "" {
		http.Error(w, "Token is missing from the URL", http.StatusUnauthorized)
		return
	}

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// If token is valid, respond with success
	claims, ok := token.Claims.(*Claims)
	if !ok {
		http.Error(w, "Invalid token structure", http.StatusUnauthorized)
		return
	}

	response := map[string]interface{}{
       "message":     "Welcome to the protected route",
		"Email":    claims.Email,
		"username": claims.Username,
		"Password": claims.Password,
		"Age":      claims.Age,
		"Gender":   claims.Gender,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Main handler to route requests
// Main handler to route requests
func Handler(w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()

	// Define routes for signup, login, and other actions
	router.HandleFunc("/", helloHandler).Methods("GET")
	router.HandleFunc("/signup", signup).Methods("POST") // No verification here
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/contactus", contactus).Methods("POST")
	router.HandleFunc("/decodeHandler/{token}", decodeHandler).Methods("GET")

	router.HandleFunc("/BookingD", BookingD).Methods("POST")

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
