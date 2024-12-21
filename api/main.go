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
	Name         string `json:"Name"`
	Email        string `json:"email"`
	Phone_Number string `json:"Phone_Number"`
	Message      string `json:"Message"`
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
	client          *mongo.Client
	usersCollection *mongo.Collection
	jwtSecret       = []byte("abdullah")
)

type Booking struct {
	CarType            string    `json:"car_type"`
	PickupLocation     string    `json:"pickup_location"`
	DropoffLocation    string    `json:"dropoff_location"`
	PickupDate         string    `json:"pickup_date"`
	PickupTime         string    `json:"pickup_time"`
	DropoffTime        string    `json:"dropoff_time"`
	BookingID          string    `json:"booking_id,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
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

// Signup function// Signup function
func signup(w http.ResponseWriter, r *http.Request) {
    var User user

    if err := json.NewDecoder(r.Body).Decode(&User); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

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

    // Insert new user into MongoDB
    _, err = usersCollection.InsertOne(context.TODO(), User)
    if err != nil {
        http.Error(w, "Error inserting user", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(User)
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

func Decode(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenString, exists := vars["token"]
	if !exists || tokenString == "" {
		http.Error(w, "Token is missing from the URL", http.StatusUnauthorized)
		return
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || claims.StandardClaims.ExpiresAt < time.Now().Unix() {
		http.Error(w, "Token is expired", http.StatusUnauthorized)
		return
	}

	// Return the user information
	response := map[string]interface{}{
		"username": claims.Username,
		"email":    claims.Email,
		"age":      claims.Age,
		"gender":   claims.Gender,
		"password": claims.Password,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func contactus(w http.ResponseWriter, r *http.Request) {
	var contactus Contactus

	if err := json.NewDecoder(r.Body).Decode(&contactus); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	_, err := usersCollection.InsertOne(context.TODO(), contactus)
	if err != nil {
		http.Error(w, "Error inserting contactus", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(contactus)
}

func BookingD(w http.ResponseWriter, r *http.Request) {
	var booking Booking

	if err := json.NewDecoder(r.Body).Decode(&booking); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	_, err := usersCollection.InsertOne(context.TODO(), booking)
	if err != nil {
		http.Error(w, "Error inserting booking", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(booking)
}

// HelloHandler function
func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "hello go from vercel !!!!",
	})
}
func Handler(w http.ResponseWriter, r *http.Request) {
    router := mux.NewRouter()

    // Define routes for signup, login, and other actions
    router.HandleFunc("/", helloHandler).Methods("GET")
    router.HandleFunc("/signup", signup).Methods("POST")  // Only signup here
    router.HandleFunc("/login", login).Methods("POST")
    // router.HandleFunc("/protected/{token}", Decode).Methods("GET")  // Token required here, after login
    router.HandleFunc("/contactus", contactus).Methods("POST")
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
