package handler

import (
	"context"
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

// Structs
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

type Booking struct {
	CarType         string `json:"car_type"`
	PickupLocation  string `json:"pickup_location"`
	DropoffLocation string `json:"dropoff_location"`
	PickupDate      string `json:"pickup_date"`
	PickupTime      string `json:"pickup_time"`
	DropoffTime     string `json:"dropoff_time"`
}

type Claims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Age      string `json:"age"`
	Gender   string `json:"gender"`
	jwt.StandardClaims
}

// MongoDB connection details
var (
	mongoURI = "mongodb+srv://muhammadabdullahgohar572:ilove1382005@cluster0.kxsr5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
	client   *mongo.Client
)

func init() {
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}
	log.Println("Connected to MongoDB")
}

// Handlers
func signup(w http.ResponseWriter, r *http.Request) {
	var newUser user
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	newUser.Password = string(hashedPassword)

	userCollection := client.Database("test").Collection("users")
	_, err = userCollection.InsertOne(context.TODO(), newUser)
	if err != nil {
		http.Error(w, "Error saving user details", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Signup successful"})
}

func login(w http.ResponseWriter, r *http.Request) {
	var loginUser user
	if err := json.NewDecoder(r.Body).Decode(&loginUser); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userCollection := client.Database("test").Collection("users")
	var dbUser user
	err := userCollection.FindOne(context.TODO(), bson.M{"email": loginUser.Email}).Decode(&dbUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(loginUser.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	claims := &Claims{
		Username: dbUser.Username,
		Email:    dbUser.Email,
		Password: dbUser.Password,
		Age:      dbUser.Age,
		Gender:   dbUser.Gender,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("abdullah55"))
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func decodeHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := mux.Vars(r)["token"]

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("abdullah55"), nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(claims)
}

func contactUs(w http.ResponseWriter, r *http.Request) {
	var contact Contactus
	if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	contactCollection := client.Database("test").Collection("contacts")
	_, err := contactCollection.InsertOne(context.TODO(), contact)
	if err != nil {
		http.Error(w, "Error saving contact details", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Contact details submitted successfully"})
}

func bookingOrder(w http.ResponseWriter, r *http.Request) {
	var booking Booking
	if err := json.NewDecoder(r.Body).Decode(&booking); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	bookingCollection := client.Database("test").Collection("bookings")
	_, err := bookingCollection.InsertOne(context.TODO(), booking)
	if err != nil {
		http.Error(w, "Error saving booking details", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Booking details submitted successfully"})
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Hello, Go from Vercel!"})
}

func getconectus(w http.ResponseWriter, r *http.Request) {
	conectuscollection := client.Database("test").Collection("contacts")
	cusor, err := conectuscollection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Error fetching data", http.StatusInternalServerError)
		return
	}

	defer cusor.Close(context.TODO())

	var contextus []Contactus
	for cusor.Next(context.TODO()) {
		var contact Contactus
		err := cusor.Decode(&contact)
		if err != nil {
			http.Error(w, "Error decoding data", http.StatusInternalServerError)
			return
		}
		contextus = append(contextus, contact)

	}
	if err := cusor.Err(); err != nil {
		http.Error(w, "Error reading cursor", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(contextus)
}

func getUserDetails(w http.ResponseWriter, r *http.Request) {
	bookingDeatils := client.Database("test").Collection("bookings")
	result, err := bookingDeatils.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Error fetching data", http.StatusInternalServerError)
		return
	}
	defer result.Close(context.TODO())
	var bookingDetails []Booking
	for result.Next(context.TODO()) {
		var booking Booking
		err := result.Decode(&booking)
		if err != nil {
			http.Error(w, "Error decoding data", http.StatusInternalServerError)
			return
		}
		bookingDetails = append(bookingDetails, booking)
	}
	if err := result.Err(); err != nil {
		http.Error(w, "Error reading cursor", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(bookingDetails)

}

func userAllDeatils(w http.ResponseWriter, r *http.Request) {

	userCollection := client.Database("test").Collection("users")
	result, err := userCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Error fetching data", http.StatusInternalServerError)
		return
	}
	defer result.Close(context.TODO())
	var users []user
	for result.Next(context.TODO()) {
		var user user
		err := result.Decode(&user)
		if err != nil {
			http.Error(w, "Error decoding data", http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}
	if err := result.Err(); err != nil {
		http.Error(w, "Error reading cursor", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(users)

}

func Handler(w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()

	router.HandleFunc("/", helloHandler).Methods("GET")
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/decodeHandler/{token}", decodeHandler).Methods("GET")
	router.HandleFunc("/contact", contactUs).Methods("POST")
	router.HandleFunc("/booking", bookingOrder).Methods("POST")
	router.HandleFunc("/getconectus", getconectus).Methods("GET")
	router.HandleFunc("/getUserDetails", getUserDetails).Methods("GET")
	router.HandleFunc("/userAllDeatils", getUserDetails).Methods("GET")

	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}).Handler(router)

	corsHandler.ServeHTTP(w, r)
}
