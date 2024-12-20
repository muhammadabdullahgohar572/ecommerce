package handler

import (
	"context"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)


var(
	mongoURI   ="mongodb+srv://muhammadabdullahgohar572:ilove1382005@cluster0.kxsr5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
	client    *mongo.Client
	usersCollection *mongo.Collection
)

func initMongo() {
	var err error
	client, err = mongo.Connect(context.TODO(),options.Client().ApplyURI(mongoURI))
    
	if err !=nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}
	usersCollection =client.Database("test").Collection("users")
	log.Println("Connected to MongoDB")
}

func handler(w http.ResponseWriter, r *http.Request) {
	initMongo()
	router := mux.NewRouter()
	corsHandler :=cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}).Handler(router)
	corsHandler.ServeHTTP(w, r)
}
