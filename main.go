package main

import (
	"fmt"
	"log"
	"net/http"

	"ipblacklist"
)

func main() {
	bl := blacklist.New()
	h := blacklist.NewHandler(bl)

	mux := http.NewServeMux()
	mux.HandleFunc("/blacklist/add", h.Add)
	mux.HandleFunc("/blacklist/remove", h.Remove)
	mux.HandleFunc("/blacklist/check", h.Check)
	mux.HandleFunc("/blacklist/list", h.List)

	addr := ":8080"
	fmt.Printf("IP blacklist server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
