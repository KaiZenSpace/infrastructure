package restapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin/ipblocker/dnslookup"
	"github.com/gorilla/mux"
)

// ErrorResponse represents an error in the API
type ErrorResponse struct {
	Error string `json:"error"`
}

// DomainManagementRequest for adding/removing domains
type DomainManagementRequest struct {
	Domains []string `json:"domains"`
}

// DNSCheckResponse for domain checking
type DNSCheckResponse struct {
	ClientIP string `json:"clientIP"`
	Domain   string `json:"domain"`
	Allowed  bool   `json:"allowed"`
}

// APIServer represents the REST API server
type APIServer struct {
	server    *http.Server
	DNSFilter *dnslookup.DNSFilter
	running   bool
	mutex     sync.Mutex
}

// NewAPIServer creates a new API server instance
func NewAPIServer(dnsFilter *dnslookup.DNSFilter) *APIServer {
	return &APIServer{
		DNSFilter: dnsFilter,
		running:   false,
		mutex:     sync.Mutex{},
	}
}

// loggerMiddleware logs all requests
func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[API] Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// timeoutMiddleware adds timeout to all requests
func timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		done := make(chan struct{})

		go func() {
			next.ServeHTTP(w, r.WithContext(ctx))
			done <- struct{}{}
		}()

		select {
		case <-done:
			return
		case <-ctx.Done():
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestTimeout)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "request timeout"})
			return
		}
	})
}

// sendErrorResponse sends an error response
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

// sendJSONResponse sends a JSON response
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[API] Error encoding response: %v", err)
	}
}

// decodeJSONRequest decodes a JSON request
func decodeJSONRequest(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// List Management Handlers

// getAllLists returns all lists
func (api *APIServer) getAllLists(w http.ResponseWriter, r *http.Request) {
	log.Println("[API] Handler: getAllLists called")
	sendJSONResponse(w, api.DNSFilter.GetAllLists(), http.StatusOK)
}

// getListsByType returns lists by type
func (api *APIServer) getListsByType(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	listType := vars["type"]
	log.Printf("[API] Handler: getListsByType called with type: %s", listType)

	if listType != "blocklist" && listType != "whitelist" {
		sendErrorResponse(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	sendJSONResponse(w, api.DNSFilter.GetListsByType(listType), http.StatusOK)
}

// getListContent returns the content of a list
func (api *APIServer) getListContent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	listType := vars["type"]
	listName := vars["name"]
	log.Printf("[API] Handler: getListContent called with type: %s, name: %s", listType, listName)

	if listType != "blocklist" && listType != "whitelist" {
		sendErrorResponse(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	content, err := api.DNSFilter.GetListContent(listName, listType)
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	sendJSONResponse(w, content, http.StatusOK)
}

// createList creates a new list
func (api *APIServer) createList(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	listType := vars["type"]
	log.Printf("[API] Handler: createList called with type: %s", listType)

	if listType != "blocklist" && listType != "whitelist" {
		sendErrorResponse(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	var newList dnslookup.ListContent
	if err := decodeJSONRequest(r, &newList); err != nil {
		log.Printf("[API] Error decoding JSON: %v", err)
		sendErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	newList.Type = listType

	if err := api.DNSFilter.CreateList(&newList); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[API] New list created: %+v", newList)
	sendJSONResponse(w, newList, http.StatusCreated)
}

// updateList updates an existing list
func (api *APIServer) updateList(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	listType := vars["type"]
	listName := vars["name"]
	log.Printf("[API] Handler: updateList called with type: %s, name: %s", listType, listName)

	if listType != "blocklist" && listType != "whitelist" {
		sendErrorResponse(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	var updatedList dnslookup.ListContent
	if err := decodeJSONRequest(r, &updatedList); err != nil {
		log.Printf("[API] Error decoding JSON: %v", err)
		sendErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	updatedList.Name = listName
	updatedList.Type = listType

	if err := api.DNSFilter.UpdateList(&updatedList); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[API] List updated: %+v", updatedList)
	sendJSONResponse(w, updatedList, http.StatusOK)
}

// deleteList deletes a list
func (api *APIServer) deleteList(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	listType := vars["type"]
	listName := vars["name"]
	log.Printf("[API] Handler: deleteList called with type: %s, name: %s", listType, listName)

	if listType != "blocklist" && listType != "whitelist" {
		sendErrorResponse(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	if err := api.DNSFilter.DeleteList(listName, listType); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Domain Management Handlers

// addDomains adds domains to a list
func (api *APIServer) addDomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	listType := vars["type"]
	listName := vars["name"]
	log.Printf("[API] Handler: addDomains called with type: %s, name: %s", listType, listName)

	if listType != "blocklist" && listType != "whitelist" {
		sendErrorResponse(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	var request DomainManagementRequest
	if err := decodeJSONRequest(r, &request); err != nil {
		log.Printf("[API] Error decoding JSON: %v", err)
		sendErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	if err := api.DNSFilter.AddDomains(listName, listType, request.Domains); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[API] Domains added: %v", request.Domains)
	sendJSONResponse(w, struct{}{}, http.StatusOK)
}

// removeDomains removes domains from a list
func (api *APIServer) removeDomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	listType := vars["type"]
	listName := vars["name"]
	log.Printf("[API] Handler: removeDomains called with type: %s, name: %s", listType, listName)

	if listType != "blocklist" && listType != "whitelist" {
		sendErrorResponse(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	var request DomainManagementRequest
	if err := decodeJSONRequest(r, &request); err != nil {
		log.Printf("[API] Error decoding JSON: %v", err)
		sendErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	if err := api.DNSFilter.RemoveDomains(listName, listType, request.Domains); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[API] Domains removed: %v", request.Domains)
	sendJSONResponse(w, struct{}{}, http.StatusOK)
}

// Client Management Handlers

// getAllClients returns all clients
func (api *APIServer) getAllClients(w http.ResponseWriter, r *http.Request) {
	log.Println("[API] Handler: getAllClients called")
	sendJSONResponse(w, api.DNSFilter.GetAllClients(), http.StatusOK)
}

// getClientByIP returns a client by IP
func (api *APIServer) getClientByIP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientIP := vars["ip"]
	log.Printf("[API] Handler: getClientByIP called with IP: %s", clientIP)

	client, err := api.DNSFilter.GetClientByIP(clientIP)
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	sendJSONResponse(w, client, http.StatusOK)
}

// createClient creates a new client
func (api *APIServer) createClient(w http.ResponseWriter, r *http.Request) {
	log.Println("[API] Handler: createClient called")

	var newClient dnslookup.ClientConfig
	if err := decodeJSONRequest(r, &newClient); err != nil {
		log.Printf("[API] Error decoding JSON: %v", err)
		sendErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	if err := api.DNSFilter.CreateClient(&newClient); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[API] New client created: %+v", newClient)
	sendJSONResponse(w, newClient, http.StatusCreated)
}

// updateClient updates an existing client
func (api *APIServer) updateClient(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientIP := vars["ip"]
	log.Printf("[API] Handler: updateClient called with IP: %s", clientIP)

	var updatedClient dnslookup.ClientConfig
	if err := decodeJSONRequest(r, &updatedClient); err != nil {
		log.Printf("[API] Error decoding JSON: %v", err)
		sendErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	updatedClient.IP = clientIP

	if err := api.DNSFilter.UpdateClient(&updatedClient); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[API] Client updated: %+v", updatedClient)
	sendJSONResponse(w, updatedClient, http.StatusOK)
}

// deleteClient deletes a client
func (api *APIServer) deleteClient(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientIP := vars["ip"]
	log.Printf("[API] Handler: deleteClient called with IP: %s", clientIP)

	if err := api.DNSFilter.DeleteClient(clientIP); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DNS Lookup Handler

// checkDomain checks if a client is allowed to access a domain
func (api *APIServer) checkDomain(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientIP := vars["ip"]
	domain := vars["domain"]
	log.Printf("[API] Handler: checkDomain called with IP: %s, domain: %s", clientIP, domain)

	allowed := api.DNSFilter.CheckDomain(clientIP, domain)

	response := DNSCheckResponse{
		ClientIP: clientIP,
		Domain:   domain,
		Allowed:  allowed,
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// setupRoutes configures all API routes
func (api *APIServer) setupRoutes() *mux.Router {
	router := mux.NewRouter()

	// Apply middleware
	router.Use(loggerMiddleware)
	router.Use(timeoutMiddleware)

	// List management routes
	router.HandleFunc("/api/lists", api.getAllLists).Methods("GET")
	router.HandleFunc("/api/lists/{type}", api.getListsByType).Methods("GET")
	router.HandleFunc("/api/lists/{type}/{name}", api.getListContent).Methods("GET")
	router.HandleFunc("/api/lists/{type}", api.createList).Methods("POST")
	router.HandleFunc("/api/lists/{type}/{name}", api.updateList).Methods("PUT")
	router.HandleFunc("/api/lists/{type}/{name}", api.deleteList).Methods("DELETE")

	// Domain management routes
	router.HandleFunc("/api/lists/{type}/{name}/domains", api.addDomains).Methods("POST")
	router.HandleFunc("/api/lists/{type}/{name}/domains", api.removeDomains).Methods("DELETE")

	// Client management routes
	router.HandleFunc("/api/clients", api.getAllClients).Methods("GET")
	router.HandleFunc("/api/clients/{ip}", api.getClientByIP).Methods("GET")
	router.HandleFunc("/api/clients", api.createClient).Methods("POST")
	router.HandleFunc("/api/clients/{ip}", api.updateClient).Methods("PUT")
	router.HandleFunc("/api/clients/{ip}", api.deleteClient).Methods("DELETE")

	// DNS lookup routes
	router.HandleFunc("/api/check/{ip}/{domain}", api.checkDomain).Methods("GET")

	return router
}

// Initialize initializes the API server
func (api *APIServer) Initialize(configPath, blocklistDir, whitelistDir string, port int) error {
	api.mutex.Lock()
	defer api.mutex.Unlock()

	if api.running {
		return nil // Already initialized
	}

	// Get absolute paths
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	absBlocklistDir, err := filepath.Abs(blocklistDir)
	if err != nil {
		return err
	}
	absWhitelistDir, err := filepath.Abs(whitelistDir)
	if err != nil {
		return err
	}

	// Initialize DNS filter if not already provided
	if api.DNSFilter == nil {
		api.DNSFilter = dnslookup.NewDNSFilter(absConfigPath, absBlocklistDir, absWhitelistDir)
		if err := api.DNSFilter.Initialize(); err != nil {
			return err
		}
	}

	// Setup routes
	router := api.setupRoutes()

	// Configure server with timeouts
	api.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("[API] Server starting on port %d...", port)
		if err := api.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[API] Server failed to start: %v", err)
		}
	}()

	api.running = true
	return nil
}

// Shutdown gracefully stops the API server
func (api *APIServer) Shutdown(ctx context.Context) error {
	api.mutex.Lock()
	defer api.mutex.Unlock()

	if !api.running {
		return nil // Not running
	}

	log.Println("[API] Shutting down server...")
	err := api.server.Shutdown(ctx)
	api.running = false
	return err
}
