package dnslookup

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ListMetadata contains list metadata
type ListMetadata struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"` // "blocklist" or "whitelist"
	Count        int       `json:"count"`
	LastModified time.Time `json:"lastModified"`
}

// Node represents a node in the trie (part of a domain)
type Node struct {
	Children   map[string]*Node // Child nodes (next domain parts)
	IsEndpoint bool             // Marks if a rule ends here
	Exceptions map[string]bool  // Exceptions for specific subdomains (e.g. "!mail")
}

// ClientConfig contains client configuration
type ClientConfig struct {
	IP            string   `json:"ip,omitempty"` // IP address (only for output)
	BlocklistRefs []string `json:"blocklists"`   // References to blocklists
	WhitelistRefs []string `json:"whitelists"`   // References to whitelists
	Mode          string   `json:"mode"`         // "blocklist" or "whitelist"
}

// ListContent represents the content of a list
type ListContent struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"` // "blocklist" or "whitelist"
	Domains []string `json:"domains"`
}

// DNSFilter represents the complete DNS filtering system
type DNSFilter struct {
	ConfigPath     string
	BlocklistDir   string
	WhitelistDir   string
	BlocklistTries map[string]*Node
	WhitelistTries map[string]*Node
	Clients        map[string]ClientConfig
	mutex          sync.RWMutex
}

// NewDNSFilter creates a new DNSFilter instance
func NewDNSFilter(configPath, blocklistDir, whitelistDir string) *DNSFilter {
	return &DNSFilter{
		ConfigPath:     configPath,
		BlocklistDir:   blocklistDir,
		WhitelistDir:   whitelistDir,
		BlocklistTries: make(map[string]*Node),
		WhitelistTries: make(map[string]*Node),
		Clients:        make(map[string]ClientConfig),
		mutex:          sync.RWMutex{},
	}
}

// NewNode creates a new trie node
func NewNode() *Node {
	return &Node{
		Children:   make(map[string]*Node),
		IsEndpoint: false,
		Exceptions: make(map[string]bool),
	}
}

// ReverseDomainParts splits a domain into components and reverses the order
// "mail.google.com" → ["com", "google", "mail"]
func ReverseDomainParts(domain string) []string {
	parts := strings.Split(strings.ToLower(domain), ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

// ParseDomainWithExceptions analyzes a domain entry and extracts exceptions
func ParseDomainWithExceptions(entry string) (string, []string) {
	domain := entry
	var exceptions []string

	if idx := strings.Index(entry, "!"); idx > 0 {
		parts := strings.Split(entry, "!")
		domain = strings.TrimSpace(parts[0])

		for i := 1; i < len(parts); i++ {
			exPart := strings.TrimSpace(parts[i])
			exPart = strings.Trim(exPart, ", ")
			if exPart != "" {
				exceptions = append(exceptions, exPart)
			}
		}
	}

	return domain, exceptions
}

// InsertDomain adds a domain to the trie
func InsertDomain(root *Node, domain string, exceptions []string) {
	parts := ReverseDomainParts(domain)
	currentNode := root

	for _, part := range parts {
		if _, exists := currentNode.Children[part]; !exists {
			currentNode.Children[part] = NewNode()
		}
		currentNode = currentNode.Children[part]
	}

	currentNode.IsEndpoint = true
	for _, exception := range exceptions {
		currentNode.Exceptions[exception] = true
	}
}

// IsDomainBlocked checks if a domain is blocked in a blocklist
func IsDomainBlocked(root *Node, domain string) bool {
	parts := ReverseDomainParts(domain)
	currentNode := root

	for i, part := range parts {
		child, exists := currentNode.Children[part]
		if !exists {
			return false
		}

		currentNode = child

		if currentNode.IsEndpoint {
			if i+1 < len(parts) && currentNode.Exceptions[parts[i+1]] {
				return false
			}
			return true
		}
	}

	return false
}

// IsDomainAllowed checks if a domain is allowed in a whitelist
func IsDomainAllowed(root *Node, domain string) bool {
	return IsDomainBlocked(root, domain) // Same logic as IsDomainBlocked
}

// LoadDomainList loads a domain list from a file and creates a trie
func LoadDomainList(filename string) (*Node, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %v", filename, err)
	}
	defer file.Close()

	root := NewNode()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Ignore empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		domain, exceptions := ParseDomainWithExceptions(line)
		InsertDomain(root, domain, exceptions)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", filename, err)
	}

	return root, nil
}

// FormatDomainWithExceptions formats a domain with its exceptions for the file
func FormatDomainWithExceptions(domain string, exceptions []string) string {
	if len(exceptions) == 0 {
		return domain
	}

	result := domain
	for i, exception := range exceptions {
		if i == 0 {
			result += " !" + exception
		} else {
			result += ", !" + exception
		}
	}
	return result
}

// extractDomainsFromTrie extracts all domains from a trie
func extractDomainsFromTrie(node *Node, prefix []string, result *[]string) {
	if node == nil {
		return
	}

	if node.IsEndpoint {
		reversedParts := make([]string, len(prefix))
		copy(reversedParts, prefix)
		for i, j := 0, len(reversedParts)-1; i < j; i, j = i+1, j-1 {
			reversedParts[i], reversedParts[j] = reversedParts[j], reversedParts[i]
		}
		domain := strings.Join(reversedParts, ".")

		if len(node.Exceptions) > 0 {
			exceptions := []string{}
			for exception := range node.Exceptions {
				exceptions = append(exceptions, exception)
			}
			domain = FormatDomainWithExceptions(domain, exceptions)
		}

		*result = append(*result, domain)
	}

	for part, child := range node.Children {
		newPrefix := append(prefix, part)
		extractDomainsFromTrie(child, newPrefix, result)
	}
}

// countDomainsInTrie counts the number of domains in a trie
func countDomainsInTrie(node *Node) int {
	if node == nil {
		return 0
	}

	count := 0
	if node.IsEndpoint {
		count = 1
	}

	for _, child := range node.Children {
		count += countDomainsInTrie(child)
	}

	return count
}

// LoadClientConfig loads client configuration from a JSON file
func LoadClientConfig(filename string) (map[string]ClientConfig, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return make(map[string]ClientConfig), nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening client configuration: %v", err)
	}
	defer file.Close()

	var clients map[string]ClientConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&clients); err != nil {
		return nil, fmt.Errorf("error parsing client configuration: %v", err)
	}

	return clients, nil
}

// SaveClientConfig saves client configuration to a file
func (df *DNSFilter) SaveClientConfig() error {
	dir := filepath.Dir(df.ConfigPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating directory %s: %v", dir, err)
	}

	file, err := os.Create(df.ConfigPath)
	if err != nil {
		return fmt.Errorf("error creating client configuration file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(df.Clients); err != nil {
		return fmt.Errorf("error writing client configuration: %v", err)
	}

	return nil
}

// SaveDomainList saves a domain list to a file
func (df *DNSFilter) SaveDomainList(listName, listType string, domains []string) error {
	var dirPath string
	if listType == "blocklist" {
		dirPath = df.BlocklistDir
	} else if listType == "whitelist" {
		dirPath = df.WhitelistDir
	} else {
		return fmt.Errorf("invalid list type: %s", listType)
	}

	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("error creating directory %s: %v", dirPath, err)
	}

	filePath := filepath.Join(dirPath, listName)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating list file %s: %v", filePath, err)
	}
	defer file.Close()

	file.WriteString("# Automatically generated list\n")
	file.WriteString("# Last update: " + fmt.Sprint(time.Now().Format(time.RFC3339)) + "\n\n")

	for _, domain := range domains {
		file.WriteString(domain + "\n")
	}

	return nil
}

// Initialize initializes the DNS filtering system
func (df *DNSFilter) Initialize() error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	// Initialize global data structures
	df.BlocklistTries = make(map[string]*Node)
	df.WhitelistTries = make(map[string]*Node)

	// Load client configuration
	var err error
	df.Clients, err = LoadClientConfig(df.ConfigPath)
	if err != nil {
		return fmt.Errorf("error loading client configuration: %v", err)
	}

	// Collect all unique list files
	blocklists, whitelists := df.collectUniqueListFiles()

	// Ensure directories exist
	ensureDirExists(df.BlocklistDir)
	ensureDirExists(df.WhitelistDir)

	// Load blocklists
	for _, list := range blocklists {
		path := filepath.Join(df.BlocklistDir, list)
		trie, err := LoadDomainList(path)
		if err != nil {
			log.Printf("Warning: Could not load blocklist: %v", err)
			continue
		}
		df.BlocklistTries[list] = trie
		log.Printf("Blocklist loaded: %s", list)
	}

	// Load whitelists
	for _, list := range whitelists {
		path := filepath.Join(df.WhitelistDir, list)
		trie, err := LoadDomainList(path)
		if err != nil {
			log.Printf("Warning: Could not load whitelist: %v", err)
			continue
		}
		df.WhitelistTries[list] = trie
		log.Printf("Whitelist loaded: %s", list)
	}

	log.Printf("DNS filtering system initialized with %d clients, %d blocklists, and %d whitelists",
		len(df.Clients), len(df.BlocklistTries), len(df.WhitelistTries))
	return nil
}

// collectUniqueListFiles collects all unique list files from client configuration
func (df *DNSFilter) collectUniqueListFiles() ([]string, []string) {
	blocklistsMap := make(map[string]bool)
	whitelistsMap := make(map[string]bool)

	for _, config := range df.Clients {
		for _, list := range config.BlocklistRefs {
			blocklistsMap[list] = true
		}
		for _, list := range config.WhitelistRefs {
			whitelistsMap[list] = true
		}
	}

	blocklists := mapKeysToSlice(blocklistsMap)
	whitelists := mapKeysToSlice(whitelistsMap)

	return blocklists, whitelists
}

// mapKeysToSlice converts map keys to a slice
func mapKeysToSlice(m map[string]bool) []string {
	result := make([]string, 0, len(m))
	for key := range m {
		result = append(result, key)
	}
	return result
}

// ensureDirExists creates a directory if it doesn't exist
func ensureDirExists(dir string) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("Warning: Could not create directory: %v", err)
	}
}

// GetListContent returns the content of a list
func (df *DNSFilter) GetListContent(listName, listType string) (*ListContent, error) {
	df.mutex.RLock()
	defer df.mutex.RUnlock()

	var trie *Node
	var exists bool

	if listType == "blocklist" {
		trie, exists = df.BlocklistTries[listName]
	} else if listType == "whitelist" {
		trie, exists = df.WhitelistTries[listName]
	} else {
		return nil, fmt.Errorf("invalid list type: %s", listType)
	}

	if !exists {
		return nil, fmt.Errorf("list not found: %s", listName)
	}

	domains := []string{}
	extractDomainsFromTrie(trie, []string{}, &domains)

	return &ListContent{
		Name:    listName,
		Type:    listType,
		Domains: domains,
	}, nil
}

// CreateList creates a new list
func (df *DNSFilter) CreateList(list *ListContent) error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	// Check if list already exists
	if list.Type == "blocklist" {
		if _, exists := df.BlocklistTries[list.Name]; exists {
			return fmt.Errorf("blocklist already exists: %s", list.Name)
		}
	} else if list.Type == "whitelist" {
		if _, exists := df.WhitelistTries[list.Name]; exists {
			return fmt.Errorf("whitelist already exists: %s", list.Name)
		}
	} else {
		return fmt.Errorf("invalid list type: %s", list.Type)
	}

	// Create new trie
	root := NewNode()

	// Add all domains
	for _, domainEntry := range list.Domains {
		domain, exceptions := ParseDomainWithExceptions(domainEntry)
		InsertDomain(root, domain, exceptions)
	}

	// Store in memory
	if list.Type == "blocklist" {
		df.BlocklistTries[list.Name] = root
	} else {
		df.WhitelistTries[list.Name] = root
	}

	// Save to file
	return df.SaveDomainList(list.Name, list.Type, list.Domains)
}

// UpdateList updates an existing list
func (df *DNSFilter) UpdateList(list *ListContent) error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	// Check if list exists
	var exists bool
	if list.Type == "blocklist" {
		_, exists = df.BlocklistTries[list.Name]
	} else if list.Type == "whitelist" {
		_, exists = df.WhitelistTries[list.Name]
	} else {
		return fmt.Errorf("invalid list type: %s", list.Type)
	}

	if !exists {
		return fmt.Errorf("list not found: %s", list.Name)
	}

	// Create new trie
	root := NewNode()

	// Add all domains
	for _, domainEntry := range list.Domains {
		domain, exceptions := ParseDomainWithExceptions(domainEntry)
		InsertDomain(root, domain, exceptions)
	}

	// Update in memory
	if list.Type == "blocklist" {
		df.BlocklistTries[list.Name] = root
	} else {
		df.WhitelistTries[list.Name] = root
	}

	// Save to file
	return df.SaveDomainList(list.Name, list.Type, list.Domains)
}

// DeleteList deletes a list
func (df *DNSFilter) DeleteList(listName, listType string) error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	// Check if list exists
	var exists bool
	if listType == "blocklist" {
		_, exists = df.BlocklistTries[listName]
	} else if listType == "whitelist" {
		_, exists = df.WhitelistTries[listName]
	} else {
		return fmt.Errorf("invalid list type: %s", listType)
	}

	if !exists {
		return fmt.Errorf("list not found: %s", listName)
	}

	// Remove from memory
	if listType == "blocklist" {
		delete(df.BlocklistTries, listName)
	} else {
		delete(df.WhitelistTries, listName)
	}

	// Remove file
	var dirPath string
	if listType == "blocklist" {
		dirPath = df.BlocklistDir
	} else {
		dirPath = df.WhitelistDir
	}

	// Remove references from clients
	df.removeListReferencesFromClients(listName, listType)

	filePath := filepath.Join(dirPath, listName)
	if err := os.Remove(filePath); err != nil {
		log.Printf("Warning: Could not delete file: %v", err)
	}

	return nil
}

// removeListReferencesFromClients removes references to a list from clients
func (df *DNSFilter) removeListReferencesFromClients(listName, listType string) {
	updated := false

	for ip, config := range df.Clients {
		clientUpdated := false

		if listType == "blocklist" {
			newBlocklists := removeFromSlice(config.BlocklistRefs, listName)
			if len(newBlocklists) != len(config.BlocklistRefs) {
				config.BlocklistRefs = newBlocklists
				clientUpdated = true
			}
		} else {
			newWhitelists := removeFromSlice(config.WhitelistRefs, listName)
			if len(newWhitelists) != len(config.WhitelistRefs) {
				config.WhitelistRefs = newWhitelists
				clientUpdated = true
			}
		}

		if clientUpdated {
			df.Clients[ip] = config
			updated = true
		}
	}

	if updated {
		if err := df.SaveClientConfig(); err != nil {
			log.Printf("Warning: Could not save client configuration: %v", err)
		}
	}
}

// removeFromSlice removes an item from a slice
func removeFromSlice(slice []string, item string) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

// AddDomains adds domains to a list
func (df *DNSFilter) AddDomains(listName, listType string, domains []string) error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	// Get current list
	var trie *Node
	var exists bool
	if listType == "blocklist" {
		trie, exists = df.BlocklistTries[listName]
	} else if listType == "whitelist" {
		trie, exists = df.WhitelistTries[listName]
	} else {
		return fmt.Errorf("invalid list type: %s", listType)
	}

	if !exists {
		return fmt.Errorf("list not found: %s", listName)
	}

	// Add new domains to trie
	for _, domainEntry := range domains {
		domain, exceptions := ParseDomainWithExceptions(domainEntry)
		InsertDomain(trie, domain, exceptions)
	}

	// Update in memory
	if listType == "blocklist" {
		df.BlocklistTries[listName] = trie
	} else {
		df.WhitelistTries[listName] = trie
	}

	// Get current domains for file update
	allDomains := []string{}
	extractDomainsFromTrie(trie, []string{}, &allDomains)

	// Save to file
	return df.SaveDomainList(listName, listType, allDomains)
}

// RemoveDomains removes domains from a list
func (df *DNSFilter) RemoveDomains(listName, listType string, domains []string) error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	// Get current list
	var trie *Node
	var exists bool
	if listType == "blocklist" {
		trie, exists = df.BlocklistTries[listName]
	} else if listType == "whitelist" {
		trie, exists = df.WhitelistTries[listName]
	} else {
		return fmt.Errorf("invalid list type: %s", listType)
	}

	if !exists {
		return fmt.Errorf("list not found: %s", listName)
	}

	// Create new trie
	root := NewNode()

	// Get all current domains
	currentDomains := []string{}
	extractDomainsFromTrie(trie, []string{}, &currentDomains)

	// Create map of domains to remove for fast lookup
	domainsToRemove := make(map[string]bool)
	for _, domain := range domains {
		baseDomain, _ := ParseDomainWithExceptions(domain)
		domainsToRemove[baseDomain] = true
	}

	// Add only domains that should not be removed
	remainingDomains := []string{}
	for _, domainEntry := range currentDomains {
		baseDomain, exceptions := ParseDomainWithExceptions(domainEntry)
		if !domainsToRemove[baseDomain] {
			InsertDomain(root, baseDomain, exceptions)
			remainingDomains = append(remainingDomains, domainEntry)
		}
	}

	// Update in memory
	if listType == "blocklist" {
		df.BlocklistTries[listName] = root
	} else {
		df.WhitelistTries[listName] = root
	}

	// Save to file
	return df.SaveDomainList(listName, listType, remainingDomains)
}

// GetAllLists returns metadata for all lists
func (df *DNSFilter) GetAllLists() []ListMetadata {
	df.mutex.RLock()
	defer df.mutex.RUnlock()

	result := []ListMetadata{}

	// Add blocklists
	for name, trie := range df.BlocklistTries {
		count := countDomainsInTrie(trie)
		filePath := filepath.Join(df.BlocklistDir, name)
		lastModified := getLastModifiedTime(filePath)

		result = append(result, ListMetadata{
			Name:         name,
			Type:         "blocklist",
			Count:        count,
			LastModified: lastModified,
		})
	}

	// Add whitelists
	for name, trie := range df.WhitelistTries {
		count := countDomainsInTrie(trie)
		filePath := filepath.Join(df.WhitelistDir, name)
		lastModified := getLastModifiedTime(filePath)

		result = append(result, ListMetadata{
			Name:         name,
			Type:         "whitelist",
			Count:        count,
			LastModified: lastModified,
		})
	}

	return result
}

// getLastModifiedTime returns the last modified time of a file
func getLastModifiedTime(filePath string) time.Time {
	fileInfo, err := os.Stat(filePath)
	if err == nil {
		return fileInfo.ModTime()
	}
	return time.Now()
}

// GetListsByType returns metadata for all lists of a specific type
func (df *DNSFilter) GetListsByType(listType string) []ListMetadata {
	df.mutex.RLock()
	defer df.mutex.RUnlock()

	result := []ListMetadata{}

	if listType == "blocklist" {
		for name, trie := range df.BlocklistTries {
			count := countDomainsInTrie(trie)
			filePath := filepath.Join(df.BlocklistDir, name)
			lastModified := getLastModifiedTime(filePath)

			result = append(result, ListMetadata{
				Name:         name,
				Type:         "blocklist",
				Count:        count,
				LastModified: lastModified,
			})
		}
	} else if listType == "whitelist" {
		for name, trie := range df.WhitelistTries {
			count := countDomainsInTrie(trie)
			filePath := filepath.Join(df.WhitelistDir, name)
			lastModified := getLastModifiedTime(filePath)

			result = append(result, ListMetadata{
				Name:         name,
				Type:         "whitelist",
				Count:        count,
				LastModified: lastModified,
			})
		}
	}

	return result
}

// GetAllClients returns all client configurations
func (df *DNSFilter) GetAllClients() []ClientConfig {
	df.mutex.RLock()
	defer df.mutex.RUnlock()

	result := []ClientConfig{}
	for ip, config := range df.Clients {
		clientConfig := ClientConfig{
			IP:            ip,
			BlocklistRefs: make([]string, len(config.BlocklistRefs)),
			WhitelistRefs: make([]string, len(config.WhitelistRefs)),
			Mode:          config.Mode,
		}

		copy(clientConfig.BlocklistRefs, config.BlocklistRefs)
		copy(clientConfig.WhitelistRefs, config.WhitelistRefs)

		result = append(result, clientConfig)
	}

	return result
}

// GetClientByIP returns the configuration for a specific client
func (df *DNSFilter) GetClientByIP(ip string) (*ClientConfig, error) {
	df.mutex.RLock()
	defer df.mutex.RUnlock()

	config, exists := df.Clients[ip]
	if !exists {
		return nil, fmt.Errorf("client not found: %s", ip)
	}

	result := ClientConfig{
		IP:            ip,
		BlocklistRefs: make([]string, len(config.BlocklistRefs)),
		WhitelistRefs: make([]string, len(config.WhitelistRefs)),
		Mode:          config.Mode,
	}

	copy(result.BlocklistRefs, config.BlocklistRefs)
	copy(result.WhitelistRefs, config.WhitelistRefs)

	return &result, nil
}

// CreateClient creates a new client
func (df *DNSFilter) CreateClient(client *ClientConfig) error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	// Check if client already exists
	if _, exists := df.Clients[client.IP]; exists {
		return fmt.Errorf("client already exists: %s", client.IP)
	}

	// Check if all referenced lists exist
	if err := df.validateListReferences(client); err != nil {
		return err
	}

	// Check mode
	if client.Mode != "blocklist" && client.Mode != "whitelist" {
		return fmt.Errorf("invalid mode: %s", client.Mode)
	}

	// Copy client configuration
	config := ClientConfig{
		BlocklistRefs: make([]string, len(client.BlocklistRefs)),
		WhitelistRefs: make([]string, len(client.WhitelistRefs)),
		Mode:          client.Mode,
	}

	copy(config.BlocklistRefs, client.BlocklistRefs)
	copy(config.WhitelistRefs, client.WhitelistRefs)

	// Store in memory
	df.Clients[client.IP] = config

	// Save to file
	return df.SaveClientConfig()
}

// validateListReferences checks if all referenced lists exist
func (df *DNSFilter) validateListReferences(client *ClientConfig) error {
	for _, listName := range client.BlocklistRefs {
		if _, exists := df.BlocklistTries[listName]; !exists {
			return fmt.Errorf("referenced blocklist not found: %s", listName)
		}
	}
	for _, listName := range client.WhitelistRefs {
		if _, exists := df.WhitelistTries[listName]; !exists {
			return fmt.Errorf("referenced whitelist not found: %s", listName)
		}
	}
	return nil
}

// UpdateClient updates an existing client
func (df *DNSFilter) UpdateClient(client *ClientConfig) error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	// Check if client exists
	if _, exists := df.Clients[client.IP]; !exists {
		return fmt.Errorf("client not found: %s", client.IP)
	}

	// Check if all referenced lists exist
	if err := df.validateListReferences(client); err != nil {
		return err
	}

	// Check mode
	if client.Mode != "blocklist" && client.Mode != "whitelist" {
		return fmt.Errorf("invalid mode: %s", client.Mode)
	}

	// Copy client configuration
	config := ClientConfig{
		BlocklistRefs: make([]string, len(client.BlocklistRefs)),
		WhitelistRefs: make([]string, len(client.WhitelistRefs)),
		Mode:          client.Mode,
	}

	copy(config.BlocklistRefs, client.BlocklistRefs)
	copy(config.WhitelistRefs, client.WhitelistRefs)

	// Store in memory
	df.Clients[client.IP] = config

	// Save to file
	return df.SaveClientConfig()
}

// DeleteClient deletes a client
func (df *DNSFilter) DeleteClient(ip string) error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	// Check if client exists
	if _, exists := df.Clients[ip]; !exists {
		return fmt.Errorf("client not found: %s", ip)
	}

	// Remove from memory
	delete(df.Clients, ip)

	// Save to file
	return df.SaveClientConfig()
}

// CheckDomain checks if a client is allowed to access a domain
func (df *DNSFilter) CheckDomain(clientIP, domain string) bool {
	df.mutex.RLock()
	defer df.mutex.RUnlock()

	// Get client configuration
	config, exists := df.Clients[clientIP]
	if !exists {
		log.Printf("Unknown client: %s", clientIP)
		return false // Unknown client
	}

	// Blocklist mode
	if config.Mode == "blocklist" {
		// Check if domain is blocked in ANY of the blocklists
		for _, listName := range config.BlocklistRefs {
			trie, exists := df.BlocklistTries[listName]
			if !exists {
				log.Printf("Warning: Referenced blocklist not found: %s", listName)
				continue
			}

			if IsDomainBlocked(trie, domain) {
				log.Printf("Domain %s for client %s blocked by blocklist %s",
					domain, clientIP, listName)
				return false // Domain is blocked
			}
		}
		return true // Domain is allowed (not in any blocklist)
	}

	// Whitelist mode
	if config.Mode == "whitelist" {
		// Check if domain is allowed in ANY of the whitelists
		for _, listName := range config.WhitelistRefs {
			trie, exists := df.WhitelistTries[listName]
			if !exists {
				log.Printf("Warning: Referenced whitelist not found: %s", listName)
				continue
			}

			if IsDomainAllowed(trie, domain) {
				log.Printf("Domain %s for client %s allowed by whitelist %s",
					domain, clientIP, listName)
				return true // Domain is allowed
			}
		}
		log.Printf("Domain %s for client %s blocked (not in whitelist)", domain, clientIP)
		return false // Domain is blocked (not in any whitelist)
	}

	log.Printf("Invalid mode for client %s: %s", clientIP, config.Mode)
	return false // Default behavior for invalid mode
}
