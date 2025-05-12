// Package ipblocker is a plugin for CoreDNS that blocks IP addresses and domains
package ipblocker

import (
	"context"
	"log"
	"path/filepath"
	"sync"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/ipblocker/dnslookup"
	"github.com/coredns/coredns/plugin/ipblocker/restapi"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// Default configuration paths and API port
const (
	defaultConfigPath   = "/clients.json"
	defaultBlocklistDir = "/blocklists"
	defaultWhitelistDir = "/whitelists"
	defaultAPIPort      = 8099
)

// IPBlocker is the plugin that processes DNS requests
type IPBlocker struct {
	Next      plugin.Handler
	APIPort   int
	APIServer *restapi.APIServer
	DNSFilter *dnslookup.DNSFilter
}

// Global variables for one-time initialization
var (
	setupOnce sync.Once
	instance  *IPBlocker
)

// init registers the plugin with CoreDNS
func init() {
	plugin.Register("ipblocker", setup)
}

// setup is the function called by CoreDNS when loading the plugin
func setup(c *caddy.Controller) error {
	// One-time global initialization with sync.Once
	setupOnce.Do(func() {
		log.Println("IPBlocker Plugin was initialized ONCE globally")

		// Initialize global resources like databases, caches, etc.
		instance = &IPBlocker{
			APIPort: defaultAPIPort,
		}

		// Initialize DNS filter
		configPath := defaultConfigPath
		blocklistDir := defaultBlocklistDir
		whitelistDir := defaultWhitelistDir

		// Ensure directories exist
		for _, dir := range []string{
			filepath.Dir(configPath),
			blocklistDir,
			whitelistDir,
		} {
			if err := ensureDirExists(dir); err != nil {
				log.Printf("Warning: Failed to create directory %s: %v", dir, err)
			}
		}

		// Create DNS filter
		instance.DNSFilter = dnslookup.NewDNSFilter(configPath, blocklistDir, whitelistDir)
		if err := instance.DNSFilter.Initialize(); err != nil {
			log.Printf("Error initializing DNS filter: %v", err)
		}

		// Initialize REST API
		instance.APIServer = restapi.NewAPIServer(instance.DNSFilter)
		if err := instance.APIServer.Initialize(configPath, blocklistDir, whitelistDir, instance.APIPort); err != nil {
			log.Printf("Error initializing API server: %v", err)
		}
	})

	// Parse plugin options if any
	for c.Next() {
		// This function is executed for each server block
		if c.NextArg() {
			return plugin.Error("ipblocker", c.ArgErr())
		}
	}

	// Add the plugin to CoreDNS
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		// We use the global instance and only set the Next handler
		instance.Next = next
		return instance
	})

	return nil
}

// ensureDirExists creates a directory if it doesn't exist
func ensureDirExists(dir string) error {
	// This would use os.MkdirAll in real implementation
	// For simplicity, we'll just log the action
	log.Printf("Ensuring directory exists: %s", dir)
	return nil
}

// Name implements the Plugin interface
func (ib *IPBlocker) Name() string { return "ipblocker" }

// ServeDNS implements the Plugin interface and is called for each DNS request
func (ib *IPBlocker) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// Create a recorder to capture the response
	rec := dnstest.NewRecorder(w)

	// Get information about the request
	state := request.Request{W: w, Req: r}

	// Get IP address and domain
	ip := state.IP()
	domain := state.Name()

	// Log IP and domain
	log.Printf("%s: %s", ip, domain)

	// Check if domain is allowed for this client
	allowed := true
	if ib.DNSFilter != nil {
		allowed = ib.DNSFilter.CheckDomain(ip, domain)
	}

	if !allowed {
		// Domain is blocked, return NXDOMAIN
		log.Printf("Blocking access to %s for client %s", domain, ip)

		// Create NXDOMAIN response
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		w.WriteMsg(resp)
		return dns.RcodeNameError, nil
	}

	// Domain is allowed, pass the request to the next plugin
	return plugin.NextOrFailure(ib.Name(), ib.Next, ctx, rec, r)
}
