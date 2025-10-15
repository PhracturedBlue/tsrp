package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/goccy/go-yaml"
	"github.com/joho/godotenv"
	"github.com/rjeczalik/notify"
	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

var (
	configProxyFile   = flag.String("config", "", "proxy file to use")
	configSocketDir   = flag.String("socketdir", "", "socket directory")
	configTSName      = flag.String("tsname", "", "tailscale name")
	configAddress     = flag.String("address", "http://localhost", "forwarding address for -tsname")
	configTransparent = flag.Bool("transparent", false, "use transparent proxy for -tsname")
	configStateDir    = flag.String("statedir", "", "Tailscale state dir")
	configSocketPerm  = flag.Int("socketperm", -1, "override socket permissions")
	configHTTPS       = flag.Bool("https", false, "Enable HTTPS endpoints for each HTTP endpoint")
	configVerbose     = flag.Bool("verbose", false, "if set, verbosely log tsnet information")
	configIgnore      arrayFlags
	delay             int = 5
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type ProxyConfig struct {
	server      *http.Server
	serverTLS   *http.Server
	Hostname    string
	Origin      string
	Transparent bool
	Https       bool
}

func (i *ProxyConfig) unmarshalWithDefaults(b []byte) error {
	i.Https = *configHTTPS
	return yaml.Unmarshal(b, i)
}

type ProxyPair struct {
	server    *http.Server
	serverTLS *http.Server
}

type NetworkMonitor struct {
	Client *local.Client
	Alive  bool
}

func parseProxies(configPath string) []ProxyConfig {
	var proxies []ProxyConfig
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}
	err = yaml.UnmarshalWithOptions(data, &proxies, yaml.CustomUnmarshaler((*ProxyConfig).unmarshalWithDefaults))
	if err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}
	return proxies
}
func udsReverseProxy(url *url.URL) (udsProxy *httputil.ReverseProxy) {
	uds := url.Path
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			if req.URL.Scheme == "" {
				req.URL.Scheme = "http"
			}
			req.URL.Scheme = "http"
			req.Proto = "HTTP/1.1"
			req.ProtoMajor = 1
			req.ProtoMinor = 1
			req.URL.Host = "unix" // Placeholder, not used for Unix sockets
			//req.URL.Path = "" // Path to your Unix socket
			req.Header.Set("X-Real-IP", req.RemoteAddr)
			req.Header.Set("X-Original-URI", strings.Split(req.RequestURI, ":")[0])
			req.Header.Set("X-Forwarded-Port", url.Port())
		},
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return net.Dial("unix", uds)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	return proxy
}

func hasScheme(url *url.URL, scheme string) bool {
	schemes := strings.Split(url.Scheme, "+")
	for _, item := range schemes {
		if scheme == item {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func transparentProxy(listener net.Listener, url *url.URL) {
	copyData := func(src, dst net.Conn) {
		_, err := io.Copy(dst, src)
		if err != nil {
			log.Printf("Error copying data:", err)
		}
	}
	handleConnection := func(clientConn net.Conn) {
		scheme := "tcp"
		addr := url.String()
		if hasScheme(url, "unix") {
			scheme = "unix"
			addr = url.Path
		}
		targetConn, err := net.Dial(scheme, addr)
		if err != nil {
			log.Printf("Error dialing target:", err)
			return
		}
		defer targetConn.Close()

		go copyData(clientConn, targetConn)
		copyData(targetConn, clientConn)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection:", err)
			continue
		}

		go handleConnection(conn)
	}

}

func createProxy(wg *sync.WaitGroup, proxy ProxyConfig, netmon chan NetworkMonitor) error {
	defer wg.Done()
	if proxy.server == nil {
		proxy.server = &http.Server{}
	}
	originServerURL, err := url.Parse(proxy.Origin)
	if err != nil {
		log.Fatal("invalid origin server URL")
	}

	stateDir := filepath.Join(*configStateDir, proxy.Hostname)
	err = os.MkdirAll(stateDir, 0700)

	if err != nil {
		log.Fatalf("can't make proxy state directory: %v", err)
	}

	server := &tsnet.Server{
		Hostname: proxy.Hostname,
		Dir:      stateDir,
	}

	defer server.Close()
	if *configVerbose {
		server.Logf = log.New(os.Stderr, fmt.Sprintf("[tsnet:%s] ", proxy.Hostname), log.LstdFlags).Printf
	} else {
		server.Logf = nil
	}

	lc, err := server.LocalClient()
	if err != nil {
		log.Fatal(err)
	}
	netmon <- NetworkMonitor{Client: lc, Alive: true}
	defer func() {
		netmon <- NetworkMonitor{Client: lc, Alive: false}
	}()

	port := ":80"
	portTLS := ":443"
	var listenerTLS net.Listener
	var listener net.Listener

	if proxy.Transparent {
		if proxy.Https {
			port = portTLS
		}
		listener, err = server.Listen("tcp", port)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close()
		log.Printf("Setting up transparent proxy for %s on port %s", proxy.Hostname, port)
		transparentProxy(listener, originServerURL)
		return nil
	}

	var reverseProxy *httputil.ReverseProxy
	if hasScheme(originServerURL, "unix") {
		reverseProxy = udsReverseProxy(originServerURL)
	} else {
		reverseProxy = httputil.NewSingleHostReverseProxy(originServerURL)
	}

	if proxy.Https {
		if proxy.serverTLS == nil {
			proxy.serverTLS = &http.Server{}
		}
		listenerTLS, err = server.ListenTLS("tcp", portTLS)
		if err != nil {
			log.Fatal(err)
		}
		defer listenerTLS.Close()
		proxy.serverTLS.Handler = reverseProxy
		log.Printf("Serving https on %s -> %s://%s", proxy.Hostname, originServerURL.Scheme, originServerURL.Path)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := proxy.serverTLS.Serve(listenerTLS)
			if err != nil {
				log.Printf("Error serving https proxy for %s: %v", proxy.Hostname, err)
			}
		}()
	}

	listener, err = server.Listen("tcp", port)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	proxy.server.Handler = reverseProxy
	log.Printf("Serving http on %s -> %s://%s", proxy.Hostname, originServerURL.Scheme, originServerURL.Path)
	err = proxy.server.Serve(listener)
	if err != nil {
		log.Printf("Error serving proxy for %s: %v", proxy.Hostname, err)
	}
	return err
}

func ScanSockets(wg *sync.WaitGroup, proxies map[string]*ProxyPair, netmon chan NetworkMonitor) {
	log.Println("Scanning...")
	defer log.Println("Scanning complete")
	permissions := *configSocketPerm
	globpaths, err := filepath.Glob(*configSocketDir + "/*/*")
	if err != nil {
		log.Printf("Could not scan %v: %v\n", *configSocketDir, err)
		return
	}
	seen := make(map[string]bool)
	for _, filename := range globpaths {
		s, err := os.Stat(filename)
		if err != nil {
			log.Printf("Could not stat %v\n", filename)
			continue
		}
		hostname := strings.Split(path.Base(path.Dir(filename)), ".")[0]
		if s.Mode().Type() == fs.ModeSocket {
			_, ok := proxies[hostname]
			if ok {
				seen[hostname] = true
				continue
			}

			if slices.Contains(configIgnore, hostname) {
				log.Printf("Ignoring %s\n", hostname)
				continue
			}
			transparent := false
			https := *configHTTPS
			if permissions != -1 && (s.Mode().Perm()&os.FileMode(permissions)) != os.FileMode(permissions) {
				os.Chmod(filename, s.Mode().Perm()|os.FileMode(permissions))
			}
			proxies[hostname] = &ProxyPair{server: &http.Server{}}
			proxy := ProxyConfig{
				Hostname:    hostname,
				Origin:      "unix:" + filename,
				server:      proxies[hostname].server,
				serverTLS:   proxies[hostname].serverTLS,
				Https:       https,
				Transparent: transparent,
			}
			ovrd_file := filepath.Join(path.Dir(filename), "host.yml")
			if fileExists(ovrd_file) {
				data, err := os.ReadFile(ovrd_file)
				if err != nil {
					log.Printf("Failed to read %v: %v", ovrd_file, err)
				} else {
					log.Printf("Reading %v", ovrd_file)
					var m map[string]string
					err = yaml.Unmarshal(data, &m)
					if err != nil {
						log.Printf("Failed to parse %v: %v", ovrd_file, err)
					} else {
						if val, ok := m["name"]; ok {
							log.Printf("%v sets hostname=%s", ovrd_file, val)
							proxy.Hostname = val
						}
						if val, ok := m["mode"]; ok && val == "grpcs" {
							log.Printf("%v sets transparent=true, https=true\n", ovrd_file)
							proxy.Transparent = true
							proxy.Https = true
						}
						if val, ok := m["https"]; ok {
							proxy.Https = val == "true"
							log.Printf("%v sets https=%t\n", ovrd_file, proxy.Https)
						}
						if val, ok := m["transparent"]; ok {
							proxy.Transparent = val == "true"
							log.Printf("%v sets transparent=%t\n", ovrd_file, proxy.Transparent)
						}
					}
				}
			}
			if https && !transparent {
				proxies[hostname].serverTLS = &http.Server{}
				proxy.serverTLS = proxies[hostname].serverTLS
			}
			seen[hostname] = true
			wg.Add(1)
			go createProxy(wg, proxy, netmon)
		}
	}
	for hostname, srvrs := range proxies {
		_, ok := seen[hostname]
		if !ok {
			log.Printf("Shutting down http server %s\n", hostname)
			if err := srvrs.server.Shutdown(context.Background()); err != nil {
				log.Printf("Server shutdown error: %v\n", err)
			}
			if srvrs.serverTLS != nil {
				log.Printf("Shutting down https server %s\n", hostname)
				if err = srvrs.serverTLS.Shutdown(context.Background()); err != nil {
					log.Printf("TLS Server shutdown error: %v\n", err)
				}
			}
			delete(proxies, hostname)
		}
	}
}

func ScanMonitor(ch chan bool, wg *sync.WaitGroup, proxies map[string]*ProxyPair, netmon chan NetworkMonitor) {
	for _ = range ch {
		time.Sleep(time.Duration(delay) * time.Second)
	Loop:
		for {
			// Clear channel if there were any signals while sleeping
			select {
			case _ = <-ch:
			default:
				break Loop
			}
		}
		ScanSockets(wg, proxies, netmon)
	}
}

func networkMonitor(netmon chan NetworkMonitor) {
	clients := make(map[*local.Client]string)
	starting := make(map[*local.Client]time.Time)
	for {
		select {
		case nm := <-netmon:
			if nm.Alive {
				// Could also use status->CertDomains here
				prefs, err := nm.Client.GetPrefs(context.Background())
				if err != nil {
					log.Printf("Failed to get preferences for client.  Ignoring")
					continue
				}
				clients[nm.Client] = prefs.Hostname
				log.Printf("Monitoring client: %s", prefs.Hostname)
				starting[nm.Client] = time.Now().Add(30 * time.Second)
			} else {
				if host, ok := clients[nm.Client]; ok {
					log.Printf("Removing %s from network monitoring", host)
					delete(clients, nm.Client)
				}
			}
		case <-time.After(5 * time.Minute): // empty
		}
		log.Printf("Starting netmon loop")
		for client, name := range clients {
			status, err := client.StatusWithoutPeers(context.Background())
			if err != nil {
				log.Printf("Failed to get status for %s: %s", name, err)
				continue
			}
			unhealthy := []string{}
			start, ok := starting[client]
			if ok {
				if time.Now().After(start) {
					delete(starting, client)
				} else if status.BackendState == "Starting" || status.BackendState == "NoState" {
					continue
				}
			}
			if status.BackendState != "Running" {
				unhealthy = append(unhealthy, fmt.Sprintf("state = %s", status.BackendState))
			}
			for _, state := range status.Health {
				if strings.Contains(state, "getting OS base config is not supported") {
					continue
				}
				unhealthy = append(unhealthy, state)
			}
			if len(unhealthy) != 0 {
				log.Printf("%s is unhealthy: %s", name, strings.Join(unhealthy, ", "))
			}
		}
	}
}

func main() {
	var err error
	socketproxies := make(map[string]*ProxyPair)

	flag.Var(&configIgnore, "ignore", "Ignore service")
	flag.Parse()

	if *configProxyFile == "" && *configSocketDir == "" && *configTSName == "" {
		log.Fatal("At least one of -config, -socketdir, or -tsname must be specified")
	}

	if *configStateDir == "" {
		defaultDirectory, err := os.UserConfigDir()
		if err != nil {
			log.Fatalf("can't find default user config directory: %v", err)
		}
		*configStateDir = filepath.Join(defaultDirectory, "tsrp")
	}
	err = godotenv.Load()
	if err != nil {
		log.Print("Could not read .env file")
	}

	var wg sync.WaitGroup
	netmon := make(chan NetworkMonitor, 20)

	if *configProxyFile != "" {
		proxies := parseProxies(*configProxyFile)
		for _, proxy := range proxies {
			if slices.Contains(configIgnore, proxy.Hostname) {
				log.Printf("Ignoring %s\n", proxy.Hostname)
				continue
			}
			wg.Add(1)
			go createProxy(&wg, proxy, netmon)
		}
	}

	if *configTSName != "" {
		wg.Add(1)
		go func() {
			createProxy(&wg, ProxyConfig{
				Hostname:    *configTSName,
				Origin:      *configAddress,
				Transparent: *configTransparent,
				Https:       *configHTTPS,
			},
				netmon)
		}()
	}
	if *configSocketDir != "" {
		c := make(chan notify.EventInfo, 1)
		path := *configSocketDir + string(os.PathSeparator) + "..."
		if err := notify.Watch(path, c, notify.All); err != nil {
			log.Fatalf("Failed to create inotify watcher for %v: %v", path, err)
		}
		defer notify.Stop(c)
		ScanSockets(&wg, socketproxies, netmon) // scan once to find existing sockets
		scanch := make(chan bool, 1)
		go ScanMonitor(scanch, &wg, socketproxies, netmon)
		go func() {
			for ei := range c {
				log.Println("received", ei)
				select {
				case scanch <- true: // indicate a change
				default: // a change is already indicated, no need to duplicate
				}
			}
		}()
	}

	go networkMonitor(netmon)

	wg.Wait()
}
