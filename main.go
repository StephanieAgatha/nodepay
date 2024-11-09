package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	browser "github.com/itzngga/fake-useragent"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	ProxyURLTemplate string
	SessionURL       string
	PingURL          string
	RetryInterval    time.Duration
	IPCheckURL       string
	BaseURL          string
}

type IPInfo struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
}

type Bot struct {
	config     Config
	logger     *log.Logger
	client     NodePayClient
	proxyCheck ProxyChecker
}

type AccountInfo struct {
	UID       string `json:"uid"`
	BrowserID string `json:"browser_id"`
	Name      string `json:"name"`
}

type DefaultProxyChecker struct {
	config     Config
	clientPool *FastHTTPClientPool
}

type ProxyDistributor struct {
	tokens  []string
	proxies []string
	logger  *log.Logger
}

type NodePayClient interface {
	Connect(ctx context.Context, proxy, token string) error
}

type ProxyChecker interface {
	GetProxyIP(proxy string) (*IPInfo, error)
}

type DefaultNodePayClient struct {
	config     Config
	logger     *log.Logger
	clientPool *FastHTTPClientPool
}

type FastHTTPClientPool struct {
	pool sync.Pool
}

func (p *FastHTTPClientPool) Get() *fasthttp.Client {
	return p.pool.Get().(*fasthttp.Client)
}

func (p *FastHTTPClientPool) Put(c *fasthttp.Client) {
	p.pool.Put(c)
}

func NewBot(config Config, logger *log.Logger) *Bot {
	proxyChecker := NewDefaultProxyChecker(config)
	return &Bot{
		config:     config,
		logger:     logger,
		client:     NewDefaultNodePayClient(config, logger),
		proxyCheck: proxyChecker,
	}
}

func NewDefaultNodePayClient(config Config, logger *log.Logger) *DefaultNodePayClient {
	return &DefaultNodePayClient{
		config:     config,
		logger:     logger,
		clientPool: NewFastHTTPClientPool(),
	}
}

func NewFastHTTPClientPool() *FastHTTPClientPool {
	return &FastHTTPClientPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &fasthttp.Client{
					MaxConnsPerHost:     1000,
					ReadTimeout:         30 * time.Second,
					WriteTimeout:        30 * time.Second,
					MaxIdleConnDuration: 5 * time.Minute,
					MaxConnDuration:     10 * time.Minute,
					MaxConnWaitTimeout:  30 * time.Second,
				}
			},
		},
	}
}

func NewDefaultProxyChecker(config Config) *DefaultProxyChecker {
	return &DefaultProxyChecker{
		config:     config,
		clientPool: NewFastHTTPClientPool(),
	}
}

func NewProxyDistributor(tokens, proxies []string, logger *log.Logger) *ProxyDistributor {
	return &ProxyDistributor{
		tokens:  tokens,
		proxies: proxies,
		logger:  logger,
	}
}

func (pd *ProxyDistributor) Validate() error {
	if len(pd.tokens) == 0 || len(pd.proxies) == 0 {
		return fmt.Errorf("no tokens or proxies found")
	}

	if len(pd.tokens) > len(pd.proxies) {
		return fmt.Errorf("number of tokens (%d) cannot be greater than number of proxies (%d)",
			len(pd.tokens), len(pd.proxies))
	}

	return nil
}

func (pd *ProxyDistributor) DistributeProxies() map[string][]string {
	distribution := make(map[string][]string)
	baseProxiesPerToken := len(pd.proxies) / len(pd.tokens)
	remainingProxies := len(pd.proxies) % len(pd.tokens)

	currentIndex := 0
	for i, token := range pd.tokens {
		proxiesForThisToken := baseProxiesPerToken
		if i == 0 {
			proxiesForThisToken += remainingProxies
		}

		distribution[token] = pd.proxies[currentIndex : currentIndex+proxiesForThisToken]
		currentIndex += proxiesForThisToken

		pd.logger.Info("distributed proxies for token",
			"tokenPrefix", token[:8]+"...",
			"proxyCount", len(distribution[token]))
	}

	return distribution
}

func initLogger() *log.Logger {
	logger := log.NewWithOptions(os.Stderr, log.Options{
		ReportCaller:    true,
		ReportTimestamp: true,
		TimeFormat:      "2006-01-02 15:04:05",
		Level:           log.InfoLevel,
		Prefix:          "NodePay ⚡",
	})

	styles := log.DefaultStyles()
	styles.Levels[log.ErrorLevel] = lipgloss.NewStyle().
		SetString("ERROR").
		Padding(0, 1, 0, 1).
		Foreground(lipgloss.Color("204"))

	styles.Keys["error"] = lipgloss.NewStyle().
		Foreground(lipgloss.Color("204"))
	styles.Values["error"] = lipgloss.NewStyle()

	styles.Key = lipgloss.NewStyle().
		Foreground(lipgloss.Color("51"))

	logger.SetStyles(styles)
	os.Setenv("TZ", "Asia/Jakarta")

	return logger
}

func (pc *DefaultProxyChecker) GetProxyIP(proxy string) (*IPInfo, error) {
	var proxyURL string
	if strings.HasPrefix(proxy, "socks5://") {
		proxyURL = proxy
	} else if strings.HasPrefix(proxy, "http://") {
		proxyURL = proxy
	} else {
		proxyURL = "socks5://" + proxy
	}

	client := pc.clientPool.Get()
	client.Dial = fasthttpproxy.FasthttpSocksDialer(proxyURL)
	client.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	defer pc.clientPool.Put(client)

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(pc.config.IPCheckURL)
	req.Header.SetMethod("GET")

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := client.DoTimeout(req, resp, 30*time.Second); err != nil {
		return nil, fmt.Errorf("failed to perform GET request: %v", err)
	}

	var ipInfo IPInfo
	if err := json.Unmarshal(resp.Body(), &ipInfo); err != nil {
		return nil, fmt.Errorf("could not unmarshal response body: %v", err)
	}

	return &ipInfo, nil
}

func (c *DefaultNodePayClient) getSession(client *fasthttp.Client, token string, userAgent string) (*AccountInfo, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(c.config.SessionURL)
	req.Header.SetMethod("POST")

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Referer", "https://app.nodepay.ai")

	req.SetBody([]byte("{}"))

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := client.DoTimeout(req, resp, 30*time.Second); err != nil {
		return nil, fmt.Errorf("request error")
	}

	statusCode := resp.StatusCode()
	body := resp.Body()

	if statusCode == fasthttp.StatusOK {
		var response struct {
			Code int         `json:"code"`
			Data AccountInfo `json:"data"`
		}

		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("parse error")
		}

		if response.Code != 0 {
			return nil, fmt.Errorf("api error: code %d", response.Code)
		}

		if response.Data.UID == "" {
			return nil, fmt.Errorf("invalid data")
		}

		// Log user info
		c.logger.Info("session info",
			"uid", response.Data.UID[:8]+"...",
			"name", response.Data.Name)

		return &response.Data, nil
	}

	return nil, fmt.Errorf("status %d", statusCode)
}

func (c *DefaultNodePayClient) sendPing(client *fasthttp.Client, accountInfo *AccountInfo, token string, userAgent string) error {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(c.config.PingURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.nodepay.ai")
	req.Header.Set("Referer", "https://app.nodepay.ai/")
	req.Header.Set("User-Agent", userAgent)

	uid := accountInfo.UID
	browserId := accountInfo.BrowserID

	if uid == "default_uid" || uid == "" {
		h := sha256.New()
		h.Write([]byte(token))
		uid = fmt.Sprintf("%x", h.Sum(nil))[:16]
	}

	if browserId == "default_browser_id" || browserId == "" {
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%s_%d", token, time.Now().UnixNano())))
		browserId = fmt.Sprintf("%x", h.Sum(nil))[:16]
	}

	pingData := map[string]interface{}{
		"id":         uid,
		"browser_id": browserId,
		"timestamp":  int(time.Now().Unix()),
		"version":    "2.2.7",
	}

	pingJSON, err := json.Marshal(pingData)
	if err != nil {
		return fmt.Errorf("request error")
	}

	req.SetBody(pingJSON)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := client.DoTimeout(req, resp, 30*time.Second); err != nil {
		return fmt.Errorf("request error")
	}

	statusCode := resp.StatusCode()
	if statusCode != fasthttp.StatusOK {
		return fmt.Errorf("status %d", statusCode)
	}

	uidDisplay := uid
	browserDisplay := browserId
	if len(uid) > 8 {
		uidDisplay = uid[:8] + "..."
	}
	if len(browserId) > 8 {
		browserDisplay = browserId[:8] + "..."
	}

	c.logger.Info("ping sent",
		"uid", uidDisplay,
		"browser", browserDisplay)

	return nil
}

func (c *DefaultNodePayClient) Connect(ctx context.Context, proxy, token string) error {
	client := c.clientPool.Get()
	defer c.clientPool.Put(client)

	if proxy != "" {
		client.Dial = fasthttpproxy.FasthttpSocksDialer(proxy)
	}

	userAgent := browser.Chrome()
	c.logger.Info("using user agent", "ua", userAgent)

	accountInfo, err := c.getSession(client, token, userAgent)
	if err != nil {
		c.logger.Warn("session error")
		h := sha256.New()
		h.Write([]byte(token))
		uid := fmt.Sprintf("%x", h.Sum(nil))[:16]

		h.Reset()
		h.Write([]byte(fmt.Sprintf("%s_%d", token, time.Now().UnixNano())))
		browserId := fmt.Sprintf("%x", h.Sum(nil))[:16]

		accountInfo = &AccountInfo{
			UID:       uid,
			BrowserID: browserId,
		}
	} else {
		c.logger.Info("session ok")
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	if err := c.sendPing(client, accountInfo, token, userAgent); err != nil {
		c.logger.Error("ping error")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.sendPing(client, accountInfo, token, userAgent); err != nil {
				c.logger.Error("ping error")
				continue
			}
		}
	}
}

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func main() {
	config := Config{
		SessionURL:    "http://18.136.143.169/api/auth/session",
		PingURL:       "http://54.255.192.166/api/network/ping",
		RetryInterval: 30 * time.Second,
		IPCheckURL:    "https://ipinfo.io/json",
		BaseURL:       "https://nodepay.org",
	}

	logger := initLogger()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	tokens, err := readLines("token.txt")
	if err != nil {
		logger.Fatal("error reading tokens", "error", err)
	}

	proxies, err := readLines("proxy.txt")
	if err != nil {
		logger.Fatal("error reading proxies", "error", err)
	}

	distributor := NewProxyDistributor(tokens, proxies, logger)
	if err := distributor.Validate(); err != nil {
		logger.Fatal("proxy distribution validation failed", "error", err)
	}

	proxyDistribution := distributor.DistributeProxies()

	bot := NewBot(config, logger)
	var wg sync.WaitGroup

	done := make(chan struct{})

	go func() {
		for token, tokenProxies := range proxyDistribution {
			currentProxyIndex := 0
			maxProxyIndex := len(tokenProxies)

			wg.Add(1)
			go func(token string, proxies []string) {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						logger.Info("shutting down connection",
							"tokenPrefix", token[:8]+"...")
						return
					default:
						proxy := proxies[currentProxyIndex]
						currentProxyIndex = (currentProxyIndex + 1) % maxProxyIndex

						ipInfo, err := bot.proxyCheck.GetProxyIP(proxy)
						if err != nil {
							logger.Error("proxy check failed",
								"error", err,
								"proxy", proxy)
							continue
						}

						logger.Info("using proxy",
							"tokenPrefix", token[:8]+"...",
							"proxy", proxy,
							"ip", ipInfo.IP,
							"location", fmt.Sprintf("%s, %s, %s", ipInfo.City, ipInfo.Region, ipInfo.Country))

						if err := bot.client.Connect(ctx, proxy, token); err != nil {
							logger.Error("connection error",
								"error", err,
								"tokenPrefix", token[:8]+"...",
								"proxy", proxy)
							select {
							case <-ctx.Done():
								return
							case <-time.After(config.RetryInterval):
								continue
							}
						}
					}
				}
			}(token, tokenProxies)
		}
		wg.Wait()
		close(done)
	}()

	select {
	case sig := <-signals:
		logger.Info("received shutdown signal", "signal", sig.String())
		cancel()
		shutdownTimeout := time.NewTimer(30 * time.Second)
		select {
		case <-done:
			logger.Info("all connections closed successfully")
		case <-shutdownTimeout.C:
			logger.Warn("shutdown timed out, forcing exit")
		}

		logger.Info("cleaning up resources")
		time.Sleep(2 * time.Second)

	case <-done:
		logger.Info("all connections finished naturally")
	}

	logger.Info("program exiting")
}
