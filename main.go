package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"crypto/tls"
	"crypto/x509"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// AppResponse ..
type AppResponse struct {
	App App `json:"app"`
}

// AttemptResponse ..
type AttemptResponse struct {
	AppAttempts struct {
		AppAttempt []Attempt `json:"appAttempt"`
	} `json:"appAttempts"`
}

// Attempt ...
type Attempt struct {
	ID int `json:"id"`
}

// TMResponse ...
type TMResponse struct {
	List []TaskManager `json:"taskmanagers"`
}

// FlinkOverview ...
type FlinkOverview struct {
	TMCount      int    `json:"taskmanagers"`
	FlinkVersion string `json:"flink-version"`
}

// Object ...
type Object struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// App contains info of flink app
type App struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	State             string `json:"state"`
	AppType           string `json:"applicationType"`
	TrackingURL       string `json:"trackingUrl"`
	RunningContainers int    `json:"runningContainers"`
	LastAttemptID     int
}

// TaskManager ...
type TaskManager struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

// Host is ip:port ...
type Host struct {
	IP   string
	Port string
}

// ClusterApp ...
type ClusterApp struct {
	Apps struct {
		App []App `json:"app"`
	} `json:"apps"`
}

// JSONFile ...
type JSONFile struct {
	Labels struct {
		Job  string `json:"job"`
		App  string `json:"flink_id"`
		Name string `json:"flink_name"`
	} `json:"labels"`
	Targets []string `json:"targets"`
}

// New structs
type ContainerListResponse struct {
    Container []YARNContainer `json:"container"`
}

type YARNContainer struct {
    ContainerID   string `json:"containerId"`
    NodeID        string `json:"nodeId"`        // host:port
    ContainerType string `json:"containerType"` // APPLICATION_MASTER or TASK
}

type spnegoRoundTripper struct {
    client *spnego.Client
}


// const ..
const (
	JobLabel           = "flink_yarn"
	RetrySleepInterval = 2 // seconds
	MaxTries           = 5
)

// var ...
var (
	targetFolder    = flag.String("folder", "", "Provided target folder for writing json targets")
	logFile         = flag.String("log-file", "", "Provided log file path")
	yarnAddr        = flag.String("address", "", "Provided yarn resource manager address")
	appID           = flag.String("app-id", "", "If specified, runs once for the application")
	queryTimeout    = flag.Int("timeout", 15, "HTTP query timeout in seconds")
	pollInterval    = flag.Int("poll-interval", 30, "Polling interval to YARN in seconds")
	debugMode       = flag.Bool("debug", false, "Enable debug mode")
	// Auth
	basicUser       = flag.String("username", "", "Basic auth username")
	basicPass       = flag.String("password", "", "Basic auth password")
	bearerToken     = flag.String("token", "", "Bearer token for Authorization header")
	// TLS
	tlsCACert       = flag.String("tls-ca-cert", "", "Path to CA certificate")
	tlsClientCert   = flag.String("tls-client-cert", "", "Path to client certificate")
	tlsClientKey    = flag.String("tls-client-key", "", "Path to client key")
	tlsSkipVerify   = flag.Bool("tls-skip-verify", false, "Skip TLS certificate verification")
	useKerberos        = flag.Bool("use-kerberos", false, "Use Kerberos SPNEGO, bypasses Knox")
	kerberosKeytab     = flag.String("keytab", "", "Path to Kerberos keytab file")
	kerberosPrincipal  = flag.String("principal", "", "Kerberos principal e.g. user@REALM")
	krb5ConfPath       = flag.String("krb5-conf", "/etc/krb5.conf", "Path to krb5.conf")
	// New flags (add to var block)
	yarnTimelineHost  = flag.String("yarn-timeline-host", "", "YARN Timeline Server host for log access (defaults to Knox host)")
	yarnTimelinePort  = flag.String("yarn-timeline-port", "19890", "YARN Timeline Server port")
	knoxTopologyPath  = flag.String("knox-log-path", "/cdp-proxy-api/yarnuiv2/timeline", "Knox path to yarnuiv2 timeline topology")
)

func main() {
	flag.Parse()

	if *yarnAddr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if !strings.HasPrefix(*yarnAddr, "http://") && !strings.HasPrefix(*yarnAddr, "https://") {
	log.Fatal("Please specify the protocol (http:// or https://) in the --address flag")
	}
	*yarnAddr = strings.TrimRight(*yarnAddr, "/")
	*targetFolder = strings.TrimRight(*targetFolder, "/")

	// Initialise shared HTTP client (TLS + auth)
	if *useKerberos {
	    sharedClient = buildKerberosClient()
	    log.Println("Using Kerberos SPNEGO authentication (direct YARN endpoints)")
	} else {
	    sharedClient = buildHTTPClient()
	}

	// Log file
	f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	log.Println("---------- Start service ---------- ")

	// One app mode
	if *appID != "" {
		app := GetFlinkApp(*appID)
		CreateJSONFile(app)
		os.Exit(0)
	}

	// Service mode
	var curApps, prevApps, addedApps, removedApps []App
	ticker := time.NewTicker(time.Second * time.Duration(*pollInterval))
	for range ticker.C {
		curApps = GetListFlinkApps()

		for i, app := range curApps {
			attempts := GetAppAttemptList(app.ID)
			curApps[i].LastAttemptID = getMaxAttemptID(attempts)
		}

		if len(prevApps) != 0 {
			addedApps = difference(curApps, prevApps)
			removedApps = difference(prevApps, curApps)
			for i := range curApps {
				for j := range prevApps {
					if curApps[i].ID == prevApps[j].ID {
						appID := curApps[i].ID
						curLastAttemptID := curApps[i].LastAttemptID
						prevLastAttemptID := prevApps[j].LastAttemptID
						if curLastAttemptID > prevLastAttemptID {
							log.Println("---- Update status ----")
							log.Println("Running apps: ", len(curApps))
							log.Printf("Detected change in existing app. AppID: %s - (AttemptID: %d => %d)\n", appID, prevLastAttemptID, curLastAttemptID)
							CreateJSONFile(curApps[i])
						}
					}
				}
			}
		} else {
			addedApps = curApps
		}

		if len(addedApps)+len(removedApps) > 0 {
			log.Println("---- Update status ----")
			log.Println("Running apps: ", len(curApps))
			log.Println("New apps: ", len(addedApps))
			log.Println("Removed apps: ", len(removedApps))

			for _, app := range addedApps {
				if *debugMode {
					CreateJSONFile(app)
					continue
				}
				go CreateJSONFile(app)
			}
			for _, app := range removedApps {
				removeJSONFile(app.ID)
			}
		}
		prevApps = curApps
	}
}

//shared client builder
func buildHTTPClient() *http.Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: *tlsSkipVerify,
	}

	if *tlsCACert != "" {
		caCert, err := os.ReadFile(*tlsCACert)
		if err != nil {
			log.Fatalf("Failed to read CA cert: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsCfg.RootCAs = caCertPool
	}

	if *tlsClientCert != "" && *tlsClientKey != "" {
		cert, err := tls.LoadX509KeyPair(*tlsClientCert, *tlsClientKey)
		if err != nil {
			log.Fatalf("Failed to load client cert/key: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Timeout: time.Second * time.Duration(*queryTimeout),
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
}

func (s *spnegoRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
    return s.client.Do(req)
}

func buildKerberosClient() *http.Client {
    krb5Cfg, err := config.Load(*krb5ConfPath)
    if err != nil {
        log.Fatalf("Failed to load krb5.conf: %v", err)
    }

    kt, err := keytab.Load(*kerberosKeytab)
    if err != nil {
        log.Fatalf("Failed to load keytab: %v", err)
    }

    parts := strings.SplitN(*kerberosPrincipal, "@", 2)
    if len(parts) != 2 {
        log.Fatalf("Invalid principal format, expected user@REALM, got: %s", *kerberosPrincipal)
    }

    krb5Client := client.NewWithKeytab(parts[0], parts[1], kt, krb5Cfg,
        client.DisablePAFXFAST(true),
    )

    if err := krb5Client.Login(); err != nil {
        log.Fatalf("Kerberos login failed: %v", err)
    }
    log.Printf("Kerberos login successful for principal: %s", *kerberosPrincipal)

    tlsCfg := &tls.Config{InsecureSkipVerify: *tlsSkipVerify}
    if *tlsCACert != "" {
        caCert, err := os.ReadFile(*tlsCACert)
        if err != nil {
            log.Fatalf("Failed to read CA cert: %v", err)
        }
        pool := x509.NewCertPool()
        pool.AppendCertsFromPEM(caCert)
        tlsCfg.RootCAs = pool
    }

    // spnego.NewClient requires an *http.Client, not *http.Transport
    baseClient := &http.Client{
        Transport: &http.Transport{TLSClientConfig: tlsCfg},
    }
    spnegoClient := spnego.NewClient(krb5Client, baseClient, "")

    return &http.Client{
        Timeout:   time.Second * time.Duration(*queryTimeout),
        Transport: &spnegoRoundTripper{client: spnegoClient},
    }
}

var sharedClient *http.Client

func CreateJSONFile(app App) {
	jsonInfo := GetFlinkClusterInfo(app)
	err := writeJSONFile(jsonInfo)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("App ID: %s - Write file successfully\n", app.ID)
}

func newGetRequest(path string) (*http.Request, error) {
    reqURL := *yarnAddr + path
    req, err := http.NewRequest("GET", reqURL, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Accept", "application/json")
    if !*useKerberos {
        if *bearerToken != "" {
            req.Header.Set("Authorization", "Bearer "+*bearerToken)
        } else if *basicUser != "" {
            req.SetBasicAuth(*basicUser, *basicPass)
        }
    }
    return req, nil
}

func newProxyRequest(app App, path string) (*http.Request, error) {
    var rawURL string
    if *useKerberos {
        u, err := url.Parse(*yarnAddr)
        if err != nil {
            return nil, fmt.Errorf("failed to parse yarnAddr: %w", err)
        }
        rawURL = u.Scheme + "://" + u.Host + "/proxy/" + app.ID + path
    } else {
        base, err := url.Parse(app.TrackingURL)
        if err != nil {
            return nil, fmt.Errorf("failed to parse trackingUrl: %w", err)
        }
        proxyURL := &url.URL{
            Scheme:   base.Scheme,
            Host:     base.Host,
            Path:     strings.TrimRight(base.Path, "/") + path,
            RawQuery: base.RawQuery,
        }
        rawURL = proxyURL.String()
    }

    req, err := http.NewRequest("GET", rawURL, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Accept", "application/json")
    if !*useKerberos {
        if *bearerToken != "" {
            req.Header.Set("Authorization", "Bearer "+*bearerToken)
        } else if *basicUser != "" {
            req.SetBasicAuth(*basicUser, *basicPass)
        }
    }
    return req, nil
}

// GetFlinkClusterInfo gets list of JM and TMs of one Flink Cluster
func GetFlinkClusterInfo(app App) (result JSONFile) {
	hostList := []Host{}
	result.Targets = make([]string, 0)
	tries, tmCount := 0, 0

	// Waiting until get JM address
	jmAddr := GetJobManangerAddr(app)
	for len(jmAddr.IP) == 0 {
		jmAddr = GetJobManangerAddr(app)
		if len(jmAddr.IP) != 0 || tries >= MaxTries {
			time.Sleep(time.Second)
			break
		}
		tries++
		time.Sleep(RetrySleepInterval * time.Second)
	}

	// Get TM ID count
	tries = 0
	for tmCount == 0 {
		tmCount = FlinkClusterOverview(app).TMCount
		if tmCount == 0 {
			tries++
			time.Sleep(time.Second)
		}

		if tries >= MaxTries {
			break
		}
	}

	// Get TM ID list
	tmIDList := GetTaskManagerList(app)
	log.Printf("TMCount Tracking - App ID: %s - %d/%d TMs\n", app.ID, len(tmIDList), tmCount)

	//Keeping loop until get all TM addresses
	tries = 0
	for len(hostList) != len(tmIDList) {
		var waitGroup sync.WaitGroup
		hostList = []Host{}
		tmAddr := make(chan Host)
		tries++

		for _, tm := range tmIDList {
			DebugMsg("Enter go routine")
			// Add to waitGroup
			waitGroup.Add(1)
			go GetTaskManangerAddr(app, tm, tmAddr, &waitGroup)
		}
		DebugMsg("Back to main")

		for range tmIDList {
			hostList = append(hostList, <-tmAddr)
		}
		DebugMsg("Waiting for every Goroutine to be done")
		waitGroup.Wait()

		if len(hostList) != len(tmIDList) {
			log.Printf("[WARN] App ID: %s - %d/%d TMs\n", app.ID, len(hostList), len(tmIDList))
			time.Sleep(RetrySleepInterval * time.Second)
		}

		if tries >= MaxTries {
			log.Printf("[DEBUG] App ID: %s - Max Tries reached, stop waiting for TMs\n", app.ID)
			break
		}
	}
	log.Printf("[DEBUG] App ID: %s - %d/%d TMs\n", app.ID, len(hostList), len(tmIDList))
	hostList = append(hostList, jmAddr)

	// Resolve domains to IP
	hostList = resolveDomainToIP(hostList)
	result.Labels.Job = JobLabel
	result.Labels.App = app.ID
	result.Labels.Name = app.Name

	// Filter out hosts with no exporter port info
	for _, host := range hostList {
		if host.Port == "" {
			continue
		}
		result.Targets = append(result.Targets, host.IP+":"+host.Port)
	}
	return
}

// GetListFlinkApps gets list of Flink apps from YARN
func GetListFlinkApps() (flinkApps []App) {
	var clusterApp ClusterApp

	req, err := newGetRequest("/v1/cluster/apps")
	if err != nil {
		log.Println(err)
		return
	}

	q := req.URL.Query()
	q.Add("applicationType", "Apache Flink")
	q.Add("state", "Running")
	req.URL.RawQuery = q.Encode()

	// add context
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(*queryTimeout)*time.Second)
	defer cancel()

	err = do(ctx, req, &clusterApp)
	if err != nil {
		log.Printf("Error when unmarshall list flink apps, err= %s\n", err)
		return nil
	}

	for _, app := range clusterApp.Apps.App {
		if app.AppType == "Apache Flink" && app.State == "RUNNING" {
			flinkApps = append(flinkApps, app)
		}
	}
	return flinkApps
}

// GetFlinkApp one flink app info
func GetFlinkApp(appID string) (flinkApp App) {
	var appResp AppResponse
	req, err := newGetRequest("/v1/cluster/apps/" + appID)

	if err != nil {
		log.Println(err)
		return
	}

	// add context
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(*queryTimeout)*time.Second)
	defer cancel()

	err = do(ctx, req, &appResp)
	if err != nil {
		log.Printf("Error when unmarshall flink app, id= %s, err= %s\n", appID, err)
		return
	}
	return appResp.App
}

// FlinkClusterOverview ...
func FlinkClusterOverview(app App) (flinkOverview FlinkOverview) {
	req, err := newProxyRequest(app, "/overview")

	if err != nil {
		log.Println(err)
		return
	}

	// add context
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(*queryTimeout)*time.Second)
	defer cancel()

	err = do(ctx, req, &flinkOverview)
	if err != nil {
		log.Printf("Error when unmarshall flink cluster overview, id= %s, err= %s\n", app.ID, err)
		return
	}
	return flinkOverview
}

// GetJobManangerAddr get IP and port of one JobManager
func GetJobManangerAddr(app App) (jobManager Host) {
	result := make([]Object, 0)
	// Get IP from config
	req, err := newProxyRequest(app, "/jobmanager/config")
	if err != nil {
		log.Println(err)
		return
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(*queryTimeout)*time.Second)
	defer cancel()

	err = do(ctx, req, &result)
	if err != nil {
		log.Printf("Error unmarshalling JobManager address, id= %s, err= %s\n", app.ID, err)
		return
	}

	for _, obj := range result {
		if obj.Key == "jobmanager.rpc.address" {
			jobManager.IP = obj.Value
			break
		}
	}

	// Get exporter port from log
	req, err = newProxyRequest(app, "/jobmanager/log")
	if err != nil {
		log.Println(err)
		return
	}

	// add context
	ctx = context.Background()
	ctx, cancel = context.WithTimeout(ctx, time.Duration(*queryTimeout)*time.Second)
	defer cancel()


	req = req.WithContext(ctx)
	resp, err := sharedClient.Do(req)

	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadBytes('\n')
		if strings.Contains(string(line), "Started PrometheusReporter HTTP server on port") {
			re := regexp.MustCompile(`on port (\d+).`)
			submatch := re.FindStringSubmatch(string(line))
			jobManager.Port = submatch[1]
			break
		}
		if strings.Contains(string(line), "Starting TaskManager with ResourceID") ||
			strings.Contains(string(line), "Starting rest endpoint.") || err == io.EOF {
			break
		}
	}
	return jobManager
}

// GetAppAttemptList ...
func GetAppAttemptList(appID string) (attempts []Attempt) {
	var attemptResp AttemptResponse
	req, err := newGetRequest("/v1/cluster/apps/" + appID + "/appattempts")
	if err != nil {
		log.Println(err)
		return
	}

	// add context
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(*queryTimeout)*time.Second)
	defer cancel()

	err = do(ctx, req, &attemptResp)
	if err != nil {
		log.Printf("Error unmarshalling AppAttemptList, id= %s, err= %s\n", appID, err)
		return
	}
	return attemptResp.AppAttempts.AppAttempt
}

// GetTaskManagerList gets list of Flink apps from YARN
func GetTaskManagerList(app App) (taskManagers []TaskManager) {
	tmRespsone := TMResponse{}
	tmRespsone.List = make([]TaskManager, 0)

	req, err := newProxyRequest(app, "/taskmanagers")
	if err != nil {
		log.Println(err)
		return
	}

	// add context
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(*queryTimeout)*time.Second)
	defer cancel()

	err = do(ctx, req, &tmRespsone)
	if err != nil {
		log.Printf("Error when unmarshall TaskManger address list, id= %s, err= %s\n", app.ID, err)
		return nil
	}
	return tmRespsone.List
}

// GetTaskManangerAddr reads task manager log and check for prometheus exporter IP:port
func GetTaskManangerAddr(app App, tm TaskManager, result chan Host, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	// Get domain name
	tmAddr := Host{}
	u, err := url.Parse(tm.Path)
	if err != nil {
		log.Println(err)
		result <- tmAddr
		return
	}
	// Get TaskManager IP
	host, _, _ := net.SplitHostPort(u.Host)
	tmAddr.IP = host

	// Get exporter port from log
	req, err := newProxyRequest(app, "/taskmanagers/" + tm.ID + "/log")
	if err != nil {
		log.Println("Failed when make request, err= ", err)
		result <- tmAddr
		return
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(*queryTimeout)*time.Second)
	defer cancel()

	req = req.WithContext(ctx)
	resp, err := sharedClient.Do(req)

	if err != nil {
		log.Println(err)
		result <- tmAddr
		return
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			log.Println("Error when reading log: ", err)
			break
		}
		if strings.Contains(string(line), "Started PrometheusReporter HTTP server on port") {
			re := regexp.MustCompile(`on port (\d+).`)
			submatch := re.FindStringSubmatch(string(line))
			tmAddr.Port = submatch[1]
			break
		}
		if strings.Contains(string(line), "Starting TaskManager with ResourceID") ||
			strings.Contains(string(line), "Starting rest endpoint.") ||
			err == io.EOF {
			break
		}
	}
	result <- tmAddr
}

func do(ctx context.Context, req *http.Request, v interface{}) error {
	req = req.WithContext(ctx)
	resp, err := sharedClient.Do(req)
	if err != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	if *debugMode {
		log.Printf("[DEBUG] %s %s => status=%d body=%s\n", req.Method, req.URL, resp.StatusCode, string(body))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	if len(body) == 0 {
		return fmt.Errorf("empty response body (status %d) for %s", resp.StatusCode, req.URL)
	}

	if v != nil {
		if err = json.Unmarshal(body, v); err != nil {
			return fmt.Errorf("json decode error: %w, body: %s", err, string(body))
		}
	}
	return nil
}


func resolveDomainToIP(hostList []Host) (result []Host) {
	if len(hostList) == 0 {
		log.Printf("DNS Resolver: Empty domain list")
		return
	}

	for _, host := range hostList {
		ips, err := net.LookupIP(host.IP)
		if err != nil || len(ips) == 0 {
			log.Printf("Error resolving host= %s, err= %s\n", ips, err)
			// keep domain name if it is not resolved
			result = append(result, Host{
				IP:   host.IP,
				Port: host.Port,
			})
			continue
		}
		result = append(result, Host{
			IP:   ips[0].String(),
			Port: host.Port,
		})
	}
	return
}

func writeJSONFile(jsonFile JSONFile) error {
	if len(jsonFile.Targets) == 0 {
		return fmt.Errorf("[WARN] Empty target list, appID= %s. May skip", jsonFile.Labels.App)
	}

	nodes := make([]JSONFile, 0)
	nodes = append(nodes, jsonFile)
	if targetFolder != nil {
		jsonBytes, err := json.MarshalIndent(nodes, "", "  ")
		if err != nil {
			log.Println("Cannot marshal json file, err= ", err)
			return err
		}
		outputFile := *targetFolder + "/" + jsonFile.Labels.App + ".json"
		err = os.WriteFile(outputFile, jsonBytes, 0644)
		if err != nil {
			log.Println(err)
		}
	} else {
		log.Println("App ID: ", jsonFile.Labels.App)
		log.Println(jsonFile)
	}
	return nil
}

func removeJSONFile(appID string) {
	targetFile := *targetFolder + "/" + appID + ".json"
	if _, err := os.Stat(targetFile); os.IsNotExist(err) {
		log.Printf("AppID: %s - File %s is not exist. May skip\n", appID, targetFile)
		return
	}

	err := os.Remove(targetFile)
	if err != nil {
		log.Printf("AppID: %s - Failed to delete file: %s - Err: %s", appID, targetFile, err)
		return
	}
	log.Printf("AppID: %s - File %s deleted\n", appID, targetFile)
}

func getMaxAttemptID(attempts []Attempt) int {
	if len(attempts) == 0 {
		return 0
	}

	maxID := attempts[0].ID
	for _, attempt := range attempts {
		if attempt.ID > maxID {
			maxID = attempt.ID
		}
	}
	return maxID
}

// Find elements in slice 1 but not in slice 2
func difference(slice1, slice2 []App) []App {
	var diff []App

	for _, e1 := range slice1 {
		found := false
		for _, e2 := range slice2 {
			if e1 == e2 {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, e1)
		}
	}
	return diff
}

// DebugMsg prints debug messages
func DebugMsg(msg ...interface{}) {
	if *debugMode {
		fmt.Println(msg...)
	}
}
