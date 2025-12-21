package automations

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/ansi"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/httpReq"
)

// isRunningInDaemon returns true if we're running inside the automation server daemon container
func isRunningInDaemon() bool {
	return os.Getenv("BITSWAN_CADDY_HOST") != ""
}

// TransformURLForDaemon converts a public gitops URL to an internal Docker network URL
// e.g., https://foo-gitops.bs-foo.localhost/automations -> http://foo-gitops:8079/automations
func TransformURLForDaemon(originalURL string, workspaceName string) string {
	if !isRunningInDaemon() {
		return originalURL
	}

	// Parse the URL to get the path
	parsed, err := url.Parse(originalURL)
	if err != nil {
		return originalURL
	}

	// Construct the internal URL using the workspace name
	// The gitops container hostname is {workspaceName}-gitops and listens on port 8079
	internalHost := fmt.Sprintf("%s-gitops:8079", workspaceName)
	parsed.Scheme = "http"
	parsed.Host = internalHost

	return parsed.String()
}

// WorkspaceMisbehavingError is a custom error type for when the workspace API returns 500 errors
type WorkspaceMisbehavingError struct {
	WorkspaceName string
	StatusCode    int
	ResponseBody  string
}

func (e *WorkspaceMisbehavingError) Error() string {
	return fmt.Sprintf("workspace %s is misbehaving (status code: %d, response: %s)", e.WorkspaceName, e.StatusCode, e.ResponseBody)
}

type Automation struct {
	ContainerID  string `json:"container_id"`
	EndpointName string `json:"endpoint_name"`
	CreatedAt    string `json:"created_at"`
	Name         string `json:"name"`
	State        string `json:"state"`
	Status       string `json:"status"`
	DeploymentID string `json:"deployment_id"`
	Active       bool   `json:"active"`
	Workspace    string `json:"workspace"`
}

// AutomationLog represents the logs response from the gitops API
type AutomationLog struct {
	Status string   `json:"status"`
	Logs   []string `json:"logs"`
}

// Remove sends a request to remove the automation associated with the Automation object
func (a *Automation) Remove() error {
	// Retrieve workspace metadata
	metadata, err := config.GetWorkspaceMetadata(a.Workspace)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	// Construct the URL for stopping the automation
	reqURL := fmt.Sprintf("%s/automations/%s", metadata.GitopsURL, a.DeploymentID)
	reqURL = TransformURLForDaemon(reqURL, a.Workspace)

	// Send the request to remove the automation
	resp, err := SendAutomationRequest("DELETE", reqURL, metadata.GitopsSecret)
	if err != nil {
		return fmt.Errorf("failed to send request to remove automation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("no automation named '%s' found", a.DeploymentID)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to remove automation, status code: %d", resp.StatusCode)
	}

	return nil
}

// Start sends a request to start the automation
func (a *Automation) Start() error {
	metadata, err := config.GetWorkspaceMetadata(a.Workspace)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	reqURL := fmt.Sprintf("%s/automations/%s/start", metadata.GitopsURL, a.DeploymentID)
	reqURL = TransformURLForDaemon(reqURL, a.Workspace)
	resp, err := SendAutomationRequest("POST", reqURL, metadata.GitopsSecret)
	if err != nil {
		return fmt.Errorf("failed to send request to start automation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("no automation named '%s' found", a.DeploymentID)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to start automation, status code: %d", resp.StatusCode)
	}

	return nil
}

// Stop sends a request to stop the automation
func (a *Automation) Stop() error {
	metadata, err := config.GetWorkspaceMetadata(a.Workspace)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	reqURL := fmt.Sprintf("%s/automations/%s/stop", metadata.GitopsURL, a.DeploymentID)
	reqURL = TransformURLForDaemon(reqURL, a.Workspace)
	resp, err := SendAutomationRequest("POST", reqURL, metadata.GitopsSecret)
	if err != nil {
		return fmt.Errorf("failed to send request to stop automation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("no automation named '%s' found", a.DeploymentID)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to stop automation, status code: %d", resp.StatusCode)
	}

	return nil
}

// Restart sends a request to restart the automation
func (a *Automation) Restart() error {
	metadata, err := config.GetWorkspaceMetadata(a.Workspace)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	reqURL := fmt.Sprintf("%s/automations/%s/restart", metadata.GitopsURL, a.DeploymentID)
	reqURL = TransformURLForDaemon(reqURL, a.Workspace)
	resp, err := SendAutomationRequest("POST", reqURL, metadata.GitopsSecret)
	if err != nil {
		return fmt.Errorf("failed to send request to restart automation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("no automation named '%s' found", a.DeploymentID)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to restart automation, status code: %d", resp.StatusCode)
	}

	return nil
}

// GetLogs fetches logs for the automation
func (a *Automation) GetLogs(lines int) (*AutomationLog, error) {
	metadata, err := config.GetWorkspaceMetadata(a.Workspace)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	reqURL := fmt.Sprintf("%s/automations/%s/logs", metadata.GitopsURL, a.DeploymentID)
	if lines > 0 {
		reqURL += fmt.Sprintf("?lines=%d", lines)
	}
	reqURL = TransformURLForDaemon(reqURL, a.Workspace)

	resp, err := SendAutomationRequest("GET", reqURL, metadata.GitopsSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch logs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no automation named '%s' found", a.DeploymentID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get logs from automation: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var automationLog AutomationLog
	if err := json.Unmarshal(body, &automationLog); err != nil {
		return nil, fmt.Errorf("failed to parse logs response: %w", err)
	}

	return &automationLog, nil
}

func SendAutomationRequest(method, requestURL string, workspaceSecret string) (*http.Response, error) {
	// Create a new request
	req, err := httpReq.NewRequest(method, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Add headers
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+workspaceSecret)

	// When running in daemon, use simple HTTP client (URLs are already transformed)
	// When running on host, use localhost resolution for .localhost domains
	if isRunningInDaemon() {
		return http.DefaultClient.Do(req)
	}
	return httpReq.ExecuteRequestWithLocalhostResolution(req)
}

// GetAutomations fetches the list of automations for a given workspace
func GetAutomations(workspaceName string) ([]Automation, error) {
	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	reqURL := fmt.Sprintf("%s/automations", metadata.GitopsURL)
	reqURL = TransformURLForDaemon(reqURL, workspaceName)

	// Send the request
	resp, err := SendAutomationRequest("GET", reqURL, metadata.GitopsSecret)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	// Parse the response
	var automations []Automation
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Check for 5xx Server Errors (workspace misbehaving)
	if resp.StatusCode >= 500 && resp.StatusCode < 600 {
		return nil, &WorkspaceMisbehavingError{
			WorkspaceName: workspaceName,
			StatusCode:    resp.StatusCode,
			ResponseBody:  string(body),
		}
	}

	// Check for other non-200 status codes
	if resp.StatusCode != http.StatusOK {
		bodyStr := strings.TrimSpace(string(body))
		if bodyStr == "" {
			bodyStr = "(empty response)"
		}
		return nil, fmt.Errorf("HTTP request failed (status code: %d), response body: %s", resp.StatusCode, bodyStr)
	}

	err = json.Unmarshal(body, &automations)
	if err != nil {
		bodyStr := strings.TrimSpace(string(body))
		if bodyStr == "" {
			bodyStr = "(empty response)"
		}
		return nil, fmt.Errorf("error decoding JSON (status code: %d): %w. Response body: %s", resp.StatusCode, err, bodyStr)
	}

	// Set the Workspace field for each automation
	for i := range automations {
		automations[i].Workspace = workspaceName
	}

	fmt.Println("Automations fetched successfully.")
	return automations, nil
}

// Parse custom timestamp format
func parseTimestamp(timestamp string) string {
	layout := "2006-01-02T15:04:05.999999"
	t, err := time.Parse(layout, timestamp)
	if err != nil {
		return "Invalid Date"
	}
	return t.Format("02 Jan 2006 15:04") // Format as "DD MMM YYYY HH:MM"
}

func GetListAutomations(workspaceName string) ([]Automation, error) {
	automations, err := GetAutomations(workspaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get automations for workspace %s: %w", workspaceName, err)
	}

	fmt.Println("Automations fetched successfully.")
	fmt.Print("The following automations are running in this gitops:\n\n")
	// Print table header
	fmt.Printf("%s%-8s %-20s %-12s %-12s %-8s %-20s %-20s%s\n", ansi.Bold, "RUNNING", "NAME", "STATE", "STATUS", "ACTIVE", "DEPLOYMENT ID", "CREATED AT", ansi.Reset)
	fmt.Println(ansi.Gray + "--------------------------------------------------------------------------------------------------------" + ansi.Reset)

	if len(automations) == 0 {
		fmt.Println(ansi.Gray + "No automations found." + ansi.Reset)
		return nil, nil
	}

	// Print each automation
	for _, a := range automations {
		runningStatus := ansi.RedDot // Default to red (inactive)
		if a.State == "running" {
			runningStatus = ansi.GreenDot // Change to green if active
		}

		activeStatus := ansi.RedCheck // Default to red (inactive)
		if a.Active {
			activeStatus = ansi.GreenCheck // Change to green if active
		}

		// Format created_at properly
		createdAtFormatted := parseTimestamp(a.CreatedAt)

		name := a.Name
		if len(name) > 20 {
			name = name[:15] + "..."
		}

		deploymentId := a.DeploymentID
		if len(a.DeploymentID) > 20 {
			deploymentId = a.DeploymentID[:15] + "..."
		}

		// Print formatted row
		fmt.Printf("%-16s %-20s %-12s %-12s %-16s %-20s %-20s\n",
			runningStatus, name, a.State, a.Status, activeStatus, deploymentId, createdAtFormatted)
		fmt.Println(ansi.Gray + "--------------------------------------------------------------------------------------------------------" + ansi.Reset)
	}

	// Footer info
	fmt.Println(ansi.Yellow + "✔ Running containers are marked with a green dot.\n" + ansi.Reset)

	return automations, nil
}
