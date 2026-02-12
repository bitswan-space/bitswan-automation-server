package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dchest/uniuri"
)

// JobState represents the state of a job
type JobState string

const (
	JobStatePending      JobState = "pending"
	JobStateRunning      JobState = "running"
	JobStateWaitingInput JobState = "waiting_input"
	JobStateCompleted    JobState = "completed"
	JobStateFailed       JobState = "failed"
)

// JobLogEntry represents a log entry from a job
type JobLogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Prompt  string `json:"prompt,omitempty"` // Set when job is waiting for input
}

// Job represents an interactive job
type Job struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	State     JobState  `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	Error     string    `json:"error,omitempty"`

	// Internal channels for communication
	inputChan  chan string
	outputChan chan JobLogEntry
	doneChan   chan struct{}

	mu sync.Mutex
}

// JobManager manages interactive jobs
type JobManager struct {
	jobs map[string]*Job
	mu   sync.RWMutex
}

var globalJobManager = &JobManager{
	jobs: make(map[string]*Job),
}

// GetJobManager returns the global job manager
func GetJobManager() *JobManager {
	return globalJobManager
}

// CreateJob creates a new job
func (jm *JobManager) CreateJob(jobType string) *Job {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	job := &Job{
		ID:         uniuri.NewLen(16),
		Type:       jobType,
		State:      JobStatePending,
		CreatedAt:  time.Now(),
		inputChan:  make(chan string, 1),
		outputChan: make(chan JobLogEntry, 100),
		doneChan:   make(chan struct{}),
	}

	jm.jobs[job.ID] = job
	return job
}

// GetJob retrieves a job by ID
func (jm *JobManager) GetJob(id string) *Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	return jm.jobs[id]
}

// DeleteJob removes a job
func (jm *JobManager) DeleteJob(id string) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	delete(jm.jobs, id)
}

// SetState sets the job state
func (j *Job) SetState(state JobState) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.State = state
}

// GetState gets the job state
func (j *Job) GetState() JobState {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.State
}

// Log sends a log message to the job output
func (j *Job) Log(level, message string) {
	select {
	case j.outputChan <- JobLogEntry{
		Time:    time.Now().Format(time.RFC3339),
		Level:   level,
		Message: message,
	}:
	default:
		// Channel full, drop message
	}
}

// Prompt sends a prompt and waits for user input
func (j *Job) Prompt(prompt string) (string, error) {
	j.SetState(JobStateWaitingInput)

	// Send prompt to output
	select {
	case j.outputChan <- JobLogEntry{
		Time:   time.Now().Format(time.RFC3339),
		Level:  "prompt",
		Prompt: prompt,
	}:
	default:
	}

	// Wait for input
	select {
	case input := <-j.inputChan:
		j.SetState(JobStateRunning)
		return strings.TrimSpace(input), nil
	case <-j.doneChan:
		return "", fmt.Errorf("job cancelled")
	case <-time.After(5 * time.Minute):
		return "", fmt.Errorf("input timeout")
	}
}

// SendInput sends input to a waiting job
func (j *Job) SendInput(input string) error {
	if j.GetState() != JobStateWaitingInput {
		return fmt.Errorf("job is not waiting for input")
	}

	select {
	case j.inputChan <- input:
		return nil
	default:
		return fmt.Errorf("input channel full")
	}
}

// Complete marks the job as completed
func (j *Job) Complete(err error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if err != nil {
		j.State = JobStateFailed
		j.Error = err.Error()
	} else {
		j.State = JobStateCompleted
	}

	close(j.doneChan)
	close(j.outputChan)
}

// StreamOutput returns a channel for streaming job output
func (j *Job) StreamOutput() <-chan JobLogEntry {
	return j.outputChan
}

// IsDone returns true if the job is done
func (j *Job) IsDone() bool {
	select {
	case <-j.doneChan:
		return true
	default:
		return false
	}
}

// JobWriter implements io.Writer to capture output and send to job
type JobWriter struct {
	job    *Job
	level  string
	buffer strings.Builder
}

// NewJobWriter creates a writer that sends output to a job
func NewJobWriter(job *Job, level string) *JobWriter {
	return &JobWriter{job: job, level: level}
}

// Write implements io.Writer
func (w *JobWriter) Write(p []byte) (n int, err error) {
	w.buffer.Write(p)

	// Flush complete lines
	for {
		str := w.buffer.String()
		idx := strings.Index(str, "\n")
		if idx == -1 {
			break
		}

		line := str[:idx]
		w.buffer.Reset()
		w.buffer.WriteString(str[idx+1:])

		if line != "" {
			w.job.Log(w.level, line)
		}
	}

	return len(p), nil
}

// Flush flushes any remaining content
func (w *JobWriter) Flush() {
	if w.buffer.Len() > 0 {
		w.job.Log(w.level, w.buffer.String())
		w.buffer.Reset()
	}
}

// JobInputReader implements io.Reader to read input from job prompts
type JobInputReader struct {
	job    *Job
	buffer *bufio.Reader
}

// NewJobInputReader creates a reader that gets input from job prompts
func NewJobInputReader(job *Job) *JobInputReader {
	return &JobInputReader{job: job}
}

// Read implements io.Reader - blocks until input is available
func (r *JobInputReader) Read(p []byte) (n int, err error) {
	if r.job.IsDone() {
		return 0, io.EOF
	}

	// This is called by bufio.Scanner or similar - we need to wait for input
	select {
	case input := <-r.job.inputChan:
		// Add newline if not present
		if !strings.HasSuffix(input, "\n") {
			input += "\n"
		}
		copy(p, []byte(input))
		return len(input), nil
	case <-r.job.doneChan:
		return 0, io.EOF
	}
}

// HTTP Handlers for job management

// handleCreateJob creates a new job and starts it
func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type      string                 `json:"type"`
		Workspace string                 `json:"workspace"`
		Params    map[string]interface{} `json:"params"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	job := GetJobManager().CreateJob(req.Type)
	job.SetState(JobStateRunning)

	// Start the job in a goroutine based on type
	switch req.Type {
	case "couchdb_restore":
		workspace := req.Workspace
		backupPath, _ := req.Params["backup_path"].(string)
		stage, _ := req.Params["stage"].(string)
		go s.runCouchDBRestoreJob(job, workspace, stage, backupPath)
	default:
		job.Complete(fmt.Errorf("unknown job type: %s", req.Type))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id": job.ID,
		"state":  job.State,
	})
}

// handleJobStream streams job output
func (s *Server) handleJobStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract job ID from path: /jobs/{id}/stream
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		writeJSONError(w, "job ID required", http.StatusBadRequest)
		return
	}
	jobID := parts[1]

	job := GetJobManager().GetJob(jobID)
	if job == nil {
		writeJSONError(w, "job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	encoder := json.NewEncoder(w)

	for entry := range job.StreamOutput() {
		if err := encoder.Encode(entry); err != nil {
			return
		}
		flusher.Flush()
	}

	// Send final status
	encoder.Encode(map[string]interface{}{
		"type":  "complete",
		"state": job.GetState(),
		"error": job.Error,
	})
	flusher.Flush()
}

// handleJobInput sends input to a waiting job
func (s *Server) handleJobInput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract job ID from path: /jobs/{id}/input
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		writeJSONError(w, "job ID required", http.StatusBadRequest)
		return
	}
	jobID := parts[1]

	job := GetJobManager().GetJob(jobID)
	if job == nil {
		writeJSONError(w, "job not found", http.StatusNotFound)
		return
	}

	var req struct {
		Input string `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := job.SendInput(req.Input); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// handleJobStatus returns the current job status
func (s *Server) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract job ID from path: /jobs/{id}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		writeJSONError(w, "job ID required", http.StatusBadRequest)
		return
	}
	jobID := parts[1]

	job := GetJobManager().GetJob(jobID)
	if job == nil {
		writeJSONError(w, "job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         job.ID,
		"type":       job.Type,
		"state":      job.GetState(),
		"created_at": job.CreatedAt,
		"error":      job.Error,
	})
}

// handleJobs routes job-related requests
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")

	// POST /jobs - create job
	if len(parts) == 1 && r.Method == http.MethodPost {
		s.handleCreateJob(w, r)
		return
	}

	// GET /jobs/{id} - job status
	if len(parts) == 2 && r.Method == http.MethodGet {
		s.handleJobStatus(w, r)
		return
	}

	// GET /jobs/{id}/stream - stream output
	if len(parts) == 3 && parts[2] == "stream" && r.Method == http.MethodGet {
		s.handleJobStream(w, r)
		return
	}

	// POST /jobs/{id}/input - send input
	if len(parts) == 3 && parts[2] == "input" && r.Method == http.MethodPost {
		s.handleJobInput(w, r)
		return
	}

	writeJSONError(w, "not found", http.StatusNotFound)
}

// runCouchDBRestoreJob runs the CouchDB restore as an interactive job
func (s *Server) runCouchDBRestoreJob(job *Job, workspace, stage, backupPath string) {
	defer func() {
		if r := recover(); r != nil {
			job.Complete(fmt.Errorf("panic: %v", r))
		}
	}()

	// Capture stdout for the job
	oldStdout := os.Stdout
	oldStdin := os.Stdin

	// Create pipes
	stdoutR, stdoutW, _ := os.Pipe()
	stdinR, stdinW, _ := os.Pipe()

	os.Stdout = stdoutW
	os.Stdin = stdinR

	// Channel to signal stdout reader to stop
	stopReader := make(chan struct{})

	// Goroutine to read stdout and send to job
	// Uses byte-by-byte reading with timeout to detect prompts (which don't end with newline)
	go func() {
		var buffer strings.Builder
		readByte := make([]byte, 1)

		for {
			// Set read deadline to detect when output has paused (likely a prompt)
			stdoutR.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := stdoutR.Read(readByte)

			if n > 0 {
				buffer.Write(readByte[:n])

				// If we got a newline, flush the line
				if readByte[0] == '\n' {
					line := strings.TrimRight(buffer.String(), "\n\r")
					buffer.Reset()
					if line != "" {
						job.Log("info", line)
					}
				}
			}

			if err != nil {
				// Check if it's a timeout
				if os.IsTimeout(err) {
					// We have a timeout - check if there's partial content that looks like a prompt
					partial := buffer.String()
					if partial != "" && strings.Contains(partial, "(yes/no)") {
						// This is a prompt waiting for input
						job.SetState(JobStateWaitingInput)
						job.outputChan <- JobLogEntry{
							Time:   time.Now().Format(time.RFC3339),
							Level:  "prompt",
							Prompt: partial,
						}
						buffer.Reset()
					}
					continue
				}

				// Check for stop signal or EOF
				select {
				case <-stopReader:
					// Flush any remaining content
					if buffer.Len() > 0 {
						job.Log("info", buffer.String())
					}
					return
				default:
					if err == io.EOF {
						// Flush any remaining content
						if buffer.Len() > 0 {
							job.Log("info", buffer.String())
						}
						return
					}
				}
			}
		}
	}()

	// Goroutine to handle input
	go func() {
		for {
			select {
			case input := <-job.inputChan:
				job.SetState(JobStateRunning)
				stdinW.WriteString(input + "\n")
			case <-job.doneChan:
				return
			}
		}
	}()

	// Proxy the restore to gitops
	err := s.proxyCouchDBRestore(workspace, stage, backupPath)

	// Close write end first to signal EOF to reader
	stdoutW.Close()
	stdinW.Close()

	// Signal reader to stop and wait a bit for it to finish
	close(stopReader)
	time.Sleep(200 * time.Millisecond)

	// Restore stdout/stdin
	os.Stdout = oldStdout
	os.Stdin = oldStdin

	job.Complete(err)
}
