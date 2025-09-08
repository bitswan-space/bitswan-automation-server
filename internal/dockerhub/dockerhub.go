package dockerhub

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
)

func GetLatestDockerHubVersion(url string) (string, error) {
	// Get the latest version of the bitswan-gitops image by looking it up on dockerhub
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return "latest", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "latest", err
	}
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "latest", err
	}
	results := data["results"].([]interface{})
	pattern := `^\d{4}-\d+-git-[a-fA-F0-9]+$`
	// Compile the regex pattern once, before the loop
	re := regexp.MustCompile(pattern)

	for _, result := range results {
		tag := result.(map[string]interface{})["name"].(string)
		if re.MatchString(tag) {
			return tag, nil
		}
	}
	return "latest", errors.New("No valid version found")
}

// GetLatestEditorVersion gets the latest version of the bitswan-editor image
func GetLatestEditorVersion() (string, error) {
	return GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/bitswan-editor/tags/")
}

// GetLatestKafkaVersion gets the latest version of the bitswan-kafka image
func GetLatestKafkaVersion() (string, error) {
	return GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/bitswan-kafka/tags/")
}

// GetLatestZookeeperVersion gets the latest version of the bitswan-zookeeper image
func GetLatestZookeeperVersion() (string, error) {
	return GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/bitswan-zookeeper/tags/")
}

// GetLatestCouchDBVersion gets the latest version of the bitswan-couchdb image
func GetLatestCouchDBVersion() (string, error) {
	return GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/bitswan-couchdb/tags/")
}
