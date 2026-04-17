package main

import (
	"fmt"
	"log"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/containermanager"
)

func main() {
	workspaceName := os.Getenv("BITSWAN_WORKSPACE_NAME")
	if workspaceName == "" {
		log.Fatal("BITSWAN_WORKSPACE_NAME is required")
	}

	composeProject := os.Getenv("BITSWAN_COMPOSE_PROJECT")
	if composeProject == "" {
		composeProject = workspaceName + "-site"
	}

	socketPath := os.Getenv("CONTAINER_MANAGER_SOCKET")
	if socketPath == "" {
		socketPath = "/var/run/bitswan/container-manager.sock"
	}

	dockerSocket := os.Getenv("DOCKER_SOCKET")
	if dockerSocket == "" {
		dockerSocket = "/var/run/docker.sock"
	}

	fmt.Printf("Container manager starting: workspace=%s project=%s\n", workspaceName, composeProject)

	proxy := containermanager.New(workspaceName, composeProject, socketPath, dockerSocket)
	if err := proxy.ListenAndServe(); err != nil {
		log.Fatalf("Container manager failed: %v", err)
	}
}
