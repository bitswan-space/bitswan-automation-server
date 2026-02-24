#!/usr/bin/env python3
"""
Nuke script - Clean up Docker containers, networks, and local config.
Rewritten from bash to Python for better error handling and logging.
"""

import subprocess
import sys
import os
from pathlib import Path
import time


def run_command(cmd, description, check_success=True):
    """
    Run a shell command and print its output.
    
    Args:
        cmd: Command to run (list of strings)
        description: Human-readable description of what the command does
        check_success: If True, treat non-zero exit as failure. If False, allow non-zero exits.
    """
    print(f"\n{'='*60}")
    print(f"STEP: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False  # Don't raise on non-zero exit
        )
        
        if result.stdout:
            print("Output:")
            print(result.stdout)
        
        if result.returncode == 0:
            print(f"✓ Success: {description}")
        else:
            if check_success:
                print(f"✗ Command failed with exit code {result.returncode}")
            else:
                print(f"⚠ Command exited with code {result.returncode} (this may be expected if nothing to remove)")
        
        return result.returncode == 0
        
    except Exception as e:
        print(f"✗ Error running command: {e}")
        return False


def run_command_background(cmd, description):
    """
    Run a shell command in the background (for daemon processes).
    
    Args:
        cmd: Command to run (list of strings)
        description: Human-readable description of what the command does
    
    Returns:
        subprocess.Popen object if successful, None otherwise
    """
    print(f"\n{'='*60}")
    print(f"STEP: {description} (background)")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        print(f"✓ Started {description} in background (PID: {process.pid})")
        return process
    except Exception as e:
        print(f"✗ Error starting command: {e}")
        return None


def wait_for_daemon_ready(max_wait_seconds=10):
    """
    Wait for the daemon to be ready by checking if the socket exists and pinging it.
    Checks every second for up to max_wait_seconds.
    
    Args:
        max_wait_seconds: Maximum time to wait in seconds (default: 10)
    
    Returns:
        True if daemon is ready, False otherwise
    """
    socket_path = Path("/var/run/bitswan/automation-server.sock")
    print(f"Waiting for daemon to be ready (socket: {socket_path})...")
    print(f"Will check every second for up to {max_wait_seconds} seconds...")
    
    for attempt in range(max_wait_seconds):
        # Check if socket file exists
        if socket_path.exists():
            # Try to ping the daemon
            try:
                result = subprocess.run(
                    ["./bitswan", "automation-server-daemon", "status"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=1,
                    text=True
                )
                if result.returncode == 0:
                    print(f"✓ Daemon is ready! (checked {attempt + 1} time(s))")
                    return True
            except Exception as e:
                # Continue waiting if ping fails
                pass
        
        if attempt < max_wait_seconds - 1:  # Don't sleep on last attempt
            time.sleep(1)
            print(f"  Attempt {attempt + 1}/{max_wait_seconds}: Daemon not ready yet...")
    
    print(f"✗ Error: Daemon did not become ready within {max_wait_seconds} seconds")
    return False


def main():
    print("Starting nuke script...")
    print("This script will clean up Docker containers, networks, and local config.")
    
    # Step 1: Remove Docker containers matching "test1*"
    print(f"\n{'='*60}")
    print("STEP: Finding and removing Docker containers matching 'test1*'")
    print(f"{'='*60}")
    try:
        # First, get the container IDs
        list_result = subprocess.run(
            ["docker", "ps", "-aq", "--filter", "name=test1*"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False
        )
        
        if list_result.stdout.strip():
            container_ids = [cid.strip() for cid in list_result.stdout.strip().split('\n') if cid.strip()]
            print(f"Found {len(container_ids)} container(s) to remove: {', '.join(container_ids)}")
            for cid in container_ids:
                run_command(
                    ["docker", "rm", "-f", cid],
                    f"Removing container {cid}"
                )
        else:
            print("No containers matching 'test1*' found")
    except Exception as e:
        print(f"Error finding containers: {e}")
    
    # Step 2: Remove specific daemon container
    run_command(
        ["docker", "rm", "-f", "bitswan-automation-server-daemon"],
        "Removing bitswan-automation-server-daemon container",
        check_success=False
    )
    
    # Step 3: Remove Docker networks matching "bitswan_*"
    print(f"\n{'='*60}")
    print("STEP: Finding and removing Docker networks matching 'bitswan_*'")
    print(f"{'='*60}")
    try:
        # First, get the network IDs
        list_result = subprocess.run(
            ["docker", "network", "ls", "-q", "--filter", "name=bitswan_*"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False
        )
        
        if list_result.stdout.strip():
            network_ids = [nid.strip() for nid in list_result.stdout.strip().split('\n') if nid.strip()]
            print(f"Found {len(network_ids)} network(s) to remove: {', '.join(network_ids)}")
            for nid in network_ids:
                run_command(
                    ["docker", "network", "rm", nid],
                    f"Removing network {nid}"
                )
        else:
            print("No networks matching 'bitswan_*' found")
    except Exception as e:
        print(f"Error finding networks: {e}")
    
    # Step 4: Remove caddy container
    run_command(
        ["docker", "rm", "-f", "caddy"],
        "Removing caddy container",
        check_success=False
    )
    
    # Step 5: Remove local config directory
    config_dir = Path.home() / ".config" / "bitswan"
    print(f"\n{'='*60}")
    print(f"STEP: Removing local config directory: {config_dir}")
    print(f"{'='*60}")
    
    if config_dir.exists():
        try:
            import shutil
            shutil.rmtree(config_dir)
            print(f"✓ Successfully removed {config_dir}")
        except Exception as e:
            print(f"✗ Error removing directory: {e}")
            # Try with sudo if regular removal fails
            print("Attempting with sudo...")
            run_command(
                ["sudo", "rm", "-rf", str(config_dir)],
                f"Removing {config_dir} with sudo"
            )
    else:
        print(f"Directory {config_dir} does not exist, skipping")
    
    # Step 6: Build the project
    print(f"\n{'='*60}")
    print("STEP: Building the project")
    print(f"{'='*60}")
    
    # Check if ./bitswan exists and get its timestamp before build
    bitswan_path = Path("./bitswan")
    bitswan_timestamp_before = None
    if bitswan_path.exists():
        bitswan_timestamp_before = bitswan_path.stat().st_mtime
        print(f"Found existing ./bitswan (timestamp: {time.ctime(bitswan_timestamp_before)})")
    else:
        print("No existing ./bitswan found")
    
    # Run make build
    build_success = run_command(
        ["make", "build"],
        "Building the project with 'make build'",
        check_success=True
    )
    
    if not build_success:
        print(f"\n{'='*60}")
        print("✗ Build failed! Skipping subsequent steps.")
        print(f"{'='*60}")
        return
    
    # Check if ./bitswan exists and is newer after build
    bitswan_is_newer = False
    if bitswan_path.exists():
        bitswan_timestamp_after = bitswan_path.stat().st_mtime
        print(f"\nChecking if ./bitswan was updated...")
        print(f"Before build: {time.ctime(bitswan_timestamp_before) if bitswan_timestamp_before else 'N/A'}")
        print(f"After build:  {time.ctime(bitswan_timestamp_after)}")
        
        if bitswan_timestamp_before is None or bitswan_timestamp_after > bitswan_timestamp_before:
            bitswan_is_newer = True
            print("✓ ./bitswan is newer (or newly created)")
        else:
            print("⚠ ./bitswan was not updated by the build")
    else:
        print("✗ ./bitswan does not exist after build!")
    
    # Step 7: Run bitswan automation-server-daemon (if build succeeded)
    daemon_ready = False
    if build_success:
        daemon_process = run_command_background(
            ["./bitswan", "automation-server-daemon", "init"],
            "Starting bitswan automation-server-daemon"
        )
        if daemon_process:
            # Give it a moment to start up
            time.sleep(2)
            # Check if it's still running (if it exited immediately, there was an error)
            if daemon_process.poll() is not None:
                # Process already exited, try to read any output
                try:
                    stdout, _ = daemon_process.communicate(timeout=0.1)
                    if stdout:
                        print("Daemon output:")
                        print(stdout)
                except subprocess.TimeoutExpired:
                    pass
                print(f"⚠ Daemon process exited immediately with code {daemon_process.returncode}")
            else:
                print("Daemon process started, waiting for it to be ready...")
                # Wait for daemon to be ready (socket created and responding)
                # Check every second for 10 seconds
                daemon_ready = wait_for_daemon_ready(max_wait_seconds=10)
        else:
            print("✗ Failed to start daemon")
    
    # Step 8: Run bitswan workspace init (if build succeeded AND bitswan is newer AND daemon is ready)
    if build_success and bitswan_is_newer and True:
        print(f"\n{'='*60}")
        print("STEP: Initializing workspace")
        print(f"{'='*60}")
        run_command(
            ["./bitswan", "workspace", "init", "--local", "test1"],
            "Initializing workspace 'test1' with 'bitswan workspace init --local test1'",
            check_success=True
        )
    elif build_success and bitswan_is_newer and not daemon_ready:
        print(f"\n{'='*60}")
        print("Skipping workspace init: Daemon is not ready")
        print(f"{'='*60}")
    elif build_success and not bitswan_is_newer:
        print(f"\n{'='*60}")
        print("Skipping workspace init: ./bitswan was not updated by the build")
        print(f"{'='*60}")
    
    print(f"\n{'='*60}")
    print("Nuke script completed!")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
