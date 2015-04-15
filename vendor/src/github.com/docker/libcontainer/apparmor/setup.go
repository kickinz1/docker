package apparmor

import (
	"fmt"
	"os"
	"os/exec"
	"path"
)

var (
    DefaultProfilePath string
)

func InstallDefaultProfile() error {

	if !IsEnabled() {
		return nil
	}

    // Add support for snappy as /etc/docker is readonly on snappy
	if os.Getenv("SNAP_APP_DATA_PATH") != "" {
		DefaultProfilePath = "/var/lib/apparmor/profiles/docker"
	} else {
		DefaultProfilePath = "/etc/apparmor.d/docker"
	}
	

	// Make sure /etc/apparmor.d exists
	if err := os.MkdirAll(path.Dir(DefaultProfilePath), 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(DefaultProfilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if err := generateProfile(f); err != nil {
		f.Close()
		return err
	}
	f.Close()

	cmd := exec.Command("/sbin/apparmor_parser", "-r", "-W", "docker")
	// to use the parser directly we have to make sure we are in the correct
	// dir with the profile
	if os.Getenv("SNAP_APP_DATA_PATH") != "" {
		cmd.Dir = "/var/lib/apparmor/profiles"
	} else {
		cmd.Dir = "/etc/apparmor.d"
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error loading docker apparmor profile: %s (%s)", err, output)
	}
	return nil
}
