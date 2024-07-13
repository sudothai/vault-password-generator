package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"gopkg.in/yaml.v2"

	vault "github.com/hashicorp/vault/api"
	k8sauth "github.com/hashicorp/vault/api/auth/kubernetes"
)

// Config represents the configuration structure
type Config struct {
    Secrets []Secret `yaml:"secrets"`
}

// Secret represents a single secret configuration
type Secret struct {
    Name         string `yaml:"name"`
    Length       int    `yaml:"length"`
    KV2Path      string `yaml:"kv2_path"`
    ManualSecret string `yaml:"manual_secret,omitempty"`
}

func main() {
    // Get configuration from environment variables
    vaultAddr := getEnv("VAULT_ADDR", "http://vault.default.svc.cluster.local:8200")
    role := getEnv("VAULT_ROLE", "my-role")

    // Read configuration file
    configFile := getEnv("CONFIG_FILE", "/app/config.yaml")
    config, err := readConfig(configFile)
    if err != nil {
        log.Fatalf("failed to read configuration: %v", err)
    }

    // Configure Vault client
    configVault := vault.DefaultConfig()
    configVault.Address = vaultAddr

    client, err := vault.NewClient(configVault)
    if err != nil {
        log.Fatalf("failed to create Vault client: %v", err)
    }

    // Kubernetes authentication
    k8sAuth, err := k8sauth.NewKubernetesAuth(role)
    if err != nil {
        log.Fatalf("failed to create Kubernetes auth method: %v", err)
    }

    authInfo, err := client.Auth().Login(context.Background(), k8sAuth)
    if err != nil {
        log.Fatalf("failed to authenticate with Vault: %v", err)
    }

    if authInfo == nil {
        log.Fatalf("no auth info was returned after login")
    }

    // Generate or use manual secrets for each secret and store them in Vault
    for _, secret := range config.Secrets {
        var password string
        if secret.ManualSecret != "" {
            password = secret.ManualSecret
        } else {
            password, err = generateRandomPassword(client, secret.Length)
            if err != nil {
                log.Fatalf("failed to generate password for secret %s: %v", secret.Name, err)
            }
        }

        fmt.Printf("Password for %s: %s\n", secret.Name, password)

        // Store the password in Vault KV2
        err = storeSecretInVault(client, secret.KV2Path, secret.Name, password)
        if err != nil {
            log.Fatalf("failed to store password for secret %s in Vault: %v", secret.Name, err)
        }
    }
}

func getEnv(key, defaultValue string) string {
    value, exists := os.LookupEnv(key)
    if !exists {
        return defaultValue
    }
    return value
}

func readConfig(filename string) (*Config, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read file %s: %v", filename, err)
    }

    var config Config
    err = yaml.Unmarshal(data, &config)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
    }

    return &config, nil
}

func generateRandomPassword(client *vault.Client, length int) (string, error) {
    // Generate a random password using the "transit" secrets engine
    secret, err := client.Logical().Write("sys/tools/random/password", map[string]interface{}{
        "length": length,
    })
    if err != nil {
        return "", fmt.Errorf("failed to generate random password: %v", err)
    }

    password, ok := secret.Data["random_password"].(string)
    if !ok {
        return "", fmt.Errorf("failed to parse generated password")
    }

    return password, nil
}

func storeSecretInVault(client *vault.Client, path, secretName, password string) error {
    // Store the password in the KV2 secrets engine
    data := map[string]interface{}{
        "data": map[string]interface{}{
            secretName: password,
        },
    }
    _, err := client.Logical().Write(path, data)
    if err != nil {
        return fmt.Errorf("failed to write secret to Vault: %v", err)
    }
    return nil
}
