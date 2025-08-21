package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// --- CONFIGURATION & GLOBALS ---

// etcdClient is the global etcd client for all operations.
var etcdClient *clientv3.Client

// tenantKeys stores the per-namespace API and encryption keys in a concurrent-safe map.
var tenantKeys = sync.Map{}

// masterKey is the master encryption key loaded from a file.
var masterKey []byte

// --- STRUCTS ---

// TenantConfig holds the API and encryption keys for a single namespace.
type TenantConfig struct {
	APIKey         string `json:"apiKey"`
	EncryptionKey  string `json:"encryptionKey"`
}

// --- UTILITY FUNCTIONS ---

// panicOnError is a simple helper for handling errors in initialization.
func panicOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

// loadMasterKey reads the master key from a local file.
// In a production environment, this file should be highly secure.
func loadMasterKey() {
	masterKeyFile := "master.key"
	key, err := os.ReadFile(masterKeyFile)
	if err != nil {
		// If the file doesn't exist, create a new master key.
		if os.IsNotExist(err) {
			masterKey = make([]byte, 32)
			if _, err := rand.Read(masterKey); err != nil {
				panicOnError(err, "Failed to generate new master key")
			}
			err = os.WriteFile(masterKeyFile, masterKey, 0600)
			panicOnError(err, "Failed to write new master key to file")
			log.Printf("Generated a new master key at '%s'", masterKeyFile)
		} else {
			panicOnError(err, "Failed to read master key file")
		}
	} else {
		masterKey = key
	}
	if len(masterKey) != 32 {
		panicOnError(fmt.Errorf("invalid key size: %d", len(masterKey)), "Master key must be 32 bytes for AES-256")
	}
}

// encrypt encrypts a plaintext string using a provided key.
func encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decrypt decrypts an encrypted string using a provided key.
func decrypt(encryptedHex string, key []byte) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext is too short")
	}
	nonce, encryptedText := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedText, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// loadTenantKeys loads all tenant configurations from etcd on startup.
func loadTenantKeys() {
	log.Println("Loading tenant configurations from etcd...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := etcdClient.Get(ctx, "/namespaces/", clientv3.WithPrefix())
	if err != nil {
		log.Printf("Failed to load tenant keys: %v", err)
		return
	}

	for _, ev := range resp.Kvs {
		encryptedConfig := string(ev.Value)
		decryptedConfig, err := decrypt(encryptedConfig, masterKey)
		if err != nil {
			log.Printf("Failed to decrypt tenant config for key %s: %v", ev.Key, err)
			continue
		}

		var tenantCfg TenantConfig
		if err := json.Unmarshal([]byte(decryptedConfig), &tenantCfg); err != nil {
			log.Printf("Failed to unmarshal tenant config for key %s: %v", ev.Key, err)
			continue
		}

		// Extract user ID from the etcd key path
		parts := strings.Split(string(ev.Key), "/")
		if len(parts) < 3 {
			log.Printf("Invalid tenant key format: %s", ev.Key)
			continue
		}
		userID := parts[2]
		tenantKeys.Store(userID, tenantCfg)
		log.Printf("Loaded tenant config for user: %s", userID)
	}
}

// --- MIDDLEWARE ---

// authMiddleware checks for a valid API key based on the user-id in the path.
func authMiddleware(c *gin.Context) {
	userID := c.Param("user-id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		c.Abort()
		return
	}

	headerKey := c.GetHeader("X-API-Key")
	if headerKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: API key header is missing"})
		c.Abort()
		return
	}

	cfg, ok := tenantKeys.Load(userID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid user ID"})
		c.Abort()
		return
	}
	tenantCfg := cfg.(TenantConfig)

	if headerKey != tenantCfg.APIKey {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: Invalid API key"})
		c.Abort()
		return
	}
	c.Next()
}

// --- HANDLER FUNCTIONS ---

// getSecret retrieves a secret from etcd for a specific user.
func getSecret(c *gin.Context) {
	userID := c.Param("user-id")
	keyPath := c.Param("key")
	fullKey := fmt.Sprintf("/secrets/%s/%s", userID, keyPath)

	cfg, _ := tenantKeys.Load(userID)
	tenantCfg := cfg.(TenantConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := etcdClient.Get(ctx, fullKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get secret from etcd"})
		return
	}
	if len(resp.Kvs) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
		return
	}

	secretValue := string(resp.Kvs[0].Value)
	decryptedValue, err := decrypt(secretValue, []byte(tenantCfg.EncryptionKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt secret"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"key":     keyPath,
		"value":   decryptedValue,
		"version": resp.Kvs[0].ModRevision,
	})
}

// createOrUpdateSecret creates or updates a secret for a specific user.
func createOrUpdateSecret(c *gin.Context) {
	userID := c.Param("user-id")
	keyPath := c.Param("key")
	fullKey := fmt.Sprintf("/secrets/%s/%s", userID, keyPath)

	var reqBody struct {
		Value string `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg, _ := tenantKeys.Load(userID)
	tenantCfg := cfg.(TenantConfig)
	encryptedValue, err := encrypt(reqBody.Value, []byte(tenantCfg.EncryptionKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt secret"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = etcdClient.Put(ctx, fullKey, encryptedValue)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store secret in etcd"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Secret created/updated successfully"})
}

// deleteSecret deletes a secret for a specific user.
func deleteSecret(c *gin.Context) {
	userID := c.Param("user-id")
	keyPath := c.Param("key")
	fullKey := fmt.Sprintf("/secrets/%s/%s", userID, keyPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := etcdClient.Delete(ctx, fullKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete secret from etcd"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Secret deleted successfully"})
}

// getSecretVersions retrieves a list of all historical versions for a user's secret.
func getSecretVersions(c *gin.Context) {
	userID := c.Param("user-id")
	keyPath := c.Param("key")
	fullKey := fmt.Sprintf("/secrets/%s/%s", userID, keyPath)
	
	cfg, _ := tenantKeys.Load(userID)
	tenantCfg := cfg.(TenantConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := etcdClient.Get(ctx, fullKey, clientv3.WithPrefix(), clientv3.WithFromKey())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get secret versions"})
		return
	}

	if len(resp.Kvs) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found or no versions exist"})
		return
	}

	versions := make([]gin.H, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		decryptedValue, err := decrypt(string(kv.Value), []byte(tenantCfg.EncryptionKey))
		if err != nil {
			log.Printf("Failed to decrypt historical version for key %s at revision %d: %v", fullKey, kv.ModRevision, err)
			continue
		}
		versions = append(versions, gin.H{
			"version": kv.ModRevision,
			"value":   decryptedValue,
			"created_at": time.Unix(0, kv.CreateRevision),
		})
	}
	c.JSON(http.StatusOK, versions)
}

// getSecretByVersion retrieves a specific version of a user's secret.
func getSecretByVersion(c *gin.Context) {
	userID := c.Param("user-id")
	keyPath := c.Param("key")
	version := c.Param("version")
	fullKey := fmt.Sprintf("/secrets/%s/%s", userID, keyPath)
	
	revision, err := hex.DecodeString(version)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid version format"})
		return
	}
	
	cfg, _ := tenantKeys.Load(userID)
	tenantCfg := cfg.(TenantConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := etcdClient.Get(ctx, fullKey, clientv3.WithRev(int64(revision[0])))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get secret by version"})
		return
	}

	if len(resp.Kvs) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret version not found"})
		return
	}

	decryptedValue, err := decrypt(string(resp.Kvs[0].Value), []byte(tenantCfg.EncryptionKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt secret"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"key":     keyPath,
		"value":   decryptedValue,
		"version": resp.Kvs[0].ModRevision,
	})
}

// createNamespace creates a new namespace with a unique API key and encryption key.
func createNamespace(c *gin.Context) {
	userID := c.Param("user-id")
	
	// Check if a tenant config for this user already exists.
	_, ok := tenantKeys.Load(userID)
	if ok {
		c.JSON(http.StatusConflict, gin.H{"error": "Namespace already exists"})
		return
	}
	
	// Generate new keys for the tenant.
	newAPIKey := make([]byte, 16)
	rand.Read(newAPIKey)
	newEncryptionKey := make([]byte, 32)
	rand.Read(newEncryptionKey)
	
	tenantCfg := TenantConfig{
		APIKey: hex.EncodeToString(newAPIKey),
		EncryptionKey: hex.EncodeToString(newEncryptionKey),
	}
	
	// Marshal and encrypt the new config.
	cfgJSON, err := json.Marshal(tenantCfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal tenant config"})
		return
	}
	
	encryptedCfg, err := encrypt(string(cfgJSON), masterKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt tenant config"})
		return
	}

	// Store the encrypted config in etcd.
	etcdKey := fmt.Sprintf("/namespaces/%s", userID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = etcdClient.Put(ctx, etcdKey, encryptedCfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store tenant config in etcd"})
		return
	}

	// Store the new config in the in-memory map for immediate use.
	tenantKeys.Store(userID, tenantCfg)
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "Namespace created successfully",
		"user_id": userID,
		"api_key": tenantCfg.APIKey, // NOTE: This is the only time the API key is returned!
	})
}

// --- MAIN FUNCTION ---

func main() {
	// 1. Load the master key from the file.
	loadMasterKey()

	// 2. Initialize etcd client
	etcdEndpoints := os.Getenv("ETCD_ENDPOINTS")
	if etcdEndpoints == "" {
		etcdEndpoints = "localhost:2379" // Default to localhost if not set
	}
	
	var err error
	etcdClient, err = clientv3.New(clientv3.Config{
		Endpoints:   strings.Split(etcdEndpoints, ","),
		DialTimeout: 5 * time.Second,
	})
	panicOnError(err, "Failed to connect to etcd")
	defer etcdClient.Close()
	
	// 3. Load all existing tenant keys from etcd.
	loadTenantKeys()
	
	// 4. Create a Gin router.
	router := gin.Default()
	
	// Public endpoint for creating new tenants.
	router.POST("/namespaces/:user-id", createNamespace)

	// API endpoints for secrets, protected by authMiddleware.
	secretsGroup := router.Group("/secrets/:user-id")
	secretsGroup.Use(authMiddleware)
	{
		secretsGroup.POST("/*key", createOrUpdateSecret)
		secretsGroup.GET("/*key", getSecret)
		secretsGroup.PUT("/*key", createOrUpdateSecret)
		secretsGroup.DELETE("/*key", deleteSecret)
		secretsGroup.GET("/*key/versions", getSecretVersions)
		secretsGroup.GET("/*key/versions/:version", getSecretByVersion)
	}

	// Start the server.
	log.Println("Starting API server on :8080...")
	panicOnError(router.Run(":8080"), "Failed to start server")
}
