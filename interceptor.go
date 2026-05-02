package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"encrypt-decrypt/util"

	"github.com/gin-gonic/gin"
)

type bodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func EncryptResponseMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Wrap the writer
		bw := &bodyWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = bw

		// Process the request
		c.Next()

		contentType := bw.Header().Get("Content-Type")

		// Jika bukan JSON, jangan encrypt → tulis biasa
		if !strings.HasPrefix(contentType, "application/json") {
			c.Writer = bw.ResponseWriter
			c.Header("Content-Type", contentType)
			c.Writer.WriteHeader(c.Writer.Status())
			c.Writer.Write(bw.body.Bytes())
			return
		}

		// Encrypt the response body
		encrypted, err := util.EncryptGCM(bw.body.String(), "")
		if err != nil {
			c.String(http.StatusInternalServerError, "Encryption failed")
			return
		}

		// Write encrypted output
		c.Writer = bw.ResponseWriter // restore original
		c.Header("Content-Type", "text/plain")
		c.Writer.WriteHeader(c.Writer.Status())
		c.Writer.Write([]byte(encrypted))
	}
}
func DecryptRequestMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// === HANDLE GET request dengan param "data" ===
		if c.Request.Method == http.MethodGet {
			encryptedData := c.Query("data")
			if encryptedData != "" {
				// 1. URL decode dulu
				decoded, err := url.QueryUnescape(encryptedData)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid encrypted data format"})
					return
				}

				// 2. Decrypt
				plaintext, err := util.DecryptGCM(decoded, "")
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to decrypt data"})
					return
				}

				// 3. Parse JSON dari plaintext
				var params map[string]interface{}
				if err := json.Unmarshal([]byte(plaintext), &params); err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON in decrypted data"})
					return
				}

				// 4. Timpa query parameters di request
				query := c.Request.URL.Query()
				for key, value := range params {
					// Konversi value ke string (karena Query() butuh []string)
					var strVal string
					switch v := value.(type) {
					case string:
						strVal = v
					case float64: // JSON number jadi float64
						strVal = fmt.Sprintf("%.0f", v) // untuk int seperti page
					case bool:
						strVal = fmt.Sprintf("%t", v)
					default:
						strVal = fmt.Sprintf("%v", v)
					}
					query.Set(key, strVal)
				}
				c.Request.URL.RawQuery = query.Encode()

				// Lanjut ke handler (controller tetap pakai ShouldBindQuery seperti biasa)
				c.Next()
				return
			}
		}

		// === HANDLE POST/PUT dll dengan encrypted body
		if c.Request.Body == nil || c.Request.Body == http.NoBody {
			c.Next()
			return
		}

		rawBody, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			return
		}
		_ = c.Request.Body.Close()

		// Parse JSON dari body: {"payload": "..."}
		var requestWrapper struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(rawBody, &requestWrapper); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Invalid JSON format. Expected: {\"payload\": \"encrypted_string\"}",
			})
			return
		}

		// Validasi payload tidak kosong
		if requestWrapper.Payload == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Field 'payload' is required and cannot be empty"})
			return
		}

		plaintext, err := util.DecryptGCM(requestWrapper.Payload, "")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid or corrupted encrypted data"})
			return
		}

		if !json.Valid([]byte(plaintext)) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Decrypted payload is not valid JSON",
			})
			return
		}

		// Ganti body dengan plaintext agar ShouldBindJSON tetap jalan
		c.Request.Body = io.NopCloser(bytes.NewBufferString(plaintext))
		c.Request.ContentLength = int64(len(plaintext))
		c.Request.Header.Set("Content-Type", "application/json")

		c.Next()
	}
}
