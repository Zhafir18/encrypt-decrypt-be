package main

import (
	"net/http"

	"encrypt-decrypt/util"

	"github.com/gin-gonic/gin"
)

type encryptRequest struct {
	Plaintext string `json:"plaintext" binding:"required"`
	Type      string `json:"type" binding:"required"` // "cbc" or "gcm"
	Key       string `json:"key" binding:"required"`
}

type encryptResponse struct {
	Ciphertext string `json:"ciphertext"`
}

type decryptRequest struct {
	Ciphertext string `json:"ciphertext" binding:"required"`
	Type       string `json:"type" binding:"required"` // "cbc" or "gcm"
	Key        string `json:"key" binding:"required"`
}

type decryptResponse struct {
	Plaintext string `json:"plaintext"`
}

func registerRoutes(r *gin.Engine) {
	r.POST("/encrypt", func(c *gin.Context) {
		var req encryptRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing plaintext"})
			return
		}
		if req.Type == "cbc" {
			ct, err := util.EncryptCBC(req.Plaintext, req.Key)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
				return
			}
			c.JSON(http.StatusOK, encryptResponse{Ciphertext: ct})
			return
		} else {
			ct, err := util.EncryptGCM(req.Plaintext, req.Key)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
				return
			}
			c.JSON(http.StatusOK, encryptResponse{Ciphertext: ct})
		}
	})

	r.POST("/decrypt", func(c *gin.Context) {
		var req decryptRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing ciphertext"})
			return
		}
		if req.Type == "cbc" {
			pt, err := util.DecryptCBC(req.Ciphertext, req.Key)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "decryption failed"})
				return
			}
			c.JSON(http.StatusOK, decryptResponse{Plaintext: pt})
		} else {
			pt, err := util.DecryptGCM(req.Ciphertext, req.Key)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "decryption failed"})
				return
			}
			c.JSON(http.StatusOK, decryptResponse{Plaintext: pt})
		}
	})
}
