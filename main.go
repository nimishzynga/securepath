package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jordan-wright/email" // For sending email notifications
)

// Load our root certificate and key
var rootCert, rootKey = loadRootCert()

func loadRootCert() (tls.Certificate, *x509.Certificate) {
	certPEM, err := ioutil.ReadFile("path/to/rootCA.pem")
	if err != nil {
		log.Fatalf("Failed to read root certificate: %v", err)
	}
	keyPEM, err := ioutil.ReadFile("path/to/rootCA.key")
	if err != nil {
		log.Fatalf("Failed to read root key: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Failed to parse root certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatalf("Failed to decode PEM block")
	}
	rootCertParsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse root certificate: %v", err)
	}

	return cert, rootCertParsed
}

// Generate a certificate for the given domain
func generateCert(domain string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"My MITM Proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, rootCert.Leaf, &priv.PublicKey, rootCert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func inspectTraffic(data []byte) (bool, string) {
	// Simple example: look for "password" in the traffic
	if strings.Contains(string(data), "password") {
		return true, "Potential password exposure"
	}

	// Basic email phishing detection
	phishingPatterns := []string{
		`(?i)bank`, // Case insensitive match for "bank"
		`(?i)verify your account`, // Case insensitive match for "verify your account"
	}
	for _, pattern := range phishingPatterns {
		if matched, _ := regexp.Match(pattern, data); matched {
			return true, "Potential phishing attempt detected"
		}
	}

	return false, ""
}

func sendAlert(message string) {
	e := email.NewEmail()
	e.From = "Alert <alert@example.com>"
	e.To = []string{"admin@example.com"}
	e.Subject = "Security Alert"
	e.Text = []byte(message)
	err := e.Send("smtp.example.com:587", smtp.PlainAuth("", "user", "pass", "smtp.example.com"))
	if err != nil {
		log.Printf("Failed to send alert email: %v", err)
	}
}

func handleHTTPS(w http.ResponseWriter, req *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	domain := strings.Split(req.Host, ":")[0]
	cert, err := generateCert(domain)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer tlsConn.Close()

	clientReader := tlsConn
	clientWriter := tlsConn

	serverConn, err := tls.Dial("tcp", req.Host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer serverConn.Close()

	go func() {
		io.Copy(clientWriter, serverConn)
	}()

	buf := make([]byte, 4096)
	for {
		n, err := clientReader.Read(buf)
		if n > 0 {
			if detected, message := inspectTraffic(buf[:n]); detected {
				log.Println(message)
				sendAlert(message)
			}
			serverConn.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	client := &http.Client{}
	dump, err := httputil.DumpRequest(req, true)
	if err == nil {
		if detected, message := inspectTraffic(dump); detected {
			log.Println(message)
			sendAlert(message)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	dump, err = httputil.DumpResponse(resp, true)
	if err == nil {
		if detected, message := inspectTraffic(dump); detected {
			log.Println(message)
			sendAlert(message)
		}
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleRequest(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		handleHTTPS(w, req)
	} else {
		handleHTTP(w, req)
	}
}

func main() {
	http.HandleFunc("/", handleRequest)
	log.Println("Starting proxy server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
