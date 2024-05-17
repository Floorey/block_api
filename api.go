package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

type Block struct {
	Index     int    `json:"index"`
	Timestamp string `json:"timestamp"`
	Data      string `json:"data"`
	PrevHash  string `json:"prevHash"`
	Hash      string `json:"hash"`
	Nonce     int    `json:"nonce"`
}

type Blockchain struct {
	Chain []Block `json:"chain"`
	mu    sync.Mutex
}

var blockchain Blockchain

func getBlocksHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling getBlocks request...")
	blockchain.mu.Lock()
	defer blockchain.mu.Unlock()

	log.Println("Acquired lock in getBlocksHandler")
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(blockchain.Chain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println("Released lock in getBlocksHandler")
}

func generateBlock(prevBlock Block, data string) Block {
	log.Println("Generating new block...")
	var newBlock Block

	newBlock.Index = prevBlock.Index + 1
	newBlock.Timestamp = time.Now().String()
	newBlock.Data = data
	newBlock.PrevHash = prevBlock.Hash
	newBlock.Nonce = 0

	// Mining a block
	for {
		newBlock.Hash = calculateHash(newBlock)
		if isValidHash(newBlock.Hash) {
			break
		}
		newBlock.Nonce++
	}
	log.Println("New block generated:", newBlock)
	return newBlock
}

func calculateHash(block Block) string {
	record := strconv.Itoa(block.Index) + block.Timestamp + block.Data + block.PrevHash + strconv.Itoa(block.Nonce)
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func isValidHash(hash string) bool {
	return hash[:4] == "0000"
}

func handleUserInput() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Println("Choose an option:")
		fmt.Println("1. Enter block data")
		fmt.Println("2. Print blockchain")
		fmt.Println("3. Quit")

		scanner.Scan()
		choice := scanner.Text()

		switch choice {
		case "1":
			fmt.Println("Enter block data:")
			scanner.Scan()
			input := scanner.Text()

			log.Println("Acquiring lock to add new block from user input")
			blockchain.mu.Lock()
			log.Println("Lock acquired to add new block from user input")
			newBlock := generateBlock(blockchain.Chain[len(blockchain.Chain)-1], input)
			blockchain.Chain = append(blockchain.Chain, newBlock)
			log.Println("New block added from user input:", newBlock)
			blockchain.mu.Unlock()
			log.Println("Lock released after adding new block from user input")

			fmt.Println("Block added to blockchain:", newBlock)
		case "2":
			printBlocks()
		case "3":
			fmt.Println("Quitting...")
			return
		default:
			fmt.Println("Invalid choice. Please choose 1, 2, or 3.")
		}
	}
}
func printBlocks() {
	blockchain.mu.Lock()
	defer blockchain.mu.Unlock()

	fmt.Println("Current Blockchain:")
	for _, block := range blockchain.Chain {
		fmt.Printf("Index: %d, Timestamp: %s, Data: %s, PrevHash: %s, Hash: %s, Nonce: %d\n", block.Index, block.Timestamp, block.Data, block.PrevHash, block.Hash, block.Nonce)

	}
}
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})

	return tls.X509KeyPair(certPEM, keyPEMBlock)
}

func main() {
	log.Println("Starting server...")

	router := mux.NewRouter()

	router.HandleFunc("/blocks", getBlocksHandler).Methods("GET")

	blockchain = Blockchain{
		Chain: []Block{
			Block{Index: 0, Timestamp: time.Now().String(), Data: "Genesis-Block", PrevHash: "", Hash: calculateHash(Block{Index: 0, Timestamp: time.Now().String(), Data: "Genesis-Block", PrevHash: "", Hash: "", Nonce: 0})},
		},
	}

	go handleUserInput()

	// Generate self-signed certificate
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Fatal(server.ListenAndServeTLS("", ""))
}
