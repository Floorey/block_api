package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
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
}

var blockchain Blockchain

func getBlocksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(blockchain.Chain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func mineBlockHandler(w http.ResponseWriter, r *http.Request) {
	prevBlock := blockchain.Chain[len(blockchain.Chain)-1]

	newBlock := generateBlock(prevBlock, "Some test Data")

	blockchain.Chain = append(blockchain.Chain, newBlock)

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(newBlock)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func addTransactionHandler(w http.ResponseWriter, r *http.Request) {
	message := "New transaction added."

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]string{"message": message})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func getChainHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(blockchain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func generateBlock(prevBlock Block, data string) Block {
	var newBlock Block

	newBlock.Index = prevBlock.Index + 1
	newBlock.Timestamp = time.Now().String()
	newBlock.Data = data
	newBlock.PrevHash = prevBlock.Hash
	newBlock.Nonce = 0

	// mining a block
	for {
		newBlock.Hash = calculateHash(newBlock)
		if isValidHash(newBlock.Hash) {
			break
		}
		newBlock.Nonce++
	}
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
func main() {
	router := mux.NewRouter()

	router.HandleFunc("/blocks", getBlocksHandler).Methods("GET")
	router.HandleFunc("/mine_block", mineBlockHandler).Methods("POST")
	router.HandleFunc("/add_transaction", addTransactionHandler).Methods("POST")
	router.HandleFunc("/chain", getBlocksHandler).Methods("GET")

	// initialize blockchain

	blockchain = Blockchain{
		Chain: []Block{
			Block{Index: 0, Timestamp: time.Now().String(), Data: "Genesis-Block", PrevHash: "", Hash: ""},
		},
	}
	log.Fatal(http.ListenAndServe(":8080", router))
}
