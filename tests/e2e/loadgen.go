//go:build ignore

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type account struct {
	Hex    string `json:"hex"`
	Bech32 string `json:"bech32"`
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

var (
	rpcURL string
	client = &http.Client{Timeout: 20 * time.Second}
	idSeq  atomic.Int64
)

func call(method string, params ...any) (json.RawMessage, error) {
	body, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: int(idSeq.Add(1)), Method: method, Params: params})
	resp, err := client.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%s", out.Error.Message)
	}
	return out.Result, nil
}

func pendingNonce(addr common.Address) (uint64, error) {
	raw, err := call("eth_getTransactionCount", addr.Hex(), "pending")
	if err != nil {
		return 0, err
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, err
	}
	var nonce uint64
	if _, err := fmt.Sscanf(text, "0x%x", &nonce); err != nil {
		return 0, err
	}
	return nonce, nil
}

func deriveKey(seed string, index int) *ecdsa.PrivateKey {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", seed, index)))
	key, err := crypto.ToECDSA(sum[:])
	if err != nil {
		panic(err)
	}
	return key
}

func main() {
	mode := flag.String("mode", "info", "info or run")
	seed := flag.String("seed", "karsa-tps", "seed for deterministic accounts")
	count := flag.Int("accounts", 32, "number of accounts")
	perAccount := flag.Int("per-account", 200, "transactions per account")
	chainID := flag.Int64("chain-id", 262144, "EVM chain id")
	gasPrice := flag.Int64("gas-price", 100_000_000_000, "legacy gas price in akra")
	timeout := flag.Duration("timeout", 3*time.Minute, "mined wait timeout")
	flag.StringVar(&rpcURL, "rpc", "http://127.0.0.1:18545", "EVM JSON-RPC endpoint")
	flag.Parse()

	keys := make([]*ecdsa.PrivateKey, *count)
	for i := range keys {
		keys[i] = deriveKey(*seed, i)
	}

	if *mode == "info" {
		accounts := make([]account, 0, len(keys))
		for _, key := range keys {
			addr := crypto.PubkeyToAddress(key.PublicKey)
			bech32, err := sdk.Bech32ifyAddressBytes("karsa", addr.Bytes())
			if err != nil {
				panic(err)
			}
			accounts = append(accounts, account{Hex: addr.Hex(), Bech32: bech32})
		}
		json.NewEncoder(os.Stdout).Encode(accounts)
		return
	}

	to := crypto.PubkeyToAddress(keys[0].PublicKey)
	signer := types.LatestSignerForChainID(big.NewInt(*chainID))
	startNonces := make([]uint64, len(keys))
	sent := make([]int64, len(keys))
	var failures atomic.Int64

	start := time.Now()
	var wg sync.WaitGroup
	for index, key := range keys {
		nonce, err := pendingNonce(crypto.PubkeyToAddress(key.PublicKey))
		if err != nil {
			fmt.Fprintf(os.Stderr, "nonce for account %d: %v\n", index, err)
			continue
		}
		startNonces[index] = nonce

		wg.Add(1)
		go func(index int, key *ecdsa.PrivateKey, nonce uint64) {
			defer wg.Done()
			for i := 0; i < *perAccount; i++ {
				tx := types.NewTx(&types.LegacyTx{
					Nonce:    nonce + uint64(i),
					GasPrice: big.NewInt(*gasPrice),
					Gas:      21_000,
					To:       &to,
					Value:    big.NewInt(1),
				})
				signed, err := types.SignTx(tx, signer, key)
				if err != nil {
					failures.Add(1)
					continue
				}
				raw, err := signed.MarshalBinary()
				if err != nil {
					failures.Add(1)
					continue
				}
				if _, err := call("eth_sendRawTransaction", "0x"+hex.EncodeToString(raw)); err != nil {
					failures.Add(1)
					continue
				}
				sent[index]++
			}
		}(index, key, nonce)
	}
	wg.Wait()
	pushDone := time.Now()

	var totalSent int64
	for _, value := range sent {
		totalSent += value
	}
	fmt.Printf("broadcast %d txs in %s (%.0f tx/s offered, %d rejected)\n",
		totalSent, pushDone.Sub(start).Round(time.Millisecond), float64(totalSent)/pushDone.Sub(start).Seconds(), failures.Load())

	deadline := time.Now().Add(*timeout)
	var mined int
	for time.Now().Before(deadline) {
		mined = 0
		for index, key := range keys {
			if sent[index] == 0 {
				continue
			}
			addr := crypto.PubkeyToAddress(key.PublicKey)
			raw, err := call("eth_getTransactionCount", addr.Hex(), "latest")
			if err != nil {
				continue
			}
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				continue
			}
			var nonce uint64
			if _, err := fmt.Sscanf(text, "0x%x", &nonce); err != nil {
				continue
			}
			if nonce > startNonces[index] {
				mined += int(nonce - startNonces[index])
			}
		}
		if int64(mined) >= totalSent {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	elapsed := time.Since(start)
	fmt.Printf("mined %d txs in %s -> %.0f TPS\n", mined, elapsed.Round(time.Millisecond), float64(mined)/elapsed.Seconds())
}
