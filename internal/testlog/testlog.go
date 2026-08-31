// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Package testlog is an in-memory transparency log and a fake of the
// Compliance API surface axt-verify reads, for hermetic tests. Tree hashes
// and proofs come from golang.org/x/mod/sumdb/tlog — an implementation
// independent of the transparency-dev/merkle code the verifier checks them
// with.
package testlog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// LogKey is an ECDSA P-256 note signer shaped like the production log key:
// key name = origin, key hash = SHA-256(SPKI DER)[:4], verifier string
// "<origin>+<hash>+base64(0x02 || SPKI DER)".
type LogKey struct {
	name string
	hash uint32
	priv *ecdsa.PrivateKey
	VKey string
}

func NewLogKey(origin string) *LogKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(der)
	k := &LogKey{name: origin, hash: binary.BigEndian.Uint32(sum[:4]), priv: priv}
	k.VKey = fmt.Sprintf("%s+%08x+%s", origin, k.hash, base64.StdEncoding.EncodeToString(append([]byte{0x02}, der...)))
	return k
}

// Named returns the same key material under another name — how production
// signs every organization's log with one key named for each origin.
func (k *LogKey) Named(name string) *LogKey {
	c := *k
	c.name = name
	return &c
}

func (k *LogKey) Name() string    { return k.name }
func (k *LogKey) KeyHash() uint32 { return k.hash }
func (k *LogKey) Sign(msg []byte) ([]byte, error) {
	d := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, k.priv, d[:])
}

// Log is an append-only in-memory Merkle log.
type Log struct {
	Origin string
	Key    *LogKey

	mu      sync.Mutex
	entries [][]byte
	hashes  []tlog.Hash // stored-hash layout of sumdb/tlog
}

func New(origin string) *Log {
	return &Log{Origin: origin, Key: NewLogKey(origin)}
}

func (l *Log) readHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, ix := range indexes {
		if ix < 0 || ix >= int64(len(l.hashes)) {
			return nil, fmt.Errorf("stored hash %d out of range [0,%d)", ix, len(l.hashes))
		}
		out[i] = l.hashes[ix]
	}
	return out, nil
}

// Append adds entries and returns the index of the first one.
func (l *Log) Append(entries ...[]byte) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	first := uint64(len(l.entries))
	for _, e := range entries {
		hs, err := tlog.StoredHashes(int64(len(l.entries)), e, tlog.HashReaderFunc(l.readHashes))
		if err != nil {
			panic(err)
		}
		l.hashes = append(l.hashes, hs...)
		l.entries = append(l.entries, e)
	}
	return first
}

func (l *Log) Size() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.entries))
}

func (l *Log) Entry(i uint64) []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.entries[i]
}

func (l *Log) RootAt(size uint64) []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	h, err := tlog.TreeHash(int64(size), tlog.HashReaderFunc(l.readHashes))
	if err != nil {
		panic(err)
	}
	return h[:]
}

func (l *Log) InclusionProof(index, size uint64) [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, err := tlog.ProveRecord(int64(size), int64(index), tlog.HashReaderFunc(l.readHashes))
	if err != nil {
		panic(err)
	}
	return hashesToBytes(p)
}

func (l *Log) ConsistencyProof(from, to uint64) [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	if from == 0 || from == to {
		return [][]byte{}
	}
	p, err := tlog.ProveTree(int64(to), int64(from), tlog.HashReaderFunc(l.readHashes))
	if err != nil {
		panic(err)
	}
	return hashesToBytes(p)
}

func hashesToBytes(hs []tlog.Hash) [][]byte {
	out := make([][]byte, len(hs))
	for i := range hs {
		out[i] = hs[i][:]
	}
	return out
}

// Checkpoint returns the checkpoint for the first size leaves, signed by the
// log key.
func (l *Log) Checkpoint(size uint64) []byte {
	return l.CheckpointFor(l.Origin, size, l.RootAt(size))
}

// CheckpointFor signs an arbitrary (origin, size, root) — for forging.
func (l *Log) CheckpointFor(origin string, size uint64, root []byte) []byte {
	return l.SignedNote(string(log.Checkpoint{Origin: origin, Size: size, Hash: root}.Marshal()))
}

// SignedNote signs arbitrary note text with the log key.
func (l *Log) SignedNote(text string) []byte {
	raw, err := note.Sign(&note.Note{Text: text}, l.Key)
	if err != nil {
		panic(err)
	}
	return raw
}
