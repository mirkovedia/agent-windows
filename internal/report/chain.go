package report

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Chain encadena hallazgos: H_n = SHA256(H_{n-1} || SHA256(canonical(finding_n))).
// H_0 se deriva del nonce de sesión para atar la cadena a esa sesión.
type Chain struct {
	hashes []string
}

// NewChain crea una cadena inicializada con H_0 = SHA256(nonce).
func NewChain(nonce string) *Chain {
	h0 := sha256.Sum256([]byte(nonce))
	return &Chain{hashes: []string{hex.EncodeToString(h0[:])}}
}

// Append encadena un finding y devuelve el nuevo hash de la cadena.
func (c *Chain) Append(f Finding) (string, error) {
	body, err := canonicalFindingBytes(f)
	if err != nil {
		return "", err
	}
	fh := sha256.Sum256(body)
	prev, _ := hex.DecodeString(c.Root())
	combined := append(append([]byte{}, prev...), fh[:]...)
	next := sha256.Sum256(combined)
	h := hex.EncodeToString(next[:])
	c.hashes = append(c.hashes, h)
	return h, nil
}

// Root devuelve el último hash de la cadena.
func (c *Chain) Root() string { return c.hashes[len(c.hashes)-1] }

// Hashes devuelve la cadena completa (para Report.HashChain).
func (c *Chain) Hashes() []string { return c.hashes }

// canonicalFindingBytes serializa un Finding de forma determinista.
// encoding/json ordena las claves de structs por definición, garantizando
// bytes idénticos para findings idénticos.
func canonicalFindingBytes(f Finding) ([]byte, error) {
	return json.Marshal(f)
}

// Sign firma el root de la cadena con Ed25519 y devuelve la firma hex.
func Sign(priv ed25519.PrivateKey, root string) string {
	sig := ed25519.Sign(priv, []byte(root))
	return hex.EncodeToString(sig)
}

// Verify comprueba la firma hex del root contra la pubkey.
func Verify(pub ed25519.PublicKey, root, sigHex string) bool {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(root), sig)
}
