// Based on unsea (https://github.com/draeder/unsea), MIT, Daniel Raeder.
module vsea

import crypto.ecdsa
import crypto.rand
import crypto.sha256
import encoding.base64
import encoding.utf8
import time

// Pair contains independent signing and encryption keys, in unsea wire format.
pub struct Pair {
pub:
	pub   string
	priv  string
	epub  string
	epriv string
}

// EncryptedMessageWithMeta is compatible with unsea's JSON message envelope.
// sender is an ephemeral public key, not an authenticated sender identity.
// timestamp is informational and is not authenticated by AES-GCM.
pub struct EncryptedMessageWithMeta {
pub:
	ciphertext string
	iv         string
	sender     string
	timestamp  i64
}

pub struct JWK {
pub:
	kty     string
	crv     string
	x       string
	y       string
	d       string
	use     string   = 'sig'
	key_ops []string = ['sign']
}

fn new_key() !(string, string) {
	pubkey, privkey := ecdsa.generate_key()!
	defer {
		pubkey.free()
		privkey.free()
	}
	raw := privkey.bytes()!
	mut scalar := []u8{len: 32 - raw.len}
	scalar << raw
	return point_string(pubkey.bytes()!)!, base64.url_encode(scalar)
}

// generate_random_pair creates two independent cryptographically random P-256 keys.
pub fn generate_random_pair() !Pair {
	pubkey, privkey := new_key()!
	epub, epriv := new_key()!
	return Pair{
		pub:   pubkey
		priv:  privkey
		epub:  epub
		epriv: epriv
	}
}

// public_key derives an unsea x.y public key from a private scalar.
pub fn public_key(private_key string) !string {
	key := ecdsa.new_key_from_seed(private_bytes(private_key)!, fixed_size: true)!
	defer { key.free() }
	pubkey := key.public_key()!
	defer { pubkey.free() }
	return point_string(pubkey.bytes()!)
}

// sign_message signs NFC(message).trim() with ECDSA/SHA-256, producing compact low-S r||s.
pub fn sign_message(message string, private_key string) !string {
	text := normalize_message(message)!
	der := sign_digest(sha256.sum(text.bytes()), private_bytes(private_key)!)!
	return base64.url_encode(compact_signature(der)!)
}

// verify_message returns false for malformed keys, signatures or invalid UTF-8.
pub fn verify_message(message string, signature string, pubkey string) bool {
	text := normalize_message(message) or { return false }
	raw := decode64(signature) or { return false }
	der := signature_der(raw) or { return false }
	point := public_bytes(pubkey) or { return false }
	return verify_digest(sha256.sum(text.bytes()), der, point)
}

// encrypt_message_with_meta accepts a recipient encryption public key (epub).
// Like unsea, plaintext is NFC-normalized and trimmed before encryption.
pub fn encrypt_message_with_meta(message string, recipient_epub string) !EncryptedMessageWithMeta {
	text := normalize_message(message)!
	ephemeral_pub, ephemeral_priv := new_key()!
	key := shared_key(ephemeral_priv, recipient_epub)!
	iv := rand.read(12)!
	ciphertext := aes_gcm(true, text.bytes(), key, iv)!
	return EncryptedMessageWithMeta{
		ciphertext: base64.url_encode(ciphertext)
		iv:         base64.url_encode(iv)
		sender:     ephemeral_pub
		timestamp:  time.now().unix_milli()
	}
}

// decrypt_message_with_meta authenticates ciphertext before returning UTF-8 text.
pub fn decrypt_message_with_meta(payload EncryptedMessageWithMeta, receiver_epriv string) !string {
	iv := decode64(payload.iv)!
	ciphertext := decode64(payload.ciphertext)!
	if iv.len != 12 || ciphertext.len < 16 { return error('invalid AES-GCM envelope') }
	key := shared_key(receiver_epriv, payload.sender)!
	plaintext := aes_gcm(false, ciphertext, key, iv)!
	text := plaintext.bytestr()
	if !utf8.validate_str(text) { return error('plaintext is not valid UTF-8') }
	return text
}

// export_to_jwk includes public coordinates as well as the private scalar.
pub fn export_to_jwk(private_key string) !JWK {
	point := public_key(private_key)!.split('.')
	return JWK{
		kty: 'EC'
		crv: 'P-256'
		x:   point[0]
		y:   point[1]
		d:   private_key
	}
}

// import_from_jwk accepts unsea's minimal private JWK, or a complete matching JWK.
pub fn import_from_jwk(jwk JWK) !string {
	if jwk.kty != 'EC' || jwk.crv != 'P-256' { return error('JWK must be EC P-256') }
	private_bytes(jwk.d)!
	if jwk.x != '' || jwk.y != '' {
		if public_key(jwk.d)! != jwk.x + '.' + jwk.y {
			return error('JWK public and private keys do not match')
		}
	}
	return jwk.d
}

fn shared_key(private_key string, peer_public string) ![]u8 {
	secret := derive_secret(private_bytes(private_key)!, public_bytes(peer_public)!)!
	return sha256.sum(secret)
}
