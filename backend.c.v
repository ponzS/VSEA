module vsea

import encoding.utf8

#pkgconfig --cflags --libs openssl
$if macos {
	$if arm64 {
		#flag -I$when_first_existing('/opt/homebrew/opt/icu4c/include','/usr/local/opt/icu4c/include')
		#flag -L$when_first_existing('/opt/homebrew/opt/icu4c/lib','/usr/local/opt/icu4c/lib')
	} $else {
		#flag -I$when_first_existing('/usr/local/opt/icu4c/include','/opt/homebrew/opt/icu4c/include')
		#flag -L$when_first_existing('/usr/local/opt/icu4c/lib','/opt/homebrew/opt/icu4c/lib')
	}
	#flag -licuuc
} $else {
	#pkgconfig --cflags --libs icu-uc
}
#include <openssl/evp.h>
#include <unicode/unorm2.h>
#include <unicode/ustring.h>

fn C.d2i_AutoPrivateKey(a voidptr, input &&u8, length i64) voidptr
fn C.EVP_PKEY_derive_init(ctx &C.EVP_PKEY_CTX) int
fn C.EVP_PKEY_derive_set_peer(ctx &C.EVP_PKEY_CTX, peer &C.EVP_PKEY) int
fn C.EVP_PKEY_derive(ctx &C.EVP_PKEY_CTX, key &u8, size &usize) int

@[typedef]
struct C.EVP_CIPHER_CTX {}

@[typedef]
struct C.EVP_CIPHER {}

fn C.EVP_CIPHER_CTX_new() &C.EVP_CIPHER_CTX
fn C.EVP_CIPHER_CTX_free(ctx &C.EVP_CIPHER_CTX)
fn C.EVP_aes_256_gcm() &C.EVP_CIPHER
fn C.EVP_CipherInit_ex(ctx &C.EVP_CIPHER_CTX, cipher &C.EVP_CIPHER, engine voidptr, key &u8, iv &u8, enc int) int
fn C.EVP_CipherUpdate(ctx &C.EVP_CIPHER_CTX, out &u8, outlen &int, input &u8, size int) int
fn C.EVP_CipherFinal_ex(ctx &C.EVP_CIPHER_CTX, out &u8, outlen &int) int
fn C.EVP_CIPHER_CTX_ctrl(ctx &C.EVP_CIPHER_CTX, kind int, arg int, ptr voidptr) int

@[typedef]
struct C.UNormalizer2 {}

fn C.unorm2_getNFCInstance(status &int) &C.UNormalizer2
fn C.unorm2_normalize(norm &C.UNormalizer2, src &u16, size int, dst &u16, cap int, status &int) int
fn C.u_strFromUTF8(dst &u16, cap int, size &int, src &char, length int, status &int) &u16
fn C.u_strToUTF8(dst &char, cap int, size &int, src &u16, length int, status &int) &char

fn derive_secret(scalar []u8, point []u8) ![]u8 {
	der := private_der(scalar)
	mut cursor := &u8(der.data)
	private_key := C.d2i_AutoPrivateKey(unsafe { nil }, &cursor, der.len)
	if private_key == unsafe { nil } { return error('OpenSSL private key import failed') }
	defer { C.EVP_PKEY_free(private_key) }
	pubder := public_der(point)
	mut pubcursor := &u8(pubder.data)
	peer := C.d2i_PUBKEY(unsafe { nil }, &pubcursor, u32(pubder.len))
	if peer == unsafe { nil } { return error('invalid P-256 public point') }
	defer { C.EVP_PKEY_free(peer) }
	ctx := C.EVP_PKEY_CTX_new(private_key, unsafe { nil })
	if ctx == unsafe { nil } { return error('OpenSSL ECDH context allocation failed') }
	defer { C.EVP_PKEY_CTX_free(ctx) }
	if C.EVP_PKEY_derive_init(ctx) != 1 || C.EVP_PKEY_derive_set_peer(ctx, peer) != 1 {
		return error('invalid ECDH key')
	}
	mut secret := []u8{len: 32}
	mut size := usize(32)
	if C.EVP_PKEY_derive(ctx, secret.data, &size) != 1 || size != 32 {
		return error('ECDH derivation failed')
	}
	return secret
}

fn aes_gcm(encrypt bool, input []u8, key []u8, iv []u8) ![]u8 {
	if key.len != 32 || iv.len != 12 || (!encrypt && input.len < 16) {
		return error('invalid AES-256-GCM input')
	}
	if input.len > max_int - 32 { return error('message too large') }
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == unsafe { nil } { return error('OpenSSL AES context allocation failed') }
	defer { C.EVP_CIPHER_CTX_free(ctx) }
	if C.EVP_CipherInit_ex(ctx, C.EVP_aes_256_gcm(), unsafe { nil }, key.data, iv.data,
		int(encrypt)) != 1 {
		return error('AES-GCM initialization failed')
	}
	data_len := if encrypt { input.len } else { input.len - 16 }
	if !encrypt {
		mut tag := input[data_len..].clone()
		if C.EVP_CIPHER_CTX_ctrl(ctx, C.EVP_CTRL_GCM_SET_TAG, 16, tag.data) != 1 {
			return error('AES-GCM tag initialization failed')
		}
	}
	mut output := []u8{len: data_len + 32}
	mut written := 0
	if C.EVP_CipherUpdate(ctx, output.data, &written, input.data, data_len) != 1 {
		return error('AES-GCM operation failed')
	}
	mut final_len := 0
	if C.EVP_CipherFinal_ex(ctx, unsafe { &u8(output.data) + written }, &final_len) != 1 {
		// Never expose unauthenticated plaintext, including through the error.
		for i in 0 .. output.len {
			output[i] = 0
		}
		return error('AES-GCM authentication failed')
	}
	mut size := written + final_len
	if encrypt {
		if C.EVP_CIPHER_CTX_ctrl(ctx, C.EVP_CTRL_GCM_GET_TAG, 16,
			unsafe { &u8(output.data) + size }) != 1 {
			return error('AES-GCM tag extraction failed')
		}
		size += 16
	}
	return output[..size].clone()
}

// normalize_message follows JavaScript String.normalize('NFC').trim().
// ICU handles canonical composition; the explicit trim set matches ECMAScript.
pub fn normalize_message(message string) !string {
	if !utf8.validate_str(message) { return error('message is not valid UTF-8') }
	if message.len == 0 { return '' }
	if message.len > max_int / 4 { return error('message too large') }
	mut status := 0
	mut size := 0
	mut utf16 := []u16{len: message.len + 1}
	C.u_strFromUTF8(utf16.data, utf16.len, &size, message.str, message.len, &status)
	if status > 0 { return error('UTF-8 conversion failed') }
	norm := C.unorm2_getNFCInstance(&status)
	if status > 0 || norm == unsafe { nil } { return error('NFC initialization failed') }
	needed := C.unorm2_normalize(norm, utf16.data, size, unsafe { nil }, 0, &status)
	if (status > 0 && status != 15) || needed < 0 || needed > max_int / 4 - 1 {
		return error('NFC normalization failed')
	}
	status = 0
	mut normalized := []u16{len: needed + 1}
	length := C.unorm2_normalize(norm, utf16.data, size, normalized.data, normalized.len, &status)
	if status > 0 { return error('NFC normalization failed') }
	mut text := []u8{len: length * 4 + 1}
	mut text_len := 0
	C.u_strToUTF8(text.data, text.len, &text_len, normalized.data, length, &status)
	if status > 0 { return error('UTF-8 conversion failed') }
	runes := text[..text_len].bytestr().runes()
	mut start := 0
	mut end := runes.len
	for start < end && js_whitespace(runes[start]) {
		start++
	}
	for end > start && js_whitespace(runes[end - 1]) {
		end--
	}
	return runes[start..end].string()
}

fn js_whitespace(r rune) bool {
	return
		r in [rune(0x09), 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]
		|| (r >= 0x2000 && r <= 0x200a)
}

// Use EVP's prehashed operations directly: V's ecdsa .with_no_hash option
// still hashes in V 0.5.2, and its message helper rejects empty messages.
fn sign_digest(digest []u8, scalar []u8) ![]u8 {
	der := private_der(scalar)
	mut cursor := &u8(der.data)
	key := C.d2i_AutoPrivateKey(unsafe { nil }, &cursor, der.len)
	if key == unsafe { nil } { return error('OpenSSL private key import failed') }
	defer { C.EVP_PKEY_free(key) }
	ctx := C.EVP_PKEY_CTX_new(key, unsafe { nil })
	if ctx == unsafe { nil } { return error('OpenSSL signing context allocation failed') }
	defer { C.EVP_PKEY_CTX_free(ctx) }
	mut signature := []u8{len: 80}
	mut size := usize(signature.len)
	if C.EVP_PKEY_sign_init(ctx) != 1
		|| C.EVP_PKEY_sign(ctx, signature.data, &size, digest.data, digest.len) != 1 {
		return error('ECDSA signing failed')
	}
	return signature[..int(size)].clone()
}

fn verify_digest(digest []u8, signature []u8, point []u8) bool {
	der := public_der(point)
	mut cursor := &u8(der.data)
	key := C.d2i_PUBKEY(unsafe { nil }, &cursor, u32(der.len))
	if key == unsafe { nil } { return false }
	defer { C.EVP_PKEY_free(key) }
	ctx := C.EVP_PKEY_CTX_new(key, unsafe { nil })
	if ctx == unsafe { nil } { return false }
	defer { C.EVP_PKEY_CTX_free(ctx) }
	if C.EVP_PKEY_public_check(ctx) != 1 || C.EVP_PKEY_verify_init(ctx) != 1 { return false }
	return C.EVP_PKEY_verify(ctx, signature.data, signature.len, digest.data, digest.len) == 1
}
