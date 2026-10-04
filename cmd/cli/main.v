module main

import x.json2
import json as _
import encoding.utf8
import os
import vsea

struct Request {
	message   string
	priv      string
	pub       string
	epub      string
	epriv     string
	signature string
	payload   vsea.EncryptedMessageWithMeta
	jwk       vsea.JWK
}

struct SignatureResult {
	signature string
}

struct MessageResult {
	message string
}

struct VerifyResult {
	valid bool
}

struct PrivateResult {
	priv string
}

const usage = 'VSEA 0.1.0 — unsea-compatible V cryptographic toolkit
Usage: vsea <command> < request.json

Commands (one JSON object on stdin; one JSON object on stdout):
  keygen      No input. Returns {pub, priv, epub, epriv}.
  sign        Input: {message, priv}. Returns {signature}.
  verify      Input: {message, signature, pub}. Returns {valid}.
  encrypt     Input: {message, epub}. Returns an encrypted envelope.
  decrypt     Input: {payload, epriv}. Returns {message}.
  export-jwk  Input: {priv}. Returns a private JWK.
  import-jwk  Input: {jwk}. Returns {priv}.

Exit status: 0 success, 1 operation error or invalid signature, 2 usage error.
Errors go to stderr. Private keys are read from stdin, never command arguments.'

fn main() {
	if os.args.len == 2 && os.args[1] in ['--help', '-h'] {
		println(usage)
		return
	}
	if os.args.len != 2
		|| os.args[1] !in ['keygen', 'sign', 'verify', 'encrypt', 'decrypt', 'export-jwk', 'import-jwk'] {
		eprintln(usage)
		exit(2)
	}
	valid := run(os.args[1]) or {
		eprintln('VSEA: ${err}')
		exit(1)
	}
	if !valid { exit(1) }
}

fn run(command string) !bool {
	if command == 'keygen' {
		println(json2.encode(vsea.generate_random_pair()!))
		return true
	}
	// Do not echo parser errors: they can include input containing private keys.
	input := os.get_raw_lines_joined()
	validate_request_json(input)!
	request := json2.decode[Request](input, strict: true) or {
		return error('invalid JSON request')
	}
	match command {
		'sign' {
			println(json2.encode(SignatureResult{vsea.sign_message(request.message, request.priv)!}))
		}
		'verify' {
			valid := vsea.verify_message(request.message, request.signature, request.pub)
			println(json2.encode(VerifyResult{valid}))
			return valid
		}
		'encrypt' {
			println(json2.encode(vsea.encrypt_message_with_meta(request.message, request.epub)!))
		}
		'decrypt' {
			println(json2.encode(MessageResult{vsea.decrypt_message_with_meta(request.payload,
				request.epriv)!}))
		}
		'export-jwk' {
			println(json2.encode(vsea.export_to_jwk(request.priv)!))
		}
		'import-jwk' {
			println(json2.encode(PrivateResult{vsea.import_from_jwk(request.jwk)!}))
		}
		else {
			return error('unknown command')
		}
	}

	return true
}

// Validate with the standard library's bounded cJSON parser before json2
// decoding: json2 preserves embedded NUL, but its malformed-input error path
// can panic in V 0.5.2. Never include the request in diagnostics.
fn C.cJSON_ParseWithLengthOpts(value &char, length usize, end &&char, require_end int) &C.cJSON
fn C.cJSON_Delete(item &C.cJSON)

fn validate_request_json(input string) ! {
	if !utf8.validate_str(input) || input.bytes().contains(u8(0)) {
		return error('invalid JSON request')
	}
	root := C.cJSON_ParseWithLengthOpts(input.str, usize(input.len) + 1, unsafe { nil }, 1)
	if root == unsafe { nil } { return error('invalid JSON request') }
	defer { C.cJSON_Delete(root) }
	if !C.cJSON_IsObject(root) { return error('request must be a JSON object') }
}
