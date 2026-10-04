module main

import vsea

fn main() {
	alice := vsea.generate_random_pair()!
	bob := vsea.generate_random_pair()!
	message := 'Hello, VSEA! 你好！'
	signature := vsea.sign_message(message, alice.priv)!
	assert vsea.verify_message(message, signature, alice.pub)
	payload := vsea.encrypt_message_with_meta(message, bob.epub)!
	plaintext := vsea.decrypt_message_with_meta(payload, bob.epriv)!
	assert plaintext == message
	println(plaintext)
	println('Signature verified; encrypted message decrypted.')
}
