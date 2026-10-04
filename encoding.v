module vsea

import encoding.base64
import encoding.hex

const p256_order = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'
const p256_half_order = '7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8'

fn decode64(value string) ![]u8 {
	if value.len == 0 || value.len % 4 == 1 {
		return error('invalid unpadded base64url')
	}
	for b in value.bytes() {
		if !((b >= `A` && b <= `Z`) || (b >= `a` && b <= `z`)
			|| (b >= `0` && b <= `9`) || b == `-` || b == `_`) {
			return error('invalid unpadded base64url')
		}
	}
	decoded := base64.url_decode(value)
	if base64.url_encode(decoded) != value {
		return error('noncanonical base64url')
	}
	return decoded
}

fn private_bytes(value string) ![]u8 {
	data := decode64(value)!
	if data.len != 32 || data.hex() >= p256_order || data.all(it == 0) {
		return error('invalid P-256 private scalar')
	}
	return data
}

fn public_bytes(value string) ![]u8 {
	parts := value.split('.')
	if parts.len != 2 { return error('public key must contain x.y') }
	x := decode64(parts[0])!
	y := decode64(parts[1])!
	if x.len != 32 || y.len != 32 { return error('P-256 coordinates must be 32 bytes') }
	mut point := [u8(4)]
	point << x
	point << y
	return point
}

fn point_string(point []u8) !string {
	if point.len != 65 || point[0] != 4 { return error('invalid uncompressed P-256 point') }
	return base64.url_encode(point[1..33]) + '.' + base64.url_encode(point[33..])
}

fn public_der(point []u8) []u8 {
	mut der := hex.decode('3059301306072a8648ce3d020106082a8648ce3d030107034200') or { panic(err) }
	der << point
	return der
}

fn private_der(scalar []u8) []u8 {
	mut der := hex.decode('3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420') or {
		panic(err)
	}
	der << scalar
	return der
}

fn compact_signature(der []u8) ![]u8 {
	if der.len < 8 || der[0] != 0x30 || int(der[1]) != der.len - 2 {
		return error('invalid DER signature')
	}
	mut offset := 2
	mut raw := []u8{cap: 64}
	for _ in 0 .. 2 {
		if offset + 2 > der.len || der[offset] != 2 { return error('invalid DER integer') }
		size := int(der[offset + 1])
		offset += 2
		if size < 1 || size > 33 || offset + size > der.len {
			return error('invalid DER integer length')
		}
		mut part := der[offset..offset + size].clone()
		offset += size
		if part.len == 33 {
			if part[0] != 0 { return error('invalid DER integer padding') }
			part = part[1..].clone()
		}
		raw << []u8{len: 32 - part.len}
		raw << part
	}
	if offset != der.len { return error('trailing DER signature data') }
	// Emit canonical low-S signatures; verification also accepts upstream high-S.
	if raw[32..].hex() > p256_half_order {
		order := hex.decode(p256_order)!
		mut borrow := 0
		for i := 31; i >= 0; i-- {
			value := int(order[i]) - int(raw[32 + i]) - borrow
			raw[32 + i] = u8(value & 255)
			borrow = if value < 0 { 1 } else { 0 }
		}
	}
	return raw
}

fn signature_der(raw []u8) ![]u8 {
	if raw.len != 64 { return error('signature must be 64 bytes') }
	if raw[..32].all(it == 0) || raw[32..].all(it == 0) || raw[..32].hex() >= p256_order
		|| raw[32..].hex() >= p256_order {
		return error('invalid P-256 signature')
	}
	mut body := []u8{}
	for part in [raw[..32], raw[32..]] {
		mut start := 0
		for start < 31 && part[start] == 0 {
			start++
		}
		mut integer := part[start..].clone()
		if integer[0] & 0x80 != 0 { integer.prepend(u8(0)) }
		body << u8(2)
		body << u8(integer.len)
		body << integer
	}
	mut der := [u8(0x30), u8(body.len)]
	der << body
	return der
}
