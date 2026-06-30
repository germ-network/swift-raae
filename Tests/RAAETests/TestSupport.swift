import Foundation

@testable import RAAE

enum Hex {
	/// Decode a hex string to bytes. Traps on malformed input (test-only).
	static func decode(_ string: String) -> [UInt8] {
		precondition(string.count % 2 == 0, "odd-length hex: \(string)")
		var out = [UInt8]()
		out.reserveCapacity(string.count / 2)
		var index = string.startIndex
		while index < string.endIndex {
			let next = string.index(index, offsetBy: 2)
			out.append(UInt8(string[index..<next], radix: 16)!)
			index = next
		}
		return out
	}

	static func encode(_ bytes: [UInt8]) -> String {
		bytes.map { String(format: "%02x", $0) }.joined()
	}
}

/// Decodes a vector JSON resource bundled with the test target.
enum Vectors {
	static func load(_ name: String) throws -> [String: Any] {
		let url = Bundle.module.url(
			forResource: name, withExtension: "json", subdirectory: "Vectors")!
		let data = try Data(contentsOf: url)
		return try JSONSerialization.jsonObject(with: data) as! [String: Any]
	}

	/// Build the `PayloadInfo` described by a vector's `payload_info` block.
	static func payloadInfo(from v: [String: Any]) -> PayloadInfo {
		let pi = v["payload_info"] as! [String: Any]
		return PayloadInfo(
			aeadID: UInt16(pi["aead_id"] as! Int),
			segmentMax: UInt32(pi["segment_max"] as! Int),
			kdfID: UInt16(pi["kdf_id"] as! Int),
			snapID: UInt16(pi["snap_id"] as! Int),
			nonceMode: PayloadInfo.NonceMode(
				rawValue: UInt8(pi["nonce_mode"] as! Int))!,
			epochLength: UInt8(pi["epoch_length"] as! Int),
			salt: Hex.decode(pi["salt_hex"] as! String)
		)
	}

	/// Build the `PayloadSchedule` for a vector (always `SEAL-RW-v1` in Appendix E).
	static func schedule(from v: [String: Any]) throws -> PayloadSchedule {
		try PayloadSchedule(
			protocolID: ProtocolID.mutable,
			cek: Hex.decode(v["cek_hex"] as! String),
			payloadInfo: payloadInfo(from: v)
		)
	}

	/// Concatenated `ct || tag` for a segment dictionary.
	static func ciphertextWithTag(_ seg: [String: Any]) -> [UInt8] {
		Hex.decode(seg["ciphertext_hex"] as! String) + Hex.decode(seg["tag_hex"] as! String)
	}
}
