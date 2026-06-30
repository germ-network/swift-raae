import Foundation

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
}
