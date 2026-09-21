import Crypto

/// Test seam: force the pre-5.0 array path at every span decision point, so the two
/// paths can be diffed byte-for-byte in one process on a platform that has both
/// (see `PathEquivalenceTests`). Package-scoped and never set by production code; the
/// paths are byte-identical by construction, so a concurrent reader is unaffected.
package nonisolated(unsafe) var forceArrayPath = false

/// Per-segment AEAD, taking swift-crypto 5.0's in-place span path where the platform
/// provides it and falling back to the suite's own `DataProtocol` path otherwise.
///
/// The public ``AEAD`` protocol deliberately does **not** grow an in-place requirement:
/// `AES.GCM._SIV` (the MRAE suite CryptoExtras backs) has no span surface at all, so
/// the MRAE path gains nothing, and the saving here is only copies of *public* bytes
/// (`Array(box.ciphertext) + Array(box.tag)` and one whole-segment copy per call).
///
/// The `#if` gate is the same one swift-secret-bytes uses — true exactly where the span
/// surface exists at compile time (Darwin against an Xcode-27-or-newer SDK, where the
/// members come from CryptoKit and carry OS-27 availability; and every non-CryptoKit
/// platform, where swift-crypto declares them unconditionally). The bodies in the two
/// branches must stay in sync; the `#elseif` branch is Darwin against an older SDK,
/// where there is no span surface and the array path below carries everything.
func sealSegment(
	aead: any AEAD, key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]
) throws -> [UInt8] {
	#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
		if #available(macOS 27, iOS 27, *), !forceArrayPath {
			if let ciphertext = try sealSegmentInPlace(
				aead: aead, key: key, nonce: nonce, aad: aad, plaintext: plaintext)
			{
				return ciphertext
			}
		}
	#elseif canImport(CryptoKit)
	#else
		if !forceArrayPath,
			let ciphertext = try sealSegmentInPlace(
				aead: aead, key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		{
			return ciphertext
		}
	#endif
	return try aead.seal(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
}

/// ``sealSegment(aead:key:nonce:aad:plaintext:)``'s counterpart: decrypt `ct || tag`.
func openSegment(
	aead: any AEAD, key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]
) throws -> [UInt8] {
	#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
		if #available(macOS 27, iOS 27, *), !forceArrayPath {
			if let plaintext = try openSegmentInPlace(
				aead: aead, key: key, nonce: nonce, aad: aad, ciphertext: ciphertext
			) {
				return plaintext
			}
		}
	#elseif canImport(CryptoKit)
	#else
		if !forceArrayPath,
			let plaintext = try openSegmentInPlace(
				aead: aead, key: key, nonce: nonce, aad: aad, ciphertext: ciphertext
			)
		{
			return plaintext
		}
	#endif
	return try aead.open(key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
}

#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	extension AES128GCM {
		func sealInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]
		) throws -> [UInt8] {
			try gcmSealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext,
				tagLength: tagLength)
		}

		func openInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]
		) throws -> [UInt8] {
			try gcmOpenInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext,
				tagLength: tagLength)
		}
	}

	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	extension AES256GCM {
		func sealInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]
		) throws -> [UInt8] {
			try gcmSealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext,
				tagLength: tagLength)
		}

		func openInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]
		) throws -> [UInt8] {
			try gcmOpenInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext,
				tagLength: tagLength)
		}
	}

	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	extension ChaCha20Poly1305 {
		func sealInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]
		) throws -> [UInt8] {
			try chachaSealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext,
				tagLength: tagLength)
		}

		func openInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]
		) throws -> [UInt8] {
			try chachaOpenInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext,
				tagLength: tagLength)
		}
	}

	/// Dispatches to the concrete suite's in-place path; `nil` for a suite without one
	/// (`AES256GCMSIV`), which then takes its own `seal`.
	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	private func sealSegmentInPlace(
		aead: any AEAD, key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]
	) throws -> [UInt8]? {
		try aead.validate(key: key, nonce: nonce)
		switch aead {
		case let suite as AES128GCM:
			return try suite.sealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		case let suite as AES256GCM:
			return try suite.sealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		case let suite as ChaCha20Poly1305:
			return try suite.sealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		default:
			return nil
		}
	}

	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	private func openSegmentInPlace(
		aead: any AEAD, key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]
	) throws -> [UInt8]? {
		try aead.validate(key: key, nonce: nonce)
		switch aead {
		case let suite as AES128GCM:
			return try suite.openInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
		case let suite as AES256GCM:
			return try suite.openInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
		case let suite as ChaCha20Poly1305:
			return try suite.openInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
		default:
			return nil
		}
	}

	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	private func gcmSealInPlace(
		key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8], tagLength: Int
	) throws -> [UInt8] {
		var output = plaintext
		output.append(contentsOf: [UInt8](repeating: 0, count: tagLength))
		try nonce.withUnsafeBytes { nonceBytes in
			let gcmNonce = try AES.GCM.Nonce(copying: RawSpan(_unsafeBytes: nonceBytes))
			try aad.withUnsafeBytes { aadBytes in
				try output.withUnsafeMutableBytes { out in
					let base = out.baseAddress!
					let tagStart = base + plaintext.count
					var message = MutableRawSpan(
						_unsafeBytes: UnsafeMutableRawBufferPointer(
							start: base, count: plaintext.count))
					var tag = OutputRawSpan(
						buffer: UnsafeMutableRawBufferPointer(
							start: tagStart, count: tagLength),
						initializedCount: 0)
					try AES.GCM.seal(
						inPlace: &message, using: key, nonce: gcmNonce,
						authenticating: aadBytes.isEmpty
							? nil : RawSpan(_unsafeBytes: aadBytes),
						tag: &tag)
				}
			}
		}
		return output
	}

	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	private func gcmOpenInPlace(
		key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8], tagLength: Int
	) throws -> [UInt8] {
		guard ciphertext.count >= tagLength else {
			throw AEADError.invalidParameters(
				"ciphertext shorter than tag (\(tagLength) octets)")
		}
		let bodyCount = ciphertext.count - tagLength
		var output = Array(ciphertext.prefix(bodyCount))
		do {
			try nonce.withUnsafeBytes { nonceBytes in
				let gcmNonce = try AES.GCM.Nonce(
					copying: RawSpan(_unsafeBytes: nonceBytes))
				try aad.withUnsafeBytes { aadBytes in
					try ciphertext.withUnsafeBytes { ctBytes in
						let tagStart = ctBytes.baseAddress! + bodyCount
						try output.withUnsafeMutableBytes { out in
							var message = MutableRawSpan(
								_unsafeBytes:
									UnsafeMutableRawBufferPointer(
										start: out
											.baseAddress,
										count: bodyCount))
							try AES.GCM.open(
								inPlace: &message, using: key,
								nonce: gcmNonce,
								authenticating: aadBytes.isEmpty
									? nil
									: RawSpan(
										_unsafeBytes:
											aadBytes),
								tag: RawSpan(
									_unsafeBytes:
										UnsafeRawBufferPointer(
											start:
												tagStart,
											count:
												tagLength
										)))
						}
					}
				}
			}
		} catch {
			throw AEADError.authenticationFailure
		}
		return output
	}

	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	private func chachaSealInPlace(
		key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8], tagLength: Int
	) throws -> [UInt8] {
		var output = plaintext
		output.append(contentsOf: [UInt8](repeating: 0, count: tagLength))
		try nonce.withUnsafeBytes { nonceBytes in
			let chachaNonce = try ChaChaPoly.Nonce(
				copying: RawSpan(_unsafeBytes: nonceBytes))
			try aad.withUnsafeBytes { aadBytes in
				try output.withUnsafeMutableBytes { out in
					let base = out.baseAddress!
					let tagStart = base + plaintext.count
					var message = MutableRawSpan(
						_unsafeBytes: UnsafeMutableRawBufferPointer(
							start: base, count: plaintext.count))
					var tag = OutputRawSpan(
						buffer: UnsafeMutableRawBufferPointer(
							start: tagStart, count: tagLength),
						initializedCount: 0)
					try ChaChaPoly.seal(
						inPlace: &message, using: key, nonce: chachaNonce,
						authenticating: aadBytes.isEmpty
							? nil : RawSpan(_unsafeBytes: aadBytes),
						tag: &tag)
				}
			}
		}
		return output
	}

	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	private func chachaOpenInPlace(
		key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8], tagLength: Int
	) throws -> [UInt8] {
		guard ciphertext.count >= tagLength else {
			throw AEADError.invalidParameters(
				"ciphertext shorter than tag (\(tagLength) octets)")
		}
		let bodyCount = ciphertext.count - tagLength
		var output = Array(ciphertext.prefix(bodyCount))
		do {
			try nonce.withUnsafeBytes { nonceBytes in
				let chachaNonce = try ChaChaPoly.Nonce(
					copying: RawSpan(_unsafeBytes: nonceBytes))
				try aad.withUnsafeBytes { aadBytes in
					try ciphertext.withUnsafeBytes { ctBytes in
						let tagStart = ctBytes.baseAddress! + bodyCount
						try output.withUnsafeMutableBytes { out in
							var message = MutableRawSpan(
								_unsafeBytes:
									UnsafeMutableRawBufferPointer(
										start: out
											.baseAddress,
										count: bodyCount))
							try ChaChaPoly.open(
								inPlace: &message, using: key,
								nonce: chachaNonce,
								authenticating: aadBytes.isEmpty
									? nil
									: RawSpan(
										_unsafeBytes:
											aadBytes),
								tag: RawSpan(
									_unsafeBytes:
										UnsafeRawBufferPointer(
											start:
												tagStart,
											count:
												tagLength
										)))
						}
					}
				}
			}
		} catch {
			throw AEADError.authenticationFailure
		}
		return output
	}
#elseif canImport(CryptoKit)
	// Darwin against an older SDK: CryptoKit lacks the span members, so the in-place
	// path above is not declared and every segment takes the array path.
#else
	// Non-CryptoKit platforms: swift-crypto declares the same span surface
	// unconditionally. Bodies mirror the branch above; keep them in sync.
	extension AES128GCM {
		func sealInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]
		) throws -> [UInt8] {
			try gcmSealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext,
				tagLength: tagLength)
		}

		func openInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]
		) throws -> [UInt8] {
			try gcmOpenInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext,
				tagLength: tagLength)
		}
	}

	extension AES256GCM {
		func sealInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]
		) throws -> [UInt8] {
			try gcmSealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext,
				tagLength: tagLength)
		}

		func openInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]
		) throws -> [UInt8] {
			try gcmOpenInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext,
				tagLength: tagLength)
		}
	}

	extension ChaCha20Poly1305 {
		func sealInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]
		) throws -> [UInt8] {
			try chachaSealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext,
				tagLength: tagLength)
		}

		func openInPlace(
			key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]
		) throws -> [UInt8] {
			try chachaOpenInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext,
				tagLength: tagLength)
		}
	}

	private func sealSegmentInPlace(
		aead: any AEAD, key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]
	) throws -> [UInt8]? {
		try aead.validate(key: key, nonce: nonce)
		switch aead {
		case let suite as AES128GCM:
			return try suite.sealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		case let suite as AES256GCM:
			return try suite.sealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		case let suite as ChaCha20Poly1305:
			return try suite.sealInPlace(
				key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		default:
			return nil
		}
	}

	private func openSegmentInPlace(
		aead: any AEAD, key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]
	) throws -> [UInt8]? {
		try aead.validate(key: key, nonce: nonce)
		switch aead {
		case let suite as AES128GCM:
			return try suite.openInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
		case let suite as AES256GCM:
			return try suite.openInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
		case let suite as ChaCha20Poly1305:
			return try suite.openInPlace(
				key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
		default:
			return nil
		}
	}

	private func gcmSealInPlace(
		key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8], tagLength: Int
	) throws -> [UInt8] {
		var output = plaintext
		output.append(contentsOf: [UInt8](repeating: 0, count: tagLength))
		try nonce.withUnsafeBytes { nonceBytes in
			let gcmNonce = try AES.GCM.Nonce(copying: RawSpan(_unsafeBytes: nonceBytes))
			try aad.withUnsafeBytes { aadBytes in
				try output.withUnsafeMutableBytes { out in
					let base = out.baseAddress!
					let tagStart = base + plaintext.count
					var message = MutableRawSpan(
						_unsafeBytes: UnsafeMutableRawBufferPointer(
							start: base, count: plaintext.count))
					var tag = OutputRawSpan(
						buffer: UnsafeMutableRawBufferPointer(
							start: tagStart, count: tagLength),
						initializedCount: 0)
					try AES.GCM.seal(
						inPlace: &message, using: key, nonce: gcmNonce,
						authenticating: aadBytes.isEmpty
							? nil : RawSpan(_unsafeBytes: aadBytes),
						tag: &tag)
				}
			}
		}
		return output
	}

	private func gcmOpenInPlace(
		key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8], tagLength: Int
	) throws -> [UInt8] {
		guard ciphertext.count >= tagLength else {
			throw AEADError.invalidParameters(
				"ciphertext shorter than tag (\(tagLength) octets)")
		}
		let bodyCount = ciphertext.count - tagLength
		var output = Array(ciphertext.prefix(bodyCount))
		do {
			try nonce.withUnsafeBytes { nonceBytes in
				let gcmNonce = try AES.GCM.Nonce(
					copying: RawSpan(_unsafeBytes: nonceBytes))
				try aad.withUnsafeBytes { aadBytes in
					try ciphertext.withUnsafeBytes { ctBytes in
						let tagStart = ctBytes.baseAddress! + bodyCount
						try output.withUnsafeMutableBytes { out in
							var message = MutableRawSpan(
								_unsafeBytes:
									UnsafeMutableRawBufferPointer(
										start: out
											.baseAddress,
										count: bodyCount))
							try AES.GCM.open(
								inPlace: &message, using: key,
								nonce: gcmNonce,
								authenticating: aadBytes.isEmpty
									? nil
									: RawSpan(
										_unsafeBytes:
											aadBytes),
								tag: RawSpan(
									_unsafeBytes:
										UnsafeRawBufferPointer(
											start:
												tagStart,
											count:
												tagLength
										)))
						}
					}
				}
			}
		} catch {
			throw AEADError.authenticationFailure
		}
		return output
	}

	private func chachaSealInPlace(
		key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8], tagLength: Int
	) throws -> [UInt8] {
		var output = plaintext
		output.append(contentsOf: [UInt8](repeating: 0, count: tagLength))
		try nonce.withUnsafeBytes { nonceBytes in
			let chachaNonce = try ChaChaPoly.Nonce(
				copying: RawSpan(_unsafeBytes: nonceBytes))
			try aad.withUnsafeBytes { aadBytes in
				try output.withUnsafeMutableBytes { out in
					let base = out.baseAddress!
					let tagStart = base + plaintext.count
					var message = MutableRawSpan(
						_unsafeBytes: UnsafeMutableRawBufferPointer(
							start: base, count: plaintext.count))
					var tag = OutputRawSpan(
						buffer: UnsafeMutableRawBufferPointer(
							start: tagStart, count: tagLength),
						initializedCount: 0)
					try ChaChaPoly.seal(
						inPlace: &message, using: key, nonce: chachaNonce,
						authenticating: aadBytes.isEmpty
							? nil : RawSpan(_unsafeBytes: aadBytes),
						tag: &tag)
				}
			}
		}
		return output
	}

	private func chachaOpenInPlace(
		key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8], tagLength: Int
	) throws -> [UInt8] {
		guard ciphertext.count >= tagLength else {
			throw AEADError.invalidParameters(
				"ciphertext shorter than tag (\(tagLength) octets)")
		}
		let bodyCount = ciphertext.count - tagLength
		var output = Array(ciphertext.prefix(bodyCount))
		do {
			try nonce.withUnsafeBytes { nonceBytes in
				let chachaNonce = try ChaChaPoly.Nonce(
					copying: RawSpan(_unsafeBytes: nonceBytes))
				try aad.withUnsafeBytes { aadBytes in
					try ciphertext.withUnsafeBytes { ctBytes in
						let tagStart = ctBytes.baseAddress! + bodyCount
						try output.withUnsafeMutableBytes { out in
							var message = MutableRawSpan(
								_unsafeBytes:
									UnsafeMutableRawBufferPointer(
										start: out
											.baseAddress,
										count: bodyCount))
							try ChaChaPoly.open(
								inPlace: &message, using: key,
								nonce: chachaNonce,
								authenticating: aadBytes.isEmpty
									? nil
									: RawSpan(
										_unsafeBytes:
											aadBytes),
								tag: RawSpan(
									_unsafeBytes:
										UnsafeRawBufferPointer(
											start:
												tagStart,
											count:
												tagLength
										)))
						}
					}
				}
			}
		} catch {
			throw AEADError.authenticationFailure
		}
		return output
	}
#endif
