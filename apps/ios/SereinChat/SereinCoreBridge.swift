import Foundation
import SereinCore

/// Shared Rust-core API. Ratchet snapshots are sensitive and must be AEAD-encrypted before persistence.
enum SereinCoreBridge {
    enum RatchetError: Error { case unavailable, invalidInput, operationFailed }

    static let version: String = {
        guard let bytes = serein_core_version() else { return "unavailable" }
        return String(cString: UnsafeRawPointer(bytes).assumingMemoryBound(to: CChar.self))
    }()

    struct Chains {
        let initiatorToResponder: Data
        let responderToInitiator: Data
    }

    static func deriveChains(bootstrapSecret: Data, sessionID: Data) throws -> Chains {
        guard bootstrapSecret.count == 32, sessionID.count == 16 else { throw RatchetError.invalidInput }
        var output = Data(count: 64)
        let result = bootstrapSecret.withUnsafeBytes { bootstrap in
            sessionID.withUnsafeBytes { session in
                output.withUnsafeMutableBytes { destination in
                    serein_core_ratchet_derive_chains(
                        bootstrap.bindMemory(to: UInt8.self).baseAddress!,
                        session.bindMemory(to: UInt8.self).baseAddress!,
                        0,
                        destination.bindMemory(to: UInt8.self).baseAddress!
                    )
                }
            }
        }
        guard result == 1 else { throw RatchetError.operationFailed }
        return Chains(initiatorToResponder: output.subdata(in: 0..<32), responderToInitiator: output.subdata(in: 32..<64))
    }

    final class Ratchet {
        private var handle: OpaquePointer?
        private let lock = NSLock()

        init(sessionID: Data, sendDirection: UInt8, sendChainKey: Data, receiveChainKey: Data) throws {
            guard sessionID.count == 16, sendChainKey.count == 32, receiveChainKey.count == 32, sendDirection <= 1 else {
                throw RatchetError.invalidInput
            }
            handle = sessionID.withUnsafeBytes { session in
                sendChainKey.withUnsafeBytes { send in
                    receiveChainKey.withUnsafeBytes { receive in
                        serein_core_ratchet_new(
                            session.bindMemory(to: UInt8.self).baseAddress!, sendDirection,
                            send.bindMemory(to: UInt8.self).baseAddress!, receive.bindMemory(to: UInt8.self).baseAddress!
                        )
                    }
                }
            }
            guard handle != nil else { throw RatchetError.operationFailed }
        }

        init(snapshot: Data) throws {
            guard !snapshot.isEmpty else { throw RatchetError.invalidInput }
            handle = snapshot.withUnsafeBytes { bytes in
                serein_core_ratchet_restore(bytes.bindMemory(to: UInt8.self).baseAddress!, snapshot.count)
            }
            guard handle != nil else { throw RatchetError.operationFailed }
        }

        func snapshot() throws -> Data {
            lock.lock(); defer { lock.unlock() }
            guard let handle else { throw RatchetError.unavailable }
            let length = serein_core_ratchet_snapshot_len(handle)
            guard length > 0, length <= 1_048_576 else { throw RatchetError.operationFailed }
            var output = Data(count: length)
            let written = output.withUnsafeMutableBytes { bytes in
                serein_core_ratchet_snapshot(handle, bytes.bindMemory(to: UInt8.self).baseAddress!, length)
            }
            guard written == length else { throw RatchetError.operationFailed }
            return output
        }

        /// Returns the fixed 22-byte ratchet header and ciphertext; pass the fresh 12-byte nonce separately.
        func encrypt(nonce: Data, plaintext: Data, aad: Data) throws -> (header: Data, ciphertext: Data) {
            lock.lock(); defer { lock.unlock() }
            guard let handle, nonce.count == 12, plaintext.count <= 32_768, aad.count <= 4_096 else { throw RatchetError.invalidInput }
            var header = Data(count: 22)
            var ciphertext = Data(count: plaintext.count + 16)
            let written = nonce.withUnsafeBytes { nonceBytes in
                plaintext.withUnsafeBytes { clear in
                    aad.withUnsafeBytes { aadBytes in
                        header.withUnsafeMutableBytes { headerBytes in
                            ciphertext.withUnsafeMutableBytes { cipherBytes in
                                serein_core_ratchet_encrypt(
                                    handle, nonceBytes.bindMemory(to: UInt8.self).baseAddress!,
                                    clear.bindMemory(to: UInt8.self).baseAddress, plaintext.count,
                                    aadBytes.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                    headerBytes.bindMemory(to: UInt8.self).baseAddress!, header.count,
                                    cipherBytes.bindMemory(to: UInt8.self).baseAddress!, ciphertext.count
                                )
                            }
                        }
                    }
                }
            }
            guard written >= 16, written <= ciphertext.count else { throw RatchetError.operationFailed }
            ciphertext.removeSubrange(written..<ciphertext.count)
            return (header, ciphertext)
        }

        func decrypt(header: Data, nonce: Data, ciphertext: Data, aad: Data) throws -> Data {
            lock.lock(); defer { lock.unlock() }
            guard let handle, header.count == 22, nonce.count == 12, ciphertext.count >= 16,
                  ciphertext.count <= 32_768 + 16, aad.count <= 4_096 else { throw RatchetError.invalidInput }
            let capacity = ciphertext.count - 16
            var plaintext = Data(count: max(1, capacity))
            let written = header.withUnsafeBytes { headerBytes in
                nonce.withUnsafeBytes { nonceBytes in
                    ciphertext.withUnsafeBytes { cipherBytes in
                        aad.withUnsafeBytes { aadBytes in
                            plaintext.withUnsafeMutableBytes { clear in
                                serein_core_ratchet_decrypt(
                                    handle, headerBytes.bindMemory(to: UInt8.self).baseAddress!,
                                    nonceBytes.bindMemory(to: UInt8.self).baseAddress!,
                                    cipherBytes.bindMemory(to: UInt8.self).baseAddress!, ciphertext.count,
                                    aadBytes.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                    clear.bindMemory(to: UInt8.self).baseAddress!, capacity
                                )
                            }
                        }
                    }
                }
            }
            guard written >= 0, written <= capacity else { throw RatchetError.operationFailed }
            plaintext.removeSubrange(written..<plaintext.count)
            return plaintext
        }

        func close() {
            lock.lock(); defer { lock.unlock() }
            if let handle { serein_core_ratchet_free(handle); self.handle = nil }
        }

        deinit { close() }
    }
}
