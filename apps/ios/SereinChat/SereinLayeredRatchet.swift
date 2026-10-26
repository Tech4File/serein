import Foundation

/// Experimental, two-layer v3 envelope adapter shared with the browser wire format.
final class SereinLayeredRatchet {
    static let headerLength = 22
    // Reserve 58 bytes for the nested SRL1 header/nonce/length inside Layer 2.
    static let maxPlaintext = 32_710
    static let maxCiphertext = maxPlaintext + 16
    static let maxOuterCiphertext = maxPlaintext + 74
    private static let magic = Data([0x53, 0x52, 0x4c, 0x31])
    private let layer1: SereinCoreBridge.Ratchet
    private let layer2: SereinCoreBridge.Ratchet
    let layer1Name: String
    let layer2Name: String

    init(layer1: SereinCoreBridge.Ratchet, layer2: SereinCoreBridge.Ratchet, layer1Name: String, layer2Name: String) {
        self.layer1 = layer1; self.layer2 = layer2; self.layer1Name = layer1Name; self.layer2Name = layer2Name
    }

    func encrypt(_ plaintext: Data, metadata: [String: String]) throws -> [String: String] {
        guard plaintext.count <= Self.maxPlaintext else { throw SereinCoreBridge.RatchetError.invalidInput }
        let innerNonce = try SereinDeviceCrypto.randomData(count: 12)
        let inner = try layer1.encrypt(nonce: innerNonce, plaintext: plaintext, aad: Self.routeAAD(metadata, layer: "layer1"))
        let packed = try Self.pack(inner: inner, nonce: innerNonce)
        let outerNonce = try SereinDeviceCrypto.randomData(count: 12)
        let outer = try layer2.encrypt(nonce: outerNonce, plaintext: packed, aad: Self.routeAAD(metadata, layer: "layer2"))
        guard outer.header.count == Self.headerLength, outer.ciphertext.count <= Self.maxCiphertext else { throw SereinCoreBridge.RatchetError.operationFailed }
        return ["iv": outerNonce.base64EncodedString(), "ciphertext": (outer.header + outer.ciphertext).base64EncodedString()]
    }

    func decrypt(iv: String, ciphertext: String, metadata: [String: String]) throws -> Data {
        guard let nonce = Self.decodeBase64(iv, maxLength: 24), nonce.count == 12,
              let complete = Self.decodeBase64(ciphertext, maxLength: 43_744),
              complete.count >= Self.headerLength + 16, complete.count <= Self.headerLength + Self.maxOuterCiphertext else {
            throw SereinCoreBridge.RatchetError.invalidInput
        }
        let header = complete.prefix(Self.headerLength)
        let outerCipher = complete.dropFirst(Self.headerLength)
        let packed = try layer2.decrypt(header: Data(header), nonce: nonce, ciphertext: Data(outerCipher), aad: Self.routeAAD(metadata, layer: "layer2"))
        let inner = try Self.unpack(packed)
        return try layer1.decrypt(header: inner.header, nonce: inner.nonce, ciphertext: inner.ciphertext,
                                  aad: Self.routeAAD(metadata, layer: "layer1"))
    }

    func snapshots() throws -> [String: Data] {
        [layer1Name: try layer1.snapshot(), layer2Name: try layer2.snapshot()]
    }
    func close() { layer1.close(); layer2.close() }

    private static func routeAAD(_ metadata: [String: String], layer: String) throws -> Data {
        let keys = ["conversationId", "messageId", "senderUserId", "senderDeviceId", "recipientUserId", "recipientDeviceId"]
        let values = keys.map { metadata[$0] ?? "" }
        guard values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 }) else { throw SereinCoreBridge.RatchetError.invalidInput }
        return try JSONSerialization.data(withJSONObject: ["serein-message-v3-\(layer)"] + values)
    }

    private static func pack(inner: (header: Data, ciphertext: Data), nonce: Data) throws -> Data {
        guard inner.header.count == Self.headerLength, nonce.count == 12,
              inner.ciphertext.count >= 16, inner.ciphertext.count <= Self.maxCiphertext else { throw SereinCoreBridge.RatchetError.operationFailed }
        var output = magic + inner.header + nonce
        var length = UInt32(inner.ciphertext.count).bigEndian
        withUnsafeBytes(of: &length) { output.append(contentsOf: $0) }
        output.append(inner.ciphertext)
        return output
    }

    private static func unpack(_ value: Data) throws -> (header: Data, nonce: Data, ciphertext: Data) {
        let prefix = 4 + Self.headerLength + 12 + 4
        guard value.count >= prefix + 16, value.count <= prefix + Self.maxCiphertext,
              value.prefix(4) == magic else { throw SereinCoreBridge.RatchetError.invalidInput }
        let lengthStart = 4 + Self.headerLength + 12
        let length = value[lengthStart..<lengthStart + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length >= 16, length <= Self.maxCiphertext, value.count == prefix + Int(length) else { throw SereinCoreBridge.RatchetError.invalidInput }
        let headerStart = 4, nonceStart = headerStart + Self.headerLength, cipherStart = prefix
        return (Data(value[headerStart..<nonceStart]), Data(value[nonceStart..<lengthStart]), Data(value[cipherStart...]))
    }

    private static func decodeBase64(_ value: String, maxLength: Int) -> Data? {
        guard value.utf8.count <= maxLength, !value.isEmpty,
              value.range(of: "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", options: .regularExpression) != nil,
              let decoded = Data(base64Encoded: value), decoded.base64EncodedString() == value else { return nil }
        return decoded
    }
}
