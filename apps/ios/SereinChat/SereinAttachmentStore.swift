import Foundation
import UIKit

/// Persistent, app-organized downloads. The Documents subfolder is deliberately
/// exposed in Files; downloads remain sandboxed to Serein until the user opens,
/// shares, or exports one. No Photos-library permission is requested.
@MainActor
final class SereinAttachmentStore: NSObject, UIDocumentInteractionControllerDelegate {
    static let shared = SereinAttachmentStore()
    private let folderName = "Serein/Downloads"
    private let maximumDownloadBytes: Int64 = 64 * 1024 * 1024
    private var cachedDownloadsDirectory: URL?
    private var activeDocumentController: UIDocumentInteractionController?
    private var dismissHandler: (() -> Void)?

    private override init() { super.init() }

    private func downloadsDirectory() throws -> URL {
        if let cachedDownloadsDirectory, FileManager.default.fileExists(atPath: cachedDownloadsDirectory.path) { return cachedDownloadsDirectory }
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            throw StoreError.storageUnavailable
        }
        let directory = documents.appendingPathComponent(folderName, isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete]
        )
        cachedDownloadsDirectory = directory
        return directory
    }

    private func safeFilename(_ input: String?) -> String {
        let raw = (input?.isEmpty == false ? input : nil) ?? "attachment"
        var scalars = String.UnicodeScalarView()
        for scalar in raw.unicodeScalars.prefix(150) {
            scalars.append(scalar == "/" || scalar == "\\" || CharacterSet.controlCharacters.contains(scalar) ? "_" : scalar)
        }
        var safe = String(scalars).trimmingCharacters(in: .whitespacesAndNewlines)
        while safe.hasPrefix(".") { safe.removeFirst() }
        return safe.isEmpty ? "attachment" : safe
    }

    private func stableName(transferID: String, filename: String?) throws -> String {
        guard let uuid = UUID(uuidString: transferID) else { throw StoreError.invalidTransferIdentifier }
        return "\(uuid.uuidString.lowercased())_\(safeFilename(filename))"
    }

    func cleanTemporaryFiles() {
        let cutoff = Date().addingTimeInterval(-24 * 60 * 60)
        let temporary = FileManager.default.temporaryDirectory
        guard let files = try? FileManager.default.contentsOfDirectory(at: temporary, includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles]) else { return }
        for file in files where file.lastPathComponent.hasPrefix("serein-clear-") {
            let values = try? file.resourceValues(forKeys: [.contentModificationDateKey])
            if let modified = values?.contentModificationDate, modified < cutoff { try? FileManager.default.removeItem(at: file) }
        }
    }

    func existing(transferID: String, filename: String?, expectedBytes: Int64) -> URL? {
        guard expectedBytes >= 0, expectedBytes <= maximumDownloadBytes,
              let name = try? stableName(transferID: transferID, filename: filename),
              let root = try? downloadsDirectory() else { return nil }
        let url = root.appendingPathComponent(name, isDirectory: false).standardizedFileURL
        guard url.deletingLastPathComponent() == root.standardizedFileURL,
              let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = attributes[.size] as? NSNumber, size.int64Value == expectedBytes else { return nil }
        return url
    }

    /// Copies already-decrypted bytes from a temporary file to persistent local storage.
    /// The caller owns crypto and must authenticate the complete transfer before calling.
    func save(transferID: String, filename: String?, from sourceURL: URL, expectedBytes: Int64) throws -> URL {
        guard expectedBytes >= 0, expectedBytes <= maximumDownloadBytes else { throw StoreError.invalidSizeLimit }
        let root = try downloadsDirectory()
        let name = try stableName(transferID: transferID, filename: filename)
        let destination = root.appendingPathComponent(name, isDirectory: false).standardizedFileURL
        guard destination.deletingLastPathComponent() == root.standardizedFileURL else { throw StoreError.invalidFilename }
        let attributes = try FileManager.default.attributesOfItem(atPath: sourceURL.path)
        guard let size = attributes[.size] as? NSNumber, size.int64Value == expectedBytes else { throw StoreError.fileTooLarge }
        let temporary = root.appendingPathComponent(".\(UUID().uuidString).part", isDirectory: false)
        do {
            try FileManager.default.copyItem(at: sourceURL, to: temporary)
            let copiedAttributes = try FileManager.default.attributesOfItem(atPath: temporary.path)
            guard let copiedSize = copiedAttributes[.size] as? NSNumber, copiedSize.int64Value == expectedBytes else { throw StoreError.fileTooLarge }
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: temporary.path)
            if FileManager.default.fileExists(atPath: destination.path) {
                _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
            } else {
                try FileManager.default.moveItem(at: temporary, to: destination)
            }
            return destination
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }

    /// Offers the saved file to iOS' native document/open-in UI, never an inline chat preview.
    func open(_ fileURL: URL, from viewController: UIViewController, onDismiss: @escaping () -> Void = {}) throws {
        guard fileURL.isFileURL,
              let root = try? downloadsDirectory(),
              fileURL.standardizedFileURL.deletingLastPathComponent() == root.standardizedFileURL,
              FileManager.default.fileExists(atPath: fileURL.path) else { throw StoreError.fileUnavailable }
        let controller = UIDocumentInteractionController(url: fileURL)
        controller.delegate = self
        activeDocumentController = controller
        dismissHandler = onDismiss
        let anchor = CGRect(x: max(0, viewController.view.bounds.midX), y: max(0, viewController.view.bounds.midY), width: 1, height: 1)
        guard controller.presentOptionsMenu(from: anchor, in: viewController.view, animated: true) else {
            activeDocumentController = nil
            dismissHandler = nil
            throw StoreError.noCompatibleApp
        }
    }

    func documentInteractionControllerDidDismissOptionsMenu(_ controller: UIDocumentInteractionController) {
        if activeDocumentController === controller { activeDocumentController = nil; let handler = dismissHandler; dismissHandler = nil; handler?() }
    }

    enum StoreError: LocalizedError {
        case storageUnavailable, invalidTransferIdentifier, invalidSizeLimit, invalidFilename
        case fileTooLarge, fileUnavailable, noCompatibleApp
        var errorDescription: String? {
            switch self {
            case .storageUnavailable: return "Serein download storage is unavailable."
            case .invalidTransferIdentifier: return "Invalid attachment identifier."
            case .invalidSizeLimit: return "Invalid attachment size limit."
            case .invalidFilename: return "Invalid attachment filename."
            case .fileTooLarge: return "Attachment exceeds the allowed size."
            case .fileUnavailable: return "Downloaded attachment is unavailable."
            case .noCompatibleApp: return "No compatible app can open this file."
            }
        }
    }
}
