import SwiftUI
import CoreNFC
import Combine

class NFCReader: NSObject, ObservableObject, NFCTagReaderSessionDelegate {

    @Published var status: String = "Ready"
    private var session: NFCTagReaderSession?

    func startScanning() {
        print("readingAvailable =", NFCTagReaderSession.readingAvailable)
        guard NFCTagReaderSession.readingAvailable else {
            status = "NFC not available on this device."
            return
        }

        status = "Hold card near the top of the iPhone…"

        session = NFCTagReaderSession(
            pollingOption: [.iso14443],
            delegate: self,
            queue: nil
        )
        session?.alertMessage = "Hold your MIFARE card near the iPhone."
        session?.begin()
    }

    // MARK: - NFCTagReaderSessionDelegate

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        DispatchQueue.main.async {
            self.status = "Session active. Waiting for a tag…"
        }
    }

    func tagReaderSession(
        _ session: NFCTagReaderSession,
        didInvalidateWithError error: Error
    ) {
        print("NFC session invalidated: \(error)")
        //DispatchQueue.main.async {
        //    self.status = "Session ended: \(error.localizedDescription)"
        //}
        self.session = nil
    }

    func tagReaderSession(
        _ session: NFCTagReaderSession,
        didDetect tags: [NFCTag]
    ) {
        guard let first = tags.first else { return }

        session.connect(to: first) { error in
            if let error = error {
                print("connect error = \(error)")
                session.invalidate(errorMessage: "Connection error: \(error.localizedDescription)")
                return
            }

            switch first {
            case .miFare(let mifareTag):
                self.handleMiFare(tag: mifareTag, session: session)
            default:
                session.invalidate(errorMessage: "Not a MiFare tag.")
            }
        }
    }

    // MARK: - MIFARE Plus handling
    private func handleMiFare(tag: NFCMiFareTag, session: NFCTagReaderSession) {
        let family = tag.mifareFamily

        DispatchQueue.main.async {
            switch family {
            case .ultralight:
                self.status = "Detected MIFARE Ultralight"
            case .desfire:
                self.status = "Detected MIFARE DESFire"
            case .plus:
                self.status = "Detected MIFARE Plus – authenticating…"
            case .unknown:
                self.status = "Detected MIFARE (Classic/Plus/Unknown)"
            @unknown default:
                self.status = "Detected unknown MiFare family"
            }
        }

        guard family == .plus else {
            session.alertMessage = "Non-Plus tag detected."
            session.invalidate()
            return
        }

        let controller = MifarePlusController(tag: tag)

        // Key = 16 bytes 0xFF, key number 0x4000
        let key       = [UInt8](repeating: 0xFF, count: 16)
        let keyNumber: UInt16 = 0x4000

        Task {
            do {
                // 1) Authenticate
                let auth = try await controller.mfpFirstAuth(
                    key: key,
                    keyNumber: keyNumber
                )

                print("FirstAuth OK")
                print("  TI      = \(self.bytesToHex(auth.ti))")
                print("  W_Ctr   = \(auth.wCtr)")
                print("  R_Ctr   = \(auth.rCtr)")
                print("  KEY_ENC = \(self.bytesToHex(auth.keyEnc))")
                print("  KEY_MAC = \(self.bytesToHex(auth.keyMac))")

                // 2) Read sectors 1..5 (4 blocks per sector, 16 bytes per block)
                let sectorsToRead = [0, 1, 2, 3, 4, 5]
                var lines: [String] = []

                lines.append("Auth OK")
                lines.append("TI: \(self.bytesToHex(auth.ti))")
                lines.append("KEY_ENC: \(self.bytesToHex(auth.keyEnc))")
                lines.append("KEY_MAC: \(self.bytesToHex(auth.keyMac))")
                lines.append("")

                for sector in sectorsToRead {
                    let firstBlock = UInt16(sector * 4)      // sector 1 → block 4, etc.
                    let data = try await controller.mfpRead(
                        blockNumber: firstBlock,
                        blockCount: 4
                    ) // 4 * 16 = 64 bytes

                    print("Sector \(sector) raw (\(data.count) bytes): \(self.bytesToHex(data))")

                    lines.append("Sector \(sector):")
                    for i in 0..<4 {
                        let blockNo = firstBlock + UInt16(i)
                        let start = i * 16
                        let end = start + 16
                        let blockBytes = Array(data[start..<end])
                        let hex = self.bytesToHex(blockBytes)
                        lines.append(String(format: "  Block %2d: %@", blockNo, hex))
                    }
                    lines.append("") // blank line between sectors
                    
                    //try await controller.mfpWrite(blockNumber: firstBlock, blockCount: 1, blockData: Array(data[0..<16]))
                    
                }

                let statusText = lines.joined(separator: "\n")

                await MainActor.run {
                    self.status = statusText
                }

                session.alertMessage = "Sectors 1–5 read successfully."
                //session.invalidate()

            } catch {
                print("Error in auth/read:", error)
                await MainActor.run {
                    self.status = "Error: \(error.localizedDescription)"
                }
                session.invalidate(errorMessage: "Authentication or read failed.")
            }
        }
    }
    private func bytesToHex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: " ")
    }

    // MARK: - Helpers

    private func hexString(_ data: Data) -> String {
        data.map { String(format: "%02X", $0) }.joined(separator: " ")
    }

}

// MARK: - SwiftUI

struct ContentView: View {
    @StateObject private var reader = NFCReader()

    var body: some View {
        VStack(spacing: 20) {
            Text("iOS NFC Demo")
                .font(.title)

            // 👇 Scrollable output
            ScrollView {
                Text(reader.status)
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .frame(maxHeight: 300)
            .border(.gray)

            Button("Scan NFC Tag") {
                reader.startScanning()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }
}

