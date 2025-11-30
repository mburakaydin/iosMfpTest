import Foundation
import CoreNFC
import CommonCrypto

enum MifarePlusError: Error {
    case invalidResponseStatus(UInt8)
    case invalidMac
    case lengthMismatch(expected: Int, actual: Int)
    case cryptoError(String)
    case invalidInput(String)
}

final class MifarePlusController {

    private let tag: NFCMiFareTag

    init(tag: NFCMiFareTag) {
        self.tag = tag
    }

    struct FirstAuthResult {
        var wCtr: UInt16
        var rCtr: UInt16
        var ti: [UInt8]
        var keyEnc: [UInt8]
        var keyMac: [UInt8]
    }
    
    private var session: FirstAuthResult = FirstAuthResult(
        wCtr: 0,
        rCtr: 0,
        ti: [],
        keyEnc: [],
        keyMac: []
    )

    // MARK: - PUBLIC: First Auth

    @discardableResult
    func mfpFirstAuth(
        key: [UInt8],              // 16 bytes
        keyNumber: UInt16
    ) async throws -> FirstAuthResult {

        guard key.count == 16 else {
            throw MifarePlusError.invalidInput("key must be 16 bytes (AES-128)")
        }

        var sendBuf = [UInt8](repeating: 0, count: 256)
        var receiveBuf = [UInt8](repeating: 0, count: 256)

        var randA = [UInt8](repeating: 0, count: 16)
        var randB = [UInt8](repeating: 0, count: 16)

        var wCtr: UInt16 = 0
        var rCtr: UInt16 = 0

        // --- First command: 0x70 (request random B) ---
        var sentBytes = 0
        sendBuf[sentBytes] = 0x70; sentBytes += 1
        sendBuf[sentBytes] = UInt8(truncatingIfNeeded: keyNumber & 0x00FF); sentBytes += 1
        sendBuf[sentBytes] = UInt8(truncatingIfNeeded: (keyNumber >> 8) & 0x00FF); sentBytes += 1
        sendBuf[sentBytes] = 0x06; sentBytes += 1
        for _ in 0..<6 {
            sendBuf[sentBytes] = 0x00; sentBytes += 1
        }

        wCtr = 0
        rCtr = 0

        let cmd1 = Array(sendBuf[0..<sentBytes])
        print("mfpFirstAuth: CMD1 sentBytes =", sentBytes,
              "hex =", hex(cmd1))

        let resp1 = try await transceive(cmd1)
        receiveBuf.replaceSubrange(0..<resp1.count, with: resp1)
        let receivedBytes1 = resp1.count

        guard receivedBytes1 >= 1 else {
            throw MifarePlusError.invalidResponseStatus(0x00)
        }
        if receiveBuf[0] != 0x90 {
            throw MifarePlusError.invalidResponseStatus(receiveBuf[0])
        }

        guard receivedBytes1 >= 1 + 16 else {
            throw MifarePlusError.lengthMismatch(expected: 17, actual: receivedBytes1)
        }
        let encRandB = Array(receiveBuf[1..<(1 + 16)])

        // local auth1
        let auth1Out = try mfpFirstAuth1(
            key: key,
            randA: &randA,
            randB: &randB,
            encRandB: encRandB
        )

        // --- Second command: 0x72 + 32 bytes from auth1Out ---
        sentBytes = 0
        sendBuf[sentBytes] = 0x72; sentBytes += 1
        for b in auth1Out {
            sendBuf[sentBytes] = b; sentBytes += 1
        }

        let cmd2 = Array(sendBuf[0..<sentBytes])
        print("mfpFirstAuth: CMD2 sentBytes =", sentBytes,
              "hex =", hex(cmd2))

        let resp2 = try await transceive(cmd2)
        receiveBuf.replaceSubrange(0..<resp2.count, with: resp2)
        let receivedBytes2 = resp2.count

        guard receivedBytes2 >= 1 else {
            throw MifarePlusError.invalidResponseStatus(0x00)
        }
        if receiveBuf[0] != 0x90 {
            throw MifarePlusError.invalidResponseStatus(receiveBuf[0])
        }

        guard receivedBytes2 >= 1 + 32 else {
            throw MifarePlusError.lengthMismatch(expected: 33, actual: receivedBytes2)
        }
        let auth2In = Array(receiveBuf[1..<(1 + 32)])
        let auth2Out = try mfpFirstAuth2(
            key: key,
            randA: randA,
            randB: randB,
            input: auth2In
        )

        guard auth2Out.count == 36 else {
            throw MifarePlusError.lengthMismatch(expected: 36, actual: auth2Out.count)
        }

        let ti = Array(auth2Out[0..<4])
        let keyEnc = Array(auth2Out[4..<20])
        let keyMac = Array(auth2Out[20..<36])

        wCtr = 0
        rCtr = 0

        let res = FirstAuthResult(
            wCtr: wCtr,
            rCtr: rCtr,
            ti: ti,
            keyEnc: keyEnc,
            keyMac: keyMac
        )
        
        session = res
        
        return res
    }

    // MARK: - Low-level transceive (uses NFCMiFareTag directly)

    private func transceive(_ command: [UInt8]) async throws -> [UInt8] {
        print(">> CMD (\(command.count) bytes): \(hex(command))")

        if command.isEmpty {
            throw MifarePlusError.invalidInput("Empty command to tag")
        }

        let data = Data(command)

        return try await withCheckedThrowingContinuation { continuation in
            tag.sendMiFareCommand(commandPacket: data) { response, error in
                if let error = error {
                    print("<< ERR: \(error)")
                    continuation.resume(throwing: error)
                    return
                }
                let respBytes = [UInt8](response)
                print("<< RSP (\(respBytes.count) bytes): \(self.hex(respBytes))")
                continuation.resume(returning: respBytes)
            }
        }
    }

    // MARK: - Private C-static ports (firstAuth1/2) – SENİNKİYLE AYNI

    private func mfpFirstAuth1(
        key: [UInt8],
        randA: inout [UInt8],      // out
        randB: inout [UInt8],      // out
        encRandB: [UInt8]          // in (16 bytes from card)
    ) throws -> [UInt8] {          // out: 32 bytes to send

        guard key.count == 16 else {
            throw MifarePlusError.invalidInput("key must be 16 bytes")
        }
        guard encRandB.count == 16 else {
            throw MifarePlusError.invalidInput("encRandB must be 16 bytes")
        }

        // generate 16 byte random A (like rand()%0xFF)
        for i in 0..<16 {
            randA[i] = UInt8.random(in: 0...255)
        }

        let ivZero = [UInt8](repeating: 0, count: 16)

        // AES_cbc_128(key, ivec, enc_randB, randB, 16, AES_DECRYPT)
        let decrypted = try aesCBCDecrypt(
            key: key,
            iv: ivZero,
            input: encRandB
        )
        randB = decrypted

        // temp_randB = randB, shift left by 1 byte
        var tempRandB = randB
        let extra = tempRandB[0]
        for i in 0..<15 {
            tempRandB[i] = tempRandB[i + 1]
        }
        tempRandB[15] = extra

        // data = randA || tempRandB
        var data = [UInt8](repeating: 0, count: 32)
        for i in 0..<16 { data[i] = randA[i] }
        for i in 0..<16 { data[16 + i] = tempRandB[i] }

        let encrypted = try aesCBCEncrypt(
            key: key,
            iv: ivZero,
            input: data
        )

        return encrypted   // 32 bytes
    }

    private func mfpFirstAuth2(
        key: [UInt8],
        randA: [UInt8],
        randB: [UInt8],
        input: [UInt8]     // 32 bytes from card, encrypted
    ) throws -> [UInt8] {  // 36 bytes: TI(4) + ENC(16) + MAC(16)

        guard key.count == 16 else {
            throw MifarePlusError.invalidInput("key must be 16 bytes")
        }
        guard randA.count == 16 && randB.count == 16 else {
            throw MifarePlusError.invalidInput("randA/randB must be 16 bytes each")
        }
        guard input.count == 32 else {
            throw MifarePlusError.invalidInput("input must be 32 bytes")
        }

        let ivZero = [UInt8](repeating: 0, count: 16)
        var data = try aesCBCDecrypt(
            key: key,
            iv: ivZero,
            input: input
        ) // 32 bytes

        // extra = data[19]; shift data[4..19] right by 1
        let extra = data[19]
        var i = 19
        while i > 4 {
            data[i] = data[i - 1]
            i -= 1
        }
        data[4] = extra

        // check randA'
        let randAprime = Array(data[4..<20])
        if randAprime != randA {
            throw MifarePlusError.invalidInput("randA mismatch in firstAuth2")
        }

        // TI = data[0..3]
        var result = [UInt8](repeating: 0, count: 36)
        for j in 0..<4 {
            result[j] = data[j]
        }

        // KEY_ENC
        var keyEnc = [UInt8](repeating: 0, count: 16)
        // memcpy(&keyEnc[0], &randA[11], 5);
        for j in 0..<5 {
            keyEnc[j] = randA[11 + j]
        }
        // memcpy(&keyEnc[5], &randB[11], 5);
        for j in 0..<5 {
            keyEnc[5 + j] = randB[11 + j]
        }
        // XOR part
        for j in 0..<5 {
            keyEnc[10 + j] = randA[4 + j] ^ randB[4 + j]
        }
        keyEnc[15] = 0x11

        let encKeyEnc = try aesCBCEncrypt(
            key: key,
            iv: ivZero,
            input: keyEnc
        ) // 16 bytes

        for j in 0..<16 {
            result[4 + j] = encKeyEnc[j]
        }

        // KEY_MAC
        var keyMac = [UInt8](repeating: 0, count: 16)
        // memcpy(&keyMac[0], &randA[7], 5);
        for j in 0..<5 {
            keyMac[j] = randA[7 + j]
        }
        // memcpy(&keyMac[5], &randB[7], 5);
        for j in 0..<5 {
            keyMac[5 + j] = randB[7 + j]
        }
        for j in 0..<5 {
            keyMac[10 + j] = randA[j] ^ randB[j]
        }
        keyMac[15] = 0x22

        let encKeyMac = try aesCBCEncrypt(
            key: key,
            iv: ivZero,
            input: keyMac
        )

        for j in 0..<16 {
            result[20 + j] = encKeyMac[j]
        }

        return result
    }


    
    // MARK: - AES helpers + CMAC
    // Buraya da aynen mevcut aesCBCEncrypt / aesCBCDecrypt / aesECBEncryptBlock / aesCMAC fonksiyonlarını koyuyorsun.
    // Hiçbirini değiştirmeye gerek yok.

    private func aesCBCEncrypt(
        key: [UInt8],
        iv: [UInt8],
        input: [UInt8]
    ) throws -> [UInt8] {

        var outLen: size_t = 0
        // Use an allocated raw buffer to avoid overlapping access
        let outCapacity = input.count + kCCBlockSizeAES128
        let outRaw = UnsafeMutableRawBufferPointer.allocate(byteCount: outCapacity, alignment: MemoryLayout<UInt8>.alignment)
        defer { outRaw.deallocate() }

        let status: CCCryptorStatus = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                input.withUnsafeBytes { inBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(0), // no padding
                        keyBytes.baseAddress, key.count,
                        ivBytes.baseAddress,
                        inBytes.baseAddress, input.count,
                        outRaw.baseAddress, outCapacity,
                        &outLen
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw MifarePlusError.cryptoError("CCCrypt encrypt failed: \(status)")
        }

        let outBytes = UnsafeRawBufferPointer(start: outRaw.baseAddress, count: Int(outLen))
        return Array(outBytes)
    }

    private func aesCBCDecrypt(
        key: [UInt8],
        iv: [UInt8],
        input: [UInt8]
    ) throws -> [UInt8] {

        var outLen: size_t = 0
        let outCapacity = input.count + kCCBlockSizeAES128
        let outRaw = UnsafeMutableRawBufferPointer.allocate(byteCount: outCapacity, alignment: MemoryLayout<UInt8>.alignment)
        defer { outRaw.deallocate() }

        let status: CCCryptorStatus = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                input.withUnsafeBytes { inBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(0), // no padding
                        keyBytes.baseAddress, key.count,
                        ivBytes.baseAddress,
                        inBytes.baseAddress, input.count,
                        outRaw.baseAddress, outCapacity,
                        &outLen
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw MifarePlusError.cryptoError("CCCrypt decrypt failed: \(status)")
        }

        let outBytes = UnsafeRawBufferPointer(start: outRaw.baseAddress, count: Int(outLen))
        return Array(outBytes)
    }

    // AES-ECB used for CMAC
    private func aesECBEncryptBlock(
        key: [UInt8],
        block: [UInt8]
    ) throws -> [UInt8] {

        precondition(block.count == kCCBlockSizeAES128)

        var outLen: size_t = 0
        let outCapacity = kCCBlockSizeAES128
        let outRaw = UnsafeMutableRawBufferPointer.allocate(byteCount: outCapacity, alignment: MemoryLayout<UInt8>.alignment)
        defer { outRaw.deallocate() }

        let status: CCCryptorStatus = key.withUnsafeBytes { keyBytes in
            block.withUnsafeBytes { inBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES128),
                    CCOptions(kCCOptionECBMode), // ECB, no padding
                    keyBytes.baseAddress, key.count,
                    nil,
                    inBytes.baseAddress, block.count,
                    outRaw.baseAddress, outCapacity,
                    &outLen
                )
            }
        }

        guard status == kCCSuccess else {
            throw MifarePlusError.cryptoError("CCCrypt ECB encrypt failed: \(status)")
        }

        let outBytes = UnsafeRawBufferPointer(start: outRaw.baseAddress, count: Int(outLen))
        return Array(outBytes)
    }
    // AES-CMAC per RFC 4493
    private func aesCMAC(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        let blockSize = 16
        let Rb: UInt8 = 0x87

        func leftShiftOne(_ block: [UInt8]) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: block.count)
            var carry: UInt8 = 0
            for i in (0..<block.count).reversed() {
                let v = block[i]
                out[i] = (v << 1) | carry
                carry = (v & 0x80) >> 7
            }
            return out
        }

        // Generate subkeys
        let zeroBlock = [UInt8](repeating: 0, count: blockSize)
        let L = try aesECBEncryptBlock(key: key, block: zeroBlock)

        var K1 = leftShiftOne(L)
        if (L[0] & 0x80) != 0 {
            K1[blockSize - 1] ^= Rb
        }

        var K2 = leftShiftOne(K1)
        if (K1[0] & 0x80) != 0 {
            K2[blockSize - 1] ^= Rb
        }

        if message.isEmpty {
            // special case: 1 block of padding only
            var mLast = [UInt8](repeating: 0, count: blockSize)
            mLast[0] = 0x80
            for i in 0..<blockSize {
                mLast[i] ^= K2[i]
            }
            let X = [UInt8](repeating: 0, count: blockSize)
            let Y = zip(X, mLast).map { $0 ^ $1 }
            return try aesECBEncryptBlock(key: key, block: Y)
        }

        let n = Int(ceil(Double(message.count) / Double(blockSize)))
        let lastComplete = (message.count % blockSize) == 0

        let lastBlockStart = (n - 1) * blockSize
        var mLast = [UInt8](repeating: 0, count: blockSize)

        if lastComplete {
            // M_last = last 16 bytes
            for i in 0..<blockSize {
                mLast[i] = message[lastBlockStart + i]
            }
            for i in 0..<blockSize {
                mLast[i] ^= K1[i]
            }
        } else {
            // M_last = pad(last partial) then XOR K2
            let lastLen = message.count - lastBlockStart
            for i in 0..<lastLen {
                mLast[i] = message[lastBlockStart + i]
            }
            mLast[lastLen] = 0x80
            for i in 0..<blockSize {
                mLast[i] ^= K2[i]
            }
        }

        var X = [UInt8](repeating: 0, count: blockSize)

        // process all but last block
        if n > 1 {
            for i in 0..<(n - 1) {
                var block = [UInt8](repeating: 0, count: blockSize)
                let start = i * blockSize
                for j in 0..<blockSize {
                    block[j] = message[start + j]
                }
                let tmp = zip(X, block).map { $0 ^ $1 }
                X = try aesECBEncryptBlock(key: key, block: tmp)
            }
        }

        let Y = zip(X, mLast).map { $0 ^ $1 }
        let T = try aesECBEncryptBlock(key: key, block: Y)
        return T
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: " ")
    }
    
    // int mfpRead(...)
    func mfpRead(
        blockNumber: UInt16,
        blockCount: UInt8      // number of 16-byte blocks
    ) async throws -> [UInt8] {
        
            
        guard session.ti.count == 4 else {
            throw MifarePlusError.invalidInput("TI must be 4 bytes")
        }
        guard session.keyMac.count == 16 else {
            throw MifarePlusError.invalidInput("keyMac must be 16 bytes")
        }

        var macSendBuf = [UInt8](repeating: 0, count: 4096)
        var macReceiveBuf = [UInt8](repeating: 0, count: 16)

        var sendBuf = [UInt8](repeating: 0, count: 128)
        var receiveBuf = [UInt8](repeating: 0, count: 4096)

        var sentBytes = 0

        // Command header
        sendBuf[sentBytes] = 0x33; sentBytes += 1
        sendBuf[sentBytes] = UInt8(truncatingIfNeeded: blockNumber & 0x00FF); sentBytes += 1
        sendBuf[sentBytes] = UInt8(truncatingIfNeeded: (blockNumber >> 8) & 0x00FF); sentBytes += 1
        sendBuf[sentBytes] = blockCount; sentBytes += 1

        // --- Calculate CMAC (request) ---
        macSendBuf[0] = 0x33
        macSendBuf[1] = UInt8(truncatingIfNeeded: session.rCtr & 0x00FF)
        macSendBuf[2] = UInt8(truncatingIfNeeded: (session.rCtr >> 8) & 0x00FF)
        macSendBuf[3] = session.ti[0]
        macSendBuf[4] = session.ti[1]
        macSendBuf[5] = session.ti[2]
        macSendBuf[6] = session.ti[3]
        macSendBuf[7] = UInt8(truncatingIfNeeded: blockNumber & 0x00FF)
        macSendBuf[8] = UInt8(truncatingIfNeeded: (blockNumber >> 8) & 0x00FF)
        macSendBuf[9] = blockCount

        macReceiveBuf = try aesCMAC(key: session.keyMac, message: Array(macSendBuf[0..<10]))

        // append 8 odd CMAC bytes to sendBuf
        for i in 0..<16 {
            if (i % 2) == 1 {
                sendBuf[sentBytes] = macReceiveBuf[i]
                sentBytes += 1
            }
        }

        //let cmd = Data(sendBuf[0..<sentBytes])
        let cmd = Array(sendBuf[0..<sentBytes])
        let resp = try await transceive(cmd)
        receiveBuf.replaceSubrange(0..<resp.count, with: resp)
        let receivedBytes = resp.count

        session.rCtr &+= 1

        guard receivedBytes >= 1 else {
            throw MifarePlusError.invalidResponseStatus(0x00)
        }

        if receiveBuf[0] != 0x90 {
            throw MifarePlusError.invalidResponseStatus(receiveBuf[0])
        }

        let dataLen = receivedBytes - 9   // remove SC + 8-byte MAC

        let expectedLen = Int(blockCount) * 16
        if dataLen != expectedLen {
            throw MifarePlusError.lengthMismatch(expected: expectedLen, actual: dataLen)
        }

        // --- Check MAC on response ---
        macSendBuf[0] = receiveBuf[0]
        macSendBuf[1] = UInt8(truncatingIfNeeded: session.rCtr & 0x00FF)
        macSendBuf[2] = UInt8(truncatingIfNeeded: (session.rCtr >> 8) & 0x00FF)
        // Important: we DO NOT overwrite bytes 3..9, matching your C code.
        // They still contain TI + block info from request.
        // Then we copy the data (ciphertext) to offset 10.
        let dataStart = 1
        let dataEnd = 1 + dataLen
        let respDataSlice = Array(receiveBuf[dataStart..<dataEnd])
        for (idx, b) in respDataSlice.enumerated() {
            macSendBuf[10 + idx] = b
        }

        let macMsgLen = 10 + dataLen
        macReceiveBuf = try aesCMAC(
            key: session.keyMac,
            message: Array(macSendBuf[0..<macMsgLen])
        )

        var macStart = receivedBytes - 8
        for i in 0..<16 {
            if (i % 2) == 1 {
                if receiveBuf[macStart] != macReceiveBuf[i] {
                    throw MifarePlusError.invalidMac
                }
                macStart += 1
            }
        }
        // --- MAC ok ---

        let plainBlocks = Array(receiveBuf[1..<(1 + dataLen)])
        return plainBlocks
    }
    
    // int mfpWrite(...)
    func mfpWrite(
        blockNumber: UInt16,
        blockCount: Int,      // max 3
        blockData: [UInt8]    // 16 * blockCount
    ) async throws {

        guard session.ti.count == 4 else {
            throw MifarePlusError.invalidInput("TI must be 4 bytes")
        }
        guard session.keyMac.count == 16 else {
            throw MifarePlusError.invalidInput("keyMac must be 16 bytes")
        }
        guard blockCount > 0 && blockCount <= 3 else {
            throw MifarePlusError.invalidInput("blockCount must be 1..3")
        }
        guard blockData.count == blockCount * 16 else {
            throw MifarePlusError.invalidInput("blockData length mismatch")
        }

        var macSendBuf = [UInt8](repeating: 0, count: 4096)
        var macReceiveBuf = [UInt8](repeating: 0, count: 16)

        var sendBuf = [UInt8](repeating: 0, count: 4096)
        var receiveBuf = [UInt8](repeating: 0, count: 256)

        var sentBytes = 0

        sendBuf[sentBytes] = 0xA3; sentBytes += 1
        sendBuf[sentBytes] = UInt8(truncatingIfNeeded: blockNumber & 0x00FF); sentBytes += 1
        sendBuf[sentBytes] = UInt8(truncatingIfNeeded: (blockNumber >> 8) & 0x00FF); sentBytes += 1

        // copy block data
        for b in blockData {
            sendBuf[sentBytes] = b
            sentBytes += 1
        }

        // --- Calculate CMAC (request) ---
        var macLen = 0
        for i in 0..<128 { macSendBuf[i] = 0x00 }  // memset(..., 0x00, 128)

        macSendBuf[macLen] = 0xA3; macLen += 1
        macSendBuf[macLen] = UInt8(truncatingIfNeeded: session.wCtr & 0x00FF); macLen += 1
        macSendBuf[macLen] = UInt8(truncatingIfNeeded: (session.wCtr >> 8) & 0x00FF); macLen += 1
        macSendBuf[macLen] = session.ti[0]; macLen += 1
        macSendBuf[macLen] = session.ti[1]; macLen += 1
        macSendBuf[macLen] = session.ti[2]; macLen += 1
        macSendBuf[macLen] = session.ti[3]; macLen += 1
        macSendBuf[macLen] = UInt8(truncatingIfNeeded: blockNumber & 0x00FF); macLen += 1
        macSendBuf[macLen] = UInt8(truncatingIfNeeded: (blockNumber >> 8) & 0x00FF); macLen += 1

        for b in blockData {
            macSendBuf[macLen] = b
            macLen += 1
        }

        macReceiveBuf = try aesCMAC(
            key: session.keyMac,
            message: Array(macSendBuf[0..<macLen])
        )

        // append odd CMAC bytes
        for i in 0..<16 {
            if (i % 2) == 1 {
                sendBuf[sentBytes] = macReceiveBuf[i]
                sentBytes += 1
            }
        }

        let cmd = Array(sendBuf[0..<sentBytes])
        let resp = try await transceive(cmd)
        receiveBuf.replaceSubrange(0..<resp.count, with: resp)
        let receivedBytes = resp.count

        session.wCtr &+= 1

        guard receivedBytes >= 1 else {
            throw MifarePlusError.invalidResponseStatus(0x00)
        }
        if receiveBuf[0] != 0x90 {
            throw MifarePlusError.invalidResponseStatus(receiveBuf[0])
        }

        // --- Check MAC on response ---
        macSendBuf[0] = receiveBuf[0]
        macSendBuf[1] = UInt8(truncatingIfNeeded: session.wCtr & 0x00FF)
        macSendBuf[2] = UInt8(truncatingIfNeeded: (session.wCtr >> 8) & 0x00FF)
        macSendBuf[3] = session.ti[0]
        macSendBuf[4] = session.ti[1]
        macSendBuf[5] = session.ti[2]
        macSendBuf[6] = session.ti[3]

        macReceiveBuf = try aesCMAC(
            key: session.keyMac,
            message: Array(macSendBuf[0..<7])
        )

        var macStart = receivedBytes - 8
        for i in 0..<16 {
            if (i % 2) == 1 {
                if receiveBuf[macStart] != macReceiveBuf[i] {
                    throw MifarePlusError.invalidMac
                }
                macStart += 1
            }
        }
    }
    func mfpWriteSecure(
        blockNumber: UInt16,
        blockData: [UInt8],     // "key" param in C: 16 bytes of clear data to encrypt
    ) async throws {

        guard blockData.count == 16 else {
            throw MifarePlusError.invalidInput("dataKey must be 16 bytes")
        }
        guard session.ti.count == 4 else {
            throw MifarePlusError.invalidInput("TI must be 4 bytes")
        }
        guard session.keyEnc.count == 16 else {
            throw MifarePlusError.invalidInput("keyEnc must be 16 bytes")
        }
        guard session.keyMac.count == 16 else {
            throw MifarePlusError.invalidInput("keyMac must be 16 bytes")
        }

        var macSendBuf = [UInt8](repeating: 0, count: 4096)
        var macReceiveBuf = [UInt8](repeating: 0, count: 16)

        var sendBuf = [UInt8](repeating: 0, count: 4096)
        var receiveBuf = [UInt8](repeating: 0, count: 256)

        var ivec = [UInt8](repeating: 0, count: 16)
        var ivecLen = 0

        // --- Build IV (9.6.1.2), 16 bytes ---
        ivec[ivecLen] = session.ti[0]; ivecLen += 1
        ivec[ivecLen] = session.ti[1]; ivecLen += 1
        ivec[ivecLen] = session.ti[2]; ivecLen += 1
        ivec[ivecLen] = session.ti[3]; ivecLen += 1

        for _ in 0..<3 {
            ivec[ivecLen] = UInt8(truncatingIfNeeded: session.rCtr & 0x00FF); ivecLen += 1
            ivec[ivecLen] = UInt8(truncatingIfNeeded: (session.rCtr >> 8) & 0x00FF); ivecLen += 1
            ivec[ivecLen] = UInt8(truncatingIfNeeded: session.wCtr & 0x00FF); ivecLen += 1
            ivec[ivecLen] = UInt8(truncatingIfNeeded: (session.wCtr >> 8) & 0x00FF); ivecLen += 1
        }

        // Encrypt 16 bytes of dataKey using keyEnc and ivec (CBC)
        let encryptedData = try aesCBCEncrypt(
            key: session.keyEnc,
            iv: ivec,
            input: blockData
        )

        // --- Build command ---
        var sentBytes = 0
        sendBuf[sentBytes] = 0xA1; sentBytes += 1
        sendBuf[sentBytes] = UInt8(truncatingIfNeeded: blockNumber & 0x00FF); sentBytes += 1
        sendBuf[sentBytes] = UInt8(truncatingIfNeeded: (blockNumber >> 8) & 0x00FF); sentBytes += 1

        for b in encryptedData {
            sendBuf[sentBytes] = b
            sentBytes += 1
        }

        // --- CMAC (request) ---
        var macLen = 0
        for i in 0..<128 { macSendBuf[i] = 0 }

        macSendBuf[macLen] = 0xA1; macLen += 1
        macSendBuf[macLen] = UInt8(truncatingIfNeeded: session.wCtr & 0x00FF); macLen += 1
        macSendBuf[macLen] = UInt8(truncatingIfNeeded: (session.wCtr >> 8) & 0x00FF); macLen += 1
        macSendBuf[macLen] = session.ti[0]; macLen += 1
        macSendBuf[macLen] = session.ti[1]; macLen += 1
        macSendBuf[macLen] = session.ti[2]; macLen += 1
        macSendBuf[macLen] = session.ti[3]; macLen += 1
        macSendBuf[macLen] = UInt8(truncatingIfNeeded: blockNumber & 0x00FF); macLen += 1
        macSendBuf[macLen] = UInt8(truncatingIfNeeded: (blockNumber >> 8) & 0x00FF); macLen += 1

        for b in encryptedData {
            macSendBuf[macLen] = b
            macLen += 1
        }

        macReceiveBuf = try aesCMAC(
            key: session.keyMac,
            message: Array(macSendBuf[0..<macLen])
        )

        for i in 0..<16 {
            if (i % 2) == 1 {
                sendBuf[sentBytes] = macReceiveBuf[i]
                sentBytes += 1
            }
        }

        let cmd = Array(sendBuf[0..<sentBytes])
        let resp = try await transceive(cmd)
        receiveBuf.replaceSubrange(0..<resp.count, with: resp)
        let receivedBytes = resp.count

        session.wCtr &+= 1

        guard receivedBytes >= 1 else {
            throw MifarePlusError.invalidResponseStatus(0x00)
        }
        if receiveBuf[0] != 0x90 {
            throw MifarePlusError.invalidResponseStatus(receiveBuf[0])
        }

        // --- Check MAC on response ---
        macSendBuf[0] = receiveBuf[0]
        macSendBuf[1] = UInt8(truncatingIfNeeded: session.wCtr & 0x00FF)
        macSendBuf[2] = UInt8(truncatingIfNeeded: (session.wCtr >> 8) & 0x00FF)
        macSendBuf[3] = session.ti[0]
        macSendBuf[4] = session.ti[1]
        macSendBuf[5] = session.ti[2]
        macSendBuf[6] = session.ti[3]

        macReceiveBuf = try aesCMAC(
            key: session.keyMac,
            message: Array(macSendBuf[0..<7])
        )

        var macStart = receivedBytes - 8
        for i in 0..<16 {
            if (i % 2) == 1 {
                if receiveBuf[macStart] != macReceiveBuf[i] {
                    throw MifarePlusError.invalidMac
                }
                macStart += 1
            }
        }
    }
}
