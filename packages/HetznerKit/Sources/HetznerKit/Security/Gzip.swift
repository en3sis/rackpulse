import Compression
import Foundation

enum Gzip {
    enum Failure: Error, Equatable {
        case header
        case truncated
        case corrupt
        case checksum
        case size
        case tooLarge
    }

    static let chunkSize = 1 << 16

    @discardableResult
    static func decompress(_ data: Data, limit: Int, chunk: (UnsafeBufferPointer<UInt8>) throws -> Void) throws -> Int {
        let bytes = [UInt8](data)
        let start = try bodyOffset(bytes)
        var crc = CRC32()
        var total = 0
        let trailer = bytes.count - 8
        try bytes.withUnsafeBufferPointer { input in
            var stream = compression_stream(dst_ptr: UnsafeMutablePointer<UInt8>(bitPattern: 1)!, dst_size: 0, src_ptr: UnsafePointer<UInt8>(bitPattern: 1)!, src_size: 0, state: nil)
            guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else { throw Failure.corrupt }
            defer { compression_stream_destroy(&stream) }
            let output = UnsafeMutablePointer<UInt8>.allocate(capacity: chunkSize)
            defer { output.deallocate() }
            guard let base = input.baseAddress else { throw Failure.truncated }
            stream.src_ptr = base + start
            stream.src_size = trailer - start
            while true {
                stream.dst_ptr = output
                stream.dst_size = chunkSize
                let before = stream.src_size
                let status = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                let produced = chunkSize - stream.dst_size
                if produced > 0 {
                    total += produced
                    guard total <= limit else { throw Failure.tooLarge }
                    let buffer = UnsafeBufferPointer(start: output, count: produced)
                    crc.update(buffer)
                    try chunk(buffer)
                }
                switch status {
                case COMPRESSION_STATUS_END:
                    return
                case COMPRESSION_STATUS_OK:
                    if produced == 0 && stream.src_size == before { throw Failure.truncated }
                default:
                    throw Failure.corrupt
                }
            }
        }
        guard littleEndian32(bytes, at: trailer) == crc.value else { throw Failure.checksum }
        guard littleEndian32(bytes, at: trailer + 4) == UInt32(truncatingIfNeeded: total) else { throw Failure.size }
        return total
    }

    static func bodyOffset(_ bytes: [UInt8]) throws -> Int {
        guard bytes.count >= 18, bytes[0] == 0x1f, bytes[1] == 0x8b else { throw Failure.header }
        guard bytes[2] == 8 else { throw Failure.header }
        let flags = bytes[3]
        guard flags & 0xE0 == 0 else { throw Failure.header }
        var offset = 10
        if flags & 0x04 != 0 {
            guard offset + 2 <= bytes.count else { throw Failure.truncated }
            offset += 2 + Int(bytes[offset]) + Int(bytes[offset + 1]) << 8
        }
        if flags & 0x08 != 0 { offset = try skipString(bytes, from: offset) }
        if flags & 0x10 != 0 { offset = try skipString(bytes, from: offset) }
        if flags & 0x02 != 0 {
            guard offset + 2 <= bytes.count else { throw Failure.truncated }
            var crc = CRC32()
            bytes.withUnsafeBufferPointer { crc.update(UnsafeBufferPointer(rebasing: $0[..<offset])) }
            guard UInt16(truncatingIfNeeded: crc.value) == UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8 else { throw Failure.header }
            offset += 2
        }
        guard offset + 8 < bytes.count else { throw Failure.truncated }
        return offset
    }

    private static func skipString(_ bytes: [UInt8], from offset: Int) throws -> Int {
        guard offset < bytes.count, let end = bytes[offset...].firstIndex(of: 0) else { throw Failure.truncated }
        return end + 1
    }

    static func littleEndian32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8 | UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
    }
}

struct CRC32 {
    static let table: [UInt32] = (0..<256).map { index in
        var value = UInt32(index)
        for _ in 0..<8 { value = value & 1 == 1 ? 0xEDB8_8320 ^ (value >> 1) : value >> 1 }
        return value
    }

    private var state: UInt32 = 0xFFFF_FFFF

    var value: UInt32 { state ^ 0xFFFF_FFFF }

    mutating func update(_ buffer: UnsafeBufferPointer<UInt8>) {
        var crc = state
        Self.table.withUnsafeBufferPointer { table in
            for byte in buffer { crc = table[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8) }
        }
        state = crc
    }

    static func checksum(_ data: Data) -> UInt32 {
        var crc = CRC32()
        data.withUnsafeBytes { crc.update($0.bindMemory(to: UInt8.self)) }
        return crc.value
    }
}
