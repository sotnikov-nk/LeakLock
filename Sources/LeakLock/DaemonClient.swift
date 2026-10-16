import Foundation
import LeakLockCore

enum DaemonClientError: LocalizedError {
    case unreachable
    case io(String)

    var errorDescription: String? {
        switch self {
        case .unreachable: return "Служба LeakLock не отвечает."
        case .io(let detail): return "Ошибка связи со службой: \(detail)"
        }
    }
}

/// Blocking request/response over the daemon's Unix socket. Call off the main thread.
enum DaemonClient {
    static func send(_ request: IPCRequest) throws -> IPCResponse {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw DaemonClientError.io("socket") }
        defer { close(fd) }

        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(Paths.socketPath.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, size) }
        }
        guard connected == 0 else { throw DaemonClientError.unreachable }

        var payload = try IPCCoding.encoder().encode(request)
        payload.append(0x0A)
        let written = payload.withUnsafeBytes { raw -> Bool in
            var offset = 0
            while offset < raw.count {
                let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                if n <= 0 { return false }
                offset += n
            }
            return true
        }
        guard written else { throw DaemonClientError.io("write") }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if n < 0 { throw DaemonClientError.io("read") }
            if n == 0 { break }
            data.append(contentsOf: buffer[0..<n])
            if data.last == 0x0A { break }
        }
        guard !data.isEmpty else { throw DaemonClientError.io("empty response") }
        return try IPCCoding.decoder().decode(IPCResponse.self, from: data)
    }
}
