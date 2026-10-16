import Foundation
import LeakLockCore

// leaklockd: root LaunchDaemon. Watches the route to the internet, verifies the VPN's
// external IP and keeps the pf anchor in the matching mode. Rules stay loaded if this
// process dies, so a crash fails closed.

signal(SIGPIPE, SIG_IGN)

guard getuid() == 0 else {
    log("leaklockd must run as root")
    exit(1)
}

log("leaklockd \(LeakLockVersion.current) starting")
let engine = Engine(config: ConfigStore.load())
engine.start()

let server = SocketServer(path: Paths.socketPath) { request, isAdmin in
    engine.handle(request, peerIsAdmin: isAdmin)
}
do {
    try server.start()
} catch {
    // Keep enforcing even without a control channel.
    log("IPC socket failed: \(error)")
}

dispatchMain()
