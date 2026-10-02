// Compile this fixture after the production PathSignature/interfaceAddresses definitions.
// It exercises real Network.framework snapshots, including an active host VPN route.
import Foundation
import Network
import Darwin

private final class SnapshotBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Network.NWPath?
    func store(_ path: Network.NWPath) { lock.lock(); value = path; lock.unlock() }
    func load() -> Network.NWPath? { lock.lock(); defer { lock.unlock() }; return value }
}

private func snapshot(_ monitor: NWPathMonitor) -> Network.NWPath {
    let box = SnapshotBox()
    let received = DispatchSemaphore(value: 0)
    monitor.pathUpdateHandler = { path in box.store(path); received.signal() }
    monitor.start(queue: DispatchQueue(label: "PathSignatureRegression"))
    precondition(received.wait(timeout: .now() + 5) == .success, "No network path arrived within five seconds")
    monitor.cancel()
    return box.load()!
}

print("Reading the physical interface through the current VPN route...")
let firstPath = snapshot(NWPathMonitor())
guard let first = PathSignature(firstPath) else {
    fatalError("The current satisfied VPN path did not produce a physical interface signature")
}
print("Physical interface selected; checking an unchanged snapshot...")
let secondPath = snapshot(NWPathMonitor())
guard let second = PathSignature(secondPath) else { fatalError("Second path lost its physical signature") }
precondition(first == second, "Unchanged physical snapshots would repeatedly rebind WireGuard")
precondition(!first.interface.hasPrefix("utun"), "The signature selected a tunnel interface")
let prohibited = snapshot(NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback]))
let vpnPresent = firstPath.availableInterfaces.contains { $0.name.hasPrefix("utun") }
print("PASS: valid_physical_path=\(firstPath.status == .satisfied) vpn_present=\(vpnPresent) unchanged_signatures_equal=\(first == second) prohibited_status=\(prohibited.status)")
