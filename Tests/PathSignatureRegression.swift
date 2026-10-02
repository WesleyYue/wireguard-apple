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
let gatewayA = Network.NWEndpoint.hostPort(host: "192.0.2.1", port: .any)
let gatewayC = Network.NWEndpoint.hostPort(host: "192.0.2.2", port: .any)
private let knownA = PathSignature(interface: "en0", gateways: [gatewayA], addresses: ["192.0.2.10"])
private let unknown = PathSignature(interface: "en0", gateways: nil, addresses: knownA.addresses)
private let knownC = PathSignature(interface: "en0", gateways: [gatewayC], addresses: knownA.addresses)
private func rebindCount(_ observations: [PathSignature], startingWith baseline: PathSignature) -> Int {
    var bound = baseline
    var count = 0
    for observation in observations {
        if observation.hasMeaningfulDifference(from: bound) { count += 1; bound = observation }
        else { bound = observation.mergingMetadata(from: bound) }
    }
    return count
}
precondition(rebindCount([unknown, knownA], startingWith: knownA) == 0, "Hidden gateway metadata caused a rebind")
precondition(rebindCount([unknown, knownC], startingWith: knownA) == 1, "Changed gateway did not cause exactly one rebind")
precondition(rebindCount([knownA], startingWith: unknown) == 0, "Learning gateway metadata caused a rebind")
precondition(knownA != unknown && unknown != knownC && knownA != knownC, "Structural equality treated unknown as a wildcard")
print("PASS: known_unknown_same=0_rebinds known_unknown_changed=1_rebind structural_equality_preserved=true")
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
