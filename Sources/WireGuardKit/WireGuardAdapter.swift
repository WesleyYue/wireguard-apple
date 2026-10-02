// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension

#if SWIFT_PACKAGE
import WireGuardKitGo
import WireGuardKitC
@_exported import WireGuardKitTypes
#endif

public enum WireGuardAdapterError: Error {
    /// Failure to locate tunnel file descriptor.
    case cannotLocateTunnelFileDescriptor

    /// Failure to perform an operation in such state.
    case invalidState

    /// Failure to resolve endpoints.
    case dnsResolution([DNSResolutionError])

    /// Failure to set network settings.
    case setNetworkSettings(Error)

    /// Failure to start WireGuard backend.
    case startWireGuardBackend(Int32)

    /// Config has no private IPs.
    case noInterfaceIp

    /// The tunnel descriptor provided does not refer to an open tunnel
    case noSuchTunnel

    /// the tunnel exists, but does not have a virtual interface
    case noTunnelVirtualInterface

    /// ICMP socket not open
    case icmpSocketNotOpen

    /// internal error
    case internalError(Int32)
}

/// Enum representing internal state of the `WireGuardAdapter`
private enum State {
    /// The tunnel is stopped
    case stopped

    /// The tunnel is up and running
    case started(_ handle: Int32, _ settingsGenerator: PacketTunnelSettingsGenerator)

    /// The tunnel is temporarily shutdown due to device going offline
    case temporaryShutdown(_ settingsGenerator: PacketTunnelSettingsGenerator)
}

/// Exit-hop counters, read directly from the backend without serializing configuration.
public struct WireGuardTrafficStats: Sendable {
    public let bytesReceived: UInt64
    public let bytesSent: UInt64
}

/// Cumulative counters for this adapter instance. Contains no keys, endpoints or addresses.
public struct WireGuardAdapterDiagnostics: Sendable {
    public fileprivate(set) var backendGeneration: UInt64 = 0
    public fileprivate(set) var backendStarts: UInt64 = 0
    public fileprivate(set) var backendStops: UInt64 = 0
    public fileprivate(set) var icmpGeneration: UInt64?
    public fileprivate(set) var icmpOpened: UInt64 = 0
    public fileprivate(set) var icmpClosed: UInt64 = 0
    public fileprivate(set) var icmpSendErrors: UInt64 = 0
    public fileprivate(set) var icmpReadErrors: UInt64 = 0
    public fileprivate(set) var icmpCanceledReads: UInt64 = 0
    public fileprivate(set) var pathUpdates: UInt64 = 0
    public fileprivate(set) var pathUnchanged: UInt64 = 0
    public fileprivate(set) var pathRebinds: UInt64 = 0
    public fileprivate(set) var statsReads: UInt64 = 0
    public fileprivate(set) var statsErrors: UInt64 = 0
}

/// A socket belongs to exactly one backend generation, even if an integer handle is later reused.
private struct ICMPSocket {
    let tunnelHandle: Int32
    let socketHandle: Int32
    let generation: UInt64
    let pingId: UInt16
}

public class WireGuardAdapter {
    public typealias LogHandler = (WireGuardLogLevel, String) -> Void

    /// Network routes monitor.
    private var networkMonitor: NWPathMonitor?

    /// Latest path reported by `networkMonitor`.
    private var monitorPath: Network.NWPath?

    /// The path the WireGuard sockets were last bound on, or nil if not known yet.
    private var boundPathSignature: PathSignature?

    /// Pending re-check of the interface addresses after an ignored path update.
    private var addressCheck: DispatchWorkItem?

    /// Invalidates callbacks queued by canceled observers and monitors.
    private var pathObservationGeneration: UInt64 = 0

    /// Packet tunnel provider.
    private weak var packetTunnelProvider: NEPacketTunnelProvider?

    /// KVO observer for `NEProvider.defaultPath`.
    private var defaultPathObserver: NSKeyValueObservation?

    /// Last known default path.
    private var currentDefaultPath: NetworkExtension.NWPath?

    /// Log handler closure.
    private let logHandler: LogHandler

    /// Private queue used to synchronize access to `WireGuardAdapter` members.
    private let workQueue = DispatchQueue(label: "WireGuardAdapterWorkQueue")

    /// Adapter state.
    private var state: State = .stopped

    /// ICMP resource owned by the currently running backend.
    private var icmpSocket: ICMPSocket?

    private var diagnostics = WireGuardAdapterDiagnostics()

    /// Whether adapter should automatically raise the `reasserting` flag when updating
    /// tunnel configuration.
    private let shouldHandleReasserting: Bool

    /// ID to use for ICMP echo requests. Should be reset for every tunnel connection.
    private var pingId: UInt16 = UInt16.random(in: UInt16.min...UInt16.max)

    public let inTunnelTcpOpen: @convention(c) (Int32, UnsafePointer<Int8>?, UInt64) -> Int32  = wgOpenInTunnelTCP
    public let inTunnelTcpClose: @convention(c) (Int32, Int32) -> Int32 = wgCloseInTunnelTCP
    public let inTunnelTcpRecv: @convention(c) (Int32, Int32, UnsafeMutablePointer<UInt8>?, Int32) -> Int32 = wgRecvInTunnelTCP
    public let inTunnelTcpSend: @convention(c) (Int32, Int32, UnsafePointer<UInt8>?, Int32) -> Int32 = wgSendInTunnelTCP

    /// Tunnel device file descriptor.
    private var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    /// Returns a WireGuard version.
    class var backendVersion: String {
        guard let ver = wgVersion() else { return "unknown" }
        let str = String(cString: ver)
        free(UnsafeMutableRawPointer(mutating: ver))
        return str
    }

    /// Returns the tunnel device interface name, or nil on error.
    /// - Returns: String.
    public var interfaceName: String? {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else { return nil }

        var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))

        return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
            guard let baseAddress = mutableBufferPointer.baseAddress else { return nil }

            var ifnameSize = socklen_t(IFNAMSIZ)
            let result = getsockopt(
                tunnelFileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress,
                &ifnameSize)

            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    // MARK: - Initialization

    /// Designated initializer.
    /// - Parameter packetTunnelProvider: an instance of `NEPacketTunnelProvider`. Internally stored
    ///   as a weak reference.
    /// - Parameter shouldHandleReasserting: whether adapter should automatically raise the
    ///   `reasserting` flag when updating tunnel configuration.
    /// - Parameter logHandler: a log handler closure.
    public init(with packetTunnelProvider: NEPacketTunnelProvider, shouldHandleReasserting: Bool = true, logHandler: @escaping LogHandler) {
        self.packetTunnelProvider = packetTunnelProvider
        self.shouldHandleReasserting = shouldHandleReasserting
        self.logHandler = logHandler

        setupLogHandler()
    }

    deinit {
        // Force remove logger to make sure that no further calls to the instance of this class
        // can happen after deallocation.
        wgSetLogger(nil, nil)

        // Cancel network monitor
        networkMonitor?.cancel()

        // Shutdown the tunnel
        if case .started(let handle, _) = self.state {
            wgTurnOff(handle)
            self.icmpSocket = nil
        }
    }

    // MARK: - Public methods

    /// Returns a runtime configuration from WireGuard.
    /// - Parameter completionHandler: completion handler.
    public func getRuntimeConfiguration(completionHandler: @escaping (String?) -> Void) {
        workQueue.async {
            guard case .started(let handle, _) = self.state else {
                completionHandler(nil)
                return
            }

            if let settings = wgGetConfig(handle) {
                completionHandler(String(cString: settings))
                free(settings)
            } else {
                completionHandler(nil)
            }
        }
    }

    /// Completion executes on the adapter queue, like `getRuntimeConfiguration`.
    public func getTrafficStats(completionHandler: @escaping (WireGuardTrafficStats?) -> Void) {
        workQueue.async {
            guard case .started(let handle, _) = self.state else {
                completionHandler(nil)
                return
            }
            self.diagnostics.statsReads += 1
            var received: UInt64 = 0
            var sent: UInt64 = 0
            guard wgGetTrafficStats(handle, &received, &sent) == 0 else {
                self.diagnostics.statsErrors += 1
                completionHandler(nil)
                return
            }
            completionHandler(WireGuardTrafficStats(bytesReceived: received, bytesSent: sent))
        }
    }

    public func getDiagnostics(completionHandler: @escaping (WireGuardAdapterDiagnostics) -> Void) {
        workQueue.async { completionHandler(self.diagnostics) }
    }

    public func startMultihop(exitConfiguration: TunnelConfiguration, entryConfiguration: TunnelConfiguration?, daita: DaitaConfiguration? = nil, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            guard case .stopped = self.state else {
                completionHandler(.invalidState)
                return
            }

            guard let privateAddress = exitConfiguration.interface.addresses.compactMap({ $0.address as? IPv4Address }).first else
            {
                self.logHandler(.error, "WireGuardAdapter.start: No private IPv4 address found")
                completionHandler(.noInterfaceIp)
                return
            }

            self.addDefaultPathObserver()

            do {
                let settingsGenerator = try self.makeSettingsGenerator(with: exitConfiguration, entryConfiguration: entryConfiguration, daita: daita)

                try self.activateBackend(settingsGenerator: settingsGenerator, privateAddress: privateAddress)

                completionHandler(nil)
            } catch let error as WireGuardAdapterError {
                self.removeDefaultPathObserver()
                self.state = .stopped
                completionHandler(error)
            } catch {
                fatalError()
            }
        }

    }

    /// Start the tunnel tunnel.
    /// - Parameters:
    ///   - tunnelConfiguration: tunnel configuration.
    ///   - completionHandler: completion handler.
    public func start(tunnelConfiguration: TunnelConfiguration, daita: DaitaConfiguration? = nil, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        startMultihop(exitConfiguration: tunnelConfiguration, entryConfiguration: nil, daita: daita, completionHandler: completionHandler)
    }

    /// Stop the tunnel.
    /// - Parameter completionHandler: completion handler.
    public func stop(completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            switch self.state {
            case .started(let handle, _):
                self.shutdownBackend(handle)

            case .temporaryShutdown:
                self.closeICMP()

            case .stopped:
                completionHandler(.invalidState)
                return
            }

            self.removeDefaultPathObserver()

            self.state = .stopped
            self.closeICMP()

            completionHandler(nil)
        }
    }

    /// Update runtime configuration.
    /// - Parameters:
    ///   - tunnelConfiguration: tunnel configuration.
    ///   - completionHandler: completion handler.
    public func update(tunnelConfiguration: TunnelConfiguration, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            if case .stopped = self.state {
                completionHandler(.invalidState)
                return
            }

            // Tell the system that the tunnel is going to reconnect using new WireGuard
            // configuration.
            // This will broadcast the `NEVPNStatusDidChange` notification to the GUI process.
            if self.shouldHandleReasserting {
                self.packetTunnelProvider?.reasserting = true
            }

            defer {
                if self.shouldHandleReasserting {
                    self.packetTunnelProvider?.reasserting = false
                }
            }

            let settingsGenerator: PacketTunnelSettingsGenerator
            do {
                settingsGenerator = try self.makeSettingsGenerator(with: tunnelConfiguration)
            } catch let error as WireGuardAdapterError {
                completionHandler(error)
                return
            } catch {
                fatalError()
            }

            switch self.state {
            case .started(let handle, _):
                let (wgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                let (entryConfig, _) = settingsGenerator.entryUapiConfiguration() ?? (nil, [])
                self.logEndpointResolutionResults(resolutionResults)

                wgSetConfig(handle, wgConfig, entryConfig)
                #if os(iOS)
                wgDisableSomeRoamingForBrokenMobileSemantics(handle)
                #endif

                self.state = .started(handle, settingsGenerator)

                do {
                    if let gateway = tunnelConfiguration.pingableGateway {
                        try self.openICMP(address: gateway)
                    }
                } catch let error as WireGuardAdapterError {
                    completionHandler(error)
                    return
                } catch {
                    self.logHandler(.error, "Failed to open ICMP socket: \(error)")
                }

            case .temporaryShutdown:
                self.state = .temporaryShutdown(settingsGenerator)
                self.closeICMP()

            case .stopped:
                fatalError()
            }

            completionHandler(nil)
        }
    }

    // MARK: - Private methods

    /// Setup WireGuard log handler.
    private func setupLogHandler() {
        let context = Unmanaged.passUnretained(self).toOpaque()
        wgSetLogger(context) { context, logLevel, message in
            guard let context = context, let message = message else { return }

            let unretainedSelf = Unmanaged<WireGuardAdapter>.fromOpaque(context)
                .takeUnretainedValue()

            let swiftString = String(cString: message).trimmingCharacters(in: .newlines)
            let tunnelLogLevel = WireGuardLogLevel(rawValue: logLevel) ?? .verbose

            unretainedSelf.logHandler(tunnelLogLevel, swiftString)
        }
    }

    /// Resolve peers of the given tunnel configuration.
    /// - Parameter tunnelConfiguration: tunnel configuration.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: The list of resolved endpoints.
    private func resolvePeers(for tunnelConfiguration: TunnelConfiguration) throws -> [Endpoint?] {
        let endpoints = tunnelConfiguration.peers.map { $0.endpoint }
        let resolutionResults = DNSResolver.resolveSync(endpoints: endpoints)
        let resolutionErrors = resolutionResults.compactMap { result -> DNSResolutionError? in
            if case .failure(let error) = result {
                return error
            } else {
                return nil
            }
        }
        assert(endpoints.count == resolutionResults.count)
        guard resolutionErrors.isEmpty else {
            throw WireGuardAdapterError.dnsResolution(resolutionErrors)
        }

        let resolvedEndpoints = resolutionResults.map { result -> Endpoint? in
            // swiftlint:disable:next force_try
            return try! result?.get()
        }

        return resolvedEndpoints
    }

    /// Start WireGuard backend.
    /// - Parameter wgConfig: WireGuard configuration
    /// - Throws: an error of type `WireGuardAdapterError`
    /// - Returns: tunnel handle
    private func startWireGuardBackend(exitWgConfig: String, privateAddress: IPAddress, entryWgConfig: String? = nil, mtu: UInt16 = 1280, daita: DaitaConfiguration?) throws -> Int32 {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else {
            throw WireGuardAdapterError.cannotLocateTunnelFileDescriptor
        }

        var params = DaitaGoParameters(daita: daita)
        let privateAddr = "\(privateAddress)"

        let handle = if let entryWgConfig {
            wgTurnOnMultihop(exitWgConfig, entryWgConfig, privateAddr, tunnelFileDescriptor, daita?.machines ?? nil, &params)
        } else {
            wgTurnOnIAN(exitWgConfig, tunnelFileDescriptor, privateAddr, daita?.machines ?? nil, &params)
        }
        if handle < 0 {
            throw WireGuardAdapterError.startWireGuardBackend(handle)
        }
        diagnostics.backendGeneration += 1
        diagnostics.backendStarts += 1
        pingId = UInt16.random(in: UInt16.min...UInt16.max)
        #if os(iOS)
        wgDisableSomeRoamingForBrokenMobileSemantics(handle)
        #endif
        return handle
    }

    /// Startup and offline resume share one configuration path, including the entry hop and DAITA.
    private func activateBackend(settingsGenerator: PacketTunnelSettingsGenerator, privateAddress: IPAddress) throws {
        let (exitConfig, exitResolution) = settingsGenerator.uapiConfiguration()
        let entry = settingsGenerator.entryUapiConfiguration()
        logEndpointResolutionResults(exitResolution)
        if let entry { logEndpointResolutionResults(entry.1) }
        let handle = try startWireGuardBackend(
            exitWgConfig: exitConfig, privateAddress: privateAddress,
            entryWgConfig: entry?.0, daita: settingsGenerator.daita
        )
        state = .started(handle, settingsGenerator)
        boundPathSignature = monitorPath.flatMap(PathSignature.init)
        do {
            if let gateway = settingsGenerator.exit.configuration.pingableGateway {
                try openICMP(address: gateway)
            }
        } catch {
            shutdownBackend(handle)
            state = .temporaryShutdown(settingsGenerator)
            throw error
        }
    }

    /// Invalidates Swift resources before destroying their Go owner.
    private func shutdownBackend(_ handle: Int32) {
        closeICMP()
        wgTurnOff(handle)
        diagnostics.backendStops += 1
        boundPathSignature = nil
        addressCheck?.cancel()
        addressCheck = nil
    }

    /// Resolves the hostnames in the given tunnel configuration and return settings generator.
    /// - Parameter exitConfiguration: an instance of type `TunnelConfiguration`.
    /// - Parameter entryConfiguration: an optional instance of type `TunnelConfiguration` for the entry WireGuard device
    /// - Parameter daita: an optional instance of type `DaitaConfiguration` for the configuration used by the Daita feature
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: an instance of type `PacketTunnelSettingsGenerator`.
    private func makeSettingsGenerator(with exitConfiguration: TunnelConfiguration, entryConfiguration: TunnelConfiguration? = nil, daita: DaitaConfiguration? = nil) throws -> PacketTunnelSettingsGenerator {
        let resolvedExitEndpoints = try self.resolvePeers(for: exitConfiguration)

        var entry: DeviceConfiguration? = nil
        if let entryConfiguration {
            let resolvedEntryEndpoints = try self.resolvePeers(for: entryConfiguration)
            entry = DeviceConfiguration(configuration: entryConfiguration, resolvedEndpoints: resolvedEntryEndpoints, reResolveEndpoint: true)
        }

        // Disable NAT64 resolution for exit relays when multihop is enabled
        return PacketTunnelSettingsGenerator(
            exit: DeviceConfiguration(configuration: exitConfiguration, resolvedEndpoints: resolvedExitEndpoints, reResolveEndpoint: entry == nil),
            entry: entry,
            daita: daita
        )
    }

    /// Log DNS resolution results.
    /// - Parameter resolutionErrors: an array of type `[DNSResolutionError]`.
    private func logEndpointResolutionResults(_ resolutionResults: [EndpointResolutionResult?]) {
        for case .some(let result) in resolutionResults {
            switch result {
            case .success((let sourceEndpoint, let resolvedEndpoint)):
                if sourceEndpoint.host == resolvedEndpoint.host {
                    self.logHandler(.verbose, "DNS64: mapped \(sourceEndpoint.host) to itself.")
                } else {
                    self.logHandler(.verbose, "DNS64: mapped \(sourceEndpoint.host) to \(resolvedEndpoint.host)")
                }
            case .failure(let resolutionError):
                self.logHandler(.error, "Failed to resolve endpoint \(resolutionError.address): \(resolutionError.errorDescription ?? "(nil)")")
            }
        }
    }

    private func addDefaultPathObserver() {
        guard let packetTunnelProvider = packetTunnelProvider else { return }

        pathObservationGeneration += 1
        let generation = pathObservationGeneration
        defaultPathObserver?.invalidate()
        defaultPathObserver = packetTunnelProvider.observe(\.defaultPath, options: [.new]) { [weak self] _, change in
            guard let self = self, let defaultPath = change.newValue?.flatMap({ $0 }) else { return }

            self.workQueue.async {
                guard self.pathObservationGeneration == generation else { return }
                self.didReceivePathUpdate(path: defaultPath)
            }
        }

        currentDefaultPath = packetTunnelProvider.defaultPath

        // `NEProvider.defaultPath` doesn't expose the interface or gateways, so compare paths from a monitor instead.
        // The handler runs on `workQueue`.
        networkMonitor?.cancel()
        monitorPath = nil
        // Observe the physical route; the tunnel's utun route must not trigger its own socket rebind.
        let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self, self.pathObservationGeneration == generation else { return }
            self.diagnostics.pathUpdates += 1
            self.monitorPath = path
            self.rebindIfPathChanged(source: .monitor)
        }
        monitor.start(queue: workQueue)
        networkMonitor = monitor
    }

    private func removeDefaultPathObserver() {
        pathObservationGeneration += 1
        defaultPathObserver?.invalidate()
        defaultPathObserver = nil
        currentDefaultPath = nil

        networkMonitor?.cancel()
        networkMonitor = nil
        monitorPath = nil
        boundPathSignature = nil
        addressCheck?.cancel()
        addressCheck = nil
    }

    /// Method invoked by KVO observer when new network path is received.
    /// - Parameter path: new network path
    private func didReceivePathUpdate(path: NetworkExtension.NWPath) {
        diagnostics.pathUpdates += 1
        let isSamePath = currentDefaultPath?.isEqual(to: path) ?? false

        currentDefaultPath = path

        #if os(macOS)
        if case .started(let handle, _) = self.state, !isSamePath {
            diagnostics.pathRebinds += 1
            wgBumpSockets(handle)
        }
        #elseif os(iOS)
        let isSatisfiable = path.status == .satisfied || path.status == .satisfiable

        switch self.state {
        case .started(let handle, let settingsGenerator):
            if isSatisfiable {
                guard !isSamePath else {
                    self.diagnostics.pathUnchanged += 1
                    return
                }

                self.rebindIfPathChanged(source: .defaultPath)
            } else {
                self.logHandler(.verbose, "Connectivity offline, pausing backend.")

                self.shutdownBackend(handle)
                self.state = .temporaryShutdown(settingsGenerator)
            }

        case .temporaryShutdown(let settingsGenerator):
            guard isSatisfiable else { return }

            self.logHandler(.verbose, "Connectivity online, resuming backend.")

            guard let privateAddress = settingsGenerator.exit.configuration.interface.addresses.compactMap({ $0.address as? IPv4Address }).first else
            {
                self.logHandler(.error, "WireGuardAdapter.start: No private IPv4 address found")
                return
            }


            do {
                try self.activateBackend(settingsGenerator: settingsGenerator, privateAddress: privateAddress)
            } catch {
                self.logHandler(.error, "Failed to restart backend: \(error.localizedDescription)")
            }

        case .stopped:
            // no-op
            break
        }
        #else
        #error("Unsupported")
        #endif
    }

    /// Rebinds the WireGuard sockets if the preferred interface, its gateways or its addresses changed since they
    /// were last bound. `NEProvider.defaultPath` can report a new path every few seconds while none of these change,
    /// and each rebind wakes the radio and sends keepalives.
    private func rebindIfPathChanged(source: PathUpdateSource) {
        dispatchPrecondition(condition: .onQueue(workQueue))
        #if os(iOS)
        guard case .started(let handle, let settingsGenerator) = self.state else { return }

        // Without a monitor path to compare against, rebind as before.
        if let monitorPath = self.monitorPath {
            // Loss of connectivity is handled by the `defaultPath` observer.
            guard let signature = PathSignature(monitorPath) else { return }

            if signature == self.boundPathSignature {
                self.diagnostics.pathUnchanged += 1
                if source != .addressCheck {
                    self.scheduleAddressCheck()
                }
                return
            }

        }

        let (wgConfig, resolutionResults) = settingsGenerator.endpointUapiConfiguration()
        let entry = settingsGenerator.entryEndpointUapiConfiguration()
        self.logEndpointResolutionResults(resolutionResults)
        if let entry { self.logEndpointResolutionResults(entry.1) }

        guard wgSetConfig(handle, wgConfig, entry?.0) == 0 else {
            self.logHandler(.error, "Failed to update endpoint configuration for path change.")
            return
        }
        // Unknown startup paths require one real bind, since the first monitor callback may describe a newer path.
        self.boundPathSignature = self.monitorPath.flatMap(PathSignature.init)
        wgDisableSomeRoamingForBrokenMobileSemantics(handle)
        self.diagnostics.pathRebinds += 1
        wgBumpSockets(handle)
        #endif
    }

    /// Compares the addresses again a few seconds after an ignored path update, since an address can change without
    /// the path changing. Does nothing while a check is pending, so frequent updates can't postpone it.
    private func scheduleAddressCheck() {
        guard addressCheck == nil else { return }

        let generation = pathObservationGeneration
        let check = DispatchWorkItem { [weak self] in
            guard let self = self, self.pathObservationGeneration == generation else { return }
            self.addressCheck = nil
            self.rebindIfPathChanged(source: .addressCheck)
        }
        addressCheck = check
        workQueue.asyncAfter(deadline: .now() + .seconds(3), execute: check)
    }
}

private enum PathUpdateSource {
    /// `NEProvider.defaultPath` changed.
    case defaultPath

    /// `NWPathMonitor` reported a path.
    case monitor

    /// Delayed comparison of the interface addresses.
    case addressCheck
}

/// The parts of a satisfied path that matter to the WireGuard sockets: the interface the system prefers, the network
/// it's attached to, and its addresses. Adapted from `GotaTunPathObserver` in mullvadvpn-app (57f39174, 0d697bb3).
private struct PathSignature: Equatable {
    let interface: String
    let gateways: Set<Network.NWEndpoint>
    let addresses: Set<String>

    init?(_ path: Network.NWPath) {
        guard path.status == .satisfied,
              let interface = path.availableInterfaces.first(where: {
                  [.wifi, .cellular, .wiredEthernet].contains($0.type) && !$0.name.hasPrefix("utun")
              })?.name else { return nil }
        self.interface = interface
        self.gateways = Set(path.gateways)
        self.addresses = interfaceAddresses(of: interface)
    }
}

/// The IPv4 and IPv6 addresses assigned to `interface`.
private func interfaceAddresses(of interface: String) -> Set<String> {
    var list: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&list) == 0, let first = list else { return [] }
    defer { freeifaddrs(list) }

    var addresses = Set<String>()
    for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
        guard String(cString: entry.pointee.ifa_name) == interface,
              let address = entry.pointee.ifa_addr,
              [AF_INET, AF_INET6].contains(Int32(address.pointee.sa_family))
        else { continue }

        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
        else { continue }
        addresses.insert(host.withUnsafeBufferPointer { String(cString: $0.baseAddress!) })
    }
    return addresses
}

// A protocol encompassing the stateful ICMP ping capabilities of the WireGuardAdapter, decoupling them from its implementation
public protocol ICMPPingProvider {
    func sendICMPPing(seqNumber: UInt16) throws
    func receiveICMP() throws -> Int32

    /// Closes the socket to end an outstanding receive. The next ping operation reopens it.
    func cancelICMPReceive()
}

extension WireGuardAdapter: ICMPPingProvider {
    public func cancelICMPReceive() {
        workQueue.async { self.closeICMP() }
    }

    /// Serialized acquisition includes ping identity and generation, so restart cannot mix their owners.
    private func acquireICMPSocket() throws -> ICMPSocket {
        dispatchPrecondition(condition: .onQueue(workQueue))
        guard case .started(let handle, let settingsGenerator) = state else {
            throw WireGuardAdapterError.icmpSocketNotOpen
        }
        if icmpSocket == nil, let gateway = settingsGenerator.exit.configuration.pingableGateway {
            try openICMP(address: gateway)
        }
        guard let socket = icmpSocket, socket.tunnelHandle == handle,
              socket.generation == diagnostics.backendGeneration else {
            throw WireGuardAdapterError.icmpSocketNotOpen
        }
        return socket
    }

    /// MARK: ICMP Ping functionality
    private func openICMP(address: IPv4Address) throws {
        dispatchPrecondition(condition: .onQueue(workQueue))
        guard case .started(let tunnelHandle, _) = self.state else {
            throw WireGuardAdapterError.invalidState
        }

        // Ignore multiple calls to `openICMP`
        guard icmpSocket == nil else { return }

        // assumption: the description of an IPv4Address will always produce valid ASCII
        let addrString = "\(address)"
        let socket = wgOpenInTunnelICMP(tunnelHandle, addrString)
        if socket < 0 {
            switch socket {
            case -19: // errNoSuchTunnel
                throw WireGuardAdapterError.noSuchTunnel
                // this can currently only happen if we have 2^31 sockets, so if it happens, there's a bug somewhere
                default: throw WireGuardAdapterError.internalError(socket)
            }
        }
        self.icmpSocket = ICMPSocket(
            tunnelHandle: tunnelHandle, socketHandle: socket,
            generation: diagnostics.backendGeneration, pingId: pingId
        )
        diagnostics.icmpOpened += 1
        diagnostics.icmpGeneration = diagnostics.icmpOpened
    }

    public func closeICMP() {
        dispatchPrecondition(condition: .onQueue(workQueue))
        guard let socket = icmpSocket else { return }
        // Forget the resource unconditionally, including while temporarily shut down.
        icmpSocket = nil
        diagnostics.icmpGeneration = nil
        wgCloseInTunnelICMP(socket.tunnelHandle, socket.socketHandle)
        diagnostics.icmpClosed += 1
    }

    // Returns the sequence number of the ICMP message that was received.
    // This could be improved by also returning the ID of the message that was received.
    public func receiveICMP() throws -> Int32 {
        dispatchPrecondition(condition: .notOnQueue(workQueue))
        let socket = try workQueue.sync { try self.acquireICMPSocket() }
        let result = wgRecvInTunnelPing(socket.tunnelHandle, socket.socketHandle)
        if result < 0 {
            workQueue.async {
                if self.icmpSocket?.generation == socket.generation,
                   self.icmpSocket?.socketHandle == socket.socketHandle {
                    self.diagnostics.icmpReadErrors += 1
                } else {
                    self.diagnostics.icmpCanceledReads += 1
                }
            }
            try Self.throwError(result: result)
        }

        return result
    }

    public func sendICMPPing(seqNumber: UInt16) throws {
        dispatchPrecondition(condition: .notOnQueue(workQueue))
        let socket = try workQueue.sync { try self.acquireICMPSocket() }
        let seq = wgSendInTunnelPing(socket.tunnelHandle, socket.socketHandle, socket.pingId, 16, seqNumber)
        if seq < 0 {
            workQueue.async { self.diagnostics.icmpSendErrors += 1 }
            try Self.throwError(result: seq)
        }
    }

    private static func throwError(result: Int32) throws {
         switch result {
            case -14: // errICMPOpenSocket
            throw WireGuardAdapterError.icmpSocketNotOpen
            // TODO: more fine-grained errors
            default: throw WireGuardAdapterError.internalError(result)
        }

    }

    /// Returns the handle associated with the tunnel. If the tunnel is not started, this will not return anything.
    public func tunnelHandle() throws  -> Int32 {
        dispatchPrecondition(condition: .notOnQueue(workQueue))
        return try workQueue.sync {
            guard case .started(let tunnelHandle, _) = self.state else {
                throw WireGuardAdapterError.invalidState
            }

            return tunnelHandle
        }
    }
}

/// A enum describing WireGuard log levels defined in `api-apple.go`.
public enum WireGuardLogLevel: Int32 {
    case verbose = 0
    case error = 1
}

extension NetworkExtension.NWPathStatus: CustomDebugStringConvertible {
    public var debugDescription: String {
        switch self {
        case .unsatisfied:
            return "unsatisfied"
        case .satisfied:
            return "satisfied"
        case .satisfiable:
            return "satisfiable"
        case .invalid:
            return "invalid"
        @unknown default:
            return "unknown (rawValue = \(rawValue))"
        }
    }
}

extension DaitaGoParameters {
    init(daita: DaitaConfiguration?) {
        self = DaitaGoParameters()
        maybeNotMaxEvents = daita?.maxEvents ?? 0
        maybeNotMaxActions = daita?.maxActions ?? 0
        maybeNotMaxPadding = daita?.maxPadding ?? 0
        maybeNotMaxBlocking = daita?.maxBlocking ?? 0
    }
}
