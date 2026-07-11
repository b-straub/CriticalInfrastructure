import CoreBluetooth
import Foundation

/// BLE (CoreBluetooth) transport carrying the same command envelope as UDP. Scans for the
/// device's GATT service, writes the request chunked to the `rx` characteristic, and reassembles
/// the reply from `tx` notifications. macOS + iOS (no Wi-Fi/LAN, no Local Network permission).
///
/// `DeviceClient` is an actor, so `sendReceive` is called serially — there is at most one exchange
/// in flight, which keeps the delegate state simple. All state is touched only on `queue`.
public final class BleTransport: NSObject, DeviceTransport, @unchecked Sendable {
    private let serviceUUID: CBUUID
    private let rxUUID: CBUUID   // client → device (write)
    private let txUUID: CBUUID   // device → client (notify)
    private let name: String
    private let queue = DispatchQueue(label: "criticalinfra.ble")
    private let maxChunk = 240   // matches ble.rs MAX_CHUNK

    private var central: CBCentralManager!
    private var peripheral: CBPeripheral?
    private var rxChar: CBCharacteristic?
    private var txChar: CBCharacteristic?

    // In-flight exchange (guarded by `queue`).
    private var assembler: ChunkAssembler?
    private var replyCont: CheckedContinuation<Data, Error>?
    // Pending "become ready" waiter (guarded by `queue`).
    private var readyCont: CheckedContinuation<Void, Error>?
    private var scanning = false

    public init(config: DeviceConfig) {
        serviceUUID = CBUUID(string: DeviceConfig.bleServiceUUID)
        rxUUID = CBUUID(string: DeviceConfig.bleRxCharUUID)
        txUUID = CBUUID(string: DeviceConfig.bleTxCharUUID)
        name = config.bleName
        super.init()
        central = CBCentralManager(delegate: self, queue: queue)
    }

    public func sendReceive(_ payload: Data, timeout: TimeInterval) async throws -> Data {
        try await ensureReady(timeout: timeout)
        return try await exchange(payload, timeout: timeout)
    }

    private var isReady: Bool { rxChar != nil && txChar != nil && peripheral?.state == .connected }

    // MARK: connect + discover + subscribe

    private func ensureReady(timeout: TimeInterval) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async {
                if self.isReady { cont.resume(); return }
                self.readyCont = cont
                self.queue.asyncAfter(deadline: .now() + timeout) {
                    if let c = self.readyCont {
                        self.readyCont = nil
                        self.stopScan()
                        c.resume(throwing: TransportError.timeout)
                    }
                }
                self.startScanIfPowered()
            }
        }
    }

    private func startScanIfPowered() {
        guard central.state == .poweredOn, !scanning, peripheral == nil else { return }
        scanning = true
        central.scanForPeripherals(withServices: [serviceUUID], options: nil)
    }

    private func stopScan() {
        if scanning { central.stopScan(); scanning = false }
    }

    private func finishReady(_ result: Result<Void, Error>) {
        guard let c = readyCont else { return }
        readyCont = nil
        switch result {
        case .success: c.resume()
        case .failure(let e): c.resume(throwing: e)
        }
    }

    // MARK: one request/response exchange

    private func exchange(_ payload: Data, timeout: TimeInterval) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            queue.async {
                guard let p = self.peripheral, let rx = self.rxChar, p.state == .connected else {
                    cont.resume(throwing: TransportError.connection("BLE not connected"))
                    return
                }
                self.assembler = ChunkAssembler()
                self.replyCont = cont
                self.queue.asyncAfter(deadline: .now() + timeout) {
                    if let c = self.replyCont {
                        self.replyCont = nil
                        self.assembler = nil
                        c.resume(throwing: TransportError.timeout)
                    }
                }
                // Chunked write; BLE preserves per-characteristic write order, and the firmware
                // reassembles by seq. `.withResponse` keeps flow-control simple for a spike.
                for frame in FrameChunker.chunk(payload, maxChunk: self.maxChunk) {
                    p.writeValue(frame, for: rx, type: .withResponse)
                }
            }
        }
    }

    private func finishReply(_ result: Result<Data, Error>) {
        guard let c = replyCont else { return }
        replyCont = nil
        assembler = nil
        switch result {
        case .success(let d): c.resume(returning: d)
        case .failure(let e): c.resume(throwing: e)
        }
    }
}

// MARK: - CBCentralManagerDelegate

extension BleTransport: CBCentralManagerDelegate {
    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            startScanIfPowered()
        case .unauthorized, .unsupported, .poweredOff:
            finishReady(.failure(TransportError.connection("Bluetooth unavailable (\(central.state.rawValue))")))
        default:
            break
        }
    }

    public func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                               advertisementData: [String: Any], rssi RSSI: NSNumber) {
        stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.discoverServices([serviceUUID])
    }

    public func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        self.peripheral = nil
        finishReady(.failure(TransportError.connection("BLE connect failed: \(error?.localizedDescription ?? "unknown")")))
    }

    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        self.peripheral = nil
        self.rxChar = nil
        self.txChar = nil
        finishReply(.failure(TransportError.connection("BLE disconnected")))
        finishReady(.failure(TransportError.connection("BLE disconnected")))
    }
}

// MARK: - CBPeripheralDelegate

extension BleTransport: CBPeripheralDelegate {
    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let svc = peripheral.services?.first(where: { $0.uuid == serviceUUID }) else {
            finishReady(.failure(TransportError.connection("BLE service not found")))
            return
        }
        peripheral.discoverCharacteristics([rxUUID, txUUID], for: svc)
    }

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        for ch in service.characteristics ?? [] {
            if ch.uuid == rxUUID { rxChar = ch }
            if ch.uuid == txUUID { txChar = ch }
        }
        guard let tx = txChar, rxChar != nil else {
            finishReady(.failure(TransportError.connection("BLE characteristics not found")))
            return
        }
        peripheral.setNotifyValue(true, for: tx)   // ready once notifications are on
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == txUUID {
            if let error { finishReady(.failure(TransportError.connection("BLE subscribe failed: \(error.localizedDescription)"))) }
            else { finishReady(.success(())) }
        }
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == txUUID, let data = characteristic.value, let assembler else { return }
        do {
            if let full = try assembler.add(data) { finishReply(.success(full)) }
        } catch {
            finishReply(.failure(error))
        }
    }

    public func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error { finishReply(.failure(TransportError.connection("BLE write failed: \(error.localizedDescription)"))) }
    }
}
