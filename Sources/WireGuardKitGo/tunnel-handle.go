package main

import "C"

import (
	"context"
	"math"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type tunnelHandles struct {
	handles map[int32]*tunnelHandle
	lock    sync.Mutex
	// Never reuse a tunnel identity: callers can still be returning from a
	// blocking receive after the backend that owned their handle was removed.
	nextHandle int64
}

func NewTunnelHandles() *tunnelHandles {
	return &tunnelHandles{
		handles: make(map[int32]*tunnelHandle),
		lock:    sync.Mutex{},
	}
}

func (h *tunnelHandles) Get(idx int32) *tunnelHandle {
	h.lock.Lock()
	defer h.lock.Unlock()

	return h.handles[idx]
}

// Inserts handle, returns a positive key if successful. Otherwise, returns a errDeviceLimitHit.
func (h *tunnelHandles) Insert(handle *tunnelHandle) int32 {
	h.lock.Lock()
	defer h.lock.Unlock()

	if h.nextHandle >= math.MaxInt32 {
		return errDeviceLimitHit
	}
	index := int32(h.nextHandle)
	h.nextHandle++
	h.handles[index] = handle
	return index
}

// Removes the handle at `idx` and returns it. Returns nil if `idx` doesn't exist.
func (h *tunnelHandles) Remove(idx int32) *tunnelHandle {
	h.lock.Lock()
	defer h.lock.Unlock()
	handle := h.handles[idx]
	delete(h.handles, idx)
	return handle
}

type tunnelHandle struct {
	// A WireGuard device for the exit relay.
	exit *device.Device
	// A WireGuard device for the entry relay.
	entry *device.Device
	// A logger.
	logger *device.Logger
	// A virtual network used to send traffic to the exit relay.
	VirtualNet *netstack.Net
	// Socket handles that are attached to the virtual network.
	socketHandles map[int32]*socketHandle
	// Socket identities are never reused within one tunnel lifetime either.
	nextSocketHandle int64
	// Prevents a C call that captured this owner before removal from resurrecting sockets after Close.
	closed bool
	// A lock to be held when mutating this struct.
	lock *sync.Mutex
}

func NewTunnelHandle(exit *device.Device, entry *device.Device, logger *device.Logger, virtualNet *netstack.Net) tunnelHandle {
	return tunnelHandle{
		exit:          exit,
		entry:         entry,
		logger:        logger,
		VirtualNet:    virtualNet,
		socketHandles: make(map[int32]*socketHandle),
		lock:          &sync.Mutex{},
	}
}

// Returns nil if tunnel is closed
func (tun *tunnelHandle) GetConfig() *string {
	settings, err := tun.exit.IpcGet()
	if err != nil {
		return nil
	}
	return &settings
}

func (tun *tunnelHandle) SetConfig(settings, entrySettings string) int64 {
	if entrySettings != "" && tun.entry == nil {
		return errBadEntryConfig
	}
	err := tun.exit.IpcSet(settings)
	if err != nil {
		tun.logger.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return errBadWgConfig
	}
	if entrySettings != "" {
		if err := tun.entry.IpcSet(entrySettings); err != nil {
			tun.logger.Errorf("Unable to set entry IPC settings: %v", err)
			if ipcErr, ok := err.(*device.IPCError); ok {
				return ipcErr.ErrorCode()
			}
			return errBadWgConfig
		}
	}
	return 0
}

func (tun *tunnelHandle) BumpSockets() {
	device := tun.exit
	if tun.entry != nil {
		device = tun.entry
	}

	go func() {
		for i := 0; i < 10; i++ {
			err := device.BindUpdate()
			if err == nil {
				device.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			tun.logger.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		tun.logger.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

func (tun *tunnelHandle) DisableSomeRoamingForBrokenMobileSemantics() {
	tun.exit.DisableSomeRoamingForBrokenMobileSemantics()
	if tun.entry != nil {
		tun.entry.DisableSomeRoamingForBrokenMobileSemantics()
	}
}

// Creates a socket asynchronously and returns an handle to it immediately.
// Calls to get the socket will block until the passed in closure returns. The
// closure takes a context and the virtual networking stack. Any connection
// returned from the closure should be bound to virtual network.
func (tun *tunnelHandle) AddSocket(ctx context.Context, createSocket func(ctx context.Context, virtualNet *netstack.Net) (net.Conn, error)) int32 {
	tun.lock.Lock()
	defer tun.lock.Unlock()

	if tun.closed {
		return errNoSuchTunnel
	}
	if tun.nextSocketHandle >= math.MaxInt32 {
		return errDeviceLimitHit
	}
	socketHandle := newSocketHandle(tun.VirtualNet, ctx, createSocket)
	handle := int32(tun.nextSocketHandle)
	tun.nextSocketHandle++
	tun.socketHandles[handle] = socketHandle
	return handle
}

// Returns a socket bound to the virtual network. Blocks until socket is connected.
func (tun *tunnelHandle) GetSocket(id int32) (net.Conn, error, bool) {
	tun.lock.Lock()
	socket, ok := tun.socketHandles[id]
	tun.lock.Unlock()

	if !ok {
		return nil, nil, false
	}

	conn, err := socket.Get()

	return conn, err, true
}

func (tun *tunnelHandle) RemoveAndCloseSocket(id int32) bool {
	tun.lock.Lock()
	defer tun.lock.Unlock()
	socket, ok := tun.socketHandles[id]
	if ok {
		socket.close()
	}

	delete(tun.socketHandles, id)
	return ok
}

func (tun *tunnelHandle) Close() {
	tun.lock.Lock()
	defer tun.lock.Unlock()

	if tun.closed {
		return
	}
	tun.closed = true
	for _, socket := range tun.socketHandles {
		socket.close()
	}

	tun.socketHandles = make(map[int32]*socketHandle)
	tun.exit.Close()
	if tun.entry != nil {
		tun.entry.Close()
	}
}

type socketHandle struct {
	// Initializing lock is held whilst the connection is being _initialized_. It
	// expected that the equivalent of `conn.Dial` will be called whilst this
	// lock is held. This allows for creating a socket handle for a connection that is still initializing.
	// The asynchronicity is needed to allow the iOS app to shut down a tunnel
	// whilst it is trying to create a TCP connection to our relay.
	initializingLock *sync.Mutex
	// Underlying connection
	conn net.Conn
	// Error returned when connection fails to initialize
	connError error

	// Cancel function is returned by `context.WithCancel`. This should cancel
	// any initialization of a socket.
	cancelFunc func()
}

// Creates a new socket handle for a connection and spawns off a goroutine initializing the connection.
func newSocketHandle(vnet *netstack.Net, ctx context.Context, createSocket func(ctx context.Context, virtualNet *netstack.Net) (net.Conn, error)) *socketHandle {
	ctx, cancelFunc := context.WithCancel(ctx)
	handle := &socketHandle{
		initializingLock: &sync.Mutex{},
		conn:             nil,
		connError:        nil,
		cancelFunc:       cancelFunc,
	}

	handle.initializingLock.Lock()
	go func() {
		defer handle.initializingLock.Unlock()
		conn, err := createSocket(ctx, vnet)
		cancelFunc()
		if err != nil {
			handle.connError = err
		} else {
			handle.conn = conn
		}
	}()

	return handle
}

func (handle *socketHandle) close() {
	handle.cancelFunc()
	handle.initializingLock.Lock()
	defer handle.initializingLock.Unlock()
	if handle.conn != nil {
		handle.conn.Close()
	}
}

func (handle *socketHandle) Get() (net.Conn, error) {
	handle.initializingLock.Lock()
	defer handle.initializingLock.Unlock()
	return handle.conn, handle.connError
}
