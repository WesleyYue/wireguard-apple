package main

import (
	"context"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func testBackend(t *testing.T) *device.Device {
	t.Helper()
	tun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	return dev
}

func TestTunnelIdentityCannotAliasNewGeneration(t *testing.T) {
	handles := NewTunnelHandles()
	first := &tunnelHandle{}
	oldID := handles.Insert(first)
	if handles.Remove(oldID) != first {
		t.Fatal("lost old backend")
	}
	newID := handles.Insert(&tunnelHandle{})
	if oldID == newID || handles.Get(oldID) != nil {
		t.Fatal("stale backend handle aliases the new generation")
	}
	handles.nextHandle = math.MaxInt32
	if got := handles.Insert(&tunnelHandle{}); got != errDeviceLimitHit {
		t.Fatalf("identity exhaustion must fail without reuse: %d", got)
	}
}

func TestSocketCancelUnblocksReadWithoutReusingIdentity(t *testing.T) {
	handle := NewTunnelHandle(testBackend(t), nil, device.NewLogger(device.LogLevelSilent, ""), nil)
	addPipe := func() (int32, net.Conn) {
		reader, writer := net.Pipe()
		t.Cleanup(func() { writer.Close() })
		id := handle.AddSocket(context.Background(), func(context.Context, *netstack.Net) (net.Conn, error) {
			return reader, nil
		})
		return id, writer
	}
	oldID, _ := addPipe()
	reader, err, ok := handle.GetSocket(oldID)
	if !ok || err != nil {
		t.Fatalf("socket acquisition failed: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := reader.Read(make([]byte, 1)); done <- err }()
	if !handle.RemoveAndCloseSocket(oldID) {
		t.Fatal("socket cancellation failed")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled receive must fail")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled socket left receive blocked")
	}
	newID, _ := addPipe()
	if newID == oldID {
		t.Fatal("stale socket identity aliases restarted receiver")
	}
	if _, _, ok := handle.GetSocket(oldID); ok {
		t.Fatal("canceled socket remains discoverable")
	}
	handle.Close()
}

func TestClosedTunnelCannotAcquireNewSockets(t *testing.T) {
	handle := NewTunnelHandle(testBackend(t), nil, device.NewLogger(device.LogLevelSilent, ""), nil)
	handle.Close()
	id := handle.AddSocket(context.Background(), func(context.Context, *netstack.Net) (net.Conn, error) {
		t.Error("closed backend invoked socket creation")
		return nil, nil
	})
	if id != errNoSuchTunnel || len(handle.socketHandles) != 0 {
		t.Fatalf("socket resurrected after Close: %d", id)
	}
}

// Replay a receiver paused just before entering C while cancellation and a new receiver run.
// The old immutable identity must fail immediately without stealing the new session's response.
func TestDelayedOldReceiverCannotConsumeReplacementReply(t *testing.T) {
	handle := NewTunnelHandle(testBackend(t), nil, device.NewLogger(device.LogLevelSilent, ""), nil)
	tunnelID := tunnels.Insert(&handle)
	t.Cleanup(func() { wgTurnOff(tunnelID) })
	addPipe := func() (int32, net.Conn) {
		reader, writer := net.Pipe()
		t.Cleanup(func() { writer.Close() })
		id := handle.AddSocket(context.Background(), func(context.Context, *netstack.Net) (net.Conn, error) {
			return reader, nil
		})
		return id, writer
	}
	oldID, _ := addPipe()
	beginOldRead, oldResult := make(chan struct{}), make(chan int32, 1)
	go func() {
		<-beginOldRead
		oldResult <- wgRecvInTunnelPing(tunnelID, oldID)
	}()
	handle.RemoveAndCloseSocket(oldID)
	newID, newWriter := addPipe()
	close(beginOldRead)
	select {
	case result := <-oldResult:
		if result != errICMPOpenSocket {
			t.Fatalf("stale receive result: %d", result)
		}
	case <-time.After(time.Second):
		t.Fatal("stale receive acquired the replacement socket")
	}
	newResult := make(chan int32, 1)
	go func() { newResult <- wgRecvInTunnelPing(tunnelID, newID) }()
	packet, err := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: 7, Seq: 17}}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newWriter.Write(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-newResult:
		if result != 17 {
			t.Fatalf("replacement lost reply: %d", result)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement receiver did not receive its reply")
	}
}

func TestTrafficStatsBridgeBoundaryAndExitSelection(t *testing.T) {
	exit, entry := testBackend(t), testBackend(t)
	configurations, _ := genConfigs(t)
	if err := entry.IpcSet(configurations[0]); err != nil {
		t.Fatal(err)
	}
	handle := NewTunnelHandle(exit, entry, device.NewLogger(device.LogLevelSilent, ""), nil)
	id := tunnels.Insert(&handle)
	t.Cleanup(func() { wgTurnOff(id) })
	rx, tx := _Ctype_uint64_t(12), _Ctype_uint64_t(34)
	if got := wgGetTrafficStats(id, &rx, &tx); got != errNoPeer {
		t.Fatalf("entry counters must not replace missing exit counters: %d", got)
	}
	if rx != 12 || tx != 34 {
		t.Fatal("failure changed output pointers")
	}
	if got := wgGetTrafficStats(id, nil, &tx); got != errInvalidStatsOutput {
		t.Fatalf("nil output must fail: %d", got)
	}
	if err := exit.IpcSet(configurations[1]); err != nil {
		t.Fatal(err)
	}
	if got := wgGetTrafficStats(id, &rx, &tx); got != 0 || rx != 0 || tx != 0 {
		t.Fatalf("narrow bridge returned unexpected result: %d %d %d", got, rx, tx)
	}
	wgTurnOff(id)
	if got := wgGetTrafficStats(id, &rx, &tx); got != errNoSuchTunnel {
		t.Fatalf("removed backend must not return counters: %d", got)
	}
}

func TestMultihopSetConfigUpdatesEntry(t *testing.T) {
	exit, entry := testBackend(t), testBackend(t)
	configurations, _ := genConfigs(t)
	handle := NewTunnelHandle(exit, entry, device.NewLogger(device.LogLevelSilent, ""), nil)
	if got := handle.SetConfig(configurations[0], configurations[1]); got != 0 {
		t.Fatalf("multihop configuration update failed: %d", got)
	}
	if exit.TrafficStats().PeerCount != 1 || entry.TrafficStats().PeerCount != 1 {
		t.Fatal("configuration update lost the entry hop")
	}
	singlehop := NewTunnelHandle(exit, nil, handle.logger, nil)
	if got := singlehop.SetConfig("", configurations[1]); got != errBadEntryConfig {
		t.Fatalf("entry config on single-hop backend must fail: %d", got)
	}
}
