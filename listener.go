package scionquic

import (
	"crypto/tls"

	"github.com/lucas-clemente/quic-go"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/quicutil"
	"inet.af/netaddr"

	"context"
	"net"
	"time"
)

var (
	ServerTLSDummyCfg = &tls.Config{
		Certificates: quicutil.MustGenerateSelfSignedCert(),
		NextProtos:   []string{"hello-quic"},
	}
	ClientTLSDummyCfg = &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hello-quic"},
	}
)

// Conn implements net.Conn
type Conn struct {
	quic.Session
	quic.Stream
}

// Read implements net.Conn.Read
func (q *Conn) Read(b []byte) (int, error) {
	return q.Stream.Read(b)
}

// Write required to implement net.Conn
func (q *Conn) Write(b []byte) (int, error) {
	return q.Stream.Write(b)
}

// Close required to implement net.Conn
func (q *Conn) Close() error {
	return q.Stream.Close()
}

// LocalAddr required to implement net.Conn
func (q *Conn) LocalAddr() net.Addr {
	return q.Session.LocalAddr()
}

// RemoteAddr required to implement net.Conn
func (q *Conn) RemoteAddr() net.Addr {
	return q.Session.RemoteAddr()
}

// SetDeadline required to implement net.Conn
func (q *Conn) SetDeadline(t time.Time) error {
	return q.Stream.SetDeadline(t)
}

// SetReadDeadline required to implement net.Conn
func (q *Conn) SetReadDeadline(t time.Time) error {
	return q.Stream.SetReadDeadline(t)

}

// SetWriteDeadline required to implement net.Conn
func (q *Conn) SetWriteDeadline(t time.Time) error {
	return q.Stream.SetWriteDeadline(t)
}

type quicListener struct {
	quic.Listener
}

func (q *quicListener) Accept() (net.Conn, error) {
	ctx := context.Background()
	conn, err := q.Listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	qconn := Conn{conn, stream}

	return &qconn, nil
}

// ListenQUIC returns a SCION QUIC listener struct that implements net.Listener
func ListenQUIC(ctx context.Context, addr netaddr.IPPort, selector pan.ReplySelector, tlsCfg *tls.Config, qconf *quic.Config) (net.Listener, error) {
	session, err := pan.ListenQUIC(context.Background(), addr, selector, tlsCfg, qconf)
	if err != nil {
		return nil, err
	}
	return &quicListener{session}, nil
}

// ListenPort returns a SCION QUIC listener struct that implements net.Listener
func ListenPort(port uint16) (net.Listener, error) {
	return ListenIPPort(netaddr.IPPortFrom(netaddr.IPFrom4([4]byte{127, 0, 0, 1}), port))
}

// ListenIPPort returns a SCION QUIC listener struct that implements net.Listener
func ListenIPPort(addr netaddr.IPPort) (net.Listener, error) {
	return ListenQUIC(context.Background(), addr, nil, ServerTLSDummyCfg, nil)
}

// DialQUIC returns a SCION QUIC connection that implements net.Conn
func DialQUIC(ctx context.Context, local netaddr.IPPort, remote pan.UDPAddr, policy pan.Policy, selector pan.Selector, host string, tlsConf *tls.Config, quicConf *quic.Config) (net.Conn, error) {
	conn, err := pan.DialQUIC(ctx, local, remote, policy, selector, host, tlsConf, quicConf)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &Conn{conn, stream}, nil

}

// DialAddr returns a SCION QUIC connection that implements net.Conn
func DialAddr(remote pan.UDPAddr) (net.Conn, error) {
	return DialQUIC(context.Background(), netaddr.IPPort{}, remote, nil, nil, "", ClientTLSDummyCfg, nil)
}

// DialString returns a SCION QUIC connection that implements net.Conn
func DialString(remote string) (net.Conn, error) {
	addr, err := pan.ParseUDPAddr(remote)
	if err != nil {
		return nil, err
	}
	return DialAddr(addr)
}
