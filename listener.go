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

type Conn struct {
	quic.Session
	quic.Stream
}

func (q *Conn) Read(b []byte) (int, error) {
	return q.Stream.Read(b)
}

func (q *Conn) Write(b []byte) (int, error) {
	return q.Stream.Write(b)
}

func (q *Conn) Close() error {
	return q.Stream.Close()
}

func (q *Conn) LocalAddr() net.Addr {
	return q.Session.LocalAddr()
}

func (q *Conn) RemoteAddr() net.Addr {
	return q.Session.RemoteAddr()
}

func (q *Conn) SetDeadline(t time.Time) error {
	return q.Stream.SetDeadline(t)
}

func (q *Conn) SetReadDeadline(t time.Time) error {
	return q.Stream.SetReadDeadline(t)

}

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

func ListenQUIC(ctx context.Context, addr netaddr.IPPort, selector pan.ReplySelector, tlsCfg *tls.Config, qconf *quic.Config) (net.Listener, error) {
	session, err := pan.ListenQUIC(context.Background(), addr, selector, tlsCfg, qconf)
	if err != nil {
		return nil, err
	}
	return &quicListener{session}, nil
}

// Listen implements caddy.TCPServer interface.
func ListenPort(port uint16) (net.Listener, error) {
	return ListenIPPort(netaddr.IPPortFrom(netaddr.IPFrom4([4]byte{127, 0, 0, 1}), port))
}

func ListenIPPort(addr netaddr.IPPort) (net.Listener, error) {
	tlsCfg := &tls.Config{
		Certificates: quicutil.MustGenerateSelfSignedCert(),
		NextProtos:   []string{"hello-quic"},
	}
	return ListenQUIC(context.Background(), addr, nil, tlsCfg, nil)
}

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
