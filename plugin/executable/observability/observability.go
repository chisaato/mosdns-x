package observability

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	dt "github.com/dnstap/golang-dnstap"
	fs "github.com/farsightsec/golang-framestream"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/plugin/executable/adg_filter"
)

const PluginType = "observability"

var recordedMark uint

func init() {
	var err error
	recordedMark, err = query_context.AllocateMark()
	if err != nil {
		panic(fmt.Sprintf("observability: %v", err))
	}
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	PrometheusListen string `yaml:"prometheus_listen"`
	PrometheusPath   string `yaml:"prometheus_path"`
	DnstapSocket     string `yaml:"dnstap_socket"`
}

type observability struct {
	*coremain.BP
	args *Args

	reg             *prometheus.Registry
	queryTotal      prometheus.Counter
	errTotal        prometheus.Counter
	thread          prometheus.Gauge
	responseLatency prometheus.Histogram
	blockedTotal    prometheus.Counter
	passedTotal     prometheus.Counter

	dnstap *dnstapOutput
}

type dnstapOutput struct {
	listener net.Listener
	conns    map[net.Conn]*fs.Writer
	mu       sync.RWMutex
	stopCh   chan struct{}
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	return newObservability(bp, args.(*Args))
}

func newObservability(bp *coremain.BP, args *Args) (*observability, error) {
	if args.PrometheusPath == "" {
		args.PrometheusPath = "/metrics"
	}

	o := &observability{
		BP:   bp,
		args: args,
		reg:  prometheus.NewRegistry(),
	}

	o.reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	o.reg.MustRegister(collectors.NewGoCollector())

	o.queryTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "query_total",
		Help: "Total queries processed",
	})
	o.errTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "err_total",
		Help: "Total queries that returned an error",
	})
	o.thread = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "thread",
		Help: "Current concurrent queries",
	})
	o.responseLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "response_latency_millisecond",
		Help:    "Response latency in milliseconds",
		Buckets: []float64{1, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000},
	})
	o.blockedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "blocked_total",
		Help: "Total blocked queries",
	})
	o.passedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "passed_total",
		Help: "Total non-blocked queries",
	})

	o.reg.MustRegister(o.queryTotal, o.errTotal, o.thread, o.responseLatency, o.blockedTotal, o.passedTotal)

	if args.PrometheusListen != "" {
		mux := http.NewServeMux()
		mux.Handle(args.PrometheusPath, promhttp.HandlerFor(o.reg, promhttp.HandlerOpts{}))
		go func() {
			bp.L().Info("observability: starting prometheus http server",
				zap.String("addr", args.PrometheusListen),
				zap.String("path", args.PrometheusPath),
			)
			if err := http.ListenAndServe(args.PrometheusListen, mux); err != nil {
				bp.L().Error("observability: prometheus http server failed", zap.Error(err))
			}
		}()
	}

	if args.DnstapSocket != "" {
		dnstap, err := newDnstapOutput(args.DnstapSocket, bp.L())
		if err != nil {
			return nil, fmt.Errorf("observability: %w", err)
		}
		o.dnstap = dnstap
		bp.L().Info("observability: dnstap fstrm output enabled",
			zap.String("socket", args.DnstapSocket),
		)
	}

	return o, nil
}

func (o *observability) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	if qCtx.HasMark(recordedMark) {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}
	qCtx.AddMark(recordedMark)

	o.thread.Inc()
	defer o.thread.Dec()

	o.queryTotal.Inc()
	start := time.Now()

	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	if err != nil {
		o.errTotal.Inc()
	}

	blocked := qCtx.HasMark(adg_filter.BlockedMark)
	if blocked {
		o.blockedTotal.Inc()
	} else {
		o.passedTotal.Inc()
	}

	if r := qCtx.R(); r != nil {
		o.responseLatency.Observe(float64(time.Since(start).Milliseconds()))
	}

	if o.dnstap != nil {
		o.dnstap.writeMsg(qCtx, blocked)
	}

	return err
}

func (o *observability) Close() error {
	if o.dnstap != nil {
		return o.dnstap.close()
	}
	return nil
}

// ── dnstap ──

func newDnstapOutput(path string, logger *zap.Logger) (*dnstapOutput, error) {
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("dnstap listen: %w", err)
	}
	d := &dnstapOutput{
		listener: l,
		conns:    make(map[net.Conn]*fs.Writer),
		stopCh:   make(chan struct{}),
	}
	go d.acceptLoop(logger)
	return d, nil
}

func (d *dnstapOutput) acceptLoop(logger *zap.Logger) {
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-d.stopCh:
				return
			default:
			}
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return
			}
			logger.Error("observability: dnstap accept failed", zap.Error(err))
			continue
		}

		w, err := fs.NewWriter(conn, &fs.WriterOptions{
			ContentTypes: [][]byte{[]byte("protobuf:dnstap.Dnstap")},
		})
		if err != nil {
			logger.Error("observability: dnstap framestream handshake failed", zap.Error(err))
			conn.Close()
			continue
		}

		d.mu.Lock()
		d.conns[conn] = w
		d.mu.Unlock()
		logger.Debug("observability: dnstap client connected",
			zap.Stringer("remote", conn.RemoteAddr()),
		)
	}
}

func (d *dnstapOutput) writeMsg(qCtx *query_context.Context, blocked bool) {
	q := qCtx.Q()
	r := qCtx.R()
	startTime := qCtx.StartTime()
	now := time.Now()

	msg := &dt.Dnstap{
		Type: dt.Dnstap_MESSAGE.Enum(),
		Message: &dt.Message{
			Type:             dt.Message_CLIENT_QUERY.Enum(),
			QueryTimeSec:     proto.Uint64(uint64(startTime.Unix())),
			QueryTimeNsec:    proto.Uint32(uint32(startTime.Nanosecond())),
			ResponseTimeSec:  proto.Uint64(uint64(now.Unix())),
			ResponseTimeNsec: proto.Uint32(uint32(now.Nanosecond())),
			SocketFamily:     dt.SocketFamily_INET.Enum(),
			SocketProtocol:   dt.SocketProtocol_UDP.Enum(),
		},
	}

	if q != nil {
		if packed, err := q.Pack(); err == nil {
			msg.Message.QueryMessage = packed
		}
	}
	if r != nil {
		if packed, err := r.Pack(); err == nil {
			msg.Message.ResponseMessage = packed
		}
	}

	if blocked {
		msg.Extra = []byte{1}
	} else {
		msg.Extra = []byte{0}
	}

	frame, err := proto.Marshal(msg)
	if err != nil {
		return
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for conn, w := range d.conns {
		if _, err := w.WriteFrame(frame); err != nil {
			conn.Close()
			go d.removeConn(conn)
		}
	}
}

func (d *dnstapOutput) removeConn(conn net.Conn) {
	d.mu.Lock()
	delete(d.conns, conn)
	d.mu.Unlock()
}

func (d *dnstapOutput) close() error {
	close(d.stopCh)
	d.mu.Lock()
	for conn, w := range d.conns {
		_ = w.Close()
		conn.Close()
	}
	d.conns = nil
	d.mu.Unlock()
	return d.listener.Close()
}
