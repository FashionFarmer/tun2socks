package statistic

import (
	"sync"
	"time"

	"go.uber.org/atomic"
)

// DefaultManager is retained for the command-line compatibility layer. It is
// dormant until the global tunnel is first requested, so library instances do
// not acquire a process-lifetime statistics goroutine merely by importing this
// package.
var DefaultManager = newManager()

// NewManager creates an independent traffic and connection statistics manager.
// Call Close when the owning tunnel instance stops.
func NewManager() *Manager {
	m := newManager()
	m.Start()
	return m
}

func newManager() *Manager {
	return &Manager{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
}

type Manager struct {
	connections   sync.Map
	uploadTemp    *atomic.Int64
	downloadTemp  *atomic.Int64
	uploadBlip    *atomic.Int64
	downloadBlip  *atomic.Int64
	uploadTotal   *atomic.Int64
	downloadTotal *atomic.Int64
	stop          chan struct{}
	done          chan struct{}
	startOnce     sync.Once
	closeOnce     sync.Once
}

// Start activates rate sampling. It is idempotent.
func (m *Manager) Start() {
	if m == nil {
		return
	}
	m.startOnce.Do(func() { go m.handle() })
}

func (m *Manager) Join(c tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c tracker) {
	m.connections.Delete(c.ID())
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
}

func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []tracker
	m.connections.Range(func(key, value any) bool {
		connections = append(connections, value.(tracker))
		return true
	})

	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
	}
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
}

func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer close(m.done)

	for {
		select {
		case <-ticker.C:
			m.uploadBlip.Store(m.uploadTemp.Load())
			m.uploadTemp.Store(0)
			m.downloadBlip.Store(m.downloadTemp.Load())
			m.downloadTemp.Store(0)
		case <-m.stop:
			return
		}
	}
}

// Close stops the manager and closes every connection still tracked by it.
// It is safe to call more than once.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		m.Start()
		m.connections.Range(func(_, value any) bool {
			_ = value.(tracker).Close()
			return true
		})
		close(m.stop)
		<-m.done
	})
}

type Snapshot struct {
	DownloadTotal int64     `json:"downloadTotal"`
	UploadTotal   int64     `json:"uploadTotal"`
	Connections   []tracker `json:"connections"`
}
