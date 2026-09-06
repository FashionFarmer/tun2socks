package statistic

import (
	"testing"
	"time"
)

func TestManagerCloseIsIdempotent(t *testing.T) {
	m := NewManager()
	m.PushUploaded(7)
	m.PushDownloaded(9)
	m.Close()
	m.Close()

	select {
	case <-m.done:
	case <-time.After(time.Second):
		t.Fatal("manager did not stop")
	}

	snapshot := m.Snapshot()
	if snapshot.UploadTotal != 7 || snapshot.DownloadTotal != 9 {
		t.Fatalf("unexpected totals: %+v", snapshot)
	}
}
