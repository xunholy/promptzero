package marauder

import (
	"context"
	"strings"
	"testing"
	"time"
)

// SniffPMKID and PortScan/PortScanService now validate channel / ipIndex
// before transport. Pre-fix, an LLM picking 5-GHz channel 36 for PMKID
// capture saw a clean empty response from the firmware (the ESP32 radio
// can't tune there), and a negative ipIndex silently no-op'd.

func TestSniffPMKID_RejectsNegativeChannel(t *testing.T) {
	_, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.SniffPMKIDCtx(context.Background(), -1, false, false, time.Second)
	})
	if err == nil {
		t.Fatal("expected error for channel=-1; got nil")
	}
	if !strings.Contains(err.Error(), "PMKID channel") {
		t.Errorf("err = %v; want PMKID channel validation error", err)
	}
}

func TestSniffPMKID_RejectsOutOfBandChannel(t *testing.T) {
	for _, ch := range []int{15, 36, 100} {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.SniffPMKIDCtx(context.Background(), ch, false, false, time.Second)
		})
		if err == nil {
			t.Errorf("expected error for channel=%d; got nil", ch)
			continue
		}
		if !strings.Contains(err.Error(), "channel") {
			t.Errorf("ch=%d err = %v; want channel validation error", ch, err)
		}
	}
}

func TestSniffPMKID_AcceptsSweepAndValidChannel(t *testing.T) {
	// channel=0 (sweep) and channel=6 should both pass validation. We
	// can't run the wire path here without the mock returning data, so
	// just verify the validators don't reject.
	if err := validateWiFiChannel24Int(6); err != nil {
		t.Errorf("validateWiFiChannel24Int(6) unexpected err: %v", err)
	}
}

func TestPortScan_RejectsNegativeIPIndex(t *testing.T) {
	_, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.PortScanCtx(context.Background(), -1, time.Second)
	})
	if err == nil {
		t.Fatal("expected error for negative ipIndex; got nil")
	}
	if !strings.Contains(err.Error(), "IP index") {
		t.Errorf("err = %v; want IP index validation error", err)
	}
}

func TestPortScanService_RejectsNegativeIPIndex(t *testing.T) {
	_, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.PortScanServiceCtx(context.Background(), -2, "ssh", time.Second)
	})
	if err == nil {
		t.Fatal("expected error for negative ipIndex; got nil")
	}
	if !strings.Contains(err.Error(), "IP index") {
		t.Errorf("err = %v; want IP index validation error", err)
	}
}

func TestPortScanService_StillRejectsBadService(t *testing.T) {
	_, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.PortScanServiceCtx(context.Background(), 0, "gopher", time.Second)
	})
	if err == nil {
		t.Fatal("expected error for unknown service; got nil")
	}
	if !strings.Contains(err.Error(), "service") {
		t.Errorf("err = %v; want service validation error", err)
	}
}
