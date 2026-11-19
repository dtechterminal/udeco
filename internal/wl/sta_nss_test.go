package wl

import "testing"

// Rate-set lines as wl sta_info prints them on a Deco X20 (.205, 2026-11-19):
// an HT-only client (MCS 0-7), an 11ac client whose HT set is 2 streams but
// whose VHT set is 1 stream, and a 2x2 HE client (VHT continuation line, HE NSS lines, as in testdata/wl_-i_wl12_sta_info_all.txt).
const staNSSFixture = `[VER 9] STA F4:CF:A2:1E:72:64:
	 HT caps 0x116e: 40MHz SGI20 SGI40 STBC-Rx
MCS SET : [ 0 1 2 3 4 5 6 7 ]
link bandwidth = 40 MHZ 
[VER 9] STA 88:57:1D:BB:BB:86:
	 flags 0x111e13a: WME PS N_CAP VHT_CAP AMPDU AMSDU DWDS_CAP
MCS SET : [ 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 ]
VHT SET : 0x1 1x1 2x1 3x1 4x1 5x1 6x1 7x1 8x1 9x1 
vht mcs 7 Nss 1 Tx Exp 0 bw80 stbc ldpc sgi auto
link bandwidth = 80 MHZ
[VER 9] STA 02:00:00:00:00:03:
	 flags 0x1: N_CAP VHT_CAP HE_CAP
MCS SET : [ 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 32 ]
VHT SET : 0x1 1x1 2x1 3x1 4x1 5x1 6x1 7x1 8x1 9x1 
        : 0x2 1x2 2x2 3x2 4x2 5x2 6x2 7x2 8x2 9x2 
HE SET  :
	    20/40/80 MHz:
		NSS1 Tx: 0-11        Rx: 0-11
		NSS2 Tx: 0-11        Rx: 0-11
link bandwidth = 80 MHZ
[VER 9] STA 02:00:00:00:00:04:
link bandwidth = 20 MHZ
`

func TestStaInfoNSS(t *testing.T) {
	sts := parseStaInfoAll([]byte(staNSSFixture))
	want := []int{1, 1, 2, 0}
	if len(sts) != len(want) {
		t.Fatalf("%d stations, want %d", len(sts), len(want))
	}
	for i, st := range sts {
		if st.NSS != want[i] {
			t.Errorf("%s: NSS %d, want %d", st.MAC, st.NSS, want[i])
		}
	}
	if sts[1].MHz != 80 || !sts[1].VHT {
		t.Errorf("other fields disturbed: %+v", sts[1])
	}
}

func TestRateSetHelpers(t *testing.T) {
	if n := htNSS("[ 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 32 ]"); n != 3 {
		t.Errorf("htNSS 3-stream = %d", n)
	}
	if n := mcsxNSS("0x1 1x1 0x4 9x4"); n != 4 {
		t.Errorf("mcsxNSS = %d", n)
	}
}
