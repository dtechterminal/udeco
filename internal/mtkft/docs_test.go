// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"fmt"
	"testing"

	"github.com/dtechterminal/udeco/internal/repotest"
)

// docs/deco/features/garage-ft.md quotes this package's numbers; each
// phrase is the note's prose with the value taken from the code.
func TestDocsGarageFT(t *testing.T) {
	bss := MAC{0xa8, 0x42, 0xa1, 0, 0, 1}
	repotest.MustHave(t, "docs/deco/features/garage-ft.md",
		fmt.Sprintf("`FT_R1KH_ENTRY_TABLE_SIZE` is %d entries for the whole radio.", R1KHTableSize),
		fmt.Sprintf("its EtherType 0x%04X.", EtherTypeKDP),
		fmt.Sprintf("`KEY_REQ` (%#04x, `FT_KDP_KeyRequestToUs` 0x80542330)", OIDKeyReq),
		fmt.Sprintf("`KEY_RSP` (%#04x, `FT_KDP_KeyResponseToUs` 0x805431d4)", OIDKeyRsp),
		fmt.Sprintf("which is `KeyElementLen` = %d octets", KeyElementLen),
		fmt.Sprintf("It keeps the %d of `FT_CfgInitial`'s random", R0KHIDLen),
		fmt.Sprintf("hostapd's `mobility_domain=d530` is `FtMdId1=%s`", MDIDValue(0xd530)),
		fmt.Sprintf("Frame.** EtherType %#04x, OUI 00:13:74, protocol octets %02x %02x", EtherTypeOUI, FTOUI[3], FTOUI[4]),
		fmt.Sprintf("`OID_802_11_RRM_COMMAND` (0x%04X)", OIDRRMCommand),
		fmt.Sprintf("as IWEVCUSTOM flags 0x%04X", EvRRM),
		fmt.Sprintf("at most %d octets", maxNRRspLen),
		fmt.Sprintf("`OID_802_11_WNM_BTM_REQ` (%#04x,", OIDWNMBTMReq),
		fmt.Sprintf("IWEVCUSTOM %#04x:", EvBTMRsp),
		fmt.Sprintf("Station BTM queries are %#04x.", EvBTMQuery),
		fmt.Sprintf("`IW_CUSTOM_MAX` = %d octets", IWCustomMax),
		fmt.Sprintf("arrives within %d s", seqTimeoutSec),
	)
	if got := R0KHID(bss); len(got) != R0KHIDLen {
		t.Fatalf("R0KHID %q", got)
	}
}
