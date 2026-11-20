// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

// GuestRules is the guest isolation of a GuestPolicy as ebtables rules,
// for another platform's applier (mtkwifi on the JioFiber JCOW414): the
// same fail-closed chains as here (guest.go). In and Out are the rules of
// ChainIn and ChainOut (ebtables arguments after "-A <chain>"); with
// Portal, ChainIn sends unauthorised guests to ChainAuth (policy DROP,
// one "-s <mac> -j RETURN" per authorised guest).
type GuestRules struct {
	In, Out                      [][]string
	Portal                       bool
	ChainIn, ChainOut, ChainAuth string
	Notes                        []string
}

// GuestEbtables validates g and renders its rules; nil when g cannot
// isolate guests (no policy, no usable gateway MAC or IP): the guest
// SSIDs are then not served.
func GuestEbtables(g *GuestPolicy) *GuestRules {
	r, notes := normalizeGuest(g)
	if r == nil {
		return nil
	}
	in, out := r.render()
	return &GuestRules{In: in, Out: out, Portal: r.Portal, ChainIn: GuestChainIn, ChainOut: GuestChainOut,
		ChainAuth: GuestChainAuth, Notes: notes}
}
