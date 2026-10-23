package axiam

import (
	"context"
	"fmt"
)

// The `network` namespace in a manifest — CONTRACT.md §27.6.2 (contract 1.62).
//
// A site's segments and their reply profiles are exactly the SHAPE §27.6 exists
// for, so `network` is a manifest namespace: the tenant's Session-Timeout cap
// (a singleton), then its segments, then its profiles. Every write it makes is
// the version-conditional replace_* / create of §36, built from the READ, sent
// once, and never retried; a 409 or a 403 is that action's failure and apply
// stops there (rule 7).
//
// The namespace is human-only (§36.1): an Apply whose manifest has a Network
// section needs a human caller, and a service-account token meets 401 at the
// first network action.
//
// This SDK's manifest has no pruning for any namespace, so network has none
// either: an Apply never deletes a segment or a profile (§27.6 rule 4's
// default, the only mode there is). See the README's conformance table.

// NetworkSegmentSpec is a network segment (§27.6.2 item 1).
//
// Its natural key is Site + Kind + Name, where Kind is the WIRE spelling,
// NetworkSegmentKindAccess ("access") or NetworkSegmentKindQuarantine
// ("quarantine"): the value create_segment writes and every segment read
// returns. This SDK keeps no other spelling and has no "zones" value anywhere;
// the path segment `zones` is a server-side detail of where an access segment
// sits in the resource tree. Site, Kind and Name never drift (§36.3 rule 4);
// every other member is a field, reconciled by §27.6 rule 3.
type NetworkSegmentSpec struct {
	// Key is the manifest-local identifier a NetworkProfileSpec refers to.
	Key string
	// Site is the segment's site key (the wire `site_key`). Part of the natural key.
	Site string
	// Kind is NetworkSegmentKindAccess or NetworkSegmentKindQuarantine, the wire
	// spelling. Part of the natural key.
	Kind NetworkSegmentKind
	// Name is the segment's name, unique within its site and kind. Part of the
	// natural key.
	Name string
	// VlanID is the VLAN (1 to 4094). The server judges the value.
	VlanID int
	// Rank is the placement rank of an access segment. Absent leaves what the
	// read has (and sends none on create); NullOf[int]() states "none" and is
	// left out of the body.
	Rank Nullable[int]
	// FilterIDs is the segment's Filter-Id envelope. nil is UNSTATED (carried
	// from the read on an update, none on a create); a non-nil empty list states
	// an empty envelope. Compared as a SET (§27.6.2 item 3): the same names in
	// another order are NoChange, and a name listed twice is refused at Plan
	// with zero wire calls. When the SDK writes it, the order is the one stated.
	FilterIDs []string
	// Enabled is whether the segment is a placement candidate. nil is unstated.
	Enabled *bool
}

// NetworkProfileSpec is a segment's reply profile (§27.6.2 item 1). Its natural
// key is its segment: a profile has no name or id of its own.
//
// Every member is judged on the value AS THE READ RETURNS IT — the effective
// profile (§36.2, §36.3 rule 6). A SessionTimeoutSecs above the tenant's cap
// therefore differs from the read, Plan shows an Update, and Apply's
// replace_profile is refused by the server (403 authorization_denied, the write
// gate's H3). That refusal is the action's failure: it is reported as the
// server gave it, Apply stops, and nothing is retried, adjusted or lowered to
// the cap by the SDK.
type NetworkProfileSpec struct {
	// Segment is the Key of a NetworkSegmentSpec of the same manifest. A key no
	// segment declares is refused at Plan, with zero wire calls.
	Segment string
	// SessionTimeoutSecs is the Session-Timeout, in seconds.
	SessionTimeoutSecs int
	// TerminationAction is the Termination-Action. nil leaves what the read has
	// (and sends none on a create, so the server's default). It has no "none":
	// a profile always reads one back, so a stated none could never converge.
	TerminationAction *RadiusTerminationAction
	// IdleTimeoutSecs is the Idle-Timeout. Absent leaves the read's; NullOf
	// states "none" and is left out of the body.
	IdleTimeoutSecs Nullable[int]
	// FilterID is the Filter-Id, one of the segment's FilterIDs. Absent leaves
	// the read's; NullOf states "none" and is left out of the body.
	FilterID Nullable[string]
	// ServiceType is the Service-Type. Absent leaves the read's; NullOf states
	// "none" and is left out of the body.
	ServiceType Nullable[RadiusServiceType]
}

// NetworkPolicySpec is the tenant's Session-Timeout cap, a singleton: the
// tenant has exactly one, so it has no key, and a manifest carries at most one
// (ManagementManifest.Network.Policy is a pointer, so a second one cannot be
// written). It is never Create (the default exists until the tenant first
// writes one, at version 0) and never pruned.
type NetworkPolicySpec struct {
	// SessionTimeoutMaxSecs is the cap, 300 to 86 400. The server judges it.
	SessionTimeoutMaxSecs int
}

// NetworkSpec is the `network` section of a ManagementManifest. The zero value
// is "no network section": a manifest without one plans exactly as it did
// before contract 1.62, with no network request at all.
type NetworkSpec struct {
	// Policy is the tenant's cap, or nil to leave it alone.
	Policy *NetworkPolicySpec
	// Segments are the segments, in the order they are planned and applied.
	Segments []NetworkSegmentSpec
	// Profiles are the reply profiles; they are planned in their segments' order.
	Profiles []NetworkProfileSpec
}

// isEmpty reports whether the manifest has no network section.
func (n NetworkSpec) isEmpty() bool {
	return n.Policy == nil && len(n.Segments) == 0 && len(n.Profiles) == 0
}

// segmentNaturalKey is site + kind + name, the wire spellings, compared as
// exact strings.
type segmentNaturalKey struct {
	site string
	kind NetworkSegmentKind
	name string
}

func (k segmentNaturalKey) String() string {
	return fmt.Sprintf("%s/%s/%s", k.site, k.kind, k.name)
}

// validateNetwork is §27.6.2 item 1's client-side refusals, run by Plan and
// Apply before any request: a duplicate segment key or natural key, a profile
// for one segment twice, a profile naming no segment of the manifest, and a
// Filter-Id listed twice in one segment.
func validateNetwork(n NetworkSpec) []string {
	var problems []string
	segmentKeys := map[string]bool{}
	naturalKeys := map[segmentNaturalKey]string{}
	var keyList []string
	for _, s := range n.Segments {
		segmentKeys[s.Key] = true
		keyList = append(keyList, s.Key)
		nk := segmentNaturalKey{s.Site, s.Kind, s.Name}
		if first, dup := naturalKeys[nk]; dup {
			problems = append(problems, fmt.Sprintf(
				"network segments %q and %q are both site %q, kind %q, name %q: one natural key "+
					"cannot be reconciled with one server row (§27.6.2 item 1)",
				first, s.Key, s.Site, s.Kind, s.Name))
		} else {
			naturalKeys[nk] = s.Key
		}
		seen := map[string]bool{}
		for _, f := range s.FilterIDs {
			if seen[f] {
				problems = append(problems, fmt.Sprintf(
					"network segment %q lists Filter-Id %q more than once; filter_ids is compared as a "+
						"set, and a set has no repeated member (§27.6.2 item 1)", s.Key, f))
			}
			seen[f] = true
		}
	}
	problems = append(problems, duplicateKeys("network segment", keyList)...)

	profiled := map[string]bool{}
	for _, p := range n.Profiles {
		if !segmentKeys[p.Segment] {
			problems = append(problems, fmt.Sprintf(
				"network profile names segment %q, which no network segment declares", p.Segment))
			continue
		}
		if profiled[p.Segment] {
			problems = append(problems, fmt.Sprintf(
				"network segment %q has more than one profile in the manifest: a profile is keyed by its "+
					"segment, and one natural key cannot be reconciled with one server row (§27.6.2 item 1)",
				p.Segment))
		}
		profiled[p.Segment] = true
	}
	return problems
}

// networkSnapshot is the network state a plan is computed against.
type networkSnapshot struct {
	policy   *NetworkPolicyResponse
	segments []NetworkSegmentResponse
	profiles []NetworkReplyProfile
}

// readNetwork is §27.6.2 item 3's reads, GETs only: get_policy when the manifest
// states one, list_segments when it has a segment or a profile, and
// list_profiles when it has a profile, each list walked to exhaustion.
func (a *ManifestAPI) readNetwork(ctx context.Context, n NetworkSpec, snap *snapshot) error {
	if n.isEmpty() {
		return nil
	}
	start := Limited(planPageSize)
	net := &networkSnapshot{}
	if n.Policy != nil {
		policy, err := a.c.Network().GetPolicy(ctx)
		if err != nil {
			return err
		}
		net.policy = &policy
	}
	if len(n.Segments) > 0 || len(n.Profiles) > 0 {
		segments, err := a.c.Network().ListSegmentsAll(ctx, "", start)
		if err != nil {
			return err
		}
		net.segments = segments
	}
	if len(n.Profiles) > 0 {
		profiles, err := a.c.Network().ListProfilesAll(ctx, start)
		if err != nil {
			return err
		}
		net.profiles = profiles
	}
	snap.network = net
	return nil
}

// The three payloads a network step carries. Each holds the READ the write is
// built from, so the version sent is the one Plan read (§27.6.2 item 4).
type networkPolicyChange struct {
	spec NetworkPolicySpec
	read NetworkPolicyResponse
}

type networkSegmentChange struct {
	spec NetworkSegmentSpec
	// read is nil for a Create.
	read *NetworkSegmentResponse
}

type networkProfileChange struct {
	spec NetworkProfileSpec
	// read is nil for a Create.
	read *NetworkReplyProfile
}

// sameSet reports whether a and b hold the same strings, ignoring order and
// repeats. Names compare as exact strings.
func sameSet(a, b []string) bool {
	in := func(list []string) map[string]bool {
		m := make(map[string]bool, len(list))
		for _, s := range list {
			m[s] = true
		}
		return m
	}
	ma, mb := in(a), in(b)
	if len(ma) != len(mb) {
		return false
	}
	for s := range ma {
		if !mb[s] {
			return false
		}
	}
	return true
}

// nullableDiffers reports whether a STATED Nullable differs from the read's
// optional value: absent says nothing, null differs from any value read, and a
// value differs from none or from another value.
func nullableDiffers[T comparable](stated Nullable[T], read *T) bool {
	switch {
	case stated.IsAbsent():
		return false
	case stated.IsNull():
		return read != nil
	}
	v, _ := stated.Get()
	return read == nil || *read != v
}

// planNetwork appends the network actions in §27.6.2 item 2's order: the
// policy, then the segments, then the profiles (the segments' order). It is
// pure, like computeSteps, and fills res with the ids and versions of what the
// read already holds.
func planNetwork(
	n NetworkSpec, snap *snapshot, res *resolved,
	push func(Change, Target, string, string, step),
) error {
	if n.isEmpty() {
		return nil
	}
	net := snap.network
	if net == nil {
		net = &networkSnapshot{}
	}

	if n.Policy != nil && net.policy != nil {
		summary := fmt.Sprintf("network policy (Session-Timeout cap %d s)", n.Policy.SessionTimeoutMaxSecs)
		if net.policy.SessionTimeoutMaxSecs != n.Policy.SessionTimeoutMaxSecs {
			push(ChangeUpdate, TargetNetworkPolicy, "network.policy", summary, step{
				kind: stepUpdateNetworkPolicy, key: "network.policy",
				spec: networkPolicyChange{spec: *n.Policy, read: *net.policy},
			})
		} else {
			push(ChangeNone, TargetNetworkPolicy, "network.policy", summary,
				step{kind: stepNoop, key: "network.policy"})
		}
	}

	for _, spec := range n.Segments {
		summary := fmt.Sprintf("network segment %q (site %q, %s)", spec.Name, spec.Site, spec.Kind)
		var existing *NetworkSegmentResponse
		for i := range net.segments {
			s := &net.segments[i]
			if s.SiteKey == spec.Site && s.Kind == spec.Kind && s.Name == spec.Name {
				existing = s
				break
			}
		}
		if existing == nil {
			push(ChangeCreate, TargetNetworkSegment, spec.Key, summary, step{
				kind: stepCreateNetworkSegment, key: spec.Key, spec: networkSegmentChange{spec: spec},
			})
			continue
		}
		res.networkSegments[spec.Key] = existing.ID
		res.networkSegmentVersions[spec.Key] = existing.Version
		if networkSegmentDrifted(spec, *existing) {
			push(ChangeUpdate, TargetNetworkSegment, spec.Key, summary, step{
				kind: stepUpdateNetworkSegment, key: spec.Key, spec: networkSegmentChange{spec: spec, read: existing},
			})
		} else {
			push(ChangeNone, TargetNetworkSegment, spec.Key, summary, step{kind: stepNoop, key: spec.Key})
		}
	}

	// A profile follows its segment: the profiles' order is the segments'.
	profiles := map[string]NetworkProfileSpec{}
	for _, p := range n.Profiles {
		profiles[p.Segment] = p
	}
	for _, seg := range n.Segments {
		spec, ok := profiles[seg.Key]
		if !ok {
			continue
		}
		summary := fmt.Sprintf("network profile of segment %q (site %q, %s)", seg.Name, seg.Site, seg.Kind)
		segmentID, segmentExists := res.networkSegments[seg.Key]
		var existing *NetworkReplyProfile
		if segmentExists {
			for i := range net.profiles {
				if net.profiles[i].SegmentID == segmentID {
					existing = &net.profiles[i]
					break
				}
			}
		}
		if existing == nil {
			push(ChangeCreate, TargetNetworkProfile, seg.Key, summary, step{
				kind: stepCreateNetworkProfile, key: seg.Key, spec: networkProfileChange{spec: spec},
			})
			continue
		}
		if networkProfileDrifted(spec, *existing) {
			if err := refuseUnknownProfileEnum(seg.Key, spec, *existing); err != nil {
				return err
			}
			push(ChangeUpdate, TargetNetworkProfile, seg.Key, summary, step{
				kind: stepUpdateNetworkProfile, key: seg.Key, spec: networkProfileChange{spec: spec, read: existing},
			})
		} else {
			push(ChangeNone, TargetNetworkProfile, seg.Key, summary, step{kind: stepNoop, key: seg.Key})
		}
	}
	return nil
}

// refuseUnknownProfileEnum is §27.6.2 item 4 as amended in 1.62: an update
// replaces the whole profile, so an open-enum value the read returned and this
// SDK does not know (termination_action, service_type) on a member the manifest
// does not state would be re-sent as the SDK's guess at what the server meant.
// plan refuses instead, before any write, naming the member and the value.
func refuseUnknownProfileEnum(segmentKey string, spec NetworkProfileSpec, read NetworkReplyProfile) error {
	if spec.TerminationAction == nil && !knownTerminationAction(read.TerminationAction) {
		return localRefusal("manifest.plan",
			fmt.Sprintf("network.profiles[%s].termination_action", segmentKey),
			fmt.Sprintf("the server reports termination_action %q, which this SDK does not know, and the manifest does not state it: refusing to re-send it", string(read.TerminationAction)))
	}
	if spec.ServiceType.IsAbsent() && read.ServiceType != nil && *read.ServiceType != RadiusServiceTypeFramedUser {
		return localRefusal("manifest.plan",
			fmt.Sprintf("network.profiles[%s].service_type", segmentKey),
			fmt.Sprintf("the server reports service_type %q, which this SDK does not know, and the manifest does not state it: refusing to re-send it", string(*read.ServiceType)))
	}
	return nil
}

func knownTerminationAction(a RadiusTerminationAction) bool {
	return a == RadiusTerminationActionDefault || a == RadiusTerminationActionRadiusRequest
}

// networkSegmentDrifted judges every STATED member on the read (§27.6.2 item 3).
// Site, kind and name are the key and so are never drift.
func networkSegmentDrifted(spec NetworkSegmentSpec, read NetworkSegmentResponse) bool {
	if spec.VlanID != read.VlanID {
		return true
	}
	if nullableDiffers(spec.Rank, read.Rank) {
		return true
	}
	if spec.FilterIDs != nil && !sameSet(spec.FilterIDs, read.FilterIDs) {
		return true
	}
	if spec.Enabled != nil && *spec.Enabled != read.Enabled {
		return true
	}
	return false
}

// networkProfileDrifted judges every STATED member on the effective profile the
// read returns, the clamped Session-Timeout included (§27.6.2 item 3).
func networkProfileDrifted(spec NetworkProfileSpec, read NetworkReplyProfile) bool {
	if spec.SessionTimeoutSecs != read.SessionTimeoutSecs {
		return true
	}
	if spec.TerminationAction != nil && *spec.TerminationAction != read.TerminationAction {
		return true
	}
	return nullableDiffers(spec.IdleTimeoutSecs, read.IdleTimeoutSecs) ||
		nullableDiffers(spec.FilterID, read.FilterID) ||
		nullableDiffers(spec.ServiceType, read.ServiceType)
}

// nullableOrRead resolves one optional member of a replacement body: absent
// carries the read's value, null is "none" and is left OUT, a value replaces.
func nullableOrRead[T any](stated Nullable[T], read *T) *T {
	switch {
	case stated.IsAbsent():
		if read == nil {
			return nil
		}
		v := *read
		return &v
	case stated.IsNull():
		return nil
	}
	v, _ := stated.Get()
	return &v
}

// runNetwork carries out one network step. The version of every write is the
// one Plan read, exactly, except a profile's segment_version, which is the
// response of the segment write an earlier step of the same Apply made, when
// it made one (§27.6.2 item 4). Nothing is repeated or refreshed.
func (a *ManifestAPI) runNetwork(ctx context.Context, s step, res *resolved) error {
	c := a.c
	switch s.kind {
	case stepUpdateNetworkPolicy:
		ch := s.spec.(networkPolicyChange)
		_, err := c.Network().ReplacePolicy(ctx,
			NewReplaceNetworkPolicyRequest(ch.spec.SessionTimeoutMaxSecs, ch.read.Version))
		return err

	case stepCreateNetworkSegment:
		spec := s.spec.(networkSegmentChange).spec
		body := CreateNetworkSegmentRequest{
			Kind: spec.Kind, SiteKey: spec.Site, Name: spec.Name, VlanID: spec.VlanID,
			FilterIDs: append([]string(nil), spec.FilterIDs...), Enabled: spec.Enabled,
		}
		if rank, ok := spec.Rank.Get(); ok {
			body.Rank = &rank
		}
		created, err := c.Network().CreateSegment(ctx, body)
		if err != nil {
			return err
		}
		res.networkSegments[s.key] = created.ID
		res.networkSegmentVersions[s.key] = created.Version
		return nil

	case stepUpdateNetworkSegment:
		ch := s.spec.(networkSegmentChange)
		spec, read := ch.spec, *ch.read
		filterIDs := append([]string{}, read.FilterIDs...)
		if spec.FilterIDs != nil {
			filterIDs = append([]string{}, spec.FilterIDs...) // the order the manifest states
		}
		enabled := read.Enabled
		if spec.Enabled != nil {
			enabled = *spec.Enabled
		}
		// kind, site_key and name are not in a replacement (§36.2).
		body := NewReplaceNetworkSegmentRequest(enabled, filterIDs, read.Version, spec.VlanID)
		body.Rank = nullableOrRead(spec.Rank, read.Rank)
		updated, err := c.Network().ReplaceSegment(ctx, read.ID, body)
		if err != nil {
			return err
		}
		res.networkSegmentVersions[s.key] = updated.Version
		return nil

	case stepCreateNetworkProfile:
		spec := s.spec.(networkProfileChange).spec
		input := NetworkReplyProfileInput{SessionTimeoutSecs: spec.SessionTimeoutSecs}
		input.TerminationAction = spec.TerminationAction
		input.IdleTimeoutSecs = nullableOrRead(spec.IdleTimeoutSecs, nil)
		input.FilterID = nullableOrRead(spec.FilterID, nil)
		input.ServiceType = nullableOrRead(spec.ServiceType, nil)
		_, err := c.Network().CreateProfile(ctx, CreateNetworkReplyProfileRequest{
			SegmentID:      res.networkSegments[spec.Segment],
			SegmentVersion: res.networkSegmentVersions[spec.Segment],
			Profile:        input,
		})
		return err

	case stepUpdateNetworkProfile:
		ch := s.spec.(networkProfileChange)
		spec, read := ch.spec, *ch.read
		input := NetworkReplyProfileInput{
			Dictionary:         ptr(read.Dictionary),
			SessionTimeoutSecs: spec.SessionTimeoutSecs,
		}
		input.TerminationAction = ptr(read.TerminationAction)
		if spec.TerminationAction != nil {
			input.TerminationAction = ptr(*spec.TerminationAction)
		}
		input.IdleTimeoutSecs = nullableOrRead(spec.IdleTimeoutSecs, read.IdleTimeoutSecs)
		input.FilterID = nullableOrRead(spec.FilterID, read.FilterID)
		input.ServiceType = nullableOrRead(spec.ServiceType, read.ServiceType)
		_, err := c.Network().ReplaceProfile(ctx, read.SegmentID, NewReplaceNetworkReplyProfileRequest(
			input, res.networkSegmentVersions[spec.Segment], read.Version))
		return err
	}
	return &NetworkError{Message: fmt.Sprintf("unknown network manifest step %q", s.kind)}
}
