package axiam

// Local checks the generated §27 surface runs before any I/O, and the
// hand-written conveniences around the generated models (CONTRACT.md §29 –
// §32).
//
// The generator (internal/cmd/genmanagement, `prechecks`) emits a call to a
// check here at the top of an operation's call builder; nothing here performs
// I/O.

import "github.com/google/uuid"

// checkParseSAMLSpMetadata is §29.2: ParseSAMLSpMetadata is EXACTLY ONE of
// MetadataXml and MetadataURL. Both or neither is a local *ValidationError,
// raised before any request — never a request the server refuses.
func checkParseSAMLSpMetadata(body ParseSAMLSpMetadata) error {
	switch {
	case body.MetadataXml != nil && body.MetadataURL != nil:
		return localRefusal("saml.parse_sp_metadata", "metadata_xml",
			"set exactly one of metadata_xml and metadata_url, not both (CONTRACT.md §29.2)")
	case body.MetadataXml == nil && body.MetadataURL == nil:
		return localRefusal("saml.parse_sp_metadata", "metadata_url",
			"set exactly one of metadata_xml and metadata_url (CONTRACT.md §29.2)")
	}
	return nil
}

// ParseSAMLSpMetadataFromURL is a parse request for the server to fetch the
// SP's metadata from metadataURL (https only, through its SSRF guard).
func ParseSAMLSpMetadataFromURL(metadataURL string) ParseSAMLSpMetadata {
	return ParseSAMLSpMetadata{MetadataURL: &metadataURL}
}

// ParseSAMLSpMetadataFromXML is a parse request carrying the SP's metadata
// document itself (at most 512 KiB).
func ParseSAMLSpMetadataFromXML(metadataXML string) ParseSAMLSpMetadata {
	return ParseSAMLSpMetadata{MetadataXml: &metadataXML}
}

// The read-modify-write forms §27.4 rule 5 recommends for the `replace`
// updates: a read result turned back into the replacement body, every member
// carried over, so changing one field and sending it back preserves the rest.
// None of them carries a secret — the reads never return one — so each leaves
// the write-only member absent, which keeps the stored value unless the write
// moves the URL it is bound to.

// ToInput is the SAMLServiceProviderInput that re-states this service
// provider exactly — the start of an UpdateServiceProvider (§29.2: an omitted
// member takes its default, not its stored value).
//
// An ACS binding or SloBinding this SDK does not know is copied as read; the
// contract forbids SENDING one (§29.2), so replace it before writing back.
func (sp SAMLServiceProvider) ToInput() SAMLServiceProviderInput {
	return SAMLServiceProviderInput{
		AcsUrls:                 append([]AcsEndpoint(nil), sp.AcsUrls...),
		AllowIdpInitiated:       ptr(sp.AllowIdpInitiated),
		AllowedGroups:           append([]uuid.UUID(nil), sp.AllowedGroups...),
		AttributeMappings:       append([]AttributeMapping(nil), sp.AttributeMappings...),
		DisplayName:             sp.DisplayName,
		Enabled:                 ptr(sp.Enabled),
		EncryptAssertions:       ptr(sp.EncryptAssertions),
		EntityID:                sp.EntityID,
		NameIDFormat:            ptr(sp.NameIDFormat),
		SignResponses:           ptr(sp.SignResponses),
		SloBinding:              sp.SloBinding,
		SloURL:                  sp.SloURL,
		SpEncryptionCertPEM:     sp.SpEncryptionCertPEM,
		SpSigningCertPEM:        sp.SpSigningCertPEM,
		WantAuthnRequestsSigned: ptr(sp.WantAuthnRequestsSigned),
	}
}

// ToInput is the SsfStreamInput that re-states this stream — the start of an
// UpdateStream. AuthorizationHeader is absent, which keeps the stored header
// (§32.2), and so is ClearAuthorizationHeader.
//
// EventsRequested is always the list this read carried, never nil: a receiver
// that narrowed the stream to nothing reads as an empty list and goes back as
// [], because an absent member would reset the stream to every event of
// EventsAllowed (§32.2, contract 1.61). ExpectedUpdatedAt is this read's
// UpdatedAt, exactly as the server sent it: the UpdateStream then lands only if
// nobody — the receiver included — has written the stream since this read, and
// is 409 otherwise (ConflictError, never retried); reload and retry. Set it to
// nil to fall back to the server's own read-time check (last writer wins).
//
// THE CALLER'S DUTY (§32.2, contract 1.62): this converter cannot know that you
// are about to lower EventsAllowed, so if you do, YOU must cut EventsRequested
// to the new ceiling before the UpdateStream — an EventsRequested entry outside
// EventsAllowed is refused 400 — and you must keep the three meanings of
// EventsRequested apart: nil (absent) resets the stream to every allowed event,
// an empty non-nil list is the receiver's "none", a list is stored as given.
// To have the cut done for you, use ToInputWith.
func (s SsfStream) ToInput() SsfStreamInput {
	in := SsfStreamInput{
		Audience:         s.Audience,
		DeliveryMethod:   s.DeliveryMethod,
		Description:      s.Description,
		EndpointURL:      s.EndpointURL,
		EventsAllowed:    append([]SsfEventType{}, s.EventsAllowed...),
		EventsRequested:  append([]SsfEventType{}, s.EventsRequested...),
		ReceiverClientID: s.ReceiverClientID,
		Status:           ptr(s.Status),
		StatusReason:     s.StatusReason,
		SubjectFormat:    ptr(s.SubjectFormat),
	}
	if s.UpdatedAt != "" {
		in.ExpectedUpdatedAt = ptr(s.UpdatedAt)
	}
	return in
}

// SsfStreamChanges are the edits ToInputWith applies over a stream that was
// read. Every member is optional and the zero value changes nothing, so a
// literal names only what the caller means to change.
//
// The pointer members are "unchanged" when nil. The Nullable members (the ones
// the server can hold as none) are "unchanged" when absent, set when ValueOf,
// and cleared when NullOf: a cleared member is left OUT of the body, which on a
// replacement is how it returns to its default — null is never sent (§27.11
// rule 5, contract 1.62).
type SsfStreamChanges struct {
	// Audience replaces the stream's audience.
	Audience *string
	// AuthorizationHeader is the push endpoint's Authorization header. A read
	// never carries one, so it is only ever stated here; it is required again
	// when EndpointURL moves to another scheme, host or port (§32.3 rule 5).
	AuthorizationHeader *Sensitive
	// ClearAuthorizationHeader removes the stored header. Refused together with
	// AuthorizationHeader.
	ClearAuthorizationHeader *bool
	// DeliveryMethod replaces the delivery method.
	DeliveryMethod *SsfDeliveryMethod
	// Description sets or (NullOf) clears the description.
	Description Nullable[string]
	// EndpointURL sets or (NullOf) clears the push endpoint.
	EndpointURL Nullable[string]
	// EventsAllowed replaces the administrator's ceiling. When it is non-nil
	// and EventsRequested is nil, the read's EventsRequested is cut to it.
	EventsAllowed []SsfEventType
	// EventsRequested, when non-nil, is sent exactly as given: the server judges
	// it (400 outside the ceiling). An empty non-nil list is the receiver's
	// "none". Nil leaves what was read (cut to a new EventsAllowed).
	EventsRequested []SsfEventType
	// ExpectedUpdatedAt replaces the read's UpdatedAt, which is what the body
	// carries otherwise. NullOf sends no such member, so the replacement is
	// conditional only on the version the server reads during the request
	// (last writer wins).
	ExpectedUpdatedAt Nullable[string]
	// ReceiverClientID replaces the receiver's OAuth2 client.
	ReceiverClientID *string
	// Status replaces the stream's status.
	Status *SsfStreamStatus
	// StatusReason sets or (NullOf) clears the status reason.
	StatusReason Nullable[string]
	// SubjectFormat replaces the subject format.
	SubjectFormat *SsfSubjectFormat
}

// ToInputWith is the change-taking read-modify-write form for a stream
// (CONTRACT §32.2, contract 1.62): the SsfStreamInput for an UpdateStream that
// applies changes over this read.
//
// It sends the EventsRequested and the ExpectedUpdatedAt AS READ — the
// server's own string, untouched, and an empty list as []. When the changes
// lower EventsAllowed and do not name EventsRequested, it CUTS EventsRequested
// to the new ceiling: the entries of the read list that the new EventsAllowed
// still holds, in their order (an outcome of none stays [], never absent, which
// would reset the stream to every allowed event). An EventsRequested named in
// the changes is sent as given and judged by the server. AuthorizationHeader
// and ClearAuthorizationHeader are absent unless the changes state them, which
// keeps the stored header.
//
// The plain converter, ToInput, remains; it cannot know the ceiling is about
// to move, and cutting is the caller's duty there.
func (s SsfStream) ToInputWith(changes SsfStreamChanges) SsfStreamInput {
	in := s.ToInput()
	if changes.Audience != nil {
		in.Audience = *changes.Audience
	}
	if changes.DeliveryMethod != nil {
		in.DeliveryMethod = *changes.DeliveryMethod
	}
	if changes.ReceiverClientID != nil {
		in.ReceiverClientID = *changes.ReceiverClientID
	}
	if changes.Status != nil {
		in.Status = changes.Status
	}
	if changes.SubjectFormat != nil {
		in.SubjectFormat = changes.SubjectFormat
	}
	applyNullable(&in.Description, changes.Description)
	applyNullable(&in.EndpointURL, changes.EndpointURL)
	applyNullable(&in.StatusReason, changes.StatusReason)
	applyNullable(&in.ExpectedUpdatedAt, changes.ExpectedUpdatedAt)
	in.AuthorizationHeader = changes.AuthorizationHeader
	in.ClearAuthorizationHeader = changes.ClearAuthorizationHeader

	switch {
	case changes.EventsRequested != nil:
		in.EventsRequested = append([]SsfEventType{}, changes.EventsRequested...)
	case changes.EventsAllowed != nil:
		ceiling := make(map[SsfEventType]bool, len(changes.EventsAllowed))
		for _, e := range changes.EventsAllowed {
			ceiling[e] = true
		}
		cut := []SsfEventType{}
		for _, e := range in.EventsRequested {
			if ceiling[e] {
				cut = append(cut, e)
			}
		}
		in.EventsRequested = cut
	}
	if changes.EventsAllowed != nil {
		in.EventsAllowed = append([]SsfEventType{}, changes.EventsAllowed...)
	}
	return in
}

// applyNullable applies a Nullable change to an optional string member: absent
// leaves the member as read, a value sets it, and null — "none" — clears it, so
// the key is left out of the body and null is never sent.
func applyNullable(dst **string, change Nullable[string]) {
	switch {
	case change.IsAbsent():
	case change.IsNull():
		*dst = nil
	default:
		v, _ := change.Get()
		*dst = &v
	}
}

// ToInput is the SCIMTargetInput that re-states this target — the start of an
// Update. Credential is absent, which keeps the stored one unless the write
// moves its URL (§31.3 rule 2). ExpectedUpdatedAt is this read's UpdatedAt,
// exactly as the server sent it (§31.3 rule 4, contract 1.60): the Update then
// lands only if nobody has written the target since this read, and is 409
// otherwise — reload and retry. Set it to nil to fall back to the server's own
// read-time check (last writer wins).
func (t SCIMTargetResponse) ToInput() SCIMTargetInput {
	in := SCIMTargetInput{
		Auth:         t.Auth,
		BaseURL:      t.BaseURL,
		Deprovision:  ptr(t.Deprovision),
		Enabled:      ptr(t.Enabled),
		Name:         t.Name,
		PushGroups:   ptr(t.PushGroups),
		Scope:        t.Scope,
		UserNameFrom: ptr(t.UserNameFrom),
	}
	if t.UpdatedAt != "" {
		in.ExpectedUpdatedAt = ptr(t.UpdatedAt)
	}
	return in
}

// ToInput is the SetDirectoryConfig that re-states this configuration — the
// start of a Set. BindSecret is absent, which keeps the stored secret unless
// the write moves the connection (§30.3 rule 2).
func (c DirectoryConfig) ToInput() SetDirectoryConfig {
	return SetDirectoryConfig{
		BaseDn:               c.BaseDn,
		BindDn:               c.BindDn,
		Enabled:              c.Enabled,
		GroupBaseDn:          c.GroupBaseDn,
		GroupFilter:          c.GroupFilter,
		GroupMappings:        append([]GroupMapping(nil), c.GroupMappings...),
		GroupMemberAttribute: ptr(c.GroupMemberAttribute),
		GroupNestingDepth:    ptr(c.GroupNestingDepth),
		JitProvisioning:      ptr(c.JitProvisioning),
		Kind:                 c.Kind,
		StartTLS:             c.StartTLS,
		SyncIntervalSecs:     ptr(c.SyncIntervalSecs),
		TrustAnchorsPEM:      append([]string(nil), c.TrustAnchorsPEM...),
		URL:                  c.URL,
		UserAttributeMap:     ptr(c.UserAttributeMap),
		UserFilter:           c.UserFilter,
	}
}
