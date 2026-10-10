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
func (s SsfStream) ToInput() SsfStreamInput {
	return SsfStreamInput{
		Audience:         s.Audience,
		DeliveryMethod:   s.DeliveryMethod,
		Description:      s.Description,
		EndpointURL:      s.EndpointURL,
		EventsAllowed:    append([]SsfEventType(nil), s.EventsAllowed...),
		EventsRequested:  append([]SsfEventType(nil), s.EventsRequested...),
		ReceiverClientID: s.ReceiverClientID,
		Status:           ptr(s.Status),
		StatusReason:     s.StatusReason,
		SubjectFormat:    ptr(s.SubjectFormat),
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
