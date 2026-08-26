package axiam

import (
	"context"
	"net/url"
	"sort"
	"strconv"
)

// Pagination for the §27 management surface.
//
// Twenty of the 146 operations take offset/limit and answer with the envelope
// {items, total, offset, limit}. The other thirteen collection reads answer
// with a bare array and are NOT paginated — §27.4 rule 4 forbids modelling
// those as a page, because a Page reporting Total == len(Items) is
// indistinguishable from a real one right up to the moment a caller relies on
// Total.

// PageRequest says where a paginated read starts and how much of it to take.
//
// Limit is deliberately a pointer with no SDK-side default: §27.4 rule 4
// forbids silently truncating, and a client-side default does exactly that
// while leaving the caller no way to tell a short page from a complete one.
// A nil Limit lets the server decide.
type PageRequest struct {
	// Offset is how many items to skip.
	Offset int
	// Limit is how many items to take. Nil lets the server decide.
	Limit *int
}

// Limited returns a PageRequest asking the server for n items per page.
func Limited(n int) PageRequest { return PageRequest{Limit: &n} }

// Page is one page of a paginated management read.
type Page[T any] struct {
	// Items are the items on this page.
	Items []T `json:"items"`
	// Total is how many items exist in the whole set, across every page.
	Total int `json:"total"`
	// Offset is the offset this page starts at.
	Offset int `json:"offset"`
	// Limit is the page size the server applied.
	Limit int `json:"limit"`
}

// HasMore reports whether another page follows p.
func (p Page[T]) HasMore() bool {
	return len(p.Items) > 0 && p.Offset+len(p.Items) < p.Total
}

// pageQuery is the query contribution of a PageRequest.
//
// limit is omitted entirely when unset rather than sent as 0 — the server
// reads limit=0 as "none", which would return an empty page.
func pageQuery(page PageRequest, into url.Values) url.Values {
	if into == nil {
		into = url.Values{}
	}
	into.Set("offset", strconv.Itoa(page.Offset))
	if page.Limit != nil {
		into.Set("limit", strconv.Itoa(*page.Limit))
	}
	return into
}

// collectPages walks a paginated read to exhaustion, concatenating every page.
//
// The ListAll shape §27.4 rule 4 requires. The walk stops on an empty page
// even when Total disagrees, so a misreporting server costs one wasted request
// rather than an unbounded loop.
func collectPages[T any](
	ctx context.Context,
	start PageRequest,
	fetch func(context.Context, PageRequest) (Page[T], error),
) ([]T, error) {
	request := start
	var out []T
	for {
		page, err := fetch(ctx, request)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		next := page.Offset + len(page.Items)
		if len(page.Items) == 0 || next >= page.Total {
			return out, nil
		}
		request = PageRequest{Offset: next, Limit: request.Limit}
	}
}

// sortedKeys returns m's keys in a stable order, so anything built from them
// is the same on every run.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
