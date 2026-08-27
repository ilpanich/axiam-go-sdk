package axiam

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"
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
	// Search is a free-text filter applied by the SERVER, before Offset/Limit.
	//
	// Matched case-insensitively against the identifying fields of whatever is
	// being listed — a name or username, plus the record id, so a UUID out of a
	// log line can be pasted in as-is. Page.Total then counts MATCHES, not rows,
	// which is what lets a pager built on it show a page count belonging to the
	// result set it is paging.
	//
	// It lives here rather than as a third argument on each of the twenty
	// generated List methods (§27.4 rule 4), and that is what makes ListAll
	// carry it across the whole walk — a walk that filtered its first request
	// and not the rest would return the matches followed by the unfiltered tail.
	//
	// The zero value sends no search parameter. A term that is all whitespace is
	// treated the same way: a search box that fires on every keystroke sends one
	// the moment it is cleared, and "rows containing the empty string" is a
	// different question from "all rows".
	//
	// The server caps the term's length. This SDK deliberately does not
	// re-implement that cap — a client-side truncation the server would not have
	// made is a silently different query.
	Search string
}

// Limited returns a PageRequest asking the server for n items per page.
func Limited(n int) PageRequest { return PageRequest{Limit: &n} }

// Matching returns a PageRequest of n items per page, filtered by term.
//
// The §27.4 rule 4 shape: the term rides on the page request, so ListAll
// carries it across every request of the walk rather than only the first.
func Matching(n int, term string) PageRequest {
	return PageRequest{Limit: &n, Search: term}
}

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
// reads limit=0 as "none", which would return an empty page. search is omitted
// when unset AND when blank, so an unfiltered read and a read whose box was
// cleared are the same request on the wire.
func pageQuery(page PageRequest, into url.Values) url.Values {
	if into == nil {
		into = url.Values{}
	}
	into.Set("offset", strconv.Itoa(page.Offset))
	if page.Limit != nil {
		into.Set("limit", strconv.Itoa(*page.Limit))
	}
	if term := normalizeSearch(page.Search); term != "" {
		into.Set("search", term)
	}
	return into
}

// normalizeSearch is the trimmed term, or "" when there is nothing to filter on.
//
// Mirrors the server's own normalisation minus the length cap, which is the
// server's to apply — see PageRequest.Search.
func normalizeSearch(term string) string { return strings.TrimSpace(term) }

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
		// Search is carried, not dropped (§27.4 rule 4). A walk that filtered
		// only its first request would concatenate the matches with the
		// unfiltered remainder, which reads as a server bug from the caller's
		// side.
		request = PageRequest{Offset: next, Limit: request.Limit, Search: request.Search}
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
