/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package adg_forward

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	dnsproxy_upstream "github.com/AdguardTeam/dnsproxy/upstream"
)

// defaultPassthroughCacheSize is used when client_id_passthrough is enabled
// but passthrough_cache_size is not configured (or <= 0).
const defaultPassthroughCacheSize = 16

// closeUpstreamGroup closes every upstream in a variant group, releasing their
// connection pools. Used on LRU eviction and on shutdown.
func closeUpstreamGroup(ups []dnsproxy_upstream.Upstream) {
	for _, u := range ups {
		u.Close()
	}
}

// clientIDsKey returns an order-insensitive cache key for a set of client IDs.
// ["accel", "intl"] and ["intl", "accel"] both map to "accel/intl" so that a
// single variant upstream group is reused regardless of the incoming order.
func clientIDsKey(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	sorted := make([]string, len(ids))
	copy(sorted, ids)
	sort.Strings(sorted)
	return strings.Join(sorted, "/")
}

// buildVariantAddr appends each client ID as a single escaped path segment to
// the path of rawAddr.
//
// For example, base "https://hub.example:4215/dns-query" with ids
// ["accel", "international"] yields
// "https://hub.example:4215/dns-query/accel/international".
//
// Each ID is escaped independently with url.PathEscape, so an ID containing a
// literal "/" (e.g. "a/b", which the server decoded from "a%2Fb") is emitted as
// a single segment "a%2Fb" and does not split into two. u.Path (decoded) and
// u.RawPath (escaped) are kept consistent so that url.URL.String re-encodes
// correctly.
func buildVariantAddr(rawAddr string, ids []string) (string, error) {
	u, err := url.Parse(rawAddr)
	if err != nil {
		return "", err
	}

	base := strings.TrimRight(u.EscapedPath(), "/")
	segments := make([]string, 0, len(ids))
	for _, id := range ids {
		segments = append(segments, url.PathEscape(id))
	}
	escaped := base + "/" + strings.Join(segments, "/")

	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return "", err
	}
	u.RawPath = escaped
	u.Path = decoded

	return u.String(), nil
}

// upstreamsForIDs returns the upstream group for the given client IDs, building
// and caching a variant group lazily. An empty ids slice returns the base group
// unchanged.
func (f *adgForward) upstreamsForIDs(ids []string) ([]dnsproxy_upstream.Upstream, error) {
	if len(ids) == 0 {
		return f.rawUpstreams, nil
	}

	key := clientIDsKey(ids)
	if ups, ok := f.passthroughCache.Get(key); ok {
		return ups, nil
	}

	// Serialize builds so concurrent queries for the same/new key do not create
	// duplicate upstream groups (and leak their connection pools).
	f.passthroughMu.Lock()
	defer f.passthroughMu.Unlock()

	if ups, ok := f.passthroughCache.Get(key); ok {
		return ups, nil
	}

	addrs := make([]string, 0, len(f.args.Upstream))
	for _, c := range f.args.Upstream {
		addr, err := buildVariantAddr(c.Addr, ids)
		if err != nil {
			return nil, fmt.Errorf("failed to build client_id variant for %s: %w", c.Addr, err)
		}
		addrs = append(addrs, addr)
	}

	ups, err := f.buildUpstreamGroup(addrs)
	if err != nil {
		return nil, err
	}
	f.passthroughCache.Add(key, ups)
	return ups, nil
}
