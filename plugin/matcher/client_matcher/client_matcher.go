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

package client_matcher

import (
	"context"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/matcher/elem"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "client_matcher"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.MatcherPlugin = (*clientMatcher)(nil)

type Args struct {
	ClientID []string `yaml:"client_id"`
}

type clientMatcher struct {
	*coremain.BP

	matcher *elem.StrMatcher
}

func (m *clientMatcher) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	id := qCtx.ReqMeta().GetClientID()
	if id == "" {
		return false, nil
	}
	return m.matcher.Match(id), nil
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newClientMatcher(bp, args.(*Args))
}

func newClientMatcher(bp *coremain.BP, args *Args) (*clientMatcher, error) {
	return &clientMatcher{
		BP:      bp,
		matcher: elem.NewStrMatcher(args.ClientID),
	}, nil
}
