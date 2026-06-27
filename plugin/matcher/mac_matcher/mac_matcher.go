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

package mac_matcher

import (
	"context"
	"io"

	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/matcher/macaddr"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "mac_matcher"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
	coremain.RegNewPersetPluginFunc("_has_mac_addr", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &hasMACAddr{BP: bp}, nil
	})
}

var _ coremain.MatcherPlugin = (*macMatcher)(nil)

type hasMACAddr struct {
	*coremain.BP
}

var _ coremain.MatcherPlugin = (*hasMACAddr)(nil)

func (h *hasMACAddr) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	return macaddr.ExtractFromMsg(qCtx.Q()) != nil, nil
}

// Args contains configuration for the mac_matcher plugin.
type Args struct {
	MacAddress []string `yaml:"mac_address"`
}

type macMatcher struct {
	*coremain.BP

	macMatcher *macaddr.LocalMatcherGroup
	closer     []io.Closer
}

func (m *macMatcher) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	mac := macaddr.ExtractFromMsg(qCtx.Q())
	if mac == nil {
		return false, nil
	}
	return m.macMatcher.Match(mac), nil
}

func (m *macMatcher) Close() error {
	for _, c := range m.closer {
		_ = c.Close()
	}
	return nil
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newMacMatcher(bp, args.(*Args))
}

func newMacMatcher(bp *coremain.BP, args *Args) (*macMatcher, error) {
	m := &macMatcher{
		BP: bp,
	}

	mg, err := macaddr.BatchLoadMacProvider(
		args.MacAddress,
		bp.M().GetDataManager(),
	)
	if err != nil {
		return nil, err
	}
	m.macMatcher = mg
	m.closer = append(m.closer, mg)
	bp.L().Info("mac address matcher loaded", zap.Int("length", mg.Len()))

	return m, nil
}

// Ensure executable_seq.Matcher interface is satisfied.
var _ executable_seq.Matcher = (*macMatcher)(nil)
