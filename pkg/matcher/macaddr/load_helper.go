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

package macaddr

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/pmkol/mosdns-x/pkg/data_provider"
)

// LocalMatcher defines the interface for MAC address matching in load_helper.
type LocalMatcher interface {
	Match(mac net.HardwareAddr) bool
	Len() int
	Close() error
}

// LocalWriteableMatcher defines the interface for adding MAC addresses in load_helper.
type LocalWriteableMatcher interface {
	LocalMatcher
	Add(pattern string, v struct{}) error
}

// Load loads a MAC address string to the matcher.
func Load(m LocalWriteableMatcher, s string) error {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return nil
	}
	return m.Add(s, struct{}{})
}

// BatchLoad loads multiple MAC address strings to the matcher.
func BatchLoad(m LocalWriteableMatcher, b []string) error {
	for _, s := range b {
		if err := Load(m, s); err != nil {
			return fmt.Errorf("failed to load data %s: %w", s, err)
		}
	}
	return nil
}

type LocalMatcherGroup struct {
	g      []LocalMatcher
	closer []func()
}

func (mg *LocalMatcherGroup) Close() error {
	for _, f := range mg.closer {
		f()
	}
	return nil
}

func (mg *LocalMatcherGroup) Match(mac net.HardwareAddr) bool {
	for _, m := range mg.g {
		if m.Match(mac) {
			return true
		}
	}
	return false
}

func (mg *LocalMatcherGroup) Len() int {
	s := 0
	for _, m := range mg.g {
		s += m.Len()
	}
	return s
}

func (mg *LocalMatcherGroup) Append(nm LocalMatcher) {
	mg.g = append(mg.g, nm)
}

func (mg *LocalMatcherGroup) AppendCloser(f func()) {
	mg.closer = append(mg.closer, f)
}

// BatchLoadMacProvider loads multiple data entries.
// Caller must call LocalMatcherGroup.Close to detach this matcher from data_provider.DataManager to avoid leaking.
func BatchLoadMacProvider(
	e []string,
	dm *data_provider.DataManager,
) (*LocalMatcherGroup, error) {
	mg := &LocalMatcherGroup{}
	staticMatcher := NewMatcher()
	mg.Append(staticMatcher)

	for _, s := range e {
		if strings.HasPrefix(s, "provider:") {
			providerTag := strings.TrimPrefix(s, "provider:")
			provider := dm.GetDataProvider(providerTag)
			if provider == nil {
				return nil, fmt.Errorf("cannot find provider %s", providerTag)
			}
			parseFunc := func(b []byte) (LocalMatcher, error) {
				return ParseTextMacFile(b)
			}
			dmMatcher := NewDynamicMatcher(parseFunc)
			if err := provider.LoadAndAddListener(dmMatcher); err != nil {
				return nil, fmt.Errorf("failed to load data from provider %s, %w", providerTag, err)
			}
			mg.Append(dmMatcher)
			mg.AppendCloser(func() {
				provider.DeleteListener(dmMatcher)
			})
		} else {
			if err := Load(staticMatcher, s); err != nil {
				return nil, fmt.Errorf("failed to load data %s: %w", s, err)
			}
		}
	}
	return mg, nil
}

// LoadFromTextReader loads multiple lines from reader r.
func LoadFromTextReader(m LocalWriteableMatcher, r io.Reader) error {
	lineCounter := 0
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lineCounter++
		s := scanner.Text()
		s = strings.TrimSpace(s)
		if len(s) == 0 || strings.HasPrefix(s, "#") {
			continue
		}
		if err := Load(m, s); err != nil {
			return fmt.Errorf("line %d: %w", lineCounter, err)
		}
	}
	return scanner.Err()
}

type DynamicMatcher struct {
	parserFunc func(b []byte) (LocalMatcher, error)
	l          sync.RWMutex
	m          LocalMatcher
}

func NewDynamicMatcher(parserFunc func(b []byte) (LocalMatcher, error)) *DynamicMatcher {
	return &DynamicMatcher{parserFunc: parserFunc}
}

func (d *DynamicMatcher) Match(mac net.HardwareAddr) bool {
	d.l.RLock()
	m := d.m
	d.l.RUnlock()
	if m == nil {
		return false
	}
	return m.Match(mac)
}

func (d *DynamicMatcher) Len() int {
	d.l.RLock()
	m := d.m
	d.l.RUnlock()
	if m == nil {
		return 0
	}
	return m.Len()
}

func (d *DynamicMatcher) Close() error {
	d.l.RLock()
	m := d.m
	d.l.RUnlock()
	if m != nil {
		return m.Close()
	}
	return nil
}

func (d *DynamicMatcher) Update(b []byte) error {
	m, err := d.parserFunc(b)
	if err != nil {
		return err
	}
	d.l.Lock()
	d.m = m
	d.l.Unlock()
	return nil
}

// ParseTextMacFile parses MAC addresses from text bytes.
func ParseTextMacFile(in []byte) (*Matcher, error) {
	m := NewMatcher()
	if err := LoadFromTextReader(m, bytes.NewReader(in)); err != nil {
		return nil, err
	}
	return m, nil
}

// Ensure LocalMatcherGroup implements LocalMatcher.
var _ LocalMatcher = (*LocalMatcherGroup)(nil)

// Ensure *Matcher implements LocalMatcher and LocalWriteableMatcher.
var _ LocalMatcher = (*Matcher)(nil)
var _ LocalWriteableMatcher = (*Matcher)(nil)

// Ensure DynamicMatcher implements LocalMatcher.
var _ LocalMatcher = (*DynamicMatcher)(nil)