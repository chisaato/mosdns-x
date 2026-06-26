package elem

// StrMatcher matches a string against a set of predefined strings.
type StrMatcher struct {
	m map[string]struct{}
}

// NewStrMatcher inits a new StrMatcher.
func NewStrMatcher(elem []string) *StrMatcher {
	m := &StrMatcher{m: make(map[string]struct{}, len(elem))}
	for _, v := range elem {
		m.m[v] = struct{}{}
	}
	return m
}

// Match checks if v is in the set.
func (m *StrMatcher) Match(v string) bool {
	_, ok := m.m[v]
	return ok
}

// Len returns the number of strings in the matcher.
func (m *StrMatcher) Len() int {
	return len(m.m)
}
