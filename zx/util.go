package zx

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// Make sure s is an absolute path and return it cleaned and never empty.
func UseAbsPath(s string) (string, error) {
	if len(s) == 0 || s[0] != '/' {
		return "", fmt.Errorf("'%s' is not an absolute path", s)
	}
	return path.Clean(s), nil
}

// Return path elements, empty for /
func Elems(p string) []string {
	if p == "/" || p == "" {
		return []string{}
	}
	if p[0] == '/' {
		p = p[1:]
	}
	return strings.Split(p, "/")
}

// Return true if pref is a prefix path of p (or the same path)
func HasPrefix(p, pref string) bool {
	if pref == "" {
		return true
	}
	p = path.Clean(p)
	pref = path.Clean(pref)
	if len(pref) > len(p) {
		return false
	}
	if !strings.HasPrefix(p, pref) {
		return false
	}
	return pref == "/" || len(p) == len(pref) || p[len(pref)] == '/'
}

// Make a path starting with / for elems
func Path(elems ...string) string {
	s := strings.Join(elems, "/")
	s = "/" + s
	return path.Clean(s)
}

// Return the suffix of p relative to base
// Both paths must be absolute or both relative.
// Pref can be empty.
// If there's no such suffix, the empty string is returned.
// The suffix starts with '/' and is "/" if b == p
func Suffix(p, pref string) string {
	if len(p) == 0 {
		return ""
	}
	p = path.Clean(p)
	if pref == "" {
		return p
	}
	pref = path.Clean(pref)
	if (pref[0] == '/') != (p[0] == '/') {
		return ""
	}
	if pref == "." || pref == "/" {
		return p
	}
	np := len(p)
	npref := len(pref)
	if np < npref {
		return ""
	}
	switch {
	case !strings.HasPrefix(p, pref):
		return ""
	case np == npref:
		return "/"
	case p[npref] != '/':
		return ""
	default:
		return p[npref:]
	}
}

// returns -1,0, or 1 if the path a is found before, at or after b
// like string compare but operates on one element at a time to compare.
func PathCmp(path0, path1 string) int {
	els0 := Elems(path0)
	els1 := Elems(path1)
	for i := 0; i < len(els0) && i < len(els1); i++ {
		if els0[i] < els1[i] {
			return -1
		}
		if els0[i] > els1[i] {
			return 1
		}
	}
	if len(els0) < len(els1) {
		return -1
	}
	if len(els0) > len(els1) {
		return 1
	}
	return 0
}

// Match expr against any element name if it's not /...
// or match it against any prefix of p
func PathPrefixMatch(p, exp string) bool {
	els := Elems(exp)
	pels := Elems(p)
	if len(els) == 0 {
		return true
	}
	if len(pels) < len(els) {
		return false
	}
	var m bool
	var err error
	n := len(els)
	if exp[0] != '/' {
		n = len(pels)
	}
	for i := 0; i < n; i++ {
		if exp[0] == '/' {
			m, err = filepath.Match(els[i], pels[i])
			if err != nil {
				return false
			}
			if !m {
				return false
			}
		} else {
			m, err = filepath.Match(exp, pels[i])
			if err != nil {
				return false
			}
			if m {
				return true
			}
		}
	}
	return exp[0] == '/'
}
