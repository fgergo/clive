package main

import (
	"clive/sre"
	"fmt"
	"io"
	"strings"
)

struct par {
	sc     chan<- string
	dc     chan bool
	right  bool
	fn     func(string) string
	out    io.Writer
	wid    int
	tab    string
	i0, in string
}

struct roffFmt {
	lvl int
	*par
}

func escRoff(s string) string {
	resc := rune(cmdEsc[0])
	rnoesc := rune(cmdNoEsc[0])
	ns := ""
	atnl := true
	noesc := false
	for _, r := range s {
		switch {
		case r == resc:
			noesc = true
			continue
		case r == rnoesc:
			noesc = false
			continue
		case noesc:
		case atnl && r == '.':
			ns += `\&.`
			atnl = false
			continue
		case atnl && r == '\'':
			ns += `\&'`
			atnl = false
			continue
		case r == '\\':
			ns += `\e`
			continue
		case r == '¯', r == '¸':
			r = '\\'
		case r == '©':
			ns += "(c)"
			continue
		case r > rune(0x7F):
			// Use groff escapes for all codepoints not in 7bits.
			// We might use named chars for common 8bit latin but
			// this is easier.
			ns += fmt.Sprintf(`\[u%04X]`, r)
			continue
		}
		ns += string(r)
		if r == '\n' {
			atnl = true
		} else if r != ' ' && r != '\t' {
			atnl = false
		}
	}
	return ns
}

var digits = []rune("⁰¹²³⁴⁵⁶⁷⁸⁹")

func footRef(d string) string {
	rs := []rune{}
	for _, r := range d {
		if r >= '0' && r <= '9' {
			rs = append(rs, digits[int(r)-int('0')])
		} else {
			rs = append(rs, r)
		}
	}
	return string(rs)
}

func (f *roffFmt) wrText(e *Elem) {
	if e == nil {
		return
	}
	switch e.Kind {
	case Kchap:
		f.printPar(labels[e.Kind]+" "+e.Nb, ": ")
	case Khdr1, Khdr2, Khdr3:
	case Kfoot:
		if e.Nb != "" {
			f.printPar(e.Nb, ". ")
		}
	default:
		if e.Nb != "" {
			f.printPar(e.Nb, " ")
		}
	}
	switch e.Kind {
	case Kit, Kbf, Ktt, Kitend, Kbfend, Kttend:
		f.wrFnt(e)
	case Kfont:
		f.printCmd(".ps %s\n", e.Data)
	case Kurl:
		toks := strings.SplitN(e.Data, "|", 2)
		if len(toks) == 1 {
			e.Data = "[" + e.Data + "]"
		} else {
			e.Data = toks[0] + " [" + toks[1] + "]"
		}
	case Kcite:
		rg, _ := sre.Match(mrexp, e.Data)
		if len(rg) == 3 {
			break
		}
		fallthrough
	case Kbib:
		e.Data = "[" + e.Data + "]"
	case Knref:
		e.Data = footRef(e.Data)
	case Kcref, Keref, Ktref, Kfref, Ksref:
	}
	f.printPar(e.Data)
	for _, c := range e.Textchild {
		f.wrText(c)
	}
}

var fnts = map[Kind]string{
	Kit:    "I",
	Kbf:    "B",
	Ktt:    "CW",
	Kitend: "R",
	Kbfend: "R",
	Kttend: "R",
}
var ifnts = map[Kind]string{
	Kit:    "I",
	Kbf:    "B",
	Ktt:    "(CW",
	Kitend: "P",
	Kbfend: "P",
	Kttend: "P",
}

var hdrs = map[Kind]string{
	Kchap: "SH",
	Khdr1: "NH",
	Khdr2: "NH 2",
	Khdr3: "NH 3",
}

func (f *roffFmt) wrFnt(e *Elem) {
	if e.Inline {
		f.printParCmd(`\f`, ifnts[e.Kind])
	} else {
		f.printCmd(".%s\n", fnts[e.Kind])
	}
}

func (f *roffFmt) wrCaption(e *Elem, tag string) {
	f.printCmd(".RS\n")
	if e.Caption == nil {
		f.printParCmd(fmt.Sprintf("\\fB%s %s.\\fP ", tag, e.Nb))
	} else {
		f.printParCmd(fmt.Sprintf("\\fB%s %s:\\fP \\fI", tag, e.Nb))
		f.wrText(e.Caption)
		f.printParCmd(`\fP`)
	}
	f.printCmd(".RE\n")
}

func (f *roffFmt) wrElems(els ...*Elem) {
	nb := 0
	inabs := false
	firstnh := false
	firstchap := true
	f.lvl++
	defer func() {
		f.lvl--
	}()
	for _, e := range els {
		switch e.Kind {
		case Kit, Kbf, Ktt, Kitend, Kbfend, Kttend:
			f.wrFnt(e)
		case Kfont:
			f.printCmd(".ps %s\n", e.Data)
		case Kcop:
			f.printCmd(".OF '(c) " + e.Data + " ' ' '\n")
			f.printCmd(".EF '(c) " + e.Data + " ' ' '\n")
		case Kchap, Khdr1, Khdr2, Khdr3:
			if e.Kind == Kchap {
				if firstchap {
					f.printCmd(".LP\n  \n")
					f.printCmd(".nr %% 0\n")
					f.printCmd(".bp\n")
				}
				firstchap = false
			}
			if inabs {
				f.printCmd(".AE\n")
				inabs = false
			}
			if strings.ToLower(e.Data) == "abstract" {
				if firstchap {
					f.printCmd(".AB\n")
					inabs = true
				}
				break
			}

			if e.Kind == Kchap {
				f.printCmd(".ds LH \n")
				f.printCmd(".ds RH \n")
				f.printCmd(".bp\n")
			}
			if firstnh && e.Kind == Khdr1 {
				f.printCmd(".bp\n")
				f.printCmd(".NH 0\n")
				firstnh = false
			} else {
				f.printCmd(".%s\n", hdrs[e.Kind])
			}
			if e.Kind == Kchap {
				f.printCmd(".ps +10\n")
				firstnh = true
			}
			f.wrText(e)
			if e.Kind == Kchap {
				ct := escRoff(labels[e.Kind])
				dt := escRoff(e.Data)
				f.printCmd(".br\n \n")
				f.printCmd(".ds LH " + ct + " " + e.Nb + "\n")
				f.printCmd(".ds RH " + dt + "\n")
			}
			f.printCmd(".XS\n")
			if e.Kind >= Khdr1 {
				f.printCmd("    " + e.Nb + " ")
			}
			if e.Kind >= Khdr2 {
				f.printCmd("    ")
			}
			if e.Kind >= Khdr3 {
				f.printCmd("    ")
			}
			f.wrText(e)
			f.printCmd(".XE\n")
			f.printCmd(".LP\n")
		case Kpar:
			f.printCmd("\n")
			if inabs {
				f.printCmd(".AE\n")
				inabs = false
			}
		case Kbr:
			f.printCmd(".br\n")
		case Kindent, Kitemize, Kenumeration, Kdescription:
			nb = 0
			f.printCmd(".P\n.RS\n")
			f.wrElems(e.Child...)
			f.printCmd(".RE\n")
		case Kname:
			f.closePar()
			f.printParCmd(`\(bu`)
			f.printPar(" ")
			switch e.NameKind {
			case Kit:
				f.printParCmd(`\fI`)
			case Ktt:
				f.printParCmd(`\f(CW`)
			default:
				f.printParCmd(`\fB`)
			}
			f.wrText(e)
			f.printParCmd(`\fP`)
			f.printCmd(".RS\n")
			f.wrElems(e.Child...)
			f.printCmd(".RE\n")
		case Kitem, Kenum:
			f.closePar()
			if e.Kind == Kitem {
				f.printCmd(".IP \\(bu\n")
			} else {
				nb++
				f.printCmd(".IP %d.\n", nb)
			}
			f.wrText(e)
		case Kverb, Ksh:
			f.printCmd(".DS\n")
			if e.Kind == Kverb && e.Tag != "" {
				f.printCmd(`\f(CB[` + e.Tag + `]\fP` + ":\n")
				f.printCmd(".br\n")
			}
			f.printCmd(".CW\n")
			f.printCmd(".ps -2\n")
			e.Data = indentVerb(e.Data, "", f.tab)
			f.printCmd("%s", escRoff(e.Data))
			f.printCmd(".ps +2\n")
			f.printCmd(".R\n")
			f.printCmd(".DE\n")
		case Kcode:
			e.Data = strings.TrimSpace(e.Data)
			e.Tag = strings.TrimSpace(e.Tag)
			f.printCmd(".DS\n")
			tag := labels[e.Kind]
			if e.Tag == "+" {
				// continued code, ignore tag
			} else if e.Tag == "" {
				f.printParCmd(fmt.Sprintf("\\fB%s %s.\\fP ", tag, e.Nb))
			} else {
				f.printParCmd(fmt.Sprintf("\\fB%s %s:\\fP \\fI", tag, e.Nb))
				f.printParCmd(`\fP`)
				f.printParCmd(`\f(CW`)
				f.printParCmd(escRoff(e.Tag))
				f.printParCmd(`\fP`)
			}
			f.printCmd(".br\n.CW\n")
			f.printCmd(".ps -2\n")
			e.Data = indentVerb(e.Data, "", f.tab)
			f.printCmd("%s", escRoff(e.Data))
			f.printCmd(".ps +2\n")
			f.printCmd(".R\n")
			f.printCmd(".DE\n")
		case Kfoot:
			f.printCmd(".FS\n")
			f.wrText(e)
			f.printCmd(".FE\n")
		case Ktext, Kurl, Kbib, Kcref, Knref, Keref, Ktref, Kfref, Ksref, Kcite:
			f.wrText(e)
		case Kfig, Kpic, Kgrap:
			f.closePar()
			f.printCmd(".KF\n")
			e.Data = strings.TrimSpace(e.Data)
			if e.Kind == Kgrap {
				f.printCmd(".G1\n%s\n.G2\n", e.Data)
			} else if e.Kind == Kfig {
				f.printCmd(".PSPIC %s\n", e.epsfig())
			} else {
				f.printCmd(".PS\n")
				f.printCmd("%s\n", e.Data)
				f.printCmd(".PE\n")
			}
			f.wrCaption(e, labels[e.Kind])
			f.printCmd(".KE\n")
		case Ktbl:
			f.closePar()
			f.printCmd(".KF\n")
			f.lvl += 2
			f.wrTbl(e.Tbl)
			f.lvl -= 2
			f.wrCaption(e, labels[e.Kind])
			f.printCmd(".KE\n")
		case Keqn:
			f.printCmd(".KF\n")
			f.printCmd(".EQ\n")
			f.printCmd("%s\n", e.Data)
			f.printCmd(".EN\n")
			f.wrCaption(e, labels[e.Kind])
			f.printCmd(".KE\n")
		}
	}
	f.closePar()
}

func (f *roffFmt) wrTbl(rows [][]string) {
	if len(rows) < 2 || len(rows[0]) < 2 || len(rows[1]) < 2 {
		return
	}
	f.printCmd(".TS\n")
	f.printCmd("center allbox;\n")
	fmtr := rows[0]
	fmtr[0] = "lB"
	for i := 0; i < len(fmtr); i++ {
		if i > 0 {
			f.printCmd(" ")
		}
		f.printCmd("cB")
	}
	f.printCmd("\n")
	for i := 0; i < len(fmtr); i++ {
		if i > 0 {
			f.printCmd(" ")
		}
		f.printCmd("%s", fmtr[i])
	}
	f.printCmd(".\n")

	rows = rows[1:]
	rows[0][0] = ""
	for _, r := range rows {
		for i, c := range r {
			if i > 0 {
				f.printCmd("\t")
			}
			f.printCmd("%s", c)
		}
		f.printCmd("\n")
	}
	f.printCmd(".TE\n")
}

func (f *roffFmt) wrBib(refs []string) {
	if len(refs) == 0 {
		return
	}
	f.printCmd(".SH\n")
	if eflag {
		f.printCmd("Referencias\n")
	} else {
		f.printCmd("References\n")
	}
	f.printCmd(".OH 'Refs.' ' ' \n")
	f.printCmd(".EH ' ' 'Refs.' \n")
	f.printCmd(".LP\n.SM\n")
	for i, r := range refs {
		f.printPar(fmt.Sprintf("%d. %s", i+1, r))
		f.printCmd(".br\n")
	}
	f.printCmd(".NS\n")
}

func (f *roffFmt) run(t *Text) {
	fmt.Fprintln(f.out)
	els := t.Elems
	n := 0
	for len(els) > 0 && els[0].Kind == Ktitle {
		switch n {
		case 0:
			f.printCmd(".TL\n")
		case 1:
			f.printCmd(".AU\n")
		default:
			f.printCmd(".br\n")
		}
		n++
		f.wrText(els[0])
		f.closePar()
		els = els[1:]
	}
	f.printCmd("\n")
	f.wrElems(els...)
	f.closePar()
	if t.nchap > 0 {
		f.printCmd(".br\n")
		f.printCmd(".OH '' ' ' \n")
		f.printCmd(".EH ' ' '' \n")
		f.printCmd(".bp\n")
	}
	f.wrBib(t.bibrefs)
	f.closePar()
	if t.nchap > 0 {
		f.printCmd(".bp\n")
		f.printCmd(".TC\n")
	}
}

// roff writer
func wrroff(t *Text, wid int, out io.Writer, outfig string) {
	f := &roffFmt{
		par: &par{fn: escRoff, out: out, wid: wid, tab: "    "},
	}
	f.run(t)
}
