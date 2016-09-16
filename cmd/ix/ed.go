package main

import (
	"clive/cmd"
	"clive/cmd/look"
	"clive/cmd/run"
	"clive/net/ink"
	"clive/txt"
	"clive/zx"
	"errors"
	"fmt"
	"net/url"
	fpath "path"
	"strconv"
	"strings"
	"time"
)

// Command run within an edit.
struct Cmd {
	ed    *Ed
	name  string
	mark  string
	hasnl bool
	p     *run.Proc
	all   bool // replace all text with output, for c.pipe()
}

struct Dot {
	P0, P1 int
}

// edit
struct Ed {
	tag     string
	dir     string
	d       zx.Dir
	dot     Dot
	ix      *IX
	win     *ink.Txt
	winid   string
	markgen int
	gone    bool
	ncmds   int
	waitc   chan func()
	ctx     *cmd.Ctx
	temp    bool    // don't save, don't ever flag as dirty
	iscmd   bool    // it's a command win, used by the event loop
	laddr   zx.Addr // last look addr
}

var notDirty = errors.New("not dirty")

func (d Dot) String() string {
	return fmt.Sprintf(":#%d,#%d", d.P0, d.P1)
}

func (ix *IX) delEd(ed *Ed) int {
	ix.Lock()
	defer ix.Unlock()
	ed.gone = true
	if ix.dot == ed {
		ix.dot = nil
	}
	if ix.msgs == ed {
		ix.msgs = nil
		for _, e := range ix.eds {
			if e != ed && e.iscmd {
				ix.msgs = e
			}
		}
	}
	for i, e := range ix.eds {
		if e == ed {
			copy(ix.eds[i:], ix.eds[i+1:])
			ix.eds = ix.eds[:len(ix.eds)-1]
			ix.pg.Del(ed.winid)
			return ed.ncmds
		}
	}
	return ed.ncmds
}

func (ix *IX) addCmd(c *Cmd) {
	ix.Lock()
	defer ix.Unlock()
	ix.cmds = append(ix.cmds, c)
	c.ed.ncmds++
}

func (ix *IX) delCmd(c *Cmd) int {
	ix.Lock()
	defer ix.Unlock()
	c.ed.ncmds--
	for i, e := range ix.cmds {
		if e == c {
			copy(ix.cmds[i:], ix.cmds[i+1:])
			ix.cmds = ix.cmds[:len(ix.cmds)-1]
			break
		}
	}
	return c.ed.ncmds
}

func (ix *IX) goneEd(ed *Ed) bool {
	ix.Lock()
	defer ix.Unlock()
	return ed.gone
}

func (ix *IX) newEd(tag string) *Ed {
	win := ink.NewTxt()
	win.SetTag(tag)
	win.ClientDoesUndoRedo()
	win.SetFont("t")
	ed := &Ed{win: win, ix: ix, tag: tag, waitc: make(chan func())}
	ed.dir = cmd.Dot()
	return ed
}

func (ix *IX) newCmds(dir, tag string) *Ed {
	if tag == "" {
		tag = fmt.Sprintf("ql!%d!%s", ix.newId(), dir)
	}
	d, err := cmd.Stat(dir)
	if err != nil {
		if ix.msgs != nil {
			ix.Warn("newCmds: %s", err)
		} else {
			cmd.Warn("newCmds: %s", err)
		}
		return nil
	}
	if d["type"] != "d" {
		if ix.msgs != nil {
			ix.Warn("newCmds: %s: not a directory", dir)
		} else {
			cmd.Warn("newCmds: %s: not a directory", dir)
		}
		return nil
	}
	ed := ix.newEd(tag)
	ed.temp = true
	ed.iscmd = true
	ed.d = zx.Dir{
		"type": "-",
		"path": tag,
		"name": fpath.Base(tag),
	}
	ix.Lock()
	defer ix.Unlock()
	ix.eds = append(ix.eds, ed)
	if ix.msgs == nil {
		ix.msgs = ed
	}
	// We can't make the editLoop the new ctx main func because:
	// 1. commands may reopen the window and
	// recreate it while commands run. So the context must
	// wait for all outstanding commands to die.
	// 2. the new windows must have their event loops in the same
	// context, or changes in the NS/env/... will be gone.
	ed.ctx = cmd.New(func() {
		if err := cmd.Cd(dir); err != nil {
			go ed.win.Ins([]rune("can't cd to "+dir+": "+err.Error()+"\n"), 0)
		}
		ed.editLoop()
		// new command loops are sent to waitc
		for fn := range ed.waitc {
			if fn != nil {
				fn()
			}
		}
		cmd.Dprintf("%s context done\n", ed)
	})
	return ed
}

func (ix *IX) newEdit(path string) *Ed {
	ed := ix.newEd(path)
	ix.Lock()
	defer ix.Unlock()
	ix.eds = append(ix.eds, ed)
	ed.ctx = cmd.New(func() {
		cmd.ForkDot()
		cmd.Cd(fpath.Dir(ed.tag))
		cmd.Dprintf("edit %s dot %s\n", ed.tag, cmd.Dot())
		ed.editLoop()
		// new command loops are sent to waitc
		for fn := range ed.waitc {
			if fn != nil {
				fn()
			}
		}
		cmd.Dprintf("%s context done\n", ed)
	})
	return ed
}

func (ix *IX) reopen(ed *Ed) {
	ix.Lock()
	defer ix.Unlock()
	if !ed.gone {
		return
	}
	ed.gone = false
	for _, e := range ix.eds {
		if e == ed {
			return
		}
	}
	win := ink.NewTxt()
	win.SetTag(ed.tag)
	win.ClientDoesUndoRedo()
	win.SetFont("t")
	for _, m := range ed.win.Marks() {
		win.SetMark(m, 0)
	}
	ed.win = win
	ed.temp = true
	ix.eds = append(ix.eds, ed)
	ed.waitc <- ed.editLoop
	ed.winid, _ = ix.pg.Add(win)
}

func (ed *Ed) String() string {
	return ed.win.Tag()
}

func (ed *Ed) menuLine() string {
	switch {
	case ed.iscmd:
		return "> " + ed.tag
	case ed.temp:
		return "/ " + ed.tag
	case ed.win.IsDirty():
		return "! " + ed.tag
	default:
		return "- " + ed.tag
	}
}

func (ed *Ed) replDot(s string) {
	some := false
	t := ed.win.GetText()
	defer ed.win.PutText()
	rs := []rune(s)
	if ed.dot.P1 > ed.dot.P0 {
		t.Del(ed.dot.P0, ed.dot.P1-ed.dot.P0)
		ed.dot.P1 = ed.dot.P0
	}
	if len(rs) > 0 {
		t.ContdEdit()
		t.Ins(rs, ed.dot.P0)
		ed.dot.P1 = ed.dot.P0 + len(rs)
	}
	ed.win.SetSel(ed.dot.P0, ed.dot.P1)
	return
	// This is how we should do it, but it's quite slow
	// Safari takes a very long time to post the ins events
	// perhaps because we take some time in js to process
	// them, although safari delay is like 30s (!!) and
	// we take just a bit of time.
	// It seems that a plain reload is a lot faster, because it
	// just adds the data as it comes to the lines array in js
	// and then updates everything.
	if ed.dot.P1 > ed.dot.P0 {
		some = true
		ed.win.Del(ed.dot.P0, ed.dot.P1-ed.dot.P0)
	}
	if len(rs) > 0 {
		some = true
		ed.win.ContdEdit()
		ed.win.Ins(rs, ed.dot.P0)
	}
	if some {
		ed.dot.P1 = ed.dot.P0 + len(rs)
		// sets p0 and p1 marks
		ed.win.SetSel(ed.dot.P0, ed.dot.P1)
	}
}

func (ed *Ed) newMark(pos int) string {
	ed.markgen++
	m := fmt.Sprintf("cmd%d", ed.markgen)
	ed.win.SetMark(m, pos)
	return m
}

func (ed *Ed) Addr() zx.Addr {
	ln0, ln1 := ed.win.LinesAt(ed.dot.P0, ed.dot.P1)
	return zx.Addr{
		Name: ed.tag,
		Ln0:  ln0,
		Ln1:  ln1,
		P0:   ed.dot.P0,
		P1:   ed.dot.P1,
	}
}

func (ed *Ed) SetAddr(a zx.Addr) {
	p0, p1 := a.P0, a.P1
	if a.Ln0 != 0 && a.Ln1 != 0 && p0 == 0 && p1 == 0 {
		p0, p1 = ed.win.LinesOff(a.Ln0, a.Ln1)
	}
	ed.dot.P0 = p0
	ed.dot.P1 = p1
	cmd.Dprintf("%s: dot set to %s (%s) for %s\n", ed, ed.dot, ed.Addr(), a)
	a.P0, a.P1 = p0, p1
	ed.laddr = a
	ed.win.SetSel(p0, p1)
}

func (c *Cmd) printf(f string, args ...face{}) {
	s := fmt.Sprintf(f, args...)
	if !c.hasnl {
		s = "\n" + s
		c.hasnl = true
	}
	if c.ed.gone {
		ix.reopen(c.ed)
	}
	if err := c.ed.win.MarkIns(c.mark, []rune(s)); err != nil {
		cmd.Warn("mark ins: %s", err)
	}
}

func (ed *Ed) runCmd(at int, line string) {
	cmd.Dprintf("run cmd %s at %d\n", line, at)
	hasnl := len(line) > 0 && line[len(line)-1] == '\n'
	ln := strings.TrimSpace(line)
	if len(ln) == 0 {
		return
	}
	args := strings.Fields(ln)
	// If the command is the name of a dir, then use cd dir
	// if it's a commands window, or reload the window in
	// another dir for dir windows.
	if len(args) == 1 {
		d, err := cmd.Stat(args[0])
		if err == nil && d["type"] == "d" {
			if !ed.iscmd && !ed.temp {
				ed.look(d["path"])
				return
			}
			if !ed.iscmd {
				ed.tag = d["path"]
				if ed.tag != "/" {
					ed.tag += "/"
				}
				ed.load(d)
				ed.win.SetTag(ed.tag)
				return
			}
			args = []string{"cd", args[0]}
		}
	}
	if !ed.iscmd && !ed.temp {
		ced := ed.ix.lookCmds(ed.dir, 0)
		// command on a plain edit window, locate or start
		// a commands window in the same dir.
		if ced != nil {
			ed = ced
		}
	}
	c := &Cmd{
		name:  args[0],
		ed:    ed,
		mark:  ed.newMark(at),
		hasnl: hasnl,
	}
	if b := builtin(args[0]); b != nil {
		b(c, args...)
		// We don't del the output mark for builtins,
		// Some will keep bg processes and must defer that.
		// Thus builtins del their mark.
		return
	}
	args = append([]string{"ql", "-uc"}, args...)
	inkc := make(chan face{})
	setio := func(c *cmd.Ctx) {
		c.ForkEnv()
		c.ForkNS()
		c.ForkDot()
		c.SetOut("ink", inkc)
	}
	p, err := run.CtxCmd(setio, args...)
	if err != nil {
		c.printf("error: %s\n", err)
		ed.win.DelMark(c.mark)
		return
	}
	c.p = p
	ed.ix.addCmd(c)
	go c.io(hasnl)
	go c.inkio(inkc)
}

func (ed *Ed) lookFiles(name string) {
	dc := cmd.Dirs(name)
	for d := range dc {
		d, ok := d.(zx.Dir)
		if !ok || d["type"] != "-" {
			continue
		}
		ed.ix.lookFile(d["path"], "", -1)
	}
	if err := cerror(dc); err != nil {
		ed.ix.Warn("look: %s", err)
	}
}

func (ed *Ed) look(what string) {
	s := strings.TrimSpace(what)
	c, err := rules.CmdFor(s)
	if err == nil {
		cmd.Dprintf("look rule %q\n", s)
		ed.exec(c, s)
		return
	}
	if err != look.ErrNoMatch {
		ed.ix.Warn("look: %s", err)
		return
	}
	names := strings.SplitN(s, ":", 2)
	d, err := cmd.Stat(names[0])
	if err == nil {
		names[0] = d["path"]
		// It's a file
		if len(names) == 1 {
			names = append(names, "")
		} else {
			names[1] = ":" + names[1]
		}
		cmd.Dprintf("look file %q %q\n", names[0], names[1])
		ed.ix.lookFile(names[0], names[1], -1)
		return
	}
	if strings.HasPrefix(s, "file:///zx/") {
		n := len("file://")
		s = "https://localhost:8181" + s[n:]
	}
	if strings.HasPrefix(s, "https://") {
		toks := strings.Split(s, "|")
		uri, err := url.Parse(toks[0])
		if err == nil && uri.IsAbs() {
			cmd.Dprintf("look url %q\n", s)
			ed.ix.lookURL(s)
			return
		}
	}
	cmd.Dprintf("look files %q\n", s)
	ed.lookFiles(s)
}

func (ed *Ed) exec(what, tag string) {
	what = strings.TrimSpace(what)
	if len(what) == 0 {
		return
	}
	cmd.Dprintf("exec %s\n", what)
	if tag == "" {
		tag = what
	} else {
		tag = strings.TrimSpace(tag)
	}
	if len(tag) > 50 {
		tag = tag[:50] + "..."
	}
	args := strings.Fields(what)
	c := &Cmd{
		name: args[0],
		ed:   ed,
	}
	c.exec(tag, args...)
}

func (ed *Ed) hasText(rs []rune, p0 int) bool {
	if p0 < 0 || p0 >= ed.win.Len() {
		return false
	}
	for i := range rs {
		if r := ed.win.Getc(p0 + i); r != rs[i] {
			return false
		}
	}
	return true
}

func (ed *Ed) findText(rs []rune, p0 int) int {
	for ; p0 < ed.win.Len(); p0++ {
		if ed.hasText(rs, p0) {
			return p0
		}
	}
	return -1
}
func (ed *Ed) lookText(what string, p0 int) {
	rs := []rune(what)
	pos := ed.findText(rs, p0)
	cmd.Dprintf("look text %s: %q %d -> %d\n", ed, what, p0, pos)
	if pos < 0 && p0 > 0 {
		pos = ed.findText(rs, 0)
	}
	if pos >= 0 {
		ed.dot.P0 = pos
		ed.dot.P1 = pos + len(rs)
		cmd.Dprintf("%s: dot set to %s (%s)\n", ed, ed.dot, ed.Addr())
		ed.win.SetSel(ed.dot.P0, ed.dot.P1)
	}
}

func (ed *Ed) click248(ev *ink.Ev) {
	if len(ev.Args) < 4 {
		cmd.Warn("edit: short click24 event")
		return
	}
	p0, err := strconv.Atoi(ev.Args[2])
	if err != nil {
		cmd.Warn("bad p0 in click24 event")
		return
	}
	p1, err := strconv.Atoi(ev.Args[3])
	if err != nil {
		cmd.Warn("bad p1 in click24 event")
		return
	}
	if (ev.Args[0] == "click2" || ev.Args[0] == "click4") &&
		len(strings.TrimSpace(ev.Args[1])) == 0 {
		return
	}
	if ev.Args[0] == "click2" {
		go ed.runCmd(p1, ev.Args[1])
	} else if ev.Args[0] == "click8" {
		what := ed.ix.lookstr
		if what == "" {
			what = ev.Args[1]
		}
		ed.refreshDot()
		go ed.lookText(what, ed.dot.P1)
	} else if p0 == ed.laddr.P0 && p1 == ed.laddr.P1 {
		go ed.ix.lookNext(ed.laddr)
	} else {
		go ed.look(ev.Args[1])
	}
}

func (ed *Ed) clear() {
	ed.win.SetSel(0, 0)
	t := ed.win.GetText()
	defer ed.win.PutText()
	t.DelAll()
	t.Ins([]rune("\n"), 0)
	t.DropEdits()
}

func (ed *Ed) undoRedo(isredo bool) bool {
	t := ed.win.GetText()
	some := false
	var e *txt.Edit
	for {
		if !isredo {
			e = t.Undo()
		} else {
			e = t.Redo()
		}
		if e == nil {
			cmd.Dprintf("%s: no more undos/redos\n", ed)
			break
		}
		some = true
		cmd.Dprintf("%s: undo/redo\n", ed)
		ed.dot.P0 = e.Off
		ed.dot.P1 = e.Off
		if e.Op == txt.Eins {
			ed.dot.P1 += len(e.Data)
		}
		if !e.Contd {
			break
		}
	}
	ed.win.PutText()
	if some {
		ed.win.SetSel(ed.dot.P0, ed.dot.P1)
	}
	return some
}

func (ed *Ed) move(to string) error {
	to = cmd.AbsPath(to)
	d, err := cmd.Stat(to)
	if err == nil && d["type"] == "d" {
		return fmt.Errorf("%s: %s", to, zx.ErrIsDir)
	}
	ed.tag = to
	ed.win.SetTag(ed.tag)
	return nil
}

func (ed *Ed) wasChanged() error {
	nd, err := cmd.Stat(ed.tag)
	if err != nil {
		return nil
	}
	if nd["type"] != ed.d["type"] {
		return errors.New("file type changed")
	}
	// Some file systems can't record with more
	// granularity than seconds.
	// That's the best we can check.
	nt := nd.Time("mtime").Truncate(time.Second)
	ot := ed.d.Time("mtime").Truncate(time.Second)
	if !nt.Equal(ot) {
		ed.d["mtime"] = nd["mtime"]
		return fmt.Errorf("file read on %v changed by %s on %v",
			ot, nd["wuid"], nt)
	}
	return nil
}

func (ed *Ed) save() error {
	if !ed.win.IsDirty() {
		cmd.Dprintf("save: %s not dirty\n", ed.tag)
		ed.win.Clean()
		return notDirty
	}
	if dryrun {
		cmd.Warn("not saving %s: dry run", ed)
		ed.win.Clean()
		return notDirty
	}
	if ed.d["type"] != "-" {
		// not a regular file
		cmd.Dprintf("save: %s type '%s' not saved\n", ed.tag, ed.d["type"])
		ed.win.Clean()
		return notDirty
	}
	if err := ed.wasChanged(); err != nil {
		return err
	}
	defer ed.win.Clean()
	dc := make(chan []byte)
	rc := cmd.Put(ed.tag, zx.Dir{"type": "-"}, 0, dc)
	tc := ed.win.Get(0, -1)
	for rs := range tc {
		dat := []byte(string(rs))
		if ok := dc <- dat; !ok {
			close(tc, cerror(dc))
			break
		}
	}
	close(dc)
	rd := <-rc
	if err := cerror(rc); err != nil {
		ed.ix.Warn("save %s: %s", ed, err)
		return err
	}
	if mt, ok := rd["mtime"]; ok {
		ed.d["mtime"] = mt
	}
	return nil
}

func (ed *Ed) load(nd zx.Dir) error {
	what := ed.tag
	if nd == nil {
		d, err := cmd.Stat(what)
		if err != nil {
			return err
		}
		nd = d
	}
	ed.d = nd
	t := ed.win.GetText()
	defer ed.win.PutText()
	if t.Len() > 0 {
		t.DelAll()
	}
	t.DropEdits()
	var dc <-chan []byte
	if ed.d["type"] == "d" {
		ed.temp = true
		if ed.temp {
			ed.win.DoesntGetDirty()
		}
		c := make(chan []byte)
		dc = c
		go func() {
			ds, err := cmd.GetDir(what)
			for _, d := range ds {
				c <- []byte(d.Fmt()+"\n")
			}
			close(c, err)
		}()
	} else {
		dc = cmd.Get(what, 0, -1)
	}
	for m := range dc {
		runes := []rune(string(m))
		t.ContdEdit()
		if err := t.Ins(runes, t.Len()); err != nil {
			close(dc, err)
			cmd.Warn("%s: insert: %s", what, err)
		}
	}
	err := cerror(dc)
	if err != nil {
		ed.ix.Warn("%s: get: %s", what, err)
	}
	ed.win.Clean()
	return err
}

func (ed *Ed) refreshDot() {
	if ed.win == nil {
		return
	}
	if p0 := ed.win.Mark("p0"); p0 != nil {
		ed.dot.P0 = p0.Off
	}
	if p1 := ed.win.Mark("p1"); p1 != nil {
		ed.dot.P1 = p1.Off
	}
}

func (ed *Ed) editLoop() {
	if ed.iscmd {
		cmd.ForkDot()
		cmd.ForkNS()
		cmd.ForkEnv()
	}
	cmd.Dprintf("%s started\n", ed)
	c := ed.win.Events()
	for ev := range c {
		ev := ev
		cmd.Dprintf("ix ev %v\n", ev)
		switch ev.Args[0] {
		case "focus":
			ed.ix.dot = ed
		case "tick":
			ed.refreshDot()
		case "click1":
			ed.ix.lookstr = ev.Args[1]
		case "click2", "click4", "click8":
			ed.click248(ev)
		case "end":
			if len(ed.win.Views()) == 0 {
				cmd.Dprintf("%s w/o views\n", ed)
			}
		case "quit":
			n := ed.ix.delEd(ed)
			cmd.Dprintf("%s terminated\n", ed)
			close(c, "quit")
			if n == 0 {
				close(ed.waitc)
			}
			return
		case "clear":
			if ed.iscmd {
				ed.clear()
			} else {
				ed.load(nil)
			}
		case "eundo", "eredo":
			if ed.undoRedo(ev.Args[0] == "eredo") {
				ed.win.Dirty()
			}
		}
		if !ed.iscmd {
			switch ev.Args[0] {
			case "eins", "edel":
				ed.win.Dirty()
			case "save":
				ed.save()
			}
		}
	}
	cmd.Dprintf("%s terminated\n", ed)
	n := ed.ix.delEd(ed)
	if n == 0 {
		close(ed.waitc)
	}
}
