/*
	Clive command tools and interfaces

	Each application has a context including

		- A set of IO channels

		- A name space

		- A dot path

		- A set of environment variables

		- A wait channel and exit status


	Importing this package initializes a command context for
	the underlying OS environment.
	Further commands may be created within the same OS process
	with different contexts if so desired.
	They may later change or dup the resources used.

	All IO channels carry interface{} messages,
	which usually are a series of zx.Dir{} []byte and error messages.
	Other data may be sent as well.
	In some cases it's context or app. specific data
	not to be forwarded outside of the system.

	All commands are expected to forward messages not understood
	and process those they understand along the way, in very much
	the same way a roff pipeline works.

	The name space is constructed by the first method that works:
		1. Using $NS as the description (see ns.Parse).
		2. Using the contents of $HOME/NS as the description.
		3. Using "/"
	Methods 2 and 3 set $NS to the resulting name space.
*/
package cmd

import (
	"bytes"
	"clive/dbg"
	"clive/ns"
	"errors"
	"fmt"
	"os"
	"os/signal"
	fpath "path"
	"runtime"
	"strings"
	"sync"
)

// Command context.
// In, Out, and Err carry []byte as data, but may carry other pieces of
// data as context (eg., zx.Dir)
// When fed into external processes, non []byte messages are discarded.
struct Ctx {
	lk   sync.Mutex
	id   int64    // AppId() for this ctx
	Args []string // command line arguments
	wc   chan error

	ns  *ns.NS  // name space
	dot *cwd    // dot
	env *envSet // environment
	io  *ioSet  // io chans

	Debug, Verb bool
}

var (
	ctxs  = map[int64]*Ctx{}
	ctxlk sync.Mutex

	ErrIO = errors.New("no such IO chan")

	mainctx *Ctx
)

// Return the current command application context.
func AppCtx() *Ctx {
	ctxlk.Lock()
	defer ctxlk.Unlock()
	id := runtime.AppId()
	c := ctxs[id]
	if c == nil {
		return nil
	}
	return c
}

func ctx() *Ctx {
	c := AppCtx()
	if c == nil {
		dbg.Warn("no context for %d", runtime.AppId())
		panic("no context")
	}
	return c
}

func (c *Ctx) close(sts string) {
	if c != nil {
		if sts != "" {
			close(c.wc, sts)
		} else {
			close(c.wc)
		}
		c.io.close()
		ctxlk.Lock()
		delete(ctxs, c.id)
		ctxlk.Unlock()
	}
}

func mkCtx() *Ctx {
	wc := make(chan error)
	c := &Ctx{
		Args: os.Args,
		wc:   wc,
		env:  mkEnv(),
		io:   mkIO(),
		dot:  mkDot(),
	}
	if len(c.Args) > 0 {
		c.Args[0] = fpath.Base(c.Args[0])
	}
	ctxlk.Lock()
	runtime.NewApp() // we use the main AtExit for our main proc
	c.id = runtime.AppId()
	ctxs[c.id] = c
	ctxlk.Unlock()
	c.ns = mkNS()
	runtime.AtExit(func() {
		close(wc)
	})
	return c
}

// Run the given function in a new process on a new context and return its context.
// If wc is supplied, the new function won't run until wc is closed and the caller has
// time to adjust the new context for the function to run, eg. to set the Args, etc.
// The new conext shares everything with the parent, but for io, which is a dup.
func New(fun func(), wc ...chan bool) *Ctx {
	ctxc := make(chan *Ctx, 1)
	var w chan bool
	if wc != nil {
		w = wc[0]
	}
	go func() {
		if runtime.GoId() == runtime.AppId() {
			panic("cmd.New() already called on this proc")
		}
		old := ctx()
		old.lk.Lock()
		env := old.env
		ns := old.ns
		dot := old.dot
		dbg, verb := old.Debug, old.Verb
		io := old.io.dup()
		args := make([]string, len(old.Args))
		for i := range old.Args {
			args[i] = old.Args[i]
		}
		old.lk.Unlock()
		wc := make(chan error)
		c := &Ctx{
			Args: args,
			wc:   wc,
			env:  env,
			io:   io,
			dot:  dot,
			ns:   ns,
		}
		c.Debug, c.Verb = dbg, verb
		c.id = runtime.NewApp()
		ctxlk.Lock()
		ctxs[c.id] = c
		ctxlk.Unlock()
		ctxc <- c
		if w != nil {
			<-w
		}
		defer func() {
			if r := recover(); r != nil {
				if s, ok := r.(string); ok && strings.HasPrefix(s, "appexit") {
					c.close(s[7:])
					return
				}
				c.close("")
				// We could decide that an app panic
				// is not a panic for others not in the main app.
				// In that case, this should go.
				panic(r)
				return
			} else {
				c.close("")
			}
		}()
		fun()
	}()

	return <-ctxc
}

func (c *Ctx) ForkDot() {
	c.lk.Lock()
	defer c.lk.Unlock()
	c.dot = c.dot.dup()
}

func ForkDot() {
	ctx().ForkDot()
}

func (c *Ctx) ForkNS() {
	c.lk.Lock()
	defer c.lk.Unlock()
	c.ns = c.ns.Dup()
}

func ForkNS() {
	ctx().ForkNS()
}

func (c *Ctx) ForkEnv() {
	c.lk.Lock()
	defer c.lk.Unlock()
	c.env = c.env.dup()
}

func ForkEnv() {
	ctx().ForkEnv()
}

func (c *Ctx) ForkIO() {
	c.lk.Lock()
	defer c.lk.Unlock()
	nio := c.io.dup()
	oio := c.io
	c.io = nio
	oio.close()
}

func ForkIO() {
	ctx().ForkIO()
}

func Args() []string {
	return ctx().Args
}

func (c *Ctx) NS() *ns.NS {
	c.lk.Lock()
	defer c.lk.Unlock()
	return c.ns
}

func NS() *ns.NS {
	return ctx().NS()
}

func (c *Ctx) Dot() string {
	c.lk.Lock()
	d := c.dot
	c.lk.Unlock()
	return d.get()
}

func Dot() string {
	return ctx().Dot()
}

func (c *Ctx) Cd(to string) error {
	c.lk.Lock()
	d := c.dot
	c.lk.Unlock()
	return d.set(to)
}

func Cd(to string) error {
	d, err := Stat(to)
	if err != nil {
		return fmt.Errorf("cd: %s", err)
	}
	return ctx().Cd(d["path"])
}

func (c *Ctx) GetEnv(name string) string {
	c.lk.Lock()
	defer c.lk.Unlock()
	return c.env.get(name)
}

func EnvList(val string) []string {
	// rc seems to use \1 for lists
	if val == "" {
		return []string{}
	}
	val = strings.Replace(val, "\001", "\b", -1)
	return strings.Split(val, "\b")
}

func EnvMap(env string) map[string][]string {
	if env == "" {
		return map[string][]string{}
	}
	toks := strings.Split(env, "\a")
	if len(toks) > 0 {
		toks = toks[1:]
	}
	m := map[string][]string{}
	for _, t := range toks {
		lst := EnvList(t)
		if len(lst) == 0 {
			continue
		}
		m[lst[0]] = lst[1:]
	}
	return m
}

func Path() []string {
	pval := GetEnvList("path")
	if len(pval) == 0 {
		ospath := GetEnv("PATH")
		pval = strings.Split(ospath, ":")
	}
	if len(pval) == 0 {
		return []string{"/bin", "/usr/bin", "."}
	}
	return pval
}

// Returns "" if there's no such cmd in the path.
// Returns the absolute path for cmd if it's /... or ./... or ../...
func LookPath(cmd string) string {
	if strings.HasPrefix(cmd, "/") || strings.HasPrefix(cmd, "./") ||
		strings.HasPrefix(cmd, "../") {
		path := AbsPath(cmd)
		if fi, err := os.Stat(path); err == nil {
			if !fi.IsDir() && fi.Mode()&0111 != 0 {
				return path
			}
		}
		return ""
	}
	for _, d := range Path() {
		path := fpath.Join(d, cmd)
		if fi, err := os.Stat(path); err == nil {
			if !fi.IsDir() && fi.Mode()&0111 != 0 {
				return path
			}
		}
	}
	return ""
}

func MapEnv(m map[string][]string) string {
	s := ""
	for k, v := range m {
		lst := append([]string{k}, v...)
		s += "\a" + ListEnv(lst)
	}
	return s
}

func IsEnvMap(value string) bool {
	return strings.ContainsRune(value, '\a')
}

func ListEnv(lst []string) string {
	return strings.Join(lst, "\b")
}

func GetEnvList(v string) []string {
	return EnvList(GetEnv(v))
}

func GetEnvMap(v string) map[string][]string {
	return EnvMap(GetEnv(v))
}

func SetEnvList(v string, val []string) {
	SetEnv(v, ListEnv(val))
}

func SetEnvMap(v string, val map[string][]string) {
	SetEnv(v, MapEnv(val))
}

func GetEnv(v string) string {
	return ctx().GetEnv(v)
}

func (c *Ctx) SetEnv(name, value string) {
	c.lk.Lock()
	c.env.set(name, value)
	c.lk.Unlock()
}

func SetEnv(name, value string) {
	ctx().SetEnv(name, value)
}

// Return a copy of the environment in the format expected by go os.
func OSEnv() []string {
	var env []string
	c := ctx()
	c.lk.Lock()
	e := c.env
	c.lk.Unlock()
	e.Lock()
	defer e.Unlock()
	for k, v := range e.vars {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}

// Set Unix IO for the named chans (all if none is given)
func (c *Ctx) UnixIO(name ...string) {
	c.lk.Lock()
	io := c.io
	c.lk.Unlock()
	io.unixIO(name...)
}

func UnixIO(name ...string) {
	ctx().UnixIO(name...)
}

func (c *Ctx) Chans() (in []string, out []string) {
	c.lk.Lock()
	io := c.io
	c.lk.Unlock()
	return io.chans()
}

func (c *Ctx) In(name string) <-chan face{} {
	c.lk.Lock()
	io := c.io
	c.lk.Unlock()
	cc := io.get(name)
	if cc == nil {
		return nil
	}
	return cc.inc
}

func (c *Ctx) Out(name string) chan<- face{} {
	c.lk.Lock()
	io := c.io
	c.lk.Unlock()
	cc := io.get(name)
	if cc == nil {
		return nil
	}
	return cc.outc
}

func In(name string) <-chan face{} {
	return ctx().In(name)
}

func Out(name string) chan<- face{} {
	return ctx().Out(name)
}

func Chans() (in []string, out []string) {
	return ctx().Chans()
}

func (c *Ctx) CloseIO(name string) {
	c.lk.Lock()
	io := c.io
	c.lk.Unlock()
	io.del(name)
}

func (c *Ctx) Waitc() chan error {
	return c.wc
}

func CloseIO(name string) {
	ctx().CloseIO(name)
}

func (c *Ctx) SetIn(name string, ioc <-chan face{}) {
	if ioc == nil {
		ioc = make(chan face{})
		close(ioc)
	}
	c.lk.Lock()
	io := c.io
	c.lk.Unlock()
	io.addIn(name, ioc)
}

func (c *Ctx) SetOut(name string, ioc chan<- face{}) {
	if ioc == nil {
		ioc = make(chan face{})
		close(ioc)
	}
	c.lk.Lock()
	io := c.io
	c.lk.Unlock()
	io.addOut(name, ioc)
}

func (c *Ctx) cprintf(name, f string, args ...face{}) (n int, err error) {
	out := c.Out(name)
	if out == nil {
		return 0, ErrIO
	}
	var buf bytes.Buffer
	n, _ = fmt.Fprintf(&buf, f, args...)
	if ok := out <- buf.Bytes(); !ok {
		return 0, cerror(out)
	}
	return n, nil
}

func Printf(f string, args ...face{}) (n int, err error) {
	return ctx().cprintf("out", f, args...)
}

func Eprintf(f string, args ...face{}) (n int, err error) {
	return ctx().cprintf("err", f, args...)
}

func Cprintf(io, f string, args ...face{}) (n int, err error) {
	return ctx().cprintf(io, f, args...)
}

func Dprintf(f string, args ...face{}) (n int, err error) {
	c := ctx()
	if c.Debug {
		return c.cprintf("err", f, args...)
	}
	return 0, nil
}

// Return a function that calls Eprintf but only when flag is set.
func FlagPrintf(flag *bool) dbg.PrintFunc {
	return func(fmts string, arg ...face{}) (int, error) {
		if *flag {
			return Eprintf(fmts, arg...)
		}
		return 0, nil
	}
}

// Warn if verbose flag is set
func VWarn(f string, args ...face{}) (n int, err error) {
	c := ctx()
	if c.Verb {
		return c.cprintf("err", "%s: %s\n", c.Args[0], fmt.Sprintf(f, args...))
	}
	return 0, nil
}

func SetIn(name string, c <-chan face{}) {
	ctx().SetIn(name, c)
}

func SetOut(name string, c chan<- face{}) {
	ctx().SetOut(name, c)
}

func HandleIntr() <-chan os.Signal {
	sigc := make(chan os.Signal, 16)
	signal.Notify(sigc, os.Interrupt)
	return sigc
}

func init() {
	mainctx = mkCtx()
	ns.AddLfsPath("/", nil)
	cdot := GetEnv("dot")
	if cdot != "" {
		Cd(cdot)
	}
	if os.Getenv("clivebg") != "" {
		ic := HandleIntr()
		go func() {
			for range ic {
				Dprintf("*interrupted*\n")
			}
		}()
	}
}

func appexit(sts string) {
	if ctx() == mainctx {
		mainctx.close(sts)
		if sts != "" {
			os.Exit(1)
		}
		os.Exit(0)
	}
	panic("appexit" + sts)
}

func Exit(sts ...face{}) {
	if len(sts) == 0 || sts[0] == nil {
		appexit("")
	}
	if s, ok := sts[0].(string); ok {
		appexit(s)
	}
	if err, ok := sts[0].(error); ok {
		if err == nil {
			appexit("")
		}
		appexit(err.Error())
	}
	appexit("failure")
}

// Warn and exit
func Fatal(args ...face{}) {
	if len(args) == 0 || args[0] == nil {
		appexit("")
	}
	if s, ok := args[0].(string); ok {
		if s == "" {
			appexit("failure")
		}
		Warn(s, args[1:]...)
		appexit(fmt.Sprintf(s, args[1:]...))
	} else if e, ok := args[0].(error); ok {
		if e == nil {
			appexit("failure")
		}
		Warn("%s", e)
		appexit(e.Error())
	} else {
		Warn("fatal")
	}
	appexit("failure")
}

// Printf to stderr, prefixed with app name and terminating with \n.
// Each warn is atomic.
func Warn(f string, args ...face{}) (n int, err error) {
	c := ctx()
	return c.cprintf("err", "%s: %s\n", c.Args[0], fmt.Sprintf(f, args...))
}
