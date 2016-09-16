/* 
	Go tool yacc parse.y ; Go install
	Lgo tool yacc parse.y ; Lgo install
	other toks: = { } ; [ ] ^ = $ ( )
*/

%token FOR WHILE FUNC NL OR AND LEN SINGLE ERROR COND OR

%token <sval> PIPE IREDIR OREDIR BG APP NAME INBLK OUTBLK

%type <nd> name names cmd optnames list nameel mapels
%type <nd> bgpipe pipe cmd redir spipe
%type <nd> blkcmds func cond setvar optname
%type <sval> optbg
%type <bval> optin
%type <redirs> redirs optredirs
%{
package main

%}

%union {
	sval string
	nd *Nd
	bval bool
	redirs []*Redir
}

%left '^'

%%
start
	: topcmds
	|
	;

topcmds
	: topcmds topcmd
	| topcmd
	;


topcmd
	: bgpipe sep
	{
		$1.run()
	}
	| func sep
	{
		$1.run()
	}
	| sep
	| error NL
	{
		// scripts won't continue upon errors
		yylex.(*lex).nerrors++
		if !yylex.(*lex).interactive {
			panic(parseErr)
		}
	}
	;

func
	: FUNC NAME '{' optsep blkcmds optsep '}'
	{
		$$ = newNd(Nfunc, $2).Add($5)
	}
	;

bgpipe
	: pipe optbg
	{
		$$ = $1
		$$.Args[0] = $2
	}
	| IREDIR name
	{
		$$ = newList(Nsrc, $2)
	}
	;

optbg
	: BG
	{
		$$ = $1
		if $$ == "" {
			$$ = "&"
		}
	}
	|
	{
		$$ = ""
	}
	;

pipe
	: optin spipe
	{
		$$ = $2
		$$.Args = append([]string{""}, $$.Args...)
		$$.addPipeRedirs($1)
	}
	;

optin
	: PIPE
	{
		$$ = true
	}
	|
	{
		$$ = false
	}
	;

spipe
	: spipe PIPE optnl cmd
	{
		$$ = $1.Add($4)
		$$.Args = append($$.Args, $2)
	}
	| cmd
	{
		$$ = newList(Npipe, $1)
	}
	;

optnl
	: NL
	|
	;

cmd
	: names optredirs
	{
		$$ = newList(Ncmd, $1)
		$$.Redirs = $2
	}
	| '{' optsep blkcmds optsep '}' optredirs
	{
		$$ = $3
		$$.Redirs = $6
	}
	| FOR names '{' optsep blkcmds optsep '}' optredirs
	{
		$$ = newList(Nfor, $2, $5)
		$$.Redirs = $8
	}
	| WHILE pipe '{' optsep blkcmds optsep '}' optredirs
	{
		$$ = newList(Nwhile, $2, $5)
		$$.Redirs = $8
	}
	| cond optredirs
	{
		$$ = $1
		$1.Redirs = $2
	}
	| setvar
	;

setvar
	: NAME as names
	{
		$$ = newNd(Nset, $1).Add($3)
	}
	| NAME as '(' mapels ')'
	{
		$$ = $4
		$$.Args = []string{$1}
	}
	| NAME '[' name ']' as names
	{
		$$ = newNd(Nset, $1).Add($3).Add($6)
	}
	;
as
	: '='
	| '←'
	;

cond
	: COND '{' optsep blkcmds optsep '}'
	{
		nd := $4
		nd.typ = Nor
		$$ = newList(Ncond, nd)
	}
	| cond OR '{' optsep blkcmds optsep '}'
	{
		nd := $5
		nd.typ = Nor
		$$ = $1.Add(nd)
	}
	;
blkcmds
	: blkcmds sep bgpipe
	{
		$$ = $1.Add($3)
	}
	| bgpipe
	{
		$$ = newList(Nblock, $1)
	}
	;

optredirs
	: redirs
	{
		$$ = $1
	}
	|
	{
		$$ = nil
	}
	;

redirs
	: redirs redir
	{
		$$ = $1
		$$ = $2.addRedirTo($$)
	}
	| redir
	{
		$$ = nil
		$$ = $1.addRedirTo($$)
	}
	;

redir
	: IREDIR name
	{
		$$ = newRedir("<", $1, $2)
	}
	| OREDIR optname
	{
		$$ = newRedir(">", $1, $2)
	}
	| APP name {
		$$ = newRedir(">>", $1, $2)
	}
	;

optname
	: name
	|
	{
		$$ = nil
	}

sep
	: NL
	| ';'
	;

optsep
	: sep
	|
	;

names
	: names nameel
	{
		$$ = $1.Add($2)
	}
	| nameel
	{
		$$ = newList(Nnames, $1)
	}
	;

nameel
	: name
	| list
	;
list
	: '(' optnames ')'
	{
		$$ = $2
	}
	| name '^' list
	{
		nd := newList(Nnames, $1)
		$$ = newList(Napp, nd, $3)
	}
	| name '^' name
	{
		nd1 := newList(Nnames, $1)
		nd2 := newList(Nnames, $3)
		$$ = newList(Napp, nd1, nd2)
	}
	| list '^' name
	{
		nd := newList(Nnames, $3)
		$$ = newList(Napp, $1, nd)
	}
	| list '^' list
	{
		$$ = newList(Napp, $1, $3)
	}
	| INBLK optsep blkcmds optsep '}' 
	{
		$$ = $3
		$3.Args = []string{"<"}
		if $1 != "" {
			$3.Args = append($3.Args, $1)
		}
		$3.typ = Nioblk
	}
	| OUTBLK optsep blkcmds optsep '}' 
	{
		$$ = $3
		if $1 == "" {
			$1 = "out"
		}
		$3.Args = []string{">", $1}
		$3.typ = Nioblk
	}
	;

mapels
	:  mapels '[' names ']'
	{
		$$ = $1.Add($3)
	}
	| '[' names ']' 
	{
		// the parent adds Args with the var name
		$$ = newList(Nsetmap, $2)
	}
	;

optnames
	: names
	|
	{
		$$ = newList(Nnames)
	}
	;
name
	: NAME
	{
		$$ = newNd(Nname, $1)
	}
	| '$' NAME
	{
		$$ = newNd(Nval, $2)
	}
	| SINGLE NAME
	{
		$$ = newNd(Nsingle, $2)
	}
	| '$' NAME '[' name ']'
	{
		$$ = newNd(Nval, $2).Add($4)
	}
	| SINGLE NAME '[' name ']'
	{
		$$ = newNd(Nsingle, $2).Add($4)
	}
	| LEN NAME
	{
		$$ = newNd(Nlen, $2)
	}
	;
%%
