package ink

import (
	"clive/cmd"
	"clive/net/auth"
	"fmt"
	"golang.org/x/net/websocket"
	"net/http"
	"strings"
)

func authFailed(w http.ResponseWriter, r *http.Request) {
	outs := `<html><head><title> Logged out of Clive ink</title></head>
		<body style="background-color:#ddddc8">
		<script>
		document.cookie = "clive=xxx; expires=Thu, 01 Jan 1970 00:00:01 GMT;";
		</script>
		<p>
		<p>
		<p>
		<p>
		<p><p><center><b><tt>
		<b><tt>You are logged out.</tt></b><br>
		<b>You may proceed to the <a href="/login">login page</a>.
		</tt></b></center><p><p>
		<img src="http://lsub.org/clive.gif"  alt="" style="position:fixed; top:0; left:0; z-index:-1; width:100px;">
		<img src="http://lsub.org/zxlogo.gif"  alt="" style="position:fixed; bottom:0; right:0; z-index:-1; width:100px;">
		</body></html>
	`
	fmt.Fprintf(w, "%s\n", outs)
}

func checkOrigin(config *websocket.Config, req *http.Request) (err error) {
	config.Origin, err = websocket.Origin(config, req)
	if err == nil && config.Origin == nil {
		return fmt.Errorf("null origin")
	}
	return err
}

// Authenticate a websocket before servicing it.
func AuthWebSocketHandler(h websocket.Handler) http.HandlerFunc {
	hndler := func(w http.ResponseWriter, r *http.Request) {
		if auth.TLSserver != nil && auth.Enabled {
			clive, err := r.Cookie("clive")
			if err != nil {
				cmd.Warn("wax/auth: no cookie: %s", err)
				http.Error(w, "auth failed", 403)
				return
			}
			toks := strings.SplitN(string(clive.Value), ":", 3)
			switch len(toks) {
			case 3:	// time-based one-time password auth token
				if toks[0] != "totp" {
					cmd.Warn("wax/totp authws: wrong cookie, not totp")
					http.Error(w, "auth failed", 403)
					return
				}
				u, ok := auth.TotpOk("wax", toks[1], toks[2])
				if !ok {
					cmd.Warn("wax/totp authws: failed for %s", u)
					http.Error(w, "auth failed", 403)
					return
				}
				cmd.Warn("totp ok");
			case 2:	// challenge-response auth token
				ch, resp := toks[0], toks[1]
				u, ok := auth.ChallengeResponseOk("wax", ch, resp)
				if !ok {
					cmd.Warn("wax/authws: failed for %s", u)
					http.Error(w, "auth failed", 403)
					return
				}
			default:	// unknown auth token
				cmd.Warn("wax/authws: wrong cookie")
				http.Error(w, "auth failed", 403)
				return
			}
		}
		s := websocket.Server{Handler: h, Handshake: checkOrigin}
		s.ServeHTTP(w, r)
	}
	return hndler
}

// Authenticate before calling the handler.
// When TLS is disabled, or there's no key file, auth is considered ok.
func AuthHandler(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.TLSserver == nil || !auth.Enabled {
			fn(w, r)
			return
		}
		clive, err := r.Cookie("clive")
		if err != nil {
			cmd.Warn("wax/auth: no cookie: %s", err)
			authFailed(w, r)
			return
		}
		toks := strings.SplitN(string(clive.Value), ":", 3)
		switch len(toks) {
		case 3:	// time-based one-time password auth token
			if toks[0] != "totp" {
				cmd.Warn("wax/totp auth: wrong cookie, not totp")
				authFailed(w, r)
				return
			}
			u, ok := auth.TotpOk("wax", toks[1], toks[2])
			if !ok {
				cmd.Warn("wax/totp auth: failed for %s", u)
				authFailed(w, r)
				return
			}
			cmd.Warn("totp ok");
		case 2:	// challenge-response auth token
			ch, resp := toks[0], toks[1]
			u, ok := auth.ChallengeResponseOk("wax", ch, resp)
			if !ok {
				cmd.Warn("wax/auth: failed for %s", u)
				authFailed(w, r)
				return
			}
		default:	// unknown auth token
			cmd.Warn("wax/auth: wrong cookie")
			authFailed(w, r)
			return
		}

		// TODO: We should decorate r adding the user id to
		// the url as a query, so fn can inspect the query and
		// know which user did auth.
		fn(w, r)
	}
}

// Serve the /login and /logout pages, proceeding to the indicated page
// after each login.
func serveLoginFor(proceedto string) {
	http.HandleFunc("/logout", authFailed)

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		vals := r.URL.Query()
		if len(vals["dst"]) > 0 {
			proceedto = vals["dst"][0]
		}
		js := `
		<html>
		<body style="background-color:#ddddc8">
		<script type="text/javascript" src="/js/aes.js"></script>
		<script type="text/javascript" src="/js/ansix923.js"></script>
		<script type="text/javascript" src="/js/pbkdf2.js"></script>
		<script type="text/javascript" src="/js/jquery-2.2.0.min.js"></script>
		<p>
		<script>
		$(function(){
			$("#dialog").on('submit', function(e) {
				var salt ='ltsa';
				var usrkey = $("#pass").val();
				var key = CryptoJS.PBKDF2(usrkey, salt, { keySize: 256/32, iterations: 1000});
				usrkey = "XXXXXXXXXXXX";
				var ch = Math.random().toPrecision(16).slice(2);
				var iv  = CryptoJS.enc.Hex.parse('12131415161718191a1b1c1d1e1f1011');
				var enc  = CryptoJS.AES.encrypt(ch, key, { iv: iv, padding: CryptoJS.pad.Pkcs7});
				var c =  "clive=" + ch + ":" + enc.ciphertext + ";secure=secure";
				document.cookie = c;
				clive = c;
				window.location = "` + proceedto + `";
				return false;
			});
		})

		$(function(){
			$("#dialog_totp").on('submit', function(e) {
				var totp_code = $("#pass_totp").val();
				var totp_timestamp = Math.round((new Date()).getTime()/1000);
				var c =  "clive=totp:" + totp_code + ":" + totp_timestamp + ";secure=secure";
				document.cookie = c;
				clive = c;
				window.location = "` + proceedto + `";
				return false;
			});
		})

		if(window.location.protocol !== "https:") {
			window.location = "` + proceedto + `";
		}
		</script>
		<p><center><tt>
		<b><form name="form" id="dialog" action="" method="get" >
			<label for="box">Clive ink password: </label>
			<input name="box" id="pass" type="password"/ ></form></b>
		<p>or use totp (time-based one-time password)</p>
		<b><form name="form_totp" id="dialog_totp" action="" method="get" >
			<label for="box_totp">6 digit code: </label>
			<input name="box_totp" id="pass_totp"/ ></form></b>
			<p>or <a href="/login">set up</a> totp.</tt></center>
`
		fmt.Fprintf(w, "%s\n<p>\n", js)
		fmt.Fprintf(w, `<img src="http://lsub.org/clive.gif"  alt="" style="position:fixed; top:0; left:0; z-index:-1; width:100px;">
		<img src="http://lsub.org/zxlogo.gif"  alt="" style="position:fixed; bottom:0; right:0; z-index:-1; width:100px;">
			</body></html>`+"\n")
	})
}
