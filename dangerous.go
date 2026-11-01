package dynv

import "strings"

var dangerousKeys = map[string]struct{}{
	"NODE_OPTIONS": {}, "NODE_PATH": {}, "NODE_EXTRA_CA_CERTS": {},
	"NODE_TLS_REJECT_UNAUTHORIZED": {}, "NODE_REPL_EXTERNAL_MODULE": {},
	"BUN_OPTIONS": {}, "BUN_CONFIG_PRELOAD": {}, "DENO_CERT": {},
	"PATH": {}, "HOME": {}, "SHELL": {}, "ENV": {}, "BASH_ENV": {},
	"PROMPT_COMMAND": {}, "IFS": {},
	"PYTHONPATH": {}, "PYTHONSTARTUP": {}, "PYTHONHOME": {}, "PYTHONINSPECT": {},
	"PYTHONWARNINGS": {}, "PYTHONBREAKPOINT": {}, "PYTHONUSERBASE": {},
	"PERL5OPT": {}, "PERL5LIB": {}, "PERLLIB": {}, "PERL5DB": {},
	"RUBYOPT": {}, "RUBYLIB": {}, "GEM_PATH": {},
	"JAVA_TOOL_OPTIONS": {}, "JAVA_OPTS": {}, "CATALINA_OPTS": {}, "_JAVA_OPTIONS": {},
	"JDK_JAVA_OPTIONS": {}, "CLASSPATH": {},
	"SSL_CERT_FILE": {}, "SSL_CERT_DIR": {}, "REQUESTS_CA_BUNDLE": {}, "CURL_CA_BUNDLE": {},
	"GIT_SSL_NO_VERIFY": {}, "GIT_SSH": {}, "GIT_SSH_COMMAND": {}, "GIT_EXEC_PATH": {},
	"GIT_ASKPASS": {}, "SSH_ASKPASS": {}, "LESSOPEN": {}, "EDITOR": {}, "VISUAL": {}, "PAGER": {},
	"DOTNET_STARTUP_HOOKS": {}, "PHPRC": {}, "ZDOTDIR": {}, "GOFLAGS": {},
	"RUSTC_WRAPPER": {}, "RUSTC_WORKSPACE_WRAPPER": {}, "GLIBC_TUNABLES": {},
	"GCONV_PATH": {}, "MALLOC_CONF": {}, "TMPDIR": {}, "ELECTRON_RUN_AS_NODE": {},
}

// IsDangerousKey reports whether key controls program startup or code loading.
// It matches is_dangerous_key in crates/dynv-proto/src/lib.rs: exact names are
// case-sensitive, as are the DYLD_, LD_ and GIT_CONFIG_ prefixes.
func IsDangerousKey(key string) bool {
	_, exact := dangerousKeys[key]
	return exact || strings.HasPrefix(key, "DYLD_") || strings.HasPrefix(key, "LD_") || strings.HasPrefix(key, "GIT_CONFIG_")
}
