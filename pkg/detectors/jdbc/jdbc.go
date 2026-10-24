package jdbc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"regexp" //nolint:depguard // used instead of github.com/wasilibs/go-re2 due to differences in utf-8 handling
	"strings"
	"time"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	ignorePatterns []*regexp.Regexp
}

func New(opts ...func(*Scanner)) *Scanner {
	scanner := &Scanner{
		ignorePatterns: []*regexp.Regexp{},
	}
	for _, opt := range opts {
		opt(scanner)
	}

	return scanner
}

func WithIgnorePattern(ignoreStrings []string) func(*Scanner) {
	return func(s *Scanner) {
		var ignorePatterns []*regexp.Regexp
		for _, ignoreString := range ignoreStrings {
			ignorePattern, err := regexp.Compile(ignoreString)
			if err != nil {
				panic(fmt.Sprintf("%s is not a valid regex, error received: %v", ignoreString, err))
			}
			ignorePatterns = append(ignorePatterns, ignorePattern)
		}

		s.ignorePatterns = ignorePatterns
	}
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	// Matches typical JDBC connection strings.
	// The terminal character class additionally excludes () and & to avoid
	// capturing surrounding delimiters (e.g. "(jdbc:…)" or "…&user=x&").
	keyPat = regexp.MustCompile(`(?i)jdbc:[\w]{3,10}:[^\s"'<>,{}[\]]{10,511}[^\s"'<>,{}[\]()&]`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"jdbc"}
}

// FromData will find and optionally verify Jdbc secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logCtx := logContext.AddLogger(ctx)
	dataStr := string(data)

	matches := keyPat.FindAllStringIndex(dataStr, -1)
matchLoop:
	for _, match := range matches {
		jdbcConn := dataStr[match[0]:match[1]]
		if len(s.ignorePatterns) != 0 {
			for _, ignore := range s.ignorePatterns {
				if ignore.MatchString(jdbcConn) {
					continue matchLoop
				}
			}
		}

		// A password-free URL is connection metadata, not a source secret.
		// Keep ordinary extraction stable; the engine applies IsFalsePositive.
		if detectors.SourceRedactionEnabled(ctx) {
			// The ordinary regex stops before a comma. Do not mistake the
			// first host of a multi-host URL for a complete password-free URL.
			if match[1] < len(dataStr) && dataStr[match[1]] == ',' {
				return nil, errors.New("JDBC source URL uses unsupported host syntax")
			}
			passwords, known, parseErr := jdbcURLPasswords(jdbcConn)
			if parseErr != nil {
				return nil, parseErr
			}
			if known && len(passwords) == 0 {
				continue
			}
		}

		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_JDBC,
			Raw:          []byte(jdbcConn),
			Redacted:     tryRedactAnonymousJDBC(jdbcConn),
			SecretParts:  map[string]string{"connection_string": jdbcConn},
		}

		// Try to parse connection info for ExtraData regardless of verification.
		if j, parseErr := NewJDBC(logCtx, jdbcConn); parseErr == nil {
			if info := j.GetConnectionInfo(); info != nil {
				extraData := make(map[string]string)
				if info.Host != "" {
					extraData["host"] = info.Host
				}
				if info.User != "" {
					extraData["username"] = info.User
				}
				if info.Database != "" {
					extraData["database"] = info.Database
				}
				if len(extraData) > 0 {
					result.ExtraData = extraData
				}
			}

			if verify {
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				pingRes := j.ping(ctx)
				result.Verified = pingRes.err == nil
				// If there's a ping error that is marked as "determinate" we throw it away. We do this because this was the
				// behavior before tri-state verification was introduced and preserving it allows us to gradually migrate
				// detectors to use tri-state verification.
				if pingRes.err != nil && !pingRes.determinate {
					result.SetVerificationError(pingRes.err, jdbcConn)
				}
			}
		} else if verify {
			// The connection string could not be parsed, so the credential was never tested.
			// That is an indeterminate outcome, not a rejection: we report it as unverified carrying the parse error.
			// Dropping it here made the reported findings depend on whether verification was requested,
			// since the unparseable match is kept when verify is false.
			result.SetVerificationError(parseErr, jdbcConn)
		}

		results = append(results, result)
	}

	return
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	if result.Verified {
		return false, ""
	}
	passwords, known, _ := jdbcURLPasswords(string(result.Raw))
	if !known {
		return false, ""
	}
	if len(passwords) == 0 {
		return true, "JDBC URL contains no password"
	}
	for _, password := range passwords {
		if password != "REDACTED" {
			return false, ""
		}
	}
	return true, "JDBC passwords are redaction markers"
}

// Only classify reviewed hierarchical URL syntax. Other connection formats stay
// candidates; unreviewed properties in a supported URL must also stop source
// redaction because a driver may interpret them as additional credentials.
func jdbcURLPasswords(conn string) ([]string, bool, error) {
	if len(conn) < len("jdbc:") || !strings.EqualFold(conn[:len("jdbc:")], "jdbc:") {
		return nil, false, nil
	}
	value := conn[len("jdbc:"):]
	scheme, rest, _ := strings.Cut(value, ":")
	switch strings.ToLower(scheme) {
	case "mysql", "postgres", "postgresql":
	default:
		return nil, false, nil
	}
	if !strings.HasPrefix(rest, "//") {
		return nil, false, nil
	}
	unsupported := errors.New("JDBC source URL uses unsupported connection properties")
	if strings.ContainsAny(value, ";#") {
		return nil, false, unsupported
	}
	_, rawQuery, _ := strings.Cut(value, "?")
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, false, unsupported
	}
	for key, values := range query {
		switch strings.ToLower(key) {
		case "password", "pwd", "spring.datasource.password", "user", "sslmode":
		case "ssl":
			// pgJDBC defines ssl as Boolean connection metadata. Keep its
			// accepted syntax narrow; sslpassword is an independent secret.
			if !strings.EqualFold(scheme, "postgres") && !strings.EqualFold(scheme, "postgresql") {
				return nil, false, unsupported
			}
			for _, value := range values {
				if value != "" && !strings.EqualFold(value, "true") && !strings.EqualFold(value, "false") {
					return nil, false, unsupported
				}
			}
		default:
			// MySQL password1/2/3 and pgJDBC sslpassword are credentials,
			// not public properties. Unknown future properties are not safe.
			return nil, false, unsupported
		}
	}
	authority := rest[2:]
	if end := strings.IndexAny(authority, "/?"); end >= 0 {
		authority = authority[:end]
	}
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}
	// Keep the existing precisely parsed MySQL tcp(host:port) DSN path.
	// It is never classified as password-free URL metadata.
	if strings.HasPrefix(authority, "tcp(") && strings.HasSuffix(authority, ")") &&
		!strings.ContainsAny(authority[4:len(authority)-1], "(),=%\\") {
		return nil, false, nil
	}
	if strings.ContainsAny(authority, "(),=%\\") {
		return nil, false, unsupported
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, false, nil
	}
	var passwords []string
	if u.User != nil {
		if password, ok := u.User.Password(); ok && password != "" {
			passwords = append(passwords, password)
		}
	}
	for key, values := range query {
		switch strings.ToLower(key) {
		case "password", "pwd", "spring.datasource.password":
			for _, password := range values {
				if password != "" {
					passwords = append(passwords, password)
				}
			}
		}
	}
	return passwords, true, nil
}

func tryRedactAnonymousJDBC(conn string) string {
	if s, ok := tryRedactURLParams(conn); ok {
		return s
	}
	if s, ok := tryRedactODBC(conn); ok {
		return s
	}
	if s, ok := tryRedactBasicAuth(conn); ok {
		return s
	}
	if s, ok := tryRedactRegex(conn); ok {
		return s
	}
	return conn
}

// Basic authentication "username:password@host" style
func tryRedactBasicAuth(conn string) (string, bool) {
	userPass, postfix, found := strings.Cut(conn, "@")
	if !found {
		return "", false
	}
	index := strings.LastIndex(userPass, ":")
	if index == -1 {
		return "", false
	}
	prefix, pass := userPass[:index], userPass[index+1:]
	return prefix + ":" + strings.Repeat("*", len(pass)) + "@" + postfix, true
}

// URL param "?password=password" style
func tryRedactURLParams(conn string) (string, bool) {
	prefix, paramString, found := strings.Cut(conn, "?")
	if !found {
		return "", false
	}
	var newParams []string
	found = false
	for _, param := range strings.Split(paramString, "&") {
		key, val, _ := strings.Cut(param, "=")
		if strings.Contains(strings.ToLower(key), "pass") {
			newParams = append(newParams, key+"="+strings.Repeat("*", len(val)))
			found = true
			continue
		}
		newParams = append(newParams, param)
	}
	if !found {
		return "", false
	}
	return prefix + "?" + strings.Join(newParams, "&"), true
}

// ODBC params ";password=password" style
func tryRedactODBC(conn string) (string, bool) {
	var found bool
	var newParams []string
	for _, param := range strings.Split(conn, ";") {
		key, val, isKvp := strings.Cut(param, "=")
		if isKvp && strings.Contains(strings.ToLower(key), "pass") {
			newParams = append(newParams, key+"="+strings.Repeat("*", len(val)))
			found = true
			continue
		}
		newParams = append(newParams, param)
	}
	if !found {
		return "", false
	}
	return strings.Join(newParams, ";"), true
}

// Naively search the string for "pass="
func tryRedactRegex(conn string) (string, bool) {
	pattern := regexp.MustCompile(`(?i)pass.*?=(.+?)\b`)
	var found bool
	newConn := pattern.ReplaceAllStringFunc(conn, func(s string) string {
		index := strings.Index(s, "=")
		if index == -1 {
			// unreachable due to regex containing '='
			return s
		}
		found = true
		return s[:index+1] + strings.Repeat("*", len(s[index+1:]))
	})
	if !found {
		return "", false
	}
	return newConn, true
}

var supportedSubprotocols = map[string]func(logContext.Context, string) (JDBC, error){
	"mysql":      parseMySQL,
	"postgresql": parsePostgres,
	"sqlserver":  parseSqlServer,
}

func NewJDBC(ctx logContext.Context, conn string) (JDBC, error) {
	// expected format: "jdbc:{subprotocol}:{subname}"
	if !strings.HasPrefix(strings.ToLower(conn), "jdbc:") {
		return nil, errors.New("expected jdbc prefix")
	}
	conn = conn[len("jdbc:"):]

	subprotocol, subname, found := strings.Cut(conn, ":")
	if !found {
		return nil, errors.New("expected a colon separated subprotocol and subname")
	}

	parser, ok := supportedSubprotocols[strings.ToLower(subprotocol)]
	if !ok {
		return nil, fmt.Errorf("unsupported subprotocol: %s", subprotocol)
	}

	return parser(ctx, subname)
}

func ping(ctx context.Context, driverName string, isDeterminate func(error) bool, candidateConns ...string) pingResult {
	var indeterminateErrors []error
	for _, c := range candidateConns {
		err := pingErr(ctx, driverName, c)
		if err == nil || isDeterminate(err) {
			return pingResult{err, true}
		}
		indeterminateErrors = append(indeterminateErrors, err)
	}
	return pingResult{errors.Join(indeterminateErrors...), false}
}

func pingErr(ctx context.Context, driverName, conn string) error {
	db, err := sql.Open(driverName, conn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	if err := db.PingContext(ctx); err != nil {
		return err
	}
	return nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_JDBC
}

func (s Scanner) Description() string {
	return "JDBC (Java Database Connectivity) is an API for connecting and executing queries with databases. JDBC connection strings can be used to access and manipulate databases."
}
