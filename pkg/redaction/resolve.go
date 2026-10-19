package redaction

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/go-logr/logr"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/jdbc"
)

// PartPolicy is exhaustive. New upstream component names must be reviewed.
// IDs and connection metadata are retained in the original source.
func PartPolicy(name string) string {
	switch name {
	case "key", "secret", "token", "client_secret", "password", "pat", "api_key", "private_key", "refresh_token", "account_key", "consumer_secret", "secret_access_key", "skey", "write_key", "api_secret", "session_token", "user_key", "subscribe_key", "pat_secret", "secret_id", "app_key", "passphrase", "client":
		return "secret"
	case "access_key_id", "client_id", "consumer_key", "id", "username", "domain", "host", "email", "endpoint", "project_id", "organization", "organization_id", "account_id", "sid", "env_id", "ikey", "account_name", "cloud_name", "database", "application", "user", "user_id", "account_url", "role_id", "service", "app", "key_name", "search_engine", "token_name", "access_type", "store_url", "subdomain", "subject_id", "region", "type", "registry", "url":
		return "public"
	case "auth", "connection_string":
		return "structured"
	default:
		return "unknown"
	}
}

// Resolve identifies sensitive ranges using credential components, never Raw's
// ID/deduplication semantics. Every sensitive component must have a source match.
func Resolve(data []byte, results []detectors.Result) ([]Span, error) {
	var spans []Span
	for _, result := range results {
		values, err := secretValues(result)
		if err != nil {
			return nil, err
		}
		for _, secret := range values {
			if secret == Marker {
				continue
			}
			matches := literalSpans(data, []byte(secret))
			// Findings may normalize URI escapes; map every source representation.
			if decoded, err := url.PathUnescape(secret); err == nil && decoded != secret {
				matches = append(matches, literalSpans(data, []byte(decoded))...)
			}
			encoded, _ := json.Marshal(secret)
			if len(encoded) > 2 && !bytes.Equal(encoded[1:len(encoded)-1], []byte(secret)) {
				matches = append(matches, literalSpans(data, encoded[1:len(encoded)-1])...)
			}
			if len(matches) == 0 {
				return nil, errors.New("credential component has no exact source match")
			}
			spans = append(spans, matches...)
			if len(spans) > maxSourceSpans {
				return nil, errors.New("source edit limit exceeded")
			}
		}
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start == spans[j].Start {
			return spans[i].End < spans[j].End
		}
		return spans[i].Start < spans[j].Start
	})
	var merged []Span
	for _, s := range spans {
		if len(merged) > 0 && s.Start < merged[len(merged)-1].End {
			if s.End > merged[len(merged)-1].End {
				merged[len(merged)-1].End = s.End
			}
			continue
		}
		merged = append(merged, s)
	}
	return merged, nil
}

func componentPolicy(typ, name, value string) string {
	policy := PartPolicy(name)
	if typ == "TwilioApiKey" && name == "sid" || typ == "CustomerGuru" && name == "id" {
		return "secret"
	}
	if name == "key" && publicPairedKey[typ] || typ == "Cloudinary" && name == "api_key" || typ == "StripePaymentIntent" && name == "key" && strings.HasPrefix(value, "pk_") {
		return "public"
	}
	return policy
}

// Use the same exhaustive component validation during mapping and residual audit.
func secretValues(result detectors.Result) ([]string, error) {
	var secrets []string
	for name, value := range result.SecretParts {
		switch componentPolicy(result.DetectorType.String(), name, value) {
		case "unknown":
			return nil, errors.New("unreviewed credential component")
		case "public":
			continue
		}
		if value == "" {
			return nil, errors.New("empty credential component")
		}
		values, err := sensitiveValues(result.DetectorType.String(), name, value)
		if err != nil {
			return nil, err
		}
		if len(values) == 0 {
			return nil, errors.New("credential component has no sensitive values")
		}
		for _, secret := range values {
			if secret == "" {
				return nil, errors.New("empty sensitive value")
			}
		}
		secrets = append(secrets, values...)
	}
	if len(secrets) == 0 {
		return nil, errors.New("finding has no sensitive components")
	}
	return secrets, nil
}

func hasUnredactedComponent(result detectors.Result) (bool, error) {
	values, err := secretValues(result)
	if err != nil {
		return false, err
	}
	for _, secret := range values {
		if secret != Marker {
			return true, nil
		}
	}
	return false, nil
}

var publicPairedKey = map[string]bool{
	"TrelloApiKey": true,
	"Agora":        true, "Amadeus": true, "Autodesk": true, "FourSquare": true,
	"LarkSuiteApiKey": true, "Ramp": true, "Rownd": true, "Smooch": true,
	"PusherChannelKey": true, "Mux": true, "RazorPay": true, "TwitterConsumerkey": true,
	"Guru": true, "Instamojo": true, "Mrticktock": true, "TrufflehogEnterprise": true,
	"TwilioApiKey": true,
	"SquareApp":    true,
}

func literalSpans(data, value []byte) []Span {
	if len(value) == 0 {
		return nil
	}
	var out []Span
	if bytes.Contains(value, []byte("%")) {
		var pattern strings.Builder
		for i := 0; i < len(value); i++ {
			if value[i] == '%' && i+2 < len(value) && isHex(value[i+1]) && isHex(value[i+2]) {
				pattern.WriteString("%(?i:" + string(value[i+1:i+3]) + ")")
				i += 2
			} else {
				pattern.WriteString(regexp.QuoteMeta(string(value[i])))
			}
		}
		for _, match := range regexp.MustCompile(pattern.String()).FindAllIndex(data, maxSourceSpans+1) {
			if literalBoundary(data, value, match[0], match[1]) {
				out = append(out, Span{match[0], match[1]})
			}
		}
		return out
	}
	for start := 0; start <= len(data)-len(value); {
		i := bytes.Index(data[start:], value)
		if i < 0 {
			break
		}
		i += start
		// Avoid replacing a short component inside an unrelated identifier.
		if literalBoundary(data, value, i, i+len(value)) {
			out = append(out, Span{i, i + len(value)})
			if len(out) > maxSourceSpans {
				break
			}
		}
		start = i + len(value)
	}
	return out
}

func word(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}

func literalBoundary(data, value []byte, start, end int) bool {
	return (!word(value[0]) || start == 0 || !word(data[start-1])) && (!word(value[len(value)-1]) || end == len(data) || !word(data[end]))
}

func isHex(b byte) bool { return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F' }

var parameterPassword = regexp.MustCompile(`(?i)(?:^|[?;&\s])(?:password|pwd|spring\.datasource\.password)\s*=\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^;&\s]+))`)

func sensitiveValues(typ, name, value string) ([]string, error) {
	if value == Marker {
		return []string{Marker}, nil
	}
	if typ == "Netsuite" && name == "token" {
		return strings.Split(value, "\n"), nil
	}
	if name == "auth" {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, errors.New("invalid Docker auth component")
		}
		_, password, ok := strings.Cut(string(decoded), ":")
		if !ok || password == "" {
			return nil, errors.New("Docker auth has no password")
		}
		// This value is located in a mapped base64 view, preserving the username.
		return []string{password}, nil
	}
	if typ == "GCP" && name == "key" {
		return privateKeys(value)
	}
	if typ == "AzureSasToken" && name == "key" {
		if values := querySignatures(value); len(values) > 0 {
			return values, nil
		}
		return nil, errors.New("SAS credential has no signature")
	}
	if name == "connection_string" || name == "key" && (typ == "MongoDB" || typ == "FTP" || typ == "RabbitMQ") {
		return connectionSecrets(typ, value)
	}
	if name == "key" && typ == "MicrosoftTeamsWebhook" {
		u, err := url.Parse(value)
		if err != nil {
			return nil, errors.New("invalid Teams webhook credential")
		}
		if values := querySignatures(u.RawQuery); len(values) > 0 {
			return values, nil
		}
		parts := strings.Split(u.EscapedPath(), "/")
		for i, p := range parts {
			if p == "IncomingWebhook" && i+1 < len(parts) && parts[i+1] != "" {
				return []string{parts[i+1]}, nil
			}
		}
		return nil, errors.New("Teams webhook has no signing token")
	}
	if name == "key" && (typ == "SlackWebhook" || typ == "DiscordWebhook" || typ == "TinesWebhook" || typ == "ZapierWebhook") {
		u, err := url.Parse(value)
		if err != nil {
			return nil, errors.New("invalid webhook credential")
		}
		parts := strings.Split(strings.TrimRight(u.EscapedPath(), "/"), "/")
		if len(parts) < 2 || parts[len(parts)-1] == "" {
			return nil, errors.New("webhook has no token")
		}
		return []string{parts[len(parts)-1]}, nil
	}
	return []string{value}, nil
}

// URI userinfo and query/property passwords can coexist. A query password must
// never authorize output when userinfo parsing failed: MySQL DSNs need their
// own parser, and unsupported connection formats must withhold the source.
func connectionSecrets(typ, value string) ([]string, error) {
	var found []string
	u, uriErr := url.Parse(strings.TrimPrefix(value, "jdbc:"))
	if uriErr == nil && u.User != nil {
		if password, ok := u.User.Password(); ok && password != "" {
			// Preserve percent encoding as it appeared in the URI userinfo.
			_, encoded, _ := strings.Cut(u.User.String(), ":")
			found = append(found, encoded)
		}
	}
	for _, match := range parameterPassword.FindAllStringSubmatch(value, -1) {
		for _, part := range match[1:] {
			if part != "" {
				found = append(found, part)
			}
		}
	}
	if typ == "JDBC" && (uriErr != nil || len(found) == 0) {
		parsed, err := jdbc.NewJDBC(logContext.WithLogger(logContext.Background(), logr.Discard()), value)
		if err == nil && parsed.GetConnectionInfo() != nil && parsed.GetConnectionInfo().Password != "" {
			found = append(found, parsed.GetConnectionInfo().Password)
			uriErr = nil // The JDBC parser resolved the non-URI connection format.
		}
	}
	if uriErr != nil || len(found) == 0 {
		return nil, errors.New("connection credential cannot be parsed precisely")
	}
	return found, nil
}

func querySignatures(query string) []string {
	var found []string
	for _, pair := range strings.Split(query, "&") {
		key, value, ok := strings.Cut(pair, "=")
		if ok && key == "sig" && value != "" {
			found = append(found, value)
		}
	}
	return found
}

// json.Unmarshal overwrites duplicate keys. Collect each private_key explicitly
// so an earlier credential cannot survive when the final value is masked.
func privateKeys(value string) ([]string, error) {
	if !json.Valid([]byte(value)) {
		return nil, errors.New("invalid GCP credential")
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("invalid GCP credential")
	}
	var keys []string
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return nil, errors.New("invalid GCP credential")
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, errors.New("invalid GCP credential")
		}
		if name == "private_key" {
			var key string
			if json.Unmarshal(raw, &key) != nil || key == "" {
				return nil, errors.New("GCP credential has invalid private key")
			}
			keys = append(keys, key)
		}
	}
	if _, err := decoder.Token(); err != nil || len(keys) == 0 {
		return nil, errors.New("GCP credential has no private key")
	}
	return keys, nil
}
