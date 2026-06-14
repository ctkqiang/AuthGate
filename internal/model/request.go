package model

// RequestHttpHeader defines security-centric HTTP response headers.
// Each field follows current best practices to mitigate common web
// vulnerabilities: XSS, clickjacking, MIME sniffing, data leakage, etc.
type RequestHttpHeader struct {
	// XContentTypeOption prevents MIME type sniffing.
	XContentTypeOption string `json:"x_content_type_option"`

	// XFrameOptions prevents clickjacking by disallowing framing.
	XFrameOptions string `json:"x_frame_options"`

	// ReferrerPolicy controls how much referrer info is sent.
	ReferrerPolicy string `json:"referrer_policy"`

	// PermissionsPolicy restricts browser features (camera, mic, etc.).
	PermissionsPolicy string `json:"permissions_policy"`

	// StrictTransportSecurity enforces HTTPS via HSTS.
	StrictTransportSecurity string `json:"strict_transport_security"`

	// ContentSecurityPolicy mitigates XSS and data injection.
	ContentSecurityPolicy string `json:"content_security_policy"`

	// --- CORS headers ---
	AccessControlAllowOrigin   string `json:"access_control_allow_origin"`
	AccessControlAllowMethods  string `json:"access_control_allow_methods"`
	AccessControlAllowHeaders  string `json:"access_control_allow_headers"`
	AccessControlMaxAge        string `json:"access_control_max_age"`
	AccessControlExposeHeaders string `json:"access_control_expose_headers"`

	// --- Cross-Origin isolation headers ---
	CrossOriginResourcePolicy string `json:"cross_origin_resource_policy"`
	CrossOriginEmbedderPolicy string `json:"cross_origin_embedder_policy"`
	CrossOriginOpenerPolicy   string `json:"cross_origin_opener_policy"`
}

// DefaultSecurityHeaders returns the baseline set of hardened HTTP headers.
// CORS origins should be overridden per-request based on the trusted origin list.
var DefaultSecurityHeaders = RequestHttpHeader{
	XContentTypeOption:      "nosniff",
	XFrameOptions:           "DENY",
	ReferrerPolicy:          "strict-origin-when-cross-origin",
	PermissionsPolicy:       "camera=(), microphone=(), geolocation=(), interest-cohort=()",
	StrictTransportSecurity: "max-age=63072000; includeSubDomains; preload",
	ContentSecurityPolicy: "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'; " +
		"form-action 'self'; " +
		"base-uri 'self'",

	AccessControlAllowOrigin:   "",
	AccessControlAllowMethods:  "GET, POST, PUT, DELETE, OPTIONS, PATCH",
	AccessControlAllowHeaders:  "Content-Type, Authorization, X-Request-ID, X-API-Key",
	AccessControlMaxAge:        "86400",
	AccessControlExposeHeaders: "X-Request-ID, X-RateLimit-Remaining, X-RateLimit-Reset",

	CrossOriginResourcePolicy: "same-origin",
	CrossOriginEmbedderPolicy: "require-corp",
	CrossOriginOpenerPolicy:   "same-origin",
}

// ToMap converts the header struct to a map for direct use with http.ResponseWriter.
// Empty-valued headers are omitted so callers can leave CORS origins unset.
func (h RequestHttpHeader) ToMap() map[string]string {
	m := make(map[string]string, 16)

	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}

	set("X-Content-Type-Options", h.XContentTypeOption)
	set("X-Frame-Options", h.XFrameOptions)
	set("Referrer-Policy", h.ReferrerPolicy)
	set("Permissions-Policy", h.PermissionsPolicy)
	set("Strict-Transport-Security", h.StrictTransportSecurity)
	set("Content-Security-Policy", h.ContentSecurityPolicy)

	set("Access-Control-Allow-Origin", h.AccessControlAllowOrigin)
	set("Access-Control-Allow-Methods", h.AccessControlAllowMethods)
	set("Access-Control-Allow-Headers", h.AccessControlAllowHeaders)
	set("Access-Control-Max-Age", h.AccessControlMaxAge)
	set("Access-Control-Expose-Headers", h.AccessControlExposeHeaders)

	set("Cross-Origin-Resource-Policy", h.CrossOriginResourcePolicy)
	set("Cross-Origin-Embedder-Policy", h.CrossOriginEmbedderPolicy)
	set("Cross-Origin-Opener-Policy", h.CrossOriginOpenerPolicy)

	return m
}

// GetRequestHttpHeaders builds security headers for a given JWT.
// When the JWT is present (non-empty AccessToken), CORS may be relaxed;
// otherwise the most restrictive set is returned.
func GetRequestHttpHeaders(jwt JWT) RequestHttpHeader {
	h := DefaultSecurityHeaders

	if jwt.AccessToken != "" && jwt.Validate() == nil {
		if jwt.Audience != "" {
			h.AccessControlAllowOrigin = jwt.Audience
		}
	}

	return h
}
