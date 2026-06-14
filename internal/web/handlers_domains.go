package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"rookery/internal/auth"
	"rookery/internal/domains"
)

func handleMTASTS(domMgr *domains.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		if !strings.HasPrefix(host, "mta-sts.") {
			http.NotFound(w, r)
			return
		}
		domainName := strings.TrimPrefix(host, "mta-sts.")

		d, err := domMgr.GetByName(r.Context(), domainName)
		if err != nil || d.VerifiedAt == nil {
			http.NotFound(w, r)
			return
		}

		mode := domMgr.EffectiveMTASTSMode(d)
		if mode == "disabled" {
			http.NotFound(w, r)
			return
		}

		mxHost := domMgr.PrimaryDomain()
		maxAge := 86400
		if mode == "enforce" {
			maxAge = 604800
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "version: STSv1\nmode: %s\nmx: %s\nmax_age: %d\n",
			mode, mxHost, maxAge)
	}
}

func handleTLSAsk(domMgr *domains.Manager) http.HandlerFunc {
	primary := domMgr.PrimaryDomain()
	return func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, "domain required", http.StatusBadRequest)
			return
		}

		switch domain {
		case primary,
			"mta-sts." + primary,
			"openpgpkey." + primary:
			w.WriteHeader(http.StatusOK)
			return
		}

		for _, pfx := range []string{"mta-sts.", "openpgpkey."} {
			if strings.HasPrefix(domain, pfx) {
				base := strings.TrimPrefix(domain, pfx)
				d, err := domMgr.GetByName(r.Context(), base)
				if err == nil && d.VerifiedAt != nil {
					w.WriteHeader(http.StatusOK)
					return
				}
				break
			}
		}

		http.Error(w, "domain not approved", http.StatusForbidden)
	}
}

type domainResponse struct {
	ID         string     `json:"id"`
	Domain     string     `json:"domain"`
	VerifiedAt *time.Time `json:"verified_at"`
	PendingDNS []dnsEntry `json:"pending_dns,omitempty"`
	MTASTSMode string     `json:"mta_sts_mode"`
	MTASTSID   string     `json:"mta_sts_id"`
	CatchAll   bool       `json:"catch_all_enabled"`
	CreatedAt  time.Time  `json:"created_at"`
}

type dnsEntry struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	Group string `json:"group"`
}

func domainToResponse(d *domains.Domain, primaryDomain string) domainResponse {
	r := domainResponse{
		ID:         d.ID,
		Domain:     d.Domain,
		VerifiedAt: d.VerifiedAt,
		CatchAll:   d.CatchAllEnabled,
		CreatedAt:  d.CreatedAt,
	}
	if d.MTASTSMode != nil {
		r.MTASTSMode = *d.MTASTSMode
	}
	if d.MTASTSID != nil {
		r.MTASTSID = *d.MTASTSID
	}
	if d.VerifiedAt == nil {
		r.PendingDNS = buildRequiredDNS(d, primaryDomain)
	}
	return r
}

// Empty Status / no DNS lookups, so the settings page reuses the verify-status table layout.
func requiredRecords(d *domains.Domain, primary string) []domains.RecordStatus {
	entries := buildRequiredDNS(d, primary)
	out := make([]domains.RecordStatus, 0, len(entries))
	for _, e := range entries {
		out = append(out, domains.RecordStatus{
			Name:     e.Name,
			Type:     e.Type,
			Key:      keyForEntry(e),
			Expected: e.Value,
		})
	}
	return out
}

// Maps to the same RecordStatus.Key checkDNSRecords emits, so both paths group identically.
func keyForEntry(e dnsEntry) string {
	switch {
	case e.Type == "TXT" && strings.HasPrefix(e.Name, "_rookery-challenge."):
		return "CHALLENGE"
	case e.Type == "MX":
		return "MX"
	case e.Type == "TXT" && strings.HasPrefix(e.Value, "v=spf1"):
		return "SPF"
	case e.Type == "CNAME" && strings.HasPrefix(e.Name, "rookery-ed25519."):
		return "DKIM_ED25519_CNAME"
	case e.Type == "CNAME" && strings.HasPrefix(e.Name, "rookery-rsa."):
		return "DKIM_RSA_CNAME"
	case e.Type == "CNAME" && strings.HasPrefix(e.Name, "openpgpkey."):
		return "WKD_CNAME"
	case e.Type == "CNAME" && strings.HasPrefix(e.Name, "mta-sts."):
		return "MTA_STS_CNAME"
	case e.Type == "TXT" && strings.HasPrefix(e.Name, "_mta-sts."):
		return "MTA_STS_TXT"
	case e.Type == "TXT" && strings.HasPrefix(e.Name, "_dmarc."):
		return "DMARC"
	case e.Type == "TXT" && strings.HasPrefix(e.Name, "_smtp._tls."):
		return "TLS_RPT"
	}
	return ""
}

func buildRequiredDNS(d *domains.Domain, primary string) []dnsEntry {
	var entries []dnsEntry

	token := ""
	if d.VerificationToken != nil {
		token = *d.VerificationToken
	}
	mtsID := ""
	if d.MTASTSID != nil {
		mtsID = *d.MTASTSID
	}

	entries = append(entries,
		dnsEntry{
			Group: "verification (TXT)",
			Name:  "_rookery-challenge." + d.Domain,
			Type:  "TXT",
			Value: token,
		},
		dnsEntry{
			Group: "mail routing (MX)",
			Name:  d.Domain,
			Type:  "MX",
			Value: "10 " + primary,
		},
		dnsEntry{
			Group: "SPF (TXT)",
			Name:  d.Domain,
			Type:  "TXT",
			Value: "v=spf1 include:_spf." + primary + " ~all",
		},
		dnsEntry{
			Group: "DKIM (CNAME)",
			Name:  "rookery-ed25519._domainkey." + d.Domain,
			Type:  "CNAME",
			Value: "rookery-ed25519._domainkey." + primary,
		},
		dnsEntry{
			Group: "DKIM (CNAME)",
			Name:  "rookery-rsa._domainkey." + d.Domain,
			Type:  "CNAME",
			Value: "rookery-rsa._domainkey." + primary,
		},
		dnsEntry{
			Group: "web key directory (CNAME)",
			Name:  "openpgpkey." + d.Domain,
			Type:  "CNAME",
			Value: "openpgpkey." + primary,
		},
		dnsEntry{
			Group: "MTA-STS policy (CNAME)",
			Name:  "mta-sts." + d.Domain,
			Type:  "CNAME",
			Value: "mta-sts." + primary,
		},
		dnsEntry{
			Group: "MTA-STS version (TXT)",
			Name:  "_mta-sts." + d.Domain,
			Type:  "TXT",
			Value: "v=STSv1; id=" + mtsID,
		},
		dnsEntry{
			Group: "DMARC (TXT)",
			Name:  "_dmarc." + d.Domain,
			Type:  "TXT",
			Value: "v=DMARC1; p=quarantine; rua=mailto:postmaster@" + d.Domain,
		},
		dnsEntry{
			Group: "TLS-RPT (TXT)",
			Name:  "_smtp._tls." + d.Domain,
			Type:  "TXT",
			Value: "v=TLSRPTv1; rua=mailto:postmaster@" + d.Domain,
		},
	)
	return entries
}

func handleAPIRegisterDomain(domMgr *domains.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		var req struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body.")
			return
		}
		req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
		if req.Domain == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "domain is required.")
			return
		}

		d, err := domMgr.Register(r.Context(), userID, req.Domain)
		if errors.Is(err, domains.ErrConflict) {
			respondError(w, http.StatusConflict, "DOMAIN_CONFLICT", "Domain already registered.")
			return
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not register domain.")
			return
		}
		respondJSON(w, http.StatusCreated, domainToResponse(d, domMgr.PrimaryDomain()))
	}
}

func handleAPIListDomains(domMgr *domains.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		list, err := domMgr.ListForUser(r.Context(), userID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not list domains.")
			return
		}
		out := make([]domainResponse, 0, len(list))
		for i := range list {
			out = append(out, domainToResponse(&list[i], domMgr.PrimaryDomain()))
		}
		respondJSON(w, http.StatusOK, out)
	}
}

func handleAPIGetDomain(domMgr *domains.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		id := r.PathValue("id")

		d, err := domMgr.Get(r.Context(), id)
		if errors.Is(err, domains.ErrNotFound) {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "Domain not found.")
			return
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch domain.")
			return
		}
		if d.OwnerUserID == nil || *d.OwnerUserID != userID {
			respondError(w, http.StatusForbidden, "FORBIDDEN", "Not your domain.")
			return
		}
		respondJSON(w, http.StatusOK, domainToResponse(d, domMgr.PrimaryDomain()))
	}
}

func handleAPIDeleteDomain(domMgr *domains.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		id := r.PathValue("id")

		if err := domMgr.Delete(r.Context(), id, userID); err != nil {
			switch {
			case errors.Is(err, domains.ErrNotFound):
				respondError(w, http.StatusNotFound, "NOT_FOUND", "Domain not found.")
			case errors.Is(err, domains.ErrForbidden):
				respondError(w, http.StatusForbidden, "FORBIDDEN", "Not your domain.")
			case errors.Is(err, domains.ErrAddressesExist):
				respondError(w, http.StatusConflict, "ADDRESSES_EXIST",
					"Remove all non-reserved addresses on this domain first.")
			default:
				respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not delete domain.")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleAPIVerifyDomain(domMgr *domains.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		id := r.PathValue("id")

		// Ownership check before the (slower) DNS queries.
		d, err := domMgr.Get(r.Context(), id)
		if errors.Is(err, domains.ErrNotFound) {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "Domain not found.")
			return
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch domain.")
			return
		}
		if d.OwnerUserID == nil || *d.OwnerUserID != userID {
			respondError(w, http.StatusForbidden, "FORBIDDEN", "Not your domain.")
			return
		}

		result, err := domMgr.CheckVerification(r.Context(), id)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "DNS check failed.")
			return
		}
		respondJSON(w, http.StatusOK, result)
	}
}

func handleAPIPatchDomain(domMgr *domains.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		id := r.PathValue("id")

		var req struct {
			MTASTSMode      *string `json:"mta_sts_mode"` // null clears override
			CatchAllEnabled *bool   `json:"catch_all_enabled"`
			CatchAllTarget  string  `json:"catch_all_address_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body.")
			return
		}

		if req.MTASTSMode != nil {
			mode := *req.MTASTSMode
			if err := domMgr.SetMTASTSMode(r.Context(), id, userID, mode); err != nil {
				switch {
				case errors.Is(err, domains.ErrNotFound):
					respondError(w, http.StatusNotFound, "NOT_FOUND", "Domain not found.")
				case errors.Is(err, domains.ErrForbidden):
					respondError(w, http.StatusForbidden, "FORBIDDEN", "Not your domain.")
				default:
					respondError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
				}
				return
			}
		}

		if req.CatchAllEnabled != nil {
			if err := domMgr.SetCatchAll(r.Context(), id, userID, *req.CatchAllEnabled, req.CatchAllTarget); err != nil {
				switch {
				case errors.Is(err, domains.ErrNotFound):
					respondError(w, http.StatusNotFound, "NOT_FOUND", "Domain not found.")
				case errors.Is(err, domains.ErrForbidden):
					respondError(w, http.StatusForbidden, "FORBIDDEN", "Not your domain.")
				default:
					respondError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
				}
				return
			}
		}

		d, err := domMgr.Get(r.Context(), id)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch domain.")
			return
		}
		respondJSON(w, http.StatusOK, domainToResponse(d, domMgr.PrimaryDomain()))
	}
}

type recordGroup struct {
	Label   string
	Records []domains.RecordStatus
}

// The label carries the DNS type so the template can drop the per-row type column.
var recordKeyGroup = map[string]string{
	"CHALLENGE":          "verification (TXT)",
	"MX":                 "mail routing (MX)",
	"SPF":                "SPF (TXT)",
	"DKIM_ED25519_CNAME": "DKIM (CNAME)",
	"DKIM_RSA_CNAME":     "DKIM (CNAME)",
	"WKD_CNAME":          "web key directory (CNAME)",
	"MTA_STS_CNAME":      "MTA-STS policy (CNAME)",
	"MTA_STS_TXT":        "MTA-STS version (TXT)",
	"DMARC":              "DMARC (TXT)",
	"TLS_RPT":            "TLS-RPT (TXT)",
}

var recordGroupOrder = []string{
	"verification (TXT)",
	"mail routing (MX)",
	"SPF (TXT)",
	"DKIM (CNAME)",
	"DMARC (TXT)",
	"web key directory (CNAME)",
	"MTA-STS policy (CNAME)",
	"MTA-STS version (TXT)",
	"TLS-RPT (TXT)",
	"other",
}

func groupRecords(records []domains.RecordStatus) []recordGroup {
	byLabel := make(map[string][]domains.RecordStatus)
	for _, r := range records {
		label := recordKeyGroup[r.Key]
		if label == "" {
			label = "other"
		}
		byLabel[label] = append(byLabel[label], r)
	}
	out := make([]recordGroup, 0, len(byLabel))
	for _, label := range recordGroupOrder {
		if recs, ok := byLabel[label]; ok {
			out = append(out, recordGroup{Label: label, Records: recs})
		}
	}
	return out
}

type verifyStatusData struct {
	Domain          *domains.Domain
	Result          *domains.VerificationResult
	PrimaryDomain   string
	Groups          []recordGroup
	MTASTSMode      string
	MTASTSEnforceAt *time.Time
}

func handleDomainVerifyStatusFragment(domMgr *domains.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		id := r.PathValue("id")

		d, err := domMgr.Get(r.Context(), id)
		if errors.Is(err, domains.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil || d.OwnerUserID == nil || *d.OwnerUserID != userID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		result, err := domMgr.CheckVerification(r.Context(), id)
		if err != nil {
			http.Error(w, "dns check failed", http.StatusInternalServerError)
			return
		}

		// CheckVerification may have just set verified_at; re-fetch to reflect it.
		d, _ = domMgr.Get(r.Context(), id)

		data := verifyStatusData{
			Domain:        d,
			Result:        result,
			PrimaryDomain: domMgr.PrimaryDomain(),
			Groups:        groupRecords(result.Records),
		}
		if result.Verified {
			data.MTASTSMode = domMgr.EffectiveMTASTSMode(d)
			if d.MTASTSMode == nil && d.MTASTSModeChangedAt != nil {
				enforceAt := d.MTASTSModeChangedAt.Add(48 * time.Hour)
				if enforceAt.After(time.Now()) {
					data.MTASTSEnforceAt = &enforceAt
				}
			}
		}
		renderFragment(w, "domain_verify_status.gohtml", data)
	}
}
