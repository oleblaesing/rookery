package queue

import (
	"context"
	"io"
	"strings"
	"testing"

	"rookery/internal/config"
	smtppkg "rookery/internal/smtp"
)

// fakeSign prepends a marker line so tests can prove the bytes handed to a
// delivery function are the *signed* output, not the raw message.
func fakeSign(_ context.Context, _ string, r io.Reader) (io.Reader, error) {
	body, _ := io.ReadAll(r)
	return strings.NewReader("X-Signed: yes\r\n" + string(body)), nil
}

func TestDeliverExternal_SmarthostBranchSignsBeforeHandoff(t *testing.T) {
	var (
		smarthostCalled bool
		mxCalled        bool
		gotSmarthost    smtppkg.Smarthost
		gotMsg          []byte
	)

	w := &Worker{
		cfg: &config.Config{
			Domain: "rookery.example",
			SMTP: config.SMTPConfig{Smarthost: config.SmarthostConfig{
				Enabled:    true,
				Host:       "smtp.example",
				Port:       587,
				Username:   "u",
				RequireTLS: true,
				Auth:       true,
			}},
			Secrets: config.Secrets{SMTPRelayPassword: "pw"},
		},
		signFn: fakeSign,
		deliverFn: func(context.Context, string, string, string, []byte) error {
			mxCalled = true
			return nil
		},
		smarthostFn: func(_ context.Context, _ string, sh smtppkg.Smarthost, _, _ string, msg []byte) error {
			smarthostCalled = true
			gotSmarthost = sh
			gotMsg = msg
			return nil
		},
	}

	deliveryErr, internalErr := w.deliverExternal(context.Background(),
		"rookery.example", "from@rookery.example", "to@elsewhere.example", []byte("Subject: hi\r\n\r\nbody\r\n"))
	if deliveryErr != nil || internalErr != nil {
		t.Fatalf("deliverExternal: deliveryErr=%v internalErr=%v", deliveryErr, internalErr)
	}

	if !smarthostCalled {
		t.Error("smarthost branch was not taken despite Enabled = true")
	}
	if mxCalled {
		t.Error("direct-MX path was called despite smarthost enabled")
	}
	// Sign-then-handoff: the smarthost must receive the signed bytes.
	if !strings.HasPrefix(string(gotMsg), "X-Signed: yes") {
		t.Errorf("message handed to smarthost was not signed first: %q", gotMsg)
	}
	// Config → Smarthost struct mapping, including the password from secrets.
	if gotSmarthost.Host != "smtp.example" || gotSmarthost.Username != "u" ||
		gotSmarthost.Password != "pw" || !gotSmarthost.RequireTLS || !gotSmarthost.Auth {
		t.Errorf("smarthost params mismatch: %+v", gotSmarthost)
	}
}

func TestDeliverExternal_DirectMXWhenDisabled(t *testing.T) {
	var smarthostCalled, mxCalled bool
	var gotMsg []byte

	w := &Worker{
		cfg: &config.Config{
			Domain: "rookery.example",
			SMTP:   config.SMTPConfig{Smarthost: config.SmarthostConfig{Enabled: false}},
		},
		signFn: fakeSign,
		deliverFn: func(_ context.Context, _, _, _ string, msg []byte) error {
			mxCalled = true
			gotMsg = msg
			return nil
		},
		smarthostFn: func(context.Context, string, smtppkg.Smarthost, string, string, []byte) error {
			smarthostCalled = true
			return nil
		},
	}

	if _, internalErr := w.deliverExternal(context.Background(),
		"rookery.example", "from@rookery.example", "to@elsewhere.example", []byte("body")); internalErr != nil {
		t.Fatalf("internalErr: %v", internalErr)
	}

	if smarthostCalled {
		t.Error("smarthost branch taken despite Enabled = false")
	}
	if !mxCalled {
		t.Error("direct-MX path not taken when smarthost disabled")
	}
	if !strings.HasPrefix(string(gotMsg), "X-Signed: yes") {
		t.Errorf("message handed to MX delivery was not signed first: %q", gotMsg)
	}
}
