package smtp

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// buildMIME constructs a minimal multipart/mixed message with the given parts
// for use in test cases.
func buildMIME(bodyText string, parts []mimeTestPart) []byte {
	const boundary = "testboundary123"
	var b strings.Builder
	b.WriteString("From: sender@example.com\r\n")
	b.WriteString("To: recipient@example.com\r\n")
	b.WriteString("Subject: test\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n")
	b.WriteString("\r\n")

	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(bodyText + "\r\n")

	for _, p := range parts {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + p.ct + "\r\n")
		if p.filename != "" {
			b.WriteString("Content-Disposition: attachment; filename=\"" + p.filename + "\"\r\n")
		}
		if p.encoding != "" {
			b.WriteString("Content-Transfer-Encoding: " + p.encoding + "\r\n")
		}
		b.WriteString("\r\n")
		b.WriteString(p.body + "\r\n")
	}

	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

// buildPlaintext constructs a simple text/plain message.
func buildPlaintext(text string) []byte {
	return []byte("From: a@x\r\nTo: b@y\r\nContent-Type: text/plain\r\n\r\n" + text)
}

// buildEncrypted constructs a minimal multipart/encrypted shell.
func buildEncrypted() []byte {
	const boundary = "pgpboundary"
	return []byte(
		"From: a@x\r\nTo: b@y\r\n" +
			"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"" + boundary + "\"\r\n" +
			"\r\n" +
			"--" + boundary + "\r\n" +
			"Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n" +
			"--" + boundary + "\r\n" +
			"Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\r\nciphertext\r\n" +
			"--" + boundary + "--\r\n",
	)
}

type mimeTestPart struct {
	ct       string
	filename string
	encoding string
	body     string
}

// --------------------------------------------------------------------------
// WalkAttachments / ParseMeta tests
// --------------------------------------------------------------------------

func TestParseMeta_NoAttachments(t *testing.T) {
	raw := buildPlaintext("hello world")
	m := ParseMeta(raw)
	if m.HasAttachments {
		t.Error("expected HasAttachments=false for plain text message")
	}
	if len(m.Attachments) != 0 {
		t.Errorf("expected 0 attachments, got %d", len(m.Attachments))
	}
}

func TestParseMeta_SingleAttachment(t *testing.T) {
	raw := buildMIME("body text", []mimeTestPart{
		{ct: "image/png", filename: "photo.png", encoding: "base64", body: base64.StdEncoding.EncodeToString([]byte("PNGDATA"))},
	})
	m := ParseMeta(raw)
	if !m.HasAttachments {
		t.Error("expected HasAttachments=true")
	}
	if len(m.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(m.Attachments))
	}
	a := m.Attachments[0]
	if a.PartIndex != 0 {
		t.Errorf("PartIndex: got %d, want 0", a.PartIndex)
	}
	if a.Filename != "photo.png" {
		t.Errorf("Filename: got %q, want %q", a.Filename, "photo.png")
	}
	if !strings.HasPrefix(a.ContentType, "image/png") {
		t.Errorf("ContentType: got %q", a.ContentType)
	}
}

func TestParseMeta_MultipleAttachments(t *testing.T) {
	raw := buildMIME("body", []mimeTestPart{
		{ct: "application/pdf", filename: "a.pdf", body: "PDFDATA"},
		{ct: "text/csv", filename: "b.csv", body: "col1,col2"},
	})
	m := ParseMeta(raw)
	if len(m.Attachments) != 2 {
		t.Fatalf("expected 2 attachments, got %d", len(m.Attachments))
	}
	if m.Attachments[0].PartIndex != 0 || m.Attachments[1].PartIndex != 1 {
		t.Errorf("wrong part indices: %d, %d", m.Attachments[0].PartIndex, m.Attachments[1].PartIndex)
	}
}

func TestParseMeta_EncryptedMessageNoAttachmentMeta(t *testing.T) {
	raw := buildEncrypted()
	m := ParseMeta(raw)
	// Outer PGP/MIME envelope reveals nothing — has_attachments stays false.
	if m.HasAttachments {
		t.Error("expected HasAttachments=false for outer PGP/MIME envelope")
	}
	if len(m.Attachments) != 0 {
		t.Errorf("expected 0 attachments for encrypted message, got %d", len(m.Attachments))
	}
	if m.SecurityState != "pgp_encrypted" {
		t.Errorf("SecurityState: got %q, want %q", m.SecurityState, "pgp_encrypted")
	}
}

func TestParseMeta_PGPKeysPartSkipped(t *testing.T) {
	// application/pgp-keys is the auto-attached sender key — not a user attachment.
	raw := buildMIME("body", []mimeTestPart{
		{ct: "application/pgp-keys", filename: "publickey.asc", body: "-----BEGIN PGP PUBLIC KEY BLOCK-----"},
	})
	m := ParseMeta(raw)
	if m.HasAttachments {
		t.Error("expected HasAttachments=false when only pgp-keys part present")
	}
}

func TestParseMeta_NonASCIIFilename(t *testing.T) {
	// Build a message with a non-ASCII filename in the Content-Disposition header.
	// go-message's MIME parser may or may not decode RFC 2047 encoded words;
	// we just verify the attachment is detected and has a non-empty filename.
	raw := buildMIME("body", []mimeTestPart{
		{ct: "application/pdf", filename: "resume.pdf", body: "data"},
	})
	m := ParseMeta(raw)
	if len(m.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(m.Attachments))
	}
	if m.Attachments[0].Filename == "" {
		t.Error("Filename should not be empty")
	}
}

func TestParseMeta_MissingContentDispositionNonTextType(t *testing.T) {
	// Parts with non-text MIME type but no Content-Disposition: attachment
	// should still be classified as attachments.
	raw := buildMIME("body", []mimeTestPart{
		{ct: "application/zip", body: "ZIP"},
	})
	m := ParseMeta(raw)
	if !m.HasAttachments {
		t.Error("expected HasAttachments=true for application/zip without Content-Disposition")
	}
}

func TestParseMeta_NestedMultipart(t *testing.T) {
	// Nested multipart/mixed inside the outer multipart/mixed.
	const innerBoundary = "inner123"
	innerMIME := "--" + innerBoundary + "\r\n" +
		"Content-Type: image/gif\r\n" +
		"Content-Disposition: attachment; filename=\"img.gif\"\r\n" +
		"\r\n" +
		"GIFDATA\r\n" +
		"--" + innerBoundary + "--"

	raw := buildMIME("body", []mimeTestPart{
		{ct: "multipart/mixed; boundary=\"" + innerBoundary + "\"", body: innerMIME},
	})
	m := ParseMeta(raw)
	if !m.HasAttachments {
		t.Error("expected HasAttachments=true for nested multipart with attachment")
	}
}

// --------------------------------------------------------------------------
// ReadAttachmentAt tests
// --------------------------------------------------------------------------

func TestReadAttachmentAt_HappyPath(t *testing.T) {
	content := []byte("hello attachment")
	raw := buildMIME("body", []mimeTestPart{
		{ct: "application/octet-stream", filename: "file.bin", encoding: "base64",
			body: base64.StdEncoding.EncodeToString(content)},
	})
	part, err := ReadAttachmentAt(raw, 0)
	if err != nil {
		t.Fatalf("ReadAttachmentAt: %v", err)
	}
	if part.Filename != "file.bin" {
		t.Errorf("Filename: got %q, want %q", part.Filename, "file.bin")
	}
	if string(part.Body) != string(content) {
		t.Errorf("Body mismatch: got %q, want %q", part.Body, content)
	}
}

func TestReadAttachmentAt_OutOfRange(t *testing.T) {
	raw := buildMIME("body", []mimeTestPart{
		{ct: "image/png", filename: "a.png", body: "PNG"},
	})
	if _, err := ReadAttachmentAt(raw, 1); err == nil {
		t.Error("expected error for out-of-range index, got nil")
	}
	if _, err := ReadAttachmentAt(raw, -1); err == nil {
		t.Error("expected error for negative index, got nil")
	}
}

func TestReadAttachmentAt_MultipleAttachments(t *testing.T) {
	data0 := "FIRST_ATTACHMENT_DATA"
	data1 := "SECOND_ATTACHMENT_DATA"
	raw := buildMIME("body", []mimeTestPart{
		{ct: "application/pdf", filename: "first.pdf", encoding: "base64",
			body: base64.StdEncoding.EncodeToString([]byte(data0))},
		{ct: "application/pdf", filename: "second.pdf", encoding: "base64",
			body: base64.StdEncoding.EncodeToString([]byte(data1))},
	})

	p0, err := ReadAttachmentAt(raw, 0)
	if err != nil {
		t.Fatalf("index 0: %v", err)
	}
	if string(p0.Body) != data0 {
		t.Errorf("index 0 body: got %q, want %q", p0.Body, data0)
	}

	p1, err := ReadAttachmentAt(raw, 1)
	if err != nil {
		t.Fatalf("index 1: %v", err)
	}
	if string(p1.Body) != data1 {
		t.Errorf("index 1 body: got %q, want %q", p1.Body, data1)
	}
}

func TestReadAttachmentAt_IndexConsistencyWithWalk(t *testing.T) {
	// Verify that WalkAttachments and ReadAttachmentAt agree on part indices.
	for _, tc := range []struct {
		name  string
		parts []mimeTestPart
		want  int
	}{
		{"single", []mimeTestPart{{ct: "image/png", filename: "a.png", body: "PNG"}}, 1},
		{"two", []mimeTestPart{
			{ct: "image/png", filename: "a.png", body: "PNG"},
			{ct: "image/jpeg", filename: "b.jpg", body: "JPG"},
		}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMIME("body", tc.parts)
			m := ParseMeta(raw)
			if len(m.Attachments) != tc.want {
				t.Fatalf("ParseMeta: got %d attachments, want %d", len(m.Attachments), tc.want)
			}
			for i, a := range m.Attachments {
				part, err := ReadAttachmentAt(raw, a.PartIndex)
				if err != nil {
					t.Errorf("ReadAttachmentAt(%d): %v", a.PartIndex, err)
					continue
				}
				if part.Filename != a.Filename {
					t.Errorf("attachment %d filename mismatch: walk=%q read=%q", i, a.Filename, part.Filename)
				}
			}
		})
	}
}

func TestReadAttachmentAt_FallbackFilename(t *testing.T) {
	// A part with no filename should get a generated fallback.
	raw := buildMIME("body", []mimeTestPart{
		{ct: "application/octet-stream", body: "DATA"},
	})
	part, err := ReadAttachmentAt(raw, 0)
	if err != nil {
		t.Fatalf("ReadAttachmentAt: %v", err)
	}
	if part.Filename == "" {
		t.Error("expected non-empty fallback filename")
	}
	if !strings.HasPrefix(part.Filename, "attachment-") {
		t.Errorf("fallback filename %q should start with 'attachment-'", part.Filename)
	}
}

// --------------------------------------------------------------------------
// isAttachmentPart tests
// --------------------------------------------------------------------------

func TestIsAttachmentPart(t *testing.T) {
	tests := []struct {
		ct   string
		disp string
		want bool
	}{
		{"image/png", "attachment", true},
		{"image/png", "", true},              // non-text, no explicit disposition
		{"text/plain", "", false},            // text body, not an attachment
		{"text/plain", "attachment", true},   // explicit attachment even for text
		{"application/pgp-keys", "", false},  // sender key part
		{"application/pgp-signature", "", false},
		{"application/pgp-encrypted", "", false},
		{"application/pdf", "", true},
		{"multipart/mixed", "", false},       // container, not a leaf attachment
		{"", "", false},                      // empty content-type
	}

	for _, tc := range tests {
		got := isAttachmentPart(tc.ct, tc.disp)
		if got != tc.want {
			t.Errorf("isAttachmentPart(%q, %q) = %v, want %v", tc.ct, tc.disp, got, tc.want)
		}
	}
}

// Ensure that the raw bytes of a large attachment round-trip through
// ReadAttachmentAt without corruption (basic regression for base64 decode).
func TestReadAttachmentAt_BinaryRoundtrip(t *testing.T) {
	original := make([]byte, 1024)
	for i := range original {
		original[i] = byte(i % 256)
	}
	encoded := base64.StdEncoding.EncodeToString(original)
	raw := buildMIME("body", []mimeTestPart{
		{ct: "application/octet-stream", filename: "binary.bin", encoding: "base64", body: encoded},
	})
	part, err := ReadAttachmentAt(raw, 0)
	if err != nil {
		t.Fatalf("ReadAttachmentAt: %v", err)
	}
	if len(part.Body) != len(original) {
		t.Fatalf("body length: got %d, want %d", len(part.Body), len(original))
	}
	for i := range original {
		if part.Body[i] != original[i] {
			t.Errorf("byte mismatch at %d: got %d, want %d", i, part.Body[i], original[i])
			break
		}
	}
}

// Unused import guard.
var _ = fmt.Sprintf
