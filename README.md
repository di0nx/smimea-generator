# SMIMEA Generator

Eine komplett statische Web-App zum Erzeugen, optionalen Veröffentlichen und Prüfen von SMIMEA DNS Records für S/MIME Discovery nach RFC 8162.

## Was die App macht

- nimmt eine E-Mail-Adresse und ein S/MIME-Zertifikat entgegen (`.pem`, `.crt`, `.cer`, `.der`, `.txt`)
- verarbeitet Zertifikat und E-Mail vollständig im Browser
- konvertiert PEM nach DER und nutzt DER direkt, wenn bereits vorhanden
- zeigt Zertifikatsdetails inklusive Subject, Issuer, Serial, Gültigkeit, Algorithmen, SAN/RFC822Name, Key Usage, Extended Key Usage sowie SHA-256/SHA-512 Fingerprints an
- berechnet den SMIMEA Owner Name nach RFC 8162:
  - SHA-256 über den exakten Local-Part der E-Mail-Adresse
  - erste 28 Bytes / 56 Hex-Zeichen
  - `<hash>._smimecert.<mail-domain>`
- erzeugt den Record Content für frei wählbare Usage-, Selector- und Matching-Type-Kombinationen
- Default und Empfehlung für S/MIME Discovery: `3 0 0 <vollständiges DER-Zertifikat als Hex>`
- zeigt FQDN, Cloudflare-relativen Namen, Record Content, `dig` Command und Cloudflare API JSON an
- kann optional per Cloudflare API einen Record erstellen, aktualisieren oder löschen/neu erstellen
- prüft per DNS-over-HTTPS bei Cloudflare und Google, ob der Record veröffentlicht wurde und exakt passt

## Security- und Datenschutz-Hinweise

- Es gibt kein Backend. Die App besteht nur aus HTML, CSS und JavaScript.
- E-Mail-Adresse und Zertifikat bleiben im Browser.
- Keine Analytics, kein Tracking und keine Third-Party-CDNs.
- Daten werden nicht dauerhaft gespeichert, außer du aktivierst explizit „Token lokal merken“.
- Lokales Merken nutzt ausschließlich `localStorage` und ist sichtbar abschaltbar.
- Cloudflare API Token werden niemals hardcodiert.
- Verwende für Cloudflare ein eingeschränktes API Token statt des Global API Key.
- Empfohlene Cloudflare Token Permissions:
  - `Zone:Read`
  - `DNS:Edit`
  - optional `Account:Read`, wenn du Account-Informationen in eigenen Workflows auflösen möchtest
- Ein API Token im Browser ist sensibel. Am besten erstellst du ein Token, das nur für genau die betroffene Zone gilt.

## Beispiel

E-Mail:

```text
dion@kitsos.net
```

Erwarteter SMIMEA Owner Name:

```text
d55bcf8025bdb22b72cf95c0306748d814c0effe3859bddc00d2b1aa._smimecert.kitsos.net
```

Default Record:

```text
3 0 0 <DER certificate hex>
```

## Lokal starten

```bash
npm install
npm run dev
```

Danach die von Vite ausgegebene lokale URL im Browser öffnen.

## Tests und Build

```bash
npm test
npm run build
```

Der statische Produktions-Build liegt danach in `dist/`.

## Statisch deployen

Die App ist für statische Hoster geeignet:

### GitHub Pages

1. `npm run build` ausführen.
2. Den Inhalt von `dist/` als Pages-Artefakt veröffentlichen, z. B. über GitHub Actions.
3. Alternativ kann ein Pages-Workflow Node installieren, `npm ci` und `npm run build` ausführen und `dist/` deployen.

### Cloudflare Pages

- Framework preset: `Vite`
- Build command: `npm run build`
- Output directory: `dist`

### Netlify

- Build command: `npm run build`
- Publish directory: `dist`

## Cloudflare API im Browser

Die App nutzt die aktuelle Cloudflare DNS Records API für `SMIMEA` Records. Der Request enthält sowohl formatierten `content` als auch die strukturierte `data`-Form:

```json
{
  "type": "SMIMEA",
  "name": "<fqdn>",
  "content": "3 0 0 ...",
  "ttl": 300,
  "data": {
    "usage": 3,
    "selector": 0,
    "matching_type": 0,
    "certificate": "..."
  }
}
```

Falls Cloudflare API Requests im Browser durch CORS oder Browser-Richtlinien blockiert werden, zeigt die App eine verständliche Fehlermeldung und generiert einen `curl`-Befehl. Führe diesen lokal in einem Terminal aus oder lege den Record manuell im Cloudflare Dashboard an:

1. Cloudflare Dashboard öffnen.
2. Zone auswählen.
3. DNS → Records → Add record.
4. Typ `SMIMEA` wählen.
5. Name und Content aus der App übernehmen.
6. TTL setzen und speichern.

## Projektstruktur

```text
src/
  main.ts                  UI und App-Orchestrierung
  style.css                responsives Light/Dark Dashboard
  smimea/
    emailHash.ts           RFC-8162 Local-Part-Hash und Cloudflare-relative Namen
    certificateParser.ts   PEM/DER-Verarbeitung, X.509 Parsing, SPKI-Extraktion
    smimeaRecord.ts        SMIMEA Content-Erzeugung
    dnsCheck.ts            DNS-over-HTTPS Prüfung und Response Parsing
    cloudflareApi.ts       Cloudflare API Requests und curl-Fallback
    smimea.test.ts         Vitest Tests
```
