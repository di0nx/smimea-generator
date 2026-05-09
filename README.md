# SMIMEA Generator

Eine komplett statische Web-App zum Erzeugen, optionalen Veröffentlichen und Prüfen von SMIMEA DNS Records für S/MIME Discovery nach RFC 8162.

## Was die App macht

- lädt ein S/MIME-Zertifikat (`.pem`, `.crt`, `.cer`, `.der`, `.txt`) vollständig clientseitig im Browser
- liest die RFC822Name/SAN-E-Mail-Adressen aus dem Zertifikat aus
- lässt dich eine oder mehrere der gefundenen Adressen auswählen
- berechnet für jede ausgewählte Adresse den SMIMEA Owner Name nach RFC 8162:
  - SHA-256 über den exakten Local-Part der E-Mail-Adresse
  - erste 28 Bytes / 56 Hex-Zeichen
  - `<hash>._smimecert.<mail-domain>`
- erzeugt den Record Content für frei wählbare Usage-, Selector- und Matching-Type-Kombinationen
- Default und Empfehlung für S/MIME Discovery: `3 0 0 <vollständiges DER-Zertifikat als Hex>`
- zeigt pro Adresse FQDN, Cloudflare-relativen Namen, Record Content, `dig` Command und Cloudflare API JSON an
- kann optional per Cloudflare API Records erstellen, aktualisieren oder löschen/neu erstellen
- setzt beim Cloudflare-API-Body automatisch eine Record-Notiz im Format `SMIMEA for <email>`
- enthält einen Check-Modus für bereits vorhandene Records und prüft per DNS-over-HTTPS bei Cloudflare und Google, ob der Record veröffentlicht wurde und exakt passt

## Security- und Datenschutz-Hinweise

- Es gibt kein Backend. Die App besteht nur aus HTML, CSS und JavaScript.
- Zertifikat und daraus gelesene E-Mail-Adressen bleiben im Browser.
- Keine Analytics, kein Tracking und keine Third-Party-CDNs.
- Daten werden nicht dauerhaft gespeichert, außer du aktivierst explizit „Token lokal merken“.
- Lokales Merken nutzt ausschließlich `localStorage` und ist sichtbar abschaltbar.
- Cloudflare API Token werden niemals hardcodiert.
- Verwende für Cloudflare ein eingeschränktes API Token statt des Global API Key.
- Empfohlene Cloudflare Token Permissions:
  - `Zone:Read`
  - `DNS:Edit`
- Ein API Token im Browser ist sensibel. Am besten erstellst du ein Token, das nur für genau die betroffene Zone gilt.

## Beispiel mit neutralen Platzhaltern

E-Mail:

```text
<selected-email>
```

SMIMEA Owner Name Schema:

```text
<56-hex-localpart-hash>._smimecert.example.org
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

Der statische Produktions-Build liegt danach in `dist/`. Die Vite-Konfiguration nutzt relative Asset-URLs, damit die Seite auch unter GitHub-Pages-Projektpfaden nicht leer bleibt.

## Statisch deployen

Die App ist für statische Hoster geeignet. Wichtig: Deploye den kompletten Inhalt von `dist/`, inklusive `dist/assets/`. Das gebaute `index.html` verweist absichtlich mit relativen Pfaden auf `./assets/...`, damit Deployments in Unterpfaden nicht leer bleiben.

### GitHub Pages

1. `npm run build` ausführen.
2. Den Inhalt von `dist/` als Pages-Artefakt veröffentlichen, z. B. über GitHub Actions.
3. Alternativ kann ein Pages-Workflow Node installieren, `npm ci` und `npm run build` ausführen und `dist/` deployen.

### Cloudflare Pages

Wenn du das Git-Repository verbindest, muss Cloudflare Pages am Ende `dist/` ausliefern. Das Repository enthält eine `wrangler.toml` mit `pages_build_output_dir = "./dist"`; deshalb kann Cloudflare auch dann deployen, wenn kein Build Command gesetzt ist, weil der aktuelle `dist/`-Build eingecheckt ist.

Empfohlen ist trotzdem, Cloudflare Pages so zu konfigurieren, dass bei jedem Git-Deploy neu gebaut wird:

- Framework preset: `Vite` oder `React (Vite)`
- Build command: `npm run build`
- Build output directory: `dist`
- Root directory: leer lassen / Repository root

Falls im Build-Log `No build command specified. Skipping build step.` steht, ist das nicht fatal, solange `dist/` im Repository vorhanden ist. Wenn weiterhin nur „SMIMEA Generator lädt…“ erscheint, wird die Quell-`index.html` aus der Repository-Wurzel statt `dist/index.html` ausgeliefert; prüfe dann das Pages-Ausgabeverzeichnis und deploye erneut.

### Netlify

- Build command: `npm run build`
- Publish directory: `dist`

## Cloudflare API im Browser

Die App nutzt die Cloudflare DNS Records API für `SMIMEA` Records. Der Request enthält formatierten `content`, die strukturierte `data`-Form und eine automatisch gesetzte Notiz mit der ausgewählten E-Mail-Adresse:

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
  },
  "comment": "SMIMEA for <selected-email>"
}
```

Falls Cloudflare API Requests im Browser durch CORS oder Browser-Richtlinien blockiert werden, zeigt die App eine verständliche Fehlermeldung und generiert einen `curl`-Befehl. Führe diesen lokal in einem Terminal aus oder lege den Record manuell im Cloudflare Dashboard an:

1. Cloudflare Dashboard öffnen.
2. Zone auswählen.
3. DNS → Records → Add record.
4. Typ `SMIMEA` wählen.
5. Name und Content aus der App übernehmen.
6. TTL setzen und speichern.

## Check-Modus

Der Check-Modus kann zwei Wege nutzen:

- Mit hochgeladenem Zertifikat: SAN-Adressen auswählen, Records erzeugen und anschließend DNS prüfen.
- Ohne Zertifikat: FQDN eintragen und optional erwarteten SMIMEA Content für einen exakten Vergleich ergänzen.

Die App fragt Cloudflare DoH und Google DoH ab, zeigt Status, TTL, AD-Flag und RRSIG-Hinweise an und markiert Abweichungen vom erwarteten Content.

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
