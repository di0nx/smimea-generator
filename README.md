# SMIMEA Generator

Eine clientseitige Web-App zum Erzeugen, optionalen Veröffentlichen und Prüfen von SMIMEA DNS Records für S/MIME Discovery nach RFC 8162. Die Generator- und Check-Funktionen laufen im Browser; für funktionierende Cloudflare-API-Aufrufe auf Cloudflare Pages ist eine kleine Same-Origin Pages Function enthalten.

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
- kann optional per Cloudflare Pages Function oder per `curl` Records in Cloudflare erstellen, aktualisieren oder löschen/neu erstellen
- setzt beim Cloudflare-API-Body automatisch eine Record-Notiz im Format `SMIMEA for <email>`
- enthält eine separate Check-Seite: Nur E-Mail-Adresse eingeben, Owner Name berechnen, vorhandenen SMIMEA Record per DNS-over-HTTPS abrufen und bei `3 0 0` das veröffentlichte Zertifikat anzeigen und als `.der` herunterladen

## Security- und Datenschutz-Hinweise

- Generator, Zertifikatsverarbeitung und DNS-Check laufen im Browser. Nur der optionale Cloudflare-API-Button nutzt auf Cloudflare Pages eine Same-Origin Function als Proxy, weil Cloudflare direkte API-Aufrufe aus fremden Browser-Origins per CORS blockieren kann.
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
- Functions directory: `functions` (Cloudflare erkennt diesen Ordner normalerweise automatisch)
- Root directory: leer lassen / Repository root

Falls im Build-Log `No build command specified. Skipping build step.` steht, ist das nicht fatal, solange `dist/` im Repository vorhanden ist. Wenn weiterhin nur „SMIMEA Generator lädt…“ erscheint, wird die Quell-`index.html` aus der Repository-Wurzel statt `dist/index.html` ausgeliefert; prüfe dann das Pages-Ausgabeverzeichnis und deploye erneut.

### Netlify

- Build command: `npm run build`
- Publish directory: `dist`

## UI-Aufbau

Die App ist als helles, minimalistisches Dashboard mit getrennten Seiten aufgebaut:

- `#/check`: separate Seite zum Prüfen bereits vorhandener Records und zum Herunterladen veröffentlichter Full-Certificate-Zertifikate.
- `#/generator`: Zertifikat hochladen, SAN-Adressen auswählen und SMIMEA Records erzeugen.
- `#/publish`: Cloudflare-Veröffentlichung und curl-Fallback.

Längere Erklärungen und Detailausgaben sind bewusst in aufklappbaren Bereichen (`details`/`summary`) untergebracht, damit die Oberfläche übersichtlich bleibt.

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

Cloudflare blockiert direkte API-Aufrufe aus beliebigen Browser-Origin häufig per CORS. Das Cloudflare Dashboard funktioniert, weil es eine von Cloudflare erlaubte Origin nutzt; eine statische Seite auf einer eigenen Domain hat diese Freigabe normalerweise nicht. Deshalb enthält das Repository eine Cloudflare Pages Function unter `functions/api/cloudflare-dns.ts`. Wenn die App auf Cloudflare Pages deployed ist, ruft der Browser diese Same-Origin-Function auf, und die Function leitet den Request an die Cloudflare API weiter. Auf anderen Hostern kannst du den direkten Browser-Transport testen oder den immer erzeugten `curl`-Befehl lokal ausführen.

Die Function speichert keine Tokens und schreibt sie nicht in Logs; das Token wird nur für den aktuellen API-Request als `Authorization: Bearer ...` weitergereicht. Führe alternativ den `curl`-Befehl lokal in einem Terminal aus oder lege den Record manuell im Cloudflare Dashboard an:

1. Cloudflare Dashboard öffnen.
2. Zone auswählen.
3. DNS → Records → Add record.
4. Typ `SMIMEA` wählen.
5. Name und Content aus der App übernehmen.
6. TTL setzen und speichern.

## Check-Modus

Die Check-Funktion ist eine eigene Seite in der App (`#/check`) und funktioniert auch für Records, die vorher manuell oder mit einem anderen Tool angelegt wurden. Du kannst einfach eine E-Mail-Adresse eingeben; die App berechnet daraus den korrekten SMIMEA Owner Name (`<hash>._smimecert.<mail-domain>`), fragt Cloudflare DoH und Google DoH ab und zeigt den gefundenen Record. Google wird über den RFC-8484-Endpunkt `https://dns.google/dns-query` mit `application/dns-message` abgefragt, nicht über `/resolve`.

Wenn der veröffentlichte Record das vollständige Zertifikat enthält (Selector `0`, Matching Type `0`, typischerweise `3 0 0`), dekodiert die App die DER-Daten direkt aus DNS, zeigt Subject, Issuer, SAN-Adressen, Gültigkeit und Fingerprints an und bietet einen Download als `.der`-Zertifikat an. Bei Hash-basierten Records (`3 0 1`, `3 0 2` oder Selector `1`) kann aus DNS kein vollständiges Zertifikat rekonstruiert werden; die App weist dann darauf hin.

Optional kannst du weiterhin einen FQDN manuell eintragen oder erwarteten SMIMEA Content für einen exakten Vergleich ergänzen. Die App zeigt Status, TTL, AD-Flag und RRSIG-Hinweise an und markiert Abweichungen vom erwarteten Content.

## Projektstruktur

```text
src/
  main.ts                  Minimalistische Mehrseiten-UI und App-Orchestrierung
  style.css                responsives Light/Dark Dashboard
  smimea/
    emailHash.ts           RFC-8162 Local-Part-Hash und Cloudflare-relative Namen
    certificateParser.ts   PEM/DER-Verarbeitung, X.509 Parsing, SPKI-Extraktion
    smimeaRecord.ts        SMIMEA Content-Erzeugung
    dnsCheck.ts            DNS-over-HTTPS Prüfung und Response Parsing
    cloudflareApi.ts       Cloudflare API Requests über Pages Function, direkt oder curl
    smimea.test.ts         Vitest Tests
functions/
  api/cloudflare-dns.ts    Same-Origin Cloudflare-Pages-Proxy für DNS API
```
