# fxcloud paq - lutmeywIj

paqDaj moHwIjvam lutmey lo'wI'wIj: nom, che' lutmey, boq, chuSQang, je
passkey. nItlhvam paqqu'wI' wa'DIch lutmeywIj chut yIpoS - ngagh
pujlaHbogh chut, cloud.example.com.

Developer-facing documents:

- [README.md](README.md) - the feature list and the map of this documentation
- [INSTALL.md](INSTALL.md) - install, configuration table, systemd unit
- [API.md](API.md) - HTTP endpoints and protocol details
- [ENCRYPTION.md](ENCRYPTION.md) - the cryptographic design in full
- [ARCHITECTURE.md](ARCHITECTURE.md) - code layout, storage, quotas

## nIteb

1. [Installation](#1-installation)
2. [yuQ chu'](#2-yuq-chu)
3. [nom](#3-nom)
4. [che' lutmey](#4-che-lutmey)
5. [boq](#5-boq)
6. [ghom bIQroq](#6-ghom-biqroq)
7. [bIQtIq](#7-biqtiq)
8. [quota](#8-quota)
9. [lo'wI' poH](#9-lowi-poh)
10. [choH](#10-choh)
11. [chuSQang](#11-chusqang)
12. [Passkeys](#12-passkeys)
13. [HTTPS paS'op](#13-https-pasop-worked-example)
14. [WebDAV](#14-webdav)
15. [Troubleshooting](#15-troubleshooting)

## 1. Installation

fxcloud chut wa'DIch: SQLite je weboberfläche poS, database chut je
runtime chut neH.

**chut wa'DIch** - fxcloud systemdDaq chut, curl je Linux (pujDaq);
chut chutDat yIpoS:

```bash
curl -fsSL https://raw.githubusercontent.com/floyd54/fxcloud/main/install.sh | sh
```

**chu' binary** - GitHub ReleasesDaq tag lughlu'bogh Datachugh, static
Linux x86_64 build (~6 MB) botlu':

```bash
chmod +x fxcloud-<tag>-x86_64-unknown-linux-musl
FXCLOUD_DATA=/srv/fxcloud ./fxcloud-<tag>-x86_64-unknown-linux-musl
```

**Sourcevo'**:

```bash
cargo build --release
./target/release/fxcloud      # ./data chut, DB je file blobs
```

<http://127.0.0.1:8080> poS. systemdDaq chutmey, hardened unit
lo': [`deploy/fxcloud.service`](deploy/fxcloud.service) -
[INSTALL.md](INSTALL.md#deployment) chut steps bot. chut chutDat neH
environment variables (bind address, port, data directory, quota-related
limits, ...); table complete in [INSTALL.md](INSTALL.md#configuration).

## 2. yuQ chu'

Instance chu'chugh, **yuQ chu'** tab poS, username (mI' wa' je chop),
display name, je password (mI' jav je chop) wIv.

**yuQ chu'Daq** instanceDaq chu'bogh yuQ nomDaq activate, administrator
qaw'lu'. yuQ chu'boghDat yuQ nomDaq activate: registration qang, nom
administratorDaq activate chunwI' yuQ chel (see
[lo'wI' poH](#9-lowi-poh)).

## 3. nom

nom pageDat tab wej:

- **nom** - username je password.
- **Passkey** - username neH; chut puj biometrics (see
  [Passkeys](#12-passkeys)).
- **yuQ chu'** - registration, chutDat.

Session juH7 (default) (`FXCLOUD_SESSION_TTL`, useDaq sliding).

### App chut

fxcloud web app chut: Chrome/Edge address bar **App install** iPhone/iPad
Safari **Share > Add to Home Screen**, Android Chrome **menu > Add to
home screen**. app iconvo' poS, browser chrome neH - yuQ chut, session
chut, configure chut.

paQ'a' yIjatlh: launcher neH (offline chut neH - fxcloud server client),
service worker app chutDaq **cache chut** - installed app server botlu'ghach
neH legh ([ENCRYPTION.md](ENCRYPTION.md), section11).

app chutDat JavaScript check: app yIpoS fresh app yIpoS default off je
install dialog switch chut (Google PixelDaq report). symptom: nom page
dead - see [Troubleshooting](#15-troubleshooting); icon long-press >
Settings > JavaScript chut.

## 4. che' lutmey

file explorer desktop file manager, browserDaq:

- **che' chu'** / **bIQroq chu'** current folderDat entry chu'; che' text
  file editorDat poS (Markdown preview je **qan**).
- **che' laD** / **bIQroq laD**, je drop zone drag & drop, file je whole
  folder tree laD (empty subfolder included).
- **nogh yItu'** name dotvo' entry toggle; choice browserDat remember.
- file click preview: image, video, audio, PDF, HTML je text lightboxDat
  poS; text file editorDat poS.
- editor unsaved changepo' close - gallery arrowvo' file chel - yIjatlh
  default **qan** (Enter), **mej** je **taHbe'**. save qaw'lu'chugh
  lightbox taH status lineDat error, text qaw'lu'neH.
- selection checkbox (Shift+click range) bulk bar bot: **yuD**
  (selection wa' ZIP), **ghoS...**, **qon...**, **boq**, **qaw** je
  **wIv yIchIm**.
- row menuDat: yuD, boq, gHoS, qon, pong chu', qaw.
- folder row recursive size bot; breadcrumb treevo' yIpoS.

ZIP download requestDaq assemble, uncompressed1 GiB cap; item puS yIwiv
error yIjatlhchugh.

### QeS

content replace - editor **qan**, WebDAV `PUT` - replaced bytes QeSDat
keep, wrong save file'Daq ending neH. row menu **QeS** file history poS,
newest first, time je size versionDat:

- **yuD** version exact bytes, range included (player versionDat seek
  current file'latlh).
- **qa'** swap: wIv version file content, current newest version - qa'
  chuqDaq je qa'lu'.
- **qaw** version je bytes qaw.

read-only share history legh je version yuD; change write perm. kept
version quotaDaq count, trash file history purgeDat. **choH** ("QeS")
wej bound: file versionDaq chenmoH, je age days - `0` bound disable.
background sweep age bound trash purge cadence; count bound version saveDat
apply.

### Office lutmey

instance office engine chut (see
[INSTALL.md](INSTALL.md#office-integration-optional)), office file -
docx, xlsx, pptx, odt, ods, odp - browser editorDat poS (inert neH):
file click (row menu **poS**), chooseH, close. save write same door: quota
count, QeSDat show, encrypted fileDat refuse (built-in editor handle). engine
chut chugh nothing change - row latlhBeh.

## 5. boq

file je folder instance accountDat boq:

1. item wIv, **boq** yIpoS.
2. dropdownvo' user wIv.
3. permission tick: **legh**, **choH**, **chu'**, **qaw** (boq box
   wejlu', boq chut, effect chut neH).
4. **boq** yIpoS.

boq user root file treeDat show, your name mark; name taken chugh, suffix
bot (`Projekte` `Projekte (alice) 2`Dat). shared folderDat chu'bogh
anything *your* treeDat land, *your* quotaDaq count.

revoke: item **boq** dialog chutDat yIpoS, personDap **yu'** yIpoS.

[chuSQang](#11-chusqang) both sides chut, boq key envelope bot - other
person public keyvo' seal; fingerprint dialogDat show, bandDat compare,
trust chunwI'.

### Public link

public link folder je file bot URL lo'wI' - yuQ neH, nom neH. **Public
link** section **boq** dialogDat:

1. visitor wIv: **Read - view and download**, **Add - upload only** je
   **Full - upload, download and delete**.
2. link expiry wIv: **30/90 days after last use** (rolling, default),
   **30/90 days after creation** (fixed) je **Never**.
3. optional **Label** yIchuv, link DIS distinction.
4. **Create link** yIpoS. URL wa'DIch, **Copy link** button - copy now.
   server hash token neH, URL chut neH chut.

link lo'wI' plain page folder contents legh (folder wej level, download
attachment) - nom neH, referrer neH, search engine index neH. link item
exact je below reach; account Dat something else expose.

section every link created list: label, preset, deadline, last visit je
download count, **yu'** revoke. revoke instant - URL *not found* bot next
requestvo'.

qaSbogh yIjatlh:

- **rolling vs. fixed:** rolling link visit je day qaw'lu' neH, visit
  deadline full windowDat push. fixed link create N daysDat expire, open
  qaj. expired link "gone" bot first, shortly after permanent - open
  chu'chugh je bring back.
- **Add je Full writeable inbox link:** URL lo'wI' *your* treeDat file
  put (*your* quotaDaq count). **Add** visitor upload box neH - list je
  download chut, file name je. **Full** chugh browse je delete inside
  shared folder - delete *your* trashDat land, shared folder own linkvo'
  delete chut. **Read** wivchugh hand out neH.
- **plaintext neH:** encrypted file je folder link chut (section yIjatlh),
  linked folder encrypted file visitorDat invisible taH.
- **ghom bIQroq link chut** - membership access grant.

## 6. ghom bIQroq

ghom bIQroq ghom bot, person neH: workspace chu', own quota, managed
membership, memberDat tree latlh. ghom bIQroq ghom name badge rootDat wear,
same name personal folderDIS distinction.

**chu'.** administrator ghom chu' (see [lo'wI' poH](#9-lowi-poh): name,
quota MiB, member role - creator first manager vo'). ghom root folder
**ghom bIQroq chu'** buttonvo' chu' file list topDat - root listingDat neH,
ghom member chutDat. from member rootDat folder legh, whole tree work -
upload, pong, gHoS, bIQtIq - individual boq neH. ghom bIQroq person boq
chut: membership access grant.

**quota.** ghom storage own budget, administrator set. ghom bIQroq write
ghomDaq count, your personal quota neH; ghom full chugh `507 Insufficient
Storage` bot, budget raise chutpu' je someone space free. trash file purgeDat
count taH.

**pon.** chuSQang chut, manager folder pon distribute: ghom root row menu
("..." column) **bIQroq pon yIpevn** yIpoS, then member wa'DaQ wrap je
send. pon chut member file name legh, content decrypt chut; file encryption
setup chut member pon receive chut (button yIjatlh). pon membership follow:
member remove chugh ghom pon remove.

**bIQtIq je delete.** ghom file trashDat land, member ghom trash row own
trash viewDat legh - qa' je purge memberDat. ghom administrator delete empty
chugh: member neH, folder neH.

## 7. bIQtIq

nothing instant delete: **qaw** entry your personal trash ghoS, **qa'**
je **permanent qaw**. **bIQtIq yIQaw** everything clear.

background sweep trash entry30 daysDat qaw' (`FXCLOUD_TRASH_DAYS`);
trash list entry deadline bot, trash content your quotaDaq count taH.

## 8. quota

every account storage quota - default1 GiB, administrator accountDat set.
count *your own*: upload file, copy create, other *your* share content
original ownerDaq count. exceed chugh clear `507 Insufficient Storage`
web UI je WebDAV; current use **choH** show ("Storage: used of quota").

## 9. lo'wI' poH

administrator top bar name menuDaq **lo'wI' poH** entry. dialog **Users**
tab poS; **Group folders** tab [section6](#6-ghom-biqroq) group admin
bot. Users tabDat:

- account **activate / deactivate** (instant: session je WebDAV included;
  administrator self deactivate chut),
- **administrator role grant / revoke** (last active administrator
  deactivate chut je demote chut),
- account **quota set**,
- **password reset**, user next nomDat one-time temporary password bot.

deactivated account nom je WebDAV chut,403 bot administrator yIchel.
display name, je password listDat *neH*: user **choH** self change.

same switch databaseDat available (restart neH). systemd deploy file
`/home/fxcloud/data/fxcloud.db`, development `./data/fxcloud.db`:

```bash
DB=/home/fxcloud/data/fxcloud.db

# overview
sqlite3 "$DB" "SELECT id, username, is_active, is_admin, quota_bytes FROM users ORDER BY id;"

# activate / deactivate (takes effect instantly: sessions + WebDAV included)
sqlite3 "$DB" "UPDATE users SET is_active = 1 WHERE username = 'max';"
sqlite3 "$DB" "UPDATE users SET is_active = 0 WHERE username = 'max';"

# administrator role
sqlite3 "$DB" "UPDATE users SET is_admin = 1 WHERE username = 'max';"

# quota (bytes;1073741824 =1 GiB, the default for every account)
sqlite3 "$DB" "UPDATE users SET quota_bytes = 2147483648 WHERE username = 'alice';"
```

## 10. choH

top bar name menuDat **choH** poS:

- **Konto** - username, member since, storage quotaDaq.
- **Display name** - your self change, other userDat show.
- **Theme** - light je dark.
- **Password** - change; current password first yIchel.
- **Passkeys** - your nom device manage (below).

## 11. chuSQang

fxcloud file **your browser**Dat encrypt, your device leave chenN: server
ciphertext je wrapped key store, file name, size je share je legh - storage
service needed. full design (threat model, key hierarchy, DECISIONs)
[ENCRYPTION.md](ENCRYPTION.md); user view:

- top bar badge state show: **chuSQang laD** (setup chut neH),
  **Unencrypted**, je **Encrypted**.
- enablechugh, **fxcloud nom password use** (default) je **separate
  password choose** wIv.
- then **Recovery key** (64 hex digit) show. save: passphrase forgetchugh
  file back way only.
- key current tab memory only - reload **Unencrypted**Dat back, unlock
  pane passphrase chu'.
- encryption chut, upload encrypt, download je preview browserDat decrypt,
  share key envelope bot (above). WebDAV desktop client encrypt neH:
  encrypted file ciphertextDat visible, theyvo' write chut.

### Auto-unlock: passphrase neH poS

**choH > Konto > Auto-unlock** accountDat switch: device wa'DIch unlock
chut, browser device key your wrapped account key bot (`localStorage`,
password neH), later every poS - reload, new tab, password **je** passkey
nom - unlocked start. passphrase device wa'DIch neH yIchel, exact moment:
badge **Unencrypted** vo' **Verschlüsselt** switch live tabDat. fresh
device wa'DIch ask, then silent. **Off** stored unlock delete, strict
behavior back: key current tab only. trade-off, open: browser profile
whole readHogh, account key devicevo' get - switch default off
(ENCRYPTION.md5.7, DECISION7).

### Encrypt existing files

**choH > Konto > Encrypt existing files** whole tree browserDat walk,
plaintext file encrypt, old version history qaw - history *is* plaintext.
dialog `i of n` show, cancel available, resume where stopped: rerun
already encrypted skip. quota full, quota message pause **Continue after
freeing space** bot. folder row menu same action subtree only (**Encrypt
folder now...**).

### Encryption zones

folder row menu (**Encryption zone: on/off**) zone mark: below new file
je save passphrase yIchel even badge **Unencrypted** yIjatlh, folder
encrypt taH, account rest WebDAV-compatible. owner (ghom manager) only
flag change, descendant inherit, folder copy flag carry - copyDat chu'
set.

### Recovery key: show again je new issue

**choH > Konto** **Recovery key** section: storage passphrase yIchuv
**Show recovery key** again show (64 hex digit, **Download** je), je
**Issue a new one** fresh key confirm behind generate - old key new
storeDat moment qaw'lu'. wrong passphrase far neH. old version setup
account stored copy chut, "issue one here" bot; first reissue show enable.

## 12. Passkeys

passkey PIN je biometricsDat nom, password neH. fxcloud username-first
FIDO2/WebAuthn ES256 use, user verification yIchel (PIN je biometric
gesture, touch neH).

**Add one:** **choH** poS, **Passkeys**, **Add passkey** yIpoS, name
yIchuv (example "phone", "security key") je device confirm. list your
device last use show; each **Rename** je **Remove**. last one remove
allowed - your password taH, lost device immediate cut.

**nom:** nom page **Passkey** tab ghoS, username yIchuv, device PIN je
biometrics confirm. unknown username je passkey chut account same answer,
dialog who account yIjatlhchut neH.

requirements:

- **secure context:** browser passkey HTTPS neH `localhost` neH legh.
  plain HTTP LAN addressDat UI yIjatlh browser block.
- passkey origin je hostname bound created. instance URLDat serve chugh,
  URL `FXCLOUD_ORIGIN`Dat fxcloud yIchel - next section how, error legh.

## 13. HTTPS paS'op (worked example)

fxcloud plain HTTP speak, reverse proxy front TLS terminate. passkey reason
extra setting needed: WebAuthn every passkey exact `scheme://host[:port]`
bound created, browser `Origin` every passkey requestDat send. fxcloud
header forwarded scheme je `Host`vo' derive origin compare - proxy `Host`
rewrite scheme forward chut, two disagree.

error symptom, passkey add use:

```
bad request: Origin does not match this server's address - set
FXCLOUD_ORIGIN to the URL users open it under
```

fix environment variable wa'DIch: fxcloud URL yIchel user actual open.
nginx worked example `cloud.example.com` fxcloud same host, port8080:

**1. fxcloud** (systemd unit, je quick test shell):

```bash
FXCLOUD_BIND=127.0.0.1 FXCLOUD_PORT=8080 \
FXCLOUD_SECURE_COOKIE=1 \
FXCLOUD_ORIGIN=https://cloud.example.com \
./fxcloud
```

unit file (`deploy/fxcloud.service`) two line same, comment, environment
sectionDat wait:

```ini
# Enable when serving over HTTPS behind a TLS-terminating reverse proxy:
# Environment=FXCLOUD_SECURE_COOKIE=1
# The exact URL users open fxcloud under - required for passkeys when a
# reverse proxy rewrites Host or terminates TLS (e.g. https://cloud.example.com):
# Environment=FXCLOUD_ORIGIN=https://cloud.example.com
```

**2. nginx** TLS terminate forward:

```nginx
server {
    listen 443 ssl;
    server_name cloud.example.com;

    client_max_body_size 10G;   # keep in sync with FXCLOUD_MAX_UPLOAD_MB

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_request_buffering off;
        proxy_buffering off;
    }
}
```

**3. fxcloud restart** (unit change: `sudo systemctl daemon-reload &&
sudo systemctl restart fxcloud`).

`FXCLOUD_ORIGIN` value rules:

- browser address bar origin equal: scheme, host, port default neH (https
  443, http80) - **trailing slash neH**, path neH.
- user instance several nameDat reach, passkeys configured oneDat work;
  canonical URL wIv.
- WebAuthn only. everything else nginx block headerDat work, proxy chut
  harmless.

`FXCLOUD_ORIGIN` chut, fxcloud origin request `X-Forwarded-Proto`
(`FXCLOUD_SECURE_COOKIE` je) `Host`vo' derive - proxy both unchanged
forward correct, momentDat wrong.

## 14. WebDAV

fxcloud **`/dav/`**Dat WebDAV speak, HTTP Basic auth (your fxcloud
username + password; passkey web-only). `/dav/` after path your home
folder relative:

```bash
rclone config    # type: webdav, url: https://your-host/dav/, user/pass
rclone lsd remote:

# Windows "Map network drive" / macOS Finder "Connect to Server" -> /dav/
```

deactivated account403, quota violation507. encrypted file ciphertextDat
visible, desktop clientvo' write chut (see
[chuSQang](#11-chusqang)); web UI those way in out.

## 15. Troubleshooting

**"Origin does not match this server's address - set FXCLOUD_ORIGIN ..."**
passkey add use: URL user fxcloud open fxcloud proxy headervo' derive
disagree. `FXCLOUD_ORIGIN` set [section13](#13-https-pasop-worked-example)Dat, restart.

**passkey UI browser block passkey yIjatlh**: plain HTTP (IP address)
HTTPS localhost neH - browser secure contextDat passkey legh neH. fxcloud
HTTPS serve.

**"Account created. It has to be activated before you can sign in"**:
first account after expected - administrator **lo'wI'poH**Dat activate.

**"account is not activated yet - ask an administrator to activate it"**
nomDat je WebDAV: same cause, existing accountDat.

**507 "storage quota exceeded: X of Y used"**: your quota full - trash
yIQaw (count taH), file qaw, je administrator quota raise yIchel.

**encrypted file poS chut**: storage passphrase current tab unlock neH
(key tab memory only) - unlock pane yIlo'; passphrase forgetchugh, setup
recovery key recover.

**sync client encrypted file write qaw'lu'chugh**: desktop client encrypt
neH; WebDAV those file ciphertext serve, read-only. encrypted content web
UI yIlo'.

**nom page dead: Passkey / yuQ chu' tab react neH, page English show even
browser German, submit mask Dat back error neH**: fxcloud JavaScript off.
fresh installed web app default, install dialog switch neH (Google Pixel
report; Samsung setting offer neH) - page script tab wire je form
intercept, without browser plain reload fallback. fix: fxcloud icon
long-press, **choH** poS, **JavaScript** enable (Chrome > Settings > Site
settings > JavaScript), app reopen. different cause partial overlap: tab
*react* page your languageDat yet nom maskDat back loop chugh, session
cookie drop - address bar `https://` check, site data browser settingsDat
clear.
