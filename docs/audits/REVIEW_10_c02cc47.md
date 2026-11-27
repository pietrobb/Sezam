# Review č. 10: commit c02cc47

- **Dátum:** 2026-11-27
- **Rozsah:** 201 commitov od e443cbc (review č. 9), zhruba +30 500 riadkov.
- **Oblasti:** server, team log a key vouchers (#443), Rust core, web, mobil, desktop (sync, zámky, kľúče), AI broker, CI a hygiena verejného repozitára. K tomu kontrola dodržiavania `docs/ROOT_CAUSE_PLAN.md` vrátane mutačného testovania.
- **Metóda:** sedem nezávislých review. Najvážnejšie nálezy sa overili spustením (sondy na skutočnom serveri s MariaDB, WebTab na Node 24, state machine) alebo priamo v kóde. Mobil sa kontroloval len čítaním, Flutter toolchain nebol k dispozícii.

Report zámerne neobsahuje postup na zneužitie otvorených nálezov. Popisuje chybu, jej dopad a smer opravy. Sondy, ktoré nálezy reprodukujú, nie sú súčasťou repozitára.

---

## 1. Verdikt

Toto je zatiaľ najlepšie kolo:

- Väčšina vysokých nálezov z review č. 9 je opravená.
- State machine prvýkrát systematicky nachádza skutočné chyby.
- S1 a S4 existujú ako registre vynútené testami.
- INV-6 je na desktope vynútený v databázovej vrstve.

Nová funkcia key vouchers (#443) však priniesla dieru rovnakej triedy ako predtým: vedľajšia cesta overuje menej než hlavná (INV-2, INV-3). Docker image servera na c02cc47 navyše nenaštartuje.

## 2. Testy

Celá sada bežala s `-n 4` a Node 24 pre web: **4541 prešlo, 5 zlyhalo**, 380 bolo preskočených a 1 je xfail.

Všetkých 5 zlyhaní spôsobilo prostredie review:

- V čistom venv bez extra `gui` chýbal PySide6. Zlyhali na tom 4 prípady `test_authority_map`.
- V uv venv chýbal `pip`. Na tom zlyhal 1 prípad `test_commit_discipline`.

Drobnosť: `test_authority_map` by sa mal bez PySide6 preskočiť, podobne ako to už robia ostatné GUI testy.

## 3. Stav nálezov z review č. 9

| Oblasť | Opravené | Čiastočne | Stále otvorené |
|---|---|---|---|
| Server | V1 (cyklus v rotačnej mape, `key_reused` v jadre), V2 (restore používa `_prepare` a `_check_against_users(history=True)`; readmit restore funguje), V4 (store berie zámok `commit_counter`) | V5: `is_admin` z logu pri autentifikácii, ale pri pushi sa pod zámkom znova nečíta | V3: `/api/sync` parsuje team log pod globálnym zámkom; `_prepare` parsuje všetky telá pred limitom členov. V5: cache workera ide len dopredu; `GET /api/team-log` bez SQL LIMIT; `ever_admin` sa parsuje pod zámkom; `/org-recovery/status` je bez autentifikácie |
| Team log / core | T1 (admin drží kľúče z titulu roly, handover nepíše `access.set`), T3 (Shamir a zmena hesla pri odmietnutom logu), oživovanie tombstonov pod GC floor, únik `opPtr` v Darte, GIL | T2: príčina forget sa už určuje zo záznamov, ale po forget sa znova uplatnia pravidlá spred logu. T4: rez na head je opravený, chybné heady stále nie (15 zo 101 prípadov sa medzi klientmi líši) | `reseal.rs` má stále rovnakú zložitosť; permisívny `#[serde(default)]`; equivocation hlási len desktop; WASM build je reprodukovateľný iba v `/src` |
| Web | W1 (forget v Team trust exportuje a vyprázdni frontu), W3 (kľúče osobného stromu len z vlastných top-level rootov), W4 (checkpoint aj pri odmietnutom logu), adopt-as-base, race pri ukladaní v jednej karte, replay tombstonov, `...payload` spread, druh blobu v `decryptEnvelope` | Replay pri full pull je opravený v rámci session, pri prihlásení nie | W2 (refusal bez `teamLogRefused`; `webInPersonalTree` pri parente, ktorý je tombstone), poškodený checkpoint blokuje prihlásenie, team DEK sa mažú bez memzero, head-of-line Retry a ďalšie staršie položky |
| Mobil | Q1 (pull pred pushom je v try), Q4 (forget a discard vyžadujú heslo), odmietnutý stav ukáže len osobný strom | Q2: stav po forget sa stále správa ako stav pred logom | Q3 (konfliktná obálka zamkne vault), Q5 (otvorenie Nastavení vie zapisovať do team logu, chýba re-login pri 401), väčšina Q6 |
| Desktop | E2 (cache `team_state` už neobchádza kontroly), E4a (org recovery status len zadržiava), E4b (handover: najprv push, potom jedna požiadavka), Shamir a zmena hesla pri odmietnutom logu | E1 (`client.push()` osobný strom pošle, CLI a GUI nie, pozri N4), E3 (triggery a dva zámky áno; `forget_team_log_pin`, RMW na CONFIRMED_MEMBER_KEYS a piny pri unlocku bez sync zámku) | GUI `_finish_rekeys` ignoruje výsledky; „wait“ chyba pri jednotlivej položke; fold pri unlocku bez zámku; Lock/Quit ignorujú `background_busy`; ďalšie položky E5 |
| AI broker | A1: nedostupná kotva sa už neráta ako overená, chýbajúci `server_url` už neobíde kontrolu, náhodné id kotvy, zápis kotvy vyžaduje podpisový kľúč. A2: `--sudo-command` je allowlist (všetkých 59 starých obchádzok odmietnutých) | A1: `ai off` pri zamknutom vaulte bez brokera nie je ukotvený | A2: web root môže byť v `/var/spool/cron`, `/var/lib`, `/var/log` alebo v cudzom home; chýbajú `AuthorizedKeysCommand none`, `DisableForwarding` a kontrola `sshd -T`. A3: dialógy po `ai off` sa ešte zobrazujú. A4: race medzi čítaním a redakciou; shelly a ControlMaster prežijú obyčajné `ai off` |

## 4. Nové nálezy

### Vysoké

**N1 – Key vouchers neviažu celú podpísanú správu.**
- **Kde:** `src/sezam/key_vouchers.py`, `sync_vouchers.py`, `sync_client.py` (`_verify_object_signature`), `web/static/js/app.js` (verifikácia vyradeného kľúča), `mobile/lib/services/sync_service.dart`.
- **Chyba:** položka voucheru je (id, version, payload_hash). Podpis objektu však pokrýva aj `parent_ref`, `is_deleted`, typ, `target_user_id` a podpisovateľa.
  - Podpis vyradeným kľúčom sa prijme pre akýkoľvek objekt s rovnakou trojicou, aj s inými metadátami.
  - Vouchery vlastného účtu, adminov aj držaných verzií platia pre vyradený kľúč ktoréhokoľvek podpisovateľa.
- **Dopad:**
  - Kto drží vyradený kľúč (presne útočník, proti ktorému je #443), vie objekty presúvať, mazať a pripisovať inému podpisovateľovi. Na desktope aj na webe overené spustením.
  - V kombinácii s `fold_unlogged_folder_keys` sa nový obsah nesúkromného priečinka môže prebaliť na tímový kľúč. Je to strata dôvernosti, tiež overené spustením. Osobné rooty (`personal: true`) touto cestou nie sú zasiahnuté.
- **Súvisí:**
  - Pri rotácii klient vouchuje to, čo mu vráti server zo `/me/signed-objects`, a `_require_vouched` vyžaduje vouchovať všetko, čo server uvedie. Verzie sfalšované pred rotáciou sa tak prenesú ďalej.
  - Pri prvom syncu s #443 sa vouchujú aj verzie prijaté podľa starých pravidiel.
  - Záznam v `unsigned_fields.py` („a lie only leaves an object out“) neplatí.
- **Smer opravy:**
  - Položka voucheru má byť digest celej kanonickej podpísanej správy (alebo samotný podpis), viazaný na účet podpisovateľa a vyradený kľúč.
  - V `against_held` porovnávať celý digest: rovnaká verzia s inými metadátami je equivocation, nikdy „Same“.
  - `parent_ref` a `is_deleted` patria do state hashu.
  - Rotačné zoznamy stavať z verzií, ktoré zariadenie drží.
  - Fold nikdy pre priečinok, ktorého posledná zmena rodiča prišla vyradeným kľúčom.

**N2 – Docker image servera nenaštartuje.**
- **Kde:** `Dockerfile:21` kopíruje `src/sezam/key_vouchers.py` ako `server/app/key_vouchers_core.py`. Ten importuje `from .models import ulid_to_bytes`, ale `server/app/models` taký symbol nemá.
- **Dopad:** pri importe `server.app.main` spadne každý worker. Nasadenie c02cc47 nefunguje.
- **Smer opravy:**
  - Voucher core urobiť samostatným, napríklad vložiť doň `ulid_to_bytes`.
  - Pridať test, ktorý naimportuje server v rozložení Dockerfile bez balíka `sezam`, ako už existuje pre `teamlog_core`.
  - V CI image zostaviť a spustiť smoke test na `/api/meta`.

**N3 – `sezam ai off` (CLI aj GUI) zlyhá, keď niekto drží zápisový zámok vaultu.**
- **Kde:** `src/sezam/cli.py`, vetva brzdy s CLI session (unlock pred `pull_brake`), a `gui/ai_switch.py`.
- **Chyba:** od R15-P5 berie každý zápis do vaultu zámok `sezam.db.write` a unlock zapisuje. `VaultBusy` je `RuntimeError` a `except ValueError` ho nezachytí.
- **Dopad:** proces, ktorý drží zámok, zabráni vypnutiu AI. Príkaz zhruba po 2 minútach skončí chybou a brzda sa nespustí. Telefónna brzda a brzda bez session fungujú.
- **Smer opravy:**
  - Najprv spustiť brzdu nad zamknutým vaultom, až potom robiť unlock pre audit a kotvu, a zachytiť každú výnimku.
  - Regresný test s drženým `<db>.write`.
  - Kill switch má byť trvalý akceptačný test aj za nepriaznivých podmienok: držaný zámok, nedostupný server, plný disk.

**N4 – `sezam push` a GUI push pri odmietnutom logu admina nepošlú nič (INV-7, pravidlo 1).**
- **Kde:** `cli.py` (push) a `revocation.push_with_queued_revocations`. Funkcia `queue_revoked_holders` vyhodí `TeamLogMismatch` ešte pred `client.push()`.
- **Dopad:** admin, ktorý zdieľa čo i len jeden priečinok, neodošle ani svoj osobný strom. `client.push()` sám osebe funguje. Testy R15-P4 pushujú od člena, ktorý nedrží obálky pre iných, takže túto cestu nespúšťajú.
- **Smer opravy:**
  - Jeden vstupný bod pre push.
  - Revokačná fronta zaznamená odmietnutie a preskočí len tímovú časť.
  - Testy pushu od admina s otvoreným grantom.

**N5 – Odmietnuté prevzatie rotovaného kľúča sa aplikuje napolovicu.**
- **Kde:** `sync_client.adopt_rotated_key_material`. `adopt_account_kek` (vrátane `_adopt_key_epoch`) sa commitne pred kontrolou v `rebind_server_identity`, ktorá operáciu odmietne.
- **Dopad:** neodoslaná rotácia identity sa stratí a zariadenie sa už neprihlási (401). Reprodukuje sa to zo state machine (TeamLogMachine).
- **Smer opravy:** kontrolu kotvy a downgradu urobiť pred adopciou, alebo adopciu a rebind spojiť do jednej transakcie.

### Stredné

**N6 – Web pri zadržanom podpisovateľovi vytvorí a odošle vlastný root (regresia z c3d1913).**
- Člen, ktorého celý strom podpísal admin, má po zadržaní objektov prázdny zoznam uzlov, a `createRootFolderLocked` vtedy vytvorí nový root.
- Odmietnutá vetva `assertTeamLogAllowsWrite` považuje každý nový top-level uzol za osobný, čo je v rozpore s pravidlom 3.
- Nový root sa stane `rootNodeId` a nové položky idú pod kľúč člena. Overené spustením.
- **Smer opravy:** nikdy automaticky nevytvárať root, keď niečo bolo zadržané alebo keď je log odmietnutý.

**N7 – Výpadok voucherov alebo kľúčov zamkne vault namiesto zadržania jedného podpisovateľa.** Týka sa webu, desktopu aj mobilu.
- Web: chyba zoznamu voucherov znamená prázdnu množinu a následne `REJECT` pre každý objekt vyradeného kľúča, vrátane vlastných. Vault sa neodomkne, ani osobný strom.
- Všetci klienti: jeden nevouchovaný objekt zhodí celý pull. Nový člen alebo nové zariadenie, ktoré danú verziu nikdy nedržalo, nedostane nič.
- Mobil: zlyhaný fetch voucherov preruší pull a id s `:` zhodí parsovanie kľúča voucheru.
- Je to v rozpore s pravidlom 1 sekcie „Prednosť INV-5 a INV-7“ aj s cieľom „chyba pri ktoromkoľvek requeste nikdy nedrží osobný strom“.
- **Smer opravy:** jedno pravidlo pre zlyhanie podpisovateľa na všetkých klientoch, teda zadržať a pomenovať objekty toho podpisovateľa a odmietnuť tím, nikdy nevyhodiť výnimku pre celý pull. Endpointy `/keys` a `/key-vouchers` pridať do property „chyba pri každom requeste“.

**N8 – Re-key batch nesie zaradený `access.set` pre už odstráneného člena (state machine, seed 20261127).**
- Push zlyháva navždy, pretože záznam je `not_active`. Člen je na serveri odvolaný, ale jeho priečinky sa nikdy neprekľúčujú.
- Chybová správa (`sync_push.py`, „another device re-keyed the folder first“) ukazuje na nesprávnu príčinu.
- **Smer opravy:** pri stavbe `member.remove` vyradiť zaradené zmeny prístupu pre toho člena. Má to byť pravidlo logu, nie ďalšia výnimka. Chyba má niesť skutočný kód záznamu.

**N9 – Mobil zahodí stratené tímové zmeny bez upozornenia.**
- **Kde:** `sync_service.dart`, opätovné odoslanie stratených zmien pri sledovaní forku.
- Každé 4xx okrem 409, teda aj 401 a 429, označí zmenu ako stiahnutú a odloží ju bokom. `team_log_set_aside` však nikto nečíta.
- Podpisová funkcia drží referenciu na živý kľúč, ktorý `lock()` vynuluje.
- **Dopad:** napríklad `member.remove` sa stratí a admin sa to nedozvie.
- **Smer opravy:** pri 401 sa prihlásiť znova, pracovať s kópiou kľúča alebo kontrolovať generáciu zámku, a odložené zmeny zobraziť v Nastaveniach.

**N10 – Na voucher endpointoch nie sú limity.**
- `POST /me/key-vouchers` nemá deduplikáciu, limit na účet ani rate limit.
- Podpis nepokrýva nič, čo by bránilo opätovnému odoslaniu starého zoznamu iba s JWT.
- `GET /users/{id}/key-vouchers` vracia všetko a dekóduje na event loope. Merané: stovky MiB uložené, desiatky sekúnd na jeden GET a zablokovaný worker.
- **Smer opravy:** UNIQUE na (user_id, signing_pk, signature), limit riadkov a bajtov na kľúč, stránkovanie a overovanie mimo event loopu a pred zámkom pushu.

**N11 – `_is_below` (kontrola cyklu priečinkov) beží pod globálnym zámkom.** Robí jeden SELECT na úroveň pre každý nový alebo presunutý priečinok. Dlhý push člena zdrží push admina o desiatky sekúnd.
- **Smer opravy:** preskočiť nové id, cachovať riadky v autoritnej cache pushu a obmedziť hĺbku.

### Nízke až stredné

- **AI:** presun vaultu na iný server nevyradí starú kotvu (`rehome_anchor`). `ai on` sa ukotví na nezapečatený `server_url`. Synchrónny PUT kotvy (30 s) oddiali `--terminate-remote`.
- **Server, restore:**
  - Restore môže skončiť uprostred append dávky, napríklad sa vymažú share linky pri čiastočnom readmite.
  - Restore autora blobu preskočí kontrolu „superseded“ pre `org.recovery`.
- **Server, `/api/meta`:** náklady rastú s počtom používateľov, čo je aj časový orákulum.
- **Web:**
  - Forget v Team trust zahodí aj osobné zaradené zápisy, ktoré by pravidlo 1 poslalo. Export nemá žiadny import.
  - Vouchery adminov sa počítajú aj z logu, ktorý nie je dôveryhodný.
  - `webIsAdmin` odpovie pred kontrolou refusal.
  - `trashedNode` určí „personal“ bez kontroly podpisovateľa.
- **Mobil:**
  - Otvorenie Nastavení a začatie forget môže zapisovať do team logu.
  - Telefón vouchuje verziu prevzatú z neautentifikovaného importného súboru.
  - Cesta 409 „Identity key rotated“ ukladá nepodpísané meno účtu.
- **Desktop:**
  - Náhradný tímový kľúč držaný len cez obálku sa už neotvorí, lebo `may_open_superseded` a `envelope_valid` si odporujú. Pri jednom zlyhaní sa vymaže celá cache DEK.
  - `team-log status`, `confirm-founder` a `forget-pin` synchronizujú team log bez sync zámku.
- **Parsery voucherov sa líšia:** verzia `3.0`, hex so medzerami, limit počtu položiek. Spôsobí to len odmietnutie, nie falzifikát.

## 5. CI a hygiena verejného repozitára

- **Dobré:**
  - Strom aj autori commitov sú čisté (len noreply adresy a vzorové dáta).
  - `permissions: contents: read`, žiadny `pull_request_target`.
  - Job `commits` posiela SHA cez `env`; red line sa spúšťa ako argv bez shellu.
  - `cla.yml` je pripnutý na SHA.
  - Používa sa `cargo --locked`.
  - Beh s 10 000 príkladmi a job mutantov bežia nočne.
- **Produkčný dynamic-DNS host je stále v starších verejných commitoch** (aj v `refs/pull/*`, ktoré sa bez GitHub Support nedajú vyčistiť). Treba ho považovať za prezradený a zmeniť.
- **Otvorené:**
  - Väčšina actions je pripnutá na tag, vrátane third-party `subosito/flutter-action`.
  - Rust sa inštaluje cez `curl | sh`.
  - Python sa inštaluje bez locku a hashov, hoci `uv.lock` existuje.
  - `flutter pub get` beží bez `--enforce-lockfile`.
  - Chýba cargo-audit a pip-audit. pip-audit spustený pri review nenašiel nič.
  - `mariadb` v `compose.yaml` je pripnutá len tagom, nie digestom, a Dependabot ju nesleduje.
  - `SEZAM_BOOTSTRAP_DISABLED` sa v compose neposiela ďalej.
  - HMAC secret nemá kontrolu minimálnej dĺžky.
  - `/docs`, `/redoc` a `/openapi.json` sú zapnuté.
  - Fonty sa načítavajú z Google Fonts.
  - README nevysvetľuje, že JS webového klienta servíruje server.

## 6. Dodržiavanie ROOT_CAUSE_PLAN

| Položka | Stav |
|---|---|
| INV-1 | Čiastočne. Na serveri štrukturálne (`authority.team_admin`, register `CACHE_READS`); web a mobil berú admina z logu. Zostáva režim bez logu (S6). |
| INV-2 | Čiastočne, silné. Restore používa cestu appendu; property zabíja mutanty restore. `RESTORE_EXCEPTIONS` narástol z 2 na 5 položiek. Key vouchers sú nová cesta, ktorá overuje menej (N1). |
| INV-3 / S4 | Register je hotový (desktop 180 polí, web 146, mobil 127). State machine však klame len v desktopových poliach, na webe a mobile v žiadnom. |
| INV-4 | Hotové pre objekty (`against_held` v core). |
| INV-5 | Čiastočne. Fault injection pri každom requeste na všetkých troch klientoch, ale chýbajú voucher a keys endpointy (N7). Počet `except Exception` 160 → 167, prázdnych catch v JS/Dart 96 → 103. |
| INV-6 / S7 | Desktop štrukturálne (zámok pri každom zápise, TEMP triggery, inventár zámkov). Nedokryté cesty sú v nálezoch vyššie. |
| INV-7 | Čiastočne. Pravidlá prednosti sú zapísané, ale implementácia je samostatná v každom klientovi (N4, N6, N7). |
| INV-8 | Čiastočne. Tabuľka príčin; forget vyžaduje heslo všade. Forget pri chybe nie je na webe otestovaný. |
| INV-9 / S3 | **Nezačaté.** Team log sa stále prehráva v Pythone, JS a Darte. |
| INV-10 | Strom je čistý; host v histórii pozri sekciu 5. |
| S1 | Hotové (`server/app/authority.py`, `sezam.authority`, `test_authority_map`). |
| S2 | Čiastočne. |
| S5 | Výnimky sa evidujú, ale neubúdajú. |
| S6 | **Nezačaté.** Cesta „pre-log grant“ narástla. |
| S8 | Prevažne hotové. |

**State machine:**
- Pribudol TeamLogMachine (team-log operácie, handover, restore strateného logu, forget-pin, org recovery), zlomyseľný člen a klamúci server (log, polia registra, uniknutý vyradený kľúč, org recovery). Je uložených 42 protipríkladov.
- Nové protipríklady z tohto kola: TeamLogMachine 858585, 101010, 404040, 777777 (desktop) a 20261127 (meta review).
- Chýba: zariadenie mobil, reseed, AI kill switch, klamanie webu a mobilu, a pravidlo „rovnaká verzia s inými metadátami“.

**Mutácie:**
- 4 zo 7 vlaňajších preživších sú teraz zabité (O1, O5, O8 a O11, ten posledný len state machine).
- Preživší: O2 (pravdepodobne takmer ekvivalentný), O12 a O14.
- Nové mutanty: 8 z 10 zabitých, ale len 6 z 10 behaviorálne.
- Spolu 12 zo 17 (71 %).
- `scripts/mutants.py` beží len nočne a pokrýva server, core team log a oplock. Neobsahuje O11, O12, O14, vouchery ani pravidlá osobného stromu.

**Proces:**
- Commit disciplína funguje: posledných 63 commitov je bez porušenia a vzorka 15 riadkov „Red on“ na uvedenom sha naozaj zlyhá.
- Asi 20 commitov však uvádza dávny sha namiesto rodiča.
- Job `commits` beží až po pushi na main.
- Zhruba 16 commitov iba uvoľnilo orákulum state machine.
- **Freeze bol porušený:** `ai on --server-gone`, sledovanie forku, pre-log granty a 4 nové routes.

## 7. Odporúčania

1. **Hneď:** N2 (Docker), N3 (kill switch), N1 (väzba voucherov), N4 (push pri odmietnutom logu). Pre každý najprv červený test podľa sekcie 4 plánu.
2. **Jedno pravidlo pre zlyhanie podpisovateľa** (N6, N7): v core, nie trikrát v klientoch.
3. **S3 a S6 pred ďalšími funkciami.** N6, N7 a N9 sú tri rôzne zlyhania tej istej myšlienky v troch implementáciách.
4. **Klamúci server aj pre web a mobil** (`CLIENT_FIELDS`), zariadenie mobil v state machine a pravidlo pre re-sign rovnakej verzie s inými metadátami.
5. **Mutanty z tejto review do `scripts/mutants.py`** (O2, O11, O12, O14, väzba voucherov, identita webu z verify odpovede, core tombstone na strane Pythonu) a ich podmnožinu spúšťať na PR.
6. **Job `commits` ako povinná kontrola PR** a „Red on“ vždy na rodičovi.

## 8. Ako zabrániť, aby sa chyby znova rozrastali

1. **Žiadna funkcia bez nepriateľského pravidla.** Každá nová cesta, ktorá prijíma alebo podpisuje dáta, prichádza naraz s pravidlom state machine pre klamúci server alebo člena a s mutantom, ktorý toto pravidlo zabije. Key vouchers prišli s pravidlom „uniknutý kľúč falšuje novú verziu“, ale nie „rovnakú verziu s inými poľami“, a práve tam je diera.
2. **Jeden digest pre všetko podpísané.** Jedna funkcia `signed_digest(obj)`, ktorú používa podpis, voucher, receipt aj porovnanie verzií. Test v štýle registra S4 vyjmenuje podpísané polia a overí, že každý pomocný dôkaz pokrýva všetky.
3. **Odvodzovať, nie vymenúvať.** Zoznam endpointov pre fault-injection property sa má generovať z mapy autority (S1 ROUTES), aby každý nový endpoint automaticky dostal test „chyba pri tomto requeste“. To isté platí pre polia, na ktorých server klame (z registra S4).
4. **Ráčna na metriky.** CI počíta: `except Exception`, prázdne catch, funkcie osobného stromu, odkazy na NO_LOG alebo pre-log, počet implementácií pravidiel team logu. Číslo smie klesnúť; ak stúpne, commit musí pridať záznam do registra výnimiek s dôvodom.
5. **Uvoľnenie orákula je tiež zmena.** Commit, ktorý len uvoľní orákulum state machine, pomenuje invariant, ktorý zužuje, a pridá mutant, ktorý zúžené orákulum stále chytí.
6. **Freeze naozaj.** Kým nie sú hotové S3 a S6, žiadne nové núdzové ani autoritné cesty. Väčšina nových nálezov tohto kola je v kóde pridanom počas freeze.
7. **Akceptačné testy pre veci, ktoré nesmú zlyhať:** kill switch a štart Docker image so smoke testom, spúšťané pri každom pushi a za nepriaznivých podmienok.
