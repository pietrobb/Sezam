# Sezam: ako odstrániť príčiny chýb, nie len ich prejavy

**Stav:** návrh postupu, báza `main@8bc70f7`, po ôsmich kolách code review.
**Pre:** vývojára a agenta, ktorý opravuje.
**Cieľ:** prestať opravovať nález po náleze a urobiť chyby rovnakého typu štrukturálne nemožnými.

> Tento dokument je zámerne bez návodov na zneužitie práve otvorených nálezov.
> Konkrétne nálezy sa odovzdávajú zvlášť, mimo verejného repozitára
> (pozri `SECURITY.md`).

---

## 1. Diagnóza: čo osem kôl review ukázalo

1. **Opravené chyby sa nevracajú.** Takmer každý nález dostal regresný test
   a sada narástla z ~650 na ~3 300 testov. Konkrétne chyby po oprave nové kolá nenachádzajú.
2. **Vracajú sa typy chýb, a to v najnovšom kóde.** Každé kolo pridalo silnú novú
   funkciu (tímový denník, obnova denníka, forget-pin, odovzdanie roly admina,
   ukotvenie AI vypínača, outbox, zdieľané jadro). Vysoké nálezy boli takmer vždy
   práve v nej.
3. **Približne 1–2 regresie za kolo.** Oprava presunie zámok, výnimku alebo poradie
   a tým rozbije inú vlastnosť.
4. **Klienti sa rozchádzajú.** Oprava na desktope sa nedostane na web alebo mobil,
   prípadne každý klient opraví ten istý problém inak.
5. **Drobnosti nikto neuzavrie.** Časť nálezov nízkej závažnosti je otvorená od 2.–3. kola.

### Koreňové príčiny

| # | Príčina | Prejav |
|---|---|---|
| K1 | **Autorita je rozptýlená.** O tom, kto smie čo, rozhoduje server (`users.is_admin`, `write_acl`), tímový denník, každý klient zvlášť a desiatky výnimiek. | Stačí jedna vrstva, ktorá rozhodne inak, a vznikne diera. |
| K2 | **Núdzové a obnovovacie cesty sú samostatný kód** s vlastnými, slabšími kontrolami (restore, migrácia, odovzdanie roly, reseed, org recovery, forget-pin, rejoin, ukotvenie). | Útočník nejde hlavnými dverami, ale núdzovým východom. |
| K3 | **Opravy sa robia po nálezoch.** Pribudne výnimka (`own_cleanup`, `_rotation_lost_here`, `former_admins`, osobný strom…) a test presne na nahlásený scenár. | Vlastnosť sa nezaručí a každá výnimka je ďalšie miesto pre chybu. |
| K4 | **Ten istý algoritmus je vo viacerých implementáciách** (Python, JS, Dart, server). | Drift a oprava len na jednom mieste. |
| K5 | **Pri neistote kód povolí, neodmietne (fail-open).** Chýbajúca hodnota znamená povolené, chyba kontroly „skontrolované“, neznámy rodič „pustiť“. | Útok sa robí cez chýbajúce, poškodené alebo zadržané dáta. |
| K6 | **Funkcie pribúdajú rýchlejšie, než sa uzatvárajú.** | Povrch rastie rýchlejšie, než sa stihne preveriť. |

---

## 2. Invarianty: čo musí platiť vždy

Každý invariant má **pravidlo**, **vynútenie v kóde** a **test vlastnosti**. Oprava
nálezu sa začína otázkou, ktorý invariant porušuje. Ak taký nie je, doplní sa sem.

### INV-1 Jeden zdroj autority

- **Pravidlo:** v organizácii s viacerými používateľmi rozhoduje o členstve, roli,
  prístupe k priečinku, práve zápisu, aktuálnom kľúči priečinka a o tom, kto smie
  dostať kľúč, **iba prehratý tímový denník**.
- **Vynútenie:**
  - Serverové `users.is_admin`, `users.status` a `write_acl` sú len cache odvodená
    z denníka. V rozhodnutiach sa ako autorita nečítajú nikde.
  - Organizácia s viac ako jedným používateľom bez denníka sa nepovoľuje. Denník
    sa založí najneskôr pri pozvaní prvého člena, potom sa legacy heuristiky zmažú (krok S6).
- **Test:** pravidlo zlomyseľného servera mení `is_admin`, `status`, `write_acl`,
  `owner_id` a `access_level` na náhodné hodnoty. Žiadny klient potom nezmení to,
  kto vidí, kto zapisuje a komu sa pečatí kľúč.

### INV-2 Žiadna cesta nemá viac moci ako hlavná cesta

- **Pravidlo:** každá operácia, ktorá mení členstvo, rolu, kľúče, prístup alebo maže
  či obnovuje dáta, prechádza **tou istou** autorizačnou funkciou ako bežný zápis.
  Platí to pre append, restore, migráciu, odovzdanie roly, reseed, org recovery,
  rejoin aj „upratovanie“.
- **Vynútenie:**
  - Na serveri jedna funkcia `authorize(change, actor, state) -> Allow | Refuse(reason)`.
  - Restore je „append záznamu, ktorý už raz existoval“. Smie byť prísnejší, nikdy voľnejší.
  - Register všetkých zapisujúcich endpointov (krok S1). Test zlyhá, ak nový
    endpoint nedeklaruje svoju autorizáciu.
- **Test:** pre každý pár (bežná cesta, núdzová cesta) property test overí, že
  núdzová cesta neprijme nič, čo by bežná odmietla.

### INV-3 Server môže zadržať, nie sfalšovať

- **Pravidlo:** klient nikdy nezvýši práva, nevyberie kľúč, nezmaže ani nenahradí dáta
  na základe nepodpísaného údaju zo servera.
- **Vynútenie:** udržiavaný **zoznam nepodpísaných polí**. Každé pole sa buď podpíše,
  alebo sa smie použiť len ako nápoveda, ktorá nemôže uškodiť. Aspoň:
  - `owner_id`, `scope`, `access_level`, `is_admin`, `status`,
  - `gc_floor_seq`, `head_commit_seq`, `commit_token`, `key_epoch`,
  - Argon2 parametre, odpovede `/status` (org recovery, AI ukotvenie),
  - poradie objektov, časové pečiatky.
- **Test:** pravidlo „server klame v poli X“ pre každé pole zo zoznamu, plus pravidlá
  zadržania, starej verzie, falošného 410 a falošného rollbacku. Po kroku sa overia
  invarianty zo sekcie 4.

### INV-4 Monotónnosť

- **Pravidlo:** verzia objektu, generácia kľúča, key epoch, hlava denníka a AI-off
  epocha sa na základe vonkajšieho vstupu nikdy neznížia. Zníženie môže urobiť len
  používateľ, s heslom a s varovaním.
- **Vynútenie:** jedna funkcia v jadre `accept_newer(local, pulled)`, ktorú volajú
  všetci klienti pre každý typ objektu.
- **Test:** server prehrá ľubovoľnú staršiu podpísanú verziu ľubovoľného objektu.
  Žiadne zariadenie ju nezobrazí a tombstone sa nevzkriesi.

### INV-5 Pri neistote odmietnuť (fail-closed)

- **Pravidlo:** všetky tieto situácie vedú k odmietnutiu alebo čakaniu, nikdy k povoleniu:
  - chýbajúca hodnota,
  - chyba kontroly,
  - neznámy rodič,
  - neznámy alebo vymenený kľúč,
  - nedostupný server (pri kontrolách, ktoré ho potrebujú),
  - neznáme pole na vstupe.
- **Vynútenie:**
  - Vstupy jadra sú striktné: všetky polia povinné (aj s hodnotou `null`)
    a `deny_unknown_fields`.
  - Žiadne `except Exception: pass` ani „unreachable counts as checked“ okolo
    bezpečnostných rozhodnutí.
  - Audit `grep`-om pri každej zmene (zoznam vzorov v sekcii 6).
- **Test:** fault injection vyhodí výnimku alebo odpoveď 5xx v každom kroku každej
  kontroly. Výsledok nikdy nie je povolenie.

### INV-6 Atomicita a jedno poradie

- **Pravidlo:** zmena, ktorá má viac častí, je **lokálne jedna transakcia**
  a **na serveri jedna atomická požiadavka**. Príklady:
  - envelope a jeho `access.set`,
  - `member.remove` a re-key,
  - rebind a `server_url` a pending stav,
  - pridelenie prístupu a zmena roly.
- **Vynútenie:**
  - Všetky stavové zmeny idú cez outbox v transakcii `BEGIN IMMEDIATE` pod
    medziprocesovým zámkom (oplock), a to v každom procese vrátane GUI, `mcp-serve`
    a ssh-agenta.
  - Žiadne čítanie a prepis `vault_meta` mimo transakcie.
- **Test:** state machine s druhým procesom, ktorý robí ľubovoľné operácie súbežne,
  a s pádom medzi akýmikoľvek dvoma lokálnymi krokmi.
- **Pozor na regresie:** presun alebo odstránenie `@oplock.held`, transakcie alebo
  poradia krokov musí mať v commite zdôvodnenie a test (sekcia 5).

### INV-7 Práca používateľa sa nestratí a z každého stavu vedie cesta von

- **Pravidlo:** neodoslaná zmena sa nikdy nezahodí bez výslovného súhlasu. Každý
  blokujúci stav má cestu von **dostupnú z miesta, kde používateľ uviazne**:
  prihlasovacia obrazovka, zamknutý telefón, CLI bez odomknutia.
- **Tímový denník nikdy nezamkne trezor** (capability run 397): nesúlad tímového
  denníka (poškodená lokálna kópia, účtové kľúče menujú iný genesis, než zariadenie
  drží) blokuje len tímové operácie, nikdy odomknutie ani osobné položky. Denník sa
  overuje tam, kde sa tím používa (`local_team_state`), nie v odomknutí; každá
  príčina má cestu von z odomknutého trezoru: poškodená kópia sa pri ďalšom pulle
  stiahne znova pod tými istými pinmi (genesis a videná hlava), konfliktné piny sa
  zabudnú spolu (s označením rizika, INV-8). Pred opravou odomknutie denník
  kontrolovalo a pri chybe trezor znova zamklo.
- **Vynútenie:**
  - Tabuľka stavov a ich ciest von (rozšírenie `pending_states.BLOCKS` na všetkých
    troch klientoch).
  - Každý stav má export, zahodenie, prevzatie serverovej verzie alebo inú výslovnú akciu.
- **Test:** po každom kroku state machine sa overí, že ku každému aktuálnemu stavu
  existuje akcia, ktorá ho z UI ukončí a nezahodí dáta bez potvrdenia.

### INV-8 Núdzovú akciu nesmie vyvolať útočník

- **Pravidlo:** forget-pin, „server bol obnovený“, nahradenie org recovery, reset
  a zahodenie čakajúcich zmien:
  - vyžadujú heslo,
  - nikdy ich nespustí samotná odpoveď servera,
  - nenúkajú sa pri stavoch, ktoré naznačujú útok (iný genesis, iný zakladateľ,
    nižšia epocha), alebo sú pri nich jasne označené ako riziko.
- **Vynútenie:** jeden zoznam núdzových akcií a pre každú definované, kedy sa smie ponúknuť.
- **Test:** zlomyseľný server vyvolá každý chybový stav. Klient v ňom sám nevykoná
  žiadnu núdzovú akciu a neponúkne tú, ktorú by útočník chcel.

### INV-9 Rozhodnutia sa implementujú raz

- **Pravidlo:** každé rozhodnutie o synchronizácii aj autorite je v zdieľanom Rust jadre:
  - pull gate, prijatie verzie, reseal, výber nástupcu kľúča,
  - **prehranie denníka**, `item_refusal`, `envelope_valid`, `may_hold_key`.
- **Vynútenie:**
  - Klienti len zbierajú vstupy a vykonávajú výsledok.
  - Python, JS a Dart replay sa zmažú, prípadne zostanú len ako testovací orákulum.
  - Tabuľka „rozhodnutie → akcia“ je jedna a pokrytá testom na každom klientovi.
- **Test:** conformance scenáre bežia na desktope, webe aj mobile. Každý nový
  scenár sa pridá trom klientom naraz.

### INV-10 Verejné repo neprezrádza

- **Pravidlo:** v repozitári ani v histórii nie sú osobné údaje, infraštruktúra
  ani tajomstvá, ani ako hash, ani zakódované v binárke.
- **Vynútenie:**
  - pre-push hook a CI kontrola: autori len `noreply`, denylist s porovnaním aj
    častí FQDN a e-mailov (denylist mimo repa),
  - build bez lokálnych ciest (`--remap-path-prefix`),
  - Dependabot pre všetky ekosystémy, image pripnuté cez digest.

---

## 3. Štrukturálne kroky (odstránia celé triedy chýb)

| Krok | Čo | Ktoré invarianty zatvorí |
|---|---|---|
| S1 | **Mapa autority:** tabuľka všetkých operácií, ktoré menia autoritu alebo dáta (endpoint, CLI, GUI, MCP), s údajom, kto smie, akou funkciou sa to overuje a kde je test. Register v kóde a test, ktorý zlyhá pri nezaregistrovanej operácii. | INV-2 |
| S2 | **Jedna autorizačná funkcia na serveri** pre append, restore, migráciu, odovzdanie roly, rejoin, reseed a zápisy objektov. Výnimky sa smú len pridať do tabuľky v S1, nie roztrúsiť v kóde. | INV-1, INV-2 |
| S3 | **Prehranie denníka a autorita do Rust jadra** (`teamlog` → `core/`), duplicitné implementácie zmazať. | INV-9, K4 |
| S4 | **Zoznam nepodpísaných polí** (INV-3) ako súbor v repe a pravidlo state machine, ktoré klame v každom z nich. | INV-3, INV-4 |
| S5 | **Revízia výnimiek:** pre každú (`own_cleanup`, `_rotation_lost_here`, výnimka pre bývalých adminov, pravidlá začiatku osobného stromu, presun vlastnej položky, legacy cesty bez denníka) rozhodnúť, či sa **zmaže**, **nahradí pravidlom v denníku**, alebo **zostane so zdôvodnením a property testom**. | K3 |
| S6 | **Zrušiť režim „viac používateľov bez denníka“**, zmigrovať a legacy heuristiky zmazať. | INV-1, veľká časť povrchu |
| S7 | **Jeden mechanizmus pre čakajúce zmeny** (outbox + oplock + `BEGIN IMMEDIATE`) a test, že nikto nezapisuje pending stav mimo neho. | INV-6, INV-7 |
| S8 | **Odovzdanie roly admina ako pravidlo v denníku**, nie ako pridelené prístupy: admin smie mať kľúče podľa pravidla; zníženie roly označí priečinky na re-key. | INV-1, INV-2 |

---

## 4. Testovať vlastnosti, nie scenáre

**Rozšíriť state machine** (`tests/test_sync_state_machine.py`):

- **Pravidlá tímového denníka:** založenie, pridanie, pridelenie prístupu, odobratie
  prístupu, odvolanie člena, rotácia identity, odovzdanie roly admina, restore,
  forget-pin, reseed, zmena hesla.
- **Aktéri:**
  - zlomyseľný člen, ktorý podpisuje, čo chce, a posiela, čo chce;
  - zlomyseľný server, ktorý klame vo všetkých poliach z INV-3, zadržiava, prehráva
    staré verzie, vymýšľa účty a vracia falošné 410 a falošný rollback;
  - druhý proces;
  - pád medzi krokmi.
- **Zariadenia:** desktop, web a mobil (cez conformance harness).

**Invarianty kontrolované po každom kroku:**

1. Odvolaný člen nemá envelope na aktuálnom kľúči žiadneho priečinka.
2. Nikto nemá kľúč priečinka, ktorý mu denník nepriznáva.
3. Bežný člen nevie zmazať, presunúť ani prepísať položku, ku ktorej mu denník nedáva zápis.
4. Žiadna položka nezmizne a nezmení sa bez akcie oprávneného používateľa.
5. Po ustálení vidia všetky zariadenia ten istý obsah.
6. Ku každému blokujúcemu stavu existuje cesta von (INV-7).
7. Server nevie zvýšiť práva, vrátiť staršiu verziu ani vyvolať núdzovú akciu.
8. AI vypínač: po `ai off` nič neobnoví prístup bez `ai on` s heslom.

**Prevádzka testov:**

- Nočný beh s náhodnými seedmi na oboch strojoch.
- Každý protipríklad sa uloží ako regresný test (blob a seed).

**Pravidlo pre každý nález:**

1. Určiť invariant, ktorý nález porušuje. Ak taký nie je, doplniť ho sem.
2. Rozšíriť property test tak, aby nález **našiel sám** a na pôvodnom kóde zlyhal.
3. Až potom opraviť, a to **na úrovni príčiny**: odstrániť výnimku, presunúť
   rozhodnutie do jadra alebo autorizačnej funkcie. Nepridávať ďalší špeciálny prípad.
4. Opravu preniesť na všetkých klientov naraz, ideálne tým, že je v jadre.

---

## 5. Proces

1. **Zmrazenie funkcií.** Žiadne nové núdzové ani obnovovacie funkcie a žiadne nové
   cesty, ktoré menia autoritu, kým INV-1 až INV-8 nemajú property testy a kroky
   S1, S2 a S6 nie sú hotové.
2. **Kontrolný zoznam autority pri každej zmene** (sekcia 6). Odpovede patria do
   popisu commitu.
3. **Ochrana proti regresiám:**
   - každá zmena v zámkoch, transakciách, poradí krokov alebo dekorátoroch
     (`@oplock.held`) má v commite zdôvodnenie a test,
   - pred merge beží state machine na N seedov,
   - CI odmietne odstránenie `@oplock.held` z metódy, ktorá mení kľúče, bez
     aktualizácie zoznamu výnimiek.
4. **Drobnosti.** Raz za kolo uprace jeden blok dlhodobo otvorených nálezov. Každý
   otvorený nález má dátum. Po dvoch kolách sa uzavrie, alebo sa výslovne prijme ako
   „nebude opravené“ so zdôvodnením.
5. **Rozsah vydania.** Kým nie sú hotové kroky S1–S6 a nezávislý audit:
   - vydávať pre **osobné použitie** (jeden používateľ, viac zariadení),
   - tímové funkcie dať za prepínač „experimentálne“,
   - v dokumentácii jasne uviesť, čo je hotové.
6. **Nezávislý audit človekom** pred tímovým použitím. Cyklus „AI review → AI oprava“
   má klesajúci prínos a nenahradí ho.
7. **Hygiena:**
   - pre-push hook (autori `noreply`, denylist),
   - Dependabot,
   - CI inštaluje z lockfilov,
   - image pripnuté cez digest.

---

## 6. Kontrolný zoznam pre každú zmenu

Odpovede patria do popisu commitu alebo PR. Vynucuje to commit-msg hook
(`.githooks/commit-msg`, `git config core.hooksPath .githooks`) a CI job `commits`
(`scripts/commit_discipline.py`): riadok `Checklist (docs/ROOT_CAUSE_PLAN.md section 6)`
s odpoveďami `1.` až `9.` a riadok `Red on <sha>: python -m pytest ...` (príkaz na <sha>
s testami commitu padne; CI ho spustí) alebo `No fix: <dôvod>`.

1. Mení zmena autoritu (kto smie čo) alebo dáta iného používateľa? Ak áno, kde je
   v mape autority (S1) a ktorou funkciou sa overuje?
2. Pridáva výnimku alebo špeciálny prípad? Prečo sa to nedá vyjadriť pravidlom
   v denníku alebo v jadre?
3. Používa nepodpísaný údaj zo servera (INV-3)? Ak áno, prečo nemôže uškodiť?
4. Čo sa stane, keď hodnota chýba, kontrola zlyhá alebo server neodpovie (INV-5)?
5. Má zmena viac častí? Sú v jednej transakcii a jednej atomickej požiadavke (INV-6)?
   Drží sa oplock?
6. Je to núdzová cesta? Má rovnaké kontroly ako hlavná (INV-2)? Môže ju vyvolať
   útočník (INV-8)?
7. Môže používateľ uviaznuť? Kde je cesta von a je dostupná z obrazovky, kde
   uviazne (INV-7)?
8. Je rozhodnutie v jadre, alebo sa implementuje v každom klientovi zvlášť (INV-9)?
9. Ktorý property test by túto zmenu rozbil, keby bola zlá?

**Vzory, ktoré treba pri každej zmene preveriť `grep`-om:**

- `except Exception` okolo kontroly,
- `or True` alebo predvolené `True` či `"write"`,
- komentáre typu „counts as checked“ alebo „unknown … allow“,
- `INSERT OR REPLACE` bez porovnania verzie,
- čítanie `is_admin` alebo `owner_id` v rozhodnutí,
- `get_meta(...)` a potom `set_meta(...)` mimo transakcie.

---

## 7. Poradie práce

1. **Fáza 0 (hneď):** uzavrieť otvorené vysoké nálezy z poslednej review (odovzdávajú
   sa zvlášť). Pre každý najprv property test podľa sekcie 4.
2. **Fáza 1:** S1 (mapa autority a register), S4 (zoznam nepodpísaných polí),
   rozšírenie state machine o pravidlá denníka, zlomyseľného člena a server.
3. **Fáza 2:** S2 (jedna autorizačná funkcia), S5 (revízia výnimiek), S8 (odovzdanie
   roly v denníku), S7 (jeden mechanizmus čakajúcich zmien).
4. **Fáza 3:** S3 (denník a autorita v jadre), S6 (zrušenie režimu bez denníka pre
   tímy), zmazanie duplicitných implementácií.
5. **Fáza 4:** nezávislý audit, potom zapnutie tímových funkcií ako stabilných.

**Kritérium hotovosti:** nočný state machine so zlomyseľným serverom a členom nenájde
počas jedného týždňa žiadny protipríklad. Nezávislý audit nenájde žiadny vysoký nález
v oblastiach S1–S8.
