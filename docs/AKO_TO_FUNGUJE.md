# Sezam — Ako to funguje

**Prístupná technická príručka**
**Verzia:** 1.0
**Posledná aktualizácia:** 2026-03-19

---

## Obsah

1. [Prečo existuje Sezam](#1-prečo-existuje-sezam)
2. [Základné princípy](#2-základné-princípy)
3. [Ako Sezam chráni vaše dáta](#3-ako-sezam-chráni-vaše-dáta)
4. [Dva kľúčové páry](#4-dva-kľúčové-páry)
5. [Ako funguje prihlásenie](#5-ako-funguje-prihlásenie)
6. [Ako funguje zdieľanie](#6-ako-funguje-zdieľanie)
7. [Čo sa stane keď...](#7-čo-sa-stane-keď)
8. [Shamir Secret Sharing](#8-shamir-secret-sharing)
9. [Audit log](#9-audit-log)
10. [Synchronizácia](#10-synchronizácia)
11. [Bezpečné zdieľanie odkazom](#11-bezpečné-zdieľanie-odkazom)

---

## 1. Prečo existuje Sezam

### Problém

Kde dnes ľudia ukladajú heslá a prístupové údaje?

- V **textových súboroch** na disku (`hesla.txt`, `passwords.xlsx`) — bez akejkoľvek ochrany
- V **e-mailoch** — „Posielam ti heslo k serveru" — každý, kto sa dostane k vášmu e-mailu, ho vidí
- Na **WhatsApp-e / Slack-u** — „Hej, daj mi heslo k databáze" — správa zostáva v histórii na všetkých zariadeniach
- Na **papierikoch** — prilepené na monitore alebo v zásuvke
- V **hlave** — a keď zabudnete, resetujete ho (ak môžete)

Každý z týchto spôsobov má vážne problémy:

| Spôsob | Problém |
|--------|---------|
| Textový súbor | Ktokoľvek s prístupom k disku ho prečíta. Žiadne šifrovanie. |
| E-mail / chat | Správa zostáva v histórii. Môže ju prečítať ktokoľvek s prístupom k účtu. |
| Zdieľanie hesla textom | Heslo putuje cez servery tretích strán (Google, Meta, Microsoft). |
| Rovnaké heslo všade | Únik jedného hesla kompromituje všetky účty. |

### Riešenie

Sezam tieto problémy rieši:

- **Všetko je šifrované** — nikto okrem vás (a vašich oprávnených kolegov) nevidí obsah.
- **Server je slepý** — server ukladá len šifrované dáta. Ani administrátor servera nevie, čo v nich je.
- **Zdieľanie je bezpečné** — kolegovi sa prístup pridelí kryptograficky, nie poslaním hesla cez chat.
- **Každý má prístup len k tomu, čo potrebuje** — admin určuje, kto vidí ktorý priečinok.

---

## 2. Základné princípy

Predtým než vysvetlíme, ako Sezam funguje, potrebujeme porozumieť trom základným pojmom. Vysvetlíme si ich pomocou analógií.

### Čo je šifrovanie

**Analógia: Trezor so zámkom**

Predstavte si, že máte papier s dôležitými údajmi. Vložíte ho do trezora a zamknete. Bez správneho kľúča je papier nečitateľný — trezor je zamknutý a steny sú nepriestrelné.

V digitálnom svete je to rovnaké:
- **Vaše dáta** = papier s údajmi
- **Šifrovanie** = zamknutie do trezora
- **Šifrovací kľúč** = kľúč od trezora
- **Šifrované dáta** (ciphertext) = zamknutý trezor — vidíte len kus kovu, nie čo je vnútri

```
Vaše heslo: "xK9!mP2$"
        |
   [ ŠIFROVANIE ]
        |
        v
Šifrované dáta: "7f3a9b2c...e8d1" (nečitateľný blob)
```

Bez správneho kľúča je šifrovaný blob bezcenný — nevie ho prečítať nikto, ani najvýkonnejší počítač na svete.

### Čo je kľúč

**Analógia: Jedinečný kľúč k zámku**

Každý zámok má svoj jedinečný kľúč. Ak máte správny kľúč, zámok sa otvorí. Ak nie, nič sa nestane.

V Sezame sú kľúče dlhé čísla (256 bitov = 256 jednotiek a núl). Vyzerajú napríklad takto:

```
Kľúč: a1b2c3d4e5f6... (64 hexadecimálnych znakov = 256 bitov)
```

256-bitový kľúč znamená, že existuje 2^256 možných kľúčov. To je číslo:

```
115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,
640,564,039,457,584,007,913,129,639,936

(~1.16 x 10^77)
```

Pre porovnanie: počet atómov v pozorovateľnom vesmíre je „len" ~10^80. Uhádnuť správny kľúč je prakticky nemožné.

### Čo je hash

**Analógia: Odtlačok prsta**

Hash je ako digitálny odtlačok prsta:
- Z **človeka** môžete vytvoriť **odtlačok** — jednoznačný, unikátny.
- Z **odtlačku** nemôžete **zrekonštruovať človeka** — proces je jednosmerný.

Rovnako hash funkcia:
- Z **dát** vytvoríte **hash** — vždy rovnaký pre rovnaké dáta.
- Z **hashu** nezískate **pôvodné dáta** — neexistuje cesta späť.

```
"MojeHeslo123" --> SHA-256 --> "3a7f8c...2b1e" (64 hex znakov, vždy rovnakých)
"MojeHeslo124" --> SHA-256 --> "9d2e4f...8c3a" (úplne iný hash — stačí zmena jedného znaku)
```

Hash sa používa na overenie: „Je toto správne heslo?" — porovnáme hash, nie heslo samotné.

---

## 3. Ako Sezam chráni vaše dáta

Teraz, keď rozumieme základom, poďme krok po kroku. Celá cesta od vášho hesla k zašifrovaným dátam vyzerá takto:

```
   Vaše master heslo
          |
          v
    +-----------+
    |  Argon2id  |  <-- 1 sekunda výpočtu, 256 MB pamäte
    +-----------+
          |
          v
      Root KEK        (Key Encryption Key — „kľúč od budovy")
          |
    +-----+-----+-----+
    |     |     |     |
    v     v     v     v
   DEK   DEK   DEK   DEK    (Data Encryption Keys — „kľúče od kancelárií")
   root  servers fin  clients
    |     |     |     |
    v     v     v     v
   dáta  dáta  dáta  dáta   (šifrované záznamy)
```

### Krok 1: Master heslo sa stane kľúčom (KEK)

Vaše heslo sa pretransformuje na šifrovací kľúč. Tento proces (nazývaný **Argon2id**) je **zámerne pomalý** — trvá približne 1 sekundu a používa 256 MB operačnej pamäte.

```
Heslo: "MojSuperTajnýTrezor2024!"
  +
Náhodná soľ: [16 náhodných bajtov, unikátnych pre každého používateľa]
  |
  v
Argon2id (čas=3 iterácie, pamäť=256 MB, paralelizmus=4)
  |
  v  (~1 sekunda na modernom počítači)
Root KEK: [256-bitový šifrovací kľúč]
```

**Prečo je to pomalé?**

Keby premena hesla na kľúč bola okamžitá, útočník by mohol skúšať milióny hesiel za sekundu. S Argon2id dokáže skúsiť len ~1 heslo za sekundu na jednom jadre procesora. A používanie 256 MB pamäte na každý pokus znamená, že ani špecializovaný hardvér (GPU farmy) nepomôže — každý pokus zaberá obrovské množstvo pamäte.

| Scenár | Čas na prelomenie |
|--------|-------------------|
| Slabé heslo (8 znakov, len písmená) | Dni až týždne |
| Dobré heslo (12 znakov, mix) | Tisíce rokov |
| Silné heslo (16+ znakov, mix) | Dlhšie než existencia vesmíru |

### Krok 2: KEK odomkne DEK-y

KEK (Key Encryption Key) neodomyká priamo vaše dáta. Namiesto toho odomyká ďalšie kľúče — **DEK-y** (Data Encryption Keys), každý pre jeden priečinok.

**Analógia: KEK je kľúč od budovy. DEK je kľúč od konkrétnej kancelárie.**

```
Root KEK ("kľúč od budovy")
    |
    |-- odomkne --> DEK pre "Servery"       ("kľúč od kancelárie Servery")
    |-- odomkne --> DEK pre "Financie"       ("kľúč od kancelárie Financie")
    |-- odomkne --> DEK pre "Klienti"        ("kľúč od kancelárie Klienti")
    |-- odomkne --> DEK pre "Audit"          ("kľúč od archívnej skrine")
    `-- odomkne --> Root DEK                 ("kľúč od recepcie")
```

**Prečo nie jeden kľúč na všetko?**

Keby sme mali len jeden kľúč, nemohli by sme zdieľať prístup granulárne. Takto môže admin dať kolegovi kľúč len od „Klientov" — kolega nevidí „Servery" ani „Financie".

### Krok 3: DEK šifruje dáta

Každý záznam (heslo, SSH kľúč, poznámka) je zašifrovaný DEK-om svojho priečinka.

```
Príklad: Záznam "Gmail heslo" v priečinku "Osobné"

Vstup (plaintext):
{
  "username": "jan@gmail.com",
  "password": "xK9!mP2$",
  "url": "https://mail.google.com"
}

         |
    [ XChaCha20-Poly1305 šifrovanie s DEK-om priečinka "Osobné" ]
         |
         v

Výstup (ciphertext):
7f3a9b2c4d5e6f...a8b9c0d1e2f3  (nečitateľný blob — uložený v databáze)
```

Šifrujeme algoritmom **XChaCha20-Poly1305**, čo je moderný šifrovací štandard:
- **XChaCha20** — rýchle šifrovanie dát
- **Poly1305** — overenie, že dáta neboli pozmenené (autentifikácia)

Každý blob má navyše náhodný **nonce** (24 bajtov) — to znamená, že aj keby ste zašifrovali to isté heslo dvakrát, výsledok bude vždy iný.

### Krok 4: Čo vidí server

Server ukladá vaše dáta, ale nevie, čo v nich je. Tu je presný prehľad:

| Server VIDÍ | Server NEVIDÍ |
|-------------|---------------|
| Počet objektov (koľko záznamov máte) | Názvy priečinkov a záznamov |
| Typ objektu (či je to priečinok alebo záznam) | Heslá, kľúče, poznámky |
| Kto vlastní ktorý objekt | Názvy polí („username", „password") |
| Veľkosti šifrovaných blobov | Tagy |
| Kedy bol objekt naposledy synchronizovaný | Kedy bol záznam vytvorený alebo zmenený |

Server je **content-blind** („obsahovo slepý") — vidí len nečitateľné šifrované bloby. Nevie, že „blob X" je vaše heslo ku Gmailu a „blob Y" je SSH kľúč k serveru.

---

## 4. Dva kľúčové páry

Každý používateľ Sezamu má dva oddelené kľúčové páry. Každý pár sa skladá z **privátneho kľúča** (tajný, len váš) a **verejného kľúča** (môže ho vidieť každý).

### Podpisový pár (Ed25519)

**Analógia: Váš osobný pečatný prsteň**

V stredoveku kráľ zapečatil list prsteňom — každý vedel, že list napísal kráľ, lebo pečatný prsteň mal len on.

```
Petrov privátny podpisový kľúč (tajný)
    |
    v
Podpis správy: "Presúvam záznam do priečinka Servery"
    |
    v
Ktokoľvek s Petrovým VEREJNÝM kľúčom vie overiť:
  "Áno, toto podpísal Peter. Správu nikto nezmenil."
```

Použitie:
- **Prihlásenie** — server overuje vašu identitu
- **Audit log** — každá akcia je podpísaná, nikto ju nemôže sfalšovať
- **Synchronizácia** — každá zmena je podpísaná, server ju nemôže podmeniť

### Šifrovací pár (X25519)

**Analógia: Poštová schránka**

Predstavte si poštovú schránku: ktokoľvek vie vhodiť list (použije otvor), ale len vy ju viete otvoriť kľúčom.

```
Jankova verejná šifrovacia adresa (verejný kľúč)
    |
    v
Admin zašifruje správu pre Janka
    |
    v
Len Janko (so svojím privátnym kľúčom) ju vie dešifrovať
```

Použitie:
- **Zdieľanie priečinkov** — admin zašifruje kľúč od priečinka pre konkrétneho kolegu (viď sekcia 6)

### Prečo dva páry?

Sú to odlišné matematické operácie:
- **Ed25519** (podpis) — vie podpísať a overiť podpis. **Nevie šifrovať.**
- **X25519** (šifrovanie) — vie šifrovať a dešifrovať. **Nevie podpisovať.**

Je to ako pero a zámok — pero slúži na písanie (podpis), zámok slúži na zamykanie (šifrovanie). Používať pero ako zámok by nefungovalo.

### Fingerprint — digitálny odtlačok

Z oboch verejných kľúčov sa vypočíta **fingerprint** (digitálny odtlačok):

```
SHA-256(podpisový_verejný_kľúč + šifrovací_verejný_kľúč)
    = "a3b7c2d9e4f1..."

Zobrazenie v GUI:
  - Vizuálne:   [unikátny obrázok]    — výrazná zmena pri podvrhu
  - Slovne:     "Kôň Jablko Skala Modrá"   — pre jednoduché overenie
  - Plný hex:   a3b7c2d9e4f1...       — pre úplnú verifikáciu
```

Admin pri schvaľovaní kolegu overuje fingerprint — ideálne osobne alebo telefonicky. Ak by server podmienil kľúče, fingerprint by bol iný a admin by si to všimol.

---

## 5. Ako funguje prihlásenie

Prihlásenie v Sezame je odlišné od bežných webov. Neposielate heslo na server — namiesto toho dokazujete svoju identitu cez **challenge-response** (výzva-odpoveď).

### Krok po kroku

```
   Klient (váš prehliadač/appka)              Server
   ============================              ======

   1. "Chcem sa prihlásiť, som Peter" ------->

                                     2. Server vytvorí náhodnú výzvu:
                                        challenge = [32 náhodných bajtov]
                                        + časová pečiatka

                               <------- 3. "Tu máš výzvu: abc123..."

   4. Peter podpíše výzvu svojím
      PRIVÁTNYM podpisovým kľúčom:
      signature = Sign(privátny_kľúč, "sezam-auth-challenge-signature-v1" + challenge)
      (s pevnou predponou, aby server nemohol nechať podpísať niečo iné)

   5. Pošle podpis na server -------->

                                     6. Server overí podpis Petrovým
                                        VEREJNÝM kľúčom:
                                        Verify(verejný_kľúč, challenge, signature)
                                        --> "Áno, to je Peter!"

                                     7. Server skontroluje:
                                        - Časová pečiatka < 30 sekúnd stará
                                        - Výzva ešte nebola použitá

                               <------- 8. Server vydá JWT token
                                           (ako vstupenku platnú 1 hodinu)

   9. Peter používa JWT token
      na všetky ďalšie požiadavky
```

### Prečo je to bezpečné?

- **Heslo nikdy neopustí vaše zariadenie** — server ho nikdy nevidí.
- **Každá výzva je jednorazová** — zachytený podpis sa nedá použiť znova (replay ochrana).
- **Časový limit** — výzva platí len 30 sekúnd.
- **JWT token** — po úspešnom prihlásení dostanete „vstupenku" platnú 1 hodinu. Nemusíte sa prihlasovať pri každom kliknutí.

### Kde vstupuje heslo?

Heslo sa používa **lokálne na vašom zariadení** na odomknutie privátnych kľúčov:

```
Vaše heslo --> Argon2id --> KEK --> odomkne privátne kľúče (podpisový + šifrovací)
```

Server nikdy nevidí vaše heslo. Vidí len verejné kľúče a podpisy.

---

## 6. Ako funguje zdieľanie

### Zdieľanie priečinkov v tíme (Envelope Encryption)

Keď admin chce dať Jankovi prístup k priečinku „Klienti", nepošle mu heslo cez chat. Namiesto toho použije **obálky** (envelopes).

**Analógia: Admin vloží kľúč od kancelárie do zapečatenej obálky adresovanej Jankovi**

```
KROK 1: Admin má DEK pre priečinok "Klienti"
        (kľúč od kancelárie)

KROK 2: Admin zabalí DEK do obálky pre Janka:
        ┌─────────────────────────────┐
        │  OBÁLKA PRE JANKA           │
        │                             │
        │  Obsah: DEK pre "Klienti"   │
        │                             │
        │  Zašifrované tak, že len    │
        │  Janko ju vie otvoriť       │
        │  (Jankov verejný kľúč)      │
        └─────────────────────────────┘

KROK 3: Obálka sa uloží na server

KROK 4: Janko si stiahne obálku a otvorí ju
        svojím privátnym kľúčom:
        Obálka --> Jankov privátny kľúč --> DEK --> dáta v priečinku "Klienti"
```

Technická poznámka: Obálka je vytvorená pomocou **NaCl crypto_box** — autentifikované šifrovanie, ktoré zaručuje, že obálku vytvoril admin (nie server ani nikto iný).

### Čo sa stane pri odobratí prístupu

Keď admin odoberie Jankovi prístup:

```
1. Admin odoberie Jankovi prístup ku "Klienti"

2. Systém vygeneruje NOVÝ DEK pre "Klienti"
   (nový kľúč od kancelárie — ten starý je kompromitovaný)

3. Všetky záznamy v "Klienti" sa prešifrujú novým DEK-om
   (všetko v kancelárii sa preloží do nového trezora)

4. Admin vytvorí NOVÉ obálky pre zostávajúcich kolegov
   (nový kľúč sa rozdá ostatným — ale nie Jankovi)

5. Jankov starý DEK je bezcenný — nový DEK nemá
```

Toto sa nazýva **re-key** (prešifrovanie). Je to jediná bezpečná cesta — nestačí len vymazať obálku, pretože Janko si mohol DEK uložiť. Preto sa celý priečinok prešifruje novým DEK-om.

---

## 7. Čo sa stane keď...

### ...stratíte heslo

**Prečo neexistuje „resetovať heslo"?**

Keby existoval spôsob, ako obnoviť heslo bez jeho znalosti, znamenalo by to, že niekto iný (server, admin, Sezam) má k vašim dátam prístup. To je presne to, čomu sa snažíme zabrániť. Žiadny backdoor neexistuje — a to je vlastnosť, nie chyba.

```
Osobný vault:
┌──────────────────────────────────────────┐
│  STRATA DÁT — by design                 │
│                                          │
│  Nikto nemá backdoor. Nikto nevie        │
│  obnoviť vaše heslo. Vaše dáta sú       │
│  permanentne zamknuté.                   │
│                                          │
│  Toto nie je chyba — je to vlastnosť.   │
│  Keby existoval spôsob obnovenia,        │
│  mohol by ho zneužiť útočník.            │
└──────────────────────────────────────────┘

Firemný vault:
┌──────────────────────────────────────────┐
│  BREAK-GLASS mechanizmus                 │
│                                          │
│  3 z 5 dôveryhodných osôb sa stretnú,    │
│  zrekonštruujú recovery kľúč             │
│  a odomknú vault (viď sekcia 8).         │
│                                          │
│  POZOR: Toto je len pre firemného        │
│  admina! Bežný používateľ, ktorý         │
│  zabudol heslo, prišiel o dáta.          │
└──────────────────────────────────────────┘
```

### ...stratíte zariadenie

Existujú tri cesty obnovy, v závislosti od vašej situácie:

```
Scenár 1: Stratené zariadenie + viete heslo (NAJČASTEJŠIE)
  --> Nainštalujte Sezam na nové zariadenie
  --> Zadajte meno a heslo
  --> Server má vaše šifrované kľúče
  --> Heslo --> Argon2id --> KEK --> odomkne kľúče
  --> Všetko sa automaticky stiahne

Scenár 2: Stratené zariadenie + viete heslo + bez servera
  --> Použite súbor .sezam-key (offline záloha)
  --> Importujte súbor na novom zariadení
  --> Zadajte heslo
  --> Kľúče sa odomknú lokálne (bez servera)

Scenár 3: Admin zabudol heslo (len firemný vault!)
  --> Shamir recovery: 3 z 5 dôveryhodných osôb
  --> Zrekonštruujú recovery kľúč
  --> Odomknú vault a nastavia nové heslo

Scenár 4: Bežný používateľ zabudol heslo
  --> STRATA DÁT (by design)
  --> Žiadna obnova nie je možná
  --> Admin ho môže pozvať nanovo (stratí staré dáta)
```

> **Kľúčový rozdiel:** Scenáre 1 a 2 vyžadujú znalosť hesla. Scenár 3 je len pre firemného admina a vyžaduje fyzickú prítomnosť dôveryhodných osôb. Scenár 4 je zámerný — je to cena za to, že nikto iný nemá prístup k vašim dátam.

### ...je admin kompromitovaný

Admin má plný prístup k celému vaultu (má KEK, ktorý odomkne všetky DEK-y). Ak útočník získa prístup k admin zariadeniu:

| Ohrozené | Prečo |
|----------|-------|
| Všetky heslá a záznamy | Admin má kľúče ku všetkému |
| Obálky (prideľovanie prístupu) | Admin ich vie vytvoriť/zmeniť |
| Audit log (admin záznamy) | Admin vie podpísať falošné záznamy |

| Zostáva bezpečné | Prečo |
|-------------------|-------|
| Server stále nevidí plaintext | Server nemá KEK |
| Audit záznamy iných ľudí | Podpísané ICH kľúčmi, admin ich nevie sfalšovať |
| Zdieľacie odkazy iných | Kľúč je v URL, admin ho nemá (ak odkaz nevidel) |

> Toto je rovnaký model bezpečnosti ako KeePass alebo Bitwarden self-hosted. Pre vyšší stupeň ochrany by bol potrebný multi-admin systém (viacero adminov musí súhlasiť), čo je mimo rozsah aktuálnej verzie.

### ...je server hacknutý

```
Čo útočník získa:               Čo s tým môže robiť:
┌───────────────────┐           ┌─────────────────────┐
│ Šifrované bloby   │    -->    │ NIČ — bez KEK       │
│ Verejné kľúče     │           │ sú bezcenné          │
│ Štruktúru vaultu  │           │                     │
│ (koľko záznamov,  │           │ Môže skúsiť offline  │
│  kto vlastní čo)  │           │ útok na heslo, ale   │
└───────────────────┘           │ Argon2id to robí     │
                                │ extrémne pomalé      │
                                └─────────────────────┘
```

Server je **content-blind** — aj keby bol úplne kompromitovaný, útočník vidí len šifrované dáta. Bez vášho hesla (a teda KEK-u) sú bezcenné.

Jediná možnosť útočníka: offline brute-force na vaše heslo. Ale s Argon2id (256 MB pamäte, 1 sekunda na pokus) a silným heslom je to prakticky nemožné.

---

## 8. Shamir Secret Sharing

Pre firemné vaults existuje núdzový mechanizmus — **Shamir Secret Sharing** (Shamirovo zdieľanie tajomstva).

**Dôležité:** Shamir je určený **výhradne pre firemný vault**, keď admin stratí heslo alebo je nedostupný. Nie je to obnova hesla pre bežných používateľov — tí pri strate hesla prichádzajú o dáta (by design).

### Myšlienka

**Analógia: Mapa pokladu rozrezaná na 5 kusov**

```
Recovery kľúč (tajomstvo)
      |
      v
 Shamir (3 z 5)
      |
   +--+--+--+--+--+
   |  |  |  |  |  |
   v  v  v  v  v  v
  C1 C2 C3 C4 C5     <-- 5 častí, každá u inej dôveryhodnej osoby
  CEO CTO Legal CFO IT

  Rekonštrukcia: stačia AKÉKOĽVEK 3 z 5 častí
  Napríklad: CEO + CTO + Legal --> recovery kľúč --> odomkne vault
```

### Ako to funguje

1. Pri vytvorení firemného vaultu sa vygeneruje **recovery kľúč**.
2. Recovery kľúč sa rozdelí na **5 častí** (shares) pomocou Shamirovej schémy.
3. Každá časť sa dá jednej dôveryhodnej osobe (CEO, CTO, právnik, CFO, IT riaditeľ).
4. **Žiadna jednotlivá časť nie je použiteľná** — je to len náhodná sekvencia čísel.
5. Na rekonštrukciu recovery kľúča sú potrebné **minimálne 3 z 5 častí**.

### Matematika za tým (zjednodušene)

Shamirova schéma je založená na fakte, že na určenie priamky potrebujete 2 body, na určenie paraboly 3 body, atď.

```
Pre prah 3 z 5:
  - Tajomstvo je konštantný člen polynómu stupňa 2 (parabola)
  - Každá časť je bod na tejto parabole
  - 2 body = nekonečne veľa paraból (nedostatočné)
  - 3 body = presne jedna parabola = tajomstvo odhalené
  - 4 alebo 5 bodov = stále tá istá parabola (redundancia)
```

### Kedy sa používa

- Admin stratil heslo a nemá .sezam-key
- Admin zariadenie bolo zničené
- Firma potrebuje prístup k vaultu bez admina (napr. admin odišiel)

3 z 5 osôb sa **fyzicky stretnú**, každý zadá svoju časť, systém zrekonštruuje recovery kľúč a odomkne vault.

---

## 9. Audit log

### Čo je audit log

Audit log je záznam o všetkom, čo sa v Sezame stalo. Každá akcia je zapísaná a **kryptograficky podpísaná** — nikto ju nemôže sfalšovať ani vymazať bez zanechania stopy.

```
Príklad audit záznamu:

Kto:    Peter
Kedy:   2026-03-19 14:32:15
Akcia:  Prečítal záznam "servers/hetzner/ssh"
Podpis: [Ed25519 podpis Petrovým kľúčom]
```

### Prečo je to dôležité

- **Zodpovednosť** — viete, kto a kedy pristupoval k akému záznamu.
- **Detekcia** — ak niekto pristupoval k niečomu, čo nemal, uvidíte to.
- **Nesfalšovateľnosť** — záznamy sú podpísané privátnym kľúčom autora. Nikto iný ich nevie vytvoriť.

### Merkle DAG — pokročilá integrita

Audit záznamy nie sú len zoznam — sú prepojené do **Merkle DAG** (orientovaný acyklický graf). Každý záznam referencuje predchádzajúce záznamy:

```
Lineárny reťazec (problém pri offline používaní):

  A --> B --> C --> [Peter offline] --> D_peter
                     \--> [Janko offline] --> D_janko
                           PROBLÉM: reťazec sa rozbil!

Merkle DAG (riešenie v Sezame):

  A --> B --> C --> D_peter (rodič: C)
                \-> D_janko (rodič: C)
                    \-> E_merge (rodičia: D_peter, D_janko)  -- OK!
```

DAG umožňuje, aby viacero ľudí pracovalo súčasne (aj offline), a ich záznamy sa neskôr bezpečne zlúčili.

### Overovanie integrity

Ktokoľvek môže overiť integritu audit logu:

1. Začínam od najstaršieho záznamu.
2. Pre každý záznam overím Ed25519 podpis autorovým verejným kľúčom.
3. Ak podpis nesedí — záznam bol sfalšovaný.
4. Ak chýba záznam v reťazci — niekto ho vymazal.

---

## 10. Synchronizácia

### Ako to funguje

Sezam používa **offline-first** model — vaše dáta sú uložené lokálne na vašom zariadení. Synchronizácia so serverom prebieha explicitne (push/pull) alebo automaticky:

```
Lokálne zariadenie                     Server
================                     ======

Pridávate, meníte záznamy              Ukladá šifrované bloby
      |                                     ^
      v                                     |
  [ PUSH ]  ---  šifrované zmeny  --->      |
                                            |
      ^                                     |
      |                                     v
  [ PULL ]  <---  zmeny od iných  ---       |
```

### Delta sync

Server neposiela celý vault pri každej synchronizácii. Posiela len to, čo sa zmenilo od poslednej synchronizácie (**delta sync**). Každý objekt má `commit_seq` (poradové číslo zmeny) a klient si pamätá, kde skončil.

### Konflikty

Ak Peter a Janko zmenia ten istý záznam súčasne:

```
Peter:   zmení heslo na "abc123"    -->  push
Janko:   zmení poznámku na "nový"   -->  push --> KONFLIKT (409)

Riešenie:
  - Sezam stiahne obe verzie
  - Ak sú zmeny v rôznych poliach: automatický merge
  - Ak sú zmeny v rovnakom poli: GUI ukáže obe verzie, používateľ si vyberie
```

### Ochrana pred rollbackom

Klient si lokálne udržuje **kontrolný súčet** (state hash) celého vaultu. Po každej synchronizácii ho prepočíta a porovná. Ak server vráti staršie dáta (rollback), klient to detekuje a zobrazí varovanie.

---

## 11. Bezpečné zdieľanie odkazom

Ak potrebujete jednorazovo poslať heslo niekomu (aj tomu, kto nemá Sezam), môžete vytvoriť **zdieľací odkaz** (share link).

### Ako to funguje

```
1. Peter chce zdieľať heslo k serveru

2. Sezam vygeneruje náhodný kľúč (share_key)
   a zašifruje ním dáta

3. Upload na server:
   - šifrovaný blob (server nevidí obsah)
   - časový limit (napr. 24 hodín)
   - počet zobrazení (napr. 1x)

4. Odkaz:
   https://sezam.firma.sk/s/Kx7mP9...qR2#share_key_base64
                                          ^^^^^^^^^^^^^^^^
                                          KĽÚČ — nikdy na server!
                                          (časť za # sa neposiela)

5. Peter pošle odkaz kolegovi

6. Kolega otvorí odkaz:
   - Prehliadač stiahne šifrovaný blob
   - Dešifruje ho kľúčom z URL (časť za #)
   - Zobrazí heslo
   - Po zobrazení (alebo po 24h): blob sa VYMAŽE zo servera
```

### Bezpečnostné vlastnosti

| Vlastnosť | Popis |
|-----------|-------|
| **Jednorazový** | Po prvom prečítaní sa dáta vymažú zo servera (default) |
| **Časovo obmedzený** | Po 24 hodinách (alebo kratšom čase) sa dáta automaticky vymažú |
| **PIN ochrana** | Voliteľne môžete nastaviť PIN — max 3 pokusy za 15 minút |
| **Server nevidí obsah** | Kľúč je v URL fragmente (#), ktorý sa na server neposiela |
| **Nezávislý** | Zdieľací odkaz používa vlastný jednorazový kľúč, nesúvisí s priečinkovými kľúčmi |

---

## Zhrnutie

```
┌─────────────────────────────────────────────────────────┐
│                    SEZAM — PREHĽAD                       │
│                                                         │
│  Heslo --> Argon2id (1s, 256MB) --> KEK                  │
│                                      |                   │
│                                   odomkne               │
│                                      |                   │
│  Ed25519 (podpis) + X25519 (šifrovanie) — dva páry      │
│                                      |                   │
│                                   DEK-y                  │
│                              (per-folder)                │
│                                      |                   │
│                                   XChaCha20-Poly1305     │
│                                      |                   │
│                              šifrované dáta              │
│                                      |                   │
│                              uložené na serveri          │
│                              (server nevidí obsah)       │
│                                                         │
│  Zdieľanie: obálky (crypto_box) pre kolegov             │
│  Prihlásenie: challenge-response (bez poslania hesla)    │
│  Audit: Merkle DAG s Ed25519 podpismi                    │
│  Recovery: Shamir 3/5 (firemný) | žiadna (osobný)       │
│  Sync: offline-first, delta, ochrana pred rollbackom     │
└─────────────────────────────────────────────────────────┘
```

Každý komponent Sezamu je navrhnutý tak, aby bol bezpečný aj v prípade, že server je kompromitovaný. Vaše dáta sú chránené vaším heslom — a to je jediná vec, ktorú musíte chrániť vy.

---

*Sezam — Váš bezpečný trezor na heslá. Navrhnutý tak, aby ste mu nemuseli veriť — stačí veriť matematike.*
