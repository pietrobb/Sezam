# Sezam — Príručka používateľa

**Verzia:** 1.0
**Posledná aktualizácia:** 2026-03-19

---

## Čo je Sezam

Sezam je bezpečný trezor na heslá, prístupové údaje a citlivé poznámky. Všetky vaše dáta sú šifrované — to znamená, že sú zamknuté tak, že ich môže otvoriť len ten, kto pozná správne heslo. Ani server, na ktorom sú dáta uložené, nevie, čo je vo vašom trezore. Sezam môžete používať osobne (na vlastné heslá) alebo v tíme (na zdieľané firemné prístupy).

---

## Čo potrebujete

Sezam môžete používať tromi spôsobmi:

| Spôsob | Popis |
|--------|-------|
| **Webový prehliadač** | Otvorte stránku Sezamu v prehliadači (Chrome, Firefox, Safari, Edge). Bez inštalácie. |
| **Desktop aplikácia** | Aplikácia pre Windows, macOS alebo Linux. Plné funkcie vrátane editácie. |
| **Mobilná aplikácia** | Aplikácia pre Android a iOS. Plné funkcie, offline prístup. |

Pre webové použitie nepotrebujete nič inštalovať — stačí moderný prehliadač a prístup na internet.

---

## Prvé kroky

### 1. Dostávate pozvánku

Váš administrátor (admin) vám pošle odkaz — pozvánku do Sezamu. Môže to byť e-mailom, cez správu alebo osobne. Odkaz vyzerá napríklad takto:

```
https://sezam.firma.sk/invite#abc123...
```

> Pozvánka je jednorazová a platí 72 hodín. Ak vyprší, požiadajte admina o novú.

### 2. Otvorte odkaz a nastavte si heslo

Po otvorení odkazu v prehliadači uvidíte formulár:

1. **Zadajte svoje meno** — použite celé meno alebo prezývku, ktorú vám admin určil.
2. **Vytvorte si heslo** — toto je vaše hlavné heslo (master password). Je to jediný kľúč k vašim dátam.
3. Kliknite na **„Registrovať sa"**.

Prehliadač vám môže ponúknuť stiahnutie zálohovacieho súboru (`.sezam-key`). **Uložte si ho na bezpečné miesto** (napr. USB kľúč v sejfe) — je to poistka pre prípad, že stratíte zariadenie a nemáte prístup k serveru.

### 3. Počkajte na schválenie

Po registrácii uvidíte správu: **„Čakám na schválenie administrátorom."**

Admin musí:
- Overiť vašu identitu (osobne alebo telefonicky)
- Schváliť váš prístup
- Pridať vám prístupy k príslušným priečinkom

Keď vás admin schváli, dostávate oznámenie a môžete sa prihlásiť.

### 4. Prihláste sa a používajte Sezam

Po schválení sa prihláste svojím menom a heslom. Uvidíte priečinky a záznamy, ku ktorým vám admin pridelil prístup.

---

## Denné používanie

### Prihlásenie

1. Otvorte Sezam (webovú stránku alebo aplikáciu).
2. Zadajte svoje **meno** a **heslo**.
3. Počas odomykania uvidíte spinner — trvá to približne 1 sekundu (je to zámerne, aby bolo vaše heslo lepšie chránené).
4. Po odomknutí uvidíte svoje priečinky.

### Prezeranie priečinkov a záznamov

- **Priečinky** (folders) sú ako zložky v počítači — organizujú vaše záznamy do skupín (napr. „Servery", „Financie", „Klienti").
- **Záznamy** (entries) sú jednotlivé položky — každá obsahuje meno, heslo, poznámky a ďalšie údaje.
- Kliknite na priečinok, aby ste ho otvorili.
- Kliknite na záznam, aby ste videli jeho detaily.

### Kopírovanie hesla

1. Kliknite na ikonku kopírovania vedľa hesla (alebo na tlačidlo „Kopírovať").
2. Heslo sa skopíruje do schránky.
3. **Po 15 sekundách sa schránka automaticky vymaže** — uvidíte odpočítavanie.
4. Prilepte heslo tam, kde ho potrebujete, skôr než vyprší čas.

> Táto funkcia chráni vaše heslo — ak zabudnete prilepiť a necháte to byť, heslo zo schránky zmizne samo.

### Hľadanie

1. Kliknite do vyhľadávacieho poľa (alebo stlačte klávesovú skratku, napr. `Ctrl+Alt+V` v desktop appke).
2. Zadajte časť názvu záznamu — napríklad „hetzner" alebo „gmail".
3. Výsledky sa zobrazia okamžite.
4. Kliknite na výsledok, aby ste ho otvorili.

Hľadanie prehľadáva názvy záznamov a priečinkov. **Nehľadá v hodnotách hesiel** (to je bezpečnostné opatrenie).

### TOTP kódy (dvojfaktorové overenie)

Ak máte v zázname uložený TOTP kód (časový jednorazový kód), Sezam ho automaticky generuje:

- Uvidíte 6-ciferný kód s odpočítavaním (30 sekúnd).
- Kliknite na kód, aby ste ho skopírovali.
- Ak zostáva menej ako 5 sekúnd, Sezam počká na nový kód, aby ste mali dosť času ho použiť.

---

## Bezpečnostné rady

### Silné heslo

Vaše hlavné heslo (master password) je jediný kľúč k vašim dátam. Zvoľte si ho starostlivo:

- **Dlhé** — minimálne 12 znakov, ideálne 16 a viac.
- **Unikátne** — nepoužívajte ho nikde inde.
- **Zapamätateľné** — môžete použiť vetu, napríklad: `Môj pes Rex má 3 nohy a 7 životov!`
- **Nepredvídateľné** — nesmie to byť meno, dátum narodenia ani bežné slovo.

Sezam vám pri vytváraní hesla ukáže, či je dostatočne silné.

### Zabudnuté heslo = strata dát

**Toto je najdôležitejšie, čo potrebujete vedieť:**

Nikto — ani administrátor, ani tvorcovia Sezamu — nemá možnosť obnoviť zabudnuté heslo. Vaše dáta sú šifrované vaším heslom a bez neho sú permanentne nedostupné.

Preto:
- Heslo si zapamätajte.
- Zálohovací súbor (`.sezam-key`) si uložte na bezpečné miesto.
- Ak máte firemný vault, existuje núdzový mechanizmus (break-glass), ale vyžaduje súčinnosť viacerých dôveryhodných osôb.

### Záloha .sezam-key súboru

Pri registrácii vám Sezam ponúkne stiahnutie súboru `.sezam-key`. Tento súbor je vaša poistka:

- **Uložte ho na USB kľúč** a dajte do sejfu alebo na bezpečné miesto.
- **Neukladajte ho na rovnaké zariadenie**, kde používate Sezam.
- **Nezdieľajte ho** — kto má tento súbor a pozná vaše heslo, má prístup k vašim dátam.

Ak stratíte všetky zariadenia (notebook aj telefón) a nemáte prístup k serveru, môžete sa obnoviť pomocou tohto súboru.

---

## Obnova pri strate zariadenia alebo hesla

### Stratili ste zariadenie? Máte heslo?

**Toto je najčastejší scenár.** Nainštalujte appku na nové zariadenie, zadajte heslo a server URL. Všetko sa automaticky stiahne.

Presný postup:
1. Otvorte Sezam na novom zariadení (napr. v prehliadači alebo novej appke).
2. Zvoľte „Obnova prístupov".
3. Zadajte svoje meno a heslo.
4. Sezam stiahne vaše šifrované kľúče zo servera a odomkne ich vaším heslom.

**Ak poznáte heslo, nepotrebujete .sezam-key súbor.** Heslo je všetko, čo potrebujete.

### Stratili ste zariadenie a nemáte prístup k serveru?

Použite záložný súbor `.sezam-key` (stále potrebujete heslo):
1. Importujte súbor `.sezam-key` na novom zariadení.
2. Zadajte heslo.
3. Kľúče sa odomknú lokálne (bez servera).

### Zabudli ste heslo?

- **Osobný vault:** Dáta sú nenávratne stratené. Nikto ich nevie obnoviť. Toto nie je chyba — je to vlastnosť. Keby existoval spôsob, ako obnoviť heslo bez jeho znalosti, znamenalo by to, že niekto iný má k vašim dátam prístup.
- **Firemný vault:** Kontaktujte držiteľov recovery kľúčov (Shamir). Minimálne 3 z 5 dôveryhodných osôb (napr. CEO, CTO, právnik) sa musia stretnúť a spoločne odomknúť vault.

---

## Automatické zamknutie

Sezam sa po 15 minútach nečinnosti automaticky zamkne. To znamená:

- Vaše dáta zmiznú z pamäte zariadenia.
- Na znovupoužitie budete musieť zadať heslo.
- Toto vás chráni, ak odídete od počítača bez zamknutia.

### Pozor na správce schránky

Niektoré programy (clipboard managers) ukladajú históriu schránky. Skopírované heslo sa môže objaviť v ich histórii, aj po automatickom vymazaní zo schránky. Ak používate takéto programy, zvážte ich vypnutie pre citlivé dáta.

---

## Často kladené otázky

### Moje dáta sú naozaj bezpečné?

Áno. Všetky dáta v Sezame sú šifrované — to znamená, že sú premenené na nerozpoznateľný kód, ktorý môže prečítať len ten, kto pozná heslo. Ani server, na ktorom sú dáta uložené, nevidí ich obsah. Používame rovnaké šifrovacie metódy, aké používajú banky a vojenské systémy.

### Čo ak zabudnem heslo?

Ak máte osobný vault (len pre vás): **dáta sú stratené**. Nikto ich nevie obnoviť. Preto si heslo zapamätajte a založte si `.sezam-key` súbor.

Ak máte firemný vault: Existuje núdzový mechanizmus, ale vyžaduje, aby sa stretli minimálne 3 z 5 dôveryhodných osôb (napr. CEO, CTO, právnik), ktoré spoločne odomknú vault.

### Môžem zmeniť heslo?

Áno. V nastaveniach zvoľte „Zmena hesla". Budete potrebovať staré heslo a zadáte nové. Všetky dáta zostanú dostupné — len sa prešifrujú novým heslom.

### Čo ak stratím telefón/notebook?

Ak poznáte heslo, môžete sa prihlásiť na inom zariadení a všetko bude fungovať. Ak nepoznáte heslo a máte `.sezam-key`, môžete obnoviť prístup aj bez servera.

### Vidí administrátor moje osobné heslá?

V rámci firemného vaultu administrátor vidí priečinky, ku ktorým má prístup (čo sú zvyčajne všetky firemné priečinky). Ak admin vytvorí priečinok a pridá vás doň, obe strany vidia obsah. Administrátor nemá prístup k vášmu osobnému vaultu (ak používate samostatný).

### Prečo trvá odomykanie ~1 sekundu?

Je to zámerne bezpečnostné opatrenie. Proces premeny vášho hesla na šifrovací kľúč je zámerne pomalý a náročný — používa veľké množstvo pamäte počítača. Vďaka tomu útočník, ktorý by chcel uhádnuť vaše heslo, by musel stráviť mesiace až roky, aj keby mal veľmi výkonný počítač.

### Môžem používať Sezam offline?

- **Desktop a mobilná appka:** Áno, vaše dáta sú uložené lokálne na zariadení. Môžete ich používať bez internetu. Synchronizácia so serverom prebehne, keď sa pripojíte.
- **Webový prehliadač:** Nie, webové rozhranie vyžaduje pripojenie na server.

### Ako funguje zdieľanie hesiel v tíme?

Administrátor vám pridelí prístup k priečinkom. Vy uvidíte len tie priečinky, ku ktorým máte prístup. Všetko je šifrované — ani server nevidí, čo je v priečinku.

### Čo je to zdieľací odkaz (share link)?

Ak potrebujete jednorazovo poslať heslo kolegovi (aj tomu, kto nemá Sezam), môžete vytvoriť časovo obmedzený odkaz. Odkaz sa po prečítaní alebo po uplynutí času sám znefunkční a dáta sa zo servera vymažú.

---

## Podpora

Ak máte problémy alebo otázky:
1. Obráťte sa na vášho administrátora (osobu, ktorá vám poslala pozvánku).
2. Skontrolujte, či používate aktuálnu verziu prehliadača alebo aplikácie.
3. Ak vidíte chybovú správu, zaznamenajte si ju — pomôže pri riešení problému.

---

*Sezam — Váš bezpečný trezor na heslá.*
