/**
 * Sezam Web UI — vanilla JS + libsodium-wrappers-sumo + argon2-browser
 *
 * Full CRUD: create/edit/delete entries and folders, synced to server.
 * Identity/auth operations (onboarding, key upload) included.
 */

const API_BASE = window.location.origin;
let state = {
    token: null,
    userId: null,
    username: null,
    isAdmin: false,
    keypair: null,    // {signing_sk, signing_pk, encryption_sk, encryption_pk}
    kek: null,        // derived KEK (Uint8Array)
    kdf: null,        // { argon2_salt, argon2_params } the KEK was derived with
    deks: {},         // dek_id → Uint8Array(32) decrypted DEK bytes
    rootDekId: null,  // ULID of root DEK
    tree: null,       // decrypted node tree
    entries: {},      // entry_id → decrypted entry
    allEntries: [],   // flat list for search
    nodes: {},        // node_id → decrypted node
    allNodes: [],     // flat list of all nodes
    selectedEntry: null,    // currently displayed entry
    selectedFolderId: null, // currently selected folder in tree
    rootNodeId: null,       // id of the root "Vault" folder
    keyEpoch: 0,            // highest server-confirmed KEK/password epoch
    keyMaterialHash: null,  // server's key_material_hash at that epoch (SM80)
    syncCheckpoint: null,   // authenticated rollback checkpoint loaded from IndexedDB
    syncCheckpointLoaded: false,
    syncObjects: null,      // raw ciphertext objects keyed by id; null until a full snapshot exists
    teamLog: null,          // {records, team}: the replayed signed team log (TL5), null without one
    teamLogRefusal: null,   // INV-7: the TEAM LOG MISMATCH the last pull refused the team with
    teamLogDamaged: null,   // INV-7: local_damaged, the anchor held here does not open
    confirmedTeamGenesis: null, // external anchor, never inferred from the server checkpoint
    teamTrustReview: null,      // account/session/genesis displayed by the confirmation form
    // docs/SYNC_SINGLE_SOURCE.md point 3: what waits for the server, by id in
    // send order - each the complete encrypted write with its base. A change
    // queued again replaces its write in place; an accepted one leaves.
    outbox: {},
    // The operations waiting in the same queue record, in send order: a
    // revocation's re-key ({kind: 'rekey', revoked_user_id, phase, objects}).
    outboxOps: [],
    // id → [[version, payload_hash], ...] this browser sent of a queued write.
    outboxSent: {},
    // The queue record as this tab last read or wrote it ({objects,
    // conflicts, ops, sent}): what differs from it is this tab's change.
    outboxBaseline: null,
    outboxLoaded: false,
    acceptedBases: {},      // node/entry id → {version, payload_hash} the server took, until a pull brings it
    syncConflicts: {},      // object_id → encrypted local/server conflict shadow
    sodium: null,     // libsodium instance
    userKeys: {},     // user_id → Uint8Array[] current + archived signing keys
    userEncryptionKeys: {},  // user_id → Uint8Array[] X25519 keys paired with userKeys
    retiredKeys: {},         // user_id → Set of retired signing pk hex (goal #443)
    voucherKeys: {},         // user_id → the signing pk hex whose voucher lists count (current)
};

const I18N = globalThis.SezamI18n || Object.freeze({
    defaultLanguage: 'sk',
    languages: Object.freeze({ sk: Object.freeze({}) }),
    applyDocument: () => 'sk',
    listLanguages: () => [],
    resolveLanguage: () => 'sk',
    translate: (_language, key, values = {}) => Object.entries(values).reduce(
        (text, [name, value]) => text.replaceAll(`{${name}}`, String(value)),
        key,
    ),
});
const TRANSLATIONS = I18N.languages;

let currentLanguage = I18N.defaultLanguage;

function t(key, values = {}) {
    return I18N.translate(currentLanguage, key, values);
}

function applyLanguage(language) {
    currentLanguage = I18N.applyDocument(document, language);
    const selector = document.getElementById('language-select');
    if (selector) selector.value = currentLanguage;
    localStorage.setItem('sezam-language', currentLanguage);
    updatePasswordStrength(document.getElementById('onboard-password')?.value || '');
    updateBootstrapPasswordStrength(document.getElementById('bootstrap-password')?.value || '');
    refreshLocalizedVaultUI();
}

function initI18n() {
    const selector = document.getElementById('language-select');
    if (selector) {
        selector.replaceChildren(...I18N.listLanguages().map(({ code, name }) => {
            const option = document.createElement('option');
            option.value = code;
            option.textContent = name;
            return option;
        }));
        selector.addEventListener('change', (event) => applyLanguage(event.target.value));
    }
    applyLanguage(localStorage.getItem('sezam-language'));
}

function refreshLocalizedVaultUI() {
    if (state.tree) {
        state.tree = buildTree(state.allNodes, state.allEntries);
        renderTree(state.tree);
    }
    if (state.selectedEntry) renderEntry(state.selectedEntry);
    const searchInput = document.getElementById('search-input');
    if (searchInput?.value) handleSearch(searchInput.value);
    renderWebSyncConflicts();
    if (!document.getElementById('audit-panel')?.classList.contains('hidden')) {
        loadAuditEntries();
    }
    if (state.isAdmin && document.getElementById('admin-user-list')) {
        apiFetch('/api/users').then(renderAdminUserList).catch(() => {});
    }
}

// ── JWT refresh state ──
let _jwtRefreshTimer = null;
// The refresh in flight: callers that meet a 401 meanwhile wait for its outcome.
let _refreshInFlight = null;

// ── Encryption constants (spec section 2.5, 2.6) ──

const ENVELOPE_ALG = 1; // xchacha20poly1305_ietf
const SCHEMA_VERSION = 1;
const BLOB_KIND = {
    NODE_META: 1,
    ENTRY_META: 2,
    ENTRY_DATA: 3,
    HISTORY_SNAPSHOT: 4,
    AUDIT_DETAILS: 5,
    DEK_WRAP: 6,
    KEYPAIR_WRAP: 7,
};

// ── Slovak word list for fingerprint display (spec 2.2, BIP39-style) ──
// 1392-word list matching the desktop client. Used with 11-bit indices (4 x 11 bits
// from first 6 bytes of fingerprint hash). Index modulo wordlist length for wrapping.

const SK_WORDLIST = [
    'ábeceda','aby','achát','adresa','aerobik','agát','agenda','ahoj',
    'akácia','akcia','aktívny','album','alej','alfabet','alkohol','amatér',
    'ambícia','americký','analýza','ananás','anémia','anjel','anketa','antika',
    'anulár','aperitív','aplaus','apríl','arašid','architekt','aréna','argument',
    'aristokrat','armáda','aróma','artéria','asistent','askéta','aspekt','asteroid',
    'atelier','atika','atletika','atmosféra','atóm','audit','august','auto',
    'autobus','automat','autor','avantgarda','avokádo','azalka','azúr','ázijský',
    'bábätko','babička','bábka','bacil','bádanie','bageta','bahno','bajka',
    'bakuľa','balada','baldachýn','balet','balík','balón','balzam','bambus',
    'banán','banda','baník','banka','bar','barabizňa','baran','barista',
    'barón','bárka','baroko','barok','barva','básnik','baterka','batoh',
    'bažant','bazén','bažina','bedňa','behúň','beloba','benzín','beštia',
    'betón','bezpečný','bieda','bielizeň','bikiny','bilión','biológia','biskup',
    'bitúnok','bizón','blaho','blanketa','bláznovstvo','blcha','bledý','blesk',
    'blíženec','blízko','blok','bludár','bobor','bobula','bodka','bohatý',
    'bojovník','bolestivý','bonbón','bordel','borovica','bosý','botanik','bôčik',
    'brána','bravčovina','brecht','bremeno','brest','brezina','brigáda','britva',
    'brloh','brniť','brokát','bronz','broskyňa','brucho','brúska','brutálny',
    'búdka','budova','bujný','búrka','burza','busta','butik','bystrý',
    'bývanie','byť','bzučiak','bžúchať','cáp','ceduľa','cédrika','celkový',
    'cement','cena','centimeter','centrum','cenzúra','ceremónia','certifikát','cesta',
    'cibuľa','cieľ','cifra','cigareta','cimbál','cintorín','cipka','cirkulár',
    'cirkus','cisterna','citadela','citrón','cnostný','cola','colt','copyright',
    'cukor','cukráreň','cupitať','cvičenie','cylinder','cyprián','cytoplazma','čaj',
    'čajka','čalúnenie','čapík','čarodejník','čas','časopis','časť','čata',
    'čelenka','čeľaď','čelo','čerešňa','čerpadlo','čerstvý','červený','česká',
    'česnek','čestný','četník','čiapka','čiara','čierny','čipka','číslo',
    'čistý','čítanie','čitateľ','čln','člnok','čmeliak','čokoláda','črieda',
    'čučoriedka','čudný','čudesný','čundra','čuprina','čurák','dáma','dámsky',
    'darček','darca','dátum','dáva','dávka','dcéra','debata','december',
    'deficit','definícia','dekáda','dekorácia','delegát','delfín','delostrelec','demokracia',
    'deň','deravý','derniéra','detektív','detective','deti','deviatka','dezert',
    'diaľka','diamant','diár','diela','dieťa','digitálny','diplom','dirigent',
    'disciplína','diskusia','divák','divadlo','diviak','dlažba','dlhý','dno',
    'dobrota','dobyť','docent','dohoda','dojem','doktor','dokument','dolár',
    'dôležitý','dolina','domáci','domček','dôraz','dosah','doskočiť','dospelý',
    'dostatok','dotyk','dôvera','dôvod','dráha','drak','dráma','drastický',
    'dravec','drevo','drina','drobec','drobný','dromedár','dron','drsný',
    'druh','družba','duálny','dub','dúha','dukát','duša','dužina',
    'dvanásť','dvere','dvorec','dvojčata','dvojica','dynamit','dynamo','džbán',
    'eben','edícia','efekt','egypt','echo','ekonomika','ekológia','elegancia',
    'elektrina','element','eliminovať','elita','email','emócia','energia','epidémia',
    'epocha','epos','erupcia','esencia','eskorta','espresso','estetika','etapa',
    'etiketa','evanjelium','evolúcia','excelentný','exemplár','exil','existencia','exodus',
    'expedícia','expert','explózia','export','expozícia','extrakt','extrém','fábrika',
    'fajka','fakľa','fakulta','falošný','fantázia','fara','farba','farmár',
    'fazuľa','február','federácia','fenomén','festival','figúra','fijalka','filozofia',
    'filtrovat','finále','firma','fixný','flakon','flaša','flaut','florista',
    'flotila','fólia','folklór','fond','fontána','formát','formula','fortel',
    'fosília','fotograf','frakcia','francúzsky','frekvencia','fréza','fronta','funkcia',
    'futbal','fúzia','gala','galéria','galoš','garancia','garáž','gáza',
    'génium','geografia','geometria','gerilla','gesto','gitara','glazúra','globálny',
    'glóbus','gnóm','gobelin','golf','gondola','gorila','gotika','grác',
    'grafika','gramofón','granát','granit','gravitácia','gril','groteska','guma',
    'guľka','guľatý','gurman','gymnaziálny','gymnázium','habánsky','había','hadica',
    'hádka','hala','halier','haluška','hanba','harmonika','harpa','havária',
    'havran','háčik','hárok','hecovať','herec','heslá','hever','hierarchia',
    'hlavný','hľadanie','hlboký','hlina','hlísť','hluk','hmatateľný','hmla',
    'hmota','hnedý','hnevať','hniezdny','hniloba','hodinár','hodiny','hodnota',
    'holica','holub','hora','horčica','horizont','horúci','hospoda','hostina',
    'hotel','hovoriť','hôrka','hrad','hrana','hranol','hrdina','hrebienok',
    'hrianka','hriatô','hriech','hrob','hromadný','hrôza','hrozno','hrubý',
    'hruška','huba','hudba','huncút','húsatko','húsenica','hustý','hutor',
    'hviezda','hyacint','hybrid','hydrant','hymna','hypotéka','ibištek','idea',
    'ideál','ihla','ihneď','ikona','ilegálny','ilustrácia','imelo','impérium',
    'import','indigó','individuum','infantný','infarkt','informácia','inšpirácia','inteligencia',
    'interiér','internet','interval','intriga','intuícia','inventár','investícia','inžinier',
    'irónia','izolácia','izotop','izúver','jabĺčko','jablko','jachta','jahoda',
    'jánsky','jarmo','jarný','jaskyňa','jasnota','jaspis','jašter','javor',
    'jazda','jazero','jázik','jedáleň','jedľa','jednoduchý','jednorožec','jeleň',
    'jelša','jemný','jeseter','jeseň','jeskyňa','ježko','jiskra','jogging',
    'jogurt','junák','jupiter','jurisdikcia','justícia','juta','kabát','kabela',
    'kabína','kadernička','kafeín','kahanec','kajak','kakao','kaktus','kalamita',
    'kaleidoskop','kalendár','kameň','kamera','kamión','kanál','kandidát','kanón',
    'kaňon','kapacita','kapitán','kapor','kapucňa','karamel','karavána','karta',
    'kartón','kaskáda','kastelán','kašeľ','katalóg','katastrofa','katedrála','kaviareň',
    'kazateľ','kazeta','každý','keramika','kilo','kľúč','kľúčový','klobúk',
    'klokan','klonkať','klonový','klosár','klub','kmeť','kmeň','kníhkupec',
    'kniha','kňaz','koberec','kobyla','kocka','kočiar','kocúr','koeficient',
    'kohút','kokos','kolega','koleso','kolíska','kolobežka','kolónia','kolosálny',
    'kombinovať','komédia','komín','komora','kompas','komplex','komunita','konár',
    'koncert','kondícia','konferenčný','konfitúra','konflikt','kontrola','konverzácia','kópia',
    'kopija','koráb','korál','korčuľa','korenina','korisť','koruna','koryta',
    'kosatec','kostol','kôš','košeľa','kotva','kovadlina','kozmetika','koža',
    'krajina','krajčír','králik','kráľ','kráska','kravata','kredit','kresba',
    'kreslo','krieda','krivda','krivolaký','kríž','krokodíl','krokus','kronika',
    'krošňa','krúžok','krv','krývať','kryštál','krýzl','kubík','kuchyňa',
    'kukurica','kulička','kultúra','kúpeľ','kupóla','kuriér','kúsok','kufrík',
    'laby','labyrinth','lacný','ladička','lagúna','lahodný','lajdák','lakmus',
    'lakomec','lampa','lanko','lasica','lavica','lávka','lavína','lazar',
    'lebed','ľad','ľadovec','legenda','lehota','lekáreň','lekcia','lekno',
    'leopard','lepidlo','les','letisko','letmo','lev','ľavý','lezec',
    'líčenie','líder','liečba','lienka','lietadlo','ligot','likér','limetka',
    'limuzína','linka','líška','listina','liter','literatura','ľudia','ľúbosť',
    'lucerna','lúka','luna','lúpež','luxus','lýceum','lyrica','lyžiar',
    'mágia','magnet','mahagón','maják','majestát','major','makovica','maliar',
    'malina','málo','mamut','mango','manica','manžel','mapa','maratón',
    'marhula','marioneta','marmeláda','márnosť','martini','maska','maslo','matador',
    'materiál','matka','matrica','mazaný','mdloba','mechanik','medaila','medveď',
    'melodia','melón','meteor','metóda','metro','metrový','mičuda','miesto',
    'milión','minerál','miniatúra','minister','minuta','miska','mišmaš','mladosť',
    'mlčať','mliečny','mliekar','mlyn','modrá','mohol','mokrý','molekula',
    'moment','monarchia','monitor','monopol','monsún','montáž','monument','morálka',
    'more','moriak','mortadela','mosaika','moskyt','most','motív','motor',
    'mozog','mravenec','mrholenie','mrkva','mrzutý','múdrosť','mumifikácia','múr',
    'múzeum','muzikál','mýdlo','myseľ','myslieť','mýtus','náboj','nábytoik',
    'nádej','nádherný','nádvorie','náhoda','náhrada','naivný','nájazd','nálada',
    'nálep','námestie','námietka','nápis','nápoj','náramok','narcis','národ',
    'nástroj','nátierka','návod','návrat','nebezpečný','nečakaný','nedávny','nedeľa',
    'nehoda','neitrón','nekľud','nelegálny','nemocnica','nenosový','nepokojný','neptún',
    'nervový','nesúhlas','netopier','neuveriteľný','nevesta','nezávislosť','nežný','niečo',
    'nikdy','nikel','nimbus','nitka','noc','nohavice','nominálny','nora',
    'norma','nostalgia','nota','notiť','november','novela','novina','nový',
    'oáza','obálka','obchod','obdivovať','obelisk','obet','obidva','objav',
    'oblak','obloha','obnoviteľný','obojstranný','obrázok','obrovský','obsah','obstáť',
    'obtiažny','obuv','obývačka','oceán','ocenenie','ochranca','odborník','oddych',
    'odev','odchod','odišiel','odkaz','odmenenie','odolnosť','odpočinok','odpoveď',
    'ohnisko','ohrada','ohrievač','okamih','okno','okolo','okraj','okruh',
    'október','olivový','olovo','olympiáda','omáčka','omeleta','opera','operácia',
    'opica','opora','optika','oranžový','orbita','orchidea','orden','organizácia',
    'originál','ornament','ortuť','osamotený','osika','osláviť','osoba','ostrov',
    'ostrý','ošetrenie','otázka','otec','otvor','oválny','ovčiar','overenie',
    'ovládať','ozdoba','ozón','oznam','paberk','palác','paletka','palma',
    'pamätník','panáčik','pancier','panička','panoráma','pantomíma','papier','papagáj',
    'paradajka','parafrázovať','paralela','parapet','park','parlament','partner','party',
    'pasáž','pastier','pastva','patent','patriarcha','pavilón','pavúk','pazúrik',
    'pečať','pechovať','pekáreň','penalta','perla','pero','perspektíva','pesnička',
    'pestrosť','petrolej','pevnina','pečeň','piesok','piešťany','piknik','pilier',
    'pilot','piránia','pirát','pivnica','plachta','plagát','plameň','planéta',
    'platidlo','platina','plavba','plávanie','plecniak','pleť','plnosť','plodina',
    'plotovať','plyn','pľúca','pobrežie','počasie','počítač','podbradník','podlaha',
    'podmienka','podnik','podpis','podsvetie','podvečer','podzemie','poézia','pohár',
    'pohľad','pohodlie','poistka','poklad','pokojný','pokora','polárny','polícia',
    'politika','polnoc','polostrov','pomáhať','pomaranč','pomník','poník','ponúka',
    'poobede','popol','porcelán','porevoluční','porotca','portfólio','portrét','poruba',
    'posledný','postava','postieľka','potápač','potešenie','potrubí','poukážka','povinný',
    'povoz','povrch','pozadie','pozlátka','pozornosť','požiar','práca','pradávny',
    'pramienok','pravidlo','pravda','predmet','predslov','prehliadka','prekážka','prelet',
    'premiéra','prepych','presnosť','preto','prevládať','prezident','príbeh','príchuť',
    'priestor','prihrádka','primabalka','princezná','prizvuk','problém','proces','produkcia',
    'profesor','profil','program','projekt','prorok','prsteň','prvok','psík',
    'púčik','pudding','puma','purpur','púšťa','pyramída','rádio','radosť',
    'radnica','raffia','rámček','rapkáč','rapsódia','rast','ratolesť','razba',
    'recepcia','recept','redaktor','referát','reflexia','reforma','región','register',
    'rehoľný','rekonštrukcia','rekord','remeslo','renesancia','reportáž','republika','reťaz',
    'revízia','rezerva','ribezľa','rifle','rigorózny','rímsky','risoto','rituál',
    'riverbend','roba','robot','rodina','rokoko','roleta','román','rovnováha',
    'rozbor','rozdiel','rozhodnutie','rozhovor','rozhľadňa','rozkvitať','rozsah','rúčka',
    'rúfus','rúško','rybár','rýchlosť','rytier','rytmus','rypák','rýžový',
    'sabotáž','sadovník','safari','šáfran','sakura','salám','saláma','salón',
    'samota','sandál','šarkan','šarlát','satén','satelit','šatka','saudský',
    'saxofón','sčítanie','sedliak','šedivý','sekera','sekvoja','selekcia','semafor',
    'semester','semienkok','senátor','seno','september','serenáda','serif','servírovať',
    'šestnásť','šikovný','silometer','silueta','sinusoida','síra','situácia','škála',
    'skala','škapuliare','skelét','skeptik','skica','škriatok','skrinka','skrutka',
    'skupina','slávnosť','sled','šľachta','slimák','sloboda','slnečnica','slnko',
    'slogan','slon','slúchadlo','služba','smaragd','smetana','šmýkačka','smiech',
    'šnúrka','sneh','sniežik','socha','sofistikovaný','sokel','sokol','soľ',
    'šošovka','špageta','špeciálny','spektrum','šperkovnica','spev','špiónsky','splnomocnenie',
    'spolok','spomienka','sporiteľňa','spotrebiteľ','správa','sprievod','šprint','stabilita',
    'stanica','šťastie','stáž','stedlosť','štedrý','stena','štiepenie','stĺp',
    'stoličia','stopka','strana','stratégia','streda','strelec','strieborný','strom',
    'strúhanka','štrukturálny','struna','štvornásobný','štvrtok','stúdium','stupienok','štýl',
    'šťuka','sultanát','suma','supermarket','surovina','sused','šuster','sústava',
    'svadba','svätý','svedomie','svetlo','svietnik','sviňa','švorc','symbol',
    'symfónia','systém','tabletka','tábor','tajomstvo','talent','tanier','tapeta',
    'tatranský','tečka','tehla','technológia','tekutina','telefón','televízia','telo',
    'temnota','tendencia','teplo','tera','teraz','terén','termín','tesár',
    'ticho','tieň','tiger','tísíc','tlačiareň','topánka','tradícia','tramvaj',
    'triangel','tribúna','tričko','triedny','triumf','trochu','trofej','trón',
    'trubka','truhla','tržnica','tulipán','tunel','turbína','turista','tvárosť',
    'tvrdosť','tvorba','tyrkys','účet','učiteľ','údolie','uhoľ','uhorka',
    'uhradiť','ulica','ultimátum','umenie','umývadlo','uniforma','únos','úplatok',
    'upozornenie','úprava','uragán','urbánny','usmiať','ústav','útok','utópia',
];

// ── Fingerprint display (spec 2.2) ──

/**
 * Compute a key fingerprint from signing and encryption public keys.
 * Returns { hex, identicon, words }:
 *  - hex: 64 hex chars (SHA-256 of signing_pk || encryption_pk)
 *  - identicon: inline SVG string (5x5 grid colored from hash bytes)
 *  - words: 4 human-readable Slovak words derived from hash bytes (11-bit indices)
 *
 * @param {Uint8Array} signingPk   - 32-byte Ed25519 public key
 * @param {Uint8Array} encryptionPk - 32-byte X25519 public key
 * @returns {Promise<{hex: string, identicon: string, words: string}>}
 */
async function displayFingerprint(signingPk, encryptionPk) {
    // Concatenate signing_pk || encryption_pk
    const combined = new Uint8Array(signingPk.length + encryptionPk.length);
    combined.set(signingPk, 0);
    combined.set(encryptionPk, signingPk.length);

    // SHA-256 -> 32 bytes -> 64 hex chars
    const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
    const hashBytes = new Uint8Array(hashBuffer);
    const hex = bytesToHex(hashBytes);

    // Extract 4 x 11-bit indices from first 6 bytes (48 bits) — matches desktop algorithm
    // JS bitwise ops are 32-bit, so use Number arithmetic for 48-bit value
    const bits48 = hashBytes[0] * 0x10000000000 + hashBytes[1] * 0x100000000
                 + hashBytes[2] * 0x1000000 + hashBytes[3] * 0x10000
                 + hashBytes[4] * 0x100 + hashBytes[5];
    const wordIndices = [
        (Math.floor(bits48 / Math.pow(2, 37))) & 0x7FF,  // bits 47..37
        (Math.floor(bits48 / Math.pow(2, 26))) & 0x7FF,  // bits 36..26
        (Math.floor(bits48 / Math.pow(2, 15))) & 0x7FF,  // bits 25..15
        (Math.floor(bits48 / Math.pow(2, 4)))  & 0x7FF,  // bits 14..4
    ];
    const words = wordIndices.map(i => SK_WORDLIST[i % SK_WORDLIST.length]).join(' ');

    // Generate 5x5 identicon from hash bytes
    // Use bytes 4..16 for color/pattern decisions
    // The grid is symmetric along the vertical axis for visual appeal
    const cellSize = 6;
    const gridSize = 5;
    const svgSize = cellSize * gridSize;

    // Foreground color from bytes 4,5,6 (hue derived, decent saturation)
    const hue = (hashBytes[4] * 360) / 256;
    const sat = 50 + (hashBytes[5] % 30);       // 50-80%
    const lum = 45 + (hashBytes[6] % 20);       // 45-65%
    const fg = `hsl(${Math.round(hue)},${sat}%,${lum}%)`;
    const bg = '#2a2c24';

    let cells = '';
    for (let row = 0; row < gridSize; row++) {
        for (let col = 0; col < gridSize; col++) {
            // Mirror: use the column closest to center for symmetry
            const mirrorCol = col < 3 ? col : (4 - col);
            const byteIdx = 7 + row * 3 + mirrorCol; // bytes 7..21
            const filled = (hashBytes[byteIdx % 32] >> (row % 8)) & 1;
            const color = filled ? fg : bg;
            cells += `<rect x="${col * cellSize}" y="${row * cellSize}" width="${cellSize}" height="${cellSize}" fill="${color}"/>`;
        }
    }

    const identicon = `<svg xmlns="http://www.w3.org/2000/svg" width="${svgSize}" height="${svgSize}" viewBox="0 0 ${svgSize} ${svgSize}" class="identicon">${cells}</svg>`;

    return { hex, identicon, words };
}

// ── Envelope encryption (spec section 2.6) ──

/**
 * Build AAD (59 bytes): alg(1) + schema(1) + kind(1) + dekId(26) + objectId(26) + version_u32be(4)
 */
function validateCanonicalEnvelopeHeader(envelopeBytes, expectedBlobKind = null) {
    if (!(envelopeBytes instanceof Uint8Array) || envelopeBytes.length < 53 ||
            envelopeBytes[0] !== ENVELOPE_ALG || envelopeBytes[1] !== SCHEMA_VERSION ||
            (expectedBlobKind !== null && envelopeBytes[2] !== expectedBlobKind)) {
        throw new Error('Invalid canonical envelope header');
    }
}

function buildAAD(blobKind, dekId, objectId, version) {
    // The envelope's AAD (spec 2.6) from the core (docs/CORE_UNIFICATION.md U6).
    return hexToBytes(globalThis.SezamSyncCore.call('aad', {
        blob_kind: blobKind, dek_id: dekId, object_id: objectId, version,
    }));
}

// R16-Z SM3 (INV-3): a 26-byte id field holds exactly one id. A longer id
// (or one holding a NUL, or non-ASCII) throws instead of being cut or padded
// into another id's bytes: a server appending a character to a signed
// parent_ref kept the signature valid. Same as sezam.models.ulid_to_bytes.
function idBytes26(id) {
    const text = String(id ?? '');
    if (text.length > 26 || !/^[\x01-\x7f]*$/.test(text)) {
        throw new Error('An id is at most 26 ASCII characters without NUL');
    }
    const out = new Uint8Array(26);
    out.set(new TextEncoder().encode(text));
    return out;
}

// Portable account bundle: versioned keys + independently confirmed genesis,
// inside the existing account-ID-bound KEYPAIR_WRAP. Legacy keys carry no trust.
// Capability run 269 (aead.py PRE_ANCHOR_*): the wrap binds no epoch, so a
// pre-anchor bundle the server kept opens again under a password that opened
// it then. The anchored bundle (SZACCT02) records each such password state as
// salt(16) || time, memory, lanes (u32be) || SHA-256(label || KEK); no client
// may move the account back to one of them.
const PRE_ANCHOR_ENTRY_LEN = 60;
const PRE_ANCHOR_MAX = 8;
const ACCOUNT_BUNDLE_LENGTHS = [64, 96, 104,
    ...Array.from({ length: PRE_ANCHOR_MAX }, (_, i) => 105 + (i + 1) * PRE_ANCHOR_ENTRY_LEN)];

function preAnchorCheck(kek, _sodium) {
    const label = new TextEncoder().encode('sezam-pre-anchor-kek-v1');
    const input = new Uint8Array(label.length + kek.length);
    input.set(label);
    input.set(kek, label.length);
    try { return _sodium.crypto_hash_sha256(input); } finally { _sodium.memzero(input); }
}

// The states' format is the core's (docs/CORE_UNIFICATION.md U6e); the check
// of a KEK is this page's libsodium.
function parsePreAnchor(blob) {
    return globalThis.SezamSyncCore.call('pre_anchor_parse', { blob: (blob?.length ? bytesToHex(blob) : null) }).map(e => ({
        raw: hexToBytes(e.raw), salt: hexToBytes(e.salt), check: hexToBytes(e.check),
        time_cost: e.time_cost, memory_cost: e.memory_cost, parallelism: e.parallelism,
    }));
}

// `kept` plus the states only `other` records, newest last (a rebind never forgets one).
function mergePreAnchor(kept, other) {
    const merged = globalThis.SezamSyncCore.call('pre_anchor_merge', {
        kept: (kept?.length ? bytesToHex(kept) : null), other: (other?.length ? bytesToHex(other) : null),
    });
    return merged ? hexToBytes(merged) : null;
}

function addPreAnchor(blob, salt, params, kek, _sodium) {
    if (!(salt instanceof Uint8Array)) throw new Error('Invalid pre-anchor salt');
    return hexToBytes(globalThis.SezamSyncCore.call('pre_anchor_add', {
        blob: (blob?.length ? bytesToHex(blob) : null), salt: bytesToHex(salt), time_cost: params.time_cost,
        memory_cost: params.memory_cost, parallelism: params.parallelism,
        check: bytesToHex(preAnchorCheck(kek, _sodium)),
    }));
}

// Does `password` (any of its KDF forms) derive a recorded pre-anchor KEK?
// A state below the browser's Argon2 floor cannot be derived here: refused.
async function passwordReopensPreAnchor(password, blob, _sodium) {
    for (const e of parsePreAnchor(blob)) {
        const params = { time_cost: e.time_cost, memory_cost: e.memory_cost, parallelism: e.parallelism, hash_len: 64 };
        if (globalThis.SezamSyncCore.call('account_kdf_refusal', params) !== null) return true;
        for (const form of passwordForms(password)) {
            const derived = await deriveKEK(form, e.salt, params, { exact: true });
            try {
                if (_sodium.memcmp(preAnchorCheck(derived.subarray(0, 32), _sodium), e.check)) return true;
            } finally { _sodium.memzero(derived); }
        }
    }
    return false;
}

// Capability run 273: the password states this browser left while the
// account had no anchor; a later publication carries them all.
async function loadPreAnchorHistory(userId) {
    const stored = await idbKeysRequest('readonly', store => store.get(`pre_anchor_history:${userId}`));
    if (!stored) return null;
    if (typeof stored.states !== 'string' || !/^[0-9a-f]+$/.test(stored.states)) {
        throw new Error('Invalid pre-anchor password history');
    }
    const states = hexToBytes(stored.states);
    parsePreAnchor(states);
    return states;
}

async function savePreAnchorHistory(userId, states) {
    await idbKeysRequest('readwrite', store => store.put({
        id: `pre_anchor_history:${userId}`, states: bytesToHex(states),
    }));
}

// INV-3 (review e443cbc): the password states this browser saw open this
// account's keys (salt + params + the KEK's check, the pre-anchor entry
// format). Org recovery records the forgotten password from here: the one
// bound to the recovered KEK, never the server's unsigned salt and params.
async function rememberWebKdfState(_sodium) {
    const userId = state.userId;
    const kdf = state.kdf;
    if (!userId || !kdf?.argon2_salt || !kdf.argon2_params || !state.kek) return;
    try {
        const stored = await idbKeysRequest('readonly', store => store.get(`kdf_states:${userId}`));
        const known = stored && typeof stored.states === 'string' ? hexToBytes(stored.states) : null;
        const states = addPreAnchor(known, hexToBytes(kdf.argon2_salt), kdf.argon2_params,
            state.kek.subarray(0, 32), _sodium);
        await idbKeysRequest('readwrite', store => store.put({ id: `kdf_states:${userId}`, states: bytesToHex(states) }));
    } catch (err) {
        // INV-7: never refuses the sign-in; a recovery then publishes no anchor.
        console.warn('Password state not remembered', err.message || err);
    }
}

// The remembered state whose KEK is `kek` (one pre-anchor entry), or null.
async function webKdfStateOf(userId, kek, _sodium) {
    const stored = await idbKeysRequest('readonly', store => store.get(`kdf_states:${userId}`));
    if (!stored || typeof stored.states !== 'string') return null;
    let entries;
    try { entries = parsePreAnchor(hexToBytes(stored.states)); } catch { return null; }
    const check = preAnchorCheck(kek, _sodium);
    const entry = entries.find(e => _sodium.memcmp(e.check, check));
    if (!entry) return null;
    const one = new Uint8Array(1 + PRE_ANCHOR_ENTRY_LEN);
    one[0] = 1;
    one.set(entry.raw, 1);
    return one;
}

function encodeAccountKeypair(keypairData, confirmedGenesis, _sodium, preAnchor = null) {
    if (!(keypairData instanceof Uint8Array) || ![64, 96].includes(keypairData.length)) {
        throw new Error('Invalid account keypair keys or confirmed genesis');
    }
    const parts = globalThis.SezamSyncCore.call('account_bundle_encode', {
        confirmed_genesis: confirmedGenesis, pre_anchor: (preAnchor?.length ? bytesToHex(preAnchor) : null),
    });
    const version = hexToBytes(parts.version), tail = hexToBytes(parts.tail);
    const decoded = decodeAccountKeypair(keypairData, _sodium);
    try {
        const payload = new Uint8Array(version.length + 64 + tail.length);
        payload.set(version);
        payload.set(decoded.keypairData, version.length);
        payload.set(tail, version.length + 64);
        return payload;
    } finally { _sodium.memzero(decoded.keypairData); }
}

// The bundle's kind is the core's; the keys never leave this page (a bundle
// shorter than 104 bytes is all key, so only its length goes).
function decodeAccountKeypair(payload, _sodium) {
    if (!(payload instanceof Uint8Array)) throw new Error('Invalid account keypair payload');
    const whole = payload.length >= 104;
    const kind = globalThis.SezamSyncCore.call('account_bundle_decode', {
        length: payload.length,
        version: whole ? bytesToHex(payload.subarray(0, 8)) : null,
        tail: whole ? bytesToHex(payload.subarray(72)) : null,
    });
    if (kind.kind === 'anchored' || kind.kind === 'v1') {
        return { keypairData: payload.slice(8, 72), confirmedGenesis: kind.confirmed_genesis,
                 preAnchor: kind.pre_anchor ? hexToBytes(kind.pre_anchor) : null };
    }
    if (kind.kind === 'legacy64') return { keypairData: payload.slice(), confirmedGenesis: null, preAnchor: null };
    if (payload.length === 96) {
        const signing = _sodium.crypto_sign_seed_keypair(payload.subarray(0, 32));
        try {
            if (!_sodium.memcmp(signing.publicKey, payload.subarray(32, 64))) {
                throw new Error('Invalid account keypair public key');
            }
            const keys = new Uint8Array(64);
            keys.set(payload.subarray(0, 32));
            keys.set(payload.subarray(64), 32);
            return { keypairData: keys, confirmedGenesis: null, preAnchor: null };
        } finally { _sodium.memzero(signing.privateKey); }
    }
    throw new Error('Invalid account keypair payload length');
}

function encryptAccountKeypair(keypairData, confirmedGenesis, kek, kekDekId, userId, _sodium, preAnchor = null) {
    const payload = encodeAccountKeypair(keypairData, confirmedGenesis, _sodium, preAnchor);
    try { return encryptKeypairWrap(payload, kek, kekDekId, userId, _sodium); }
    finally { _sodium.memzero(payload); }
}

function decryptAccountKeypair(envelope, kek, userId, _sodium) {
    const payload = decryptKeypairWrap(envelope, kek, userId, _sodium, ACCOUNT_BUNDLE_LENGTHS);
    try { return decodeAccountKeypair(payload, _sodium); }
    finally { _sodium.memzero(payload); }
}

function decryptLoginKeypair(envelope, kek, userId, _sodium) {
    const decoded = decryptAccountKeypair(envelope, kek, userId, _sodium);
    return {
        keypairBytes: expandDesktopKeypair(decoded.keypairData, _sodium),
        confirmedGenesis: decoded.confirmedGenesis,
        preAnchor: decoded.preAnchor,
    };
}

function encryptKeypairWrap(keypairData, kek, kekDekId, userId, _sodium) {
    if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(kekDekId) ||
            !/^[0-9A-HJKMNP-TV-Z]{26}$/.test(userId)) {
        throw new Error('KEYPAIR_WRAP requires canonical 26-character IDs');
    }
    const padded = padPlaintext(keypairData);
    const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const aad = buildAAD(BLOB_KIND.KEYPAIR_WRAP, kekDekId, userId, 1);
    const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        padded, aad, null, nonce, kek
    );
    const envelope = new Uint8Array(53 + ciphertext.length);
    envelope[0] = ENVELOPE_ALG;
    envelope[1] = SCHEMA_VERSION;
    envelope[2] = BLOB_KIND.KEYPAIR_WRAP;
    envelope.set(new TextEncoder().encode(kekDekId), 3);
    envelope.set(nonce, 29);
    envelope.set(ciphertext, 53);
    return envelope;
}

function decryptKeypairWrap(envelope, kek, userId, _sodium, allowedPayloadLengths = [96]) {
    if (!(envelope instanceof Uint8Array) || envelope.length <= 53 ||
            envelope[0] !== ENVELOPE_ALG || envelope[1] !== SCHEMA_VERSION ||
            envelope[2] !== BLOB_KIND.KEYPAIR_WRAP ||
            !/^[0-9A-HJKMNP-TV-Z]{26}$/.test(userId)) {
        throw new Error('Invalid canonical KEYPAIR_WRAP envelope');
    }
    const kekDekId = new TextDecoder().decode(envelope.slice(3, 29));
    if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(kekDekId)) {
        throw new Error('Invalid KEYPAIR_WRAP key ID');
    }
    const aad = buildAAD(BLOB_KIND.KEYPAIR_WRAP, kekDekId, userId, 1);
    const padded = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, envelope.slice(53), aad, envelope.slice(29, 53), kek
    );
    let keypairData = unpadPlaintext(new Uint8Array(padded));
    if (keypairData.length === 64 && !allowedPayloadLengths.includes(64)) {
        keypairData = expandDesktopKeypair(keypairData, _sodium);
    }
    if (!allowedPayloadLengths.includes(keypairData.length)) {
        _sodium.memzero(keypairData);
        throw new Error('Invalid keypair payload length');
    }
    return keypairData;
}

// The desktop wraps signing_seed(32) || encryption_sk(32) and uploads that
// envelope unchanged; web and mobile use signing_sk(64 = seed || pk) ||
// encryption_sk(32). Expands the desktop form and wipes the input.
function expandDesktopKeypair(keypairData, _sodium) {
    const signing = _sodium.crypto_sign_seed_keypair(keypairData.slice(0, 32));
    const expanded = new Uint8Array(96);
    expanded.set(signing.privateKey, 0);
    expanded.set(keypairData.subarray(32, 64), 64);
    _sodium.memzero(signing.privateKey);
    _sodium.memzero(keypairData);
    return expanded;
}

const SEZAM_KEY_MAGIC = new TextEncoder().encode('SEZAMK02');
const SEZAM_KEY_HEADER_SIZE = 24;

/** /api/auth/recover failure → what the user can do about it (lockout review
 *  #7): a throttled address or a server outage is not a wrong password. */
function recoverFailureMessage(err) {
    if (err && err.status === 429) return t('error.recover_rate_limited');
    if (err && err.status === 423) return t('error.recover_locked');
    if (err && (err.status === 401 || err.status === 404)) return t('error.wrong_password');
    return t('error.recover_unavailable');
}

function validateSezamKeyKdf(salt, params) {
    const refusal = globalThis.SezamSyncCore.call('sezam_key_kdf_refusal', {
        salt_len: salt instanceof Uint8Array ? salt.length : null,
        time_cost: params.time_cost, memory_cost: params.memory_cost,
        parallelism: params.parallelism, hash_len: params.hash_len ?? null,
    });
    if (refusal !== null) throw new Error(refusal);
}

function buildSezamKeyBackup(
    keypairData, signingPk, encryptionPk, kek, argon2Salt, argon2Params, _sodium
) {
    if (!(keypairData instanceof Uint8Array) || ![64, 96].includes(keypairData.length) ||
            signingPk.length !== 32 || encryptionPk.length !== 32 || kek.length !== 32) {
        throw new Error('Invalid .sezam-key key material');
    }
    validateSezamKeyKdf(argon2Salt, argon2Params);
    const kekDekId = generateULID();
    const userObjectId = generateULID();
    const encryptedEnvelope = encryptKeypairWrap(
        keypairData, kek, kekDekId, userObjectId, _sodium
    );
    const output = new Uint8Array(
        SEZAM_KEY_HEADER_SIZE + argon2Salt.length + 32 + 32 + 26 + 26 +
        encryptedEnvelope.length
    );
    output.set(SEZAM_KEY_MAGIC, 0);
    const view = new DataView(output.buffer);
    view.setUint16(8, argon2Salt.length, false);
    view.setUint32(10, argon2Params.time_cost, false);
    view.setUint32(14, argon2Params.memory_cost, false);
    view.setUint32(18, argon2Params.parallelism, false);
    view.setUint16(22, argon2Params.hash_len, false);
    let offset = SEZAM_KEY_HEADER_SIZE;
    for (const part of [
        argon2Salt,
        signingPk,
        encryptionPk,
        new TextEncoder().encode(kekDekId),
        new TextEncoder().encode(userObjectId),
        encryptedEnvelope,
    ]) {
        output.set(part, offset);
        offset += part.length;
    }
    return output;
}

async function parseSezamKeyBackup(fileBytes, password, _sodium, deriveFn = deriveKEK) {
    const data = fileBytes instanceof Uint8Array ? fileBytes : new Uint8Array(fileBytes);
    if (data.length < SEZAM_KEY_HEADER_SIZE ||
            new TextDecoder().decode(data.slice(0, 8)) !== 'SEZAMK02') {
        throw new Error('Invalid .sezam-key file');
    }
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const saltLength = view.getUint16(8, false);
    const params = {
        time_cost: view.getUint32(10, false),
        memory_cost: view.getUint32(14, false),
        parallelism: view.getUint32(18, false),
        hash_len: view.getUint16(22, false),
    };
    const bodyOffset = SEZAM_KEY_HEADER_SIZE + saltLength;
    if (data.length <= bodyOffset + 116) throw new Error('Truncated .sezam-key file');
    const salt = data.slice(SEZAM_KEY_HEADER_SIZE, bodyOffset);
    validateSezamKeyKdf(salt, params);
    const signingPk = data.slice(bodyOffset, bodyOffset + 32);
    const encryptionPk = data.slice(bodyOffset + 32, bodyOffset + 64);
    const userObjectId = new TextDecoder().decode(data.slice(bodyOffset + 90, bodyOffset + 116));
    const encryptedEnvelope = data.slice(bodyOffset + 116);
    if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(userObjectId)) {
        throw new Error('Invalid .sezam-key user object ID');
    }

    const derived = await deriveFn(password, salt, {
        time_cost: params.time_cost,
        memory_cost: params.memory_cost,
        parallelism: params.parallelism,
    });
    let keypairData, confirmedGenesis, preAnchor;
    try {
        ({ keypairData, confirmedGenesis, preAnchor } = decryptAccountKeypair(
            encryptedEnvelope, derived.subarray(0, 32), userObjectId, _sodium
        ));
    } finally {
        _sodium.memzero(derived);
    }

    const seed = keypairData.slice(0, 32);
    const signingKeypair = _sodium.crypto_sign_seed_keypair(seed);
    const encryptionSk = keypairData.length === 96
        ? keypairData.slice(64, 96)
        : keypairData.slice(32, 64);
    const derivedEncryptionPk = _sodium.crypto_scalarmult_base(encryptionSk);
    if (bytesToHex(signingKeypair.publicKey) !== bytesToHex(signingPk) ||
            bytesToHex(derivedEncryptionPk) !== bytesToHex(encryptionPk)) {
        _sodium.memzero(keypairData);
        _sodium.memzero(signingKeypair.privateKey);
        _sodium.memzero(encryptionSk);
        throw new Error('Invalid .sezam-key public keys');
    }

    let normalizedKeypair = keypairData;
    if (keypairData.length === 64) {
        normalizedKeypair = new Uint8Array(96);
        normalizedKeypair.set(signingKeypair.privateKey, 0);
        normalizedKeypair.set(encryptionSk, 64);
        _sodium.memzero(keypairData);
    }
    _sodium.memzero(signingKeypair.privateKey);
    _sodium.memzero(seed);
    _sodium.memzero(encryptionSk);
    return {
        keypairBytes: normalizedKeypair,
        confirmedGenesis,
        preAnchor,
        signingPk,
        encryptionPk,
        encryptedEnvelope,
        userObjectId,
        params,
        salt,
    };
}

function offerSezamKeyDownload(backupBytes, username) {
    const button = document.getElementById('onboard-backup-btn');
    const warning = document.getElementById('onboard-backup-warning');
    if (!button) return;
    button.classList.remove('hidden');
    warning?.classList.remove('hidden');
    button.onclick = () => {
        const blob = new Blob([backupBytes], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${username.replace(/[^A-Za-z0-9_-]/g, '_')}.sezam-key`;
        link.click();
        URL.revokeObjectURL(url);
    };
}

/**
 * Size a padded blob of n bytes takes: the next power of 2 (min 32); where
 * that needs more padding than the u16 prefix holds, the next multiple of
 * 64 KiB. Review 18c300f R16-L3: padding stopped at 0xFFFF bytes there and
 * the blob told its exact length. Python padding.padded_size, mobile: same.
 */
function paddedSize(n) {
    return globalThis.SezamSyncCore.call('padded_size', { n });
}

/**
 * Pad plaintext to paddedSize(2 + data.length).
 * Format: u16be(padding_len) + random_padding + data
 */
function padPlaintext(data) {
    const targetSize = paddedSize(2 + data.length); // 2 bytes for padding_len prefix
    const paddingLen = targetSize - 2 - data.length;
    const padded = new Uint8Array(targetSize);
    const view = new DataView(padded.buffer);
    view.setUint16(0, paddingLen, false); // u16be
    if (paddingLen > 0) {
        const paddingBytes = crypto.getRandomValues(new Uint8Array(paddingLen));
        padded.set(paddingBytes, 2);
    }
    padded.set(data, 2 + paddingLen);
    return padded;
}

/**
 * Remove padding: read u16be prefix, skip padding bytes, return actual data.
 */
function unpadPlaintext(padded) {
    const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
    const paddingLen = view.getUint16(0, false);
    return padded.slice(2 + paddingLen);
}

/**
 * Encrypt plaintext object to ciphertext envelope.
 * Returns Uint8Array: alg(1) + schema(1) + kind(1) + dekId(26) + nonce(24) + ciphertext
 */
function encryptEnvelope(plaintextObj, blobKind, dekId, objectId, version, dek, _sodium) {
    const jsonBytes = new TextEncoder().encode(JSON.stringify(plaintextObj));
    const padded = padPlaintext(jsonBytes);
    const aad = buildAAD(blobKind, dekId, objectId, version);
    const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES); // 24 bytes

    const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(padded, aad, null, nonce, dek);

    // Build envelope binary
    const dekIdBytes = idBytes26(dekId);
    const envelope = new Uint8Array(1 + 1 + 1 + 26 + nonce.length + ciphertext.length);
    envelope[0] = ENVELOPE_ALG;
    envelope[1] = SCHEMA_VERSION;
    envelope[2] = blobKind;
    envelope.set(dekIdBytes, 3);
    envelope.set(nonce, 29);
    envelope.set(ciphertext, 29 + nonce.length);
    return envelope;
}

/**
 * Decrypt ciphertext envelope back to plaintext object.
 * Returns parsed JSON object.
 *
 * expectedKind is the BLOB_KIND the caller is about to read. Review 18c300f
 * R16-L2: the header's kind is authenticated, but an entry's meta and data
 * blobs share its id, version and key, so only this check tells them apart;
 * on 18c300f the two swapped decrypted and the entry showed up empty.
 */
function decryptEnvelope(envelopeBytes, objectId, version, dekMap, _sodium, expectedKind) {
    validateCanonicalEnvelopeHeader(envelopeBytes);
    const blobKind = envelopeBytes[2];
    if (!Number.isInteger(expectedKind)) throw new Error('decryptEnvelope needs the blob kind it reads');
    if (blobKind !== expectedKind) {
        throw new Error(`Unexpected blob kind ${blobKind} (expected ${expectedKind})`);
    }
    const dekIdBytes = envelopeBytes.slice(3, 29);
    const dekId = new TextDecoder().decode(dekIdBytes).replace(/\0/g, '');
    const nonce = envelopeBytes.slice(29, 53);
    const ciphertext = envelopeBytes.slice(53);

    const dek = dekMap[dekId];
    if (!dek) throw new Error('No DEK for id: ' + dekId);

    const aad = buildAAD(blobKind, dekId, objectId, version);
    const padded = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, dek);
    const jsonBytes = unpadPlaintext(new Uint8Array(padded));
    return JSON.parse(new TextDecoder().decode(jsonBytes));
}

/**
 * Check if a base64-decoded payload is an encrypted envelope (starts with alg=1)
 * vs legacy plaintext JSON (starts with '{' = 0x7B or other printable ASCII).
 */
function isEncryptedEnvelope(bytes) {
    return bytes.length >= 53 && bytes[0] === ENVELOPE_ALG && bytes[1] === SCHEMA_VERSION;
}

/**
 * Canonical entry wire format (spec §4.1 + §8.2, cross-client with desktop/mobile):
 * an entry serializes as TWO separate AEAD envelopes framed with a length prefix:
 *   payload = u32be(len(encrypted_meta)) || encrypted_meta || encrypted_data
 *   encrypted_meta = ENTRY_META(blob_kind=2) envelope over {name, tags?}
 *   encrypted_data = ENTRY_DATA(blob_kind=3) envelope over {fields}
 * Both envelopes share the same dek, dek_id, object_id (= entry id) and version.
 */
function encryptEntryPayload(entryObj, dekId, objectId, version, dek, _sodium) {
    // Every meta key the entry carries (desktop tier / AI-broker settings too).
    const { fields, tags, ...metaObj } = entryObj;
    if (tags && tags.length) metaObj.tags = tags;
    const dataObj = { fields: fields || [] };
    const metaEnv = encryptEnvelope(metaObj, BLOB_KIND.ENTRY_META, dekId, objectId, version, dek, _sodium);
    const dataEnv = encryptEnvelope(dataObj, BLOB_KIND.ENTRY_DATA, dekId, objectId, version, dek, _sodium);
    const payload = new Uint8Array(4 + metaEnv.length + dataEnv.length);
    new DataView(payload.buffer).setUint32(0, metaEnv.length >>> 0, false); // u32be
    payload.set(metaEnv, 4);
    payload.set(dataEnv, 4 + metaEnv.length);
    return payload;
}

/**
 * Parse the canonical two-envelope entry payload and return the merged object
 * {name, tags, fields}. Mirrors desktop _apply_entry framing.
 */
function decryptEntryPayload(payloadBytes, objectId, version, dekMap, _sodium) {
    if (payloadBytes.length < 4) throw new Error('Entry payload too short');
    const metaLen = new DataView(
        payloadBytes.buffer, payloadBytes.byteOffset, payloadBytes.byteLength
    ).getUint32(0, false); // u32be
    if (4 + metaLen > payloadBytes.length) {
        throw new Error('Entry meta_len exceeds payload size');
    }
    const metaEnv = payloadBytes.slice(4, 4 + metaLen);
    const dataEnv = payloadBytes.slice(4 + metaLen);
    const meta = decryptEnvelope(metaEnv, objectId, version, dekMap, _sodium, BLOB_KIND.ENTRY_META);
    const data = decryptEnvelope(dataEnv, objectId, version, dekMap, _sodium, BLOB_KIND.ENTRY_DATA);
    return { ...meta, tags: meta.tags || [], fields: (data && data.fields) || [] };
}

/**
 * Base64 decode that works with both standard and URL-safe base64.
 */
function base64ToBytes(b64) {
    const binaryStr = atob(b64);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
    }
    return bytes;
}

/**
 * Base64 encode bytes (standard base64).
 */
function bytesToBase64(bytes) {
    let binaryStr = '';
    for (let i = 0; i < bytes.length; i++) {
        binaryStr += String.fromCharCode(bytes[i]);
    }
    return btoa(binaryStr);
}

/**
 * Wrap (encrypt) a DEK with KEK using AEAD, blob_kind=6.
 * Returns envelope bytes.
 */
function wrapDEK(dekBytes, dekId, version, kek, _sodium) {
    return wrapDEKWithKey(
        dekBytes, generateULID(), dekId, version, kek, _sodium
    );
}

function wrapDEKWithKey(dekBytes, wrappingKeyId, objectId, version, wrappingKey, _sodium) {
    if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(wrappingKeyId) ||
            !/^[0-9A-HJKMNP-TV-Z]{26}$/.test(objectId) ||
            !Number.isInteger(version) || version < 1) {
        throw new Error('DEK_WRAP requires canonical IDs and a positive version');
    }
    const padded = padPlaintext(dekBytes);
    const aad = buildAAD(BLOB_KIND.DEK_WRAP, wrappingKeyId, objectId, version);
    const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        padded, aad, null, nonce, wrappingKey
    );

    const envelope = new Uint8Array(1 + 1 + 1 + 26 + nonce.length + ciphertext.length);
    envelope[0] = ENVELOPE_ALG;
    envelope[1] = SCHEMA_VERSION;
    envelope[2] = BLOB_KIND.DEK_WRAP;
    envelope.set(new TextEncoder().encode(wrappingKeyId), 3);
    envelope.set(nonce, 29);
    envelope.set(ciphertext, 29 + nonce.length);
    return envelope;
}

/**
 * Unwrap (decrypt) a DEK from its envelope using KEK.
 * Returns raw DEK bytes (32 bytes).
 */
function unwrapDEK(envelopeBytes, kek, dekId, version, _sodium) {
    if (envelopeBytes.length <= 53 || envelopeBytes[0] !== ENVELOPE_ALG ||
            envelopeBytes[1] !== SCHEMA_VERSION || envelopeBytes[2] !== BLOB_KIND.DEK_WRAP ||
            !/^[0-9A-HJKMNP-TV-Z]{26}$/.test(dekId) ||
            !Number.isInteger(version) || version < 1) {
        throw new Error('Invalid canonical DEK_WRAP envelope');
    }
    const kekDekId = new TextDecoder().decode(envelopeBytes.slice(3, 29));
    if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(kekDekId)) {
        throw new Error('Invalid DEK_WRAP key ID');
    }
    const nonce = envelopeBytes.slice(29, 53);
    const ciphertext = envelopeBytes.slice(53);

    const aad = buildAAD(BLOB_KIND.DEK_WRAP, kekDekId, dekId, version);
    const padded = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, ciphertext, aad, nonce, kek
    );
    const dekBytes = unpadPlaintext(new Uint8Array(padded));
    if (dekBytes.length !== 32) throw new Error('Invalid DEK payload length');
    return dekBytes;
}

// ── Resizable tree panel ──

const TREE_PANEL_WIDTH_KEY = 'sezam-tree-panel-width';
const TREE_PANEL_DEFAULT_WIDTH = 280;
const TREE_PANEL_MIN_WIDTH = 240;
const TREE_PANEL_MAX_RATIO = 0.45;
const TREE_PANEL_KEYBOARD_STEP = 16;

function initTreePanelSplitter() {
    const panel = document.getElementById('tree-panel');
    const splitter = document.getElementById('tree-splitter');
    const mainContent = document.querySelector('.main-content');
    if (!panel || !splitter || !mainContent) return;

    const storedWidth = Number.parseInt(localStorage.getItem(TREE_PANEL_WIDTH_KEY), 10);
    let preferredWidth = Number.isFinite(storedWidth) ? storedWidth : TREE_PANEL_DEFAULT_WIDTH;
    let currentWidth = TREE_PANEL_DEFAULT_WIDTH;
    let activePointerId = null;

    function maximumWidth() {
        const layoutWidth = mainContent.getBoundingClientRect().width || window.innerWidth;
        return Math.max(TREE_PANEL_MIN_WIDTH, Math.floor(layoutWidth * TREE_PANEL_MAX_RATIO));
    }

    function applyWidth(width) {
        const maxWidth = maximumWidth();
        const nextWidth = Math.max(TREE_PANEL_MIN_WIDTH, Math.min(maxWidth, Math.round(width)));
        mainContent.style.setProperty('--tree-panel-width', `${nextWidth}px`);
        splitter.setAttribute('aria-valuemax', String(maxWidth));
        splitter.setAttribute('aria-valuenow', String(nextWidth));
        currentWidth = nextWidth;
        return nextWidth;
    }

    function saveWidth() {
        preferredWidth = currentWidth;
        localStorage.setItem(TREE_PANEL_WIDTH_KEY, String(currentWidth));
    }

    function finishDrag(event) {
        if (event.pointerId !== activePointerId) return;
        const pointerId = activePointerId;
        activePointerId = null;
        document.body.classList.remove('resizing-tree-panel');
        if (splitter.hasPointerCapture?.(pointerId)) {
            splitter.releasePointerCapture(pointerId);
        }
        saveWidth();
    }

    splitter.addEventListener('pointerdown', (event) => {
        if (activePointerId !== null) return;
        if (event.button !== undefined && event.button !== 0) return;
        activePointerId = event.pointerId;
        splitter.setPointerCapture?.(event.pointerId);
        document.body.classList.add('resizing-tree-panel');
        event.preventDefault();
    });
    splitter.addEventListener('pointermove', (event) => {
        if (event.pointerId !== activePointerId) return;
        const layoutLeft = mainContent.getBoundingClientRect().left;
        preferredWidth = applyWidth(event.clientX - layoutLeft);
    });
    splitter.addEventListener('pointerup', finishDrag);
    splitter.addEventListener('pointercancel', finishDrag);
    splitter.addEventListener('lostpointercapture', finishDrag);
    splitter.addEventListener('keydown', (event) => {
        let requestedWidth = null;
        if (event.key === 'ArrowLeft') requestedWidth = currentWidth - TREE_PANEL_KEYBOARD_STEP;
        if (event.key === 'ArrowRight') requestedWidth = currentWidth + TREE_PANEL_KEYBOARD_STEP;
        if (event.key === 'Home') requestedWidth = TREE_PANEL_MIN_WIDTH;
        if (event.key === 'End') requestedWidth = maximumWidth();
        if (requestedWidth === null) return;
        preferredWidth = applyWidth(requestedWidth);
        saveWidth();
        event.preventDefault();
    });
    window.addEventListener('resize', () => applyWidth(preferredWidth));

    applyWidth(preferredWidth);
}

// ── Init ──

async function init() {
    if (typeof sodium !== 'undefined' && sodium.ready) {
        await sodium.ready;
        await globalThis.SezamSyncCore.ready;  // the team log's rules (teamlog.js)
        state.sodium = sodium;
        console.log('libsodium ready');
    } else {
        console.log('Waiting for libsodium...');
    }

    // Register service worker for offline fallback (spec 7.2)
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/static/sw.js').then(
            (reg) => console.log('Service worker registered, scope:', reg.scope),
            (err) => console.warn('Service worker registration failed:', err)
        );
    }

    const params = new URLSearchParams(window.location.search);
    if (params.has('invite')) {
        setupEventListeners();
        showScreen('onboarding-screen');
        // Auto-show invite token info on the onboarding screen
        const inviteToken = params.get('invite');
        const inviteInfo = document.getElementById('onboard-invite-info');
        if (inviteInfo) {
            inviteInfo.textContent = t('onboard.invited');
            inviteInfo.classList.remove('hidden');
        }
        // Focus on username field
        const usernameField = document.getElementById('onboard-username');
        if (usernameField) usernameField.focus();
        return;
    }

    // Check if server needs first-admin bootstrap
    try {
        const resp = await fetch(API_BASE + '/api/bootstrap-status');
        if (resp.ok) {
            const data = await resp.json();
            if (data.needs_setup) {
                setupEventListeners();
                showScreen('bootstrap-screen');
                const usernameField = document.getElementById('bootstrap-username');
                if (usernameField) usernameField.focus();
                return;
            }
            // Review e4cd15a (low): an unfinished first-admin setup this
            // network may not redo left a login nobody could pass, with the
            // reason in the server log only.
            if (data.unfinished_setup) {
                setupEventListeners();
                showScreen('login-screen');
                const loginError = document.getElementById('login-error');
                if (loginError) {
                    loginError.textContent = t('bootstrap.unfinished_elsewhere');
                    loginError.classList.remove('hidden');
                }
                return;
            }
        }
    } catch (e) {
        console.warn('Bootstrap status check failed:', e);
    }

    setupEventListeners();
    showScreen('login-screen');
}

function setupEventListeners() {
    document.getElementById('login-form')?.addEventListener('submit', handleLogin);
    document.getElementById('onboard-form')?.addEventListener('submit', handleOnboarding);
    document.getElementById('bootstrap-form')?.addEventListener('submit', handleBootstrap);
    document.getElementById('onboard-password')?.addEventListener('input', (e) => {
        updatePasswordStrength(e.target.value);
        validateConfirmPassword();
    });
    document.getElementById('onboard-confirm')?.addEventListener('input', validateConfirmPassword);
    document.getElementById('bootstrap-password')?.addEventListener('input', (e) => {
        updateBootstrapPasswordStrength(e.target.value);
        validateBootstrapConfirmPassword();
    });
    document.getElementById('bootstrap-confirm')?.addEventListener('input', validateBootstrapConfirmPassword);
    document.getElementById('lock-btn')?.addEventListener('click', handleLock);
    document.getElementById('team-trust-btn')?.addEventListener('click', openTeamTrustModal);
    document.getElementById('team-trust-form')?.addEventListener('submit', handleConfirmTeamFounder);
    document.getElementById('team-trust-cancel')?.addEventListener('click', closeTeamTrustModal);
    document.getElementById('team-forget-form')?.addEventListener('submit', handleForgetTeamPin);
    document.getElementById('import-unsent-file')?.addEventListener('change', handleImportUnsentFile);
    document.getElementById('org-recovery-btn')?.addEventListener('click', openOrgRecoveryModal);
    document.getElementById('audit-btn')?.addEventListener('click', openAuditPanel);
    document.getElementById('audit-back-btn')?.addEventListener('click', closeAuditPanel);
    document.getElementById('audit-refresh-btn')?.addEventListener('click', () => loadAuditEntries());
    document.getElementById('audit-apply-btn')?.addEventListener('click', () => { _auditOffset = 0; loadAuditEntries(); });
    document.getElementById('audit-reset-btn')?.addEventListener('click', resetAuditFilters);
    document.getElementById('audit-csv-btn')?.addEventListener('click', exportAuditCSV);
    document.getElementById('audit-prev-btn')?.addEventListener('click', auditPrevPage);
    document.getElementById('audit-next-btn')?.addEventListener('click', auditNextPage);

    // Tree action buttons
    document.getElementById('new-folder-btn')?.addEventListener('click', () => openFolderModal());
    document.getElementById('new-personal-btn')?.addEventListener('click', () => openPersonalFolderModal());
    document.getElementById('new-entry-btn')?.addEventListener('click', () => openEntryModal());

    // Entry detail action buttons
    document.getElementById('edit-entry-btn')?.addEventListener('click', () => {
        if (state.selectedEntry && canEditObject(state.selectedEntry)) openEntryModal(state.selectedEntry);
    });
    document.getElementById('delete-entry-btn')?.addEventListener('click', () => {
        if (state.selectedEntry && canEditObject(state.selectedEntry)) openDeleteModal(state.selectedEntry);
    });

    // Modal buttons
    document.getElementById('entry-form')?.addEventListener('submit', handleModalSave);
    document.getElementById('modal-cancel-btn')?.addEventListener('click', closeEntryModal);
    document.getElementById('add-field-btn')?.addEventListener('click', addFieldRow);
    document.getElementById('delete-cancel-btn')?.addEventListener('click', closeDeleteModal);
    document.getElementById('delete-confirm-btn')?.addEventListener('click', handleDeleteConfirm);

    // Close modals on overlay click
    document.getElementById('entry-modal')?.addEventListener('click', (e) => {
        if (e.target === e.currentTarget) closeEntryModal();
    });
    document.getElementById('delete-modal')?.addEventListener('click', (e) => {
        if (e.target === e.currentTarget) closeDeleteModal();
    });

    // Escape key closes modals
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const shamirSetup = document.getElementById('shamir-setup-modal');
            const shamirShares = document.getElementById('shamir-shares-modal');
            const orgRecovery = document.getElementById('org-recovery-modal');
            if (shamirSetup) { closeShamirSetupModal(); return; }
            if (shamirShares) { shamirShares.remove(); return; }
            if (orgRecovery) { closeOrgRecoveryModal(); return; }
            if (!document.getElementById('team-trust-modal')?.classList.contains('hidden')) {
                closeTeamTrustModal();
            } else if (!document.getElementById('audit-panel')?.classList.contains('hidden')) {
                closeAuditPanel();
            } else if (!document.getElementById('delete-modal')?.classList.contains('hidden')) {
                closeDeleteModal();
            } else if (!document.getElementById('entry-modal')?.classList.contains('hidden')) {
                closeEntryModal();
            }
        }
    });

    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        let debounce;
        searchInput.addEventListener('input', (e) => {
            clearTimeout(debounce);
            debounce = setTimeout(() => handleSearch(e.target.value), 200);
        });
        searchInput.addEventListener('focus', () => {
            if (searchInput.value) handleSearch(searchInput.value);
        });
        document.addEventListener('click', (e) => {
            if (!e.target.closest('#search-input') && !e.target.closest('#search-results')) {
                document.getElementById('search-results')?.classList.add('hidden');
            }
        });
    }
}

function showScreen(id) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    document.getElementById(id)?.classList.add('active');
}

// ── Ensure sodium ──

async function ensureSodium() {
    if (state.sodium) return state.sodium;
    if (typeof sodium !== 'undefined' && sodium.ready) {
        await sodium.ready;
        // The team log (teamlog.js) answers from the core (docs/CORE_UNIFICATION.md U3).
        await globalThis.SezamSyncCore.ready;
        state.sodium = sodium;
        return state.sodium;
    }
    throw new Error(t('error.crypto_unavailable'));
}

// ── Login ──

// Login steps 2-4 with one form of the password (see passwordForms). A
// wrong password throws an error with wrongPassword = true so the next form
// can be tried; throttling, outages and TOFU changes end the login.
// options.derivedKey: this form's derivation, owned (and zeroed) by the
// caller. options.localOnly: a cached keypair this form does not open is a
// wrong password here, no /recover (review 688edcb V3).
async function openLoginKeypair(username, passwordForm, meta, backupFile, _sodium, options) {
    options = options || {};
    let derivedKey = options.derivedKey || null;
    const ownsKey = !options.derivedKey;
    try {
        // 2. Derive KEK from password using Argon2id with server params + hard floor
        // Also sent to /recover: an account stored without params adopts the
        // ones a matching proof was derived with (lockout review N2).
        const kdfParams = accountKdfParams(meta);
        if (!derivedKey) derivedKey = await deriveLoginKey(passwordForm, meta);
        const kek = derivedKey.subarray(0, 32);
        const authProof = derivedKey.subarray(32, 64);

        // 3. Optional offline Path C, otherwise IndexedDB then server recovery (Path B).
        let encryptedKeypairHex = null;
        let keypairUserId = null;
        let keypairBytes = null;
        let confirmedGenesis = null;
        let preAnchor = null;
        let fromIndexedDB = false;
        let kekChangedElsewhere = false;
        let importedBackup = null;
        if (backupFile) {
            try {
                importedBackup = await parseSezamKeyBackup(
                    new Uint8Array(await backupFile.arrayBuffer()), passwordForm, _sodium,
                    (pw, salt, params) => deriveKEK(pw, salt, params, { exact: true }),
                );
            } catch (backupErr) {
                backupErr.wrongPassword = true;
                throw backupErr;
            }
            keypairBytes = importedBackup.keypairBytes;
            confirmedGenesis = importedBackup.confirmedGenesis;
            preAnchor = importedBackup.preAnchor;
            encryptedKeypairHex = bytesToHex(importedBackup.encryptedEnvelope);
            keypairUserId = importedBackup.userObjectId;
        } else {
            const stored = await loadFromIndexedDB();
            if (stored && stored.encrypted_keypair && stored.user_id) {
                encryptedKeypairHex = stored.encrypted_keypair;
                keypairUserId = stored.user_id;
                fromIndexedDB = true;
            } else {
                let recoverResp;
                try {
                    recoverResp = await apiFetch('/api/auth/recover', {
                        method: 'POST',
                        body: {
                            username, auth_proof: bytesToHex(authProof),
                            argon2_params: kdfParams,
                        },
                    });
                } catch (recoverErr) {
                    throw recoverError(recoverErr);
                }
                if (!recoverResp.encrypted_keypair) {
                    throw new Error(t('error.no_keypair'));
                }
                encryptedKeypairHex = recoverResp.encrypted_keypair;
                keypairUserId = recoverResp.user_id;
                await saveToIndexedDB({
                    encrypted_keypair: encryptedKeypairHex,
                    user_id: keypairUserId,
                });
            }
        }

        // 4. Decrypt only a canonical KEYPAIR_WRAP envelope.
        if (!keypairBytes) {
            try {
                ({ keypairBytes, confirmedGenesis, preAnchor } = decryptLoginKeypair(
                    hexToBytes(encryptedKeypairHex), kek, keypairUserId, _sodium
                ));
            } catch (decryptError) {
                // A corrupt local cache may be replaced only by the authenticated
                // server copy; neither path accepts a legacy null-AAD ciphertext.
                if (!fromIndexedDB || options.localOnly) {
                    decryptError.wrongPassword = true;
                    throw decryptError;
                }
                let recoverResp;
                try {
                    recoverResp = await apiFetch('/api/auth/recover', {
                        method: 'POST',
                        body: {
                            username, auth_proof: bytesToHex(authProof),
                            argon2_params: kdfParams,
                        },
                    });
                } catch (recoverErr) {
                    throw recoverError(recoverErr);
                }
                if (!recoverResp.encrypted_keypair || !recoverResp.user_id) {
                    throw new Error(t('error.wrong_password_or_keypair'));
                }
                encryptedKeypairHex = recoverResp.encrypted_keypair;
                keypairUserId = recoverResp.user_id;
                ({ keypairBytes, confirmedGenesis, preAnchor } = decryptLoginKeypair(
                    hexToBytes(encryptedKeypairHex), kek, keypairUserId, _sodium
                ));
                // The cached keypair was under another KEK: the password was
                // most likely changed on another device. The cache is replaced
                // only after the login set aside the records of the old KEK
                // (review d615826 H7), see handleLogin.
                kekChangedElsewhere = true;
            }
        }

        // Opened from this browser's cache, not checked by the server yet.
        const cachedKeypair = fromIndexedDB && !kekChangedElsewhere;
        return {
            derivedKey, keypairBytes, kekChangedElsewhere, importedBackup, cachedKeypair,
            encryptedKeypairHex, keypairUserId, confirmedGenesis, preAnchor,
        };
    } catch (err) {
        if (derivedKey && ownsKey) _sodium.memzero(derivedKey);
        throw err;
    }
}

function deriveLoginKey(passwordForm, meta) {
    const argon2Salt = hexToBytes(meta.argon2_salt);
    const kdfParams = accountKdfParams(meta);
    return deriveKEK(passwordForm, argon2Salt, kdfParams, { exact: true });
}

// Login steps 2-4 over every form of the password, NFC first (lockout review
// M8). Review 688edcb V3: with a keypair cached in this browser every form is
// tried on the cache first. An account from before normalization opens the
// cache with its typed form, and the NFC proof never reaches /recover. Before,
// each such login sent one wrong proof, and after ten the name was locked
// (423), ending every later login. Only when no form opens the cache does the
// server decide, form by form after 401, with the same derivations.
async function openLoginKeypairAnyForm(username, password, meta, backupFile, _sodium) {
    const forms = passwordForms(password);
    const stored = backupFile ? null : await loadFromIndexedDB();
    if (!(stored && stored.encrypted_keypair && stored.user_id) || forms.length === 1) {
        for (let i = 0; ; i++) {
            try {
                return await openLoginKeypair(username, forms[i], meta, backupFile, _sodium);
            } catch (openErr) {
                if (!openErr.wrongPassword || i + 1 === forms.length) throw openErr;
            }
        }
    }
    const derived = [];
    let opened = null;
    try {
        for (const form of forms) {
            const derivedKey = await deriveLoginKey(form, meta);
            derived.push(derivedKey);
            try {
                opened = await openLoginKeypair(
                    username, form, meta, null, _sodium, { derivedKey, localOnly: true }
                );
                return opened;
            } catch (openErr) {
                if (!openErr.wrongPassword) throw openErr;
            }
        }
        for (let i = 0; ; i++) {
            try {
                opened = await openLoginKeypair(
                    username, forms[i], meta, null, _sodium, { derivedKey: derived[i] }
                );
                return opened;
            } catch (openErr) {
                if (!openErr.wrongPassword || i + 1 === forms.length) throw openErr;
            }
        }
    } finally {
        for (const derivedKey of derived) {
            if (!opened || derivedKey !== opened.derivedKey) _sodium.memzero(derivedKey);
        }
    }
}

/**
 * Answer a server login challenge. The identity key signs only
 * context || challenge, and only a challenge of the server's fixed layout,
 * so a server cannot have it sign bytes of its choosing (a sync object, a
 * policy) under the guise of a login.
 */
function signAuthChallenge(challengeHex, signingSk, _sodium) {
    // The message is the core's (docs/CORE_UNIFICATION.md U6c).
    let message;
    try {
        message = hexToBytes(globalThis.SezamSyncCore.call(
            'auth_challenge_message', { challenge: String(challengeHex ?? '') }));
    } catch (_) {
        throw new Error('Server sent a malformed login challenge');
    }
    return _sodium.crypto_sign_detached(message, signingSk);
}

// Login steps 5-7: challenge, sign it with the keypair, verify → JWT.
// INV-3 (server/app/unsigned_fields.py VerifyResponse.user_id): the account a
// verify reply names is this browser's identity only when its keys were
// wrapped for it (the KEYPAIR_WRAP AAD); another one refuses the sign-in, as
// on the phone (review 8595ec1 R10-F).
function signedInUserId(authResp, keypairUserId) {
    if (!authResp || !keypairUserId || authResp.user_id !== keypairUserId) {
        throw new Error(t('error.identity_mismatch'));
    }
    return keypairUserId;
}

// A .sezam-key wraps its keys for a random object id (buildSezamKeyBackup, as
// desktop keys.py and the phone do), not for an account: they are bound to the
// account at their first sign-in, as the desktop's rebind_server_identity does.
// From then on the own-key check of getUserSigningPks refuses another account's keys.
function firstSignInUserId(authResp) {
    if (!authResp || typeof authResp.user_id !== 'string' || !/^[0-9A-HJKMNP-TV-Z]{26}$/.test(authResp.user_id)) {
        throw new Error(t('error.identity_mismatch'));
    }
    return authResp.user_id;
}

async function signInWithKeypair(username, keypairBytes, _sodium) {
    // Get the challenge right before signing, so it doesn't expire.
    const challengeResp = await apiFetch('/api/auth/challenge', {
        method: 'POST',
        body: { username },
    });
    const signingSk = keypairBytes.slice(0, 64);
    try {
        const signature = signAuthChallenge(challengeResp.challenge, signingSk, _sodium);
        // Challenge and signature as separate fields per spec 2.7.
        return await apiFetch('/api/auth/verify', {
            method: 'POST',
            body: {
                username,
                challenge: challengeResp.challenge,
                signature: bytesToHex(signature),
            },
        });
    } finally {
        _sodium.memzero(signingSk);
    }
}

// Lockout review N5: a keypair cached in this browser opens with the password
// it was cached under, even after the account's key material moved on
// elsewhere — and the identity key it holds still signs in. So the cached copy
// counts only while it is the server's current one (key_material_hash) and
// the server accepts its key. Otherwise only the server's copy is tried, under
// this password's proof: an outdated password ends as a wrong password, the
// current one replaces the cache.
async function signInWithLoginKeypair(username, opened, meta, _sodium) {
    let authResp = null;
    try {
        authResp = await signInWithKeypair(username, opened.keypairBytes, _sodium);
    } catch (authErr) {
        if (!opened.cachedKeypair || !authErr || authErr.status !== 401) throw authErr;
    }
    if (!opened.cachedKeypair) {
        return { authResp, keypairBytes: null,
            userId: opened.importedBackup ? firstSignInUserId(authResp) : opened.keypairUserId };
    }
    if (authResp) {
        const cachedHash = bytesToHex(_sodium.crypto_hash_sha256(hexToBytes(opened.encryptedKeypairHex)));
        if (authResp.key_material_hash === cachedHash) return { authResp, keypairBytes: null, userId: opened.keypairUserId };
        // Issued to a stale cache only: never used, revoked right away.
        try {
            await apiFetch('/api/auth/logout', {
                method: 'POST',
                headers: { Authorization: `Bearer ${authResp.token}` },
            });
        } catch (logoutErr) {
            console.warn('Could not revoke the token of a stale keypair cache:', logoutErr.message || logoutErr);
        }
    }
    let recoverResp;
    try {
        recoverResp = await apiFetch('/api/auth/recover', {
            method: 'POST',
            body: {
                username,
                auth_proof: bytesToHex(opened.derivedKey.subarray(32, 64)),
                argon2_params: accountKdfParams(meta),
            },
        });
    } catch (recoverErr) {
        throw recoverError(recoverErr);
    }
    if (!recoverResp.encrypted_keypair || !recoverResp.user_id) {
        throw new Error(t('error.wrong_password_or_keypair'));
    }
    let keypairBytes, confirmedGenesis, preAnchor;
    try {
        ({ keypairBytes, confirmedGenesis, preAnchor } = decryptLoginKeypair(
            hexToBytes(recoverResp.encrypted_keypair), opened.derivedKey.subarray(0, 32),
            recoverResp.user_id, _sodium
        ));
    } catch {
        throw new Error(t('error.wrong_password_or_keypair'));
    }
    try {
        // Capability run 416 (INV-7): server keys naming another genesis than
        // the cached ones (a password changed on a device that left the log)
        // never fail the sign-in; the cached anchor stays pinned (keepTeamAnchor)
        // and the team is refused as anchor_conflict, its way out signed in.
        const cachedGenesis = opened.confirmedGenesis && confirmedGenesis !== opened.confirmedGenesis
            ? opened.confirmedGenesis : null;
        const authResp = await signInWithKeypair(username, keypairBytes, _sodium);
        await saveToIndexedDB({
            encrypted_keypair: recoverResp.encrypted_keypair,
            user_id: recoverResp.user_id,
        });
        // A server copy never makes this browser forget a recorded pre-anchor state.
        return { authResp, keypairBytes, confirmedGenesis, cachedGenesis, userId: recoverResp.user_id,
            preAnchor: mergePreAnchor(preAnchor, opened.preAnchor) };
    } catch (err) {
        _sodium.memzero(keypairBytes);
        throw err;
    }
}

function recoverError(recoverErr) {
    const err = new Error(recoverFailureMessage(recoverErr));
    err.wrongPassword = !!recoverErr && (recoverErr.status === 401 || recoverErr.status === 404);
    return err;
}

// Review 688edcb N3: the name every client sends - trimmed of the union of
// what Python, JS and Dart trim (NBSP, BOM, NEL, \x1c-\x1f, zero-width space)
// and NFC, so one visible name is one account. Must equal
// server.app.models.schemas.normalize_username.
function normalizeUsername(value) {
    return globalThis.SezamSyncCore.call('normalize_username', { value });
}

async function handleLogin(e) {
    e.preventDefault();
    // N3: onboarding stores the trimmed name (IndexedDB, server account), so
    // " alice" must log in as "alice".
    const username = normalizeUsername(document.getElementById('username').value);
    const password = document.getElementById('password').value;
    const spinner = document.getElementById('login-spinner');
    const error = document.getElementById('login-error');

    if (!username) {
        error.textContent = t('error.username_required');
        error.classList.remove('hidden');
        return;
    }

    // Review 8bc70f7 H4: shown (and read) only after a login failed on a lost team log.
    const forgetTyped = state.loginTeamLogLost
        ? (document.getElementById('login-team-forget-genesis')?.value || '').trim() : '';
    spinner.classList.remove('hidden');
    error.classList.add('hidden');
    resetSession();  // never merge a new login into leftovers of a previous one
    const loginSession = state.sessionSerial;
    let loginDerivedKey = null;

    try {
        const _sodium = await ensureSodium();

        // 0. Finish an interrupted org-recovery KEK rotation, if any. One that
        // cannot finish must not lock the account out of this browser (review
        // 2052248): the normal login below decides whether the password works.
        let unfinishedRotation = null;
        let resumedRecoveryStore = null;
        try {
            const resumed = await resumeKekRotation(username, password, _sodium);
            if (resumed && resumed.recovery_signing_pk) resumedRecoveryStore = resumed;
        } catch (resumeErr) {
            if (resumeErr instanceof KeyEpochChangedError ||
                    resumeErr instanceof KekRotationRefusedError ||
                    resumeErr instanceof TofuKeyChangeError) throw resumeErr;
            console.warn('Interrupted password change could not be finished:', resumeErr.message || resumeErr);
            unfinishedRotation = await loadKekRotationJournal(username);
        }

        // 1. Get meta (argon2 params + salts)
        const meta = await apiFetch(`/api/meta?username=${encodeURIComponent(username)}`);

        if (!meta.argon2_salt) {
            throw new Error(t('error.user_not_found'));
        }
        const backupFile = document.getElementById('sezam-key-import')?.files?.[0];

        // 2.-4. Derive the KEK, get the keypair and open it (any form of the
        // password, the browser's cache before the server).
        const opened = await openLoginKeypairAnyForm(username, password, meta, backupFile, _sodium);
        loginDerivedKey = opened.derivedKey;
        const kek = loginDerivedKey.subarray(0, 32);
        const authProof = loginDerivedKey.subarray(32, 64);
        const { importedBackup, kekChangedElsewhere } = opened;

        // 5.-7. Signed challenge → JWT; a stale cached keypair is replaced
        // by the server's copy or the login fails (N5).
        let signedIn;
        try {
            signedIn = await signInWithLoginKeypair(username, opened, meta, _sodium);
        } catch (signInErr) {
            _sodium.memzero(opened.keypairBytes);
            throw signInErr;
        }
        const { authResp } = signedIn;
        if (signedIn.keypairBytes) _sodium.memzero(opened.keypairBytes);
        const keypairBytes = signedIn.keypairBytes || opened.keypairBytes;

        // Parse keypair: signing_sk (64B) + encryption_sk (32B)
        const signingSk = keypairBytes.slice(0, 64);
        const encryptionSk = keypairBytes.slice(64, 96);
        const signingPk = signingSk.slice(32, 64); // Ed25519 pk is last 32B of sk
        _sodium.memzero(keypairBytes);

        state.keypair = { signingSk, signingPk, encryptionSk,
            confirmedGenesis: signedIn.keypairBytes ? signedIn.confirmedGenesis : opened.confirmedGenesis,
            preAnchor: signedIn.keypairBytes ? signedIn.preAnchor : opened.preAnchor };
        state.kek = kek;
        state.kdf = { argon2_salt: meta.argon2_salt, argon2_params: accountKdfParams(meta) };
        // Review e4cd15a (low): the server's name migration may have moved
        // this account off the typed name; its answer carries the current one.
        state.username = authResp.username || username;
        _sodium.memzero(authProof);

        state.token = authResp.token;
        state.userId = signedInUserId(authResp, signedIn.userId);
        state.isAdmin = authResp.is_admin;
        await rememberWebKdfState(_sodium);
        // Start periodic JWT refresh
        startJwtRefreshTimer();

        // Records sealed under the old KEK would fail every login from now
        // on (lockout review #4): set them aside before the pull reads them.
        // Review d615826 H7: the server's keypair replaces the cache only
        // after that. Cached first, a login interrupted in between left a
        // cache the new password opens, so no later login saw the change and
        // the old records blocked this browser for good. Review 7c10379
        // (R7-H): a .sezam-key import is such a login too — after a password
        // change elsewhere it replaced the cache without setting anything
        // aside, and the old queue failed this and every later login.
        // Review 8595ec1 #5: a tab still open with the old KEK may seal its
        // queue after the cache took the new one, so every login sets aside
        // what its KEK does not open (the checkpoint only on a key change).
        const keyChanged = Boolean(kekChangedElsewhere || importedBackup);
        const unsentSetAside = await setAsideRecordsOfOldKek(_sodium, keyChanged);
        if (keyChanged) {
            await saveToIndexedDB(importedBackup ? {
                username,
                user_id: importedBackup.userObjectId,
                signing_pk: bytesToHex(importedBackup.signingPk),
                encryption_pk: bytesToHex(importedBackup.encryptionPk),
                encrypted_keypair: bytesToHex(importedBackup.encryptedEnvelope),
            } : {
                encrypted_keypair: opened.encryptedKeypairHex,
                user_id: opened.keypairUserId,
            });
            if (unsentSetAside) alert(t('sync.old_kek_records_set_aside'));
        }

        // Import only the anchor authenticated inside this account's keypair wrap.
        if (signedIn.cachedGenesis) await keepTeamAnchor(signedIn.cachedGenesis, _sodium);
        if (state.keypair.confirmedGenesis) await importAccountTeamAnchor(_sodium);
        // The password just opened the keypair and signed in: it authorizes
        // leaving the pinned team log before the pull that would refuse it.
        if (forgetTyped) await forgetTeamLogPinAtLogin(forgetTyped, password, loginSession, _sodium);
        // 8. Pull vault and build tree
        await pullAndBuildTree();
        await settleUnfinishedKekRotation(unfinishedRotation, meta);
        if (resumedRecoveryStore) {
            // A recovery finished only now: its wrap goes to the log too (R11, low).
            const unanchored = await anchorWebOrgRecovery(
                resumedRecoveryStore.recovery_signing_pk, resumedRecoveryStore, _sodium);
            if (unanchored) alert(t('recovery.wrap_anchor_failed', { error: unanchored }));
        }

        // What a password change set aside, in this login or an earlier one:
        // revocations are finished, unsent changes offered back (review
        // 688edcb, web #4). Neither may fail the login.
        try {
            const unfinished = await finishSetAsideWebRevocations(_sodium);
            if (unfinished.length) {
                alert(t('sync.set_aside_revocation_unfinished', { users: unfinished.join(', ') }));
            }
            await renderSetAsideWebChanges();
        } catch (setAsideErr) {
            alert(setAsideErr.message || setAsideErr);
        }

        // 9. Display user info with fingerprint in header
        await renderUserInfoWithFingerprint(username);
        if (loginSession !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
        showScreen('vault-screen');
        state.loginTeamLogLost = false;
        document.getElementById('login-team-forget')?.classList.add('hidden');

    } catch (err) {
        if (state.sodium && loginDerivedKey) state.sodium.memzero(loginDerivedKey);
        // Locked while this login still pulled: the lock already reset, and
        // a login made since must not be signed out by this one's failure.
        if (loginSession !== state.sessionSerial) return;
        // Drop DEKs, entries and keys this attempt (or an earlier session)
        // left behind so the next person in this browser inherits nothing.
        resetSession();
        showScreen('login-screen');
        if (err instanceof TofuKeyChangeError) {
            // resetSession() removed the dialog: show it again so the changed
            // key can be accepted, then the next login goes through.
            showMITMWarning(err.username, err.userId, err.signingPkHex, err.encryptionPkHex);
            error.textContent = t('error.tofu_key_changed');
        } else {
            error.textContent = err.message || t('error.login_failed');
        }
        error.classList.remove('hidden');
        // Without this the browser stayed at TEAM LOG MISMATCH for good: the
        // way out was only in the vault this login never reached.
        state.loginTeamLogLost = !!(err.teamLogLost || forgetTyped);
        const forgetPanel = document.getElementById('login-team-forget');
        if (state.loginTeamLogLost) forgetPanel?.classList.remove('hidden');
        else forgetPanel?.classList.add('hidden');
    } finally {
        spinner.classList.add('hidden');
    }
}

/** Review 8bc70f7 H4: "Forget the pinned team log" on the sign-in screen, for a
 * login that fails on a lost team log; runs once the login's password signed in. */
async function forgetTeamLogPinAtLogin(typed, password, session, _sodium) {
    if (!window.confirm(t('team.forget_confirm'))) throw new Error(t('team.forget_cancelled'));
    await withWebSyncLock(() => forgetWebTeamLogPinLocked(typed, password, session, _sodium));
    const input = document.getElementById('login-team-forget-genesis');
    if (input) input.value = '';
    document.getElementById('login-team-forget')?.classList.add('hidden');
}

// ── Onboarding ──

async function handleOnboarding(e) {
    e.preventDefault();
    const username = normalizeUsername(document.getElementById('onboard-username').value);
    const password = document.getElementById('onboard-password').value;
    const confirm = document.getElementById('onboard-confirm').value;
    const spinner = document.getElementById('onboard-spinner');
    const error = document.getElementById('onboard-error');
    const statusEl = document.getElementById('onboard-status');

    if (!username) {
        error.textContent = t('error.username_required');
        error.classList.remove('hidden');
        return;
    }

    if (password !== confirm) {
        error.textContent = t('error.password_mismatch');
        error.classList.remove('hidden');
        return;
    }

    if (!meetsNewPasswordPolicy(password)) {
        error.textContent = t('error.password_policy');
        error.classList.remove('hidden');
        return;
    }

    spinner.classList.remove('hidden');
    error.classList.add('hidden');

    try {
        const _sodium = await ensureSodium();
        const params = new URLSearchParams(window.location.search);
        const inviteToken = params.get('invite');
        const invitedGenesis = invitationTeamGenesis(window.location.hash);

        statusEl.textContent = t('status.generating_keypair');
        statusEl.classList.remove('hidden');

        // 1. Generate Ed25519 signing keypair
        const signingKeypair = _sodium.crypto_sign_keypair();
        const signingPk = signingKeypair.publicKey;
        const signingSk = signingKeypair.privateKey;

        // 2. Generate X25519 encryption keypair
        const encryptionKeypair = _sodium.crypto_box_keypair();
        const encryptionPk = encryptionKeypair.publicKey;
        const encryptionSk = encryptionKeypair.privateKey;

        // 3. Derive KEK from password using Argon2id — before the account
        // exists (lockout review #10), so registration and keypair upload
        // are only a local wrap apart.
        statusEl.textContent = t('status.deriving_key');
        const argon2Salt = _sodium.randombytes_buf(16);
        const authSalt = _sodium.randombytes_buf(16);
        const meta = await apiFetch('/api/meta');
        const onboardingKdfParams = normalizeKdfParams(meta.argon2_web_params);
        const derivedKey = await deriveKEK(password, argon2Salt, onboardingKdfParams);
        const kek = derivedKey.subarray(0, 32);
        const authProof = derivedKey.subarray(32, 64);

        // 4. Register with server
        statusEl.textContent = t('status.registering');
        const resp = await apiFetch('/api/users/register', {
            method: 'POST',
            body: {
                invitation_token: inviteToken,
                username,
                signing_pk: bytesToHex(signingPk),
                encryption_pk: bytesToHex(encryptionPk),
            },
        });

        state.token = resp.token;
        state.userId = resp.user_id;


        // 5. Encrypt keypair with KEK using AEAD envelope format (blob_kind=7, KEYPAIR_WRAP)
        statusEl.textContent = t('status.encrypting_keypair');
        const keypairPlaintext = new Uint8Array(signingSk.length + encryptionSk.length);
        keypairPlaintext.set(signingSk, 0);
        keypairPlaintext.set(encryptionSk, signingSk.length);

        // The invitation anchor travels in the account envelope so the
        // member's next device trusts it rather than the server.
        const encryptedWithNonce = invitedGenesis
            ? encryptAccountKeypair(keypairPlaintext, invitedGenesis, kek, generateULID(), state.userId, _sodium)
            : encryptKeypairWrap(keypairPlaintext, kek, generateULID(), state.userId, _sodium);

        // 6. Upload encrypted keypair
        statusEl.textContent = t('status.uploading_keypair');
        await apiFetch('/api/me/keypair', {
            method: 'PUT',
            body: {
                encrypted_keypair: bytesToHex(encryptedWithNonce),
                argon2_salt: bytesToHex(argon2Salt),
                auth_salt: bytesToHex(authSalt),
                auth_proof: bytesToHex(authProof),
                argon2_params: onboardingKdfParams,
            },
        });
        if (invitedGenesis) await saveConfirmedTeamGenesis(invitedGenesis, _sodium);
        // 7. Save public keys + encrypted keypair to IndexedDB
        await saveToIndexedDB({
            username,
            user_id: state.userId,
            signing_pk: bytesToHex(signingPk),
            encryption_pk: bytesToHex(encryptionPk),
            encrypted_keypair: bytesToHex(encryptedWithNonce),
        });

        const backupBytes = buildSezamKeyBackup(
            keypairPlaintext,
            signingPk,
            encryptionPk,
            kek,
            argon2Salt,
            onboardingKdfParams,
            _sodium
        );
        offerSezamKeyDownload(backupBytes, username);

        // The approval wait signs challenges with these copies instead of
        // re-deriving and calling /recover (capability review run 49).
        const pollKeys = {
            signingSk: signingSk.slice(),
            encryptionSk: encryptionSk.slice(),
            kek: kek.slice(),
            kdf: { argon2_salt: bytesToHex(argon2Salt), argon2_params: onboardingKdfParams },
            userId: state.userId,
            encryptedKeypairHex: bytesToHex(encryptedWithNonce),
        };

        // Zeroize
        _sodium.memzero(signingSk);
        _sodium.memzero(encryptionSk);
        _sodium.memzero(keypairPlaintext);
        _sodium.memzero(kek);
        _sodium.memzero(authProof);

        document.getElementById('onboard-btn').disabled = true;
        document.getElementById('onboard-btn').textContent = t('onboard.done');

        // Start polling for admin approval
        await pollForApproval(username, pollKeys, statusEl, error);

    } catch (err) {
        error.textContent = err.message || t('error.registration_failed');
        error.classList.remove('hidden');
        statusEl.classList.add('hidden');
    } finally {
        spinner.classList.add('hidden');
    }
}

// ── Bootstrap (first admin setup) ──

function translatedStrengthLabel(score) {
    const keys = [
        'strength.very_weak',
        'strength.weak',
        'strength.moderate',
        'strength.strong',
        'strength.very_strong',
    ];
    return t(keys[score] || keys[0]);
}

function updateBootstrapPasswordStrength(password) {
    const container = document.getElementById('bootstrap-password-strength');
    const fill = document.getElementById('bootstrap-strength-fill');
    const label = document.getElementById('bootstrap-strength-label');
    const entropy = document.getElementById('bootstrap-strength-entropy');
    if (!container || !fill) return;

    if (!password) {
        container.classList.add('hidden');
        return;
    }
    container.classList.remove('hidden');
    const strength = estimateStrength(password);
    const colors = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#27ae60'];
    fill.style.width = Math.min(100, (strength.score + 1) * 20) + '%';
    fill.style.background = colors[strength.score] || colors[0];
    if (label) label.textContent = translatedStrengthLabel(strength.score);
    if (entropy) entropy.textContent = t('strength.bits', { bits: strength.entropy });
}

function validateBootstrapConfirmPassword() {
    const pw = document.getElementById('bootstrap-password')?.value || '';
    const confirm = document.getElementById('bootstrap-confirm')?.value || '';
    const confirmInput = document.getElementById('bootstrap-confirm');
    if (confirmInput && confirm && pw !== confirm) {
        confirmInput.style.borderColor = '#e74c3c';
    } else if (confirmInput) {
        confirmInput.style.borderColor = '';
    }
}

async function handleBootstrap(e) {
    e.preventDefault();
    const username = normalizeUsername(document.getElementById('bootstrap-username').value);
    const password = document.getElementById('bootstrap-password').value;
    const confirm = document.getElementById('bootstrap-confirm').value;
    const spinner = document.getElementById('bootstrap-spinner');
    const error = document.getElementById('bootstrap-error');
    const statusEl = document.getElementById('bootstrap-status');

    if (!username) {
        error.textContent = t('error.username_required');
        error.classList.remove('hidden');
        return;
    }

    if (password !== confirm) {
        error.textContent = t('error.password_mismatch');
        error.classList.remove('hidden');
        return;
    }

    if (!meetsNewPasswordPolicy(password)) {
        error.textContent = t('error.password_policy');
        error.classList.remove('hidden');
        return;
    }

    spinner.classList.remove('hidden');
    error.classList.add('hidden');

    try {
        const _sodium = await ensureSodium();

        statusEl.textContent = t('status.generating_keypair');
        statusEl.classList.remove('hidden');

        // 1. Generate Ed25519 signing keypair
        const signingKeypair = _sodium.crypto_sign_keypair();
        const signingPk = signingKeypair.publicKey;
        const signingSk = signingKeypair.privateKey;

        // 2. Generate X25519 encryption keypair
        const encryptionKeypair = _sodium.crypto_box_keypair();
        const encryptionPk = encryptionKeypair.publicKey;
        const encryptionSk = encryptionKeypair.privateKey;

        // 3. Derive KEK from password using Argon2id. Lockout review #10:
        // done BEFORE the admin exists on the server, so the gap between
        // bootstrap and keypair upload (private key only in memory) is a
        // single local wrap instead of seconds of Argon2 plus a fetch.
        statusEl.textContent = t('status.deriving_key');
        const argon2Salt = _sodium.randombytes_buf(16);
        const authSalt = _sodium.randombytes_buf(16);
        const meta = await apiFetch('/api/meta');
        const bootstrapKdfParams = normalizeKdfParams(meta.argon2_web_params);
        const derivedKey = await deriveKEK(password, argon2Salt, bootstrapKdfParams);
        const kek = derivedKey.subarray(0, 32);
        const authProof = derivedKey.subarray(32, 64);

        // 4. Bootstrap — create first admin on server
        statusEl.textContent = t('status.creating_admin');
        const resp = await apiFetch('/api/bootstrap', {
            method: 'POST',
            body: {
                username: username,
                signing_pk: bytesToHex(signingPk),
                encryption_pk: bytesToHex(encryptionPk),
            },
        });

        state.token = resp.token;
        state.userId = resp.user_id;
        state.isAdmin = true;

        // 5. Encrypt keypair with KEK using AEAD envelope format (blob_kind=7, KEYPAIR_WRAP)
        statusEl.textContent = t('status.encrypting_keypair');
        const keypairPlaintext = new Uint8Array(signingSk.length + encryptionSk.length);
        keypairPlaintext.set(signingSk, 0);
        keypairPlaintext.set(encryptionSk, signingSk.length);

        const encryptedWithNonce = encryptKeypairWrap(
            keypairPlaintext, kek, generateULID(), state.userId, _sodium
        );

        // 6. Upload encrypted keypair
        statusEl.textContent = t('status.uploading_keypair');
        await apiFetch('/api/me/keypair', {
            method: 'PUT',
            body: {
                encrypted_keypair: bytesToHex(encryptedWithNonce),
                argon2_salt: bytesToHex(argon2Salt),
                auth_salt: bytesToHex(authSalt),
                auth_proof: bytesToHex(authProof),
                argon2_params: bootstrapKdfParams,
            },
        });

        // 7. Save to IndexedDB
        await saveToIndexedDB({
            username: username,
            user_id: state.userId,
            signing_pk: bytesToHex(signingPk),
            encryption_pk: bytesToHex(encryptionPk),
            encrypted_keypair: bytesToHex(encryptedWithNonce),
        });

        // 8. Set state for vault session
        state.keypair = {
            signingSk,
            signingPk,
            encryptionSk,
        };
        state.kek = kek;
        state.kdf = { argon2_salt: bytesToHex(argon2Salt), argon2_params: bootstrapKdfParams };
        state.username = username;

        // 9. Authenticate with challenge-response to get a full JWT
        statusEl.textContent = t('status.authenticating');
        const challengeResp = await apiFetch('/api/auth/challenge', {
            method: 'POST',
            body: { username: username },
        });
        const signature = signAuthChallenge(challengeResp.challenge, signingSk, _sodium);
        const authResp = await apiFetch('/api/auth/verify', {
            method: 'POST',
            body: {
                username: username,
                challenge: challengeResp.challenge,
                signature: bytesToHex(signature),
            },
        });

        state.token = authResp.token;
        state.userId = signedInUserId(authResp, state.userId);
        state.isAdmin = authResp.is_admin;
        await rememberWebKdfState(_sodium);

        // Start periodic JWT refresh
        startJwtRefreshTimer();

        // Zeroize sensitive material
        _sodium.memzero(keypairPlaintext);
        _sodium.memzero(authProof);

        // 10. Pull vault (empty) and show vault screen
        statusEl.textContent = t('status.loading_vault');
        await pullAndBuildTree();
        await renderUserInfoWithFingerprint(username);
        showScreen('vault-screen');

    } catch (err) {
        error.textContent = err.message || t('error.bootstrap_failed');
        error.classList.remove('hidden');
        statusEl.classList.add('hidden');
    } finally {
        spinner.classList.add('hidden');
    }
}

/**
 * Poll the server every 5 seconds to check if admin has approved the user.
 * On success, proceeds to the vault. Times out after 10 minutes.
 *
 * Approval is detected by signing a challenge with the keypair onboarding
 * still holds: /verify answers 401 while the account is pending and counts
 * nothing. Polling /recover instead charged every round to the address's
 * recovery limit, so after ~50 s the approved owner got 429 (capability
 * review run 49).
 */
async function pollForApproval(username, keys, statusEl, errorEl) {
    const POLL_INTERVAL = 5000;     // 5 seconds
    const POLL_TIMEOUT = 10 * 60 * 1000; // 10 minutes
    const startTime = Date.now();
    const _sodium = await ensureSodium();
    let handedOver = false;
    const wipeKeys = () => {
        if (handedOver) return;
        _sodium.memzero(keys.signingSk);
        _sodium.memzero(keys.encryptionSk);
        _sodium.memzero(keys.kek);
    };

    // Show waiting UI with spinner
    statusEl.innerHTML = `<span class="spinner-inline"></span> ${escapeHtml(t('approval.waiting'))}`;
    statusEl.classList.remove('hidden');

    // Add a cancel button
    const cancelBtn = document.createElement('button');
    cancelBtn.type = 'button';
    cancelBtn.className = 'modal-btn cancel';
    cancelBtn.style.marginTop = '12px';
    cancelBtn.textContent = t('common.dismiss');
    let cancelled = false;
    cancelBtn.addEventListener('click', () => {
        cancelled = true;
        cancelBtn.remove();
        statusEl.textContent = t('approval.dismissed');
    });
    statusEl.parentNode.insertBefore(cancelBtn, statusEl.nextSibling);

    try {
        while (!cancelled) {
            if (Date.now() - startTime > POLL_TIMEOUT) {
                cancelBtn.remove();
                statusEl.textContent = t('approval.timeout');
                return;
            }

            await new Promise(r => setTimeout(r, POLL_INTERVAL));
            if (cancelled) break;

            let authResp;
            try {
                const challengeResp = await apiFetch('/api/auth/challenge', {
                    method: 'POST',
                    body: { username },
                });
                const signature = signAuthChallenge(challengeResp.challenge, keys.signingSk, _sodium);
                authResp = await apiFetch('/api/auth/verify', {
                    method: 'POST',
                    body: {
                        username,
                        challenge: challengeResp.challenge,
                        signature: bytesToHex(signature),
                    },
                });
            } catch (pollErr) {
                if (pollErr && (pollErr.status === 401 || pollErr.status === 403)) {
                    continue; // still pending
                }
                if (pollErr && pollErr.status === 429) {
                    // Throttled: say so instead of waiting silently into a
                    // timeout, and back off before the next round.
                    errorEl.textContent = recoverFailureMessage(pollErr);
                    errorEl.classList.remove('hidden');
                    await new Promise(r => setTimeout(r, 60000));
                    continue;
                }
                console.debug('Approval poll: transient error:', pollErr && pollErr.message);
                continue;
            }

            const signingPk = keys.signingSk.slice(32, 64);
            state.keypair = {
                signingSk: keys.signingSk,
                signingPk,
                encryptionSk: keys.encryptionSk,
            };
            state.kek = keys.kek;
            state.kdf = keys.kdf;
            state.username = username;
            state.token = authResp.token;
            state.userId = signedInUserId(authResp, keys.userId);
            state.isAdmin = authResp.is_admin;
            await rememberWebKdfState(_sodium);
            handedOver = true;
            errorEl.classList.add('hidden');

            startJwtRefreshTimer();

            await saveToIndexedDB({
                username,
                user_id: keys.userId,
                encrypted_keypair: keys.encryptedKeypairHex,
            });

            cancelBtn.remove();
            statusEl.textContent = t('approval.approved');

            await pullAndBuildTree();
            await renderUserInfoWithFingerprint(username);
            showScreen('vault-screen');
            return;
        }
    } finally {
        wipeKeys();
    }
}

// ── Fingerprint display in header (spec 2.2) ──

/**
 * Render the current user's name + fingerprint identicon + abbreviated hex in the header.
 * Also fetches and displays the admin user list with fingerprints if admin.
 */
async function renderUserInfoWithFingerprint(username) {
    const userInfoEl = document.getElementById('user-info');
    if (!userInfoEl) return;

    // Show/hide audit button based on admin status
    const auditBtn = document.getElementById('audit-btn');
    if (auditBtn) {
        if (state.isAdmin) {
            auditBtn.classList.remove('hidden');
        } else {
            auditBtn.classList.add('hidden');
        }
    }

    if (state.keypair && state.keypair.signingPk) {
        try {
            // Derive encryption_pk from encryption_sk via crypto_scalarmult_base
            const _sodium = await ensureSodium();
            const encryptionPk = _sodium.crypto_scalarmult_base(state.keypair.encryptionSk);

            const fp = await displayFingerprint(state.keypair.signingPk, encryptionPk);
            const shortHex = fp.hex.slice(0, 8) + '...' + fp.hex.slice(-4);
            userInfoEl.innerHTML = `${fp.identicon} <span class="username-text">${escapeHtml(username)}</span> <span class="fingerprint-hex" title="${fp.hex}&#10;${fp.words}">${shortHex}</span>`;
        } catch (err) {
            console.warn('Failed to compute fingerprint:', err);
            userInfoEl.textContent = username;
        }
    } else {
        userInfoEl.textContent = username;
    }
}

// ── Lock ──

function handleLock() {
    // Invalidate JWT on the server (best-effort, don't block on failure)
    if (state.token) {
        apiFetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    }
    resetSession();
    showScreen('login-screen');
    document.getElementById('password').value = '';
}

/**
 * Remove every trace of the unlocked session from the DOM: entry detail,
 * edit modal, Shamir shares / recovery dialogs and TOTP timers.
 */
function clearSensitiveDom() {
    _totpTimers.forEach(timer => clearInterval(timer));
    _totpTimers = [];

    state.teamTrustReview = null;
    document.getElementById('team-trust-form')?.reset();
    document.getElementById('team-trust-details')?.replaceChildren();
    document.getElementById('team-trust-error')?.replaceChildren();
    const staticModals = new Set(['entry-modal', 'delete-modal', 'team-trust-modal']);
    document.querySelectorAll('.modal-overlay').forEach(el => {
        if (staticModals.has(el.id)) el.classList.add('hidden');
        else el.remove();
    });
    document.getElementById('set-aside-banner')?.remove();  // holds a password field
    document.getElementById('entry-form')?.reset();
    for (const id of ['modal-fields-list', 'entry-tags', 'entry-fields', 'tree-container',
        'search-list', 'audit-table-body']) {
        document.getElementById(id)?.replaceChildren();
    }
    const entryName = document.getElementById('entry-name');
    if (entryName) entryName.textContent = '';
    const userInfo = document.getElementById('user-info');
    if (userInfo) userInfo.textContent = '';
    document.getElementById('entry-detail')?.classList.add('hidden');
    document.getElementById('no-selection')?.classList.remove('hidden');
    document.getElementById('search-results')?.classList.add('hidden');
    document.getElementById('audit-panel')?.classList.add('hidden');
    const search = document.getElementById('search-input');
    if (search) search.value = '';
}

/** The account key material was rotated on another device first. */
class KeyEpochChangedError extends Error {
    constructor() {
        super(t('error.key_epoch_changed'));
        this.name = 'KeyEpochChangedError';
    }
}

/** The server refused an interrupted org-recovery password change for good. */
class KekRotationRefusedError extends Error {
    constructor() {
        super(t('recovery.rotation_refused'));
        this.name = 'KekRotationRefusedError';
    }
}

function endSessionForKeyEpochChange() {
    endSessionWithMessage('error.key_epoch_changed');
}

function endSessionWithMessage(messageKey) {
    resetSession();
    showScreen('login-screen');
    const error = document.getElementById('login-error');
    if (error) {
        error.textContent = t(messageKey);
        error.classList.remove('hidden');
    }
}

// Review a159e97 (web): a lock does not wait for the sync lock, so a pull
// already under way went on into the next session. It reconciled the queue
// reset() had emptied and, once the same user signed in again, saved that
// empty queue over the offline changes in IndexedDB. Each session gets a
// serial (state.sessionSerial); a sync step of an ended session stops
// before it writes anything.
/** Wipe keys, decrypted vault data and DOM of the current (or a half-finished) session. */
function resetSession() {
    state.sessionSerial = (state.sessionSerial || 0) + 1;
    // Stop JWT refresh timer
    if (_jwtRefreshTimer) {
        clearInterval(_jwtRefreshTimer);
        _jwtRefreshTimer = null;
    }

    if (state.sodium && state.keypair) {
        try {
            if (state.keypair.signingSk) state.sodium.memzero(state.keypair.signingSk);
            if (state.keypair.encryptionSk) state.sodium.memzero(state.keypair.encryptionSk);
            if (state.kek) state.sodium.memzero(state.kek);
            // Best-effort zeroize DEK material
            for (const key of [...Object.values(state.deks), ...Object.values(state.supersededDeks || {})]) {
                try { state.sodium.memzero(key); } catch {}
            }
        } catch {}
    }
    state.token = null;
    state.kek = null;
    state.kdf = null;
    state.deks = {};
    state.supersededDeks = {};
    state.rootDekId = null;
    state.kekDekIds = [];
    state.tree = null;
    state.entries = {};
    state.allEntries = [];
    state.nodes = {};
    state.allNodes = [];
    state.selectedEntry = null;
    state.selectedFolderId = null;
    state.rootNodeId = null;
    state.keyEpoch = 0;
    state.keyMaterialHash = null;
    state.syncCheckpoint = null;
    state.syncCheckpointLoaded = false;
    state.syncObjects = null;
    state.heldBeforeRestore = null;
    state.fullPullHeld = null;
    state.teamLog = null;
    state.teamLogRefusal = null;
    state.teamLogDamaged = null;
    state.confirmedTeamGenesis = null;
    state.forgottenTeamGenesis = [];
    state.outbox = {};
    state.outboxOps = [];
    state.outboxSent = {};
    state.outboxBaseline = null;
    state.outboxLoaded = false;
    state.acceptedBases = {};
    state.syncConflicts = {};
    state.userKeys = {};
    state.userEncryptionKeys = {};
    state.retiredKeys = {};
    state.voucherKeys = {};
    state.keypair = null;
    state._mitmWarnings = null;
    state.userId = null;
    state.username = null;
    state.isAdmin = false;

    // Remove admin user list if present
    const adminList = document.getElementById('admin-user-list');
    if (adminList) adminList.remove();

    // Hide audit button
    const auditBtn = document.getElementById('audit-btn');
    if (auditBtn) auditBtn.classList.add('hidden');

    clearSensitiveDom();
}

// ── Vault operations ──

// The verified team log as the shared sync core reads it (core/src/reseal.rs):
// each folder's keys, oldest first, and the keys the log lets `userId` hold.
// With `keys`, only the folders that name one of them: the log names a key in
// one folder only, and the core's answer about a key reads that folder alone
// (review 8bc70f7 M8: each queued write sent every folder of the team).
function syncCoreTeam(team, userId, keys = null) {
    const TL = globalThis.SezamTeamLog;
    const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
    const folders = keys === null
        ? Object.entries(team.folders)
        : [...new Set(keys.filter(k => own(team.dekIndex, k)).map(k => team.dekIndex[k][0]))]
            .filter(folder => own(team.folders, folder)).map(folder => [folder, team.folders[folder]]);
    return {
        folders: Object.fromEntries(folders.map(([folder, gens]) => [folder, gens.map(g => g[0])])),
        may_hold: folders.flatMap(([, gens]) => gens.map(g => g[0])).filter(id => TL.mayHoldKey(team, userId, id)),
    };
}

// What a pulled object does to a queued write: the shared sync core decides
// (core/src/pull.rs, docs/SYNC_SINGLE_SOURCE.md 4b), as on the desktop and phone.
function syncCoreVersion(obj) {
    return {
        version: Number(obj.version),
        hash: obj.payload_hash || '',
        parent_ref: obj.parent_ref || null,
        is_deleted: !!obj.is_deleted,
    };
}

// R17-N1: a copy is the whole message its signer signed, not its payload
// alone: the version held served with another parent or as deleted is an
// equivocation, never the copy held. As the phone (pulledIsStale).
function heldCopyKey(obj) {
    if (!obj.payload_hash) return '';
    return [obj.object_type, obj.parent_ref || '', obj.target_user_id || '',
        obj.is_deleted ? 1 : 0, String(obj.payload_hash).toLowerCase()].join('|');
}

// Review c78fd19 (web): a delta pull took a folder or entry back to an older
// version than this browser held (or another copy of the version it held), so
// a server could serve an old, validly signed password again. The held copy
// stays, as on the desktop and the phone: the shared core decides
// (core/src/pull.rs against_held); only a tombstone the server collected
// below its GC floor may come back (stateful test SM8).
function webPulledIsStale(held, pulled, gcFloorSeq) {
    if (!held || !['node', 'entry'].includes(pulled.object_type)) return false;
    const seq = Number(held.commit_seq);
    const [decision] = globalThis.SezamSyncCore.call('against_held', {
        items: [{
            held: {
                version: Number(held.version),
                hash: heldCopyKey(held),
                is_deleted: !!held.is_deleted,
                queued: false,  // a queued write meets the copy in decide_pulled_batch
                commit_seq: Number.isSafeInteger(seq) ? seq : null,
            },
            pulled: { version: Number(pulled.version), hash: heldCopyKey(pulled) },
        }],
        gc_floor_seq: gcFloorSeq,
    });
    return decision === 'keep_held' || decision === 'equivocation';
}

// What this browser sent of an object while it waited in the queue (version,
// payload hash), as the desktop's object_sent_version: a pulled copy that is
// one of them is this browser's own earlier push whose reply was lost
// (review c78fd19, web: the edit after it was a conflict with itself). The
// last 8 per object.
function rememberWebSent(sent, obj) {
    if (!['node', 'entry'].includes(obj.object_type) || !obj.payload_hash) return sent;
    const mine = (sent[obj.id] || []).filter(([v, h]) => !(v === Number(obj.version) && h === obj.payload_hash));
    return { ...sent, [obj.id]: [...mine, [Number(obj.version), obj.payload_hash]].slice(-8) };
}

function webOwnEarlierPush(sent, pulled) {
    return (sent?.[pulled.id] || []).some(([v, h]) => v === Number(pulled.version) && h === pulled.payload_hash);
}

/**
 * A queued folder or entry an older version saved without its base (review
 * c78fd19, web): sent as a new object, the server refused it on every Retry.
 * The edit was made one version above the copy it changed, so the server's
 * copy one below it is that base.
 */
function withLegacyWebBase(localObject, serverObject) {
    if (localObject.base_version != null || !['node', 'entry'].includes(localObject.object_type) ||
            !serverObject.payload_hash || Number(serverObject.version) !== Number(localObject.version) - 1) {
        return localObject;
    }
    return {
        ...localObject,
        base_version: Number(serverObject.version), base_payload_hash: serverObject.payload_hash,
    };
}

function reconcileWebDirtyState(serverObjects, outbox, priorConflicts, sent) {
    const nextDirtyObjects = { ...(outbox || {}) };
    const nextConflicts = { ...(priorConflicts || {}) };
    const visibleObjects = new Map(serverObjects.map(obj => [obj.id, obj]));

    const met = serverObjects.filter(obj => nextDirtyObjects[obj.id]);
    for (const serverObject of met) {
        nextDirtyObjects[serverObject.id] = withLegacyWebBase(nextDirtyObjects[serverObject.id], serverObject);
    }
    const decisions = met.length ? globalThis.SezamSyncCore.call('decide_pulled_batch', {
        items: met.map(serverObject => {
            const localObject = nextDirtyObjects[serverObject.id];
            return {
                unsent: {
                    ...syncCoreVersion(localObject),
                    base: localObject.base_version == null ? null : {
                        version: Number(localObject.base_version),
                        hash: localObject.base_payload_hash || '',
                    },
                },
                pulled: { ...syncCoreVersion(serverObject), own_earlier_push: webOwnEarlierPush(sent, serverObject) },
            };
        }),
    }) : [];
    met.forEach((serverObject, i) => {
        if (decisions[i] === 'adopt_as_base') {
            // Its push landed and the reply was lost: the edit after it is a
            // change of that copy, and leaves with it as its base.
            nextDirtyObjects[serverObject.id] = {
                ...nextDirtyObjects[serverObject.id],
                base_version: Number(serverObject.version), base_payload_hash: serverObject.payload_hash,
            };
            delete nextConflicts[serverObject.id];
        } else if (decisions[i] === 'sent') {
            delete nextDirtyObjects[serverObject.id];
            delete nextConflicts[serverObject.id];
        } else if (decisions[i] === 'conflict') {
            nextConflicts[serverObject.id] = {
                local_object: nextDirtyObjects[serverObject.id],
                server_object: serverObject,
                detected_at: Date.now(),
            };
        }
        // keep_unsent: the change builds on this copy (or a newer one).
    });
    for (const localObject of Object.values(nextDirtyObjects)) {
        visibleObjects.set(localObject.id, localObject);
    }
    return {
        outbox: nextDirtyObjects,
        conflicts: nextConflicts,
        visibleObjects: [...visibleObjects.values()],
    };
}

function exportWebDirtyObjects(outbox) {
    const backup = {
        exported_at: new Date().toISOString(),
        reason: 'full_resync',
        objects: outbox,
    };
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `sezam_dirty_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
}

// The phone's limit for the same kind of file (unsent_changes.dart).
const MAX_UNSENT_IMPORT_CHARS = 64 * 1024 * 1024;
const UNSENT_SIGNED_FIELDS = ['id', 'object_type', 'parent_ref', 'target_user_id', 'is_deleted', 'version',
    'payload', 'payload_hash', 'signature'];

/**
 * Review c02cc47 R17-L: queue again what exportWebDirtyObjects saved (a forget
 * or a full resync). The file is not trusted: only a folder or item whose
 * signature is this account's current key and whose payload matches its hash
 * comes back (a delete, a share or a key never), and none queued or in a
 * conflict here. Its base is not signed: it counts only when it is the copy
 * this browser holds now; else the held copy and the import are a conflict
 * the user settles. The push then sends it under today's rules (the log, the
 * folder's key, the server's copy). Call with the sync lock held.
 */
async function importWebUnsentChangesLocked(text, _sodium) {
    if (text.length > MAX_UNSENT_IMPORT_CHARS) throw new Error(t('sync.import_unsent_too_large'));
    let backup = null;
    try { backup = JSON.parse(text); } catch { /* named below */ }
    if (!Array.isArray(backup?.objects)) throw new Error(t('sync.import_unsent_not_export'));
    const outbox = { ...state.outbox }, conflicts = { ...state.syncConflicts };
    let queued = 0, conflicted = 0, skipped = 0;
    for (const raw of backup.objects) {
        const object = raw && typeof raw === 'object' && typeof raw.id === 'string'
            ? Object.fromEntries(UNSENT_SIGNED_FIELDS.filter(k => Object.hasOwn(raw, k)).map(k => [k, raw[k]]))
            : null;
        const held = object && state.syncObjects?.[object.id];
        if (!object || !['node', 'entry'].includes(object.object_type) || object.is_deleted ||
                typeof object.payload !== 'string' || outbox[object.id] || conflicts[object.id] ||
                held?.payload_hash === object.payload_hash ||
                await sha256hexBytes(base64ToBytes(object.payload)) !== object.payload_hash ||
                !state.keypair?.signingPk || !verifyObjectSignature(object, state.keypair.signingPk, _sodium)) {
            skipped++;
            continue;
        }
        const base = held && !held.is_deleted ? { version: Number(held.version), payload_hash: held.payload_hash } : null;
        if (!base || (Number(raw.base_version) === base.version && raw.base_payload_hash === base.payload_hash)) {
            outbox[object.id] = base ? { ...object, base_version: base.version, base_payload_hash: base.payload_hash }
                : object;
            queued++;
        } else {
            conflicts[object.id] = {
                local_object: object,
                server_object: { id: object.id, version: base.version, payload_hash: base.payload_hash },
                detected_at: Date.now(),
            };
            conflicted++;
        }
    }
    if (queued || conflicted) {
        await saveWebDirtyState(outbox, conflicts, _sodium);
        state.outbox = outbox;
        state.syncConflicts = conflicts;
    }
    return { queued, conflicted, skipped };
}

async function handleImportUnsentFile(event) {
    const file = event.target.files?.[0];
    event.target.value = '';
    const result = document.getElementById('import-unsent-result');
    if (!file || !result) return;
    result.classList.remove('hidden');
    try {
        if (file.size > MAX_UNSENT_IMPORT_CHARS) throw new Error(t('sync.import_unsent_too_large'));
        const _sodium = await ensureSodium();
        const text = await file.text();
        const counts = await withWebSyncLock(() => importWebUnsentChangesLocked(text, _sodium));
        result.textContent = t('sync.import_unsent_done', counts);
        renderWebSyncConflicts();
    } catch (err) {
        result.textContent = err.message;
    }
}

async function confirmWebFullResync() {
    const outbox = Object.values(state.outbox || {});
    const warning = outbox.length
        ? t('sync.full_resync_dirty', { count: outbox.length })
        : t('sync.full_resync_clean');
    if (!window.confirm(warning)) {
        throw new Error(t('sync.full_resync_cancelled'));
    }
    if (outbox.length) exportWebDirtyObjects(outbox);
}

function parseCanonicalAuditRecord(syncObject) {
    let parsed;
    try {
        parsed = globalThis.SezamSyncCore.call('audit_parse', {
            id: syncObject.id, version: syncObject.version, is_deleted: !!syncObject.is_deleted,
            payload: bytesToHex(base64ToBytes(syncObject.payload || '')),
        });
    } catch (e) {
        throw new Error(`REJECT audit ${syncObject.id} — ${e.message}`);
    }
    return {
        id: syncObject.id,
        actor_id: parsed.actor_id,
        action: parsed.action,
        timestamp: parsed.timestamp,
        parent_ids: parsed.parent_ids,
        encrypted_details_bytes: hexToBytes(parsed.encrypted_details),
        signature_bytes: hexToBytes(parsed.signature),
        // The signed bytes as the core read them: a JS number above 2**53
        // would not rebuild the timestamp exactly.
        message_bytes: hexToBytes(parsed.message),
    };
}

// The bytes the actor's key signs (docs/CORE_UNIFICATION.md U6d).
function buildAuditCanonical(record) {
    return hexToBytes(globalThis.SezamSyncCore.call('audit_message', {
        id: record.id, actor_id: record.actor_id, parent_ids: record.parent_ids,
        action: record.action, timestamp: record.timestamp,
        encrypted_details: bytesToHex(record.encrypted_details_bytes),
    }));
}

async function verifyAuditGraph(syncObjects, _sodium) {
    const records = {};
    for (const syncObject of Object.values(syncObjects || {})) {
        if (syncObject.object_type !== 'audit') continue;
        const record = parseCanonicalAuditRecord(syncObject);
        const signingPks = state.userKeys[record.actor_id] ||
            await getUserSigningPks(record.actor_id);
        if (!signingPks || !signingPks.some(signingPk =>
            _sodium.crypto_sign_verify_detached(
                record.signature_bytes, record.message_bytes, signingPk
            ))) {
            throw new Error(`REJECT audit ${syncObject.id} — invalid audit signature`);
        }
        records[syncObject.id] = record;
    }
    try {
        globalThis.SezamSyncCore.call('audit_dag', {
            records: Object.values(records).map(r => ({ id: r.id, parent_ids: r.parent_ids })),
        });
    } catch (e) {
        throw new Error(`REJECT audit DAG — ${e.message}`);
    }
}

// Review 7c10379 (R7-H, web; the mobile lock of review d615826): pulls and
// the queue's read-modify-writes ran interleaved with each other and with
// pushes in one page. A pull answered after a later one went to the
// server's older seq and raised a false ROLLBACK DETECTED, and a pull wrote
// back the queue it had read before an edit was queued offline: the edit
// was gone, also after a reload. These now run alone (withWebSyncLock).
// Pushes only change the live queue in place and may overlap each other
// (review 526419e #2), not a pull (withWebSyncShared). The *Locked
// functions expect the lock held: the pull's own steps call them.
let webSyncTail = Promise.resolve();
const webSyncSharedRuns = new Set();

function withWebSyncLock(op) {
    const shared = [...webSyncSharedRuns];
    const run = webSyncTail.then(() => Promise.allSettled(shared)).then(() => op());
    webSyncTail = run.then(() => {}, () => {});
    return run;
}

function withWebSyncShared(op) {
    const run = webSyncTail.then(() => op());
    const settled = run.then(() => {}, () => {});
    webSyncSharedRuns.add(settled);
    settled.then(() => webSyncSharedRuns.delete(settled));
    return run;
}

function pullAndBuildTree() {
    return withWebSyncLock(pullAndBuildTreeLocked);
}

async function pullAndBuildTreeLocked(session = state.sessionSerial) {
    const _sodium = await ensureSodium();
    if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
    if (!state.syncCheckpointLoaded || !state.outboxLoaded) await loadWebLocalStateLocked(session, _sodium);
    // The web client keeps its ciphertext snapshot in memory. After a reload it
    // must reconstruct the complete snapshot before a persisted checkpoint can
    // be verified; only then are delta pulls safe.
    // The shared sync core (vendor/sezam-sync-core.js) makes the decisions below.
    await globalThis.SezamSyncCore.ready;
    const sinceSeq = state.syncObjects === null ? 0 : (state.syncCheckpoint?.last_sync_seq || 0);
    let isFullPull = sinceSeq === 0;

    // SM71 (as the desktop's SM7): the token of the last commit this browser
    // saw tells whether a restored server handed that commit_seq out again.
    // SM75: a full pull too (after "Use the server's version" or a reload);
    // it took the restored history as it was, and what only this browser
    // had sent was gone without the question.
    const checkSeq = state.syncCheckpoint?.last_sync_seq || 0;
    const checkToken = checkSeq > 0 && (isFullPull || checkSeq === sinceSeq)
        ? state.syncCheckpoint.commit_token || null : null;
    const checkQuery = checkToken ? `&check_seq=${checkSeq}&check_token=${checkToken}` : '';

    let data;
    try {
        // No ETag (sync redesign S2): the checkpoint is the only pull state.
        data = await apiFetch(`/api/sync?since_commit_seq=${sinceSeq}${checkQuery}`);
    } catch (err) {
        // W2: Handle 410 Gone — server compacted past our checkpoint, full resync
        if (err.message && err.message.includes('410')) {
            console.warn('Server returned 410 Gone — explicit full resync is required');
            await confirmWebFullResync();
            isFullPull = true;
            data = await apiFetch(`/api/sync?since_commit_seq=0&full_resync=true${checkQuery}`);
        } else {
            throw err;
        }
    }

    if (!data || !Array.isArray(data.objects)) {
        throw new Error('Invalid sync response');
    }
    // May the reply be applied: the shared sync core decides (core/src/gate.rs).
    const replyHead = Number(data.head_commit_seq);
    const gate = globalThis.SezamSyncCore.call('gate', {
        checkpoint: { seq: checkSeq, anchor_token: checkToken },
        // A 410 was turned into a confirmed full pull above; a rollback is
        // asked about at once below, never left pending in this browser.
        reply: {
            gone: false,
            head_commit_seq: Number.isSafeInteger(replyHead) ? replyHead : null,
            check_token: data.check_token ?? null,
        },
        rollback_pending: false,
    }).gate;
    const restoredDetail = gate === 'reissued'
        ? `ROLLBACK DETECTED: the server no longer holds commit ${checkSeq} as this browser saw it`
        : gate === 'head_behind' ? `ROLLBACK DETECTED: server seq ${replyHead} < stored ${checkSeq}` : null;
    if (restoredDetail && !isFullPull) {
        // CI 44293105454: a restored server's delta is not on top of this
        // browser's history. Its audit records hang off parents only the
        // restored history holds, so the DAG check refused it ("missing
        // parent") before the rollback below was ever asked about.
        const detail = restoredDetail;
        if (!window.confirm(t('sync.rollback_confirm', { detail }))) {
            throw new Error(`${detail}. ${t('sync.rollback_cancelled')}`);
        }
        state.syncCheckpoint = null;
        state.heldBeforeRestore = state.syncObjects;
        state.fullPullHeld = null;  // the user takes the restored server's state
        state.syncObjects = null;
        return pullAndBuildTreeLocked(session);
    }

    const pagedObjects = [...data.objects];
    let previousCursor = sinceSeq;
    while (data.has_more === true) {
        const nextCursor = Number(data.next_cursor);
        const pageMax = Number(data.max_commit_seq);
        if (!Number.isSafeInteger(nextCursor) || nextCursor <= previousCursor || nextCursor !== pageMax) {
            throw new Error('Invalid continuation cursor in sync response');
        }
        previousCursor = nextCursor;
        const baseQuery = isFullPull
            ? 'since_commit_seq=0&full_resync=true'
            : `since_commit_seq=${sinceSeq}`;
        data = await apiFetch(`/api/sync?${baseQuery}&cursor=${nextCursor}`);
        if (!data || !Array.isArray(data.objects)) {
            throw new Error('Invalid continuation page in sync response');
        }
        pagedObjects.push(...data.objects);
    }
    data.objects = pagedObjects;
    // Review 1141a20 (R9-G): the last page's head, as on the desktop. Objects
    // of a later page can need log records the first page's head has not
    // reached yet (a team folder shared while the pages were fetched).
    const teamLogHead = data.team_log_head || null;

    const responseSeq = Number(data.max_commit_seq ?? sinceSeq);
    if (!Number.isSafeInteger(responseSeq) || responseSeq < 0) {
        throw new Error('Invalid max_commit_seq in sync response');
    }
    const responseKeyEpoch = Number(data.key_epoch ?? state.keyEpoch);
    if (!Number.isSafeInteger(responseKeyEpoch) || responseKeyEpoch < state.keyEpoch) {
        throw new Error('Invalid or rolled-back key_epoch in sync response');
    }
    // Stateful test SM80: a server restored from a backup forgot a key change
    // this session signed in after, and another device's change then took the
    // same epoch again: the epoch matches, the key material does not.
    // A full pull later in the session (Use the server's version, an accepted
    // restore) starts from syncObjects = null too: only a login's first pull
    // has seen no key material yet.
    const responseKeyHash = typeof data.key_material_hash === 'string' ? data.key_material_hash : null;
    const sessionPulled = state.syncObjects !== null || state.keyMaterialHash != null;
    if (sessionPulled && (responseKeyEpoch > state.keyEpoch || (
        responseKeyHash && state.keyMaterialHash && responseKeyHash !== state.keyMaterialHash
    ))) {
        // Another device rotated the account KEK during this session: its
        // DEKs no longer open with our KEK. A new login derives the new one.
        endSessionForKeyEpochChange();
        throw new Error(t('error.key_epoch_changed'));
    }

    // Separate objects by type
    const nodeObjs = [];
    const entryObjs = [];
    const dekObjs = [];
    const envelopeObjs = [];

    for (const obj of data.objects) {
        if (obj.is_deleted) continue; // skip deleted objects
        switch (obj.object_type) {
            case 'node': nodeObjs.push(obj); break;
            case 'entry': entryObjs.push(obj); break;
            case 'dek': dekObjs.push(obj); break;
            case 'envelope': envelopeObjs.push(obj); break;
        }
    }

    // Step 0: populate trusted key rings for every latest-version signer.
    const signerIds = new Set();
    for (const obj of data.objects) {
        const signerId = obj.signature_user_id || obj.owner_id;
        if (signerId) signerIds.add(signerId);
    }
    // R15-P4 rule 1: keys that did not come (no answer, a 5xx, none served)
    // withhold that signer's objects from this pull and refuse the team for it,
    // never the vault: this account's own key is the one its password opened.
    const signerKeys = new Map();
    const unreachableSigners = [];
    for (const signerId of signerIds) {
        let keys = await getUserSigningPks(signerId);
        if (!keys) {
            unreachableSigners.push(signerId);
            if (signerId === state.userId && state.keypair?.signingPk) keys = [state.keypair.signingPk];
        }
        if (keys) signerKeys.set(signerId, keys);
    }

    // The log this pull brings decides which keys it retired (capability run
    // 294), as on the desktop: a fresh session holds no log of its own yet.
    // INV-7: a log this browser refuses refuses the team, never the vault:
    // the personal tree opens, no team key does, and the refusal names its
    // way out. A damaged anchor is named first; the log is still fetched
    // under the checkpoint's pin for the founder to be confirmed again.
    let teamLog = null;
    let teamLogRefusal = webLocalTeamLogRefusal();
    if (!teamLogRefusal || teamLogRefusal.teamLogCause === 'local_damaged') {
        try {
            teamLog = await syncWebTeamLog(
                teamLogHead, state.teamLog || null, state.syncCheckpoint?.team_log || null, _sodium);
        } catch (err) {
            // R15-P4 rule 1: a log that did not come (no answer, a 5xx) refuses
            // the team for this pull, never the vault: a sign-in opens the
            // personal tree, and it is no mismatch, so nothing offers a forget.
            teamLogRefusal ||= err.teamLogCause ? err : teamLogUnreachable(`The team log (${err.message || err})`);
        }
    }
    if (unreachableSigners.length && !teamLogRefusal) {
        teamLogRefusal = teamLogUnreachable(`The keys of ${unreachableSigners.join(', ')}`);
    }
    if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
    if (teamLogRefusal && teamLogRefusal.teamLogCause !== 'unreachable' &&
            teamLogRefusal.message !== state.teamLogRefusal?.message) alert(teamLogRefusal.message);
    if (state.teamLogRefusal && !teamLogRefusal && !isFullPull) {
        // The refused pulls dropped the team keys and a delta pull does not
        // resend their envelopes: once the team's log is served again, all is pulled.
        state.teamLogRefusal = null;
        state.fullPullHeld = state.syncObjects;  // M7: the full pull meets what was held
        state.syncObjects = null;
        return pullAndBuildTreeLocked(session);
    }
    state.teamLogRefusal = teamLogRefusal;
    const teamUsable = teamLogRefusal ? null : teamLog;
    // Review c02cc47 R17-L: an admin's voucher list counts only by a log this
    // browser trusts (§7), as the desktop's admins_by_log; a served or refused
    // log's admins were any keys the server named.
    const voucherTeam = webTeamLogTrusted(_sodium, teamLog, teamLogRefusal) ? teamLog.team : null;

    // Verify every object before applying any of the response; abort on any invalid object
    const verifiedObjects = [];
    const vouchedBySigner = new Map();
    let withheld = 0;
    for (const obj of data.objects) {
        // Fail-closed (spec §8.2 pull 3a/4): every object MUST carry a valid
        // Ed25519 signature from a known owner. Missing signature, missing owner,
        // or missing/unknown signing key => REJECT (do not apply). A compromised
        // server must not be able to fabricate or delete objects unsigned.
        const sigHex = obj.client_signature || obj.signature;
        const signerId = obj.signature_user_id || obj.owner_id;
        if (!sigHex || !signerId) {
            throw new Error(`REJECT object ${obj.id} — missing signature or signer (fail-closed)`);
        }
        const sigPks = signerKeys.get(signerId);
        if (!sigPks) {  // withheld this pull (the team is refused above); never applied
            withheld++;
            continue;
        }
        if (sigPks.length === 0) {
            throw new Error(`REJECT object ${obj.id} — no signing key for signer ${signerId} (fail-closed)`);
        }
        const payloadBytes = base64ToBytes(obj.payload || '');
        const actualPayloadHash = bytesToHex(_sodium.crypto_hash_sha256(payloadBytes));
        if (actualPayloadHash !== String(obj.payload_hash || '').toLowerCase()) {
            throw new Error(`REJECT object ${obj.id} — payload_hash does not match ciphertext`);
        }
        const retired = state.retiredKeys[signerId] || new Set();
        const vouches = async sigPk => {
            const pkHex = bytesToHex(sigPk);
            if (!retired.has(pkHex)) {
                // Capability run 294: a key the log retired for this member is
                // no current key, whatever a (restored) server says.
                return !globalThis.SezamTeamLog.signingKeyRetired(teamLog?.team, signerId, pkHex);
            }
            // Goal #443: a retired key vouches only for what a voucher list
            // names, not for whatever the server dates before its rotation
            // (retired_seq, commit_seq): a list of the signer's current key,
            // of this account's key (its desktop or phone posts the versions it holds;
            // the web holds none and posts none)
            // or of a current admin of the verified log, so that an account
            // that rotated before #443 and never syncs again is still read
            // (capability review run 480).
            if (!vouchedBySigner.has(signerId)) {
                const team = voucherTeam;
                const posters = [[signerId, state.voucherKeys[signerId]]];
                if (state.keypair?.signingPk) posters.push([state.userId, bytesToHex(state.keypair.signingPk)]);
                for (const [uid, member] of Object.entries(team?.members || {})) {
                    if (globalThis.SezamTeamLog.isAdmin(team, uid) && member.signingPk) {
                        posters.push([uid, member.signingPk]);
                    }
                }
                const out = new Set();
                for (const [poster, keyHex] of posters) {
                    for (const key of await fetchVouchedEntries(poster, keyHex, _sodium)) out.add(key);
                }
                vouchedBySigner.set(signerId, out);
            }
            // R17-N1: the entry names the whole signed message, signer and key.
            const entry = keyVoucherObjectEntry(obj, signerId, sigPk, _sodium);
            return !!entry && vouchedBySigner.get(signerId).has(keyVoucherKey(...entry));
        };
        let verified = false;
        for (const sigPk of sigPks) {
            if (await vouches(sigPk) && verifyObjectSignature(obj, sigPk, _sodium)) {
                verified = true;
                break;
            }
        }
        if (!verified) {
            throw new Error(`REJECT object ${obj.id} — invalid Ed25519 signature from signer ${signerId}`);
        }
        verifiedObjects.push(obj);
    }
    // Review 8bc70f7 M7: a full pull (Use the server's version, a 410, the
    // team log served again) took an older copy than the one held here: it
    // started from nothing. It meets what this page held as a delta pull
    // does; only a restore the user accepted takes the server's state.
    const heldCopies = isFullPull ? (restoredDetail ? null : state.syncObjects || state.fullPullHeld) : state.syncObjects;
    const keptHeld = {};
    if (heldCopies) {
        const gcFloor = Number(data.gc_floor_seq);
        const gcFloorSeq = Number.isSafeInteger(gcFloor) ? gcFloor : 0;
        for (let i = verifiedObjects.length - 1; i >= 0; i--) {
            const obj = verifiedObjects[i];
            const held = heldCopies[obj.id];
            // A queued change meets every copy in the shared core's decision.
            if (!state.outbox[obj.id] && webPulledIsStale(held, obj, gcFloorSeq)) {
                console.warn(`Kept ${obj.id} v${held.version}: the server sent v${obj.version}`);
                if (isFullPull) {
                    keptHeld[obj.id] = held;  // decrypted below as the copy held
                    verifiedObjects[i] = held;
                } else {
                    verifiedObjects.splice(i, 1);
                }
            }
        }
    }

    const reconciledDirtyState = reconcileWebDirtyState(
        verifiedObjects, state.outbox, state.syncConflicts, state.outboxSent
    );

    // Re-separate verified objects by type
    nodeObjs.length = 0;
    entryObjs.length = 0;
    dekObjs.length = 0;
    envelopeObjs.length = 0;
    for (const obj of reconciledDirtyState.visibleObjects) {
        if (obj.is_deleted) continue;
        switch (obj.object_type) {
            case 'node': nodeObjs.push(obj); break;
            case 'entry': entryObjs.push(obj); break;
            case 'dek': dekObjs.push(obj); break;
            case 'envelope': envelopeObjs.push(obj); break;
        }
    }

    // Build the candidate ciphertext state without mutating the trusted snapshot.
    // Tombstones, DEKs, envelopes, archives and audit objects all remain covered.
    const candidateSyncObjects = isFullPull ? {} : { ...(state.syncObjects || {}) };
    for (const obj of verifiedObjects) {
        candidateSyncObjects[obj.id] = syncObjectRecord(obj);
    }
    Object.assign(candidateSyncObjects, keptHeld);  // the record as held (its verified signer)
    await verifyAuditGraph(candidateSyncObjects, _sodium);
    const stateHash = await computeWebStateHash(candidateSyncObjects, _sodium);
    const liveStateHash = await computeWebStateHash(liveSyncObjects(candidateSyncObjects), _sodium);
    // R17-N1: a checkpoint from before state_v 2 is compared by its formula.
    const legacy = state.syncCheckpoint && state.syncCheckpoint.state_v !== 2 ? {
        stateHash: await computeWebStateHash(candidateSyncObjects, _sodium, true),
        liveStateHash: await computeWebStateHash(liveSyncObjects(candidateSyncObjects), _sodium, true),
    } : null;
    const pulledSeqs = {
        responseSeq,
        headSeq: Number(data.head_commit_seq),
        gcFloor: Number(data.gc_floor_seq),
        stateHash,
        liveStateHash,
        legacy,
        // Capability run 465: objects held back for a signer whose keys did
        // not come make this state differ from the server's without the
        // server changing anything; a lower seq is still a rollback.
        served: withheld === 0,
    };
    try {
        if (restoredDetail) throw new Error(restoredDetail);
        checkPulledStateAgainstCheckpoint(state.syncCheckpoint, pulledSeqs);
    } catch (err) {
        // Stateful test SM71: after a server restore from a backup every
        // later sign-in in this browser failed here, with no way out. As
        // with 'sezam pull --full-resync', the user may accept the server's
        // state as it is now; the full pull below is verified as usual.
        if (!/^(ROLLBACK DETECTED|STATE MISMATCH)/.test(err.message || '')) throw err;
        if (!window.confirm(t('sync.rollback_confirm', { detail: err.message }))) {
            throw new Error(`${err.message}. ${t('sync.rollback_cancelled')}`);
        }
        state.syncCheckpoint = null;
        const priorHeld = state.syncObjects || state.fullPullHeld;
        if (priorHeld) state.heldBeforeRestore = priorHeld;
        state.fullPullHeld = null;  // M7: an accepted restore takes the server's state
        if (!isFullPull || Object.keys(keptHeld).length) {
            state.syncObjects = null;
            return pullAndBuildTreeLocked(session);
        }
    }
    const syncPosition = syncPositionAfter(isFullPull ? 0 : sinceSeq, pulledSeqs);

    // Stage all decrypted state so a full snapshot replaces local state only
    // after every object and the authenticated checkpoint have been accepted.
    const candidateDeks = isFullPull ? {} : { ...state.deks };
    // DEKs our own KEK opens: only these can be the root DEK we write with.
    const kekDekIds = new Set(isFullPull ? [] : (state.kekDekIds || []));
    const TL = globalThis.SezamTeamLog;
    const trustedTeam = teamUsable && webTeamLogTrusted(_sodium, teamUsable);
    const refusedTeamKeys = new Set(Object.keys(teamLog?.team.dekIndex || {}).filter(id =>
        !trustedTeam || !TL.mayHoldKey(teamLog.team, state.userId, id)));
    for (const id of refusedTeamKeys) {
        delete candidateDeks[id];
        kekDekIds.delete(id);
    }
    // A team folder's earlier key this browser held (or its KEK opens), while
    // the log lets it hold the folder's current one: kept apart, only to seal
    // again under the current key what was queued under it
    // (resealUnderFolderSuccessor; conformance scenario
    // member_revoked_under_an_unsent_write: refused with the rest, the queued
    // write went out under the old key on every Retry). The shared core
    // decides, as on the desktop and phone (capability review run 365).
    const coreTeam = trustedTeam ? syncCoreTeam(teamLog.team, state.userId) : null;
    const supersededOk = id => !!coreTeam && refusedTeamKeys.has(id) &&
        globalThis.SezamSyncCore.call('may_open_superseded', { team: coreTeam, key: id });
    const candidateSuperseded = {};
    if (!isFullPull) {
        for (const id of refusedTeamKeys) {
            if (!supersededOk(id)) continue;
            const kept = state.supersededDeks?.[id];
            if (kept) candidateSuperseded[id] = kept;
            else if (state.deks[id]) candidateSuperseded[id] = new Uint8Array(state.deks[id]);
        }
    }

    // Step 1: Unwrap DEK objects into the candidate state. A legacy plaintext
    // DEK object is never trusted (review 2052248: anyone allowed to push a
    // DEK could name its own DEK the root and read what we encrypt next).
    for (const dekObj of dekObjs) {
        if (refusedTeamKeys.has(dekObj.id)) {
            if (supersededOk(dekObj.id)) {
                try {
                    const payloadBytes = base64ToBytes(dekObj.payload);
                    if (isEncryptedEnvelope(payloadBytes)) {
                        candidateSuperseded[dekObj.id] = unwrapDEK(
                            payloadBytes, state.kek, dekObj.id, dekObj.version, _sodium
                        );
                    }
                } catch {
                    // not this account's key (a member's envelope opens it)
                }
            }
            continue;
        }
        try {
            const payloadBytes = base64ToBytes(dekObj.payload);
            if (isEncryptedEnvelope(payloadBytes)) {
                const dekBytes = unwrapDEK(
                    payloadBytes, state.kek, dekObj.id, dekObj.version, _sodium
                );
                candidateDeks[dekObj.id] = dekBytes;
                kekDekIds.add(dekObj.id);
            }
        } catch (err) {
            console.warn('Failed to unwrap DEK', dekObj.id, err.message);
        }
    }

    // Step 1b: folder DEKs shared with this user arrive as authenticated
    // crypto_box envelopes from the (already signature-verified) envelope signer:
    // the folder tree's owner or this account only (review 7c10379 H3, #345).
    for (const envelope of teamLogRefusal ? [] : keyEnvelopesForUser(
        Object.values(candidateSyncObjects).filter(obj => obj.object_type === 'envelope' && !obj.is_deleted),
        candidateSyncObjects, state.userId, teamLog, _sodium)) {
        if (candidateDeks[envelope.parent_ref]) continue;
        try {
            candidateDeks[envelope.parent_ref] = openDekEnvelope(envelope, _sodium);
        } catch (err) {
            console.warn('Failed to open DEK envelope', envelope.id, err.message);
        }
    }

    // A log-only regrant can open a cached envelope; its ciphertext need not
    // appear in the delta again. Keep dirty local versions selected above.
    const visibleIds = new Set([...nodeObjs, ...entryObjs].map(obj => obj.id));
    for (const obj of Object.values(candidateSyncObjects)) {
        if (obj.is_deleted || visibleIds.has(obj.id) || !['node', 'entry'].includes(obj.object_type)) continue;
        const dekId = sealingDekId(obj);
        if (!candidateDeks[dekId] || state.deks[dekId]) continue;
        (obj.object_type === 'node' ? nodeObjs : entryObjs).push(obj);
    }

    // Step 2: Decrypt node and entry objects
    // INV-3 (review e443cbc): who wrote each copy is the account whose
    // signature verified above (syncObjectRecord), or this one for a change
    // still queued here; owner_id is the server's unsigned ACL owner.
    const verifiedSigner = obj => (reconciledDirtyState.outbox[obj.id]
        ? state.userId : candidateSyncObjects[obj.id]?.signer || null);
    const decryptedNodes = [];
    const decryptedEntries = [];
    // Review 18c300f R16-H2: what the sealed content says comes first and the
    // object's own fields after it. On 18c300f a member with write access in a
    // team folder pushed a node whose content said {"id": <the victim's
    // personal root>, "personal": true}; it took that root's place and what
    // the victim saved in its personal tree was sealed with the team key.
    const signedFields = obj => ({
        id: obj.id, parent_ref: obj.parent_ref, version: obj.version || 1, owner_id: obj.owner_id,
        signer: verifiedSigner(obj), write_policy: obj.write_policy || 'owner_only',
    });

    for (const obj of nodeObjs) {
        try {
            const payloadBytes = base64ToBytes(obj.payload);
            if (isEncryptedEnvelope(payloadBytes)) {
                // Extract DEK ID from envelope header (bytes 3..29)
                const nodeDekId = new TextDecoder().decode(payloadBytes.slice(3, 29)).replace(/\0/g, '');
                // New format: encrypted envelope
                const meta = decryptEnvelope(payloadBytes, obj.id, obj.version || 1, candidateDeks, _sodium,
                    BLOB_KIND.NODE_META);
                // A personal folder is this account's (signed by it, TL7) and
                // sealed with a key of its own (its KEK opens it), never one an
                // envelope gave: a teammate's node is no personal folder here.
                const isPersonal = !!(meta && meta.personal) && verifiedSigner(obj) === state.userId &&
                    kekDekIds.has(nodeDekId);
                decryptedNodes.push({ ...meta, ...signedFields(obj), personal: isPersonal, dekId: nodeDekId });
            } else {
                // Legacy format: plaintext base64 JSON (transition support)
                const payload = JSON.parse(atob(obj.payload));
                decryptedNodes.push({ ...payload, ...signedFields(obj), personal: false, dekId: undefined });
            }
        } catch (err) {
            console.warn('Failed to decrypt node', obj.id, err.message);
            // Node could not be decrypted — likely a personal folder of another user
            decryptedNodes.push({ id: obj.id, name: '(osobne \u2014 zasifrovane)', _undecryptable: true, parent_ref: obj.parent_ref, version: obj.version || 1, owner_id: obj.owner_id, signer: verifiedSigner(obj) });
        }
    }

    for (const obj of entryObjs) {
        try {
            const payloadBytes = base64ToBytes(obj.payload);
            if (isEncryptedEnvelope(payloadBytes)) {
                // Legacy single-envelope entry (pre-C6 web format): whole {name,tags,fields}
                // in one ENTRY_DATA blob. Read it directly for backward compatibility.
                const entryDekId = new TextDecoder().decode(payloadBytes.slice(3, 29)).replace(/\0/g, '');
                const decrypted = decryptEnvelope(payloadBytes, obj.id, obj.version || 1, candidateDeks, _sodium,
                    BLOB_KIND.ENTRY_DATA);
                decryptedEntries.push({ ...decrypted, ...signedFields(obj), dekId: entryDekId });
            } else if (payloadBytes.length >= 4 + 53 && payloadBytes[4] === ENVELOPE_ALG && payloadBytes[5] === SCHEMA_VERSION) {
                // Canonical two-envelope framing: u32be(meta_len) || meta_env || data_env
                const entryDekId = new TextDecoder().decode(payloadBytes.slice(7, 33)).replace(/\0/g, '');
                const decrypted = decryptEntryPayload(payloadBytes, obj.id, obj.version || 1, candidateDeks, _sodium);
                decryptedEntries.push({ ...decrypted, ...signedFields(obj), dekId: entryDekId });
            } else {
                // Legacy format: plaintext base64 JSON
                const payload = JSON.parse(atob(obj.payload));
                decryptedEntries.push({ ...payload, ...signedFields(obj), dekId: undefined });
            }
        } catch (err) {
            console.warn('Failed to decrypt entry', obj.id, err.message);
            decryptedEntries.push({
                id: obj.id, name: t('tree.encrypted_entry'), _undecryptable: true,
                fields: [], tags: [], parent_ref: obj.parent_ref, version: obj.version || 1,
                signer: verifiedSigner(obj),
            });
        }
    }

    // Merge into candidate maps. Full pull starts empty; delta pull clones the
    // trusted maps. Nothing user-visible is mutated before checkpoint commit.
    const candidateEntries = isFullPull ? {} : { ...state.entries };
    const candidateNodes = isFullPull ? {} : { ...state.nodes };
    for (const e of decryptedEntries) {
        candidateEntries[e.id] = e;
    }
    for (const n of decryptedNodes) {
        candidateNodes[n.id] = n;
    }

    for (const obj of reconciledDirtyState.visibleObjects) {
        if (obj.is_deleted) {
            delete candidateEntries[obj.id];
            delete candidateNodes[obj.id];
        }
    }
    const blockedWrites = unauthorizedWrites(
        candidateSyncObjects, state.userId, teamUsable?.team || null, state.syncObjects,
        teamUsable?.team ? webLogAdmins(teamUsable) : null);
    for (const id of blockedWrites) {
        delete candidateEntries[id];
        delete candidateNodes[id];
        // A change the team log refuses is not applied: what this browser
        // showed before stays (as on the desktop, which skips it).
        if (blockedWrites.byTeamLog.has(id)) {
            if (state.entries?.[id]) candidateEntries[id] = state.entries[id];
            if (state.nodes?.[id]) candidateNodes[id] = state.nodes[id];
        }
    }
    // INV-7: while the log is refused only this account's personal tree opens,
    // under its personal roots' own keys; every other key counts as a team key.
    const personalKeys = new Set();
    if (teamLogRefusal) {
        for (const id of refusedLogPersonalKeys(candidateNodes, candidateSyncObjects)) personalKeys.add(id);
        for (const id of Object.keys(candidateDeks)) {
            if (!personalKeys.has(id)) refusedTeamKeys.add(id);
        }
        for (const id of refusedTeamKeys) {
            delete candidateDeks[id];
            kekDekIds.delete(id);
        }
    }
    // A log-only delta can withdraw a key without sending the old ciphertext again.
    // Do not retain plaintext from the preceding authorized view in that case.
    for (const [objects, kind] of [[candidateEntries, 'entry'], [candidateNodes, 'node']]) {
        for (const [id, obj] of Object.entries(objects)) {
            if (!refusedTeamKeys.has(obj.dekId) && !(teamLogRefusal && !personalKeys.has(obj.dekId))) continue;
            objects[id] = { id, parent_ref: obj.parent_ref, version: obj.version,
                dekId: obj.dekId, _undecryptable: true,
                name: kind === 'entry' ? t('tree.encrypted_entry') : '(osobne — zasifrovane)' };
        }
    }
    const candidateAllEntries = Object.values(candidateEntries);
    const candidateAllNodes = Object.values(candidateNodes);
    const candidateRootDekId = selectRootDekId(
        candidateAllNodes, candidateSyncObjects, kekDekIds, candidateDeks, state.userId
    );

    // Commit the checkpoint last. IndexedDB/AEAD failure leaves both the trusted
    // checkpoint (the only pull state) unchanged, so this response will be retried.
    const nextCheckpoint = {
        last_sync_seq: syncPosition,
        state_hash: stateHash,
        state_v: 2,  // computeWebStateHash formula (sync_common.STATE_HASH_VERSION)
        live_state_hash: liveStateHash,
        commit_token: syncPosition === responseSeq && typeof data.max_token === 'string'
            ? data.max_token : null,
        // A refused log keeps the pin it is held to: no log a refused pull
        // saw becomes this browser's pin (its seq floor does, below).
        team_log: teamLogRefusal ? state.syncCheckpoint?.team_log || null : teamLogPin(teamLog?.team),
        timestamp: Date.now(),
    };
    if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
    await saveWebDirtyState(
        reconciledDirtyState.outbox, reconciledDirtyState.conflicts, _sodium
    );
    // Review e443cbc (INV-2): a refused pull moves the rollback floor too, or
    // a server restored between the last clean pull and this one is taken at
    // the next sign-in. The log's pin stays (above). With a signer's objects
    // withheld the hashes are of no server state: only the seq and the
    // commit token are kept (core check_state compares a missing hash as equal).
    await saveSyncCheckpoint(withheld
        ? { ...nextCheckpoint, state_hash: null, live_state_hash: null } : nextCheckpoint, _sodium);
    if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
    for (const id of refusedTeamKeys) {
        if (state.deks[id]) _sodium.memzero(state.deks[id]);
    }
    for (const [id, key] of Object.entries(state.supersededDeks || {})) {
        if (candidateSuperseded[id] !== key) _sodium.memzero(key);
    }
    state.deks = candidateDeks;
    state.supersededDeks = candidateSuperseded;
    state.rootDekId = candidateRootDekId;
    state.kekDekIds = [...kekDekIds];
    state.entries = candidateEntries;
    state.nodes = candidateNodes;
    if (refusedTeamKeys.has(state.selectedEntry?.dekId)) {
        renderEntry({ id: state.selectedEntry.id, name: '', fields: [] });
        state.selectedEntry = null;
        document.getElementById('entry-detail').classList.add('hidden');
        document.getElementById('no-selection').classList.remove('hidden');
    }
    state.allEntries = candidateAllEntries;
    state.allNodes = candidateAllNodes;
    state.syncObjects = candidateSyncObjects;
    state.fullPullHeld = null;
    for (const [id, base] of Object.entries(state.acceptedBases)) {
        if (Number(candidateSyncObjects[id]?.version) >= base.version) delete state.acceptedBases[id];
    }
    state.teamLog = teamLogRefusal?.teamLogCause === 'local_damaged' ? teamLog : teamUsable;
    // Capability run 465: a state with a signer's objects held back is no
    // state of the server's; the next pull is checked against the last one that was.
    if (!withheld) state.syncCheckpoint = nextCheckpoint;
    state.keyEpoch = responseKeyEpoch;
    if (responseKeyHash) state.keyMaterialHash = responseKeyHash;
    state.outbox = reconciledDirtyState.outbox;
    state.syncConflicts = reconciledDirtyState.conflicts;
    let requeued = 0;
    if (isFullPull && state.heldBeforeRestore) {
        const held = state.heldBeforeRestore;
        state.heldBeforeRestore = null;
        requeued = await requeueWritesTheServerLost(held, pulledSeqs.gcFloor, _sodium);
    }
    renderWebSyncConflicts();

    // Auto-create root folder if vault is empty (no nodes at all)
    if (state.allNodes.length === 0) {
        if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
        await createRootFolderLocked();
        return; // createRootFolderLocked pulls again
    }

    // Find/store root node id (the one with no parent). TL7: a personal root
    // is top-level too but never the root; one this account cannot open (the
    // org root of a member, or someone's personal root) only as a fallback,
    // the oldest first (the org root is made at bootstrap).
    const tops = state.allNodes.filter(n => !n.parent_ref && !n.personal)
        .sort((a, b) => (a._undecryptable ? 1 : 0) - (b._undecryptable ? 1 : 0) || (a.id < b.id ? -1 : 1));
    const rootNode = tops[0];
    if (rootNode) state.rootNodeId = rootNode.id;

    // Default folder selection to root
    if (!state.selectedFolderId && state.rootNodeId) {
        state.selectedFolderId = state.rootNodeId;
    }

    // TOFU must succeed before any newly pulled state is rendered.
    await performTOFUChecks();
    if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');

    // Repair descendants created by older web builds that encrypted only the
    // personal root itself. Each accepted object is versioned independently;
    // an interrupted migration safely resumes on the next pull.
    if (await migrateLegacyPersonalDescendants()) {
        await pullAndBuildTreeLocked(session);
        return;
    }
    if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
    if (await resealOwnWritesUnderSuccessors()) {
        await pullAndBuildTreeLocked(session);
        return;
    }
    if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
    if (await resealQueuedUnderSuccessors(_sodium)) {
        await pullAndBuildTreeLocked(session);
        return;
    }
    if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
    if (requeued) {
        // The tree above was built before they were queued again.
        await pullAndBuildTreeLocked(session);
        return;
    }
    if (await reviveFoldersOfUnsentWork(_sodium)) {
        await pullAndBuildTreeLocked(session);
        return;
    }
    if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
    if (await sealToRotatedMembers(_sodium, session)) {
        await pullAndBuildTreeLocked(session);
        return;
    }
    if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');

    // Build tree structure from merged state
    const tree = buildTree(state.allNodes, state.allEntries);
    state.tree = tree;
    renderTree(tree);
}

/**
 * What this browser keeps for the session (checkpoint, team log pins, the
 * queue), loaded once per session with the sync lock held. Review 8bc70f7 H4:
 * forgetting the pin at sign-in checks the queue before any pull loaded it.
 */
async function loadWebLocalStateLocked(session, _sodium) {
    const ended = () => {
        if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
    };
    if (!state.syncCheckpointLoaded) {
        // INV-7: an anchor this browser cannot open refuses the team
        // (local_damaged), never the sign-in; confirming the founder again
        // replaces it (saveConfirmedTeamGenesis).
        let confirmedGenesis = null, forgottenGenesis = [], damaged = null;
        try {
            confirmedGenesis = await loadConfirmedTeamGenesis(_sodium);
            forgottenGenesis = await loadForgottenTeamGenesis(_sodium);
            await loadWebTeamLedger(_sodium);
        } catch (err) {
            damaged = teamLogMismatch(`anchor held in this browser cannot be read (${err.message}); ` +
                'confirming the team\'s founder again (Team trust) replaces it', 'local_damaged');
        }
        ended();
        state.confirmedTeamGenesis = confirmedGenesis;
        state.forgottenTeamGenesis = forgottenGenesis;
        state.teamLogDamaged = damaged;
        state.syncCheckpoint = await loadSyncCheckpoint(_sodium);
        state.syncCheckpointLoaded = true;
    }
    if (!state.outboxLoaded) {
        let pending;
        try {
            pending = await loadWebDirtyState(_sodium);
        } catch {
            // Review 8595ec1 #5: a queue this KEK does not open (sealed by a
            // tab with an older one) is set aside, not an error for good.
            await setAsideRecordsOfOldKek(_sodium, false);
            pending = await loadWebDirtyState(_sodium);
            renderSetAsideWebChanges().catch(() => {});
        }
        if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
        state.outbox = pending.objects;
        state.outboxOps = pending.ops;
        state.syncConflicts = pending.conflicts;
        state.outboxSent = pending.sent;
        state.outboxBaseline = JSON.parse(JSON.stringify(pending));
        // S3 (docs/SYNC_SINGLE_SOURCE.md 3.7): the server copy's signer says
        // which writes are this account's; the old record of them goes.
        await idbKeysRequest('readwrite', store => store.delete(`sent_writes:${state.userId}`));
        state.outboxLoaded = true;
        await adoptLegacyWebRekeyJournals(_sodium);
    }
}

/**
 * Review 1141a20 H1 / goal #369, capability run 286 (desktop
 * _seal_to_rotated_members): a member cannot seal team keys, so after its
 * member.keys only envelopes on its retired encryption key exist. An admin
 * browser holding a folder's current key seals it to the member's new key
 * (the signed record names it) at the log's level. The marker moves only
 * after the server took the envelopes; an envelope this account already
 * sealed to that key (a desktop of the same account, a lost answer) counts.
 * Returns true when it pushed envelopes (the caller pulls again).
 */
async function sealToRotatedMembers(_sodium, session) {
    const TL = globalThis.SezamTeamLog;
    const teamLog = state.teamLog;
    if (!teamLog?.records?.length || !state.keypair?.encryptionSk) return false;
    const team = teamLog.team;
    const markerId = `rotation_sealed:${state.userId}:${team.genesisHash}`;
    const marker = await idbKeysRequest('readonly', store => store.get(markerId));
    const done = Number.isInteger(marker?.seq) ? marker.seq : -1;
    if (done >= team.headSeq) return false;
    // docs/CORE_UNIFICATION.md U7e: who gets an envelope, and whether the
    // marker moves, is the core's (core/src/teamlog/rotated.rs). A pending
    // re-key or revocation seals to the log's recipients itself.
    const plan = TL.rotatedSeals(
        team, done, teamLog.records.map(record => record.body), state.userId,
        webTeamLogTrusted(_sodium, teamLog), (await pendingWebRevocations()).length > 0, [], null,
    );
    const objects = [];
    const writeIds = [];
    for (const { dek_id: dekId, user_id: userId, encryption_pk: pkHex, level } of plan.seal) {
        const dek = state.deks[dekId];
        if (!(dek instanceof Uint8Array) || dek.length !== 32) continue;  // another admin holds it
        const recipientPk = hexToBytes(pkHex);
        const sealed = Object.values(state.syncObjects || {}).some(env => {
            if (env.object_type !== 'envelope' || env.is_deleted || env.parent_ref !== dekId ||
                    env.target_user_id !== userId || env.access_level !== level ||
                    (env.signer || env.owner_id) !== state.userId) return false;
            try {
                const blob = base64ToBytes(env.payload);
                const n = _sodium.crypto_box_NONCEBYTES;
                const opened = _sodium.crypto_box_open_easy(
                    blob.slice(n), blob.slice(0, n), recipientPk, state.keypair.encryptionSk
                );
                _sodium.memzero(opened);
                return true;
            } catch {
                return false;
            }
        });
        if (sealed) continue;
        const nonce = _sodium.randombytes_buf(_sodium.crypto_box_NONCEBYTES);
        const ciphertext = _sodium.crypto_box_easy(dek, nonce, recipientPk, state.keypair.encryptionSk);
        const encryptedDek = new Uint8Array(nonce.length + ciphertext.length);
        encryptedDek.set(nonce, 0);
        encryptedDek.set(ciphertext, nonce.length);
        const envelopeId = generateULID();
        objects.push(await buildSignedSyncObject(_sodium, {
            id: envelopeId, object_type: 'envelope', parent_ref: dekId,
            target_user_id: userId, access_level: level, version: 1,
        }, encryptedDek));
        if (level === 'write') writeIds.push(envelopeId);
    }
    if (objects.length) {
        if (writeIds.length) {
            // Recorded before the batch can land; an id that never does is unused.
            const vouched = await loadWebWriteGrants(_sodium);
            for (const id of writeIds) vouched.add(id);
            await saveWebWriteGrants(vouched, _sodium);
        }
        if (session !== state.sessionSerial) throw new Error('The session this sync started in has ended; nothing was saved');
        let response;
        try {
            response = await postAtomicSyncBatch(objects, { key_epoch: state.keyEpoch });
        } catch (err) {
            console.warn('Sealing team keys to a rotated member failed; retried on the next sync', err.message);
            return false;
        }
        const accepted = new Set((response?.accepted || []).map(item => item.id));
        if ((response?.conflicts || []).length || objects.some(obj => !accepted.has(obj.id))) {
            console.warn('The server refused envelopes for a rotated member; retried on the next sync');
            return false;
        }
    }
    if (plan.advance) {
        await idbKeysRequest('readwrite', store => store.put({ id: markerId, seq: team.headSeq }));
    }
    return objects.length > 0;
}

async function migrateLegacyPersonalDescendants() {
    let migrated = false;
    // Only the DEKs the old web build wrongly used below a personal root are
    // repaired. A tier-2 / share / personal / audit DEK is there on purpose.
    const keptScopes = new Set(['tier2', 'personal', 'share', 'audit']);
    const legacyDek = (dekId) => {
        const dekObj = (state.syncObjects || {})[dekId];
        return !(dekObj && keptScopes.has(dekObj.scope));
    };

    const repair = async (obj, objectType) => {
        // INV-3: only what this account signed, never what owner_id names.
        if (obj._undecryptable || obj.signer !== state.userId) return;
        let inheritedDekId;
        try {
            inheritedDekId = resolveInheritedPersonalDekId(obj.parent_ref);
        } catch {
            // Stateful test SM68: its folder was deleted elsewhere (or is
            // unreadable). Nothing to repair; throwing here stopped every pull.
            return;
        }
        const currentDekId = obj.dekId || state.rootDekId;
        if (!inheritedDekId || currentDekId === inheritedDekId || !legacyDek(currentDekId)) return;

        await pushVaultObjectLocked({
            id: obj.id,
            object_type: objectType,
            payloadData: storedPayload(obj),
            parent_ref: obj.parent_ref,
            version: (obj.version || 1) + 1,
            dekId: inheritedDekId,
            write_policy: obj.write_policy || 'owner_only',
        });
        migrated = true;
    };

    for (const node of state.allNodes) {
        if (!node.personal) await repair(node, 'node');
    }
    for (const entry of state.allEntries) {
        if (Number(entry.tier) !== 2) await repair(entry, 'entry');
    }

    return migrated;
}

// Keys the web adds to a decrypted object; never part of its encrypted payload.
const CLIENT_OBJECT_KEYS = new Set([
    'id', 'dekId', 'parent_ref', 'version', 'owner_id', 'signer', 'write_policy', '_undecryptable',
]);

function storedPayload(obj) {
    const payload = {};
    for (const [key, value] of Object.entries(obj)) {
        if (!CLIENT_OBJECT_KEYS.has(key)) payload[key] = value;
    }
    if (payload.personal !== true) delete payload.personal;
    return payload;
}

/**
 * Perform TOFU (Trust On First Use) key checks (spec 2.4).
 * Checks own keys, and if admin, fetches user list and checks all users' keys.
 * Shows MITM warning dialog on key change.
 */
async function performTOFUChecks() {
    // Check own keys. Any cache failure aborts the unlock/sync flow.
    if (state.userId && state.keypair && state.keypair.signingPk) {
        const _sodium = await ensureSodium();
        const encryptionPk = _sodium.crypto_scalarmult_base(state.keypair.encryptionSk);
        const ownSigningPkHex = bytesToHex(state.keypair.signingPk);
        const ownEncryptionPkHex = bytesToHex(encryptionPk);

        const ownResult = await checkKnownKey(state.userId, ownSigningPkHex, ownEncryptionPkHex);
        if (ownResult === 'changed') {
            showMITMWarning(state.username, state.userId, ownSigningPkHex, ownEncryptionPkHex);
        }
    }

    // Admin key-list failures must not silently skip peer pin verification.
    // INV-3: the server's is_admin only asks for its own admin list (which it
    // authorizes) to add these pin checks; no admin decision rests on it
    // (webIsAdmin), and every key sealed to a member is checked where fetched.
    if (state.isAdmin && state.token) {
        let users;
        try {
            users = await apiFetch('/api/users');
        } catch (err) {
            // INV-1: the server's team log says who the admin is. One this
            // browser refused can name another, and the refusal is the way
            // out to show (INV-7), not its "Admin required". Nothing is sealed
            // to a member under a refused log, so no peer pin is needed now.
            if (err.status === 403 && state.teamLogRefusal) return;
            // R15-P4 rule 1: a list that did not come (no answer, a 5xx) never
            // keeps the vault shut; the next pull asks again, and every key
            // sealed to a member is checked against its pin where it is fetched
            // (getUserSigningPks, getVerifiedEncryptionPkForRekey).
            if (!err.status || err.status >= 500) {
                console.warn('The user list did not come; the members\' keys are checked again on the next sync:', err);
                return;
            }
            throw err;
        }
        for (const user of users) {
            if (!user.signing_pk || !user.encryption_pk) continue;
            const result = await checkKnownKey(user.id, user.signing_pk, user.encryption_pk);
            if (result === 'changed') {
                showMITMWarning(user.username, user.id, user.signing_pk, user.encryption_pk);
            }
        }

        await renderAdminUserList(users);
    }
}

/**
 * Render admin user list with fingerprints in the tree panel (below the tree).
 */
/**
 * R15 #428 (INV-3): the user list's fingerprint is the pinned key's (TOFU)
 * or this device's own, never the server's unsigned signing_pk,
 * encryption_pk or key_fingerprint: an admin comparing it with the member's
 * saw the real one while the key sealed for was the server's.
 */
async function adminUserFingerprintHtml(user) {
    let keys = null;
    try {
        if (user.id === state.userId && state.keypair && state.keypair.signingPk) {
            const _sodium = await ensureSodium();
            keys = [state.keypair.signingPk, _sodium.crypto_scalarmult_base(state.keypair.encryptionSk)];
        } else {
            const pinned = await getKnownKey(user.id);
            if (pinned) keys = [hexToBytes(pinned.signing_pk), hexToBytes(pinned.encryption_pk)];
        }
        if (keys) {
            const fp = await displayFingerprint(keys[0], keys[1]);
            const shortHex = fp.hex.slice(0, 8) + '...' + fp.hex.slice(-4);
            return `<span class="admin-user-fp">${fp.identicon} <span class="fingerprint-hex" title="${fp.hex}&#10;${fp.words}">${shortHex}</span></span>`;
        }
    } catch (err) {
        console.warn('Fingerprint not shown:', err);
    }
    return `<span class="admin-user-fp">${escapeHtml(t('admin.not_pinned'))}</span>`;
}

async function renderAdminUserList(users) {
    // Only render if admin
    if (!state.isAdmin) return;

    // Remove existing user list if present
    const existing = document.getElementById('admin-user-list');
    if (existing) existing.remove();

    const container = document.createElement('div');
    container.id = 'admin-user-list';
    container.className = 'admin-user-list';

    // Title row with Invite button
    const titleRow = document.createElement('div');
    titleRow.className = 'admin-user-list-header';
    titleRow.innerHTML = `
        <h3 class="admin-user-list-title">${escapeHtml(t('admin.users'))}</h3>
        <button type="button" class="admin-action-btn admin-invite-btn" id="admin-invite-btn">${escapeHtml(t('admin.invite'))}</button>
        <button type="button" class="admin-action-btn admin-recovery-btn" id="admin-recovery-setup-btn" title="${escapeHtml(t('admin.org_recovery_title'))}">${escapeHtml(t('admin.org_recovery'))}</button>
    `;
    container.appendChild(titleRow);

    // Bind invite button
    titleRow.querySelector('#admin-invite-btn').addEventListener('click', handleInviteUser);
    titleRow.querySelector('#admin-recovery-setup-btn').addEventListener('click', openShamirSetupModal);

    for (const user of users) {
        const userEl = document.createElement('div');
        userEl.className = 'admin-user-item';

        const fpHtml = await adminUserFingerprintHtml(user);

        // Action buttons based on user status
        let actionsHtml = '';
        if (user.status === 'pending') {
            actionsHtml = `<button type="button" class="admin-action-btn admin-approve-btn" data-user-id="${escapeHtml(String(user.id))}">${escapeHtml(t('admin.approve'))}</button>`;
        } else if (user.status === 'active' && !user.is_admin) {
            actionsHtml = `<button type="button" class="admin-action-btn admin-revoke-btn" data-user-id="${escapeHtml(String(user.id))}" data-username="${escapeHtml(user.username)}">${escapeHtml(t('admin.revoke'))}</button>`;
        }

        const statusClass = user.status === 'active' ? 'status-active' : (user.status === 'pending' ? 'status-pending' : 'status-revoked');
        const statusLabel = t(`admin.status.${user.status}`);
        userEl.innerHTML = `
            <div class="admin-user-name">${escapeHtml(user.username)} ${user.is_admin ? `<span class="admin-badge">${escapeHtml(t('admin.badge'))}</span>` : ''}</div>
            <div class="admin-user-meta">
                <span class="user-status ${statusClass}">${escapeHtml(statusLabel)}</span>
                ${fpHtml}
                ${actionsHtml}
            </div>
        `;
        container.appendChild(userEl);
    }

    // Bind approve buttons
    container.querySelectorAll('.admin-approve-btn').forEach(btn => {
        btn.addEventListener('click', () => handleApproveUser(btn.dataset.userId));
    });

    // Bind revoke buttons
    container.querySelectorAll('.admin-revoke-btn').forEach(btn => {
        btn.addEventListener('click', () => handleRevokeUser(btn.dataset.userId, btn.dataset.username));
    });

    // Insert at bottom of tree panel
    const treePanel = document.getElementById('tree-panel');
    if (treePanel) treePanel.appendChild(container);
}

// ── Admin actions: Invite, Approve, Revoke ──

async function handleInviteUser() {
    try {
        const _sodium = await ensureSodium();
        if (state.teamLogRefusal) throw state.teamLogRefusal;
        if ((state.teamLog || state.confirmedTeamGenesis) && !webTeamLogTrusted(_sodium)) {
            throw teamLogRefusedError('the founder is not confirmed on this device');
        }
        const genesis = state.teamLog?.team.genesisHash || null;
        const resp = await apiFetch('/api/users/invite', { method: 'POST' });
        const token = resp.invitation_token || resp.token;
        if (!token) throw new Error('No invitation token returned');
        const inviteLink = `${window.location.origin}${window.location.pathname}?invite=${encodeURIComponent(token)}` +
            (genesis ? `#g=${genesis}` : '');
        showInviteModal(token, inviteLink);
    } catch (err) {
        alert(t('admin.invitation_failed', { error: err.message || err }));
    }
}

async function handleApproveUser(userId) {
    try {
        await apiFetch(`/api/users/${userId}/approve`, { method: 'PATCH' });
        // Refresh user list
        const users = await apiFetch('/api/users');
        await renderAdminUserList(users);
    } catch (err) {
        alert(t('admin.approval_failed', { error: err.message || err }));
    }
}

async function handleRevokeUser(userId, username) {
    // Show confirmation via the revoke modal
    showRevokeConfirmModal(userId, username);
}

async function buildSignedSyncObject(_sodium, fields, payloadBytes) {
    const payloadHash = await sha256hexBytes(payloadBytes);
    const signature = signSyncObject(
        _sodium, fields.id, fields.object_type, fields.parent_ref || null,
        fields.target_user_id || null, fields.is_deleted || 0,
        fields.version, hexToBytes(payloadHash)
    );
    return {
        id: fields.id,
        object_type: fields.object_type,
        payload: bytesToBase64(payloadBytes),
        parent_ref: fields.parent_ref || null,
        target_user_id: fields.target_user_id || null,
        version: fields.version,
        is_deleted: fields.is_deleted || 0,
        payload_hash: payloadHash,
        signature: bytesToHex(signature),
        write_policy: fields.write_policy || null,
        access_level: fields.access_level || null,
        scope: fields.scope || null,
        ...(fields.base_version != null
            ? { base_version: fields.base_version, base_payload_hash: fields.base_payload_hash }
            : {}),
    };
}

function encryptedPayloadDekId(syncObj) {
    const payload = base64ToBytes(syncObj.payload || '');
    let offset = -1;
    if (payload.length >= 53 && payload[0] === ENVELOPE_ALG) offset = 0;
    if (syncObj.object_type === 'entry' && payload.length >= 57 &&
            payload[4] === ENVELOPE_ALG) offset = 4;
    if (offset < 0) return null;
    return new TextDecoder().decode(payload.slice(offset + 3, offset + 29)).replace(/\0/g, '');
}

async function getVerifiedEncryptionPkForRekey(userId, _sodium) {
    const keys = await apiFetch(`/api/users/${userId}/keys`);
    const signingPk = hexToBytes(keys?.signing_pk || '');
    const encryptionPk = hexToBytes(keys?.encryption_pk || '');
    if (signingPk.length !== 32 || encryptionPk.length !== 32) {
        throw new Error(`Missing canonical public keys for remaining user ${userId}`);
    }
    const signingHex = bytesToHex(signingPk);
    const encryptionHex = bytesToHex(encryptionPk);
    const pinned = await checkKnownKey(userId, signingHex, encryptionHex);
    if (pinned === 'changed') {
        throw tofuKeyChange(userId, userId, signingHex, encryptionHex);
    }
    const trustedSigningKeys = state.userKeys[userId];
    if (trustedSigningKeys?.length && bytesToHex(trustedSigningKeys[0]) !== signingHex) {
        throw new Error(`Signing key changed during re-key for user ${userId}`);
    }
    if (userId === state.userId) {
        const localEncryptionPk = _sodium.crypto_scalarmult_base(state.keypair.encryptionSk);
        if (bytesToHex(localEncryptionPk) !== encryptionHex) {
            throw new Error('Server returned a different encryption key for this device');
        }
    }
    return encryptionPk;
}

async function buildWebRekeyBatch(revokedUserId, _sodium) {
    if (!webIsAdmin() || !state.syncObjects || !state.keypair?.encryptionSk || !state.kek) {
        throw new Error('A complete unlocked admin snapshot is required for revocation');
    }
    const activeObjects = Object.values(state.syncObjects).filter(obj => !obj.is_deleted);
    const revokedEnvelopes = activeObjects.filter(obj =>
        obj.object_type === 'envelope' && obj.target_user_id === revokedUserId
    );
    // TL5: once the organisation has a team log, its folders are re-keyed by
    // the log (webTeamRekeyPlan); the rules below stay for keys outside it.
    const team = state.teamLog?.team || null;
    const plan = team ? webTeamRekeyPlan(team, revokedUserId, _sodium) : null;
    const legacyKept = new Set();
    const affectedDekIds = [...new Set(revokedEnvelopes.map(obj => obj.parent_ref))].filter(dekId => {
        if (!team) return true;
        const folder = state.syncObjects[dekId]?.parent_ref || null;
        if (Object.hasOwn(team.dekIndex, dekId)) return false;
        // A key below a team folder the log does not know (from before the
        // log, a tier-2 key): the server takes no new key there without a
        // folder.key; it stays until that item gets a folder of its own (TL7).
        if (webTeamFolderAbove(state.syncObjects, team, folder)) {
            legacyKept.add(dekId);
            return false;
        }
        return true;
    });
    const users = await apiFetch('/api/users');
    const activeUserIds = new Set(users.filter(user => user.status === 'active').map(user => user.id));
    // Capability review run 141: the archive tag names only revokedUserId, and
    // another admin's device grants again to every member a tagged re-key
    // did not name. Dropping a non-active holder here withdrew them unnamed,
    // so only the server's unsigned status kept the new key from them. As on
    // desktop, only revokedUserId is dropped; another holder that is not
    // active has to be removed first (its own re-key names it).
    const unnamed = [...new Set(activeObjects.filter(obj =>
        obj.object_type === 'envelope' && affectedDekIds.includes(obj.parent_ref) &&
        obj.target_user_id !== revokedUserId && !activeUserIds.has(obj.target_user_id)
    ).map(obj => obj.target_user_id))];
    if (unnamed.length) {
        throw new Error(
            `These folders are also shared with members whose account is not active (${unnamed.join(', ')}). ` +
            "Remove them first ('sezam revoke-user ID' on a desktop), then remove this member again."
        );
    }
    const objects = [];
    const notToSeal = writesNotToSeal(state.syncObjects, state.userId);
    const notResealed = new Set();
    const downgraded = new Set();
    const vouchedWrites = await loadWebWriteGrants(_sodium);
    const writeGrantIds = [];

    // A new key for the folder of `oldDekId`: its DEK object, the archive
    // that proves the successor, every live folder/item under the old key
    // sealed again, the old key's envelopes withdrawn, and the new key sealed
    // to `recipients(oldEnvelopes)` ([[userId, encryptionPk, level]]).
    const rekeyOne = async (oldDekId, folder, recipients) => {
        const oldDek = state.deks[oldDekId];
        const oldDekObject = state.syncObjects[oldDekId];
        if (!(oldDek instanceof Uint8Array) || oldDek.length !== 32 ||
                !oldDekObject || oldDekObject.object_type !== 'dek' ||
                !oldDekObject.parent_ref || oldDekObject.parent_ref !== folder) {
            throw new Error(`Cannot safely re-key affected DEK ${oldDekId}`);
        }

        const newDekId = generateULID();
        const newDek = _sodium.randombytes_buf(32);
        try {
            const wrappedNewDek = wrapDEK(newDek, newDekId, 1, state.kek, _sodium);
            objects.push(await buildSignedSyncObject(_sodium, {
                id: newDekId,
                object_type: 'dek',
                parent_ref: folder,
                version: 1,
                scope: oldDekObject.scope || null,
            }, wrappedNewDek));

            const archiveId = removalArchiveId(newDekId, newDek, revokedUserId, _sodium);
            const archivedOldDek = wrapDEKWithKey(
                oldDek, newDekId, archiveId, 1, newDek, _sodium
            );
            objects.push(await buildSignedSyncObject(_sodium, {
                id: archiveId,
                object_type: 'dek_archive',
                parent_ref: newDekId,
                version: 1,
            }, archivedOldDek));

            for (const syncObj of activeObjects) {
                if (!['node', 'entry'].includes(syncObj.object_type) ||
                        encryptedPayloadDekId(syncObj) !== oldDekId || notToSeal.has(syncObj.id)) continue;
                const oldPayload = base64ToBytes(syncObj.payload);
                const version = syncObj.version + 1;
                let newPayload;
                if (syncObj.object_type === 'node') {
                    const plaintext = decryptEnvelope(
                        oldPayload, syncObj.id, syncObj.version, state.deks, _sodium, BLOB_KIND.NODE_META
                    );
                    newPayload = encryptEnvelope(
                        plaintext, BLOB_KIND.NODE_META, newDekId, syncObj.id, version, newDek, _sodium
                    );
                } else {
                    const plaintext = oldPayload[0] === ENVELOPE_ALG
                        ? decryptEnvelope(oldPayload, syncObj.id, syncObj.version, state.deks, _sodium,
                            BLOB_KIND.ENTRY_DATA)
                        : decryptEntryPayload(oldPayload, syncObj.id, syncObj.version, state.deks, _sodium);
                    newPayload = encryptEntryPayload(
                        plaintext, newDekId, syncObj.id, version, newDek, _sodium
                    );
                }
                objects.push(await buildSignedSyncObject(_sodium, {
                    id: syncObj.id,
                    object_type: syncObj.object_type,
                    parent_ref: syncObj.parent_ref,
                    version,
                    write_policy: syncObj.write_policy,
                    base_version: syncObj.version,
                    base_payload_hash: syncObj.payload_hash,
                }, newPayload));
            }

            const oldEnvelopes = activeObjects.filter(obj =>
                obj.object_type === 'envelope' && obj.parent_ref === oldDekId
            );
            for (const envelope of oldEnvelopes) {
                objects.push(await buildSignedSyncObject(_sodium, {
                    id: envelope.id,
                    object_type: 'envelope',
                    parent_ref: oldDekId,
                    target_user_id: envelope.target_user_id,
                    access_level: envelope.access_level,
                    version: envelope.version + 1,
                    is_deleted: 1,
                }, base64ToBytes(envelope.payload)));
            }
            for (const [remainingUserId, recipientPk, accessLevel] of await recipients(oldEnvelopes)) {
                const nonce = _sodium.randombytes_buf(_sodium.crypto_box_NONCEBYTES);
                const ciphertext = _sodium.crypto_box_easy(
                    newDek, nonce, recipientPk, state.keypair.encryptionSk
                );
                const encryptedDek = new Uint8Array(nonce.length + ciphertext.length);
                encryptedDek.set(nonce, 0);
                encryptedDek.set(ciphertext, nonce.length);
                const envelopeId = generateULID();
                objects.push(await buildSignedSyncObject(_sodium, {
                    id: envelopeId,
                    object_type: 'envelope',
                    parent_ref: newDekId,
                    target_user_id: remainingUserId,
                    access_level: accessLevel,
                    version: 1,
                }, encryptedDek));
                if (accessLevel === 'write') writeGrantIds.push(envelopeId);
            }
            return newDekId;
        } finally {
            _sodium.memzero(newDek);
        }
    };

    for (const oldDekId of affectedDekIds) {
        await rekeyOne(oldDekId, state.syncObjects[oldDekId]?.parent_ref || null, async oldEnvelopes => {
            const remainingAccess = new Map();
            const foreignGrants = new Set();
            const claimedWrite = new Set();
            for (const envelope of oldEnvelopes) {
                // Review a159e97 H4 (desktop D1, reseal_key_row): the new key
                // goes only to a member this account granted the folder (it
                // signed the envelope). An envelope another account signed may
                // be one the server made up (an account 'Eve' it created); the
                // web has no fingerprint confirmations, so such a member is
                // told about, not sealed to.
                if (envelope.target_user_id !== revokedUserId &&
                        (envelope.signer || envelope.owner_id) !== state.userId) {
                    foreignGrants.add(envelope.target_user_id);
                } else if (envelope.target_user_id !== revokedUserId) {
                    // Review a159e97 H3 (desktop vouched_access_level): the
                    // access_level is not signed. A server that turned a
                    // member's 'read' into 'write' had it copied into the
                    // envelope this account signs here, so the escalation
                    // stayed after the server stopped lying. 'write' carries
                    // over only from an envelope this browser made.
                    let level = 'read';
                    if (envelope.access_level === 'write') {
                        if (vouchedWrites.has(envelope.id)) level = 'write';
                        else claimedWrite.add(envelope.target_user_id);
                    }
                    const prior = remainingAccess.get(envelope.target_user_id);
                    if (!prior || level === 'write') remainingAccess.set(envelope.target_user_id, level);
                }
            }

            for (const userId of foreignGrants) {
                if (!remainingAccess.has(userId)) notResealed.add(userId);
            }
            for (const userId of claimedWrite) {
                if (remainingAccess.get(userId) !== 'write') downgraded.add(userId);
            }
            const sealTo = [];
            for (const [remainingUserId, accessLevel] of remainingAccess) {
                sealTo.push([remainingUserId,
                    await getVerifiedEncryptionPkForRekey(remainingUserId, _sodium), accessLevel]);
            }
            return sealTo;
        });
    }

    // TL5 (§4.3.1): a team folder's new key goes to exactly the log's
    // recipients, at the log's level, with the log's encryption key; its
    // folder.key record lands in the same push as the objects (or nothing does).
    // Review 1141a20 H5: an envelope from before the log on a folder's
    // current key: the log never gave the member that folder, so its
    // member.remove marks nothing stale, and the member kept the current key.
    // Such a folder is re-keyed through the log too.
    const TL = globalThis.SezamTeamLog;
    const logFolders = plan ? [...plan.folders] : [];
    for (const envelope of plan ? revokedEnvelopes : []) {
        const found = Object.hasOwn(team.dekIndex, envelope.parent_ref) ? team.dekIndex[envelope.parent_ref] : null;
        if (found && TL.currentKey(plan.after, found[0]) === envelope.parent_ref &&
                !logFolders.includes(found[0])) logFolders.push(found[0]);
    }
    logFolders.sort();
    const teamLog = plan ? [...plan.records] : [];
    let after = plan ? plan.after : null;
    for (const folder of logFolders) {
        const oldDekId = TL.currentKey(after, folder);
        // R16-Z: exactly the log's recipients, this account too when the log
        // gives it access of its own (it lost the folder on handing back).
        const recipients = TL.keyRecipients(after, folder)
            .map(([userId, pkHex, level]) => [userId, hexToBytes(pkHex), level]);
        const newDekId = await rekeyOne(oldDekId, folder, async () => recipients);
        const record = TL.signRecord(TL.nextBody(after, 'folder.key', state.userId, {
            folder, gen: after.folders[folder].length, dek_id: newDekId, prev_dek_id: oldDekId,
        }), state.keypair.signingSk, _sodium);
        after = TL.applyRecord(after, record, _sodium);
        teamLog.push(record);
    }

    if (writeGrantIds.length) {
        // Recorded before the batch can land; an id that never does is unused.
        for (const id of writeGrantIds) vouchedWrites.add(id);
        await saveWebWriteGrants(vouchedWrites, _sodium);
    }
    return {
        objects,
        team_log: teamLog,
        legacy_kept: [...legacyKept].sort(),
        folders_rekeyed: affectedDekIds.length + logFolders.length,
        not_resealed: [...notResealed].sort(),
        // Members whose 'write' this browser could not vouch for: read now.
        write_downgraded: [...downgraded].sort(),
    };
}

async function pushWebRekeyBatch(journal, _sodium = state.sodium) {
    // The journal is the only queue for these objects: in outbox a
    // Retry would send them one by one (lockout review M5).
    const teamLog = Array.isArray(journal.team_log) ? journal.team_log : [];
    if (!journal.objects.length) {
        // Only the member.remove (no team folder to re-key).
        if (teamLog.length) {
            await sendWebTeamRecords(teamLog, () => apiFetch('/api/team-log', {
                method: 'POST', body: { records: teamLog },
            }), _sodium);
        }
        return;
    }
    const response = await sendWebTeamRecords(teamLog, () => postAtomicSyncBatch(journal.objects, {
        key_epoch: state.keyEpoch, ...(teamLog.length ? { team_log: teamLog } : {}),
        ...(journal.check_token ? { check_seq: journal.check_seq, check_token: journal.check_token } : {}),
    }), _sodium);
    const acceptedIds = new Set((response?.accepted || []).map(item => item.id));
    if ((response?.conflicts || []).length ||
            journal.objects.some(obj => !acceptedIds.has(obj.id))) {
        const refused = new Error('Atomic re-key batch was not fully accepted');
        refused.rekeyBatchRefused = true;
        throw refused;
    }
}

async function prepareWebRekeyJournal(revokedUserId, _sodium) {
    await pullAndBuildTree();
    const batch = await buildWebRekeyBatch(revokedUserId, _sodium);
    assertSyncUnitFits(batch.objects);  // never journalled if it cannot be sent
    const journal = {
        revoked_user_id: revokedUserId,
        folders_rekeyed: batch.folders_rekeyed,
        not_resealed: batch.not_resealed,
        write_downgraded: batch.write_downgraded,
        legacy_kept: batch.legacy_kept,
        phase: 'prepared',
        objects: batch.objects,
        team_log: batch.team_log,
    };
    // R16-Z SM16: the commit the batch was built on. A folder key another
    // device of this account committed after it makes the server refuse the
    // batch (folder_key_moved); it is rebuilt from the pull, never stored next.
    const checkSeq = state.syncCheckpoint?.last_sync_seq || 0;
    const checkToken = checkSeq > 0 ? state.syncCheckpoint.commit_token || null : null;
    if (checkToken) Object.assign(journal, { check_seq: checkSeq, check_token: checkToken });
    await saveWebRekeyJournal(journal, _sodium);
    return journal;
}

/**
 * Re-key the revoked member's folders, then remove the member. Lockout
 * review M5 / review 688edcb: a batch the server refuses (409: an object
 * changed since it was built) was pushed unchanged on every Retry and never
 * went through. It is rebuilt from the server's current state instead, as on
 * desktop. Rebuilding is safe either way: the batch is atomic, so after one
 * that was accepted (lost response) the rebuilt one is empty.
 */
async function finishWebRevocation(revokedUserId, _sodium) {
    let journal = await loadWebRekeyJournal(revokedUserId, _sodium) ||
        await prepareWebRekeyJournal(revokedUserId, _sodium);
    if (journal.phase === 'prepared') {
        try {
            try {
                if (journal.objects.length || journal.team_log?.length) await pushWebRekeyBatch(journal, _sodium);
            } catch (err) {
                if (!err.rekeyBatchRefused && err.status !== 409 && !err.syncUnitTooLarge) throw err;
                journal = await prepareWebRekeyJournal(revokedUserId, _sodium);
                if (journal.objects.length || journal.team_log?.length) await pushWebRekeyBatch(journal, _sodium);
            }
        } catch (err) {
            if (err.status === 400 && journal.team_log?.length) {
                // Review 1141a20 H4: the server refused the member.remove. It
                // is not dropped: the journal stays, so this browser starts no
                // other revocation (whose re-key would seal the next key to the
                // member) and the member is NOT reported removed. Retry sends
                // it again; the rest of a Retry goes on.
                err.teamLogRefused = true;
                throw err;
            }
            if (!err.syncUnitTooLarge) throw err;
            // Review d150605 S3: a journal the server can never take (saved by
            // an older version, or still too large when rebuilt) failed every
            // Retry and blocked every other revocation. Nothing of it reached
            // the server, so it is dropped; the member is NOT removed and
            // keeps the old keys until the folders fit and the revocation is
            // started again.
            await clearWebRekeyJournal(revokedUserId, _sodium);
            const tooLarge = new Error(t('admin.rekey_too_large', {
                user: revokedUserId, reason: err.message,
            }));
            tooLarge.rekeyTooLarge = true;
            throw tooLarge;
        }
        journal.phase = 'pushed';
        await saveWebRekeyJournal(journal, _sodium);
    }
    try {
        await apiFetch(`/api/users/${revokedUserId}`, { method: 'DELETE' });
    } catch (err) {
        if (err.status !== 404) throw err;  // already removed elsewhere
    }
    await clearWebRekeyJournal(revokedUserId, _sodium);
    return {
        notResealed: Array.isArray(journal.not_resealed) ? journal.not_resealed : [],
        writeDowngraded: Array.isArray(journal.write_downgraded) ? journal.write_downgraded : [],
        legacyKept: Array.isArray(journal.legacy_kept) ? journal.legacy_kept : [],
    };
}

async function confirmRevokeUser(userId) {
    try {
        const _sodium = await ensureSodium();
        if ((await pendingWebRevocations()).some(id => id !== userId)) {
            throw new Error('A different user revocation is still pending; retry it first');
        }
        const { notResealed, writeDowngraded, legacyKept } = await finishWebRevocation(userId, _sodium);
        closeRevokeModal();
        if (legacyKept.length) alert(t('admin.rekey_legacy_kept', { keys: legacyKept.join(', ') }));
        if (notResealed.length) alert(t('admin.rekey_not_resealed', { users: notResealed.join(', ') }));
        if (writeDowngraded.length) alert(t('admin.rekey_write_downgraded', { users: writeDowngraded.join(', ') }));
        await pullAndBuildTree();
        const users = await apiFetch('/api/users');
        await renderAdminUserList(users);
    } catch (err) {
        const message = err.rekeyTooLarge ? err.message : typeof t === 'function'
            ? t('admin.revocation_failed', { error: err.message || err })
            : 'Failed to revoke user: ' + (err.message || err);
        alert(message);
    }
}

// ── Invite token modal ──

function showInviteModal(token, inviteLink) {
    // Remove any existing invite modal
    let modal = document.getElementById('invite-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'invite-modal';
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-panel modal-panel-small">
                <div class="modal-inner">
                    <h2 class="modal-title" data-i18n="invite.title">${escapeHtml(t('invite.title'))}</h2>
                    <p class="modal-message" data-i18n="invite.message">${escapeHtml(t('invite.message'))}</p>
                    <div class="invite-token-display">
                        <input type="text" id="invite-link-input" class="invite-link-input" readonly>
                    </div>
                    <div class="modal-buttons">
                        <button type="button" id="invite-copy-btn" class="modal-btn save" data-i18n="invite.copy_link">${escapeHtml(t('invite.copy_link'))}</button>
                        <button type="button" id="invite-close-btn" class="modal-btn cancel" data-i18n="common.close">${escapeHtml(t('common.close'))}</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeInviteModal();
        });
    } else {
        modal.classList.remove('hidden');
    }

    const linkInput = document.getElementById('invite-link-input');
    linkInput.value = inviteLink;

    document.getElementById('invite-copy-btn').onclick = () => {
        linkInput.select();
        navigator.clipboard.writeText(inviteLink).then(() => {
            const btn = document.getElementById('invite-copy-btn');
            btn.textContent = t('invite.copied');
            setTimeout(() => { btn.textContent = t('invite.copy_link'); }, 2000);
        }).catch(() => {
            // Fallback
            document.execCommand('copy');
        });
    };

    document.getElementById('invite-close-btn').onclick = closeInviteModal;
}

function closeInviteModal() {
    const modal = document.getElementById('invite-modal');
    if (modal) modal.classList.add('hidden');
}

// ── Revoke confirmation modal ──

function showRevokeConfirmModal(userId, username) {
    let modal = document.getElementById('revoke-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'revoke-modal';
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-panel modal-panel-small">
                <div class="modal-inner">
                    <h2 class="modal-title" data-i18n="revoke.title">${escapeHtml(t('revoke.title'))}</h2>
                    <p id="revoke-message" class="modal-message"></p>
                    <div class="modal-buttons">
                        <button type="button" id="revoke-cancel-btn" class="modal-btn cancel" data-i18n="common.cancel">${escapeHtml(t('common.cancel'))}</button>
                        <button type="button" id="revoke-confirm-btn" class="modal-btn danger" data-i18n="admin.revoke">${escapeHtml(t('admin.revoke'))}</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeRevokeModal();
        });
        document.getElementById('revoke-cancel-btn').addEventListener('click', closeRevokeModal);
    } else {
        modal.classList.remove('hidden');
    }

    const message = document.getElementById('revoke-message');
    message.dataset.i18n = 'revoke.message';
    message.dataset.i18nValues = JSON.stringify({ username });
    message.textContent = t('revoke.message', { username });
    document.getElementById('revoke-confirm-btn').onclick = () => confirmRevokeUser(userId);
}

function closeRevokeModal() {
    const modal = document.getElementById('revoke-modal');
    if (modal) modal.classList.add('hidden');
}

function buildTree(nodes, entries) {
    const nodeMap = {};
    for (const n of nodes) {
        nodeMap[n.id] = { ...n, children: [], entries: [] };
    }

    // Assign entries to nodes
    for (const e of entries) {
        if (e.parent_ref && nodeMap[e.parent_ref]) {
            nodeMap[e.parent_ref].entries.push(e);
        }
    }

    // Build parent-child relationships
    const roots = [];
    for (const n of Object.values(nodeMap)) {
        if (n.parent_ref && nodeMap[n.parent_ref]) {
            nodeMap[n.parent_ref].children.push(n);
        } else {
            roots.push(n);
        }
    }

    // If no nodes at all, show entries at root level
    if (roots.length === 0 && entries.length > 0) {
        return [{ id: 'root', name: t('tree.vault'), children: [], entries }];
    }

    // If empty vault
    if (roots.length === 0) {
        return [{ id: 'root', name: t('tree.vault_empty'), children: [], entries: [] }];
    }

    return roots;
}

function renderTree(tree) {
    const container = document.getElementById('tree-container');
    if (!tree || tree.length === 0) {
        const empty = document.createElement('p');
        empty.style.cssText = 'color: var(--text-muted); padding: 1rem; font-style: italic;';
        empty.textContent = t('tree.empty');
        container.replaceChildren(empty);
        return;
    }
    container.innerHTML = '';
    for (const node of tree) {
        container.appendChild(renderTreeNode(node, 0));
    }
}

function renderTreeNode(node, depth) {
    const fragment = document.createDocumentFragment();

    // Render folder
    const folderEl = document.createElement('div');
    folderEl.className = 'tree-node';
    if (state.selectedFolderId === node.id) folderEl.classList.add('folder-selected');
    folderEl.style.paddingLeft = (depth * 16 + 8) + 'px';
    folderEl.dataset.nodeId = node.id;

    // Determine folder icon and display name
    let folderIcon, displayName;
    if (node._undecryptable) {
        // Node could not be decrypted — belongs to another user's personal vault
        folderIcon = '\uD83D\uDD12'; // lock emoji
        displayName = escapeHtml(t('tree.other_personal'));
        folderEl.style.opacity = '0.5';
        folderEl.style.fontStyle = 'italic';
    } else if (node.personal) {
        // Personal folder owned by current user
        folderIcon = '\uD83D\uDD12'; // lock emoji
        displayName = escapeHtml(node.name || t('tree.personal'));
    } else {
        folderIcon = (node.children?.length || node.entries?.length) ? '\u25BC' : '\u25B6';
        const nodeName = node.id === state.rootNodeId && node.name === 'Vault'
            ? t('tree.vault')
            : (node.name || t('tree.folder'));
        displayName = escapeHtml(nodeName);
    }

    folderEl.innerHTML = `<span class="icon">${folderIcon}</span>${displayName}`;
    folderEl.addEventListener('click', () => {
        if (node._undecryptable) return; // Can't select undecryptable folders
        state.selectedFolderId = node.id;
        document.querySelectorAll('.tree-node.folder-selected').forEach(n => n.classList.remove('folder-selected'));
        folderEl.classList.add('folder-selected');
    });
    fragment.appendChild(folderEl);

    // Render entries under this node
    if (node.entries) {
        for (const entry of node.entries) {
            const entryEl = document.createElement('div');
            entryEl.className = 'tree-node tree-entry';
            entryEl.style.paddingLeft = ((depth + 1) * 16 + 8) + 'px';
            entryEl.innerHTML = `<span class="icon">\u{1F511}</span>${escapeHtml(entry.name || t('tree.entry'))}`;
            entryEl.addEventListener('click', (e) => {
                e.stopPropagation();
                document.querySelectorAll('.tree-node.selected').forEach(n => n.classList.remove('selected'));
                entryEl.classList.add('selected');
                renderEntry(entry);
                logFieldAccess('entry_view', entry.name || '');
            });
            fragment.appendChild(entryEl);
        }
    }

    // Render child folders
    if (node.children) {
        for (const child of node.children) {
            fragment.appendChild(renderTreeNode(child, depth + 1));
        }
    }

    return fragment;
}

// ── TOTP generation (RFC 6238) using Web Crypto API ──

// Active TOTP timers for cleanup
let _totpTimers = [];

/**
 * Base32 decode (RFC 4648). Handles both upper and lower case, strips spaces/dashes.
 */
function base32Decode(input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const cleaned = input.replace(/[\s=-]/g, '').toUpperCase();
    let bits = '';
    for (const ch of cleaned) {
        const idx = alphabet.indexOf(ch);
        if (idx < 0) continue;
        bits += idx.toString(2).padStart(5, '0');
    }
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
    }
    return bytes;
}

/**
 * Generate a TOTP code (6 digits, 30s period) using HMAC-SHA1 via Web Crypto.
 * @param {string} secret - base32-encoded TOTP secret
 * @param {number} [timestamp] - Unix timestamp in seconds (default: now)
 * @returns {Promise<string>} 6-digit TOTP code
 */
async function generateTOTP(secret, timestamp) {
    const key = base32Decode(secret);
    const time = timestamp || Math.floor(Date.now() / 1000);
    const counter = Math.floor(time / 30);

    // Convert counter to 8-byte big-endian buffer
    const counterBuf = new ArrayBuffer(8);
    const counterView = new DataView(counterBuf);
    counterView.setUint32(0, Math.floor(counter / 0x100000000), false);
    counterView.setUint32(4, counter >>> 0, false);

    // HMAC-SHA1
    const cryptoKey = await crypto.subtle.importKey(
        'raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
    );
    const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, counterBuf));

    // Dynamic truncation
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code = (
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)
    ) % 1000000;

    return code.toString().padStart(6, '0');
}

/**
 * Check if a field should be treated as a TOTP field.
 */
function isTOTPField(field) {
    if (field.field_type === 'totp') return true;
    const k = (field.key || '').toLowerCase();
    return k === 'totp' || k === 'totp_secret' || k === 'otp' || k === 'totp_seed';
}

/**
 * Get seconds remaining in current TOTP period (30s).
 */
function totpSecondsRemaining() {
    return 30 - (Math.floor(Date.now() / 1000) % 30);
}

/**
 * Ownership + folder ACL (spec 3.4): can the current user edit this object?
 * Admins and owners may edit. A non-owner shared object additionally requires
 * an authenticated envelope with access_level='write' for its parent folder.
 * The server remains authoritative; this drives the fail-closed UI.
 */
function folderAccessLevelForObject(obj) {
    const folderId = obj.parent_ref;
    if (!folderId || !state.syncObjects || !state.userId) return null;
    let level = null;
    for (const envelope of Object.values(state.syncObjects)) {
        if (envelope.object_type !== 'envelope' || envelope.is_deleted ||
                envelope.target_user_id !== state.userId ||
                !['read', 'write'].includes(envelope.access_level)) continue;
        const dekObject = state.syncObjects[envelope.parent_ref];
        if (!dekObject || dekObject.object_type !== 'dek' || dekObject.is_deleted ||
                dekObject.parent_ref !== folderId) continue;
        if (envelope.access_level === 'write') return 'write';
        level = 'read';
    }
    return level;
}

/**
 * INV-3 (review e443cbc): this account is admin as the verified team log says
 * (as on the desktop). The server's unsigned is_admin (state.isAdmin) only
 * stands while this browser knows no team log at all, where the server
 * authorizes that vault's admin calls itself (S6); a refused log, or one
 * pinned and not held yet, makes nobody admin here.
 */
function webIsAdmin() {
    // Review c02cc47 R17-L: a refused log is checked first; it is still held.
    if (state.teamLogRefusal) return false;
    const team = state.teamLog?.team;
    if (team) return !!state.userId && globalThis.SezamTeamLog.isAdmin(team, state.userId);
    if (webPinnedTeamGenesis().length) return false;
    return state.isAdmin === true;
}

function canEditObject(obj) {
    if (!obj) return false;
    if (webIsAdmin()) return true;
    if (!obj.owner_id) return false;
    if (obj.owner_id === state.userId) return true;
    if (obj.write_policy === 'shared') {
        return folderAccessLevelForObject(obj) === 'write';
    }
    return false;
}

function renderEntry(entry) {
    state.selectedEntry = entry;
    document.getElementById('no-selection').classList.add('hidden');
    const detail = document.getElementById('entry-detail');
    detail.classList.remove('hidden');

    // Ownership ACL: hide edit/delete for non-editable entries, show badge.
    const canEdit = canEditObject(entry);
    document.getElementById('edit-entry-btn')?.classList.toggle('hidden', !canEdit);
    document.getElementById('delete-entry-btn')?.classList.toggle('hidden', !canEdit);
    document.getElementById('entry-readonly-badge')?.classList.toggle('hidden', canEdit);

    // Clear any existing TOTP timers
    _totpTimers.forEach(t => clearInterval(t));
    _totpTimers = [];

    document.getElementById('entry-name').textContent = entry.name || '';

    const tagsEl = document.getElementById('entry-tags');
    tagsEl.innerHTML = (entry.tags || []).map(t =>
        `<span class="tag">${escapeHtml(t)}</span>`
    ).join('');

    const fieldsEl = document.getElementById('entry-fields');
    fieldsEl.innerHTML = (entry.fields || []).map((f, idx) => {
        if (isTOTPField(f)) {
            return `
                <div class="field-row">
                    <span class="field-key">${escapeHtml(f.key)}</span>
                    <span class="field-value totp-code" id="totp-code-${idx}" data-totp-secret="${escapeHtml(f.value)}">
                        ------
                    </span>
                    <div class="field-actions">
                        <span class="totp-countdown" id="totp-timer-${idx}">
                            <span class="totp-seconds"></span>s
                            <span class="totp-bar"></span>
                        </span>
                        <button class="field-btn" data-action="copy-totp" data-totp-idx="${idx}">${escapeHtml(t('common.copy'))}</button>
                    </div>
                </div>`;
        }
        return `
            <div class="field-row">
                <span class="field-key">${escapeHtml(f.key)}</span>
                <span class="field-value ${f.sensitive ? 'masked' : ''}" data-value="${escapeHtml(f.value)}">
                    ${f.sensitive ? '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022' : escapeHtml(f.value)}
                </span>
                <div class="field-actions">
                    ${f.sensitive ? `<button class="field-btn" data-action="toggle">${escapeHtml(t('common.show'))}</button>` : ''}
                    <button class="field-btn" data-action="copy">${escapeHtml(t('common.copy'))}</button>
                </div>
            </div>`;
    }).join('');

    // Attach event listeners instead of inline onclick (CSP-safe)
    fieldsEl.querySelectorAll('.field-btn[data-action="toggle"]').forEach(btn => {
        btn.addEventListener('click', () => toggleFieldBtn(btn));
    });
    fieldsEl.querySelectorAll('.field-btn[data-action="copy"]').forEach(btn => {
        btn.addEventListener('click', () => copyFieldBtn(btn));
    });

    // Initialize TOTP fields with live codes and countdown
    fieldsEl.querySelectorAll('.field-btn[data-action="copy-totp"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const idx = btn.dataset.totpIdx;
            const codeEl = document.getElementById(`totp-code-${idx}`);
            if (codeEl) {
                navigator.clipboard.writeText(codeEl.textContent.trim()).catch(() => {});
            }
        });
    });

    // Start TOTP timers
    fieldsEl.querySelectorAll('[data-totp-secret]').forEach(el => {
        const secret = el.dataset.totpSecret;
        const idx = el.id.replace('totp-code-', '');
        const timerEl = document.getElementById(`totp-timer-${idx}`);

        async function updateTOTP() {
            try {
                const code = await generateTOTP(secret);
                el.textContent = code.slice(0, 3) + ' ' + code.slice(3);
            } catch (err) {
                el.textContent = t('entry.totp_error');
                console.warn('TOTP generation failed:', err.message);
            }
            if (timerEl) {
                const remaining = totpSecondsRemaining();
                const secondsEl = timerEl.querySelector('.totp-seconds');
                const barEl = timerEl.querySelector('.totp-bar');
                if (secondsEl) secondsEl.textContent = remaining;
                if (barEl) barEl.style.width = Math.round((remaining / 30) * 40) + 'px';
            }
        }

        updateTOTP();
        const timer = setInterval(updateTOTP, 1000);
        _totpTimers.push(timer);
    });
}

// ── Search ──

function handleSearch(query) {
    if (!query.trim()) {
        document.getElementById('search-results')?.classList.add('hidden');
        return;
    }

    // Multi-token AND search (spec 5.3): all tokens must match somewhere
    const tokens = normalize(query).split(/\s+/).filter(t => t);
    if (tokens.length === 0) {
        document.getElementById('search-results')?.classList.add('hidden');
        return;
    }

    // W5: Check deep search toggle for searching in field values
    const deepSearch = document.getElementById('deep-search-toggle')?.checked || false;

    // Search entries: name, tags, field keys — and optionally field values (W5)
    const entryMatches = state.allEntries.filter(e => {
        const nameNorm = normalize(e.name || '');
        const tagsNorm = (e.tags || []).map(t => normalize(t));
        const fieldKeysNorm = (e.fields || []).map(f => normalize(f.key || ''));
        // W5: If deep search enabled, also search in decrypted field values
        const fieldValsNorm = deepSearch
            ? (e.fields || []).map(f => normalize(f.value || ''))
            : [];
        return tokens.every(t =>
            nameNorm.includes(t) ||
            tagsNorm.some(tag => tag.includes(t)) ||
            fieldKeysNorm.some(fk => fk.includes(t)) ||
            fieldValsNorm.some(fv => fv.includes(t))
        );
    });

    // Search folders by name — all tokens must match
    const folderMatches = (state.allNodes || []).filter(n => {
        const nameNorm = normalize(n.name || '');
        return tokens.every(t => nameNorm.includes(t));
    });

    const results = document.getElementById('search-results');
    const list = document.getElementById('search-list');

    if (entryMatches.length === 0 && folderMatches.length === 0) {
        list.innerHTML = `<li>${escapeHtml(t('search.no_results'))}</li>`;
    } else {
        let html = '';
        for (const n of folderMatches.slice(0, 5)) {
            html += '<li data-folder-id="' + escapeHtml(n.id) + '"><span class="icon">\u25BC</span> ' + escapeHtml(n.name || t('tree.folder')) + '</li>';
        }
        for (const e of entryMatches.slice(0, 20)) {
            html += '<li data-entry-id="' + escapeHtml(e.id) + '"><span class="icon">\u{1F511}</span> ' + escapeHtml(e.name || t('tree.entry')) + '</li>';
        }
        list.innerHTML = html;

        list.querySelectorAll('li[data-entry-id]').forEach(li => {
            li.addEventListener('click', () => {
                const entry = state.entries[li.dataset.entryId];
                if (entry) {
                    renderEntry(entry);
                    logFieldAccess('entry_view', entry.name || '');
                }
                results.classList.add('hidden');
            });
        });
        list.querySelectorAll('li[data-folder-id]').forEach(li => {
            li.addEventListener('click', () => {
                state.selectedFolderId = li.dataset.folderId;
                results.classList.add('hidden');
            });
        });
    }
    results.classList.remove('hidden');
}

// ── Audit: fire-and-forget client-side event logging ──

async function logFieldAccess(action) {
    if (!state.token || !state.userId || !state.keypair?.signingSk) return;
    try {
        const _sodium = await ensureSodium();
        const id = generateULID();
        const timestamp = Date.now();
        // The action is intentionally the only server-visible event metadata.
        // Target names and field keys are never sent to the content-blind server.
        const requestHash = await sha256hexBytes(
            new TextEncoder().encode(action)
        );
        const canonical = buildServerAuditCanonical(
            id, state.userId, action, timestamp, requestHash
        );
        const signature = _sodium.crypto_sign_detached(
            canonical, state.keypair.signingSk
        );
        await fetch(API_BASE + '/api/audit/log', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + state.token,
            },
            body: JSON.stringify({
                id,
                action,
                timestamp,
                request_hash: requestHash,
                signature: bytesToHex(signature),
            }),
        });
    } catch (_) { /* audit is fire-and-forget */ }
}

// ── Field actions (CSP-safe — no inline onclick) ──

function toggleFieldBtn(btn) {
    const valueEl = btn.closest('.field-row').querySelector('.field-value');
    if (valueEl.classList.contains('masked')) {
        valueEl.textContent = valueEl.dataset.value;
        valueEl.classList.remove('masked');
        btn.textContent = t('common.hide');
        // Log field show
        const fieldKey = btn.closest('.field-row').querySelector('.field-key')?.textContent || '';
        const entryName = state.selectedEntry?.name || '';
        logFieldAccess('field_show', entryName, fieldKey);
    } else {
        valueEl.textContent = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
        valueEl.classList.add('masked');
        btn.textContent = t('common.show');
    }
}

// What Sezam last put on the clipboard, and whether the page lost focus since.
// While the page keeps focus no other app can have written the clipboard, so
// that is enough proof of ownership when readText() is denied (Firefox,
// Safari, or a refused permission prompt).
const clipboardGuard = { value: null, focusLost: false, pendingClear: null };

function claimClipboard(value) {
    clipboardGuard.value = value;
    clipboardGuard.focusLost = false;
    clipboardGuard.pendingClear = null;
}

// The usual paste happens in ANOTHER app: when the timer fires the page has
// no focus, so the browser refuses both readText() and writeText() and the
// secret used to stay on the clipboard for good (review 2052248). Such a
// clear is retried as soon as the page is focused again.
function retryPendingClipboardClear(guard = clipboardGuard, clipboard = navigator.clipboard) {
    const pending = guard.pendingClear;
    if (pending === null || pending === undefined) return Promise.resolve();
    return clearClipboardIfUnchanged(pending, clipboard, guard);
}

if (typeof window !== 'undefined') {
    window.addEventListener('blur', () => { clipboardGuard.focusLost = true; });
    window.addEventListener('focus', () => { retryPendingClipboardClear(); });
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) clipboardGuard.focusLost = true;
        else retryPendingClipboardClear();
    });
}

async function clearClipboardIfUnchanged(expectedValue, clipboard = navigator.clipboard, guard = clipboardGuard) {
    // A newer Sezam copy owns the clipboard now; its own timer clears it.
    if (guard.value !== expectedValue) {
        guard.pendingClear = null;
        return;
    }
    let current;
    try {
        current = await clipboard.readText();
    } catch (_error) {
        current = undefined;
    }
    if (current === undefined && guard.focusLost) {
        // Never overwrite clipboard contents when ownership cannot be verified;
        // with focus back, readText() usually can verify it.
        guard.pendingClear = expectedValue;
        return;
    }
    if (current !== undefined && current !== expectedValue) {
        guard.value = null;
        guard.pendingClear = null;
        return;
    }
    try {
        await clipboard.writeText('');
        guard.value = null;
        guard.pendingClear = null;
    } catch (_error) {
        // Clearing needs document focus: retry when the page has it again.
        guard.pendingClear = expectedValue;
    }
}

function copyFieldBtn(btn) {
    const valueEl = btn.closest('.field-row').querySelector('.field-value');
    const value = valueEl.dataset.value;
    navigator.clipboard.writeText(value).then(() => {
        claimClipboard(value);
        btn.textContent = t('common.copied');
        setTimeout(() => { btn.textContent = t('common.copy'); }, 2000);
        setTimeout(() => clearClipboardIfUnchanged(value), 15000);
        // Log field copy
        const fieldKey = btn.closest('.field-row').querySelector('.field-key')?.textContent || '';
        const entryName = state.selectedEntry?.name || '';
        logFieldAccess('field_copy', entryName, fieldKey);
    });
}

// ── Password validation ──

const NEW_PASSWORD_MIN_LENGTH = 14;

function meetsNewPasswordPolicy(password) {
    return [...password].length >= NEW_PASSWORD_MIN_LENGTH
        && /\p{Ll}/u.test(password)
        && /\p{Lu}/u.test(password)
        && /[^\p{L}\p{N}\s]/u.test(password);
}

function validateConfirmPassword() {
    const password = document.getElementById('onboard-password')?.value || '';
    const confirm = document.getElementById('onboard-confirm')?.value || '';
    const error = document.getElementById('onboard-error');
    if (!error) return;

    if (confirm && password !== confirm) {
        error.textContent = t('error.password_mismatch');
        error.classList.remove('hidden');
    } else {
        error.classList.add('hidden');
    }
}

// ── Password strength ──

function estimateStrength(password) {
    const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
    const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const DIGITS = '0123456789';
    const SYMBOLS = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~";

    let charsetSize = 0;
    if ([...password].some(c => LOWERCASE.includes(c))) charsetSize += 26;
    if ([...password].some(c => UPPERCASE.includes(c))) charsetSize += 26;
    if ([...password].some(c => DIGITS.includes(c))) charsetSize += 10;
    if ([...password].some(c => SYMBOLS.includes(c))) charsetSize += SYMBOLS.length;

    const entropy = charsetSize > 0 ? password.length * Math.log2(charsetSize) : 0;

    let score, label;
    if (entropy >= 80) { score = 4; label = 'Very Strong'; }
    else if (entropy >= 60) { score = 3; label = 'Strong'; }
    else if (entropy >= 40) { score = 2; label = 'Moderate'; }
    else if (entropy >= 20) { score = 1; label = 'Weak'; }
    else { score = 0; label = 'Very Weak'; }

    return { score, label, entropy: Math.round(entropy) };
}

function updatePasswordStrength(password) {
    const container = document.getElementById('password-strength');
    const fill = document.getElementById('strength-fill');
    const label = document.getElementById('strength-label');
    const entropyEl = document.getElementById('strength-entropy');

    if (!password) {
        container.classList.add('hidden');
        return;
    }

    container.classList.remove('hidden');
    const s = estimateStrength(password);
    fill.setAttribute('data-score', s.score);
    label.setAttribute('data-score', s.score);
    label.textContent = translatedStrengthLabel(s.score);
    entropyEl.textContent = t('strength.bits', { bits: s.entropy });
}

// ── Crypto: Argon2id KDF ──

// Account params within the core's bounds (core/src/kdf.rs, spec 7.2 floor,
// the account ceiling): refused, never raised to the floor (that derives a
// KEK the account does not have) or guessed. In the server's per-account
// format so the exact params can be uploaded with the keypair. Without
// params: the defaults this browser creates accounts with.
function normalizeKdfParams(serverParams) {
    const p = serverParams || { time_cost: 3, memory_cost: 131072, parallelism: 4 };
    const params = { time_cost: p.time_cost, memory_cost: p.memory_cost, parallelism: p.parallelism };
    if (p.hash_len !== undefined) params.hash_len = p.hash_len;
    if (globalThis.SezamSyncCore.call('account_kdf_refusal', params) !== null) {
        throw new Error(t('error.kdf_params_unsupported'));
    }
    return { ...params, hash_len: 64 };
}

// KDF params of an existing account (per-user since server v1.1); legacy
// servers only expose the global web defaults.
// Without either the account's params are unknown: refuse instead of guessing
// 128 MiB (lockout review N2).
function accountKdfParams(meta) {
    const params = meta && (meta.argon2_params || meta.argon2_web_params);
    if (!params) throw new Error(t('error.kdf_params_unsupported'));
    return normalizeKdfParams(params);
}

// The KDF input of a master password is its Unicode NFC form on every client
// (lockout review M8): the same visible password may be typed or pasted
// precomposed or decomposed.
function canonicalPassword(password) {
    return password.normalize('NFC');
}

// KDF inputs to try for an EXISTING password, canonical first. An account
// created before normalization derived from the password exactly as typed,
// possibly decomposed. New passwords use canonicalPassword only.
function passwordForms(password) {
    const forms = [];
    for (const form of [canonicalPassword(password), password, password.normalize('NFD')]) {
        if (!forms.includes(form)) forms.push(form);
    }
    return forms;
}

// options.exact: derive from `password` as given (one of passwordForms).
async function deriveKEK(password, salt, serverParams = null, options = null) {
    if (!options?.exact) password = password.normalize('NFC');
    const normalized = normalizeKdfParams(serverParams);
    const time = normalized.time_cost, mem = normalized.memory_cost;
    const parallelism = normalized.parallelism;
    const params = { time, mem, parallelism };

    // Web Worker (spec 7.2). A worker that ran out of memory or time is not
    // retried on the main thread: the same allocation there kills the tab
    // (Mobile Safari) or freezes the page.
    try {
        return await deriveKEKViaWorker(password, salt, params);
    } catch (workerErr) {
        if (!workerErr.workerUnavailable) {
            console.warn('Argon2 Web Worker failed:', workerErr);
            throw new Error(t('error.kdf_failed'));
        }
        console.warn('Argon2 Web Worker unavailable, using the main thread:', workerErr);
    }

    // No Worker support at all: main-thread argon2 (already loaded via <script>)
    if (typeof argon2 === 'undefined') {
        throw new Error('Argon2 library not loaded. Please refresh the page.');
    }
    const result = await argon2.hash({
        pass: password,
        salt: salt,
        time,
        mem,
        parallelism,
        hashLen: 64,  // 32B KEK + 32B auth_proof
        type: argon2.ArgonType.Argon2id,
    });
    return result.hash instanceof Uint8Array ? result.hash : new Uint8Array(result.hash);
}

function deriveKEKViaWorker(password, salt, params) {
    return new Promise((resolve, reject) => {
        let worker;
        try {
            worker = new Worker('/static/js/argon2-worker.js');
        } catch (e) {
            const err = new Error('Cannot create Argon2 Worker: ' + e.message);
            err.workerUnavailable = true;
            return reject(err);
        }

        // 60 s for default params, more for an account with a high time cost.
        const limitMs = 60000 + Math.max(0, params.time - 3) * 10000;
        const timeout = setTimeout(() => {
            worker.terminate();
            reject(new Error(`Argon2 Worker timed out after ${limitMs / 1000}s`));
        }, limitMs);

        worker.onmessage = function(e) {
            clearTimeout(timeout);
            worker.terminate();
            if (e.data.error) {
                reject(new Error(e.data.error));
            } else {
                resolve(e.data.kek);
            }
        };

        worker.onerror = function(e) {
            clearTimeout(timeout);
            worker.terminate();
            reject(new Error('Argon2 Worker error: ' + (e.message || 'unknown')));
        };

        worker.postMessage({ password, salt, params });
    });
}

// ── IndexedDB ──

function openDB() {
    return new Promise((resolve, reject) => {
        // Version 3 only repairs databases that an old iOS check created at
        // version 2 without any stores; the upgrade adds whatever is missing.
        const req = indexedDB.open('sezam', 3);
        req.onupgradeneeded = (event) => {
            const db = req.result;
            // Version 1 → create 'keys' store
            if (!db.objectStoreNames.contains('keys')) {
                db.createObjectStore('keys', { keyPath: 'id' });
            }
            // Version 2 → create 'known_keys' store for TOFU key cache (spec 2.4)
            if (!db.objectStoreNames.contains('known_keys')) {
                db.createObjectStore('known_keys', { keyPath: 'user_id' });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function saveToIndexedDB(data) {
    const db = await openDB();
    const tx = db.transaction('keys', 'readwrite');
    tx.objectStore('keys').put({ id: 'keypair', ...data });
    await new Promise((resolve, reject) => {
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error);
    });
    // Review 8595ec1 #5: a tab of this account with the old KEK locks now,
    // before it seals anything under it (onWebKeypairChanged).
    if (typeof BroadcastChannel === 'function' && data.encrypted_keypair) {
        const channel = new BroadcastChannel('sezam-keypair');
        channel.postMessage({ userId: data.user_id });
        channel.close();
    }
}

async function loadFromIndexedDB() {
    const db = await openDB();
    const tx = db.transaction('keys', 'readonly');
    const req = tx.objectStore('keys').get('keypair');
    return new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error || new Error('Keypair read failed'));
        tx.onabort = () => reject(tx.error || new Error('Keypair read aborted'));
    });
}

function syncCheckpointRecordId() {
    if (!state.userId || !state.kek) throw new Error('Vault must be unlocked before checkpoint access');
    return `sync_checkpoint:${state.userId}`;
}

function syncCheckpointAAD(sealed = 'device-v2') {
    const version = sealed === 'device-v2' ? 'v2' : 'v1';
    return new TextEncoder().encode(`sezam-sync-checkpoint-${version}:${state.userId}`);
}

// Stateful tests SM89/SM90: sealed with the KEK, the checkpoint was dropped by
// the first sign-in after a password change, org recovery or identity
// rotation elsewhere, and a server restored in between was taken without the
// SM71 question. It guards against the server, not this browser (whoever can
// write here can as well delete it), so a random key of this browser seals
// it, which no key change of the account touches.
async function syncCheckpointKey(sealed, _sodium, create = false) {
    if (sealed !== 'device-v2') return state.kek;
    const id = `sync_checkpoint_key:${state.userId}`;
    const db = await openDB();
    const tx = db.transaction('keys', 'readwrite');
    const store = tx.objectStore('keys');
    return new Promise((resolve, reject) => {
        const req = store.get(id);
        req.onerror = () => reject(req.error || new Error('Checkpoint key read failed'));
        req.onsuccess = () => {
            if (req.result?.key) return resolve(hexToBytes(req.result.key));
            if (!create) return reject(new Error('Checkpoint key is missing'));
            const key = _sodium.randombytes_buf(32);
            const put = store.put({ id, key: bytesToHex(key) });
            put.onerror = () => reject(put.error || new Error('Checkpoint key write failed'));
            put.onsuccess = () => resolve(key);
        };
    });
}

async function loadSyncCheckpoint(_sodium) {
    const db = await openDB();
    const tx = db.transaction('keys', 'readonly');
    const req = tx.objectStore('keys').get(syncCheckpointRecordId());
    const stored = await new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error || new Error('Checkpoint read failed'));
    });
    if (!stored) return null;
    if (!stored.encrypted_checkpoint) {
        throw new Error('Refusing plaintext or malformed sync checkpoint');
    }

    try {
        const packed = hexToBytes(stored.encrypted_checkpoint);
        const nonceLen = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        if (packed.length <= nonceLen) throw new Error('Checkpoint ciphertext is truncated');
        const plaintext = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, packed.slice(nonceLen), syncCheckpointAAD(stored.sealed), packed.slice(0, nonceLen),
            await syncCheckpointKey(stored.sealed, _sodium),
        );
        const checkpoint = JSON.parse(new TextDecoder().decode(plaintext));
        if (!Number.isSafeInteger(checkpoint.last_sync_seq) || checkpoint.last_sync_seq < 0 ||
                // null: a pull with a signer's objects withheld (seq floor only).
                (checkpoint.state_hash !== null && !/^[0-9a-f]{64}$/.test(checkpoint.state_hash || '')) ||
                (checkpoint.live_state_hash != null &&
                    !/^[0-9a-f]{64}$/.test(checkpoint.live_state_hash)) ||
                (checkpoint.commit_token != null && !/^[0-9a-f]{1,64}$/.test(checkpoint.commit_token)) ||
                (checkpoint.team_log != null && (
                    !Number.isSafeInteger(checkpoint.team_log.seq) || checkpoint.team_log.seq < 0 ||
                    !/^[0-9a-f]{64}$/.test(checkpoint.team_log.hash || '') ||
                    !/^[0-9a-f]{64}$/.test(checkpoint.team_log.genesis_hash || ''))) ||
                !Number.isSafeInteger(checkpoint.timestamp)) {
            throw new Error('Checkpoint fields are invalid');
        }
        return checkpoint;
    } catch (err) {
        throw new Error(`Invalid encrypted sync checkpoint: ${err.message}`);
    }
}

async function saveSyncCheckpoint(checkpoint, _sodium) {
    const plaintext = new TextEncoder().encode(JSON.stringify(checkpoint));
    const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, syncCheckpointAAD('device-v2'), null, nonce, await syncCheckpointKey('device-v2', _sodium, true)
    );
    const packed = new Uint8Array(nonce.length + ciphertext.length);
    packed.set(nonce, 0);
    packed.set(ciphertext, nonce.length);

    const db = await openDB();
    const tx = db.transaction('keys', 'readwrite');
    tx.objectStore('keys').put({
        id: syncCheckpointRecordId(),
        encrypted_checkpoint: bytesToHex(packed),
        sealed: 'device-v2',
    });
    await new Promise((resolve, reject) => {
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error || new Error('Checkpoint write failed'));
        tx.onabort = () => reject(tx.error || new Error('Checkpoint write aborted'));
    });
}

function webDirtyStateRecordId() {
    if (!state.userId || !state.kek) throw new Error('Vault must be unlocked before dirty-state access');
    return `dirty_state:${state.userId}`;
}

function webDirtyStateAAD() {
    return new TextEncoder().encode(`sezam-web-dirty-v1:${state.userId}`);
}

async function loadWebDirtyState(_sodium) {
    const db = await openDB();
    const tx = db.transaction('keys', 'readonly');
    const req = tx.objectStore('keys').get(webDirtyStateRecordId());
    const stored = await new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error || new Error('Dirty state read failed'));
    });
    return openWebDirtyState(stored, _sodium);
}

function openWebDirtyState(stored, _sodium) {
    if (!stored) return { objects: {}, conflicts: {}, ops: [], sent: {} };
    if (!stored.encrypted_dirty_state) throw new Error('Refusing plaintext dirty state');
    try {
        const packed = hexToBytes(stored.encrypted_dirty_state);
        const nonceLen = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        if (packed.length <= nonceLen) throw new Error('Dirty state is truncated');
        const plaintext = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, packed.slice(nonceLen), webDirtyStateAAD(), packed.slice(0, nonceLen), state.kek
        );
        const parsed = JSON.parse(new TextDecoder().decode(plaintext));
        if (!parsed.objects || Array.isArray(parsed.objects) ||
                !parsed.conflicts || Array.isArray(parsed.conflicts) ||
                (parsed.ops !== undefined && !validWebOutboxOps(parsed.ops)) ||
                (parsed.sent !== undefined && (!parsed.sent || typeof parsed.sent !== 'object' || Array.isArray(parsed.sent)))) {
            throw new Error('Dirty state fields are invalid');
        }
        return { objects: parsed.objects, conflicts: parsed.conflicts, ops: parsed.ops || [], sent: parsed.sent || {} };
    } catch (err) {
        throw new Error(`Invalid encrypted dirty state: ${err.message}`);
    }
}

async function saveWebDirtyState(objects, conflicts, _sodium, ops = state.outboxOps || []) {
    // A queue this session never loaded is not the one in IndexedDB: saving
    // it would put an empty queue over the stored offline changes.
    if (!state.outboxLoaded) {
        throw new Error('The offline queue of this session is not loaded yet; nothing was saved');
    }
    const id = webDirtyStateRecordId();
    await withWebDirtyStateLock(id, async () => {
        // Review 8595ec1 #5: a tab still open from before a password change
        // (in another tab, or a login that took a change from another device)
        // sealed the queue under the old KEK, and every later login failed on
        // it. Its queue goes aside (the old password restores it) and the tab
        // locks.
        if (!await webKekIsCurrent(_sodium)) {
            if (Object.keys(objects).length || Object.keys(conflicts).length || ops.length) {
                await idbKeysRequest('readwrite', store => store.put({
                    id: `stale_kek:${Date.now()}:${id}`,
                    ...sealWebDirtyState(objects, conflicts, _sodium, ops, state.outboxSent || {}),
                }));
            }
            endSessionWithMessage('sync.stale_tab');
            throw new Error(t('sync.stale_tab'));
        }
        // Nor does a queue this KEK cannot open (such a tab's, written
        // before) get overwritten: it goes aside too.
        const live = await idbKeysRequest('readonly', store => store.get(id));
        const opens = live && webDirtyStateOpens(live, _sodium);
        // Review c78fd19 (web): another tab of this browser saved its own
        // queue whole, and one tab's save dropped what the other had queued,
        // a member's pending removal too. What this tab changed since it last
        // read or wrote the record goes over the stored queue; the rest of it
        // (the other tab's work) stays, and joins this tab's queue.
        const written = JSON.parse(JSON.stringify({ objects, conflicts, ops, sent: state.outboxSent || {} }));
        const merged = mergeWebDirtyState(
            state.outboxBaseline || openWebDirtyState(null, _sodium),
            written,
            opens ? openWebDirtyState(live, _sodium) : openWebDirtyState(null, _sodium),
        );
        const empty = !Object.keys(merged.objects).length && !Object.keys(merged.conflicts).length &&
            !merged.ops.length;
        const db = await openDB();
        const tx = db.transaction('keys', 'readwrite');
        const store = tx.objectStore('keys');
        if (live && !opens) {
            store.put({ ...live, id: `stale_kek:${Date.now()}:${id}` });
        }
        if (empty) {
            store.delete(id);
        } else {
            store.put({ id, ...sealWebDirtyState(merged.objects, merged.conflicts, _sodium, merged.ops, merged.sent) });
        }
        await new Promise((resolve, reject) => {
            tx.oncomplete = resolve;
            tx.onerror = () => reject(tx.error || new Error('Dirty state write failed'));
            tx.onabort = () => reject(tx.error || new Error('Dirty state write aborted'));
        });
        // The callers hold these very objects (or make them the session's).
        // Review 8bc70f7 M7: what this tab queued while the record was
        // written (another save, a Retry) stays over it; the next save writes it.
        const now = mergeWebDirtyState(written, { objects, conflicts, ops, sent: state.outboxSent || {} }, merged);
        replaceWebKeyed(objects, now.objects);
        replaceWebKeyed(conflicts, now.conflicts);
        ops.splice(0, ops.length, ...now.ops);
        state.outboxSent = now.sent;
        state.outboxBaseline = JSON.parse(JSON.stringify(merged));
    });
}

// One save of the queue record at a time in all tabs of this browser.
function withWebDirtyStateLock(id, op) {
    const locks = globalThis.navigator?.locks;
    return locks?.request ? locks.request(`sezam:${id}`, op) : op();
}

/**
 * Each id as this tab has it if this tab changed it since `baseline`, else as
 * stored. What this tab took out (sent, settled) stays when another tab
 * changed it meanwhile: that is a newer write.
 */
function mergeWebKeyed(baseline, mine, stored) {
    const has = (map, id) => Object.prototype.hasOwnProperty.call(map, id);
    const same = (a, b, id) => has(a, id) === has(b, id) && JSON.stringify(a[id]) === JSON.stringify(b[id]);
    const merged = { ...stored };
    for (const id of new Set([...Object.keys(baseline), ...Object.keys(mine)])) {
        if (same(baseline, mine, id)) continue;
        if (has(mine, id)) merged[id] = mine[id];
        else if (same(baseline, stored, id)) delete merged[id];
    }
    return merged;
}

function mergeWebDirtyState(baseline, mine, stored) {
    const opKey = op => `${op.kind}:${op.revoked_user_id}`;
    const byKey = list => Object.fromEntries(list.map(op => [opKey(op), op]));
    const ops = mergeWebKeyed(byKey(baseline.ops), byKey(mine.ops), byKey(stored.ops));
    const order = [...new Set([...stored.ops, ...mine.ops].map(opKey))];
    const objects = mergeWebKeyed(baseline.objects, mine.objects, stored.objects);
    // A record of what was sent lasts as long as its write waits.
    const sent = Object.fromEntries(Object.entries(mergeWebKeyed(baseline.sent, mine.sent, stored.sent))
        .filter(([id]) => objects[id]));
    return {
        objects,
        conflicts: mergeWebKeyed(baseline.conflicts, mine.conflicts, stored.conflicts),
        ops: order.filter(key => ops[key]).map(key => ops[key]),
        sent,
    };
}

function replaceWebKeyed(target, source) {
    for (const id of Object.keys(target)) {
        if (!Object.prototype.hasOwnProperty.call(source, id)) delete target[id];
    }
    Object.assign(target, source);
}

function sealWebDirtyState(objects, conflicts, _sodium, ops = [], sent = null) {
    const record = sent && Object.keys(sent).length ? { objects, conflicts, ops, sent } : { objects, conflicts, ops };
    const plaintext = new TextEncoder().encode(JSON.stringify(record));
    const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, webDirtyStateAAD(), null, nonce, state.kek
    );
    const packed = new Uint8Array(nonce.length + ciphertext.length);
    packed.set(nonce, 0);
    packed.set(ciphertext, nonce.length);
    // kdf (public): a copy set aside after a password change elsewhere
    // opens with the previous password (review 688edcb, web #4). The members
    // whose removal waits (public, as the admin's user list shows them) are
    // finished from the server's state without that password; has_changes
    // says whether there is more that needs it.
    return {
        encrypted_dirty_state: bytesToHex(packed), kdf: state.kdf || null,
        revocations: ops.filter(op => op.kind === 'rekey').map(op => op.revoked_user_id),
        has_changes: Object.keys(objects).length > 0,
    };
}

function validWebOutboxOps(ops) {
    return Array.isArray(ops) && ops.every(op => op && op.kind === 'rekey' &&
        typeof op.revoked_user_id === 'string' && ['prepared', 'pushed'].includes(op.phase) &&
        Array.isArray(op.objects));
}

function webDirtyStateOpens(stored, _sodium) {
    try {
        const packed = hexToBytes(stored.encrypted_dirty_state || '');
        const nonceLen = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, packed.slice(nonceLen), webDirtyStateAAD(), packed.slice(0, nonceLen), state.kek
        );
        return true;
    } catch {
        return false;
    }
}

/**
 * Whether this tab's KEK still opens the keypair this browser caches for its
 * account (review 8595ec1 #5). After a password change in another tab, or a
 * login there that took a change from another device, it does not: this
 * tab's KEK is the old one. A cache of another account says nothing.
 */
async function webKekIsCurrent(_sodium) {
    const stored = await loadFromIndexedDB();
    if (!stored || !stored.encrypted_keypair || stored.user_id !== state.userId) return true;
    try {
        const opened = decryptLoginKeypair(hexToBytes(stored.encrypted_keypair), state.kek, stored.user_id, _sodium);
        _sodium.memzero(opened.keypairBytes);
        return true;
    } catch {
        return false;
    }
}

/** Another tab cached a keypair (BroadcastChannel 'sezam-keypair'). */
async function onWebKeypairChanged(message, _sodium) {
    if (!state.kek || !message || message.userId !== state.userId) return;
    const session = state.sessionSerial;
    if (!await webKekIsCurrent(_sodium) && session === state.sessionSerial) {
        endSessionWithMessage('sync.stale_tab');
    }
}

function webWriteGrantsAAD() {
    return new TextEncoder().encode(`sezam-web-write-grants-v1:${state.userId}`);
}

/**
 * Ids of the 'write' envelopes this browser made (its re-keys). Review
 * a159e97 H3 (desktop vouched_access_level): an envelope's access_level is
 * not signed, so only these may carry 'write' into a new envelope. An empty
 * set when unreadable (sealed under a previous password): read access only.
 */
async function loadWebWriteGrants(_sodium) {
    const stored = await idbKeysRequest('readonly', store => store.get(`write_grants:${state.userId}`));
    if (!stored || !stored.encrypted_grants) return new Set();
    try {
        const packed = hexToBytes(stored.encrypted_grants);
        const nonceLen = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        const plaintext = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, packed.slice(nonceLen), webWriteGrantsAAD(), packed.slice(0, nonceLen), state.kek
        );
        const parsed = JSON.parse(new TextDecoder().decode(plaintext));
        return new Set(Array.isArray(parsed) ? parsed.filter(id => typeof id === 'string') : []);
    } catch {
        return new Set();
    }
}

async function saveWebWriteGrants(grants, _sodium) {
    const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        new TextEncoder().encode(JSON.stringify([...grants].sort())), webWriteGrantsAAD(), null, nonce, state.kek
    );
    const packed = new Uint8Array(nonce.length + ciphertext.length);
    packed.set(nonce, 0);
    packed.set(ciphertext, nonce.length);
    await idbKeysRequest('readwrite', store => store.put({
        id: `write_grants:${state.userId}`, encrypted_grants: bytesToHex(packed),
    }));
}

async function retryAllWebDirtyObjects() {
    // The queue in order: its re-key operations first, each the one atomic
    // batch it was built as. Sent object by object, a partly accepted re-key
    // leaves folders whose entries and key envelopes disagree (lockout review
    // M5); the writes after it are resealed under the keys it made.
    const _sodium = await ensureSodium();
    const problems = [];
    for (const revokedUserId of await pendingWebRevocations()) {
        try {
            await finishWebRevocation(revokedUserId, _sodium);
        } catch (err) {
            if (!err.rekeyTooLarge && !err.teamLogRefused) throw err;
            problems.push(err.message);  // the rest of the Retry goes on (S3, H4)
        }
    }
    // Review d150605 S2: an object queued over the 1 MiB limit (by an older
    // version) stopped this loop, so nothing after it went out. It stays
    // queued and is named; the banner can drop it.
    // INV-7: a refusal is what the last pull saw; the push decides from the
    // log the server serves now (as the desktop's push reads it again), so a
    // log put back sends what waited for it.
    let pulled = !!state.teamLogRefusal;
    if (pulled) await pullAndBuildTree();
    let oversized = oversizedQueuedObjects();
    let waiting = [];
    let waitingForLog = [];
    const sent = new Set();
    for (;;) {  // at most twice: the second pass runs on a pull
        waiting = [];
        waitingForLog = [];
        let context = {};
        let refusedByLastPull = false;
        const pending = webPushOrder(Object.values(state.outbox));
        for (const object of pending) {
            if (oversized.includes(object) || sent.has(object.id)) continue;
            const resealed = await resealUnderFolderSuccessor(object, object.version, context);
            if (['dek', 'dek_archive'].includes(object.object_type)) context = {};  // the keys may change
            if (!resealed) {
                waiting.push(object.id);  // stays queued until the new key arrives
                continue;
            }
            try {
                await pushEncryptedVaultObject(resealed);
                sent.add(object.id);
            } catch (err) {
                // A team write waits for the log; the personal ones still go out.
                if (state.teamLogRefusal && err === state.teamLogRefusal) {
                    waitingForLog.push(object.id);
                    continue;
                }
                // R16-Z SM17: the rule refused it by the log of this page's last
                // pull (a folder waiting for a re-key another device has made
                // since). The server's log decides, as the desktop's push reads
                // it again: pulled, the write is resealed under the new key.
                if (!err.teamLogRefused || pulled) throw err;
                refusedByLastPull = true;
                break;
            }
        }
        if (!refusedByLastPull) break;
        pulled = true;
        await pullAndBuildTree();
        oversized = oversizedQueuedObjects();
    }
    await pullAndBuildTree();
    if (waiting.length) {
        problems.push(t('sync.queued_waits_for_key', { count: waiting.length, ids: waiting.join(', ') }));
    }
    if (waitingForLog.length) problems.push(state.teamLogRefusal?.message || waitingForLog.join(', '));
    if (oversized.length) {
        problems.push(t('sync.queued_too_large', {
            count: oversized.length, ids: oversized.map(object => object.id).join(', '),
        }));
    }
    if (problems.length) throw new Error(problems.join('\n'));
}

// Review c78fd19 (web): the queue went out in the order it was made, so an
// item queued before the new offline folder it was moved into was refused
// (no such folder) and stayed a conflict for good. Keys first, folders
// parent before child, then the rest: the shared core's order (core/src/order.rs).
function webPushOrder(objects) {
    const order = globalThis.SezamSyncCore.call('order_pulled', {
        objects: objects.map(o => ({ id: o.id, object_type: o.object_type || '', parent_ref: o.parent_ref || null })),
    });
    return order.map(index => objects[index]);
}

function oversizedQueuedObjects() {
    return Object.values(state.outbox || {}).filter(
        object => syncPayloadBytes(object) > MAX_OBJECT_PAYLOAD_BYTES
    );
}

function renderWebSyncConflicts() {
    let banner = document.getElementById('sync-conflict-banner');
    const conflicts = Object.values(state.syncConflicts || {});
    const oversized = oversizedQueuedObjects();
    if (!conflicts.length && !oversized.length) {
        if (banner) banner.remove();
        return;
    }
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'sync-conflict-banner';
        banner.className = 'sync-conflict-banner';
        document.body.appendChild(banner);
    }
    banner.replaceChildren();
    const message = document.createElement('span');
    message.textContent = conflicts.map(conflict => t('sync.conflict', {
        id: conflict.local_object.id,
        local: conflict.local_object.version,
        server: conflict.server_object.version,
    })).concat(oversized.map(object => t('sync.queued_object_too_large', {
        id: object.id, size: Math.ceil(syncPayloadBytes(object) / 1024),
        max: MAX_OBJECT_PAYLOAD_BYTES / 1024,
    }))).join('; ');
    const retry = document.createElement('button');
    retry.type = 'button';
    retry.textContent = t('sync.retry');
    retry.addEventListener('click', () => retryAllWebDirtyObjects().catch(err => alert(err.message || err)));
    const exportButton = document.createElement('button');
    exportButton.type = 'button';
    exportButton.textContent = t('sync.export');
    exportButton.addEventListener('click', () => exportWebDirtyObjects(Object.values(state.outbox)));
    // Retry alone can never succeed against a newer server version, so the
    // conflict stayed forever (review 2052248).
    const useServer = document.createElement('button');
    useServer.type = 'button';
    useServer.textContent = t('sync.use_server');
    useServer.addEventListener('click', () => {
        if (!window.confirm(t('sync.use_server_confirm', { count: conflicts.length }))) return;
        exportWebDirtyObjects(conflicts.map(conflict => conflict.local_object));
        discardWebConflictedChanges(conflicts.map(conflict => conflict.local_object.id))
            .catch(err => alert(err.message || err));
    });
    banner.append(message, retry, exportButton);
    if (conflicts.length) banner.append(useServer);
    if (oversized.length) {
        // The server never takes it: drop it (an encrypted copy is exported first).
        const drop = document.createElement('button');
        drop.type = 'button';
        drop.textContent = t('sync.drop_too_large');
        drop.addEventListener('click', () => {
            if (!window.confirm(t('sync.drop_too_large_confirm', { count: oversized.length }))) return;
            exportWebDirtyObjects(oversized);
            discardWebConflictedChanges(oversized.map(object => object.id))
                .catch(err => alert(err.message || err));
        });
        banner.append(drop);
    }
}

/** Drop the queued local versions of `ids`; a full pull shows the server's. */
async function discardWebConflictedChanges(ids) {
    const _sodium = await ensureSodium();
    await withWebSyncLock(async () => {
        const outbox = { ...state.outbox };
        const conflicts = { ...state.syncConflicts };
        for (const id of ids) {
            delete outbox[id];
            delete conflicts[id];
        }
        await saveWebDirtyState(outbox, conflicts, _sodium);
        state.outbox = outbox;
        state.syncConflicts = conflicts;
        // A delta pull would not resend server objects we already saw. M7:
        // the full pull still meets the copies held here.
        state.fullPullHeld = state.syncObjects;
        state.syncObjects = null;
        await pullAndBuildTreeLocked();
    });
    renderWebSyncConflicts();
}

// S3 (docs/SYNC_SINGLE_SOURCE.md 3.8): a revocation's re-key is an operation
// of the outbox (state.outboxOps, sealed in the same record as the queued
// writes), not a record of its own beside it.

function webOutboxOps() {
    if (!state.outboxLoaded) {
        throw new Error('The offline queue of this session is not loaded yet');
    }
    return state.outboxOps || [];
}

/** The members whose removal waits in the outbox, in queue order. */
async function pendingWebRevocations() {
    return webOutboxOps().filter(op => op.kind === 'rekey').map(op => op.revoked_user_id);
}

async function loadWebRekeyJournal(revokedUserId, _sodium) {
    const op = webOutboxOps().find(o => o.kind === 'rekey' && o.revoked_user_id === revokedUserId);
    return op ? JSON.parse(JSON.stringify(op)) : null;
}

/** Replace the queue's operations with `change(ops)`, under the sync lock. */
function changeWebOutboxOps(change, _sodium) {
    return withWebSyncLock(async () => {
        const ops = change([...webOutboxOps()]);
        await saveWebDirtyState(state.outbox, state.syncConflicts, _sodium, ops);
        state.outboxOps = ops;
    });
}

/** Queue the re-key of `journal.revoked_user_id`, or update it in its place. */
async function saveWebRekeyJournal(journal, _sodium) {
    const op = { ...JSON.parse(JSON.stringify(journal)), kind: 'rekey' };
    await changeWebOutboxOps(ops => {
        const at = ops.findIndex(o => o.kind === 'rekey' && o.revoked_user_id === op.revoked_user_id);
        if (at >= 0) ops[at] = op; else ops.push(op);
        return ops;
    }, _sodium);
}

async function clearWebRekeyJournal(revokedUserId, _sodium) {
    await changeWebOutboxOps(
        ops => ops.filter(o => !(o.kind === 'rekey' && o.revoked_user_id === revokedUserId)), _sodium
    );
}

// Before S3 the re-key waited in a `pending_rekey:` record of its own.

function webRekeyJournalRecordId(revokedUserId) {
    if (!state.userId || !state.kek) throw new Error('Vault must be unlocked before re-key access');
    return `pending_rekey:${state.userId}:${revokedUserId}`;
}

function webRekeyJournalAAD(revokedUserId) {
    return new TextEncoder().encode(`sezam-web-rekey-v1:${state.userId}:${revokedUserId}`);
}

async function legacyWebRekeyRecordIds() {
    const ids = await idbKeysRequest('readonly', store => store.getAllKeys());
    const prefix = `pending_rekey:${state.userId}:`;
    return (ids || []).filter(id => typeof id === 'string' && id.startsWith(prefix));
}

async function loadLegacyWebRekeyJournal(revokedUserId, _sodium) {
    const stored = await idbKeysRequest('readonly', store => store.get(webRekeyJournalRecordId(revokedUserId)));
    if (!stored) return null;
    if (!stored.encrypted_journal) throw new Error('Refusing plaintext or malformed re-key journal');

    try {
        const packed = hexToBytes(stored.encrypted_journal);
        const nonceLen = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        if (packed.length <= nonceLen) throw new Error('Re-key journal is truncated');
        const plaintext = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, packed.slice(nonceLen), webRekeyJournalAAD(revokedUserId),
            packed.slice(0, nonceLen), state.kek
        );
        const journal = JSON.parse(new TextDecoder().decode(plaintext));
        if (journal.revoked_user_id !== revokedUserId ||
                !['prepared', 'pushed'].includes(journal.phase) ||
                !Array.isArray(journal.objects)) {
            throw new Error('Re-key journal fields are invalid');
        }
        return journal;
    } catch (err) {
        throw new Error(`Invalid encrypted re-key journal: ${err.message}`);
    }
}

/**
 * Move the re-key records of an older version into the outbox. The copies of
 * their objects an even older version queued as single writes go: they leave
 * only in the re-key's atomic batch. A record this KEK does not open stays
 * (the login sets it aside). Call with the queue loaded.
 */
async function adoptLegacyWebRekeyJournals(_sodium) {
    const ids = await legacyWebRekeyRecordIds();
    if (!ids.length) return;
    const prefix = `pending_rekey:${state.userId}:`;
    const ops = [...webOutboxOps()];
    const outbox = { ...state.outbox };
    const conflicts = { ...state.syncConflicts };
    const adopted = [];
    for (const id of ids) {
        let journal;
        try {
            journal = await loadLegacyWebRekeyJournal(id.slice(prefix.length), _sodium);
        } catch {
            continue;
        }
        if (!journal) continue;
        if (!ops.some(op => op.kind === 'rekey' && op.revoked_user_id === journal.revoked_user_id)) {
            ops.push({ ...journal, kind: 'rekey' });
        }
        for (const obj of journal.objects) {
            if (outbox[obj.id] && outbox[obj.id].payload === obj.payload) {
                delete outbox[obj.id];
                delete conflicts[obj.id];
            }
        }
        adopted.push(id);
    }
    if (!adopted.length) return;
    await saveWebDirtyState(outbox, conflicts, _sodium, ops);
    state.outbox = outbox;
    state.syncConflicts = conflicts;
    state.outboxOps = ops;
    await idbKeysRequest('readwrite', store => {
        for (const id of adopted) store.delete(id);
        return null;
    });
}

/**
 * After the password changed on another device, move the records this
 * browser sealed under the old KEK out of the way: the checkpoint is dropped
 * (the next pull is a full one), the outbox (unsent changes and re-keys) and
 * an older version's re-key records are kept under a `stale_kek:` id instead
 * of deleted. Records the current KEK still opens stay. Returns true when
 * unsent data was set aside.
 */
async function setAsideRecordsOfOldKek(_sodium, checkpoint = true) {
    const prefix = `pending_rekey:${state.userId}:`;
    const candidates = [
        { id: webDirtyStateRecordId(), keep: true, load: () => loadWebDirtyState(_sodium) },
    ];
    if (checkpoint) {
        candidates.push({ id: syncCheckpointRecordId(), keep: false, load: () => loadSyncCheckpoint(_sodium) });
    }
    for (const id of await legacyWebRekeyRecordIds()) {
        const revokedUserId = id.slice(prefix.length);
        candidates.push({ id, keep: true, load: () => loadLegacyWebRekeyJournal(revokedUserId, _sodium) });
    }
    const unreadable = [];
    for (const candidate of candidates) {
        try {
            await candidate.load();
        } catch {
            unreadable.push(candidate);
        }
    }
    if (!unreadable.length) return false;
    const records = await Promise.all(unreadable.map(
        c => idbKeysRequest('readonly', store => store.get(c.id))
    ));
    const stamp = Date.now();
    await idbKeysRequest('readwrite', store => {
        unreadable.forEach((candidate, i) => {
            if (candidate.keep && records[i]) {
                store.put({ ...records[i], id: `stale_kek:${stamp}:${candidate.id}` });
            }
            store.delete(candidate.id);
        });
        return null;
    });
    // The stored queue went aside, not to another tab's push: what this tab
    // read of it says nothing about the record now.
    if (unreadable.some(candidate => candidate.id === webDirtyStateRecordId())) state.outboxBaseline = null;
    return unreadable.some((candidate, i) => candidate.keep && records[i]);
}

// Review 688edcb (web #4): nothing read the records set aside above again, so
// unsent changes were lost and a re-key journal set aside mid-revocation left
// the member in place with access. A revocation needs no old password: the
// revoked member is public in the record (`revocations`; the record id of an
// older version's re-key record) and the re-key is rebuilt from the server's
// state. Unsent changes open with the previous password, derived with the
// salt and KDF params stored next to them.

async function listSetAsideRecords() {
    const ids = await idbKeysRequest('readonly', store => store.getAllKeys());
    const dirtyId = `dirty_state:${state.userId}`;
    const rekeyPrefix = `pending_rekey:${state.userId}:`;
    const found = { changes: [], revocations: [] };
    for (const id of ids || []) {
        if (typeof id !== 'string' || !id.startsWith('stale_kek:')) continue;
        const original = id.split(':').slice(2).join(':');
        if (original === dirtyId) {
            const record = await idbKeysRequest('readonly', store => store.get(id));
            if (!record) continue;
            if (record.has_changes !== false) found.changes.push(id);
            for (const revokedUserId of record.revocations || []) {
                found.revocations.push({ id, revokedUserId, queued: true });
            }
        }
        if (original.startsWith(rekeyPrefix)) {
            found.revocations.push({ id, revokedUserId: original.slice(rekeyPrefix.length) });
        }
    }
    return found;
}

/**
 * Finish revocations set aside by a password change; returns the unfinished
 * ones. Review e4cd15a (low): the next login may come days later, so each
 * removal is confirmed again; a declined one is dropped (the member stays and
 * can be removed again from the admin panel).
 */
async function finishSetAsideWebRevocations(_sodium) {
    const unfinished = [];
    const revocations = (await listSetAsideRecords()).revocations;
    if (!revocations.length) return unfinished;
    let names = new Map();
    try {
        const users = await apiFetch('/api/users');
        if (Array.isArray(users)) names = new Map(users.map(user => [user.id, user.username]));
    } catch {
        // Names only label the question; the ids still identify the members.
    }
    for (const revocation of revocations) {
        const { revokedUserId } = revocation;
        const label = names.get(revokedUserId) || revokedUserId;
        if (!window.confirm(t('sync.set_aside_revocation_confirm', { user: label }))) {
            await dropSetAsideRevocation(revocation);
            continue;
        }
        try {
            await finishWebRevocation(revokedUserId, _sodium);
            await dropSetAsideRevocation(revocation);
        } catch (err) {
            console.warn(`Set-aside revocation of ${revokedUserId} not finished:`, err.message || err);
            unfinished.push(revokedUserId);
        }
    }
    return unfinished;
}

/** A set-aside outbox keeps its changes (for the old password) when its re-key is done. */
async function dropSetAsideRevocation(revocation) {
    const { id, revokedUserId, queued } = revocation;
    const record = queued ? await idbKeysRequest('readonly', store => store.get(id)) : null;
    const revocations = (record?.revocations || []).filter(user => user !== revokedUserId);
    await idbKeysRequest('readwrite', store => (
        record && (revocations.length || record.has_changes !== false)
            ? store.put({ ...record, revocations })
            : store.delete(id)
    ));
}

async function openSetAsideWebChanges(recordId, oldPassword, _sodium) {
    const stored = await idbKeysRequest('readonly', store => store.get(recordId));
    if (!stored || !stored.encrypted_dirty_state) throw new Error('Refusing plaintext dirty state');
    if (!stored.kdf || !stored.kdf.argon2_salt || !stored.kdf.argon2_params) {
        // Set aside by a version that did not keep the salt: no password opens it.
        const err = new Error(t('sync.set_aside_unrecoverable'));
        err.unrecoverable = true;
        throw err;
    }
    const packed = hexToBytes(stored.encrypted_dirty_state);
    const nonceLen = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    for (const form of passwordForms(oldPassword)) {
        const derived = await deriveKEK(
            form, hexToBytes(stored.kdf.argon2_salt), stored.kdf.argon2_params, { exact: true }
        );
        const oldKek = derived.slice(0, 32);
        _sodium.memzero(derived);
        try {
            const plaintext = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                null, packed.slice(nonceLen), webDirtyStateAAD(), packed.slice(0, nonceLen), oldKek
            );
            return { oldKek, objects: JSON.parse(new TextDecoder().decode(plaintext)).objects || {} };
        } catch {
            _sodium.memzero(oldKek);
        }
    }
    throw new Error(t('sync.set_aside_wrong_password'));
}

/**
 * Put unsent changes set aside by a password change back into the queue.
 * A new DEK among them is wrapped under the old KEK: it is re-wrapped under
 * the current one, or the folder it opens would be unreadable once pushed.
 * A change made in this session to the same object wins. Returns the count.
 */
async function restoreSetAsideWebChanges(recordId, oldPassword, _sodium) {
    const { oldKek, objects } = await openSetAsideWebChanges(recordId, oldPassword, _sodium);
    const restored = {};
    try {
        for (const object of Object.values(objects)) {
            if (['node', 'entry'].includes(object.object_type)) {
                // Signed again: an identity rotation elsewhere (conformance
                // scenario ref_rotates_identity_with_a_member) left the old
                // signature, and the server refused it for good.
                restored[object.id] = await buildSignedSyncObject(
                    _sodium, object, base64ToBytes(object.payload));
                continue;
            }
            if (object.object_type !== 'dek') {
                restored[object.id] = object;
                continue;
            }
            const dek = unwrapDEK(base64ToBytes(object.payload), oldKek, object.id, object.version, _sodium);
            try {
                const wrapped = wrapDEK(dek, object.id, object.version, state.kek, _sodium);
                restored[object.id] = await buildSignedSyncObject(_sodium, object, wrapped);
            } finally {
                _sodium.memzero(dek);
            }
        }
    } finally {
        _sodium.memzero(oldKek);
    }
    await withWebSyncLock(async () => {
        const outbox = { ...restored, ...state.outbox };
        await saveWebDirtyState(outbox, state.syncConflicts, _sodium);
        state.outbox = outbox;
    });
    await discardSetAsideWebChanges([recordId]);
    return Object.keys(restored).length;
}

/** When a set-aside record was set aside (its id carries the time). */
function setAsideStamp(recordId) {
    return Number(recordId.split(':')[1]) || 0;
}

/**
 * Restore the set-aside changes the password opens, newest record first
 * (review 4acfdde R11): an object restored from a newer record is in the
 * queue when an older record comes, and the queue's copy wins, so an older
 * version of an edit never replaces a newer one. A record the password does
 * not open no longer keeps every newer one back; the older ones wait behind
 * it (until its own password restores it, or it is discarded on its own),
 * or they would win over it. A record no password opens holds nothing back.
 * Returns { restored, waiting }; throws when the password opened none.
 */
async function restoreAllSetAsideWebChanges(oldPassword, _sodium) {
    const { changes } = await listSetAsideRecords();
    let restored = 0, opened = 0, waiting = 0, refusal = null, unrecoverable = null;
    for (const id of [...changes].sort((a, b) => setAsideStamp(b) - setAsideStamp(a))) {
        if (refusal) {
            waiting += 1;
            continue;
        }
        try {
            restored += await restoreSetAsideWebChanges(id, oldPassword, _sodium);
            opened += 1;
        } catch (err) {
            if (!err.unrecoverable) {
                refusal = err;
                waiting += 1;
            } else {
                unrecoverable = err;
            }
        }
    }
    if (!opened && (refusal || unrecoverable)) throw refusal || unrecoverable;
    return { restored, waiting };
}

/** The changes go; a removal still waiting in the same set-aside record stays. */
async function discardSetAsideWebChanges(recordIds) {
    const records = await Promise.all(recordIds.map(id => idbKeysRequest('readonly', store => store.get(id))));
    await idbKeysRequest('readwrite', store => {
        recordIds.forEach((id, i) => {
            if (records[i]?.revocations?.length) store.put({ ...records[i], has_changes: false });
            else store.delete(id);
        });
        return null;
    });
}

async function renderSetAsideWebChanges() {
    const { changes } = await listSetAsideRecords();
    let banner = document.getElementById('set-aside-banner');
    if (!changes.length) {
        if (banner) banner.remove();
        return;
    }
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'set-aside-banner';
        banner.className = 'sync-conflict-banner';
        document.body.appendChild(banner);
    }
    banner.replaceChildren();
    const message = document.createElement('span');
    message.textContent = t('sync.set_aside_changes');
    // Review 4acfdde R11: one Discard dropped every record; each goes on its own.
    const list = document.createElement('ul');
    for (const id of [...changes].sort((a, b) => setAsideStamp(b) - setAsideStamp(a))) {
        const row = document.createElement('li');
        const when = document.createElement('span');
        when.textContent = t('sync.set_aside_record', { when: new Date(setAsideStamp(id)).toLocaleString() });
        const drop = document.createElement('button');
        drop.type = 'button';
        drop.textContent = t('sync.set_aside_discard');
        drop.addEventListener('click', () => {
            if (!window.confirm(t('sync.set_aside_discard_confirm'))) return;
            discardSetAsideWebChanges([id]).then(renderSetAsideWebChanges)
                .catch(err => alert(err.message || err));
        });
        row.append(when, drop);
        list.append(row);
    }
    const password = document.createElement('input');
    password.type = 'password';
    password.autocomplete = 'current-password';
    password.placeholder = t('sync.set_aside_old_password');
    const restore = document.createElement('button');
    restore.type = 'button';
    restore.textContent = t('sync.set_aside_restore');
    restore.addEventListener('click', async () => {
        try {
            const _sodium = await ensureSodium();
            const { waiting } = await restoreAllSetAsideWebChanges(password.value, _sodium);
            password.value = '';
            await renderSetAsideWebChanges();
            await retryAllWebDirtyObjects();
            if (waiting) alert(t('sync.set_aside_older_wait', { count: waiting }));
        } catch (err) {
            alert(err.message || err);
        }
    });
    banner.append(message, list, password, restore);
}

// ── KEK rotation journal (org recovery) ──
// Holds only ciphertext under the NEW KEK plus public data, so a crash
// between server writes can be resumed by logging in with the new password.

function kekRotationRecordId(username) {
    return `pending_kek_rotation:${username}`;
}

async function idbKeysRequest(mode, op) {
    const db = await openDB();
    const tx = db.transaction('keys', mode);
    const req = op(tx.objectStore('keys'));
    return new Promise((resolve, reject) => {
        tx.oncomplete = () => resolve(req ? req.result : undefined);
        tx.onerror = () => reject(tx.error || new Error('Key store access failed'));
        tx.onabort = () => reject(tx.error || new Error('Key store access aborted'));
    });
}

async function saveKekRotationJournal(journal) {
    await idbKeysRequest('readwrite', store => store.put({
        id: kekRotationRecordId(journal.username), journal,
    }));
}

async function loadKekRotationJournal(username) {
    const record = await idbKeysRequest('readonly', store => store.get(kekRotationRecordId(username)));
    return record && record.journal ? record.journal : null;
}

async function clearKekRotationJournal(username) {
    await idbKeysRequest('readwrite', store => store.delete(kekRotationRecordId(username)));
}

// Idempotent replay (review 2052248 #1): ONE push carries the re-wrapped DEKs,
// the key_epoch advance and the new key material, which the server applies in
// a single transaction — never new DEK wraps under an old password or the
// reverse. Then the recovery blob.
async function applyKekRotationJournal(
    journal, authProof, signingSk, _sodium, recoverySigningSk = null, currentProof = null
) {
    if (!journal.deks.length && !journal.publishes_anchor) throw new Error(t('recovery.no_active_dek'));
    let keyEpoch = Number(journal.key_epoch);
    if (journal.key_epoch === undefined) {
        // Journal written before epochs were journaled: advance the current one.
        const head = await apiFetch('/api/sync?since_commit_seq=0');
        keyEpoch = Number(head && head.key_epoch) + 1;
    }
    if (!Number.isSafeInteger(keyEpoch) || keyEpoch < 1) {
        throw new Error('Invalid key rotation journal');
    }
    // Replacing key material needs a fresh challenge signed by the signing key.
    const challenge = await apiFetch('/api/auth/challenge', {
        method: 'POST', body: { username: journal.username }, noAuth: true,
    });
    const challengeSig = signAuthChallenge(challenge.challenge, signingSk, _sodium);
    const keyRotation = {
        encrypted_keypair: journal.encrypted_keypair,
        argon2_salt: journal.argon2_salt,
        auth_salt: journal.argon2_salt, // legacy field; Option B derives proof from argon2_salt
        auth_proof: bytesToHex(authProof),
        argon2_params: journal.argon2_params,
        challenge: challenge.challenge,
        signature: bytesToHex(challengeSig),
    };
    if (currentProof) keyRotation.current_auth_proof = bytesToHex(currentProof);
    if (recoverySigningSk) {
        // Review 688edcb K1: without the old password the server takes the
        // new one only on proof of the reconstructed recovery key.
        const recoveryChallenge = await apiFetch('/api/org-recovery/challenge', {
            method: 'POST', body: {}, noAuth: true,
        });
        keyRotation.recovery_challenge = recoveryChallenge.challenge;
        keyRotation.recovery_signature = bytesToHex(
            signAuthChallenge(recoveryChallenge.challenge, recoverySigningSk, _sodium)
        );
    }
    let resp;
    try {
        resp = await postAtomicSyncBatch(journal.deks, {
            key_epoch: keyEpoch,
            key_rotation: keyRotation,
        });
    } catch (err) {
        // Another device changed the password first (same or newer epoch):
        // this rotation lost for good. Resending it would fail forever, so
        // drop it; the account password is now the other device's.
        if (String(err && err.message).startsWith('Stale key epoch')) {
            await clearKekRotationJournal(journal.username);
            throw new KeyEpochChangedError();
        }
        // Review e4cd15a (low): every other 409 refuses this exact journal for
        // good (a data key added or changed elsewhere since it was written).
        // It used to be resent at every login, forever; drop it and say so.
        if (err && err.status === 409) {
            await clearKekRotationJournal(journal.username);
            throw new KekRotationRefusedError();
        }
        throw err;
    }
    // The rotation bumps token_epoch: every older token, ours included, is dead.
    if (resp && resp.token) state.token = resp.token;
    const accepted = new Set(((resp && resp.accepted) || []).map(obj => obj.id));
    const conflicts = new Map(((resp && resp.conflicts) || []).map(obj => [obj.id, obj]));
    for (const obj of journal.deks) {
        if (accepted.has(obj.id)) continue;
        const conflict = conflicts.get(obj.id);
        // Already applied by an interrupted earlier attempt.
        if (!conflict || conflict.server_payload_hash !== obj.payload_hash) {
            throw new Error(t('recovery.rewrap_rejected'));
        }
    }
    state.keyEpoch = Math.max(state.keyEpoch || 0, keyEpoch);
    state.keyMaterialHash = bytesToHex(_sodium.crypto_hash_sha256(hexToBytes(journal.encrypted_keypair)));
    let stored = null;
    if (journal.recovery_store) {
        try {
            const body = journalRecoveryStore(journal, keyEpoch);
            await apiFetch('/api/org-recovery/store', { method: 'POST', body });
            stored = body;
        } catch (err) {
            // A journal from before review d615826 has no recovery signature;
            // the password change itself landed. Org recovery then reports
            // stale and is set up again.
            if (!(err && err.status === 403)) throw err;
            console.warn('The server did not re-store the org recovery blob:', err.message || err);
        }
    }
    await clearKekRotationJournal(journal.username);
    return stored; // the org recovery blob now stored, for the team log
}

// Hex auth proof of `password` when it is the password of this session's KEK
// (review e4cd15a #1: the server registers a new recovery key only with it),
// else null.
async function currentPasswordProof(password) {
    if (!password || !state.kek || !state.kdf) return null;
    const _sodium = await ensureSodium();
    const salt = hexToBytes(state.kdf.argon2_salt);
    for (const form of passwordForms(password)) {
        const derived = await deriveKEK(form, salt, state.kdf.argon2_params, { exact: true });
        try {
            if (_sodium.memcmp(derived.subarray(0, 32), state.kek)) {
                return bytesToHex(derived.subarray(32, 64));
            }
        } finally {
            _sodium.memzero(derived);
        }
    }
    return null;
}

// Review 18c300f R16-L4: version 1 used the Shamir recovery secret itself as
// the blob's AEAD key and the Ed25519 seed. Version 2 (every new setup)
// derives each with HKDF-SHA256 under its own label, as key_rotation.py does;
// version 1 recoveries keep working. A new setup is version 2.
async function orgRecoveryKeys(secret, version, _sodium) {
    const encode = (text) => new TextEncoder().encode(text);
    let wrapKey;
    let seed;
    if (version === 1) {
        wrapKey = secret.slice();
        seed = secret.slice();
    } else if (version === 2) {
        const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
        const derive = async (purpose) => new Uint8Array(await crypto.subtle.deriveBits({
            name: 'HKDF', hash: 'SHA-256', salt: encode('sezam-org-recovery-v2'),
            info: encode('sezam/org-recovery/v2/' + purpose),
        }, ikm, 256));
        wrapKey = await derive('kek-wrap');
        seed = await derive('ed25519');
    } else {
        throw new Error('Unknown org recovery version ' + version);
    }
    const signing = _sodium.crypto_sign_seed_keypair(seed);
    _sodium.memzero(seed);
    return { version, wrapKey, signing, aad: encode('sezam-org-recovery-v' + version) };
}

// The server's blob of the recovery the secret rebuilds: the server knows a
// recovery by the Ed25519 key of its version, newest version first.
async function fetchOrgRecoveryBlob(secret, _sodium) {
    let recoveryKeys = null;
    let blobResp = null;
    for (const version of [2, 1]) {
        recoveryKeys = await orgRecoveryKeys(secret, version, _sodium);
        blobResp = await fetch(API_BASE + '/api/org-recovery/blob?recovery_signing_pk='
            + bytesToHex(recoveryKeys.signing.publicKey));
        if (blobResp.status !== 404) break;
        _sodium.memzero(recoveryKeys.wrapKey);
        _sodium.memzero(recoveryKeys.signing.privateKey);
    }
    return { recoveryKeys, blobResp };
}

// Bytes the recovery key signs to re-store its server blob without the
// password (review d615826); the core's (docs/CORE_UNIFICATION.md U6c).
function orgRecoveryRewrapMessage(userId, keyEpoch, threshold, totalShares, wrappedKek) {
    return hexToBytes(globalThis.SezamSyncCore.call('org_recovery_rewrap_message', {
        user_id: userId, key_epoch: Number(keyEpoch), threshold, total_shares: totalShares,
        wrapped_kek: bytesToHex(wrappedKek),
    }));
}

// The blob carries the epoch of the KEK it wraps (review 688edcb #3b).
// Journals saved before that have it only as the journal's own key_epoch.
function journalRecoveryStore(journal, keyEpoch) {
    const store = journal.recovery_store;
    return { ...store, key_epoch: store.key_epoch ?? keyEpoch };
}

// After a login whose resume of the journal failed: if the server already
// serves the journal's key material, its push went through and only the
// recovery blob may be missing. Store that and drop the journal; if even that
// fails, the journal stays and the next login tries again (without blocking).
async function settleUnfinishedKekRotation(journal, meta) {
    if (!journal || !meta || !meta.argon2_salt ||
            String(journal.argon2_salt).toLowerCase() !== String(meta.argon2_salt).toLowerCase()) {
        return false;
    }
    try {
        if (journal.recovery_store) {
            let keyEpoch = Number(journal.key_epoch);
            if (journal.key_epoch === undefined) {
                // The server serves this journal's key material: its epoch is the KEK's.
                const head = await apiFetch('/api/sync?since_commit_seq=0');
                keyEpoch = Number(head && head.key_epoch);
            }
            await apiFetch('/api/org-recovery/store', {
                method: 'POST', body: journalRecoveryStore(journal, keyEpoch),
            });
        }
        await clearKekRotationJournal(journal.username);
        return true;
    } catch (err) {
        console.warn('Could not finish the recovery part of a password change:', err.message || err);
        return false;
    }
}

// Called at login: if an org-recovery rotation was interrupted and the typed
// password is the NEW one, finish the server writes before normal login.
async function resumeKekRotation(username, password, _sodium) {
    const journal = await loadKekRotationJournal(username);
    if (!journal) return false;
    const derived = await deriveKEK(password, hexToBytes(journal.argon2_salt), journal.argon2_params);
    let keypairBytes = null;
    let recoverySk = null;
    let currentProof = null;
    const previousToken = state.token;
    try {
        try {
            ({ keypairBytes } = decryptLoginKeypair(
                hexToBytes(journal.encrypted_keypair), derived.subarray(0, 32), journal.user_id, _sodium
            ));
        } catch {
            return false; // not the new password — continue with the normal login
        }
        const signingSk = keypairBytes.subarray(0, 64);
        const challenge = await apiFetch('/api/auth/challenge', {
            method: 'POST', body: { username }, noAuth: true,
        });
        const signature = signAuthChallenge(challenge.challenge, signingSk, _sodium);
        const auth = await apiFetch('/api/auth/verify', {
            method: 'POST',
            body: { username, challenge: challenge.challenge, signature: bytesToHex(signature) },
            noAuth: true,
        });
        state.token = auth.token;
        // Review 688edcb K1 (capability run 79): the server takes the new
        // password only on proof of the recovery key, and the first attempt's
        // challenge is spent. The journal holds that key under the new KEK,
        // so the resume signs a fresh challenge itself.
        recoverySk = journalRecoverySigningSk(journal, derived.subarray(0, 32), _sodium);
        currentProof = openJournalSecret(
            journal.current_proof, journalCurrentProofAad(journal.user_id), derived.subarray(0, 32), _sodium
        );
        const stored = await applyKekRotationJournal(
            journal, derived.subarray(32, 64), signingSk, _sodium, recoverySk, currentProof
        );
        return stored || true;
    } finally {
        state.token = previousToken;
        if (keypairBytes) _sodium.memzero(keypairBytes);
        if (recoverySk) _sodium.memzero(recoverySk);
        if (currentProof) _sodium.memzero(currentProof);
        _sodium.memzero(derived);
    }
}

// The org recovery signing key travels in the journal sealed under the NEW
// KEK, so only the new password can resume the rotation with it.
function journalRecoverySkAad(userId) {
    return new TextEncoder().encode(`sezam-kek-journal-recovery-sk-v1:${userId}`);
}

function sealJournalSecret(secret, aad, newKek, _sodium) {
    const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(secret, aad, null, nonce, newKek);
    const sealed = new Uint8Array(nonce.length + ciphertext.length);
    sealed.set(nonce, 0);
    sealed.set(ciphertext, nonce.length);
    return bytesToHex(sealed);
}

function openJournalSecret(sealedHex, aad, newKek, _sodium) {
    if (!sealedHex) return null;
    const sealed = hexToBytes(sealedHex);
    if (sealed.length < 25) return null;
    try {
        return _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, sealed.slice(24), aad, sealed.slice(0, 24), newKek
        );
    } catch {
        return null;
    }
}

function sealJournalRecoverySigningSk(recoverySk, newKek, userId, _sodium) {
    return sealJournalSecret(recoverySk, journalRecoverySkAad(userId), newKek, _sodium);
}

function journalRecoverySigningSk(journal, newKek, _sodium) {
    return openJournalSecret(journal.recovery_signing_sk, journalRecoverySkAad(journal.user_id), newKek, _sodium);
}

// An anchor publication changes the password: the server takes it on the
// proof of the OLD one, kept in the journal under the new KEK for the resume.
function journalCurrentProofAad(userId) {
    return new TextEncoder().encode(`sezam-kek-journal-current-proof-v1:${userId}`);
}

// ── TOFU Key Cache (spec 2.4) ──

/**
 * Save a user's public keys to the known_keys IndexedDB store.
 * Used for Trust On First Use (TOFU) key pinning.
 *
 * @param {string} userId
 * @param {string} signingPk   - hex-encoded signing public key
 * @param {string} encryptionPk - hex-encoded encryption public key
 */
async function saveKnownKey(userId, signingPk, encryptionPk) {
    const db = await openDB();
    const tx = db.transaction('known_keys', 'readwrite');
    tx.objectStore('known_keys').put({
        user_id: userId,
        signing_pk: signingPk,
        encryption_pk: encryptionPk,
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
    });
    return new Promise((resolve, reject) => {
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error || new Error('TOFU key write failed'));
        tx.onabort = () => reject(tx.error || new Error('TOFU key write aborted'));
    });
}

/** The pinned {signing_pk, encryption_pk} (hex) of a user, or null; pins nothing. */
async function getKnownKey(userId) {
    const db = await openDB();
    const tx = db.transaction('known_keys', 'readonly');
    const req = tx.objectStore('known_keys').get(userId);
    return new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error || new Error('TOFU key read failed'));
        tx.onabort = () => reject(tx.error || new Error('TOFU key read aborted'));
    });
}

/**
 * Check a user's public keys against the TOFU cache.
 * Returns: 'ok' | 'new' | 'changed'
 *  - 'ok': keys match stored record
 *  - 'new': no stored record (trust on first use → auto-save)
 *  - 'changed': keys differ from stored record → MITM warning
 *
 * @param {string} userId
 * @param {string} signingPk   - hex-encoded signing public key
 * @param {string} encryptionPk - hex-encoded encryption public key
 * @returns {Promise<'ok'|'new'|'changed'>}
 */
async function checkKnownKey(userId, signingPk, encryptionPk) {
    const db = await openDB();
    const tx = db.transaction('known_keys', 'readonly');
    const req = tx.objectStore('known_keys').get(userId);
    const stored = await new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error || new Error('TOFU key read failed'));
        tx.onabort = () => reject(tx.error || new Error('TOFU key read aborted'));
    });

    if (!stored) {
        // Trust on first use succeeds only after the pin is persisted.
        await saveKnownKey(userId, signingPk, encryptionPk);
        return 'new';
    }

    if (stored.signing_pk === signingPk && stored.encryption_pk === encryptionPk) {
        const db2 = await openDB();
        const tx2 = db2.transaction('known_keys', 'readwrite');
        stored.last_seen = new Date().toISOString();
        tx2.objectStore('known_keys').put(stored);
        await new Promise((resolve, reject) => {
            tx2.oncomplete = resolve;
            tx2.onerror = () => reject(tx2.error || new Error('TOFU timestamp write failed'));
            tx2.onabort = () => reject(tx2.error || new Error('TOFU timestamp write aborted'));
        });
        return 'ok';
    }

    // Keys changed — potential MITM
    return 'changed';
}

/**
 * A pinned key no longer matches (review 2052248 #7). Typed so a failed login
 * can wipe the session and still show the "accept new key" dialog again —
 * otherwise resetSession() removes it and the login can never succeed.
 */
class TofuKeyChangeError extends Error {
    constructor(username, userId, signingPkHex, encryptionPkHex) {
        super(`TOFU key change rejected for ${userId}`);
        this.name = 'TofuKeyChangeError';
        this.username = username;
        this.userId = userId;
        this.signingPkHex = signingPkHex;
        this.encryptionPkHex = encryptionPkHex;
    }
}

/** Show the key-change dialog and return the typed error to throw. */
function tofuKeyChange(username, userId, signingPkHex, encryptionPkHex) {
    showMITMWarning(username, userId, signingPkHex, encryptionPkHex);
    return new TofuKeyChangeError(username, userId, signingPkHex, encryptionPkHex);
}

/**
 * Show a MITM warning modal when a user's key has changed.
 * Spec: "GUI zobrazí varovanie pri zmene kľúča"
 */
function showMITMWarning(username, userId, signingPk, encryptionPk) {
    // Check if warning already shown for this user in this session
    if (!state._mitmWarnings) state._mitmWarnings = new Set();
    if (state._mitmWarnings.has(userId)) return;
    state._mitmWarnings.add(userId);

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.style.zIndex = '10000';
    overlay.innerHTML = `
        <div class="modal-panel modal-panel-small">
            <div class="modal-inner">
                <h2 class="modal-title mitm-title" data-i18n="mitm.title">${escapeHtml(t('mitm.title'))}</h2>
                <p class="modal-message mitm-message" data-i18n-html="mitm.message">${t('mitm.message', { username: escapeHtml(username || userId) })}</p>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn cancel mitm-accept-btn" data-i18n="mitm.accept">${escapeHtml(t('mitm.accept'))}</button>
                    <button type="button" class="modal-btn danger mitm-dismiss-btn" data-i18n="mitm.close">${escapeHtml(t('mitm.close'))}</button>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);
    overlay.querySelector('[data-i18n-html="mitm.message"]').dataset.i18nValues = JSON.stringify({
        username: escapeHtml(username || userId),
    });

    overlay.querySelector('.mitm-dismiss-btn').addEventListener('click', () => {
        overlay.remove();
    });

    overlay.querySelector('.mitm-accept-btn').addEventListener('click', async () => {
        // User explicitly accepts the new key — update the TOFU cache
        if (signingPk && encryptionPk) {
            await acceptChangedKey(userId, signingPk, encryptionPk);
        }
        overlay.remove();
    });
}

/**
 * Accept a changed key (update TOFU cache with new keys).
 */
async function acceptChangedKey(userId, signingPk, encryptionPk) {
    await saveKnownKey(userId, signingPk, encryptionPk);
}

// ── JWT refresh ──

/**
 * Parse JWT payload to get expiration time.
 * Returns exp as Unix timestamp (seconds), or null if invalid.
 */
function getJwtExp(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        return payload.exp || null;
    } catch {
        return null;
    }
}

/**
 * Attempt to refresh the JWT token.
 * Returns true if refresh succeeded, false if the server refused it (401/403:
 * the session is over), 'unavailable' for anything else (network, 5xx, 429).
 */
async function refreshJWT() {
    if (_refreshInFlight) return _refreshInFlight;
    if (!state.token || !state.keypair?.signingSk) return false;
    _refreshInFlight = (async () => {
        const challengeResp = await fetchWithTimeout(API_BASE + '/api/auth/challenge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: state.username }),
        });
        if (!challengeResp.ok) return 'unavailable';
        const challenge = await challengeResp.json();
        const _sodium = await ensureSodium();
        const signature = signAuthChallenge(challenge.challenge, state.keypair.signingSk, _sodium);

        const url = API_BASE + '/api/auth/refresh';
        const resp = await fetchWithTimeout(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${state.token}`,
            },
            body: JSON.stringify({
                challenge: challenge.challenge,
                signature: bytesToHex(signature),
            }),
        });
        // Review d615826: any failure here ended the session, so a network
        // blip or a busy server signed the user out and dropped the keys.
        if (resp.status === 403) return false;
        if (resp.status === 401) return reverifySession(_sodium);
        if (!resp.ok) return 'unavailable';
        const data = await resp.json();
        if (data.token) {
            state.token = data.token;
            return true;
        }
        return 'unavailable';
    })().catch(() => 'unavailable').finally(() => { _refreshInFlight = null; });
    return _refreshInFlight;
}

/**
 * Review 7c10379: the server revokes the old token as it issues the new one,
 * so a refresh whose response was lost left the page only a revoked token and
 * the next refresh ended the session. A refused refresh now signs in again
 * with this session's keypair. The session still ends when the server refuses
 * that too, or when the account's key material is no longer the one this
 * session holds (a password change elsewhere revokes every token, SM67).
 */
async function reverifySession(_sodium) {
    if (!state.keyMaterialHash || !state.userId) return false;
    const challengeResp = await fetchWithTimeout(API_BASE + '/api/auth/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: state.username }),
    });
    if (!challengeResp.ok) return 'unavailable';
    const challenge = await challengeResp.json();
    const signature = signAuthChallenge(challenge.challenge, state.keypair.signingSk, _sodium);
    const resp = await fetchWithTimeout(API_BASE + '/api/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: state.username,
            challenge: challenge.challenge,
            signature: bytesToHex(signature),
        }),
    });
    // Any other refusal (409: another device rotated the identity key) ends
    // the session too; only a busy or failing server leaves it.
    if (resp.status === 429 || resp.status >= 500) return 'unavailable';
    if (!resp.ok) return false;
    const data = await resp.json();
    if (!data.token || data.user_id !== state.userId ||
            data.key_material_hash !== state.keyMaterialHash) {
        return false;
    }
    state.token = data.token;
    return true;
}

/**
 * Start periodic JWT refresh timer. Checks every 5 minutes;
 * refreshes if token expires within 10 minutes.
 */
function startJwtRefreshTimer() {
    if (_jwtRefreshTimer) clearInterval(_jwtRefreshTimer);
    _jwtRefreshTimer = setInterval(async () => {
        if (!state.token) return;
        const exp = getJwtExp(state.token);
        if (!exp) return;
        const nowSec = Math.floor(Date.now() / 1000);
        // Refresh if token expires within 10 minutes
        if (exp - nowSec < 600) {
            await refreshJWT();
        }
    }, 5 * 60 * 1000); // every 5 minutes
}

// ── API fetch ──

// Review a159e97 (web, medium): the sync lock had no timeout. A request the
// server (or a dead connection) never answered held it for good: every later
// pull, push and the lock's own sign-in waited behind it until a reload. Each
// request of a sync run now fails after this long (body included), which
// releases the lock; the run is retried like after a network error.
const WEB_FETCH_TIMEOUT_MS = 5 * 60 * 1000;

async function fetchWithTimeout(url, init = {}, timeoutMs = WEB_FETCH_TIMEOUT_MS) {
    // The signal also ends a body that stops arriving (resp.json()).
    try {
        return await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    } catch (err) {
        if (err?.name !== 'TimeoutError') throw err;
        throw new Error(`No answer from the server in ${timeoutMs / 1000} s`);
    }
}

async function apiFetch(path, options = {}) {
    const url = API_BASE + path;
    const headers = {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
    };
    if (state.token && !headers['Authorization']) {
        headers['Authorization'] = `Bearer ${state.token}`;
    }

    const resp = await fetchWithTimeout(url, {
        method: options.method || 'GET',
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
    });

    // On 401, attempt JWT refresh and retry once (skip for auth endpoints to avoid loops)
    if (resp.status === 401 && state.token && !path.startsWith('/api/auth/')) {
        const refreshed = await refreshJWT();
        if (refreshed === 'unavailable') {
            // Keep the session: the next request tries the refresh again.
            throw new Error(t('error.session_refresh_unavailable'));
        }
        if (refreshed === true) {
            // Retry the original request with the new token
            const retryHeaders = {
                'Content-Type': 'application/json',
                ...(options.headers || {}),
                'Authorization': `Bearer ${state.token}`,
            };
            const retryResp = await fetchWithTimeout(url, {
                method: options.method || 'GET',
                headers: retryHeaders,
                body: options.body ? JSON.stringify(options.body) : undefined,
            });
            if (retryResp.status === 410) throw new Error('410 Gone — full resync required');
            if (!retryResp.ok) {
                const err = await retryResp.json().catch(() => ({ detail: retryResp.statusText }));
                throw new Error(err.detail || `HTTP ${retryResp.status}`);
            }
            return retryResp.json();
        }
        // Stateful test (web): the server revoked the session (a password
        // change on another device revokes every token) and it cannot be
        // refreshed. The page stayed unlocked and every save failed on
        // "Token revoked"; it now ends the session and asks to sign in again.
        endSessionWithMessage('error.session_ended');
        throw new Error(t('error.session_ended'));
    }

    // W2: 410 Gone — propagate as error for caller to handle
    if (resp.status === 410) {
        throw new Error('410 Gone — full resync required');
    }

    if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        const error = new Error(err.detail || `HTTP ${resp.status}`);
        error.status = resp.status;
        error.code = typeof err.code === 'string' ? err.code : null;  // server/app/errors.py
        throw error;
    }

    return resp.json();
}

// ── Utils ──

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Safe for element text AND quoted attribute values (data-value="…", value='…').
function escapeHtml(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function normalize(s) {
    return s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

// ── ULID generator ──

function generateULID() {
    const ENCODING = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    // Encode 48-bit timestamp as 10 Crockford base32 characters
    let ts = Date.now();
    let timePart = '';
    for (let i = 0; i < 10; i++) {
        timePart = ENCODING[ts & 0x1f] + timePart;
        ts = Math.floor(ts / 32);
    }

    // Encode 80 bits of randomness as 16 Crockford base32 characters
    const randomBytes = new Uint8Array(10);
    crypto.getRandomValues(randomBytes);
    let randomPart = '';
    let bitBuffer = 0;
    let bitsInBuffer = 0;
    for (let i = 0; i < 10 && randomPart.length < 16; i++) {
        bitBuffer = (bitBuffer << 8) | randomBytes[i];
        bitsInBuffer += 8;
        while (bitsInBuffer >= 5 && randomPart.length < 16) {
            bitsInBuffer -= 5;
            randomPart += ENCODING[(bitBuffer >> bitsInBuffer) & 0x1f];
        }
    }

    return timePart + randomPart;
}

// Capability review run 140: the archive id of a re-key that removed a
// member tags it under the new key, so a desktop's grant again can tell the
// member this re-key withdrew from a grant it never saw (desktop
// dek.removal_archive_id; same bytes). The core (core/src/rekey_archive.rs)
// builds what is hashed and encodes it; the keyed BLAKE2b under the new DEK
// stays here.
function removalArchiveId(newDekId, newDek, removedUserId, _sodium) {
    const messages = globalThis.SezamSyncCore.call('removal_archive_messages',
        { new_dek_id: newDekId, user_id: removedUserId });
    const digest = name => bytesToHex(_sodium.crypto_generichash(16, hexToBytes(messages[name]), newDek));
    return globalThis.SezamSyncCore.call('removal_archive_id',
        { prefix: generateULID().slice(0, 10), mark: digest('mark'), member: digest('member') });
}

// ── SHA-256 hex ──

// payload_hash = SHA-256 over the RAW payload bytes (spec 8.2), NOT the base64
// text. Must match server C2 (sha256(base64decode(payload))) and desktop/mobile.
async function sha256hexBytes(bytes) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(hashBuffer));
}

function buildServerAuditCanonical(id, userId, action, timestamp, requestHash) {
    const encoder = new TextEncoder();
    const timestampBuffer = new ArrayBuffer(8);
    new DataView(timestampBuffer).setBigUint64(0, BigInt(timestamp), false);
    const parts = [
        encoder.encode(id),
        encoder.encode(userId),
        encoder.encode(action),
        new Uint8Array(timestampBuffer),
        hexToBytes(requestHash),
    ];
    const canonical = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        canonical.set(part, offset);
        offset += part.length;
    }
    return canonical;
}

// ── Sync a vault object to server ──

// The tree shows the queued local version of a conflicted object, so a new
// edit would get local+1 — enough to outrank the colleague's server version
// and silently overwrite it. Only a retry of the queued version may go out.
function assertNotStackedOnConflict(vaultObj, conflicts = state.syncConflicts) {
    const conflict = (conflicts || {})[vaultObj.id];
    if (conflict && Number(vaultObj.version) > Number(conflict.local_object.version)) {
        const err = new Error(t('sync.edit_blocked'));
        err.isSyncConflict = true;
        throw err;
    }
}

// Review 526419e #1: what one POST /api/sync may carry (server/app/models/
// schemas.py). Over it the request was refused as a whole, on every retry.
const MAX_OBJECT_PAYLOAD_BYTES = 1024 * 1024;
// Review d150605 #3: an all-or-nothing batch over one request is staged in
// parts (POST /api/sync/stage) up to the server's MAX_STAGED_* limits.
const MAX_STAGED_OBJECTS = 100000;
const MAX_STAGED_BYTES = 255 * 1024 * 1024;

function syncPayloadBytes(obj) {
    const b64 = obj.payload || '';
    return Math.floor(b64.length * 3 / 4) - (b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0);
}

function assertSyncObjectFits(obj) {
    const size = syncPayloadBytes(obj);
    if (size > MAX_OBJECT_PAYLOAD_BYTES) {
        const err = new Error(t('sync.object_too_large', {
            size: Math.ceil(size / 1024), max: MAX_OBJECT_PAYLOAD_BYTES / 1024,
        }));
        err.syncUnitTooLarge = true;
        throw err;
    }
}

// An all-or-nothing batch the server could never take is refused with the reason.
function assertSyncUnitFits(objects) {
    objects.forEach(assertSyncObjectFits);
    const bytes = objects.reduce((sum, obj) => sum + JSON.stringify(obj).length + 1, 0);
    if (objects.length > MAX_STAGED_OBJECTS || bytes > MAX_STAGED_BYTES) {
        const err = new Error(t('sync.unit_too_large', {
            count: objects.length, kib: Math.ceil(bytes / 1024),
        }));
        err.syncUnitTooLarge = true;
        throw err;
    }
}

function splitForPush(objects) {
    // Chunk sizes from the core (docs/CORE_UNIFICATION.md U6); the bytes each
    // object takes in the request are this encoder's.
    const counts = globalThis.SezamSyncCore.call('split_for_push', {
        sizes: objects.map((obj) => JSON.stringify(obj).length + 1),
    });
    let start = 0;
    return counts.map((count) => objects.slice(start, start += count));
}

// One all-or-nothing push (review d150605 #3): the parts over one request go
// to /api/sync/stage first and the last request applies all of it at once.
async function postAtomicSyncBatch(objects, fields) {
    assertSyncUnitFits(objects);
    const chunks = splitForPush(objects);
    const body = { ...fields, objects: chunks[chunks.length - 1] || [], atomic_batch: true };
    if (chunks.length > 1) {
        const batchId = generateULID();
        let staged = 0;
        for (const chunk of chunks.slice(0, -1)) {
            await apiFetch('/api/sync/stage', {
                method: 'POST', body: { batch_id: batchId, start: staged, objects: chunk },
            });
            staged += chunk.length;
        }
        body.staged_batch_id = batchId;
        body.staged_count = staged;
    }
    return apiFetch('/api/sync', { method: 'POST', body });
}

function pushEncryptedVaultObject(vaultObj) {
    return withWebSyncShared(() => pushEncryptedVaultObjectLocked(vaultObj));
}

// docs/SYNC_SINGLE_SOURCE.md point 1: a folder or entry change names the
// server copy it was made on by version AND payload hash. A queued change
// keeps that base when it is edited again or re-sealed; a new object has none.
function webBase(id) {
    const queued = state.outbox[id];
    if (queued) {
        return queued.base_version != null && queued.base_payload_hash
            ? { version: Number(queued.base_version), payload_hash: queued.base_payload_hash }
            : null;
    }
    const pulled = state.syncObjects?.[id];
    const accepted = state.acceptedBases[id];
    const copy = accepted && (!pulled || Number(accepted.version) > Number(pulled.version))
        ? accepted : pulled;
    return copy && copy.payload_hash
        ? { version: Number(copy.version), payload_hash: copy.payload_hash }
        : null;
}

function withWebBase(vaultObj) {
    if (!['node', 'entry'].includes(vaultObj.object_type) || vaultObj.base_version != null) {
        return vaultObj;
    }
    const base = webBase(vaultObj.id);
    if (!base) return vaultObj;
    return { ...vaultObj, base_version: base.version, base_payload_hash: base.payload_hash };
}

/**
 * Review 8bc70f7 M7: an edit saved after a push of the same item whose reply
 * was lost (or while it was out) has that push's version number: the tree had
 * not moved on. The pull takes the landed push as its base (adopt_as_base),
 * and a write not above its base was refused as not newer on every Retry.
 * Sealed again one above its base, as the desktop's edits always are.
 */
async function renumberedAboveBase(vaultObj) {
    if (!['node', 'entry'].includes(vaultObj.object_type) || vaultObj.base_version == null ||
            Number(vaultObj.version) > Number(vaultObj.base_version)) {
        return vaultObj;
    }
    const dekId = payloadDekId(vaultObj);
    if (!dekId || !state.deks[dekId]) return vaultObj;  // refused as before; the queue keeps it
    const _sodium = await ensureSodium();
    const bytes = base64ToBytes(vaultObj.payload);
    const payloadData = vaultObj.object_type === 'entry'
        ? decryptEntryPayload(bytes, vaultObj.id, vaultObj.version, state.deks, _sodium)
        : decryptEnvelope(bytes, vaultObj.id, vaultObj.version, state.deks, _sodium, BLOB_KIND.NODE_META);
    const sealed = await sealVaultObject({
        ...vaultObj, payloadData, dekId, version: Number(vaultObj.base_version) + 1,
    });
    return { ...sealed, base_version: vaultObj.base_version, base_payload_hash: vaultObj.base_payload_hash };
}

async function pushEncryptedVaultObjectLocked(vaultObj) {
    vaultObj = await renumberedAboveBase(withWebBase(vaultObj));
    assertNotStackedOnConflict(vaultObj);
    assertTeamLogAllowsWrite(vaultObj);
    // Never queued: it could never be sent (review 526419e #1).
    assertSyncObjectFits(vaultObj);
    const _sodium = await ensureSodium();
    state.outbox[vaultObj.id] = vaultObj;
    state.outboxSent = rememberWebSent(state.outboxSent || {}, vaultObj);
    await saveWebDirtyState(state.outbox, state.syncConflicts, _sodium);
    const resp = await apiFetch('/api/sync', {
        method: 'POST',
        body: {
            objects: [vaultObj],
            atomic_batch: false,
            key_epoch: state.keyEpoch,
        },
    });
    const conflicts = (resp && resp.conflicts) || [];
    const conflict = conflicts.find((c) => c.id === vaultObj.id) ||
        (conflicts.length ? conflicts[0] : null);
    if (conflict) {
        const serverVer = conflict.server_version != null ? conflict.server_version : '?';
        state.syncConflicts[vaultObj.id] = {
            local_object: vaultObj,
            server_object: {
                id: vaultObj.id,
                version: conflict.server_version,
                payload_hash: conflict.server_payload_hash,
            },
            detected_at: Date.now(),
        };
        await saveWebDirtyState(state.outbox, state.syncConflicts, _sodium);
        renderWebSyncConflicts();
        // R16-Z SM22: another device moved the new parent into this folder
        // first; sent again it is refused again ('Use the server's version').
        const err = new Error(conflict.code === 'folder_move_cycle'
            ? `Sync conflict: "${vaultObj.id}" cannot move: the new parent is inside this folder ` +
              "(moved there on another device). Use the server's version to keep the folder where it is."
            : `Sync conflict: "${vaultObj.id}" was modified on the server (server version ${serverVer}). ` +
              'Your encrypted local change remains queued for export or retry.'
        );
        err.isSyncConflict = true;
        err.conflict = conflict;
        throw err;
    }
    const accepted = (resp && resp.accepted) || [];
    if (!accepted.some((acceptedObj) => acceptedObj.id === vaultObj.id)) {
        throw new Error(`Sync failed: object "${vaultObj.id}" was not accepted by the server.`);
    }
    // Review 526419e #2: only the version that was sent leaves the queue. An
    // edit saved while this request was out (a Retry racing a new save) was
    // dropped with it and never reached the server.
    if (isSameSyncVersion(state.outbox[vaultObj.id], vaultObj)) {
        delete state.outbox[vaultObj.id];
    }
    if (['node', 'entry'].includes(vaultObj.object_type)) {
        state.acceptedBases[vaultObj.id] = {
            version: Number(vaultObj.version), payload_hash: vaultObj.payload_hash,
        };
    }
    // A refusal (no server version: the log refused the key it was sealed
    // with) is settled by any accepted copy - conformance scenario
    // member_revoked_under_an_unsent_write: resealed under the folder's new
    // key, the write went out and its refusal stayed as an open conflict.
    const settled = state.syncConflicts[vaultObj.id];
    if (settled && (Number(settled.local_object.version) < Number(vaultObj.version) ||
            settled.server_object?.version == null ||
            isSameSyncVersion(settled.local_object, vaultObj))) {
        delete state.syncConflicts[vaultObj.id];
    }
    await saveWebDirtyState(state.outbox, state.syncConflicts, _sodium);
    renderWebSyncConflicts();
}

// Review d150605 S4: also the content. An edit saved while a push of the same
// object was out gets the same version (the tree has not moved on yet); with
// the version alone it left the queue with the accepted one and was lost.
function isSameSyncVersion(queued, sent) {
    return Boolean(queued) &&
        Number(queued.version) === Number(sent.version) &&
        Boolean(queued.is_deleted) === Boolean(sent.is_deleted) &&
        queued.payload === sent.payload;
}

// Review 18c300f R16-M1: an edit names the server copy it was made on when it
// is made, not when it is sent. A pull that brought another device's version
// while the edit was sealed (or waited for the sync lock) became its base, and
// the edit was renumbered over that version: the other device's change was
// lost without a conflict. Now the server sees the old base: a conflict shown.
// A queued change keeps its queue's base (a pull never replaces it).
function webBaseNow(id) {
    if (state.outbox[id]) return {};
    const base = webBase(id);
    return base ? { base_version: base.version, base_payload_hash: base.payload_hash } : {};
}

async function pushVaultObject(obj) {
    // Keep the exact encrypted payload until the server explicitly accepts it.
    // A later full resync can therefore export every unsynchronised change.
    const base = ['node', 'entry'].includes(obj.object_type) ? webBaseNow(obj.id) : {};
    await pushEncryptedVaultObject({ ...await sealVaultObject(obj), ...base });
}

async function pushVaultObjectLocked(obj) {
    await pushEncryptedVaultObjectLocked(await sealVaultObject(obj));
}

/** The DEK named in a node's or entry's ciphertext header, or null. */
function payloadDekId(vaultObj) {
    if (!vaultObj.payload || !['node', 'entry'].includes(vaultObj.object_type)) return null;
    let bytes = base64ToBytes(vaultObj.payload);
    if (vaultObj.object_type === 'entry') bytes = bytes.slice(4);
    if (!isEncryptedEnvelope(bytes)) return null;
    return new TextDecoder().decode(bytes.slice(3, 29)).replace(/\0/g, '');
}

/**
 * What every reseal of one pass reads: whether the log is trusted, the signed
 * archives' successors and the keys held. Review 8bc70f7 M8: read again for
 * each write (each archive unwrapped, the log's founder walked), a pass over
 * many writes was quadratic.
 */
function resealContext(_sodium) {
    return {
        trusted: Boolean(state.teamLog?.team) && webTeamLogTrusted(_sodium),
        successors: provenDekSuccessors(),
        held: Object.keys(state.deks),
    };
}

/**
 * Stateful test SM70: a change queued here before its folder was re-keyed
 * (a member removed) still named the folder's old DEK, which the removed
 * member holds; Retry sent it as it was. Sealed again under the folder's
 * current DEK, the way the desktop reseals its unsent items.
 */
async function resealUnderFolderSuccessor(vaultObj, version = vaultObj.version, context = {}) {
    // R16-N1: a tombstone keeps the blob of the version below it (a restore
    // queues it again so), and goes as it is, as on the desktop and phone: the
    // trash keeps the old key. Opened at its own version, Retry threw.
    if (vaultObj.is_deleted) return vaultObj;
    const dekId = payloadDekId(vaultObj);
    const dekObject = dekId && state.syncObjects?.[dekId];
    const oldKey = state.deks[dekId] || state.supersededDeks?.[dekId];
    if (!dekObject || dekObject.object_type !== 'dek' || !oldKey) {
        return vaultObj;
    }
    // Review d615826 H3: the key a signed archive names as this one's
    // replacement (also when the retired key came back unbound, run 134);
    // for a team folder the log's current key. The shared core decides
    // (capability review run 365), as on the desktop and phone.
    const _sodium = await ensureSodium();
    context.pass ??= resealContext(_sodium);  // a caller's {} is filled once per pass
    const { trusted, successors, held } = context.pass;
    const team = trusted ? syncCoreTeam(state.teamLog.team, state.userId, [dekId]) : null;
    const [to] = globalThis.SezamSyncCore.call('reseal_targets', { team, successors, held, keys: [dekId] });
    if (to.send === 'as_is') {
        return vaultObj;  // not a re-keyed DEK, or still the folder's current one
    }
    if (to.send === 'wait') {
        // Review c78fd19: the folder's new key is not here yet; sent as it
        // was, the write left under the retired key a removed member reads.
        return null;
    }
    const successor = to.key;
    const bytes = base64ToBytes(vaultObj.payload);
    const keys = { ...state.deks, [dekId]: oldKey };
    const payloadData = vaultObj.object_type === 'entry'
        ? decryptEntryPayload(bytes, vaultObj.id, vaultObj.version, keys, _sodium)
        : decryptEnvelope(bytes, vaultObj.id, vaultObj.version, keys, _sodium, BLOB_KIND.NODE_META);
    return sealVaultObject({ ...vaultObj, payloadData, dekId: successor, version });
}

/**
 * Stateful test SM74 (the desktop's SM28): an entry this browser saved in a
 * shared folder reached the server before another device's re-key of that
 * folder, which did not know it: the server held it under the old DEK the
 * removed member can read. After a pull, a write of this account (the server
 * copy it signed) held under a retired folder DEK is sealed again one version
 * up and sent.
 *
 * Capability review run 134: that record of its own writes is sealed under
 * the KEK, so a sign-in after a password change elsewhere (or a new tab)
 * starts without it, and nothing resealed the entry. The folder's owner, whose
 * KEK opens the folder's current DEK, finishes the re-key for every live item,
 * whoever wrote it, as the re-key itself does (and the desktop).
 */
async function resealOwnWritesUnderSuccessors() {
    const _sodium = await ensureSodium();
    const due = new Map();
    for (const held of Object.values(state.syncObjects || {})) {
        // S3: this account's own write is the server copy it signed, not a
        // second record of what this browser sent (lost with a password change).
        if (['node', 'entry'].includes(held.object_type) && !held.is_deleted &&
                held.signer === state.userId && !state.outbox[held.id] && !state.syncConflicts[held.id]) {
            due.set(held.id, held);
        }
    }
    const own = new Set(due.keys());
    const retired = retiredFolderDekIds();
    const notToSeal = writesNotToSeal(state.syncObjects || {}, state.userId);
    for (const held of Object.values(state.syncObjects || {})) {
        if (!held.is_deleted && !due.has(held.id) && !notToSeal.has(held.id) && !state.outbox[held.id] &&
                !state.syncConflicts[held.id] && retired.has(payloadDekId(held))) {
            due.set(held.id, held);
        }
    }
    const ownKeys = new Set(state.kekDekIds || []);
    let sent = 0;
    const context = {};  // only nodes and entries are pushed below: one read for the pass
    for (const held of due.values()) {
        const resealed = await resealUnderFolderSuccessor(held, Number(held.version) + 1, context);
        if (!resealed || resealed === held) continue;  // as it is, or the new key is not here yet
        if (!own.has(held.id) && !ownKeys.has(payloadDekId(resealed))) continue;  // a member's
        try {
            await pushEncryptedVaultObjectLocked(resealed);
            sent += 1;
        } catch (err) {
            if (err.teamLogRefused) continue;  // not this account's to seal there (TL5)
            if (!err.isSyncConflict) throw err;
            // Another device wrote it (or resealed it) first. This copy only
            // changed the key: drop it; the next pull reseals what still needs it.
            if (isSameSyncVersion(state.outbox[held.id], resealed)) {
                delete state.outbox[held.id];
            }
            delete state.syncConflicts[held.id];
            await saveWebDirtyState(state.outbox, state.syncConflicts, _sodium);
            renderWebSyncConflicts();
        }
    }
    return sent;
}

/**
 * R16-Z SM19a: a write queued here under a folder key a re-key replaced was
 * shown as an item the page cannot open (the log refuses the old key for
 * reading) until Retry sealed it again, and for good while it was in
 * conflict, which Retry does not send. Sealed again under the folder's current
 * key as soon as the re-key is pulled, in the queue and in the conflict, as
 * the desktop's _reseal_under_successors and the phone's
 * resealUnsentOnCurrentKeys do. Returns how many were sealed again.
 */
async function resealQueuedUnderSuccessors(_sodium) {
    let changed = 0;
    const context = {};
    for (const queued of Object.values(state.outbox || {})) {
        if (!['node', 'entry'].includes(queued.object_type) || queued.is_deleted) continue;
        const resealed = await resealUnderFolderSuccessor(queued, queued.version, context);
        if (!resealed || resealed === queued) continue;  // as it is, or the new key is not here yet
        const copy = { ...queued, ...resealed };  // the base it builds on stays
        state.outbox[queued.id] = copy;
        if (state.syncConflicts[queued.id]) {
            state.syncConflicts[queued.id] = { ...state.syncConflicts[queued.id], local_object: copy };
        }
        changed += 1;
    }
    if (changed) await saveWebDirtyState(state.outbox, state.syncConflicts, _sodium);
    return changed;
}

/**
 * A folder another device deleted while this browser queued an item in it
 * comes back (desktop sync_state._revive_folders_of_unsent, phone
 * VaultService.reviveFoldersOfUnsent; conformance scenario
 * offline_write_under_deleted_folder, docs/SYNC_SINGLE_SOURCE.md point 4a).
 * The server refuses an item below a deleted folder, so Retry failed on it for
 * good. The folder is queued one version above its tombstone (whose blob is
 * sealed below it), ahead of the work below it. Returns how many came back.
 */
async function reviveFoldersOfUnsentWork(_sodium) {
    let revived = 0;
    const refused = new Set();
    for (let level = 0; level < 64; level++) {
        const workIn = [...new Set(Object.values(state.outbox)
            .filter(q => !q.is_deleted && q.parent_ref && ['node', 'entry'].includes(q.object_type))
            .map(q => q.parent_ref))];
        const deleted = workIn.map(id => state.syncObjects?.[id]).filter(held =>
            held?.object_type === 'node' && held.is_deleted && !state.outbox[held.id] && !refused.has(held.id));
        // docs/CORE_UNIFICATION.md U7e: which come back, at which version (above
        // every version this browser sent too, R16-Z SM18), is the core's.
        const due = globalThis.SezamSyncCore.call('revive_folders', {
            work_in: workIn,
            deleted: deleted.map(held => ({
                id: held.id, version: Number(held.version),
                sent: Math.max(0, ...(state.outboxSent?.[held.id] || []).map(([v]) => v)) || null,
            })),
        });
        if (!due.length) break;
        for (const { id, version } of due) {
            const held = state.syncObjects[id];
            const bytes = base64ToBytes(held.payload);
            const tombstone = Number(held.version);
            let meta = null;
            for (let sealedAt = tombstone - 1; !meta && sealedAt >= 0 && sealedAt > tombstone - 256; sealedAt--) {
                try {
                    meta = decryptEnvelope(bytes, held.id, sealedAt, state.deks, _sodium, BLOB_KIND.NODE_META);
                } catch {
                    // sealed at a lower version (other clients' bumps)
                }
            }
            if (!meta) {
                refused.add(held.id);  // not this browser's to open: the item stays queued
                continue;
            }
            const folder = withWebBase(await sealVaultObject({
                id: held.id, object_type: 'node', payloadData: meta, parent_ref: held.parent_ref || null,
                version, dekId: payloadDekId(held), write_policy: held.write_policy,
            }));
            try {
                assertTeamLogAllowsWrite(folder);
            } catch (err) {
                if (!err.teamLogRefused) throw err;
                refused.add(held.id);
                continue;
            }
            state.outbox = { [held.id]: folder, ...state.outbox };
            revived += 1;
        }
    }
    if (revived) {
        await saveWebDirtyState(state.outbox, state.syncConflicts, _sodium);
        renderWebSyncConflicts();
    }
    return revived;
}

/**
 * Sync redesign S4a (conformance scenario own_write_only_the_client_had): the
 * user accepted that the server was restored from a backup. What this account
 * wrote and this browser held as the server's copy, and the restored server
 * lost — missing though it was committed above the GC floor (so not deleted
 * and collected), or there at an older version — is queued again as it was
 * signed, as the desktop's 'sezam pull --full-resync' and the phone keep it.
 * Before, it was gone unless another device still had it.
 */
async function requeueWritesTheServerLost(held, gcFloor, _sodium) {
    const floor = Number.isSafeInteger(gcFloor) ? gcFloor : 0;
    let queued = 0;
    for (const copy of Object.values(held || {})) {
        if (!['node', 'entry', 'dek'].includes(copy.object_type)) continue;
        if ((copy.signer || copy.owner_id) !== state.userId || !copy.client_signature) continue;
        if (state.outbox[copy.id] || state.syncConflicts[copy.id]) continue;
        const server = state.syncObjects[copy.id];
        const lost = server
            ? Number(copy.version) > Number(server.version)
            : copy.commit_seq != null && copy.commit_seq > floor;
        if (!lost) continue;
        state.outbox[copy.id] = withWebBase({
            id: copy.id,
            object_type: copy.object_type,
            payload: copy.payload,
            parent_ref: copy.parent_ref || null,
            version: copy.version,
            is_deleted: copy.is_deleted || 0,
            payload_hash: copy.payload_hash,
            signature: copy.client_signature,
            write_policy: copy.write_policy || 'owner_only',
            ...(copy.target_user_id ? { target_user_id: copy.target_user_id } : {}),
        });
        queued += 1;
    }
    if (queued) await saveWebDirtyState(state.outbox, state.syncConflicts, _sodium);
    return queued;
}

/** Encrypt and sign a node/entry/DEK object for /api/sync. */
async function sealVaultObject(obj) {
    const _sodium = await ensureSodium();
    let payloadB64;

    if (obj.rawPayload) {
        // Pre-built binary payload (e.g., wrapped DEK envelope)
        payloadB64 = bytesToBase64(obj.rawPayload);
    } else if (obj.object_type === 'dek') {
        // DEK objects: payload is already the wrapped envelope binary
        payloadB64 = bytesToBase64(obj.payloadData);
    } else {
        // Encrypt payload with the appropriate DEK
        // Use custom DEK if provided (e.g., for entries in personal folders),
        // otherwise fall back to root DEK
        const dekId = obj.dekId || state.rootDekId;
        const dek = state.deks[dekId];
        if (!dek) throw new Error('No DEK for id: ' + dekId);

        if (obj.object_type === 'entry') {
            // Canonical two-envelope framing (cross-client with desktop/mobile).
            const entryPayload = encryptEntryPayload(
                obj.payloadData, dekId, obj.id, obj.version || 1, dek, _sodium
            );
            payloadB64 = bytesToBase64(entryPayload);
        } else {
            const blobKind = BLOB_KIND.NODE_META; // node (and fallback)
            const envelope = encryptEnvelope(
                obj.payloadData, blobKind, dekId, obj.id, obj.version || 1, dek, _sodium
            );
            payloadB64 = bytesToBase64(envelope);
        }
    }

    const payloadHash = await sha256hexBytes(base64ToBytes(payloadB64));
    const payloadHashBytes = hexToBytes(payloadHash);

    // Build canonical signed data for Ed25519 signature (spec 8.2)
    const signature = signSyncObject(
        _sodium, obj.id, obj.object_type, obj.parent_ref || null,
        obj.target_user_id || null, obj.is_deleted || 0,
        obj.version || 1, payloadHashBytes
    );

    return {
        id: obj.id,
        object_type: obj.object_type,
        payload: payloadB64,
        parent_ref: obj.parent_ref || null,
        version: obj.version || 1,
        is_deleted: obj.is_deleted || 0,
        payload_hash: payloadHash,
        signature: bytesToHex(signature),
        write_policy: obj.write_policy || 'owner_only',
    };
}

/**
 * Build canonical signed data and sign with Ed25519.
 * Spec 8.2: id(26B) || u8(len(object_type)) || object_type
 *   || parent_ref_or_zero(26B) || target_user_id_or_zero(26B)
 *   || u8(is_deleted) || u32be(version) || payload_hash(32B)
 */
function signSyncObject(_sodium, id, objectType, parentRef, targetUserId, isDeleted, version, payloadHashBytes) {
    // R15 #428 (INV-3): a value the message cannot hold exactly is refused,
    // never truncated into one the signature covers.
    const canonical = signedObjectMessage({
        id, object_type: objectType, parent_ref: parentRef, target_user_id: targetUserId,
        is_deleted: isDeleted ? 1 : 0, version, payload_hash: bytesToHex(payloadHashBytes),
    });
    if (!canonical) throw new Error('A sync object field does not fit its signed message');
    return _sodium.crypto_sign_detached(canonical, state.keypair.signingSk);
}

/**
 * Verify Ed25519 signature on a sync object.
 * Builds canonical signed data (same layout as signSyncObject) and verifies
 * the detached signature against the owner's signing public key.
 *
 * @param {object} obj - Sync object with id, object_type, parent_ref, target_user_id, is_deleted, version, payload_hash, signature
 * @param {Uint8Array} signingPk - 32-byte Ed25519 public key of the object owner
 * @param {object} _sodium - libsodium instance
 * @returns {boolean} true if signature is valid
 */
function verifyObjectSignature(obj, signingPk, _sodium) {
    try {
        // Server serializes the Ed25519 signature as `client_signature` (spec §8.2
        // pull response). Keep `signature` as a fallback for locally-built objects.
        const sigHex = obj.client_signature || obj.signature;
        if (!sigHex || !signingPk) return false;

        const signatureBytes = hexToBytes(sigHex);
        const canonical = signedObjectMessage(obj);
        if (!canonical) return false;
        return _sodium.crypto_sign_verify_detached(signatureBytes, canonical, signingPk);
    } catch (err) {
        console.warn('Signature verification error:', err.message);
        return false;
    }
}

/**
 * The bytes a sync object's signature covers (spec 8.2; key_vouchers.signed_message),
 * or null when a field cannot be held exactly (R15 #428, INV-3).
 */
function signedObjectMessage(obj) {
    const object = {
        id: obj.id, object_type: obj.object_type || '', parent_ref: obj.parent_ref || null,
        target_user_id: obj.target_user_id || null, is_deleted: obj.is_deleted ?? 0,
        version: obj.version ?? 1, payload_hash: obj.payload_hash || '',
    };
    try {
        return hexToBytes(globalThis.SezamSyncCore.call('key_voucher_signed_message', {object}));
    } catch {
        return null;
    }
}

/**
 * Fetch and cache a user's signing public key for signature verification.
 * Admin users populate keys from /api/users list; non-admin users fetch via
 * GET /api/users/:id/keys.
 *
 * @param {string} userId
 * @returns {Promise<Uint8Array|null>} signing_pk or null
 */
function liveSyncObjects(syncObjects) {
    return Object.fromEntries(Object.entries(syncObjects).filter(([, obj]) => !obj.is_deleted));
}

/**
 * Check a pull against the trusted checkpoint (rollback protection, W3).
 *
 * Review d150605 #4: tombstone GC removes rows the checkpoint covered, so a
 * vault where only a delete happened and nothing since failed every login
 * (STATE MISMATCH, or ROLLBACK DETECTED when the tombstone held the highest
 * seq). When the server reports GC'd tombstones the live objects
 * (live_state_hash) must still match exactly. A hidden tombstone cannot bring
 * anything back: the live set would differ. The shared sync core decides
 * (core/src/gate.rs check_state); a server head behind the checkpoint is
 * its gate's answer before this (SM71).
 */
function checkPulledStateAgainstCheckpoint(checkpoint, pulled) {
    if (!checkpoint) return;
    const { responseSeq } = pulled;
    const { stateHash, liveStateHash } = checkpoint.state_v === 2 || !pulled.legacy
        ? pulled : pulled.legacy;
    const verdict = globalThis.SezamSyncCore.call('check_state', {
        stored: {
            seq: checkpoint.last_sync_seq,
            state_hash: checkpoint.state_hash || null,
            live_state_hash: checkpoint.live_state_hash || null,
        },
        candidate: {
            max_commit_seq: responseSeq,
            state_hash: stateHash,
            live_state_hash: liveStateHash || null,
            gc_floor_seq: Number.isSafeInteger(pulled.gcFloor) ? pulled.gcFloor : 0,
            served: pulled.served !== false,
        },
    });
    if (verdict.state === 'rollback') {
        throw new Error(`ROLLBACK DETECTED: server seq ${verdict.seq} < stored ${verdict.stored}`);
    }
    if (verdict.state !== 'mismatch') return;
    throw new Error(
        `STATE MISMATCH at seq ${verdict.seq}: ` +
        `computed ${stateHash.slice(0, 16)}... != stored ${checkpoint.state_hash.slice(0, 16)}...`
    );
}

// Where deltas resume after a pull (core/src/gate.rs next_cursor). A full
// pull (lastSeq 0) holds everything up to the GC floor too: only collected
// tombstones are missing there. Resuming below the floor was a 410.
function syncPositionAfter(lastSeq, pulled) {
    return globalThis.SezamSyncCore.call('next_cursor', {
        last_seq: lastSeq,
        max_commit_seq: pulled.responseSeq,
        gc_floor_seq: Number.isSafeInteger(pulled.gcFloor) ? pulled.gcFloor : 0,
        head_commit_seq: Number.isSafeInteger(pulled.headSeq) ? pulled.headSeq : null,
    });
}

// The raw sync object this browser keeps of a verified pulled object.
// owner_id (the server's ACL owner) tells our KEK-wrapped DEKs from
// colleagues' ones for org recovery (ownKekDekIdsToRewrap).
function syncObjectRecord(obj) {
    return {
        id: obj.id,
        object_type: obj.object_type,
        owner_id: obj.owner_id || null,
        // The account whose signature was verified (unauthorizedWrites).
        signer: obj.signature_user_id || obj.owner_id || null,
        client_signature: obj.client_signature || obj.signature || null,
        payload_hash: obj.payload_hash || null,
        parent_ref: obj.parent_ref || null,
        target_user_id: obj.target_user_id || null,
        version: obj.version,
        is_deleted: obj.is_deleted || 0,
        payload: obj.payload,
        // Where the server committed it: a copy a restored server lacks above
        // its GC floor was lost, not deleted (requeueWritesTheServerLost).
        commit_seq: Number.isSafeInteger(Number(obj.commit_seq)) ? Number(obj.commit_seq) : null,
        write_policy: obj.write_policy || null,
        access_level: obj.access_level || null,
        scope: obj.scope || null,  // DEK type label (unsigned, a hint only)
    };
}

// The DEK id a sealed folder meta or item meta names in its header (the
// core's rule, core/src/authority.rs: 57 bytes of the payload suffice).
function sealingDekId(record) {
    let head;
    try { head = base64ToBytes((record.payload || '').slice(0, 76)); } catch { return null; }
    return globalThis.SezamSyncCore.call('authority_sealing_dek_id', {
        object_type: record.object_type, head: bytesToHex(head),
    });
}

// ── Signed team log (docs/DESIGN_TEAM_LOG.md §6, TL5) ──
// The browser replays the organisation's log with SezamTeamLog (teamlog.js)
// and keeps it for the session (state.teamLog = {records, team}); the head it
// saw ({genesis_hash, seq, hash}) is part of the encrypted sync checkpoint,
// so a reload refuses a server whose log is shorter, forked or restarted.
const TEAM_LOG_PAGES = 1000;

function invitationTeamGenesis(fragment) {
    const values = new URLSearchParams((fragment || '').replace(/^#/, '')).getAll('g');
    if (!values.length) return null;
    if (values.length !== 1 || !/^[0-9a-fA-F]{64}$/.test(values[0])) {
        throw new Error('Invalid team genesis in invitation');
    }
    return values[0].toLowerCase();
}

// This device anchor is independent of the observed sync checkpoint and KEK.
// Cross-device account transport must not turn an observed head into a confirmation.
async function loadConfirmedTeamGenesis(_sodium) {
    if (!state.userId) throw new Error('An account is required for the team anchor');
    const userId = state.userId;
    const stored = await idbKeysRequest('readonly', store => store.get(`confirmed_team_genesis:${userId}`));
    if (!stored) return null;
    try {
        if (typeof stored.encrypted_genesis !== 'string' || !/^[0-9a-f]+$/.test(stored.encrypted_genesis)) {
            throw new Error('invalid ciphertext');
        }
        const packed = hexToBytes(stored.encrypted_genesis);
        const nonceLen = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        const plaintext = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, packed.slice(nonceLen), new TextEncoder().encode(`sezam-team-genesis-v1:${userId}`),
            packed.slice(0, nonceLen), await syncCheckpointKey('device-v2', _sodium),
        );
        const genesis = new TextDecoder().decode(plaintext);
        if (!/^[0-9a-f]{64}$/.test(genesis)) throw new Error('invalid genesis hash');
        return genesis;
    } catch (err) {
        throw new Error(`Invalid encrypted team anchor: ${err.message}`);
    }
}

async function saveConfirmedTeamGenesis(genesis, _sodium) {
    if (typeof genesis !== 'string' || !/^[0-9a-f]{64}$/.test(genesis)) {
        throw new Error('Invalid confirmed team genesis');
    }
    const userId = state.userId;
    const session = state.sessionSerial;
    // INV-7: an anchor that does not open (local_damaged) is replaced by this confirmation.
    const damaged = !!state.teamLogDamaged;
    const prior = damaged ? null : await loadConfirmedTeamGenesis(_sodium);
    if (userId !== state.userId || session !== state.sessionSerial) throw new Error('The anchor session has ended');
    const observed = state.teamLog?.team.genesisHash || state.syncCheckpoint?.team_log?.genesis_hash;
    if ((prior && prior !== genesis) || (observed && observed !== genesis)) {
        throw new Error('TEAM LOG MISMATCH: the invitation conflicts with this browser\'s team anchor');
    }
    if (prior === genesis) return;  // already confirmed: the stored record stays as it is
    const key = await syncCheckpointKey('device-v2', _sodium, true);
    if (userId !== state.userId || session !== state.sessionSerial) throw new Error('The anchor session has ended');
    const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        new TextEncoder().encode(genesis), new TextEncoder().encode(`sezam-team-genesis-v1:${userId}`),
        null, nonce, key,
    );
    await idbKeysRequest('readwrite', store => store.put({
        id: `confirmed_team_genesis:${userId}`,
        encrypted_genesis: bytesToHex(new Uint8Array([...nonce, ...ciphertext])),
    }));
    if (userId !== state.userId || session !== state.sessionSerial) throw new Error('The anchor session has ended');
    state.confirmedTeamGenesis = genesis;
    const forgotten = damaged ? await loadForgottenTeamGenesis(_sodium).catch(() => []) : await loadForgottenTeamGenesis(_sodium);
    if (damaged || forgotten.includes(genesis)) await saveForgottenTeamGenesis(forgotten.filter(g => g !== genesis), _sodium);
    state.forgottenTeamGenesis = forgotten.filter(g => g !== genesis);
    if (damaged && !await loadWebTeamLedger(_sodium).then(() => true, () => false)) {
        await saveWebTeamLedger({ sent: {}, withdrawn: new Set(), setAside: [] }, _sodium);
    }
    state.teamLogDamaged = null;
}

// Review c78fd19 (medium): a browser pinned to a team log the server lost for
// good (moved, reseeded, no restore) had no way out of TEAM LOG MISMATCH. The
// user types the pinned genesis; the browser drops its pin and its copy, and
// follows the server's log as a new one, trusted only once its founder is
// confirmed again. The account bundle may still name the old genesis: this
// browser remembers it left it and does not take it back from there.
const FORGET_PIN_MIN_CHARS = 16;

function forgottenTeamGenesisAad(userId) {
    return new TextEncoder().encode(`sezam-team-genesis-forgotten-v1:${userId}`);
}

async function loadForgottenTeamGenesis(_sodium) {
    const userId = state.userId;
    const stored = await idbKeysRequest('readonly', store => store.get(`forgotten_team_genesis:${userId}`));
    if (!stored) return [];
    const packed = hexToBytes(stored.encrypted_list);
    const nonceLen = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const list = JSON.parse(new TextDecoder().decode(_sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, packed.slice(nonceLen), forgottenTeamGenesisAad(userId), packed.slice(0, nonceLen),
        await syncCheckpointKey('device-v2', _sodium),
    )));
    if (!Array.isArray(list) || !list.every(g => /^[0-9a-f]{64}$/.test(g))) throw new Error('Invalid forgotten team anchors');
    return list;
}

async function saveForgottenTeamGenesis(list, _sodium) {
    const userId = state.userId;
    const id = `forgotten_team_genesis:${userId}`;
    if (!list.length) {
        await idbKeysRequest('readwrite', store => store.delete(id));
        return;
    }
    const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        new TextEncoder().encode(JSON.stringify([...new Set(list)].sort())), forgottenTeamGenesisAad(userId),
        null, nonce, await syncCheckpointKey('device-v2', _sodium, true),
    );
    await idbKeysRequest('readwrite', store => store.put({
        id, encrypted_list: bytesToHex(new Uint8Array([...nonce, ...ciphertext])),
    }));
}

/** The anchor the cached keys named, before the server's keys named another:
 * pinned unless this browser left it or pins one (run 416), never followed away from. */
async function keepTeamAnchor(genesis, _sodium) {
    try {
        if ((await anchorPin(genesis, _sodium)).pin) await saveConfirmedTeamGenesis(genesis, _sodium);
    } catch {
        // INV-7: refused where the team is used (local_damaged), never the sign-in
    }
}

/** The core's {note, pin, conflict} for `genesis` named by account keys
 * (core/src/teamlog/local.rs anchor_pin, capability run 709). INV-7: a trust
 * record that does not open pins nothing and is refused where the team is
 * used (local_damaged), never the sign-in. */
async function anchorPin(genesis, _sodium) {
    let unreadable = state.teamLogDamaged ? String(state.teamLogDamaged.message) : null;
    let forgotten = [], confirmed = null;
    try {
        forgotten = await loadForgottenTeamGenesis(_sodium);
        confirmed = await loadConfirmedTeamGenesis(_sodium);
    } catch (err) {
        unreadable ??= String(err?.message || err);
    }
    const held = state.teamLog?.team?.genesisHash || null;
    return globalThis.SezamSyncCore.call('team_log_anchor_pin', {
        unreadable, anchor: genesis, forgotten, confirmed: confirmed || null,
        pins: [state.syncCheckpoint?.team_log?.genesis_hash || null],
        held: held ? { genesis: held } : null,
    });
}

/** The genesis an account bundle names, pinned as the core says. INV-7: keys
 * naming another log than this browser pins are refused where the team is
 * used (anchor_conflict, webLocalTeamLogRefusal), never the sign-in. */
async function importAccountTeamAnchor(_sodium) {
    const genesis = state.keypair?.confirmedGenesis;
    if (!genesis) return;
    const to = await anchorPin(genesis, _sodium);
    if (to.note === null) state.keypair.confirmedGenesis = null;  // this browser left that log
    if (to.pin) await saveConfirmedTeamGenesis(genesis, _sodium);
}

function webPinnedTeamGenesis() {
    return [...new Set([
        state.confirmedTeamGenesis, state.teamLog?.team.genesisHash,
        state.syncCheckpoint?.team_log?.genesis_hash, state.keypair?.confirmedGenesis,
    ].filter(Boolean))].sort();
}

/** Why this browser refuses the server's team log now (the TEAM LOG MISMATCH
 * error), or null: it follows it. Call with the sync lock held. */
async function webTeamLogRefusal(_sodium) {
    const held = webLocalTeamLogRefusal();
    if (held) return held;
    const local = state.teamLog || null;
    const resp = await apiFetch(`/api/team-log?since=${local ? local.team.headSeq : -1}`);
    try {
        await syncWebTeamLog(resp.head || null, local, state.syncCheckpoint?.team_log || null, _sodium);
    } catch (err) {
        if (err.teamLogCause) return err;
        throw err;
    }
    return null;
}

/** Drop this browser's team log pin; call with the sync lock held.
 * INV-8 (review e443cbc): the forget, and the drop of unsent changes with
 * it, only with this account's password, on every screen and every client. */
async function forgetWebTeamLogPinLocked(typed, password, session, _sodium) {
    const ended = () => session !== state.sessionSerial || !state.kek;
    if (ended()) throw new Error(t('team.stale'));
    if (!await currentPasswordProof(password)) throw new Error(t('team.forget_wrong_password'));
    if (ended()) throw new Error(t('team.stale'));
    await loadWebLocalStateLocked(session, _sodium);
    const pins = webPinnedTeamGenesis();
    if (!pins.length) throw new Error(t('team.forget_none'));
    // INV-7: conflicting pins (anchor_conflict: the account keys name another
    // log than this browser pins) are left together, each one typed.
    const parts = (typed || '').replace(/,/g, ' ').toLowerCase().split(/\s+/).filter(Boolean);
    if (!parts.length || parts.some(part => part.length < FORGET_PIN_MIN_CHARS) ||
            !pins.every(pin => parts.some(part => pin.startsWith(part))) ||
            !parts.every(part => pins.some(pin => pin.startsWith(part)))) {
        throw new Error(t('team.forget_typed', { pins: pins.join(', ') }));
    }
    // INV-8: only a log this browser refuses as lost now (the pull's own
    // judgment, TEAM_LOG_MISMATCH_FORGET), never a fork; asked before any
    // unsent change is dropped.
    const refusal = await webTeamLogRefusal(_sodium);
    if (!refusal?.teamLogLost) {
        throw new Error(t('team.forget_not_lost', { reason: refusal ? refusal.message : 'this browser follows it' }));
    }
    if (ended()) throw new Error(t('team.stale'));
    // INV-7 (review e443cbc H2): nothing queued can reach a lost log, so the
    // forget exports it and drops it once asked, whichever screen forgets.
    // Before, only the sign-in screen did; since INV-7 that sign-in opens the
    // vault, whose Team trust forget then refused for good with anything queued.
    // Review c02cc47 R17-L: only the team's. A write in the personal tree is
    // one rule 1 sends under the refused log; it stays queued, and so does a
    // conflict over one.
    const outbox = {}, conflicts = {}, ops = [];
    const objects = [];
    for (const [id, object] of Object.entries(state.outbox || {})) {
        if (webPersonalWrite(object)) outbox[id] = object; else objects.push(object);
    }
    for (const [id, conflict] of Object.entries(state.syncConflicts || {})) {
        if (webPersonalWrite(conflict.local_object)) conflicts[id] = conflict; else objects.push(conflict.local_object);
    }
    const count = objects.length + (state.outboxOps || []).length;
    if (count) {
        if (!window.confirm(t('team.forget_discard_unsent', { count }))) throw new Error(t('team.forget_unsent'));
        if (objects.length) exportWebDirtyObjects(objects);
        await saveWebDirtyState(outbox, conflicts, _sodium, ops);
        state.outbox = outbox;
        state.syncConflicts = conflicts;
        state.outboxOps = ops;
    }
    if (ended()) throw new Error(t('team.stale'));
    const forgotten = [...new Set([...await loadForgottenTeamGenesis(_sodium), ...pins])].sort();
    await saveForgottenTeamGenesis(forgotten, _sodium);
    state.forgottenTeamGenesis = forgotten;
    await idbKeysRequest('readwrite', store => store.delete(`confirmed_team_genesis:${state.userId}`));
    state.confirmedTeamGenesis = null;
    if (state.syncCheckpoint?.team_log) {
        const checkpoint = { ...state.syncCheckpoint, team_log: null };
        await saveSyncCheckpoint(checkpoint, _sodium);
        state.syncCheckpoint = checkpoint;
    }
    state.teamLog = null;
    if (state.keypair) state.keypair.confirmedGenesis = null;
    return pins;
}

async function handleForgetTeamPin(event) {
    event.preventDefault();
    const input = document.getElementById('team-forget-genesis');
    const error = document.getElementById('team-trust-error');
    const typed = input.value;
    const passwordInput = document.getElementById('team-forget-password');
    const password = passwordInput ? passwordInput.value : '';
    if (passwordInput) passwordInput.value = '';
    error.classList.add('hidden');
    try {
        if (!window.confirm(t('team.forget_confirm'))) return;
        const _sodium = await ensureSodium();
        const session = state.sessionSerial;
        await withWebSyncLock(async () => {
            await forgetWebTeamLogPinLocked(typed, password, session, _sodium);
            await pullAndBuildTreeLocked(session);
        });
        input.value = '';
        await openTeamTrustModal();
    } catch (err) {
        error.textContent = err.message;
        error.classList.remove('hidden');
    }
}

// Review 1141a20 H2: the pin this browser holds independently (invitation
// #g=, founder confirmation) goes into the encrypted account bundle, so the
// account's next browser, phone or desktop trusts the same log without the
// server. Capability run 264: only together with a NEW password. The wrap
// binds no epoch, so under the same password the server could hand a new
// device the account's older salt + keys without the genesis and they would
// open; the new password cannot open them. Journaled first (the old proof
// sealed under the new KEK): a lost response is finished by the next login
// with the new password (resumeKekRotation). Call with the sync lock held.
async function publishWebTeamAnchorLocked(password, newPassword, session, _sodium) {
    const userId = state.userId;
    const ended = () => session !== state.sessionSerial || userId !== state.userId || !state.kek;
    if (ended()) throw new Error(t('team.stale'));
    const genesis = await loadConfirmedTeamGenesis(_sodium);
    if (!genesis || state.teamLog?.team.genesisHash !== genesis) throw new Error(t('team.publish_untrusted'));
    if (Object.keys(state.outbox || {}).length || Object.keys(state.syncConflicts || {}).length ||
            (state.outboxOps || []).length) {
        throw new Error(t('team.publish_unsent'));
    }
    const proofHex = await currentPasswordProof(password);
    if (!proofHex) throw new Error(t('team.publish_wrong_password'));
    if (await currentPasswordProof(newPassword)) throw new Error(t('team.publish_same_password'));
    if (!meetsNewPasswordPolicy(newPassword)) throw new Error(t('error.password_policy'));
    const knownPreAnchor = mergePreAnchor(state.keypair.preAnchor, await loadPreAnchorHistory(userId));
    if (await passwordReopensPreAnchor(newPassword, knownPreAnchor, _sodium)) {
        throw new Error(t('team.publish_pre_anchor_password'));
    }
    const status = await apiFetch('/api/org-recovery/status');
    if (status && status.configured && status.created_by === userId && !status.stale) {
        throw new Error(t('team.publish_recovery'));
    }
    if (ended()) throw new Error(t('team.stale'));
    const keyEpoch = state.keyEpoch + 1;
    const argon2Params = state.kdf.argon2_params;
    const newSalt = _sodium.randombytes_buf(16);
    const derived = await deriveKEK(newPassword, newSalt, argon2Params);
    const newKek = derived.slice(0, 32);
    const authProof = derived.slice(32, 64);
    const currentProof = hexToBytes(proofHex);
    _sodium.memzero(derived);
    try {
        if (ended()) throw new Error(t('team.stale'));
        const deks = await rewrapOwnDeks(newKek, _sodium, true);
        const kpData = new Uint8Array(96);
        kpData.set(state.keypair.signingSk, 0);
        kpData.set(state.keypair.encryptionSk, 64);
        // Capability run 269: the password state left now opened bundles without the anchor.
        const preAnchor = state.keypair.confirmedGenesis ? knownPreAnchor
            : addPreAnchor(knownPreAnchor, hexToBytes(state.kdf.argon2_salt), argon2Params, state.kek, _sodium);
        let encryptedKeypair;
        try {
            encryptedKeypair = encryptAccountKeypair(kpData, genesis, newKek, generateULID(), userId, _sodium, preAnchor);
        } finally {
            _sodium.memzero(kpData);
        }
        const journal = {
            username: state.username, user_id: userId,
            argon2_salt: bytesToHex(newSalt), argon2_params: argon2Params,
            encrypted_keypair: bytesToHex(encryptedKeypair), deks, key_epoch: keyEpoch,
            publishes_anchor: true,
            current_proof: sealJournalSecret(currentProof, journalCurrentProofAad(userId), newKek, _sodium),
        };
        assertSyncUnitFits(deks);
        await saveKekRotationJournal(journal);
        await applyKekRotationJournal(journal, authProof, state.keypair.signingSk, _sodium, null, currentProof);
        if (ended()) return;
        for (const obj of deks) {
            state.syncObjects[obj.id] = { ...state.syncObjects[obj.id], version: obj.version, payload: obj.payload };
        }
        state.kek = newKek.slice();
        state.kdf = { argon2_salt: journal.argon2_salt, argon2_params: argon2Params };
        state.keypair.confirmedGenesis = genesis;
        state.keypair.preAnchor = preAnchor;
        await rememberWebKdfState(_sodium);
        await saveToIndexedDB({ encrypted_keypair: journal.encrypted_keypair, user_id: userId });
    } finally {
        _sodium.memzero(newKek);
        _sodium.memzero(authProof);
        _sodium.memzero(currentProof);
    }
    await pullAndBuildTreeLocked(session);
}

async function openTeamTrustModal() {
    closeTeamTrustModal();
    const error = document.getElementById('team-trust-error');
    error.classList.add('hidden');
    document.getElementById('team-trust-details').textContent = '';
    document.getElementById('team-trust-modal').classList.remove('hidden');
    const session = state.sessionSerial;
    const userId = state.userId;
    const review = { session, userId, genesis: null };
    state.teamTrustReview = review;
    try {
        const _sodium = await ensureSodium();
        if (review !== state.teamTrustReview || !state.kek || !userId || session !== state.sessionSerial || userId !== state.userId) return;
        // INV-7: a refused log is named here with its way out.
        if (!state.teamLog?.records.length) throw state.teamLogRefusal || new Error(t('team.no_log'));
        const team = globalThis.SezamTeamLog.replay(state.teamLog.records, _sodium);
        const { founderId, known } = webFounderLineage(state.teamLog);
        const fingerprints = known.map(([s, e]) => bytesToHex(_sodium.crypto_hash_sha256(
            new Uint8Array([...hexToBytes(s), ...hexToBytes(e)]))));
        review.genesis = team.genesisHash;
        document.getElementById('team-trust-details').textContent =
            `${founderId}\nGenesis: ${team.genesisHash}\n${fingerprints.join('\n')}`;
        if (state.teamLogRefusal) throw state.teamLogRefusal;
    } catch (err) {
        if (session !== state.sessionSerial || userId !== state.userId) return;
        error.textContent = err.message;
        error.classList.remove('hidden');
    }
}

function closeTeamTrustModal() {
    state.teamTrustReview = null;
    document.getElementById('team-founder-fingerprint').value = '';
    for (const id of ['team-publish-password', 'team-publish-new-password', 'team-publish-confirm-password']) {
        const input = document.getElementById(id);
        if (input) input.value = '';
    }
    document.getElementById('team-trust-modal').classList.add('hidden');
}

async function handleConfirmTeamFounder(event) {
    event.preventDefault();
    const review = state.teamTrustReview;
    const error = document.getElementById('team-trust-error');
    const button = document.getElementById('team-trust-confirm');
    const fingerprint = document.getElementById('team-founder-fingerprint').value.trim().toLowerCase();
    const takeInput = id => {
        const input = document.getElementById(id);
        const value = input ? input.value : '';
        if (input) input.value = '';
        return value;
    };
    const password = takeInput('team-publish-password');
    const newPassword = takeInput('team-publish-new-password');
    const confirmPassword = takeInput('team-publish-confirm-password');
    button.disabled = true;
    error.classList.add('hidden');
    let saved = false;
    let published = false;
    try {
        const _sodium = await ensureSodium();
        if (!review || review !== state.teamTrustReview || review.session !== state.sessionSerial ||
                review.userId !== state.userId || !state.kek) throw new Error(t('team.stale'));
        const team = globalThis.SezamTeamLog.replay(state.teamLog.records, _sodium);
        if (team.genesisHash !== review.genesis) throw new Error(t('team.stale'));
        const { known } = webFounderLineage(state.teamLog);
        if (!/^[0-9a-f]{64}$/.test(fingerprint) || !known.some(([s, e]) =>
            bytesToHex(_sodium.crypto_hash_sha256(new Uint8Array([...hexToBytes(s), ...hexToBytes(e)]))) === fingerprint)) {
            throw new Error(t('team.mismatch'));
        }
        if (password && newPassword !== confirmPassword) throw new Error(t('team.publish_mismatch'));
        await withWebSyncLock(async () => {
            if (review !== state.teamTrustReview || review.session !== state.sessionSerial ||
                    review.userId !== state.userId) throw new Error(t('team.stale'));
            await saveConfirmedTeamGenesis(review.genesis, _sodium);
            saved = true;
            // Reconsider cached ciphertext under the new trust.
            await pullAndBuildTreeLocked(review.session);
            if (password) {
                published = true;
                await publishWebTeamAnchorLocked(password, newPassword, review.session, _sodium);
            }
        });
        if (review === state.teamTrustReview) closeTeamTrustModal();
    } catch (err) {
        if (review !== state.teamTrustReview) return;
        error.textContent = published ? t('team.saved_publish_failed', { error: err.message })
            : saved ? t('team.saved_refresh_failed', { error: err.message }) : err.message;
        error.classList.remove('hidden');
    } finally {
        button.disabled = false;
    }
}

function teamLogPin(team) {
    return team ? { genesis_hash: team.genesisHash, seq: team.headSeq, hash: team.headHash } : null;
}

// INV-7 (docs/ROOT_CAUSE_PLAN.md): why this browser refuses the server's team
// log, and for which causes "Forget the pinned team log" is offered: the
// core's list (team_log_mismatch_causes, core/src/teamlog/follow.rs), as the
// desktop and the phone take it (tests/vectors/team_log_mismatch.json).
/** The TEAM LOG MISMATCH error for `cause`; err.teamLogLost (the sign-in
 * screen's and Team trust's offer to forget) follows from the cause alone. */
function teamLogMismatch(detail, cause) {
    const causes = globalThis.SezamSyncCore.call('team_log_mismatch_causes', {});
    if (!Object.hasOwn(causes, cause)) throw new Error(`unknown team log mismatch cause ${cause}`);
    const lost = causes[cause];
    // INV-8: every offer is marked as a risk (RISK_MARKER in team_log_local.py).
    const err = new Error(`TEAM LOG MISMATCH: the server's team log ${detail}` + (lost
        ? '. RISK: a hostile server can cause this on purpose (drop its log, serve a new genesis) so that ' +
          'this browser drops its pin. Only if your admin confirms out of band that the team\'s log is lost ' +
          'for good (another server, a reseed), "Forget the pinned team log" (Team trust, or the sign-in ' +
          'screen) leaves it in this browser'
        : ''));
    err.teamLogCause = cause;
    err.teamLogLost = lost;
    return err;
}

/** What the team needs did not come this pull (`what`: the log, or a signer's
 * keys; no answer, a 5xx): the team waits for the next pull; no mismatch,
 * nothing lost, no forget offered. */
function teamLogUnreachable(what) {
    const refusal = new Error(`${what} did not come from the server; ` +
        'the team waits for the next sync, the personal tree is open');
    refusal.teamLogCause = 'unreachable';
    refusal.teamLogLost = false;
    return refusal;
}

/**
 * INV-7: why this browser refuses the team log before asking the server: the
 * anchor it holds does not open (local_damaged; confirming the founder again
 * replaces it), or the account keys name another genesis than it pins
 * (anchor_conflict; the pins are forgotten together). Never a failed sign-in.
 */
function webLocalTeamLogRefusal() {
    // docs/CORE_UNIFICATION.md U7f: whether and why is the core's
    // (core/src/teamlog/local.rs); the held log is replayed and verified.
    const held = state.teamLog?.team?.genesisHash || null;
    const refusal = globalThis.SezamSyncCore.call('team_log_local_refusal', {
        unreadable: state.teamLogDamaged ? String(state.teamLogDamaged.message) : null,
        anchor: state.keypair?.confirmedGenesis || null,
        forgotten: state.forgottenTeamGenesis || [],
        confirmed: state.confirmedTeamGenesis || null,
        pins: [state.syncCheckpoint?.team_log?.genesis_hash || null],
        held: held ? { genesis: held } : null,
    });
    if (refusal === null) return null;
    if (refusal.what === 'trust') return state.teamLogDamaged;
    return teamLogMismatch(
        'names another genesis than the account keys (another server, or a log left elsewhere)', refusal.cause);
}

/** This account's personal trees (TL7, INV-7 rule 3): the core's
 * authority_personal_tree over the folders this browser holds. */
function webPersonalTree(nodes, syncObjects) {
    const objects = Object.entries(nodes).map(([id, node]) => ({
        id, object_type: 'node', parent_ref: node.parent_ref || null,
        signer: syncObjects[id]?.signer ?? null, dek_id: node.dekId || null,
        personal: !!node.personal, opened: !node._undecryptable,
    }));
    return globalThis.SezamSyncCore.call('authority_personal_tree', {objects, own_user_id: state.userId ?? null});
}

/** INV-7: folder `id` is this account's personal root or lies below one, each
 * folder on the way opened and signed by this account. */
function webInPersonalTree(nodes, syncObjects, id) {
    return webPersonalTree(nodes, syncObjects).tree.includes(id);
}

/** The keys that stay open while the team log is refused: each personal
 * root's own. Review e443cbc (R15-P4 rule 3): not every key sealing something
 * below a personal root. */
function refusedLogPersonalKeys(nodes, syncObjects) {
    return new Set(webPersonalTree(nodes, syncObjects).root_keys);
}

/**
 * Bring `local` (this session's copy, or null) up to `head` (the pull's
 * team_log_head). `pin` is the head an earlier session saw. Returns
 * {records, team}, or null while the organisation has no log. Throws
 * 'TEAM LOG MISMATCH' when the server's log does not continue what this
 * browser saw: never followed.
 */
async function syncWebTeamLog(head, local, pin, _sodium) {
    const TL = globalThis.SezamTeamLog;
    const core = globalThis.SezamSyncCore;
    const refuse = answer => {
        if (answer.refused) throw teamLogMismatch(answer.refused.detail, answer.refused.cause);
    };
    if (local && (!head || head.seq < local.team.headSeq)) {
        // R9-E: a server restored from a backup lost records this browser
        // accepted. It puts them back onto a prefix of its own copy; any
        // other server log (fork, another genesis, a refused upload) stays
        // a mismatch below.
        const restored = await restoreWebTeamLog(head, local, pin, _sodium);
        if (restored !== false) head = restored;
    }
    // U7b (core/src/teamlog/follow.rs): what the core makes of the head.
    const pins = pin && Number.isSafeInteger(pin.seq) ? [{ seq: pin.seq, hashes: [pin.hash] }] : [];
    const plan = core.call('team_log_follow_plan', {
        head: head || null,
        local: local ? { seq: local.team.headSeq, hash: local.team.headHash, genesis_hash: local.team.genesisHash } : null,
        pins, pinned_genesis: pin?.genesis_hash || null, confirmed_genesis: state.confirmedTeamGenesis || null,
        left_earlier_log: !!state.forgottenTeamGenesis?.length, who: 'this browser',
    });
    if (plan.check_served) {
        // Goal #440: a cause that offers to forget the pin only as far as
        // the records served bear it out, never on the unsigned head alone.
        const resp = await apiFetch('/api/team-log?since=-1');
        const served = Array.isArray(resp?.records) ? resp.records : [];
        let first = null;
        if (served.length) {
            try {
                first = { genesis: TL.replay(served.slice(0, 1), _sodium).genesisHash };
            } catch (err) {
                first = { error: err.message };
            }
        }
        refuse(core.call('team_log_follow_served', { check: plan.check_served, head_shown: !!head, first }));
    }
    if (plan.none) return null;
    let result;
    try {
        refuse(plan);  // went back, or differs at a head seen: maybe a fork to follow
        result = plan.same ? local : await catchUpWebTeamLog(head, local, pins, plan.fetch, _sodium, refuse);
    } catch (err) {
        if (!local || !globalThis.SezamTeamLog.forkFollows(err.teamLogCause)) throw err;
        const followed = await followWebTeamLogFork(head, local, pin, _sodium);
        if (followed?.refusal) {
            throw teamLogMismatch(`${err.message.replace(/^TEAM LOG MISMATCH: the server's team log /, '')}; it forks from this browser's copy and is ` +
                 `not followed: ${followed.refusal}`, err.teamLogCause);
        }
        if (!followed) throw err;
        result = followed;
    }
    await noteWebTeamLogStored(result.records, _sodium);
    return result;
}

/** This browser's identity keys as the team log names them, or null. */
function webHeldTeamKeys(_sodium) {
    if (!state.keypair?.signingPk || !state.keypair?.encryptionSk) return null;
    return [bytesToHex(state.keypair.signingPk), bytesToHex(_sodium.crypto_scalarmult_base(state.keypair.encryptionSk))];
}

/**
 * Goal #442 (bg344 random run of TeamLogMachine): the server lost its log and
 * one device of this account put back a shorter copy, so it forks from what
 * this browser holds. Review 18c300f R16-H1: the server keeps what it refused
 * (a hand-over the admin took back, a dropped rotation), so a fork is
 * followed only as far as the core allows (U7d); a member's browser
 * follows once every change it saw is on the server's side. Returns
 * {records, team}, {refusal}, or null: the mismatch stands.
 */
async function followWebTeamLogFork(head, local, pin, _sodium) {
    const TL = globalThis.SezamTeamLog;
    if (!Number.isSafeInteger(head.seq) || head.seq < 0) return null;
    const served = [];
    for (let page = 0; page < TEAM_LOG_PAGES && served.length <= head.seq; page++) {
        const resp = await apiFetch(`/api/team-log?since=${served.length - 1}`);
        const got = (Array.isArray(resp?.records) ? resp.records : []).slice(0, head.seq + 1 - served.length);
        if (!got.length) break;
        served.push(...got);
    }
    // U7d: where it forks, whether it is followed and what is made again
    // are the core's (core/src/teamlog/fork_follow.rs).
    const pins = pin && Number.isSafeInteger(pin.seq) ? [{ seq: pin.seq, hashes: [pin.hash] }] : [];
    const held = webHeldTeamKeys(_sodium);
    const split = TL.forkSplit(local.records, served, pins, state.userId || null, held,
                               (await loadWebTeamLedger(_sodium)).withdrawn);
    if (split.refusal) return { refusal: split.refusal };
    if (split.stand) return null;
    const lost = local.records.slice(split.fork);
    let team;
    try {
        team = TL.replay(served, _sodium);
    } catch {
        return null;
    }
    // This browser keeps no unpushed identity rotation: a lost one is not linked again.
    const take = TL.forkTake(team, head, lost, split.missing, state.userId || null, held, null);
    if (take.stand) return null;
    const { remake, abandoned } = take.follow;
    const followed = remake.length
        ? await remakeWebLostTeamChanges(remake, served, team, _sodium)
        : { records: served, team };
    if (followed) {
        // Capability finding 505 (desktop: _follow_fork): this account's
        // records left behind are withdrawn - a server serving them again
        // later is not followed (their changes went out again, or aside).
        if (abandoned.length) {
            const ledger = await loadWebTeamLedger(_sodium);
            for (const hash of abandoned) { delete ledger.sent[hash]; ledger.withdrawn.add(hash); }
            await saveWebTeamLedger(ledger, _sodium);
        }
        console.warn(`Followed the server's team log from record ${split.fork}, which forks from this browser's copy`);
    }
    return followed;
}

/**
 * Review 18c300f R16-M5 (desktop: _follow_fork queues them again): this
 * account's lost team changes go out again on the server's head - this
 * browser made them, or nobody else holds them; on 18c300f the fork waited
 * for them for good. What the log or the server no longer takes is set aside
 * in the ledger, with why (the desktop's 'sezam team-log queue'). Returns
 * {records, team}, or null: the mismatch stands (another device appended
 * meanwhile, or a change bound to the head it was signed on).
 */
async function remakeWebLostTeamChanges(bodies, served, team, _sodium) {
    const TL = globalThis.SezamTeamLog;
    if (!state.userId || !state.keypair?.signingSk) return null;
    const records = [];
    let after = team;
    let reason = null;
    try {
        for (const body of bodies) {
            const data = TL.resolveChange(after, body.type, body.data);
            if (data === null) continue;
            const record = TL.signRecord(TL.nextBody(after, body.type, state.userId, data), state.keypair.signingSk, _sodium);
            after = TL.applyRecord(after, record, _sodium);
            records.push(record);
        }
    } catch (err) {
        if (!(err instanceof TL.TeamLogError)) throw err;
        reason = err.message;  // as the desktop's queue: made together, set aside together
    }
    if (reason === null && records.length) {
        try {
            await sendWebTeamRecords(records, () => apiFetch('/api/team-log', { method: 'POST', body: { records } }),
                                     _sodium);
            return { records: [...served, ...records], team: after };
        } catch (err) {
            if (err.status === 409) return null;  // the head moved: the next pull compares again
            // R17-N9: only the log's own refusal sets them aside; any other
            // answer (429, 403, 5xx) throws and the next pull makes them again.
            if (!webTeamLogRefusedAnswer(err)) throw err;
            reason = 'the server refused them';
        }
    }
    if (reason !== null) {
        const ledger = await loadWebTeamLedger(_sodium);
        ledger.setAside.push(...bodies.map(body => ({ type: body.type, data: body.data, reason })));
        await saveWebTeamLedger(ledger, _sodium);
        console.warn(`Set aside ${bodies.length} lost team change(s): ${reason}`);
        renderWebTeamChangesSetAside(ledger.setAside);
    }
    return { records: served, team };
}

/** R17-N9: a 400 team_log_refused (the desktop's _refusal_from_server). */
function webTeamLogRefusedAnswer(err) {
    return err?.status === 400 && err?.code === 'team_log_refused';
}

/** R17-N9: the team changes set aside are shown (nothing read them). */
function renderWebTeamChangesSetAside(setAside) {
    let banner = document.getElementById('team-set-aside-banner');
    if (!setAside?.length) {
        if (banner) banner.remove();
        return;
    }
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'team-set-aside-banner';
        banner.className = 'sync-conflict-banner';
        document.body.appendChild(banner);
    }
    const message = document.createElement('span');
    message.textContent = t('sync.team_changes_set_aside', { count: setAside.length });
    const list = document.createElement('ul');
    for (const item of setAside) {
        const row = document.createElement('li');
        row.textContent = `${item.type} ${item.data?.user_id || ''}: ${item.reason}`;
        list.append(row);
    }
    banner.replaceChildren(message, list);
}

function webTeamLedgerAad() {
    return new TextEncoder().encode(`sezam-web-team-ledger-v2:${state.userId}`);
}

/**
 * Review 18c300f R16-H1 (desktop: vault/team_log_withdrawn.py): the records
 * of this account this browser sent while the server has not taken them
 * (sent: hash -> [seq, prev]) and the ones it withdrew - the server answered
 * 4xx, the log holds another record at that seq, or it followed a fork
 * without them (capability finding 505). A server that keeps a
 * withdrawn record never puts it in this browser's log.
 *
 * Capability finding 520: sealed under the KEK, it no longer opened after a
 * password change or org recovery here, or a sign-in with a password changed
 * elsewhere, and read as empty. Like the sync checkpoint it guards against
 * the server, not this browser, so this browser's own random key seals it,
 * which no key change of the account touches. One that does not open refuses
 * the team (INV-7: local_damaged; confirming the founder again starts it anew).
 */
async function loadWebTeamLedger(_sodium) {
    const empty = { sent: {}, withdrawn: new Set(), setAside: [] };
    if (!state.kek || !state.userId) return empty;
    const stored = await idbKeysRequest('readonly', store => store.get(`team_ledger:${state.userId}`));
    if (!stored) return empty;
    try {
        if (stored.sealed !== 'device-v2' || typeof stored.encrypted_ledger !== 'string') {
            throw new Error('unknown format');
        }
        const packed = hexToBytes(stored.encrypted_ledger);
        const nonceLen = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        const parsed = JSON.parse(new TextDecoder().decode(_sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, packed.slice(nonceLen), webTeamLedgerAad(), packed.slice(0, nonceLen),
            await syncCheckpointKey('device-v2', _sodium))));
        return { sent: parsed.sent || {}, withdrawn: new Set(parsed.withdrawn || []), setAside: parsed.set_aside || [] };
    } catch (err) {
        throw new Error(
            `the record of this browser's withdrawn team-log changes cannot be read (${err.message})`);
    }
}

async function saveWebTeamLedger(ledger, _sodium) {
    if (!state.kek || !state.userId) return;
    // A record signed on a withdrawn one is withdrawn with it.
    for (let moved = true; moved;) {
        moved = false;
        for (const [hash, [, prev]] of Object.entries(ledger.sent)) {
            if (ledger.withdrawn.has(prev)) { delete ledger.sent[hash]; ledger.withdrawn.add(hash); moved = true; }
        }
    }
    const key = await syncCheckpointKey('device-v2', _sodium, true);
    const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(new TextEncoder().encode(JSON.stringify({
        sent: ledger.sent, withdrawn: [...ledger.withdrawn].sort(), set_aside: ledger.setAside || [],
    })), webTeamLedgerAad(), null, nonce, key);
    const packed = new Uint8Array(nonce.length + ciphertext.length);
    packed.set(nonce, 0);
    packed.set(ciphertext, nonce.length);
    await idbKeysRequest('readwrite', store => store.put({
        id: `team_ledger:${state.userId}`, sealed: 'device-v2', encrypted_ledger: bytesToHex(packed),
    }));
}

/** `records` went out and the server did not take them: refused (an answer
 * 4xx applied none of them) or not known (the next pull shows it). A 409
 * refuses the request, not the records: another device of this account may
 * have put the same record in the log (desktop: _note_not_taken). */
async function noteWebTeamRecordsSent(records, err, _sodium) {
    if (!records.length || !state.kek || !_sodium) return;
    const TL = globalThis.SezamTeamLog;
    const refused = Number.isInteger(err?.status) && err.status >= 400 && err.status < 500 && err.status !== 409;
    const ledger = await loadWebTeamLedger(_sodium);
    for (const record of records) {
        const hash = TL.recordHash(record, _sodium);
        const body = TL.parseBody(record.body, null);
        if (refused) {
            delete ledger.sent[hash];
            ledger.withdrawn.add(hash);
        } else {
            ledger.withdrawn.delete(hash);
            ledger.sent[hash] = [body.seq, body.prev];
        }
    }
    await saveWebTeamLedger(ledger, _sodium);
}

/** The log this browser follows is `records`: a sent record there was taken,
 * another one at its seq was left behind. */
async function noteWebTeamLogStored(records, _sodium) {
    if (!state.kek) return;
    const ledger = await loadWebTeamLedger(_sodium);
    const sent = Object.entries(ledger.sent).filter(([, [seq]]) => seq < records.length);
    if (!sent.length) return;
    const TL = globalThis.SezamTeamLog;
    for (const [hash, [seq]] of sent) {
        delete ledger.sent[hash];
        if (TL.recordHash(records[seq], _sodium) !== hash) ledger.withdrawn.add(hash);
    }
    await saveWebTeamLedger(ledger, _sodium);
}

/** The server took `records`: one withdrawn on a 409 and built the same again
 * is this browser's will again (deep stateful run on c6d3dff, SM6). */
async function noteWebTeamRecordsTaken(records, _sodium) {
    if (!records.length || !state.kek || !_sodium) return;
    const TL = globalThis.SezamTeamLog;
    const ledger = await loadWebTeamLedger(_sodium);
    const taken = records.map(r => TL.recordHash(r, _sodium)).filter(h => ledger.withdrawn.has(h));
    if (!taken.length) return;
    for (const hash of taken) ledger.withdrawn.delete(hash);
    await saveWebTeamLedger(ledger, _sodium);
}

/** POST team log records with `send`, noting them when the server does or does not take them. */
async function sendWebTeamRecords(records, send, _sodium) {
    let result;
    try {
        result = await send();
    } catch (err) {
        await noteWebTeamRecordsSent(records, err, _sodium);
        throw err;
    }
    await noteWebTeamRecordsTaken(records, _sodium);
    return result;
}

async function catchUpWebTeamLog(head, local, pins, fetch, _sodium, refuse) {
    const TL = globalThis.SezamTeamLog;
    let team = local ? local.team : TL.emptyState();
    const records = local ? [...local.records] : [];
    const fetched = [];
    let error = null;
    for (let page = 0; page < TEAM_LOG_PAGES && team.headSeq < fetch.upto; page++) {
        const resp = await apiFetch(`/api/team-log?since=${team.headSeq}`);
        const got = Array.isArray(resp?.records) ? resp.records : [];
        if (!got.length) break;
        // Appended after this pull's head: the next pull takes it.
        const batch = got.slice(0, fetch.upto - team.headSeq);
        try {
            team = TL.replay(batch, _sodium, team);  // prev of the first = this browser's head
        } catch (err) {
            error = err.message;
            break;
        }
        records.push(...batch);
        fetched.push(...batch.map(r => TL.recordHash(r, _sodium)));
    }
    const { withdrawn } = await loadWebTeamLedger(_sodium);
    refuse(globalThis.SezamSyncCore.call('team_log_follow_caught_up', {
        head, since: fetch.since, pins, fetched, replay_error: error,
        state: { seq: team.headSeq, hash: team.headSeq < 0 ? null : team.headHash,
                 genesis_hash: team.headSeq < 0 ? null : team.genesisHash },
        withdrawn: [...withdrawn], admin_refusal: team.headSeq < 0 ? null : (TL.adminPolicyRefusal(team) || null),
        who: 'this browser',
    }));
    return { records, team };
}

/** Upload the records the server lost onto its prefix of `local`; its new head, or false. */
async function restoreWebTeamLog(head, local, pin, _sodium) {
    const TL = globalThis.SezamTeamLog;
    const serverSeq = head ? head.seq : -1;
    if (!Number.isSafeInteger(serverSeq) || serverSeq >= local.records.length) return false;
    if (Number.isSafeInteger(pin?.seq) && pin.seq > local.team.headSeq) return false;
    if (head && (head.genesis_hash !== local.team.genesisHash ||
            TL.recordHash(local.records[serverSeq], _sodium) !== head.hash)) return false;
    let current = head;
    const bodies = local.records.map((r, seq) => TL.parseBody(r.body, seq));
    // R17-L: a part ends nowhere inside a readmit (its share links).
    for (let start = serverSeq + 1, end; start < local.records.length; start = end) {
        end = TL.restorePartEnd(bodies, start, TEAM_LOG_PAGES);
        const part = local.records.slice(start, end).map(r => ({ body: r.body, sig: r.sig }));
        try {
            current = (await apiFetch('/api/team-log/restore', { method: 'POST', body: { records: part } }))?.head || null;
        } catch (err) {
            // 409: its head is not the one it announced (another device put
            // them back meanwhile, or a lie): the next pull compares again.
            console.error('The server did not take back the team log records it lost:', err);
            return false;
        }
    }
    return current;
}

/**
 * §7: may this browser seal keys to anyone from the log? An external genesis
 * anchor or this account's founder key lineage must match. An observed head
 * in the sync checkpoint alone never confirms a founder; fingerprint
 * confirmation and cross-device account transport remain separate work.
 */
function webTeamLogTrusted(_sodium, teamLog = state.teamLog, refusal = state.teamLogRefusal) {
    if (refusal || !teamLog?.records?.length) return false;
    if (state.confirmedTeamGenesis) return teamLog.team.genesisHash === state.confirmedTeamGenesis;
    if (!state.keypair?.signingPk || !state.keypair?.encryptionSk) return false;
    const { founderId, known } = webFounderLineage(teamLog);
    const encryptionPk = bytesToHex(_sodium.crypto_scalarmult_base(state.keypair.encryptionSk));
    return founderId === state.userId && known.some(([s, e]) => s === bytesToHex(state.keypair.signingPk) && e === encryptionPk);
}

function webFounderLineage(teamLog) {
    const TL = globalThis.SezamTeamLog;
    const genesis = TL.parseBody(teamLog.records[0].body, 0).data;
    const known = [[genesis.signing_pk, genesis.encryption_pk]];
    let linked = true;
    for (const record of teamLog.records) {
        const body = TL.parseBody(record.body);
        const data = body.data;
        if (data.user_id !== genesis.user_id) continue;
        if (body.type === 'member.remove') linked = false;
        else if (body.type === 'member.add') {
            linked = known.some(([s, e]) => s === data.signing_pk && e === data.encryption_pk);
        } else if (body.type === 'member.keys' && linked) {
            known.push([data.signing_pk, data.encryption_pk]);
        }
    }
    return { founderId: genesis.user_id, known };
}

/**
 * The team-log part of removing `revokedUserId` (§4.2, §4.3.1): a signed
 * member.remove (unless the log has it already) and the folders that then
 * wait for a re-key. Refused unless this account is an admin in the log and
 * this browser may seal from it.
 */
function webTeamRekeyPlan(team, revokedUserId, _sodium) {
    const TL = globalThis.SezamTeamLog;
    if (!webTeamLogTrusted(_sodium)) {
        throw teamLogRefusedError('only the admin who founded the team log removes members from the web; use a desktop');
    }
    if (!TL.isAdmin(team, state.userId)) throw teamLogRefusedError('this account is not an admin in the team log');
    const records = [];
    let after = team;
    if (team.members[revokedUserId]?.active) {
        const record = TL.signRecord(TL.nextBody(after, 'member.remove', state.userId, {
            user_id: revokedUserId,
        }), state.keypair.signingSk, _sodium);
        after = TL.applyRecord(after, record, _sodium);
        records.push(record);
    }
    const folders = Object.keys(after.stale).filter(folder => TL.isStale(after, folder)).sort();
    return { records, after, folders };
}

/**
 * Review 8595ec1 #4: the team log names this admin's org recovery key, so a
 * server restored from before the registration still takes its reset proof,
 * and (capability run 316) carries the KEK wrap the shares open, so it still
 * serves that too without any desktop keeping a copy.
 * The setup stands without it: the server takes the newest of its blob and
 * the keys the log names (review 4acfdde R11 #2), so the older shares are
 * void either way. Returns why the log refused, or '' (said to the admin, not
 * only to the console: a restored server would lack the new key).
 */
async function anchorWebOrgRecovery(recoveryPkHex, store, _sodium) {
    const TL = globalThis.SezamTeamLog;
    const team = state.teamLog?.team || null;
    if (!team || !TL.isAdmin(team, state.userId) || !webTeamLogTrusted(_sodium)) return '';
    const wrap = {
        wrapped_kek: store.wrapped_kek, key_epoch: store.key_epoch,
        threshold: store.threshold, total_shares: store.total_shares,
    };
    try {
        const records = [];
        let after = team;
        const append = (kind, data) => {
            const record = TL.signRecord(TL.nextBody(after, kind, state.userId, data), state.keypair.signingSk, _sodium);
            after = TL.applyRecord(after, record, _sodium);
            records.push(record);
        };
        if ((team.orgRecovery || {})[state.userId] !== recoveryPkHex) {
            append('org.recovery', { recovery_pk: recoveryPkHex });
        }
        const logged = (after.orgRecoveryWrap || {})[state.userId] || null;
        const changed = !logged || Object.keys(wrap).some(k => logged[k] !== wrap[k]);
        if (changed && Number.isInteger(wrap.key_epoch)) append('org.recovery.wrap', wrap);
        if (records.length) {
            await sendWebTeamRecords(records, () => apiFetch('/api/team-log', { method: 'POST', body: { records } }),
                                     _sodium);
        }
        return '';
    } catch (err) {
        console.warn('The team log did not take the org recovery key:', err.message || err);
        return String(err.message || err);
    }
}

function teamLogRefusedError(reason) {
    const err = new Error(typeof t === 'function'
        ? t('vault.team_log_refused', { reason })
        : `The team log does not allow this change (${reason})`);
    err.teamLogRefused = true;
    return err;
}

/**
 * Before a folder or item leaves this browser: the server's push rule
 * (SezamTeamLog.itemRefusal, sealing=true; tombstone and move-out rules).
 * Refused here, it is not queued at all: the server would refuse it for good.
 */
/** INV-7 rule 1: a write a refused log still lets out — one in the personal
 * tree (from and to), sealed with a key it holds: while refused this browser
 * holds no team key. A personal folder's own key goes too. */
function webPersonalWrite(vaultObj) {
    const objects = state.syncObjects || {};
    const held = objects[vaultObj.id] && !objects[vaultObj.id].is_deleted ? objects[vaultObj.id] : null;
    const personal = parent => parent ? webInPersonalTree(state.nodes || {}, objects, parent)
        : vaultObj.object_type === 'node' && !!(state.nodes?.[vaultObj.id]?.personal ?? !held);
    if (vaultObj.object_type === 'dek' && !vaultObj.parent_ref && !held) return true;
    const dekId = vaultObj.is_deleted ? held && sealingDekId(held) : payloadDekId(vaultObj);
    return ['node', 'entry'].includes(vaultObj.object_type) && !!dekId && !!state.deks[dekId] &&
        personal(vaultObj.parent_ref) && (!held || personal(held.parent_ref));
}

function assertTeamLogAllowsWrite(vaultObj) {
    const refused = state.teamLogRefusal;
    if (refused) {
        if (webPersonalWrite(vaultObj)) return;
        throw refused;
    }
    const team = state.teamLog?.team || null;
    if (state.confirmedTeamGenesis && team?.genesisHash !== state.confirmedTeamGenesis) {
        throw teamLogRefusedError('the externally confirmed team log is not downloaded');
    }
    if (!team || !['node', 'entry'].includes(vaultObj.object_type)) return;
    const objects = state.syncObjects || {};
    const held = objects[vaultObj.id] && !objects[vaultObj.id].is_deleted ? objects[vaultObj.id] : null;
    const dekId = vaultObj.is_deleted ? null : payloadDekId(vaultObj);
    const touchesTeam = webTeamFolderAbove(objects, team, vaultObj.parent_ref) !== null ||
        (held && webTeamFolderAbove(objects, team, held.parent_ref) !== null) ||
        Object.hasOwn(team.dekIndex, dekId) ||
        (held && Object.hasOwn(team.dekIndex, sealingDekId(held)));
    if (touchesTeam && !webTeamLogTrusted(state.sodium)) {
        throw teamLogRefusedError('the founder is not confirmed on this device');
    }
    // The push rule is the core's (core/src/authority.rs write_refusal).
    const [{ refusal }] = globalThis.SezamSyncCore.call('authority_write_refusal', {
        writes: [{
            id: vaultObj.id, object_type: vaultObj.object_type, parent_ref: vaultObj.parent_ref || null,
            is_deleted: !!vaultObj.is_deleted, signer: state.userId, dek_id: dekId,
        }],
        objects: webWriteState(objects, vaultObj.id, dekId),
        ...globalThis.SezamTeamLog.teamArgument(team),
    });
    if (refusal) throw teamLogRefusedError(refusal);
}

// What the core's push rule reads: the folders, the keys and who signed
// them, the copy held of `id`. A key this browser holds that the server has
// not got yet was made here, by this account.
function webWriteState(objects, id, dekId) {
    const out = [];
    for (const rec of Object.values(objects)) {
        if (rec.object_type !== 'node' && rec.object_type !== 'dek' && rec.id !== id) continue;
        out.push({
            id: rec.id, object_type: rec.object_type, parent_ref: rec.parent_ref || null,
            is_deleted: !!rec.is_deleted, signer: rec.signer || rec.owner_id || null,
            dek_id: rec.id === id && !rec.is_deleted ? sealingDekId(rec) : null,
        });
    }
    if (dekId && !objects[dekId] && state.deks?.[dekId]) {
        out.push({ id: dekId, object_type: 'dek', parent_ref: null, signer: state.userId });
    }
    return out;
}

/**
 * Accounts the log ever made admin that are still active members: what they
 * wrote outside team folders while admin stays valid after a handover
 * (review 1141a20); an account the server calls admin is not one.
 */
function webLogAdmins(teamLog) {
    return new Set(globalThis.SezamSyncCore.call('authority_log_admins', {
        bodies: teamLog.records.map(record => record.body),
        ...globalThis.SezamTeamLog.teamArgument(teamLog.team),
    }));
}

/** The team folder at or above node `nodeId` in `objects`, or null (the core's walk). */
function webTeamFolderAbove(objects, team, nodeId) {
    if (!nodeId) return null;
    const parents = {};
    for (const rec of Object.values(objects || {})) {
        if (rec.object_type === 'node') parents[rec.id] = rec.parent_ref || null;
    }
    return globalThis.SezamSyncCore.call('authority_team_folder_above', {
        node_id: nodeId, parents, ...globalThis.SezamTeamLog.teamArgument(team),
    });
}

// Which pulled folders and items not to show (and all below them): the
// core's rule, core/src/authority.rs (docs/CORE_UNIFICATION.md U5; review
// 7c10379 H4, a159e97 H4, 1141a20 H5/H6, TL5, TL7). `previous`: the snapshot
// before this pull; `teamAdmins`: the admins outside team folders with a log
// (webLogAdmins). The ids the log refused are in `.byTeamLog` too: the caller
// keeps what it showed before.
function unauthorizedWrites(syncObjects, ownUserId, team = null, previous = null, teamAdmins = null) {
    const out = globalThis.SezamSyncCore.call('authority_unauthorized_writes', {
        objects: authorityObjects(syncObjects),
        own_user_id: ownUserId || null,
        previous: previous ? authorityObjects(previous) : null,
        team_admins: team && teamAdmins ? [...teamAdmins] : null,
        ...(team ? globalThis.SezamTeamLog.teamArgument(team) : {}),
    });
    const blocked = new Set(out.blocked);
    blocked.byTeamLog = new Set(out.by_team_log);
    return blocked;
}

// The fields core/src/authority.rs judges by (the signer that verified, the
// unsigned owner_id when none did; the key a folder or item header names).
function authorityObjects(syncObjects) {
    return Object.values(syncObjects || {}).map(rec => ({
        id: rec.id,
        object_type: rec.object_type,
        parent_ref: rec.parent_ref || null,
        is_deleted: !!rec.is_deleted,
        signer: rec.signer || rec.owner_id || null,
        access_level: rec.access_level ?? null,
        target_user_id: rec.target_user_id ?? null,
        dek_id: ['node', 'entry'].includes(rec.object_type) ? sealingDekId(rec) : null,
    }));
}

/**
 * Review a159e97 H4: the folders and items this account must never seal and
 * sign again. unauthorizedWrites only kept them out of view, while the re-key
 * and the successor sweep took state.syncObjects as it was: a forged folder
 * came back as this admin's own signed v2, which every client then trusted.
 * A write below a folder this browser does not know (withheld, or never
 * there) cannot be judged and is not taken either, unless this account wrote it.
 */
function writesNotToSeal(syncObjects, ownUserId) {
    const teamLog = state.teamLog?.team ? state.teamLog : null;
    const skip = unauthorizedWrites(syncObjects, ownUserId, teamLog?.team || null, syncObjects,
        teamLog ? webLogAdmins(teamLog) : null);
    for (const rec of Object.values(syncObjects || {})) {
        if (!['node', 'entry'].includes(rec.object_type) || !rec.parent_ref) continue;
        if (!syncObjects[rec.parent_ref] && (rec.signer || rec.owner_id) !== ownUserId) skip.add(rec.id);
    }
    const below = id => {  // and everything below a folder not taken
        const seen = new Set();
        for (let cur = syncObjects[id]?.parent_ref; cur && !seen.has(cur); cur = syncObjects[cur]?.parent_ref) {
            if (skip.has(cur)) return true;
            seen.add(cur);
        }
        return false;
    };
    for (const rec of Object.values(syncObjects || {})) {
        if (['node', 'entry'].includes(rec.object_type) && below(rec.id)) skip.add(rec.id);
    }
    return skip;
}

/**
 * W3: state_hash for rollback protection: the core's formula
 * (core/src/formats.rs state_hash, docs/CORE_UNIFICATION.md U6g). R17-N1:
 * the signed parent and deleted flag count. ``legacy``: the formula of a
 * checkpoint without state_v. Covers every raw sync object, including
 * tombstones and non-content objects.
 */
async function computeWebStateHash(syncObjects, _sodium, legacy = false) {
    const objects = Object.values(syncObjects).map((obj) => ({
        id: String(obj.id || ''),
        version: Number(obj.version),
        payload_hash: bytesToHex(_sodium.crypto_hash_sha256(base64ToBytes(obj.payload || ''))),
        parent_ref: obj.parent_ref == null ? null : String(obj.parent_ref),
        is_deleted: Boolean(obj.is_deleted),
    }));
    return globalThis.SezamSyncCore.call('state_hash', { objects, legacy });
}

// The successor key's certificate over an archived key: the core's message
// (docs/CORE_UNIFICATION.md U6c).
function keyRotationMessage(userId, oldSigningPk, oldEncryptionPk, newSigningPk, newEncryptionPk) {
    return hexToBytes(globalThis.SezamSyncCore.call('key_rotation_message', {
        user_id: userId, old_signing_pk: bytesToHex(oldSigningPk),
        old_encryption_pk: bytesToHex(oldEncryptionPk), new_signing_pk: bytesToHex(newSigningPk),
        new_encryption_pk: bytesToHex(newEncryptionPk),
    }));
}

// Current key plus archived keys reachable through rotation certificates
// signed by their successor, so the server cannot inject historical keys.
// ── Key vouchers (goal #443, src/sezam/key_vouchers.py, tests/vectors/key_vouchers.json) ──

// The rules and every byte are the Rust core's (core/src/vouchers.rs, U5);
// the page only verifies the Ed25519 signatures the core names.
function keyVoucherKey(id, version, digest) {
    return `${id}:${version}:${String(digest || '').toLowerCase()}`;
}

/**
 * R17-N1: the entry a voucher names for a served object as `signingPk` of
 * `signerId` signed it: the digest of the whole signed message, the signer's
 * account and key. Null when malformed.
 */
function keyVoucherObjectEntry(obj, signerId, signingPk, _sodium) {
    try {
        const signed = {};
        for (const name of ['id', 'object_type', 'parent_ref', 'target_user_id', 'is_deleted', 'version', 'payload_hash']) if (obj && name in obj) signed[name] = obj[name];
        return globalThis.SezamSyncCore.call('key_voucher_object_entry', {
            object: signed, signer_id: signerId, signing_pk: bytesToHex(signingPk),
        });
    } catch {
        return null;
    }
}

function canonicalKeyVoucherEntries(entries) {
    return globalThis.SezamSyncCore.call('key_voucher_canonical', { entries });
}

function keyVoucherMessage(userId, signingPk, entries) {
    if (signingPk.length !== 32) throw new Error('A voucher signing key is 32 bytes');
    const out = globalThis.SezamSyncCore.call('key_voucher_message', {
        user_id: userId, signing_pk: bytesToHex(signingPk), entries,
    });
    return hexToBytes(out.message);
}

function vouchedEntries(userId, currentSigningPk, lists, _sodium) {
    try {
        const args = { user_id: userId, current_signing_pk: bytesToHex(currentSigningPk), lists: lists ?? null };
        const verified = globalThis.SezamSyncCore.call('key_voucher_lists', args).map((check) => {
            try {
                return !!check && _sodium.crypto_sign_verify_detached(
                    hexToBytes(check.signature), hexToBytes(check.message), currentSigningPk
                );
            } catch {
                return false;
            }
        });
        const entries = globalThis.SezamSyncCore.call('key_voucher_vouched', { ...args, verified });
        return new Set(entries.map(([id, version, digest]) => keyVoucherKey(id, version, digest)));
    } catch {
        return new Set();
    }
}

const KEY_VOUCHER_MAX_PAGES = 64;

async function fetchVouchedEntries(userId, currentHex, _sodium) {
    if (!currentHex) return new Set();
    // R17-N10: the server pages the lists; "next" is '' after the last page
    // (at most KEY_VOUCHER_MAX_PAGES, src/sezam/key_vouchers.py MAX_PAGES).
    const lists = [];
    try {
        let after = '';
        for (let page = 0; page < KEY_VOUCHER_MAX_PAGES; page++) {
            const query = after ? `?after=${encodeURIComponent(after)}` : '';
            const data = await apiFetch(`/api/users/${userId}/key-vouchers${query}`);
            lists.push(...(data?.lists || []));
            after = data?.next || '';
            if (!after) break;
        }
    } catch (err) {
        console.warn('No key vouchers for', userId, err.message);
        return new Set();
    }
    return vouchedEntries(userId, hexToBytes(currentHex), lists, _sodium);
}

// The current key and the archived ones its rotation certificates reach, as
// [{signingPk, encryptionPk}] in chain order; throws on a malformed response.
// The rule is the core's (core/src/keyring.rs, capability review 716); the
// page only verifies the signatures it names.
function keyRing(userId, currentSigningPk, currentEncryptionPk, archivedKeys, _sodium) {
    const args = {
        user_id: userId,
        current_signing_pk: bytesToHex(currentSigningPk),
        current_encryption_pk: bytesToHex(currentEncryptionPk),
        archived_keys: archivedKeys ?? null,
    };
    const verified = globalThis.SezamSyncCore.call('key_ring_checks', args).map((check) => {
        try {
            return _sodium.crypto_sign_verify_detached(
                hexToBytes(check.signature), hexToBytes(check.message), hexToBytes(check.public_key)
            );
        } catch {
            return false;
        }
    });
    return globalThis.SezamSyncCore.call('key_ring', { ...args, verified }).map((pair) => ({
        signingPk: hexToBytes(pair.signing_pk), encryptionPk: hexToBytes(pair.encryption_pk),
    }));
}

async function getUserSigningPks(userId) {
    if (state.userKeys[userId]) return state.userKeys[userId];

    try {
        const data = await apiFetch(`/api/users/${userId}/keys`);
        if (!data || !data.signing_pk) return null;

        const current = hexToBytes(data.signing_pk);
        const currentEncryption = hexToBytes(data.encryption_pk || '');
        if (current.length !== 32 || currentEncryption.length !== 32) {
            throw new Error('Current public keys must be 32 bytes');
        }
        await globalThis.SezamSyncCore.ready;  // the key ring's rule (keyRing)
        const ring = keyRing(userId, current, currentEncryption, data.archived_keys, await ensureSodium());
        const keys = ring.map(pair => pair.signingPk);

        const currentSigningHex = bytesToHex(current);
        const currentEncryptionHex = bytesToHex(currentEncryption);
        if (userId === state.userId && state.keypair?.signingPk && state.keypair?.encryptionSk) {
            const localSigningHex = bytesToHex(state.keypair.signingPk);
            const localEncryptionHex = bytesToHex(
                (await ensureSodium()).crypto_scalarmult_base(state.keypair.encryptionSk)
            );
            if (currentSigningHex !== localSigningHex || currentEncryptionHex !== localEncryptionHex) {
                throw tofuKeyChange(state.username, userId, currentSigningHex, currentEncryptionHex);
            }
            // Our own keys are proven by the keypair the password just opened;
            // after an identity rotation the old pin is replaced, not a MITM.
            await saveKnownKey(userId, currentSigningHex, currentEncryptionHex);
        } else {
            const tofuResult = await checkKnownKey(
                userId, currentSigningHex, currentEncryptionHex
            );
            if (tofuResult === 'changed') {
                throw tofuKeyChange(userId, userId, currentSigningHex, currentEncryptionHex);
            }
        }

        state.userKeys[userId] = keys;
        // Goal #443: the archived keys vouch only for what the voucher lists
        // of the current key name (fetchVouchedEntries); retired_seq is not read.
        state.retiredKeys = {
            ...state.retiredKeys,
            [userId]: new Set(keys.map(pk => bytesToHex(pk)).filter(pkHex => pkHex !== currentSigningHex)),
        };
        state.voucherKeys = { ...state.voucherKeys, [userId]: currentSigningHex };
        // X25519 keys paired with the trusted signing keys (current first),
        // used to authenticate DEK envelopes from this user.
        state.userEncryptionKeys = {
            ...state.userEncryptionKeys,
            [userId]: ring.map(pair => pair.encryptionPk),
        };
        return keys;
    } catch (err) {
        if (err instanceof TofuKeyChangeError) throw err;
        console.warn('Failed to fetch signing keys for user', userId, err.message);
    }
    return null;
}

// ── Auto-create root folder ──

async function createRootFolderLocked() {
    const _sodium = await ensureSodium();

    // 1. Generate Root DEK (32 random bytes)
    const dekId = generateULID();
    const dekBytes = _sodium.randombytes_buf(32);

    // 2. Wrap DEK with KEK (blob_kind=6)
    const wrappedDek = wrapDEK(dekBytes, dekId, 1, state.kek, _sodium);

    // 3. Push DEK to server as vault_object type='dek'
    const dekPayloadHash = await sha256hexBytes(wrappedDek);
    const dekSig = signSyncObject(
        _sodium, dekId, 'dek', null, null, 0, 1, hexToBytes(dekPayloadHash)
    );
    await pushEncryptedVaultObjectLocked({
        id: dekId,
        object_type: 'dek',
        payload: bytesToBase64(wrappedDek),
        parent_ref: null,
        version: 1,
        is_deleted: 0,
        payload_hash: dekPayloadHash,
        signature: bytesToHex(dekSig),
        scope: 'root',
    });

    // 4. Store DEK in state
    state.deks[dekId] = dekBytes;
    state.kekDekIds = [...(state.kekDekIds || []), dekId];
    state.rootDekId = dekId;

    // 5. Create root node, encrypted with Root DEK (blob_kind=1)
    const rootId = generateULID();
    const rootPayload = { name: 'Vault' };
    const envelope = encryptEnvelope(
        rootPayload, BLOB_KIND.NODE_META, dekId, rootId, 1, dekBytes, _sodium
    );
    const rootPayloadB64 = bytesToBase64(envelope);
    const rootPayloadHash = await sha256hexBytes(envelope);
    const rootSig = signSyncObject(
        _sodium, rootId, 'node', null, null, 0, 1, hexToBytes(rootPayloadHash)
    );

    await pushEncryptedVaultObjectLocked({
        id: rootId,
        object_type: 'node',
        payload: rootPayloadB64,
        parent_ref: null,
        version: 1,
        is_deleted: 0,
        payload_hash: rootPayloadHash,
        signature: bytesToHex(rootSig),
    });

    state.rootNodeId = rootId;
    state.selectedFolderId = rootId;
    await pullAndBuildTreeLocked();
}

// ── Folder modal ──

function openFolderModal(existingNode) {
    const modal = document.getElementById('entry-modal');
    const title = document.getElementById('modal-title');
    const modeInput = document.getElementById('modal-mode');
    const idInput = document.getElementById('modal-entry-id');
    const nameInput = document.getElementById('modal-name');
    const tagsGroup = document.getElementById('modal-tags-group');
    const fieldsSection = document.getElementById('modal-fields-section');
    const parentGroup = document.getElementById('modal-parent-group');
    const errorEl = document.getElementById('modal-error');

    modeInput.value = 'folder';
    errorEl.classList.add('hidden');

    // Hide tags and fields for folders
    tagsGroup.classList.add('hidden');
    fieldsSection.classList.add('hidden');

    if (existingNode) {
        title.textContent = t('entry.modal.edit_folder');
        idInput.value = existingNode.id;
        nameInput.value = existingNode.name || '';
    } else {
        title.textContent = t('entry.modal.new_folder');
        idInput.value = '';
        nameInput.value = '';
    }

    populateParentSelect(
        existingNode ? existingNode.id : null,
        existingNode ? existingNode.parent_ref : null
    );
    parentGroup.classList.remove('hidden');
    modal.classList.remove('hidden');
    nameInput.focus();
}

// ── Personal folder modal ──

function openPersonalFolderModal() {
    const modal = document.getElementById('entry-modal');
    const title = document.getElementById('modal-title');
    const modeInput = document.getElementById('modal-mode');
    const idInput = document.getElementById('modal-entry-id');
    const nameInput = document.getElementById('modal-name');
    const tagsGroup = document.getElementById('modal-tags-group');
    const fieldsSection = document.getElementById('modal-fields-section');
    const parentGroup = document.getElementById('modal-parent-group');
    const errorEl = document.getElementById('modal-error');

    modeInput.value = 'personal';
    errorEl.classList.add('hidden');

    tagsGroup.classList.add('hidden');
    fieldsSection.classList.add('hidden');
    parentGroup.classList.add('hidden');

    title.textContent = t('entry.modal.new_personal');
    idInput.value = '';
    nameInput.value = '';

    modal.classList.remove('hidden');
    nameInput.focus();
}

/**
 * Create a personal folder with its own DEK — no admin envelope.
 * The DEK is wrapped with the current user's KEK only.
 */
async function createPersonalFolder(name) {
    const _sodium = await ensureSodium();

    // 1. Generate a personal DEK (32 random bytes)
    const personalDekId = generateULID();
    const personalDekBytes = _sodium.randombytes_buf(32);

    // 2. Wrap DEK with user's KEK — NO envelopes for other users
    const wrappedDek = wrapDEK(personalDekBytes, personalDekId, 1, state.kek, _sodium);

    // 3. Push personal DEK to server
    const dekPayloadHash = await sha256hexBytes(wrappedDek);
    const dekSig = signSyncObject(
        _sodium, personalDekId, 'dek', null, null, 0, 1, hexToBytes(dekPayloadHash)
    );
    await pushEncryptedVaultObject({
        id: personalDekId,
        object_type: 'dek',
        payload: bytesToBase64(wrappedDek),
        parent_ref: null,
        version: 1,
        is_deleted: 0,
        payload_hash: dekPayloadHash,
        signature: bytesToHex(dekSig),
        scope: 'personal',
    });

    // 4. Store personal DEK in state
    state.deks[personalDekId] = personalDekBytes;

    // 5. Create node encrypted with personal DEK, with scope marker
    const nodeId = generateULID();
    const nodePayload = { name: name, personal: true };
    const envelope = encryptEnvelope(
        nodePayload, BLOB_KIND.NODE_META, personalDekId, nodeId, 1, personalDekBytes, _sodium
    );
    const nodePayloadB64 = bytesToBase64(envelope);
    const nodePayloadHash = await sha256hexBytes(envelope);
    // TL7: a personal root, top-level, not below the (organisation's) root.
    const nodeSig = signSyncObject(
        _sodium, nodeId, 'node', null, null, 0, 1, hexToBytes(nodePayloadHash)
    );

    await pushEncryptedVaultObject({
        id: nodeId,
        object_type: 'node',
        payload: nodePayloadB64,
        parent_ref: null,
        version: 1,
        is_deleted: 0,
        payload_hash: nodePayloadHash,
        signature: bytesToHex(nodeSig),
    });

    // 6. Add to local state
    state.nodes[nodeId] = {
        id: nodeId,
        name: name,
        parent_ref: null,
        version: 1,
        personal: true,
    };

    await pullAndBuildTree();
    return nodeId;
}

// ── Entry modal ──

function openEntryModal(existingEntry) {
    const modal = document.getElementById('entry-modal');
    const title = document.getElementById('modal-title');
    const modeInput = document.getElementById('modal-mode');
    const idInput = document.getElementById('modal-entry-id');
    const nameInput = document.getElementById('modal-name');
    const tagsInput = document.getElementById('modal-tags');
    const tagsGroup = document.getElementById('modal-tags-group');
    const fieldsSection = document.getElementById('modal-fields-section');
    const fieldsList = document.getElementById('modal-fields-list');
    const parentGroup = document.getElementById('modal-parent-group');
    const errorEl = document.getElementById('modal-error');

    modeInput.value = 'entry';
    errorEl.classList.add('hidden');

    // Show tags and fields for entries
    tagsGroup.classList.remove('hidden');
    fieldsSection.classList.remove('hidden');

    // Clear fields list
    fieldsList.innerHTML = '';

    const sharedInput = document.getElementById('modal-shared');
    if (existingEntry) {
        title.textContent = t('entry.modal.edit');
        idInput.value = existingEntry.id;
        nameInput.value = existingEntry.name || '';
        tagsInput.value = (existingEntry.tags || []).join(', ');
        if (sharedInput) sharedInput.checked = existingEntry.write_policy === 'shared';

        // Populate existing fields
        (existingEntry.fields || []).forEach(f => {
            addFieldRow(null, f.key, f.value, f.sensitive);
        });
    } else {
        title.textContent = t('entry.modal.new');
        idInput.value = '';
        nameInput.value = '';
        tagsInput.value = '';
        if (sharedInput) sharedInput.checked = false;

        // Add one default field row with "password" key
        addFieldRow(null, 'password', '', true);
    }

    populateParentSelect(null, existingEntry ? existingEntry.parent_ref : null);
    parentGroup.classList.remove('hidden');
    modal.classList.remove('hidden');
    nameInput.focus();
}

function closeEntryModal() {
    document.getElementById('entry-modal').classList.add('hidden');
    document.getElementById('entry-form').reset();
    document.getElementById('modal-fields-list').innerHTML = '';
}

// ── Populate parent folder dropdown ──

function populateParentSelect(excludeNodeId, preselectedId) {
    const select = document.getElementById('modal-parent');
    select.innerHTML = '';

    // Collect all folders
    const folders = [];
    function walk(nodeList, depth) {
        for (const n of nodeList) {
            if (n._undecryptable || (excludeNodeId && n.id === excludeNodeId)) continue;
            folders.push({ id: n.id, name: n.name || t('tree.folder'), depth });
            if (n.children) walk(n.children, depth + 1);
        }
    }

    if (state.tree) walk(state.tree, 0);

    if (folders.length === 0) {
        // Fallback: add root
        const opt = document.createElement('option');
        opt.value = state.rootNodeId || '';
        opt.textContent = t('tree.vault');
        select.appendChild(opt);
        return;
    }

    for (const f of folders) {
        const opt = document.createElement('option');
        opt.value = f.id;
        const indent = '\u00A0\u00A0'.repeat(f.depth);
        opt.textContent = indent + f.name;
        select.appendChild(opt);
    }

    // Set selected value
    const targetId = preselectedId || state.selectedFolderId || (folders.length > 0 ? folders[0].id : '');
    if (targetId) select.value = targetId;
}

// ── Add a field row to the modal ──

function addFieldRow(e, key, value, sensitive) {
    if (e) e.preventDefault();

    const fieldsList = document.getElementById('modal-fields-list');
    const row = document.createElement('div');
    row.className = 'modal-field-row';
    row.innerHTML = `
        <input type="text" class="field-key-input" placeholder="${escapeHtml(t('entry.field_key'))}" value="${escapeHtml(key || '')}" autocomplete="off">
        <input type="text" class="field-value-input" placeholder="${escapeHtml(t('entry.field_value'))}" value="${escapeHtml(value || '')}" autocomplete="off">
        <label class="sensitive-toggle">
            <input type="checkbox" class="field-sensitive-input" ${sensitive ? 'checked' : ''}>
            <span>${escapeHtml(t('entry.field_secret'))}</span>
        </label>
        <button type="button" class="remove-field-btn" title="${escapeHtml(t('entry.remove_field'))}">&times;</button>
    `;

    row.querySelector('.remove-field-btn').addEventListener('click', () => {
        row.remove();
    });

    fieldsList.appendChild(row);
}

/**
 * Stateful test SM72: a folder another device deleted while this one saved a
 * folder in it stays live below the deleted one (the page shows it at the
 * top). The deleted folder is still a tombstone in the snapshot; its sealed
 * name tells whether it was a personal folder. Without it nothing could be
 * saved in the live folder ('Parent folder is unavailable.').
 * R16-N29: the blob may be sealed several versions below the tombstone (a
 * delete kept over a conflict goes out a version above the server's), so it
 * is read at every version below, as desktop sealed.py and the page's own
 * reviveFoldersOfUnsentWork do.
 */
function trashedNode(nodeId) {
    const obj = state.syncObjects?.[nodeId];
    if (!obj || obj.object_type !== 'node' || !obj.is_deleted || !state.sodium) return null;
    const payloadBytes = base64ToBytes(obj.payload || '');
    if (!isEncryptedEnvelope(payloadBytes)) return null;
    const dekId = new TextDecoder().decode(payloadBytes.slice(3, 29)).replace(/\0/g, '');
    const top = Number(obj.version);
    const versions = [top - 1, top];
    for (let v = top - 2; v >= 0 && v > top - 256; v--) versions.push(v);
    for (const version of versions.filter(v => v >= 0)) {
        try {
            const meta = decryptEnvelope(payloadBytes, obj.id, version, state.deks, state.sodium,
                BLOB_KIND.NODE_META);
            // Review c02cc47 R17-L: a personal folder is signed by its author
            // only (TL7), so a tombstone another account signed is never ours.
            const signer = obj.signature_user_id || obj.owner_id || null;
            return { id: obj.id, parent_ref: obj.parent_ref, dekId, signer,
                     personal: !!(meta && meta.personal) && signer === state.userId
                         && (state.kekDekIds || []).includes(dekId) };
        } catch {
            // the other version
        }
    }
    return null;
}

function resolveInheritedPersonalDekId(parentRef) {
    // INV-7: outside the personal tree a refused log names itself and its way out.
    if (state.teamLogRefusal && parentRef && !webInPersonalTree(state.nodes || {}, state.syncObjects || {}, parentRef)) {
        throw state.teamLogRefusal;
    }
    const visited = new Set();
    let nodeId = parentRef;

    while (nodeId) {
        if (visited.has(nodeId)) throw new Error('Folder hierarchy contains a cycle.');
        visited.add(nodeId);

        const node = state.nodes[nodeId] || trashedNode(nodeId);
        if (!node) throw new Error('Parent folder is unavailable.');
        if (node._undecryptable) {
            // Review 2052248 #8: a team member cannot read the admin's folders
            // above a shared one. Another user's folder is never OUR personal
            // folder, so keep walking; our own unreadable folder fails closed.
            // INV-3: "another user's" is who signed it (a personal folder is
            // signed by its author only, TL7), never the server's owner_id.
            if (!node.signer || node.signer === state.userId) {
                throw new Error('Parent folder is unavailable.');
            }
            nodeId = node.parent_ref;
            continue;
        }
        if (node.personal) {
            if (!node.dekId || !state.deks[node.dekId]) {
                throw new Error('Personal folder key is unavailable.');
            }
            return node.dekId;
        }
        nodeId = node.parent_ref;
    }

    return undefined;
}

/**
 * Open an access envelope: payload = nonce(24) || crypto_box(DEK), sealed by
 * the envelope signer's X25519 key (any key of its verified key ring).
 */
function openDekEnvelope(envelope, _sodium) {
    const senderId = envelope.signature_user_id || envelope.signer || envelope.owner_id;
    const senderPks = state.userEncryptionKeys[senderId] || [];
    const blob = base64ToBytes(envelope.payload || '');
    const nonceLen = _sodium.crypto_box_NONCEBYTES;
    if (blob.length !== nonceLen + _sodium.crypto_box_MACBYTES + 32) {
        throw new Error('Malformed DEK envelope');
    }
    const nonce = blob.slice(0, nonceLen);
    const box = blob.slice(nonceLen);
    for (const senderPk of senderPks) {
        try {
            return _sodium.crypto_box_open_easy(box, nonce, senderPk, state.keypair.encryptionSk);
        } catch {
            // try the next trusted key of the sender
        }
    }
    throw new Error(`No trusted key of ${senderId} opens the envelope`);
}

/**
 * The root DEK we encrypt top-level objects with: the DEK heading a top-level
 * folder, preferring one our own KEK opens (ours first when several admins
 * have roots), then one the server labels 'root' that our KEK opens, then a
 * root DEK an admin shared with us. Never simply the first DEK found, and
 * never a legacy plaintext DEK object (review 2052248: anyone allowed to push
 * a DEK could name its own DEK the root and read what we encrypt next).
 */
function selectRootDekId(nodes, syncObjects, kekDekIds, heldDeks, userId) {
    const byOwnerThenId = (a, b) =>
        (a.owner_id === userId ? 0 : 1) - (b.owner_id === userId ? 0 : 1) ||
        (a.id < b.id ? -1 : (a.id > b.id ? 1 : 0));
    const topLevel = nodes
        .filter(n => !n.parent_ref && !n.personal && !n._undecryptable && n.dekId)
        .sort(byOwnerThenId);
    const own = topLevel.find(n => kekDekIds.has(n.dekId));
    if (own) return own.dekId;
    const labelled = Object.values(syncObjects || {})
        .filter(obj => obj.object_type === 'dek' && !obj.is_deleted &&
            obj.scope === 'root' && kekDekIds.has(obj.id))
        .map(obj => obj.id)
        .sort();
    if (labelled.length) return labelled[0];
    const shared = topLevel.find(n => heldDeks[n.dekId]);
    return shared ? shared.dekId : null;
}

/**
 * The account that signed the top-level folder `nodeId` lies under, or null
 * when the chain breaks (a folder this browser does not know) or, given
 * `openedNodes`, when that top-level folder does not open here (a version
 * another account re-signed cannot be sealed under the owner's key).
 */
function folderTreeOwner(syncObjects, nodeId, openedNodes = null, ownUserId = null) {
    const seen = new Set();
    let rec = nodeId ? syncObjects?.[nodeId] : null;
    while (rec && rec.object_type === 'node' && !seen.has(rec.id)) {
        if (!rec.parent_ref) {
            if (openedNodes && (!openedNodes[rec.id] || openedNodes[rec.id]._undecryptable)) return null;
            // Review 1141a20 H5: the AAD binds no signer, so a lying server
            // serves this account's own top-level folder as a copy another
            // account ('Eve') signed, and it opens. Sealed with a key this
            // account's KEK opens, it is this account's whoever signed the
            // copy; with a team log only a log admin owns one, or its signer
            // under a key of their own (TL7: a personal tree).
            const signer = rec.signer || rec.owner_id || null;
            const dekId = openedNodes?.[rec.id]?.dekId ?? (rec.payload ? sealingDekId(rec) : null);
            if (ownUserId && dekId && (state.kekDekIds || []).includes(dekId)) return ownUserId;
            if (state.teamLog?.team && signer && !webLogAdmins(state.teamLog).has(signer)) {
                const dek = dekId ? syncObjects[dekId] : null;
                const personal = dek && dek.object_type === 'dek' && !dek.parent_ref &&
                    (dek.signer || dek.owner_id) === signer;
                if (!personal) return null;
            }
            return signer;
        }
        seen.add(rec.id);
        rec = syncObjects[rec.parent_ref];
    }
    return null;
}

/**
 * Review 7c10379 H3: the accounts whose keys, key envelopes and key archives
 * this browser takes for folder `nodeId`. #345 (desktop: capability run 196):
 * these were this account and every account that signed a top-level folder,
 * taken for the admin. The server decides which top-level folders it takes
 * and serves, so an account it made ('Eve') with a folder of her own counted
 * as an admin for every folder: her key for the admin's empty folder sealed
 * the next item there, her archive retired the folder's key. A folder's keys
 * now come from this account or the account that signed the top of the
 * folder's tree only.
 */
function keyAuthors(syncObjects, ownUserId, nodeId, openedNodes = null) {
    const authors = new Set(ownUserId ? [ownUserId] : []);
    const owner = folderTreeOwner(syncObjects, nodeId, openedNodes, ownUserId);
    if (owner) authors.add(owner);
    return authors;
}

/**
 * The key envelopes addressed to `userId` that this account signed or the
 * owner of the folder tree the enveloped key names (keyAuthors). With a team
 * log, another account's envelope counts only on a key the log knows.
 */
function keyEnvelopesForUser(envelopes, syncObjects, userId, teamLog = null, _sodium = null) {
    return envelopes.filter(envelope => {
        if (envelope.target_user_id !== userId) return false;
        if (teamLog) {
            if (!webTeamLogTrusted(_sodium, teamLog)) return false;
            const team = teamLog.team;
            if (team.dekIndex[envelope.parent_ref]) {
                const signer = envelope.signature_user_id || envelope.signer || envelope.owner_id;
                const encryptionPk = bytesToHex(_sodium.crypto_scalarmult_base(state.keypair.encryptionSk));
                if (!globalThis.SezamTeamLog.envelopeValid(team, signer, userId, envelope.parent_ref,
                    envelope.access_level, encryptionPk)) return false;
                // Archived account keys alone cannot authorize a new team envelope.
                return verifyObjectSignature(envelope, hexToBytes(team.members[signer].signingPk), _sodium);
            }
            // Review 1141a20 H6: with a log, another account's key reaches this
            // one only through the log (§9), not by who signed the folder tree.
            return (envelope.signature_user_id || envelope.signer || envelope.owner_id) === userId;
        }
        const folder = syncObjects?.[envelope.parent_ref]?.parent_ref || null;
        return keyAuthors(syncObjects, userId, folder)
            .has(envelope.signature_user_id || envelope.signer || envelope.owner_id);
    });
}

/** The millisecond time in a ULID's first ten characters, or NaN. */
function ulidTimeMs(id) {
    const ENCODING = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    let time = 0;
    for (const ch of String(id || '').slice(0, 10).toUpperCase()) {
        const digit = ENCODING.indexOf(ch);
        if (digit < 0) return NaN;
        time = time * 32 + digit;
    }
    return String(id || '').length >= 10 ? time : NaN;
}

/**
 * Review d615826 H3: which key a re-key replaced is proven by the signed
 * dek_archive that seals the old key under the new one (the desktop's
 * successor_of), never by the unsigned scope label or the newest ULID. A
 * server relabelling a personal DEK 'folder' had the sweep reseal the
 * personal folder under the shared parent's key. Old DEK id -> new DEK id,
 * for keys this browser holds.
 */
function provenDekSuccessors() {
    // Review 7c10379: this kept every held key as a hex string, which nothing
    // can wipe; the archived key is now matched byte for byte and wiped.
    // A team folder's superseded key counts: the log refuses it for reading,
    // but what was queued under it is sealed again under its successor.
    const held = [...Object.entries(state.deks || {}), ...Object.entries(state.supersededDeks || {})]
        .filter(([, bytes]) => bytes instanceof Uint8Array);
    const successors = {};
    for (const obj of Object.values(state.syncObjects || {})) {
        if (obj.object_type !== 'dek_archive' || obj.is_deleted || !obj.parent_ref) continue;
        const folder = state.syncObjects[obj.parent_ref]?.parent_ref || null;
        if (!keyAuthors(state.syncObjects, state.userId, folder, state.nodes)
            .has(obj.signer || obj.owner_id)) continue;
        const newDek = state.deks?.[obj.parent_ref];
        if (!(newDek instanceof Uint8Array)) continue;
        let oldDek;
        try {
            const bytes = base64ToBytes(obj.payload);
            if (new TextDecoder().decode(bytes.slice(3, 29)) !== obj.parent_ref) continue;
            oldDek = unwrapDEK(bytes, newDek, obj.id, Number(obj.version) || 1, state.sodium);
        } catch {
            continue;  // not an archive under this key
        }
        const match = held.find(([, bytes]) =>
            bytes.length === oldDek.length && state.sodium.memcmp(bytes, oldDek));
        state.sodium.memzero(oldDek);
        const oldId = match?.[0];
        if (oldId && oldId !== obj.parent_ref) successors[oldId] = obj.parent_ref;
    }
    return successors;
}

/** The key at the end of `dekId`'s proven re-key chain, or null. */
function finalDekSuccessor(dekId, successors = provenDekSuccessors()) {
    const seen = new Set([dekId]);
    let current = dekId;
    while (successors[current] && !seen.has(successors[current])) {
        current = successors[current];
        seen.add(current);
    }
    return current === dekId ? null : current;
}

/** Folder DEKs a re-key replaced (a signed archive proves each one). */
function retiredFolderDekIds() {
    return new Set(Object.keys(provenDekSuccessors()));
}

/**
 * The current DEK of the nearest folder (self or ancestor) that has one we
 * hold. Review d615826 H3: only signed facts pick the folder - the DEK's
 * parent_ref, a tier-2 entry naming it, an archive retiring it. The unsigned
 * scope label only orders a folder's own keys: a server labelling a
 * subfolder's key 'tier2' had a new entry sealed under the parent folder's
 * key, which a member with access to the parent only could read.
 *
 * Review 7c10379 H3: any entry with tier 2 in its meta took its key out, so
 * one item a write member sealed under the folder's key with tier 2 (or an
 * honest move of a tier-2 item) had new items sealed under the parent
 * folder's key; and the newest key id won, so a key a member signed with a
 * ULID from the future stayed the folder's key after the member was removed.
 * Now, as on the desktop (_is_folders_own_key), a tier-2 entry only ranks a
 * folder's keys when there are several: a key sealing a subfolder or a tier
 * 0/1 item of the folder, or a re-key's successor, is the folder's; a key
 * only tier-2 items name (signed by the admin or us - only they make keys)
 * comes last. Keys come from the folder tree's owner or this account only
 * (keyAuthors, #345), and a key id from the future is ignored.
 */
function nearestFolderDekId(folderId) {
    // TL5 (§4.3.2): in a team folder the key is the log's current generation
    // only, never one a heuristic below picks.
    const team = state.teamLog?.team || null;
    const teamFolder = team ? webTeamFolderAbove(state.syncObjects, team, folderId) : null;
    if (teamFolder) {
        const current = globalThis.SezamTeamLog.currentKey(team, teamFolder);
        if (state.deks?.[current]) return current;
        throw teamLogRefusedError("this browser does not hold the folder's current key");
    }
    const visited = new Set();
    const nonFolderScopes = new Set(['root', 'tier2', 'personal', 'audit', 'share']);
    const authors = keyAuthors(state.syncObjects, state.userId, folderId, state.nodes);
    const retired = provenDekSuccessors();
    const successors = new Set(Object.values(retired));
    const latest = Date.now() + 10 * 60 * 1000;  // a key id may run this far ahead of our clock
    const author = id => {
        const rec = state.syncObjects?.[id];
        return rec ? (rec.signer || rec.owner_id) : null;
    };
    const entries = Object.values(state.entries || {}).filter(e => !e._undecryptable && e.dekId);
    const role = (dekId, nodeId) => {
        if (successors.has(dekId) ||
                Object.values(state.nodes || {}).some(n => n.parent_ref === nodeId && n.dekId === dekId) ||
                entries.some(e => e.parent_ref === nodeId && e.dekId === dekId && Number(e.tier) !== 2)) {
            return 2;
        }
        return entries.some(e => e.dekId === dekId && Number(e.tier) === 2 && authors.has(author(e.id)))
            ? 0 : 1;
    };
    let nodeId = folderId;
    while (nodeId && !visited.has(nodeId)) {
        visited.add(nodeId);
        const folderKeys = Object.values(state.syncObjects || {})
            .filter(obj => obj.object_type === 'dek' && !obj.is_deleted &&
                obj.parent_ref === nodeId && state.deks[obj.id] && !retired[obj.id] &&
                authors.has(obj.signer || obj.owner_id));
        const held = folderKeys.filter(obj => ulidTimeMs(obj.id) <= latest);
        if (!held.length && folderKeys.length) {
            // Review a159e97 H5: the folder's only key has an id from the
            // future (this computer's clock is behind, or the key was made
            // with a clock ahead). Skipping it sealed the item under the
            // parent folder's key, which members of the parent only can read.
            const err = new Error(typeof t === 'function'
                ? t('vault.folder_key_from_future')
                : "This folder's key is dated in the future; check this computer's clock");
            err.folderKeyFromFuture = true;
            throw err;
        }
        if (held.length) {
            const roles = new Map(held.map(obj => [obj.id, held.length > 1 ? role(obj.id, nodeId) : 2]));
            held.sort((a, b) =>
                roles.get(a.id) - roles.get(b.id) ||
                (nonFolderScopes.has(b.scope) ? 1 : 0) - (nonFolderScopes.has(a.scope) ? 1 : 0) ||
                (a.id < b.id ? -1 : (a.id > b.id ? 1 : 0)));
            return held[held.length - 1].id;  // the folder's key, newest
        }
        nodeId = state.nodes[nodeId]?.parent_ref;
    }
    return null;
}

/**
 * DEK for (re-)encrypting an object under `parentRef`. Personal subtrees use
 * their private DEK. An existing object that stays in its folder keeps the DEK
 * named in its ciphertext header; anything else uses the nearest folder DEK
 * (also one shared with us through an envelope), else the root DEK. A tier-2
 * item moved elsewhere keeps its own key, as on the desktop (review 7c10379
 * H3: sealed under the new folder's key, its tier 2 took that key out).
 */
function resolveWriteDekId(parentRef, existing = null) {
    const personalDekId = resolveInheritedPersonalDekId(parentRef);
    if (personalDekId) return personalDekId;
    const team = state.teamLog?.team || null;
    if (team && webTeamFolderAbove(state.syncObjects, team, parentRef)) return nearestFolderDekId(parentRef);
    // Review a159e97 (web, medium): a server replaying an item's version from
    // before a re-key named the key the re-key retired, and the edit sealed
    // the item under it again - readable by the member the re-key removed.
    // A retired key is followed to its proven successor (one this browser
    // holds: provenDekSuccessors maps to no other).
    let dekId = existing?.dekId || null;
    if (dekId) dekId = finalDekSuccessor(dekId) || dekId;
    if (existing && (existing.parent_ref || null) === (parentRef || null) &&
            dekId && state.deks[dekId]) {
        return dekId;
    }
    if (existing && Number(existing.tier) === 2 && dekId && state.deks[dekId] &&
            state.syncObjects?.[dekId]?.parent_ref &&
            nearestFolderDekId(existing.parent_ref) !== dekId) {
        return dekId;
    }
    return nearestFolderDekId(parentRef) || state.rootDekId;
}

// ── Modal save handler ──

async function handleModalSave(e) {
    e.preventDefault();
    const mode = document.getElementById('modal-mode').value;
    const errorEl = document.getElementById('modal-error');
    const saveBtn = document.getElementById('modal-save-btn');
    errorEl.classList.add('hidden');

    const entryId = document.getElementById('modal-entry-id').value;
    const name = document.getElementById('modal-name').value.trim();
    const parentRef = document.getElementById('modal-parent').value || null;

    if (!name) {
        errorEl.textContent = t('entry.name_required');
        errorEl.classList.remove('hidden');
        return;
    }

    saveBtn.disabled = true;
    saveBtn.textContent = t('common.saving');

    try {
        if (mode === 'personal') {
            // Create personal folder with its own DEK
            await createPersonalFolder(name);
        } else if (mode === 'folder') {
            // Save folder
            const id = entryId || generateULID();
            const existingNode = entryId ? state.nodes[entryId] : null;
            const version = existingNode ? (existingNode.version || 1) + 1 : 1;
            const isPersonalRoot = !!(existingNode && existingNode.personal);
            const folderDekId = isPersonalRoot
                ? existingNode.dekId
                : resolveWriteDekId(parentRef, existingNode);
            const currentDekId = existingNode ? (existingNode.dekId || state.rootDekId) : null;
            const destinationDekId = folderDekId || state.rootDekId;
            if (existingNode && currentDekId !== destinationDekId) {
                throw new Error(t('entry.cross_scope_move'));
            }

            await pushVaultObject({
                id: id,
                object_type: 'node',
                payloadData: isPersonalRoot ? { name: name, personal: true } : { name: name },
                parent_ref: parentRef,
                version: version,
                dekId: folderDekId,
            });
        } else {
            // Save entry
            const tags = document.getElementById('modal-tags').value
                .split(',')
                .map(t => t.trim())
                .filter(t => t.length > 0);

            const fields = [];
            document.querySelectorAll('#modal-fields-list .modal-field-row').forEach(row => {
                const key = row.querySelector('.field-key-input').value.trim();
                const value = row.querySelector('.field-value-input').value;
                const sensitive = row.querySelector('.field-sensitive-input').checked;
                if (key) {
                    fields.push({ key, value, sensitive });
                }
            });

            const id = entryId || generateULID();
            const existingEntry = entryId ? state.entries[entryId] : null;
            if (existingEntry && !canEditObject(existingEntry)) {
                throw new Error(t('entry.read_only_error'));
            }
            const version = existingEntry ? (existingEntry.version || 1) + 1 : 1;

            // Every descendant of a personal root inherits its private DEK;
            // otherwise the key comes from the ciphertext header / folder DEK.
            const isPersonal = !!resolveInheritedPersonalDekId(parentRef);
            const entryDekId = resolveWriteDekId(parentRef, existingEntry);

            const writePolicy = !isPersonal && document.getElementById('modal-shared')?.checked
                ? 'shared'
                : 'owner_only';

            await pushVaultObject({
                id: id,
                object_type: 'entry',
                // Keep the desktop meta (tier, AI-broker settings) the form doesn't show.
                payloadData: {
                    ...(existingEntry ? storedPayload(existingEntry) : {}),
                    ...(existingEntry && existingEntry.modified_at ? { modified_at: Date.now() } : {}),
                    name, tags, fields,
                },
                parent_ref: parentRef,
                version: version,
                dekId: entryDekId,
                write_policy: writePolicy,
            });
        }

        closeEntryModal();

        // Log create/edit audit event
        if (mode === 'personal') {
            logFieldAccess('personal_folder_create', name);
        } else if (mode === 'folder') {
            logFieldAccess('folder_create', name);
        } else {
            logFieldAccess(entryId ? 'entry_edit' : 'entry_create', name);
        }

        await pullAndBuildTree();

        // If we edited the currently displayed entry, refresh it
        if (entryId && state.entries[entryId]) {
            renderEntry(state.entries[entryId]);
        }
    } catch (err) {
        errorEl.textContent = err.message || t('entry.save_failed');
        errorEl.classList.remove('hidden');
    } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = t('common.save');
    }
}

// ── Delete modal ──

function openDeleteModal(entry) {
    const modal = document.getElementById('delete-modal');
    const msg = document.getElementById('delete-message');
    msg.textContent = t('entry.delete_message', { name: entry.name || t('tree.entry') });
    modal.dataset.entryId = entry.id;
    modal.classList.remove('hidden');
}

function closeDeleteModal() {
    const modal = document.getElementById('delete-modal');
    modal.classList.add('hidden');
    delete modal.dataset.entryId;
}

async function handleDeleteConfirm() {
    const modal = document.getElementById('delete-modal');
    const entryId = modal.dataset.entryId;
    const confirmBtn = document.getElementById('delete-confirm-btn');

    if (!entryId) return;

    confirmBtn.disabled = true;
    confirmBtn.textContent = t('common.deleting');

    try {
        const _sodium = await ensureSodium();
        const entry = state.entries[entryId];
        if (!entry) throw new Error(t('entry.not_found'));
        if (!canEditObject(entry)) throw new Error(t('entry.read_only_error'));

        // Push as deleted — preserve the entry's inherited encryption scope.
        const version = (entry.version || 1) + 1;
        const base = webBaseNow(entryId);  // R16-M1: the copy it was made on
        const entryData = { name: entry.name, tags: entry.tags || [], fields: entry.fields || [] };
        const entryDekId = resolveWriteDekId(entry.parent_ref, entry);
        const entryDek = state.deks[entryDekId];
        if (!entryDek) throw new Error('No DEK for id: ' + entryDekId);

        // Canonical two-envelope framing (cross-client with desktop/mobile).
        let entryPayload = encryptEntryPayload(
            entryData, entryDekId, entryId, version, entryDek, _sodium
        );
        if (entryPayload.length > MAX_OBJECT_PAYLOAD_BYTES) {
            // Review d150605 S2: the tombstone of an entry over the server's
            // limit was refused too, so it could not be deleted. It keeps the
            // name and tags only (the content never reached the server).
            entryPayload = encryptEntryPayload(
                { ...entryData, fields: [] }, entryDekId, entryId, version, entryDek, _sodium
            );
        }
        const payloadB64 = bytesToBase64(entryPayload);

        const payloadHash = await sha256hexBytes(base64ToBytes(payloadB64));
        const delSig = signSyncObject(
            _sodium, entryId, 'entry', entry.parent_ref || null,
            null, 1, version, hexToBytes(payloadHash)
        );

        await pushEncryptedVaultObject({
            id: entryId,
            object_type: 'entry',
            payload: payloadB64,
            parent_ref: entry.parent_ref || null,
            version: version,
            is_deleted: 1,
            payload_hash: payloadHash,
            signature: bytesToHex(delSig),
            write_policy: entry.write_policy || 'owner_only',
            ...base,
        });

        closeDeleteModal();
        logFieldAccess('entry_delete', entry.name || '');
        state.selectedEntry = null;

        // Reset detail panel
        document.getElementById('entry-detail').classList.add('hidden');
        document.getElementById('no-selection').classList.remove('hidden');

        await pullAndBuildTree();
    } catch (err) {
        alert(t('entry.delete_failed', { error: err.message || t('common.unknown_error') }));
    } finally {
        confirmBtn.disabled = false;
        confirmBtn.textContent = t('common.delete');
    }
}

// ── Auto-lock after 15 min inactivity (spec 7.2) ──

let _inactivityTimer = null;
const INACTIVITY_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

function resetInactivityTimer() {
    if (_inactivityTimer) clearTimeout(_inactivityTimer);
    if (state.token) {
        _inactivityTimer = setTimeout(() => {
            handleLock();
            alert(t('vault.session_expired'));
        }, INACTIVITY_TIMEOUT_MS);
    }
}

// Track user activity
['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(event => {
    document.addEventListener(event, resetInactivityTimer, { passive: true });
});

// ── "Are you sure you want to leave?" dialog (spec 7.2) ──

window.addEventListener('beforeunload', (e) => {
    if (state.token && state.kek) {
        e.preventDefault();
        e.returnValue = t('vault.unlocked_leave');
        return e.returnValue;
    }
});

// ── Zeroize on tab close / visibility change (spec 7.2) ──

document.addEventListener('visibilitychange', () => {
    // When tab becomes hidden for extended period, lock vault
    if (document.visibilityState === 'hidden' && state.kek) {
        // Set a shorter timer when tab is hidden (5 minutes)
        if (_inactivityTimer) clearTimeout(_inactivityTimer);
        _inactivityTimer = setTimeout(() => {
            handleLock();
        }, 5 * 60 * 1000);
    }
});

// ── iOS Safari IndexedDB 7-day purge detection ──

function checkiOSIndexedDB() {
    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
    const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
    if (!isIOS || !isSafari) return;

    // Only warn if IndexedDB has no stored keypair (i.e., fresh or purged state).
    // Go through openDB(): a bare open at the current version would create an
    // empty v2 database without its stores and break every later login.
    openDB().then((db) => {
        const countReq = db.transaction('keys', 'readonly').objectStore('keys').count();
        countReq.onsuccess = () => {
            db.close();
            if (countReq.result === 0) _showIOSWarning();
        };
        countReq.onerror = () => {
            db.close();
            _showIOSWarning();
        };
    }).catch(() => _showIOSWarning());
}

function _showIOSWarning() {
    const banner = document.createElement('div');
    banner.className = 'ios-warning';
    banner.dataset.i18nHtml = 'ios.warning';
    banner.innerHTML = t('ios.warning');
    banner.style.cssText = 'background:#8B4513;color:#fff;padding:8px;text-align:center;font-size:12px;';
    document.body.prepend(banner);
}

// ── Audit Log — Full-page Panel ──

let _auditOffset = 0;
const _auditLimit = 50;
let _auditTotal = 0;

function openAuditPanel() {
    const panel = document.getElementById('audit-panel');
    panel.classList.remove('hidden');
    // Hide vault content
    document.querySelector('.main-content')?.style.setProperty('display', 'none');
    document.getElementById('search-results')?.classList.add('hidden');
    _auditOffset = 0;
    loadAuditEntries();
}

function closeAuditPanel() {
    document.getElementById('audit-panel').classList.add('hidden');
    // Show vault content
    document.querySelector('.main-content')?.style.setProperty('display', '');
}

function resetAuditFilters() {
    document.getElementById('audit-ip-filter').value = '';
    document.getElementById('audit-user-filter').value = '';
    document.getElementById('audit-action-filter').value = '';
    document.getElementById('audit-time-filter').value = '86400000';
    _auditOffset = 0;
    loadAuditEntries();
}

function _buildAuditQueryParams() {
    const actionFilter = document.getElementById('audit-action-filter').value;
    const timeFilter = document.getElementById('audit-time-filter').value;
    const ipFilter = document.getElementById('audit-ip-filter').value.trim();
    const userFilter = document.getElementById('audit-user-filter').value.trim();

    let params = `?limit=${_auditLimit}&offset=${_auditOffset}`;
    if (actionFilter) params += '&action=' + encodeURIComponent(actionFilter);
    if (ipFilter) params += '&ip=' + encodeURIComponent(ipFilter);
    if (userFilter) params += '&user=' + encodeURIComponent(userFilter);
    if (timeFilter) {
        const sinceMs = Date.now() - parseInt(timeFilter, 10);
        params += '&since=' + sinceMs;
    }
    return params;
}

async function loadAuditEntries() {
    const tbody = document.getElementById('audit-table-body');
    tbody.innerHTML = `<tr><td colspan="5" class="audit-empty">${escapeHtml(t('audit.loading'))}</td></tr>`;

    const queryParams = _buildAuditQueryParams();

    try {
        const data = await apiFetch('/api/audit' + queryParams);
        const entries = data.entries || [];
        _auditTotal = data.total || 0;

        if (entries.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="audit-empty">${escapeHtml(t('audit.empty'))}</td></tr>`;
            _updateAuditPagination(0);
            return;
        }

        // W4: Verify audit entry signatures
        const _sodium = state.sodium || (typeof sodium !== 'undefined' ? await sodium.ready.then(() => sodium) : null);

        tbody.innerHTML = entries.map(entry => {
            const dt = new Date(entry.timestamp);
            const timeStr = dt.getFullYear() + '-'
                + String(dt.getMonth() + 1).padStart(2, '0') + '-'
                + String(dt.getDate()).padStart(2, '0') + ' '
                + String(dt.getHours()).padStart(2, '0') + ':'
                + String(dt.getMinutes()).padStart(2, '0') + ':'
                + String(dt.getSeconds()).padStart(2, '0');

            let details = _formatAuditDetails(entry);

            // Verify the exact §4.2 canonical record, never a proxy payload.
            let sigBadge = '';
            const userPks = state.userKeys[entry.user_id];
            if (entry.client_signature && entry.request_hash && userPks && _sodium) {
                try {
                    const canonical = buildServerAuditCanonical(
                        entry.id, entry.user_id, entry.action,
                        entry.timestamp, entry.request_hash
                    );
                    const signature = hexToBytes(entry.client_signature);
                    const valid = userPks.some(userPk =>
                        _sodium.crypto_sign_verify_detached(signature, canonical, userPk)
                    );
                    sigBadge = valid
                        ? `<span title="${escapeHtml(t('audit.signature.verified'))}" class="sig-badge sig-ok">&#x2714;</span>`
                        : `<span title="${escapeHtml(t('audit.signature.invalid'))}" class="sig-badge sig-bad">&#x2718;</span>`;
                } catch {
                    sigBadge = `<span title="${escapeHtml(t('audit.signature.error'))}" class="sig-badge sig-bad">&#x2718;</span>`;
                }
            } else {
                sigBadge = `<span title="${escapeHtml(t('audit.signature.unavailable'))}" class="sig-badge sig-bad">&#x2718;</span>`;
            }

            const badgeClass = _auditBadgeClass(entry.action);
            const actionLabel = _auditActionLabel(entry.action);

            return '<tr>' +
                '<td class="audit-time">' + escapeHtml(timeStr) + '</td>' +
                '<td><span class="audit-action-badge ' + badgeClass + '">' + escapeHtml(actionLabel) + '</span>' + sigBadge + '</td>' +
                '<td class="audit-user">' + escapeHtml(entry.username || entry.user_id) + '</td>' +
                '<td class="audit-ip">' + escapeHtml(entry.client_ip || '\u2014') + '</td>' +
                '<td class="audit-details">' + (details || '\u2014') + '</td>' +
                '</tr>';
        }).join('');

        _updateAuditPagination(entries.length);

    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="audit-empty">${escapeHtml(t('audit.load_error', { error: err.message || t('common.unknown_error') }))}</td></tr>`;
    }
}

function _updateAuditPagination(currentCount) {
    const infoEl = document.getElementById('audit-pagination-info');
    const prevBtn = document.getElementById('audit-prev-btn');
    const nextBtn = document.getElementById('audit-next-btn');

    if (_auditTotal === 0) {
        infoEl.textContent = t('audit.empty');
    } else {
        const from = _auditOffset + 1;
        const to = _auditOffset + currentCount;
        infoEl.textContent = t('audit.showing', { from, to, total: _auditTotal });
    }

    prevBtn.disabled = _auditOffset <= 0;
    nextBtn.disabled = (_auditOffset + _auditLimit) >= _auditTotal;
}

function auditPrevPage() {
    _auditOffset = Math.max(0, _auditOffset - _auditLimit);
    loadAuditEntries();
}

function auditNextPage() {
    if ((_auditOffset + _auditLimit) < _auditTotal) {
        _auditOffset += _auditLimit;
        loadAuditEntries();
    }
}

function _auditBadgeClass(action) {
    const map = {
        'login': 'audit-badge-login',
        'sync_push': 'audit-badge-sync_push',
        'sync_pull': 'audit-badge-sync_pull',
        'share_create': 'audit-badge-share_create',
        'share_view': 'audit-badge-share_view',
        'field_show': 'audit-badge-field',
        'field_copy': 'audit-badge-field',
        'entry_view': 'audit-badge-entry',
        'entry_create': 'audit-badge-entry',
        'entry_edit': 'audit-badge-entry',
        'entry_delete': 'audit-badge-entry',
        'folder_create': 'audit-badge-entry',
    };
    return map[action] || 'audit-badge-default';
}

function _auditActionLabel(action) {
    const key = `audit.action.${action}`;
    const label = t(key);
    return label === key ? action : label;
}

function _formatAuditDetails(entry) {
    const action = entry.action;

    if (action === 'field_show') {
        return t('audit.detail.field_show');
    }
    if (action === 'field_copy') {
        return t('audit.detail.field_copy');
    }
    if (action === 'entry_view') {
        return t('audit.detail.entry_view');
    }
    if (action === 'entry_create') {
        return t('audit.detail.entry_create');
    }
    if (action === 'entry_edit') {
        return t('audit.detail.entry_edit');
    }
    if (action === 'entry_delete') {
        return t('audit.detail.entry_delete');
    }
    if (action === 'folder_create') {
        return t('audit.detail.folder_create');
    }
    if (action === 'login') {
        return t('audit.detail.login');
    }
    if (action === 'sync_push') {
        const seqRange = entry.commit_seq_range || '';
        return t('audit.detail.sync_push', {
            range: seqRange ? ` (seq ${escapeHtml(seqRange)})` : '',
        });
    }
    if (action === 'sync_pull') {
        return t('audit.detail.sync_pull');
    }
    if (action === 'share_create') {
        return t('audit.detail.share_create');
    }
    if (action === 'share_view') {
        return t('audit.detail.share_view');
    }

    // Fallback
    let fallback = '';
    if (entry.commit_seq_range) {
        fallback = 'seq: ' + escapeHtml(entry.commit_seq_range);
    }
    if (entry.request_hash) {
        fallback += (fallback ? ', ' : '') + 'hash: ' + escapeHtml(entry.request_hash.slice(0, 12)) + '...';
    }
    return fallback || '\u2014';
}

async function exportAuditCSV() {
    const queryParams = _buildAuditQueryParams().replace(/limit=\d+/, 'limit=10000').replace(/offset=\d+/, 'offset=0');
    try {
        const url = API_BASE + '/api/audit/csv' + queryParams;
        const resp = await fetch(url, {
            headers: { 'Authorization': 'Bearer ' + state.token },
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ detail: resp.statusText }));
            throw new Error(err.detail || 'CSV export failed');
        }
        const blob = await resp.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'sezam-audit.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
    } catch (err) {
        alert(t('audit.csv_failed', { error: err.message || t('common.unknown_error') }));
    }
}

// ── GF(256) Shamir Secret Sharing (spec 9.4) ──

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(function initGFTables() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
        GF_EXP[i] = x;
        GF_LOG[x] = i;
        // Multiply by generator (x + 1) in GF(2^8) with AES polynomial
        x = x ^ (x << 1);
        if (x & 0x100) x ^= 0x11b;
    }
    for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function gfDiv(a, b) {
    if (b === 0) throw new Error('Division by zero in GF(256)');
    if (a === 0) return 0;
    return GF_EXP[(GF_LOG[a] - GF_LOG[b] + 255) % 255];
}

function shamirSplit(secret, threshold, numShares) {
    // secret: Uint8Array, returns: [[index, Uint8Array], ...]
    // Refusals as the desktop's split_secret (tests/vectors/shamir.json).
    if (!Number.isInteger(threshold) || threshold < 2) throw new Error('Threshold must be at least 2');
    if (!Number.isInteger(numShares) || numShares < threshold) throw new Error('Number of shares must be >= threshold');
    if (numShares > 255) throw new Error('Maximum 255 shares');
    if (!secret || secret.length === 0) throw new Error('Secret must not be empty');
    const shareBytes = Array.from(
        { length: numShares },
        () => new Uint8Array(secret.length),
    );
    for (let b = 0; b < secret.length; b++) {
        const coeffs = [secret[b]];
        for (let c = 1; c < threshold; c++) {
            coeffs.push(crypto.getRandomValues(new Uint8Array(1))[0]);
        }
        for (let s = 1; s <= numShares; s++) {
            // Horner's method: evaluate this byte's polynomial at x=s
            let val = 0;
            for (let c = coeffs.length - 1; c >= 0; c--) {
                val = coeffs[c] ^ gfMul(val, s);
            }
            shareBytes[s - 1][b] = val;
        }
    }
    return shareBytes.map((share, index) => [index + 1, share]);
}

function shamirReconstruct(shares) {
    // shares: [[index, Uint8Array], ...]
    // Refusals as the desktop's reconstruct_secret: a short share was read
    // as zeros and gave a wrong key without an error.
    if (!Array.isArray(shares) || shares.length < 2) throw new Error('At least 2 shares required for reconstruction');
    const len = shares[0][1].length;
    for (const [idx, bytes] of shares) {
        if (bytes.length !== len) throw new Error(`Share ${idx} has length ${bytes.length}, expected ${len}`);
        if (!Number.isInteger(idx) || idx < 1 || idx > 255) throw new Error(`Share index must be 1-255, got ${idx}`);
    }
    if (new Set(shares.map(s => s[0])).size !== shares.length) throw new Error('Duplicate share indices detected');
    const result = new Uint8Array(len);
    for (let b = 0; b < len; b++) {
        let value = 0;
        for (let i = 0; i < shares.length; i++) {
            let basis = 1;
            for (let j = 0; j < shares.length; j++) {
                if (i === j) continue;
                const num = shares[j][0];
                const den = shares[j][0] ^ shares[i][0];
                basis = gfMul(basis, gfDiv(num, den));
            }
            value ^= gfMul(shares[i][1][b], basis);
        }
        result[b] = value;
    }
    return result;
}

// ── Org Recovery Setup (admin) ──

async function openShamirSetupModal() {
    if (!webIsAdmin() || !state.kek) {
        alert(t('recovery.admin_required'));
        return;
    }

    let modal = document.getElementById('shamir-setup-modal');
    if (modal) modal.remove();

    modal = document.createElement('div');
    modal.id = 'shamir-setup-modal';
    modal.className = 'modal-overlay';
    modal.innerHTML = `
        <div class="modal-panel modal-panel-small">
            <div class="modal-inner">
                <h2 class="modal-title" data-i18n="recovery.setup_title">${escapeHtml(t('recovery.setup_title'))}</h2>
                <p class="modal-message" data-i18n="recovery.setup_intro">${escapeHtml(t('recovery.setup_intro'))}</p>
                <div class="modal-input-group">
                    <label for="shamir-threshold" data-i18n="recovery.threshold">${escapeHtml(t('recovery.threshold'))}</label>
                    <input type="number" id="shamir-threshold" min="2" max="255" value="3" class="modal-input">
                </div>
                <div class="modal-input-group">
                    <label for="shamir-total" data-i18n="recovery.total">${escapeHtml(t('recovery.total'))}</label>
                    <input type="number" id="shamir-total" min="2" max="255" value="5" class="modal-input">
                </div>
                <div class="modal-input-group">
                    <label for="shamir-password" data-i18n="recovery.setup_password">${escapeHtml(t('recovery.setup_password'))}</label>
                    <input type="password" id="shamir-password" autocomplete="current-password" class="modal-input">
                </div>
                <div id="shamir-setup-error" class="error hidden"></div>
                <div class="modal-buttons">
                    <button type="button" id="shamir-cancel-btn" class="modal-btn cancel" data-i18n="common.cancel">${escapeHtml(t('common.cancel'))}</button>
                    <button type="button" id="shamir-generate-btn" class="modal-btn save" data-i18n="recovery.generate">${escapeHtml(t('recovery.generate'))}</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeShamirSetupModal();
    });

    document.getElementById('shamir-cancel-btn').onclick = closeShamirSetupModal;
    document.getElementById('shamir-generate-btn').onclick = handleShamirGenerate;
}

function closeShamirSetupModal() {
    const modal = document.getElementById('shamir-setup-modal');
    if (modal) modal.remove();
}

async function handleShamirGenerate() {
    const thresholdEl = document.getElementById('shamir-threshold');
    const totalEl = document.getElementById('shamir-total');
    const errorEl = document.getElementById('shamir-setup-error');

    const threshold = parseInt(thresholdEl.value, 10);
    const total = parseInt(totalEl.value, 10);

    if (threshold < 2) {
        errorEl.textContent = t('recovery.threshold_min');
        errorEl.classList.remove('hidden');
        return;
    }
    if (total < threshold) {
        errorEl.textContent = t('recovery.total_min');
        errorEl.classList.remove('hidden');
        return;
    }
    if (total > 255) {
        errorEl.textContent = t('recovery.total_max');
        errorEl.classList.remove('hidden');
        return;
    }

    errorEl.classList.add('hidden');
    const passwordEl = document.getElementById('shamir-password');

    try {
        // Review e4cd15a #1: a new recovery key can reset the password, so
        // the server registers it only with proof of the current password.
        const currentAuthProof = await currentPasswordProof(passwordEl ? passwordEl.value : '');
        if (passwordEl) passwordEl.value = '';
        if (!currentAuthProof) {
            errorEl.textContent = t('recovery.setup_wrong_password');
            errorEl.classList.remove('hidden');
            return;
        }
        // A new setup voids every share of the current one: say so first.
        let replaceOtherAdmin = false;
        // Review c02cc47 R17-R9s: who set it up is told to a session only.
        const current = await apiFetch('/api/org-recovery/status');
        if (current && current.configured) {
            replaceOtherAdmin = current.created_by !== state.userId;
            const warning = replaceOtherAdmin ? 'recovery.replace_other_admin'
                : current.stale ? 'recovery.replace_stale' : 'recovery.replace_own';
            if (!confirm(t(warning))) return;
        }

        const _sodium = await ensureSodium();

        // 1. Generate the 32-byte recovery secret and its keys (R16-L4).
        const recoveryKey = _sodium.randombytes_buf(32);
        const recoveryKeys = await orgRecoveryKeys(recoveryKey, 2, _sodium);

        // 2. Wrap current KEK with the recovery wrap key using XChaCha20-Poly1305
        const nonce = _sodium.randombytes_buf(_sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        const ciphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            state.kek, recoveryKeys.aad, null, nonce, recoveryKeys.wrapKey
        );
        _sodium.memzero(recoveryKeys.wrapKey);

        // Build wrapped blob: nonce(24) || ciphertext(32+16)
        const wrappedBlob = new Uint8Array(nonce.length + ciphertext.length);
        wrappedBlob.set(nonce, 0);
        wrappedBlob.set(ciphertext, nonce.length);

        // 3. Derive a proof keypair and split the recovery key into shares.
        const recoverySigningKeypair = recoveryKeys.signing;
        const recoverySigningPk = recoverySigningKeypair.publicKey;
        const shares = shamirSplit(recoveryKey, threshold, total);

        // 4. Zeroize private recovery material.
        _sodium.memzero(recoverySigningKeypair.privateKey);
        _sodium.memzero(recoveryKey);

        // 5. Store wrapped blob on server
        const store = {
            wrapped_kek: bytesToHex(wrappedBlob),
            recovery_signing_pk: bytesToHex(recoverySigningPk),
            threshold: threshold,
            total_shares: total,
            replace_other_admin: replaceOtherAdmin,
            // The epoch of the KEK wrapped above, not the server's
            // (review 688edcb #3b): a stale KEK must not look current.
            key_epoch: state.keyEpoch,
            current_auth_proof: currentAuthProof,
        };
        await apiFetch('/api/org-recovery/store', { method: 'POST', body: store });
        const unanchored = await anchorWebOrgRecovery(store.recovery_signing_pk, store, _sodium);

        // 6. Show shares in a modal
        closeShamirSetupModal();
        showShamirSharesModal(shares, threshold, total);
        if (unanchored) alert(t('recovery.anchor_failed', { error: unanchored }));

    } catch (err) {
        errorEl.textContent = t('recovery.setup_failed', { error: err.message || t('common.unknown_error') });
        errorEl.classList.remove('hidden');
    }
}

function showShamirSharesModal(shares, threshold, total) {
    let modal = document.getElementById('shamir-shares-modal');
    if (modal) modal.remove();

    const shareLines = shares.map(([idx, data]) => {
        const hex = bytesToHex(data);
        const values = `{"index":${idx},"total":${total}}`;
        return `<div class="shamir-share-line"><strong data-i18n="recovery.share" data-i18n-values='${values}'>${escapeHtml(t('recovery.share', { index: idx, total }))}</strong>: <code>${idx}:${hex}</code></div>`;
    }).join('');

    modal = document.createElement('div');
    modal.id = 'shamir-shares-modal';
    modal.className = 'modal-overlay';
    modal.innerHTML = `
        <div class="modal-panel">
            <div class="modal-inner">
                <h2 class="modal-title" data-i18n="recovery.shares_title">${escapeHtml(t('recovery.shares_title'))}</h2>
                <p class="modal-message" data-i18n-html="recovery.shares_intro" data-i18n-values='{"threshold":${threshold},"total":${total}}'>
                    ${t('recovery.shares_intro', { threshold, total })}
                </p>
                <div class="shamir-shares-list">${shareLines}</div>
                <div class="modal-buttons">
                    <button type="button" id="shamir-print-btn" class="modal-btn save" data-i18n="recovery.print">${escapeHtml(t('recovery.print'))}</button>
                    <button type="button" id="shamir-shares-close-btn" class="modal-btn cancel" data-i18n="common.close">${escapeHtml(t('common.close'))}</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    document.getElementById('shamir-print-btn').onclick = () => {
        const printWin = window.open('', '_blank');
        printWin.document.write(`<html lang="${currentLanguage}"><head><title>${escapeHtml(t('recovery.print_title'))}</title>
            </head><body><h1>${escapeHtml(t('recovery.print_heading', { threshold, total }))}</h1>`);
        shares.forEach(([idx, data]) => {
            printWin.document.write(`<div class="share"><strong>${escapeHtml(t('recovery.share', { index: idx, total }))}:</strong> ${idx}:${bytesToHex(data)}</div>`);
        });
        printWin.document.write(`<p class="created">${escapeHtml(t('recovery.created', { date: new Date().toLocaleString(currentLanguage) }))}</p></body></html>`);
        printWin.document.close();
        // The print window inherits the page CSP (no inline styles): use CSSOM.
        const printDoc = printWin.document;
        printDoc.body.style.cssText = 'font-family:monospace;padding:2rem';
        printDoc.querySelector('h1').style.fontSize = '18px';
        printDoc.querySelectorAll('.share').forEach(el => { el.style.cssText = 'margin:0.5rem 0;font-size:14px'; });
        printDoc.querySelector('.created').style.cssText = 'margin-top:2rem;color:#666';
        printWin.print();
    };

    document.getElementById('shamir-shares-close-btn').onclick = () => {
        modal.remove();
    };

    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.remove();
    });
}

// ── Org Recovery (reconstruct from shares) ──

async function openOrgRecoveryModal() {
    // Check if org recovery is configured
    let statusResp;
    try {
        statusResp = await fetch(API_BASE + '/api/org-recovery/status');
        statusResp = await statusResp.json();
    } catch {
        alert(t('recovery.server_unavailable'));
        return;
    }

    if (!statusResp.configured) {
        alert(t('recovery.not_configured'));
        return;
    }
    if (statusResp.stale) {
        alert(t('recovery.stale'));
        return;
    }

    const threshold = statusResp.threshold || 3;

    let modal = document.getElementById('org-recovery-modal');
    if (modal) modal.remove();

    let shareInputs = '';
    for (let i = 0; i < threshold; i++) {
        shareInputs += `
            <div class="modal-input-group">
                <label for="recovery-share-${i}" data-i18n="recovery.share_label" data-i18n-values='{"index":${i + 1}}'>${escapeHtml(t('recovery.share_label', { index: i + 1 }))}</label>
                <input type="text" id="recovery-share-${i}" placeholder="${escapeHtml(t('recovery.share_placeholder'))}" data-i18n-placeholder="recovery.share_placeholder" class="modal-input" autocomplete="off">
            </div>`;
    }

    modal = document.createElement('div');
    modal.id = 'org-recovery-modal';
    modal.className = 'modal-overlay';
    modal.innerHTML = `
        <div class="modal-panel">
            <div class="modal-inner">
                <h2 class="modal-title" data-i18n="recovery.title">${escapeHtml(t('recovery.title'))}</h2>
                <p class="modal-message" data-i18n="recovery.enter_shares" data-i18n-values='{"threshold":${threshold}}'>${escapeHtml(t('recovery.enter_shares', { threshold }))}</p>
                ${shareInputs}
                <div class="modal-input-group">
                    <label for="recovery-new-password" data-i18n="recovery.new_password">${escapeHtml(t('recovery.new_password'))}</label>
                    <input type="password" id="recovery-new-password" placeholder="${escapeHtml(t('password.new_placeholder'))}" data-i18n-placeholder="password.new_placeholder" class="modal-input" minlength="14" autocomplete="new-password">
                    <p class="password-requirements" data-i18n="password.requirements">${escapeHtml(t('password.requirements'))}</p>
                </div>
                <div class="modal-input-group">
                    <label for="recovery-confirm-password" data-i18n="password.confirm_label">${escapeHtml(t('password.confirm_label'))}</label>
                    <input type="password" id="recovery-confirm-password" placeholder="${escapeHtml(t('password.confirm_placeholder'))}" data-i18n-placeholder="password.confirm_placeholder" class="modal-input" minlength="14" autocomplete="new-password">
                </div>
                <div id="org-recovery-error" class="error hidden"></div>
                <div id="org-recovery-spinner" class="spinner hidden" data-i18n="recovery.progress">${escapeHtml(t('recovery.progress'))}</div>
                <div class="modal-buttons">
                    <button type="button" id="org-recovery-cancel-btn" class="modal-btn cancel" data-i18n="common.cancel">${escapeHtml(t('common.cancel'))}</button>
                    <button type="button" id="org-recovery-submit-btn" class="modal-btn save" data-i18n="recovery.submit">${escapeHtml(t('recovery.submit'))}</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeOrgRecoveryModal();
    });

    document.getElementById('org-recovery-cancel-btn').onclick = closeOrgRecoveryModal;
    document.getElementById('org-recovery-submit-btn').onclick = () =>
        handleOrgRecovery(threshold, statusResp.total_shares || threshold);
}

function closeOrgRecoveryModal() {
    const modal = document.getElementById('org-recovery-modal');
    if (modal) modal.remove();
}

/**
 * Ids of this account's active DEK objects, all of which our KEK opened, or
 * null when one of them did not unwrap (re-keying the rest would strand it
 * under the old KEK). An object without signer or owner_id counts as ours.
 */
function ownKekDekIdsToRewrap(syncObjects, kekDekIds, userId) {
    // Review d615826: state.syncObjects did not keep owner_id, so every
    // colleague's DEK counted as ours and recovery failed in every
    // organization with more than one user (see syncObjectRecord).
    // Review 7c10379: owner_id is the server's word. A server naming a
    // colleague owner of one of our DEKs left it out of the rewrap, and it
    // stayed under the KEK the recovery replaced. Ours is what our KEK opens
    // or what we signed (the verified signer).
    const opened = new Set(kekDekIds || []);
    const own = Object.values(syncObjects || {}).filter(obj =>
        obj.object_type === 'dek' && !obj.is_deleted &&
        (opened.has(obj.id) || (obj.signer || obj.owner_id || userId) === userId)
    ).map(obj => obj.id);
    if (own.length === 0 || own.some(id => !opened.has(id))) return null;
    return own;
}

// Every active DEK of this account wrapped under `kek` at the next version:
// the atomic batch of a key epoch advance.
// `allowNone`: an account that holds no DEK of its own (a member reading only
// shared folders) rewraps nothing.
async function rewrapOwnDeks(kek, _sodium, allowNone = false) {
    const ownDekIds = ownKekDekIdsToRewrap(state.syncObjects, state.kekDekIds, state.userId);
    if (ownDekIds === null) {
        const opened = new Set(state.kekDekIds || []);
        const hasOwn = Object.values(state.syncObjects || {}).some(obj =>
            obj.object_type === 'dek' && !obj.is_deleted &&
            (opened.has(obj.id) || (obj.signer || obj.owner_id || state.userId) === state.userId));
        if (allowNone && !hasOwn) return [];
        throw new Error(t('recovery.unlock_all_deks_failed'));
    }
    const rewrappedDeks = [];
    for (const dekId of ownDekIds) {
        const current = state.syncObjects[dekId];
        const dekBytes = state.deks[dekId];
        if (!dekBytes) {
            throw new Error(t('recovery.missing_dek', { id: dekId }));
        }
        const version = Number(current.version) + 1;
        const wrappedDek = wrapDEK(dekBytes, dekId, version, kek, _sodium);
        const payloadHash = await sha256hexBytes(wrappedDek);
        const signature = signSyncObject(
            _sodium, dekId, 'dek', current.parent_ref || null,
            current.target_user_id || null, 0, version, hexToBytes(payloadHash)
        );
        rewrappedDeks.push({
            id: dekId,
            object_type: 'dek',
            payload: bytesToBase64(wrappedDek),
            parent_ref: current.parent_ref || null,
            target_user_id: current.target_user_id || null,
            version,
            is_deleted: 0,
            payload_hash: payloadHash,
            signature: bytesToHex(signature),
        });
    }
    if (rewrappedDeks.length === 0) {
        throw new Error(t('recovery.no_active_dek'));
    }
    return rewrappedDeks;
}

async function handleOrgRecovery(threshold, totalShares) {
    const errorEl = document.getElementById('org-recovery-error');
    const spinnerEl = document.getElementById('org-recovery-spinner');
    errorEl.classList.add('hidden');

    // Parse share inputs
    const shares = [];
    for (let i = 0; i < threshold; i++) {
        const input = document.getElementById(`recovery-share-${i}`);
        const val = (input.value || '').trim();
        if (!val) {
            errorEl.textContent = t('recovery.share_empty', { index: i + 1 });
            errorEl.classList.remove('hidden');
            return;
        }
        const colonIdx = val.indexOf(':');
        if (colonIdx < 1) {
            errorEl.textContent = t('recovery.share_format', { index: i + 1 });
            errorEl.classList.remove('hidden');
            return;
        }
        const idx = parseInt(val.slice(0, colonIdx), 10);
        const hex = val.slice(colonIdx + 1);
        if (isNaN(idx) || idx < 1 || idx > 255) {
            errorEl.textContent = t('recovery.share_index', { index: i + 1 });
            errorEl.classList.remove('hidden');
            return;
        }
        try {
            shares.push([idx, hexToBytes(hex)]);
        } catch {
            errorEl.textContent = t('recovery.share_hex', { index: i + 1 });
            errorEl.classList.remove('hidden');
            return;
        }
    }

    // Check for duplicate indices
    const indices = shares.map(s => s[0]);
    if (new Set(indices).size !== indices.length) {
        errorEl.textContent = t('recovery.share_duplicate');
        errorEl.classList.remove('hidden');
        return;
    }

    // Validate passwords
    const newPassword = document.getElementById('recovery-new-password').value;
    const confirmPassword = document.getElementById('recovery-confirm-password').value;
    if (!meetsNewPasswordPolicy(newPassword)) {
        errorEl.textContent = t('error.password_policy');
        errorEl.classList.remove('hidden');
        return;
    }
    if (newPassword !== confirmPassword) {
        errorEl.textContent = t('error.password_mismatch');
        errorEl.classList.remove('hidden');
        return;
    }

    spinnerEl.classList.remove('hidden');
    document.getElementById('org-recovery-submit-btn').disabled = true;

    try {
        const _sodium = await ensureSodium();

        // 1. Reconstruct recovery key and its deterministic proof keypair.
        const recoveryKey = shamirReconstruct(shares);

        // 2. Fetch the wrapped KEK blob of this recovery key from the server
        // (stored, or from the team log after a restore: capability run 316).
        const { recoveryKeys, blobResp } = await fetchOrgRecoveryBlob(recoveryKey, _sodium);
        if (!blobResp.ok) throw new Error(t('recovery.blob_load_failed'));
        const recoverySigningKeypair = recoveryKeys.signing;
        const blobData = await blobResp.json();
        // The owner's KEK changed after setup: the shares would only recover a
        // KEK that opens nothing (lockout review #3).
        if (blobData.stale) throw new Error(t('recovery.stale'));
        const wrappedBlob = hexToBytes(blobData.wrapped_kek);

        // 3. Unwrap KEK: extract nonce(24) || ciphertext
        if (wrappedBlob.length < 25) throw new Error(t('recovery.blob_invalid'));
        const nonce = wrappedBlob.slice(0, 24);
        const ciphertext = wrappedBlob.slice(24);
        const aad = recoveryKeys.aad;

        let recoveredKek;
        try {
            recoveredKek = new Uint8Array(
                _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, recoveryKeys.wrapKey)
            );
        } catch {
            throw new Error(t('recovery.decrypt_failed'));
        }

        // 4. Sign a fresh server challenge. This proves possession of the
        // reconstructed recovery key without sending that key to the server.
        const recoveryChallenge = await apiFetch('/api/org-recovery/challenge', {
            method: 'POST',
            body: {},
            noAuth: true,
        });
        const proofSignature = signAuthChallenge(
            recoveryChallenge.challenge, recoverySigningKeypair.privateKey, _sodium
        );
        const keypairResp = await apiFetch('/api/org-recovery/keypair', {
            method: 'POST',
            body: {
                challenge: recoveryChallenge.challenge,
                signature: bytesToHex(proofSignature),
            },
            noAuth: true,
        });

        if (!keypairResp.encrypted_keypair) {
            throw new Error(t('recovery.keypair_missing'));
        }

        // 5. Decrypt only the canonical KEYPAIR_WRAP envelope.
        const encryptedData = hexToBytes(keypairResp.encrypted_keypair);
        const { keypairBytes, confirmedGenesis, preAnchor } = decryptLoginKeypair(
            encryptedData, recoveredKek, keypairResp.user_id, _sodium
        );
        // Capability runs 269, 273: never back to a password that opened a bundle without the anchor.
        const knownPreAnchor = mergePreAnchor(preAnchor, await loadPreAnchorHistory(keypairResp.user_id));
        // Without an anchor in the new bundle a return loses no pin (checked below).
        if (confirmedGenesis && await passwordReopensPreAnchor(newPassword, knownPreAnchor, _sodium)) {
            _sodium.memzero(keypairBytes);
            throw new Error(t('team.publish_pre_anchor_password'));
        }

        // Parse keypair: signing_sk(64) + encryption_sk(32)
        const signingSk = keypairBytes.slice(0, 64);
        const encryptionSk = keypairBytes.slice(64, 96);
        const signingPk = signingSk.slice(32, 64);

        // 6. Challenge-response auth with recovered keypair
        const challengeResp = await apiFetch('/api/auth/challenge', {
            method: 'POST',
            body: { username: keypairResp.username },
            noAuth: true,
        });
        const sig = signAuthChallenge(challengeResp.challenge, signingSk, _sodium);
        const authResp = await apiFetch('/api/auth/verify', {
            method: 'POST',
            body: {
                username: keypairResp.username,
                challenge: challengeResp.challenge,
                signature: bytesToHex(sig),
            },
            noAuth: true,
        });

        state.token = authResp.token;
        state.userId = signedInUserId(authResp, keypairResp.user_id);
        state.username = keypairResp.username;
        state.isAdmin = authResp.is_admin;
        state.keypair = { signingSk, signingPk, encryptionSk, confirmedGenesis, preAnchor };
        state.kek = recoveredKek;
        _sodium.memzero(keypairBytes);
        if (confirmedGenesis) await importAccountTeamAnchor(_sodium);

        // Recovery must first unlock every active DEK with the old KEK (§9.4).
        await pullAndBuildTree();

        // 7. Derive new KEK from new password and re-wrap all key material
        const metaResp = await fetch(API_BASE + '/api/meta');
        const meta = await metaResp.json();
        const argon2Params = normalizeKdfParams(meta.argon2_web_params);

        const newSalt = _sodium.randombytes_buf(16);
        const newDerivedKey = await deriveKEK(newPassword, newSalt, argon2Params);
        const newKek = newDerivedKey.subarray(0, 32);
        const authProof = newDerivedKey.subarray(32, 64);

        // Re-wrap every active DEK of this account with the new KEK and push one
        // atomic batch. Colleagues' DEK objects and DEKs shared with us via
        // envelopes are not under our KEK (lockout review #3: counting them made
        // recovery fail in every multi-user organization).
        const rewrappedDeks = await rewrapOwnDeks(newKek, _sodium);

        // Keep org recovery usable after the KEK rotation.
        const newRecoveryNonce = _sodium.randombytes_buf(
            _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
        );
        const newRecoveryCiphertext = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            newKek, aad, null, newRecoveryNonce, recoveryKeys.wrapKey
        );
        const newWrappedRecovery = new Uint8Array(
            newRecoveryNonce.length + newRecoveryCiphertext.length
        );
        newWrappedRecovery.set(newRecoveryNonce, 0);
        newWrappedRecovery.set(newRecoveryCiphertext, newRecoveryNonce.length);

        // Re-encrypt keypair with canonical KEYPAIR_WRAP AAD.
        const kpData = new Uint8Array(96);
        kpData.set(signingSk, 0);
        kpData.set(encryptionSk, 64);
        // Review 1141a20 H2: also publish this browser's independent pin for new devices.
        let publishedGenesis = confirmedGenesis || await loadConfirmedTeamGenesis(_sodium) || null;
        let publishedPreAnchor = knownPreAnchor;
        if (!confirmedGenesis) {
            // The recovered KEK's password state opened the bundle without the
            // anchor: recorded, published now or by this browser's later
            // publication. INV-3 (review e443cbc): with the salt + params this
            // browser saw that password open (bound to the recovered KEK by
            // its check), never the server's unsigned argon2_salt / params: a
            // wrong pair hides the forgotten password from passwordReopensPreAnchor.
            const left = await webKdfStateOf(keypairResp.user_id, recoveredKek, _sodium);
            if (left) {
                publishedPreAnchor = mergePreAnchor(knownPreAnchor, left);
                await savePreAnchorHistory(keypairResp.user_id, publishedPreAnchor);
            } else {
                // Unknown here: an anchor published now could not refuse that
                // password again. The bundle stays without it, as it came; a
                // device that knew the password publishes it with its state.
                publishedGenesis = null;
            }
            if (publishedGenesis && await passwordReopensPreAnchor(newPassword, publishedPreAnchor, _sodium)) {
                _sodium.memzero(kpData);
                throw new Error(t('team.publish_pre_anchor_password'));
            }
        }
        const newEncryptedKeypair = publishedGenesis
            ? encryptAccountKeypair(kpData, publishedGenesis, newKek, generateULID(), state.userId, _sodium,
                publishedPreAnchor)
            : encryptKeypairWrap(kpData, newKek, generateULID(), state.userId, _sodium);
        _sodium.memzero(kpData);

        // 8. Journal every server write first (ciphertext under the new KEK +
        // public data only), then apply. An interruption is finished by the
        // next login with the new password (resumeKekRotation).
        assertSyncUnitFits(rewrappedDeks);
        const rotationJournal = {
            username: keypairResp.username,
            user_id: state.userId,
            argon2_salt: bytesToHex(newSalt),
            argon2_params: argon2Params,
            encrypted_keypair: bytesToHex(newEncryptedKeypair),
            deks: rewrappedDeks,
            key_epoch: state.keyEpoch + 1,
            recovery_signing_sk: sealJournalRecoverySigningSk(
                recoverySigningKeypair.privateKey, newKek, state.userId, _sodium
            ),
            recovery_store: {
                wrapped_kek: bytesToHex(newWrappedRecovery),
                recovery_signing_pk: bytesToHex(recoverySigningKeypair.publicKey),
                threshold,
                total_shares: totalShares,
                key_epoch: state.keyEpoch + 1,
                // Review d615826: the server re-stores this recovery key's
                // blob without the password only signed by the key itself.
                recovery_signature: bytesToHex(_sodium.crypto_sign_detached(
                    orgRecoveryRewrapMessage(
                        state.userId, state.keyEpoch + 1, threshold, totalShares,
                        newWrappedRecovery
                    ),
                    recoverySigningKeypair.privateKey
                )),
            },
        };
        await saveKekRotationJournal(rotationJournal);
        try {
            await applyKekRotationJournal(
                rotationJournal, authProof, signingSk, _sodium, recoverySigningKeypair.privateKey
            );
        } finally {
            _sodium.memzero(authProof);
        }
        for (const obj of rewrappedDeks) {
            state.syncObjects[obj.id] = {
                ...state.syncObjects[obj.id],
                version: obj.version,
                payload: obj.payload,
            };
        }
        state.kek = newKek;
        state.kdf = { argon2_salt: bytesToHex(newSalt), argon2_params: argon2Params };
        if (publishedGenesis) {
            state.keypair.confirmedGenesis = publishedGenesis;
            state.keypair.preAnchor = publishedPreAnchor;
        }
        await rememberWebKdfState(_sodium);

        _sodium.memzero(recoverySigningKeypair.privateKey);
        _sodium.memzero(recoveryKeys.wrapKey);
        _sodium.memzero(recoveryKey);
        _sodium.memzero(recoveredKek);

        // Save to IndexedDB for future logins
        await saveToIndexedDB({
            encrypted_keypair: bytesToHex(newEncryptedKeypair),
            user_id: state.userId,
        });

        spinnerEl.classList.add('hidden');
        closeOrgRecoveryModal();

        // Start normal session
        startJwtRefreshTimer();
        await pullAndBuildTree();
        // Review 4acfdde R11 (low): the log's org.recovery.wrap still wrapped
        // the old KEK, so a server restored from a backup served the shares a
        // wrap of the forgotten password. The desktop logs the new one too.
        const store = rotationJournal.recovery_store;
        const unanchored = await anchorWebOrgRecovery(store.recovery_signing_pk, store, _sodium);
        await renderUserInfoWithFingerprint(keypairResp.username);
        showScreen('vault-screen');

        alert(t('recovery.success'));
        if (unanchored) alert(t('recovery.wrap_anchor_failed', { error: unanchored }));

    } catch (err) {
        spinnerEl.classList.add('hidden');
        document.getElementById('org-recovery-submit-btn').disabled = false;
        if (err instanceof KeyEpochChangedError) {
            closeOrgRecoveryModal();
            endSessionForKeyEpochChange();
            return;
        }
        errorEl.textContent = t('recovery.failed', { error: err.message || t('common.unknown_error') });
        errorEl.classList.remove('hidden');
    }
}

globalThis.SezamKeyBackup = Object.freeze({
    build: buildSezamKeyBackup,
    parse: parseSezamKeyBackup,
});
globalThis.SezamPasswordPolicy = Object.freeze({
    minLength: NEW_PASSWORD_MIN_LENGTH,
    meets: meetsNewPasswordPolicy,
});
globalThis.SezamTranslations = TRANSLATIONS;
globalThis.SezamApplyLanguage = applyLanguage;
globalThis.SezamTranslate = t;
globalThis.SezamTreePanelSplitter = Object.freeze({ init: initTreePanelSplitter });

// ── Start ──

document.addEventListener('DOMContentLoaded', () => {
    initI18n();
    initTreePanelSplitter();
    init();
    checkiOSIndexedDB();
    if (typeof BroadcastChannel === 'function') {
        new BroadcastChannel('sezam-keypair').onmessage = event => {
            ensureSodium().then(_sodium => onWebKeypairChanged(event.data, _sodium)).catch(() => {});
        };
    }
});
