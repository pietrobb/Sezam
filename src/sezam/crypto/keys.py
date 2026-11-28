"""Ed25519 (signing) + X25519 (encryption) key pair generation and management.

Two separate key pairs per user (spec 2.2):
- Ed25519: server auth (challenge-response), audit log signatures, sync integrity
- X25519: NaCl crypto_box for DEK envelopes (envelope encryption)

Fingerprint: SHA-256(signing_pk || encryption_pk)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from nacl.public import PrivateKey as X25519PrivateKey
from nacl.public import PublicKey as X25519PublicKey
from nacl.signing import SigningKey, VerifyKey

from .kdf import Argon2Params, derive_kek, password_forms


_SEZAM_KEY_MAGIC_V2 = b"SEZAMK02"
_SEZAM_KEY_HEADER = struct.Struct(">8sHIIIH")


@dataclass(repr=False)
class KeyPair:
    """Combined Ed25519 + X25519 key pair for a user."""

    signing_sk: bytearray  # Ed25519 private key (32 bytes)
    signing_pk: bytes  # Ed25519 public key (32 bytes)
    encryption_sk: bytearray  # X25519 private key (32 bytes)
    encryption_pk: bytes  # X25519 public key (32 bytes)
    confirmed_genesis: Optional[str] = None
    # Authenticated pre-anchor password states (aead.parse_pre_anchor); travel with the anchor.
    pre_anchor: bytes = b""

    def __repr__(self) -> str:
        return f"KeyPair(fingerprint={self.fingerprint[:16]}…)"

    @property
    def fingerprint(self) -> str:
        """SHA-256(signing_pk || encryption_pk) as hex string (64 chars)."""
        h = hashlib.sha256(self.signing_pk + self.encryption_pk)
        return h.hexdigest()

    @property
    def fingerprint_bytes(self) -> bytes:
        """Raw 32-byte fingerprint."""
        return hashlib.sha256(self.signing_pk + self.encryption_pk).digest()

    def fingerprint_words(self, wordlist: Optional[list[str]] = None) -> list[str]:
        """4 BIP39-style words from fingerprint (44 bits = 4 x 11 bit).

        For TOFU verification. Full verification requires hex fingerprint.
        """
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        fp = self.fingerprint_bytes
        # Take first 6 bytes (48 bits), extract 4 x 11-bit indices
        bits = int.from_bytes(fp[:6], "big")
        words = []
        for i in range(4):
            shift = (48 - 11) - i * 11  # 37, 26, 15, 4
            idx = (bits >> shift) & 0x7FF  # 11 bits = 0..2047
            words.append(wordlist[idx % len(wordlist)])
        return words

    def zeroize(self) -> None:
        """Best-effort zeroize private key material (Python GC limitation)."""
        if self.signing_sk:
            self.signing_sk[:] = b"\x00" * len(self.signing_sk)
        if self.encryption_sk:
            self.encryption_sk[:] = b"\x00" * len(self.encryption_sk)

    def to_nacl_signing_key(self) -> SigningKey:
        """Get nacl SigningKey for Ed25519 operations."""
        return SigningKey(bytes(self.signing_sk))

    def to_nacl_verify_key(self) -> VerifyKey:
        """Get nacl VerifyKey for Ed25519 verification."""
        return VerifyKey(self.signing_pk)

    def to_nacl_private_key(self) -> X25519PrivateKey:
        """Get nacl PrivateKey for X25519 operations."""
        return X25519PrivateKey(bytes(self.encryption_sk))

    def to_nacl_public_key(self) -> X25519PublicKey:
        """Get nacl PublicKey for X25519 operations."""
        return X25519PublicKey(self.encryption_pk)

    def serialize_private(self) -> bytearray:
        """Serialize private keys, retaining an authenticated account anchor if present."""
        from .aead import encode_account_keypair

        raw = bytearray(self.signing_sk + self.encryption_sk)
        if self.confirmed_genesis is None:
            return raw
        try:
            return encode_account_keypair(raw, self.confirmed_genesis, self.pre_anchor)
        finally:
            raw[:] = bytes(len(raw))

    @classmethod
    def from_private_bytes(
        cls, data: bytes, signing_pk: bytes, encryption_pk: bytes
    ) -> KeyPair:
        """Reconstruct legacy or anchored keys and verify the supplied public keys."""
        keypair = cls.from_private_only(data)
        if keypair.signing_pk != signing_pk or keypair.encryption_pk != encryption_pk:
            keypair.zeroize()
            raise ValueError("Invalid keypair public keys")
        return keypair

    @classmethod
    def from_private_only(cls, data: bytes) -> KeyPair:
        """Reconstruct from serialized private keys, deriving the public keys."""
        from .aead import decode_account_bundle

        raw, genesis, pre_anchor = decode_account_bundle(data)
        try:
            return cls(
                signing_sk=bytearray(raw[:32]),
                signing_pk=bytes(SigningKey(bytes(raw[:32])).verify_key),
                encryption_sk=bytearray(raw[32:]),
                encryption_pk=bytes(X25519PrivateKey(bytes(raw[32:])).public_key),
                confirmed_genesis=genesis,
                pre_anchor=pre_anchor,
            )
        finally:
            raw[:] = bytes(len(raw))


def _validate_sezam_key_kdf(salt: bytes, params: Argon2Params) -> None:
    """The core's .sezam-key bounds (core/src/kdf.rs)."""
    from ..vault import sync_core

    if params.salt_len != len(salt):
        raise ValueError("Invalid .sezam-key Argon2 salt length")
    refusal = sync_core.call(
        "sezam_key_kdf_refusal", salt_len=len(salt), time_cost=params.time_cost,
        memory_cost=params.memory_cost, parallelism=params.parallelism, hash_len=params.hash_len,
    )
    if refusal is not None:
        raise ValueError(refusal)


def export_sezam_key(
    keypair: KeyPair,
    kek: bytearray,
    path: str | Path,
    argon2_salt: bytes,
    argon2_params: Argon2Params,
) -> None:
    """Export a self-contained .sezam-key backup (spec 2.2, Path C)."""
    from .aead import encrypt_keypair_wrap
    from ..models import new_ulid, ulid_to_bytes

    _validate_sezam_key_kdf(argon2_salt, argon2_params)
    kek_dek_id = new_ulid()
    user_object_id = new_ulid()
    encrypted_kp = encrypt_keypair_wrap(
        keypair_data=keypair.serialize_private(),
        kek=kek,
        kek_dek_id=ulid_to_bytes(kek_dek_id),
        user_object_id=ulid_to_bytes(user_object_id),
    )

    header = _SEZAM_KEY_HEADER.pack(
        _SEZAM_KEY_MAGIC_V2,
        len(argon2_salt),
        argon2_params.time_cost,
        argon2_params.memory_cost,
        argon2_params.parallelism,
        argon2_params.hash_len,
    )
    data = (
        header
        + argon2_salt
        + keypair.signing_pk
        + keypair.encryption_pk
        + ulid_to_bytes(kek_dek_id)
        + ulid_to_bytes(user_object_id)
        + encrypted_kp
    )

    from ..securefile import private_output

    with private_output(path, "wb") as f:
        f.write(data)


def import_sezam_key(path: str | Path, password: str) -> KeyPair:
    """Decrypt a self-contained .sezam-key backup with its original KDF metadata."""
    from .aead import decrypt_keypair_wrap

    data = Path(path).read_bytes()
    if data[:8] == b"SEZAMKEY":
        raise ValueError("Legacy .sezam-key file lacks required KDF metadata")
    if len(data) < _SEZAM_KEY_HEADER.size:
        raise ValueError("Invalid .sezam-key file")

    magic, salt_len, time_cost, memory_cost, parallelism, hash_len = (
        _SEZAM_KEY_HEADER.unpack_from(data)
    )
    if magic != _SEZAM_KEY_MAGIC_V2:
        raise ValueError("Invalid .sezam-key file")

    body_offset = _SEZAM_KEY_HEADER.size + salt_len
    if len(data) <= body_offset + 116:
        raise ValueError("Truncated .sezam-key file")

    salt = data[_SEZAM_KEY_HEADER.size:body_offset]
    params = Argon2Params(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        salt_len=salt_len,
        hash_len=hash_len,
    )
    _validate_sezam_key_kdf(salt, params)

    signing_pk = data[body_offset:body_offset + 32]
    encryption_pk = data[body_offset + 32:body_offset + 64]
    user_obj_id_raw = data[body_offset + 90:body_offset + 116]
    encrypted_envelope = data[body_offset + 116:]

    # NFC first; a file exported before normalization (lockout review M8)
    # may need the password as typed or decomposed.
    forms = password_forms(password)
    for index, form in enumerate(forms):
        kek = derive_kek(form, salt, params, exact=True)
        try:
            kp_data = decrypt_keypair_wrap(
                envelope_blob=encrypted_envelope,
                kek=kek,
                user_object_id=user_obj_id_raw,
            )
            break
        except Exception:
            if index + 1 == len(forms):
                raise
        finally:
            kek[:] = b"\x00" * len(kek)

    try:
        keypair = KeyPair.from_private_bytes(bytes(kp_data), signing_pk, encryption_pk)
    finally:
        kp_data[:] = b"\x00" * len(kp_data)

    expected_signing_pk = bytes(SigningKey(bytes(keypair.signing_sk)).verify_key)
    expected_encryption_pk = bytes(X25519PrivateKey(bytes(keypair.encryption_sk)).public_key)
    if signing_pk != expected_signing_pk or encryption_pk != expected_encryption_pk:
        keypair.zeroize()
        raise ValueError("Invalid .sezam-key public keys")
    return keypair

def generate_keypair() -> KeyPair:
    """Generate fresh Ed25519 + X25519 key pairs.

    Returns a KeyPair with both signing and encryption keys.
    """
    # Ed25519 signing key pair
    signing_key = SigningKey.generate()
    signing_pk = bytes(signing_key.verify_key)
    signing_sk = bytearray(bytes(signing_key))

    # X25519 encryption key pair (separate — no cross-protocol risk)
    encryption_key = X25519PrivateKey.generate()
    encryption_pk = bytes(encryption_key.public_key)
    encryption_sk = bytearray(bytes(encryption_key))

    return KeyPair(
        signing_sk=signing_sk,
        signing_pk=signing_pk,
        encryption_sk=encryption_sk,
        encryption_pk=encryption_pk,
    )


def compute_fingerprint(signing_pk: bytes, encryption_pk: bytes) -> str:
    """Compute fingerprint from public keys: SHA-256(signing_pk || encryption_pk)."""
    return hashlib.sha256(signing_pk + encryption_pk).hexdigest()


# Slovak BIP39-style wordlist (2048 words for 11-bit indices).
# Curated for TOFU fingerprint verification — distinct, easy-to-pronounce Slovak words.
# Organized alphabetically for reproducibility. Uses base forms (nominative singular).
_DEFAULT_WORDLIST = [
    # A (0-63)
    "ábeceda", "aby", "achát", "adresa", "aerobik", "agát", "agenda", "ahoj",
    "akácia", "akcia", "aktívny", "album", "alej", "alfabet", "alkohol", "amatér",
    "ambícia", "americký", "analýza", "ananás", "anémia", "anjel", "anketa", "antika",
    "anulár", "aperitív", "aplaus", "apríl", "arašid", "architekt", "aréna", "argument",
    "aristokrat", "armáda", "aróma", "artéria", "asistent", "askéta", "aspekt", "asteroid",
    "atelier", "atika", "atletika", "atmosféra", "atóm", "audit", "august", "auto",
    "autobus", "automat", "autor", "avantgarda", "avokádo", "azalka", "azúr", "ázijský",
    "absynt", "absolvent", "adaptácia", "adresár", "afrikánsky", "akademik", "akordeon", "akrobat",
    # B (64-183)
    "bábätko", "babička", "bábka", "bacil", "bádanie", "bageta", "bahno", "bajka",
    "bakuľa", "balada", "baldachýn", "balet", "balík", "balón", "balzam", "bambus",
    "banán", "banda", "baník", "banka", "bar", "barabizňa", "baran", "barista",
    "barón", "bárka", "baroko", "barok", "barva", "básnik", "baterka", "batoh",
    "bažant", "bazén", "bažina", "bedňa", "behúň", "beloba", "benzín", "beštia",
    "betón", "bezpečný", "bieda", "bielizeň", "bikiny", "bilión", "biológia", "biskup",
    "bitúnok", "bizón", "blaho", "blanketa", "bláznovstvo", "blcha", "bledý", "blesk",
    "blíženec", "blízko", "blok", "bludár", "bobor", "bobula", "bodka", "bohatý",
    "bojovník", "bolestivý", "bonbón", "bordel", "borovica", "bosý", "botanik", "bôčik",
    "brána", "bravčovina", "brecht", "bremeno", "brest", "brezina", "brigáda", "britva",
    "brloh", "brniť", "brokát", "bronz", "broskyňa", "brucho", "brúska", "brutálny",
    "búdka", "budova", "bujný", "búrka", "burza", "busta", "butik", "bystrý",
    "bývanie", "byť", "bzučiak", "bžúchať", "balustráda", "banket", "barbakan", "baríkáda",
    "bazilika", "bedľa", "bermúdy", "besiedka", "bežec", "blúzka", "bobuľa", "bojisko",
    "botanika", "bravúra", "brečtan", "brieždenie", "bryndza", "bubon", "bučina", "bukovina",
    # C-Č (184-263)
    "cáp", "ceduľa", "cédrika", "celkový", "cement", "cena", "centimeter", "centrum",
    "cenzúra", "ceremónia", "certifikát", "cesta", "cibuľa", "cieľ", "cifra", "cigareta",
    "cimbál", "cintorín", "cipka", "cirkulár", "cirkus", "cisterna", "citadela", "citrón",
    "cnostný", "cola", "colt", "copyright", "cukor", "cukráreň", "cupitať", "cvičenie",
    "cylinder", "cyprián", "cytoplazma", "čaj", "čajka", "čalúnenie", "čapík", "čarodejník",
    "čas", "časopis", "časť", "čata", "čelenka", "čeľaď", "čelo", "čerešňa",
    "čerpadlo", "čerstvý", "červený", "česká", "česnek", "čestný", "četník", "čiapka",
    "čiara", "čierny", "čipka", "číslo", "čistý", "čítanie", "čitateľ", "čln",
    "člnok", "čmeliak", "čokoláda", "črieda", "čučoriedka", "čudný", "čudesný", "čundra",
    "čuprina", "čakanka", "čerešeň", "činnosť", "čižma", "článok", "človek", "črepina",
    # D (264-359)
    "dáma", "dámsky", "darček", "darca", "dátum", "dáva", "dávka", "dcéra",
    "debata", "december", "deficit", "definícia", "dekáda", "dekorácia", "delegát", "delfín",
    "delostrelec", "demokracia", "deň", "deravý", "derniéra", "detektív", "detective", "deti",
    "deviatka", "dezert", "diaľka", "diamant", "diár", "diela", "dieťa", "digitálny",
    "diplom", "dirigent", "disciplína", "diskusia", "divák", "divadlo", "diviak", "dlažba",
    "dlhý", "dno", "dobrota", "dobyť", "docent", "dohoda", "dojem", "doktor",
    "dokument", "dolár", "dôležitý", "dolina", "domáci", "domček", "dôraz", "dosah",
    "doskočiť", "dospelý", "dostatok", "dotyk", "dôvera", "dôvod", "dráha", "drak",
    "dráma", "drastický", "dravec", "drevo", "drina", "drobec", "drobný", "dromedár",
    "dron", "drsný", "druh", "družba", "duálny", "dub", "dúha", "dukát",
    "duša", "dužina", "dvanásť", "dvere", "dvorec", "dvojčata", "dvojica", "dynamit",
    "dynamo", "džbán", "dážď", "dávkovač", "dolinka", "dopravca", "doslov",  "dozorca",
    # E (360-415)
    "eben", "edícia", "efekt", "egypt", "echo", "ekonomika", "ekológia", "elegancia",
    "elektrina", "element", "eliminovať", "elita", "email", "emócia", "energia", "epidémia",
    "epocha", "epos", "erupcia", "esencia", "eskorta", "espresso", "estetika", "etapa",
    "etiketa", "evanjelium", "evolúcia", "excelentný", "exemplár", "exil", "existencia", "exodus",
    "expedícia", "expert", "explózia", "export", "expozícia", "extrakt", "extrém", "emblém",
    "encyklopédia", "erbový", "erózia", "eskimák", "etnický", "eurový", "exotický", "extravagantný",
    "elipsa", "emigrant", "empatia", "enkláva", "epitaf", "erekcia", "escudo", "eufória",
    # F (416-471)
    "fábrika", "fajka", "fakľa", "fakulta", "falošný", "fantázia", "fara", "farba",
    "farmár", "fazuľa", "február", "federácia", "fenomén", "festival", "figúra", "fijalka",
    "filozofia", "filtrovat", "finále", "firma", "fixný", "flakon", "flaša", "flaut",
    "florista", "flotila", "fólia", "folklór", "fond", "fontána", "formát", "formula",
    "fortel", "fosília", "fotograf", "frakcia", "francúzsky", "frekvencia", "fréza", "fronta",
    "funkcia", "futbal", "fúzia", "fialový", "fiškál", "fľaška", "fľak", "formulár",
    "fosfor", "frajer", "fúkať", "furiant", "fyzika", "falzifikát", "fazóna", "ferina",
    # G (472-519)
    "gala", "galéria", "galoš", "garancia", "garáž", "gáza", "génium", "geografia",
    "geometria", "gerilla", "gesto", "gitara", "glazúra", "globálny", "glóbus", "gnóm",
    "gobelin", "golf", "gondola", "gorila", "gotika", "grác", "grafika", "gramofón",
    "granát", "granit", "gravitácia", "gril", "groteska", "guma", "guľka", "guľatý",
    "gurman", "gymnaziálny", "gymnázium", "gaštan", "gazda", "gazdinka", "grécky", "gúľať",
    "gombík", "gágor", "generácia", "génius", "gustovať", "gardista", "galiba", "gazela",
    # H (520-599)
    "habánsky", "había", "hadica", "hádka", "hala", "halier", "haluška", "hanba",
    "harmonika", "harpa", "havária", "havran", "háčik", "hárok", "hecovať", "herec",
    "heslá", "hever", "hierarchia", "hlavný", "hľadanie", "hlboký", "hlina", "hlísť",
    "hluk", "hmatateľný", "hmla", "hmota", "hnedý", "hnevať", "hniezdny", "hniloba",
    "hodinár", "hodiny", "hodnota", "holica", "holub", "hora", "horčica", "horizont",
    "horúci", "hospoda", "hostina", "hotel", "hovoriť", "hôrka", "hrad", "hrana",
    "hranol", "hrdina", "hrebienok", "hrianka", "hriatô", "hriech", "hrob", "hromadný",
    "hrôza", "hrozno", "hrubý", "hruška", "huba", "hudba", "huncút", "húsatko",
    "húsenica", "hustý", "hutor", "hviezda", "hyacint", "hybrid", "hydrant", "hymna",
    "hypotéka", "hájnik", "hamovať", "hanobný", "háveď", "hedvábie", "hektár", "herbár",
    # I-J (600-695)
    "ibištek", "idea", "ideál", "ihla", "ihneď", "ikona", "ilegálny", "ilustrácia",
    "imelo", "impérium", "import", "indigó", "individuum", "infantný", "infarkt", "informácia",
    "inšpirácia", "inteligencia", "interiér", "internet", "interval", "intriga", "intuícia", "inventár",
    "investícia", "inžinier", "irónia", "izolácia", "izotop", "izúver", "iskra", "istota",
    "ivica", "ihrisko", "implantát", "inaugural", "indián", "induktívny", "inkvizícia", "inovácia",
    "inscenácia", "integrita", "izba", "iskriť", "jabĺčko", "jablko", "jachta", "jahoda",
    "jánsky", "jarmo", "jarný", "jaskyňa", "jasnota", "jaspis", "jašter", "javor",
    "jazda", "jazero", "jázik", "jedáleň", "jedľa", "jednoduchý", "jednorožec", "jeleň",
    "jelša", "jemný", "jeseter", "jeseň", "jeskyňa", "ježko", "jiskra", "jogging",
    "jogurt", "junák", "jupiter", "jurisdikcia", "justícia", "juta", "jadro", "jantár",
    "jarmok", "jaseň", "jazvec", "jelito", "jemnosť", "jutový", "jablkový", "jahodový",
    "január", "jarabica", "ječmeň", "jednota", "jetel", "johančík", "jódový", "jubilant",
    # K (696-855)
    "kabát", "kabela", "kabína", "kadernička", "kafeín", "kahanec", "kajak", "kakao",
    "kaktus", "kalamita", "kaleidoskop", "kalendár", "kameň", "kamera", "kamión", "kanál",
    "kandidát", "kanón", "kaňon", "kapacita", "kapitán", "kapor", "kapucňa", "karamel",
    "karavána", "karta", "kartón", "kaskáda", "kastelán", "kašeľ", "katalóg", "katastrofa",
    "katedrála", "kaviareň", "kazateľ", "kazeta", "každý", "keramika", "kilo", "kľúč",
    "kľúčový", "klobúk", "klokan", "klonkať", "klonový", "klosár", "klub", "kmeť",
    "kmeň", "kníhkupec", "kniha", "kňaz", "koberec", "kobyla", "kocka", "kočiar",
    "kocúr", "koeficient", "kohút", "kokos", "kolega", "koleso", "kolíska", "kolobežka",
    "kolónia", "kolosálny", "kombinovať", "komédia", "komín", "komora", "kompas", "komplex",
    "komunita", "konár", "koncert", "kondícia", "konferenčný", "konfitúra", "konflikt", "kontrola",
    "konverzácia", "kópia", "kopija", "koráb", "korál", "korčuľa", "korenina", "korisť",
    "koruna", "koryta", "kosatec", "kostol", "kôš", "košeľa", "kotva", "kovadlina",
    "kozmetika", "koža", "krajina", "krajčír", "králik", "kráľ", "kráska", "kravata",
    "kredit", "kresba", "kreslo", "krieda", "krivda", "krivolaký", "kríž", "krokodíl",
    "krokus", "kronika", "krošňa", "krúžok", "krv", "krývať", "kryštál", "krýzl",
    "kubík", "kuchyňa", "kukurica", "kulička", "kultúra", "kúpeľ", "kupóla", "kuriér",
    "kúsok", "kufrík", "kabriolet", "kadidlo", "kamzík", "kanister", "kapela", "kaplnka",
    "kapusta", "kaštieľ", "katedra", "kečup", "klient", "klietka", "klišé", "klobása",
    "kľukatý", "koalícia", "kolekcia", "kolobeh", "kometa", "komodita", "konopica", "konzola",
    "kopcovitý", "koridor", "koromyslo", "kotlík", "kozorožec", "kramár", "krásny", "krivka",
    # L (856-927)
    "laby", "labyrinth", "lacný", "ladička", "lagúna", "lahodný", "lajdák", "lakmus",
    "lakomec", "lampa", "lanko", "lasica", "lavica", "lávka", "lavína", "lazar",
    "lebed", "ľad", "ľadovec", "legenda", "lehota", "lekáreň", "lekcia", "lekno",
    "leopard", "lepidlo", "les", "letisko", "letmo", "lev", "ľavý", "lezec",
    "líčenie", "líder", "liečba", "lienka", "lietadlo", "ligot", "likér", "limetka",
    "limuzína", "linka", "líška", "listina", "liter", "literatura", "ľudia", "ľúbosť",
    "lucerna", "lúka", "luna", "lúpež", "luxus", "lýceum", "lyrica", "lyžiar",
    "labúť", "lahôdka", "lakeť", "lanovka", "lastúra", "láskavý", "latinka", "lazaret",
    "ľahký", "legionár", "lekár", "lenivý", "lepšie", "letiaci", "levočský", "libela",
    # M (928-1055)
    "mágia", "magnet", "mahagón", "maják", "majestát", "major", "makovica", "maliar",
    "malina", "málo", "mamut", "mango", "manica", "manžel", "mapa", "maratón",
    "marhula", "marioneta", "marmeláda", "márnosť", "martini", "maska", "maslo", "matador",
    "materiál", "matka", "matrica", "mazaný", "mdloba", "mechanik", "medaila", "medveď",
    "melodia", "melón", "meteor", "metóda", "metro", "metrový", "mičuda", "miesto",
    "milión", "minerál", "miniatúra", "minister", "minuta", "miska", "mišmaš", "mladosť",
    "mlčať", "mliečny", "mliekar", "mlyn", "modrá", "mohol", "mokrý", "molekula",
    "moment", "monarchia", "monitor", "monopol", "monsún", "montáž", "monument", "morálka",
    "more", "moriak", "mortadela", "mosaika", "moskyt", "most", "motív", "motor",
    "mozog", "mravenec", "mrholenie", "mrkva", "mrzutý", "múdrosť", "mumifikácia", "múr",
    "múzeum", "muzikál", "mýdlo", "myseľ", "myslieť", "mýtus", "mandľa", "manéver",
    "manufaktúra", "marazmus", "marinát", "matematik", "mazanec", "medailón", "medovník", "membrána",
    "menčester", "meridián", "mešťan", "metafora", "mierový", "milenec", "mincovňa", "minóza",
    "misijný", "mládenec", "mletý", "mobilný", "monokel", "morský", "motivácia", "mozaika",
    "mučeník", "mudrc", "múčnik", "muflón", "muláž", "murár", "muškát", "mušketier",
    "múzický", "mydlina", "myšlienka", "mýtnik", "mátoha", "mechúr", "mendlík", "miazga",
    # N (1056-1135)
    "náboj", "nábytoik", "nádej", "nádherný", "nádvorie", "náhoda", "náhrada", "naivný",
    "nájazd", "nálada", "nálep", "námestie", "námietka", "nápis", "nápoj", "náramok",
    "narcis", "národ", "nástroj", "nátierka", "návod", "návrat", "nebezpečný", "nečakaný",
    "nedávny", "nedeľa", "nehoda", "neitrón", "nekľud", "nelegálny", "nemocnica", "nenosový",
    "nepokojný", "neptún", "nervový", "nesúhlas", "netopier", "neuveriteľný", "nevesta", "nezávislosť",
    "nežný", "niečo", "nikdy", "nikel", "nimbus", "nitka", "noc", "nohavice",
    "nominálny", "nora", "norma", "nostalgia", "nota", "notiť", "november", "novela",
    "novina", "nový", "nádražie", "nakladač", "nákup", "nanometer", "náplasť", "nárečie",
    "nasávač", "natieračka", "náušnica", "nebeský", "nedotknutý", "nektár", "neochvejný", "neónový",
    "nestály", "neutrálny", "ničivý", "nížina", "nocľah", "nosič", "notár", "nožnice",
    # O (1136-1231)
    "oáza", "obálka", "obchod", "obdivovať", "obelisk", "obet", "obidva", "objav",
    "oblak", "obloha", "obnoviteľný", "obojstranný", "obrázok", "obrovský", "obsah", "obstáť",
    "obtiažny", "obuv", "obývačka", "oceán", "ocenenie", "ochranca", "odborník", "oddych",
    "odev", "odchod", "odišiel", "odkaz", "odmenenie", "odolnosť", "odpočinok", "odpoveď",
    "ohnisko", "ohrada", "ohrievač", "okamih", "okno", "okolo", "okraj", "okruh",
    "október", "olivový", "olovo", "olympiáda", "omáčka", "omeleta", "opera", "operácia",
    "opica", "opora", "optika", "oranžový", "orbita", "orchidea", "orden", "organizácia",
    "originál", "ornament", "ortuť", "osamotený", "osika", "osláviť", "osoba", "ostrov",
    "ostrý", "ošetrenie", "otázka", "otec", "otvor", "oválny", "ovčiar", "overenie",
    "ovládať", "ozdoba", "ozón", "oznam", "oblačný", "obloúk", "obnova", "obojok",
    "obranca", "obrusok", "obväz", "odliv", "odrazka", "odvaha", "oheň", "ohňostroj",
    "okením", "okrúhly", "oleander", "omietka", "omotávka", "opasok", "oplatka", "opevnenie",
    # P (1232-1439)
    "paberk", "palác", "paletka", "palma", "pamätník", "panáčik", "pancier", "panička",
    "panoráma", "pantomíma", "papier", "papagáj", "paradajka", "parafrázovať", "paralela", "parapet",
    "park", "parlament", "partner", "party", "pasáž", "pastier", "pastva", "patent",
    "patriarcha", "pavilón", "pavúk", "pazúrik", "pečať", "pechovať", "pekáreň", "penalta",
    "perla", "pero", "perspektíva", "pesnička", "pestrosť", "petrolej", "pevnina", "pečeň",
    "piesok", "piešťany", "piknik", "pilier", "pilot", "piránia", "pirát", "pivnica",
    "plachta", "plagát", "plameň", "planéta", "platidlo", "platina", "plavba", "plávanie",
    "plecniak", "pleť", "plnosť", "plodina", "plotovať", "plyn", "pľúca", "pobrežie",
    "počasie", "počítač", "podbradník", "podlaha", "podmienka", "podnik", "podpis", "podsvetie",
    "podvečer", "podzemie", "poézia", "pohár", "pohľad", "pohodlie", "poistka", "poklad",
    "pokojný", "pokora", "polárny", "polícia", "politika", "polnoc", "polostrov", "pomáhať",
    "pomaranč", "pomník", "poník", "ponúka", "poobede", "popol", "porcelán", "porevoluční",
    "porotca", "portfólio", "portrét", "poruba", "posledný", "postava", "postieľka", "potápač",
    "potešenie", "potrubí", "poukážka", "povinný", "povoz", "povrch", "pozadie", "pozlátka",
    "pozornosť", "požiar", "práca", "pradávny", "pramienok", "pravidlo", "pravda", "predmet",
    "predslov", "prehliadka", "prekážka", "prelet", "premiéra", "prepych", "presnosť", "preto",
    "prevládať", "prezident", "príbeh", "príchuť", "priestor", "prihrádka", "primabalka", "princezná",
    "prizvuk", "problém", "proces", "produkcia", "profesor", "profil", "program", "projekt",
    "prorok", "prsteň", "prvok", "psík", "púčik", "pudding", "puma", "purpur",
    "púšťa", "pyramída", "pahorok", "pancúch", "papraď", "páračka", "parkovisko", "párny",
    "paródia", "pasienok", "patrola", "pätička", "pečiatka", "peknota", "peňažný", "pepermint",
    "pergamen", "permeť", "pestovať", "petúnia", "pichľavý", "pivónia", "pláštenka", "platan",
    "plazivý", "plesnivý", "pletivo", "plúžik", "podhorie", "podkova", "podstata", "pohárik",
    "pohonka", "pokladňa", "pokrývka", "poliankou", "poludnie", "pomôcka", "popruh", "poradca",
    "postroj", "potrava", "povesť", "poviedka", "povolanie", "prameň", "praslica", "prátelia",
    "predpoveď", "premostenie", "presvedčenie", "priečinok", "priemysel", "príroda",
    # R (1440-1535)
    "rádio", "radosť", "radnica", "raffia", "rámček", "rapkáč", "rapsódia", "rast",
    "ratolesť", "razba", "recepcia", "recept", "redaktor", "referát", "reflexia", "reforma",
    "región", "register", "rehoľný", "rekonštrukcia", "rekord", "remeslo", "renesancia", "reportáž",
    "republika", "reťaz", "revízia", "rezerva", "ribezľa", "rifle", "rigorózny", "rímsky",
    "risoto", "rituál", "riverbend", "roba", "robot", "rodina", "rokoko", "roleta",
    "román", "rovnováha", "rozbor", "rozdiel", "rozhodnutie", "rozhovor", "rozhľadňa", "rozkvitať",
    "rozsah", "rúčka", "rúfus", "rúško", "rybár", "rýchlosť", "rytier", "rytmus",
    "rypák", "rýžový", "raňajky", "rásť", "ražný", "recinovať", "remienok", "remeselník",
    "repúblik", "rezať", "riasa", "ríbezľa", "riedky", "rímsa", "ročník", "rodinný",
    "rokovanie", "rondel", "rosička", "rovníkový", "rozeta", "rozmýšľať", "rozpočet", "ručička",
    "rudý", "rukoväť", "rumunský", "ružový", "rybnička", "rýľ", "rýpadlo", "rýžovisko",
    "raketoplán", "rapsód", "razidlo", "remíza", "rezbarstvo", "ríša", "robotník", "rolník",
    # S (1536-1663)
    "sabotáž", "sadovník", "safari", "sakura", "salám", "saláma", "salón", "samota",
    "sandál", "satén", "satelit", "saudský", "saxofón", "sčítanie", "sedliak", "sekera",
    "sekvoja", "selekcia", "semafor", "semester", "semienkok", "senátor", "seno", "september",
    "serenáda", "serif", "servírovať", "silometer", "silueta", "sinusoida", "síra", "situácia",
    "skala", "skelét", "skeptik", "skica", "skrinka", "skrutka", "skupina", "sled",
    "slimák", "sloboda", "slnečnica", "slnko", "slogan", "slon", "slúchadlo", "služba",
    "smaragd", "smetana", "smiech", "sneh", "sniežik", "socha", "sofistikovaný", "sokel",
    "sokol", "soľ", "spektrum", "spev", "splnomocnenie", "spolok", "spomienka", "sporiteľňa",
    "spotrebiteľ", "správa", "sprievod", "stabilita", "stanica", "stáž", "stedlosť", "stena",
    "stĺp", "stoličia", "stopka", "strana", "stratégia", "streda", "strelec", "strieborný",
    "strom", "strúhanka", "struna", "stúdium", "stupienok", "sultanát", "suma", "supermarket",
    "surovina", "sused", "sústava", "svadba", "svätý", "svedomie", "svetlo", "svietnik",
    "sviňa", "symbol", "symfónia", "systém", "sáčok", "samopal", "samovar", "sanitka",
    "sánky", "sardinka", "sedačka", "sediment", "seizmický", "seminár", "senník", "séria",
    "sieťoviny", "signál", "silný", "sínusový", "skalisko", "sklenár", "skleník", "skok",
    "slabika", "slanina", "slavík", "slepý", "slivka", "slotina", "smútok", "snežienka",
    # Š (1664-1727)
    "šáfran", "šarkan", "šarlát", "šatka", "šedivý", "šestnásť", "šikovný", "škála",
    "škapuliare", "škriatok", "šľachta", "šmýkačka", "šnúrka", "šošovka", "špageta", "špeciálny",
    "šperkovnica", "špiónsky", "šprint", "šťastie", "štedrý", "štiepenie", "štrukturálny", "štvornásobný",
    "štvrtok", "štýl", "šťuka", "šuster", "švorc", "šablóna", "šachista", "šalát",
    "šampión", "šatník", "šatňa", "šelest", "šelma", "šetrný", "šifrovať", "šindel",
    "škaredý", "škorec", "škôlka", "škrabka", "škrupina", "škvrna", "šľapka", "šnečí",
    "šoférovať", "šortky", "špachtľa", "špaček", "špenát", "šplhať", "špongia", "šrubovák",
    "šťavnatý", "štefánia", "štíhly", "štipka", "štolovať", "študent", "štvavý", "šúľok",
    # T (1728-1839)
    "tabletka", "tábor", "tajomstvo", "talent", "tanier", "tapeta", "tatranský", "tečka",
    "tehla", "technológia", "tekutina", "telefón", "televízia", "telo", "temnota", "tendencia",
    "teplo", "tera", "teraz", "terén", "termín", "tesár", "ticho", "tieň",
    "tiger", "tísíc", "tlačiareň", "topánka", "tradícia", "tramvaj", "triangel", "tribúna",
    "tričko", "triedny", "triumf", "trochu", "trofej", "trón", "trubka", "truhla",
    "tržnica", "tulipán", "tunel", "turbína", "turista", "tvárosť", "tvrdosť", "tvorba",
    "tyrkys", "tabuľka", "tajga", "tankista", "tapiséria", "taxikár", "téglik", "tekvica",
    "teliatko", "telocvičňa", "tenista", "tepelný", "terakota", "terasa", "termálny", "testovacie",
    "textil", "tinktúra", "tiskový", "tkáč", "tlaková", "tmelenie", "toaleta", "tokajský",
    "toliar", "tombolový", "topásový", "topolčiansky", "tornádo", "torpédo", "torzový", "tovar",
    "tragédia", "tranzit", "travertín", "trebárs", "trénovaný", "tresť", "tribút", "tridsať",
    "trnka", "trpezlivý", "trúba", "trucovať", "trvalý", "tuniak", "tutovka", "tvárlivý",
    "tvorca", "tvaroh", "tŕň", "tŕstie", "táboriť", "ťahák", "ťažký", "ťava",
    "ťažisko", "ťažoba", "ťapkať", "ťažný", "typický", "tyčinka", "týždenník", "tvorivý",
    # U-Ú (1840-1919)
    "účet", "učiteľ", "údolie", "uhoľ", "uhorka", "uhradiť", "ulica", "ultimátum",
    "umenie", "umývadlo", "uniforma", "únos", "úplatok", "upozornenie", "úprava", "uragán",
    "urbánny", "usmiať", "ústav", "útok", "utópia", "udržať", "uhlík", "ujec",
    "ukazovateľ", "ukľudniť", "ukončenie", "ulovček", "umiestnenie", "unikát", "univerzita", "úpätie",
    "uplynúť", "uprednostniť", "urobený", "úrodný", "úschovňa", "usilovný", "usporiadať", "ustálený",
    "útecha", "utierka", "útočisko", "utorkový", "útulný", "úzadina", "úžasný", "uzlový",
    "účasť", "účinný", "učebnica", "udatný", "úder", "uhasínať", "uhlopriečka", "ujsť",
    "úkos", "úľava", "úloha", "umáčka", "umenšiť", "úmorný", "umožniť", "únava",
    "undulát", "únik", "upevniť", "úprimný", "uraziť", "úrodina", "urýchliť", "uskutočniť",
    "úsmev", "usvedčiť", "útesy", "využiť", "uzáver", "užitočný", "úžitok", "učenec",
    # V (1920-2007)
    "vábivý", "vačok", "vaďba", "vahadlo", "vajíčko", "valašský", "valčík", "vaľkový",
    "vanilka", "variť", "varovný", "vášeň", "vazba", "včela", "včerajší", "vedec",
    "vedľajší", "vedúci", "veličina", "veliteľ", "velvyslanec", "ventil", "verejný", "vernosť",
    "verzia", "veselý", "veslo", "vesna", "vesmír", "vestica", "veterán", "vetrom",
    "veverička", "vianočný", "víchor", "vietor", "viečko", "viera", "vihola", "vikár",
    "vínny", "vinohrad", "virtuálny", "víťaz", "vitráž", "vízum", "vkladný", "vlajka",
    "vlákno", "vlastník", "vlčiak", "vlhkosť", "vlna", "vnútorný", "vodopád", "vodovod",
    "vojenský", "vojna", "vojsko", "voľba", "voľný", "vonkajší", "vôňa", "vopred",
    "vosk", "vozidlo", "vrabec", "vráskavý", "vrátnik", "vrba", "vrchol", "vreckový",
    "vrkoč", "vrstevník", "vrtuľník", "vstupný", "výber", "výborný", "vybúrený", "vydarený",
    "vydavateľ", "výhľad", "výhodný", "výklenok", "vykonať", "výlet", "výmenný", "výnimočný",
    # W-X-Y-Z (2008-2047)
    "záber", "začiatok", "záclona", "záhada", "záhon", "záchranár", "zájem", "základ",
    "záliv", "zámka", "zamestnanec", "zápach", "západ", "zápalka", "závada", "závej",
    "závod", "závora", "závrat", "zbierka", "zdanlivo", "zdravie", "zelený", "zemepisný",
    "zemiak", "zemplín", "zenit", "zhotoviteľ", "zima", "zimovať", "zinok", "zjazd",
    "zlatý", "zľava", "zmena", "zmysel", "značka", "znalec", "znovuzrodenie", "zobák",
    "zrkadlo", "žiariť",
]
