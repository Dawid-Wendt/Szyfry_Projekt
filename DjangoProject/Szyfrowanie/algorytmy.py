# ----------------- Importy i rejestracja algorytmów -----------------

from Crypto.Cipher import AES  # Biblioteka do szyfrowania symetrycznego (AES)
from Crypto.PublicKey import RSA  # Biblioteka do generowania kluczy RSA
from Crypto.Cipher import PKCS1_OAEP  # RSA z paddingiem OAEP (bezpieczniejszy niż surowy RSA)
import base64  # Do konwersji danych binarnych na tekst i odwrotnie
from hashlib import sha256  # Hashowanie danych do 256-bitów (np. z hasła)
import random  # Losowość np. dla RSA
import secrets  # Bezpieczne generowanie losowych wartości (kryptograficzne)
import numpy as np  # Obsługa macierzy i operacji matematycznych (dla McEliece)
from sympy import Matrix

# Dwa słowniki przechowujące zarejestrowane algorytmy
# Klucze to nazwy algorytmów (np. "AES", "RSA"), a wartości to funkcje
SZYFRY = {}      # SZYFRY["AES"] = <funkcja szyfrująca>, używane później do wyboru algorytmu
DE_SZYFRY = {}   # DE_SZYFRY["AES"] = <funkcja deszyfrująca>

# Dekorator rejestrujący funkcję szyfrującą
# Umożliwia dodanie funkcji do słownika pod wybraną nazwą (np. "AES", "RSA")
# Dzięki temu można potem wywoływać funkcje dynamicznie po nazwie algorytmu
# np. SZYFRY["AES"]("tekst", "haslo") wywoła odpowiednią funkcję szyfrującą

def rejestruj_szyfr(nazwa):
    def wrapper(funkcja):
        SZYFRY[nazwa] = funkcja  # Rejestracja funkcji szyfrującej pod wskazaną nazwą
        return funkcja  # Zwrócenie tej samej funkcji bez zmian
    return wrapper  # Zwraca wewnętrzną funkcję "wrapper", która dokona rejestracji

# Analogiczny dekorator do rejestrowania funkcji deszyfrujących
# Pozwala zarejestrować funkcję deszyfrującą pod nazwą algorytmu
# Dzięki temu DE_SZYFRY["RSA"]("tekst", "klucz") odwoła się do odpowiedniej funkcji

def rejestruj_de_szyfr(nazwa):
    def wrapper(funkcja):
        DE_SZYFRY[nazwa] = funkcja  # Rejestracja funkcji deszyfrującej
        return funkcja  # Zwrócenie jej bez zmian
    return wrapper  # Zwraca funkcję, która wykonuje rejestrację

# ----------------- AES -----------------

def aes_key(haslo):
    # Funkcja pomocnicza – generuje 128-bitowy klucz AES z hasła
    # SHA256 daje 256 bitów, ale bierzemy tylko pierwsze 128 (16 bajtów)
    return sha256(haslo.encode()).digest()[:16]

@rejestruj_szyfr("AES")
def szyfr_aes(tekst, haslo):
    try:
        klucz = aes_key(haslo)  # Generujemy klucz na podstawie hasła
        cipher = AES.new(klucz, AES.MODE_EAX)  # Tworzymy szyfr w trybie EAX (zapewnia poufność i integralność)

        # Szyfrujemy tekst, jednocześnie tworząc tag do weryfikacji poprawności
        ciphertext, tag = cipher.encrypt_and_digest(tekst.encode("utf-8"))

        # Łączymy nonce + tag + ciphertext – wszystko co potrzeba do deszyfrowania
        wynik = cipher.nonce + tag + ciphertext

        # Zwracamy tekst zaszyfrowany (base64) i klucz (również w base64)
        return base64.b64encode(wynik).decode(), base64.b64encode(klucz).decode()
    except:
        return None, None

@rejestruj_de_szyfr("AES")
def deszyfr_aes(tekst, klucz_b64):
    try:
        klucz = base64.b64decode(klucz_b64)  # Odtwarzamy klucz AES
        d = base64.b64decode(tekst)  # Odtwarzamy cały blok danych: nonce + tag + ciphertext

        # Oddzielamy nonce, tag i ciphertext (pierwsze 16, potem 16, reszta)
        nonce, tag, c = d[:16], d[16:32], d[32:]

        # Tworzymy instancję szyfru z tymi samymi parametrami
        cipher = AES.new(klucz, AES.MODE_EAX, nonce=nonce)

        # Deszyfrujemy i sprawdzamy integralność przez tag
        return cipher.decrypt_and_verify(c, tag).decode()
    except:
        return None

# ----------------- RSA -----------------

def klucz_rsa(haslo):
    # Deterministyczna generacja klucza RSA z hasła – ten sam klucz dla tego samego hasła
    seed = int.from_bytes(sha256(haslo.encode()).digest(), "big")
    r = random.Random(seed)

    # Funkcja generująca losowe bajty z danego seeda
    randfunc = lambda n: bytes([r.getrandbits(8) for _ in range(n)])

    # Generujemy parę kluczy (2048-bitowy RSA)
    klucz = RSA.generate(2048, randfunc=randfunc)
    return klucz

@rejestruj_szyfr("RSA")
def szyfr_rsa(tekst, haslo):
    try:
        klucz = klucz_rsa(haslo)  # Generujemy klucz RSA (priv + pub)
        pubkey = klucz.publickey()  # Bierzemy klucz publiczny

        cipher = PKCS1_OAEP.new(pubkey)  # Szyfrowanie z paddingiem OAEP (zabezpieczenie przed atakami)

        zaszyfrowane = cipher.encrypt(tekst.encode("utf-8"))  # Szyfrujemy tekst

        # Zwracamy zaszyfrowany tekst i klucz PRYWATNY w formacie PEM (tekstowy)
        return base64.b64encode(zaszyfrowane).decode("utf-8"), klucz.export_key().decode("utf-8")
    except:
        return None, None

@rejestruj_de_szyfr("RSA")
def deszyfr_rsa(tekst, klucz):
    try:
        p_klucz = RSA.import_key(klucz.encode("utf-8"))  # Wczytujemy klucz prywatny z tekstu
        cipher = PKCS1_OAEP.new(p_klucz)  # Tworzymy deszyfrator z paddingiem OAEP

        # Deszyfrujemy i zwracamy tekst
        return cipher.decrypt(base64.b64decode(tekst)).decode("utf-8")
    except:
        return None

# ----------------- McEliece (symulacja) -----------------

# Parametry algorytmu – rozmiar macierzy kodującej G
n, k = 256, 128 # Typowe wartości dla McEliece'a: n > k

# Losowa odwracalna macierz kwadratowa nad GF(2)
def losowa_macierz_odwracalna(rozmiar, rng):
    while True:
        mat = rng.integers(0, 2, size=(rozmiar, rozmiar), dtype=np.uint8)
        if np.linalg.matrix_rank(mat) == rozmiar:
            return mat

# Losowa macierz permutacji n x n
def losowa_macierz_permutacji(rozmiar, rng):
    perm = rng.permutation(rozmiar)
    P = np.zeros((rozmiar, rozmiar), dtype=np.uint8)
    P[np.arange(rozmiar), perm] = 1
    return P

# Mnożenie nad GF(2)
def gf2_matmul(A, B):
    return np.mod(np.dot(A, B), 2).astype(np.uint8)

@rejestruj_szyfr("McEliece")
def szyfr_mceliece(tekst, haslo):
    try:
        seed = int.from_bytes(sha256(haslo.encode()).digest(), "big")
        rng = np.random.default_rng(seed)

        G_prim = rng.integers(0, 2, size=(k, n), dtype=np.uint8)
        while np.linalg.matrix_rank(G_prim) < k:
            G_prim = rng.integers(0, 2, size=(k, n), dtype=np.uint8)

        S = losowa_macierz_odwracalna(k, rng)
        P = losowa_macierz_permutacji(n, rng)

        G = gf2_matmul(gf2_matmul(S, G_prim), P)

        bity = np.unpackbits(np.frombuffer(tekst.encode(), dtype=np.uint8))
        if len(bity) > k:
            m = bity[:k]
        else:
            m = np.pad(bity, (0, k - len(bity)), 'constant')

        c = gf2_matmul(m, G)
        zaszyfrowane = base64.b64encode(np.packbits(c)).decode()

        key = {
            "S": S.tolist(),
            "G_prim": G_prim.tolist(),
            "P": P.tolist()
        }
        key_str = base64.b64encode(str(key).encode()).decode()
        return zaszyfrowane, key_str
    except:
        return None, None

@rejestruj_de_szyfr("McEliece")
def deszyfr_mceliece(cipher_b64, key_b64):
    try:
        key = eval(base64.b64decode(key_b64).decode())
        S = np.array(key["S"], dtype=np.uint8)
        G_prim = np.array(key["G_prim"], dtype=np.uint8)
        P = np.array(key["P"], dtype=np.uint8)

        c = np.unpackbits(np.frombuffer(base64.b64decode(cipher_b64), dtype=np.uint8))[:n]

        # Odwrócenie permutacji P bez kosztownego inv
        P_inv = np.argsort(np.argmax(P, axis=0))
        P_inv_mat = np.eye(n, dtype=np.uint8)[:, P_inv]
        c_prime = gf2_matmul(c, P_inv_mat)

        G_pinv = np.linalg.pinv(G_prim).astype(np.float32)
        m_approx = np.round(np.dot(c_prime, G_pinv)) % 2

        S_inv = np.linalg.inv(S) % 2
        m = gf2_matmul(m_approx.astype(np.uint8), S_inv.astype(np.uint8))

        bajty = np.packbits(m[:8 * (len(m) // 8)])
        return bajty.tobytes().decode("utf-8", errors="ignore")
    except Exception as e:
        return None