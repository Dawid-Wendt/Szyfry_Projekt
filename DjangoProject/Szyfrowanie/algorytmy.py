# ----------------- Importy i rejestracja algorytmów -----------------

from Crypto.Cipher import AES  # Biblioteka do szyfrowania symetrycznego (AES)
from Crypto.PublicKey import RSA  # Biblioteka do generowania kluczy RSA
from Crypto.Cipher import PKCS1_OAEP  # RSA z paddingiem OAEP (bezpieczniejszy niż surowy RSA)
import base64  # Do konwersji danych binarnych na tekst i odwrotnie
from hashlib import sha256  # Hashowanie danych do 256-bitów (np. z hasła)
import random  # Losowość np. dla RSA
import secrets  # Bezpieczne generowanie losowych wartości (kryptograficzne)
import numpy as np  # Obsługa macierzy i operacji matematycznych (dla McEliece)
from numpy.random import default_rng
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

# Parametry algorytmu – G musi być kwadratowa, by była odwracalna
n, k = 64, 64

def losowa_macierz_odwracalna(rozmiar, rng):
    while True:
        mat = rng.integers(0, 2, size=(rozmiar, rozmiar), dtype=np.uint8)
        if np.linalg.matrix_rank(mat) == rozmiar:
            return mat

def losowa_macierz_permutacji(rozmiar, rng):
    perm = rng.permutation(rozmiar)
    P = np.zeros((rozmiar, rozmiar), dtype=np.uint8)
    P[np.arange(rozmiar), perm] = 1
    return P

def gf2_matmul(A, B):
    return np.mod(np.dot(A, B), 2).astype(np.uint8)

def gf2_inv(A):
    A = A.copy()
    n = A.shape[0]
    I = np.eye(n, dtype=np.uint8)
    AI = np.concatenate((A, I), axis=1)

    for i in range(n):
        if AI[i, i] == 0:
            for j in range(i+1, n):
                if AI[j, i] == 1:
                    AI[[i, j]] = AI[[j, i]]
                    break
        for j in range(n):
            if i != j and AI[j, i] == 1:
                AI[j] ^= AI[i]
    return AI[:, n:]

@rejestruj_szyfr("McEliece")
def szyfr_mceliece(tekst, haslo):
    try:
        seed = int.from_bytes(sha256(haslo.encode()).digest(), "big")
        rng = default_rng(seed)

        G_prim = rng.integers(0, 2, size=(k, n), dtype=np.uint8)
        while np.linalg.matrix_rank(G_prim) < k:
            G_prim = rng.integers(0, 2, size=(k, n), dtype=np.uint8)

        S = losowa_macierz_odwracalna(k, rng)
        P = losowa_macierz_permutacji(n, rng)
        G = gf2_matmul(gf2_matmul(S, G_prim), P)

        tekst_bytes = tekst.encode("utf-8")
        bity = np.unpackbits(np.frombuffer(tekst_bytes, dtype=np.uint8))
        bit_len = len(bity)

        zaszyfrogramy = []
        for i in range(0, len(bity), k):
            blok = bity[i:i + k]
            if len(blok) < k:
                blok = np.pad(blok, (0, k - len(blok)), constant_values=0)
            c = gf2_matmul(blok, G)
            zaszyfrogramy.append(np.packbits(c))
        zaszyfrowane = base64.b64encode(np.concatenate(zaszyfrogramy)).decode()

        key = {
            "S": S.tolist(),
            "G_prim": G_prim.tolist(),
            "P": P.tolist(),
            "bit_len": bit_len,
            "byte_len": len(tekst_bytes)
        }
        key_str = base64.b64encode(str(key).encode()).decode()
        return zaszyfrowane, key_str
    except Exception:
        return None, None

@rejestruj_de_szyfr("McEliece")
def deszyfr_mceliece(cipher_b64, key_b64):
    try:
        key = eval(base64.b64decode(key_b64).decode())
        S = np.array(key["S"], dtype=np.uint8)
        G_prim = np.array(key["G_prim"], dtype=np.uint8)
        P = np.array(key["P"], dtype=np.uint8)
        bit_len = key["bit_len"]
        byte_len = key["byte_len"]

        n = P.shape[0]
        k = S.shape[0]

        c_zbior = np.unpackbits(np.frombuffer(base64.b64decode(cipher_b64), dtype=np.uint8))
        m_odtworzone = []

        for i in range(0, len(c_zbior), n):
            blok = c_zbior[i:i + n]
            if len(blok) < n:
                blok = np.pad(blok, (0, n - len(blok)), constant_values=0)

            c_prime = gf2_matmul(blok, np.eye(n, dtype=np.uint8)[:, np.argsort(np.argmax(P, axis=0))])
            m_blok = gf2_matmul(gf2_matmul(c_prime, gf2_inv(G_prim)), gf2_inv(S))
            m_odtworzone.append(m_blok)

        m_calosc = np.concatenate(m_odtworzone)[:bit_len]
        padded_bits = np.pad(m_calosc, (0, 8 - (m_calosc.size % 8)), constant_values=0)
        byte_array = np.packbits(padded_bits)
        odtworzone = byte_array.tobytes()[:byte_len]
        return odtworzone.decode("utf-8", errors="strict")
    except Exception:
        return None