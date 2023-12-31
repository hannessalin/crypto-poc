import sys
sys.path.insert(1,'/Users/hannessalin/Development/mcl-python/mcl-python')
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as spadding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

from mcl import GT
from mcl import G2
from mcl import G1
from mcl import Fr
from mcl import Fp

import time

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()

def rsa_encryption(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decryption(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

def encrypt_message(key, message):
    # Generate an IV
    iv = os.urandom(16)

    # Pad the message
    padder = spadding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Create and use a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Return the IV and encrypted message
    return iv + encrypted_message

def decrypt_message(key, encrypted_message_with_iv):
    # Extract the IV and encrypted message
    iv = encrypted_message_with_iv[:16]
    encrypted_message = encrypted_message_with_iv[16:]

    # Create and use a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Unpad the message
    unpadder = spadding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()
    return unpadded_message.decode()

def bls_sign(sk,m):
    sig = G1.hashAndMapTo(m)
    return (sig * sk)

def bls_verify(sigma,m,g2, pk):
    v_left = GT.pairing(sigma, g2)
    v_right = GT.pairing(G1.hashAndMapTo(m), pk)
    if v_left == v_right:
        return 1
    return 0

def xor_strings(str1, str2):
    # Convert strings to byte arrays
    bytes1 = str1.encode()
    bytes2 = str2.encode()

    # Determine the length of the longer string
    max_length = max(len(bytes1), len(bytes2))

    # Pad the shorter string with 0-bytes
    bytes1 = bytes1.ljust(max_length, b'\x00')
    bytes2 = bytes2.ljust(max_length, b'\x00')

    # Perform XOR on each pair of bytes and build the result
    result_bytes = bytes([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)])

    # Convert result back to a string
    return result_bytes.decode()


# paper I
def P1_Id(g,ski,m):
    r1 = Fr()
    h1 = Fr()
    r1.setByCSPRNG()
    r1big = g * r1

    r1big_str = r1big.getStr().decode('utf-8')
    concatenated_message = m + r1big_str
    concatenated_message_bytes = concatenated_message.encode('utf-8')

    h1.setStr(concatenated_message_bytes)
    s1 = r1 + (ski * h1)     # this value is in Z_q
    ghat = G1().hashAndMapTo(concatenated_message_bytes)
    shat = ghat * s1
    return (shat, r1big)

def P1_Ver(g2,pki,shat,r1big,m):
    r1big_str = r1big.getStr().decode('utf-8')
    concatenated_message = m + r1big_str
    concatenated_message_bytes = concatenated_message.encode('utf-8')

    h1 = Fr()
    h1.setStr(concatenated_message_bytes)
    ghat = G1().hashAndMapTo(concatenated_message_bytes)

    pairing_check_one = G1()
    pairing_check_one = pki * h1
    pairing_check_one = pairing_check_one + r1big     # need to adjust later for a R2 in G2
    pleft = GT.pairing(shat,g2)
    pright = GT.pairing(ghat,g2)
    #    pright = GT.pairing(ghat,pairing_check_one)      # need to make a pairing_check_one in G2

    return True

def P1_SC(g1,skp,shat,r1big,m,pkr):
    concatenated_message_bytes = m.encode('utf-8')

    r2 = Fr()
    h2 = Fr()
    r2.setByCSPRNG()
    r2big = g1 * r2
    r2bighat = pkr * r2
    k = pkr * skp
    k1 = os.urandom(32)
    k2 = os.urandom(32)
    g2hat = G1.hashAndMapTo(concatenated_message_bytes)
    h2.setStr(concatenated_message_bytes)
    s2 = r2 + (skp * h2)
    s2hat = g2hat * s2
    bigshat = shat + s2hat
    c = encrypt_message(k1, m)

    return (bigshat,r1big,r2bighat,c,k1,k2)

def P1_USC(g2,skr,pki,pkp,bigshat,r1big,r2bighat,c,k1,k2,m):
    r1big_str = r1big.getStr().decode('utf-8')
    concatenated_message = m + r1big_str
    concatenated_message_bytes = concatenated_message.encode('utf-8')
    concatenated_message_bytes_simple = m.encode('utf-8')

    skrinv = ~skr
    r2big = r2bighat * skrinv
    k = pkp * skr
    k1temp = os.urandom(32)
    k2temp = os.urandom(32)
    mdec = encrypt_message(k1, m)

    h1 = Fr()
    h1.setStr(concatenated_message_bytes)
    ghat = G1().hashAndMapTo(concatenated_message_bytes)

    h2 = Fr()
    g2hat = G1.hashAndMapTo(concatenated_message_bytes_simple)
    h2.setStr(concatenated_message_bytes_simple)

    vleft = GT.pairing(bigshat,g2)
    temp1 = r1big + (pki * h1)
    temp2 = r2big + (pkp * h2)
    vright1 = GT.pairing(ghat,g2)
    vright2 = GT.pairing(g2hat,g2)
    vrightmult = vright1 * vright2

def P2_UKeyGen(g):
    x_id = Fr()
    x_id.setByCSPRNG()
    xbig_id = g * x_id
    return (xbig_id, x_id)

def P2_IPKeyGen(g,a, userid, upkid):
    r_id = Fr()
    r_id.setByCSPRNG()
    rbig_id = g * r_id
    xbig_id = upkid
    n_id = Fr()
    n_id.setByCSPRNG()

    n_str = n_id.getStr().decode('utf-8')
    x_str = rbig_id.getStr().decode('utf-8')
    r_str = xbig_id.getStr().decode('utf-8')
    concatenated_message = n_str + x_str + r_str
    concatenated_message_bytes = concatenated_message.encode('utf-8')

    h_1id = Fr()
    h_1id.setStr(concatenated_message_bytes)
    ha = Fr()
    ha.setStr(x_str.encode('utf-8'))
    ha = ha * a
    ah1 = a * h_1id
    u_id = r_id + ah1 + ha
    return (n_id, rbig_id, u_id)

def P2_PKeyGen(x_id,A,upkid, ippkid, ipskid):
    u_id = ipskid
    f_of_A = A * x_id
    f_of_A_str = f_of_A.getStr()
    h_of_A = Fr()
    h_of_A.setStr(f_of_A_str)
    d_id = u_id - h_of_A
    pskid = d_id

    SK_id = (x_id, pskid)
    PK_id = (upkid, ippkid)
    return (SK_id, PK_id)

def P2_AEn_1(g, A, PK_id, SK_id, PK_k, m):

    # same code for all schemes
    x_id, d_id = SK_id
    xbig_id, ippkid = PK_id
    n_id, rbig_id = ippkid

    v_id = Fr()
    v_id.setByCSPRNG()
    vbig_id = g * v_id
    h1k = Fr()
    n_str = n_id.getStr().decode('utf-8')
    x_str = rbig_id.getStr().decode('utf-8')
    r_str = xbig_id.getStr().decode('utf-8')
    concatenated_message = n_str + x_str + r_str
    concatenated_message_bytes = concatenated_message.encode('utf-8')
    h1k.setStr(concatenated_message_bytes)
    Ah = A * h1k
    z_id = xbig_id + rbig_id + Ah
    zbig_id = z_id * v_id

    n_str = n_id.getStr().decode('utf-8')
    v_str = vbig_id.getStr().decode('utf-8')
    z_str = zbig_id.getStr().decode('utf-8')
    concatenated_message2 = n_str + v_str + z_str
    concatenated_message_bytes2 = concatenated_message2.encode('utf-8')
    h2id = Fr()
    h2id.setStr(concatenated_message_bytes2)
    c_id = xor_strings(h2id.getStr().decode('utf-8'), m)
    h3id = Fr()
    concatenated_message3 = v_str + n_str + c_id + x_str + r_str + z_str
    concatenated_message_bytes3 = concatenated_message3.encode('utf-8')
    h3id.setStr(concatenated_message_bytes3)

    # unique code for MPAE-1
    gidhat = G1().hashAndMapTo(concatenated_message_bytes3)
    sidhat_t1 = gidhat * v_id
    sidhat_t2 = gidhat * d_id
    xh = x_id * h3id
    sidhat_t3 = gidhat * xh
    sidhat = sidhat_t1+sidhat_t2+sidhat_t3

    return (sidhat, vbig_id, c_id)

def P2_AEn_2(g, A, PK_id, SK_id, PK_k, m):
        # same code for all schemes
        x_id, d_id = SK_id
        xbig_id, ippkid = PK_id
        n_id, rbig_id = ippkid

        v_id = Fr()
        v_id.setByCSPRNG()
        vbig_id = g * v_id
        h1k = Fr()
        n_str = n_id.getStr().decode('utf-8')
        x_str = rbig_id.getStr().decode('utf-8')
        r_str = xbig_id.getStr().decode('utf-8')
        concatenated_message = n_str + x_str + r_str
        concatenated_message_bytes = concatenated_message.encode('utf-8')
        h1k.setStr(concatenated_message_bytes)
        Ah = A * h1k
        z_id = xbig_id + rbig_id + Ah
        zbig_id = z_id * v_id

        n_str = n_id.getStr().decode('utf-8')
        v_str = vbig_id.getStr().decode('utf-8')
        z_str = zbig_id.getStr().decode('utf-8')
        concatenated_message2 = n_str + v_str + z_str
        concatenated_message_bytes2 = concatenated_message2.encode('utf-8')
        h2id = Fr()
        h2id.setStr(concatenated_message_bytes2)
        c_id = xor_strings(h2id.getStr().decode('utf-8'), m)
        h3id = Fr()
        concatenated_message3 = v_str + n_str + c_id + x_str + r_str + z_str
        concatenated_message_bytes3 = concatenated_message3.encode('utf-8')
        h3id.setStr(concatenated_message_bytes3)

        # unique code for MPAE-2
        com = 'commitment string'
        gidhat = G1().hashAndMapTo(com.encode('utf-8'))
        sidhat_t1 = gidhat * v_id
        sidhat_t2 = gidhat * d_id
        xh = x_id * h3id
        sidhat_t3 = gidhat * xh
        sidhat = sidhat_t1 + sidhat_t2 + sidhat_t3

        return (sidhat, vbig_id, c_id)


def P2_MA(act_id):
    # Initialize variables
    sbig = G1()
    v_arr = []
    c_arr = []

    # Iterate through each tuple in act_id
    for sidhat, vbig_id, c_id in act_id:
        # Accumulate sidhat values
        sbig = sbig + sidhat

        # Append vbig_id and c_id to their respective arrays
        v_arr.append(vbig_id)
        c_arr.append(c_id)

    # Return the sum and the two arrays
    return sbig, v_arr, c_arr

def P2_ADe_1(A,SK,PKlist,act,bigs,g2):
    if len(PKlist) != len(act):
        raise ValueError("PKlist and act must have the same number of elements")

    x_k,d_k = SK
    secret_sum = x_k + d_k
    p_acc = GT()
    # Iterate over both PKlist and act simultaneously
    for pk, (s_id, v_id, c_id) in zip(PKlist, act):
        xbig_id, rbig_id, n_id = pk
        zbig_id = v_id * secret_sum
        n_str = n_id.getStr().decode('utf-8')
        x_str = rbig_id.getStr().decode('utf-8')
        r_str = xbig_id.getStr().decode('utf-8')
        conc_message = n_str + x_str + r_str
        conc_message_bytes = conc_message.encode('utf-8')
        h1id = Fr()
        h1id.setStr(conc_message_bytes)
        h3id = Fr()
        v_str = v_id.getStr().decode('utf-8')
        z_str = zbig_id.getStr().decode('utf-8')
        conc_message2 = n_str + x_str + r_str + v_str + z_str + c_id
        conc_message_bytes2 = conc_message2.encode('utf-8')
        h3id.setStr(conc_message_bytes2)

        gidhat = G1().hashAndMapTo(conc_message_bytes2)
        # simulate the G2 calculation
        pright_1 = v_id + rbig_id
        pright_2 = A * h1id
        pright_3 = xbig_id * h3id
        pright = pright_1 + pright_2 + pright_3 # to be used in G2 later
        p = GT().pairing(gidhat,g2)
        p_acc = p_acc * p

    vleft = GT().pairing(bigs,g2)
    vright = p_acc

    message_list = []
    for pk, (s_id, v_id, c_id) in zip(PKlist, act):
        xbig_id, rbig_id, n_id = pk
        zbig_id = v_id * secret_sum
        n_str = n_id.getStr().decode('utf-8')
        v_str = v_id.getStr().decode('utf-8')
        z_str = zbig_id.getStr().decode('utf-8')
        conc_message3 = n_str + v_str + z_str
        conc_message_bytes3 = conc_message3.encode('utf-8')
        h2id = Fr()
        h2id.setStr(conc_message_bytes3)
        m = xor_strings(h2id.getStr().decode('utf-8'),c_id)
        message_list.append(m)
    return message_list


def P2_ADe_2(A,SK,PKlist,act,bigs,g2):
    if len(PKlist) != len(act):
        raise ValueError("PKlist and act must have the same number of elements")

    com = 'commitment string'
    x_k,d_k = SK
    secret_sum = x_k + d_k
    p_acc = GT()
    h1sum = Fr()
    vprod = G1()
    rprod = G1()
    xprod = G1()
    # Iterate over both PKlist and act simultaneously
    for pk, (s_id, v_id, c_id) in zip(PKlist, act):
        xbig_id, rbig_id, n_id = pk
        zbig_id = v_id * secret_sum
        n_str = n_id.getStr().decode('utf-8')
        x_str = rbig_id.getStr().decode('utf-8')
        r_str = xbig_id.getStr().decode('utf-8')
        conc_message = n_str + x_str + r_str
        conc_message_bytes = conc_message.encode('utf-8')
        h1id = Fr()
        h1id.setStr(conc_message_bytes)
        h3id = Fr()
        v_str = v_id.getStr().decode('utf-8')
        z_str = zbig_id.getStr().decode('utf-8')
        conc_message2 = n_str + x_str + r_str + v_str + z_str + c_id
        conc_message_bytes2 = conc_message2.encode('utf-8')
        h3id.setStr(conc_message_bytes2)

        # unique code for MPAE-2
        gidhat = G1().hashAndMapTo(com.encode('utf-8'))
        h1sum = h1sum + h1id
        vprod = vprod + v_id
        rprod = rprod + rbig_id
        xprod = xprod + xbig_id

    # simulate the G2 calculation
    pright_1 = vprod + rprod
    pright_2 = A * h1id
    pright = pright_1 + pright_2 + xprod # to be used in G2 later
    p = GT().pairing(gidhat,g2)
    p_acc = p_acc * p
    vleft = GT().pairing(bigs,g2)
    vright = p_acc

    message_list = []
    for pk, (s_id, v_id, c_id) in zip(PKlist, act):
        xbig_id, rbig_id, n_id = pk
        zbig_id = v_id * secret_sum
        n_str = n_id.getStr().decode('utf-8')
        v_str = v_id.getStr().decode('utf-8')
        z_str = zbig_id.getStr().decode('utf-8')
        conc_message3 = n_str + v_str + z_str
        conc_message_bytes3 = conc_message3.encode('utf-8')
        h2id = Fr()
        h2id.setStr(conc_message_bytes3)
        m = xor_strings(h2id.getStr().decode('utf-8'),c_id)
        message_list.append(m)
    return message_list

def P3_InitRF(sk):
    sk1 = Fr()
    sk1.setByCSPRNG()
    sk2 = sk - sk1
    # then store sk1 in HSM1 and sk2 in HSM2
    return (sk1,sk2)

def P3_RF(sk1, sk2):
    xi = Fr()
    xi.setByCSPRNG()
    sk1new = sk1 + xi
    sk2new = sk2 - xi
    return (sk1new, sk2new)

def P3_SignRF(m, sk1, sk2):
    h1 = G1().hashAndMapTo(m.encode('utf-8'))
    f1 = h1 * sk1
    f2 = h1 * sk2
    sigma = f1 + f2
    return sigma

def P4_RignSign(m, PKSsign):
    sigma_agg = G1()
    for (s,p) in PKSsign:
        h1 = G1().hashAndMapTo(m.encode('utf-8'))
        h1 = h1 * s
        sigma_agg = sigma_agg + h1
    return sigma_agg

def P4_RingVerify(m, g2, sigma_acc, PKsign):
    agg_ver = GT()
    for (s,p) in PKsign:
        h1 = G1().hashAndMapTo(m.encode('utf-8'))
        vright = GT().pairing(h1,p)
        agg_ver = agg_ver + vright
    vleft = GT().pairing(sigma_acc,g2)
    return True

def P4_OnionHiding(m, sigma, rsa_sk, PKSenc):

    # preparing for sending to server
    # c0 = f"{m},{sigma}"
    c0 = 'dummy message'
    e_i = rsa_encryption(PKSenc[0], c0)

    for p in PKSenc[1:]:  # Start from the second element
        # Convert the encrypted result to a string
        # e_i_str = e_i.hex()
        e_i_str = c0

        # Encrypt the previous result
        e_i = rsa_encryption(p, e_i_str)

    # after receiving from server, simulating n number of onions
    for e in PKSenc:
        d_i = rsa_decryption(rsa_sk, e_i)

    # simulate shuffle
    os.urandom(32)


run_fundamentals = False
run_p1 = False
run_p2 = False
run_p3 = False
run_p4 = True


G1_STR = b"1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569"
G2_STR = b"1 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582"

s = Fr()
x1 = Fr()
x2 = Fr()
s.setByCSPRNG()
x1.setByCSPRNG()
x2.setByCSPRNG()

g1 = G1()
g1.setStr(G1_STR)
g2 = G2()
g2.setStr(G2_STR)
gt = GT().pairing(g1,g2)

message_to_use = 'secret message'

if run_fundamentals == True:
    time_1_start = time.time()
    for i in range(1000):
        g1 + g1
    time_1_stop = time.time()
    print("G1 addition: ", f'{(time_1_stop-time_1_start)/1000:.10f}')

    time_2_start = time.time()
    for i in range(1000):
        g2 + g2
    time_2_stop = time.time()
    print("G2 addition: ", f'{(time_2_stop-time_2_start)/1000:.10f}')

    time_3_start = time.time()
    for i in range(1000):
        g1 * s
    time_3_stop = time.time()
    print("G1 mul: ", f'{(time_3_stop-time_3_start)/1000:.10f}')

    time_4_start = time.time()
    for i in range(1000):
        g2 * s
    time_4_stop = time.time()
    print("G2 mul: ", f'{(time_4_stop-time_4_start)/1000:.10f}')

    time_p_start = time.time()
    for i in range(1000):
        GT.pairing(g1, g2)
    time_p_stop = time.time()
    print("pairing: ", f'{(time_p_stop-time_p_start)/1000:.10f}')

    time_p2_start = time.time()
    for i in range(1000):
        gt ** s
    time_p2_stop = time.time()
    print("Gt: exponent: ", f'{(time_p2_stop-time_p2_start)/1000:.10f}')

    time_p3_start = time.time()
    for i in range(1000):
        G1.hashAndMapTo(b'123')
    time_p3_stop = time.time()
    print("hash to G1: ", f'{(time_p3_stop-time_p3_start)/1000:.10f}')

    time_p4_start = time.time()
    for i in range(1000):
        G2.hashAndMapTo(b'123')
    time_p4_stop = time.time()
    print("hash to G2: ", f'{(time_p4_stop-time_p4_start)/1000:.10f}')

    stest = Fr()
    time_p5_start = time.time()
    for i in range(1000):
        stest.setByCSPRNG()
    time_p5_stop = time.time()
    print("hash to Z: ", f'{(time_p5_stop-time_p5_start)/1000:.10f}')

    stest2 = Fr()
    time_p6_start = time.time()
    for i in range(1000):
        stest2.setStr(b'x')
    time_p6_stop = time.time()
    print("hash to Z: ", f'{(time_p6_stop-time_p6_start)/1000:.10f}')

    message = b'some secret message'
    sigma = bls_sign(x1,message)
    result = bls_verify(sigma,message,g2,g2*x1)

    time_bls_start = time.time()
    for i in range(1000):
        bls_sign(s, message)
    time_bls_stop = time.time()
    print("BLS signing: ", f'{(time_bls_stop-time_bls_start)/1000:.10f}')

    sig = bls_sign(s, message)
    time_bls2_start = time.time()
    for i in range(1000):
        bls_verify(sig, message, g2, g2)
    time_bls2_stop = time.time()
    print("BLS verifying: ", f'{(time_bls2_stop-time_bls2_start)/1000:.10f}')

    omessage = "This is a secret message."
    testkey = os.urandom(32)
    time_aes_start = time.time()
    for i in range(1000):
        encrypted_with_iv = encrypt_message(testkey, omessage)
    time_aes_stop = time.time()
    print("AES enc: ", f'{(time_aes_stop-time_aes_start)/1000:.10f}')

    encrypted_with_iv = encrypt_message(testkey, omessage)
    time_aes2_start = time.time()
    for i in range(1000):
        decrypted = decrypt_message(testkey, encrypted_with_iv)
    time_aes2_stop = time.time()
    print("AES dec: ", f'{(time_aes2_stop-time_aes2_start)/1000:.10f}')

    rsa_private_key, rsa_public_key = generate_rsa_key_pair()
    time_rsa_start = time.time()
    for i in range(1000):
        rsa_encryption(rsa_public_key, omessage)
    time_rsa_stop = time.time()
    print("RSA enc: ", f'{(time_rsa_stop-time_rsa_start)/1000:.10f}')

    rsa_ciphertext = rsa_encryption(rsa_public_key, omessage)
    time_rsa2_start = time.time()
    for i in range(1000):
        rsa_decryption(rsa_private_key, rsa_ciphertext)
    time_rsa2_stop = time.time()
    print("RSA dec: ", f'{(time_rsa2_stop-time_rsa2_start)/1000:.10f}')


# running paper 1 algorithms
# pargen simulation
if run_p1 == True:
    ski = Fr()
    skp = Fr()
    skr = Fr()
    ski.setByCSPRNG()
    skp.setByCSPRNG()
    skr.setByCSPRNG()
    pki = g1 * ski
    pkp = g1 * skp
    pkr = g1 * skr

    time_p1_id_start = time.time()
    for i in range(1000):
        s1hat,r1big = P1_Id(g1, ski, message_to_use)
    time_p1_id_stop = time.time()
    print("P1 Id run-time: ", f'{(time_p1_id_stop-time_p1_id_start)/1000:.10f}')

    s1hat, r1big = P1_Id(g1, ski, message_to_use)
    time_p1_ver_start = time.time()
    for i in range(1000):
        P1_Ver(g2, pki, s1hat, r1big, message_to_use)
    time_p1_ver_stop = time.time()
    print("P1 Id run-time: ", f'{(time_p1_ver_stop-time_p1_ver_start)/1000:.10f}')

    time_p1_sc_start = time.time()
    for i in range(1000):
        P1_SC(g1, skp, s1hat, r1big, message_to_use, pkr)
    time_p1_sc_stop = time.time()
    print("P1 SC run-time: ", f'{(time_p1_sc_stop-time_p1_sc_start)/1000:.10f}')

    bigshat,r1big,r2bighat,c,k1,k2 = P1_SC(g1, skp, s1hat, r1big, message_to_use, pkr)
    time_p1_usc_start = time.time()
    for i in range(1000):
        P1_USC(g2, skr, pki, pkp, bigshat, r1big, r2bighat, c, k1, k2, message_to_use)
    time_p1_usc_stop = time.time()
    print("P1 USC run-time: ", f'{(time_p1_usc_stop-time_p1_sc_start)/1000:.10f}')


# running paper 2 algorithms
# pargen simulation

# upk_id = xbig_id
# usk_id = x_id

# ippk_id = (n_id, r_id)
# ipsk_id = u_id

# ppk_id = (n_id, r_id)
# psk_id = d_id

# SK_id = (usk_id, psk_id)
# PK_id = (upk_id, ppk_id)


if run_p2 == True:
    a = Fr()
    a.setByCSPRNG()
    idstr = 'ID'
    upkid = G1()

    time_p2_uk_start = time.time()
    for i in range(1000):
        P2_UKeyGen(g1)
    time_p2_uk_stop = time.time()
    print("P2 UKeyGen run-time: ", f'{(time_p2_uk_stop-time_p2_uk_start)/1000:.10f}')

    xbig_id, x_id = P2_UKeyGen(g1)
    upkid = xbig_id
    uskid = x_id

    time_p2_ipk_start = time.time()
    for i in range(1000):
        P2_IPKeyGen(g1, a, idstr, upkid)
    time_p2_ipk_stop = time.time()
    print("P2 IPKeyGen run-time: ", f'{(time_p2_ipk_stop-time_p2_ipk_start)/1000:.10f}')

    n_id, rbig_id, u_id = P2_IPKeyGen(g1, a,idstr, upkid)
    A = g1 * a
    ippkid = (n_id, rbig_id)
    ipskid = u_id
    time_p2_pk_start = time.time()
    for i in range(1000):
        P2_PKeyGen(x_id, A, upkid, ippkid, ipskid)
    time_p2_pk_stop = time.time()
    print("P2 PKeyGen run-time: ", f'{(time_p2_pk_stop-time_p2_pk_start)/1000:.10f}')

    SK, PK = P2_PKeyGen(x_id, A, upkid, ippkid, ipskid)
    time_p2_aen1_start = time.time()
    for i in range(1000):
        P2_AEn_1(g1, A, PK, SK, PK, message_to_use)
    time_p2_aen1_stop = time.time()
    print("P2 AEN MPAE-1 run-time: ", f'{(time_p2_aen1_stop-time_p2_aen1_start)/1000:.10f}')

    time_p2_aen2_start = time.time()
    for i in range(1000):
        P2_AEn_2(g1, A, PK, SK, PK, message_to_use)
    time_p2_aen2_stop = time.time()
    print("P2 AEN MPAE-2 run-time: ", f'{(time_p2_aen2_stop-time_p2_aen2_start)/1000:.10f}')

    sidhat_1, vbig_id_1, c_id_1 = P2_AEn_1(g1, A, PK, SK, PK, message_to_use)
    sidhat_2, vbig_id_2, c_id_2 = P2_AEn_2(g1, A, PK, SK, PK, message_to_use)

    # single act_id
    act_id = [(sidhat_1, vbig_id_1, c_id_1)]

    # 100 act_id
    act_id_100 = [(sidhat_1, vbig_id_1, c_id_1) for _ in range(100)]

    # 1000 act_id
    act_id_1000 = [(sidhat_1, vbig_id_1, c_id_1) for _ in range(1000)]

    # 1000 act_id
    act_id_10000 = [(sidhat_1, vbig_id_1, c_id_1) for _ in range(10000)]


    time_p2_ma_start = time.time()
    for i in range(1000):
        P2_MA(act_id)
    time_p2_ma_stop = time.time()
    print("P2 MA run-time: ", f'{(time_p2_ma_stop-time_p2_ma_start)/1000:.10f}')

    time_p2_ma100_start = time.time()
    for i in range(1000):
        P2_MA(act_id_100)
    time_p2_ma100_stop = time.time()
    print("P2 MA 100 nodes run-time: ", f'{(time_p2_ma100_stop-time_p2_ma100_start)/1000:.10f}')

    time_p2_ma1000_start = time.time()
    for i in range(1000):
        P2_MA(act_id_1000)
    time_p2_ma1000_stop = time.time()
    print("P2 MA 1000 nodes run-time: ", f'{(time_p2_ma1000_stop-time_p2_ma1000_start)/1000:.10f}')

    time_p2_ma10000_start = time.time()
    for i in range(1000):
        P2_MA(act_id_10000)
    time_p2_ma10000_stop = time.time()
    print("P2 MA 10000 nodes run-time: ", f'{(time_p2_ma10000_stop-time_p2_ma10000_start)/1000:.10f}')

    sbig, v_arr, c_arr = P2_MA(act_id)
    PKlist = [(xbig_id, rbig_id, n_id)]

    # 100 PKlist
    PKlist_100 = [(xbig_id, rbig_id, n_id) for _ in range(100)]

    # 1000 PKlist
    PKlist_1000 = [(xbig_id, rbig_id, n_id) for _ in range(1000)]

    # 1000 PKlist
    PKlist_10000 = [(xbig_id, rbig_id, n_id) for _ in range(10000)]

    time_p2_ade_start = time.time()
    for i in range(1000):
        P2_ADe_1(A,SK, PKlist, act_id, sbig, g2)
    time_p2_ade_stop = time.time()
    print("P2 ADe MPAE-1 run-time: ", f'{(time_p2_ade_stop-time_p2_ade_start)/1000:.10f}')

    time_p2_ade1_100_start = time.time()
    P2_ADe_1(A,SK, PKlist_100, act_id_100, sbig, g2)
    time_p2_ade1_100_stop = time.time()
    print("P2 ADe 100 MPAE-1 run-time: ", f'{(time_p2_ade1_100_stop-time_p2_ade1_100_start):.10f}')

    time_p2_ade1_1000_start = time.time()
    P2_ADe_1(A,SK, PKlist_1000, act_id_1000, sbig, g2)
    time_p2_ade1_1000_stop = time.time()
    print("P2 ADe 1000 MPAE-1 run-time: ", f'{(time_p2_ade1_1000_stop-time_p2_ade1_1000_start):.10f}')

    time_p2_ade1_10000_start = time.time()
    P2_ADe_1(A,SK, PKlist_10000, act_id_10000, sbig, g2)
    time_p2_ade1_10000_stop = time.time()
    print("P2 ADe 10000 MPAE-1 run-time: ", f'{(time_p2_ade1_10000_stop-time_p2_ade1_10000_start):.10f}')

# ADe MPAE-2 scaling

    time_p2_ade2_start = time.time()
    for i in range(1000):
        P2_ADe_2(A,SK, PKlist, act_id, sbig, g2)
    time_p2_ade2_stop = time.time()
    print("P2 ADe MPAE-2 run-time: ", f'{(time_p2_ade2_stop-time_p2_ade2_start)/1000:.10f}')

    time_p2_ade2_100_start = time.time()
    P2_ADe_2(A,SK, PKlist_100, act_id_100, sbig, g2)
    time_p2_ade2_100_stop = time.time()
    print("P2 ADe 100 MPAE-2 run-time: ", f'{(time_p2_ade2_100_stop-time_p2_ade2_100_start):.10f}')

    time_p2_ade2_1000_start = time.time()
    P2_ADe_2(A,SK, PKlist_1000, act_id_1000, sbig, g2)
    time_p2_ade2_1000_stop = time.time()
    print("P2 ADe 1000 MPAE-2 run-time: ", f'{(time_p2_ade2_1000_stop-time_p2_ade2_1000_start):.10f}')

    time_p2_ade2_10000_start = time.time()
    P2_ADe_2(A,SK, PKlist_10000, act_id_10000, sbig, g2)
    time_p2_ade2_10000_stop = time.time()
    print("P2 ADe 10000 MPAE-2 run-time: ", f'{(time_p2_ade2_10000_stop-time_p2_ade2_10000_start):.10f}')


if run_p3 == True:
    sk = Fr()
    sk.setByCSPRNG()

    time_p3init_start = time.time()
    for i in range(1000):
        P3_InitRF(sk)
    time_p3init_stop = time.time()
    print("P3 InitRF run-time: ", f'{(time_p3init_stop-time_p3init_start)/1000:.10f}')

    sk1,sk2 = P3_InitRF(sk)
    time_p3rf_start = time.time()
    for i in range(1000):
        P3_RF(sk1, sk2)
    time_p3rf_stop = time.time()
    print("P3 RF run-time: ", f'{(time_p3rf_stop-time_p3rf_start)/1000:.10f}')

    sk1new, sk2new = P3_RF(sk1,sk2)
    time_p3sig_start = time.time()
    for i in range(1000):
        P3_SignRF('some message', sk1new, sk2new)
    time_p3sig_stop = time.time()
    print("P3 SignRF run-time: ", f'{(time_p3sig_stop-time_p3sig_start)/1000:.10f}')

    # note that verification is a BlS verification, hence we do not implement it here.

if run_p4 == True:
    # pargen and keygen
    rsa_private_key_p4, rsa_public_key_p4 = generate_rsa_key_pair()
    PKSenc = [rsa_public_key_p4]
    ringsignsk = Fr()
    ringsignsk.setByCSPRNG()
    ringsignpk = G2()
    ringsignpk = g2 * ringsignsk
    PKSsign = [(ringsignsk, ringsignpk)]

    sigma = P4_RignSign(message_to_use, PKSsign)
    P4_RingVerify(message_to_use, g2, sigma, PKSsign)
    P4_OnionHiding(message_to_use, sigma, rsa_private_key_p4,PKSenc)

    time_p4rsig_start = time.time()
    for i in range(1000):
        P4_RignSign(message_to_use, PKSsign)
    time_p4rsig_stop = time.time()
    print("P4 RingSign run-time: ", f'{(time_p4rsig_stop-time_p4rsig_start)/1000:.10f}')

    time_p4rver_start = time.time()
    for i in range(1000):
        P4_RingVerify(message_to_use, g2, sigma, PKSsign)
    time_p4rver_stop = time.time()
    print("P4 RingSignVerify run-time: ", f'{(time_p4rver_stop-time_p4rver_start)/1000:.10f}')

    time_p4o_start = time.time()
    for i in range(1000):
        sigma = P4_RignSign(message_to_use, PKSsign)
        P4_OnionHiding(message_to_use, sigma, rsa_private_key_p4, PKSenc)
    time_p4o_stop = time.time()
    print("P4 OnionHiding run-time: ", f'{(time_p4o_stop-time_p4o_start)/1000:.10f}')

    # 100 ringsigners
    PKSsign_100 = [(ringsignsk, ringsignpk) for _ in range(100)]
    PKSsign_1000 = [(ringsignsk, ringsignpk) for _ in range(1000)]
    PKSsign_10000 = [(ringsignsk, ringsignpk) for _ in range(10000)]
    PKSenc_100 = [rsa_public_key_p4 for _ in range(100)]

    sigma = P4_RignSign(message_to_use, PKSsign_100)

    time_p4rsig100_start = time.time()
    P4_RignSign(message_to_use, PKSsign_100)
    time_p4rsig100_stop = time.time()
    print("P4 RingSign 100 run-time: ", f'{(time_p4rsig100_stop-time_p4rsig100_start):.10f}')

    time_p4rsig1000_start = time.time()
    P4_RignSign(message_to_use, PKSsign_1000)
    time_p4rsig1000_stop = time.time()
    print("P4 RingSign 1000 run-time: ", f'{(time_p4rsig1000_stop-time_p4rsig1000_start):.10f}')

    time_p4rsig10000_start = time.time()
    P4_RignSign(message_to_use, PKSsign_10000)
    time_p4rsig10000_stop = time.time()
    print("P4 RingSign 10000 run-time: ", f'{(time_p4rsig10000_stop-time_p4rsig10000_start):.10f}')

    time_p4rv100_start = time.time()
    P4_RingVerify(message_to_use, g2, sigma, PKSsign_100)
    time_p4rv100_stop = time.time()
    print("P4 RingVerify 100 run-time: ", f'{(time_p4rv100_stop-time_p4rv100_start):.10f}')

    time_p4rv1000_start = time.time()
    P4_RingVerify(message_to_use, g2, sigma, PKSsign_1000)
    time_p4rv1000_stop = time.time()
    print("P4 RingVerify 1000 run-time: ", f'{(time_p4rv1000_stop-time_p4rv1000_start):.10f}')

    time_p4rv10000_start = time.time()
    P4_RingVerify(message_to_use, g2, sigma, PKSsign_10000)
    time_p4rv10000_stop = time.time()
    print("P4 RingVerify 10000 run-time: ", f'{(time_p4rv10000_stop-time_p4rv10000_start):.10f}')

    time_p4o100_start = time.time()
    sigma = P4_RignSign(message_to_use, PKSsign)
    P4_OnionHiding(message_to_use, sigma, rsa_private_key_p4, PKSenc_100)
    time_p4o100_stop = time.time()
    print("P4 OnionHiding 100 signers run-time: ", f'{(time_p4o100_stop-time_p4o100_start):.10f}')