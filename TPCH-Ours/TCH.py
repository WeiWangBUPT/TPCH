
# A implementation of decentralized trapdoor verifiable delay function DTVDF
#
# run as /path/to/sage -python DTVDF.py
#
# Warning: unaudited code.
#
# Copyright (c) 2023 Wei Wang <weiwangscsc@bupt.edu.com>

import time
import math
from math import factorial

from Crypto.Util.number import inverse, size
from ecdsa.numbertheory import is_prime


import random
import hashlib
from hashlib import sha512

#from rsa.common import extended_gcd


time_multiplier = 1000

t=10
n=15



param = {
    # RSA modulus length, in bits.
    'rsa_modulus_length_in_bits': 2048,
    # Number of DTVDF shares needed to obtain a DTVDF result y
    # This is the threshold ω in the paper.
    'number_parties_needed': t,
    # Number of players are corrupted in the scheme.
    'number_parties_corrupted':0,
    # Number of players engaging in the scheme.
    'number_parties_total': n,
    # The factorial of n in the paper.
    'delta': factorial(n),

}

# The current version of the script.
__version__ = '2023-08-24/001'


urandom = random.SystemRandom()

#++++++++++++++++++++++++++++++++++++++++++++
def extended_gcd(a, b):
    """
    Return r, s, t such that gcd(a, b) = r = a * s + b * t
    """
    r0, r1 = a, b
    s0, s1, t0, t1 = 1, 0, 0, 1
    if r0 > r1:
        r0, r1, s0, s1, t0, t1 = r1, r0, t0, t1, s0, s1
    while r1 > 0:
        q = r0 // r1
        r = r0 % r1
        r0, r1, s0, s1, t0, t1 = r1, r, s1, s0 - q * s1, t1, t0 - q * t1
    return r0, s0, t0

def gcd(p: int, q: int) -> int:
    #Returns the greatest common divisor of p and q
    while q != 0:
        (p, q) = (q, p % q)
    return p

def random_1(n):
    return urandom.randint(0, n-1)  # inclusive 0 and n-1

def pow_mod(base, exponent, modulo):
    return pow(int(base), int(exponent), int(modulo))

def mod_1(a, b):
    return a % b

def mul_mod(op1, op2, modulo):
    return mod_1(int(op1) * int(op2), modulo)

def is_sophie_germain(n):
    return is_prime(n) and is_prime((n-1)/2)



def prime_gen(param):
    #((pub_key, priv_key), ph1) = rsa.newkeys(1024)

    #N=p*q,where p=2*p1+1 and q=2*q1+1

    #N is 1024 bits
    #p1=22477664609411115811764585530871397671644918508656968363395279165227515181191964394952975584329516345811304346752842235325165208926862467646321831306556109391609653
    #q1=1149893074682290650662789001443543062233708223909929288384093692406801223515128786013496681854535378889342595764296587783880602765548521211213903

    #N is 2048 bits
    p1 =1520760909515346305367990380626704828881533480985774821905369161325277043102054668743225163476654279819535334065276616324731538452062419866484041372115070215434324443089900433295858890143497159495300049281919505770228155315952735922014513248420995120629979767712193468186148470013074244537431136331846041542665360920615796132281
    q1=4771988445224992977022630428658388959833772111982240594367901235076277699109819766861998446649705389415039582251659830799678010407778398554237775917426726850336949056027527530936129355490368990646462784510381677531328910675713942044300535533364066919743846425705811615088054884502150835563

    p = int(p1 * 2 + 1)
    q = int(q1 * 2 + 1)

    #print("p：", p)
    #print("q：", q)

    Nsize = size(p * q)
    print("Nsize:",Nsize)

    return (p, q)


def key_gen_TCH(param, primes):
    (p, q) = primes

    p2 = (p - 1) // 2
    q2 = (q - 1) // 2

    #print("p2：", p2)
    #print("q2：", q2)

    # φ(N)=(p-1)*(q-1)=4m.
    # Here, φ(N) is an RSA modulus, and φ(N) is Euler function of N.
    m = p2 * q2
    e = 0x10001

    sk_unshared = {
        'p': p,
        'q': q,
        'd': inverse(e,m)%m,
        'm': m,
    }
    pk1 = {
        'n': p * q,
        'e': e,
    }
    return (sk_unshared, pk1)


def evaluate_poly(poly, point, m):
    ret = 0
    for i in range(len(poly)):
        ret = ret + mod_1((poly[i] * mod_1(point ** i, m)), m)
    return mod_1(ret, m)


def split_shamir_TCH(secret, number_coeffs, number_shares, modulus):
    a = [0] * number_coeffs
    a[0] = secret

    for i in range(1, number_coeffs):
        a[i] = random_1(modulus)
    s = [0] * number_shares
    for i in range(number_shares):
        s[i] = evaluate_poly(a, i+1, modulus)

    return s,a


def gen_r1_shares_TCH(param, pk1, sk_shared, message):
    xi = [0] * param['number_parties_total']
    for i in range(param['number_parties_total']):
        exponent = 2 * param['delta'] * sk_shared['s'][i]
        # print("param['delta']:", param['delta'])
        # print("sk_shared['s'][i]:", sk_shared['s'][i])
        # print("message:",message)
        # print("exponent:",exponent)
        xi[i] = pow_mod(message, exponent, pk1['n'])
    return xi


def lagrange(S, i, j, delta):
    ret = delta
    for j_prime in S:
        if j_prime != j:
            ret = (ret * (i - j_prime)) / (j - j_prime)
    return ret


def hash_transcript(**transcript):
    hexdigest = hashlib.sha256(str(transcript).encode('utf-8')).hexdigest()
    return int(hexdigest, base=16)

def lift_message(message, delta, n):
    return pow_mod(message, 4*delta, n)


def construct_proofs_TCH(param, pk1, sk_shared, message, sigshares):
    n = pk1['n']
    v = sk_shared['v']
    L = param['number_parties_total']
    xt = lift_message(message, param['delta'], n)
    proofs = [0] * L
    quorum = list(range(L))
    for i in quorum:
        r = random_1(n)
        c = hash_transcript(script_version=__version__,
                            param=param,
                            pk1=pk1,
                            party_index=i,
                            v=v,
                            xt=xt,
                            vi=sk_shared['vs'][i],
                            xi2=pow_mod(sigshares[i], 2, n),
                            vp=pow_mod(v, r, n),
                            xp=pow_mod(xt, r, n))


        z = int(sk_shared['s'][i])*c + r
        proofs[i] = (z, c)
    return proofs


def validate_param(param):
    assert(param['number_parties_needed'] >=
           param['number_parties_corrupted']+1)
    assert((param['number_parties_total'] - param['number_parties_corrupted'])
           >= param['number_parties_needed'])
    param['delta'] = factorial(param['number_parties_total'])


def TCH_setup(param, pem_file=None):
    validate_param(param)

    (sk_unshared, pk1) = key_gen_TCH(param, prime_gen(param))


    return (sk_unshared, pk1)

def random_message(pk1):
    return random_1(pk1['n'])

#111111111111TCH_KGen------------------------
def TCH_KGen(param, sk_unshared, pk1):
    # Generate shares for the secret key by Shamir splitting
    # and shares of the verification key.
    n =pk1['n']

    s,a = split_shamir_TCH(secret=sk_unshared['d'],
                     number_coeffs=param['number_parties_needed'],
                     number_shares=param['number_parties_total'],
                     modulus=sk_unshared['m'])

    # verification keys
    v_pre = random_1(n)
    assert(gcd(v_pre, n) == 1)
    v = mul_mod(v_pre, v_pre, n)

    vs = [0] * param['number_parties_total']
    for i in range(len(vs)):
        vs[i] = pow_mod(v, s[i], n)

    cv = [0] * param['number_parties_needed']
    for i in range(len(cv)):
        cv[i] = pow_mod(v, a[i], n)

    sk_shared = {
        'v': v,
        's': s,
        'vs': vs,
    }
    return sk_shared

#222222222222TCH_Hash------------------------
def VV_Hash(pk1, h_msg): 

    # step 2 RSACH
    # r1 = random.getrandbits(1024)
    m = int.from_bytes(h_msg, byteorder='big')
    h1,r1 = TCH_Hash(pk1,m)

    return h1, r1

#33333333333TCH_Verify------------------------
def VV_Verify(pk1, h_msg, r, h):
    m = int.from_bytes(h_msg, byteorder='big')

    h1Prime = int.from_bytes(sha512(str(m).encode()).digest(), byteorder='big') * pow(r, pk1['e'], pk1['n']) % pk1['n']
    if (h== h1Prime):
        return 1
    else:
        return 0

#4444444444444TCH_ParAdapt------------------
def VV_ParAdapt(param,pk1, sk_shared, h_msg, h_msgPrime, r):
    
    # step 3
    m = int.from_bytes(h_msg, byteorder='big')
    mPrime = int.from_bytes(h_msgPrime, byteorder='big')
    temp_hmsg = m
    temp_hmsgPrime = mPrime
    x1 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big')
    x1Prime = int.from_bytes(sha512(str(temp_hmsgPrime).encode()).digest(), byteorder='big')
    y1 = x1 * pow(r, pk1['e'], pk1['n']) % pk1['n']

    x1PrimeInv = inverse(x1Prime,pk1['n'])%pk1['n']

    message_base1=y1*x1PrimeInv%pk1['n']

    #---------------------------------------------------------
    # print("")
    # print("message_base1 in TCH:", message_base1)

    # Construct the CH r1 share
    r1_shares = gen_r1_shares_TCH(param, pk1, sk_shared, message_base1)
    
    # Construct the proof of TCH shares
    proofs = construct_proofs_TCH(param, pk1, sk_shared,
                              message_base1, r1_shares)

    return (r1_shares, proofs)

#5555555555555TCH_ParVer------------------

def VV_ParVer(param, pk1, sk_shared, proofs, h_msg, h_msgPrime, r, TCH_r1_shares):
    n = pk1['n']
    v = sk_shared['v']


    #Computing message_base1-----------------
    m = int.from_bytes(h_msg, byteorder='big')
    mPrime = int.from_bytes(h_msgPrime, byteorder='big')
    temp_hmsg = m
    temp_hmsgPrime = mPrime
    x1 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big')
    x1Prime = int.from_bytes(sha512(str(temp_hmsgPrime).encode()).digest(), byteorder='big')
    y1 = x1 * pow(r, pk1['e'], pk1['n']) % pk1['n']

    x1PrimeInv = inverse(x1Prime,pk1['n'])%pk1['n']

    message_base1=y1*x1PrimeInv%pk1['n']

    xt = lift_message(message_base1, param['delta'], n)
    quorum = list(range(param['number_parties_total']))

    for i in quorum:
        their_z, their_c = proofs[i]
        #"In Python 3.6, you cannot directly use pow(x, negative number, z)."
        sk_shared_inv = inverse(sk_shared['vs'][i], n)
        vp1 = pow_mod(v, their_z, n)
        vp2 = pow_mod( sk_shared_inv, their_c, n)
        #"In Python 3.6, you cannot directly use pow(x, negative number, z)."
        sigshares_inv = inverse(TCH_r1_shares[i], n)
        xp1 = pow_mod(xt, their_z, n)
        xp2 = pow_mod(sigshares_inv, 2*their_c, n)

        our_c = hash_transcript(script_version=__version__,
                                param=param,
                                pk1=pk1,
                                party_index=i,
                                v=v,
                                xt=xt,
                                vi=sk_shared['vs'][i],
                                xi2=pow_mod(TCH_r1_shares[i], 2, n),
                                vp=mul_mod(vp1, vp2, n),
                                xp=mul_mod(xp1, xp2, n))
        assert(our_c == their_c)



#TPCH++++++++++++++++++++++++++++++
def TCH_ParAdapt_TPCH(param,pk1, sk_shared, h_msg, h_msgPrime, r, etd_rsaKey):
    
    # step 3
    m = int.from_bytes(h_msg, byteorder='big')
    mPrime = int.from_bytes(h_msgPrime, byteorder='big')
    temp_hmsg = m + pk1['n'] + etd_rsaKey.n
    temp_hmsgPrime = mPrime + pk1['n'] + etd_rsaKey.n
    x1 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big')
    x1Prime = int.from_bytes(sha512(str(temp_hmsgPrime).encode()).digest(), byteorder='big')
    y1 = x1 * pow(r[0], pk1['e'], pk1['n']) % pk1['n']

    x1PrimeInv = inverse(x1Prime,pk1['n'])%pk1['n']
    
    #r1Prime = pow(y1*x1PrimeInv%pk1['n'], rsaKey.d, pk1['n'])

    message_base1=y1*x1PrimeInv%pk1['n']

    #---------------------------------------------------------
    # print("")
    # print("message_base1 in TCH:", message_base1)

    # Construct the CH r1 share
    r1_shares = gen_r1_shares_TCH(param, pk1, sk_shared, message_base1)
    
    # Construct the proof of TCH shares
    proofs = construct_proofs_TCH(param, pk1, sk_shared,
                              message_base1, r1_shares)

    return (r1_shares, proofs)


#4444444444444TCH_ParAdapt------------------
def TCH_ParAdapt(param, pk1, sk_shared, message_to_sign):
    # Construct the DTVDF share
    y_shares = gen_r1_shares_TCH(param, pk1, sk_shared, message_to_sign)
    # Construct the proof of TCH shares
    proofs = construct_proofs_TCH(param, pk1, sk_shared,
                              message_to_sign, y_shares)
    return (y_shares, proofs)
#5555555555555TCH_ParVer------------------
def TCH_ParVer(param, pk1, sk_shared, proofs, massage_TCH, TCH_r1_shares):
    n = pk1['n']
    v = sk_shared['v']
    xt = lift_message(massage_TCH, param['delta'], n)
    quorum = list(range(param['number_parties_total']))

    for i in quorum:
        their_z, their_c = proofs[i]
        #python3.6版本不可以直接pow(x,负数,z)
        sk_shared_inv = inverse(sk_shared['vs'][i], n)
        vp1 = pow_mod(v, their_z, n)
        vp2 = pow_mod( sk_shared_inv, their_c, n)
         #python3.6版本不可以直接pow(x,负数,z)
        sigshares_inv = inverse(TCH_r1_shares[i], n)
        xp1 = pow_mod(xt, their_z, n)
        xp2 = pow_mod(sigshares_inv, 2*their_c, n)

        our_c = hash_transcript(script_version=__version__,
                                param=param,
                                pk1=pk1,
                                party_index=i,
                                v=v,
                                xt=xt,
                                vi=sk_shared['vs'][i],
                                xi2=pow_mod(TCH_r1_shares[i], 2, n),
                                vp=mul_mod(vp1, vp2, n),
                                xp=mul_mod(xp1, xp2, n))
        assert(our_c == their_c)



#6666666666666TCH.combine------------------
def VV_Combine(param, pk1, TCH_r1_shares, h_msg, h_msgPrime, r):
    n = pk1['n']
    e = pk1['e']
    delta = param['delta']
    #Calculate e in the paper
    e_prime = 4 * delta * delta
    (gcd_e_eprime, bezout_a, bezout_b) = extended_gcd(e_prime, e)
    assert(gcd_e_eprime == 1)

    #+++++++++++++++++++++++++++++++++++++++++++++++++++

    # print("gcd_e_eprime:", gcd_e_eprime)
    # print("Computed:", bezout_a*e_prime+bezout_b*e)

    #Calculate \tilde{r} in the paper
    w = 1
    quorum = list(range(1, param['number_parties_needed']+1))
    for i in quorum:
        exponent = 2 * lagrange(quorum, 0, i, delta)
        if exponent >= 0:
            part = pow_mod(TCH_r1_shares[i - 1], exponent, n)
        else:
            # If the exponent is negative, calculate the modular inverse.
            sigshares_inv = inverse(TCH_r1_shares[i - 1], n)
            exponent=-exponent
            part = pow_mod(sigshares_inv, exponent, n)
        w = mul_mod(w, part, n)

    #calculate message_base1-----------------
    m = int.from_bytes(h_msg, byteorder='big')
    mPrime = int.from_bytes(h_msgPrime, byteorder='big')
    temp_hmsg = m
    temp_hmsgPrime = mPrime
    x1 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big')
    x1Prime = int.from_bytes(sha512(str(temp_hmsgPrime).encode()).digest(), byteorder='big')
    y1 = x1 * pow(r, pk1['e'], pk1['n']) % pk1['n']

    x1PrimeInv = inverse(x1Prime,pk1['n'])%pk1['n']

    message_base1=y1*x1PrimeInv%pk1['n']
    
    #w^e=x^{4 * delta * delta}
    #print("pow_mod(w, e, n):", pow_mod(w, e, n))
    #print("pow_mod(message_base1, e_prime, n):", pow_mod(message_base1, e_prime, n))


    assert(pow_mod(w, e, n) == pow_mod(message_base1, e_prime, n))
    #y=w^a*x^b
    if bezout_a >= 0:
         p1 = pow_mod(w, bezout_a, n)
    else:
        # If the bezout_a is negative, calculate the modular inverse.
        sigshares_inv = inverse(w, n)
        bezout_a=-bezout_a
        p1 = pow_mod(sigshares_inv, bezout_a, n)

    #p1 = pow_mod(w, bezout_a, n)

    if bezout_b >= 0:
         p2 = pow_mod(message_base1, bezout_b, n)
    else:
        #  If the bezout_b is negative, calculate the modular inverse.
        message_base_inv = inverse(message_base1, n)
        bezout_b=-bezout_b
        p2 = pow_mod(message_base_inv, bezout_b, n)

    #p2 = pow_mod(message_base1, bezout_b, n)


    # Multiplying p1 and p2 together will yield y.
    signature_recombined = mul_mod(p1, p2, n)
    #++++++++++++++++++++++++
    # print("signature_recombined:", signature_recombined)
    # print("e:", e)
    # print("n:", n)
    # print("Expected:", message)
    # print("pow_mod(signature_recombined, e, n):",pow_mod(signature_recombined, e, n))
    assert(pow_mod(signature_recombined, e, n) == message_base1)
    return signature_recombined


#6666666666666TCH.combine in TPCH------------------

def TCH_Combine(param, pk1, TCH_r1_shares, massage_TCH):
    n = pk1['n']
    e = pk1['e']
    delta = param['delta']
    #Calculate the value of "e" in the paper.
    e_prime = 4 * delta * delta
    (gcd_e_eprime, bezout_a, bezout_b) = extended_gcd(e_prime, e)
    assert(gcd_e_eprime == 1)

    #+++++++++++++++++++++++++++++++++++++++++++++++++++

    # print("gcd_e_eprime:", gcd_e_eprime)
    # print("Computed:", bezout_a*e_prime+bezout_b*e)


    #Calculate \tilde{r} in the paper
    w = 1
    quorum = list(range(1, param['number_parties_needed']+1))
    for i in quorum:
        exponent = 2 * lagrange(quorum, 0, i, delta)
        if exponent >= 0:
            part = pow_mod(TCH_r1_shares[i - 1], exponent, n)
        else:
            # If the exponent is negative, calculate the modular inverse.
            sigshares_inv = inverse(TCH_r1_shares[i - 1], n)
            exponent=-exponent
            part = pow_mod(sigshares_inv, exponent, n)
        w = mul_mod(w, part, n)


    #w^e=x^{4 * delta * delta}
    assert(pow_mod(w, e, n) == pow_mod(massage_TCH, e_prime, n))
    #y=w^a*x^b
    if bezout_a >= 0:
         p1 = pow_mod(w, bezout_a, n)
    else:
        # If the bezout_a is negative, calculate the modular inverse.
        sigshares_inv = inverse(w, n)
        bezout_a=-bezout_a
        p1 = pow_mod(sigshares_inv, bezout_a, n)

    #p1 = pow_mod(w, bezout_a, n)
    #p2 = pow_mod(massage_TCH, bezout_b, n)

    if bezout_b >= 0:
         p2 = pow_mod(massage_TCH, bezout_b, n)
    else:
        # If the bezout_b is negative, calculate the modular inverse.
        massage_TCH_inv = inverse(massage_TCH, n)
        bezout_b=-bezout_b
        p2 = pow_mod(massage_TCH_inv, bezout_b, n)

    # Multiplying p1 and p2 together will yield y.
    signature_recombined = mul_mod(p1, p2, n)
    #++++++++++++++++++++++++
    # print("signature_recombined:", signature_recombined)
    # print("e:", e)
    # print("n:", n)
    # print("Expected:", message)
    # print("pow_mod(signature_recombined, e, n):",pow_mod(signature_recombined, e, n))
    assert(pow_mod(signature_recombined, e, n) == massage_TCH)
    return signature_recombined


def TCH_Hash(pk1,temp_hmsg):
    r1 = random.getrandbits(1024)
    h1 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big') * pow(r1, pk1['e'],pk1['n']) % pk1['n']
    return h1, r1

def test_TCH_algorithms():

    (sk_unshared, pk1) = TCH_setup(param)

    h_msg = b"0123456789"
    h_msgPrime = b"abcdefg"

    #m = int.from_bytes(h_msg, byteorder='big')

    massage_TCH = 15619920774592561628351138998371642294622340518469892832433140464182509560910157

    # 1111111111111TCH_KGen------------------
    print("")
    print("(1) Start testing TCH_KGen-------------------------")
    for _ in range(10):
        start_t = time.time() * time_multiplier

        # Generate of shares of the private key
        sk_shared = TCH_KGen(param, sk_unshared, pk1)
        TCH_KGen_time = round(time.time() * time_multiplier - start_t)
        #print("    - TCH_KGen_time:", (TCH_KGen_time), "ms")
        print((TCH_KGen_time))

    # 22222222222222TCH_Hash------------------
    print("")
    print("(2) Start testing TCH_Hash-------------------------")
    for _ in range(1):
        start_t = time.time() * time_multiplier

        # Generate of shares of the private key
        h1,r1= VV_Hash(pk1, h_msg)
        TCH_Hash_time = round((time.time() * time_multiplier - start_t), 2)
        #print("    - TCH_KGen_time:", (TCH_Hash_time), "ms")   
        print((TCH_Hash_time))


    #3333333333333333TCH_Verify------------------
    print("")
    print("(3) Start testing TCH_Verify-------------------------")
    for _ in range(1):
        start_t = time.time() * time_multiplier

        # Generate shares of DTVDF result y and generate the corresponding proof
        br = VV_Verify(pk1, h_msg, r1, h1)

        TCH_Verify_time = round((time.time() * time_multiplier - start_t), 2)
        #print("    - TCH_Verify_time:", (TCH_Verify_time), "ms")
        print((TCH_Verify_time))
    if (br == 1): 
        print ("Hash: Successful verification.")
    else:
        print ("Hash: Verification failed.")
            

    #444444444444444TCH_ParAdapt------------------
    print("")
    print("(4) Start testing TCH_ParAdapt-------------------------")
    for _ in range(1):
        start_t = time.time() * time_multiplier

        # Generate shares of DTVDF result y and generate the corresponding proof
        (TCH_r1_shares, proofs) = VV_ParAdapt(param,pk1, sk_shared, h_msg, h_msgPrime, r1)

        TCH_ParAdapt_time = round(time.time() * time_multiplier - start_t)
        #print("    - TCH_ParAdapt_time:", (TCH_ParAdapt_time), "ms")
        print((TCH_ParAdapt_time))

    #5555555555555555555TCH_ParVer------------------
    print("")
    print("(5) Start testing TCH_ParVer-------------------------")
    for _ in range(1):
        start_t = time.time() * time_multiplier

        # Verify the proof
        VV_ParVer(param, pk1, sk_shared, proofs, h_msg, h_msgPrime, r1, TCH_r1_shares)
        TCH_ParVer_time = round(time.time() * time_multiplier - start_t)
        #print("    - TCH_ParVer_time:", (TCH_ParVer_time), "ms")
        print((TCH_ParVer_time))

    #6666666666666666666666combine------------------
    print("")
    print("(6) Start testing combine-------------------------")
    for _ in range(10):
        start_t = time.time() * time_multiplier

        # Combine the TCH results r
        TCH_r1_recombined=VV_Combine(param, pk1, TCH_r1_shares, h_msg, h_msgPrime, r1)

        #print("The combined TCH results r:",TCH_r1_recombined)
        combine_time = round((time.time() * time_multiplier - start_t), 2)
        #print("    - combine_time:", (combine_time), "ms")
        print((combine_time))



if __name__ == '__main__':

    # The time difficulty parameter T of DTVDF
    T = 0
    for i in range(1):
        T = 1000 * (i + 1)
        print("")
        print("setting the time difficulty parameter", T)
        test_TCH_algorithms()
        print("OK")
