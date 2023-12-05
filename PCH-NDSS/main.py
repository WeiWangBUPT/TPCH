from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT,pair
from ac17 import AC17CPABE
from charm.toolbox.ABEnc import ABEnc
import string
from hashlib import sha512
from hashlib import sha256
import time
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import inverse
#from Cryptodome.Util import Padding
import binascii
from math import gcd



# keys
sig_params = {}
group = None


def Setup(N):
    pairing_group = PairingGroup('MNT224')

    # AC17 CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # run the set up
    (pk, msk) = cpabe.setup()
    
    g = pk['g']
    h = pk['h']
    alpha = cpabe.group.random(ZR)
    beta = cpabe.group.random(ZR)
    g_beta = g ** beta
    h_1_alpha = h ** (1/alpha)
    h_beta_alpha = h ** (beta/alpha)
    beta_alpha = beta / alpha
    sig_params = {'g_beta':g_beta, 'h_1_alpha':h_1_alpha, 'h_beta_alpha':h_beta_alpha, 'beta_alpha':beta_alpha}

    attr_list = []
    i = 0
    while i < N:
        attr_list.append(str(i))
        i += 1

    return cpabe,pk,msk, pairing_group, attr_list, sig_params


def KeyGen(cpabe, pk, msk, attr_list):
    key = cpabe.keygen(pk, msk, attr_list)
    rsaKey = RSA.generate(2048)
    
    return key, rsaKey

def H4(cpabe, m):
    group = cpabe.get_group_obj()
    s1 = group.hash(m+"1", ZR)
    s2 = group.hash(m+"2", ZR)
    return {'s1':s1, 's2':s2}


def Hash(cpabe,pk,ct_msg, h_msg, policy_str,key, rsaKey, sig_params):
    h=pk['h']
    g = pk['g']
    group = cpabe.get_group_obj()

    # Generate ephemeral trapdoor
    etd_rsaKey = RSA.generate(2048)    
    while (gcd(rsaKey.n, etd_rsaKey.n) != 1):
        etd_rsaKey = RSA.generate(2048)
     
    # step 1
    phiN2 = (etd_rsaKey.p-1) * (etd_rsaKey.q-1)
    d2 = inverse(etd_rsaKey.e, phiN2)
    
    # step 2 RSACH
    r1 = random.getrandbits(1024)
    r2 = random.getrandbits(1024)
    m = int.from_bytes(h_msg, byteorder='big')
    temp_hmsg = m + rsaKey.n + etd_rsaKey.n
    h1 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big') * pow(r1, rsaKey.e, rsaKey.n) % rsaKey.n
    h2 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big') * pow(r2, etd_rsaKey.e, etd_rsaKey.n) % etd_rsaKey.n
    rPrime = [r1, r2]
    hPrime = [h1, h2]

    # step 3     
    r = random.getrandbits(64)
    
    # AES encryption    
    aesKey = b'1234567890123456' 
    iv = get_random_bytes(16)
    data = d2.to_bytes(2048, 'big')
    cipher = AES.new(aesKey, AES.MODE_CBC, iv)
    aes_data= cipher.encrypt(data)
    K = aesKey + r.to_bytes(8, 'big')
    randomness = H4(cpabe, str(r))
    
    # ABE encryption
    ctxt = cpabe.encrypt(pk, int.from_bytes(K, byteorder='big'), randomness, policy_str)


    return ctxt, hPrime, rPrime, etd_rsaKey, aes_data, iv


def Verify(rsaKey, etd_rsaKey, h_msg, r, h):
    m = int.from_bytes(h_msg, byteorder='big')
    temp_hmsg = m + rsaKey.n + etd_rsaKey.n
    h1Prime = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big') * pow(r[0], rsaKey.e, rsaKey.n) % rsaKey.n
    h2Prime = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big') * pow(r[1], etd_rsaKey.e, etd_rsaKey.n) % etd_rsaKey.n

    if (h[0] == h1Prime and h[1] == h2Prime):
        return 0
    else:
        return 1


def Adapt(cpabe,pk, ctxt, aes_data, iv, h_msg, h_msgPrime, r, key, rsaKey, etd_rsaKey, h_rsa, policy_str):
    g = pk['g']
    h = pk['h']
    group = cpabe.get_group_obj()
    
    # step 1
    data = cpabe.decrypt(pk, ctxt, key)
    Kprime = int(data).to_bytes(16+8, 'big')
    Karray = bytearray(Kprime)
    aesKey = Kprime[0:16]
    rPrime = int.from_bytes(Kprime[16:24], byteorder='big')

    # step 2
    randomness = H4(cpabe, str(rPrime))
    ctxtPrime = cpabe.encrypt(pk, int.from_bytes(Kprime, byteorder='big'), randomness, policy_str)
    if (ctxtPrime != ctxt): # fail
        print('reencryption check failed')
        return None
    cipher = AES.new(aesKey, AES.MODE_CBC, iv)
    data = cipher.decrypt(aes_data)
    d2 = int.from_bytes(data, byteorder='big')

    # step 3
    m = int.from_bytes(h_msg, byteorder='big')
    mPrime = int.from_bytes(h_msgPrime, byteorder='big')
    temp_hmsg = m + rsaKey.n + etd_rsaKey.n
    temp_hmsgPrime = mPrime + rsaKey.n + etd_rsaKey.n
    x1 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big')
    x1Prime = int.from_bytes(sha512(str(temp_hmsgPrime).encode()).digest(), byteorder='big')
    y1 = x1 * pow(r[0], rsaKey.e, rsaKey.n) % rsaKey.n
    x2 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big')
    x2Prime = int.from_bytes(sha512(str(temp_hmsgPrime).encode()).digest(), byteorder='big')
    y2 = x2 * pow(r[1], etd_rsaKey.e, etd_rsaKey.n) % etd_rsaKey.n

    x1PrimeInv = inverse(x1Prime,rsaKey.n)%rsaKey.n
    r1Prime = pow(y1*x1PrimeInv%rsaKey.n, rsaKey.d, rsaKey.n)
    r2Prime = pow(y2*inverse(x2Prime,etd_rsaKey.n)%etd_rsaKey.n, etd_rsaKey.d, etd_rsaKey.n)


    # step 4
    h1Prime = x1Prime * pow(r1Prime, rsaKey.e, rsaKey.n) % rsaKey.n
    h2Prime = x2Prime * pow(r2Prime, etd_rsaKey.e, etd_rsaKey.n) % etd_rsaKey.n
    if (h1Prime != h_rsa[0] or h2Prime != h_rsa[1]): #fail
        return None

    rPrime = []
    rPrime.append(r1Prime)
    rPrime.append(r2Prime)
    return rPrime



def main():
    
    d = 10
    trial = 100
    Test_Setup = False
    Test_KeyGen = False
    Test_Hash = False
    Test_Adapt = True
    Test_Verify = False

    id = 1010
    ct_msg = 1034342
    h_msg = b"0123456789"
    h_msgPrime = b"abcdefg"

    # instantiate a bilinear pairing map
    #pairing_group = PairingGroup('MNT224')
    
    # AC17 CP-ABE under DLIN (2-linear)
    #pchba = PCHBA(pairing_group, 2, 10)    # k = 10 (depth of the tree)

    # run the set up
    (cpabe,pk,msk, pairing_group, attr_list, sig_params) =Setup(d)

    
    if Test_Setup:
        print ('Testing Setup ...')
        k = 10
        f = open('result_setup.txt', 'w+')
        #f.write("("+str(k)+",")
        T=0
        Temp=0
        start = 0
        end = 0
        for i in range(trial):
            start = time.time()
            (cpabe,pk,msk, pairing_group, attr_list, sig_params) =Setup(d)
            end = time.time()
            Temp = (end - start) * 1000
            T+=Temp
        T=T/trial
        #f.write(str(T) + ")\n")
        f.write(str(T) + "\n")
        f.close()

    # generate a key
    key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)

    if Test_KeyGen:
        print ('Testing KeyGen ...')
        d=10      # number of attributes
        NN = 100
        
        f = open('result_keygen.txt', 'w+')
        while d <= NN:
            print (d)
            #f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(d):
                attr_list.append(str(i))
            for i in range(trial):
                start = time.time()
                key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)
                end = time.time()
                Temp = (end - start) * 1000
                T += Temp
            T = T / trial
            #f.write(str(T) + ")\n")
            f.write(str(T) + "\n")
            d += 10
        f.close()

   
    # generate a ciphertext
    policy_str=""
    for j in range(d):
        if j!=d-1:
            policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
        else:
            policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"

    ctxt, h_rsa, r, etd_rsaKey, aes_data, iv = Hash(cpabe,pk,ct_msg, h_msg, policy_str, key, rsaKey, sig_params)

    if Test_Hash:
        print ('Testing Hash ...')
        d=10      # number of attributes
        NN = 100
        f = open('result_hash.txt', 'w+')
        while d <= NN:
            print (d)
            #f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            for i in range(trial):
                m = None
                start = time.time()
                ctxt, h_rsa, r, etd_rsaKey, aes_data, iv = Hash(cpabe,pk,ct_msg, h_msg, policy_str, key, rsaKey, sig_params)
                end = time.time()
                Temp = (end - start) * 1000
                T += Temp
            T = T / trial
            #f.write(str(T) + ")\n")
            f.write(str(T) + "\n")
            d += 10
        f.close()

    if (Verify(rsaKey, etd_rsaKey, h_msg, r, h_rsa) == 0):
        print ("Hash: Successful verification.")
    else:
        print ("Hash: Verification failed.")

    if Test_Verify:
        print ('Testing Verify ...')
        d=10      # number of attributes
        NN = 100
        f = open('result_verify.txt', 'w+')
        while d <= NN:
            #f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            ctxt, h_rsa, r, etd_rsaKey, aes_data, iv = Hash(cpabe,pk,ct_msg, h_msg, policy_str, key, rsaKey, sig_params)
            
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                Verify(rsaKey, etd_rsaKey, h_msg, r, h_rsa)
                end = time.time()
                Temp = (end - start) * 1000
                T += Temp
            T = T / trial
            #f.write(str(T) + ")\n")
            f.write(str(T) + "\n")
            d += 10
        f.close()

    _r = Adapt(cpabe, pk, ctxt, aes_data, iv, h_msg, h_msgPrime, r, key, rsaKey, etd_rsaKey, h_rsa, policy_str)

    if Test_Adapt:
        print ('Testing Adapt ...')
        d=10      # number of attributes
        NN = 100
        f = open('result_adapt.txt', 'w+')
        while d <= NN:
            print (d)
            #f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            ctxt, h_rsa, r, etd_rsaKey, aes_data, iv = Hash(cpabe,pk,ct_msg, h_msg, policy_str, key, rsaKey, sig_params)
            
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                _r = Adapt(cpabe, pk, ctxt, aes_data, iv, h_msg, h_msgPrime, r, key, rsaKey, etd_rsaKey, h_rsa, policy_str)
                end = time.time()
                Temp = (end - start) * 1000
                T += Temp
            T = T / trial
            #f.write(str(T) + ")\n")
            f.write(str(T) + "\n")
            d += 10
        f.close()
    
    if (Verify(rsaKey, etd_rsaKey, h_msgPrime, _r, h_rsa) == 0):
        print ("Adapt: Successful verification.")
    else:
        print ("Adapt: Verification failed.")

    
    '''
    NN = 100
    d=10
    trial=100
    id = 1010
    ct_msg = 1034342
    h_msg = b"0123456789"

    (cpabe,pk,msk, pairing_group, attr_list, sig_params) =Setup(d)
    key, rsaKey = KeyGen(cpabe, pk, msk,attr_list)

    policy_str=""
    for j in range(d):
        if j!=d-1:
            policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
        else:
            policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"

    ctxt, h_rsa, r, etd_rsaKey, aes_data, iv = Hash(cpabe,pk,ct_msg, h_msg, policy_str, key, rsaKey, sig_params)
    print (Verify(rsaKey, etd_rsaKey, h_msg, r, h_rsa))
    h_msgPrime = b"abcdefg"
    h_msgPrime = b"abcdefg"
    _r = Adapt(cpabe, pk, ctxt, aes_data, iv, h_msg, h_msgPrime, r, key, rsaKey, etd_rsaKey, h_rsa, policy_str)
    print (Verify(rsaKey, etd_rsaKey, h_msgPrime, _r, h_rsa))
    '''



if __name__ == "__main__":
    #debug = False
    debug = True
    main()
