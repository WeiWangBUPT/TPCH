


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

#新加的
from TCH import TCH_Combine, TCH_Hash, TCH_KGen, TCH_ParAdapt_TPCH, TCH_setup, param
from BLS import BLS01


# keys
sig_params = {}
group = None

#N is the number of attributes
def Setup(N):
    # step 1 CP-ABE
    pairing_group = PairingGroup('MNT224')

    # AC17 CP-ABE under DLIN (2-linear), IBS
    cpabe = AC17CPABE(pairing_group, 2)
    bls = BLS01(pairing_group)

    # step 2 run the CP-ABE set up
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


    #step 3新加的 TCH.Setup
    (sk_unshared, pk1) = TCH_setup(param)
    sk_shared = TCH_KGen(param, sk_unshared, pk1)

    #新加返回 sk_unshared, pk1
    return cpabe,  bls, pk, msk, pairing_group, attr_list, sig_params, sk_unshared, pk1, sk_shared

#333333333333333TPCH.USetup/IBS-------------------
def KeyGenIBS(bls,id):
    (public_key, secret_key) = bls.keygen()
    signature_id = bls.sign(secret_key['x'], id)

    return public_key, secret_key, signature_id


#4444444444444444TPCH.UKeyGen-------------------
#新增加输入bls, public_key, signature, messages,
def KeyGenABE(bls, public_key, signature, messages, cpabe, pk, msk, attr_list):

    if bls.verify(public_key, signature, messages) == False:
        return False  
    key = cpabe.keygen(pk, msk, attr_list)
    return key



#pk主公钥，msk主私钥，属性attr_list
def KeyGenCH():
    rsaKey = RSA.generate(2048)
    return rsaKey



def H4(cpabe, m):
    group = cpabe.get_group_obj()
    s1 = group.hash(m+"1", ZR)
    s2 = group.hash(m+"2", ZR)
    return {'s1':s1, 's2':s2}


#新加pk1, bls, secret_key
def Hash(pk1,cpabe,pk,ct_msg, h_msg, policy_str,key, sig_params, bls, secret_key): 
    h=pk['h']
    g = pk['g']
    group = cpabe.get_group_obj()

    # Generate ephemeral trapdoor
    etd_rsaKey = RSA.generate(2048)    
    while (gcd(pk1['n'], etd_rsaKey.n) != 1):
        etd_rsaKey = RSA.generate(2048)
     
    # step 1
    phiN2 = (etd_rsaKey.p-1) * (etd_rsaKey.q-1)
    d2 = inverse(etd_rsaKey.e, phiN2)
    
    # step 2 RSACH
    # r1 = random.getrandbits(1024)
    r2 = random.getrandbits(1024)
    m = int.from_bytes(h_msg, byteorder='big')
    temp_hmsg = m + pk1['n'] + etd_rsaKey.n
    # h1 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big') * pow(r1, rsaKey.e, rsaKey.n) % rsaKey.n
    h2 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big') * pow(r2, etd_rsaKey.e, etd_rsaKey.n) % etd_rsaKey.n
    h1,r1 = TCH_Hash(pk1,temp_hmsg)
    rPrime = [r1, r2]
    hPrime = [h1, h2]

    # step 3 CP-ABE    
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

    # step 4 BLS.Sign
    message = f"{rPrime}_{hPrime}_{m}_{ctxt}"
    signature_hash = bls.sign(secret_key['x'], message)

    #新加signature_hash
    return ctxt, hPrime, rPrime, etd_rsaKey, aes_data, iv, signature_hash

#新加 pk1, bls, public_key, signature, ctxt
def Verify(pk1, etd_rsaKey, h_msg, r, h, bls, public_key, signature, ctxt):
    m = int.from_bytes(h_msg, byteorder='big')
    temp_hmsg = m + pk1['n'] + etd_rsaKey.n
    # print("pk1:", pk1)
    # print("r:", r)
    # print("temp_hmsg:", temp_hmsg)
    h1Prime = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big') * pow(r[0], pk1['e'], pk1['n']) % pk1['n']
    
    #h1Prime = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big') * pow(r[0], rsaKey.e, rsaKey.n) % rsaKey.n
    h2Prime = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big') * pow(r[1], etd_rsaKey.e, etd_rsaKey.n) % etd_rsaKey.n

    #新加bls验证
    messages = f"{r}_{h}_{m}_{ctxt}"

    if (h[0] == h1Prime and h[1] == h2Prime and bls.verify(public_key, signature, messages)==True):
        return 1
    else:
        return 0


#新加param,pk1,TCH_r1_shares,++++++sk_unshared,bls,secret_key
def Adapt(param,pk1,TCH_r1_shares,sk_unshared,cpabe,pk, ctxt, aes_data, iv, h_msg, h_msgPrime, r, key, etd_rsaKey, h_rsa, policy_str, bls, secret_key):
    g = pk['g']
    h = pk['h']
    group = cpabe.get_group_obj()
    
    # step 1 ABE.Dec
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


    # step 3 Adapting

    # m = int.from_bytes(h_msg, byteorder='big')
    # mPrime = int.from_bytes(h_msgPrime, byteorder='big')
    # temp_hmsg = m + rsaKey.n + etd_rsaKey.n
    # temp_hmsgPrime = mPrime + rsaKey.n + etd_rsaKey.n


    m = int.from_bytes(h_msg, byteorder='big')
    mPrime = int.from_bytes(h_msgPrime, byteorder='big')
    temp_hmsg = m + pk1['n'] + etd_rsaKey.n
    temp_hmsgPrime = mPrime + pk1['n'] + etd_rsaKey.n

    x1 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big')
    x1Prime = int.from_bytes(sha512(str(temp_hmsgPrime).encode()).digest(), byteorder='big')
    y1 = x1 * pow(r[0], pk1['e'], pk1['n']) % pk1['n']
    x2 = int.from_bytes(sha512(str(temp_hmsg).encode()).digest(), byteorder='big')
    x2Prime = int.from_bytes(sha512(str(temp_hmsgPrime).encode()).digest(), byteorder='big')
    y2 = x2 * pow(r[1], etd_rsaKey.e, etd_rsaKey.n) % etd_rsaKey.n



    x1PrimeInv = inverse(x1Prime,pk1['n'])%pk1['n']
    message_base1=y1*x1PrimeInv%pk1['n']
    #-------------------------------------------------------------------------
    #print("")
    #print("message_base1", message_base1)
    #Expected_r1Prime = pow(message_base1, sk_unshared['d'], pk1['n'])
    #-------------------------------------------------------------------------
    #print("")
    #print("Expected r1Prime:", Expected_r1Prime)

    
    r1Prime= TCH_Combine(param,
                                                             pk1,
                                                             TCH_r1_shares,
                                                             message_base1)
    r2Prime = pow(y2*inverse(x2Prime,etd_rsaKey.n)%etd_rsaKey.n, etd_rsaKey.d, etd_rsaKey.n)

    

    #-----------------------------------------------------------------------
    # print("")
    # print("Computed r1Prime:", r1Prime)
    # print("r2Prime:", r2Prime)

    # step 4 Compute the two hashes, h1 and h2, and verify if they are correct.
    h1Prime = x1Prime * pow(r1Prime, pk1['e'], pk1['n']) % pk1['n']
    #-----------------------------------------------------------------------
    # print("")
    # print("Expected h1Prime:", h_rsa[0])
    # print("Computed h1Prime:", h1Prime)

    h2Prime = x2Prime * pow(r2Prime, etd_rsaKey.e, etd_rsaKey.n) % etd_rsaKey.n
    if (h1Prime != h_rsa[0] or h2Prime != h_rsa[1]): #fail
        return None

    rPrime = []
    rPrime.append(r1Prime)
    rPrime.append(r2Prime)
    #-----------------------------------------------------------------------
    # step 4 BLS.Sign
    message = f"{rPrime}_{h_rsa}_{mPrime}_{ctxt}"
    signature_adapt = bls.sign(secret_key['x'], message)
    

    return rPrime, signature_adapt



def main():
    #Policy size
    d = 10
    #Test the number of iterations.
    trial = 100
    Test_Setup = False
    Test_KeyGenBLS = False
    Test_KeyGenABE = False
    Test_Hash = False
    Test_Adapt = False
    Test_Verify = True
    Test_All = False

    id ="weiwang@email.com"
    ct_msg = 1034342
    h_msg = b"0123456789"
    h_msgPrime = b"abcdefg"

    # instantiate a bilinear pairing map
    #pairing_group = PairingGroup('MNT224')
    
    # AC17 CP-ABE under DLIN (2-linear)
    #pchba = PCHBA(pairing_group, 2, 10)    # k = 10 (depth of the tree)

    # run the set up
    (cpabe, bls,pk,msk, pairing_group, attr_list, sig_params, sk_unshared, pk1,sk_shared) =Setup(d)

    
    if Test_Setup:
        print ('Testing Setup ...')
        k = 10
        f = open('TPCH_setup.txt', 'w+')
        f.write("("+str(k)+",")
        T=0
        Temp=0
        start = 0
        end = 0
        for i in range(trial):
            start = time.time()
            (cpabe, bls,pk,msk, pairing_group, attr_list, sig_params, sk_unshared, pk1,sk_shared) =Setup(d)
            end = time.time()
            Temp=end - start
            T+=Temp
        T=T/trial
        f.write(str(T) + ")\n")
        f.close()
    # generate a signature_id
    (public_key, secret_key, signature_id) =KeyGenIBS(bls,id)

    if Test_KeyGenBLS:
        print ('Testing KeyGenBLS ...')
        k = 10
        f = open('TPCH_keygenIBS.txt', 'w+')
        #f.write("("+str(k)+",")
        T=0
        Temp=0
        start = 0
        end = 0
        for i in range(trial):
            start = time.time()
            (public_key, secret_key, signature_id) =KeyGenIBS(bls,id)
            end = time.time()
            Temp = (end - start) * 1000
            T+=Temp
        T=T/trial
        #f.write(str(T) + ")\n")
        f.write(str(T) + "\n")
        f.close()

    # generate a key
    key = KeyGenABE(bls, public_key, signature_id, id, cpabe, pk, msk, attr_list)

    if Test_KeyGenABE:
        print ('Testing KeyGenABE ...')
        d=10      # number of attributes
        NN = 100
        
        f = open('TPCH_keygen.txt', 'w+')
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
                key = KeyGenABE(bls, public_key, signature_id, id, cpabe, pk, msk, attr_list)
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

    ctxt, h_rsa, r, etd_rsaKey, aes_data, iv, signature_hash = Hash(pk1,cpabe,pk,ct_msg, h_msg, policy_str,key, sig_params, bls, secret_key) 

    (TCH_r1_shares, proofs)= TCH_ParAdapt_TPCH(param,pk1, sk_shared, h_msg, h_msgPrime, r, etd_rsaKey)
    
    #print("etd_rsaKey=",etd_rsaKey)
    #print("h_rsa=",h_rsa)
    #print("policy_str=",policy_str)
    if Test_Hash:
        print ('Testing Hash ...')
        d=10      # number of attributes
        NN = 100
        f = open('TPCH_hash.txt', 'w+')
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
            key = KeyGenABE(bls, public_key, signature_id, id, cpabe, pk, msk, attr_list)
            rsaKey = KeyGenCH()
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            for i in range(trial):
                m = None
                start = time.time()
                ctxt, h_rsa, r, etd_rsaKey, aes_data, iv, signature_hash = Hash(pk1,cpabe,pk,ct_msg, h_msg, policy_str,key, sig_params, bls, secret_key)
                end = time.time()
                Temp = (end - start) * 1000
                T += Temp
            T = T / trial

            (TCH_r1_shares, proofs)= TCH_ParAdapt_TPCH(param,pk1, sk_shared, h_msg, h_msgPrime, r, etd_rsaKey)
            #f.write(str(T) + ")\n")
            f.write(str(T) + "\n")
            d += 10
        f.close()

    
    if (Verify(pk1, etd_rsaKey, h_msg, r, h_rsa, bls, public_key, signature_hash, ctxt) == 1): 
        print ("Hash: Successful verification.")
    else:
        print ("Hash: Verification failed.")

    if Test_Verify:
        print ('Testing Verify ...')
        d=10      # number of attributes
        NN = 100
        f = open('TPCH_verify.txt', 'w+')
        while d <= NN:
            #f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key = KeyGenABE(bls, public_key, signature_id, id, cpabe, pk, msk, attr_list)
            rsaKey = KeyGenCH()
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            ctxt, h_rsa, r, etd_rsaKey, aes_data, iv, signature_hash = Hash(pk1,cpabe,pk,ct_msg, h_msg, policy_str,key, sig_params, bls, secret_key)

            (TCH_r1_shares, proofs)= TCH_ParAdapt_TPCH(param,pk1, sk_shared, h_msg, h_msgPrime, r, etd_rsaKey)
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                Verify(pk1, etd_rsaKey, h_msg, r, h_rsa, bls, public_key, signature_hash, ctxt)
                end = time.time()
                Temp = (end - start) * 1000
                T += Temp
            T = T / trial
            #f.write(str(T) + ")\n")
            f.write(str(T) + "\n")
            d += 10
        f.close()

    _r, signature_adapt = Adapt(param,pk1,TCH_r1_shares,sk_unshared,cpabe,pk, ctxt, aes_data, iv, h_msg, h_msgPrime, r, key, etd_rsaKey, h_rsa, policy_str, bls, secret_key)

    if Test_Adapt:
        print ('Testing Adapt ...')
        d=10      # number of attributes
        NN = 100
        f = open('TPCH_adapt.txt', 'w+')
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
            key = KeyGenABE(bls, public_key, signature_id, id, cpabe, pk, msk, attr_list)
            rsaKey = KeyGenCH()
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            ctxt, h_rsa, r, etd_rsaKey, aes_data, iv, signature_hash = Hash(pk1,cpabe,pk,ct_msg, h_msg, policy_str,key, sig_params, bls, secret_key)

            (TCH_r1_shares, proofs)= TCH_ParAdapt_TPCH(param,pk1, sk_shared, h_msg, h_msgPrime, r, etd_rsaKey)
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                _r, signature_adapt = Adapt(param,pk1,TCH_r1_shares,sk_unshared,cpabe,pk, ctxt, aes_data, iv, h_msg, h_msgPrime, r, key, etd_rsaKey, h_rsa, policy_str, bls, secret_key)
                end = time.time()
                Temp = (end - start) * 1000
                T += Temp
            T = T / trial
            #f.write(str(T) + ")\n")
            f.write(str(T) + "\n")
            d += 10
        f.close()
    
    #---------------------------------------------------------
    # print("")
    # print("--------------_r:", _r)


    if (Verify(pk1, etd_rsaKey,h_msgPrime, _r, h_rsa, bls, public_key, signature_adapt, ctxt) == 1):
        print ("Adapt: Successful verification.")
    else:
        print ("Adapt: Verification failed.")




if __name__ == "__main__":
    #debug = False
    debug = True
    main()
