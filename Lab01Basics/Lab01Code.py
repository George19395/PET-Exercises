#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py

###########################
# Group Members: TODO
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can
#           be imported.

import petlib

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher

def encrypt_message(K, message):
    """ Encrypt a message under a key K """

    plaintext = message.encode("utf8")
    aes= Cipher.aes_128_gcm()   ## intialise aes gcm cipher
    iv = urandom(16)            ## Generate random IV of length 16


    ciphertext,tag = aes.quick_gcm_enc(K,iv,plaintext)   ## produce cipher and tag using the encryption function provided
    ## YOUR CODE HERE

    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K

        In case the decryption fails, throw an exception.
    """
    ## YOUR CODE HERE
    aes= Cipher.aes_128_gcm()                       #Intialise Advanced encryption standart
    plain = aes.quick_gcm_dec(K,iv,ciphertext,tag)  # produce the plaintext using decryption function given using the arguments of the function

    return plain.encode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) \
           or (x == None and y == None)

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = (x*x*x + a*x + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """

    # ADD YOUR CODE BELOW
    xr, yr = None, None

    if not (is_point_on_curve(a,b,p,x0,y0) and is_point_on_curve(a,b,p,x1,y1)): ## check if points not on curve and throw exception
        raise Exception("EC Points are not on curve")

    if x0 is None and y0 is None:                                               ## if one point is infinity then return the other point
        xr,yr=x1,y1
    elif x1 is None and y1 is None:
        xr,yr=x0,y0
    elif x0 == x1 and y0==y1 :                                                  ## if points are equal then raise exception as this will be handled in next function
        raise Exception("EC Points must not be equal")
    elif x0==x1 and y0==y1.mod_mul(-1,p):                                       ##if point 2 is the inverse of point 1 the return infinite
        xr,yr=None,None
    else:

        lam = ((y1-y0) * (x1-x0).mod_inverse(p)) % p                              ##otherwise we calculate the new coordinates of the new point
        xr  = ((lam*lam) - x0 - x1) % p
        yr  = (lam * (x0 - xr) - y0) % p

    return xr,yr

def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """
    xr, yr = None, None
    # ADD YOUR CODE BELOW
    if x is None and y is None:
        xr,yr = None,None
    else:
        lam = ((3*(x*x) + a) * (2*y).mod_inverse(p))%p                              ## the special case of point doubling which we raised an exception on the previous
        xr  = ((lam**2) - 2*x)%p                                                    ## function is handled here with a sleight variation of the algorithm
        yr  = ((lam * (x - xr)) - y)%p

    return xr, yr

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    Q = (None, None)
    P = (x, y)
    for i in range(scalar.num_bits()):                                          ## scalar multiplication use our 2 previous functions
#        pass ## ADD YOUR CODE HEre                                             ## adding a point n times to it selve
        if scalar.is_bit_set(i) ==1:
            Q = point_add(a,b,p,Q[0],Q[1],P[0],P[1])                            ## if bit i is set to 1 we add P to Q
        P= point_double(a,b,p,P[0],P[1])                                            ## then we just double point P

    return Q

def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """
    R0 = (None, None)
    R1 = (x, y)

    for i in reversed(range(0,scalar.num_bits())):                              ### optimised version of the scalar multiplication
#        pass ## ADD YOUR CODE HERE                                             ### implemented the algorithm provided above
        if scalar.is_bit_set(i) ==0:
            R1= point_add(a,b,p,R0[0],R0[1],R1[0],R1[1])
            R0=point_double(a,b,p,R0[0],R0[1])
        else:
            R0 = point_add(a,b,p,R0[0],R0[1],R1[0],R1[1])
            R1=point_double(a,b,p,R1[0],R1[1])
    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification
#            using petlib.ecdsa

from hashlib import sha256
from petlib.ec import EcGroup, EcPt
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
import petlib.ec

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest()                                             ## implementng a signature scheme
                                                                                    ## hash the message and get the digest code(hash function as binary string)
    sig = do_ecdsa_sign(G,priv_sign,digest)                                         ## sign the message
    return sig

def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest()                                         #prdouce hash function as binary string

    res = do_ecdsa_verify(G,pub_verify,sig,digest)                              # verify  by applying the verification function
    return res

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE:

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)


def dh_encrypt(pub, message, aliceSig = None):
    """ Assume you know the public key of someone else (Bob),
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.
    """

    ## YOUR CODE HERE
    gene, priv_key, pub_key = dh_get_key()                                          #allice generates her keys

    K = pub.pt_mul(priv_key)                                                        ## produce shared key using BoBs publick key and alices private key
                                                                                    #(multipy using function from the petlib library)

    len_str_k = str(K)[:16]                                                     #first 16 bytes of string as it is required by encryption scheme to use 16 bytes

    iv,cipher,tag = encrypt_message(len_str_k,message)                          ## use function from exercise 2 to encrypt
    ciphertext =pub_key, iv, cipher, tag
    return ciphertext                                                           ## return ciphertext as a tuple of 4 including alices public key
    pass

def dh_decrypt(priv, c, aliceVer = None):
    """ Decrypt a received message encrypted using your public key,
    of which the private key is provided. Optionally verify
    the message came from Alice using her verification key."""
#    iv,cipher,tag,pub_e=ciphertext

    ## YOUR CODE HERE
    K=c[0].pt_mul(priv)                                                         ## Bobs in this case will use alices public key and his private key to produce the shared key
    len_str_k=str(K)[:16]                                                       ## gets first 16 byts of the string of the key as the decryption fucntion required
    plaintext = decrypt_message(len_str_k,c[1],c[2],c[3])                       ## produce the plaintext using function from task 2
    return plaintext


## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py
G,Pr,P=dh_get_key()
def test_encrypt():                                                             ## used the tests from task2 as guidine to create tests for task 5 which check if the
    message= u"Hello World"                                                     ## implemention of task 5 is correct

    pub_key,iv,cipher,tag = dh_encrypt(P,message,None)
    assert True
    assert len(iv) == 16
    assert len(cipher)==len(message)
    assert len(tag) == 16

def test_decrypt():
    message= u"Hello World"
    ciphertext = dh_encrypt(P,message)
    assert dh_decrypt(Pr,ciphertext) == message

def test_fails():
    from pytest import raises

    from os import urandom
    message = u"Hello World!"
    ciphertext= dh_encrypt(P,message)
    Pub,iv,cipher,tag=ciphertext

    cipher1 = urandom(len(cipher))
    ciphertext1=Pub,iv,cipher1,tag
    with raises(Exception) as excinfo:
        dh_decrypt(Pr, ciphertext1)
    assert 'decryption failed' in str(excinfo.value)

    tag1= urandom(len(tag))
    ciphertext2=Pub,iv,cipher,tag1
    with raises(Exception) as excinfo:
        dh_decrypt(Pr,ciphertext2)
    assert 'decryption failed' in str(excinfo.value)

    iv1= urandom(len(iv))
    ciphertext3 = Pub,iv1,cipher,tag
    with raises(Exception) as excinfo:
        dh_decrypt(Pr,ciphertext3)
    assert 'decryption failed' in str(excinfo.value)


#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.

def time_scalar_mul():
    pass
