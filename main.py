from charm.toolbox.pairinggroup import PairingGroup, GT
from TLABKS.algo import TLABKS01


def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')

    cpabe = TLABKS01(pairing_group, 2)

    # initiates setup algorithm
    (pp, msk) = cpabe.setup()

    # generate a key
    attr_list = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX']
    uid = random.random()
    sk = cpabe.keygen(pp, msk, uid, attr_list)

    # choose a random message
    f = pairing_group.random(GT)

    # generate a  intermediate ciphertext
    policy_str = '((ONE and THREE) and (TWO OR FOUR) OR (FIVE and SIX))'
    ict = cpabe.do_enc(pp, f, policy_str)

    # generate full ciphertext
    ct = cpabe.edge_enc(pp, ict)
    kw = {k1, k2, k3, k4, k5, k6, k7, k8, k9, k10}
    
    #index generation
    I = cpabe.indexgen(pp,kw)

    kwprime = {k3, k5}
    #trapdoor generation
    T = cpabe.trapgen(sk,kwprime)
    
    #initiating search algorithm
    res = None
    res = search(I,T)
    
    # partial decryption at edge node
    t = cpabe.edge_dec(sk,ict)
    
    # full decryption
    f1 = cpabe.du_dec(t,sk)
    if debug:
        if f1 == f:
            print ("Successful decryption.")
        else:
            print ("Decryption failed.")
    #key sanity check
    res = keysanitycheck(sk)

    #trace
    uid = trace(sk)


if __name__ == "__main__":
    debug = False
    main()
