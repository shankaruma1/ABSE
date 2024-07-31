from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP
import hashlib
from cryptography.fernet import Fernet
debug = False


class TLABKS(ABEnc):

    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.util = MSP(self.group, verbose)

    def setup(self, U):
        """
        This algorithm generates public parameters and master secret key.
        U is an universal attribute set
        """
        if debug:
            print('Setup algorithm:\n')

        # pick a random elements
        g1 = self.group.random(G1)
        beta = self.group.random(ZR)
        alpha = self.group.random(ZR)
        H = hashlib.sha256()
        p_pow_beta = g1 ** beta
        g_pwr_alpha = g1 ** alpha
        e_pair = pair (g1_alpha, g1)
        g_pwr_a_i={}
        for i in U:
          a_i = self.group.random(ZR)
          g_pwr_a_i = g1 ** a_i
        pp = {'g1': g1, 'p_pow_beta':p_pow_beta, ' g_pwr_alpha': g_pwr_alpha, 'g_pwr_a_i':g_pwr_a_i, 'e_pair':e_pair}
        msk = {'alpha':alpha, 'beta': beta}
        return pp, msk

    def keygen(self, pp, msk, uid, attr_list):
        """
        Generate a sectrt key for given set of attributes.
        """

        if debug:
            print('Key generation algorithm:\n')
        key = Fernet.generate_key()
        in_key = Fernet(key) 
        x = f.encrypt(uid) #user id uid is encrypted with a symmetric key k
        n1 = self.group.random(ZR)
        n2 = self.group.random(ZR)
        D1 = x
        beta_inverse = 1 / msk['beta']
        beta_inversex =  beta_inverse * x
        D2 = g1 ** (msk['alpha'] * beta_inversex)
        D3 = g1 ** n1
        D4 = pp['p_pow_beta'] * n1
    
        D = {}
        for attr in attr_list:
            Di1 = g1 ** n2
            Di2 = pp['g_pwr_a_i'] ** n2  
            D[attr] = (Di1, Di2)

        return {'attr_list': attr_list, 'D1': D1, 'D2': D2, 'D3': D3, 'D4': D4, 'D': D}

    def do_enc(self, pp, F, policy_str):
        """
         Encrypt a file F under a policy string. This is an intermediate encryption stage
        """

        if debug:
            print('Encryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        u = []
        for i in range(num_cols):
            rand = self.group.random(ZR)
            u.append(rand)
        s = u[0]    # shared secret

        c0 = F * (pp['g_pwr_alpha'] ** s)
        c1 = g1 ** s
        c2 = pp['beta'] ** s
      
        Xi = {}
        for attr, row in mono_span_prog.items():
            cols = len(row)
            sum = 0
            for i in range(cols):
                Xi += row[i] * u[i]
          ICT = {}
          ICT = (c0,c1,c2,)
         
          return {'policy': policy, 'ICT': ICT, 'Xi': Xi}
    
    def edge-enc(self, PP, ICT, Xi):
        """
        performs full encryption at edge device
        """
          for attr, row in mono_span_prog.items():
            cc = self.group.random(ZR)
            c_i1 = g1 ** Xi
            c_i2 = pp['g_pwr_a_i'] ** cc
            c_i3 = g1 ** cc
          
        return {'ICT': ICT, 'c_i1':c_i1, 'c_i2':c_i2, 'c_i3':c_i3}
    def IndexGen(self, PP, KW):
      """
      This algorithm generates encrypted index
      """
      t1 = self.group.random(ZR)
      t2 = self.group.random(ZR)
      I2 = g1 ** t1
      I3 = g1 ** t2
      I4 = pp['beta'] ** t2
      I1 = {}
      for kw in KW:
        hs = self.group.hash(kw, G1)
        I1 = pp['beta'] ** (hs * t1)
      return {'I1':I1, 'I2':I2, 'I3':I3, 'I4':I4}
    def trapgen(self, KWprime, D1, D3, D4):
      u = self.group.random(ZR)
      T2 = g1 ** u
      T3 = D3 ** u
      T4 = D4 ** u
      T1 ={}
      for kw in KWprime:
         hs = self.group.hash(kw, G1)
         T1 =pp['beta'] ** (hs * u)
      return {'T1':T1, 'T2':T2, 'T3':T3, 'T4':T4}



    def decrypt(self, pk, ctxt, key):
        """
         Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')

        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prod = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            (c_attr1, c_attr2) = ctxt['C'][attr]
            (k_attr1, k_attr2) = key['K'][attr_stripped]
            prod *= (pair(k_attr1, c_attr1) / pair(c_attr2, k_attr2))

        return (ctxt['c_m'] * prod) / (pair(key['k0'], ctxt['c0']))
