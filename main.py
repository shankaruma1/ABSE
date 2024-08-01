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

    def search(self, I1, I2, I3, I4, T1, T2, T3, T4):
        """
         This algorithm searches between index and trapdoor
        """

        if debug:
            print('Search algorithm:\n')
        s1 = pair(T3, I4)
        s2 = pair(T1, I2)
        s1 = pair(T4, I3)
        s1 = pair(T2, I1)
        if (s1 * s2) == (s3 * s4):
            return True

    def edge_dec(self, D1, D2, Di1, Di2, C1, C2, Ci2, Ci3):
        """
         This algorithm performs partial decryption at edge node
        """

        if debug:
            print('Edge decryption algorithm:\n')
        ed = C1 ** D1
        ed1 = ed * C2
        abt = self.util.prune(Ci2['policy'], Di1['attr_list'])
        if not abt:
            print ("Policy not satisfied.")
            return None

        for ab in abt:
            attr = ab.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            (c_attr1, c_attr2) = ctxt['C'][attr]
            (k_attr1, k_attr2) = key['K'][attr_stripped]
            ICT = pair(D2, ed1) * pair(k_attr1, c_attr1) / pair(c_attr2, k_attr2)
        return {'ICT':ICT}

    def du_dec(self, ICT, D1, D3, D4):
        """
         This algorithm performs full decryption
        """

        if debug:
            print('user full decryption algorithm:\n')
        fd = D3 ** D1
        fd1 = fd * D4
        wi={}
        abs = self.util.prune(ICT['policy'])
        if not abs:
            print ("Policy not satisfied.")
            return None

        for i in abs:
            attr = i.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            wi = self.group.random(ZR)
            E = pair(fd1, Ci1) ** wi
        F = (C0 * E)/T
        return {'F':F}
    def keysanitycheck(self, D1, D2, D3, D4, Di1, Di2):
         """
         This algorithm checks whether the given secret key is valid or not
        """

        if debug:
            print('key santity check algorithm:\n')
        ks = pp['beta'] * (g1 ** D1)
        kse1 = pair(D2, ks)
        sc = D3 ** D1
        sc1 = sc * D4
        kse2 = pair(sc1, g)
        kse3 = pair(Di2,g)
        kse4 = pair(pp['g_pow_ai', Di1)
        if (kse1 = = kse2) && (kse3 = = kse4):
            return True
    def trace(self, D1):
         """
         This algorithm returns user id
         """

        if debug:
            print('Trace algorithm:\n')
        uid = f.decrept(x)
        return {'uid':uid}
        
