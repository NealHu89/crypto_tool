import os
import sys
from gmssl import sm3, func ,sm2
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import base64
import binascii
#from general import KeyClass
sys.path.append(os.path.dirname(os.path.abspath(__file__))) 
from gmssl.func import xor, bytes_to_list, list_to_bytes

class SMUsageError(Exception):
    pass

class SM2Public():
    def __init__(self, public_key):
        #Use encrypt API,only need public key
        self.public_key = public_key.hex()
        self.private_key = None
        self.sm2_crypt = sm2.CryptSM2(
            public_key=self.public_key, private_key=self.private_key)

    def verify_with_sm3(self, signature, data):
        signature = signature.hex()
        return self.sm2_crypt.verify(signature, data)

    def encrypt(self, payload):
        #数据和加密后数据为bytes类型
        enc_data = self.sm2_crypt.encrypt((payload))
        return enc_data
    def _sm3_z(self, data):
        """
        SM3WITHSM2 签名规则:  SM2.sign(SM3(Z+MSG)，PrivateKey)
        其中: z = Hash256(Len(ID) + ID + a + b + xG + yG + xA + yA)
        """
        # sm3withsm2 的 z 值
        z = '0080'+'31323334353637383132333435363738' + \
            self.sm2_crypt.ecc_table['a'] + self.sm2_crypt.ecc_table['b'] + self.sm2_crypt.ecc_table['g'] + \
            self.sm2_crypt.public_key
        z = binascii.a2b_hex(z)
        #print(len(z))
        #dump(z)
        Za = sm3.sm3_hash(func.bytes_to_list(z))
        M_ = (Za + data.hex()).encode('utf-8')
        e = sm3.sm3_hash(func.bytes_to_list(binascii.a2b_hex(M_)))
        return e

    def verify_digest(self, sign, data):
        sign_data = binascii.a2b_hex(self._sm3_z(data).encode('utf-8'))
        ret = self.verify_with_sm3(sign, sign_data)
        if ret == False:
            raise ValueError("Invalid digest!")
        return ret

    def enc_tlv(self):
        return"ENCSM2"

    def sig_tlv(self):
        return"SM2"

    def export_public(self, path):
        """Write the public key to the given file."""
        if "sm" not in path or "pub" not in path:
          print("path need contains 'sm' and 'pub'!!!")
          exit(1)
        else:
          with open(path, 'wb') as f:
              #encode:bytes -> base64
              #print("export key " + str(self.key))
              b64data = base64.b64encode(bytes.fromhex(self.public_key))
              f.write(b64data)
              f.close
        return None

    def get_public_bytes(self):
        return bytes.fromhex(self.public_key)

    def get_bytes(self, minimal):
        pub = bytes.fromhex(self.public_key)
        #FIX what's mean minimal
        #if minimal:
        #    priv = self._build_minimal_rsa_privkey(priv)
        return pub

class SM2Private(SM2Public):
    def __init__(self, private_key):
        self.private_key = private_key.hex()
        #Get the pubkey from pri key
        self.public_key = self.get_public_bytes().hex()
        self.sm2_crypt = sm2.CryptSM2(
            public_key=self.public_key, private_key=self.private_key)
    def sign_with_sm3(self, payload, random_hex_str = None):
        if random_hex_str is None:
            random_hex_str = func.random_hex(self.sm2_crypt.para_len)
            #print((random_hex_str))
        sign = self.sm2_crypt.sign(payload, random_hex_str) #  16进制
        return bytes.fromhex(sign)
    #DEBUG if need verify and encrypt,set pubkey

    def decrypt(self, payload):
        dec_data =self.sm2_crypt.decrypt(payload)
        return dec_data

    def sign_digest(self, data, random_hex_str=None):
        sign_data = binascii.a2b_hex(self._sm3_z(data).encode('utf-8'))
        if random_hex_str is None:
            random_hex_str = func.random_hex(self.sm2_crypt.para_len)
        sign = self.sign_with_sm3(sign_data, random_hex_str)  # 16进制
        return sign

    @staticmethod
    def generate_private_key(path):
        if "sm" not in path or "pri" not in path:
          print("path contains sm and pri!!!")
          exit(1)
        else:
          key = os.urandom(32)
          with open(path, 'wb') as f:
              #encode:bytes -> base64
              #print("export key " + str(self.key))
              b64data = base64.b64encode(key)
              f.write(b64data)
              f.close

    def export_public(self, path):
        """Write the public key to the given file."""
        if "sm" not in path or "pub" not in path:
          print("path need contains 'sm' and 'pri'!!!")
          exit(1)
        else:
          with open(path, 'wb') as f:
              #encode:bytes -> base64
              #print("export key " + str(self.key))
              b64data = base64.b64encode(bytes.fromhex(self.public_key))
              f.write(b64data)
              f.close
        return None

    def get_public_bytes(self):
        k_int = int(self.private_key, 16)
        sm2_temp = sm2.CryptSM2(
            public_key=None, private_key=self.private_key)
        self.public_key = sm2_temp._kg(k_int, sm2_temp.ecc_table['g'])
        return bytes.fromhex(self.public_key)
        
    def get_bytes(self, minimal):
        priv = bytes.fromhex(self.private_key)
        #FIX what's mean minimal
        #if minimal:
        #    priv = self._build_minimal_rsa_privkey(priv)
        return priv

class SM4_CTR():
    def __init__(self, key):
        self.key = key
        self.iv = bytes([0]*16) #  bytes类型
        self.crypt_sm4 = CryptSM4()

    def setiv(self, iv):
        self.iv = iv

    def encrypt(self, plaintext):
        self.crypt_sm4.set_key(self.key, SM4_ENCRYPT)
        encrypt_value = self.crypt_ctr(self.iv , plaintext)
        return encrypt_value
    
    def decrypt(self, ciphertext):
        #SM4-CTR decrypt same with encrypt
        self.crypt_sm4.set_key(self.key, SM4_ENCRYPT)
        decrypt_value = self.crypt_ctr(self.iv , ciphertext) #  bytes类型
        return decrypt_value

    def enc_tlv(self):
        return"SM4"

    def add_iv(self,iv):
        #iv: 计时器初值
        #msgLen: 密文长度(明文)
        output = iv
        iv_int = int.from_bytes(iv, 'big')
        iv_int +=1
        output = iv_int.to_bytes(16, 'big')
        return output

    def crypt_ctr(self, iv, input_data):
        #SM4-CTR buffer encryption/decryption
        i = 0
        output_data = []
        tmp_input = [0]*16

        if self.crypt_sm4.mode == SM4_ENCRYPT:
            #print('before padding ' + str(len(bytes_to_list(input_data))))
            totalLen = length = len(input_data)
            input_data = bytes_to_list(input_data)
            #print('after padding ' + str(length))
            while length > 0:
                #do block cipher
                tmp_input = self.crypt_sm4.one_round(self.crypt_sm4.sk, iv[0:16])
                #xor
                output_data += xor(tmp_input[0:16], input_data[i:i+16])
                #add counter in loop
                iv = self.add_iv(iv)
                i += 16
                length -= 16
            return list_to_bytes(output_data)
        else:
            #print('before padding ' + str(len(bytes_to_list(input_data))))
            totalLen = length = len(input_data)
            input_data = bytes_to_list(input_data)
            #print('after padding ' + str(length))
            while length > 0:
                #do block cipher
                tmp_input = self.crypt_sm4.one_round(self.crypt_sm4.sk, iv[0:16])
                #xor
                output_data += xor(tmp_input[0:16], input_data[i:i+16])
                #add counter in loop
                iv = self.add_iv(iv)
                i += 16
                length -= 16
            return list_to_bytes(output_data)


class SM3():
    @staticmethod
    def hash(context):
        hash = (sm3.sm3_hash(func.bytes_to_list(context)))
        return bytes.fromhex(hash)

def b64tobytes(text):
    return base64.b64decode(text)
def bytesTob64(text):
    return base64.b64encode(text)

def ByteToHex( bins ):
    return bytes(bins).hex()

def HexToByte( hex ):
    return bytes.fromhex(hex)

def dump(encoded_bytes, len_format=None):
    for count, b in enumerate(encoded_bytes):
        print("0x{:02x},".format(b),end='')
        if (count + 1) % 16 == 0:
            print("\n" ,end='' )
        else:
            print(" ",end='')
    print('')

def SM_TEST():
    #private_key = 'AD28A4ADC6CCAD828D05D9B2BDCDBA81F9E77BAF332F4EF8DAD56F518303524F'
    #public_key = '1347694BD9F10724C17F7E5FA96C6EA39178DB38EDA462A7C637415606F46602368B63533EEA6BC5EF8EB086C89E6C3CAFE437DD4E148608E416B1EF92B436D8'
    #debug
    import pdb
    pdb.set_trace()
    private_key=HexToByte('ad28a4adc6ccad828d05d9b2bdcdba81f9e77baf332f4ef8dad56f518303524f')
    public_key=HexToByte('1347694bd9f10724c17f7e5fa96c6ea39178db38eda462a7c637415606f46602368b63533eea6bc5ef8eb086c89e6c3cafe437dd4e148608e416b1ef92b436d8')

    print('SM2 private_key:')
    print(base64.b64encode(private_key))
    dump((private_key))
    print('SM2 public_key:')
    print(base64.b64encode(public_key))
    dump((public_key))
    sm2_pri = SM2Private(private_key) 
    sm2_pub = SM2Public(public_key)
    #context = b'cmiot test encrypt and sign now'
    context = bytes.fromhex('22 b9 80 b5 1b a4 5d f0 e1 2a 41 b7 4c b5 2a ad')
    print('========================TEST SM2======================================')
    print('context: ')
    print(context.hex())
    dump(context)
    hash = SM3.hash(context)
    print('sm3 hash: ')
    print(hash.hex())
    dump(hash)
    sig = sm2_pri.sign_digest(hash)
    print('sm2 sign hash: ')
    print( base64.b64encode(sig))
    dump(sig)
    print('sm2 verify sig: ')
    ret = sm2_pub.verify_digest(sig, hash)
    print(ret)
    print('sm2 encrypt: ')
    enc = sm2_pub.encrypt(hash)
    dump(enc)
    print('sm2 decrypt: ')
    dec = sm2_pri.decrypt(enc)
    dump(dec)

    print('=========================TEST SM4-CTR==================================')
    key = bytes.fromhex('22b980b51ba45df0e12a41b74cb52aad')
    context = bytes.fromhex('308204a40201000282010100b42614493d16133a6d9c84a98b6a102061ef4804a44b24f30032ac22e030277018e555c8b8053403b0f8a596d24858ef70b009dbe35862ef996301b289c4b3f69e62bf4dc28ad0c94d43a3d8e51dec626308e220a5fc78d03e74c8a41b36ad7bf506ae4d519b40ce304f6ceaf9e974ea06ee9ce4146820b93de711148b25a3ff4c8af353ee6b3eef34cd6a3f6268c0ff784cb0c3e69661fc1f18f17a82e28f35a82b8616a446fbac7e41db0205916ddfc1de13959cf99e5e72baa72593fbdce8ab864588472dedeeee979ece5d9b0404407ccb7c3d2c74aba4cc64a35c953dd4a2dc92b2c818cbf90039818f8f40c2df9929ac8ac23bd8a4f2adaf74c011c7990203010001028201004247804f31da5d58b1db5433ccc74907a100984e9ce3c8c45ede45d6cf04e87da5ab3ad48e5fdbb33ff93b73320acc2dcc17f8889e2c76ba10850caad3653b9110d4e3ed8815ea9b25822d562f75c2f2afdd24d53e3c957688840f0dd1b55c3eaef7b6495c2cf2bae9ab4f37649b3018aa544004ea3d254d0229716f4d829bc3442a9d0c98d3c8150d04936030c75e79ea539dc00e81ac90bc9e1ed2280f10f51fdf387f8a908d49077d78cba7ef926d3b13959bba83c6b3712527079954823decc5f8b4a0387a596a0bca696c17a418e0b4aa89998fcb7134091b6ee68700b5ba708a293d9a06182d665e6137ebdd5ec828920530fdb865b17fbf2d551291c102818100da65da387c18fb001160eb3765b8836288c43a4e646af33e4ec034198acb4aca2f5d507aacf79e875afc4d49d7f921f50b6f57413d8fb8ec7fcc9209bed3a4c31485215d05a3aa20f6624450035e534acd6ab6658e4e4b3f25c61631f599137742dadc704d65b0990fdf5ab145f0b98ea0ae4f4d650984b53829bf69e0881f2702818100d32a59ec28c30d4f9296ca6794fc2ea68668455392cc867f8ae15de81d9ebb1e00261d8012ff9c110abda6c38d48dafc10f77a160715a03ad394fb528739eee7c4264916c6c08325bf6a4e8c0b108566ab7eaeac4c693c44ebcde9f6648b4ad86a4d6d47a9b85572c1fdf4814c66be49f2754f80f12038b86a1b7541300f1b3f0281800935fa7a1f61be5446675c043e1a061085cc20d9658acd2f778acba7b81ed2ccac2ab756352d4c5651140afe6e4967913a263bfbd868d357c61c0e9cb29ba27b47c6459df2baf055eb8e416b4e790ff23bafa079b002c551a87a2e3d752a3b93f011e2f229917c5d383a274d0ab21861578d8272b52c2d98a701bbbcef674e4902818100b2705354708d82adff1d55247a8d2f8ea07d7437cf10ed86d180e7adc179e47cd17b63ea5a238d6a093d81b235ad9efeea07762f2f056344d28e4e61cacb75ca7bc22e7904b2a12040c44063aee5e314834ea5a40b5dd2041b8f0169a844dc964c1de97e6938cf5c0df9dfa7733c4f0885ce03c4ddfd7070c59936584398405902818100d5aafbec8dc6ddfa2b5a24d0da58bd87921a2962131d4b791bbe797dad79ca1775dae832e8a09ea87753ac38d6ebe62265c4aa4cc8d0331a1ebebd73094afa855cf30c9c815630a7f79bf4929c6b936a0033dc2f541e78d497ec24a2db3d033309b22c030540de52f29bfa008d4bfe5b9b9c73adfb7a0042629ea09555503287')
    crypt_sm4 = SM4_CTR(key)
    encrypt_value = crypt_sm4.encrypt(context)
    print('enc : ')
    dump(encrypt_value)

    dec_value = crypt_sm4.decrypt(encrypt_value)
    print('dec : ')
    dump(dec_value)
