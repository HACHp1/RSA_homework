import re
import random

# 全局变量
meta = {}  # 存储密钥信息
primality_confidence = 20  # 设置置信度
message = []  # 储存明文

messagefile = 'message.txt'
cypher = 'cypher.txt'

pfile = 'p.txt'
qfile = 'q.txt'
nfile = 'n.txt'
efile = 'e.txt'
dfile = 'd.txt'


def bin_pow(a, b, c):  # 平方乘法算法
    out = 1  # 记录结果
    a = a % c
    while (b != 0):
        if (b & 1):  # 取最后一位
            out = (out * a) % c
        b >>= 1  # 去掉最后一位
        a = (a * a) % c
    return out


def miller_rabin_test(n):  # 米勒拉宾素性检验(单步)
    m = n - 1
    k = 0
    while ((m & 1) == 0):
        m >>= 1
        k += 1
    # print(str(n-1)+"=2^"+str(k)+"*"+str(m))
    a = random.randrange(2, n - 1)
    b = bin_pow(a, m, n)
    if b == 1:
        return True
    for i in range(k):
        if b == n - 1:
            return True
        else:
            b = (b * b) % n
    return False


'''
利用素性检验产生大素数，n为上限
'''


def miller_rabin(n, confidence):  # confidence:置信度，越大越有可能为素数
    for i in range(confidence):
        if not miller_rabin_test(n):
            return False
    return True


def Gcd(a, b):  # 辗转相处求最大公因数
    if a < b:
        a, b = b, a  # 交换a、b
    while b != 0:
        a, b = b, (a % b)
    return a


def extendEuclid(a, b):  # 拓展欧几里得求逆元（返回值分别为：1、a在模b下的逆元 2、中间产物 3、最大公因数）
    if b == 0:
        return 1, 0, a
    else:
        x, y, gcd = extendEuclid(b, a % b)
        return y, x - y * (a // b), gcd


def inverse(a, m):  # 利用拓展欧几里得求逆元并处理为正
    x, y, gcd = extendEuclid(a, m)
    if gcd == 1:
        return x % m
    else:
        return None


'''
文件生成、储存密钥
'''


def dumpMeta(filename, e):
    with open(filename, 'w') as f:
        print("%x" % e, file=f)


'''
将生成的整数p、q、n、e、d分别写入文件p.txt、q.txt、n.txt、e.txt、d.txt中。
加密时先分别从指定的明文文件、密钥文件中读取有关信息，然后进行加密，最后将密文写入指定的密文文件。
'''


def dumpAllMeta():
    dumpMeta(pfile, meta['p'])
    dumpMeta(qfile, meta['q'])
    dumpMeta(nfile, meta['n'])
    dumpMeta(efile, meta['e'])
    dumpMeta(dfile, meta['d'])


# 产生密钥 p、q均小于2^512以保证最大的n为1024位

def genKeys():
    # 生成 p
    while 1:
        p = random.randrange(pow(10, 10) + 1, 2 << 512, 2)
        if miller_rabin(p, primality_confidence):
            meta.update({'p': p})
            break
    # 生成 q
    while 1:
        q = random.randrange(pow(10, 10) + 1, 2 << 512, 2)
        if miller_rabin(q, primality_confidence):
            meta.update({'q': q})
            break

    # 计算n: ( p * q )
    modulus = meta['p'] * meta['q']
    meta.update({'n': modulus})

    # 计算φ(n): ( ( p - 1 )( q - 1 ) )
    phi = int((meta['p'] - 1) * (meta['q'] - 1))
    meta.update({'phi': phi})

    # 选择 e 满足 1 < e < φ(n) 并且 e和φ(n)互素
    while 1:
        while 1:
            e = random.randrange(phi)
            if e == 0: continue
            if Gcd(e, phi) == 1:  # 互素
                meta.update({'e': e})
                meta.update({'pub_key': (modulus, e)})
                break

        # 计算 d:
        d = int(inverse(int(meta['e']), phi))
        if d is None:
            continue
        else:
            meta.update({'d': d})
            meta.update({'priv_key': (modulus, d)})
            break
    dumpAllMeta()


'''
读取密钥信息
'''


def loadMeta(filename, kind):
    with open(filename) as f:
        meta[kind] = int(f.readlines()[0], 16)


'''
加载密文/明文文件,64位为一个block
'''


def loadMessage(filename):
    with open(filename, 'r') as f:
        block = f.readline()
        while (block):
            message.append(int(block, 16))
            block = f.readline()  # 16个字符为64位


def encrypt():
    loadMeta(efile, 'e')
    loadMeta(nfile, 'n')
    loadMessage(messagefile)
    block = 0
    with open(cypher, 'w') as f:
        for block in message:
            print("%x" % (bin_pow(block, meta['e'], meta['n'])), file=f)


def decrypt():
    # print('\n\n\ndddddd')
    loadMeta(dfile, 'd')
    loadMeta(nfile, 'n')
    loadMessage(cypher)
    block = 0
    with open(messagefile, 'w') as f:
        for block in message:
            print("%x" % (bin_pow(block, meta['d'], meta['n'])), file=f)


print(
    '''
    ****************************RSA V 1.0****************************
    
     e3rsa -g -p plainfile -n nfile [-e efile] [-d dfile] -c cipherfile 
      参数(注：文件名不加引号)： 
      -g 生成密钥对至文件中
      -p plainfile		指定明文文件的位置和名称
      -n nfile			指定存放整数n的文件的位置和名称
      -e efile			在数据加密时，指定存放整数e的文件的位置和名称
      -d dfile			在数据解密时，指定存放整数d的文件的位置和名称
      -c cipherfile		指定密文文件的位置和名称
      
    *****************************************************************
    请输入命令：
    '''
)

inputText = input()
temp = []

temp = re.findall('-g', inputText)
if (len(temp) != 0):
    genKeys()
    exit(0)
temp = re.findall('-e[\s]+(\S+)', inputText)
if (len(temp) != 0):
    # print('123')
    efile = temp[0]
    temp = re.findall('-p[\s]+(\S+)', inputText)
    if (len(temp) != 0):
        messagefile = temp[0]
    temp = re.findall('-n[\s]+(\S+)', inputText)
    if (len(temp) != 0):
        nfile = temp[0]
    temp = re.findall('-c[\s]+(\S+)', inputText)
    if (len(temp) != 0):
        cypher = temp[0]
    encrypt()

temp = re.findall('-d[\s]+(\S+)', inputText)
if (len(temp) != 0):
    # print('123')
    dfile = temp[0]
    temp = re.findall('-c[\s]+(\S+)', inputText)
    if (len(temp) != 0):
        cypher = temp[0]
    temp = re.findall('-n[\s]+(\S+)', inputText)
    if (len(temp) != 0):
        nfile = temp[0]
    temp = re.findall('-p[\s]+(\S+)', inputText)
    if (len(temp) != 0):
        messagefile = temp[0]
    decrypt()

# 1、实验验证
'''
plaintext=0x63727970746F677261706879
e=0x10001
n=0x73299B42DBD959CDB3FB176BD1
d = 0x63C3264A0BF3A4FC0FF0940935
print ("%x"%bin_pow(plaintext,e,n))
print("%x"%bin_pow(bin_pow(plaintext,e,n),d,n))
'''
# 6326DC198AAE1DB64FDC32D440
