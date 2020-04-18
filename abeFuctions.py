from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair,extract_key
from charm.core.math.pairing import pc_element
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
from Crypto import Random
from  charm.schemes.abenc.abenc_maabe_yj14 import MAABE as CP_ABE
import json
import sys
import getopt
import base64
import chardet


groupObj = PairingGroup('SS512')
cp_abe = CP_ABE(groupObj)

class AesEncryption(object):
    def __init__(self, key, mode=AES.MODE_CFB):
        self.key = self.check_key(key)
        # 密钥key长度必须为16,24或者32bytes的长度
        self.mode = mode
        self.iv =b'\xf7\xd1@\x04\xe4\xc9\ryLb\xa6U\x94\xb2c\xc6'

    def check_key(self, key):
        '检测key的长度是否为16,24或者32bytes的长度'
        try:
            if isinstance(key, bytes):
                assert len(key) in [16, 24, 32]
                return key
            elif isinstance(key, str):
                assert len(key.encode()) in [16, 24, 32]
                return key.encode()
            else:
                raise Exception(f'密钥必须为str或bytes,不能为{type(key)}')
        except AssertionError:
            print('输入的长度不正确')

    def check_data(self, data):
        '检测加密的数据类型'
        if isinstance(data, str):
            data = data.encode()
        elif isinstance(data, bytes):
            pass
        else:
            raise Exception(f'加密的数据必须为str或bytes,不能为{type(data)}')
        return data

    def encrypt(self, data):
        ' 加密函数 '
        data = self.check_data(data)
        cryptor = AES.new(self.key, self.mode, self.iv)
        return b2a_hex(cryptor.encrypt(data)).decode()

    def decrypt(self, data):
        ' 解密函数 '
        data = self.check_data(data)
        cryptor = AES.new(self.key, self.mode, self.iv)
        return cryptor.decrypt(a2b_hex(data)).decode()

def CAstup():
    GPP, GMK = cp_abe.setup()
    result={
        'GPP':GPP2Json(GPP),
        'GMK':GMK2Json(GMK)
    }
    return result

def AAstup(GPP, authorityId, attributes):
    GPP = json2GPP(GPP)
    attributes =json.loads(attributes)
    authorities={}
    cp_abe.setupAuthority(GPP, authorityId, attributes, authorities)
    return authorities2Json(authorities)

def userRegister(GPP,userId):
    GPP = json2GPP(GPP)
    publicUserData = {}
    user = { 'id': userId, 'authoritySecretKeys': {}, 'keys': None }
    user['keys'], publicUserData[user['id']] = cp_abe.registerUser(GPP)
    user['contentKey']=''
    res={
        'privateData':privateUser2Json(user),
        'publicData':publicUser2Json(publicUserData),
    }
    return json.dumps(res)

def keyGen(GPP,authorities,authorityId,attributes,user,publicUserData):
    GPP = json2GPP(GPP)
    authorityAttributes = json.loads(attributes)
    authorities = json2Authorities(authorities)
    publicUserData = json2PublicUser(publicUserData)
    user = json2PrivateUser(user)
    user['authoritySecretKeys']={}
    for attr in authorityAttributes:
        cp_abe.keygen(GPP, authorities[authorityId], attr, publicUserData[user['id']], user['authoritySecretKeys'])
    contentKey = groupObj.random(GT)
    user['contentKey']=contentKey
    res={
        'publicData':publicUser2Json(publicUserData),
        'privateData':privateUser2Json(user),
    }
    return json.dumps(res)

def encrypt(GPP, data, policy_str, authorities, authorityId, user):
    GPP = json2GPP(GPP)
    authorities = json2Authorities(authorities)
    user = json2PrivateUser(user)
    contentKey = user['contentKey']
    encryptedKey = cp_abe.encrypt(GPP, policy_str, contentKey, authorities[authorityId])
    symmetricKey = extract_key(contentKey)
    aes = AesEncryption(symmetricKey)
    encryptedData = aes.encrypt(str.encode(data))
    CT={
        'encryptedKey' :encryptedKey,
        'encryptedData':encryptedData
    }
    return CT2Json(CT)

def decrypt(GPP, user, CT):
    GPP = json2GPP(GPP)
    user = json2PrivateUser(user)
    CT = json2CT(CT)
    encryptedKey = CT['encryptedKey']
    encryptData  = CT['encryptedData']
    contentKey = cp_abe.decrypt(GPP, encryptedKey, user)
    symmetricKey = extract_key(contentKey)
    aes = AesEncryption(symmetricKey)
    data = aes.decrypt(encryptData)
    return data

def ukyeGen(GPP, authorities, authorityId,revokedMap,UKsVersion, UKcVersion):
    GPP = json2GPP(GPP)
    authorities = json2Authorities(authorities)
    UKsVersion = json2UKsVersion(UKsVersion)
    UKcVersion = json2UKcVersion(UKcVersion)
    oneVersion4UKs = dict()
    oneVersion4UKc = dict()
    for (attr, users) in revokedMap.items():
        UK = cp_abe.ukeygen(GPP, authorities[authorityId], attr, users)
        oneVersion4UKc[attr]=UK['UKc']
        for (userId,uks) in UK['UKs'].items():
            if userId not in oneVersion4UKs.keys():
                oneVersion4UKs[userId]={}
            oneVersion4UKs[userId][attr]=uks
    UKcVersion.append(oneVersion4UKc)
    keys=UKsVersion.keys();
    for(userId,version) in oneVersion4UKs.items():
        if userId not in keys:
            UKsVersion[userId]=list()
        UKsVersion[userId].append(version)
    res={
        'UKcVersion':UKcVersion2Json(UKcVersion),
        'UKsVersion':UKsVersion2Json(UKsVersion),
        'authorities':authorities2Json(authorities)
    }
    return json.dumps(res)

def skUpdate(user,versionList):
    user=json2PrivateUser(user)
    for version in versionList:
        for (attr, UKs) in version.items():
            cp_abe.skupdate(user['authoritySecretKeys'], attr,UKs)
    return privateUser2Json(user)

def ctUpdate(GPP, CT, UKcVersion):
    GPP = json2GPP(GPP)
    CT = json2CT(CT)
    UKcVersion = json2UKcVersion(UKcVersion)
    encryptedKey = CT['encryptedKey']
    for version in UKcVersion:
        for (attr, UKc) in version.items():
            cp_abe.ctupdate(GPP, encryptedKey, attr, UKc)
    CT['encryptedKey']=encryptedKey
    return CT2Json(CT)
def b64ToJson(b64Str):
    b64Bytes=str.encode(b64Str,"utf-8");
    resJson=bytes.decode(base64.b64decode(b64Bytes));
    return resJson

def jsonTob64(jsonStr):
    byteData=str.encode(jsonStr,"utf-8")
    resB64=bytes.decode(base64.b64decode(byteData))
    return resB64

def CT2Json(CT):
    contentKey=CT['encryptedKey']
    C1 = pairingElement2str(contentKey['C1'])
    C2 = pairingElement2str(contentKey['C2'])
    C3 = pairingElement2str(contentKey['C3'])
    C = {}
    for (attr, key) in contentKey['C'].items():
        C[attr] = pairingElement2str(key)
    CS = {}
    for (attr, key) in contentKey['CS'].items():
        CS[attr] = pairingElement2str(key)
    D = {}
    for (attr, key) in contentKey['D'].items():
        D[attr] = pairingElement2str(key)
    DS = {}
    for (attr, key) in contentKey['DS'].items():
        DS[attr] = pairingElement2str(key)
    policy=contentKey['policy']
    newContentKey={
        'C1':C1,
        'C2':C2,
        'C3':C3,
        'C' :C,
        'CS':CS,
        'D' :D,
        'DS':DS,
        'policy':policy
    }
    CT['encryptedKey']=newContentKey
    return json.dumps(CT)


def json2CT(jsonCT):
    CT=json.loads(jsonCT)
    contentKey=CT['encryptedKey']
    C1 = str2pairingElement(contentKey['C1'])
    C2 = str2pairingElement(contentKey['C2'])
    C3 = str2pairingElement(contentKey['C3'])
    C = {}
    for (attr, key) in contentKey['C'].items():
        C[attr] = str2pairingElement(key)
    CS = {}
    for (attr, key) in contentKey['CS'].items():
        CS[attr] = str2pairingElement(key)
    D = {}
    for (attr, key) in contentKey['D'].items():
        D[attr] = str2pairingElement(key)
    DS = {}
    for (attr, key) in contentKey['DS'].items():
        DS[attr] = str2pairingElement(key)
    policy=contentKey['policy']
    newContentKey={
        'C1':C1,
        'C2':C2,
        'C3':C3,
        'C' :C,
        'CS':CS,
        'D' :D,
        'DS':DS,
        'policy':policy
    }
    CT['encryptedKey']=newContentKey
    return CT



def UKcVersion2Json(UKcVersion):
    newUKcVersion = list()
    for oneVersion in UKcVersion:
        newOneVersion = dict()
        for (attr, UKc) in oneVersion.items():
            e0 = pairingElement2str(UKc[0])
            e1 = pairingElement2str(UKc[1])
            newOneVersion[attr]=(e0, e1)
        newUKcVersion.append(newOneVersion)
    return json.dumps(newUKcVersion)

def json2UKcVersion(jsonUKcVersion):
    UKcVersion = list()
    if(not jsonUKcVersion):
        return UKcVersion
    oldUKcVersion = json.loads(jsonUKcVersion)
    for oldOneVersion in oldUKcVersion:
        oneVersion = dict()
        for (attr, UKc) in oldOneVersion.items():
            UKc=json.loads(UKc)
            e0 = str2pairingElement(UKc[0])
            e1 = str2pairingElement(UKc[1])
            oneVersion[attr] = (e0, e1)
        UKcVersion.append(oneVersion)
    return UKcVersion

def UKsVersion2Json(UKsVersion):
    for(userId, versionList) in UKsVersion.items():
        for version in versionList:
            for (attr, UKs) in version.items():
                version[attr]=pairingElement2str(UKs)
    return json.dumps(UKsVersion)

def json2UKsVersion(jsonUKsVersion):
    if(not jsonUKsVersion):
        return {}
    UKsVersion=json.loads(jsonUKsVersion)
    for (userId,versionList) in UKsVersion.items():
        for version in versionList:
            for(attr, UKs) in version.items():
                version[attr] = str2pairingElement(UKs)
    return UKsVersion

def GPP2Json(GPP):
    g = pairingElement2str(GPP['g'])
    g_a = pairingElement2str(GPP['g_a'])
    g_b = pairingElement2str(GPP['g_b'])
    newGPP = {
        'g': g,
        'g_a': g_a,
        'g_b': g_b
    }
    return json.dumps(newGPP)

def json2GPP(jsonGPP):
    GPP=json.loads(jsonGPP)
    g = str2pairingElement(GPP['g'])
    g_a = str2pairingElement(GPP['g_a'])
    g_b = str2pairingElement(GPP['g_b'])
    cp_abe = CP_ABE(groupObj)
    newGPP, tempGMK = cp_abe.setup()
    newGPP['g']=g
    newGPP['g_a']=g_a
    newGPP['g_b']=g_b
    return newGPP

def GMK2Json(GMK):
    a = pairingElement2str(GMK['a'])
    b = pairingElement2str(GMK['b'])
    newGMK={
        'a':a,
        'b':b
    }
    return json.dumps(newGMK)

def json2GMK(jsonGMK):
    GMK = json.loads(jsonGMK)
    a = str2pairingElement(GMK['a'])
    b = str2pairingElement(GMK['b'])
    newGMK={
        'a':a,
        'b':b
    }
    return newGMK

def pairingElement2str(element):
    n=type(element)
    if (not element):
        return ''
    if(not isinstance(element,pc_element)):
        raise Exception("输入对象不是pc_element类型")
    else:
        byteData=groupObj.serialize(element)
        return bytes.decode(byteData)

def str2pairingElement(strData):
    if(not strData):
        return ""
    byteData=str.encode(strData)
    return groupObj.deserialize(byteData)

def privateUser2Json(user):
    ugpk1=pairingElement2str(user['keys'][0])
    ugsk2=pairingElement2str(user['keys'][1])
    contentKey=pairingElement2str(user['contentKey'])

    oldAuthKeys = user['authoritySecretKeys']
    newAuthKeys = {}
    if(oldAuthKeys):
        K  = pairingElement2str(oldAuthKeys['K'])
        KS = pairingElement2str(oldAuthKeys['KS'])
        AK = {}
        for (attrName, attrKey) in oldAuthKeys['AK'].items():
            AK[attrName] = pairingElement2str(attrKey)
        newAuthKeys = {
           'K' : K,
           'KS': KS,
           'AK': AK
        }
    newUser = {
        'id'  : user['id'],
        'authoritySecretKeys':newAuthKeys,
        'keys': (ugpk1, ugsk2),
        'contentKey': contentKey
    }
    return json.dumps(newUser)

def json2PrivateUser(jsonUser):
    user=json.loads(jsonUser)
    user['authoritySecretKeys']=json.loads(user['authoritySecretKeys'])
    user['keys']=json.loads(user['keys'])
    ugpk1 = str2pairingElement(user['keys'][0])
    ugsk2 = str2pairingElement(user['keys'][1])
    contentKey = str2pairingElement(user['contentKey'])

    oldAuthKeys = user['authoritySecretKeys']
    newAuthKeys = {}
    if (oldAuthKeys):
        K = str2pairingElement(oldAuthKeys['K'])
        KS = str2pairingElement(oldAuthKeys['KS'])
        AK = {}
        for (attrName, attrKey) in oldAuthKeys['AK'].items():
            AK[attrName] = str2pairingElement(attrKey)
        newAuthKeys = {
            'K': K,
            'KS': KS,
            'AK': AK
        }
    newUser = {
        'id': user['id'],
        'authoritySecretKeys': newAuthKeys,
        'keys': (ugpk1, ugsk2),
        'contentKey': contentKey
    }
    return newUser

def publicUser2Json(users):
    for (userName, userKeys) in users.items():
        for (k,v) in userKeys.items():
            userKeys[k]=pairingElement2str(v)
    return json.dumps(users)

def json2PublicUser(jsonUsers):
    users=json.loads(jsonUsers)
    for (userName, userKeys) in users.items():
        users[userName]=json.loads(userKeys)
    for (userName, userKeys) in users.items():
        for (k, v) in userKeys.items():
            userKeys[k] = str2pairingElement(v)
    return users

def authorities2Json(authorities):
    dictAuthorities={}
    for authorityId in authorities:
        authority = authorities[authorityId]
        alpha = pairingElement2str(authority[0]['alpha'])
        beta  = pairingElement2str(authority[0]['beta'])
        gamma = pairingElement2str(authority[0]['gamma'])

        SK = {'alpha': alpha, 'beta': beta, 'gamma': gamma}
        e_alpha = pairingElement2str(authority[1]['e_alpha'])
        g_beta = pairingElement2str(authority[1]['g_beta'])
        g_beta_inv = pairingElement2str(authority[1]['g_beta_inv'])

        PK = {
            'e_alpha': e_alpha,
            'g_beta': g_beta,
            'g_beta_inv': g_beta_inv
        }
        oldAuthAttrs = authority[2]
        newAuthAttrs = {}
        for attrName in oldAuthAttrs:
            VK  = pairingElement2str(oldAuthAttrs[attrName]['VK'])
            PK1 = pairingElement2str(oldAuthAttrs[attrName]['PK1'])
            PK2 = pairingElement2str(oldAuthAttrs[attrName]['PK2'])
            newAuthAttrs[attrName]={
                'VK' :VK,
                'PK1':PK1,
                'PK2':PK2
            }
        dictAuthorities[authorityId] = (SK, PK, newAuthAttrs)
    return json.dumps(dictAuthorities)

def json2Authorities(jsonAuthorities):
    authorities=json.loads(jsonAuthorities)

    for authorityId in authorities:
        authorities[authorityId]=json.loads(authorities[authorityId])
        authority = authorities[authorityId]
        alpha = str2pairingElement(authority[0]['alpha'])
        beta  = str2pairingElement(authority[0]['beta'])
        gamma = str2pairingElement(authority[0]['gamma'])

        SK = {'alpha': alpha, 'beta': beta, 'gamma': gamma}
        e_alpha = str2pairingElement(authority[1]['e_alpha'])
        g_beta  = str2pairingElement(authority[1]['g_beta'])
        g_beta_inv = str2pairingElement(authority[1]['g_beta_inv'])

        PK = {
            'e_alpha': e_alpha,
            'g_beta': g_beta,
            'g_beta_inv': g_beta_inv
        }
        oldAuthAttrs = authority[2]
        newAuthAttrs = {}
        for attrName in oldAuthAttrs:
            VK  = str2pairingElement(oldAuthAttrs[attrName]['VK'])
            PK1 = str2pairingElement(oldAuthAttrs[attrName]['PK1'])
            PK2 = str2pairingElement(oldAuthAttrs[attrName]['PK2'])
            newAuthAttrs[attrName] = {
                'VK': VK,
                'PK1': PK1,
                'PK2': PK2
            }
        authorities[authorityId] = (SK, PK, newAuthAttrs)
    return authorities
def b64RevokedMap2Obj(b64JsonMap):
    jsonMap=b64ToJson(b64JsonMap)
    ObjMap=json.loads(jsonMap)
    for (attr, users) in ObjMap.items():
        for (userName, userKeys) in users.items():
            users[userName]=json.loads(userKeys)
            for (k, v) in users[userName].items():
                users[userName][k] = str2pairingElement(v)
    return ObjMap

def b64VersionList2Obj(b64VersionList):
    jsonVersionList=b64ToJson(b64VersionList)
    versionList=json.loads(jsonVersionList)
    for version in versionList:
        for (attr, UKs) in version.items():
            version[attr] = str2pairingElement(UKs)
    return versionList
def main(argv):

    try:
        opts, args = getopt.getopt(argv[1:], "hm:", ["help", "method="])

    except getopt.GetoptError:
        print("选择参数错误")
        sys.exit(2)
    for (opt, arg) in opts:
        if opt in ("-m","--method"):
            if(arg=="CAstup"):
                res=CAstup()
                print(res)
            elif (arg=="AAstup"):
                GPP=b64ToJson(args[0])
                authorityId=args[1]
                attributes=b64ToJson(args[2])
                res=AAstup(GPP,authorityId,attributes)
                print(res)

            elif (arg=="userRegister"):
                GPP=args[0]
                userId=args[1]
                GPP=b64ToJson(GPP)
                res=userRegister(GPP,userId)
                print(res)

            elif (arg=="keyGen"):
                GPP=b64ToJson(args[0])
                authorities=b64ToJson(args[1])
                authorityId=args[2]
                attributes=b64ToJson(args[3])
                user=b64ToJson(args[4])
                publicUserData=b64ToJson(args[5])

                res=keyGen(GPP,authorities,authorityId,attributes,user,publicUserData)
                print(res)

            elif (arg=="encrypt"):
                GPP=b64ToJson(args[0])
                sourceFile=args[1]
                targetFile=args[2]
                extName=args[3]
                b64StrData = ''
                with open(sourceFile, 'rb') as f:
                    byteData = f.read();
                    b64ByteData = base64.b64encode(byteData)
                    b64StrData = bytes.decode(b64ByteData)
                policy_str=b64ToJson(args[4])
                authorities=b64ToJson(args[5])
                authorityId=args[6]
                user=b64ToJson(args[7])
                CT = encrypt(GPP,b64StrData,policy_str,authorities,authorityId,user)

                res={
                    "extName":extName,
                    "content":CT
                }

                with open(targetFile, "w+") as f:
                    f.write(json.dumps(res))
                print("success")

            elif (arg=="decrypt"):
                GPP=b64ToJson(args[0])
                user=b64ToJson(args[1])
                sourceFile=args[2]
                targetFile=args[3]
                CT={}
                with open(sourceFile, "r+") as f:
                    jsonStrData = f.read()
                    jsonObjData=json.loads(jsonStrData)
                    CT=jsonObjData['content']
                    targetFile+=jsonObjData['extName']
                b64StrData = decrypt(GPP,user,CT)
                with open(targetFile,"ab+") as f:
                    b64ByteData=str.encode(b64StrData)
                    byteData=base64.b64decode(b64ByteData)
                    f.write(byteData)
                print("success")

            elif (arg=="ukyeGen"):
                UKsVersion={}
                UKcVersion=()
                GPP=b64ToJson(args[0])
                authorities=b64ToJson(args[1])
                authorityId=args[2]
                revokedMap=b64RevokedMap2Obj(args[3])
                if(len(args)==6):
                    UKsVersion=b64ToJson(args[4])
                    UKcVersion=b64ToJson(args[5])

                res=ukyeGen(GPP,authorities,authorityId,revokedMap,UKsVersion,UKcVersion)
                print(res)
            elif (arg=="skUpdate"):
                user=b64ToJson(args[0])
                versionList=b64VersionList2Obj(args[1])
                res=skUpdate(user,versionList)
                print(res)

            elif (arg=="ctUpdate"):
                GPP=b64ToJson(args[0])
                sourceFile=args[1]
                targetFile=args[1]
                UKcVersion=b64ToJson(args[2])
                CT = {}
                jsonObjData={}
                with open(sourceFile, "r+") as f:
                    jsonStrData = f.read()
                    jsonObjData = json.loads(jsonStrData)
                    CT = jsonObjData['content']
                updateCT=ctUpdate(GPP,CT,UKcVersion)
                jsonObjData["content"]=updateCT
                with open(targetFile, "w+") as f:
                    f.write(json.dumps(jsonObjData))
                print("success")
            else:
                print("method %s not found" % arg)


if(__name__=='__main__'):
    main(sys.argv)

