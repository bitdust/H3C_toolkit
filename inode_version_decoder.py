#coding=utf-8

# H3C inode 版本号解密工具
# 使用方法：
# 修改base64_data为你的inode发出的base64信息
# 运行本脚本，观察输出的版本号，请以16进制结果为准
# 如果输出版本号类似于乱码，请更换H3C—KEY值继续测试
from hashlib import md5
import base64
from binascii import hexlify

def XOR(txt,key):
    result =range(0,len(txt)) 
    new_key = key+key
    new_key = new_key[:len(txt)]
    new_key_r = new_key[::-1]
    for i in range(0,len(txt)):
        result[i] = new_key[i] ^ new_key_r[i] ^ txt[i]
    return result

H3C_KEY = 'Oly5D62FaE94W7'
# H3C_KEY = 'HuaWei3COM1X' # 可能的 H3C_KEY 值
base64_data = 'bTMMHhsGZ3YvHx5gJlQqf1D7G3Y='
raw = (base64.b64decode(base64_data))
raw2 = XOR(map(ord,raw),map(ord,H3C_KEY))
random_key = raw2[16:]
random_key_str = "%02x%02x%02x%02x" %(random_key[0],random_key[1],random_key[2],random_key[3])
version_raw = XOR(raw2[:16],map(ord,random_key_str))
print "解密版本号为：（可能包含不可见字符，请以16进制结果为准！）"
print "版本号格式类似为： EN V3.60-6708"
print map(chr,version_raw)
print "对应的16进制结果为："
print map(hex,version_raw)



