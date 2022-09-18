import base64

def to_base64(a):
    if(a//26==0):
        return chr(ord('A')+a%26)
    elif(a//26==1):
        return chr(ord('a')+a%26)
    elif(a//26==2):
        if(a%26<=9):
            return chr(ord('0')+a%26)
        elif(a % 26 == 10):
            return '+'
        elif(a % 26 == 11):
            return '/'

def from_base64(b):
    if(ord(b)-ord('A') < 26 and ord(b)-ord('A')>=0):
        return(ord(b)-ord('A'))
    elif(ord(b)-ord('a') < 26 and ord(b)-ord('a')>=0):
        return(26+ord(b)-ord('a'))
    elif(ord(b)-ord('0') < 10 and ord(b)-ord('0') >= 0):
        return(52+ord(b)-ord('0'))
    elif(b=='+'):
            return 62
    elif(b == '/'):
            return 63

def substitute(a,b):
    return to_base64((from_base64(a) + from_base64(b)) % 64)



def main():
    message= input()
    # adding padding to the encoded message
    message =  message + '\0'*(12-len(message)%12)
    key=input()
    encoded= base64.b64encode(message.encode())
    if(len(key)<128):
        key = key*(16//len(key)) + key[:16%len(key)]
    elif(len(key)>128):
        key = key[:16]
    print(len(encoded))
    for i in range(len(encoded)//16):
        block=encoded[i*16:i*16+16]
        print(block)
    

   

    


if __name__ == "__main__":
    print(substitute('A','z'))