def bits_to_num(list_):
    res=0
    for i in range(4):
        res+=int(list_[i])*(2**i)
    
    return res

def list_in_byte(list_):
    res=b''
    
    res=res.join(bytes(i,'ascii') for i in list_)
    
    return res

def rotate(list_,n):
    return list_[n:]+list_[:n]

def list_to_str(list_):
    string=""
    
    for i in list_:
        string+=str(i)
    
    return string

def if_64(text_len):
    if text_len>=64:
        return 64
    else:
        return text_len

def text_to_byte(text):
    res=''
    bit_text=""
    bit_list=[]
    bit_text=''.join(format(ord(i), '08b') for i in text)
    append_int=64 - (len(bit_text))%64 

    if (len(bit_text))%64!=0:
        print("Block deficiency - "+str(append_int))
        if (64 - append_int-8)>=0:
            for i in range(append_int-8):
                bit_text+='0'
        for i in range(8):
            res+=str(append_int%2)
            append_int=append_int//2
                  
        bit_text+=res
    #print(len(bit_text))
    for i in range(int(len(bit_text)/64)):
        bit_list.append(bit_text[:64])
        bit_text=bit_text[64:]
    
    return bit_list

def text_to_byte_for_gamma(text):
    res=''
    bit_text=""
    bit_list=[]
    bit_text=''.join(format(ord(i), '08b') for i in text)
    
    for i in range(int(len(bit_text)/64)):
        try:
            bit_list.append(bit_text[:64])
            bit_text=bit_text[64:]
        except:
            break
    bit_list.append(bit_text)
    
    return bit_list

def hex_to_bit(text):
    hex_dict = {'0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100', '5': '0101', '6': '0110', '7': '0111', '8': '1000', '9': '1001', 'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'}
    bit_text = ""
    
    for o in text:
        bit_text+=hex_dict[o]
        
    return bit_text





def f(text,key_):
    list_=[0,0,0,0]
    ciphertext=[]
    xor_result = [int(text[i]) ^ int(key_[i]) for i in range(32)]
    
    #print(xor_result)
    s_box = [
        [ 4, 10,  9,  2, 13,  8,0,14,   6,	11,	1,	12,	7,	15,	5,	3],
	[14, 11,  4, 12,  6, 13,15,10,	2,	3,	8,	1,	0,	7,	5,	9],
	[ 5,  8,  1, 13, 10,  3,4,2,	14,	15,	12,	7,	6,	0,	9,	11],
	[ 7, 13, 10,  1,  0,  8,9,15,	14,	4,	6,	12,	11,	2,	5,	3],
	[ 6, 12,  7,  1,  5, 15,13,8,	4,	10,	9,	14,	0,	3,	11,	2],
	[ 4, 11, 10,  0,  7,  2,1,13,	3,	6,	8,	5,	9,	12,	15,	14],
	[13, 11,  4,  1,  3, 15,5,9,	0,	10,	14,	7,	6,	8,	2,	12],
	[ 1, 15, 13,  0,  5,  7,10,4,	9,	2,	3,	14,	6,	11,	8,	12],
    ]
    
    for s_box_block in s_box:
        coded_block=xor_result[:4]
        xor_result=xor_result[4:]
        s_box_output = s_box_block[s_box_block.index(bits_to_num(coded_block))-3]
    
        for i in range(4):
            list_[3-i] = s_box_output % 2
            s_box_output = s_box_output // 2            
        ciphertext=ciphertext+list_
        list_=[0,0,0,0]
    
    result=rotate(ciphertext,11)
    
    #print(xor_result)
    
    return result

def key_generator(key):
    key_list=[]
    for x in range(8):
        key_list.append(key[:32])
        key=key[32:]
    
    return key_list

def dsty_encrypt(plaintext,key):
    k=key_generator(key)
    #print(k)
    left=plaintext[:32]
    right=plaintext[32:]
    swap_var=""
    
    for i in range(24):
        swap_var=right 
        result=f(right,k[i%8])
        right = [int(result[p]) ^ int(left[p]) for p in range(32)]
        left = swap_var
        
    for i in range(8):
        swap_var=right 
        result=f(right,k[7-i])
        right=[int(result[p]) ^ int(left[p]) for p in range(32)]
        left=swap_var    
    
    ciphertext = right+left
    
    return list_to_str(ciphertext)

def dsty_decrypt(ciphertext,key):
    k=key_generator(key)
    left=ciphertext[:32]
    right=ciphertext[32:]
    swap_var=""
    
    for i in range(8):
        swap_var=right 
        result=f(right,k[i])
        right=[int(result[p]) ^ int(left[p]) for p in range(32)]
        left=swap_var    
    
    for i in range(24):
        swap_var=right 
        result=f(right,k[7-(i%8)])
        right = [int(result[p]) ^ int(left[p]) for p in range(32)]
        left = swap_var
    
    plaintext = right+left
    #print(plaintext)
    return list_to_str(plaintext)

def rezhime_prost_zaminy():
    while True:
        text=input("Enter text: ")
        key_int=int(input("Enter key: "))
        enc_decr=int(input("Encrypt - 1, Decrypt - 0 "))
        ciphertext=""
        plaintext=""
        hexStr=""
        key=[None]*256
        
        for i in range(256):
            key[255-i] = key_int % 2
            key_int = key_int // 2
        
        key=list_to_str(key)
            
        if(enc_decr==1):
            text=text.replace(' ', '_')
            bit_list=text_to_byte(text)
            #print(list_to_str(bit_list))
        
            for o in bit_list:
                hexStr+=hex(int(dsty_encrypt(o,key),2))
            
            hexStr=hexStr.replace('0x','')
            print("Your ciphertext: "+hexStr)
        else:
            ned_block=int(input("Do you have block lack? "))
            #print(ned_block)
            text=hex_to_bit(text)
            #print(text)
            res=""
            for o in range(int(len(text)/64)):
                disp_var = text[:64]
                text = text[64:]
                plaintext+=dsty_decrypt(disp_var,key)
                
            res=""
            #print(plaintext)
            
            if ned_block==1:
                print(" ")
                ned_int=int(plaintext[-8:],2)
                plaintext=plaintext[:-ned_int]
                
            text_len=int(len(plaintext)/8)
            for i in range(text_len):
                res+=chr(int(plaintext[:8],2))
                plaintext=plaintext[8:]
            
            print("Your plaintext: "+res)
            
def rezhime_gamyvannya():
    while True:
        text=input("Enter text: ")
        key_int=int(input("Enter key: "))
        vector_inic=input("Enter inicialization vector: ")
        enc_decr=int(input("Encrypt - 1, Decrypt - 0 "))
        ciphertext=""
        plaintext=""
        hexStr=""
        key=[None]*256
        
        for i in range(256):
            key[255-i] = key_int % 2
            key_int = key_int // 2
        
        key=list_to_str(key)
            
        if(enc_decr==1):
            text=text.replace(' ', '_')
            bit_list=text_to_byte_for_gamma(text)
            #print(list_to_str(bit_list))
            n3 = vector_inic[:32]
            n4 = vector_inic[32:]
            res_str=dsty_encrypt(n3+n4,key)
            n3 = res_str[:32]
            n4 = res_str[32:]
            c2 = hex_to_bit("1010101")
            c1 = hex_to_bit("1010104")
            
            for o in range(len(bit_list)):
                n1 = list_to_str([int(n3[i]) ^ int(c2[i]) for i in range(28)])
                n2 = list_to_str([int(n4[i]) ^ int(c1[i]) for i in range(28)])
                n1+=n3[28:]
                n2+=n4[28:]
                string_to_xor=n1+n2
                try:
                    hexStr+=hex(int( list_to_str([int(bit_list[o][i]) ^ int(string_to_xor[i]) for i in range(len(bit_list[o]))]),2 ) )
                except ValueError:
                    n3 = n1
                    n4 = n2                    
                n3 = n1
                n4 = n2
                
            
            hexStr=hexStr.replace('0x','')
            print("Your ciphertext: "+hexStr)
        else:
            text=hex_to_bit(text)
            #print(text)
            res=""
            
            n3 = vector_inic[:32]
            n4 = vector_inic[32:]
            res_str=dsty_encrypt(n3+n4,key)
            n3 = res_str[:32]
            n4 = res_str[32:]
            c2 = hex_to_bit("1010101")
            c1 = hex_to_bit("1010104")
            
            text_len=len(text)//64
            
            if len(text)%64!=0:
                text_len+=1
            
            for o in range(text_len):
                n1 = list_to_str([int(n3[i]) ^ int(c2[i]) for i in range(28)])
                n2 = list_to_str([int(n4[i]) ^ int(c1[i]) for i in range(28)])
                n1+=n3[28:]
                n2+=n4[28:]
                string_to_xor=n1+n2
                plaintext+=list_to_str([int(text[i]) ^ int(string_to_xor[i]) for i in range(if_64(len(text)))])
                n3 = n1
                n4 = n2
                text=text[64:]
            
            text_len=int(len(plaintext)/8)
            for i in range(text_len):
                res+=chr(int(plaintext[:8],2))
                plaintext=plaintext[8:]
            
            print("Your plaintext: "+res)    
    
def rezhime_gamyvannya_zi_zvor_zvyazkom():
    while True:
        text=input("Enter text: ")
        key_int=int(input("Enter key: "))
        vector_inic=input("Enter inicialization vector: ")
        enc_decr=int(input("Encrypt - 1, Decrypt - 0 "))
        ciphertext=""
        plaintext=""
        hexStr=""
        key=[None]*256
        
        for i in range(256):
            key[255-i] = key_int % 2
            key_int = key_int // 2
        
        key=list_to_str(key)
            
        if(enc_decr==1):
            text=text.replace(' ', '_')
            bit_list=text_to_byte_for_gamma(text)
            #print(list_to_str(bit_list))
            n1 = vector_inic[:32]
            n2 = vector_inic[32:]
            gamma_block=dsty_encrypt(n1+n2,key)
            res=list_to_str([int(bit_list[0][i]) ^ int(gamma_block[i]) for i in range(len(bit_list[0]))])
            hexStr+=hex(int(res,2))
            try:
                gamma_block=dsty_encrypt(res,key)
                #print(gamma_block)
            except:
                res=""
            
            for o in range(len(bit_list)):
                if o==0:
                    continue                
                else:
                    res=list_to_str([int(bit_list[o][i]) ^ int(gamma_block[i]) for i in range(len(bit_list[o]))])
                    hexStr+=hex(int(res,2))
                    try:
                        gamma_block=dsty_encrypt(res,key)
                        #print(gamma_block)
                    except IndexError:
                        break
                    
                        
            
            hexStr=hexStr.replace('0x','')
            print("Your ciphertext: "+hexStr)
        else:
            text=hex_to_bit(text)
            #print(text)
            res=""
            
            n1 = vector_inic[:32]
            n2 = vector_inic[32:]
            
            text_len=len(text)//64
            
            if len(text)%64!=0:
                text_len+=1
            
            
            for o in range(text_len):
                gamma_block=dsty_encrypt(n1+n2,key)               
                #print(gamma_block)
                if(len(text)<64):
                    ciphertext=text
                else:
                    ciphertext=text[:64]

                plaintext+=list_to_str([int(text[i]) ^ int(gamma_block[i]) for i in range(if_64(len(text)))])
                try:
                    n1=ciphertext[:32]
                    n2=ciphertext[32:]
                    #gamma_block=dsty_encrypt(ciphertext,key)
                except IndexError:
                    break
                text=text[64:]
            
            text_len=int(len(plaintext)/8)
            for i in range(text_len):
                res+=chr(int(plaintext[:8],2))
                plaintext=plaintext[8:]
            
            print("Your plaintext: "+res)

def main():
    func=input("Which type of encyption would you like to use? \n1) rezhime_prost_zaminy \n2) rezhime_gamyvannya \n3) rezhime_gamyvannya_zi_zvor_zvyazkom\n")
    if func == "1":
        rezhime_prost_zaminy()
    if func == "2":
        rezhime_gamyvannya()
    else:
        rezhime_gamyvannya_zi_zvor_zvyazkom()


main()






