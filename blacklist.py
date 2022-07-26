#verifying urls among black and whitelist

whitelist = ['a', 'b', 'd', 'f', 'h', 'i', 'j', 'k', 'l', 'm', 'p', 'q',
            'r', 'u', 'v', 'w', 'z',’0’,’1’,’2’,’3’,’4’,’5’,’6’,’7’,’8’,’9’,’:’,’//’]


blacklist = ['a', 'b', 'd', 'f', 'h', 'i', 'j', 'k', 'l', 'm', 'p', 'q',
            'r', 'u', 'v', 'w', 'z',’0’,’1’,’2’,’3’,’4’,’5’,’6’,’7’,’8’,’9’,’:’,’//’]

def stringTreat(string):
    if not any(ch in string for ch in blacklist):
        if all(ch in whitelist for ch in string):
            print('OK!!')
        else:
            print('stop at whitelist')
    else:
        print('stop at blacklist')

string = input('input:')

stringTreat(string)




