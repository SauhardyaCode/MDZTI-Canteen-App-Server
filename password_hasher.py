import math
import random
import re

class PasswordHasher():
    def __init__(self):
        self.__ascii_list = [
            48+i for i in range(58-48)]+[65+i for i in range(91-65)]+[97+i for i in range(123-97)]

    def __set_hash(self, pswd: str) -> str:

        self.__ascii_str = ""
        self.__a_list = []
        if pswd == '':
            pswd = '\n'
        self.__pswd_list = [ord(pswd[i]) for i in range(len(pswd))]

        hash = ""

        for i in range(len(self.__pswd_list)):
            raw_computed_float = math.pow(
                        round(
                            math.log(
                                abs(round(self.__pswd_list[i]*math.pi, 2))+1,
                                abs(round(math.tan(i+1), 2))+2
                            ),
                            2
                        ),
                        2
                    )
            
            clean_str_float = f"{raw_computed_float:.2f}"
            self.__pswd_list[i] = math.ceil(float(clean_str_float) * 100)
            self.__ascii_str += str(self.__pswd_list[i])

        for x in range(len(self.__ascii_str)):
            if self.__ascii_str[x] == '1' and x <= (len(self.__ascii_str)-3):
                self.__a_list.append(int(self.__ascii_str[x: x+3]))
            else:
                self.__a_list.append(int(self.__ascii_str[x: x+2]))

        for x in self.__a_list:
            if x in self.__ascii_list:
                hash += chr(x)
                if x == 92:
                    hash += '\\'
            else:
                x += 48
                if x in self.__ascii_list:
                    hash += chr(x)
                    if x == 92:
                        hash += '\\'

        return hash

    def __get_hash(self, pswd: str, check: int = 0) -> str:

        self.__check = check
        hash = self.__set_hash(pswd)
        salt = self.__set_hash(hash)

        final = salt+hash
        store = ""
        leftout = ""
        count = 0
        rand = random.randint(10, 20)

        if not self.__check:
            self.__check = rand

        while len(final) > 64:
            count += 1
            for i in range(0, len(final), self.__check):
                store += final[i]
                try:
                    if count == 1:
                        leftout += final[i+1]
                except:
                    pass

            final = store
            store = ''

        while len(final) < 64:
            final += self.__set_hash(leftout)[:64-len(final)]
            leftout = self.__set_hash(leftout)

        return f"${self.__check}${final}"
    
    def create_hash(self, password: str) -> str:
        return self.__get_hash(password)
    
    def check_password(self, password: str, original_hash: str) -> bool:
        code = int(re.findall(r'\$(\d+)\$', original_hash)[0])
        return (self.__get_hash(password, code) == original_hash)
    
    def generate_particular_hash(self, password: str, hash_code: int) -> str:
        return self.__get_hash(password, hash_code)
    

if __name__ == "__main__":
    hasher = PasswordHasher()
    pswd = "f07f2dc446f308ea7fecf38baea7ac11764acba7112aab7dfe0482de2e6665e8||2026-06-15 10:59:00"
    print(hasher.create_hash(pswd))