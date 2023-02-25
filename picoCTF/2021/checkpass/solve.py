import gdb
import re
import string

# --------

"""
This is a gdb script and not supposed to be executed on its own.
"""

# --------

FLAG_START = "picoCTF{"
FLAG_END = "}"

FILENAME = "checkpass"

KEYLEN = 0x20
ALPHABET = list(string.ascii_letters) + list(string.digits) + ['_']
CRIBSIZE = 7    # num of chars to try at once

RETURN_FROM_LAST_SUBSTITUTION = 0x555555405c10
BEFORE_FIRST_COMPARISON = 0x555555405d0b

assert len(ALPHABET) % CRIBSIZE == 0    # this helps make the algorithm easier

# --------

def passwordFromCharList(charList):
        return FLAG_START + "".join(charList) + FLAG_END

def genPassWithUniqueFrequencies(charList):
        return FLAG_START + "".join([charList[i]*(i+1) for i in range(CRIBSIZE)]) + charList[CRIBSIZE - 1]*4 + FLAG_END

def getDistinctInputCharacters(cipherToPlain, n=KEYLEN):
        return list(cipherToPlain.values())[:n]

def findSubstitutionForCharList(charList, cipherToPlainDict, plainToCipherDict):

        password = genPassWithUniqueFrequencies(charList)

        gdb.execute(f"r {password}")

        results = gdb.parse_and_eval(f"(unsigned char[{KEYLEN}]) *$rdi")

        frequencies = {}

        for i in range(KEYLEN):
                character = int(results[i])
                frequencies[character] = frequencies.get(character, 0) + 1

        for (substituted_character, frequency) in frequencies.items():
                original_character = charList[min(frequency - 1, 6)]
                cipherToPlainDict[substituted_character] = original_character
                plainToCipherDict[original_character] = substituted_character

def crackSubstitution(cipherToPlainDict, plainToCipherDict):

        gdb.execute(f"b *{RETURN_FROM_LAST_SUBSTITUTION}")

        for i in range(0, len(ALPHABET), CRIBSIZE):
                charList = ALPHABET[i : i + CRIBSIZE]
                findSubstitutionForCharList(charList, cipherToPlainDict, plainToCipherDict)

def crackTransposition(cipherToKeys):

        gdb.execute('d break')
        gdb.execute(f"b *{BEFORE_FIRST_COMPARISON}")

        inputCharList = getDistinctInputCharacters(cipherToKeys)
        password = passwordFromCharList(inputCharList)

        gdb.execute(f"r {password}")

        resultList = [None for i in range(KEYLEN)]

        pattern = re.compile('cmp\s+\(%([a-z]+),%([a-z]+),1\),%([a-z]+)')

        for i in range(KEYLEN):

                # Skip ahead until next fitting compare instruction:
                m = None
                while m is None:
                        gdb.execute('si')
                        instruction = gdb.execute('x/i $pc', to_string=True)
                        m = re.search(pattern, instruction)

                # Parse instruction:
                expectedBaseReg = m.group(1)
                expectedIndexReg = m.group(2)
                actualValueReg = m.group(3)

                expectedValue = int(gdb.parse_and_eval(f"*((unsigned char*)(${expectedBaseReg}+${expectedIndexReg}))"))
                actualValue = int(gdb.parse_and_eval(f"(unsigned char)${actualValueReg}"))

                originalInputValue = cipherToKeys[actualValue]
                pos = inputCharList.index(originalInputValue)
                resultList[pos] = cipherToKeys[expectedValue]

                # Set the value inside gdb, so the program keeps running:
                gdb.execute(f"set ${actualValueReg}={hex(expectedValue)}")

        return resultList

# --------

def main():

        # load executable:
        gdb.execute(f"file {FILENAME}")

        cipherToPlainDict = {}
        plainToCipherDict = {}

        crackSubstitution(cipherToPlainDict, plainToCipherDict)
        print({hex(c): p for (c, p) in cipherToPlainDict.items()})

        keyChars = crackTransposition(cipherToPlainDict)

        flag = passwordFromCharList(keyChars)
        print(flag)

# --------

# Gdb *does* invoke this script with __name__ == "__main__"
if __name__ == "__main__":
        main()

# --------


