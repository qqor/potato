import os, sys

bl = ["sha256sum", "sha512sum", "cat", "cut", "df", "dir"]


bp1 = "~/fuzzing/data/gcc/gcc_coreutils_64_O0_"
bp2 = "~/fuzzing/data/gcc/gcc_coreutils_64_O3_"

'''
for b in bl:
    cmd = "time python process.py " + bp1 + b + " " + bp2 + b + ' ""'
    os.system(cmd)

    os.system("mv fv.txt fv.txt."+b)
'''

sbl = ["false","echo","tty","true"]

for b in bl:
    cmd = "time python process.py " + bp1 + b + " " + bp2 + b + ' ""'
    os.system(cmd)
    os.system("mv fv.txt fv.txt."+b)
