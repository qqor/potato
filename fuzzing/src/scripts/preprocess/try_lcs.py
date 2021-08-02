from __future__ import print_function
import os, sys, re, os.path
import pickle
import lcs as LCS

def write_to_file(res, fn):
    output = open(fn, 'wb')

    pickle.dump(res, output)
    output.close()


def read_from_file(fn):
    pkl_file = open(fn, 'rb')

    res = pickle.load(pkl_file)
    pkl_file.close()

    return res

def warning(*objs):
    print(*objs, file=sys.stderr)

warning("==================================================================")

'''fn1 = "/home/cereal/fuzzing/data/gcc/gcc_coreutils_64_O3_cat"
fn2 = "/home/cereal/fuzzing/data/gcc/gcc_coreutils_64_O0_cat"

sim = read_from_file('similarity_dic_cat.pkl')
failed_list = []
LCS.process(fn1, fn2, sim, failed_list)'''

fn1 = "/home/cereal/fuzzing/data/gcc/gcc_coreutils_64_O3_true"
fn2 = "/home/cereal/fuzzing/data/gcc/gcc_coreutils_64_O0_true"

sim = read_from_file('similarity_dic_true.pkl')
failed_list = []
LCS.process(fn1, fn2, sim, failed_list)