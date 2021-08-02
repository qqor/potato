fn1 = "/home/cereal/fuzzing/data/gcc/gcc_coreutils_64_O3_cat"

new = fn1[fn1.find("O")+3:]
fn = 'similarity_dic_%s.pkl'%fn1[fn1.find("O")+3:]
print(fn)