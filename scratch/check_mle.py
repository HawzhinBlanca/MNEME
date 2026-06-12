import random

P = 2**64 - 2**32 + 1

def add(a, b): return (a + b) % P
def sub(a, b): return (a - b) % P
def mul(a, b): return (a * b) % P

def evaluate_mle(evals, r):
    v = len(r)
    current = list(evals)
    for r_j in r:
        next_len = len(current) // 2
        next_vec = [0] * next_len
        for i in range(next_len):
            next_vec[i] = add(mul(sub(1, r_j), current[2 * i]), mul(r_j, current[2 * i + 1]))
        current = next_vec
    return current[0]

# Helper: quantize floats
def quantize_vector(v_float, scale=1000):
    return [int(round(x * scale)) % P for x in v_float]

random.seed(42)
n = 1024
d = 16
k = 10
b = 30 # Use 30 bits

V_floats = [[random.uniform(-1, 1) for _ in range(d)] for _ in range(n)]
q_float = [random.uniform(-1, 1) for _ in range(d)]

V = [quantize_vector(v) for v in V_floats]
q = quantize_vector(q_float)

D = []
for i in range(n):
    dist_val = 0
    for j in range(d):
        diff = sub(q[j], V[i][j])
        dist_val = add(dist_val, mul(diff, diff))
    D.append(dist_val)

indexed_distances = list(enumerate(D))
indexed_distances.sort(key=lambda x: (x[1], x[0]))
S_indices = [idx for idx, _ in indexed_distances[:k]]
d_k = indexed_distances[k-1][1]

B = [0] * n
for idx in S_indices:
    B[idx] = 1

slacks = []
bit_matrices = [[] for _ in range(b)]
for i in range(n):
    if B[i] == 1:
        sl = sub(d_k, D[i])
    else:
        sl = sub(sub(D[i], d_k), 1)
    slacks.append(sl)
    
    # Decompose sl
    temp = sl
    for j in range(b):
        bit = temp & 1
        bit_matrices[j].append(bit)
        temp >>= 1

# Let's check if the decomposition is correct for all i
mismatch_count = 0
for i in range(n):
    decomp = sum(bit_matrices[j][i] * (2**j) for j in range(b)) % P
    if decomp != slacks[i]:
        mismatch_count += 1
        if mismatch_count < 5:
            print(f"Mismatch at {i}: slack={slacks[i]}, decomp={decomp}")

print("Total mismatches:", mismatch_count)
