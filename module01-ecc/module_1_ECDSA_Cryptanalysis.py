import math
import operator
import random

import numpy.linalg
from fpylll import LLL
from fpylll import BKZ
from fpylll import IntegerMatrix
from fpylll import CVP
from fpylll import SVP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


# Euclidean algorithm for gcd computation
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


# Modular inversion computation
def mod_inv(a, p):
    if a < 0:
        return p - mod_inv(-a, p)
    g, x, y = egcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p


def check_x(x, Q):
    """ Given a guess for the secret key x and a public key Q = [x]P,
        checks if the guess is correct.

        :params x:  secret key, as an int
        :params Q:  public key, as a tuple of two ints (Q_x, Q_y)
    """
    x = int(x)
    if x <= 0:
        return False
    Q_x, Q_y = Q
    sk = ec.derive_private_key(x, ec.SECP256R1())
    pk = sk.public_key()
    xP = pk.public_numbers()
    return xP.x == Q_x and xP.y == Q_y


# attack when nonce k is known
def recover_x_known_nonce(k, h, r, s, q):
    x = (mod_inv(r, q) * (k * s - h)) % q
    return x


# attack for unknown, but repeated nonce k
def recover_x_repeated_nonce(h_1, r_1, s_1, h_2, r_2, s_2, q):
    delta_sig = r_2 * s_1 - r_1 * s_2
    x = ((h_1 * s_2 - h_2 * s_1) * mod_inv(delta_sig, q)) % q
    return x


# returns the integer value given a 'list' of bits with list[0] being the MSB
def convert_to_int(list_L_bits):
    exp = len(list_L_bits) - 1
    a = 0
    # iteration starts at MSB of list of bits
    for i in range(len(list_L_bits)):
        b = list_L_bits[i]
        if b == 1:
            a += pow(2, exp - i)
        else:
            continue
    return a


# computes midpoint of interval k may lie in, given the MSBs of k
def MSB_to_Padded_Int(N, L, list_k_MSB):
    a = convert_to_int(list_k_MSB)
    exp = N - L
    midpoint_interval = a * pow(2, exp) + pow(2, exp - 1)
    return midpoint_interval


# converts bits (LSBs) to integer value
def LSB_to_Int(list_k_LSB):
    a = convert_to_int(list_k_LSB)
    return a


# setup single instance (= equation) of hidden number problem
def setup_hnp_single_sample(N, L, list_k_MSB, h, r, s, q, givenbits="msbs", algorithm="ecdsa"):
    t = 0
    u = 0

    # MSBs of nonce k known
    if givenbits == "msbs":
        a = MSB_to_Padded_Int(N, L, list_k_MSB)

        if algorithm == "ecdsa":
            s_inv = mod_inv(s, q)
            z = (h * s_inv) % q
            t = (r * s_inv) % q
            u = (a - z) % q
        elif algorithm == 'ecschnorr':
            t = h % q
            u = (a - s) % q

    # LSBs of nonce k known
    elif givenbits == "lsbs":
        two_powL_inv = mod_inv(pow(2, L), q)
        a = LSB_to_Int(list_k_MSB)

        if algorithm == "ecdsa":
            s_inv = mod_inv(s, q)
            z = (h * s_inv) % q
            t = (r * s_inv * two_powL_inv) % q
            u = ((a - z) * two_powL_inv) % q
        elif algorithm == "ecschnorr":
            t = (h * two_powL_inv) % q
            u = ((a - s) * two_powL_inv) % q

    return t, u


# setup HNP for all signatures given
def setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    t = []
    u = []

    # iterate over all signatures and setup hnp equations
    for i in range(num_Samples):
        t_i, u_i = setup_hnp_single_sample(N, L, listoflists_k_MSB[i], list_h[i], list_r[i], list_s[i], q, givenbits, algorithm)
        t.append(t_i)
        u.append(u_i)

    return t, u


# convert HNP instance to CVP problem (prepare for solver)
def hnp_to_cvp(N, L, num_Samples, list_t, list_u, q):
    scaling_factor = pow(2, L + 1)
    n = num_Samples

    # initialize scaled basis matrix for CVP problem (n+1 x n+1)
    B_cvp = [[] * (n + 1)] * n
    for i in range(n):
        row_i = []
        for j in range(n + 1):
            if i == j:
                row_i.append(q * scaling_factor)
            else:
                row_i.append(0)
        B_cvp[i] = row_i
    # last row contains scaled vector t
    last_row = list(map(lambda t_j: t_j * scaling_factor, list_t))
    last_row.append(1)
    B_cvp.append(last_row)

    # initialize scaled target vector u for CVP problem
    u_cvp = list(map(lambda u_j: u_j * scaling_factor, list_u))
    u_cvp.append(0)

    return B_cvp, u_cvp


# transform the CVP problem into an instance of the SVP problem
def cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u):
    scaling_factor = pow(2, L + 1)
    n = num_Samples

    # educated guess for M
    M = int(pow(num_Samples + 1, 0.5) * pow(2, N - L - 1) * 0.5)

    # initialize scaled basis matrix for SVP problem (n+2 x n+2)
    B_svp = cvp_basis_B
    for i in range(n + 1):
        B_svp[i].append(0)
    # last row contains scaled vector t
    last_row = cvp_list_u
    last_row.append(M * scaling_factor)
    B_svp.append(last_row)

    return B_svp


# use the fpylll solver on a given CVP instance
def solve_cvp(cvp_basis_B, cvp_list_u):
    u = tuple(cvp_list_u)
    B_cvp = IntegerMatrix.from_matrix(cvp_basis_B)

    # reduce CVP basis matrix using LLL algorithm
    lll_alg = LLL()
    B_cvp = lll_alg.reduction(B_cvp)

    # solve CVP problem with fpylll solver, solution vector v
    cvp_solver = CVP()
    v = cvp_solver.closest_vector(B_cvp, u)

    return v


# use the fpylll solver on a given SVP instance
def solve_svp(svp_basis_B):
    # convert to IntegerMatrix
    B_svp = IntegerMatrix.from_matrix(svp_basis_B)

    # use fpylll SVP solver to find the shortest vectors (reduce basis)
    svp_solver = SVP()
    svp_solver.shortest_vector(B_svp)

    return B_svp


# recover signing key x via CVP solver
def recover_x_partial_nonce_CVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits, algorithm)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    v_List = solve_cvp(cvp_basis_B, cvp_list_u)

    # recover the secret signing key x
    x = v_List[num_Samples] % q

    # referring to Q1: check output of cvp_solver
    if check_x(x, Q):
        return x
    else:
        return x + q


# recover signing key x via SVP solver
def recover_x_partial_nonce_SVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits, algorithm)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    svp_basis_B = cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u)
    list_of_f_List = solve_svp(svp_basis_B)

    # find possible solution
    x = 0
    n = num_Samples

    # iterate through shortest vectors
    for f in list_of_f_List:
        v_n = (cvp_list_u[n] - f[n]) % q
        if v_n == 0:
            continue

        # check for right signing key
        if check_x(v_n, Q):
            x = v_n
            break
        elif check_x(v_n + q, Q):
            x = v_n + q
            break

    return x


# testing code: do not modify
from module_1_ECDSA_Cryptanalysis_tests import run_tests

run_tests(recover_x_known_nonce,
    recover_x_repeated_nonce,
    recover_x_partial_nonce_CVP,
    recover_x_partial_nonce_SVP
)