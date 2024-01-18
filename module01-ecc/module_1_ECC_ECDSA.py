import math
import random
import warnings
import hashlib

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

# Function to map a message to a bit string
def hash_message_to_bits(msg):
    h = hashlib.sha256()
    h.update(msg.encode())
    h_as_bits = ''.join(format(byte, '08b') for byte in h.digest())
    return h_as_bits

# Function to map a truncated bit string to an integer modulo q
def bits_to_int(h_as_bits, q):
    val = 0
    len = int(math.log(q, 2) + 1)
    for i in range(len):
        val = val * 2
        if(h_as_bits[i] == '1'):
            val = val + 1
    return val % q

# An elliptic curve is represented as an object of type Curve. 
# Note that for this lab, we use the short Weierstrass form of representation.
class Curve(object):

    def __init__(self, a, b, p, P_x, P_y, q):
        self.a = a
        self.b = b
        self.p = p
        self.P_x = P_x
        self.P_y = P_y
        self.q = q

    def is_singular(self):
        return (4 * self.a**3 + 27 * self.b**2) % self.p == 0

    def on_curve(self, x, y):
        return (y**2 - x**3 - self.a * x - self.b) % self.p == 0

    def is_equal(self, other):
        if not isinstance(other, Curve):
            return False
        return self.a == other.a and self.b == other.b and self.p == other.p

# A point at infinity on an elliptic curve is represented separately as an object of type PointInf. 
# We make this distinction between a point at infinity and a regular point purely for the ease of implementation.
class PointInf(object):

    def __init__(self, curve):
        self.curve = curve

    def is_equal(self, other):
        if not isinstance(other, PointInf):
            return False
        return self.curve.is_equal(other.curve)

    def negate(self):
        # inverse of O is O
        return self

    def double(self):
        # O+O=O (O is additive identity)
        return self

    def add(self, other):
        if not isinstance(other, PointInf):
            return other
        return self


# A point on an elliptic curve is represented as an object of type Point. 
# Note that for this lab, we will use the affine coordinates-based representation of a point on an elliptic curve.
class Point(object):

    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
        self.p = self.curve.p
        self.on_curve = True
        if not self.curve.on_curve(self.x, self.y):
            warnings.warn("Point (%d, %d) is not on curve \"%s\"" % (self.x, self.y, self.curve))
            self.on_curve = False

    # same point on same curve
    def is_equal(self, other):
        if not isinstance(other, Point):
            return False
        return self.curve.is_equal(other.curve) and self.x == other.x and self.y == other.y

    def negate(self):
        # Write a function that negates a Point object and returns the resulting Point object
        # Ths is an optional extension and is not evaluated
        y_new = (-1 * self.y) % self.p
        self.y = y_new
        return self

    def double(self):
        y_inv = mod_inv(2 * self.y, self.p)
        slope = ((3 * self.x**2 + self.curve.a) * y_inv) % self.p
        x_ = (slope**2 - 2 * self.x) % self.p
        y_ = (-1 * (self.y + slope * (x_ - self.x))) % self.p
        return Point(self.curve, x_, y_)

    def add(self, other):
        # point must lie on same curve
        assert self.curve.is_equal(other.curve), "Can't add points that are not on the same curve."

        # special case if other is PointInf
        if isinstance(other, PointInf):
            return self

        # special case if same x-coord
        if self.x == other.x:
            # same point, double the point
            if self.y == other.y:
                return self.double()
            # negative of point, yields point at inf
            else:
                return PointInf(self.curve)
        # add two points on curve
        else:
            # formula
            delta_x_inv = mod_inv(self.x - other.x, self.p)
            slope = ((self.y - other.y) * delta_x_inv) % self.p
            x_ = (slope**2 - self.x - other.x) % self.p
            y_ = (-1 * (self.y + slope * (x_ - self.x))) % self.p
            return Point(self.curve, x_, y_)


    def scalar_multiply(self, scalar):
        assert isinstance(scalar, int), "Scalar is not of type int."

        if scalar != 0:
            # adding q times yields point at infinity
            if scalar == self.curve.q:
                return PointInf(self.curve)
            else:
                bitstring = bin(scalar)
                point = Point(self.curve, self.x, self.y)
                for b in bitstring[3:]:
                    point = point.double()
                    if int(b) == 1:
                        point = point.add(self)
                return point
        else:
            return PointInf(self.curve)

    def scalar_multiply_Montgomery_Ladder(self, scalar):
        # Write a function that performs a "constant-time" scalar multiplication on the current Point object and returns the resulting Point object 
        # Make sure to check that the scalar is of type int or long
        # Implement an elementary timer to check that your implementation is indeed constant-time
        # This is not graded but is an extension for you to try out on your own
        raise NotImplementedError()


# The parameters for an ECDSA scheme are represented as an object of type ECDSA_Params
class ECDSA_Params(object):
    def __init__(self, a, b, p, P_x, P_y, q):
        self.p = p
        self.q = q
        self.curve = Curve(a, b, p, P_x, P_y, q)
        self.P = Point(self.curve, P_x, P_y)


def KeyGen(params):
    # random choice of x in [1, q-1]
    x = random.randrange(1, params.q)
    Q = params.P.scalar_multiply(x)
    return x, Q

def Sign_FixedNonce(params, k, x, msg):
    # create hash of message
    msg_b = hash_message_to_bits(msg)
    h = bits_to_int(msg_b, params.q)
    k_inv = mod_inv(k, params.q)

    # ECDSA formula
    mult_P = params.P.scalar_multiply(k)
    r = mult_P.x % params.q
    s = (k_inv * (h + x * r)) % params.q
    return r, s


def Sign(params, x, msg):
    r = 0
    s = 0
    # loop until both non-zero
    while r == 0 or s == 0:
        k = random.randrange(1, params.q)
        r, s = Sign_FixedNonce(params, k, x, msg)
    return r, s

def Verify(params, Q, msg, r, s):
    # check range of r and s
    if r < 1 or r >= params.q:
        return 0
    if s < 1 or s >= params.q:
        return 0

    # hash msg and compute parameters for signature
    msg_b = hash_message_to_bits(msg)
    h = bits_to_int(msg_b, params.q)
    w = mod_inv(s, params.q)
    u1 = (w * h) % params.q
    u2 = (w * r) % params.q

    u1P = params.P.scalar_multiply(u1)
    u2Q = Q.scalar_multiply(u2)
    Z = u1P.add(u2Q)

    # check if signature is valid
    if r == (Z.x % params.q):
        return 1
    else:
        return 0


from module_1_ECC_ECDSA_tests import run_tests
run_tests(ECDSA_Params, Point, KeyGen, Sign, Sign_FixedNonce, Verify)
