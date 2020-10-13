from secrets import randbelow
from random import shuffle
from functools import reduce
from operator import mul

# Crypto-safe RNG from python secrets module
def randrange(a,b):
    return randbelow(b-a)+a

# Modular Inverse
def mod_inv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m

def extended_gcd(a, b):
    lastremainder, remainder = abs(a), abs(b)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if a < 0 else 1), lasty * (-1 if b < 0 else 1)

def prod(vals):
    return reduce(mul, vals, 1)
