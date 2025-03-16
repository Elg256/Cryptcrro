# Definition of the secp256k1 elliptic curve parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # Prime (modulus)
a = 0x0000000000000000000000000000000000000000000000000000000000000000  # Coefficient a of the equation y^2 = x^3 + ax + b (for secp256k1, a = 0)
b = 0x0000000000000000000000000000000000000000000000000000000000000007  # Coefficient b of the equation y^2 = x^3 + ax + b (for secp256k1, b = 7)
gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798  # x-coordinate of the generator G
gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8  # y-coordinate of the generator G
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # Order of the generator G

# Function to add two points on the elliptic curve
def point_addition(x1, y1, x2, y2):
    if x1 == 0 and y1 == 0:  # If the first point is at infinity, return the second point
        return x2, y2
    if x2 == 0 and y2 == 0:  # If the second point is at infinity, return the first point
        return x1, y1
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return 0, 0
    if x1 == x2:  # Point doubling
        m = (3 * x1 * x1) % p
        m = (m * pow(2 * y1, p - 2, p)) % p
    else:  # Regular addition
        m = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return x3, y3

def point_addition_manual(x1, y1, x2, y2):
    if x1 == 0 and y1 == 0:  # If the first point is at infinity, return the second point
        return x2, y2
    if x2 == 0 and y2 == 0:  # If the second point is at infinity, return the first point
        return x1, y1
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return 0, 0
    if x1 == x2:  # Point doubling
        m = (3 * x1 * x1) % p
        m = (m * pow(2 * y1, p - 2, p)) % p
    else:  # Regular addition
        m = ((y2 - y1) / (x2 - x1)) % p
    x3 = m**2-(x2+x1) % p
    y3 = (m*(x2-x3)-y2) % p
    return x3, y3

# Function to double a point on the elliptic curve
def point_double(x1, y1):
    return point_addition(x1, y1, x1, y1)

# Function to multiply a point by a scalar (using the double and add method)
def point_multiply(scalar, generator):
    result = (0, 0)
    addend = generator
    while scalar:
        if scalar & 1:
            result = point_addition(result[0], result[1], addend[0], addend[1])
        addend = point_double(addend[0], addend[1])
        scalar >>= 1
    return result
