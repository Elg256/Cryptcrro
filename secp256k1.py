

# Définition des paramètres de la courbe elliptique secp256k1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # Premier (modulus)
a = 0x0000000000000000000000000000000000000000000000000000000000000000  # Coefficient a de l'équation y^2 = x^3 + ax + b (pour secp256k1, a = 0)
b = 0x0000000000000000000000000000000000000000000000000000000000000007  # Coefficient b de l'équation y^2 = x^3 + ax + b (pour secp256k1, b = 7)
gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798  # Coordonnée x du générateur G
gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8  # Coordonnée y du générateur G
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # Ordre du générateur G

# Fonction pour ajouter deux points sur la courbe elliptique
def point_addition(x1, y1, x2, y2):
    if x1 == 0 and y1 == 0:  # Si le premier point est l'infini, retourner le deuxième point
        return x2, y2
    if x2 == 0 and y2 == 0:  # Si le deuxième point est l'infini, retourner le premier point
        return x1, y1
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return 0, 0
    if x1 == x2:  # Doublage du point
        m = (3 * x1 * x1) % p
        m = (m * pow(2 * y1, p - 2, p)) % p
    else:  # Addition normale
        m = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return x3, y3

def point_addition_manual(x1, y1, x2, y2):
    if x1 == 0 and y1 == 0:  # Si le premier point est l'infini, retourner le deuxième point
        return x2, y2
    if x2 == 0 and y2 == 0:  # Si le deuxième point est l'infini, retourner le premier point
        return x1, y1
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return 0, 0
    if x1 == x2:  # Doublage du point
        m = (3 * x1 * x1) % p
        m = (m * pow(2 * y1, p - 2, p)) % p
    else:  # Addition normale
        m = ((y2 - y1) / (x2 - x1)) % p
    x3 = m**2-(x2+x1) % p
    y3 = (m*(x2-x3)-y2) % p
    return x3, y3

# Fonction pour doubler un point sur la courbe elliptique
def point_double(x1, y1):
    return point_addition(x1, y1, x1, y1)

# Fonction pour multiplier un point par un scalaire (utilisant la méthode de doublement et d'addition)
def point_multiply(scalar, generator):
    result = (0, 0)
    addend = generator
    while scalar:
        if scalar & 1:
            result = point_addition(result[0], result[1], addend[0], addend[1])
        addend = point_double(addend[0], addend[1])
        scalar >>= 1
    return result


