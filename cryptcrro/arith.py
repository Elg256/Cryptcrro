import random

def next_prime(n):
    if n % 2 == 0:
        n += 1

    while True:
        if miller_rabin(n):
            return n
        n += 2


# based on github.com/bouDeScotch version
def miller_rabin(n, k=40):
    if n < 2:
        return False
    if n in {2, 3, 5, 7, 11, 13, 17}:
        return True
    if n % 2 == 0:
        return False

    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    def check(a):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False

    for _ in range(k):
        a = random.randint(2, n - 2)
        if not check(a):
            return False
    return True
