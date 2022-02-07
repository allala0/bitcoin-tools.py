def inverse(x: int, p: int) -> int:

    inv1 = 1
    inv2 = 0
    while p != 1 and p != 0:
        inv1, inv2 = inv2, inv1 - inv2 * (x // p)
        x, p = p, x % p
    return inv2


def double(pt: tuple, p: int) -> tuple:
    if pt is None:
        return
    (x, y) = pt
    if y == 0:
        return

    # Calculate 3*x^2/(2*y)  modulus p
    slope = 3 * pow(x, 2, p) * inverse(2 * y, p)
    xsum = pow(slope, 2, p) - 2 * x
    ysum = slope * (x - xsum) - y

    return xsum % p, ysum % p


def add(p1: tuple, p2: tuple, p: int) -> tuple:
    if p1 is None or p2 is None:
        return None
    (x1, y1) = p1
    (x2, y2) = p2
    if x1 == x2:
        return double(p1, p)
    slope = (y1 - y2) * inverse(x1 - x2, p)
    xsum = pow(slope, 2, p) - (x1 + x2)
    ysum = slope * (x1 - xsum) - y1
    return xsum % p, ysum % p


def multiply(gen: tuple, a: int, p: int) -> tuple:
    scale = gen
    acc = None
    while a:
        if a & 1:
            if acc is None:
                acc = scale
            else:
                acc = add(acc, scale, p)
        scale = double(scale, p)
        a >>= 1
    return acc
