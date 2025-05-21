from Point import *

def get_slope(P1: Point, P2: Point) -> Fraction:
    if P1.x == P2.x and P1.y == P2.y:
        # Special case: P1 == P2
        if P1.y == 0:
            return None
        return Fraction(3 * P1.x**2 + P1.a, 2 * P1.y)
    elif P1.x != P2.x:
        return Fraction(P1.y - P2.y, P1.x - P2.x)
    else:
        return None

# Problem 4-1
# Curve: y^2 = x^3 - 11x + 11
A1 = -11
B1 = 11
P1 = Point( 5, -9, A1, B1)
print('4-1.')
print("Slope:", get_slope(P1, P1))
print(P1 + P1)

# Problem 4-2
# Curve: y^2 = x^3 - 9x + 1
A2 = -9
B2 = 1
P2 = Point( 5,  9, A2, B2)
print('4-2.')
print("Slope:", get_slope(P2, P2))
print(P2 + P2)