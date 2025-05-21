from Point import *
from fractions import Fraction

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

# Problem 3-1
# Curve: y^2 = x^3 - 11x + 11
A1 = -11
B1 = 11
P1_1 = Point(-2, -5, A1, B1)
P1_2 = Point( 5, -9, A1, B1)
print('3-1.')
print("Slope:", get_slope(P1_1, P1_2))
print(P1_1 + P1_2)

# Problem 3-2
# Curve: y^2 = x^3 - 7x + 3
A2 = -7
B2 = 3
P2_1 = Point(-2, -3, A2, B2)
P2_2 = Point( 3,  3, A2, B2)
print('3-2.')
print("Slope:", get_slope(P2_1, P2_2))
print(P2_1 + P2_2)

# Problem 3-3
# Curve: y^2 = x^3 - 9x + 1
A3 = -9
B3 = 1
P3_1 = Point(-3, -1, A3, B3)
P3_2 = Point( 5,  9, A3, B3)
print('3-3.')
print("Slope:", get_slope(P3_1, P3_2))
print(P3_1 + P3_2)