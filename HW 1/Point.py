from __future__ import annotations
from fractions import Fraction

class Point:

    # Constructor
    # Elliptic Curve : y^2 = x^3 + ax + b
    def __init__(self, x, y, a, b) -> None:
        
        try:
            self.x = Fraction(x) if x is not None else None
            self.y = Fraction(y) if y is not None else None
            self.a = Fraction(a)
            self.b = Fraction(b)
        except:
            raise TypeError('Arguments contains non-numeric value')

        if self.x is None and self.y is None:
            return

        if self.y**2 != self.x**3 + a*x + b:
            raise ValueError(f'({self.x}, {self.y}) is not on the curve')

    # Representation
    def __repr__(self) -> str:
        return f'Point({self.x},{self.y})_{self.a}_{self.b}'
        
    # Equal Overloading
    def __eq__(self, other: Point) -> bool:
        return self.x == other.x and self.y == other.y \
               and self.a == other.a and self.b == other.b
    
    # Addition Overloading
    def __add__(self, other: Point) -> Point:

        # Error Handling
        if self.a != other.a or self.b != other.b:
            raise TypeError(f'Points {self}, {other} are not on the same curve')
        
        # Identity
        if self.x is None:
            return other
        if other.x is None:
            return self
        
        # slope in different conditions
        # P1 == P2
        if self == other:
            # Special Case:
            if self.y == 0:
                return self.__class__(None, None, self.a, self.b)
            s = (3 * self.x**2 + self.a) / (2 * self.y)
        
        # x1 != x2
        if self.x != other.x:
            s = (self.y - other.y) / (self.x - other.x)
        # x1 == x2
        else:
            return self.__class__(None, None, self.a, self.b)

        x3 = s**2 - self.x - other.x
        y3 = s * (self.x - x3) - self.y

        return self.__class__(x3, y3, self.a, self.b)