from __future__ import annotations

class FieldElement:

    # Constructor
    def __init__(self, num: int, prime: int) -> None:

        if num >= prime or num < 0:
            error = f'Num {num} not in field range 0 to {prime - 1}'
            raise ValueError(error)
        self.num = num
        self.prime = prime

    # Representation
    def __repr__(self) -> str:

        return f'FieldElement_{self.prime}({self.num})'

    # Equal Overloading
    def __eq__(self, other: FieldElement) -> bool:
        
        if other is None:
            return False
        
        return self.num == other.num and self.prime == other.prime
    
    # Not Equal Overloading
    def __ne__(self, other: FieldElement) -> bool:
        
        return not (self == other)
    
    # Addition Overloading
    def __add__(self, other: FieldElement) -> FieldElement:

        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)
    
    # Subtraction Overloading
    def __sub__(self, other: FieldElement) -> FieldElement:

        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different Fields')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)
    
    # Multiplication Overloading (Left)
    def __mul__(self, other) -> FieldElement:

        if isinstance(other, int):
            return self * self.__class__(other, self.prime)

        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')
        
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)
    
    # Multiplication Overloading (Right)
    def __rmul__(self, other) -> FieldElement:

        if isinstance(other, int):
            return self * self.__class__(other, self.prime)
        else:
            return self * other
    
    # Division Overloading
    def __truediv__(self, other: FieldElement) -> FieldElement:

        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        num = self.num * pow(other.num, self.prime - 2, self.prime) % self.prime
        return self.__class__(num, self.prime)
    
    # Power Overloading
    def __pow__(self, exponent: int) -> FieldElement:

        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)