from FieldElement import FieldElement

PRIME = 881
print(f'Solving Prblems in Field_{PRIME}')

# Problem 2-1
P2_1_1 = FieldElement(800, PRIME)
P2_1_2 = FieldElement(31, PRIME)
print('2-1. ', P2_1_1 / P2_1_2)

# Problem 2-2
P2_2_1 = FieldElement(201, PRIME)
P2_2_2 = P2_2_1 ** -101
P2_2_3 = FieldElement(57, PRIME)
print('2-2. ', P2_2_2 * P2_2_3)
