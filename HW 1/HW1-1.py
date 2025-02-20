from FieldElement import FieldElement

PRIME = 701
print(f'Solving Prblems in Field_{PRIME}')

# Problem 1-1
P1_1 = FieldElement(599, PRIME)
P1_2 = FieldElement(607, PRIME)
P1_3 = FieldElement(613, PRIME)
print('1-1. ', P1_1 * P1_2 * P1_3)

# Problem 1-2
P2_1 = FieldElement(23, PRIME)
P2_2 = FieldElement(223, PRIME)
P2_3 = FieldElement(509, PRIME)
P2_4 = FieldElement(666, PRIME)
print('1-2. ', P2_1 * P2_2 * P2_3 * P2_4)

# Problem 1-3
P3_1 = FieldElement(337, PRIME)
P3_2 = FieldElement(557, PRIME)
P3_3 = P3_1 ** 79
P3_4 = P3_2 ** 131
print('1-3. ', P3_3 * P3_4)