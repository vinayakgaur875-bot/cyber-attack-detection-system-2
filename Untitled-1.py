cgpas = []

with open("student.txt") as file:
    for line in file:
        fields = line.strip().split(",")
        cgpas.append(float(fields[3]))


def find_minimum(numbers):
    minimum = numbers[0]

    for value in numbers:
        if value < minimum:
            minimum = value

    return minimum


def find_maximum(numbers):
    maximum = numbers[0]

    for value in numbers:
        if value > maximum:
            maximum = value

    return maximum


average = sum(cgpas) / len(cgpas)

above_average = 0

for value in cgpas:
    if value > average:
        above_average += 1


print(find_minimum(cgpas), find_maximum(cgpas), average, above_average)