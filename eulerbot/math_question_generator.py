import random

OPERATIONS = [
    '+',
    '-',
    '*'
]

def random_question(binary_operations, operand_range, operand_number):
    random_operations = [random.choice(binary_operations)for _ in range(operand_number-1)]
    random_numbers = [random.randint(min(operand_range), max(operand_range)) for _ in range(operand_number)]
    question = ""
    for i in range(operand_number-1):
        question += '{} {} '.format(random_numbers[i], random_operations[i])
    question += "{}".format(random_numbers[-1])

    answer = eval(question, {'__builtins__':None})
    return question, answer

def question_generator(level):
    if level == "Easy":
        return random_question(['+', '-'], [10, 100], 2)
    elif level == "Medium":
        return random_question(OPERATIONS, [10, 100], 2)
    elif level == "Hard":
        return random_question(OPERATIONS, [10, 100], 3)

if __name__ == '__main__':
    print(question_generator("Medium"))