import operator
import random

OPERATIONS = [
    ('+', operator.add),
    ('-', operator.sub),
    ('*', operator.mul),
]

def random_question(binary_operations, operand_range):
    """Generate a pair consisting of a random question (as a string)
    and its answer (as a number)"""
    op_sym, op_func = random.choice(binary_operations)
    n1 = random.randint(min(operand_range), max(operand_range))
    n2 = random.randint(min(operand_range), max(operand_range))
    question = '{} {} {}'.format(n1, op_sym, n2)
    answer = op_func(n1, n2)
    return question, answer

def quiz(number_of_questions):
    """Ask the specified number of questions, and return the number of correct
    answers."""
    score = 0
    for _ in range(number_of_questions):
        question, answer = random_question(OPERATIONS, range(0, 21))
        print('What is {}'.format(question))
        try:
            user_input = float(input("Enter the answer: "))
        except ValueError:
            print("I'm sorry that's invalid")
        else:
            if answer == user_input:
                print("Correct!\n")
                score += 1
            else:
                print("Incorrect!\n")
    return score

def identify_user():
    # TODO, as an exercise for you
    pass

def display_score(first_name, last_name, class_name):
    # TODO, as an exercise for you
    pass

def menu():
    # TODO, as an exercise for you
    pass

def main():
    first_name, last_name, class_name = identify_user()
    while True:
        menu_choice = menu()
        if menu_choice == 1:        # Display score
            display_score(first_name, last_name, class_name)

        elif menu_choice == 2:      # Run quiz
            QUESTIONS = 10
            score = quiz(QUESTIONS)
            print('{first_name} {last_name}, you scored {score} out of {QUESTIONS}'.format(**locals()))

        elif menu_choice == 3:      # Exit
            break

        else:
            print("Sorry, I don't understand. Please try again...")
            print()

if __name__ == '__main__':
    #main()
    print(quiz(10))