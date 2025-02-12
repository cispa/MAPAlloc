#include <linux/ctype.h>
#include <linux/string.h>
#include "../include/interfaces.h"


// Stack for operators
typedef struct {
    char op[100][3];  // Adjusted to store multi-character operators
    int top;
} OperatorStack;

// Stack for values
typedef struct {
    unsigned long values[100];
    int top;
} ValueStack;

static void push_operator(OperatorStack *stack, char *op) {
    strcpy(stack->op[++stack->top], op);
}

static char* pop_operator(OperatorStack *stack) {
    return stack->op[stack->top--];
}

static char* peek_operator(OperatorStack *stack) {
    return stack->op[stack->top];
}

static int is_empty_operator(OperatorStack *stack) {
    return stack->top == -1;
}

static void push_value(ValueStack *stack, unsigned long value) {
    stack->values[++stack->top] = value;
}

static unsigned long pop_value(ValueStack *stack) {
    return stack->values[stack->top--];
}

// Function to get precedence of operators
static int precedence(char *op) {
    if (strcmp(op, "==") == 0 || strcmp(op, "!=") == 0) return 1;
    if (strcmp(op, "<") == 0 || strcmp(op, ">") == 0 || strcmp(op, "<=") == 0 || strcmp(op, ">=") == 0) return 2;
    if (strcmp(op, "|") == 0) return 3;
    if (strcmp(op, "^") == 0) return 4;
    if (strcmp(op, "&") == 0) return 5;
    if (strcmp(op, "||") == 0 || strcmp(op, "&&") == 0) return 6;
    if (strcmp(op, "<<") == 0 || strcmp(op, ">>") == 0) return 7;
    if (strcmp(op, "+") == 0 || strcmp(op, "-") == 0) return 8;
    if (strcmp(op, "*") == 0 || strcmp(op, "/") == 0 || strcmp(op, "%") == 0) return 9;
    if (strcmp(op, "~") == 0) return 10;
    return -1;
}

// Apply operator function
static unsigned long apply_operator(char *op, unsigned long b, unsigned long a) {
    if (strcmp(op, "||") == 0) return a || b;
    if (strcmp(op, "&&") == 0) return a && b;
    if (strcmp(op, "+") == 0) return a + b;
    if (strcmp(op, "-") == 0) return a - b;
    if (strcmp(op, "*") == 0) return a * b;
    if (strcmp(op, "/") == 0) return a / b;
    if (strcmp(op, "&") == 0) return a & b;
    if (strcmp(op, "|") == 0) return a | b;
    if (strcmp(op, "^") == 0) return a ^ b;
    if (strcmp(op, "<<") == 0) return a << b;
    if (strcmp(op, ">>") == 0) return a >> b;
    if (strcmp(op, "~") == 0) return ~b;  // Unary operator
    if (strcmp(op, "==") == 0) return a == b;
    if (strcmp(op, "!=") == 0) return a != b;
    if (strcmp(op, "<") == 0) return a < b;
    if (strcmp(op, ">") == 0) return a > b;
    if (strcmp(op, "<=") == 0) return a <= b;
    if (strcmp(op, ">=") == 0) return a >= b;
    if (strcmp(op, "%") == 0) return a % b;
    return 0;
}

// Helper function to check if a character is an operator
static int is_operator(char c) {
    return strchr("+-*/&|^~<>!=()%", c) != NULL;
}

// Function to parse the expression without relying on whitespace
unsigned long shunting_yard(const char *expression, unsigned long x_value) {
    OperatorStack operators = { .top = -1 };
    ValueStack values = { .top = -1 };
    int i = 0, n = strlen(expression);
    
    while (i < n) {
        // If the token is a digit, parse the whole number
        if (isdigit(expression[i])) {
            unsigned long num = 0;
            while (i < n && isdigit(expression[i])) {
                num = num * 10 + (expression[i] - '0');
                i++;
            }
            push_value(&values, num);
            continue;
        }
        // If token is 'x', push the value of 'x' (variable)
        else if (expression[i] == 'x') {
            push_value(&values, x_value);
        }
        // If token is '(', push it to the operator stack
        else if (expression[i] == '(') {
            push_operator(&operators, "(");
        }
        // If token is ')', pop until '('
        else if (expression[i] == ')') {
            while (!is_empty_operator(&operators) && strcmp(peek_operator(&operators), "(") != 0) {
                char *op = pop_operator(&operators);
                if (strcmp(op, "~") == 0) {
                    unsigned long val = pop_value(&values);
                    push_value(&values, apply_operator(op, val, 0));
                } else {
                    unsigned long val2 = pop_value(&values);
                    unsigned long val1 = pop_value(&values);
                    push_value(&values, apply_operator(op, val2, val1));
                }
            }
            pop_operator(&operators); // Remove '('
        }
        // Handle bit shift operators (<< and >>), and comparison operators (<=, >=, ==, !=, ||, &&)
        else if (expression[i] == '<' || expression[i] == '>' || expression[i] == '=' ||
			expression[i] == '!' || expression[i] == '&' || expression[i] == '|') {
            char op[3] = { expression[i], expression[i + 1], '\0' };
            if (op[1] == '=' || (op[0] == '<' && op[1] == '<') || (op[0] == '>' && op[1] == '>')) {
                i++;
                while (!is_empty_operator(&operators) && precedence(peek_operator(&operators)) >= precedence(op)) {
                    char *top_op = pop_operator(&operators);
                    unsigned long val2 = pop_value(&values);
                    unsigned long val1 = pop_value(&values);
                    push_value(&values, apply_operator(top_op, val2, val1));
                }
                push_operator(&operators, op); // Push the operator (like <<, >>, <=, >=, ==, !=)
            } else if ((op[0] == '|' && op[1] == '|') || (op[0] == '&' && op[1] == '&')) {
                i++;
                while (!is_empty_operator(&operators) && precedence(peek_operator(&operators)) >= precedence(op)) {
                    char *top_op = pop_operator(&operators);
                    unsigned long val2 = pop_value(&values);
                    unsigned long val1 = pop_value(&values);
                    push_value(&values, apply_operator(top_op, val2, val1));
                }
                push_operator(&operators, op); // Push the operator (like ||, &&)
	    } else {
                char op_single[2] = { expression[i], '\0' };
                while (!is_empty_operator(&operators) && precedence(peek_operator(&operators)) >= precedence(op_single)) {
                    char *top_op = pop_operator(&operators);
                    unsigned long val2 = pop_value(&values);
                    unsigned long val1 = pop_value(&values);
                    push_value(&values, apply_operator(top_op, val2, val1));
                }
                push_operator(&operators, op_single);
            }
        }
        // If token is an operator
        else if (is_operator(expression[i])) {
            char op[2] = { expression[i], '\0' };
            while (!is_empty_operator(&operators) && precedence(peek_operator(&operators)) >= precedence(op)) {
                char *top_op = pop_operator(&operators);
                if (strcmp(top_op, "~") == 0) {
                    unsigned long val = pop_value(&values);
                    push_value(&values, apply_operator(top_op, val, 0));
                } else {
                    unsigned long val2 = pop_value(&values);
                    unsigned long val1 = pop_value(&values);
                    push_value(&values, apply_operator(top_op, val2, val1));
                }
            }
            push_operator(&operators, op);
        }
        i++;
    }
    
    // Apply remaining operators
    while (!is_empty_operator(&operators)) {
        char *op = pop_operator(&operators);
        if (strcmp(op, "~") == 0) {
            unsigned long val = pop_value(&values);
            push_value(&values, apply_operator(op, val, 0));
        } else {
            unsigned long val2 = pop_value(&values);
            unsigned long val1 = pop_value(&values);
            push_value(&values, apply_operator(op, val2, val1));
        }
    }
    
    return pop_value(&values);
}