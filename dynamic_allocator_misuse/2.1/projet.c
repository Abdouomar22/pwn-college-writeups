#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_MSG_LEN 100

// Node structure
typedef struct Chest {
    int identifier;
    char message[MAX_MSG_LEN];
    struct Chest* next;
} Chest;

// Prime checker
int is_prime(int n) {
    if (n < 2) return 0;
    for (int i = 2; i * i <= n; i++) {
        if (n % i == 0) return 0;
    }
    return 1;
}

// Extract the first number in the message
int extract_number(const char* msg) {
    int number = 0, found = 0;
    for (int i = 0; msg[i]; i++) {
        if (isdigit(msg[i])) {
            number = number * 10 + (msg[i] - '0');
            found = 1;
        } else if (found) {
            break;
        }
    }
    return found ? number : -1;
}

// Add chest sorted by identifier
Chest* add_chest(Chest* head, int id, const char* msg) {
    Chest* new_node = (Chest*)malloc(sizeof(Chest));
    new_node->identifier = id;
    strncpy(new_node->message, msg, MAX_MSG_LEN);
    new_node->next = NULL;

    if (!head || id < head->identifier) {
        new_node->next = head;
        return new_node;
    }

    Chest* curr = head;
    while (curr->next && curr->next->identifier < id)
        curr = curr->next;

    new_node->next = curr->next;
    curr->next = new_node;
    return head;
}

// Remove a chest by id
Chest* remove_chest(Chest* head, int id) {
    Chest* curr = head;
    Chest* prev = NULL;

    while (curr) {
        if (curr->identifier == id) {
            if (prev)
                prev->next = curr->next;
            else
                head = curr->next;
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    return head;
}

// Modify a chest's message
void modify_chest(Chest* head, int id, const char* new_msg) {
    while (head) {
        if (head->identifier == id) {
            strncpy(head->message, new_msg, MAX_MSG_LEN);
            break;
        }
        head = head->next;
    }
}

// Display chests
void display_chests(Chest* head) {
    while (head) {
        printf("ID: %d, Message: \"%s\"\n", head->identifier, head->message);
        head = head->next;
    }
}

// Compute the treasure combination
int discover_treasure(Chest* head) {
    int sum = 0;
    while (head) {
        int msg_len = strlen(head->message);
        if (is_prime(msg_len)) {
            int num = extract_number(head->message);
            if (num != -1)
                sum += num;
        }
        head = head->next;
    }
    return sum;
}

// Main interactive menu
int main() {
    Chest* head = NULL;
    int choice, id;
    char msg[MAX_MSG_LEN];

    do {
        printf("\n--- Pirate Treasure Menu ---\n");
        printf("1. Add chest\n");
        printf("2. Remove chest\n");
        printf("3. Modify chest\n");
        printf("4. Display chests\n");
        printf("5. Discover treasure combination\n");
        printf("0. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);
        getchar(); // consume newline

        switch (choice) {
            case 1:
                printf("Enter chest ID: ");
                scanf("%d", &id);
                getchar();
                printf("Enter message: ");
                fgets(msg, MAX_MSG_LEN, stdin);
                msg[strcspn(msg, "\n")] = '\0';
                head = add_chest(head, id, msg);
                break;
            case 2:
                printf("Enter chest ID to remove: ");
                scanf("%d", &id);
                head = remove_chest(head, id);
                break;
            case 3:
                printf("Enter chest ID to modify: ");
                scanf("%d", &id);
                getchar();
                printf("Enter new message: ");
                fgets(msg, MAX_MSG_LEN, stdin);
                msg[strcspn(msg, "\n")] = '\0';
                modify_chest(head, id, msg);
                break;
            case 4:
                display_chests(head);
                break;
            case 5:
                printf("Treasure Combination: %d\n", discover_treasure(head));
                break;
            case 0:
                printf("Goodbye!\n");
                break;
            default:
                printf("Invalid option.\n");
        }
    } while (choice != 0);

    // Free memory
    while (head) {
        Chest* temp = head;
        head = head->next;
        free(temp);
    }

    return 0;
}
