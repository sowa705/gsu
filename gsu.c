//gsu - switch users the based way
//Copyright (C) 2021 Łukasz Sowa
//
//This program is free software: you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>

//fast and """secure""" rng for password generation
uint32_t xorshift32(uint32_t *state)
{
    /* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return *state = x;
}

//generates an uid from password
uint16_t calculate_uid(const char *password_buf)
{
    uint16_t uid = 0;
    int i = 0;
    while (password_buf[i])
    {
        uid *= 2;
        uid += password_buf[i];
        i++;
    }
    return uid;
}
//generates a random password from uid compatible with the official gsu algorithm
char *generate_password(int target_uid, int length,uint32_t rng)
{
    char *password_buf = malloc(length + 1);
    password_buf[length] = 0;

    while (1)
    {
        for (int i = 0; i < length; i++)
        {
            password_buf[i] = 'A' + (xorshift32(&rng) % 26);
        }
        uint16_t uid = calculate_uid(password_buf);
        if (uid == target_uid)
        {
            break;
        }
    }
    return password_buf;
}
// opens the user's shell
void open_shell(int uid){
    char* shell = getpwuid(uid)->pw_shell;
    if(execl(shell, shell, NULL)){
        perror("execl");
        exit(1);
    }
    
}
// prints the usage information
void usage(const char* arg){
    printf("To log in with your password: %s\n", arg);
    printf("To generate a single password for a specific UID: %s --generate <uid>\n", arg);
    printf("To generate multiple passwords for a specific UID: %s --generate <uid> <password count>\n", arg);
}

//generates and prints a list of passwords for a specific uid
void generate(int uid,int count){
    int rng=time(NULL);
    xorshift32(&rng);

    for (int i = 0; i < count; i++)
    {
        rng++;
        xorshift32(&rng);
        char *password = generate_password(uid, 12,rng);
        printf("%s\n",password);
    }
}

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "--help") == 0)
    {
        usage(argv[0]);
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "--generate") == 0)
    {
        int target_uid = atoi(argv[2]);
        int passwordcount = 1;
        if (argc == 4)
        {
            passwordcount = atoi(argv[3]);
        }

        generate(target_uid, passwordcount);
        
        return 0;
    }
    //what could go wrong with a fixed size bufffer?
    char password_buf[100];
    printf("Enter password: ");
    scanf("%s", password_buf);
    int uid = calculate_uid(password_buf);
    printf("Logging in as %d\n", uid);

    if (setuid(uid)){
        printf("Failed to setuid(%d)\nCheck your password and try again\n", uid);
        return 1;
    }

    open_shell(uid);

    return 0;
}

