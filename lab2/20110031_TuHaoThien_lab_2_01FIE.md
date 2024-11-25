![image](https://github.com/user-attachments/assets/4d021fb8-3059-4d0b-8e35-efc7552227a5)# Task 1: Transfer files between computers  
**Question 1**: 
Conduct transfering a single plaintext file between 2 computers, 
Using openssl to implementing measures manually to ensure file integerity and authenticity at sending side, 
then veryfing at receiving side. 

**Answer 1**:

Setup in Docker Desktop
**Step 1:** Create Two Docker Containers
Simulate two computers by creating two Docker containers: Sender and Receiver.

Open a terminal and create the Sender container:
```
docker run -it --name sender ubuntu
```
Create the Receiver container:
```
docker run -it --name receiver ubuntu
```


**Step 2:** Install OpenSSL
We need OpenSSL for generating keys, signing files, and verifying signatures. We'll install OpenSSL in both the Sender and Receiver containers.
Inside each container, install OpenSSL:
For Sender:
```
apt update && apt install -y openssl
```
Repeat the same to install openssl in the Receiver container.

**Step 3:** Generate Keys for Authenticity
Run these commands in the sender container key:
```
openssl genrsa -out private_key.pem 2048
```
openssl genrsa: Generates an RSA private key.
-out private_key.pem: Specifies the file to store the private key.
2048: The number of bits for the key. A larger number means stronger encryption.
```
openssl rsa -in private_key.pem -pubout -out public_key.pem
```
openssl rsa: This command allows you to work with RSA keys.
-in private_key.pem: Specifies the private key file.
-pubout: Tells OpenSSL to output the corresponding public key.
-out public_key.pem: Specifies the file to store the public key.

We need a private key to sign files (only the Sender knows this) and a public key to verify the signature (the Receiver uses this). These keys are a core part of digital signatures and cryptographic verification.

![image](https://github.com/user-attachments/assets/7d064b3d-63b5-46df-9863-3f23f0e0fac2)

Then we exit the sender container and copy the file to the host machine then from the host machine move it to the receiver container (Docker does not support copying between containers)
```
docker cp sender:/public_key.pem C:\Users\NHIEN\public_key.pem
docker cp C:\Users\NHIEN\public_key.pem receiver:/public_key.pem
```
Check the file existence on receiver container
![image](https://github.com/user-attachments/assets/350fc31f-d455-4372-837a-6a70a300c87e)

**Step 4:** Create and Sign the Plaintext File

Then, in the sender container, we create a message.txt file to contain the plaintext with the content
```
This is a secure file transfer test.
```
We run this command on sender container:
```
echo "This is a secure file transfer test." > message.txt
```

![image](https://github.com/user-attachments/assets/05aee315-525d-486c-8183-ddc0e5100937)
Then we sign the file for authenticity with openssl
```
openssl dgst -sha256 -sign private_key.pem -out signature.bin message.txt
```
openssl dgst: This is used to create a hash of the file.
-sha256: Specifies the hash algorithm (SHA-256).
-sign private_key.pem: Signs the hash using the private key.
-out signature.bin: The signed hash is saved in signature.bin.
message.txt: The file to be signed.

Now, we should have the file signature.bin
![image](https://github.com/user-attachments/assets/b17c72a8-101c-49cf-83ca-a280599a4f9a)
Now, we cope the file signature.bin and message.txt to the receiver container like Step 3
```
docker cp sender:/message.txt C:\Users\NHIEN\message.txt
docker cp sender:/signature.bin C:\Users\NHIEN\signature.bin
docker cp C:\Users\NHIEN\message.txt receiver:/message.txt
docker cp C:\Users\NHIEN\signature.bin receiver:/signature.bin
```
**Step 5:** Verify File Integrity and Authenticity
In the Receiver container:
- Verify the authenticity of the file using the Sender's public key:
```
openssl dgst -sha256 -verify public_key.pem -signature signature.bin message.txt
```
![image](https://github.com/user-attachments/assets/45cef6f2-b607-45d2-aa8c-c451ce5d8172)

 
# Task 2: Transfering encrypted file and decrypt it with hybrid encryption. 
**Question 1**:
Conduct transfering a file (deliberately choosen by you) between 2 computers. 
The file is symmetrically encrypted/decrypted by exchanging secret key which is encrypted using RSA. 
All steps are made manually with openssl at the terminal of each computer.

**Answer 1**:


# Task 3: Firewall configuration
**Question 1**:
From VMs of previous tasks, install iptables and configure one of the 2 VMs as a web and ssh server. Demonstrate your ability to block/unblock http, icmp, ssh requests from the other host.

**Answer 1**:


