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
In this step, we will use the same containers from task 1 without reinstallation of openssl. We just need to remove the old files like private_ket.pem, public_key.pem, signature.bin
**Step 1:** Generate RSA Keys for Asymmetric Encryption
We'll generate a pair of RSA keys for each container. The private key will be kept secure on each container, and the public key will be shared.
In the **Sender** container, generate RSA Private and Public Key:
```
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```
![image](https://github.com/user-attachments/assets/9290fbc1-8518-46a5-8bb3-9fe4207f743c)
![image](https://github.com/user-attachments/assets/6f22224c-8d09-4bf6-9caa-5baa65de2c57)

Then, we copy the public_ket.pem and private_key.pem from the sender container to the receiver container.
```
docker cp sender:/private_key.pem C:\Users\NHIEN\private_key.pem
docker cp C:\Users\NHIEN\private_key.pem receiver:/private_key.pem
docker cp sender:/public_key.pem C:\Users\NHIEN\public_key.pem
docker cp C:\Users\NHIEN\public_key.pem receiver:/public_key.pem
```

**Step 2:** Encrypt the Secret Symmetric Key Using RSA (For Transmission)
In the Sender Container:
Generate a Random Secret Key for AES encryption (a 256-bit key):
```
openssl rand -out secret.key 32
```
Then, we encrypt the File Using AES (Symmetric Encryption). Suppose the file we want to encrypt is message.txt. Use the secret key to encrypt the file with AES-256-CBC.
```
openssl enc -aes-256-cbc -salt -in message.txt -out message.txt.enc -pass file:./secret.key
```
enc -aes-256-cbc: Specifies the AES-256-CBC encryption algorithm.
-salt: Adds a random salt to strengthen encryption.
-in message.txt: Specifies the input file to encrypt.
-out message.txt.enc: Specifies the output encrypted file.
-pass file:./secret.key: Uses the secret.key file as the password (AES symmetric key).
![image](https://github.com/user-attachments/assets/fbb1bcb4-44a1-4a8e-b136-2d58e2ebc9c6)


Then, we encrypt the Secret Key with the Receiver's Public Key (RSA Encryption).
```
 openssl pkeyutl -encrypt -inkey public_key.pem -pubin -in secret.key -out secret.key.enc
```
pkeyutl -encrypt: Encrypts data using RSA.
-inkey public_key.pem: Specifies the Receiver's public key.
-pubin: Indicates the key is a public key.
-in secret.key: Specifies the file containing the secret AES key.
-out secret.key.enc: Specifies the output encrypted file.
![image](https://github.com/user-attachments/assets/101a5f85-4f0c-44b6-90b3-be3c9b7040a6)


Now, message.txt.enc and secret.key.enc are ready to be transferred.

**Step 3:** Transfer the Encrypted Files to the Receiver Container
```
docker cp sender:/secret.key.enc C:\Users\NHIEN\secret.key.enc
docker cp sender:/message.txt.enc C:\Users\NHIEN\message.txt.enc
docker cp C:\Users\NHIEN\message.txt.enc receiver:/message.txt.enc
docker cp C:\Users\NHIEN\secret.key.enc receiver:/secret.key.enc
```
Now, we check if these files existence on the receiver container or not
![image](https://github.com/user-attachments/assets/64165099-5153-4b07-b7f4-b32d6f249978)

**Step 4:** Decrypt the Secret Key Using RSA (Receiver)
In the Receiver Container, decrypt the Secret Key (which was encrypted using the Sender's RSA public key):
```
openssl pkeyutl -decrypt -inkey private_key.pem -in secret.key.enc -out secret.key
```
pkeyutl -decrypt: Decrypts data using RSA.
-inkey private_key.pem: Specifies the Receiver’s private key.
-in secret.key.enc: The encrypted secret key received from the Sender.
-out secret.key: The decrypted secret key (AES key).
![image](https://github.com/user-attachments/assets/30bf5de9-ded5-440f-8a34-68285f476bae)
After decryption, we should now have a secret.key file containing the original AES key used for encrypting the file.
![image](https://github.com/user-attachments/assets/4b7b6236-98cc-48b6-9659-bc721f46f9c7)
Now that the Receiver has the secret key, they can decrypt the file using the AES key.
```
openssl enc -d -aes-256-cbc -in message.txt.enc -out message.txt -pass file:./secret.key
```
enc -d -aes-256-cbc: Specifies decryption using AES-256-CBC.
-in message.txt.enc: The encrypted file.
-out message.txt: The decrypted file will be saved here.
-pass file:./secret.key: The AES key used for decryption (which we just decrypted).



**Step 7:** Decrypt the File Using AES (Receiver)
Now, we have the secret key that has been decrypted, all we need to do is to use that secret key (secret.key file) to decrypt the message.txt.enc file so that we can get the original content of message.txt file
```
openssl enc -d -aes-256-cbc -in message.txt.enc -out message.txt -pass file:./secret.key
```
![image](https://github.com/user-attachments/assets/3f9ad8ea-5d72-4bba-9db9-57c63735dbf6)


# Task 3: Firewall configuration
**Question 1**:
From VMs of previous tasks, install iptables and configure one of the 2 VMs as a web and ssh server. Demonstrate your ability to block/unblock http, icmp, ssh requests from the other host.

**Answer 1**:
**Step 1:** Install necessary packages in both containers
Inside both containers (sender and receiver), install iptables, curl, ssh, and Apache.
```
apt update
apt install iptables curl openssh-server apache2 -y
```
**Step 2:** Configure the Receiver Container (Web and SSH Server)
