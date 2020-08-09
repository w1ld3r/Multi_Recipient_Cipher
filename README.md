# Multi-Recipient Cipher
Multi-recipient encryption software which protect a file in confidentiality and integrity.

Once the file is protected, it is sent to N recipients. If the recipient is legitimate, he can unprotect it, otherwise he cannot do anything with it.

Each participant has an RSA-2048 key pair for the encryption / decryption and an RSA-2048 key pair for signing.

## Details
- Protect file confidentiality:
    - Kc : random()
    - IV : random()
    - C = AES-CBC-256(input, Kc, IV)
    - RSA PKCS#1 OAEP
- Protect file integrity:
    - Sign the entire message to be sent
    - RSA PKCS#1 PSS

## File strucure
SHA256(kpub-1) || RSA\_kpub-1(Kc) || ... || SHA256(kpub-N) || RSA\_kpub-N(Kc) || 0xDEADBEEF || IV || C || Sign

# Getting started
### Prerequisites
Install python3 and pip:
```
sudo apt install python3 python3-pip
```
Install PyCryptodome:
```
pip3 install pycryptodome
```
### Usage
Generate cipher keys:
```
openssl genrsa 2048 > my_ciph_priv.pem
openssl rsa -in my_ciph_priv.pem -pubout > my_ciph_pub.pem
```
Generate sign keys:
```
openssl genrsa 2048 > my_sign_priv.pem
openssl rsa -in my_sign_priv.pem -pubout > my_sign_pub.pem
```
Protect an input\_file:
```
python3 multi_protect.py -e input_file output_file my_sign_priv.pem my_ciph_pub.pem [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]
```
Unprotect an input\_file:
```
python3 multi_protect.py -d input_file output_file my_priv_ciph.pem my_pub_ciph.pem sender_sign_pub.pem
```
Print help:
```
python3 multi_protect.py -h
```

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.


