## Hashing
* Irreversible process, to create unique identifier for given input
* Need hash algorithm but does not involve a secret key
* Length is determined by hash function, produces fixed-length hash value
* Focused on data integrity rather than confidentiality, ensures original data
* Types
    1. MD5
        <br/>Output size : 128-bit / Block size : 512-bit / Rounds : 4
    2. SHA-1
        <br/>Output size : 160-bit / Block size : 512-bit / Rounds : 80
    3. SHA-256
        <br/>Output size : 256-bit / Block size : 512-bit / Rounds : 512

## Encryption/Decryption
* Reversible process, to secure communication or storage of data
* Need encryption algorithm and secret key
* Length is same as or longer than the original plaintext
* Focused on providing confidentiality by unintelligible to unauthorized parties
* Types
    1. DES (Symmetric)
        <br/>Key length : 56-bit / Block size : 64-bit / Rounds : 16
    2. 3DES (Symmetric)
        <br/>Key length : 112-bit(EDE), 168-bit(EEE) / Block size : 64-bit / Rounds : 48
    3. AES (Symmetric)
        <br/>Key length : 128, 192, 256-bit / Block size : 128-bit / Rounds : 10, 12, 14

## Encoding/Decoding
* Process of converting data from one format to another for transmission
* To ensure compatibility or efficient representation
* Types
    1. Base64
        <br/>Consisted of following 64 characters (6-bit needed for each)
        <br/>ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
        <br/>'=' is used for padding
    2. UTF-8
    3. URL encoding
    4. ASCII encoding
    5. JSON encoding