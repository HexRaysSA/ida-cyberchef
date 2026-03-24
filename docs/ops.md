# CyberChef Operations Reference

This document lists all 443 available CyberChef operations.

Unsupported operations shipped in the current runtime remain listed here and are annotated per operation.
See the Runtime support section in `readme.md` for the broader support policy.

## Operations

### `A1Z26CipherDecode()`

**Operation:** `A1Z26 Cipher Decode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Converts alphabet order numbers into their corresponding  alphabet character.

e.g. `1` becomes `a` and `2` becomes `b`.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+3 more)

---

### `A1Z26CipherEncode()`

**Operation:** `A1Z26 Cipher Encode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Converts alphabet characters into their corresponding alphabet order number.

e.g. `a` becomes `1` and `b` becomes `2`.

Non-alphabet characters are dropped.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+3 more)

---

### `ADD()`

**Operation:** `ADD`

**Category:** `Arithmetic / Logic`

**Module:** Default

ADD the input with the given key (e.g. `fe023da5`), MOD 255

[More info](https://wikipedia.org/wiki/Bitwise_operation#Bitwise_operators)

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Key** (toggleString): default ``

---

### `AESDecrypt()`

**Operation:** `AES Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Advanced Encryption Standard (AES) is a U.S. Federal Information Processing Standard (FIPS). It was selected after a 5-year process where 15 competing designs were evaluated.

Key: The following algorithms will be used based on the size of the key:16 bytes = AES-12824 bytes = AES-19232 bytes = AES-256

IV: The Initialization Vector should be 16 bytes long. If not entered, it will default to 16 null bytes.

Padding: In CBC and ECB mode, PKCS#7 padding will be used as a default.

GCM Tag: This field is ignored unless 'GCM' mode is used.

[More info](https://wikipedia.org/wiki/Advanced_Encryption_Standard)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Mode** (argSelector): `CBC`, `CFB`, `OFB` (+5 more)
  - **Input** (option): `Hex`, `Raw`
  - **Output** (option): `Raw`, `Hex`
  - **GCM Tag** (toggleString): default ``
  - **Additional Authenticated Data** (toggleString): default ``

---

### `AESEncrypt()`

**Operation:** `AES Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Advanced Encryption Standard (AES) is a U.S. Federal Information Processing Standard (FIPS). It was selected after a 5-year process where 15 competing designs were evaluated.

Key: The following algorithms will be used based on the size of the key:16 bytes = AES-12824 bytes = AES-19232 bytes = AES-256You can generate a password-based key using one of the KDF operations.

IV: The Initialization Vector should be 16 bytes long. If not entered, it will default to 16 null bytes.

Padding: In CBC and ECB mode, PKCS#7 padding will be used.

[More info](https://wikipedia.org/wiki/Advanced_Encryption_Standard)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Mode** (argSelector): `CBC`, `CFB`, `OFB` (+5 more)
  - **Input** (option): `Raw`, `Hex`
  - **Output** (option): `Hex`, `Raw`
  - **Additional Authenticated Data** (toggleString): default ``

---

### `AESKeyUnwrap()`

**Operation:** `AES Key Unwrap`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Decryptor for a key wrapping algorithm defined in RFC3394, which is used to protect keys in untrusted storage or communications, using AES.

This algorithm uses an AES key (KEK: key-encryption key) and a 64-bit IV to decrypt 64-bit blocks.

[More info](https://wikipedia.org/wiki/Key_wrap)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key (KEK)** (toggleString): default ``
  - **IV** (toggleString): default `a6a6a6a6a6a6a6a6`
  - **Input** (option): `Hex`, `Raw`
  - **Output** (option): `Hex`, `Raw`

---

### `AESKeyWrap()`

**Operation:** `AES Key Wrap`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

A key wrapping algorithm defined in RFC3394, which is used to protect keys in untrusted storage or communications, using AES.

This algorithm uses an AES key (KEK: key-encryption key) and a 64-bit IV to encrypt 64-bit blocks.

[More info](https://wikipedia.org/wiki/Key_wrap)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key (KEK)** (toggleString): default ``
  - **IV** (toggleString): default `a6a6a6a6a6a6a6a6`
  - **Input** (option): `Hex`, `Raw`
  - **Output** (option): `Hex`, `Raw`

---

### `AMFDecode()`

**Operation:** `AMF Decode`

**Category:** `Data format`

**Module:** Encodings

Action Message Format (AMF) is a binary format used to serialize object graphs such as ActionScript objects and XML, or send messages between an Adobe Flash client and a remote service, usually a Flash Media Server or third party alternatives.

[More info](https://wikipedia.org/wiki/Action_Message_Format)

**Input:** `ArrayBuffer` → **Output:** `JSON`

**Arguments:**
  - **Format** (option): `AMF0`, `AMF3`; default `AMF3`

---

### `AMFEncode()`

**Operation:** `AMF Encode`

**Category:** `Data format`

**Module:** Encodings

Action Message Format (AMF) is a binary format used to serialize object graphs such as ActionScript objects and XML, or send messages between an Adobe Flash client and a remote service, usually a Flash Media Server or third party alternatives.

[More info](https://wikipedia.org/wiki/Action_Message_Format)

**Input:** `JSON` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Format** (option): `AMF0`, `AMF3`; default `AMF3`

---

### `AND()`

**Operation:** `AND`

**Category:** `Arithmetic / Logic`

**Module:** Default

AND the input with the given key.
e.g. `fe023da5`

[More info](https://wikipedia.org/wiki/Bitwise_operation#AND)

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Key** (toggleString): default ``

---

### `AddTextToImage()`

**Operation:** `Add Text To Image`

**Category:** `Multimedia`

**Module:** Image

**Support:** Unsupported in the current STPyV8 runtime. Requires browser-style asset loading that this project does not provide.

Adds text onto an image.

Text can be horizontally or vertically aligned, or the position can be manually specified.
Variants of the Roboto font face are available in any size or colour.

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Text** (string): default ``
  - **Horizontal align** (option): `None`, `Left`, `Center` (+1 more)
  - **Vertical align** (option): `None`, `Top`, `Middle` (+1 more)
  - **X position** (number): default ``
  - **Y position** (number): default ``
  - **Size** (number): default `32`
  - **Font face** (option): `Roboto`, `Roboto Black`, `Roboto Mono` (+1 more)
  - **Red** (number): default `255`
  - **Green** (number): default `255`
  - **Blue** (number): default `255`
  - **Alpha** (number): default `255`

---

### `AddLineNumbers()`

**Operation:** `Add line numbers`

**Category:** `Utils`

**Module:** Default

Adds line numbers to the output.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Offset** (number): default ``

---

### `AffineCipherDecode()`

**Operation:** `Affine Cipher Decode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

The Affine cipher is a type of monoalphabetic substitution cipher. To decrypt, each letter in an alphabet is mapped to its numeric equivalent, decrypted by a mathematical function, and converted back to a letter.

[More info](https://wikipedia.org/wiki/Affine_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **a** (number): default `1`
  - **b** (number): default ``

---

### `AffineCipherEncode()`

**Operation:** `Affine Cipher Encode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

The Affine cipher is a type of monoalphabetic substitution cipher, wherein each letter in an alphabet is mapped to its numeric equivalent, encrypted using simple mathematical function, `(ax + b) % 26`, and converted back to a letter.

[More info](https://wikipedia.org/wiki/Affine_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **a** (number): default `1`
  - **b** (number): default ``

---

### `AlternatingCaps()`

**Operation:** `Alternating Caps`

**Category:** `Utils`

**Module:** Default

Alternating caps, also known as studly caps, sticky caps, or spongecase is a form of text notation in which the capitalization of letters varies by some pattern, or arbitrarily. An example of this would be spelling 'alternative caps' as 'aLtErNaTiNg CaPs'.

[More info](https://en.wikipedia.org/wiki/Alternating_caps)

**Input:** `string` → **Output:** `string`

---

### `AnalyseUUID()`

**Operation:** `Analyse UUID`

**Category:** `Other`

**Module:** Crypto

Tries to determine information about a given UUID and suggests which version may have been used to generate it

[More info](https://wikipedia.org/wiki/Universally_unique_identifier)

**Input:** `string` → **Output:** `string`

---

### `AnalyseHash()`

**Operation:** `Analyse hash`

**Category:** `Hashing`

**Module:** Crypto

Tries to determine information about a given hash and suggests which algorithm may have been used to generate it based on its length.

[More info](https://wikipedia.org/wiki/Comparison_of_cryptographic_hash_functions)

**Input:** `string` → **Output:** `string`

---

### `Argon2()`

**Operation:** `Argon2`

**Category:** `Hashing`

**Module:** Crypto

**Support:** Unsupported in the current STPyV8 runtime.

Argon2 is a key derivation function that was selected as the winner of the Password Hashing Competition in July 2015. It was designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich from the University of Luxembourg.

Enter the password in the input to generate its hash.

[More info](https://wikipedia.org/wiki/Argon2)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Salt** (toggleString): default `somesalt`
  - **Iterations** (number): default `3`
  - **Memory (KiB)** (number): default `4096`
  - **Parallelism** (number): default `1`
  - **Hash length (bytes)** (number): default `32`
  - **Type** (option): `Argon2i`, `Argon2d`, `Argon2id`
  - **Output format** (option): `Encoded hash`, `Hex hash`, `Raw hash`

---

### `Argon2Compare()`

**Operation:** `Argon2 compare`

**Category:** `Hashing`

**Module:** Crypto

**Support:** Unsupported in the current STPyV8 runtime.

Tests whether the input matches the given Argon2 hash. To test multiple possible passwords, use the 'Fork' operation.

[More info](https://wikipedia.org/wiki/Argon2)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Encoded hash** (string): default ``

---

### `AtbashCipher()`

**Operation:** `Atbash Cipher`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Atbash is a mono-alphabetic substitution cipher originally used to encode the Hebrew alphabet. It has been modified here for use with the Latin alphabet.

[More info](https://wikipedia.org/wiki/Atbash)

**Input:** `string` → **Output:** `string`

---

### `AvroToJSON()`

**Operation:** `Avro to JSON`

**Category:** `Data format`

**Module:** Serialise

Converts Avro encoded data into JSON.

[More info](https://wikipedia.org/wiki/Apache_Avro)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Force Valid JSON** (boolean): default `true`

---

### `BLAKE2b()`

**Operation:** `BLAKE2b`

**Category:** `Hashing`

**Module:** Hashing

Performs BLAKE2b hashing on the input.  
        

 BLAKE2b is a flavour of the BLAKE cryptographic hash function that is optimized for 64-bit platforms and produces digests of any size between 1 and 64 bytes.
        

 Supports the use of an optional key.

[More info](https://wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2b_algorithm)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Size** (option): `512`, `384`, `256` (+2 more)
  - **Output Encoding** (option): `Hex`, `Base64`, `Raw`
  - **Key** (toggleString): default ``

---

### `BLAKE2s()`

**Operation:** `BLAKE2s`

**Category:** `Hashing`

**Module:** Hashing

Performs BLAKE2s hashing on the input.  
        

BLAKE2s is a flavour of the BLAKE cryptographic hash function that is optimized for 8- to 32-bit platforms and produces digests of any size between 1 and 32 bytes.
        

Supports the use of an optional key.

[More info](https://wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Size** (option): `256`, `160`, `128`
  - **Output Encoding** (option): `Hex`, `Base64`, `Raw`
  - **Key** (toggleString): default ``

---

### `BLAKE3()`

**Operation:** `BLAKE3`

**Category:** `Hashing`

**Module:** Hashing

Hashes the input using BLAKE3 (UTF-8 encoded), with an optional key (also UTF-8), and outputs the result in hexadecimal format.

[More info](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE3)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Size (bytes)** (number): default ``
  - **Key** (string): default ``

---

### `BSONDeserialise()`

**Operation:** `BSON deserialise`

**Category:** `Code tidy`

**Module:** Serialise

BSON is a computer data interchange format used mainly as a data storage and network transfer format in the MongoDB database. It is a binary form for representing simple data structures, associative arrays (called objects or documents in MongoDB), and various data types of specific interest to MongoDB. The name 'BSON' is based on the term JSON and stands for 'Binary JSON'.

Input data should be in a raw bytes format.

[More info](https://wikipedia.org/wiki/BSON)

**Input:** `ArrayBuffer` → **Output:** `string`

---

### `BSONSerialise()`

**Operation:** `BSON serialise`

**Category:** `Code tidy`

**Module:** Serialise

BSON is a computer data interchange format used mainly as a data storage and network transfer format in the MongoDB database. It is a binary form for representing simple data structures, associative arrays (called objects or documents in MongoDB), and various data types of specific interest to MongoDB. The name 'BSON' is based on the term JSON and stands for 'Binary JSON'.

Input data should be valid JSON.

[More info](https://wikipedia.org/wiki/BSON)

**Input:** `string` → **Output:** `ArrayBuffer`

---

### `BaconCipherDecode()`

**Operation:** `Bacon Cipher Decode`

**Category:** `Encryption / Encoding`

**Module:** Default

Bacon's cipher or the Baconian cipher is a method of steganography devised by Francis Bacon in 1605. A message is concealed in the presentation of text, rather than its content.

[More info](https://wikipedia.org/wiki/Bacon%27s_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Alphabet** (option): `Standard (I=J and U=V)`, `Complete`
  - **Translation** (option): `0/1`, `A/B`, `Case` (+1 more)
  - **Invert Translation** (boolean): default ``

---

### `BaconCipherEncode()`

**Operation:** `Bacon Cipher Encode`

**Category:** `Encryption / Encoding`

**Module:** Default

Bacon's cipher or the Baconian cipher is a method of steganography devised by Francis Bacon in 1605. A message is concealed in the presentation of text, rather than its content.

[More info](https://wikipedia.org/wiki/Bacon%27s_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Alphabet** (option): `Standard (I=J and U=V)`, `Complete`
  - **Translation** (option): `0/1`, `A/B`
  - **Keep extra characters** (boolean): default ``
  - **Invert Translation** (boolean): default ``

---

### `Bcrypt()`

**Operation:** `Bcrypt`

**Category:** `Encryption / Encoding`

**Module:** Crypto

bcrypt is a password hashing function designed by Niels Provos and David Mazières, based on the Blowfish cipher, and presented at USENIX in 1999. Besides incorporating a salt to protect against rainbow table attacks, bcrypt is an adaptive function: over time, the iteration count (rounds) can be increased to make it slower, so it remains resistant to brute-force search attacks even with increasing computation power.

Enter the password in the input to generate its hash.

[More info](https://wikipedia.org/wiki/Bcrypt)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Rounds** (number): default `10`

---

### `BcryptCompare()`

**Operation:** `Bcrypt compare`

**Category:** `Hashing`

**Module:** Crypto

Tests whether the input matches the given bcrypt hash. To test multiple possible passwords, use the 'Fork' operation.

[More info](https://wikipedia.org/wiki/Bcrypt)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Hash** (string): default ``

---

### `BcryptParse()`

**Operation:** `Bcrypt parse`

**Category:** `Hashing`

**Module:** Crypto

Parses a bcrypt hash to determine the number of rounds used, the salt, and the password hash.

[More info](https://wikipedia.org/wiki/Bcrypt)

**Input:** `string` → **Output:** `string`

---

### `BifidCipherDecode()`

**Operation:** `Bifid Cipher Decode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

The Bifid cipher is a cipher which uses a Polybius square in conjunction with transposition, which can be fairly difficult to decipher without knowing the alphabet keyword.

[More info](https://wikipedia.org/wiki/Bifid_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Keyword** (string): default ``

---

### `BifidCipherEncode()`

**Operation:** `Bifid Cipher Encode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

The Bifid cipher is a cipher which uses a Polybius square in conjunction with transposition, which can be fairly difficult to decipher without knowing the alphabet keyword.

[More info](https://wikipedia.org/wiki/Bifid_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Keyword** (string): default ``

---

### `BitShiftLeft()`

**Operation:** `Bit shift left`

**Category:** `Arithmetic / Logic`

**Module:** Default

Shifts the bits in each byte towards the left by the specified amount.

[More info](https://wikipedia.org/wiki/Bitwise_operation#Bit_shifts)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Amount** (number): default `1`

---

### `BitShiftRight()`

**Operation:** `Bit shift right`

**Category:** `Arithmetic / Logic`

**Module:** Default

Shifts the bits in each byte towards the right by the specified amount.

Logical shifts replace the leftmost bits with zeros.
Arithmetic shifts preserve the most significant bit (MSB) of the original byte keeping the sign the same (positive or negative).

[More info](https://wikipedia.org/wiki/Bitwise_operation#Bit_shifts)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Amount** (number): default `1`
  - **Type** (option): `Logical shift`, `Arithmetic shift`

---

### `BlowfishDecrypt()`

**Operation:** `Blowfish Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Blowfish is a symmetric-key block cipher designed in 1993 by Bruce Schneier and included in a large number of cipher suites and encryption products. AES now receives more attention.

IV: The Initialization Vector should be 8 bytes long. If not entered, it will default to 8 null bytes.

[More info](https://wikipedia.org/wiki/Blowfish_(cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Mode** (option): `CBC`, `CFB`, `OFB` (+2 more)
  - **Input** (option): `Hex`, `Raw`
  - **Output** (option): `Raw`, `Hex`

---

### `BlowfishEncrypt()`

**Operation:** `Blowfish Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Blowfish is a symmetric-key block cipher designed in 1993 by Bruce Schneier and included in a large number of cipher suites and encryption products. AES now receives more attention.

IV: The Initialization Vector should be 8 bytes long. If not entered, it will default to 8 null bytes.

[More info](https://wikipedia.org/wiki/Blowfish_(cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Mode** (option): `CBC`, `CFB`, `OFB` (+2 more)
  - **Input** (option): `Raw`, `Hex`
  - **Output** (option): `Hex`, `Raw`

---

### `BlurImage()`

**Operation:** `Blur Image`

**Category:** `Multimedia`

**Module:** Image

Applies a blur effect to the image.

Gaussian blur is much slower than fast blur, but produces better results.

[More info](https://wikipedia.org/wiki/Gaussian_blur)

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Amount** (number): default `5`
  - **Type** (option): `Fast`, `Gaussian`

---

### `Bombe()`

**Operation:** `Bombe`

**Category:** `Encryption / Encoding`

**Module:** Bletchley

Emulation of the Bombe machine used at Bletchley Park to attack Enigma, based on work by Polish and British cryptanalysts.

To run this you need to have a 'crib', which is some known plaintext for a chunk of the target ciphertext, and know the rotors used. (See the 'Bombe (multiple runs)' operation if you don't know the rotors.) The machine will suggest possible configurations of the Enigma. Each suggestion has the rotor start positions (left to right) and known plugboard pairs.

Choosing a crib: First, note that Enigma cannot encrypt a letter to itself, which allows you to rule out some positions for possible cribs. Secondly, the Bombe does not simulate the Enigma's middle rotor stepping. The longer your crib, the more likely a step happened within it, which will prevent the attack working. However, other than that, longer cribs are generally better. The attack produces a 'menu' which maps ciphertext letters to plaintext, and the goal is to produce 'loops': for example, with ciphertext ABC and crib CAB, we have the mappings A<->C, B<->A, and C<->B, which produces a loop A-B-C-A. The more loops, the better the crib. The operation will output this: if your menu has too few loops or is too short, a large number of incorrect outputs will usually be produced. Try a different crib. If the menu seems good but the right answer isn't produced, your crib may be wrong, or you may have overlapped the middle rotor stepping - try a different crib.

Output is not sufficient to fully decrypt the data. You will have to recover the rest of the plugboard settings by inspection. And the ring position is not taken into account: this affects when the middle rotor steps. If your output is correct for a bit, and then goes wrong, adjust the ring and start position on the right-hand rotor together until the output improves. If necessary, repeat for the middle rotor.

By default this operation runs the checking machine, a manual process to verify the quality of Bombe stops, on each stop, discarding stops which fail. If you want to see how many times the hardware actually stops for a given input, disable the checking machine.

More detailed descriptions of the Enigma, Typex and Bombe operations can be found here.

[More info](https://wikipedia.org/wiki/Bombe)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Model** (argSelector): `3-rotor`, `4-rotor`
  - **Left-most (4th) rotor** (editableOption): `Beta`, `Gamma`
  - **Left-hand rotor** (editableOption): `I`, `II`, `III` (+5 more)
  - **Middle rotor** (editableOption): `I`, `II`, `III` (+5 more); default `II`
  - **Right-hand rotor** (editableOption): `I`, `II`, `III` (+5 more); default `III`
  - **Reflector** (editableOption): `B`, `C`, `B Thin` (+1 more)
  - **Crib** (string): default ``
  - **Crib offset** (number): default ``
  - **Use checking machine** (boolean): default `true`

---

### `Bzip2Compress()`

**Operation:** `Bzip2 Compress`

**Category:** `Compression`

**Module:** Compression

Bzip2 is a compression library developed by Julian Seward (of GHC fame) that uses the Burrows-Wheeler algorithm. It only supports compressing single files and its compression is slow, however is more effective than Deflate (.gz & .zip).

[More info](https://wikipedia.org/wiki/Bzip2)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Block size (100s of kb)** (number): default `9`
  - **Work factor** (number): default `30`

---

### `Bzip2Decompress()`

**Operation:** `Bzip2 Decompress`

**Category:** `Compression`

**Module:** Compression

Decompresses data using the Bzip2 algorithm.

[More info](https://wikipedia.org/wiki/Bzip2)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Use low-memory, slower decompression algorithm** (boolean): default ``

---

### `CBORDecode()`

**Operation:** `CBOR Decode`

**Category:** `Data format`

**Module:** Serialise

Concise Binary Object Representation (CBOR) is a binary data serialization format loosely based on JSON. Like JSON it allows the transmission of data objects that contain name–value pairs, but in a more concise manner. This increases processing and transfer speeds at the cost of human readability. It is defined in IETF RFC 8949.

[More info](https://wikipedia.org/wiki/CBOR)

**Input:** `ArrayBuffer` → **Output:** `JSON`

---

### `CBOREncode()`

**Operation:** `CBOR Encode`

**Category:** `Data format`

**Module:** Serialise

Concise Binary Object Representation (CBOR) is a binary data serialization format loosely based on JSON. Like JSON it allows the transmission of data objects that contain name–value pairs, but in a more concise manner. This increases processing and transfer speeds at the cost of human readability. It is defined in IETF RFC 8949.

[More info](https://wikipedia.org/wiki/CBOR)

**Input:** `JSON` → **Output:** `ArrayBuffer`

---

### `CMAC()`

**Operation:** `CMAC`

**Category:** `Hashing`

**Module:** Crypto

CMAC is a block-cipher based message authentication code algorithm.

RFC4493 defines AES-CMAC that uses AES encryption with a 128-bit key.
NIST SP 800-38B suggests usages of AES with other key lengths and Triple DES.

[More info](https://wikipedia.org/wiki/CMAC)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **Encryption algorithm** (option): `AES`, `Triple DES`

---

### `CRCChecksum()`

**Operation:** `CRC Checksum`

**Category:** `Hashing`

**Module:** Default

A Cyclic Redundancy Check (CRC) is an error-detecting code commonly used in digital networks and storage devices to detect accidental changes to raw data.

[More info](https://wikipedia.org/wiki/Cyclic_redundancy_check)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Algorithm** (argSelector): `Custom`, `CRC-3/GSM`, `CRC-3/ROHC` (+169 more)
  - **Width (bits)** (toggleString): default `0`
  - **Polynomial** (toggleString): default `0`
  - **Initialization** (toggleString): default `0`
  - **Reflect input** (option): `True`, `False`
  - **Reflect output** (option): `True`, `False`
  - **Xor Output** (toggleString): default `0`

---

### `CSSBeautify()`

**Operation:** `CSS Beautify`

**Category:** `Code tidy`

**Module:** Code

Indents and prettifies Cascading Style Sheets (CSS) code.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Indent string** (binaryShortString): default `\\t`

---

### `CSSMinify()`

**Operation:** `CSS Minify`

**Category:** `Code tidy`

**Module:** Code

Compresses Cascading Style Sheets (CSS) code.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Preserve comments** (boolean): default ``

---

### `CSSSelector()`

**Operation:** `CSS selector`

**Category:** `Extractors`

**Module:** Code

Extract information from an HTML document with a CSS selector

[More info](https://wikipedia.org/wiki/Cascading_Style_Sheets#Selector)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **CSS selector** (string): default ``
  - **Delimiter** (binaryShortString): default `\\n`

---

### `CSVToJSON()`

**Operation:** `CSV to JSON`

**Category:** `Data format`

**Module:** Default

Converts a CSV file to JSON format.

[More info](https://wikipedia.org/wiki/Comma-separated_values)

**Input:** `string` → **Output:** `JSON`

**Arguments:**
  - **Cell delimiters** (binaryShortString): default `,`
  - **Row delimiters** (binaryShortString): default `\\r\\n`
  - **Format** (option): `Array of dictionaries`, `Array of arrays`

---

### `CTPH()`

**Operation:** `CTPH`

**Category:** `Hashing`

**Module:** Crypto

Context Triggered Piecewise Hashing, also called Fuzzy Hashing, can match inputs that have homologies. Such inputs have sequences of identical bytes in the same order, although bytes in between these sequences may be different in both content and length.

CTPH was originally based on the work of Dr. Andrew Tridgell and a spam email detector called SpamSum. This method was adapted by Jesse Kornblum and published at the DFRWS conference in 2006 in a paper 'Identifying Almost Identical Files Using Context Triggered Piecewise Hashing'.

[More info](https://forensics.wiki/context_triggered_piecewise_hashing/)

**Input:** `string` → **Output:** `string`

---

### `CaesarBoxCipher()`

**Operation:** `Caesar Box Cipher`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Caesar Box is a transposition cipher used in the Roman Empire, in which letters of the message are written in rows in a square (or a rectangle) and then, read by column.

[More info](https://www.dcode.fr/caesar-box-cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Box Height** (number): default `1`

---

### `CartesianProduct()`

**Operation:** `Cartesian Product`

**Category:** `Arithmetic / Logic`

**Module:** Default

Calculates the cartesian product of multiple sets of data, returning all possible combinations.

[More info](https://wikipedia.org/wiki/Cartesian_product)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Sample delimiter** (binaryString): default `\\n\\n`
  - **Item delimiter** (binaryString): default `,`

---

### `CetaceanCipherDecode()`

**Operation:** `Cetacean Cipher Decode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Decode Cetacean Cipher input. e.g. `EEEEEEEEEeeEeEEEEEEEEEEEEeeEeEEe` becomes `hi`

[More info](https://hitchhikers.fandom.com/wiki/Dolphins)

**Input:** `string` → **Output:** `string`

---

### `CetaceanCipherEncode()`

**Operation:** `Cetacean Cipher Encode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Converts any input into Cetacean Cipher. e.g. `hi` becomes `EEEEEEEEEeeEeEEEEEEEEEEEEeeEeEEe`

[More info](https://hitchhikers.fandom.com/wiki/Dolphins)

**Input:** `string` → **Output:** `string`

---

### `ChaCha()`

**Operation:** `ChaCha`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

ChaCha is a stream cipher designed by Daniel J. Bernstein. It is a variant of the Salsa stream cipher. Several parameterizations exist; 'ChaCha' may refer to the original construction, or to the variant as described in RFC-8439. ChaCha is often used with Poly1305, in the ChaCha20-Poly1305 AEAD construction.

Key: ChaCha uses a key of 16 or 32 bytes (128 or 256 bits).

Nonce: ChaCha uses a nonce of 8 or 12 bytes (64 or 96 bits).

Counter: ChaCha uses a counter of 4 or 8 bytes (32 or 64 bits); together, the nonce and counter must add up to 16 bytes. The counter starts at zero at the start of the keystream, and is incremented at every 64 bytes.

[More info](https://wikipedia.org/wiki/Salsa20#ChaCha_variant)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **Nonce** (toggleString): default ``
  - **Counter** (number): default ``
  - **Rounds** (option): `20`, `12`, `8`
  - **Input** (option): `Hex`, `Raw`
  - **Output** (option): `Raw`, `Hex`

---

### `ChangeIPFormat()`

**Operation:** `Change IP format`

**Category:** `Data format`

**Module:** Default

Convert an IP address from one format to another, e.g. `172.20.23.54` to `ac141736`

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input format** (option): `Dotted Decimal`, `Decimal`, `Octal` (+1 more)
  - **Output format** (option): `Dotted Decimal`, `Decimal`, `Octal` (+1 more)

---

### `ChiSquare()`

**Operation:** `Chi Square`

**Category:** `Other`

**Module:** Default

Calculates the Chi Square distribution of values.

[More info](https://wikipedia.org/wiki/Chi-squared_distribution)

**Input:** `ArrayBuffer` → **Output:** `number`

---

### `CipherSaber2Decrypt()`

**Operation:** `CipherSaber2 Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Crypto

CipherSaber is a simple symmetric encryption protocol based on the RC4 stream cipher. It gives reasonably strong protection of message confidentiality, yet it's designed to be simple enough that even novice programmers can memorize the algorithm and implement it from scratch.

[More info](https://wikipedia.org/wiki/CipherSaber)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Key** (toggleString): default ``
  - **Rounds** (number): default `20`

---

### `CipherSaber2Encrypt()`

**Operation:** `CipherSaber2 Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Crypto

CipherSaber is a simple symmetric encryption protocol based on the RC4 stream cipher. It gives reasonably strong protection of message confidentiality, yet it's designed to be simple enough that even novice programmers can memorize the algorithm and implement it from scratch.

[More info](https://wikipedia.org/wiki/CipherSaber)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Key** (toggleString): default ``
  - **Rounds** (number): default `20`

---

### `CitrixCTX1Decode()`

**Operation:** `Citrix CTX1 Decode`

**Category:** `Encryption / Encoding`

**Module:** Encodings

Decodes strings in a Citrix CTX1 password format to plaintext.

[More info](https://www.reddit.com/r/AskNetsec/comments/1s3r6y/citrix_ctx1_hash_decoding/)

**Input:** `ArrayBuffer` → **Output:** `string`

---

### `CitrixCTX1Encode()`

**Operation:** `Citrix CTX1 Encode`

**Category:** `Encryption / Encoding`

**Module:** Encodings

Encodes strings to Citrix CTX1 password format.

[More info](https://www.reddit.com/r/AskNetsec/comments/1s3r6y/citrix_ctx1_hash_decoding/)

**Input:** `string` → **Output:** `byteArray`

---

### `Colossus()`

**Operation:** `Colossus`

**Category:** `Encryption / Encoding`

**Module:** Bletchley

Colossus is the name of the world's first electronic computer. Ten Colossi were designed by Tommy Flowers and built at the Post Office Research Labs at Dollis Hill in 1943 during World War 2. They assisted with the breaking of the German Lorenz cipher attachment, a machine created to encipher communications between Hitler and his generals on the front lines.

To learn more, Virtual Colossus, an online, browser based simulation of a Colossus computer is available at virtualcolossus.co.uk.

A more detailed description of this operation can be found here.

[More info](https://wikipedia.org/wiki/Colossus_computer)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Input** (label)
  - **Pattern** (option): `KH Pattern`, `ZMUG Pattern`, `BREAM Pattern`
  - **QBusZ** (option): ``, `Z`, `ΔZ`
  - **QBusΧ** (option): ``, `Χ`, `ΔΧ`
  - **QBusΨ** (option): ``, `Ψ`, `ΔΨ`
  - **Limitation** (option): `None`, `Χ2`, `Χ2 + P5` (+2 more)
  - **K Rack Option** (argSelector): `Select Program`, `Top Section - Conditional`, `Bottom Section - Addition` (+1 more)
  - **Program to run** (option): ``, `Letter Count`, `1+2=. (1+2 Break In, Find X1,X2)` (+2 more)
  - **K Rack: Conditional** (label)
  - **R1-Q1** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R1-Q2** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R1-Q3** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R1-Q4** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R1-Q5** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R1-Negate** (boolean): default ``
  - **R1-Counter** (option): ``, `1`, `2` (+3 more)
  - **R2-Q1** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R2-Q2** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R2-Q3** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R2-Q4** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R2-Q5** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R2-Negate** (boolean): default ``
  - **R2-Counter** (option): ``, `1`, `2` (+3 more)
  - **R3-Q1** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R3-Q2** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R3-Q3** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R3-Q4** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R3-Q5** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **R3-Negate** (boolean): default ``
  - **R3-Counter** (option): ``, `1`, `2` (+3 more)
  - **Negate All** (boolean): default ``
  - **K Rack: Addition** (label)
  - **Add-Q1** (boolean): default ``
  - **Add-Q2** (boolean): default ``
  - **Add-Q3** (boolean): default ``
  - **Add-Q4** (boolean): default ``
  - **Add-Q5** (boolean): default ``
  - **Add-Equals** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **Add-Counter1** (boolean): default ``
  - **Add Negate All** (boolean): default ``
  - **Total Motor** (editableOptionShort): `Up (.)`, `Centre`, `Down (x)`; default `Centre`
  - **Master Control Panel** (label)
  - **Set Total** (number): default ``
  - **Fast Step** (option): ``, `X1`, `X2` (+10 more)
  - **Slow Step** (option): ``, `X1`, `X2` (+10 more)
  - **Start Χ1** (number): default `1`
  - **Start Χ2** (number): default `1`
  - **Start Χ3** (number): default `1`
  - **Start Χ4** (number): default `1`
  - **Start Χ5** (number): default `1`
  - **Start M61** (number): default `1`
  - **Start M37** (number): default `1`
  - **Start Ψ1** (number): default `1`
  - **Start Ψ2** (number): default `1`
  - **Start Ψ3** (number): default `1`
  - **Start Ψ4** (number): default `1`
  - **Start Ψ5** (number): default `1`

---

### `Comment()`

**Operation:** `Comment`

**Category:** `Flow control`

**Module:** Default

Provides a place to write comments within the flow of the recipe. This operation has no computational effect.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **** (text)

---

### `CompareCTPHHashes()`

**Operation:** `Compare CTPH hashes`

**Category:** `Hashing`

**Module:** Crypto

Compares two Context Triggered Piecewise Hashing (CTPH) fuzzy hashes to determine the similarity between them on a scale of 0 to 100.

[More info](https://forensics.wiki/context_triggered_piecewise_hashing/)

**Input:** `string` → **Output:** `number`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `CRLF`, `Space` (+1 more)

---

### `CompareSSDEEPHashes()`

**Operation:** `Compare SSDEEP hashes`

**Category:** `Hashing`

**Module:** Crypto

Compares two SSDEEP fuzzy hashes to determine the similarity between them on a scale of 0 to 100.

[More info](https://forensics.wiki/ssdeep/)

**Input:** `string` → **Output:** `number`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `CRLF`, `Space` (+1 more)

---

### `ConditionalJump()`

**Operation:** `Conditional Jump`

**Category:** `Flow control`

**Module:** Default

Conditionally jump forwards or backwards to the specified Label  based on whether the data matches the specified regular expression.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Match (regex)** (string): default ``
  - **Invert match** (boolean): default ``
  - **Label name** (shortString)
  - **Maximum jumps (if jumping backwards)** (number): default `10`

---

### `ContainImage()`

**Operation:** `Contain Image`

**Category:** `Multimedia`

**Module:** Image

Scales an image to the specified width and height, maintaining the aspect ratio. The image may be letterboxed.

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Width** (number): default `100`
  - **Height** (number): default `100`
  - **Horizontal align** (option): `Left`, `Center`, `Right`; default `Center`
  - **Vertical align** (option): `Top`, `Middle`, `Bottom`; default `Middle`
  - **Resizing algorithm** (option): `Nearest Neighbour`, `Bilinear`, `Bicubic` (+2 more); default `Bilinear`
  - **Opaque background** (boolean): default `true`

---

### `ConvertImageFormat()`

**Operation:** `Convert Image Format`

**Category:** `Multimedia`

**Module:** Image

Converts an image between different formats. Supported formats:
Joint Photographic Experts Group (JPEG)Portable Network Graphics (PNG)Bitmap (BMP)Tagged Image File Format (TIFF)
Note: GIF files are supported for input, but cannot be outputted.

[More info](https://wikipedia.org/wiki/Image_file_formats)

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Output Format** (option): `JPEG`, `PNG`, `BMP` (+1 more)
  - **JPEG Quality** (number): default `80`
  - **PNG Filter Type** (option): `Auto`, `None`, `Sub` (+3 more)
  - **PNG Deflate Level** (number): default `9`

---

### `ConvertLeetSpeak()`

**Operation:** `Convert Leet Speak`

**Category:** `Language`

**Module:** Default

Converts to and from Leet Speak.

[More info](https://wikipedia.org/wiki/Leet)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Direction** (option): `To Leet Speak`, `From Leet Speak`

---

### `ConvertArea()`

**Operation:** `Convert area`

**Category:** `Utils`

**Module:** Default

Converts a unit of area to another format.

[More info](https://wikipedia.org/wiki/Orders_of_magnitude_(area))

**Input:** `BigNumber` → **Output:** `BigNumber`

**Arguments:**
  - **Input units** (option): `[Metric]`, `Square metre (sq m)`, `Square kilometre (sq km)` (+42 more)
  - **Output units** (option): `[Metric]`, `Square metre (sq m)`, `Square kilometre (sq km)` (+42 more)

---

### `ConvertDataUnits()`

**Operation:** `Convert data units`

**Category:** `Utils`

**Module:** Default

Converts a unit of data to another format.

[More info](https://wikipedia.org/wiki/Orders_of_magnitude_(data))

**Input:** `BigNumber` → **Output:** `BigNumber`

**Arguments:**
  - **Input units** (option): `Bits (b)`, `Nibbles`, `Octets` (+43 more)
  - **Output units** (option): `Bits (b)`, `Nibbles`, `Octets` (+43 more)

---

### `ConvertDistance()`

**Operation:** `Convert distance`

**Category:** `Utils`

**Module:** Default

Converts a unit of distance to another format.

[More info](https://wikipedia.org/wiki/Orders_of_magnitude_(length))

**Input:** `BigNumber` → **Output:** `BigNumber`

**Arguments:**
  - **Input units** (option): `[Metric]`, `Nanometres (nm)`, `Micrometres (µm)` (+33 more)
  - **Output units** (option): `[Metric]`, `Nanometres (nm)`, `Micrometres (µm)` (+33 more)

---

### `ConvertMass()`

**Operation:** `Convert mass`

**Category:** `Utils`

**Module:** Default

Converts a unit of mass to another format.

[More info](https://wikipedia.org/wiki/Orders_of_magnitude_(mass))

**Input:** `BigNumber` → **Output:** `BigNumber`

**Arguments:**
  - **Input units** (option): `[Metric]`, `Yoctogram (yg)`, `Zeptogram (zg)` (+75 more)
  - **Output units** (option): `[Metric]`, `Yoctogram (yg)`, `Zeptogram (zg)` (+75 more)

---

### `ConvertSpeed()`

**Operation:** `Convert speed`

**Category:** `Utils`

**Module:** Default

Converts a unit of speed to another format.

[More info](https://wikipedia.org/wiki/Orders_of_magnitude_(speed))

**Input:** `BigNumber` → **Output:** `BigNumber`

**Arguments:**
  - **Input units** (option): `[Metric]`, `Metres per second (m/s)`, `Kilometres per hour (km/h)` (+30 more)
  - **Output units** (option): `[Metric]`, `Metres per second (m/s)`, `Kilometres per hour (km/h)` (+30 more)

---

### `ConvertToNATOAlphabet()`

**Operation:** `Convert to NATO alphabet`

**Category:** `Language`

**Module:** Default

Converts characters to their representation in the NATO phonetic alphabet.

[More info](https://wikipedia.org/wiki/NATO_phonetic_alphabet)

**Input:** `string` → **Output:** `string`

---

### `CountOccurrences()`

**Operation:** `Count occurrences`

**Category:** `Utils`

**Module:** Default

Counts the number of times the provided string occurs in the input.

**Input:** `string` → **Output:** `number`

**Arguments:**
  - **Search string** (toggleString): default ``

---

### `CoverImage()`

**Operation:** `Cover Image`

**Category:** `Multimedia`

**Module:** Image

Scales the image to the given width and height, keeping the aspect ratio. The image may be clipped.

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Width** (number): default `100`
  - **Height** (number): default `100`
  - **Horizontal align** (option): `Left`, `Center`, `Right`; default `Center`
  - **Vertical align** (option): `Top`, `Middle`, `Bottom`; default `Middle`
  - **Resizing algorithm** (option): `Nearest Neighbour`, `Bilinear`, `Bicubic` (+2 more); default `Bilinear`

---

### `CropImage()`

**Operation:** `Crop Image`

**Category:** `Multimedia`

**Module:** Image

Crops an image to the specified region, or automatically crops edges.

Autocrop
Automatically crops same-colour borders from the image.

Autocrop tolerance
A percentage value for the tolerance of colour difference between pixels.

Only autocrop frames
Only crop real frames (all sides must have the same border)

Symmetric autocrop
Force autocrop to be symmetric (top/bottom and left/right are cropped by the same amount)

Autocrop keep border
The number of pixels of border to leave around the image.

[More info](https://wikipedia.org/wiki/Cropping_(image))

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **X Position** (number): default ``
  - **Y Position** (number): default ``
  - **Width** (number): default `10`
  - **Height** (number): default `10`
  - **Autocrop** (boolean): default ``
  - **Autocrop tolerance (%)** (number): default `0.02`
  - **Only autocrop frames** (boolean): default `true`
  - **Symmetric autocrop** (boolean): default ``
  - **Autocrop keep border (px)** (number): default ``

---

### `DESDecrypt()`

**Operation:** `DES Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

DES is a previously dominant algorithm for encryption, and was published as an official U.S. Federal Information Processing Standard (FIPS). It is now considered to be insecure due to its small key size.

Key: DES uses a key length of 8 bytes (64 bits).

IV: The Initialization Vector should be 8 bytes long. If not entered, it will default to 8 null bytes.

Padding: In CBC and ECB mode, PKCS#7 padding will be used as a default.

[More info](https://wikipedia.org/wiki/Data_Encryption_Standard)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Mode** (option): `CBC`, `CFB`, `OFB` (+4 more)
  - **Input** (option): `Hex`, `Raw`
  - **Output** (option): `Raw`, `Hex`

---

### `DESEncrypt()`

**Operation:** `DES Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

DES is a previously dominant algorithm for encryption, and was published as an official U.S. Federal Information Processing Standard (FIPS). It is now considered to be insecure due to its small key size.

Key: DES uses a key length of 8 bytes (64 bits).

You can generate a password-based key using one of the KDF operations.

IV: The Initialization Vector should be 8 bytes long. If not entered, it will default to 8 null bytes.

Padding: In CBC and ECB mode, PKCS#7 padding will be used.

[More info](https://wikipedia.org/wiki/Data_Encryption_Standard)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Mode** (option): `CBC`, `CFB`, `OFB` (+2 more)
  - **Input** (option): `Raw`, `Hex`
  - **Output** (option): `Hex`, `Raw`

---

### `DNSOverHTTPS()`

**Operation:** `DNS over HTTPS`

**Category:** `Networking`

**Module:** Default

**Support:** Unsupported in the current STPyV8 runtime. Requires browser-style request APIs and live network access.

Takes a single domain name and performs a DNS lookup using DNS over HTTPS.

By default, Cloudflare and Google DNS over HTTPS services are supported.

Can be used with any service that supports the GET parameters `name` and `type`.

[More info](https://wikipedia.org/wiki/DNS_over_HTTPS)

**Input:** `string` → **Output:** `JSON`

**Arguments:**
  - **Resolver** (editableOption): `Google`, `Cloudflare`
  - **Request Type** (option): `A`, `AAAA`, `ANAME` (+20 more)
  - **Answer Data Only** (boolean): default ``
  - **Disable DNSSEC validation** (boolean): default ``

---

### `DateTimeDelta()`

**Operation:** `DateTime Delta`

**Category:** `Date / Time`

**Module:** Default

Calculates a new DateTime value given an input DateTime value and a time difference (delta) from the input DateTime value.

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Built in formats** (populateOption): default `[{'name': 'Standard date and time', 'value': 'DD/MM/YYYY HH:mm:ss'}, {'name': 'American-style date and time', 'value': 'MM/DD/YYYY HH:mm:ss'}, {'name': 'International date and time', 'value': 'YYYY-MM-DD HH:mm:ss'}, {'name': 'Verbose date and time', 'value': 'dddd Do MMMM YYYY HH:mm:ss Z z'}, {'name': 'UNIX timestamp (seconds)', 'value': 'X'}, {'name': 'UNIX timestamp offset (milliseconds)', 'value': 'x'}, {'name': 'Automatic', 'value': ''}]`
  - **Input format string** (binaryString): default `DD/MM/YYYY HH:mm:ss`
  - **Time Operation** (option): `Add`, `Subtract`
  - **Days** (number): default ``
  - **Hours** (number): default ``
  - **Minutes** (number): default ``
  - **Seconds** (number): default ``

---

### `DechunkHTTPResponse()`

**Operation:** `Dechunk HTTP response`

**Category:** `Networking`

**Module:** Default

Parses an HTTP response transferred using Transfer-Encoding: Chunked

[More info](https://wikipedia.org/wiki/Chunked_transfer_encoding)

**Input:** `string` → **Output:** `string`

---

### `DecodeNetBIOSName()`

**Operation:** `Decode NetBIOS Name`

**Category:** `Networking`

**Module:** Default

NetBIOS names as seen across the client interface to NetBIOS are exactly 16 bytes long. Within the NetBIOS-over-TCP protocols, a longer representation is used.

There are two levels of encoding. The first level maps a NetBIOS name into a domain system name.  The second level maps the domain system name into the 'compressed' representation required for interaction with the domain name system.

This operation decodes the first level of encoding. See RFC 1001 for full details.

[More info](https://wikipedia.org/wiki/NetBIOS)

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Offset** (number): default `65`

---

### `DecodeText()`

**Operation:** `Decode text`

**Category:** `Data format`

**Module:** Encodings

Decodes text from the chosen character encoding.

Supported charsets are:

UTF-8 (65001)
UTF-7 (65000)
UTF-16LE (1200)
UTF-16BE (1201)
UTF-32LE (12000)
UTF-32BE (12001)
IBM EBCDIC International (500)
IBM EBCDIC US-Canada (37)
IBM EBCDIC Multilingual/ROECE (Latin 2) (870)
IBM EBCDIC Greek Modern (875)
IBM EBCDIC French (1010)
IBM EBCDIC Turkish (Latin 5) (1026)
IBM EBCDIC Latin 1/Open System (1047)
IBM EBCDIC Lao (1132/1133/1341)
IBM EBCDIC US-Canada (037 + Euro symbol) (1140)
IBM EBCDIC Germany (20273 + Euro symbol) (1141)
IBM EBCDIC Denmark-Norway (20277 + Euro symbol) (1142)
IBM EBCDIC Finland-Sweden (20278 + Euro symbol) (1143)
IBM EBCDIC Italy (20280 + Euro symbol) (1144)
IBM EBCDIC Latin America-Spain (20284 + Euro symbol) (1145)
IBM EBCDIC United Kingdom (20285 + Euro symbol) (1146)
IBM EBCDIC France (20297 + Euro symbol) (1147)
IBM EBCDIC International (500 + Euro symbol) (1148)
IBM EBCDIC Icelandic (20871 + Euro symbol) (1149)
IBM EBCDIC Germany (20273)
IBM EBCDIC Denmark-Norway (20277)
IBM EBCDIC Finland-Sweden (20278)
IBM EBCDIC Italy (20280)
IBM EBCDIC Latin America-Spain (20284)
IBM EBCDIC United Kingdom (20285)
IBM EBCDIC Japanese Katakana Extended (20290)
IBM EBCDIC France (20297)
IBM EBCDIC Arabic (20420)
IBM EBCDIC Greek (20423)
IBM EBCDIC Hebrew (20424)
IBM EBCDIC Korean Extended (20833)
IBM EBCDIC Thai (20838)
IBM EBCDIC Icelandic (20871)
IBM EBCDIC Cyrillic Russian (20880)
IBM EBCDIC Turkish (20905)
IBM EBCDIC Latin 1/Open System (1047 + Euro symbol) (20924)
IBM EBCDIC Cyrillic Serbian-Bulgarian (21025)
OEM United States (437)
OEM Greek (formerly 437G); Greek (DOS) (737)
OEM Baltic; Baltic (DOS) (775)
OEM Russian; Cyrillic + Euro symbol (808)
OEM Multilingual Latin 1; Western European (DOS) (850)
OEM Latin 2; Central European (DOS) (852)
OEM Cyrillic (primarily Russian) (855)
OEM Turkish; Turkish (DOS) (857)
OEM Multilingual Latin 1 + Euro symbol (858)
OEM Portuguese; Portuguese (DOS) (860)
OEM Icelandic; Icelandic (DOS) (861)
OEM Hebrew; Hebrew (DOS) (862)
OEM French Canadian; French Canadian (DOS) (863)
OEM Arabic; Arabic (864) (864)
OEM Nordic; Nordic (DOS) (865)
OEM Russian; Cyrillic (DOS) (866)
OEM Modern Greek; Greek, Modern (DOS) (869)
OEM Cyrillic (primarily Russian) + Euro Symbol (872)
Windows-874 Thai (874)
Windows-1250 Central European (1250)
Windows-1251 Cyrillic (1251)
Windows-1252 Latin (1252)
Windows-1253 Greek (1253)
Windows-1254 Turkish (1254)
Windows-1255 Hebrew (1255)
Windows-1256 Arabic (1256)
Windows-1257 Baltic (1257)
Windows-1258 Vietnam (1258)
ISO-8859-1 Latin 1 Western European (28591)
ISO-8859-2 Latin 2 Central European (28592)
ISO-8859-3 Latin 3 South European (28593)
ISO-8859-4 Latin 4 North European (28594)
ISO-8859-5 Latin/Cyrillic (28595)
ISO-8859-6 Latin/Arabic (28596)
ISO-8859-7 Latin/Greek (28597)
ISO-8859-8 Latin/Hebrew (28598)
ISO 8859-8 Hebrew (ISO-Logical) (38598)
ISO-8859-9 Latin 5 Turkish (28599)
ISO-8859-10 Latin 6 Nordic (28600)
ISO-8859-11 Latin/Thai (28601)
ISO-8859-13 Latin 7 Baltic Rim (28603)
ISO-8859-14 Latin 8 Celtic (28604)
ISO-8859-15 Latin 9 (28605)
ISO-8859-16 Latin 10 (28606)
ISO 2022 JIS Japanese with no halfwidth Katakana (50220)
ISO 2022 JIS Japanese with halfwidth Katakana (50221)
ISO 2022 Japanese JIS X 0201-1989 (1 byte Kana-SO/SI) (50222)
ISO 2022 Korean (50225)
ISO 2022 Simplified Chinese (50227)
ISO 6937 Non-Spacing Accent (20269)
EUC Japanese (51932)
EUC Simplified Chinese (51936)
EUC Korean (51949)
ISCII Devanagari (57002)
ISCII Bengali (57003)
ISCII Tamil (57004)
ISCII Telugu (57005)
ISCII Assamese (57006)
ISCII Oriya (57007)
ISCII Kannada (57008)
ISCII Malayalam (57009)
ISCII Gujarati (57010)
ISCII Punjabi (57011)
Japanese Shift-JIS (932)
Simplified Chinese GBK (936)
Korean (949)
Traditional Chinese Big5 (950)
US-ASCII (7-bit) (20127)
Simplified Chinese GB2312 (20936)
KOI8-R Russian Cyrillic (20866)
KOI8-U Ukrainian Cyrillic (21866)
Mazovia (Polish) MS-DOS (620)
Arabic (ASMO 708) (708)
Arabic (Transparent ASMO); Arabic (DOS) (720)
Kamenický (Czech) MS-DOS (895)
Korean (Johab) (1361)
MAC Roman (10000)
Japanese (Mac) (10001)
MAC Traditional Chinese (Big5) (10002)
Korean (Mac) (10003)
Arabic (Mac) (10004)
Hebrew (Mac) (10005)
Greek (Mac) (10006)
Cyrillic (Mac) (10007)
MAC Simplified Chinese (GB 2312) (10008)
Romanian (Mac) (10010)
Ukrainian (Mac) (10017)
Thai (Mac) (10021)
MAC Latin 2 (Central European) (10029)
Icelandic (Mac) (10079)
Turkish (Mac) (10081)
Croatian (Mac) (10082)
CNS Taiwan (Chinese Traditional) (20000)
TCA Taiwan (20001)
ETEN Taiwan (Chinese Traditional) (20002)
IBM5550 Taiwan (20003)
TeleText Taiwan (20004)
Wang Taiwan (20005)
Western European IA5 (IRV International Alphabet 5) (20105)
IA5 German (7-bit) (20106)
IA5 Swedish (7-bit) (20107)
IA5 Norwegian (7-bit) (20108)
T.61 (20261)
Japanese (JIS 0208-1990 and 0212-1990) (20932)
Korean Wansung (20949)
Extended/Ext Alpha Lowercase (21027)
Europa 3 (29001)
Atari ST/TT (47451)
HZ-GB2312 Simplified Chinese (52936)
Simplified Chinese GB18030 (54936)

[More info](https://wikipedia.org/wiki/Character_encoding)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Encoding** (option): `UTF-8 (65001)`, `UTF-7 (65000)`, `UTF-16LE (1200)` (+149 more)

---

### `DefangIPAddresses()`

**Operation:** `Defang IP Addresses`

**Category:** `Networking`

**Module:** Default

Takes a IPv4 or IPv6 address and 'Defangs' it, meaning the IP becomes invalid, removing the risk of accidentally utilising it as an IP address.

[More info](https://isc.sans.edu/forums/diary/Defang+all+the+things/22744/)

**Input:** `string` → **Output:** `string`

---

### `DefangURL()`

**Operation:** `Defang URL`

**Category:** `Networking`

**Module:** Default

Takes a Universal Resource Locator (URL) and 'Defangs' it; meaning the URL becomes invalid, neutralising the risk of accidentally clicking on a malicious link.

This is often used when dealing with malicious links or IOCs.

Works well when combined with the 'Extract URLs' operation.

[More info](https://isc.sans.edu/forums/diary/Defang+all+the+things/22744/)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Escape dots** (boolean): default `true`
  - **Escape http** (boolean): default `true`
  - **Escape ://** (boolean): default `true`
  - **Process** (option): `Valid domains and full URLs`, `Only full URLs`, `Everything`

---

### `DeriveEVPKey()`

**Operation:** `Derive EVP key`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

This operation performs a password-based key derivation function (PBKDF) used extensively in OpenSSL. In many applications of cryptography, user security is ultimately dependent on a password, and because a password usually can't be used directly as a cryptographic key, some processing is required.

A salt provides a large set of keys for any given password, and an iteration count increases the cost of producing keys from a password, thereby also increasing the difficulty of attack.

If you leave the salt argument empty, a random salt will be generated.

[More info](https://wikipedia.org/wiki/Key_derivation_function)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Passphrase** (toggleString): default ``
  - **Key size** (number): default `128`
  - **Iterations** (number): default `1`
  - **Hashing function** (option): `SHA1`, `SHA256`, `SHA384` (+2 more)
  - **Salt** (toggleString): default ``

---

### `DeriveHKDFKey()`

**Operation:** `Derive HKDF key`

**Category:** `Encryption / Encoding`

**Module:** Crypto

A simple Hashed Message Authenticaton Code (HMAC)-based key derivation function (HKDF), defined in RFC5869.

[More info](https://wikipedia.org/wiki/HKDF)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Salt** (toggleString): default ``
  - **Info** (toggleString): default ``
  - **Hashing function** (option): `MD2`, `MD4`, `MD5` (+17 more); default `SHA256`
  - **Extract mode** (argSelector): `with salt`, `no salt`, `skip`
  - **L (number of output octets)** (number): default `16`

---

### `DerivePBKDF2Key()`

**Operation:** `Derive PBKDF2 key`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

PBKDF2 is a password-based key derivation function. It is part of RSA Laboratories' Public-Key Cryptography Standards (PKCS) series, specifically PKCS #5 v2.0, also published as Internet Engineering Task Force's RFC 2898.

In many applications of cryptography, user security is ultimately dependent on a password, and because a password usually can't be used directly as a cryptographic key, some processing is required.

A salt provides a large set of keys for any given password, and an iteration count increases the cost of producing keys from a password, thereby also increasing the difficulty of attack.

If you leave the salt argument empty, a random salt will be generated.

[More info](https://wikipedia.org/wiki/PBKDF2)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Passphrase** (toggleString): default ``
  - **Key size** (number): default `128`
  - **Iterations** (number): default `1`
  - **Hashing function** (option): `SHA1`, `SHA256`, `SHA384` (+2 more)
  - **Salt** (toggleString): default ``

---

### `DetectFileType()`

**Operation:** `Detect File Type`

**Category:** `Forensics`

**Module:** Default

Attempts to guess the MIME (Multipurpose Internet Mail Extensions) type of the data based on 'magic bytes'.

Currently supports the following file types: 123d, 7z, B64, abcdp, accda, accdb, accde, accdu, ace, ai, aif, aifc, alz, amr, arj, arw, au, auf, avi, axf, bash, bct, bin, bitlocker, bk!, bmp, bplist, bz2, cab, cat, cer, chi, chm, chw, class, com, cr2, crl, crt, crw, crx, db, dbx, deb, der, dex, dll, dmf, dmg, dmp, doc, docx, dot, drv, dwg, dwt, dylib, edb, elf, eot, eps, epub, evt, evtx, exe, f4v, fdb, flac, flv, fon, gif, gpg, gz, hbin, hdr, heic, heif, hqx, ichat, ico, ipmeta, iso, jar, job, jpe, jpeg, jpg, jxr, keychain, kgb, lnk, luac, lzo, lzop, m4a, m4v, mda, mdb, mdbackup, mde, mdi, mdinfo, mdt, midi, mkv, mov, mp3, mp4, mpg, mpo, mrw, msg, msi, nib, o, ocx, ogg, ogm, ogv, ogx, ole2, one, opus, ost, otf, p7b, p7c, p7m, p7s, pab, pdf, pf, pfa, pgd, phar, php, php-s, php3, php4, php5, php7, phps, pht, phtml, pkr, pl, plist, pm, png, pod, pot, ppa, pps, ppt, pptx, prx, ps, psa, psb, psd, psp, pst, pwl, py, pyc, pyd, pyo, pyw, pyz, qtz, raf, rar, rb, registry, rgs, rsa, rtf, scr, sdw, sh, skr, sml, so, sqlite, strings, swf, swz, sys, t, tar, tar.z, tcp, tga, thm, tif, torrent, ttf, txt, udp, utf16le, utf32le, vbx, vhd, vmdk, vsd, vxd, wallet, wasm, wav, wcm, webbookmark, webhistory, webm, webp, wmv, woff, woff2, wp, wp5, wp6, wpd, wpp, xcf, xla, xls, xlsx, xz, zip, zlib.

[More info](https://wikipedia.org/wiki/List_of_file_signatures)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Images** (boolean): default `true`
  - **Video** (boolean): default `true`
  - **Audio** (boolean): default `true`
  - **Documents** (boolean): default `true`
  - **Applications** (boolean): default `true`
  - **Archives** (boolean): default `true`
  - **Miscellaneous** (boolean): default `true`

---

### `Diff()`

**Operation:** `Diff`

**Category:** `Utils`

**Module:** Diff

Compares two inputs (separated by the specified delimiter) and highlights the differences between them.

[More info](https://wikipedia.org/wiki/File_comparison)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Sample delimiter** (binaryString): default `\\n\\n`
  - **Diff by** (option): `Character`, `Word`, `Line` (+3 more)
  - **Show added** (boolean): default `true`
  - **Show removed** (boolean): default `true`
  - **Show subtraction** (boolean): default ``
  - **Ignore whitespace** (boolean): default ``

---

### `DisassembleX86()`

**Operation:** `Disassemble x86`

**Category:** `Other`

**Module:** Shellcode

Disassembly is the process of translating machine language into assembly language.

This operation supports 64-bit, 32-bit and 16-bit code written for Intel or AMD x86 processors. It is particularly useful for reverse engineering shellcode.

Input should be in hexadecimal.

[More info](https://wikipedia.org/wiki/X86)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Bit mode** (option): `64`, `32`, `16`
  - **Compatibility** (option): `Full x86 architecture`, `Knights Corner`, `Larrabee` (+4 more)
  - **Code Segment (CS)** (number): default `16`
  - **Offset (IP)** (number): default ``
  - **Show instruction hex** (boolean): default `true`
  - **Show instruction position** (boolean): default `true`

---

### `DitherImage()`

**Operation:** `Dither Image`

**Category:** `Multimedia`

**Module:** Image

Apply a dither effect to an image.

[More info](https://wikipedia.org/wiki/Dither)

**Input:** `ArrayBuffer` → **Output:** `html`

---

### `Divide()`

**Operation:** `Divide`

**Category:** `Arithmetic / Logic`

**Module:** Default

Divides a list of numbers. If an item in the string is not a number it is excluded from the list.

e.g. `0x0a 8 .5` becomes `2.5`

**Input:** `string` → **Output:** `BigNumber`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `Space`, `Comma` (+3 more)

---

### `DropBytes()`

**Operation:** `Drop bytes`

**Category:** `Utils`

**Module:** Default

Cuts a slice of the specified number of bytes out of the data. Negative values are allowed.

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Start** (number): default ``
  - **Length** (number): default `5`
  - **Apply to each line** (boolean): default ``

---

### `DropNthBytes()`

**Operation:** `Drop nth bytes`

**Category:** `Utils`

**Module:** Default

Drops every nth byte starting with a given byte.

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Drop every** (number): default `4`
  - **Starting at** (number): default ``
  - **Apply to each line** (boolean): default ``

---

### `ECDSASign()`

**Operation:** `ECDSA Sign`

**Category:** `Public Key`

**Module:** Ciphers

Sign a plaintext message with a PEM encoded EC key.

[More info](https://wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **ECDSA Private Key (PEM)** (text): default `-----BEGIN EC PRIVATE KEY-----`
  - **Message Digest Algorithm** (option): `SHA-256`, `SHA-384`, `SHA-512` (+2 more)
  - **Output Format** (option): `ASN.1 HEX`, `P1363 HEX`, `JSON Web Signature` (+1 more)

---

### `ECDSASignatureConversion()`

**Operation:** `ECDSA Signature Conversion`

**Category:** `Public Key`

**Module:** Ciphers

Convert an ECDSA signature between hex, asn1 and json.

[More info](https://wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input Format** (option): `Auto`, `ASN.1 HEX`, `P1363 HEX` (+2 more)
  - **Output Format** (option): `ASN.1 HEX`, `P1363 HEX`, `JSON Web Signature` (+1 more)

---

### `ECDSAVerify()`

**Operation:** `ECDSA Verify`

**Category:** `Public Key`

**Module:** Ciphers

Verify a message against a signature and a public PEM encoded EC key.

[More info](https://wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input Format** (option): `Auto`, `ASN.1 HEX`, `P1363 HEX` (+2 more)
  - **Message Digest Algorithm** (option): `SHA-256`, `SHA-384`, `SHA-512` (+2 more)
  - **ECDSA Public Key (PEM)** (text): default `-----BEGIN PUBLIC KEY-----`
  - **Message** (text)
  - **Message format** (option): `Raw`, `Hex`, `Base64`

---

### `ELFInfo()`

**Operation:** `ELF Info`

**Category:** `Forensics`

**Module:** Default

Implements readelf-like functionality. This operation will extract the ELF Header, Program Headers, Section Headers and Symbol Table for an ELF file.

[More info](https://www.wikipedia.org/wiki/Executable_and_Linkable_Format)

**Input:** `ArrayBuffer` → **Output:** `string`

---

### `EncodeNetBIOSName()`

**Operation:** `Encode NetBIOS Name`

**Category:** `Networking`

**Module:** Default

NetBIOS names as seen across the client interface to NetBIOS are exactly 16 bytes long. Within the NetBIOS-over-TCP protocols, a longer representation is used.

There are two levels of encoding. The first level maps a NetBIOS name into a domain system name.  The second level maps the domain system name into the 'compressed' representation required for interaction with the domain name system.

This operation carries out the first level of encoding. See RFC 1001 for full details.

[More info](https://wikipedia.org/wiki/NetBIOS)

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Offset** (number): default `65`

---

### `EncodeText()`

**Operation:** `Encode text`

**Category:** `Data format`

**Module:** Encodings

Encodes text into the chosen character encoding.

Supported charsets are:

UTF-8 (65001)
UTF-7 (65000)
UTF-16LE (1200)
UTF-16BE (1201)
UTF-32LE (12000)
UTF-32BE (12001)
IBM EBCDIC International (500)
IBM EBCDIC US-Canada (37)
IBM EBCDIC Multilingual/ROECE (Latin 2) (870)
IBM EBCDIC Greek Modern (875)
IBM EBCDIC French (1010)
IBM EBCDIC Turkish (Latin 5) (1026)
IBM EBCDIC Latin 1/Open System (1047)
IBM EBCDIC Lao (1132/1133/1341)
IBM EBCDIC US-Canada (037 + Euro symbol) (1140)
IBM EBCDIC Germany (20273 + Euro symbol) (1141)
IBM EBCDIC Denmark-Norway (20277 + Euro symbol) (1142)
IBM EBCDIC Finland-Sweden (20278 + Euro symbol) (1143)
IBM EBCDIC Italy (20280 + Euro symbol) (1144)
IBM EBCDIC Latin America-Spain (20284 + Euro symbol) (1145)
IBM EBCDIC United Kingdom (20285 + Euro symbol) (1146)
IBM EBCDIC France (20297 + Euro symbol) (1147)
IBM EBCDIC International (500 + Euro symbol) (1148)
IBM EBCDIC Icelandic (20871 + Euro symbol) (1149)
IBM EBCDIC Germany (20273)
IBM EBCDIC Denmark-Norway (20277)
IBM EBCDIC Finland-Sweden (20278)
IBM EBCDIC Italy (20280)
IBM EBCDIC Latin America-Spain (20284)
IBM EBCDIC United Kingdom (20285)
IBM EBCDIC Japanese Katakana Extended (20290)
IBM EBCDIC France (20297)
IBM EBCDIC Arabic (20420)
IBM EBCDIC Greek (20423)
IBM EBCDIC Hebrew (20424)
IBM EBCDIC Korean Extended (20833)
IBM EBCDIC Thai (20838)
IBM EBCDIC Icelandic (20871)
IBM EBCDIC Cyrillic Russian (20880)
IBM EBCDIC Turkish (20905)
IBM EBCDIC Latin 1/Open System (1047 + Euro symbol) (20924)
IBM EBCDIC Cyrillic Serbian-Bulgarian (21025)
OEM United States (437)
OEM Greek (formerly 437G); Greek (DOS) (737)
OEM Baltic; Baltic (DOS) (775)
OEM Russian; Cyrillic + Euro symbol (808)
OEM Multilingual Latin 1; Western European (DOS) (850)
OEM Latin 2; Central European (DOS) (852)
OEM Cyrillic (primarily Russian) (855)
OEM Turkish; Turkish (DOS) (857)
OEM Multilingual Latin 1 + Euro symbol (858)
OEM Portuguese; Portuguese (DOS) (860)
OEM Icelandic; Icelandic (DOS) (861)
OEM Hebrew; Hebrew (DOS) (862)
OEM French Canadian; French Canadian (DOS) (863)
OEM Arabic; Arabic (864) (864)
OEM Nordic; Nordic (DOS) (865)
OEM Russian; Cyrillic (DOS) (866)
OEM Modern Greek; Greek, Modern (DOS) (869)
OEM Cyrillic (primarily Russian) + Euro Symbol (872)
Windows-874 Thai (874)
Windows-1250 Central European (1250)
Windows-1251 Cyrillic (1251)
Windows-1252 Latin (1252)
Windows-1253 Greek (1253)
Windows-1254 Turkish (1254)
Windows-1255 Hebrew (1255)
Windows-1256 Arabic (1256)
Windows-1257 Baltic (1257)
Windows-1258 Vietnam (1258)
ISO-8859-1 Latin 1 Western European (28591)
ISO-8859-2 Latin 2 Central European (28592)
ISO-8859-3 Latin 3 South European (28593)
ISO-8859-4 Latin 4 North European (28594)
ISO-8859-5 Latin/Cyrillic (28595)
ISO-8859-6 Latin/Arabic (28596)
ISO-8859-7 Latin/Greek (28597)
ISO-8859-8 Latin/Hebrew (28598)
ISO 8859-8 Hebrew (ISO-Logical) (38598)
ISO-8859-9 Latin 5 Turkish (28599)
ISO-8859-10 Latin 6 Nordic (28600)
ISO-8859-11 Latin/Thai (28601)
ISO-8859-13 Latin 7 Baltic Rim (28603)
ISO-8859-14 Latin 8 Celtic (28604)
ISO-8859-15 Latin 9 (28605)
ISO-8859-16 Latin 10 (28606)
ISO 2022 JIS Japanese with no halfwidth Katakana (50220)
ISO 2022 JIS Japanese with halfwidth Katakana (50221)
ISO 2022 Japanese JIS X 0201-1989 (1 byte Kana-SO/SI) (50222)
ISO 2022 Korean (50225)
ISO 2022 Simplified Chinese (50227)
ISO 6937 Non-Spacing Accent (20269)
EUC Japanese (51932)
EUC Simplified Chinese (51936)
EUC Korean (51949)
ISCII Devanagari (57002)
ISCII Bengali (57003)
ISCII Tamil (57004)
ISCII Telugu (57005)
ISCII Assamese (57006)
ISCII Oriya (57007)
ISCII Kannada (57008)
ISCII Malayalam (57009)
ISCII Gujarati (57010)
ISCII Punjabi (57011)
Japanese Shift-JIS (932)
Simplified Chinese GBK (936)
Korean (949)
Traditional Chinese Big5 (950)
US-ASCII (7-bit) (20127)
Simplified Chinese GB2312 (20936)
KOI8-R Russian Cyrillic (20866)
KOI8-U Ukrainian Cyrillic (21866)
Mazovia (Polish) MS-DOS (620)
Arabic (ASMO 708) (708)
Arabic (Transparent ASMO); Arabic (DOS) (720)
Kamenický (Czech) MS-DOS (895)
Korean (Johab) (1361)
MAC Roman (10000)
Japanese (Mac) (10001)
MAC Traditional Chinese (Big5) (10002)
Korean (Mac) (10003)
Arabic (Mac) (10004)
Hebrew (Mac) (10005)
Greek (Mac) (10006)
Cyrillic (Mac) (10007)
MAC Simplified Chinese (GB 2312) (10008)
Romanian (Mac) (10010)
Ukrainian (Mac) (10017)
Thai (Mac) (10021)
MAC Latin 2 (Central European) (10029)
Icelandic (Mac) (10079)
Turkish (Mac) (10081)
Croatian (Mac) (10082)
CNS Taiwan (Chinese Traditional) (20000)
TCA Taiwan (20001)
ETEN Taiwan (Chinese Traditional) (20002)
IBM5550 Taiwan (20003)
TeleText Taiwan (20004)
Wang Taiwan (20005)
Western European IA5 (IRV International Alphabet 5) (20105)
IA5 German (7-bit) (20106)
IA5 Swedish (7-bit) (20107)
IA5 Norwegian (7-bit) (20108)
T.61 (20261)
Japanese (JIS 0208-1990 and 0212-1990) (20932)
Korean Wansung (20949)
Extended/Ext Alpha Lowercase (21027)
Europa 3 (29001)
Atari ST/TT (47451)
HZ-GB2312 Simplified Chinese (52936)
Simplified Chinese GB18030 (54936)

[More info](https://wikipedia.org/wiki/Character_encoding)

**Input:** `string` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Encoding** (option): `UTF-8 (65001)`, `UTF-7 (65000)`, `UTF-16LE (1200)` (+149 more)

---

### `Enigma()`

**Operation:** `Enigma`

**Category:** `Encryption / Encoding`

**Module:** Bletchley

Encipher/decipher with the WW2 Enigma machine.

Enigma was used by the German military, among others, around the WW2 era as a portable cipher machine to protect sensitive military, diplomatic and commercial communications.

The standard set of German military rotors and reflectors are provided. To configure the plugboard, enter a string of connected pairs of letters, e.g. `AB CD EF` connects A to B, C to D, and E to F. This is also used to create your own reflectors. To create your own rotor, enter the letters that the rotor maps A to Z to, in order, optionally followed by `<` then a list of stepping points.
This is deliberately fairly permissive with rotor placements etc compared to a real Enigma (on which, for example, a four-rotor Enigma uses only the thin reflectors and the beta or gamma rotor in the 4th slot).

More detailed descriptions of the Enigma, Typex and Bombe operations can be found here.

[More info](https://wikipedia.org/wiki/Enigma_machine)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Model** (argSelector): `3-rotor`, `4-rotor`
  - **Left-most (4th) rotor** (editableOption): `Beta`, `Gamma`
  - **Left-most rotor ring setting** (option): `A`, `B`, `C` (+23 more)
  - **Left-most rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **Left-hand rotor** (editableOption): `I`, `II`, `III` (+5 more)
  - **Left-hand rotor ring setting** (option): `A`, `B`, `C` (+23 more)
  - **Left-hand rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **Middle rotor** (editableOption): `I`, `II`, `III` (+5 more); default `II`
  - **Middle rotor ring setting** (option): `A`, `B`, `C` (+23 more)
  - **Middle rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **Right-hand rotor** (editableOption): `I`, `II`, `III` (+5 more); default `III`
  - **Right-hand rotor ring setting** (option): `A`, `B`, `C` (+23 more)
  - **Right-hand rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **Reflector** (editableOption): `B`, `C`, `B Thin` (+1 more)
  - **Plugboard** (string): default ``
  - **Strict output** (boolean): default `true`

---

### `Entropy()`

**Operation:** `Entropy`

**Category:** `Other`

**Module:** Charts

Shannon Entropy, in the context of information theory, is a measure of the rate at which information is produced by a source of data. It can be used, in a broad sense, to detect whether data is likely to be structured or unstructured. 8 is the maximum, representing highly unstructured, 'random' data. English language text usually falls somewhere between 3.5 and 5. Properly encrypted or compressed data should have an entropy of over 7.5.

[More info](https://wikipedia.org/wiki/Entropy_(information_theory))

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Visualisation** (option): `Shannon scale`, `Histogram (Bar)`, `Histogram (Line)` (+2 more)

---

### `EscapeUnicodeCharacters()`

**Operation:** `Escape Unicode Characters`

**Category:** `Data format`

**Module:** Default

Converts characters to their unicode-escaped notations.

Supports the prefixes:`\u``%u``U+`e.g. `σου` becomes `\u03C3\u03BF\u03C5`

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Prefix** (option): `\u`, `%u`, `U+`
  - **Encode all chars** (boolean): default ``
  - **Padding** (number): default `4`
  - **Uppercase hex** (boolean): default `true`

---

### `EscapeString()`

**Operation:** `Escape string`

**Category:** `Utils`

**Module:** Default

Escapes special characters in a string so that they do not cause conflicts. For example, `Don't stop me now` becomes `Don\'t stop me now`.

Supports the following escape sequences:`\n` (Line feed/newline)`\r` (Carriage return)`\t` (Horizontal tab)`\b` (Backspace)`\f` (Form feed)`\xnn` (Hex, where n is 0-f)`\\` (Backslash)`\'` (Single quote)`\"` (Double quote)`\unnnn` (Unicode character)`\u{nnnnnn}` (Unicode code point)

[More info](https://wikipedia.org/wiki/Escape_sequence)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Escape level** (option): `Special chars`, `Everything`, `Minimal`
  - **Escape quote** (option): `Single`, `Double`, `Backtick`
  - **JSON compatible** (boolean): default ``
  - **ES6 compatible** (boolean): default `true`
  - **Uppercase hex** (boolean): default ``

---

### `ExpandAlphabetRange()`

**Operation:** `Expand alphabet range`

**Category:** `Utils`

**Module:** Default

Expand an alphabet range string into a list of the characters in that range.

e.g. `a-z` becomes `abcdefghijklmnopqrstuvwxyz`.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (binaryString): default ``

---

### `ExtractEXIF()`

**Operation:** `Extract EXIF`

**Category:** `Extractors`

**Module:** Image

Extracts EXIF data from an image.

EXIF data is metadata embedded in images (JPEG, JPG, TIFF) and audio files.

EXIF data from photos usually contains information about the image file itself as well as the device used to create it.

[More info](https://wikipedia.org/wiki/Exif)

**Input:** `ArrayBuffer` → **Output:** `string`

---

### `ExtractFiles()`

**Operation:** `Extract Files`

**Category:** `Extractors`

**Module:** Default

Performs file carving to attempt to extract files from the input.

This operation is currently capable of carving out the following formats:
            
                
                JPG,JPEG,JPE,THM,MPOGIFPNGWEBPBMPICOTGAFLVWAVMP3PDFRTFDOCX,XLSX,PPTXEPUBEXE,DLL,DRV,VXD,SYS,OCX,VBX,COM,FON,SCRELF,BIN,AXF,O,PRX,SODYLIBZIPTARGZBZ2ZLIBXZJARLZOP,LZODEBSQLITEEVTEVTXDMPPFPLISTKEYCHAINLNK
                
            Minimum File Size can be used to prune small false positives.

[More info](https://forensics.wiki/file_carving)

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Images** (boolean): default `true`
  - **Video** (boolean): default `true`
  - **Audio** (boolean): default `true`
  - **Documents** (boolean): default `true`
  - **Applications** (boolean): default `true`
  - **Archives** (boolean): default `true`
  - **Miscellaneous** (boolean): default ``
  - **Ignore failed extractions** (boolean): default `true`
  - **Minimum File Size** (number): default `100`

---

### `ExtractID3()`

**Operation:** `Extract ID3`

**Category:** `Extractors`

**Module:** Default

This operation extracts ID3 metadata from an MP3 file.

ID3 is a metadata container most often used in conjunction with the MP3 audio file format. It allows information such as the title, artist, album, track number, and other information about the file to be stored in the file itself.

[More info](https://wikipedia.org/wiki/ID3)

**Input:** `ArrayBuffer` → **Output:** `html`

---

### `ExtractIPAddresses()`

**Operation:** `Extract IP addresses`

**Category:** `Extractors`

**Module:** Regex

Extracts all IPv4 and IPv6 addresses.

Warning: Given a string `1.2.3.4.5.6.7.8`, this will match `1.2.3.4 and 5.6.7.8` so always check the original input!

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **IPv4** (boolean): default `true`
  - **IPv6** (boolean): default ``
  - **Remove local IPv4 addresses** (boolean): default ``
  - **Display total** (boolean): default ``
  - **Sort** (boolean): default ``
  - **Unique** (boolean): default ``

---

### `ExtractLSB()`

**Operation:** `Extract LSB`

**Category:** `Forensics`

**Module:** Image

Extracts the Least Significant Bit data from each pixel in an image. This is a common way to hide data in Steganography.

[More info](https://wikipedia.org/wiki/Bit_numbering#Least_significant_bit_in_digital_steganography)

**Input:** `ArrayBuffer` → **Output:** `byteArray`

**Arguments:**
  - **Colour Pattern #1** (option): `R`, `G`, `B` (+1 more)
  - **Colour Pattern #2** (option): ``, `R`, `G` (+2 more)
  - **Colour Pattern #3** (option): ``, `R`, `G` (+2 more)
  - **Colour Pattern #4** (option): ``, `R`, `G` (+2 more)
  - **Pixel Order** (option): `Row`, `Column`
  - **Bit** (number): default ``

---

### `ExtractMACAddresses()`

**Operation:** `Extract MAC addresses`

**Category:** `Extractors`

**Module:** Regex

Extracts all Media Access Control (MAC) addresses from the input.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Display total** (boolean): default ``
  - **Sort** (boolean): default ``
  - **Unique** (boolean): default ``

---

### `ExtractRGBA()`

**Operation:** `Extract RGBA`

**Category:** `Forensics`

**Module:** Image

Extracts each pixel's RGBA value in an image. These are sometimes used in Steganography to hide text or data.

[More info](https://wikipedia.org/wiki/RGBA_color_space)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Delimiter** (editableOption): `Comma`, `Space`, `CRLF` (+1 more)
  - **Include Alpha** (boolean): default `true`

---

### `ExtractURLs()`

**Operation:** `Extract URLs`

**Category:** `Extractors`

**Module:** Regex

Extracts Uniform Resource Locators (URLs) from the input. The protocol (http, ftp etc.) is required otherwise there will be far too many false positives.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Display total** (boolean): default ``
  - **Sort** (boolean): default ``
  - **Unique** (boolean): default ``

---

### `ExtractDates()`

**Operation:** `Extract dates`

**Category:** `Date / Time`

**Module:** Regex

Extracts dates in the following formats`yyyy-mm-dd``dd/mm/yyyy``mm/dd/yyyy`Dividers can be any of /, -, . or space

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Display total** (boolean): default ``

---

### `ExtractDomains()`

**Operation:** `Extract domains`

**Category:** `Extractors`

**Module:** Regex

Extracts fully qualified domain names.
Note that this will not include paths. Use Extract URLs to find entire URLs.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Display total** (boolean): default ``
  - **Sort** (boolean): default ``
  - **Unique** (boolean): default ``
  - **Underscore (DMARC, DKIM, etc)** (boolean): default ``

---

### `ExtractEmailAddresses()`

**Operation:** `Extract email addresses`

**Category:** `Extractors`

**Module:** Regex

Extracts all email addresses from the input.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Display total** (boolean): default ``
  - **Sort** (boolean): default ``
  - **Unique** (boolean): default ``

---

### `ExtractFilePaths()`

**Operation:** `Extract file paths`

**Category:** `Extractors`

**Module:** Regex

Extracts anything that looks like a Windows or UNIX file path.

Note that if UNIX is selected, there will likely be a lot of false positives.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Windows** (boolean): default `true`
  - **UNIX** (boolean): default `true`
  - **Display total** (boolean): default ``
  - **Sort** (boolean): default ``
  - **Unique** (boolean): default ``

---

### `ExtractHashes()`

**Operation:** `Extract hashes`

**Category:** `Extractors`

**Module:** Regex

Extracts potential hashes based on hash character length

[More info](https://wikipedia.org/wiki/Comparison_of_cryptographic_hash_functions)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Hash character length** (number): default `40`
  - **All hashes** (boolean): default ``
  - **Display Total** (boolean): default ``

---

### `FangURL()`

**Operation:** `Fang URL`

**Category:** `Networking`

**Module:** Default

Takes a 'Defanged' Universal Resource Locator (URL) and 'Fangs' it. Meaning, it removes the alterations (defanged) that render it useless so that it can be used again.

[More info](https://isc.sans.edu/forums/diary/Defang+all+the+things/22744/)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Restore [.]** (boolean): default `true`
  - **Restore hxxp** (boolean): default `true`
  - **Restore ://** (boolean): default `true`

---

### `FernetDecrypt()`

**Operation:** `Fernet Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Default

Fernet is a symmetric encryption method which makes sure that the message encrypted cannot be manipulated/read without the key. It uses URL safe encoding for the keys. Fernet uses 128-bit AES in CBC mode and PKCS7 padding, with HMAC using SHA256 for authentication. The IV is created from os.random().

Key: The key must be 32 bytes (256 bits) encoded with Base64.

[More info](https://asecuritysite.com/encryption/fer)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (string): default ``

---

### `FernetEncrypt()`

**Operation:** `Fernet Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Default

Fernet is a symmetric encryption method which makes sure that the message encrypted cannot be manipulated/read without the key. It uses URL safe encoding for the keys. Fernet uses 128-bit AES in CBC mode and PKCS7 padding, with HMAC using SHA256 for authentication. The IV is created from os.random().

Key: The key must be 32 bytes (256 bits) encoded with Base64.

[More info](https://asecuritysite.com/encryption/fer)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (string): default ``

---

### `FileTree()`

**Operation:** `File Tree`

**Category:** `Utils`

**Module:** Default

Creates a file tree from a list of file paths (similar to the tree command in Linux)

[More info](https://wikipedia.org/wiki/Tree_(command))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **File Path Delimiter** (binaryString): default `/`
  - **Delimiter** (option): `Line feed`, `CRLF`, `Space` (+4 more)

---

### `Filter()`

**Operation:** `Filter`

**Category:** `Utils`

**Module:** Regex

Splits up the input using the specified delimiter and then filters each branch based on a regular expression.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `CRLF`, `Space` (+4 more)
  - **Regex** (string): default ``
  - **Invert condition** (boolean): default ``

---

### `FlipImage()`

**Operation:** `Flip Image`

**Category:** `Multimedia`

**Module:** Image

Flips an image along its X or Y axis.

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Axis** (option): `Horizontal`, `Vertical`

---

### `Fork()`

**Operation:** `Fork`

**Category:** `Flow control`

**Module:** Default

Split the input data up based on the specified delimiter and run all subsequent operations on each branch separately.

For example, to decode multiple Base64 strings, enter them all on separate lines then add the 'Fork' and 'From Base64' operations to the recipe. Each string will be decoded separately.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Split delimiter** (binaryShortString): default `\\n`
  - **Merge delimiter** (binaryShortString): default `\\n`
  - **Ignore errors** (boolean): default ``

---

### `FormatMACAddresses()`

**Operation:** `Format MAC addresses`

**Category:** `Networking`

**Module:** Default

Displays given MAC addresses in multiple different formats.

Expects addresses in a list separated by newlines, spaces or commas.

WARNING: There are no validity checks.

[More info](https://wikipedia.org/wiki/MAC_address#Notational_conventions)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Output case** (option): `Both`, `Upper only`, `Lower only`
  - **No delimiter** (boolean): default `true`
  - **Dash delimiter** (boolean): default `true`
  - **Colon delimiter** (boolean): default `true`
  - **Cisco style** (boolean): default ``
  - **IPv6 interface ID** (boolean): default ``

---

### `FrequencyDistribution()`

**Operation:** `Frequency distribution`

**Category:** `Other`

**Module:** Default

Displays the distribution of bytes in the data as a graph.

[More info](https://wikipedia.org/wiki/Frequency_distribution)

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Show 0%s** (boolean): default `true`
  - **Show ASCII** (boolean): default `true`

---

### `FromBCD()`

**Operation:** `From BCD`

**Category:** `Data format`

**Module:** Default

Binary-Coded Decimal (BCD) is a class of binary encodings of decimal numbers where each decimal digit is represented by a fixed number of bits, usually four or eight. Special bit patterns are sometimes used for a sign.

[More info](https://wikipedia.org/wiki/Binary-coded_decimal)

**Input:** `string` → **Output:** `BigNumber`

**Arguments:**
  - **Scheme** (option): `8 4 2 1`, `7 4 2 1`, `4 2 2 1` (+4 more)
  - **Packed** (boolean): default `true`
  - **Signed** (boolean): default ``
  - **Input format** (option): `Nibbles`, `Bytes`, `Raw`

---

### `FromBase()`

**Operation:** `From Base`

**Category:** `Data format`

**Module:** Default

Converts a number to decimal from a given numerical base.

[More info](https://wikipedia.org/wiki/Radix)

**Input:** `string` → **Output:** `BigNumber`

**Arguments:**
  - **Radix** (number): default `36`

---

### `FromBase32()`

**Operation:** `From Base32`

**Category:** `Data format`

**Module:** Default

Base32 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers. It uses a smaller set of characters than Base64, usually the uppercase alphabet and the numbers 2 to 7.

[More info](https://wikipedia.org/wiki/Base32)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Alphabet** (editableOption): `Standard`, `Hex Extended`
  - **Remove non-alphabet chars** (boolean): default `true`

---

### `FromBase45()`

**Operation:** `From Base45`

**Category:** `Data format`

**Module:** Default

Base45 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers. The high number base results in shorter strings than with the decimal or hexadecimal system. Base45 is optimized for usage with QR codes.

[More info](https://wikipedia.org/wiki/List_of_numeral_systems)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Alphabet** (string): default `0-9A-Z $%*+\\-./:`
  - **Remove non-alphabet chars** (boolean): default `true`

---

### `FromBase58()`

**Operation:** `From Base58`

**Category:** `Data format`

**Module:** Default

Base58 (similar to Base64) is a notation for encoding arbitrary byte data. It differs from Base64 by removing easily misread characters (i.e. l, I, 0 and O) to improve human readability.

This operation decodes data from an ASCII string (with an alphabet of your choosing, presets included) back into its raw form.

e.g. `StV1DL6CwTryKyV` becomes `hello world`

Base58 is commonly used in cryptocurrencies (Bitcoin, Ripple, etc).

[More info](https://wikipedia.org/wiki/Base58)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Alphabet** (editableOption): `Bitcoin`, `Ripple`
  - **Remove non-alphabet chars** (boolean): default `true`

---

### `FromBase62()`

**Operation:** `From Base62`

**Category:** `Data format`

**Module:** Default

Base62 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers. The high number base results in shorter strings than with the decimal or hexadecimal system.

[More info](https://wikipedia.org/wiki/List_of_numeral_systems)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Alphabet** (string): default `0-9A-Za-z`

---

### `FromBase64()`

**Operation:** `From Base64`

**Category:** `Data format`

**Module:** Default

Base64 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers.

This operation decodes data from an ASCII Base64 string back into its raw format.

e.g. `aGVsbG8=` becomes `hello`

[More info](https://wikipedia.org/wiki/Base64)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Alphabet** (editableOption): `Standard (RFC 4648): A-Za-z0-9+/=`, `URL safe (RFC 4648 §5): A-Za-z0-9-_`, `Filename safe: A-Za-z0-9+-=` (+14 more)
  - **Remove non-alphabet chars** (boolean): default `true`
  - **Strict mode** (boolean): default ``

---

### `FromBase85()`

**Operation:** `From Base85`

**Category:** `Data format`

**Module:** Default

Base85 (also called Ascii85) is a notation for encoding arbitrary byte data. It is usually more efficient that Base64.

This operation decodes data from an ASCII string (with an alphabet of your choosing, presets included).

e.g. `BOu!rD]j7BEbo7` becomes `hello world`

Base85 is commonly used in Adobe's PostScript and PDF file formats.

[More info](https://wikipedia.org/wiki/Ascii85)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Alphabet** (editableOption): `Standard`, `Z85 (ZeroMQ)`, `IPv6`
  - **Remove non-alphabet chars** (boolean): default `true`
  - **All-zero group char** (binaryShortString): default `z`

---

### `FromBase92()`

**Operation:** `From Base92`

**Category:** `Data format`

**Module:** Default

Base92 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers.

[More info](https://wikipedia.org/wiki/List_of_numeral_systems)

**Input:** `string` → **Output:** `byteArray`

---

### `FromBinary()`

**Operation:** `From Binary`

**Category:** `Data format`

**Module:** Default

Converts a binary string back into its raw form.

e.g. `01001000 01101001` becomes `Hi`

[More info](https://wikipedia.org/wiki/Binary_code)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+4 more)
  - **Byte Length** (number): default `8`

---

### `FromBraille()`

**Operation:** `From Braille`

**Category:** `Data format`

**Module:** Default

Converts six-dot braille symbols to text.

[More info](https://wikipedia.org/wiki/Braille)

**Input:** `string` → **Output:** `string`

---

### `FromCaseInsensitiveRegex()`

**Operation:** `From Case Insensitive Regex`

**Category:** `Utils`

**Module:** Default

Converts a case-insensitive regex string to a case sensitive regex string (no guarantee on it being the proper original casing) in case the i flag wasn't available at the time but now is, or you need it to be case-sensitive again.

e.g. `[mM][oO][zZ][iI][lL][lL][aA]/[0-9].[0-9] .*` becomes `Mozilla/[0-9].[0-9] .*`

[More info](https://wikipedia.org/wiki/Regular_expression)

**Input:** `string` → **Output:** `string`

---

### `FromCharcode()`

**Operation:** `From Charcode`

**Category:** `Data format`

**Module:** Default

Converts unicode character codes back into text.

e.g. `0393 03b5 03b9 03ac 20 03c3 03bf 03c5` becomes `Γειά σου`

[More info](https://wikipedia.org/wiki/Plane_(Unicode))

**Input:** `string` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+3 more)
  - **Base** (number): default `16`

---

### `FromDecimal()`

**Operation:** `From Decimal`

**Category:** `Data format`

**Module:** Default

Converts the data from an ordinal integer array back into its raw form.

e.g. `72 101 108 108 111` becomes `Hello`

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+3 more)
  - **Support signed values** (boolean): default ``

---

### `FromFloat()`

**Operation:** `From Float`

**Category:** `Data format`

**Module:** Default

Convert from IEEE754 Floating Point Numbers

[More info](https://wikipedia.org/wiki/IEEE_754)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Endianness** (option): `Big Endian`, `Little Endian`
  - **Size** (option): `Float (4 bytes)`, `Double (8 bytes)`
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+3 more)

---

### `FromHTMLEntity()`

**Operation:** `From HTML Entity`

**Category:** `Data format`

**Module:** Encodings

Converts HTML entities back to characters

e.g. `&amp;` becomes `&`

[More info](https://wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references)

**Input:** `string` → **Output:** `string`

---

### `FromHex()`

**Operation:** `From Hex`

**Category:** `Data format`

**Module:** Default

Converts a hexadecimal byte string back into its raw value.

e.g. `ce 93 ce b5 ce b9 ce ac 20 cf 83 ce bf cf 85 0a` becomes the UTF-8 encoded string `Γειά σου`

[More info](https://wikipedia.org/wiki/Hexadecimal)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Delimiter** (option): `Auto`, `Space`, `Percent` (+9 more)

---

### `FromHexContent()`

**Operation:** `From Hex Content`

**Category:** `Data format`

**Module:** Default

Translates hexadecimal bytes in text back to raw bytes. This format is used by SNORT for representing hex within ASCII text.

e.g. `foo|3d|bar` becomes `foo=bar`.

[More info](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00451000000000000000)

**Input:** `string` → **Output:** `byteArray`

---

### `FromHexdump()`

**Operation:** `From Hexdump`

**Category:** `Data format`

**Module:** Default

Attempts to convert a hexdump back into raw data. This operation supports many different hexdump variations, but probably not all. Make sure you verify that the data it gives you is correct before continuing analysis.

[More info](https://wikipedia.org/wiki/Hex_dump)

**Input:** `string` → **Output:** `byteArray`

---

### `FromMessagePack()`

**Operation:** `From MessagePack`

**Category:** `Data format`

**Module:** Code

Converts MessagePack encoded data to JSON. MessagePack is a computer data interchange format. It is a binary form for representing simple data structures like arrays and associative arrays.

[More info](https://wikipedia.org/wiki/MessagePack)

**Input:** `ArrayBuffer` → **Output:** `JSON`

---

### `FromModhex()`

**Operation:** `From Modhex`

**Category:** `Data format`

**Module:** Default

Converts a modhex byte string back into its raw value.

[More info](https://en.wikipedia.org/wiki/YubiKey#ModHex)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Delimiter** (option): `Auto`, `Space`, `Percent` (+6 more)

---

### `FromMorseCode()`

**Operation:** `From Morse Code`

**Category:** `Encryption / Encoding`

**Module:** Default

Translates Morse Code into (upper case) alphanumeric characters.

[More info](https://wikipedia.org/wiki/Morse_code)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Letter delimiter** (option): `Space`, `Line feed`, `CRLF` (+5 more)
  - **Word delimiter** (option): `Line feed`, `CRLF`, `Forward slash` (+4 more)

---

### `FromOctal()`

**Operation:** `From Octal`

**Category:** `Data format`

**Module:** Default

Converts an octal byte string back into its raw value.

e.g. `316 223 316 265 316 271 316 254 40 317 203 316 277 317 205` becomes the UTF-8 encoded string `Γειά σου`

[More info](https://wikipedia.org/wiki/Octal)

**Input:** `string` → **Output:** `byteArray`

**Arguments:**
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+3 more)

---

### `FromPunycode()`

**Operation:** `From Punycode`

**Category:** `Data format`

**Module:** Encodings

Punycode is a way to represent Unicode with the limited character subset of ASCII supported by the Domain Name System.

e.g. `mnchen-3ya` decodes to `münchen`

[More info](https://wikipedia.org/wiki/Punycode)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Internationalised domain name** (boolean): default ``

---

### `FromQuotedPrintable()`

**Operation:** `From Quoted Printable`

**Category:** `Data format`

**Module:** Default

Converts QP-encoded text back to standard text.

e.g. The quoted-printable encoded string `hello=20world` becomes `hello world`

[More info](https://wikipedia.org/wiki/Quoted-printable)

**Input:** `string` → **Output:** `byteArray`

---

### `FromUNIXTimestamp()`

**Operation:** `From UNIX Timestamp`

**Category:** `Date / Time`

**Module:** Default

Converts a UNIX timestamp to a datetime string.

e.g. `978346800` becomes `Mon 1 January 2001 11:00:00 UTC`

A UNIX timestamp is a 32-bit value representing the number of seconds since January 1, 1970 UTC (the UNIX epoch).

[More info](https://wikipedia.org/wiki/Unix_time)

**Input:** `number` → **Output:** `string`

**Arguments:**
  - **Units** (option): `Seconds (s)`, `Milliseconds (ms)`, `Microseconds (μs)` (+1 more)

---

### `FuzzyMatch()`

**Operation:** `Fuzzy Match`

**Category:** `Utils`

**Module:** Default

Conducts a fuzzy search to find a pattern within the input based on weighted criteria.

e.g. A search for `dpan` will match on `Don't Panic`

[More info](https://wikipedia.org/wiki/Fuzzy_matching_(computer-assisted_translation))

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Search** (binaryString): default ``
  - **Sequential bonus** (number): default `15`
  - **Separator bonus** (number): default `30`
  - **Camel bonus** (number): default `30`
  - **First letter bonus** (number): default `15`
  - **Leading letter penalty** (number): default `-5`
  - **Max leading letter penalty** (number): default `-15`
  - **Unmatched letter penalty** (number): default `-1`

---

### `GOSTDecrypt()`

**Operation:** `GOST Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

The GOST block cipher (Magma), defined in the standard GOST 28147-89 (RFC 5830), is a Soviet and Russian government standard symmetric key block cipher with a block size of 64 bits. The original standard, published in 1989, did not give the cipher any name, but the most recent revision of the standard, GOST R 34.12-2015 (RFC 7801, RFC 8891), specifies that it may be referred to as Magma. The GOST hash function is based on this cipher. The new standard also specifies a new 128-bit block cipher called Kuznyechik.

Developed in the 1970s, the standard had been marked 'Top Secret' and then downgraded to 'Secret' in 1990. Shortly after the dissolution of the USSR, it was declassified and it was released to the public in 1994. GOST 28147 was a Soviet alternative to the United States standard algorithm, DES. Thus, the two are very similar in structure.

[More info](https://wikipedia.org/wiki/GOST_(block_cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Input type** (option): `Hex`, `Raw`
  - **Output type** (option): `Raw`, `Hex`
  - **Algorithm** (argSelector): `GOST 28147 (1989)`, `GOST R 34.12 (Magma, 2015)`, `GOST R 34.12 (Kuznyechik, 2015)`
  - **sBox** (option): `E-TEST`, `E-A`, `E-B` (+7 more)
  - **Block mode** (option): `ECB`, `CFB`, `OFB` (+2 more)
  - **Key meshing mode** (option): `NO`, `CP`
  - **Padding** (option): `NO`, `PKCS5`, `ZERO` (+2 more)

---

### `GOSTEncrypt()`

**Operation:** `GOST Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

The GOST block cipher (Magma), defined in the standard GOST 28147-89 (RFC 5830), is a Soviet and Russian government standard symmetric key block cipher with a block size of 64 bits. The original standard, published in 1989, did not give the cipher any name, but the most recent revision of the standard, GOST R 34.12-2015 (RFC 7801, RFC 8891), specifies that it may be referred to as Magma. The GOST hash function is based on this cipher. The new standard also specifies a new 128-bit block cipher called Kuznyechik.

Developed in the 1970s, the standard had been marked 'Top Secret' and then downgraded to 'Secret' in 1990. Shortly after the dissolution of the USSR, it was declassified and it was released to the public in 1994. GOST 28147 was a Soviet alternative to the United States standard algorithm, DES. Thus, the two are very similar in structure.

[More info](https://wikipedia.org/wiki/GOST_(block_cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Input type** (option): `Raw`, `Hex`
  - **Output type** (option): `Hex`, `Raw`
  - **Algorithm** (argSelector): `GOST 28147 (1989)`, `GOST R 34.12 (Magma, 2015)`, `GOST R 34.12 (Kuznyechik, 2015)`
  - **sBox** (option): `E-TEST`, `E-A`, `E-B` (+7 more)
  - **Block mode** (option): `ECB`, `CFB`, `OFB` (+2 more)
  - **Key meshing mode** (option): `NO`, `CP`
  - **Padding** (option): `NO`, `PKCS5`, `ZERO` (+2 more)

---

### `GOSTHash()`

**Operation:** `GOST Hash`

**Category:** `Hashing`

**Module:** Hashing

The GOST hash function, defined in the standards GOST R 34.11-94 and GOST 34.311-95 is a 256-bit cryptographic hash function. It was initially defined in the Russian national standard GOST R 34.11-94 Information Technology – Cryptographic Information Security – Hash Function. The equivalent standard used by other member-states of the CIS is GOST 34.311-95.

This function must not be confused with a different Streebog hash function, which is defined in the new revision of the standard GOST R 34.11-2012.

The GOST hash function is based on the GOST block cipher.

[More info](https://wikipedia.org/wiki/GOST_(hash_function))

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Algorithm** (argSelector): `GOST 28147 (1994)`, `GOST R 34.11 (Streebog, 2012)`
  - **Digest length** (option): `256`, `512`
  - **sBox** (option): `E-TEST`, `E-A`, `E-B` (+7 more)

---

### `GOSTKeyUnwrap()`

**Operation:** `GOST Key Unwrap`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

A decryptor for keys wrapped using one of the GOST block ciphers.

[More info](https://wikipedia.org/wiki/GOST_(block_cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **User Key Material** (toggleString): default ``
  - **Input type** (option): `Hex`, `Raw`
  - **Output type** (option): `Raw`, `Hex`
  - **Algorithm** (argSelector): `GOST 28147 (1989)`, `GOST R 34.12 (Magma, 2015)`, `GOST R 34.12 (Kuznyechik, 2015)`
  - **sBox** (option): `E-TEST`, `E-A`, `E-B` (+7 more)
  - **Key wrapping** (option): `NO`, `CP`, `SC`

---

### `GOSTKeyWrap()`

**Operation:** `GOST Key Wrap`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

A key wrapping algorithm for protecting keys in untrusted storage using one of the GOST block cipers.

[More info](https://wikipedia.org/wiki/GOST_(block_cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **User Key Material** (toggleString): default ``
  - **Input type** (option): `Raw`, `Hex`
  - **Output type** (option): `Hex`, `Raw`
  - **Algorithm** (argSelector): `GOST 28147 (1989)`, `GOST R 34.12 (Magma, 2015)`, `GOST R 34.12 (Kuznyechik, 2015)`
  - **sBox** (option): `E-TEST`, `E-A`, `E-B` (+7 more)
  - **Key wrapping** (option): `NO`, `CP`, `SC`

---

### `GOSTSign()`

**Operation:** `GOST Sign`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Sign a plaintext message using one of the GOST block ciphers.

[More info](https://wikipedia.org/wiki/GOST_(block_cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Input type** (option): `Raw`, `Hex`
  - **Output type** (option): `Hex`, `Raw`
  - **Algorithm** (argSelector): `GOST 28147 (1989)`, `GOST R 34.12 (Magma, 2015)`, `GOST R 34.12 (Kuznyechik, 2015)`
  - **sBox** (option): `E-TEST`, `E-A`, `E-B` (+7 more)
  - **MAC length** (number): default `32`

---

### `GOSTVerify()`

**Operation:** `GOST Verify`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Verify the signature of a plaintext message using one of the GOST block ciphers. Enter the signature in the MAC field.

[More info](https://wikipedia.org/wiki/GOST_(block_cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **MAC** (toggleString): default ``
  - **Input type** (option): `Raw`, `Hex`
  - **Algorithm** (argSelector): `GOST 28147 (1989)`, `GOST R 34.12 (Magma, 2015)`, `GOST R 34.12 (Kuznyechik, 2015)`
  - **sBox** (option): `E-TEST`, `E-A`, `E-B` (+7 more)

---

### `GenerateDeBruijnSequence()`

**Operation:** `Generate De Bruijn Sequence`

**Category:** `Other`

**Module:** Default

Generates rolling keycode combinations given a certain alphabet size and key length.

[More info](https://wikipedia.org/wiki/De_Bruijn_sequence)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Alphabet size (k)** (number): default `2`
  - **Key length (n)** (number): default `3`

---

### `GenerateECDSAKeyPair()`

**Operation:** `Generate ECDSA Key Pair`

**Category:** `Public Key`

**Module:** Ciphers

Generate an ECDSA key pair with a given Curve.

WARNING: Cryptographic operations in CyberChef should not be relied upon to provide security in any situation. No guarantee is offered for their correctness. We advise you not to use keys generated from CyberChef in operational contexts.

[More info](https://wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Elliptic Curve** (option): `P-256`, `P-384`, `P-521`
  - **Output Format** (option): `PEM`, `DER`, `JWK`

---

### `GenerateHOTP()`

**Operation:** `Generate HOTP`

**Category:** `Other`

**Module:** Default

The HMAC-based One-Time Password algorithm (HOTP) is an algorithm that computes a one-time password from a shared secret key and an incrementing counter. It has been adopted as Internet Engineering Task Force standard RFC 4226, is the cornerstone of Initiative For Open Authentication (OAUTH), and is used in a number of two-factor authentication systems.

Enter the secret as the input or leave it blank for a random secret to be generated.

[More info](https://wikipedia.org/wiki/HMAC-based_One-time_Password_algorithm)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Name** (string): default ``
  - **Code length** (number): default `6`
  - **Counter** (number): default ``

---

### `GenerateImage()`

**Operation:** `Generate Image`

**Category:** `Multimedia`

**Module:** Image

Generates an image using the input as pixel values.

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Mode** (option): `Greyscale`, `RG`, `RGB` (+2 more)
  - **Pixel Scale Factor** (number): default `8`
  - **Pixels per row** (number): default `64`

---

### `GenerateLoremIpsum()`

**Operation:** `Generate Lorem Ipsum`

**Category:** `Other`

**Module:** Default

Generate varying length lorem ipsum placeholder text.

[More info](https://wikipedia.org/wiki/Lorem_ipsum)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Length** (number): default `3`
  - **Length in** (option): `Paragraphs`, `Sentences`, `Words` (+1 more)

---

### `GeneratePGPKeyPair()`

**Operation:** `Generate PGP Key Pair`

**Category:** `Public Key`

**Module:** PGP

Generates a new public/private PGP key pair. Supports RSA and Eliptic Curve (EC) keys.

WARNING: Cryptographic operations in CyberChef should not be relied upon to provide security in any situation. No guarantee is offered for their correctness. We advise you not to use keys generated from CyberChef in operational contexts.

[More info](https://wikipedia.org/wiki/Pretty_Good_Privacy)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key type** (option): `RSA-1024`, `RSA-2048`, `RSA-4096` (+3 more)
  - **Password (optional)** (string): default ``
  - **Name (optional)** (string): default ``
  - **Email (optional)** (string): default ``

---

### `GenerateQRCode()`

**Operation:** `Generate QR Code`

**Category:** `Other`

**Module:** Image

Generates a Quick Response (QR) code from the input text.

A QR code is a type of matrix barcode (or two-dimensional barcode) first designed in 1994 for the automotive industry in Japan. A barcode is a machine-readable optical label that contains information about the item to which it is attached.

[More info](https://wikipedia.org/wiki/QR_code)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Image Format** (option): `PNG`, `SVG`, `EPS` (+1 more)
  - **Module size (px)** (number): default `5`
  - **Margin (num modules)** (number): default `4`
  - **Error correction** (option): `Low`, `Medium`, `Quartile` (+1 more); default `Medium`

---

### `GenerateRSAKeyPair()`

**Operation:** `Generate RSA Key Pair`

**Category:** `Public Key`

**Module:** Ciphers

Generate an RSA key pair with a given number of bits.

WARNING: Cryptographic operations in CyberChef should not be relied upon to provide security in any situation. No guarantee is offered for their correctness. We advise you not to use keys generated from CyberChef in operational contexts.

[More info](https://wikipedia.org/wiki/RSA_(cryptosystem))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **RSA Key Length** (option): `1024`, `2048`, `4096`
  - **Output Format** (option): `PEM`, `JSON`, `DER`

---

### `GenerateTOTP()`

**Operation:** `Generate TOTP`

**Category:** `Other`

**Module:** Default

The Time-based One-Time Password algorithm (TOTP) is an algorithm that computes a one-time password from a shared secret key and the current time. It has been adopted as Internet Engineering Task Force standard RFC 6238, is the cornerstone of Initiative For Open Authentication (OAUTH), and is used in a number of two-factor authentication systems. A TOTP is an HOTP where the counter is the current time.

Enter the secret as the input or leave it blank for a random secret to be generated. T0 and T1 are in seconds.

[More info](https://wikipedia.org/wiki/Time-based_One-time_Password_algorithm)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Name** (string): default ``
  - **Code length** (number): default `6`
  - **Epoch offset (T0)** (number): default ``
  - **Interval (T1)** (number): default `30`

---

### `GenerateUUID()`

**Operation:** `Generate UUID`

**Category:** `Other`

**Module:** Crypto

Generates an RFC 9562 (formerly RFC 4122) compliant Universally Unique Identifier (UUID), also known as a Globally Unique Identifier (GUID).

We currently support generating the following UUID versions:
v1: Timestamp-basedv3: Namespace w/ MD5v4: Random (default)v5: Namespace w/ SHA-1v6: Timestamp, reorderedv7: Unix Epoch time-basedUUIDs are generated using the `uuid` package.

[More info](https://wikipedia.org/wiki/Universally_unique_identifier)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Version** (option): `v1`, `v3`, `v4` (+3 more); default `v4`
  - **Namespace** (string): default `1b671a64-40d5-491e-99b0-da01ff1f3341`

---

### `GenerateAllChecksums()`

**Operation:** `Generate all checksums`

**Category:** `Hashing`

**Module:** Crypto

Generates all available checksums for the input.

[More info](https://wikipedia.org/wiki/Checksum)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Length (bits)** (option): `All`, `3`, `4` (+20 more)
  - **Include names** (boolean): default `true`

---

### `GenerateAllHashes()`

**Operation:** `Generate all hashes`

**Category:** `Hashing`

**Module:** Crypto

Generates all available hashes and checksums for the input.

[More info](https://wikipedia.org/wiki/Comparison_of_cryptographic_hash_functions)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Length (bits)** (option): `All`, `128`, `160` (+5 more)
  - **Include names** (boolean): default `true`

---

### `GenericCodeBeautify()`

**Operation:** `Generic Code Beautify`

**Category:** `Code tidy`

**Module:** Code

Attempts to pretty print C-style languages such as C, C++, C#, Java, PHP, JavaScript etc.

This will not do a perfect job, and the resulting code may not work any more. This operation is designed purely to make obfuscated or minified code more easy to read and understand.

Things which will not work properly:For loop formattingDo-While loop formattingSwitch/Case indentationCertain bit shift operators

**Input:** `string` → **Output:** `string`

---

### `GetAllCasings()`

**Operation:** `Get All Casings`

**Category:** `Utils`

**Module:** Default

Outputs all possible casing variations of a string.

**Input:** `string` → **Output:** `string`

---

### `GetTime()`

**Operation:** `Get Time`

**Category:** `Date / Time`

**Module:** Default

Generates a timestamp showing the amount of time since the UNIX epoch (1970-01-01 00:00:00 UTC). Uses the W3C High Resolution Time API.

[More info](https://wikipedia.org/wiki/Unix_time)

**Input:** `string` → **Output:** `number`

**Arguments:**
  - **Granularity** (option): `Seconds (s)`, `Milliseconds (ms)`, `Microseconds (μs)` (+1 more)

---

### `GroupIPAddresses()`

**Operation:** `Group IP addresses`

**Category:** `Networking`

**Module:** Default

Groups a list of IP addresses into subnets. Supports both IPv4 and IPv6 addresses.

[More info](https://wikipedia.org/wiki/Subnetwork)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `CRLF`, `Space` (+2 more)
  - **Subnet (CIDR)** (number): default `24`
  - **Only show the subnets** (boolean): default ``

---

### `Gunzip()`

**Operation:** `Gunzip`

**Category:** `Compression`

**Module:** Compression

Decompresses data which has been compressed using the deflate algorithm with gzip headers.

[More info](https://wikipedia.org/wiki/Gzip)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

---

### `Gzip()`

**Operation:** `Gzip`

**Category:** `Compression`

**Module:** Compression

Compresses data using the deflate algorithm with gzip headers.

[More info](https://wikipedia.org/wiki/Gzip)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Compression type** (option): `Dynamic Huffman Coding`, `Fixed Huffman Coding`, `None (Store)`
  - **Filename (optional)** (string): default ``
  - **Comment (optional)** (string): default ``
  - **Include file checksum** (boolean): default ``

---

### `HASSHClientFingerprint()`

**Operation:** `HASSH Client Fingerprint`

**Category:** `Networking`

**Module:** Crypto

Generates a HASSH fingerprint to help identify SSH clients based on hashing together values from the Client Key Exchange Init message.

Input: A hex stream of the SSH_MSG_KEXINIT packet application layer from Client to Server.

[More info](https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input format** (option): `Hex`, `Base64`, `Raw`
  - **Output format** (option): `Hash digest`, `HASSH algorithms string`, `Full details`

---

### `HASSHServerFingerprint()`

**Operation:** `HASSH Server Fingerprint`

**Category:** `Networking`

**Module:** Crypto

Generates a HASSH fingerprint to help identify SSH servers based on hashing together values from the Server Key Exchange Init message.

Input: A hex stream of the SSH_MSG_KEXINIT packet application layer from Server to Client.

[More info](https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input format** (option): `Hex`, `Base64`, `Raw`
  - **Output format** (option): `Hash digest`, `HASSH algorithms string`, `Full details`

---

### `HMAC()`

**Operation:** `HMAC`

**Category:** `Hashing`

**Module:** Crypto

Keyed-Hash Message Authentication Codes (HMAC) are a mechanism for message authentication using cryptographic hash functions.

[More info](https://wikipedia.org/wiki/HMAC)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **Hashing function** (option): `MD2`, `MD4`, `MD5` (+17 more)

---

### `HTMLToText()`

**Operation:** `HTML To Text`

**Category:** `Other`

**Module:** Default

Converts an HTML output from an operation to a readable string instead of being rendered in the DOM.

**Input:** `html` → **Output:** `string`

---

### `HTTPRequest()`

**Operation:** `HTTP request`

**Category:** `Networking`

**Module:** Default

**Support:** Unsupported in the current STPyV8 runtime. Requires browser-style request APIs and live network access.

Makes an HTTP request and returns the response.

This operation supports different HTTP verbs like GET, POST, PUT, etc.

You can add headers line by line in the format `Key: Value`

The status code of the response, along with a limited selection of exposed headers, can be viewed by checking the 'Show response metadata' option. Only a limited set of response headers are exposed by the browser for security reasons.

[More info](https://wikipedia.org/wiki/List_of_HTTP_header_fields#Request_fields)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Method** (option): `GET`, `POST`, `HEAD` (+6 more)
  - **URL** (string): default ``
  - **Headers** (text)
  - **Mode** (option): `Cross-Origin Resource Sharing`, `No CORS (limited to HEAD, GET or POST)`
  - **Show response metadata** (boolean): default ``

---

### `HammingDistance()`

**Operation:** `Hamming Distance`

**Category:** `Utils`

**Module:** Default

In information theory, the Hamming distance between two strings of equal length is the number of positions at which the corresponding symbols are different. In other words, it measures the minimum number of substitutions required to change one string into the other, or the minimum number of errors that could have transformed one string into the other. In a more general context, the Hamming distance is one of several string metrics for measuring the edit distance between two sequences.

[More info](https://wikipedia.org/wiki/Hamming_distance)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (binaryShortString): default `\\n\\n`
  - **Unit** (option): `Byte`, `Bit`
  - **Input type** (option): `Raw string`, `Hex`

---

### `HaversineDistance()`

**Operation:** `Haversine distance`

**Category:** `Other`

**Module:** Default

Returns the distance between two pairs of GPS latitude and longitude co-ordinates in metres.

e.g. `51.487263,-0.124323, 38.9517,-77.1467`

[More info](https://wikipedia.org/wiki/Haversine_formula)

**Input:** `string` → **Output:** `number`

---

### `Head()`

**Operation:** `Head`

**Category:** `Utils`

**Module:** Default

Like the UNIX head utility.
Gets the first n lines.
You can select all but the last n lines by entering a negative value for n.
The delimiter can be changed so that instead of lines, fields (i.e. commas) are selected instead.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `CRLF`, `Space` (+4 more)
  - **Number** (number): default `10`

---

### `HeatmapChart()`

**Operation:** `Heatmap chart`

**Category:** `Multimedia`

**Module:** Charts

A heatmap is a graphical representation of data where the individual values contained in a matrix are represented as colors.

[More info](https://wikipedia.org/wiki/Heat_map)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Record delimiter** (option): `Line feed`, `CRLF`
  - **Field delimiter** (option): `Space`, `Comma`, `Semi-colon` (+2 more)
  - **Number of vertical bins** (number): default `25`
  - **Number of horizontal bins** (number): default `25`
  - **Use column headers as labels** (boolean): default `true`
  - **X label** (string): default ``
  - **Y label** (string): default ``
  - **Draw bin edges** (boolean): default ``
  - **Min colour value** (string): default `white`
  - **Max colour value** (string): default `black`

---

### `HexDensityChart()`

**Operation:** `Hex Density chart`

**Category:** `Multimedia`

**Module:** Charts

Hex density charts are used in a similar way to scatter charts, however rather than rendering tens of thousands of points, it groups the points into a few hundred hexagons to show the distribution.

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Record delimiter** (option): `Line feed`, `CRLF`
  - **Field delimiter** (option): `Space`, `Comma`, `Semi-colon` (+2 more)
  - **Pack radius** (number): default `25`
  - **Draw radius** (number): default `15`
  - **Use column headers as labels** (boolean): default `true`
  - **X label** (string): default ``
  - **Y label** (string): default ``
  - **Draw hexagon edges** (boolean): default ``
  - **Min colour value** (string): default `white`
  - **Max colour value** (string): default `black`
  - **Draw empty hexagons within data boundaries** (boolean): default ``

---

### `HexToObjectIdentifier()`

**Operation:** `Hex to Object Identifier`

**Category:** `Public Key`

**Module:** PublicKey

Converts a hexadecimal string into an object identifier (OID).

[More info](https://wikipedia.org/wiki/Object_identifier)

**Input:** `string` → **Output:** `string`

---

### `HexToPEM()`

**Operation:** `Hex to PEM`

**Category:** `Data format`

**Module:** PublicKey

Converts a hexadecimal DER (Distinguished Encoding Rules) string into PEM (Privacy Enhanced Mail) format.

[More info](https://wikipedia.org/wiki/Privacy-Enhanced_Mail)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Header string** (string): default `CERTIFICATE`

---

### `IPv6TransitionAddresses()`

**Operation:** `IPv6 Transition Addresses`

**Category:** `Networking`

**Module:** Default

Converts IPv4 addresses to their IPv6 Transition addresses. IPv6 Transition addresses can also be converted back into their original IPv4 address. MAC addresses can also be converted into the EUI-64 format, this can them be appended to your IPv6 /64 range to obtain a full /128 address.

Transition technologies enable translation between IPv4 and IPv6 addresses or tunneling to allow traffic to pass through the incompatible network, allowing the two standards to coexist.

Only /24 ranges and currently handled. Remove headers to easily copy out results.

[More info](https://wikipedia.org/wiki/IPv6_transition_mechanism)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Ignore ranges** (boolean): default `true`
  - **Remove headers** (boolean): default ``

---

### `ImageFilter()`

**Operation:** `Image Filter`

**Category:** `Multimedia`

**Module:** Image

Applies a greyscale or sepia filter to an image.

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Filter type** (option): `Greyscale`, `Sepia`

---

### `ImageOpacity()`

**Operation:** `Image Opacity`

**Category:** `Multimedia`

**Module:** Image

Adjust the opacity of an image.

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Opacity (%)** (number): default `100`

---

### `IndexOfCoincidence()`

**Operation:** `Index of Coincidence`

**Category:** `Other`

**Module:** Default

Index of Coincidence (IC) is the probability of two randomly selected characters being the same. This can be used to determine whether text is readable or random, with English text having an IC of around 0.066. IC can therefore be a sound method to automate frequency analysis.

[More info](https://wikipedia.org/wiki/Index_of_coincidence)

**Input:** `string` → **Output:** `html`

---

### `InvertImage()`

**Operation:** `Invert Image`

**Category:** `Multimedia`

**Module:** Image

Invert the colours of an image.

**Input:** `ArrayBuffer` → **Output:** `html`

---

### `JA3Fingerprint()`

**Operation:** `JA3 Fingerprint`

**Category:** `Networking`

**Module:** Crypto

Generates a JA3 fingerprint to help identify TLS clients based on hashing together values from the Client Hello.

Input: A hex stream of the TLS Client Hello packet application layer.

[More info](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input format** (option): `Hex`, `Base64`, `Raw`
  - **Output format** (option): `Hash digest`, `JA3 string`, `Full details`

---

### `JA3SFingerprint()`

**Operation:** `JA3S Fingerprint`

**Category:** `Networking`

**Module:** Crypto

Generates a JA3S fingerprint to help identify TLS servers based on hashing together values from the Server Hello.

Input: A hex stream of the TLS Server Hello record application layer.

[More info](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input format** (option): `Hex`, `Base64`, `Raw`
  - **Output format** (option): `Hash digest`, `JA3S string`, `Full details`

---

### `JA4Fingerprint()`

**Operation:** `JA4 Fingerprint`

**Category:** `Networking`

**Module:** Crypto

Generates a JA4 fingerprint to help identify TLS clients based on hashing together values from the Client Hello.

Input: A hex stream of the TLS or QUIC Client Hello packet application layer.

[More info](https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input format** (option): `Hex`, `Base64`, `Raw`
  - **Output format** (option): `JA4`, `JA4 Original Rendering`, `JA4 Raw` (+2 more)

---

### `JA4ServerFingerprint()`

**Operation:** `JA4Server Fingerprint`

**Category:** `Networking`

**Module:** Crypto

Generates a JA4Server Fingerprint (JA4S) to help identify TLS servers or sessions based on hashing together values from the Server Hello.

Input: A hex stream of the TLS or QUIC Server Hello packet application layer.

[More info](https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input format** (option): `Hex`, `Base64`, `Raw`
  - **Output format** (option): `JA4S`, `JA4S Raw`, `Both`

---

### `JPathExpression()`

**Operation:** `JPath expression`

**Category:** `Extractors`

**Module:** Code

Extract information from a JSON object with a JPath query.

[More info](http://goessner.net/articles/JsonPath/)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Query** (string): default ``
  - **Result delimiter** (binaryShortString): default `\\n`

---

### `JSONBeautify()`

**Operation:** `JSON Beautify`

**Category:** `Code tidy`

**Module:** Code

Indents and pretty prints JavaScript Object Notation (JSON) code.

Tags: json viewer, prettify, syntax highlighting

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Indent string** (binaryShortString): default `    `
  - **Sort Object Keys** (boolean): default ``
  - **Formatted** (boolean): default `true`

---

### `JSONMinify()`

**Operation:** `JSON Minify`

**Category:** `Code tidy`

**Module:** Code

Compresses JavaScript Object Notation (JSON) code.

**Input:** `string` → **Output:** `string`

---

### `JSONToCSV()`

**Operation:** `JSON to CSV`

**Category:** `Data format`

**Module:** Default

Converts JSON data to a CSV based on the definition in RFC 4180.

[More info](https://wikipedia.org/wiki/Comma-separated_values)

**Input:** `JSON` → **Output:** `string`

**Arguments:**
  - **Cell delimiter** (binaryShortString): default `,`
  - **Row delimiter** (binaryShortString): default `\\r\\n`

---

### `JSONToYAML()`

**Operation:** `JSON to YAML`

**Category:** `Data format`

**Module:** Default

Format a JSON object into YAML

[More info](https://en.wikipedia.org/wiki/YAML)

**Input:** `JSON` → **Output:** `string`

---

### `JWKToPEM()`

**Operation:** `JWK to PEM`

**Category:** `Public Key`

**Module:** PublicKey

Converts Keys in JSON Web Key format to PEM format (PKCS#8).

[More info](https://datatracker.ietf.org/doc/html/rfc7517)

**Input:** `string` → **Output:** `string`

---

### `JWTDecode()`

**Operation:** `JWT Decode`

**Category:** `Encryption / Encoding`

**Module:** Crypto

Decodes a JSON Web Token without checking whether the provided secret / private key is valid. Use 'JWT Verify' to check if the signature is valid as well.

[More info](https://wikipedia.org/wiki/JSON_Web_Token)

**Input:** `string` → **Output:** `JSON`

---

### `JWTSign()`

**Operation:** `JWT Sign`

**Category:** `Encryption / Encoding`

**Module:** Crypto

**Support:** Unsupported in the current STPyV8 runtime. The bundled jsonwebtoken dependency expects Node crypto KeyObject APIs that are unavailable in the current crypto-browserify compatibility layer.

Signs a JSON object as a JSON Web Token using a provided secret / private key.

The key should be either the secret for HMAC algorithms or the PEM-encoded private key for RSA and ECDSA.

[More info](https://wikipedia.org/wiki/JSON_Web_Token)

**Input:** `JSON` → **Output:** `string`

**Arguments:**
  - **Private/Secret Key** (text): default `secret`
  - **Signing algorithm** (option): `HS256`, `HS384`, `HS512` (+7 more)
  - **Header** (text): default `{}`

---

### `JWTVerify()`

**Operation:** `JWT Verify`

**Category:** `Encryption / Encoding`

**Module:** Crypto

**Support:** Unsupported in the current STPyV8 runtime. The bundled jsonwebtoken dependency expects Node crypto KeyObject APIs that are unavailable in the current crypto-browserify compatibility layer.

Verifies that a JSON Web Token is valid and has been signed with the provided secret / private key.

The key should be either the secret for HMAC algorithms or the PEM-encoded public key for RSA and ECDSA.

[More info](https://wikipedia.org/wiki/JSON_Web_Token)

**Input:** `string` → **Output:** `JSON`

**Arguments:**
  - **Public/Secret Key** (text): default `secret`

---

### `JavaScriptBeautify()`

**Operation:** `JavaScript Beautify`

**Category:** `Code tidy`

**Module:** Code

**Support:** Unsupported in the current STPyV8 runtime. Excluded by the current Node-targeted bundle.

Parses and pretty prints valid JavaScript code. Also works with JavaScript Object Notation (JSON).

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Indent string** (binaryShortString): default `\\t`
  - **Quotes** (option): `Auto`, `Single`, `Double`
  - **Semicolons before closing braces** (boolean): default `true`
  - **Include comments** (boolean): default `true`

---

### `JavaScriptMinify()`

**Operation:** `JavaScript Minify`

**Category:** `Code tidy`

**Module:** Code

**Support:** Unsupported in the current STPyV8 runtime. Excluded by the current Node-targeted bundle.

Compresses JavaScript code.

**Input:** `string` → **Output:** `string`

---

### `JavaScriptParser()`

**Operation:** `JavaScript Parser`

**Category:** `Code tidy`

**Module:** Code

**Support:** Unsupported in the current STPyV8 runtime. Excluded by the current Node-targeted bundle.

Returns an Abstract Syntax Tree for valid JavaScript code.

[More info](https://wikipedia.org/wiki/Abstract_syntax_tree)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Location info** (boolean): default ``
  - **Range info** (boolean): default ``
  - **Include tokens array** (boolean): default ``
  - **Include comments array** (boolean): default ``
  - **Report errors and try to continue** (boolean): default ``

---

### `Jq()`

**Operation:** `Jq`

**Category:** `Code tidy`

**Module:** Jq

jq is a lightweight and flexible command-line JSON processor.

[More info](https://github.com/jqlang/jq)

**Input:** `JSON` → **Output:** `string`

**Arguments:**
  - **Query** (string): default ``

---

### `JsonataQuery()`

**Operation:** `Jsonata Query`

**Category:** `Extractors`

**Module:** Code

Query and transform JSON data with a jsonata query.

[More info](https://docs.jsonata.org/overview.html)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Query** (text): default `string`

---

### `Jump()`

**Operation:** `Jump`

**Category:** `Flow control`

**Module:** Default

Jump forwards or backwards to the specified Label

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Label name** (string): default ``
  - **Maximum jumps (if jumping backwards)** (number): default `10`

---

### `Keccak()`

**Operation:** `Keccak`

**Category:** `Hashing`

**Module:** Crypto

The Keccak hash algorithm was designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche, building upon RadioGatún. It was selected as the winner of the SHA-3 design competition.

This version of the algorithm is Keccak[c=2d] and differs from the SHA-3 specification.

[More info](https://wikipedia.org/wiki/SHA-3)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Size** (option): `512`, `384`, `256` (+1 more)

---

### `LMHash()`

**Operation:** `LM Hash`

**Category:** `Hashing`

**Module:** Crypto

An LM Hash, or LAN Manager Hash, is a deprecated way of storing passwords on old Microsoft operating systems. It is particularly weak and can be cracked in seconds on modern hardware using rainbow tables.

[More info](https://wikipedia.org/wiki/LAN_Manager#Password_hashing_algorithm)

**Input:** `string` → **Output:** `string`

---

### `LS47Decrypt()`

**Operation:** `LS47 Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Crypto

This is a slight improvement of the ElsieFour cipher as described by Alan Kaminsky. We use 7x7 characters instead of original (barely fitting) 6x6, to be able to encrypt some structured information. We also describe a simple key-expansion algorithm, because remembering passwords is popular. Similar security considerations as with ElsieFour hold.
The LS47 alphabet consists of following characters: `_abcdefghijklmnopqrstuvwxyz.0123456789,-+*/:?!'()`
An LS47 key is a permutation of the alphabet that is then represented in a 7x7 grid used for the encryption or decryption.

[More info](https://github.com/exaexa/ls47)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Password** (string): default ``
  - **Padding** (number): default `10`

---

### `LS47Encrypt()`

**Operation:** `LS47 Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Crypto

This is a slight improvement of the ElsieFour cipher as described by Alan Kaminsky. We use 7x7 characters instead of original (barely fitting) 6x6, to be able to encrypt some structured information. We also describe a simple key-expansion algorithm, because remembering passwords is popular. Similar security considerations as with ElsieFour hold.
The LS47 alphabet consists of following characters: `_abcdefghijklmnopqrstuvwxyz.0123456789,-+*/:?!'()`
A LS47 key is a permutation of the alphabet that is then represented in a 7x7 grid used for the encryption or decryption.

[More info](https://github.com/exaexa/ls47)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Password** (string): default ``
  - **Padding** (number): default `10`
  - **Signature** (string): default ``

---

### `LZ4Compress()`

**Operation:** `LZ4 Compress`

**Category:** `Compression`

**Module:** Compression

LZ4 is a lossless data compression algorithm that is focused on compression and decompression speed. It belongs to the LZ77 family of byte-oriented compression schemes.

[More info](https://wikipedia.org/wiki/LZ4_(compression_algorithm))

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

---

### `LZ4Decompress()`

**Operation:** `LZ4 Decompress`

**Category:** `Compression`

**Module:** Compression

LZ4 is a lossless data compression algorithm that is focused on compression and decompression speed. It belongs to the LZ77 family of byte-oriented compression schemes.

[More info](https://wikipedia.org/wiki/LZ4_(compression_algorithm))

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

---

### `LZMACompress()`

**Operation:** `LZMA Compress`

**Category:** `Compression`

**Module:** Compression

Compresses data using the Lempel–Ziv–Markov chain algorithm. Compression mode determines the speed and effectiveness of the compression: 1 is fastest and less effective, 9 is slowest and most effective

[More info](https://wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Compression Mode** (option): `1`, `2`, `3` (+6 more); default `7`

---

### `LZMADecompress()`

**Operation:** `LZMA Decompress`

**Category:** `Compression`

**Module:** Compression

Decompresses data using the Lempel-Ziv-Markov chain Algorithm.

[More info](https://wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

---

### `LZNT1Decompress()`

**Operation:** `LZNT1 Decompress`

**Category:** `Compression`

**Module:** Compression

Decompresses data using the LZNT1 algorithm.

Similar to the Windows API `RtlDecompressBuffer`.

[More info](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/5655f4a3-6ba4-489b-959f-e1f407c52f15)

**Input:** `byteArray` → **Output:** `byteArray`

---

### `LZStringCompress()`

**Operation:** `LZString Compress`

**Category:** `Compression`

**Module:** Compression

Compress the input with lz-string.

[More info](https://pieroxy.net/blog/pages/lz-string/index.html)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Compression Format** (option): `default`, `UTF16`, `Base64`

---

### `LZStringDecompress()`

**Operation:** `LZString Decompress`

**Category:** `Compression`

**Module:** Compression

Decompresses data that was compressed with lz-string.

[More info](https://pieroxy.net/blog/pages/lz-string/index.html)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Compression Format** (option): `default`, `UTF16`, `Base64`

---

### `Label()`

**Operation:** `Label`

**Category:** `Flow control`

**Module:** Default

Provides a location for conditional and fixed jumps to redirect execution to.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Name** (shortString)

---

### `LevenshteinDistance()`

**Operation:** `Levenshtein Distance`

**Category:** `Utils`

**Module:** Default

Levenshtein Distance (also known as Edit Distance) is a string metric to measure a difference between two strings that counts operations (insertions, deletions, and substitutions) on single character that are required to change one string to another.

[More info](https://wikipedia.org/wiki/Levenshtein_distance)

**Input:** `string` → **Output:** `number`

**Arguments:**
  - **Sample delimiter** (binaryString): default `\\n`
  - **Insertion cost** (number): default `1`
  - **Deletion cost** (number): default `1`
  - **Substitution cost** (number): default `1`

---

### `Lorenz()`

**Operation:** `Lorenz`

**Category:** `Encryption / Encoding`

**Module:** Bletchley

The Lorenz SZ40/42 cipher attachment was a WW2 German rotor cipher machine with twelve rotors which attached in-line between remote teleprinters.

It used the Vernam cipher with two groups of five rotors (named the psi(ψ) wheels and chi(χ) wheels at Bletchley Park) to create two pseudorandom streams of five bits, encoded in ITA2, which were XOR added to the plaintext. Two other rotors, dubbed the mu(μ) or motor wheels, could hold up the stepping of the psi wheels meaning they stepped intermittently.

Each rotor has a different number of cams/lugs around their circumference which could be set active or inactive changing the key stream.

Three models of the Lorenz are emulated, SZ40, SZ42a and SZ42b and three example wheel patterns (the lug settings) are included (KH, ZMUG & BREAM) with the option to set a custom set using the letter 'x' for active or '.' for an inactive lug.

The input can either be plaintext or ITA2 when sending and ITA2 when receiving.

To learn more, Virtual Lorenz, an online, browser based simulation of the Lorenz SZ40/42 is available at lorenz.virtualcolossus.co.uk.

A more detailed description of this operation can be found here.

[More info](https://wikipedia.org/wiki/Lorenz_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Model** (option): `SZ40`, `SZ42a`, `SZ42b`
  - **Wheel Pattern** (argSelector): `KH Pattern`, `ZMUG Pattern`, `BREAM Pattern` (+2 more)
  - **KT-Schalter** (boolean): default ``
  - **Mode** (argSelector): `Send`, `Receive`
  - **Input Type** (option): `Plaintext`, `ITA2`
  - **Output Type** (option): `Plaintext`, `ITA2`
  - **ITA2 Format** (option): `5/8/9`, `+/-/.`
  - **Ψ1 start (1-43)** (number): default `1`
  - **Ψ2 start (1-47)** (number): default `1`
  - **Ψ3 start (1-51)** (number): default `1`
  - **Ψ4 start (1-53)** (number): default `1`
  - **Ψ5 start (1-59)** (number): default `1`
  - **Μ37 start (1-37)** (number): default `1`
  - **Μ61 start (1-61)** (number): default `1`
  - **Χ1 start (1-41)** (number): default `1`
  - **Χ2 start (1-31)** (number): default `1`
  - **Χ3 start (1-29)** (number): default `1`
  - **Χ4 start (1-26)** (number): default `1`
  - **Χ5 start (1-23)** (number): default `1`
  - **Ψ1 lugs (43)** (string): default `.x...xx.x.x..xxx.x.x.xxxx.x.x.x.x.x..x.xx.x`
  - **Ψ2 lugs (47)** (string): default `.xx.x.xxx..x.x.x..x.xx.x.xxx.x....x.xx.x.x.x..x`
  - **Ψ3 lugs (51)** (string): default `.x.x.x..xxx....x.x.xx.x.x.x..xxx.x.x..x.x.xx..x.x.x`
  - **Ψ4 lugs (53)** (string): default `.xx...xxxxx.x.x.xx...x.xx.x.x..x.x.xx.x..x.x.x.x.x.x.`
  - **Ψ5 lugs (59)** (string): default `xx...xx.x..x.xx.x...x.x.x.x.x.x.x.x.xx..xxxx.x.x...xx.x..x.`
  - **Μ37 lugs (37)** (string): default `x.x.x.x.x.x...x.x.x...x.x.x...x.x....`
  - **Μ61 lugs (61)** (string): default `.xxxx.xxxx.xxx.xxxx.xx....xxx.xxxx.xxxx.xxxx.xxxx.xxx.xxxx...`
  - **Χ1 lugs (41)** (string): default `.x...xxx.x.xxxx.x...x.x..xxx....xx.xxxx..`
  - **Χ2 lugs (31)** (string): default `x..xxx...x.xxxx..xx..x..xx.xx..`
  - **Χ3 lugs (29)** (string): default `..xx..x.xxx...xx...xx..xx.xx.`
  - **Χ4 lugs (26)** (string): default `xx..x..xxxx..xx.xxx....x..`
  - **Χ5 lugs (23)** (string): default `xx..xx....xxxx.x..x.x..`

---

### `LuhnChecksum()`

**Operation:** `Luhn Checksum`

**Category:** `Hashing`

**Module:** Default

The Luhn mod N algorithm using the english alphabet. The Luhn mod N algorithm is an extension to the Luhn algorithm (also known as mod 10 algorithm) that allows it to work with sequences of values in any even-numbered base. This can be useful when a check digit is required to validate an identification string composed of letters, a combination of letters and digits or any arbitrary set of N characters where N is divisible by 2.

[More info](https://en.wikipedia.org/wiki/Luhn_mod_N_algorithm)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Radix** (number): default `10`

---

### `MD2()`

**Operation:** `MD2`

**Category:** `Hashing`

**Module:** Crypto

The MD2 (Message-Digest 2) algorithm is a cryptographic hash function developed by Ronald Rivest in 1989. The algorithm is optimized for 8-bit computers.

Although MD2 is no longer considered secure, even as of 2014, it remains in use in public key infrastructures as part of certificates generated with MD2 and RSA. The message digest algorithm consists, by default, of 18 rounds.

[More info](https://wikipedia.org/wiki/MD2_(cryptography))

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Rounds** (number): default `18`

---

### `MD4()`

**Operation:** `MD4`

**Category:** `Hashing`

**Module:** Crypto

The MD4 (Message-Digest 4) algorithm is a cryptographic hash function developed by Ronald Rivest in 1990. The digest length is 128 bits. The algorithm has influenced later designs, such as the MD5, SHA-1 and RIPEMD algorithms.

The security of MD4 has been severely compromised.

[More info](https://wikipedia.org/wiki/MD4)

**Input:** `ArrayBuffer` → **Output:** `string`

---

### `MD5()`

**Operation:** `MD5`

**Category:** `Hashing`

**Module:** Crypto

MD5 (Message-Digest 5) is a widely used hash function. It has been used in a variety of security applications and is also commonly used to check the integrity of files.

However, MD5 is not collision resistant and it isn't suitable for applications like SSL/TLS certificates or digital signatures that rely on this property.

[More info](https://wikipedia.org/wiki/MD5)

**Input:** `ArrayBuffer` → **Output:** `string`

---

### `MD6()`

**Operation:** `MD6`

**Category:** `Hashing`

**Module:** Crypto

The MD6 (Message-Digest 6) algorithm is a cryptographic hash function. It uses a Merkle tree-like structure to allow for immense parallel computation of hashes for very long inputs.

[More info](https://wikipedia.org/wiki/MD6)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Size** (number): default `256`
  - **Levels** (number): default `64`
  - **Key** (string): default ``

---

### `MIMEDecoding()`

**Operation:** `MIME Decoding`

**Category:** `Data format`

**Module:** Default

Enables the decoding of MIME message header extensions for non-ASCII text

[More info](https://tools.ietf.org/html/rfc2047)

**Input:** `byteArray` → **Output:** `string`

---

### `Magic()`

**Operation:** `Magic`

**Category:** `Flow control`

**Module:** Default

**Support:** Unsupported in the current STPyV8 runtime.

The Magic operation attempts to detect various properties of the input data and suggests which operations could help to make more sense of it.

Options
Depth: If an operation appears to match the data, it will be run and the result will be analysed further. This argument controls the maximum number of levels of recursion.

Intensive mode: When this is turned on, various operations like XOR, bit rotates, and character encodings are brute-forced to attempt to detect valid data underneath. To improve performance, only the first 100 bytes of the data is brute-forced.

Extensive language support: At each stage, the relative byte frequencies of the data will be compared to average frequencies for a number of languages. The default set consists of ~40 of the most commonly used languages on the Internet. The extensive list consists of 284 languages and can result in many languages matching the data if their byte frequencies are similar.

Optionally enter a regular expression to match a string you expect to find to filter results (crib).

[More info](https://github.com/gchq/CyberChef/wiki/Automatic-detection-of-encoded-data-using-CyberChef-Magic)

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Depth** (number): default `3`
  - **Intensive mode** (boolean): default ``
  - **Extensive language support** (boolean): default ``
  - **Crib (known plaintext string or regex)** (string): default ``

---

### `Mean()`

**Operation:** `Mean`

**Category:** `Arithmetic / Logic`

**Module:** Default

Computes the mean (average) of a number list. If an item in the string is not a number it is excluded from the list.

e.g. `0x0a 8 .5 .5` becomes `4.75`

[More info](https://wikipedia.org/wiki/Arithmetic_mean)

**Input:** `string` → **Output:** `BigNumber`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `Space`, `Comma` (+3 more)

---

### `Median()`

**Operation:** `Median`

**Category:** `Arithmetic / Logic`

**Module:** Default

Computes the median of a number list. If an item in the string is not a number it is excluded from the list.

e.g. `0x0a 8 1 .5` becomes `4.5`

[More info](https://wikipedia.org/wiki/Median)

**Input:** `string` → **Output:** `BigNumber`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `Space`, `Comma` (+3 more)

---

### `Merge()`

**Operation:** `Merge`

**Category:** `Flow control`

**Module:** Default

Consolidate all branches back into a single trunk. The opposite of Fork. Unticking the Merge All checkbox will only consolidate all branches up to the nearest Fork/Subsection.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Merge All** (boolean): default `true`

---

### `MicrosoftScriptDecoder()`

**Operation:** `Microsoft Script Decoder`

**Category:** `Code tidy`

**Module:** Default

Decodes Microsoft Encoded Script files that have been encoded with Microsoft's custom encoding. These are often VBS (Visual Basic Script) files that are encoded and renamed with a '.vbe' extention or JS (JScript) files renamed with a '.jse' extention.

Sample

Encoded:
`#@~^RQAAAA==-mD~sX|:/TP{~J:+dYbxL~@!F@*@!+@*@!&@*eEI@#@&@#@&.jm.raY 214Wv:zms/obI0xEAAA==^#~@`

Decoded:
`var my_msg = "Testing !";

VScript.Echo(my_msg);`

[More info](https://wikipedia.org/wiki/JScript.Encode)

**Input:** `string` → **Output:** `string`

---

### `MultipleBombe()`

**Operation:** `Multiple Bombe`

**Category:** `Encryption / Encoding`

**Module:** Bletchley

Emulation of the Bombe machine used to attack Enigma. This version carries out multiple Bombe runs to handle unknown rotor configurations.

You should test your menu on the single Bombe operation before running it here. See the description of the Bombe operation for instructions on choosing a crib.

More detailed descriptions of the Enigma, Typex and Bombe operations can be found here.

[More info](https://wikipedia.org/wiki/Bombe)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Standard Enigmas** (populateMultiOption): `German Service Enigma (First - 3 rotor)`, `German Service Enigma (Second - 3 rotor)`, `German Service Enigma (Third - 4 rotor)` (+2 more)
  - **Main rotors** (text)
  - **4th rotor** (text)
  - **Reflectors** (text)
  - **Crib** (string): default ``
  - **Crib offset** (number): default ``
  - **Use checking machine** (boolean): default `true`

---

### `Multiply()`

**Operation:** `Multiply`

**Category:** `Arithmetic / Logic`

**Module:** Default

Multiplies a list of numbers. If an item in the string is not a number it is excluded from the list.

e.g. `0x0a 8 .5` becomes `40`

[More info](https://wikipedia.org/wiki/Multiplication)

**Input:** `string` → **Output:** `BigNumber`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `Space`, `Comma` (+3 more)

---

### `MurmurHash3()`

**Operation:** `MurmurHash3`

**Category:** `Hashing`

**Module:** Hashing

Generates a MurmurHash v3 for a string input and an optional seed input

[More info](https://wikipedia.org/wiki/MurmurHash)

**Input:** `string` → **Output:** `number`

**Arguments:**
  - **Seed** (number): default ``
  - **Convert to Signed** (boolean): default ``

---

### `NOT()`

**Operation:** `NOT`

**Category:** `Arithmetic / Logic`

**Module:** Default

Returns the inverse of each byte.

[More info](https://wikipedia.org/wiki/Bitwise_operation#NOT)

**Input:** `ArrayBuffer` → **Output:** `byteArray`

---

### `NTHash()`

**Operation:** `NT Hash`

**Category:** `Hashing`

**Module:** Crypto

An NT Hash, sometimes referred to as an NTLM hash, is a method of storing passwords on Windows systems. It works by running MD4 on UTF-16LE encoded input. NTLM hashes are considered weak because they can be brute-forced very easily with modern hardware.

[More info](https://wikipedia.org/wiki/NT_LAN_Manager)

**Input:** `string` → **Output:** `string`

---

### `NormaliseImage()`

**Operation:** `Normalise Image`

**Category:** `Multimedia`

**Module:** Image

Normalise the image colours.

**Input:** `ArrayBuffer` → **Output:** `html`

---

### `NormaliseUnicode()`

**Operation:** `Normalise Unicode`

**Category:** `Data format`

**Module:** Encodings

Transform Unicode characters to one of the Normalisation Forms

[More info](https://wikipedia.org/wiki/Unicode_equivalence#Normal_forms)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Normal Form** (option): `NFD`, `NFC`, `NFKD` (+1 more)

---

### `Numberwang()`

**Operation:** `Numberwang`

**Category:** `Other`

**Module:** Default

Based on the popular gameshow by Mitchell and Webb.

[More info](https://wikipedia.org/wiki/That_Mitchell_and_Webb_Look#Recurring_sketches)

**Input:** `string` → **Output:** `string`

---

### `OR()`

**Operation:** `OR`

**Category:** `Arithmetic / Logic`

**Module:** Default

OR the input with the given key.
e.g. `fe023da5`

[More info](https://wikipedia.org/wiki/Bitwise_operation#OR)

**Input:** `ArrayBuffer` → **Output:** `byteArray`

**Arguments:**
  - **Key** (toggleString): default ``

---

### `ObjectIdentifierToHex()`

**Operation:** `Object Identifier to Hex`

**Category:** `Public Key`

**Module:** PublicKey

Converts an object identifier (OID) into a hexadecimal string.

[More info](https://wikipedia.org/wiki/Object_identifier)

**Input:** `string` → **Output:** `string`

---

### `OffsetChecker()`

**Operation:** `Offset checker`

**Category:** `Utils`

**Module:** Default

Compares multiple inputs (separated by the specified delimiter) and highlights matching characters which appear at the same position in all samples.

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Sample delimiter** (binaryString): default `\\n\\n`

---

### `OpticalCharacterRecognition()`

**Operation:** `Optical Character Recognition`

**Category:** `Multimedia`

**Module:** OCR

**Support:** Unsupported in the current STPyV8 runtime. Requires browser workers and OCR assets that this project does not provide.

Optical character recognition or optical character reader (OCR) is the mechanical or electronic conversion of images of typed, handwritten or printed text into machine-encoded text.

Supported image formats: png, jpg, bmp, pbm.

[More info](https://wikipedia.org/wiki/Optical_character_recognition)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Show confidence** (boolean): default `true`
  - **OCR Engine Mode** (option): `Tesseract only`, `LSTM only`, `Tesseract/LSTM Combined`; default `LSTM only`

---

### `PEMToHex()`

**Operation:** `PEM to Hex`

**Category:** `Data format`

**Module:** Default

Converts PEM (Privacy Enhanced Mail) format to a hexadecimal DER (Distinguished Encoding Rules) string.

[More info](https://wikipedia.org/wiki/Privacy-Enhanced_Mail#Format)

**Input:** `string` → **Output:** `string`

---

### `PEMToJWK()`

**Operation:** `PEM to JWK`

**Category:** `Public Key`

**Module:** PublicKey

Converts Keys in PEM format to a JSON Web Key format.

[More info](https://datatracker.ietf.org/doc/html/rfc7517)

**Input:** `string` → **Output:** `string`

---

### `PGPDecrypt()`

**Operation:** `PGP Decrypt`

**Category:** `Public Key`

**Module:** PGP

Input: the ASCII-armoured PGP message you want to decrypt.

Arguments: the ASCII-armoured PGP private key of the recipient, 
(and the private key password if necessary).

Pretty Good Privacy is an encryption standard (OpenPGP) used for encrypting, decrypting, and signing messages.

This function uses the Keybase implementation of PGP.

[More info](https://wikipedia.org/wiki/Pretty_Good_Privacy)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Private key of recipient** (text)
  - **Private key passphrase** (string): default ``

---

### `PGPDecryptAndVerify()`

**Operation:** `PGP Decrypt and Verify`

**Category:** `Public Key`

**Module:** PGP

Input: the ASCII-armoured encrypted PGP message you want to verify.

Arguments: the ASCII-armoured PGP public key of the signer, 
the ASCII-armoured private key of the recipient (and the private key password if necessary).

This operation uses PGP to decrypt and verify an encrypted digital signature.

Pretty Good Privacy is an encryption standard (OpenPGP) used for encrypting, decrypting, and signing messages.

This function uses the Keybase implementation of PGP.

[More info](https://wikipedia.org/wiki/Pretty_Good_Privacy)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Public key of signer** (text)
  - **Private key of recipient** (text)
  - **Private key password** (string): default ``

---

### `PGPEncrypt()`

**Operation:** `PGP Encrypt`

**Category:** `Public Key`

**Module:** PGP

Input: the message you want to encrypt.

Arguments: the ASCII-armoured PGP public key of the recipient.

Pretty Good Privacy is an encryption standard (OpenPGP) used for encrypting, decrypting, and signing messages.

This function uses the Keybase implementation of PGP.

[More info](https://wikipedia.org/wiki/Pretty_Good_Privacy)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Public key of recipient** (text)

---

### `PGPEncryptAndSign()`

**Operation:** `PGP Encrypt and Sign`

**Category:** `Public Key`

**Module:** PGP

Input: the cleartext you want to sign.

Arguments: the ASCII-armoured private key of the signer (plus the private key password if necessary)
and the ASCII-armoured PGP public key of the recipient.

This operation uses PGP to produce an encrypted digital signature.

Pretty Good Privacy is an encryption standard (OpenPGP) used for encrypting, decrypting, and signing messages.

This function uses the Keybase implementation of PGP.

[More info](https://wikipedia.org/wiki/Pretty_Good_Privacy)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Private key of signer** (text)
  - **Private key passphrase** (string): default ``
  - **Public key of recipient** (text)

---

### `PGPVerify()`

**Operation:** `PGP Verify`

**Category:** `Public Key`

**Module:** PGP

Input: the ASCII-armoured encrypted PGP message you want to verify.

Argument: the ASCII-armoured PGP public key of the signer

This operation uses PGP to decrypt a clearsigned message.

Pretty Good Privacy is an encryption standard (OpenPGP) used for encrypting, decrypting, and signing messages.

This function uses the Keybase implementation of PGP.

[More info](https://wikipedia.org/wiki/Pretty_Good_Privacy)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Public key of signer** (text)

---

### `PHPDeserialize()`

**Operation:** `PHP Deserialize`

**Category:** `Code tidy`

**Module:** Default

Deserializes PHP serialized data, outputting keyed arrays as JSON.

This function does not support `object` tags.

Example:
`a:2:{s:1:"a";i:10;i:0;a:1:{s:2:"ab";b:1;}}`
becomes
`{"a": 10,0: {"ab": true}}`

Output valid JSON: JSON doesn't support integers as keys, whereas PHP serialization does. Enabling this will cast these integers to strings. This will also escape backslashes.

[More info](http://www.phpinternalsbook.com/classes_objects/serialization.html)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Output valid JSON** (boolean): default `true`

---

### `PHPSerialize()`

**Operation:** `PHP Serialize`

**Category:** `Code tidy`

**Module:** Default

Performs PHP serialization on JSON data.

This function does not support `object` tags.

Since PHP doesn't distinguish dicts and arrays, this operation is not always symmetric to `PHP Deserialize`.

Example:
`[5,"abc",true]`
becomes
a:3:{i:0;i:5;i:1;s:3:"abc";i:2;b:1;}

[More info](https://www.phpinternalsbook.com/php5/classes_objects/serialization.html)

**Input:** `JSON` → **Output:** `string`

---

### `PadLines()`

**Operation:** `Pad lines`

**Category:** `Utils`

**Module:** Default

Add the specified number of the specified character to the beginning or end of each line

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Position** (option): `Start`, `End`
  - **Length** (number): default `5`
  - **Character** (binaryShortString): default ` `

---

### `ParseCSR()`

**Operation:** `Parse CSR`

**Category:** `Public Key`

**Module:** PublicKey

Parse Certificate Signing Request (CSR) for an X.509 certificate

[More info](https://wikipedia.org/wiki/Certificate_signing_request)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input format** (option): `PEM`

---

### `ParseDateTime()`

**Operation:** `Parse DateTime`

**Category:** `Date / Time`

**Module:** Default

Parses a DateTime string in your specified format and displays it in whichever timezone you choose with the following information:DateTimePeriod (AM/PM)TimezoneUTC offsetDaylight Saving TimeLeap yearDays in this monthDay of yearWeek numberQuarterRun with no input to see format string examples if required.

[More info](https://momentjs.com/docs/#/parsing/string-format/)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Built in formats** (populateOption): default `[{'name': 'Standard date and time', 'value': 'DD/MM/YYYY HH:mm:ss'}, {'name': 'American-style date and time', 'value': 'MM/DD/YYYY HH:mm:ss'}, {'name': 'International date and time', 'value': 'YYYY-MM-DD HH:mm:ss'}, {'name': 'Verbose date and time', 'value': 'dddd Do MMMM YYYY HH:mm:ss Z z'}, {'name': 'UNIX timestamp (seconds)', 'value': 'X'}, {'name': 'UNIX timestamp offset (milliseconds)', 'value': 'x'}, {'name': 'Automatic', 'value': ''}]`
  - **Input format string** (binaryString): default `DD/MM/YYYY HH:mm:ss`
  - **Input timezone** (option): `UTC`, `Africa/Abidjan`, `Africa/Accra` (+594 more)

---

### `ParseIPRange()`

**Operation:** `Parse IP range`

**Category:** `Networking`

**Module:** Default

Given a CIDR range (e.g. `10.0.0.0/24`), hyphenated range (e.g. `10.0.0.0 - 10.0.1.0`), or a list of IPs and/or CIDR ranges (separated by a new line), this operation provides network information and enumerates all IP addresses in the range.

IPv6 is supported but will not be enumerated.

[More info](https://wikipedia.org/wiki/Subnetwork)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Include network info** (boolean): default `true`
  - **Enumerate IP addresses** (boolean): default `true`
  - **Allow large queries** (boolean): default ``

---

### `ParseIPv4Header()`

**Operation:** `Parse IPv4 header`

**Category:** `Networking`

**Module:** Default

Given an IPv4 header, this operations parses and displays each field in an easily readable format.

[More info](https://wikipedia.org/wiki/IPv4#Header)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Input format** (option): `Hex`, `Raw`

---

### `ParseIPv6Address()`

**Operation:** `Parse IPv6 address`

**Category:** `Networking`

**Module:** Default

Displays the longhand and shorthand versions of a valid IPv6 address.

Recognises all reserved ranges and parses encapsulated or tunnelled addresses including Teredo and 6to4.

[More info](https://wikipedia.org/wiki/IPv6_address)

**Input:** `string` → **Output:** `string`

---

### `ParseObjectIDTimestamp()`

**Operation:** `Parse ObjectID timestamp`

**Category:** `Utils`

**Module:** Serialise

Parse timestamp from MongoDB/BSON ObjectID hex string.

[More info](https://docs.mongodb.com/manual/reference/method/ObjectId.getTimestamp/)

**Input:** `string` → **Output:** `string`

---

### `ParseQRCode()`

**Operation:** `Parse QR Code`

**Category:** `Other`

**Module:** Image

Reads an image file and attempts to detect and read a Quick Response (QR) code from the image.

Normalise Image
Attempts to normalise the image before parsing it to improve detection of a QR code.

[More info](https://wikipedia.org/wiki/QR_code)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Normalise image** (boolean): default ``

---

### `ParseSSHHostKey()`

**Operation:** `Parse SSH Host Key`

**Category:** `Public Key`

**Module:** Default

Parses a SSH host key and extracts fields from it.
The key type can be:ssh-rsassh-dssecdsa-sha2ssh-ed25519The key format can be either Hex or Base64.

[More info](https://wikipedia.org/wiki/Secure_Shell)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input Format** (option): `Auto`, `Base64`, `Hex`

---

### `ParseTCP()`

**Operation:** `Parse TCP`

**Category:** `Networking`

**Module:** Default

Parses a TCP header and payload (if present).

[More info](https://wikipedia.org/wiki/Transmission_Control_Protocol)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Input format** (option): `Hex`, `Raw`

---

### `ParseTLSRecord()`

**Operation:** `Parse TLS record`

**Category:** `Networking`

**Module:** Default

Parses one or more TLS records

[More info](https://wikipedia.org/wiki/Transport_Layer_Security)

**Input:** `ArrayBuffer` → **Output:** `html`

---

### `ParseTLV()`

**Operation:** `Parse TLV`

**Category:** `Data format`

**Module:** Default

Converts a Type-Length-Value (TLV) encoded string into a JSON object.  Can optionally include a `Key` / `Type` entry. 

Tags: Key-Length-Value, KLV, Length-Value, LV

[More info](https://wikipedia.org/wiki/Type-length-value)

**Input:** `ArrayBuffer` → **Output:** `JSON`

**Arguments:**
  - **Type/Key size** (number): default `1`
  - **Length size** (number): default `1`
  - **Use BER** (boolean): default ``

---

### `ParseUDP()`

**Operation:** `Parse UDP`

**Category:** `Networking`

**Module:** Default

Parses a UDP header and payload (if present).

[More info](https://wikipedia.org/wiki/User_Datagram_Protocol)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Input format** (option): `Hex`, `Raw`

---

### `ParseUNIXFilePermissions()`

**Operation:** `Parse UNIX file permissions`

**Category:** `Utils`

**Module:** Default

Given a UNIX/Linux file permission string in octal or textual format, this operation explains which permissions are granted to which user groups.

Input should be in either octal (e.g. `755`) or textual (e.g. `drwxr-xr-x`) format.

[More info](https://wikipedia.org/wiki/File_system_permissions#Traditional_Unix_permissions)

**Input:** `string` → **Output:** `string`

---

### `ParseURI()`

**Operation:** `Parse URI`

**Category:** `Networking`

**Module:** URL

Pretty prints complicated Uniform Resource Identifier (URI) strings for ease of reading. Particularly useful for Uniform Resource Locators (URLs) with a lot of arguments.

[More info](https://wikipedia.org/wiki/Uniform_Resource_Identifier)

**Input:** `string` → **Output:** `string`

---

### `ParseUserAgent()`

**Operation:** `Parse User Agent`

**Category:** `Networking`

**Module:** UserAgent

Attempts to identify and categorise information contained in a user-agent string.

[More info](https://wikipedia.org/wiki/User_agent)

**Input:** `string` → **Output:** `string`

---

### `ParseColourCode()`

**Operation:** `Parse colour code`

**Category:** `Utils`

**Module:** Default

Converts a colour code in a standard format to other standard formats and displays the colour itself.

Example inputs`#d9edf7``rgba(217,237,247,1)``hsla(200,65%,91%,1)``cmyk(0.12, 0.04, 0.00, 0.03)`

[More info](https://wikipedia.org/wiki/Web_colors)

**Input:** `string` → **Output:** `html`

---

### `PlayMedia()`

**Operation:** `Play Media`

**Category:** `Multimedia`

**Module:** Default

Plays the input as audio or video depending on the type.

Tags: sound, movie, mp3, mp4, mov, webm, wav, ogg

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Input format** (option): `Raw`, `Base64`, `Hex`

---

### `PowerSet()`

**Operation:** `Power Set`

**Category:** `Arithmetic / Logic`

**Module:** Default

Calculates all the subsets of a set.

[More info](https://wikipedia.org/wiki/Power_set)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Item delimiter** (binaryString): default `,`

---

### `ProtobufDecode()`

**Operation:** `Protobuf Decode`

**Category:** `Networking`

**Module:** Protobuf

Decodes any Protobuf encoded data to a JSON representation of the data using the field number as the field key.

If a .proto schema is defined, the encoded data will be decoded with reference to the schema. Only one message instance will be decoded. 

Show Unknown Fields
When a schema is used, this option shows fields that are present in the input data but not defined in the schema.

Show Types
Show the type of a field next to its name. For undefined fields, the wiretype and example types are shown instead.

[More info](https://wikipedia.org/wiki/Protocol_Buffers)

**Input:** `ArrayBuffer` → **Output:** `JSON`

**Arguments:**
  - **Schema (.proto text)** (text)
  - **Show Unknown Fields** (boolean): default ``
  - **Show Types** (boolean): default ``

---

### `ProtobufEncode()`

**Operation:** `Protobuf Encode`

**Category:** `Networking`

**Module:** Protobuf

Encodes a valid JSON object into a protobuf byte array using the input .proto schema.

[More info](https://developers.google.com/protocol-buffers/docs/encoding)

**Input:** `JSON` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Schema (.proto text)** (text)

---

### `RAKE()`

**Operation:** `RAKE`

**Category:** `Extractors`

**Module:** Default

Rapid Keyword Extraction (RAKE)

RAKE is a domain-independent keyword extraction algorithm in Natural Language Processing.

The list of stop words are from the NLTK python package

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Word Delimiter (Regex)** (text): default `\\s`
  - **Sentence Delimiter (Regex)** (text): default `\\.\\s|\\n`
  - **Stop Words** (text): default `i,me,my,myself,we,our,ours,ourselves,you,you're,you've,you'll,you'd,your,yours,yourself,yourselves,he,him,his,himself,she,she's,her,hers,herself,it,it's,its,itsef,they,them,their,theirs,themselves,what,which,who,whom,this,that,that'll,these,those,am,is,are,was,were,be,been,being,have,has,had,having,do,does',did,doing,a,an,the,and,but,if,or,because,as,until,while,of,at,by,for,with,about,against,between,into,through,during,before,after,above,below,to,from,up,down,in,out,on,off,over,under,again,further,then,once,here,there,when,where,why,how,all,any,both,each,few,more,most,other,some,such,no,nor,not,only,own,same,so,than,too,very,s,t,can,will,just,don,don't,should,should've,now,d,ll,m,o,re,ve,y,ain,aren,aren't,couldn,couldn't,didn,didn't,doesn,doesn't,hadn,hadn't,hasn,hasn't,haven,haven't,isn,isn't,ma,mightn,mightn't,mustn,mustn't,needn,needn't,shan,shan't,shouldn,shouldn't,wasn,wasn't,weren,weren't,won,won't,wouldn,wouldn't`

---

### `RC2Decrypt()`

**Operation:** `RC2 Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

RC2 (also known as ARC2) is a symmetric-key block cipher designed by Ron Rivest in 1987. 'RC' stands for 'Rivest Cipher'.

Key: RC2 uses a variable size key.

IV: To run the cipher in CBC mode, the Initialization Vector should be 8 bytes long. If the IV is left blank, the cipher will run in ECB mode.

Padding: In both CBC and ECB mode, PKCS#7 padding will be used.

[More info](https://wikipedia.org/wiki/RC2)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Input** (option): `Hex`, `Raw`
  - **Output** (option): `Raw`, `Hex`

---

### `RC2Encrypt()`

**Operation:** `RC2 Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

RC2 (also known as ARC2) is a symmetric-key block cipher designed by Ron Rivest in 1987. 'RC' stands for 'Rivest Cipher'.

Key: RC2 uses a variable size key.

You can generate a password-based key using one of the KDF operations.

IV: To run the cipher in CBC mode, the Initialization Vector should be 8 bytes long. If the IV is left blank, the cipher will run in ECB mode.

Padding: In both CBC and ECB mode, PKCS#7 padding will be used.

[More info](https://wikipedia.org/wiki/RC2)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Input** (option): `Raw`, `Hex`
  - **Output** (option): `Hex`, `Raw`

---

### `RC4()`

**Operation:** `RC4`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

RC4 (also known as ARC4) is a widely-used stream cipher designed by Ron Rivest. It is used in popular protocols such as SSL and WEP. Although remarkable for its simplicity and speed, the algorithm's history doesn't inspire confidence in its security.

[More info](https://wikipedia.org/wiki/RC4)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Passphrase** (toggleString): default ``
  - **Input format** (option): `Latin1`, `UTF8`, `UTF16` (+4 more)
  - **Output format** (option): `Latin1`, `UTF8`, `UTF16` (+4 more)

---

### `RC4Drop()`

**Operation:** `RC4 Drop`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

It was discovered that the first few bytes of the RC4 keystream are strongly non-random and leak information about the key. We can defend against this attack by discarding the initial portion of the keystream. This modified algorithm is traditionally called RC4-drop.

[More info](https://wikipedia.org/wiki/RC4#Fluhrer,_Mantin_and_Shamir_attack)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Passphrase** (toggleString): default ``
  - **Input format** (option): `Latin1`, `UTF8`, `UTF16` (+4 more)
  - **Output format** (option): `Latin1`, `UTF8`, `UTF16` (+4 more)
  - **Number of dwords to drop** (number): default `192`

---

### `RIPEMD()`

**Operation:** `RIPEMD`

**Category:** `Hashing`

**Module:** Crypto

RIPEMD (RACE Integrity Primitives Evaluation Message Digest) is a family of cryptographic hash functions developed in Leuven, Belgium, by Hans Dobbertin, Antoon Bosselaers and Bart Preneel at the COSIC research group at the Katholieke Universiteit Leuven, and first published in 1996.

RIPEMD was based upon the design principles used in MD4, and is similar in performance to the more popular SHA-1.

[More info](https://wikipedia.org/wiki/RIPEMD)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Size** (option): `320`, `256`, `160` (+1 more)

---

### `ROT13()`

**Operation:** `ROT13`

**Category:** `Encryption / Encoding`

**Module:** Default

A simple caesar substitution cipher which rotates alphabet characters by the specified amount (default 13).

[More info](https://wikipedia.org/wiki/ROT13)

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Rotate lower case chars** (boolean): default `true`
  - **Rotate upper case chars** (boolean): default `true`
  - **Rotate numbers** (boolean): default ``
  - **Amount** (number): default `13`

---

### `ROT13BruteForce()`

**Operation:** `ROT13 Brute Force`

**Category:** `Encryption / Encoding`

**Module:** Default

Try all meaningful amounts for ROT13.

Optionally you can enter your known plaintext (crib) to filter the result.

[More info](https://wikipedia.org/wiki/ROT13)

**Input:** `byteArray` → **Output:** `string`

**Arguments:**
  - **Rotate lower case chars** (boolean): default `true`
  - **Rotate upper case chars** (boolean): default `true`
  - **Rotate numbers** (boolean): default ``
  - **Sample length** (number): default `100`
  - **Sample offset** (number): default ``
  - **Print amount** (boolean): default `true`
  - **Crib (known plaintext string)** (string): default ``

---

### `ROT47()`

**Operation:** `ROT47`

**Category:** `Encryption / Encoding`

**Module:** Default

A slightly more complex variation of a caesar cipher, which includes ASCII characters from 33 '!' to 126 '~'. Default rotation: 47.

[More info](https://wikipedia.org/wiki/ROT13#Variants)

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Amount** (number): default `47`

---

### `ROT47BruteForce()`

**Operation:** `ROT47 Brute Force`

**Category:** `Encryption / Encoding`

**Module:** Default

Try all meaningful amounts for ROT47.

Optionally you can enter your known plaintext (crib) to filter the result.

[More info](https://wikipedia.org/wiki/ROT13#Variants)

**Input:** `byteArray` → **Output:** `string`

**Arguments:**
  - **Sample length** (number): default `100`
  - **Sample offset** (number): default ``
  - **Print amount** (boolean): default `true`
  - **Crib (known plaintext string)** (string): default ``

---

### `ROT8000()`

**Operation:** `ROT8000`

**Category:** `Encryption / Encoding`

**Module:** Default

The simple Caesar-cypher encryption that replaces each Unicode character with the one 0x8000 places forward or back along the alphabet.

[More info](https://rot8000.com/info)

**Input:** `string` → **Output:** `string`

---

### `RSADecrypt()`

**Operation:** `RSA Decrypt`

**Category:** `Public Key`

**Module:** Ciphers

Decrypt an RSA encrypted message with a PEM encoded private key.

[More info](https://wikipedia.org/wiki/RSA_(cryptosystem))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **RSA Private Key (PEM)** (text): default `-----BEGIN RSA PRIVATE KEY-----`
  - **Key Password** (text)
  - **Encryption Scheme** (argSelector): `RSA-OAEP`, `RSAES-PKCS1-V1_5`, `RAW`
  - **Message Digest Algorithm** (option): `SHA-1`, `MD5`, `SHA-256` (+2 more)

---

### `RSAEncrypt()`

**Operation:** `RSA Encrypt`

**Category:** `Public Key`

**Module:** Ciphers

Encrypt a message with a PEM encoded RSA public key.

[More info](https://wikipedia.org/wiki/RSA_(cryptosystem))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **RSA Public Key (PEM)** (text): default `-----BEGIN RSA PUBLIC KEY-----`
  - **Encryption Scheme** (argSelector): `RSA-OAEP`, `RSAES-PKCS1-V1_5`, `RAW`
  - **Message Digest Algorithm** (option): `SHA-1`, `MD5`, `SHA-256` (+2 more)

---

### `RSASign()`

**Operation:** `RSA Sign`

**Category:** `Public Key`

**Module:** Ciphers

Sign a plaintext message with a PEM encoded RSA key.

[More info](https://wikipedia.org/wiki/RSA_(cryptosystem))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **RSA Private Key (PEM)** (text): default `-----BEGIN RSA PRIVATE KEY-----`
  - **Key Password** (text)
  - **Message Digest Algorithm** (option): `SHA-1`, `MD5`, `SHA-256` (+2 more)

---

### `RSAVerify()`

**Operation:** `RSA Verify`

**Category:** `Public Key`

**Module:** Ciphers

Verify a message against a signature and a public PEM encoded RSA key.

[More info](https://wikipedia.org/wiki/RSA_(cryptosystem))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **RSA Public Key (PEM)** (text): default `-----BEGIN RSA PUBLIC KEY-----`
  - **Message** (text)
  - **Message format** (option): `Raw`, `Hex`, `Base64`
  - **Message Digest Algorithm** (option): `SHA-1`, `MD5`, `SHA-256` (+2 more)

---

### `Rabbit()`

**Operation:** `Rabbit`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Rabbit is a high-speed stream cipher introduced in 2003 and defined in RFC 4503.

The cipher uses a 128-bit key and an optional 64-bit initialization vector (IV).

big-endian: based on RFC4503 and RFC3447
little-endian: compatible with Crypto++

[More info](https://wikipedia.org/wiki/Rabbit_(cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Endianness** (option): `Big`, `Little`
  - **Input** (option): `Raw`, `Hex`
  - **Output** (option): `Raw`, `Hex`

---

### `RailFenceCipherDecode()`

**Operation:** `Rail Fence Cipher Decode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Decodes Strings that were created using the Rail fence Cipher provided a key and an offset

[More info](https://wikipedia.org/wiki/Rail_fence_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (number): default `2`
  - **Offset** (number): default ``

---

### `RailFenceCipherEncode()`

**Operation:** `Rail Fence Cipher Encode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Encodes Strings using the Rail fence Cipher provided a key and an offset

[More info](https://wikipedia.org/wiki/Rail_fence_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (number): default `2`
  - **Offset** (number): default ``

---

### `RandomizeColourPalette()`

**Operation:** `Randomize Colour Palette`

**Category:** `Forensics`

**Module:** Image

Randomizes each colour in an image's colour palette. This can often reveal text or symbols that were previously a very similar colour to their surroundings, a technique sometimes used in Steganography.

[More info](https://wikipedia.org/wiki/Indexed_color)

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Seed** (string): default ``

---

### `RawDeflate()`

**Operation:** `Raw Deflate`

**Category:** `Compression`

**Module:** Compression

Compresses data using the deflate algorithm with no headers.

[More info](https://wikipedia.org/wiki/DEFLATE)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Compression type** (option): `Dynamic Huffman Coding`, `Fixed Huffman Coding`, `None (Store)`

---

### `RawInflate()`

**Operation:** `Raw Inflate`

**Category:** `Compression`

**Module:** Compression

Decompresses data which has been compressed using the deflate algorithm with no headers.

[More info](https://wikipedia.org/wiki/DEFLATE)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Start index** (number): default ``
  - **Initial output buffer size** (number): default ``
  - **Buffer expansion type** (option): `Adaptive`, `Block`
  - **Resize buffer after decompression** (boolean): default ``
  - **Verify result** (boolean): default ``

---

### `RegularExpression()`

**Operation:** `Regular expression`

**Category:** `Utils`

**Module:** Regex

Define your own regular expression (regex) to search the input data with, optionally choosing from a list of pre-defined patterns.

Supports extended regex syntax including the 'dot matches all' flag, named capture groups, full unicode coverage (including `\p{}` categories and scripts as well as astral codes) and recursive matching.

[More info](https://wikipedia.org/wiki/Regular_expression)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Built in regexes** (populateOption): default `[{'name': 'User defined', 'value': ''}, {'name': 'IPv4 address', 'value': '(?:(?:\\d|[01]?\\d\\d|2[0-4]\\d|25[0-5])\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d|\\d)(?:\\/\\d{1,2})?'}, {'name': 'IPv6 address', 'value': '((?=.*::)(?!.*::.+::)(::)?([\\dA-Fa-f]{1,4}:(:|\\b)|){5}|([\\dA-Fa-f]{1,4}:){6})((([\\dA-Fa-f]{1,4}((?!\\3)::|:\\b|(?![\\dA-Fa-f])))|(?!\\2\\3)){2}|(((2[0-4]|1\\d|[1-9])?\\d|25[0-5])\\.?\\b){4})'}, {'name': 'Email address', 'value': '(?:[\\u00A0-\\uD7FF\\uE000-\\uFFFFa-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\\.[\\u00A0-\\uD7FF\\uE000-\\uFFFFa-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*")@(?:(?:[\\u00A0-\\uD7FF\\uE000-\\uFFFFa-z0-9](?:[\\u00A0-\\uD7FF\\uE000-\\uFFFF-a-z0-9-]*[\\u00A0-\\uD7FF\\uE000-\\uFFFFa-z0-9])?\\.)+[\\u00A0-\\uD7FF\\uE000-\\uFFFFa-z0-9](?:[\\u00A0-\\uD7FF\\uE000-\\uFFFFa-z0-9-]*[\\u00A0-\\uD7FF\\uE000-\\uFFFFa-z0-9])?|\\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\\.){3}\\])'}, {'name': 'URL', 'value': '([A-Za-z]+://)([-\\w]+(?:\\.\\w[-\\w]*)+)(:\\d+)?(/[^.!,?"<>\\[\\]{}\\s\\x7F-\\xFF]*(?:[.!,?]+[^.!,?"<>\\[\\]{}\\s\\x7F-\\xFF]+)*)?'}, {'name': 'Domain', 'value': '\\b((?=[a-z0-9-]{1,63}\\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,63}\\b'}, {'name': 'Windows file path', 'value': '([A-Za-z]):\\\\((?:[A-Za-z\\d][A-Za-z\\d\\- \\x27_\\(\\)~]{0,61}\\\\?)*[A-Za-z\\d][A-Za-z\\d\\- \\x27_\\(\\)]{0,61})(\\.[A-Za-z\\d]{1,6})?'}, {'name': 'UNIX file path', 'value': '(?:/[A-Za-z\\d.][A-Za-z\\d\\-.]{0,61})+'}, {'name': 'MAC address', 'value': '[A-Fa-f\\d]{2}(?:[:-][A-Fa-f\\d]{2}){5}'}, {'name': 'UUID', 'value': '[0-9a-fA-F]{8}\\b-[0-9a-fA-F]{4}\\b-[0-9a-fA-F]{4}\\b-[0-9a-fA-F]{4}\\b-[0-9a-fA-F]{12}'}, {'name': 'Date (yyyy-mm-dd)', 'value': '((?:19|20)\\d\\d)[- /.](0[1-9]|1[012])[- /.](0[1-9]|[12][0-9]|3[01])'}, {'name': 'Date (dd/mm/yyyy)', 'value': '(0[1-9]|[12][0-9]|3[01])[- /.](0[1-9]|1[012])[- /.]((?:19|20)\\d\\d)'}, {'name': 'Date (mm/dd/yyyy)', 'value': '(0[1-9]|1[012])[- /.](0[1-9]|[12][0-9]|3[01])[- /.]((?:19|20)\\d\\d)'}, {'name': 'Strings', 'value': '[A-Za-z\\d/\\-:.,_$%\\x27"()<>= !\\[\\]{}@]{4,}'}]`
  - **Regex** (text)
  - **Case insensitive** (boolean): default `true`
  - **^ and $ match at newlines** (boolean): default `true`
  - **Dot matches all** (boolean): default ``
  - **Unicode support** (boolean): default ``
  - **Astral support** (boolean): default ``
  - **Display total** (boolean): default ``
  - **Output format** (option): `Highlight matches`, `List matches`, `List capture groups` (+1 more)

---

### `RemoveDiacritics()`

**Operation:** `Remove Diacritics`

**Category:** `Language`

**Module:** Default

Replaces accented characters with their latin character equivalent. Accented characters are made up of Unicode combining characters, so unicode text formatting such as strikethroughs and underlines will also be removed.

[More info](https://wikipedia.org/wiki/Diacritic)

**Input:** `string` → **Output:** `string`

---

### `RemoveEXIF()`

**Operation:** `Remove EXIF`

**Category:** `Forensics`

**Module:** Image

Removes EXIF data from a JPEG image.

EXIF data embedded in photos usually contains information about the image file itself as well as the device used to create it.

[More info](https://wikipedia.org/wiki/Exif)

**Input:** `ArrayBuffer` → **Output:** `byteArray`

---

### `RemoveLineNumbers()`

**Operation:** `Remove line numbers`

**Category:** `Utils`

**Module:** Default

Removes line numbers from the output if they can be trivially detected.

**Input:** `string` → **Output:** `string`

---

### `RemoveNullBytes()`

**Operation:** `Remove null bytes`

**Category:** `Utils`

**Module:** Default

Removes all null bytes (`0x00`) from the input.

**Input:** `ArrayBuffer` → **Output:** `byteArray`

---

### `RemoveWhitespace()`

**Operation:** `Remove whitespace`

**Category:** `Utils`

**Module:** Default

Optionally removes all spaces, carriage returns, line feeds, tabs and form feeds from the input data.

This operation also supports the removal of full stops which are sometimes used to represent non-printable bytes in ASCII output.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Spaces** (boolean): default `true`
  - **Carriage returns (\r)** (boolean): default `true`
  - **Line feeds (\n)** (boolean): default `true`
  - **Tabs** (boolean): default `true`
  - **Form feeds (\f)** (boolean): default `true`
  - **Full stops** (boolean): default ``

---

### `RenderImage()`

**Operation:** `Render Image`

**Category:** `Multimedia`

**Module:** Image

Displays the input as an image. Supports the following formats:

jpg/jpegpnggifwebpbmpico

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Input format** (option): `Raw`, `Base64`, `Hex`

---

### `RenderMarkdown()`

**Operation:** `Render Markdown`

**Category:** `Code tidy`

**Module:** Code

Renders input Markdown as HTML. HTML rendering is disabled to avoid XSS.

[More info](https://wikipedia.org/wiki/Markdown)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Autoconvert URLs to links** (boolean): default ``
  - **Enable syntax highlighting** (boolean): default `true`

---

### `ResizeImage()`

**Operation:** `Resize Image`

**Category:** `Multimedia`

**Module:** Image

Resizes an image to the specified width and height values.

[More info](https://wikipedia.org/wiki/Image_scaling)

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Width** (number): default `100`
  - **Height** (number): default `100`
  - **Unit type** (option): `Pixels`, `Percent`
  - **Maintain aspect ratio** (boolean): default ``
  - **Resizing algorithm** (option): `Nearest Neighbour`, `Bilinear`, `Bicubic` (+2 more); default `Bilinear`

---

### `Return()`

**Operation:** `Return`

**Category:** `Flow control`

**Module:** Default

End execution of operations at this point in the recipe.

**Input:** `string` → **Output:** `string`

---

### `Reverse()`

**Operation:** `Reverse`

**Category:** `Utils`

**Module:** Default

Reverses the input string.

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **By** (option): `Byte`, `Character`, `Line`; default `Character`

---

### `RisonDecode()`

**Operation:** `Rison Decode`

**Category:** `Data format`

**Module:** Encodings

Rison, a data serialization format optimized for compactness in URIs. Rison is a slight variation of JSON that looks vastly superior after URI encoding. Rison still expresses exactly the same set of data structures as JSON, so data can be translated back and forth without loss or guesswork.

[More info](https://github.com/Nanonid/rison)

**Input:** `string` → **Output:** `JSON`

**Arguments:**
  - **Decode Option** (editableOption): `Decode`, `Decode Object`, `Decode Array`

---

### `RisonEncode()`

**Operation:** `Rison Encode`

**Category:** `Data format`

**Module:** Encodings

Rison, a data serialization format optimized for compactness in URIs. Rison is a slight variation of JSON that looks vastly superior after URI encoding. Rison still expresses exactly the same set of data structures as JSON, so data can be translated back and forth without loss or guesswork.

[More info](https://github.com/Nanonid/rison)

**Input:** `JSON` → **Output:** `string`

**Arguments:**
  - **Encode Option** (option): `Encode`, `Encode Object`, `Encode Array` (+1 more)

---

### `RotateImage()`

**Operation:** `Rotate Image`

**Category:** `Multimedia`

**Module:** Image

Rotates an image by the specified number of degrees.

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Rotation amount (degrees)** (number): default `90`

---

### `RotateLeft()`

**Operation:** `Rotate left`

**Category:** `Arithmetic / Logic`

**Module:** Default

Rotates each byte to the left by the number of bits specified, optionally carrying the excess bits over to the next byte. Currently only supports 8-bit values.

[More info](https://wikipedia.org/wiki/Bitwise_operation#Bit_shifts)

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Amount** (number): default `1`
  - **Carry through** (boolean): default ``

---

### `RotateRight()`

**Operation:** `Rotate right`

**Category:** `Arithmetic / Logic`

**Module:** Default

Rotates each byte to the right by the number of bits specified, optionally carrying the excess bits over to the next byte. Currently only supports 8-bit values.

[More info](https://wikipedia.org/wiki/Bitwise_operation#Bit_shifts)

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Amount** (number): default `1`
  - **Carry through** (boolean): default ``

---

### `SHA0()`

**Operation:** `SHA0`

**Category:** `Hashing`

**Module:** Crypto

SHA-0 is a retronym applied to the original version of the 160-bit hash function published in 1993 under the name 'SHA'. It was withdrawn shortly after publication due to an undisclosed 'significant flaw' and replaced by the slightly revised version SHA-1. The message digest algorithm consists, by default, of 80 rounds.

[More info](https://wikipedia.org/wiki/SHA-1#SHA-0)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Rounds** (number): default `80`

---

### `SHA1()`

**Operation:** `SHA1`

**Category:** `Hashing`

**Module:** Crypto

The SHA (Secure Hash Algorithm) hash functions were designed by the NSA. SHA-1 is the most established of the existing SHA hash functions and it is used in a variety of security applications and protocols.

However, SHA-1's collision resistance has been weakening as new attacks are discovered or improved. The message digest algorithm consists, by default, of 80 rounds.

[More info](https://wikipedia.org/wiki/SHA-1)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Rounds** (number): default `80`

---

### `SHA2()`

**Operation:** `SHA2`

**Category:** `Hashing`

**Module:** Crypto

The SHA-2 (Secure Hash Algorithm 2) hash functions were designed by the NSA. SHA-2 includes significant changes from its predecessor, SHA-1. The SHA-2 family consists of hash functions with digests (hash values) that are 224, 256, 384 or 512 bits: SHA224, SHA256, SHA384, SHA512.

SHA-512 operates on 64-bit words.SHA-256 operates on 32-bit words.SHA-384 is largely identical to SHA-512 but is truncated to 384 bytes.SHA-224 is largely identical to SHA-256 but is truncated to 224 bytes.SHA-512/224 and SHA-512/256 are truncated versions of SHA-512, but the initial values are generated using the method described in Federal Information Processing Standards (FIPS) PUB 180-4. The message digest algorithm for SHA256 variants consists, by default, of 64 rounds, and for SHA512 variants, it is, by default, 160.

[More info](https://wikipedia.org/wiki/SHA-2)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Size** (argSelector): `512`, `384`, `256` (+3 more)
  - **Rounds** (number): default `64`
  - **Rounds** (number): default `160`

---

### `SHA3()`

**Operation:** `SHA3`

**Category:** `Hashing`

**Module:** Crypto

The SHA-3 (Secure Hash Algorithm 3) hash functions were released by NIST on August 5, 2015. Although part of the same series of standards, SHA-3 is internally quite different from the MD5-like structure of SHA-1 and SHA-2.

SHA-3 is a subset of the broader cryptographic primitive family Keccak designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche, building upon RadioGatún.

[More info](https://wikipedia.org/wiki/SHA-3)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Size** (option): `512`, `384`, `256` (+1 more)

---

### `SIGABA()`

**Operation:** `SIGABA`

**Category:** `Encryption / Encoding`

**Module:** Bletchley

Encipher/decipher with the WW2 SIGABA machine. 

SIGABA, otherwise known as ECM Mark II, was used by the United States for message encryption during WW2 up to the 1950s. It was developed in the 1930s by the US Army and Navy, and has up to this day never been broken. Consisting of 15 rotors: 5 cipher rotors and 10 rotors (5 control rotors and 5 index rotors) controlling the stepping of the cipher rotors, the rotor stepping for SIGABA is much more complex than other rotor machines of its time, such as Enigma. All example rotor wirings are random example sets.

To configure rotor wirings, for the cipher and control rotors enter a string of letters which map from A to Z, and for the index rotors enter a sequence of numbers which map from 0 to 9. Note that encryption is not the same as decryption, so first choose the desired mode. 

 Note: Whilst this has been tested against other software emulators, it has not been tested against hardware.

[More info](https://wikipedia.org/wiki/SIGABA)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **1st (left-hand) cipher rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+7 more)
  - **1st cipher rotor reversed** (boolean): default ``
  - **1st cipher rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **2nd cipher rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+7 more)
  - **2nd cipher rotor reversed** (boolean): default ``
  - **2nd cipher rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **3rd (middle) cipher rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+7 more)
  - **3rd cipher rotor reversed** (boolean): default ``
  - **3rd cipher rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **4th cipher rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+7 more)
  - **4th cipher rotor reversed** (boolean): default ``
  - **4th cipher rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **5th (right-hand) cipher rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+7 more)
  - **5th cipher rotor reversed** (boolean): default ``
  - **5th cipher rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **1st (left-hand) control rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+7 more)
  - **1st control rotor reversed** (boolean): default ``
  - **1st control rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **2nd control rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+7 more)
  - **2nd control rotor reversed** (boolean): default ``
  - **2nd control rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **3rd (middle) control rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+7 more)
  - **3rd control rotor reversed** (boolean): default ``
  - **3rd control rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **4th control rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+7 more)
  - **4th control rotor reversed** (boolean): default ``
  - **4th control rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **5th (right-hand) control rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+7 more)
  - **5th control rotor reversed** (boolean): default ``
  - **5th control rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **1st (left-hand) index rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+2 more)
  - **1st index rotor initial value** (option): `0`, `1`, `2` (+7 more)
  - **2nd index rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+2 more)
  - **2nd index rotor initial value** (option): `0`, `1`, `2` (+7 more)
  - **3rd (middle) index rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+2 more)
  - **3rd index rotor initial value** (option): `0`, `1`, `2` (+7 more)
  - **4th index rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+2 more)
  - **4th index rotor initial value** (option): `0`, `1`, `2` (+7 more)
  - **5th (right-hand) index rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+2 more)
  - **5th index rotor initial value** (option): `0`, `1`, `2` (+7 more)
  - **SIGABA mode** (option): `Encrypt`, `Decrypt`

---

### `SM2Decrypt()`

**Operation:** `SM2 Decrypt`

**Category:** `Public Key`

**Module:** Crypto

Decrypts a message utilizing the SM2 standard

**Input:** `string` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Private Key** (string): default `DEADBEEF`
  - **Input Format** (option): `C1C3C2`, `C1C2C3`
  - **Curve** (option): `sm2p256v1`

---

### `SM2Encrypt()`

**Operation:** `SM2 Encrypt`

**Category:** `Public Key`

**Module:** Crypto

Encrypts a message utilizing the SM2 standard

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Public Key X** (string): default `DEADBEEF`
  - **Public Key Y** (string): default `DEADBEEF`
  - **Output Format** (option): `C1C3C2`, `C1C2C3`
  - **Curve** (option): `sm2p256v1`

---

### `SM3()`

**Operation:** `SM3`

**Category:** `Hashing`

**Module:** Crypto

SM3 is a cryptographic hash function used in the Chinese National Standard. SM3 is mainly used in digital signatures, message authentication codes, and pseudorandom number generators. The message digest algorithm consists, by default, of 64 rounds and length of 256.

[More info](https://wikipedia.org/wiki/SM3_(hash_function))

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Length** (number): default `256`
  - **Rounds** (number): default `64`

---

### `SM4Decrypt()`

**Operation:** `SM4 Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

SM4 is a 128-bit block cipher, currently established as a national standard (GB/T 32907-2016) of China.

[More info](https://wikipedia.org/wiki/SM4_(cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Mode** (option): `CBC`, `CFB`, `OFB` (+4 more)
  - **Input** (option): `Raw`, `Hex`
  - **Output** (option): `Hex`, `Raw`

---

### `SM4Encrypt()`

**Operation:** `SM4 Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

SM4 is a 128-bit block cipher, currently established as a national standard (GB/T 32907-2016) of China. Multiple block cipher modes are supported. When using CBC or ECB mode, the PKCS#7 padding scheme is used.

[More info](https://wikipedia.org/wiki/SM4_(cipher))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Mode** (option): `CBC`, `CFB`, `OFB` (+2 more)
  - **Input** (option): `Raw`, `Hex`
  - **Output** (option): `Hex`, `Raw`

---

### `SQLBeautify()`

**Operation:** `SQL Beautify`

**Category:** `Code tidy`

**Module:** Code

Indents and prettifies Structured Query Language (SQL) code.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Indent string** (binaryShortString): default `\\t`

---

### `SQLMinify()`

**Operation:** `SQL Minify`

**Category:** `Code tidy`

**Module:** Code

Compresses Structured Query Language (SQL) code.

**Input:** `string` → **Output:** `string`

---

### `SSDEEP()`

**Operation:** `SSDEEP`

**Category:** `Hashing`

**Module:** Crypto

SSDEEP is a program for computing context triggered piecewise hashes (CTPH). Also called fuzzy hashes, CTPH can match inputs that have homologies. Such inputs have sequences of identical bytes in the same order, although bytes in between these sequences may be different in both content and length.

SSDEEP hashes are now widely used for simple identification purposes (e.g. the 'Basic Properties' section in VirusTotal). Although 'better' fuzzy hashes are available, SSDEEP is still one of the primary choices because of its speed and being a de facto standard.

This operation is fundamentally the same as the CTPH operation, however their outputs differ in format.

[More info](https://forensics.wiki/ssdeep)

**Input:** `string` → **Output:** `string`

---

### `SUB()`

**Operation:** `SUB`

**Category:** `Arithmetic / Logic`

**Module:** Default

SUB the input with the given key (e.g. `fe023da5`), MOD 255

[More info](https://wikipedia.org/wiki/Bitwise_operation#Bitwise_operators)

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Key** (toggleString): default ``

---

### `Salsa20()`

**Operation:** `Salsa20`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Salsa20 is a stream cipher designed by Daniel J. Bernstein and submitted to the eSTREAM project; Salsa20/8 and Salsa20/12 are round-reduced variants. It is closely related to the ChaCha stream cipher.

Key: Salsa20 uses a key of 16 or 32 bytes (128 or 256 bits).

Nonce: Salsa20 uses a nonce of 8 bytes (64 bits).

Counter: Salsa uses a counter of 8 bytes (64 bits). The counter starts at zero at the start of the keystream, and is incremented at every 64 bytes.

[More info](https://wikipedia.org/wiki/Salsa20)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **Nonce** (toggleString): default ``
  - **Counter** (number): default ``
  - **Rounds** (option): `20`, `12`, `8`
  - **Input** (option): `Hex`, `Raw`
  - **Output** (option): `Raw`, `Hex`

---

### `ScanForEmbeddedFiles()`

**Operation:** `Scan for Embedded Files`

**Category:** `Forensics`

**Module:** Default

Scans the data for potential embedded files by looking for magic bytes at all offsets. This operation is prone to false positives.

WARNING: Files over about 100KB in size will take a VERY long time to process.

[More info](https://wikipedia.org/wiki/List_of_file_signatures)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Images** (boolean): default `true`
  - **Video** (boolean): default `true`
  - **Audio** (boolean): default `true`
  - **Documents** (boolean): default `true`
  - **Applications** (boolean): default `true`
  - **Archives** (boolean): default `true`
  - **Miscellaneous** (boolean): default ``

---

### `ScatterChart()`

**Operation:** `Scatter chart`

**Category:** `Multimedia`

**Module:** Charts

Plots two-variable data as single points on a graph.

[More info](https://wikipedia.org/wiki/Scatter_plot)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Record delimiter** (option): `Line feed`, `CRLF`
  - **Field delimiter** (option): `Space`, `Comma`, `Semi-colon` (+2 more)
  - **Use column headers as labels** (boolean): default `true`
  - **X label** (string): default ``
  - **Y label** (string): default ``
  - **Colour** (string): default `black`
  - **Point radius** (number): default `10`
  - **Use colour from third column** (boolean): default ``

---

### `Scrypt()`

**Operation:** `Scrypt`

**Category:** `Encryption / Encoding`

**Module:** Crypto

scrypt is a password-based key derivation function (PBKDF) created by Colin Percival. The algorithm was specifically designed to make it costly to perform large-scale custom hardware attacks by requiring large amounts of memory. In 2016, the scrypt algorithm was published by IETF as RFC 7914.

Enter the password in the input to generate its hash.

[More info](https://wikipedia.org/wiki/Scrypt)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Salt** (toggleString): default ``
  - **Iterations (N)** (number): default `16384`
  - **Memory factor (r)** (number): default `8`
  - **Parallelization factor (p)** (number): default `1`
  - **Key length** (number): default `64`

---

### `SeriesChart()`

**Operation:** `Series chart`

**Category:** `Multimedia`

**Module:** Charts

A time series graph is a line graph of repeated measurements taken over regular time intervals.

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Record delimiter** (option): `Line feed`, `CRLF`
  - **Field delimiter** (option): `Space`, `Comma`, `Semi-colon` (+2 more)
  - **X label** (string): default ``
  - **Point radius** (number): default `1`
  - **Series colours** (string): default `mediumseagreen, dodgerblue, tomato`

---

### `SetDifference()`

**Operation:** `Set Difference`

**Category:** `Arithmetic / Logic`

**Module:** Default

Calculates the difference, or relative complement, of two sets.

[More info](https://wikipedia.org/wiki/Complement_(set_theory)#Relative_complement)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Sample delimiter** (binaryString): default `\\n\\n`
  - **Item delimiter** (binaryString): default `,`

---

### `SetIntersection()`

**Operation:** `Set Intersection`

**Category:** `Arithmetic / Logic`

**Module:** Default

Calculates the intersection of two sets.

[More info](https://wikipedia.org/wiki/Intersection_(set_theory))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Sample delimiter** (binaryString): default `\\n\\n`
  - **Item delimiter** (binaryString): default `,`

---

### `SetUnion()`

**Operation:** `Set Union`

**Category:** `Arithmetic / Logic`

**Module:** Default

Calculates the union of two sets.

[More info](https://wikipedia.org/wiki/Union_(set_theory))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Sample delimiter** (binaryString): default `\\n\\n`
  - **Item delimiter** (binaryString): default `,`

---

### `Shake()`

**Operation:** `Shake`

**Category:** `Hashing`

**Module:** Crypto

Shake is an Extendable Output Function (XOF) of the SHA-3 hash algorithm, part of the Keccak family, allowing for variable output length/size.

[More info](https://wikipedia.org/wiki/SHA-3#Instances)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Capacity** (option): `256`, `128`
  - **Size** (number): default `512`

---

### `SharpenImage()`

**Operation:** `Sharpen Image`

**Category:** `Multimedia`

**Module:** Image

Sharpens an image (Unsharp mask)

[More info](https://wikipedia.org/wiki/Unsharp_masking)

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Radius** (number): default `2`
  - **Amount** (number): default `1`
  - **Threshold** (number): default `10`

---

### `ShowBase64Offsets()`

**Operation:** `Show Base64 offsets`

**Category:** `Data format`

**Module:** Default

When a string is within a block of data and the whole block is Base64'd, the string itself could be represented in Base64 in three distinct ways depending on its offset within the block.

This operation shows all possible offsets for a given string so that each possible encoding can be considered.

[More info](https://wikipedia.org/wiki/Base64#Output_padding)

**Input:** `byteArray` → **Output:** `html`

**Arguments:**
  - **Alphabet** (binaryString): default `A-Za-z0-9+/=`
  - **Show variable chars and padding** (boolean): default `true`
  - **Input format** (option): `Raw`, `Base64`

---

### `ShowOnMap()`

**Operation:** `Show on map`

**Category:** `Utils`

**Module:** Hashing

Displays co-ordinates on a slippy map.

Co-ordinates will be converted to decimal degrees before being shown on the map.

Supported formats:Degrees Minutes Seconds (DMS)Degrees Decimal Minutes (DDM)Decimal Degrees (DD)GeohashMilitary Grid Reference System (MGRS)Ordnance Survey National Grid (OSNG)Universal Transverse Mercator (UTM)
This operation will not work offline.

[More info](https://osmfoundation.org/wiki/Terms_of_Use)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Zoom Level** (number): default `13`
  - **Input Format** (option): `Auto`, `Degrees Minutes Seconds`, `Degrees Decimal Minutes` (+5 more)
  - **Input Delimiter** (option): `Auto`, `Direction Preceding`, `Direction Following` (+4 more)

---

### `Shuffle()`

**Operation:** `Shuffle`

**Category:** `Utils`

**Module:** Default

Randomly reorders input elements.

[More info](https://wikipedia.org/wiki/Shuffling)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `CRLF`, `Space` (+4 more)

---

### `Sleep()`

**Operation:** `Sleep`

**Category:** `Utils`

**Module:** Default

Sleep causes the recipe to wait for a specified number of milliseconds before continuing execution.

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Time (ms)** (number): default `1000`

---

### `Snefru()`

**Operation:** `Snefru`

**Category:** `Hashing`

**Module:** Crypto

Snefru is a cryptographic hash function invented by Ralph Merkle in 1990 while working at Xerox PARC. The function supports 128-bit and 256-bit output. It was named after the Egyptian Pharaoh Sneferu, continuing the tradition of the Khufu and Khafre block ciphers.

The original design of Snefru was shown to be insecure by Eli Biham and Adi Shamir who were able to use differential cryptanalysis to find hash collisions. The design was then modified by increasing the number of iterations of the main pass of the algorithm from two to eight.

[More info](https://wikipedia.org/wiki/Snefru)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Size** (number): default `128`
  - **Rounds** (option): `8`, `4`, `2`

---

### `Sort()`

**Operation:** `Sort`

**Category:** `Utils`

**Module:** Default

Alphabetically sorts strings separated by the specified delimiter.

The IP address option supports IPv4 only.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `CRLF`, `Space` (+4 more)
  - **Reverse** (boolean): default ``
  - **Order** (option): `Alphabetical (case sensitive)`, `Alphabetical (case insensitive)`, `IP address` (+3 more)

---

### `Split()`

**Operation:** `Split`

**Category:** `Utils`

**Module:** Default

Splits a string into sections around a given delimiter.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Split delimiter** (editableOptionShort): `Comma`, `Space`, `Line feed` (+4 more)
  - **Join delimiter** (editableOptionShort): `Line feed`, `CRLF`, `Space` (+4 more)

---

### `SplitColourChannels()`

**Operation:** `Split Colour Channels`

**Category:** `Multimedia`

**Module:** Image

Splits the given image into its red, green and blue colour channels.

[More info](https://wikipedia.org/wiki/Channel_(digital_image))

**Input:** `ArrayBuffer` → **Output:** `html`

---

### `StandardDeviation()`

**Operation:** `Standard Deviation`

**Category:** `Arithmetic / Logic`

**Module:** Default

Computes the standard deviation of a number list. If an item in the string is not a number it is excluded from the list.

e.g. `0x0a 8 .5` becomes `4.089281382128433`

[More info](https://wikipedia.org/wiki/Standard_deviation)

**Input:** `string` → **Output:** `BigNumber`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `Space`, `Comma` (+3 more)

---

### `Streebog()`

**Operation:** `Streebog`

**Category:** `Hashing`

**Module:** Hashing

Streebog is a cryptographic hash function defined in the Russian national standard GOST R 34.11-2012 Information Technology – Cryptographic Information Security – Hash Function. It was created to replace an obsolete GOST hash function defined in the old standard GOST R 34.11-94, and as an asymmetric reply to SHA-3 competition by the US National Institute of Standards and Technology.

[More info](https://wikipedia.org/wiki/Streebog)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Digest length** (option): `256`, `512`

---

### `Strings()`

**Operation:** `Strings`

**Category:** `Extractors`

**Module:** Regex

Extracts all strings from the input.

[More info](https://wikipedia.org/wiki/Strings_(Unix))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Encoding** (option): `Single byte`, `16-bit littleendian`, `16-bit bigendian` (+1 more)
  - **Minimum length** (number): default `4`
  - **Match** (option): `[ASCII]`, `Alphanumeric + punctuation (A)`, `All printable chars (A)` (+5 more)
  - **Display total** (boolean): default ``
  - **Sort** (boolean): default ``
  - **Unique** (boolean): default ``

---

### `StripHTMLTags()`

**Operation:** `Strip HTML tags`

**Category:** `Code tidy`

**Module:** Default

Removes all HTML tags from the input.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Remove indentation** (boolean): default `true`
  - **Remove excess line breaks** (boolean): default `true`

---

### `StripHTTPHeaders()`

**Operation:** `Strip HTTP headers`

**Category:** `Networking`

**Module:** Default

Removes HTTP headers from a request or response by looking for the first instance of a double newline.

[More info](https://wikipedia.org/wiki/Hypertext_Transfer_Protocol#Message_format)

**Input:** `string` → **Output:** `string`

---

### `StripIPv4Header()`

**Operation:** `Strip IPv4 header`

**Category:** `Networking`

**Module:** Default

Strips the IPv4 header from an IPv4 packet, outputting the payload.

[More info](https://wikipedia.org/wiki/IPv4)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

---

### `StripTCPHeader()`

**Operation:** `Strip TCP header`

**Category:** `Networking`

**Module:** Default

Strips the TCP header from a TCP segment, outputting the payload.

[More info](https://wikipedia.org/wiki/Transmission_Control_Protocol)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

---

### `StripUDPHeader()`

**Operation:** `Strip UDP header`

**Category:** `Networking`

**Module:** Default

Strips the UDP header from a UDP datagram, outputting the payload.

[More info](https://wikipedia.org/wiki/User_Datagram_Protocol)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

---

### `Subsection()`

**Operation:** `Subsection`

**Category:** `Flow control`

**Module:** Default

Select a part of the input data using a regular expression (regex), and run all subsequent operations on each match separately.

You can use up to one capture group, where the recipe will only be run on the data in the capture group. If there's more than one capture group, only the first one will be operated on.

Use the Merge operation to reset the effects of subsection.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Section (regex)** (string): default ``
  - **Case sensitive matching** (boolean): default `true`
  - **Global matching** (boolean): default `true`
  - **Ignore errors** (boolean): default ``

---

### `Substitute()`

**Operation:** `Substitute`

**Category:** `Encryption / Encoding`

**Module:** Default

A substitution cipher allowing you to specify bytes to replace with other byte values. This can be used to create Caesar ciphers but is more powerful as any byte value can be substituted, not just letters, and the substitution values need not be in order.

Enter the bytes you want to replace in the Plaintext field and the bytes to replace them with in the Ciphertext field.

Non-printable bytes can be specified using string escape notation. For example, a line feed character can be written as either `\n` or `\x0a`.

Byte ranges can be specified using a hyphen. For example, the sequence `0123456789` can be written as `0-9`.

Note that blackslash characters are used to escape special characters, so will need to be escaped themselves if you want to use them on their own (e.g.`\\`).

[More info](https://wikipedia.org/wiki/Substitution_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Plaintext** (binaryString): default `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
  - **Ciphertext** (binaryString): default `XYZABCDEFGHIJKLMNOPQRSTUVW`
  - **Ignore case** (boolean): default ``

---

### `Subtract()`

**Operation:** `Subtract`

**Category:** `Arithmetic / Logic`

**Module:** Default

Subtracts a list of numbers. If an item in the string is not a number it is excluded from the list.

e.g. `0x0a 8 .5` becomes `1.5`

[More info](https://wikipedia.org/wiki/Subtraction)

**Input:** `string` → **Output:** `BigNumber`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `Space`, `Comma` (+3 more)

---

### `Sum()`

**Operation:** `Sum`

**Category:** `Arithmetic / Logic`

**Module:** Default

Adds together a list of numbers. If an item in the string is not a number it is excluded from the list.

e.g. `0x0a 8 .5` becomes `18.5`

[More info](https://wikipedia.org/wiki/Summation)

**Input:** `string` → **Output:** `BigNumber`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `Space`, `Comma` (+3 more)

---

### `SwapCase()`

**Operation:** `Swap case`

**Category:** `Utils`

**Module:** Default

Converts uppercase letters to lowercase ones, and lowercase ones to uppercase ones.

**Input:** `string` → **Output:** `string`

---

### `SwapEndianness()`

**Operation:** `Swap endianness`

**Category:** `Data format`

**Module:** Default

Switches the data from big-endian to little-endian or vice-versa. Data can be read in as hexadecimal or raw bytes. It will be returned in the same format as it is entered.

[More info](https://wikipedia.org/wiki/Endianness)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Data format** (option): `Hex`, `Raw`
  - **Word length (bytes)** (number): default `4`
  - **Pad incomplete words** (boolean): default `true`

---

### `SymmetricDifference()`

**Operation:** `Symmetric Difference`

**Category:** `Arithmetic / Logic`

**Module:** Default

Calculates the symmetric difference of two sets.

[More info](https://wikipedia.org/wiki/Symmetric_difference)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Sample delimiter** (binaryString): default `\\n\\n`
  - **Item delimiter** (binaryString): default `,`

---

### `SyntaxHighlighter()`

**Operation:** `Syntax highlighter`

**Category:** `Code tidy`

**Module:** Code

**Support:** Unsupported in the current STPyV8 runtime. Excluded by the current Node-targeted bundle.

Adds syntax highlighting to a range of source code languages. Note that this will not indent the code. Use one of the 'Beautify' operations for that.

[More info](https://wikipedia.org/wiki/Syntax_highlighting)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Language** (option): `auto detect`, `1c`, `abnf` (+190 more)

---

### `Tail()`

**Operation:** `Tail`

**Category:** `Utils`

**Module:** Default

Like the UNIX tail utility.
Gets the last n lines.
Optionally you can select all lines after line n by entering a negative value for n.
The delimiter can be changed so that instead of lines, fields (i.e. commas) are selected instead.

[More info](https://wikipedia.org/wiki/Tail_(Unix))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `CRLF`, `Space` (+4 more)
  - **Number** (number): default `10`

---

### `TakeBytes()`

**Operation:** `Take bytes`

**Category:** `Utils`

**Module:** Default

Takes a slice of the specified number of bytes from the data. Negative values are allowed.

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Start** (number): default ``
  - **Length** (number): default `5`
  - **Apply to each line** (boolean): default ``

---

### `TakeNthBytes()`

**Operation:** `Take nth bytes`

**Category:** `Utils`

**Module:** Default

Takes every nth byte starting with a given byte.

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Take every** (number): default `4`
  - **Starting at** (number): default ``
  - **Apply to each line** (boolean): default ``

---

### `Tar()`

**Operation:** `Tar`

**Category:** `Compression`

**Module:** Compression

Packs the input into a tarball.

No support for multiple files at this time.

[More info](https://wikipedia.org/wiki/Tar_(computing))

**Input:** `ArrayBuffer` → **Output:** `File`

**Arguments:**
  - **Filename** (string): default `file.txt`

---

### `Template()`

**Operation:** `Template`

**Category:** `Extractors`

**Module:** Handlebars

Render a template with Handlebars/Mustache substituting variables using JSON input. Templates will be rendered to plain-text only, to prevent XSS.

[More info](https://handlebarsjs.com/)

**Input:** `JSON` → **Output:** `string`

**Arguments:**
  - **Template definition (.handlebars)** (text)

---

### `TextEncodingBruteForce()`

**Operation:** `Text Encoding Brute Force`

**Category:** `Data format`

**Module:** Encodings

Enumerates all supported text encodings for the input, allowing you to quickly spot the correct one.

Supported charsets are:

UTF-8 (65001)
UTF-7 (65000)
UTF-16LE (1200)
UTF-16BE (1201)
UTF-32LE (12000)
UTF-32BE (12001)
IBM EBCDIC International (500)
IBM EBCDIC US-Canada (37)
IBM EBCDIC Multilingual/ROECE (Latin 2) (870)
IBM EBCDIC Greek Modern (875)
IBM EBCDIC French (1010)
IBM EBCDIC Turkish (Latin 5) (1026)
IBM EBCDIC Latin 1/Open System (1047)
IBM EBCDIC Lao (1132/1133/1341)
IBM EBCDIC US-Canada (037 + Euro symbol) (1140)
IBM EBCDIC Germany (20273 + Euro symbol) (1141)
IBM EBCDIC Denmark-Norway (20277 + Euro symbol) (1142)
IBM EBCDIC Finland-Sweden (20278 + Euro symbol) (1143)
IBM EBCDIC Italy (20280 + Euro symbol) (1144)
IBM EBCDIC Latin America-Spain (20284 + Euro symbol) (1145)
IBM EBCDIC United Kingdom (20285 + Euro symbol) (1146)
IBM EBCDIC France (20297 + Euro symbol) (1147)
IBM EBCDIC International (500 + Euro symbol) (1148)
IBM EBCDIC Icelandic (20871 + Euro symbol) (1149)
IBM EBCDIC Germany (20273)
IBM EBCDIC Denmark-Norway (20277)
IBM EBCDIC Finland-Sweden (20278)
IBM EBCDIC Italy (20280)
IBM EBCDIC Latin America-Spain (20284)
IBM EBCDIC United Kingdom (20285)
IBM EBCDIC Japanese Katakana Extended (20290)
IBM EBCDIC France (20297)
IBM EBCDIC Arabic (20420)
IBM EBCDIC Greek (20423)
IBM EBCDIC Hebrew (20424)
IBM EBCDIC Korean Extended (20833)
IBM EBCDIC Thai (20838)
IBM EBCDIC Icelandic (20871)
IBM EBCDIC Cyrillic Russian (20880)
IBM EBCDIC Turkish (20905)
IBM EBCDIC Latin 1/Open System (1047 + Euro symbol) (20924)
IBM EBCDIC Cyrillic Serbian-Bulgarian (21025)
OEM United States (437)
OEM Greek (formerly 437G); Greek (DOS) (737)
OEM Baltic; Baltic (DOS) (775)
OEM Russian; Cyrillic + Euro symbol (808)
OEM Multilingual Latin 1; Western European (DOS) (850)
OEM Latin 2; Central European (DOS) (852)
OEM Cyrillic (primarily Russian) (855)
OEM Turkish; Turkish (DOS) (857)
OEM Multilingual Latin 1 + Euro symbol (858)
OEM Portuguese; Portuguese (DOS) (860)
OEM Icelandic; Icelandic (DOS) (861)
OEM Hebrew; Hebrew (DOS) (862)
OEM French Canadian; French Canadian (DOS) (863)
OEM Arabic; Arabic (864) (864)
OEM Nordic; Nordic (DOS) (865)
OEM Russian; Cyrillic (DOS) (866)
OEM Modern Greek; Greek, Modern (DOS) (869)
OEM Cyrillic (primarily Russian) + Euro Symbol (872)
Windows-874 Thai (874)
Windows-1250 Central European (1250)
Windows-1251 Cyrillic (1251)
Windows-1252 Latin (1252)
Windows-1253 Greek (1253)
Windows-1254 Turkish (1254)
Windows-1255 Hebrew (1255)
Windows-1256 Arabic (1256)
Windows-1257 Baltic (1257)
Windows-1258 Vietnam (1258)
ISO-8859-1 Latin 1 Western European (28591)
ISO-8859-2 Latin 2 Central European (28592)
ISO-8859-3 Latin 3 South European (28593)
ISO-8859-4 Latin 4 North European (28594)
ISO-8859-5 Latin/Cyrillic (28595)
ISO-8859-6 Latin/Arabic (28596)
ISO-8859-7 Latin/Greek (28597)
ISO-8859-8 Latin/Hebrew (28598)
ISO 8859-8 Hebrew (ISO-Logical) (38598)
ISO-8859-9 Latin 5 Turkish (28599)
ISO-8859-10 Latin 6 Nordic (28600)
ISO-8859-11 Latin/Thai (28601)
ISO-8859-13 Latin 7 Baltic Rim (28603)
ISO-8859-14 Latin 8 Celtic (28604)
ISO-8859-15 Latin 9 (28605)
ISO-8859-16 Latin 10 (28606)
ISO 2022 JIS Japanese with no halfwidth Katakana (50220)
ISO 2022 JIS Japanese with halfwidth Katakana (50221)
ISO 2022 Japanese JIS X 0201-1989 (1 byte Kana-SO/SI) (50222)
ISO 2022 Korean (50225)
ISO 2022 Simplified Chinese (50227)
ISO 6937 Non-Spacing Accent (20269)
EUC Japanese (51932)
EUC Simplified Chinese (51936)
EUC Korean (51949)
ISCII Devanagari (57002)
ISCII Bengali (57003)
ISCII Tamil (57004)
ISCII Telugu (57005)
ISCII Assamese (57006)
ISCII Oriya (57007)
ISCII Kannada (57008)
ISCII Malayalam (57009)
ISCII Gujarati (57010)
ISCII Punjabi (57011)
Japanese Shift-JIS (932)
Simplified Chinese GBK (936)
Korean (949)
Traditional Chinese Big5 (950)
US-ASCII (7-bit) (20127)
Simplified Chinese GB2312 (20936)
KOI8-R Russian Cyrillic (20866)
KOI8-U Ukrainian Cyrillic (21866)
Mazovia (Polish) MS-DOS (620)
Arabic (ASMO 708) (708)
Arabic (Transparent ASMO); Arabic (DOS) (720)
Kamenický (Czech) MS-DOS (895)
Korean (Johab) (1361)
MAC Roman (10000)
Japanese (Mac) (10001)
MAC Traditional Chinese (Big5) (10002)
Korean (Mac) (10003)
Arabic (Mac) (10004)
Hebrew (Mac) (10005)
Greek (Mac) (10006)
Cyrillic (Mac) (10007)
MAC Simplified Chinese (GB 2312) (10008)
Romanian (Mac) (10010)
Ukrainian (Mac) (10017)
Thai (Mac) (10021)
MAC Latin 2 (Central European) (10029)
Icelandic (Mac) (10079)
Turkish (Mac) (10081)
Croatian (Mac) (10082)
CNS Taiwan (Chinese Traditional) (20000)
TCA Taiwan (20001)
ETEN Taiwan (Chinese Traditional) (20002)
IBM5550 Taiwan (20003)
TeleText Taiwan (20004)
Wang Taiwan (20005)
Western European IA5 (IRV International Alphabet 5) (20105)
IA5 German (7-bit) (20106)
IA5 Swedish (7-bit) (20107)
IA5 Norwegian (7-bit) (20108)
T.61 (20261)
Japanese (JIS 0208-1990 and 0212-1990) (20932)
Korean Wansung (20949)
Extended/Ext Alpha Lowercase (21027)
Europa 3 (29001)
Atari ST/TT (47451)
HZ-GB2312 Simplified Chinese (52936)
Simplified Chinese GB18030 (54936)

[More info](https://wikipedia.org/wiki/Character_encoding)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Mode** (option): `Encode`, `Decode`

---

### `ToBCD()`

**Operation:** `To BCD`

**Category:** `Data format`

**Module:** Default

Binary-Coded Decimal (BCD) is a class of binary encodings of decimal numbers where each decimal digit is represented by a fixed number of bits, usually four or eight. Special bit patterns are sometimes used for a sign

[More info](https://wikipedia.org/wiki/Binary-coded_decimal)

**Input:** `BigNumber` → **Output:** `string`

**Arguments:**
  - **Scheme** (option): `8 4 2 1`, `7 4 2 1`, `4 2 2 1` (+4 more)
  - **Packed** (boolean): default `true`
  - **Signed** (boolean): default ``
  - **Output format** (option): `Nibbles`, `Bytes`, `Raw`

---

### `ToBase()`

**Operation:** `To Base`

**Category:** `Data format`

**Module:** Default

Converts a decimal number to a given numerical base.

[More info](https://wikipedia.org/wiki/Radix)

**Input:** `BigNumber` → **Output:** `string`

**Arguments:**
  - **Radix** (number): default `36`

---

### `ToBase32()`

**Operation:** `To Base32`

**Category:** `Data format`

**Module:** Default

Base32 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers. It uses a smaller set of characters than Base64, usually the uppercase alphabet and the numbers 2 to 7.

[More info](https://wikipedia.org/wiki/Base32)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Alphabet** (editableOption): `Standard`, `Hex Extended`

---

### `ToBase45()`

**Operation:** `To Base45`

**Category:** `Data format`

**Module:** Default

Base45 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers. The high number base results in shorter strings than with the decimal or hexadecimal system. Base45 is optimized for usage with QR codes.

[More info](https://wikipedia.org/wiki/List_of_numeral_systems)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Alphabet** (string): default `0-9A-Z $%*+\\-./:`

---

### `ToBase58()`

**Operation:** `To Base58`

**Category:** `Data format`

**Module:** Default

Base58 (similar to Base64) is a notation for encoding arbitrary byte data. It differs from Base64 by removing easily misread characters (i.e. l, I, 0 and O) to improve human readability.

This operation encodes data in an ASCII string (with an alphabet of your choosing, presets included).

e.g. `hello world` becomes `StV1DL6CwTryKyV`

Base58 is commonly used in cryptocurrencies (Bitcoin, Ripple, etc).

[More info](https://wikipedia.org/wiki/Base58)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Alphabet** (editableOption): `Bitcoin`, `Ripple`

---

### `ToBase62()`

**Operation:** `To Base62`

**Category:** `Data format`

**Module:** Default

Base62 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers. The high number base results in shorter strings than with the decimal or hexadecimal system.

[More info](https://wikipedia.org/wiki/List_of_numeral_systems)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Alphabet** (string): default `0-9A-Za-z`

---

### `ToBase64()`

**Operation:** `To Base64`

**Category:** `Data format`

**Module:** Default

Base64 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers.

This operation encodes raw data into an ASCII Base64 string.

e.g. `hello` becomes `aGVsbG8=`

[More info](https://wikipedia.org/wiki/Base64)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Alphabet** (editableOption): `Standard (RFC 4648): A-Za-z0-9+/=`, `URL safe (RFC 4648 §5): A-Za-z0-9-_`, `Filename safe: A-Za-z0-9+-=` (+14 more)

---

### `ToBase85()`

**Operation:** `To Base85`

**Category:** `Data format`

**Module:** Default

Base85 (also called Ascii85) is a notation for encoding arbitrary byte data. It is usually more efficient that Base64.

This operation encodes data in an ASCII string (with an alphabet of your choosing, presets included).

e.g. `hello world` becomes `BOu!rD]j7BEbo7`

Base85 is commonly used in Adobe's PostScript and PDF file formats.

Options
AlphabetStandard - The standard alphabet, referred to as Ascii85Z85 (ZeroMQ) - A string-safe variant of Base85, which avoids quote marks and backslash charactersIPv6 - A variant of Base85 suitable for encoding IPv6 addresses (RFC 1924)Include delimiter
Adds a '' delimiter to the start and end of the data. This is standard for Adobe's implementation of Base85.

[More info](https://wikipedia.org/wiki/Ascii85)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Alphabet** (editableOption): `Standard`, `Z85 (ZeroMQ)`, `IPv6`
  - **Include delimeter** (boolean): default ``

---

### `ToBase92()`

**Operation:** `To Base92`

**Category:** `Data format`

**Module:** Default

Base92 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers.

[More info](https://wikipedia.org/wiki/List_of_numeral_systems)

**Input:** `string` → **Output:** `string`

---

### `ToBinary()`

**Operation:** `To Binary`

**Category:** `Data format`

**Module:** Default

Displays the input data as a binary string.

e.g. `Hi` becomes `01001000 01101001`

[More info](https://wikipedia.org/wiki/Binary_code)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+4 more)
  - **Byte Length** (number): default `8`

---

### `ToBraille()`

**Operation:** `To Braille`

**Category:** `Data format`

**Module:** Default

Converts text to six-dot braille symbols.

[More info](https://wikipedia.org/wiki/Braille)

**Input:** `string` → **Output:** `string`

---

### `ToCamelCase()`

**Operation:** `To Camel case`

**Category:** `Code tidy`

**Module:** Code

Converts the input string to camel case.

Camel case is all lower case except letters after word boundaries which are uppercase.

e.g. thisIsCamelCase

'Attempt to be context aware' will make the operation attempt to nicely transform variable and function names.

[More info](https://wikipedia.org/wiki/Camel_case)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Attempt to be context aware** (boolean): default ``

---

### `ToCaseInsensitiveRegex()`

**Operation:** `To Case Insensitive Regex`

**Category:** `Utils`

**Module:** Default

Converts a case-sensitive regex string into a case-insensitive regex string in case the i flag is unavailable to you.

e.g. `Mozilla/[0-9].[0-9] .*` becomes `[mM][oO][zZ][iI][lL][lL][aA]/[0-9].[0-9] .*`

[More info](https://wikipedia.org/wiki/Regular_expression)

**Input:** `string` → **Output:** `string`

---

### `ToCharcode()`

**Operation:** `To Charcode`

**Category:** `Data format`

**Module:** Default

Converts text to its unicode character code equivalent.

e.g. `Γειά σου` becomes `0393 03b5 03b9 03ac 20 03c3 03bf 03c5`

[More info](https://wikipedia.org/wiki/Plane_(Unicode))

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+3 more)
  - **Base** (number): default `16`

---

### `ToDecimal()`

**Operation:** `To Decimal`

**Category:** `Data format`

**Module:** Default

Converts the input data to an ordinal integer array.

e.g. `Hello` becomes `72 101 108 108 111`

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+3 more)
  - **Support signed values** (boolean): default ``

---

### `ToFloat()`

**Operation:** `To Float`

**Category:** `Data format`

**Module:** Default

Convert to IEEE754 Floating Point Numbers

[More info](https://wikipedia.org/wiki/IEEE_754)

**Input:** `byteArray` → **Output:** `string`

**Arguments:**
  - **Endianness** (option): `Big Endian`, `Little Endian`
  - **Size** (option): `Float (4 bytes)`, `Double (8 bytes)`
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+3 more)

---

### `ToHTMLEntity()`

**Operation:** `To HTML Entity`

**Category:** `Data format`

**Module:** Encodings

Converts characters to HTML entities

e.g. `&` becomes `&amp;`

[More info](https://wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Convert all characters** (boolean): default ``
  - **Convert to** (option): `Named entities`, `Numeric entities`, `Hex entities`

---

### `ToHex()`

**Operation:** `To Hex`

**Category:** `Data format`

**Module:** Default

Converts the input string to hexadecimal bytes separated by the specified delimiter.

e.g. The UTF-8 encoded string `Γειά σου` becomes `ce 93 ce b5 ce b9 ce ac 20 cf 83 ce bf cf 85 0a`

[More info](https://wikipedia.org/wiki/Hexadecimal)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Space`, `Percent`, `Comma` (+8 more)
  - **Bytes per line** (number): default ``

---

### `ToHexContent()`

**Operation:** `To Hex Content`

**Category:** `Data format`

**Module:** Default

Converts special characters in a string to hexadecimal. This format is used by SNORT for representing hex within ASCII text.

e.g. `foo=bar` becomes `foo|3d|bar`.

[More info](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00451000000000000000)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Convert** (option): `Only special chars`, `Only special chars including spaces`, `All chars`
  - **Print spaces between bytes** (boolean): default ``

---

### `ToHexdump()`

**Operation:** `To Hexdump`

**Category:** `Data format`

**Module:** Default

Creates a hexdump of the input data, displaying both the hexadecimal values of each byte and an ASCII representation alongside.

The 'UNIX format' argument defines which subset of printable characters are displayed in the preview column.

[More info](https://wikipedia.org/wiki/Hex_dump)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Width** (number): default `16`
  - **Upper case hex** (boolean): default ``
  - **Include final length** (boolean): default ``
  - **UNIX format** (boolean): default ``

---

### `ToKebabCase()`

**Operation:** `To Kebab case`

**Category:** `Code tidy`

**Module:** Code

Converts the input string to kebab case.

Kebab case is all lower case with dashes as word boundaries.

e.g. this-is-kebab-case

'Attempt to be context aware' will make the operation attempt to nicely transform variable and function names.

[More info](https://wikipedia.org/wiki/Kebab_case)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Attempt to be context aware** (boolean): default ``

---

### `ToLowerCase()`

**Operation:** `To Lower case`

**Category:** `Utils`

**Module:** Default

Converts every character in the input to lower case.

**Input:** `string` → **Output:** `string`

---

### `ToMessagePack()`

**Operation:** `To MessagePack`

**Category:** `Data format`

**Module:** Code

Converts JSON to MessagePack encoded byte buffer. MessagePack is a computer data interchange format. It is a binary form for representing simple data structures like arrays and associative arrays.

[More info](https://wikipedia.org/wiki/MessagePack)

**Input:** `JSON` → **Output:** `ArrayBuffer`

---

### `ToModhex()`

**Operation:** `To Modhex`

**Category:** `Data format`

**Module:** Default

Converts the input string to modhex bytes separated by the specified delimiter.

[More info](https://en.wikipedia.org/wiki/YubiKey#ModHex)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Space`, `Percent`, `Comma` (+5 more)
  - **Bytes per line** (number): default ``

---

### `ToMorseCode()`

**Operation:** `To Morse Code`

**Category:** `Encryption / Encoding`

**Module:** Default

Translates alphanumeric characters into International Morse Code.

Ignores non-Morse characters.

e.g. `SOS` becomes `... --- ...`

[More info](https://wikipedia.org/wiki/Morse_code)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Format options** (option): `-/.`, `_/.`, `Dash/Dot` (+2 more)
  - **Letter delimiter** (option): `Space`, `Line feed`, `CRLF` (+5 more)
  - **Word delimiter** (option): `Line feed`, `CRLF`, `Forward slash` (+4 more)

---

### `ToOctal()`

**Operation:** `To Octal`

**Category:** `Data format`

**Module:** Default

Converts the input string to octal bytes separated by the specified delimiter.

e.g. The UTF-8 encoded string `Γειά σου` becomes `316 223 316 265 316 271 316 254 40 317 203 316 277 317 205`

[More info](https://wikipedia.org/wiki/Octal)

**Input:** `byteArray` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Space`, `Comma`, `Semi-colon` (+3 more)

---

### `ToPunycode()`

**Operation:** `To Punycode`

**Category:** `Data format`

**Module:** Encodings

Punycode is a way to represent Unicode with the limited character subset of ASCII supported by the Domain Name System.

e.g. `münchen` encodes to `mnchen-3ya`

[More info](https://wikipedia.org/wiki/Punycode)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Internationalised domain name** (boolean): default ``

---

### `ToQuotedPrintable()`

**Operation:** `To Quoted Printable`

**Category:** `Data format`

**Module:** Default

Quoted-Printable, or QP encoding, is an encoding using printable ASCII characters (alphanumeric and the equals sign '=') to transmit 8-bit data over a 7-bit data path or, generally, over a medium which is not 8-bit clean. It is defined as a MIME content transfer encoding for use in e-mail.

QP works by using the equals sign '=' as an escape character. It also limits line length to 76, as some software has limits on line length.

[More info](https://wikipedia.org/wiki/Quoted-printable)

**Input:** `ArrayBuffer` → **Output:** `string`

---

### `ToSnakeCase()`

**Operation:** `To Snake case`

**Category:** `Code tidy`

**Module:** Code

Converts the input string to snake case.

Snake case is all lower case with underscores as word boundaries.

e.g. this_is_snake_case

'Attempt to be context aware' will make the operation attempt to nicely transform variable and function names.

[More info](https://wikipedia.org/wiki/Snake_case)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Attempt to be context aware** (boolean): default ``

---

### `ToTable()`

**Operation:** `To Table`

**Category:** `Utils`

**Module:** Default

Data can be split on different characters and rendered as an HTML, ASCII or Markdown table with an optional header row.

Supports the CSV (Comma Separated Values) file format by default. Change the cell delimiter argument to `\t` to support TSV (Tab Separated Values) or `|` for PSV (Pipe Separated Values).

You can enter as many delimiters as you like. Each character will be treat as a separate possible delimiter.

[More info](https://wikipedia.org/wiki/Comma-separated_values)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Cell delimiters** (binaryShortString): default `,`
  - **Row delimiters** (binaryShortString): default `\\r\\n`
  - **Make first row header** (boolean): default ``
  - **Format** (option): `ASCII`, `HTML`, `Markdown`

---

### `ToUNIXTimestamp()`

**Operation:** `To UNIX Timestamp`

**Category:** `Date / Time`

**Module:** Default

Parses a datetime string in UTC and returns the corresponding UNIX timestamp.

e.g. `Mon 1 January 2001 11:00:00` becomes `978346800`

A UNIX timestamp is a 32-bit value representing the number of seconds since January 1, 1970 UTC (the UNIX epoch).

[More info](https://wikipedia.org/wiki/Unix_time)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Units** (option): `Seconds (s)`, `Milliseconds (ms)`, `Microseconds (μs)` (+1 more)
  - **Treat as UTC** (boolean): default `true`
  - **Show parsed datetime** (boolean): default `true`

---

### `ToUpperCase()`

**Operation:** `To Upper case`

**Category:** `Utils`

**Module:** Default

Converts the input string to upper case, optionally limiting scope to only the first character in each word, sentence or paragraph.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Scope** (option): `All`, `Word`, `Sentence` (+1 more)

---

### `TranslateDateTimeFormat()`

**Operation:** `Translate DateTime Format`

**Category:** `Date / Time`

**Module:** Default

Parses a datetime string in one format and re-writes it in another.

Run with no input to see the relevant format string examples.

[More info](https://momentjs.com/docs/#/parsing/string-format/)

**Input:** `string` → **Output:** `html`

**Arguments:**
  - **Built in formats** (populateOption): default `[{'name': 'Standard date and time', 'value': 'DD/MM/YYYY HH:mm:ss'}, {'name': 'American-style date and time', 'value': 'MM/DD/YYYY HH:mm:ss'}, {'name': 'International date and time', 'value': 'YYYY-MM-DD HH:mm:ss'}, {'name': 'Verbose date and time', 'value': 'dddd Do MMMM YYYY HH:mm:ss Z z'}, {'name': 'UNIX timestamp (seconds)', 'value': 'X'}, {'name': 'UNIX timestamp offset (milliseconds)', 'value': 'x'}, {'name': 'Automatic', 'value': ''}]`
  - **Input format string** (binaryString): default `DD/MM/YYYY HH:mm:ss`
  - **Input timezone** (option): `UTC`, `Africa/Abidjan`, `Africa/Accra` (+594 more)
  - **Output format string** (binaryString): default `dddd Do MMMM YYYY HH:mm:ss Z z`
  - **Output timezone** (option): `UTC`, `Africa/Abidjan`, `Africa/Accra` (+594 more)

---

### `TripleDESDecrypt()`

**Operation:** `Triple DES Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Triple DES applies DES three times to each block to increase key size.

Key: Triple DES uses a key length of 24 bytes (192 bits).

IV: The Initialization Vector should be 8 bytes long. If not entered, it will default to 8 null bytes.

Padding: In CBC and ECB mode, PKCS#7 padding will be used as a default.

[More info](https://wikipedia.org/wiki/Triple_DES)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Mode** (option): `CBC`, `CFB`, `OFB` (+4 more)
  - **Input** (option): `Hex`, `Raw`
  - **Output** (option): `Raw`, `Hex`

---

### `TripleDESEncrypt()`

**Operation:** `Triple DES Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Triple DES applies DES three times to each block to increase key size.

Key: Triple DES uses a key length of 24 bytes (192 bits).

You can generate a password-based key using one of the KDF operations.

IV: The Initialization Vector should be 8 bytes long. If not entered, it will default to 8 null bytes.

Padding: In CBC and ECB mode, PKCS#7 padding will be used.

[More info](https://wikipedia.org/wiki/Triple_DES)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **IV** (toggleString): default ``
  - **Mode** (option): `CBC`, `CFB`, `OFB` (+2 more)
  - **Input** (option): `Raw`, `Hex`
  - **Output** (option): `Hex`, `Raw`

---

### `Typex()`

**Operation:** `Typex`

**Category:** `Encryption / Encoding`

**Module:** Bletchley

Encipher/decipher with the WW2 Typex machine.

Typex was originally built by the British Royal Air Force prior to WW2, and is based on the Enigma machine with some improvements made, including using five rotors with more stepping points and interchangeable wiring cores. It was used across the British and Commonwealth militaries. A number of later variants were produced; here we simulate a WW2 era Mark 22 Typex with plugboards for the reflector and input. Typex rotors were changed regularly and none are public: a random example set are provided.

To configure the reflector plugboard, enter a string of connected pairs of letters in the reflector box, e.g. `AB CD EF` connects A to B, C to D, and E to F (you'll need to connect every letter). There is also an input plugboard: unlike Enigma's plugboard, it's not restricted to pairs, so it's entered like a rotor (without stepping). To create your own rotor, enter the letters that the rotor maps A to Z to, in order, optionally followed by `<` then a list of stepping points.

More detailed descriptions of the Enigma, Typex and Bombe operations can be found here.

[More info](https://wikipedia.org/wiki/Typex)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **1st (left-hand) rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+5 more)
  - **1st rotor reversed** (boolean): default ``
  - **1st rotor ring setting** (option): `A`, `B`, `C` (+23 more)
  - **1st rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **2nd rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+5 more); default `Example 2`
  - **2nd rotor reversed** (boolean): default ``
  - **2nd rotor ring setting** (option): `A`, `B`, `C` (+23 more)
  - **2nd rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **3rd (middle) rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+5 more); default `Example 3`
  - **3rd rotor reversed** (boolean): default ``
  - **3rd rotor ring setting** (option): `A`, `B`, `C` (+23 more)
  - **3rd rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **4th (static) rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+5 more); default `Example 4`
  - **4th rotor reversed** (boolean): default ``
  - **4th rotor ring setting** (option): `A`, `B`, `C` (+23 more)
  - **4th rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **5th (right-hand, static) rotor** (editableOption): `Example 1`, `Example 2`, `Example 3` (+5 more); default `Example 5`
  - **5th rotor reversed** (boolean): default ``
  - **5th rotor ring setting** (option): `A`, `B`, `C` (+23 more)
  - **5th rotor initial value** (option): `A`, `B`, `C` (+23 more)
  - **Reflector** (editableOption): `Example`
  - **Plugboard** (string): default ``
  - **Typex keyboard emulation** (option): `None`, `Encrypt`, `Decrypt`
  - **Strict output** (boolean): default `true`

---

### `UNIXTimestampToWindowsFiletime()`

**Operation:** `UNIX Timestamp to Windows Filetime`

**Category:** `Date / Time`

**Module:** Default

Converts a UNIX timestamp to a Windows Filetime value.

A Windows Filetime is a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 UTC.

A UNIX timestamp is a 32-bit value representing the number of seconds since January 1, 1970 UTC (the UNIX epoch).

This operation also supports UNIX timestamps in milliseconds, microseconds and nanoseconds.

[More info](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724284(v=vs.85).aspx)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Input units** (option): `Seconds (s)`, `Milliseconds (ms)`, `Microseconds (μs)` (+1 more)
  - **Output format** (option): `Decimal`, `Hex (big endian)`, `Hex (little endian)`

---

### `URLDecode()`

**Operation:** `URL Decode`

**Category:** `Data format`

**Module:** URL

Converts URI/URL percent-encoded characters back to their raw values.

e.g. `%3d` becomes `=`

[More info](https://wikipedia.org/wiki/Percent-encoding)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Treat "+" as space** (boolean): default `true`

---

### `URLEncode()`

**Operation:** `URL Encode`

**Category:** `Data format`

**Module:** URL

Encodes problematic characters into percent-encoding, a format supported by URIs/URLs.

e.g. `=` becomes `%3d`

[More info](https://wikipedia.org/wiki/Percent-encoding)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Encode all special chars** (boolean): default ``

---

### `UnescapeUnicodeCharacters()`

**Operation:** `Unescape Unicode Characters`

**Category:** `Data format`

**Module:** Default

Converts unicode-escaped character notation back into raw characters.

Supports the prefixes:`\u``%u``U+`e.g. `\u03c3\u03bf\u03c5` becomes `σου`

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Prefix** (option): `\u`, `%u`, `U+`

---

### `UnescapeString()`

**Operation:** `Unescape string`

**Category:** `Utils`

**Module:** Default

Unescapes characters in a string that have been escaped. For example, `Don\'t stop me now` becomes `Don't stop me now`.

Supports the following escape sequences:`\n` (Line feed/newline)`\r` (Carriage return)`\t` (Horizontal tab)`\b` (Backspace)`\f` (Form feed)`\nnn` (Octal, where n is 0-7)`\xnn` (Hex, where n is 0-f)`\\` (Backslash)`\'` (Single quote)`\"` (Double quote)`\unnnn` (Unicode character)`\u{nnnnnn}` (Unicode code point)

[More info](https://wikipedia.org/wiki/Escape_sequence)

**Input:** `string` → **Output:** `string`

---

### `UnicodeTextFormat()`

**Operation:** `Unicode Text Format`

**Category:** `Language`

**Module:** Default

Adds Unicode combining characters to change formatting of plaintext.

[More info](https://wikipedia.org/wiki/Combining_character)

**Input:** `byteArray` → **Output:** `byteArray`

**Arguments:**
  - **Underline** (boolean): default `false`
  - **Strikethrough** (boolean): default `false`

---

### `Unique()`

**Operation:** `Unique`

**Category:** `Utils`

**Module:** Default

Removes duplicate strings from the input.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Delimiter** (option): `Line feed`, `CRLF`, `Space` (+4 more)
  - **Display count** (boolean): default ``

---

### `Untar()`

**Operation:** `Untar`

**Category:** `Compression`

**Module:** Compression

Unpacks a tarball and displays it per file.

[More info](https://wikipedia.org/wiki/Tar_(computing))

**Input:** `ArrayBuffer` → **Output:** `html`

---

### `Unzip()`

**Operation:** `Unzip`

**Category:** `Compression`

**Module:** Compression

Decompresses data using the PKZIP algorithm and displays it per file, with support for passwords.

[More info](https://wikipedia.org/wiki/Zip_(file_format))

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Password** (binaryString): default ``
  - **Verify result** (boolean): default ``

---

### `VarIntDecode()`

**Operation:** `VarInt Decode`

**Category:** `Networking`

**Module:** Default

Decodes a VarInt encoded integer. VarInt is an efficient way of encoding variable length integers and is commonly used with Protobuf.

[More info](https://developers.google.com/protocol-buffers/docs/encoding#varints)

**Input:** `byteArray` → **Output:** `string`

---

### `VarIntEncode()`

**Operation:** `VarInt Encode`

**Category:** `Networking`

**Module:** Default

Encodes a Vn integer as a VarInt. VarInt is an efficient way of encoding variable length integers and is commonly used with Protobuf.

[More info](https://developers.google.com/protocol-buffers/docs/encoding#varints)

**Input:** `string` → **Output:** `byteArray`

---

### `ViewBitPlane()`

**Operation:** `View Bit Plane`

**Category:** `Forensics`

**Module:** Image

Extracts and displays a bit plane of any given image. These show only a single bit from each pixel, and can be used to hide messages in Steganography.

[More info](https://wikipedia.org/wiki/Bit_plane)

**Input:** `ArrayBuffer` → **Output:** `html`

**Arguments:**
  - **Colour** (option): `Red`, `Green`, `Blue` (+1 more)
  - **Bit** (number): default ``

---

### `VigenereDecode()`

**Operation:** `Vigenère Decode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

The Vigenere cipher is a method of encrypting alphabetic text by using a series of different Caesar ciphers based on the letters of a keyword. It is a simple form of polyalphabetic substitution.

[More info](https://wikipedia.org/wiki/Vigenère_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (string): default ``

---

### `VigenereEncode()`

**Operation:** `Vigenère Encode`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

The Vigenere cipher is a method of encrypting alphabetic text by using a series of different Caesar ciphers based on the letters of a keyword. It is a simple form of polyalphabetic substitution.

[More info](https://wikipedia.org/wiki/Vigenère_cipher)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (string): default ``

---

### `Whirlpool()`

**Operation:** `Whirlpool`

**Category:** `Hashing`

**Module:** Crypto

Whirlpool is a cryptographic hash function designed by Vincent Rijmen (co-creator of AES) and Paulo S. L. M. Barreto, who first described it in 2000.

Several variants exist:Whirlpool-0 is the original version released in 2000.Whirlpool-T is the first revision, released in 2001, improving the generation of the s-box.Whirlpool is the latest revision, released in 2003, fixing a flaw in the diffusion matrix.

[More info](https://wikipedia.org/wiki/Whirlpool_(cryptography))

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Variant** (option): `Whirlpool`, `Whirlpool-T`, `Whirlpool-0`
  - **Rounds** (number): default `10`

---

### `WindowsFiletimeToUNIXTimestamp()`

**Operation:** `Windows Filetime to UNIX Timestamp`

**Category:** `Date / Time`

**Module:** Default

Converts a Windows Filetime value to a UNIX timestamp.

A Windows Filetime is a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 UTC.

A UNIX timestamp is a 32-bit value representing the number of seconds since January 1, 1970 UTC (the UNIX epoch).

This operation also supports UNIX timestamps in milliseconds, microseconds and nanoseconds.

[More info](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724284(v=vs.85).aspx)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Output units** (option): `Seconds (s)`, `Milliseconds (ms)`, `Microseconds (μs)` (+1 more)
  - **Input format** (option): `Decimal`, `Hex (big endian)`, `Hex (little endian)`

---

### `XKCDRandomNumber()`

**Operation:** `XKCD Random Number`

**Category:** `Other`

**Module:** Default

RFC 1149.5 specifies 4 as the standard IEEE-vetted random number.

[More info](https://xkcd.com/221/)

**Input:** `string` → **Output:** `number`

---

### `XMLBeautify()`

**Operation:** `XML Beautify`

**Category:** `Code tidy`

**Module:** Code

Indents and prettifies eXtensible Markup Language (XML) code.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Indent string** (binaryShortString): default `\\t`

---

### `XMLMinify()`

**Operation:** `XML Minify`

**Category:** `Code tidy`

**Module:** Code

Compresses eXtensible Markup Language (XML) code.

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Preserve comments** (boolean): default ``

---

### `XOR()`

**Operation:** `XOR`

**Category:** `Encryption / Encoding`

**Module:** Default

XOR the input with the given key.
e.g. `fe023da5`

Options
Null preserving: If the current byte is 0x00 or the same as the key, skip it.

Scheme:Standard - key is unchanged after each roundInput differential - key is set to the value of the previous unprocessed byteOutput differential - key is set to the value of the previous processed byteCascade - key is set to the input byte shifted by one

[More info](https://wikipedia.org/wiki/XOR)

**Input:** `ArrayBuffer` → **Output:** `byteArray`

**Arguments:**
  - **Key** (toggleString): default ``
  - **Scheme** (option): `Standard`, `Input differential`, `Output differential` (+1 more)
  - **Null preserving** (boolean): default ``

---

### `XORBruteForce()`

**Operation:** `XOR Brute Force`

**Category:** `Encryption / Encoding`

**Module:** Default

Enumerate all possible XOR solutions. Current maximum key length is 2 due to browser performance.

Optionally enter a string that you expect to find in the plaintext to filter results (crib).

[More info](https://wikipedia.org/wiki/Exclusive_or)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Key length** (number): default `1`
  - **Sample length** (number): default `100`
  - **Sample offset** (number): default ``
  - **Scheme** (option): `Standard`, `Input differential`, `Output differential`
  - **Null preserving** (boolean): default ``
  - **Print key** (boolean): default `true`
  - **Output as hex** (boolean): default ``
  - **Crib (known plaintext string)** (binaryString): default ``

---

### `XORChecksum()`

**Operation:** `XOR Checksum`

**Category:** `Hashing`

**Module:** Crypto

XOR Checksum splits the input into blocks of a configurable size and performs the XOR operation on these blocks.

[More info](https://wikipedia.org/wiki/XOR)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Blocksize** (number): default `4`

---

### `XPathExpression()`

**Operation:** `XPath expression`

**Category:** `Extractors`

**Module:** Code

Extract information from an XML document with an XPath query

[More info](https://wikipedia.org/wiki/XPath)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **XPath** (string): default ``
  - **Result delimiter** (binaryShortString): default `\\n`

---

### `XSalsa20()`

**Operation:** `XSalsa20`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

XSalsa20 is a variant of the Salsa20 stream cipher designed by Daniel J. Bernstein; XSalsa uses longer nonces.

Key: XSalsa20 uses a key of 16 or 32 bytes (128 or 256 bits).

Nonce: XSalsa20 uses a nonce of 24 bytes (192 bits).

Counter: XSalsa uses a counter of 8 bytes (64 bits). The counter starts at zero at the start of the keystream, and is incremented at every 64 bytes.

[More info](https://en.wikipedia.org/wiki/Salsa20#XSalsa20_with_192-bit_nonce)

**Input:** `string` → **Output:** `string`

**Arguments:**
  - **Key** (toggleString): default ``
  - **Nonce** (toggleString): default ``
  - **Counter** (number): default ``
  - **Rounds** (option): `20`, `12`, `8`
  - **Input** (option): `Hex`, `Raw`
  - **Output** (option): `Raw`, `Hex`

---

### `XXTEADecrypt()`

**Operation:** `XXTEA Decrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Corrected Block TEA (often referred to as XXTEA) is a block cipher designed to correct weaknesses in the original Block TEA. XXTEA operates on variable-length blocks that are some arbitrary multiple of 32 bits in size (minimum 64 bits). The number of full cycles depends on the block size, but there are at least six (rising to 32 for small block sizes). The original Block TEA applies the XTEA round function to each word in the block and combines it additively with its leftmost neighbour. Slow diffusion rate of the decryption process was immediately exploited to break the cipher. Corrected Block TEA uses a more involved round function which makes use of both immediate neighbours in processing each word in the block.

[More info](https://wikipedia.org/wiki/XXTEA)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Key** (toggleString): default ``

---

### `XXTEAEncrypt()`

**Operation:** `XXTEA Encrypt`

**Category:** `Encryption / Encoding`

**Module:** Ciphers

Corrected Block TEA (often referred to as XXTEA) is a block cipher designed to correct weaknesses in the original Block TEA. XXTEA operates on variable-length blocks that are some arbitrary multiple of 32 bits in size (minimum 64 bits). The number of full cycles depends on the block size, but there are at least six (rising to 32 for small block sizes). The original Block TEA applies the XTEA round function to each word in the block and combines it additively with its leftmost neighbour. Slow diffusion rate of the decryption process was immediately exploited to break the cipher. Corrected Block TEA uses a more involved round function which makes use of both immediate neighbours in processing each word in the block.

[More info](https://wikipedia.org/wiki/XXTEA)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Key** (toggleString): default ``

---

### `YAMLToJSON()`

**Operation:** `YAML to JSON`

**Category:** `Data format`

**Module:** Default

Convert YAML to JSON

[More info](https://en.wikipedia.org/wiki/YAML)

**Input:** `string` → **Output:** `JSON`

---

### `YARARules()`

**Operation:** `YARA Rules`

**Category:** `Forensics`

**Module:** Yara

**Support:** Unsupported in the current STPyV8 runtime.

YARA is a tool developed at VirusTotal, primarily aimed at helping malware researchers to identify and classify malware samples. It matches based on rules specified by the user containing textual or binary patterns and a boolean expression. For help on writing rules, see the YARA documentation.

[More info](https://wikipedia.org/wiki/YARA)

**Input:** `ArrayBuffer` → **Output:** `string`

**Arguments:**
  - **Rules** (text)
  - **Show strings** (boolean): default ``
  - **Show string lengths** (boolean): default ``
  - **Show metadata** (boolean): default ``
  - **Show counts** (boolean): default `true`
  - **Show rule warnings** (boolean): default `true`
  - **Show console module messages** (boolean): default `true`

---

### `Zip()`

**Operation:** `Zip`

**Category:** `Compression`

**Module:** Compression

Compresses data using the PKZIP algorithm with the given filename.

No support for multiple files at this time.

[More info](https://wikipedia.org/wiki/Zip_(file_format))

**Input:** `ArrayBuffer` → **Output:** `File`

**Arguments:**
  - **Filename** (string): default `file.txt`
  - **Comment** (string): default ``
  - **Password** (binaryString): default ``
  - **Compression method** (option): `Deflate`, `None (Store)`
  - **Operating system** (option): `MSDOS`, `Unix`, `Macintosh`
  - **Compression type** (option): `Dynamic Huffman Coding`, `Fixed Huffman Coding`, `None (Store)`

---

### `ZlibDeflate()`

**Operation:** `Zlib Deflate`

**Category:** `Compression`

**Module:** Compression

Compresses data using the deflate algorithm adding zlib headers.

[More info](https://wikipedia.org/wiki/Zlib)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Compression type** (option): `Dynamic Huffman Coding`, `Fixed Huffman Coding`, `None (Store)`

---

### `ZlibInflate()`

**Operation:** `Zlib Inflate`

**Category:** `Compression`

**Module:** Compression

Decompresses data which has been compressed using the deflate algorithm with zlib headers.

[More info](https://wikipedia.org/wiki/Zlib)

**Input:** `ArrayBuffer` → **Output:** `ArrayBuffer`

**Arguments:**
  - **Start index** (number): default ``
  - **Initial output buffer size** (number): default ``
  - **Buffer expansion type** (option): `Adaptive`, `Block`
  - **Resize buffer after decompression** (boolean): default ``
  - **Verify result** (boolean): default ``

---
