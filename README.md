# Base64_Encryptor
It is difficult to overestimate the importance of the Base64 algorithm in modern systems. Each attachment in an email, a textual representation of binary data in databases, is part of communication protocols. And all this is open to any hacker, to anyone who wants to intercept your messages and gain access to your documents, media files, applications and any other forms of binary data presented in text form. The goal of this project is to develop a variant of the Base64 algorithm that would allow data to be encrypted and decrypted during the encoding and decoding process. Without compromising performance and without increasing the memory required for encoding. The initial code will be developed in C, but as we work on the project we will add implementations in other languages with cross-testing to ensure unification of the algorithm implementation for different platforms and systems. C version is the main and basic version of this project. It might contain features which are not yet implemented in other languages.

Main Features:

1. Full support for regular Base64 encoding and all known variants if no key is specified.
2. Loadable alphabet to support any Base64 encoding variant with constants for the STANDARD, URL, QWERTY, IMAP, HQX, CRYPT, GEDCOM, BCRYPT, XX and BASH alphabets.
3. Shuffling encryption of any key length
4. Ability to use int[] of any length and string of any length as an encryption key.
5. A "gluing" technique to better dissipate ciphertext and protect integrity.
6. Padding mode ON/OFF
7. Allow ciphertext to be split into any line length with MIME and PEM text widths as constants.
8. Support for streaming and calling the function once for a full buffer. For accurate streaming and processing of internal states, use buffers that are a dividable on 3*4. For most File Systems ideal would be buffers block size multyplied by 3. For example (4096*3).
9. Internal states for streaming and a reset() function to reset internal states.
10. Using automatic alphabet indexing as an encoding and decoding method. There is no alphabet specific code.
11. Functions for estimating the size of the encoded and decoded buffer. Note that it is not obvious to predict the exact size, since there are functions to enable/disable padding and line splitting. Use buffers extended by a small number of bytes to ensure sufficiency.
