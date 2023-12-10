# Base64_Encryptor
It is difficult to overestimate the importance of the Base64 algorithm in modern systems. Each attachment in an email, a textual representation of binary data in databases, is part of communication protocols. And all this is open to any hacker, to anyone who wants to intercept your messages and gain access to your documents, media files, applications and any other forms of binary data presented in text form. The goal of this project is to develop a variant of the Base64 algorithm that would allow data to be encrypted and decrypted during the encoding and decoding process. Without compromising performance and without increasing the memory required for encoding. The initial code will be developed in C, but as we work on the project we will add implementations in other languages with cross-testing to ensure unification of the algorithm implementation for different platforms and systems. C version is the main and basic version of this project. It might contain features which are not yet implemented in other languages.

Main Features:
1. Full support for regular Base64 encoding and all its known variants if Key is not provided
2. Loadable Alphabet to support any variant of Base64 encoding with constants for STANDARD, URL, QWERTY, IMAP, HQX, CRYPT, GEDCOM, BCRYPT, XX and BASH alphabets.
3. Any Key length shuffling encryption
4. Ability to use int[] of any lenth and string of any length as encryption key
5. "Glue" method for better encrypted text scattering and integrity protection
6. Padding mode ON/OFF
7. Allowing encrypted text splitting on any line length with MIME and PEM text width as constants
8. Support for streaming and one time function call on complete buffer. For accurate streaming and inner states handling please use buffers of a size dividable on 3*4.
9. Inner states for streaming and reset() function to reset inner states.
10. Using alphabet automatic indexing as encoding and decoding method. No alphabet specific code.
11. Functions for encoded and decoded buffer size estimations. Please note, it is not obvious to predict the exact size, since there are padding On/Off and line splitting features. Use buffers extended on a little number of bytes to ensure the sufficiency.
