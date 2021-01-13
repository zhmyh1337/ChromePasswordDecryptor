Decryptor for your own chrome passwords.
Parses all the passwords from "Login Data" using the key from "Local State".
This only works on the original computer because of the `CryptUnprotectData`.

Dependencies:\
`Base64` (for base64 decryption).\
`cJSON` (for working with json files).\
`openssl` (for AES-GCM decryption).\
`sqlite3` (for working with sql db).
