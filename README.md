# Twilio Recordings Decrypter

This program downloads and decrypts media files recorded and encrypted using Twilio's Programmable Video Recording capabilities. For further information check the [Twilio Video Recording Encryption Documentation](https://www.twilio.com/docs/api/video/encrypting-your-video-recordings)

### PRE-REQUISITES

* Java 8.
* If you are using Oracle's JDK, you need have installed the [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)
in your system.

## Usage

The program requires the following arguments
* The Encrypted Recording Track SID. This is a string with the form `RTxx` where `xx` is a 32 bytes alphanumeric code.
* Your Twilio's API key and secret (`SKxx:API_SECRET`)
* The private key corresponding to the public key used by Twilio for encrypting the file. This key must be encoded according to the PKCS #8 standard. If you generated the key pair with `openssl`, you'll need to execute the following command
  ```
  openssl pkcs8 -in private_key.pem -topk8 -nocrypt -out private_key_pkcs8.pem
  ```
* The filename where the decrypted media will be stored.

1. Compile the project
    ```
    mvn clean package
    ```
2. Execute the jar file with the appropriate arguments
    ```
    java -jar target/twilio-recordings-decrypter.jar SKxx:API_SECRET RTxx privatekey-pkcs8.pem decrypted-filename.webm
    ```
