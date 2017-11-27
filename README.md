# Twilio Recordings Decrypter

This program downloads a Twilio Video Track Recording file. The track is downloaded from the location pointed to by the 
`Media` resource from the Room Recordings REST API. Tracks are encrypted with an asymmetric key, so the you'll need to 
provide the private key from the pair that was used to encrypt the recording.


## Usage

The program requires the following arguments
* The Recording Track SID. This is a string with a 32-digit number preceded by the letters `RT`
* An API secret and key (`SKxxxx:API_SECRET`)
* A text file containing the private key from the asymmetric pair used to encrypt the recording. This key must be 
encoded according to the PKCS#8 standard.If you have generated the keypair with `openssl`, it will be in PKCS#1 format.
In order to convert it to PKCS#8 format, you'll need to execute the following command 
    ```
    openssl pkcs8 -in privatekey.pem -topk8 -nocrypt -out privatekey-pkcs8.pem
    ```
* The location where you want the plain recording track to be downloaded.

1. Compile the project
    ```
    mvn clean package
    ```
2. Execute the jar file with the appropriate arguments
    ```
    java -jar target/twilio-recordings-decrypter.jar SKxxxx:API_SECRET RTxx privatekey-pkcs8.pem decrypted_video_file.mkv