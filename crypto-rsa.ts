
import { KeyObject, constants, generateKeyPairSync, privateDecrypt, publicEncrypt, sign, verify } from "crypto";

function main() {
    // Generamos las claves pública y privada
    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
        // La longitud estándar para claves RSA es de 2048 bits
        modulusLength: 2048,
      });

      signData(publicKey, privateKey);
      encryptData(publicKey, privateKey);
}

function signData(publicKey: KeyObject, privateKey: KeyObject) {
    console.log("RSA para firmar datos \n")

    const data = "Este es el mensaje que se va a cifrar";

    const encryptedData = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    // Se convierte el string a buffer
    Buffer.from(data)
    );

    // Vemos el mensaje cifrado en base64
    console.log(`Mensaje cifrado: ${encryptedData.toString("base64")} \n`);

    const decryptedData = privateDecrypt(
        {
          key: privateKey,
          // Para descifrar los datos, especificamos la misma función hash y padding que los que utilizamos para el cifrado
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        encryptedData
      );
      
      // Vemos el mensaje descifrado en formato string
      console.log(`Mensaje descifrado: ${decryptedData.toString()} \n`);


}

function encryptData(publicKey: KeyObject, privateKey: KeyObject) {
    console.log("RSA para cifrar datos \n");

    const data = "Este es el mensaje a firmar";

    // Firmamos el mensaje
    const signature = sign("sha256", Buffer.from(data), {
        key: privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
      });
      
      // Vemos el mensaje firmado
      console.log(`Mensaje firmado: ${signature.toString("base64")} \n`);
      
      // Para descifrar los datos, especificamos la misma función hash y padding que los que utilizamos para el cifrado
      const isVerified = verify(
        "sha256",
        Buffer.from(data),
        {
          key: publicKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
        },
        signature
      );
      
      // Vemos si el mensaje firmado ha sido verificado o no
      console.log(`¿Mensaje verificado? ${isVerified}`);
}

main();