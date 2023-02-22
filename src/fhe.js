/* -------------------------------------------------------------------------- */
/*                                 Imports                                    */
/* -------------------------------------------------------------------------- */
const SEAL = require('node-seal');
const fs = require('fs');

/* -------------------------------------------------------------------------- */
/*                                 Constants                                  */
/* -------------------------------------------------------------------------- */
// Strings -> BFV
const polyModulusDegreeString = 4096;
const bitSizesString = [36, 36, 37];
const bitSizeString = 20;
// Numbers -> CKKS
const polyModulusDegreeNumeric = 8192;
const bitSizesNumeric = [59, 43, 43, 59];
const bitSizeNumeric = 43;
const scale = Math.pow(2.0, bitSizeNumeric);

/* -------------------------------------------------------------------------- */
/*                              Local Functions                               */
/* -------------------------------------------------------------------------- */
const stringToByteArray = (s) => {
    var result = new Uint32Array(s.length);
    for (var i=0; i<s.length; i++){
        result[i] = s.charCodeAt(i);
    }
    return result;
}

const byteArrayToString = (array) => {
    var result = String.fromCharCode(...array);
    return result;
}

/* -------------------------------------------------------------------------- */
/*                              Key Generation                                */
/* -------------------------------------------------------------------------- */
exports.generateSecretKeys = async () => {
    // Init SEAL
    let seal = await SEAL();
    
    // Parms
    const parmsNumeric = seal.EncryptionParameters(seal.SchemeType.ckks);
    const parmsString = seal.EncryptionParameters(seal.SchemeType.bfv);
    
    // PolyModulus Degree
    parmsNumeric.setPolyModulusDegree(polyModulusDegreeNumeric);
    parmsString.setPolyModulusDegree(polyModulusDegreeString);
    
    // Coefficient Modulus Primes
    parmsNumeric.setCoeffModulus(
        seal.CoeffModulus.Create(polyModulusDegreeNumeric, Int32Array.from(bitSizesNumeric))
    );
    parmsString.setCoeffModulus(
        seal.CoeffModulus.Create(polyModulusDegreeString, Int32Array.from(bitSizesString))
    );

    // PlainModulus for the Strings
    parmsString.setPlainModulus(
        seal.PlainModulus.Batching(polyModulusDegreeString, bitSizeString)
    );
    
    // Create context
    let contextNumeric = seal.Context(
        parmsNumeric, // Encryption Parameters
        true, // ExpandModChain
        seal.SecurityLevel.tc128 // Enforce a security level
    );
    let contextString = seal.Context(
        parmsString,
        true,
        seal.SecurityLevel.tc128
    );

    // Check correctness and return context
    if (!contextNumeric.parametersSet() || !contextString.parametersSet()) {
        console.log('Error setting FHE parameters');
        return false;
    } else {
        // Numbers
        const keyGeneratorNumeric = seal.KeyGenerator(contextNumeric);
        const secretKeyNumeric = keyGeneratorNumeric.secretKey();
        const secretBase64Key = secretKeyNumeric.save();
        // Strings
        const keyGeneratorString = seal.KeyGenerator(contextString);
        const secretKeyString = keyGeneratorString.secretKey();
        const secretBase64KeyString = secretKeyString.save();

        try {
            const numericKeyExists = fs.readFileSync('./keys/sk_numeric.txt', 'utf-8');
            const stringKeyExists = fs.readFileSync('./keys/sk_str.txt', 'utf-8');

            if (!numericKeyExists || !stringKeyExists) {
                fs.writeFileSync('./keys/sk_numeric.txt', secretBase64Key, 'utf-8');
                fs.writeFileSync('./keys/sk_str.txt', secretBase64KeyString, 'utf-8');
            }
        }
        catch (e) { console.log(e); return false; }

        return true;
    }
}

/* -------------------------------------------------------------------------- */
/*                                 Encryption                                 */
/* -------------------------------------------------------------------------- */
exports.encryptString = async (data) => {
    // Init SEAL
    let seal = await SEAL();
    // Scheme Type
    const schemeType = seal.SchemeType.bfv;
    // Parms
    const parms = seal.EncryptionParameters(schemeType);
    // PolyModulus Degree
    parms.setPolyModulusDegree(polyModulusDegreeString);
    // Coefficient Modulus Primes
    parms.setCoeffModulus(
        seal.CoeffModulus.Create(
            polyModulusDegreeString, 
            Int32Array.from(bitSizesString))
    );
    // PlainModulus for the Strings
    parms.setPlainModulus(
        seal.PlainModulus.Batching(polyModulusDegreeString, bitSizeString)
    );
    // Context
    let context = seal.Context(
        parms, // Encryption Parameters
        true, // ExpandModChain
        seal.SecurityLevel.tc128 // Enforce a security level
    );

    // Obtain local SEAL objects
    const encoder = seal.BatchEncoder(context);
    // Create the Encryptor
    let encryptor;
    try {
        // Obtain the Private Key
        const path = './keys/sk_str.txt';
        const secretKeyBase64 = fs.readFileSync(path, 'utf-8');
        const secretKey = seal.SecretKey();
        secretKey.load(context, secretKeyBase64);
        // Create a Public Key
        const keyGenerator = seal.KeyGenerator(context, secretKey);
        const publicKey = keyGenerator.createPublicKey();
        // Return
        encryptor = seal.Encryptor(context, publicKey, secretKey);
    }
    catch (e) { console.log(e); return; }

    // Convert data to Byte Array
    const byteArray = stringToByteArray(data + '$');
    // Encoding
    const plainText = seal.PlainText();
    const sealArray = Uint32Array.from(byteArray);
    encoder.encode(sealArray, plainText);
    // Encryption
    const cipherText = encryptor.encryptSymmetric(plainText);
    const cipherTextBase64 = cipherText.save();
    // Clean memory
    plainText.delete();
    cipherText.delete();
    // Return
    return cipherTextBase64;
}

exports.encryptNumber = async (data) => {
    // Init SEAL
    let seal = await SEAL();
    // Scheme Type
    const schemeType = seal.SchemeType.ckks;
    // Parms
    const parms = seal.EncryptionParameters(schemeType);
    // PolyModulus Degree
    parms.setPolyModulusDegree(polyModulusDegreeNumeric);
    // Coefficient Modulus Primes
    parms.setCoeffModulus(
        seal.CoeffModulus.Create(
            polyModulusDegreeNumeric, 
            Int32Array.from(bitSizesNumeric))
    );
    // Context
    let context = seal.Context(
        parms, // Encryption Parameters
        true, // ExpandModChain
        seal.SecurityLevel.tc128 // Enforce a security level
    );

    // Obtain local SEAL objects
    const encoder = seal.CKKSEncoder(context);
    // Create the Encryptor
    let encryptor;
    try {
        // Obtain the Private Key
        const path = './keys/sk_numeric.txt';
        const secretKeyBase64 = fs.readFileSync(path, 'utf-8');
        const secretKey = seal.SecretKey();
        secretKey.load(context, secretKeyBase64);
        // Create a Public Key
        const keyGenerator = seal.KeyGenerator(context, secretKey);
        const publicKey = keyGenerator.createPublicKey();
        // Return
        encryptor = seal.Encryptor(context, publicKey, secretKey);
    }
    catch (e) { console.log(e); return; }

    // Encoding
    const plainText = seal.PlainText();
    const sealArray = Float64Array.from([data]);
    encoder.encode(sealArray, scale, plainText);
    // Encryption
    const cipherText = encryptor.encryptSymmetric(plainText);
    const cipherTextBase64 = cipherText.save();
    // Clean memory
    plainText.delete();
    cipherText.delete();
    // Return
    return cipherTextBase64;
}

/* -------------------------------------------------------------------------- */
/*                                 Decryption                                 */
/* -------------------------------------------------------------------------- */
exports.decryptString = async (enc) => {
    // Init SEAL
    let seal = await SEAL();
    // Parms
    const parms = seal.EncryptionParameters(seal.SchemeType.bfv);
    // PolyModulus Degree
    parms.setPolyModulusDegree(polyModulusDegreeString);
    // Coefficient Modulus Primes
    parms.setCoeffModulus(
        seal.CoeffModulus.Create(polyModulusDegreeString, Int32Array.from(bitSizesString))
    );
    // PlainModulus for the Strings
    parms.setPlainModulus(
        seal.PlainModulus.Batching(polyModulusDegreeString, bitSizeString)
    );
    // Context
    let context = seal.Context(
        parms, // Encryption Parameters
        true, // ExpandModChain
        seal.SecurityLevel.tc128 // Enforce a security level
    );

    // Obtain local SEAL objects
    const encoder = seal.BatchEncoder(context);
    // Create the Encryptor
    let decryptor;
    try {
        // Obtain the Private Key
        const path = './keys/sk_str.txt';
        const secretKeyBase64 = fs.readFileSync(path, 'utf-8');
        const secretKey = seal.SecretKey();
        secretKey.load(context, secretKeyBase64);
        // Return
        decryptor = seal.Decryptor(context, secretKey);
    }
    catch (e) { console.log(e); return; }

    // Decryption
    const encrypted = seal.CipherText();
    encrypted.load(context, enc);
    const decryptedPlainText = decryptor.decrypt(encrypted);
    // Decoding
    const decoded = encoder.decode(decryptedPlainText);
    // Clean memory
    encrypted.delete();
    decryptedPlainText.delete();
    // Return
    return byteArrayToString(decoded).substring(0, byteArrayToString(decoded).indexOf('$'))
}

exports.decryptNumber = async (enc) => {
    // Init SEAL
    let seal = await SEAL();
    // Scheme Type
    const schemeType = seal.SchemeType.ckks;
    // Parms
    const parms = seal.EncryptionParameters(schemeType);
    // PolyModulus Degree
    parms.setPolyModulusDegree(polyModulusDegreeNumeric);
    // Coefficient Modulus Primes
    parms.setCoeffModulus(
        seal.CoeffModulus.Create(
            polyModulusDegreeNumeric, 
            Int32Array.from(bitSizesNumeric))
    );
    // Context
    let context = seal.Context(
        parms, // Encryption Parameters
        true, // ExpandModChain
        seal.SecurityLevel.tc128 // Enforce a security level
    );

    // Obtain local SEAL objects
    const encoder = seal.CKKSEncoder(context);
    // Create the Encryptor
    let decryptor;
    try {
        // Obtain the Private Key
        const path = './keys/sk_numeric.txt';
        const secretKeyBase64 = fs.readFileSync(path, 'utf-8');
        const secretKey = seal.SecretKey();
        secretKey.load(context, secretKeyBase64);
        // Return
        decryptor = seal.Decryptor(context, secretKey);

    }
    catch (e) { console.log(e); return; }

    // Decryption
    const encrypted = seal.CipherText();
    encrypted.load(context, enc);
    const decryptedPlainText = decryptor.decrypt(encrypted);
    // Decoding
    const decoded = encoder.decode(decryptedPlainText);
    // Clean memory
    encrypted.delete();
    decryptedPlainText.delete();
    // Return
    return decoded[0];
}

/* -------------------------------------------------------------------------- */
/*                                   Average                                  */
/* -------------------------------------------------------------------------- */
exports.computeAvgFuel = async (array) => {
    // Init SEAL
    let seal = await SEAL();
    // Scheme Type
    const schemeType = seal.SchemeType.ckks;
    // Parms
    const parms = seal.EncryptionParameters(schemeType);
    // PolyModulus Degree
    parms.setPolyModulusDegree(polyModulusDegreeNumeric);
    // Coefficient Modulus Primes
    parms.setCoeffModulus(
        seal.CoeffModulus.Create(
            polyModulusDegreeNumeric, 
            Int32Array.from(bitSizesNumeric))
    );
    // Context
    let context = seal.Context(
        parms, // Encryption Parameters
        true, // ExpandModChain
        seal.SecurityLevel.tc128 // Enforce a security level
    );

    // Homomorphic evaluator
    const evaluator = seal.Evaluator(context);

    // Iterate through the json
    let encryptedArray = [];
    array.forEach(encHR => {
        const uploadedCipherText = seal.CipherText();
        try {
            uploadedCipherText.load(context, encHR);
        }
        catch (err) { console.log(err) }
        encryptedArray.push(uploadedCipherText);
    });

    var cipherTextAvg = null;
    cipherTextAvg = evaluator.add(encryptedArray[0], encryptedArray[1]);
    for (let i = 2; i < array.length; i++) {
        evaluator.add(encryptedArray[i], cipherTextAvg, cipherTextAvg);
    }

    if (cipherTextAvg != null) {
        return cipherTextAvg.save();
    } else { return null }
}
