/* -------------------------------------------------------------------------- */
/*                                 Imports                                    */
/* -------------------------------------------------------------------------- */
const SEAL = require('node-seal');
const fs = require('fs');

/* -------------------------------------------------------------------------- */
/*                                 Constants                                  */
/* -------------------------------------------------------------------------- */
// Numbers -> CKKS
const polyModulusDegreeNumeric = 8192;
const bitSizesNumeric = [59, 43, 43, 59];
const bitSizeNumeric = 43;
const scale = Math.pow(2.0, bitSizeNumeric);

/* -------------------------------------------------------------------------- */
/*                               FHE Functions                                */
/* -------------------------------------------------------------------------- */
exports.generateSecretKeys = async () => {
    // Init SEAL
    let seal = await SEAL();
    
    // Parms
    const parmsNumeric = seal.EncryptionParameters(seal.SchemeType.ckks);
    
    // PolyModulus Degree
    parmsNumeric.setPolyModulusDegree(polyModulusDegreeNumeric);
    
    // Coefficient Modulus Primes
    parmsNumeric.setCoeffModulus(
        seal.CoeffModulus.Create(polyModulusDegreeNumeric, Int32Array.from(bitSizesNumeric))
    );
    
    // Create context
    let contextNumeric = seal.Context(
        parmsNumeric, // Encryption Parameters
        true, // ExpandModChain
        seal.SecurityLevel.tc128 // Enforce a security level
    );

    // Check correctness and return context
    if (!contextNumeric.parametersSet()) {
        console.log('Error setting FHE parameters');
        return false;
    } else {
        // Numbers
        const keyGeneratorNumeric = seal.KeyGenerator(contextNumeric);
        const secretKeyNumeric = keyGeneratorNumeric.secretKey();
        const secretBase64Key = secretKeyNumeric.save();

        try {
            const numericKeyExists = fs.readFileSync('./keys/sk_numeric.txt', 'utf-8');

            if (!numericKeyExists) {
                fs.writeFileSync('./keys/sk_numeric.txt', secretBase64Key, 'utf-8');
            }
        }
        catch (e) { console.log(e); return false; }

        return true;
    }
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
exports.computeAvgHR = async (array) => {
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
