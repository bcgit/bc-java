package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * @author suraj0208
 * github.com/suraj0208
 * <p>
 * Given a Private Key file this class can be used to identify the private key type,
 * which can be PKCS#1 or PKCS#8 and get java.security.PrivateKey object from the file.
 * This class is analogous to java.security.cert.CertificateFactory therefore can be used to contrust
 * java.security.PrivateKey object without having to know the type, encoding of the private key.
 * <p>
 * <p>
 * The getJCEPrivateKey* functions return a java.security.PrivateKey object from given file/object.
 * <p>
 * <p>
 * getPrivateKeyType functions can be used to determine the private key type.
 */

public class JCEPrivateKeyFactory {
    public enum PrivateKeyType {
        PRIVATE_KEY_TYPE_UNKNOWN,
        PRIVATE_KEY_TYPE_PKCS1,
        PRIVATE_KEY_TYPE_PKCS1_ENCRYPTED,
        PRIVATE_KEY_TYPE_PKCS8,
        PRIVATE_KEY_TYPE_PKCS8_ENCRYPTED,
    }

    /**
     * Factory method to get a java.security.PrivateKey object from the given Private Key path.
     *
     * @param privateKeyPath   path of the private key.
     * @param passwordProvider JCEPrivateKeyFactory.IPasswordCallback implementation to read the password
     *                         if private key is encrypted, null otherwise.
     * @return java.security.PrivateKey object.
     * @throws IOException                   in case of any IO error.
     * @throws PrivateKeyDecryptionException if private key could not be decrypted e.g. wrong password.
     * @throws PrivateKeyParsingException    if private key is not in valid format e.g. invalid encoding.
     */
    public static PrivateKey getJCEPrivateKeyFromFile(String privateKeyPath, IPasswordProvider passwordProvider)
            throws IOException, PrivateKeyDecryptionException, PrivateKeyParsingException {
        PrivateKey jCEPrivateKey;
        byte[] privateKeyBytes = readPrivateKeyFile(privateKeyPath);
        String pemPrivateKey = new String(privateKeyBytes);
        Object bcPrivateKey = readPEMPrivateKeyInBCObject(pemPrivateKey);
        if (bcPrivateKey == null) {
            // If we cannot read private key in PEM, try reading it as DER
            bcPrivateKey = readDERPrivateKeyInBCObject(privateKeyBytes);
        }
        jCEPrivateKey = getJCEPrivateKey(bcPrivateKey, passwordProvider);
        return jCEPrivateKey;
    }

    /**
     * Factory method to get a java.security.PrivateKey object from the given PEM string.
     *
     * @param pemPrivateKey    private key in PEM format
     * @param passwordCallback JCEPrivateKeyFactory.IPasswordCallback implementation to read the password
     *                         if private key is encrypted, null otherwise.
     * @return java.security.PrivateKey object.
     * @throws IOException                   in case of any IO error.
     * @throws PrivateKeyDecryptionException if private key could not be decrypted e.g. wrong password.
     * @throws PrivateKeyParsingException    if private key is not in valid format e.g. invalid encoding.
     */
    public static PrivateKey getJCEPrivateKey(String pemPrivateKey, IPasswordProvider passwordCallback)
            throws IOException, PrivateKeyDecryptionException, PrivateKeyParsingException {
        PrivateKey jCEPrivateKey;
        Object bCastlePrivateKeyObject = readPEMPrivateKeyInBCObject(pemPrivateKey);
        jCEPrivateKey = getJCEPrivateKey(bCastlePrivateKeyObject, passwordCallback);
        return jCEPrivateKey;
    }

    /**
     * Factory method to get a java.security.PrivateKey object from the given byte[].
     *
     * @param privateKeyByteArray private key in byte[].
     * @param passwordCallback    JCEPrivateKeyFactory.IPasswordCallback implementation to read the password
     *                            if private key is encrypted, null otherwise.
     * @return java.security.PrivateKey object.
     * @throws IOException                   in case of any IO error.
     * @throws PrivateKeyDecryptionException if private key could not be decrypted e.g. wrong password.
     * @throws PrivateKeyParsingException    if private key is not in valid format e.g. invalid encoding.
     */
    public static PrivateKey getJCEPrivateKey(byte[] privateKeyByteArray, IPasswordProvider passwordCallback)
            throws IOException, PrivateKeyDecryptionException, PrivateKeyParsingException {
        PrivateKey jCEPrivateKey;
        Object bCastlePrivateKeyObject = readDERPrivateKeyInBCObject(privateKeyByteArray);
        jCEPrivateKey = getJCEPrivateKey(bCastlePrivateKeyObject, passwordCallback);
        return jCEPrivateKey;
    }

    /**
     * Factory method to get a java.security.PrivateKey object from the given object
     *
     * @param bCastlePrivateKeyObject private key, can be one of PEMKeyPair, PrivateKeyInfo, PEMEncryptedKeyPair,
     *                                PKCS8EncryptedPrivateKeyInfo.
     * @param passwordCallback        JCEPrivateKeyFactory.IPasswordCallback implementation to read the password
     *                                if private key is encrypted, null otherwise.
     * @return java.security.PrivateKey object.
     * @throws PrivateKeyDecryptionException if private key could not be decrypted e.g. wrong password.
     * @throws PrivateKeyParsingException    if private key is not in valid format e.g. invalid encoding.
     */
    private static PrivateKey getJCEPrivateKey(Object bCastlePrivateKeyObject, IPasswordProvider passwordCallback)
            throws PrivateKeyDecryptionException, PrivateKeyParsingException {
        PrivateKey jCEPrivateKey;
        PrivateKeyType privateKeyType = getPrivateKeyType(bCastlePrivateKeyObject);
        switch (privateKeyType) {
            case PRIVATE_KEY_TYPE_PKCS1:
                jCEPrivateKey = getJCEPrivateKey((PEMKeyPair) bCastlePrivateKeyObject);
                break;
            case PRIVATE_KEY_TYPE_PKCS8:
                assert bCastlePrivateKeyObject instanceof PrivateKeyInfo;
                jCEPrivateKey = getJCEPrivateKey((PrivateKeyInfo) bCastlePrivateKeyObject);
                break;
            case PRIVATE_KEY_TYPE_PKCS1_ENCRYPTED:
                assert bCastlePrivateKeyObject instanceof PEMEncryptedKeyPair;
                jCEPrivateKey = getJCEPrivateKey((PEMEncryptedKeyPair) bCastlePrivateKeyObject, passwordCallback);
                break;
            case PRIVATE_KEY_TYPE_PKCS8_ENCRYPTED:
                assert bCastlePrivateKeyObject instanceof PKCS8EncryptedPrivateKeyInfo;
                jCEPrivateKey = getJCEPrivateKey((PKCS8EncryptedPrivateKeyInfo) bCastlePrivateKeyObject,
                        passwordCallback);
                break;
            default:
                throw new PrivateKeyParsingException(new Exception("Could not identify private key type."));
        }
        return jCEPrivateKey;
    }

    /**
     * Reads the private key in byte[].
     *
     * @param privateKeyFilePath path of the private key.
     * @return private key in byte[].
     * @throws IOException in case of any IO error.
     */
    private static byte[] readPrivateKeyFile(String privateKeyFilePath) throws IOException {
        File privateKeyFile = new File(privateKeyFilePath);
        FileInputStream fileInputStream = new FileInputStream(privateKeyFile);
        DataInputStream dataInputStream = new DataInputStream(fileInputStream);

        try {
            byte[] bytes = new byte[(int) privateKeyFile.length()];
            int bytesRead = dataInputStream.read(bytes);
            if (bytesRead > 0) {
                return bytes;
            }
            throw new IOException("Cannot read private key file");
        } finally {
            fileInputStream.close();
            dataInputStream.close();
        }
    }

    /**
     * Converts the PEMKeyPair to java.security.PrivateKey object.
     *
     * @param pemKeyPair represents PKCS#1 private key.
     * @return java.security.PrivateKey object.
     * @throws PrivateKeyParsingException if private key is not in valid format e.g. invalid encoding.
     */
    public static PrivateKey getJCEPrivateKey(PEMKeyPair pemKeyPair) throws PrivateKeyParsingException {
        try {
            // Key is in PKCS#1 format
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            KeyPair kp = converter.getKeyPair(pemKeyPair);
            return kp.getPrivate();
        } catch (PEMException e) {
            throw new PrivateKeyParsingException(e);
        }
    }

    /**
     * Converts the PrivateKeyInfo to java.security.PrivateKey object.
     *
     * @param privateKeyInfo represents PKCS#8 private key.
     * @return java.security.PrivateKey object.
     * @throws PrivateKeyDecryptionException if private key could not be decrypted e.g. wrong password.
     * @throws PrivateKeyParsingException    if private key is not in valid format e.g. invalid encoding.
     */
    public static PrivateKey getJCEPrivateKey(PrivateKeyInfo privateKeyInfo)
            throws PrivateKeyDecryptionException, PrivateKeyParsingException {
        try {
            // Key is in PKCS#8 format
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return converter.getPrivateKey(privateKeyInfo);
        } catch (EncryptionException e) {
            throw new PrivateKeyDecryptionException(e);
        } catch (PEMException e) {
            throw new PrivateKeyParsingException(e);
        }
    }

    /**
     * Converts the PEMEncryptedKeyPair to java.security.PrivateKey object.
     *
     * @param pemEncryptedKeyPair represents encrypted PKCS#1 private key.
     * @return java.security.PrivateKey object.
     * @throws PrivateKeyDecryptionException if private key could not be decrypted e.g. wrong password.
     * @throws PrivateKeyParsingException    if private key is not in valid format e.g. invalid encoding.
     */
    public static PrivateKey getJCEPrivateKey(PEMEncryptedKeyPair pemEncryptedKeyPair,
                                              IPasswordProvider passwordCallback)
            throws PrivateKeyDecryptionException, PrivateKeyParsingException {
        try {
            // Key is in PKCS#1 encrypted format
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            char[] password = passwordCallback.getPassword();
            if (password == null) {
                throw new PrivateKeyDecryptionException(new Exception("Password is null"));
            }
            PEMDecryptorProvider decProvider = new JcePEMDecryptorProviderBuilder().build(password);
            KeyPair kp = converter.getKeyPair(pemEncryptedKeyPair.decryptKeyPair(decProvider));
            clearCharArray(password);
            return kp.getPrivate();
        } catch (EncryptionException e) {
            throw new PrivateKeyDecryptionException(e);
        } catch (PEMException e) {
            throw new PrivateKeyParsingException(e);
        } catch (IOException e) {
            throw new PrivateKeyDecryptionException(e);
        }
    }

    /**
     * Converts the PKCS8EncryptedPrivateKeyInfo to java.security.PrivateKey object.
     *
     * @param pkcs8EncryptedPrivateKeyInfo represents encrypted PKCS#8 private key.
     * @return java.security.PrivateKey object.
     * @throws PrivateKeyDecryptionException if private key could not be decrypted e.g. wrong password.
     * @throws PrivateKeyParsingException    if private key is not in valid format e.g. invalid encoding.
     */
    public static PrivateKey getJCEPrivateKey(PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo,
                                              IPasswordProvider passwordCallback)
            throws PrivateKeyDecryptionException, PrivateKeyParsingException {
        try {
            // Key is in encrypted PKCS#8 format
            char[] password = passwordCallback.getPassword();
            if (password == null) {
                throw new PrivateKeyDecryptionException(new Exception("Password is null"));
            }

            InputDecryptorProvider decProviderBuilder =
                    new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(password);

            PrivateKeyInfo privateKeyInfo = pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decProviderBuilder);
            clearCharArray(password);
            return BouncyCastleProvider.getPrivateKey(privateKeyInfo);
        } catch (EncryptionException e) {
            throw new PrivateKeyDecryptionException(e);
        } catch (PEMException e) {
            throw new PrivateKeyParsingException(e);
        } catch (IOException e) {
            throw new PrivateKeyDecryptionException(e);
        } catch (OperatorCreationException e) {
            throw new PrivateKeyDecryptionException(e);
        } catch (PKCSException e) {
            throw new PrivateKeyDecryptionException(e);
        }
    }

    /**
     * Reads private key in one of the BC objects.
     *
     * @param privateKeyBytes Private key represented in byte[].
     * @return one of PEMKeyPair, PrivateKeyInfo, PEMEncryptedKeyPair, PKCS8EncryptedPrivateKeyInfo
     * @throws IOException                in case of any IO error.
     * @throws PrivateKeyParsingException if private key is not in valid format e.g. invalid encoding.
     */
    private static Object readDERPrivateKeyInBCObject(byte[] privateKeyBytes)
            throws IOException, PrivateKeyParsingException {
        PrivateKeyType privateKeyType;
        ASN1Sequence asn1Sequence;
        ASN1InputStream asn1InputStream = new ASN1InputStream(privateKeyBytes);
        try {
            ASN1Primitive primitive = asn1InputStream.readObject();
            asn1Sequence = ASN1Sequence.getInstance(primitive);

            if (asn1Sequence == null || asn1Sequence.size() < 1) {
                throw new PrivateKeyParsingException(
                        new Exception("Could not parse private key into valid ASN1 sequences"));
            }
            privateKeyType = getPrivateKeyType(asn1Sequence);
        } finally {
            asn1InputStream.close();
        }

        switch (privateKeyType) {
            case PRIVATE_KEY_TYPE_PKCS1:
                return convertASN1SequenceToPKCS1BCObject(asn1Sequence);
            case PRIVATE_KEY_TYPE_PKCS8:
                return PrivateKeyInfo.getInstance(asn1Sequence);
            case PRIVATE_KEY_TYPE_PKCS8_ENCRYPTED:
                return new PKCS8EncryptedPrivateKeyInfo(privateKeyBytes);
            default:
                throw new PrivateKeyParsingException(new Exception("Could not identify private key type."));
        }
    }

    /**
     * @param pemString Private key represented in PEM string.
     * @return one of PEMKeyPair, PrivateKeyInfo, PEMEncryptedKeyPair, PKCS8EncryptedPrivateKeyInfo.
     * @throws IOException in case of any IO error.
     */
    private static Object readPEMPrivateKeyInBCObject(String pemString) throws IOException {
        PEMParser pemParser = new PEMParser(new StringReader(pemString));
        return pemParser.readObject();
    }

    /**
     * @param asn1Sequence Private key represented in ASN1Sequence.
     * @return PEMKeyPair object.
     * @throws IOException in case of any IO error.
     */
    private static PEMKeyPair convertASN1SequenceToPKCS1BCObject(ASN1Sequence asn1Sequence) throws IOException {
        RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(asn1Sequence);
        RSAPublicKey rsaPublicKey = new RSAPublicKey(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent());
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                DERNull.INSTANCE);
        return new PEMKeyPair(new SubjectPublicKeyInfo(algorithmIdentifier, rsaPublicKey),
                new PrivateKeyInfo(algorithmIdentifier, rsaPrivateKey));
    }

    /**
     * Identifies the private key type.
     *
     * @param bcPrivateKey Private key represented in PEM format.
     * @return PrivateKeyType.
     */
    private static PrivateKeyType getPrivateKeyType(Object bcPrivateKey) {
        if (bcPrivateKey instanceof PEMKeyPair) {
            return PrivateKeyType.PRIVATE_KEY_TYPE_PKCS1;
        } else if (bcPrivateKey instanceof PrivateKeyInfo) {
            return PrivateKeyType.PRIVATE_KEY_TYPE_PKCS8;
        } else if (bcPrivateKey instanceof PEMEncryptedKeyPair) {
            return PrivateKeyType.PRIVATE_KEY_TYPE_PKCS1_ENCRYPTED;
        } else if (bcPrivateKey instanceof PKCS8EncryptedPrivateKeyInfo) {
            return PrivateKeyType.PRIVATE_KEY_TYPE_PKCS8_ENCRYPTED;
        } else {
            return PrivateKeyType.PRIVATE_KEY_TYPE_UNKNOWN;
        }
    }

    /**
     * Identifies the private key type.
     *
     * @param pemPrivateKey Private key represented in PEM format.
     * @return PrivateKeyType.
     * @throws IOException in case of any IO error.
     */
    public static PrivateKeyType getPrivateKeyType(String pemPrivateKey) throws IOException {
        Object bcPrivateKey = readPEMPrivateKeyInBCObject(pemPrivateKey);
        return getPrivateKeyType(bcPrivateKey);
    }

    /**
     * Identifies the private key type.
     *
     * @param privateKeyBytes Private key represented in byte[].
     * @return PrivateKeyType.
     * @throws IOException                in case of any IO error.
     * @throws PrivateKeyParsingException if private key is not in valid format e.g. invalid encoding.
     */
    public static PrivateKeyType getPrivateKeyType(byte[] privateKeyBytes)
            throws PrivateKeyParsingException, IOException {
        ASN1Sequence asn1Sequence;
        ASN1InputStream asn1InputStream = new ASN1InputStream(privateKeyBytes);
        try {
            asn1Sequence = ASN1Sequence.getInstance(asn1InputStream.readObject());

            if (asn1Sequence != null && asn1Sequence.size() > 0) {
                return getPrivateKeyType(asn1Sequence);
            }
            throw new PrivateKeyParsingException(
                    new Exception("Could not parse private key into valid ASN1 sequences"));
        } finally {
            asn1InputStream.close();
        }
    }

    /**
     * Identifies the private key type.
     *
     * @param asn1Sequence Private key represented in ASN1Sequence.
     * @return PrivateKeyType.
     */
    public static PrivateKeyType getPrivateKeyType(ASN1Sequence asn1Sequence) {
        switch (asn1Sequence.size()) {
            case 2:
                // Key is in encrypted PKCS#8 format

                /* EncryptedPrivateKeyInfo ::= SEQUENCE {
                encryptionAlgorithm  EncryptionAlgorithmIdentifier,
                encryptedData        EncryptedData
                } */
                return PrivateKeyType.PRIVATE_KEY_TYPE_PKCS8_ENCRYPTED;
            case 3:
            case 4:
                // Key is in PKCS#8 format

                /* PrivateKeyInfo ::= SEQUENCE {
                    version                   Version,
                    privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
                    privateKey                PrivateKey,
                    attributes           [0]  IMPLICIT Attributes OPTIONAL
                } */
                return PrivateKeyType.PRIVATE_KEY_TYPE_PKCS8;
            case 9:
            case 10:
                // Key is in PKCS#1 format

                /* RSAPrivateKey ::= SEQUENCE {
                    version           Version,
                    modulus           INTEGER,  -- n
                    publicExponent    INTEGER,  -- e
                    privateExponent   INTEGER,  -- d
                    prime1            INTEGER,  -- p
                    prime2            INTEGER,  -- q
                    exponent1         INTEGER,  -- d mod (p-1)
                    exponent2         INTEGER,  -- d mod (q-1)
                    coefficient       INTEGER,  -- (inverse of q) mod p
                    otherPrimeInfos   OtherPrimeInfos OPTIONAL
                } */
                return PrivateKeyType.PRIVATE_KEY_TYPE_PKCS1;
            default:
                return PrivateKeyType.PRIVATE_KEY_TYPE_UNKNOWN;
        }
    }

    /**
     * This exception is thrown when JCEPrivateKeyFactory is unable to decrypt the private key.
     */
    public static class PrivateKeyDecryptionException extends Exception {
        public PrivateKeyDecryptionException(Exception exception) {
            super(exception);
        }
    }

    /**
     * This exception is thrown when JCEPrivateKeyFactory is unable to parse the private key.
     */
    public static class PrivateKeyParsingException extends Exception {
        public PrivateKeyParsingException(Exception e) {
            super(e);
        }
    }

    /**
     * Used to clear the password once it is used.
     */
    private static void clearCharArray(char[] array) {
        Arrays.fill(array, ' ');
    }

    /**
     * Interface to provide implementation to get password in case of encrypted private keys.
     */
    public interface IPasswordProvider {
        char[] getPassword();
    }
}
