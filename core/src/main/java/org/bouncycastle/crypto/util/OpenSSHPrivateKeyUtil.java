package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

/**
 * A collection of utility methods for parsing OpenSSH private keys.
 */
public class OpenSSHPrivateKeyUtil
{
    private OpenSSHPrivateKeyUtil()
    {
    }

    /**
     * Magic value for proprietary OpenSSH private key.
     **/
    private static final byte[] AUTH_MAGIC = Strings.toByteArray("openssh-key-v1\0"); // C string so null terminated

    /**
     * Encode a cipher parameters into an OpenSSH private key.
     * This does not add headers like ----BEGIN RSA PRIVATE KEY----
     *
     * @param params the cipher parameters.
     * @return a byte array
     */
    public static byte[] encodePrivateKey(AsymmetricKeyParameter params)
        throws IOException
    {
        if (params == null)
        {
            throw new IllegalArgumentException("param is null");
        }

        if (params instanceof RSAPrivateCrtKeyParameters)
        {
            PrivateKeyInfo pInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(params);

            return pInfo.parsePrivateKey().toASN1Primitive().getEncoded();
        }
        else if (params instanceof ECPrivateKeyParameters)
        {
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)params;
            ECDomainParameters domain = privateKey.getParameters();

            String curveName = SSHNamedCurves.getNameForParameters(domain);
            if (curveName == null)
            {
                throw new IllegalArgumentException("unable to derive ssh curve name for "
                    + domain.getCurve().getClass().getName());
            }

            // OpenSSH stores the affine public point alongside the private scalar; derive
            // it from D and the curve's base point.
            ECPoint q = new FixedPointCombMultiplier().multiply(domain.getG(), privateKey.getD()).normalize();
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(q, domain);

            SSHBuilder builder = new SSHBuilder();
            builder.writeBytes(AUTH_MAGIC);
            builder.writeString("none");    // cipher name
            builder.writeString("none");    // KDF name
            builder.writeString("");        // KDF options

            builder.u32(1); // Number of keys

            byte[] pkEncoded = OpenSSHPublicKeyUtil.encodePublicKey(publicKey);
            builder.writeBlock(pkEncoded);

            SSHBuilder pkBuild = new SSHBuilder();

            int checkint = CryptoServicesRegistrar.getSecureRandom().nextInt();
            pkBuild.u32(checkint);
            pkBuild.u32(checkint);

            pkBuild.writeString("ecdsa-sha2-" + curveName);
            pkBuild.writeString(curveName);
            pkBuild.writeBlock(q.getEncoded(false));
            pkBuild.writeBigNum(privateKey.getD());
            pkBuild.writeString("");        // Comment

            builder.writeBlock(pkBuild.getPaddedBytes());

            return builder.getBytes();
        }
        else if (params instanceof DSAPrivateKeyParameters)
        {
            DSAPrivateKeyParameters privateKey = (DSAPrivateKeyParameters)params;
            DSAParameters dsa = privateKey.getParameters();

            // public key y = g.modPow(x, p);
            BigInteger y = dsa.getG().modPow(privateKey.getX(), dsa.getP());

            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(ASN1Integer.ZERO);
            vec.add(new ASN1Integer(dsa.getP()));
            vec.add(new ASN1Integer(dsa.getQ()));
            vec.add(new ASN1Integer(dsa.getG()));
            vec.add(new ASN1Integer(y));
            vec.add(new ASN1Integer(privateKey.getX()));
            try
            {
                return new DERSequence(vec).getEncoded();
            }
            catch (Exception ex)
            {
                throw Exceptions.illegalStateException("unable to encode DSAPrivateKeyParameters", ex);
            }
        }
        else if (params instanceof Ed25519PrivateKeyParameters)
        {
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)params;
            Ed25519PublicKeyParameters publicKey = privateKey.generatePublicKey();

            SSHBuilder builder = new SSHBuilder();
            builder.writeBytes(AUTH_MAGIC);
            builder.writeString("none");    // cipher name
            builder.writeString("none");    // KDF name
            builder.writeString("");        // KDF options

            builder.u32(1); // Number of keys

            {
                byte[] pkEncoded = OpenSSHPublicKeyUtil.encodePublicKey(publicKey);
                builder.writeBlock(pkEncoded);
            }

            {
                SSHBuilder pkBuild = new SSHBuilder();

                int checkint = CryptoServicesRegistrar.getSecureRandom().nextInt();
                pkBuild.u32(checkint);
                pkBuild.u32(checkint);

                pkBuild.writeString("ssh-ed25519");

                // Public key (as part of private key pair)
                byte[] pubKeyEncoded = publicKey.getEncoded();
                pkBuild.writeBlock(pubKeyEncoded);

                // The private key in SSH is 64 bytes long and is the concatenation of the private and the public keys
                pkBuild.writeBlock(Arrays.concatenate(privateKey.getEncoded(), pubKeyEncoded));

                pkBuild.writeString("");    // Comment for this private key (empty)

                builder.writeBlock(pkBuild.getPaddedBytes());
            }

            return builder.getBytes();
        }

        throw new IllegalArgumentException("unable to convert " + params.getClass().getName() + " to openssh private key");
    }

    /**
     * Parse a private key.
     * <p>
     * This method accepts the body of the OpenSSH private key.
     * The easiest way to extract the body is to use PemReader, for example:
     * <p>
     * byte[] blob = new PemReader([reader]).readPemObject().getContent();
     * CipherParameters params = parsePrivateKeyBlob(blob);
     *
     * @param blob The key.
     * @return A cipher parameters instance.
     */
    public static AsymmetricKeyParameter parsePrivateKeyBlob(byte[] blob)
    {
        return parsePrivateKeyBlob(blob, null);
    }

    /**
     * Parse a private key, decrypting it with the supplied passphrase if it is a
     * passphrase-protected {@code openssh-key-v1} key.
     * <p>
     * This method accepts the body of the OpenSSH private key (see
     * {@link #parsePrivateKeyBlob(byte[])} for how to extract it from PEM). For an
     * unencrypted key {@code passphrase} is ignored and may be {@code null}; for an
     * encrypted key it must carry the passphrase bytes (the OpenSSH client uses the raw
     * UTF-8 bytes). The {@code bcrypt} KDF and the OpenSSH cipher suite
     * (aes128/192/256-ctr, aes128/192/256-cbc, 3des-cbc, aes128/256-gcm@openssh.com and
     * chacha20-poly1305@openssh.com) are supported.
     *
     * @param blob       The key.
     * @param passphrase The passphrase bytes, or {@code null} for an unencrypted key. The
     *                   array is not modified; the caller is responsible for clearing it.
     * @return A cipher parameters instance.
     */
    public static AsymmetricKeyParameter parsePrivateKeyBlob(byte[] blob, byte[] passphrase)
    {
        AsymmetricKeyParameter result = null;

        if (blob[0] == 0x30)
        {
            ASN1Sequence sequence = ASN1Sequence.getInstance(blob);

            if (sequence.size() == 6)
            {
                if (allIntegers(sequence) && ASN1Integer.getInstance(sequence.getObjectAt(0)).getPositiveValue().equals(BigIntegers.ZERO))
                {
                    // length of 6 and all Integers -- DSA
                    result = new DSAPrivateKeyParameters(
                        ASN1Integer.getInstance(sequence.getObjectAt(5)).getPositiveValue(),
                        new DSAParameters(
                            ASN1Integer.getInstance(sequence.getObjectAt(1)).getPositiveValue(),
                            ASN1Integer.getInstance(sequence.getObjectAt(2)).getPositiveValue(),
                            ASN1Integer.getInstance(sequence.getObjectAt(3)).getPositiveValue())
                    );
                }
            }
            else if (sequence.size() == 9)
            {
                if (allIntegers(sequence) && ASN1Integer.getInstance(sequence.getObjectAt(0)).getPositiveValue().equals(BigIntegers.ZERO))
                {
                    // length of 8 and all Integers -- RSA
                    RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(sequence);

                    result = new RSAPrivateCrtKeyParameters(
                        rsaPrivateKey.getModulus(),
                        rsaPrivateKey.getPublicExponent(),
                        rsaPrivateKey.getPrivateExponent(),
                        rsaPrivateKey.getPrime1(),
                        rsaPrivateKey.getPrime2(),
                        rsaPrivateKey.getExponent1(),
                        rsaPrivateKey.getExponent2(),
                        rsaPrivateKey.getCoefficient());
                }
            }
            else if (sequence.size() == 4)
            {
                if (sequence.getObjectAt(3) instanceof ASN1TaggedObject
                    && sequence.getObjectAt(2) instanceof ASN1TaggedObject)
                {
                    ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(sequence);

                    X962Parameters parameters = X962Parameters.getInstance(
                        ecPrivateKey.getParametersObject().toASN1Primitive());
                    ECDomainParameters domainParams;
                    if (parameters.isNamedCurve())
                    {
                        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(parameters.getParameters());
                        domainParams = ECNamedDomainParameters.lookup(oid);
                    }
                    else
                    {
                        X9ECParameters x9 = X9ECParameters.getInstance(parameters.getParameters());
                        domainParams = new ECDomainParameters(x9);
                    }

                    BigInteger d = ecPrivateKey.getKey();

                    result = new ECPrivateKeyParameters(d, domainParams);
                }
            }
        }
        else
        {
            SSHBuffer kIn = new SSHBuffer(AUTH_MAGIC, blob);

            String cipherName = kIn.readString();
            String kdfName = kIn.readString();
            byte[] kdfOptions = kIn.readBlock();

            int publicKeyCount = kIn.readU32();
            if (publicKeyCount != 1)
            {
                throw new IllegalStateException("multiple keys not supported");
            }

            // Burn off public key.
            OpenSSHPublicKeyUtil.parsePublicKey(kIn.readBlock());

            boolean encrypted = !"none".equals(cipherName);

            byte[] privateKeyBlock;
            if (!encrypted)
            {
                // unencrypted key: cipher and KDF are both "none", padding aligned to 8 bytes.
                privateKeyBlock = kIn.readPaddedBlock();
            }
            else
            {
                if (passphrase == null)
                {
                    throw new IllegalStateException("passphrase required to decrypt encrypted OpenSSH private key");
                }
                privateKeyBlock = decryptOpenSSHV1(cipherName, kdfName, kdfOptions, passphrase, kIn);
            }

            if (kIn.hasRemaining())
            {
                throw new IllegalArgumentException("decoded key has trailing data");
            }

            SSHBuffer pkIn = new SSHBuffer(privateKeyBlock);
            int check1 = pkIn.readU32();
            int check2 = pkIn.readU32();

            if (check1 != check2)
            {
                throw new IllegalStateException("private key check values are not the same");
            }

            String keyType = pkIn.readString();

            if ("ssh-ed25519".equals(keyType))
            {
                // Public key
                pkIn.readBlock();
                // Private key value..
                byte[] edPrivateKey = pkIn.readBlock();
                if (edPrivateKey.length != Ed25519PrivateKeyParameters.KEY_SIZE + Ed25519PublicKeyParameters.KEY_SIZE)
                {
                    throw new IllegalStateException("private key value of wrong length");
                }

                result = new Ed25519PrivateKeyParameters(edPrivateKey, 0);
            }
            else if (keyType.startsWith("ecdsa"))
            {
                ASN1ObjectIdentifier oid = SSHNamedCurves.getByName(Strings.fromByteArray(pkIn.readBlock()));
                if (oid == null)
                {
                    throw new IllegalStateException("OID not found for: " + keyType);
                }

                X9ECParameters curveParams = NISTNamedCurves.getByOID(oid);
                if (curveParams == null)
                {
                    throw new IllegalStateException("Curve not found for: " + oid);
                }

                // Skip public key.
                pkIn.readBlock();
                byte[] privKey = pkIn.readBlock();

                result = new ECPrivateKeyParameters(new BigInteger(1, privKey),
                    new ECNamedDomainParameters(oid, curveParams));
            }
            else if (keyType.startsWith("ssh-rsa"))
            {
                BigInteger modulus = new BigInteger(1, pkIn.readBlock());
                BigInteger pubExp = new BigInteger(1, pkIn.readBlock());
                BigInteger privExp = new BigInteger(1, pkIn.readBlock());
                BigInteger coef = new BigInteger(1, pkIn.readBlock());
                BigInteger p = new BigInteger(1, pkIn.readBlock());
                BigInteger q = new BigInteger(1, pkIn.readBlock());

                BigInteger pSub1 = p.subtract(BigIntegers.ONE);
                BigInteger qSub1 = q.subtract(BigIntegers.ONE);
                BigInteger dP = privExp.remainder(pSub1);
                BigInteger dQ = privExp.remainder(qSub1);

                result = new RSAPrivateCrtKeyParameters(
                                modulus,
                                pubExp,
                                privExp,
                                p,
                                q,
                                dP,
                                dQ,
                                coef);
            }

            // Comment for private key
            pkIn.skipBlock();

            if (!encrypted)
            {
                if (pkIn.hasRemaining())
                {
                    throw new IllegalArgumentException("private key block has trailing data");
                }
            }
            else
            {
                // the decrypted block is padded to the cipher block size with the bytes 1,2,3,...
                pkIn.checkTrailingPadding();
            }
        }

        if (result == null)
        {
            throw new IllegalArgumentException("unable to parse key");
        }

        return result;
    }

    /**
     * allIntegers returns true if the sequence holds only ASN1Integer types.
     **/
    private static boolean allIntegers(ASN1Sequence sequence)
    {
        for (int t = 0; t < sequence.size(); t++)
        {
            if (!(sequence.getObjectAt(t) instanceof ASN1Integer))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * Decrypt the encrypted private-key section of an {@code openssh-key-v1} key. The key and IV
     * are derived from the passphrase with the bcrypt_pbkdf KDF (the only KDF OpenSSH defines for
     * this format); the cipher is one of the OpenSSH cipher suite. Returns the decrypted, still
     * block-padded private section.
     */
    private static byte[] decryptOpenSSHV1(String cipherName, String kdfName, byte[] kdfOptions,
        byte[] passphrase, SSHBuffer kIn)
    {
        if (!"bcrypt".equals(kdfName))
        {
            throw new IllegalStateException("unknown KDF for encrypted OpenSSH private key: " + kdfName);
        }

        SSHBuffer options = new SSHBuffer(kdfOptions);
        byte[] salt = options.readBlock();
        int rounds = options.readU32();
        if (options.hasRemaining())
        {
            throw new IllegalArgumentException("kdfoptions has trailing data");
        }
        if (rounds <= 0)
        {
            throw new IllegalArgumentException("illegal bcrypt rounds: " + rounds);
        }

        // The encrypted private section is the full ciphertext, padded to the cipher block size.
        byte[] encrypted = kIn.readBlock();

        if ("chacha20-poly1305@openssh.com".equals(cipherName))
        {
            // AEAD: the 16-byte authentication tag follows the ciphertext (not inside the string).
            byte[] tag = kIn.readRawBytes(16);
            byte[] keyIV = BCrypt.pbkdfGenerate(passphrase, salt, rounds, 64);
            try
            {
                return decryptChaCha20Poly1305(keyIV, encrypted, tag);
            }
            finally
            {
                Arrays.fill(keyIV, (byte)0);
            }
        }

        int keyLen;
        int ivLen;
        int kind;   // 0 = AES/CTR, 1 = AES/CBC, 2 = 3DES/CBC, 3 = AES/GCM

        if ("aes128-ctr".equals(cipherName))
        {
            keyLen = 16; ivLen = 16; kind = 0;
        }
        else if ("aes192-ctr".equals(cipherName))
        {
            keyLen = 24; ivLen = 16; kind = 0;
        }
        else if ("aes256-ctr".equals(cipherName))
        {
            keyLen = 32; ivLen = 16; kind = 0;
        }
        else if ("aes128-cbc".equals(cipherName))
        {
            keyLen = 16; ivLen = 16; kind = 1;
        }
        else if ("aes192-cbc".equals(cipherName))
        {
            keyLen = 24; ivLen = 16; kind = 1;
        }
        else if ("aes256-cbc".equals(cipherName))
        {
            keyLen = 32; ivLen = 16; kind = 1;
        }
        else if ("3des-cbc".equals(cipherName))
        {
            keyLen = 24; ivLen = 8; kind = 2;
        }
        else if ("aes128-gcm@openssh.com".equals(cipherName))
        {
            keyLen = 16; ivLen = 12; kind = 3;
        }
        else if ("aes256-gcm@openssh.com".equals(cipherName))
        {
            keyLen = 32; ivLen = 12; kind = 3;
        }
        else
        {
            throw new IllegalStateException("unsupported cipher for encrypted OpenSSH private key: " + cipherName);
        }

        // AEAD: the 16-byte authentication tag follows the ciphertext (not inside the string).
        byte[] tag = (kind == 3) ? kIn.readRawBytes(16) : null;

        byte[] keyIV = BCrypt.pbkdfGenerate(passphrase, salt, rounds, keyLen + ivLen);
        KeyParameter key = new KeyParameter(keyIV, 0, keyLen);
        byte[] iv = Arrays.copyOfRange(keyIV, keyLen, keyLen + ivLen);
        try
        {
            switch (kind)
            {
            case 0:
                return processBlockCipher(SICBlockCipher.newInstance(AESEngine.newInstance()), key, iv, encrypted);
            case 1:
                return processBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()), key, iv, encrypted);
            case 2:
                return processBlockCipher(CBCBlockCipher.newInstance(new DESedeEngine()), key, iv, encrypted);
            default:
                return decryptGCM(key, iv, encrypted, tag);
            }
        }
        finally
        {
            Arrays.fill(keyIV, (byte)0);
            Arrays.fill(iv, (byte)0);
        }
    }

    private static byte[] processBlockCipher(BlockCipher cipher, KeyParameter key, byte[] iv, byte[] encrypted)
    {
        cipher.init(false, new ParametersWithIV(key, iv));

        int blockSize = cipher.getBlockSize();
        if (encrypted.length % blockSize != 0)
        {
            throw new IllegalArgumentException("encrypted private key not a multiple of the cipher block size");
        }

        byte[] out = new byte[encrypted.length];
        for (int off = 0; off < encrypted.length; off += blockSize)
        {
            cipher.processBlock(encrypted, off, out, off);
        }
        return out;
    }

    private static byte[] decryptGCM(KeyParameter key, byte[] iv, byte[] encrypted, byte[] tag)
    {
        // The GCM tag follows the ciphertext in the key blob, with no additional authenticated data.
        GCMModeCipher gcm = GCMBlockCipher.newInstance(AESEngine.newInstance());
        gcm.init(false, new AEADParameters(key, 128, iv));

        byte[] cipherTextAndTag = Arrays.concatenate(encrypted, tag);
        byte[] out = new byte[gcm.getOutputSize(cipherTextAndTag.length)];
        try
        {
            int len = gcm.processBytes(cipherTextAndTag, 0, cipherTextAndTag.length, out, 0);
            gcm.doFinal(out, len);
        }
        catch (InvalidCipherTextException e)
        {
            throw new IllegalStateException("unable to decrypt OpenSSH private key (bad passphrase or corrupted key)");
        }
        return out;
    }

    private static byte[] decryptChaCha20Poly1305(byte[] keyIV, byte[] encrypted, byte[] tag)
    {
        // 64-byte key split into two 32-byte ChaCha20 keys. The first (OpenSSH's "main" key) both
        // generates the Poly1305 key (ChaCha20 block 0) and encrypts the payload (ChaCha20 block 1
        // onwards); the second (the length key) is unused here as there is no additional
        // authenticated data. The nonce is the packet sequence number, which is zero here.
        byte[] payloadKey = Arrays.copyOfRange(keyIV, 0, 32);

        StreamCipher chacha = new ChaChaEngine();
        chacha.init(false, new ParametersWithIV(new KeyParameter(payloadKey), new byte[8]));

        byte[] block0 = new byte[64];
        chacha.processBytes(block0, 0, block0.length, block0, 0);
        byte[] polyKey = Arrays.copyOf(block0, 32);

        Poly1305 poly1305 = new Poly1305();
        poly1305.init(new KeyParameter(polyKey));
        poly1305.update(encrypted, 0, encrypted.length);
        byte[] computedTag = new byte[16];
        poly1305.doFinal(computedTag, 0);

        Arrays.fill(payloadKey, (byte)0);
        Arrays.fill(polyKey, (byte)0);
        Arrays.fill(block0, (byte)0);

        if (!Arrays.constantTimeAreEqual(computedTag, tag))
        {
            throw new IllegalStateException("unable to decrypt OpenSSH private key (bad passphrase or corrupted key)");
        }

        byte[] out = new byte[encrypted.length];
        chacha.processBytes(encrypted, 0, encrypted.length, out, 0);
        return out;
    }
}
