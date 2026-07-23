package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.SM9KEMExtractor;
import org.bouncycastle.crypto.kems.SM9KEMGenerator;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.util.Arrays;

/**
 * JCA {@code KeyGenerator} bridge for the SM9 key encapsulation mechanism
 * (GM/T 0044.4-2016). Registered as {@code KeyGenerator.SM9-KEM}; initialise with:
 * <ul>
 * <li>a {@link KEMGenerateSpec} to <b>encapsulate</b> - its {@code PublicKey} must be a
 *     {@link BCSM9EncPublicKey} (the recipient's master public key + identity); or</li>
 * <li>a {@link KEMExtractSpec} to <b>decapsulate</b> - its {@code PrivateKey} must be a
 *     {@link BCSM9EncPrivateKey} (the recipient's extracted decryption key).</li>
 * </ul>
 * The requested key length (the spec's {@code keySizeInBits}) drives SM9's own
 * GM/T 0044.4 KDF, which produces the shared key directly; the spec's generic KDF
 * fields are therefore not applied (an external KDF on top would break interoperability
 * with other GM/T 0044.4 implementations). {@code engineGenerateKey} returns a
 * {@link SecretKeyWithEncapsulation}.
 */
public class SM9KEMKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private KEMExtractSpec extSpec;
    private SecureRandom random;

    protected void engineInit(SecureRandom random)
    {
        throw new UnsupportedOperationException("SM9-KEM requires a KEMGenerateSpec or KEMExtractSpec");
    }

    protected void engineInit(int keySize, SecureRandom random)
    {
        throw new UnsupportedOperationException("SM9-KEM requires a KEMGenerateSpec or KEMExtractSpec");
    }

    protected void engineInit(AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
        if (spec instanceof KEMGenerateSpec)
        {
            this.genSpec = (KEMGenerateSpec)spec;
            this.extSpec = null;
            if (!(genSpec.getPublicKey() instanceof BCSM9EncPublicKey))
            {
                throw new InvalidAlgorithmParameterException(
                    "SM9-KEM encapsulation requires a BCSM9EncPublicKey (recipient master public key + identity)");
            }
        }
        else if (spec instanceof KEMExtractSpec)
        {
            this.extSpec = (KEMExtractSpec)spec;
            this.genSpec = null;
            if (!(extSpec.getPrivateKey() instanceof BCSM9EncPrivateKey))
            {
                throw new InvalidAlgorithmParameterException(
                    "SM9-KEM decapsulation requires a BCSM9EncPrivateKey (user decryption key)");
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException("SM9-KEM requires a KEMGenerateSpec or KEMExtractSpec");
        }
    }

    protected SecretKey engineGenerateKey()
    {
        if (genSpec == null && extSpec == null)
        {
            throw new IllegalStateException(
                "SM9-KEM KeyGenerator not initialised - supply a KEMGenerateSpec or KEMExtractSpec");
        }
        if (genSpec != null)
        {
            BCSM9EncPublicKey recipient = (BCSM9EncPublicKey)genSpec.getPublicKey();
            SM9KEMGenerator kemGen = new SM9KEMGenerator(genSpec.getKeySize(), random);
            SecretWithEncapsulation enc = kemGen.generateEncapsulated(recipient.getKeyParameters());
            try
            {
                SecretKeySpec key = new SecretKeySpec(enc.getSecret(), genSpec.getKeyAlgorithmName());
                return new SecretKeyWithEncapsulation(key, enc.getEncapsulation());
            }
            finally
            {
                try
                {
                    enc.destroy();
                }
                catch (DestroyFailedException e)
                {
                    // ignore
                }
            }
        }
        else
        {
            BCSM9EncPrivateKey userKey = (BCSM9EncPrivateKey)extSpec.getPrivateKey();
            byte[] encapsulation = extSpec.getEncapsulation();
            SM9KEMExtractor kemExt = new SM9KEMExtractor(userKey.getKeyParameters(), extSpec.getKeySize());
            byte[] secret = kemExt.extractSecret(encapsulation);
            try
            {
                SecretKeySpec key = new SecretKeySpec(secret, extSpec.getKeyAlgorithmName());
                return new SecretKeyWithEncapsulation(key, encapsulation);
            }
            finally
            {
                Arrays.clear(secret);
            }
        }
    }
}
