package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.SM9KEMExtractor;
import org.bouncycastle.crypto.kems.SM9KEMGenerator;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMKDFSpec;
import org.bouncycastle.util.Arrays;

/**
 * JCA {@code KeyGenerator} bridge for the SM9 key encapsulation mechanism
 * (GM/T 0044.4-2016). Registered as {@code KeyGenerator.SM9-KEM}; initialise with:
 * <ul>
 * <li>a {@link KEMGenerateSpec} to <b>encapsulate</b> - its {@code PublicKey} must be the
 *     recipient's {@link org.bouncycastle.jcajce.interfaces.SM9EncUserPublicKey}, from
 *     {@link org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey#getUserPublicKey(byte[])}; or</li>
 * <li>a {@link KEMExtractSpec} to <b>decapsulate</b> - its {@code PrivateKey} must be the
 *     recipient's {@link org.bouncycastle.jcajce.interfaces.SM9EncUserPrivateKey}, the KEM /
 *     decryption key from the KGC.</li>
 * </ul>
 * The requested key length (the spec's {@code keySizeInBits}) drives SM9's own
 * GM/T 0044.4 KDF, which produces the shared key directly; the spec's generic KDF
 * fields are therefore not applied (an external KDF on top would break interoperability
 * with other GM/T 0044.4 implementations - callers who want one anyway can layer it via
 * the {@code javax.crypto.KEM} API, {@code KEM.SM9-KEM}, with a KTSParameterSpec KDF).
 * A spec that asks for something this cannot honour - a KDF other than the specs' default,
 * or any otherInfo - is refused rather than quietly served as if it had not asked.
 * {@code engineGenerateKey} returns a {@link SecretKeyWithEncapsulation}.
 * <p>
 * <b>Usage warning:</b> an identity's key should be used for this service or for
 * {@code Cipher.SM9}, but not for both. A deployment needing both has its KGC publish a
 * separate hid for each function, as it already does for the key exchange, so that the two
 * keys are distinct.
 */
public class SM9KEMKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    // the KDF KEMGenerateSpec and KEMExtractSpec carry when the caller names none
    private static final AlgorithmIdentifier DEFAULT_KDF = new AlgorithmIdentifier(
        X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

    private KEMGenerateSpec genSpec;
    private KEMExtractSpec extSpec;
    private SecureRandom random;

    protected void engineInit(SecureRandom random)
    {
        uninitialise();
        throw new UnsupportedOperationException("SM9-KEM requires a KEMGenerateSpec or KEMExtractSpec");
    }

    protected void engineInit(int keySize, SecureRandom random)
    {
        uninitialise();
        throw new UnsupportedOperationException("SM9-KEM requires a KEMGenerateSpec or KEMExtractSpec");
    }

    protected void engineInit(AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        // what the previous init installed is dropped before the new spec is examined, so that an
        // init this goes on to refuse leaves the generator uninitialised - generateKey() then says
        // so - rather than still holding the last recipient or private key for generateKey() to
        // run under. The new spec is installed only once all of it has been examined, so that none
        // of a spec this refuses is left installed either.
        uninitialise();

        KEMGenerateSpec newGenSpec;
        KEMExtractSpec newExtSpec;

        if (spec instanceof KEMGenerateSpec)
        {
            newGenSpec = (KEMGenerateSpec)spec;
            newExtSpec = null;
            if (!(newGenSpec.getPublicKey() instanceof BCSM9EncPublicKey))
            {
                throw new InvalidAlgorithmParameterException(
                    "SM9-KEM encapsulation requires the recipient's SM9EncUserPublicKey, from SM9EncMasterPublicKey.getUserPublicKey(identity)");
            }
        }
        else if (spec instanceof KEMExtractSpec)
        {
            newExtSpec = (KEMExtractSpec)spec;
            newGenSpec = null;
            if (!(newExtSpec.getPrivateKey() instanceof BCSM9EncPrivateKey))
            {
                throw new InvalidAlgorithmParameterException(
                    "SM9-KEM decapsulation requires the recipient's SM9EncUserPrivateKey, the KEM / decryption key from the KGC");
            }
            if (((BCSM9EncPrivateKey)newExtSpec.getPrivateKey()).isDestroyed())
            {
                // refused here rather than taken and left to fail in generateKey(), which can
                // throw nothing checked
                throw new InvalidAlgorithmParameterException("key destroyed");
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException("SM9-KEM requires a KEMGenerateSpec or KEMExtractSpec");
        }

        KEMKDFSpec kdfSpec = (newGenSpec != null) ? (KEMKDFSpec)newGenSpec : newExtSpec;
        byte[] otherInfo = kdfSpec.getOtherInfo();
        AlgorithmIdentifier kdf = kdfSpec.getKdfAlgorithm();
        if ((otherInfo != null && otherInfo.length != 0) || (kdf != null && !DEFAULT_KDF.equals(kdf)))
        {
            // the key is the GM/T 0044.4 KDF's own output, so a KDF or otherInfo the caller chose
            // would be silently discarded: two calls binding the key to different context would
            // get the same key. Both specs carry the default KDF when none is chosen, so that one
            // - and none at all - is what is taken, as the class javadoc has always said.
            throw new InvalidAlgorithmParameterException(
                "SM9-KEM derives its key with the GM/T 0044.4 KDF and applies no other KDF or otherInfo - layer one through KEM.SM9-KEM with a KTSParameterSpec");
        }

        int keySize = kdfSpec.getKeySize();
        if (keySize <= 0 || (keySize % 8) != 0)
        {
            // refused here rather than by the mechanism's own constructor inside generateKey(),
            // which can only throw unchecked - the key comes back as bytes, so its size is a
            // positive whole number of them, as KEM.SM9-KEM already requires
            throw new InvalidAlgorithmParameterException(
                "SM9-KEM key size must be a positive whole number of bytes: " + keySize);
        }
        if (newExtSpec != null && ((BCSM9EncPrivateKey)newExtSpec.getPrivateKey()).getKeyParameters().isExchangeKey())
        {
            // the extractor refuses a key-exchange key with an unchecked IllegalArgumentException
            // at construction, inside generateKey(); answered here, where init can say so
            throw new InvalidAlgorithmParameterException(
                "SM9-KEM decapsulation requires a KEM / decryption user key, not a key-exchange key");
        }
        if (newGenSpec != null && ((BCSM9EncPublicKey)newGenSpec.getPublicKey()).getKeyParameters().getHid()
            == SM9EncMasterPrivateKeyParameters.HID_EXCHANGE)
        {
            // likewise the generator's refusal of a recipient key under the exchange's hid, which
            // would otherwise come from inside generateKey()
            throw new InvalidAlgorithmParameterException(
                "SM9-KEM encapsulation requires a KEM / encryption recipient key, not a key-exchange key under HID_EXCHANGE (0x02)");
        }

        this.genSpec = newGenSpec;
        this.extSpec = newExtSpec;
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
    }

    /**
     * Drop the configuration the last successful init installed. Every init starts here, so an
     * init that is refused leaves the generator uninitialised, as a refused init leaves
     * Cipher.SM9 and KeyAgreement.SM9, and generateKey() refuses to run until an init succeeds.
     */
    private void uninitialise()
    {
        this.genSpec = null;
        this.extSpec = null;
        this.random = null;
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
            byte[] secret = enc.getSecret();
            try
            {
                SecretKeySpec key = new SecretKeySpec(secret, genSpec.getKeyAlgorithmName());
                return new SecretKeyWithEncapsulation(key, enc.getEncapsulation());
            }
            finally
            {
                // getSecret() hands back a copy and SecretKeySpec takes one of its own, so the copy is
                // erased here, as the extract branch below erases its secret; destroy() erases the
                // result's own
                Arrays.clear(secret);
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
