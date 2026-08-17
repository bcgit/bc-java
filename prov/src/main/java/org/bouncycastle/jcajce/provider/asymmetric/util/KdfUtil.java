package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.spec.KEMKDFSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;

public class KdfUtil
{
    /**
     * Validate a KTSParameterSpec offered to a KEM, or build the default spec - the shared secret
     * used as it comes, with no KDF - when the caller supplied none.
     * <p>
     * Everything a KEM cannot honour is rejected here rather than at encapsulate/decapsulate time,
     * where it would surface as an unchecked exception the javax.crypto.KEM API does not declare.
     * Note that without a KDF the secret is the mechanism's own session key, so the requested size
     * must be a whole number of bytes no larger than that key: javax.crypto.KEM validates
     * encapsulate()'s range against secretSize(), so that size has to be honest rather than
     * quietly shortened the way {@link WrapUtil} shortens a KEK to the secret it has.
     *
     * @param spec the caller-supplied spec, or null for the default.
     * @param algorithmName the KEM's name, used in the exception messages.
     * @param parameterSetName the name of the key's parameter set, used in the exception messages.
     * @param sessionKeySize the size in bits of the mechanism's own session key for that set.
     * @return the spec to use.
     * @throws InvalidAlgorithmParameterException if the spec cannot be honoured.
     */
    public static KTSParameterSpec resolveKemSpec(AlgorithmParameterSpec spec, String algorithmName,
        String parameterSetName, int sessionKeySize)
        throws InvalidAlgorithmParameterException
    {
        if (spec == null)
        {
            // Do not wrap key, no KDF
            return new KTSParameterSpec.Builder("Generic", sessionKeySize).withNoKdf().build();
        }

        if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException(algorithmName + " can only accept KTSParameterSpec");
        }

        KTSParameterSpec ktsSpec = (KTSParameterSpec)spec;

        // KTSParameterSpec does not check its own algorithm name, and a null one is only noticed
        // once it has been substituted for a "Generic" request and handed to the SecretKey.
        if (ktsSpec.getKeyAlgorithmName() == null)
        {
            throw new InvalidAlgorithmParameterException("KTSParameterSpec has no key algorithm name");
        }

        // Nor does it check its own key size. A size below 8 would yield a zero-length secret key
        // (makeKeyBytes rounds the byte count up while a KEM's secretSize() rounds it down), one
        // that is not a whole number of bytes would silently deliver fewer bits than were asked
        // for, and one within 7 of Integer.MAX_VALUE would overflow the rounding-up itself.
        int keySize = ktsSpec.getKeySize();
        if (keySize <= 0 || (keySize % 8) != 0)
        {
            throw new InvalidAlgorithmParameterException(
                "KTSParameterSpec key size must be a positive whole number of bytes: " + keySize);
        }

        if (ktsSpec.getKdfAlgorithm() == null)
        {
            if (keySize > sessionKeySize)
            {
                throw new InvalidAlgorithmParameterException("no KDF specified and " + parameterSetName
                    + " produces a " + sessionKeySize + " bit secret, " + keySize + " requested");
            }
        }
        else if (!isSupportedKdf(ktsSpec.getKdfAlgorithm()))
        {
            throw new InvalidAlgorithmParameterException("unsupported KDF: "
                + ktsSpec.getKdfAlgorithm().getAlgorithm());
        }

        return ktsSpec;
    }

    /**
     * Reconcile the algorithm name passed to a KEM's encapsulate/decapsulate with the one its
     * KTSParameterSpec names: "Generic" on either side defers to the other, and a genuine mismatch
     * is refused.
     *
     * @param parameterSpec the spec the KEM was created with.
     * @param algorithm the algorithm name the caller asked for.
     * @return the algorithm name to label the secret key with.
     */
    public static String resolveAlgorithm(KTSParameterSpec parameterSpec, String algorithm)
    {
        String keyAlgName = parameterSpec.getKeyAlgorithmName();

        if ("Generic".equals(keyAlgName))
        {
            return algorithm;
        }
        // if algorithm is Generic then use parameterSpec to wrap key
        if ("Generic".equals(algorithm))
        {
            return keyAlgName;
        }
        // check spec algorithm mismatch provided algorithm
        if (!algorithm.equals(keyAlgName))
        {
            throw new UnsupportedOperationException(keyAlgName + " does not match " + algorithm);
        }

        return algorithm;
    }

    /**
     * Return true if makeKeyBytes can service the passed in KDF algorithm identifier.
     */
    private static boolean isSupportedKdf(AlgorithmIdentifier kdfAlgorithm)
    {
        ASN1ObjectIdentifier kdfOid = kdfAlgorithm.getAlgorithm();

        try
        {
            if (X9ObjectIdentifiers.id_kdf_kdf2.equals(kdfOid) || X9ObjectIdentifiers.id_kdf_kdf3.equals(kdfOid))
            {
                if (kdfAlgorithm.getParameters() == null)
                {
                    return false;
                }

                ASN1ObjectIdentifier digOid = AlgorithmIdentifier.getInstance(
                    kdfAlgorithm.getParameters()).getAlgorithm();

                // the digests getDigest() knows
                return NISTObjectIdentifiers.id_sha256.equals(digOid)
                    || NISTObjectIdentifiers.id_sha512.equals(digOid)
                    || NISTObjectIdentifiers.id_shake128.equals(digOid)
                    || NISTObjectIdentifiers.id_shake256.equals(digOid);
            }

            if (PKCSObjectIdentifiers.id_alg_hkdf_with_sha256.equals(kdfOid)
                || PKCSObjectIdentifiers.id_alg_hkdf_with_sha384.equals(kdfOid)
                || PKCSObjectIdentifiers.id_alg_hkdf_with_sha512.equals(kdfOid))
            {
                // HKDF parameter support has not been added
                return kdfAlgorithm.getParameters() == null;
            }

            if (NISTObjectIdentifiers.id_Kmac128.equals(kdfOid) || NISTObjectIdentifiers.id_Kmac256.equals(kdfOid))
            {
                if (kdfAlgorithm.getParameters() != null)
                {
                    ASN1OctetString.getInstance(kdfAlgorithm.getParameters());
                }
                return true;
            }

            return NISTObjectIdentifiers.id_shake256.equals(kdfOid);
        }
        catch (IllegalArgumentException e)
        {
            // a parameters field that will not decode as the branch requires
            return false;
        }
    }

    /**
     * Generate a byte[] secret key from the passed in secret. Note: passed in secret will be erased after use.
     *
     * @param kdfSpec definition of the KDF and the output size to produce.
     * @param secret  the secret value to initialize the KDF with (erased after secret key generation).
     * @return a generated secret key.
     */
    public static byte[] makeKeyBytes(KEMKDFSpec kdfSpec, byte[] secret)
    {
        byte[] keyBytes;
        try
        {
            if (kdfSpec == null)
            {
                keyBytes = new byte[secret.length];
                System.arraycopy(secret, 0, keyBytes, 0, keyBytes.length);
            }
            else
            {
                keyBytes = makeKeyBytes(kdfSpec.getKdfAlgorithm(), secret, kdfSpec.getOtherInfo(),
                    kdfSpec.getKeySize());
            }
        }
        finally
        {
            Arrays.clear(secret);
        }

        return keyBytes;
    }

    static byte[] makeKeyBytes(AlgorithmIdentifier kdfAlgorithm, byte[] secret, byte[] otherInfo, int keySize)
    {
        byte[] keyBytes = new byte[(keySize + 7) / 8];

        if (kdfAlgorithm == null)
        {
            System.arraycopy(secret, 0, keyBytes, 0, keyBytes.length);
        }
        else if (X9ObjectIdentifiers.id_kdf_kdf2.equals(kdfAlgorithm.getAlgorithm()))
        {
            AlgorithmIdentifier digAlg = AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters());
            DerivationFunction kdf = new KDF2BytesGenerator(getDigest(digAlg.getAlgorithm()));

            kdf.init(new KDFParameters(secret, otherInfo));

            kdf.generateBytes(keyBytes, 0, keyBytes.length);
        }
        else if (X9ObjectIdentifiers.id_kdf_kdf3.equals(kdfAlgorithm.getAlgorithm()))
        {
            AlgorithmIdentifier digAlg = AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters());
            DerivationFunction kdf = new ConcatenationKDFGenerator(getDigest(digAlg.getAlgorithm()));

            kdf.init(new KDFParameters(secret, otherInfo));

            kdf.generateBytes(keyBytes, 0, keyBytes.length);
        }
        else if (PKCSObjectIdentifiers.id_alg_hkdf_with_sha256.equals(kdfAlgorithm.getAlgorithm()))
        {
            if (kdfAlgorithm.getParameters() == null)
            {
                DerivationFunction kdf = new HKDFBytesGenerator(new SHA256Digest());

                kdf.init(new HKDFParameters(secret, null, otherInfo));

                kdf.generateBytes(keyBytes, 0, keyBytes.length);
            }
            else
            {
                throw new IllegalStateException("HDKF parameter support not added");
            }
        }
        else if (PKCSObjectIdentifiers.id_alg_hkdf_with_sha384.equals(kdfAlgorithm.getAlgorithm()))
        {
            if (kdfAlgorithm.getParameters() == null)
            {
                DerivationFunction kdf = new HKDFBytesGenerator(new SHA384Digest());

                kdf.init(new HKDFParameters(secret, null, otherInfo));

                kdf.generateBytes(keyBytes, 0, keyBytes.length);
            }
            else
            {
                throw new IllegalStateException("HDKF parameter support not added");
            }
        }
        else if (PKCSObjectIdentifiers.id_alg_hkdf_with_sha512.equals(kdfAlgorithm.getAlgorithm()))
        {
            if (kdfAlgorithm.getParameters() == null)
            {
                DerivationFunction kdf = new HKDFBytesGenerator(new SHA512Digest());

                kdf.init(new HKDFParameters(secret, null, otherInfo));

                kdf.generateBytes(keyBytes, 0, keyBytes.length);
            }
            else
            {
                throw new IllegalStateException("HDKF parameter support not added");
            }
        }
        else if (NISTObjectIdentifiers.id_Kmac128.equals(kdfAlgorithm.getAlgorithm()))
        {
            byte[] customStr = new byte[0];
            if (kdfAlgorithm.getParameters() != null)
            {
                customStr = ASN1OctetString.getInstance(kdfAlgorithm.getParameters()).getOctets();
            }

            KMAC mac = new KMAC(128, customStr);

            mac.init(new KeyParameter(secret, 0, secret.length));

            mac.update(otherInfo, 0, otherInfo.length);

            mac.doFinal(keyBytes, 0, keyBytes.length);
        }
        else if (NISTObjectIdentifiers.id_Kmac256.equals(kdfAlgorithm.getAlgorithm()))
        {
            byte[] customStr = new byte[0];
            if (kdfAlgorithm.getParameters() != null)
            {
                customStr = ASN1OctetString.getInstance(kdfAlgorithm.getParameters()).getOctets();
            }

            KMAC mac = new KMAC(256, customStr);

            mac.init(new KeyParameter(secret, 0, secret.length));

            mac.update(otherInfo, 0, otherInfo.length);

            mac.doFinal(keyBytes, 0, keyBytes.length);
        }
        else if (NISTObjectIdentifiers.id_shake256.equals(kdfAlgorithm.getAlgorithm()))
        {
            Xof xof = new SHAKEDigest(256);

            xof.update(secret, 0, secret.length);
            xof.update(otherInfo, 0, otherInfo.length);

            xof.doFinal(keyBytes, 0, keyBytes.length);
        }
        else
        {
            throw new IllegalArgumentException("Unrecognized KDF: " + kdfAlgorithm.getAlgorithm());
        }

        return keyBytes;
    }

    static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return new SHA512Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake128))
        {
            return new SHAKEDigest(128);
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256))
        {
            return new SHAKEDigest(256);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }
}
