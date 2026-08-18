package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
        // guarded for the benefit of a caller outside the provider: the default spec built below is
        // only meaningful for a real session key size, and a bad one would surface much later
        if (sessionKeySize <= 0 || (sessionKeySize % 8) != 0)
        {
            throw new IllegalArgumentException(
                "sessionKeySize must be a positive whole number of bytes: " + sessionKeySize);
        }

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
     * Derive a secret key from a KEM's shared secret and return the requested slice of it.
     * <p>
     * <b>Note: the passed in secret will be erased</b>, as it is by
     * {@link #makeKeyBytes(KEMKDFSpec, byte[])}, and so will the derived bytes once the key has
     * copied them. Take anything else you need from the mechanism's output - the encapsulation in
     * particular - before calling this, and destroy the SecretWithEncapsulation it came from
     * afterwards; that is left to the caller so the ordering stays visible at the call site.
     * <p>
     * The requested range is validated here rather than left to SecretKeySpec, so that an
     * out-of-range request cannot reach it after the secret has been erased.
     *
     * @param parameterSpec the KDF and output size to derive with.
     * @param kemSecret the mechanism's shared secret (erased before this returns).
     * @param from index of the first byte of the derived key to use.
     * @param to index after the last byte of the derived key to use.
     * @param algorithm the algorithm name for the returned key - reconcile it with the spec through
     *                  {@link #resolveAlgorithm(KTSParameterSpec, String)} first.
     * @return the requested slice of the derived key.
     */
    public static SecretKey makeSecretKey(KTSParameterSpec parameterSpec, byte[] kemSecret,
        int from, int to, String algorithm)
    {
        if (parameterSpec == null)
        {
            throw new NullPointerException("'parameterSpec' cannot be null");
        }
        if (kemSecret == null)
        {
            throw new NullPointerException("'kemSecret' cannot be null");
        }
        if (algorithm == null)
        {
            throw new NullPointerException("'algorithm' cannot be null");
        }

        // erased on every exit, throws included, matching makeKeyBytes' contract - the clear is
        // idempotent, so makeKeyBytes having already erased it on the derivation path is harmless
        try
        {
            // the same count makeKeyBytes will derive. Checked before deriving, and spelled out
            // rather than using Objects.checkFromToIndex, which is newer than this tree's source
            // floor allows.
            int derivedLength = (parameterSpec.getKeySize() + 7) / 8;
            if (from < 0 || to < from || to > derivedLength)
            {
                throw new IllegalArgumentException("range [" + from + ", " + to
                    + ") out of bounds for a " + derivedLength + " byte derived key");
            }

            byte[] kdfSecret = makeKeyBytes(parameterSpec, kemSecret);

            try
            {
                return new SecretKeySpec(kdfSecret, from, to - from, algorithm);
            }
            finally
            {
                Arrays.clear(kdfSecret);
            }
        }
        finally
        {
            Arrays.clear(kemSecret);
        }
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
     * @throws IllegalArgumentException if the spec asks for no KDF and the requested key size is
     * larger than the shared secret the mechanism produced.
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
            // With no KDF the shared secret is the key material, so a request for more bits than the
            // mechanism produced cannot be met. Refuse rather than truncate the request silently: a
            // caller that asked for a 256-bit key and was handed FrodoKEM-976's 192-bit secret would
            // have no way of telling. (WrapUtil clamps instead, as there the requested size is only an
            // upper bound on a wrapping key both sides derive the same way.)
            //
            // resolveKemSpec above applies the same rule to a KTSParameterSpec before a
            // javax.crypto.KEM ever encapsulates, where it can be reported as the spec failure it is.
            // This is the backstop for the callers that do not pass through it - the KEM KeyGenerator
            // services, which take a KEMGenerateSpec / KEMExtractSpec and reach makeKeyBytes directly.
            if (secret.length < keyBytes.length)
            {
                throw new IllegalArgumentException("no KDF specified and the shared secret is "
                    + (secret.length * 8) + " bits, " + keySize + " requested");
            }

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
