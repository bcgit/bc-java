package org.bouncycastle.pqc.jcajce.provider.util;

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
import org.bouncycastle.util.Arrays;

public class KdfUtil
{
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
