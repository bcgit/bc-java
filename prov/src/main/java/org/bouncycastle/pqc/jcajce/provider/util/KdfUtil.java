package org.bouncycastle.pqc.jcajce.provider.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jcajce.spec.KEMKDFSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;

import java.security.InvalidKeyException;

public class KdfUtil
{
    /**
     * Generate a byte[] secret key from the passed in secret. Note: passed in secret will be erased after use.
     *
     * @param kdfSpec definition of the KDF and the output size to produce.
     * @param secret the secret value to initialize the KDF with (erased after secret key generation).
     * @return a generated secret key.
     */
    public static byte[] makeKeyBytes(KEMKDFSpec kdfSpec, byte[] secret)
    {
        byte[] keyBytes = null;
        try
        {
            if (kdfSpec == null)
            {
                keyBytes = new byte[secret.length];
                System.arraycopy(secret, 0, keyBytes, 0, keyBytes.length);
            }

            AlgorithmIdentifier kdfAlgorithm = kdfSpec.getKdfAlgorithm();
            byte[] otherInfo = kdfSpec.getOtherInfo();
            keyBytes = new byte[(kdfSpec.getKeySize() + 7) / 8];

            if (kdfAlgorithm == null)
            {
                System.arraycopy(secret, 0, keyBytes, 0, (kdfSpec.getKeySize() + 7) / 8);
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
            else if (NISTObjectIdentifiers.id_shake256.equals(kdfAlgorithm.getAlgorithm()))
            {
                Xof xof = new SHAKEDigest(256);

                xof.update(secret, 0, secret.length);
                xof.update(otherInfo, 0, otherInfo.length);

                xof.doFinal(keyBytes, 0, keyBytes.length);
            }
            else
            {
                throw new IllegalStateException("Unrecognized KDF: " + kdfAlgorithm.getAlgorithm());
            }
        }
        finally
        {
            Arrays.clear(secret);
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
