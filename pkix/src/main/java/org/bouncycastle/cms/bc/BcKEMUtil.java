package org.bouncycastle.cms.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.engines.AESWrapPadEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * The RFC 9629 KEMRecipientInfo pieces shared by the light-weight KEM recipient info generator and
 * recipient: the key-encryption key size and wrap engine for a wrap algorithm, and the KDF step that
 * turns the KEM shared secret into the key-encryption key.
 */
class BcKEMUtil
{
    static int getKekSize(ASN1ObjectIdentifier symWrapAlg)
    {
        if (symWrapAlg.equals(CMSAlgorithm.AES256_WRAP) || symWrapAlg.equals(CMSAlgorithm.AES256_WRAP_PAD))
        {
            return 32;
        }
        else if (symWrapAlg.equals(CMSAlgorithm.AES192_WRAP) || symWrapAlg.equals(CMSAlgorithm.AES192_WRAP_PAD))
        {
            return 24;
        }
        else if (symWrapAlg.equals(CMSAlgorithm.AES128_WRAP) || symWrapAlg.equals(CMSAlgorithm.AES128_WRAP_PAD))
        {
            return 16;
        }
        else
        {
            throw new IllegalArgumentException("unknown wrap algorithm: " + symWrapAlg);
        }
    }

    static Wrapper createWrapper(ASN1ObjectIdentifier symWrapAlg)
    {
        if (symWrapAlg.equals(CMSAlgorithm.AES128_WRAP) || symWrapAlg.equals(CMSAlgorithm.AES192_WRAP)
            || symWrapAlg.equals(CMSAlgorithm.AES256_WRAP))
        {
            return new AESWrapEngine();
        }
        else if (symWrapAlg.equals(CMSAlgorithm.AES128_WRAP_PAD) || symWrapAlg.equals(CMSAlgorithm.AES192_WRAP_PAD)
            || symWrapAlg.equals(CMSAlgorithm.AES256_WRAP_PAD))
        {
            return new AESWrapPadEngine();
        }
        else
        {
            throw new IllegalArgumentException("unknown wrap algorithm: " + symWrapAlg);
        }
    }

    /**
     * Derive the key-encryption key from the KEM shared secret (RFC 9629 Section 3). The shared
     * secret is erased before this returns.
     *
     * @param kdfAlgorithm the kdf field of the KEMRecipientInfo.
     * @param secret       the KEM shared secret (erased before return).
     * @param otherInfo    the DER encoding of CMSORIforKEMOtherInfo.
     * @param kekLength    the key-encryption key length in bytes.
     * @return the key-encryption key.
     */
    static byte[] deriveKek(AlgorithmIdentifier kdfAlgorithm, byte[] secret, byte[] otherInfo, int kekLength)
    {
        try
        {
            byte[] kek = new byte[kekLength];
            ASN1ObjectIdentifier kdfOid = kdfAlgorithm.getAlgorithm();

            if (X9ObjectIdentifiers.id_kdf_kdf2.equals(kdfOid) || X9ObjectIdentifiers.id_kdf_kdf3.equals(kdfOid))
            {
                Digest digest = getDigest(AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters()).getAlgorithm());
                DerivationFunction kdf = X9ObjectIdentifiers.id_kdf_kdf2.equals(kdfOid)
                    ? (DerivationFunction)new KDF2BytesGenerator(digest) : new ConcatenationKDFGenerator(digest);

                kdf.init(new KDFParameters(secret, otherInfo));
                kdf.generateBytes(kek, 0, kek.length);
            }
            else if (PKCSObjectIdentifiers.id_alg_hkdf_with_sha256.equals(kdfOid)
                || PKCSObjectIdentifiers.id_alg_hkdf_with_sha384.equals(kdfOid)
                || PKCSObjectIdentifiers.id_alg_hkdf_with_sha512.equals(kdfOid))
            {
                if (kdfAlgorithm.getParameters() != null)
                {
                    throw new IllegalArgumentException("HKDF parameters not supported");
                }

                Digest digest = PKCSObjectIdentifiers.id_alg_hkdf_with_sha256.equals(kdfOid) ? new SHA256Digest()
                    : PKCSObjectIdentifiers.id_alg_hkdf_with_sha384.equals(kdfOid) ? (Digest)new SHA384Digest()
                    : new SHA512Digest();
                DerivationFunction kdf = new HKDFBytesGenerator(digest);

                kdf.init(new HKDFParameters(secret, null, otherInfo));
                kdf.generateBytes(kek, 0, kek.length);
            }
            else if (NISTObjectIdentifiers.id_Kmac128.equals(kdfOid) || NISTObjectIdentifiers.id_Kmac256.equals(kdfOid))
            {
                byte[] customStr = new byte[0];
                if (kdfAlgorithm.getParameters() != null)
                {
                    customStr = ASN1OctetString.getInstance(kdfAlgorithm.getParameters()).getOctets();
                }

                KMAC mac = new KMAC(NISTObjectIdentifiers.id_Kmac128.equals(kdfOid) ? 128 : 256, customStr);

                mac.init(new KeyParameter(secret));
                mac.update(otherInfo, 0, otherInfo.length);
                mac.doFinal(kek, 0, kek.length);
            }
            else if (NISTObjectIdentifiers.id_shake256.equals(kdfOid))
            {
                Xof xof = new SHAKEDigest(256);

                xof.update(secret, 0, secret.length);
                xof.update(otherInfo, 0, otherInfo.length);
                xof.doFinal(kek, 0, kek.length);
            }
            else
            {
                throw new IllegalArgumentException("unrecognized KDF: " + kdfOid);
            }

            return kek;
        }
        finally
        {
            Arrays.clear(secret);
        }
    }

    private static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha384))
        {
            return new SHA384Digest();
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
