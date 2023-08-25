package org.bouncycastle.pqc.jcajce.provider.util;

import java.security.InvalidKeyException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.engines.RFC5649WrapEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;

public class WrapUtil
{
    public static Wrapper getKeyWrapper(KTSParameterSpec ktsParameterSpec, byte[] secret)
        throws InvalidKeyException
    {
        Wrapper kWrap = getWrapper(ktsParameterSpec.getKeyAlgorithmName());

        AlgorithmIdentifier kdfAlgorithm = ktsParameterSpec.getKdfAlgorithm();
        if (kdfAlgorithm == null)
        {
            kWrap.init(true, new KeyParameter(Arrays.copyOfRange(secret, 0, (ktsParameterSpec.getKeySize() + 7) / 8)));
        }
        else
        {
            kWrap.init(true, new KeyParameter(makeKeyBytes(ktsParameterSpec, secret)));
        }

        return kWrap;
    }

    public static Wrapper getKeyUnwrapper(KTSParameterSpec ktsParameterSpec, byte[] secret)
        throws InvalidKeyException
    {
        Wrapper kWrap = getWrapper(ktsParameterSpec.getKeyAlgorithmName());

        AlgorithmIdentifier kdfAlgorithm = ktsParameterSpec.getKdfAlgorithm();
        if (kdfAlgorithm == null)
        {
            kWrap.init(false, new KeyParameter(secret, 0, (ktsParameterSpec.getKeySize()+ 7) / 8));
        }
        else
        {
            kWrap.init(false, new KeyParameter(makeKeyBytes(ktsParameterSpec, secret)));
        }

        return kWrap;
    }

    public static Wrapper getWrapper(String keyAlgorithmName)
    {
        Wrapper kWrap;

        if (keyAlgorithmName.equalsIgnoreCase("AESWRAP") || keyAlgorithmName.equalsIgnoreCase("AES"))
        {
            kWrap = new RFC3394WrapEngine(new AESEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("ARIA"))
        {
            kWrap = new RFC3394WrapEngine(new ARIAEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("Camellia"))
        {
            kWrap = new RFC3394WrapEngine(new CamelliaEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("SEED"))
        {
            kWrap = new RFC3394WrapEngine(new SEEDEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("AES-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new AESEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("Camellia-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new CamelliaEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("ARIA-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new ARIAEngine());
        }
        else
        {
            throw new UnsupportedOperationException("unknown key algorithm: " + keyAlgorithmName);
        }
        return kWrap;
    }

    private static byte[] makeKeyBytes(KTSParameterSpec ktsSpec, byte[] secret)
        throws InvalidKeyException
    {
        AlgorithmIdentifier kdfAlgorithm = ktsSpec.getKdfAlgorithm();
        byte[] otherInfo = ktsSpec.getOtherInfo();
        byte[] keyBytes = new byte[(ktsSpec.getKeySize() + 7) / 8];

        if (X9ObjectIdentifiers.id_kdf_kdf2.equals(kdfAlgorithm.getAlgorithm()))
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
            throw new InvalidKeyException("Unrecognized KDF: " + kdfAlgorithm.getAlgorithm());
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
