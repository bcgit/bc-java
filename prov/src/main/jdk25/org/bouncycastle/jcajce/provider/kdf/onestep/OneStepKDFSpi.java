package org.bouncycastle.jcajce.provider.kdf.onestep;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.OneStepKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.jcajce.spec.OneStepKDFParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * javax.crypto.KDF SPI for the NIST SP 800-56C Rev. 2 Section 4.1 one-step KDF, over
 * {@link OneStepKDFBytesGenerator}. Each derivation builds a fresh generator, so a KDF instance may be
 * shared across threads.
 */
public class OneStepKDFSpi
    extends KDFSpi
{
    private static final int HASH = 0;
    private static final int HMAC = 1;
    private static final int KMAC128 = 2;
    private static final int KMAC256 = 3;

    private final int option;
    private final String digestName;

    OneStepKDFSpi(KDFParameters kdfParameters, int option, String digestName)
        throws InvalidAlgorithmParameterException
    {
        super(requireNull(kdfParameters, "ONESTEP does not support parameters"));
        this.option = option;
        this.digestName = digestName;
    }

    @Override
    protected KDFParameters engineGetParameters()
    {
        return null;
    }

    @Override
    protected SecretKey engineDeriveKey(String alg, AlgorithmParameterSpec derivationSpec)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException
    {
        byte[] derivedKey = engineDeriveData(derivationSpec);

        try
        {
            return new SecretKeySpec(derivedKey, alg);
        }
        finally
        {
            Arrays.clear(derivedKey);
        }
    }

    @Override
    protected byte[] engineDeriveData(AlgorithmParameterSpec derivationSpec)
        throws InvalidAlgorithmParameterException
    {
        if (!(derivationSpec instanceof OneStepKDFParameterSpec spec))
        {
            throw new InvalidAlgorithmParameterException("Invalid AlgorithmParameterSpec provided");
        }

        OneStepKDFBytesGenerator kdf;
        switch (option)
        {
        case HASH:
            kdf = new OneStepKDFBytesGenerator(createDigest());
            break;
        case HMAC:
            kdf = new OneStepKDFBytesGenerator(new HMac(createDigest()), spec.getSalt());
            break;
        case KMAC128:
            kdf = new OneStepKDFBytesGenerator(new KMAC(128, Strings.toByteArray("KDF")), spec.getSalt());
            break;
        default:
            kdf = new OneStepKDFBytesGenerator(new KMAC(256, Strings.toByteArray("KDF")), spec.getSalt());
            break;
        }

        byte[] z = spec.getZ();
        try
        {
            kdf.init(new org.bouncycastle.crypto.params.KDFParameters(z, spec.getFixedInfo()));

            byte[] result = new byte[spec.getOutputLength()];
            kdf.generateBytes(result, 0, result.length);
            return result;
        }
        finally
        {
            Arrays.clear(z);
        }
    }

    private Digest createDigest()
    {
        if ("SHA384".equals(digestName))
        {
            return new SHA384Digest();
        }
        if ("SHA512".equals(digestName))
        {
            return new SHA512Digest();
        }
        return new SHA256Digest();
    }

    private static KDFParameters requireNull(KDFParameters kdfParameters, String message)
        throws InvalidAlgorithmParameterException
    {
        if (kdfParameters != null)
        {
            throw new InvalidAlgorithmParameterException(message);
        }
        return null;
    }

    public static class WithSHA256 extends OneStepKDFSpi
    {
        public WithSHA256(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException
        {
            super(kdfParameters, HASH, "SHA256");
        }

        public WithSHA256() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class WithSHA384 extends OneStepKDFSpi
    {
        public WithSHA384(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException
        {
            super(kdfParameters, HASH, "SHA384");
        }

        public WithSHA384() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class WithSHA512 extends OneStepKDFSpi
    {
        public WithSHA512(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException
        {
            super(kdfParameters, HASH, "SHA512");
        }

        public WithSHA512() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class WithHMacSHA256 extends OneStepKDFSpi
    {
        public WithHMacSHA256(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException
        {
            super(kdfParameters, HMAC, "SHA256");
        }

        public WithHMacSHA256() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class WithHMacSHA384 extends OneStepKDFSpi
    {
        public WithHMacSHA384(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException
        {
            super(kdfParameters, HMAC, "SHA384");
        }

        public WithHMacSHA384() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class WithHMacSHA512 extends OneStepKDFSpi
    {
        public WithHMacSHA512(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException
        {
            super(kdfParameters, HMAC, "SHA512");
        }

        public WithHMacSHA512() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class WithKMAC128 extends OneStepKDFSpi
    {
        public WithKMAC128(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException
        {
            super(kdfParameters, KMAC128, null);
        }

        public WithKMAC128() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class WithKMAC256 extends OneStepKDFSpi
    {
        public WithKMAC256(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException
        {
            super(kdfParameters, KMAC256, null);
        }

        public WithKMAC256() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }
}
