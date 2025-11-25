package org.bouncycastle.jcajce.provider.kdf.pbepbkdf2;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.spec.PBKDF2ParameterSpec;
import org.bouncycastle.util.Arrays;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

class PBEPBKDF2Spi
    extends KDFSpi
{
    final PasswordConverter pwdConverter;
    final PKCS5S2ParametersGenerator generator;

    protected PBEPBKDF2Spi(KDFParameters kdfParameters)
            throws InvalidAlgorithmParameterException
    {
        this(kdfParameters, new SHA1Digest(), PasswordConverter.UTF8);
    }

    protected PBEPBKDF2Spi(KDFParameters kdfParameters, Digest digest)
            throws InvalidAlgorithmParameterException
    {
        this(kdfParameters, digest, PasswordConverter.UTF8);
    }

    protected PBEPBKDF2Spi(KDFParameters kdfParameters, Digest digest, PasswordConverter pwdConverter)
            throws InvalidAlgorithmParameterException
    {
        super(requireNull(kdfParameters, "PBEPBKDF2" + " does not support parameters"));
        this.pwdConverter = pwdConverter;
        this.generator = new PKCS5S2ParametersGenerator(digest);
    }

    @Override
    protected KDFParameters engineGetParameters()
    {
        return null;
    }
    
    @Override
    protected SecretKey engineDeriveKey(String alg, AlgorithmParameterSpec derivationSpec) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException
    {
        byte[] derivedKey = engineDeriveData(derivationSpec);
        
        return new SecretKeySpec(derivedKey, alg);
    }

    @Override
    protected byte[] engineDeriveData(AlgorithmParameterSpec derivationSpec) throws InvalidAlgorithmParameterException
    {
        if (!(derivationSpec instanceof PBEKeySpec))
        {
            throw new InvalidAlgorithmParameterException("Invalid AlgorithmParameterSpec provided");
        }

        PBEKeySpec spec = (PBEKeySpec) derivationSpec;

        char[] password = spec.getPassword();
        byte[] salt = spec.getSalt();
        int iterCount = spec.getIterationCount();
        int keyLen = spec.getKeyLength();

        if (password == null || salt == null)
        {
            throw new InvalidAlgorithmParameterException("Password and salt cannot be null");
        }

        generator.init(pwdConverter.convert(password), salt, iterCount);

        KeyParameter params = (KeyParameter) generator.generateDerivedParameters(keyLen);
        byte[] derivedData = params.getKey();

        Arrays.fill(password, (char) 0);

        return derivedData;
    }

    private static KDFParameters requireNull(KDFParameters kdfParameters,
                                             String message) throws InvalidAlgorithmParameterException
    {
        if (kdfParameters != null)
        {
            throw new InvalidAlgorithmParameterException(message);
        }
        return null;
    }

    public static class PBKDF2withUTF8
            extends PBEPBKDF2Spi
    {
        public PBKDF2withUTF8(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA1Digest());
        }
        public PBKDF2withUTF8() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSHA224
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA224(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA224Digest());
        }
        public PBKDF2withSHA224() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSHA256
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA256(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA256Digest());
        }
        public PBKDF2withSHA256() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSHA384
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA384(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA384Digest());
        }
        public PBKDF2withSHA384() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSHA512
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA512(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA512Digest());
        }
        public PBKDF2withSHA512() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSHA512_224
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA512_224(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA512tDigest(224));
        }
        public PBKDF2withSHA512_224() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSHA512_256
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA512_256(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA512tDigest(256));
        }
        public PBKDF2withSHA512_256() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withGOST3411
            extends PBEPBKDF2Spi
    {
        public PBKDF2withGOST3411(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new GOST3411Digest());
        }
        public PBKDF2withGOST3411() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSHA3_224
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA3_224(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA3Digest(224));
        }
        public PBKDF2withSHA3_224() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSHA3_256
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA3_256(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA3Digest(256));
        }
        public PBKDF2withSHA3_256() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSHA3_384
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA3_384(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters,  new SHA3Digest(384));
        }
        public PBKDF2withSHA3_384() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSHA3_512
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA3_512(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA3Digest(512));
        }
        public PBKDF2withSHA3_512() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2with8BIT
            extends PBEPBKDF2Spi
    {
        public PBKDF2with8BIT(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SHA1Digest(), PasswordConverter.ASCII);
        }
        public PBKDF2with8BIT() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class PBKDF2withSM3
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSM3(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters, new SM3Digest());
        }
        public PBKDF2withSM3() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }
}
