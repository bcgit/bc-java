package org.bouncycastle.jcajce.provider.symmetric.pbepbkdf2;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import static org.bouncycastle.crypto.PBEParametersGenerator.PKCS5PasswordToUTF8Bytes;

public class PBEPBKDF2Spi
    extends KDFSpi
{

    PKCS5S2ParametersGenerator generator;

    protected PBEPBKDF2Spi(KDFParameters kdfParameters)
            throws InvalidAlgorithmParameterException
    {
        super(kdfParameters);
//        this.generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
    }
    protected PBEPBKDF2Spi(KDFParameters kdfParameters, Digest digest)
            throws InvalidAlgorithmParameterException
    {
        super(kdfParameters);
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

        generator.init(PKCS5PasswordToUTF8Bytes(password), salt, iterCount);

        KeyParameter params = (KeyParameter) generator.generateDerivedParameters(keyLen);
        byte[] derivedData = params.getKey();

        Arrays.fill(password, (char) 0);

        return derivedData;
    }

    public static class PBKDF2withUTF8
            extends PBEPBKDF2Spi
    {
        public PBKDF2withUTF8() throws InvalidAlgorithmParameterException
        {
            super(null);
        }
    }

    public static class PBKDF2withSHA224
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA224() throws InvalidAlgorithmParameterException
        {
            super(null, new SHA224Digest());
        }
    }

    public static class PBKDF2withSHA256
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA256() throws InvalidAlgorithmParameterException
        {
            super(null, new SHA256Digest());
        }
    }

    public static class PBKDF2withSHA384
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA384() throws InvalidAlgorithmParameterException
        {
            super(null, new SHA384Digest());
        }
    }

    public static class PBKDF2withSHA512
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA512() throws InvalidAlgorithmParameterException
        {
            super(null, new SHA512Digest());
        }
    }

    public static class PBKDF2withSHA512_224
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA512_224() throws InvalidAlgorithmParameterException
        {
            super(null, new SHA512tDigest(224));
        }
    }

    public static class PBKDF2withSHA512_256
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA512_256() throws InvalidAlgorithmParameterException
        {
            super(null, new SHA512tDigest(256));
        }
    }

    public static class PBKDF2withGOST3411
            extends PBEPBKDF2Spi
    {
        public PBKDF2withGOST3411() throws InvalidAlgorithmParameterException
        {
            super(null, new GOST3411Digest());
        }
    }

    public static class PBKDF2withSHA3_224
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA3_224() throws InvalidAlgorithmParameterException
        {
            super(null, new SHA3Digest(224));
        }
    }

    public static class PBKDF2withSHA3_256
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA3_256() throws InvalidAlgorithmParameterException
        {
            super(null, new SHA3Digest(256));
        }
    }

    public static class PBKDF2withSHA3_384
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA3_384() throws InvalidAlgorithmParameterException
        {
            super(null,  new SHA3Digest(384));
        }
    }

    public static class PBKDF2withSHA3_512
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSHA3_512() throws InvalidAlgorithmParameterException
        {
            super(null, new SHA3Digest(512));
        }
    }

    public static class PBKDF2with8BIT
            extends PBEPBKDF2Spi
    {
        public PBKDF2with8BIT() throws InvalidAlgorithmParameterException
        {
            super(null);
            super.generator = new PKCS5S2ParametersGenerator(); //TODO: test this
        }
    }

    public static class PBKDF2withSM3
            extends PBEPBKDF2Spi
    {
        public PBKDF2withSM3() throws InvalidAlgorithmParameterException
        {
            super(null, new SM3Digest());
        }
    }
}
