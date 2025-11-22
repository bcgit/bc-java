package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class HKDF extends SecretKeyFactorySpi
{
    protected String algName;
    protected HKDFBytesGenerator hkdf;


    private HKDF(String algName, Digest digest)
    {
        this.algName = algName;
        this.hkdf = new HKDFBytesGenerator(digest);
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        HKDFParameters hkdfParameters = (HKDFParameters) keySpec;
        int derivedDataLength = hkdfParameters.getIKM().length;
        hkdf.init(hkdfParameters);

        byte[] derivedData = new byte[derivedDataLength];
        hkdf.generateBytes(derivedData, 0, derivedDataLength);

        CipherParameters param = new KeyParameter(derivedData);

        return new BCPBEKey(this.algName, param) ;
    }


    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException
    {
        return null;
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException
    {
        return null;
    }


    public static class Mappings
            extends AlgorithmProvider
    {
        private static final String PREFIX = SCRYPT.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("SecretKeyFactory.HKDF", PREFIX + "HKDF");
            provider.addAlgorithm("SecretKeyFactory.HKDF-SHA256", PREFIX + "$HKDFwithSHA256");
            provider.addAlgorithm("SecretKeyFactory.HKDF-SHA384", PREFIX + "$HKDFwithSHA384");
            provider.addAlgorithm("SecretKeyFactory.HKDF-SHA512", PREFIX + "$HKDFwithSHA512");

        }
    }
    public static class HKDFwithSHA256 extends HKDF
    {
        public HKDFwithSHA256() throws InvalidAlgorithmParameterException
        {
            super("HKDF-SHA256", new SHA256Digest());
        }
    }
    public static class HKDFwithSHA384 extends HKDF
    {
        public HKDFwithSHA384() throws InvalidAlgorithmParameterException
        {
            super("HKDF-SHA384", new SHA384Digest());
        }
    }
    public static class HKDFwithSHA512 extends HKDF
    {

        public HKDFwithSHA512() throws InvalidAlgorithmParameterException
        {
            super("HKDF-SHA512", new SHA512Digest());
        }
    }
    
}
