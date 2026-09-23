package org.bouncycastle.operator.jcajce;

import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.cms.GenericHybridParameters;
import org.bouncycastle.asn1.cms.RsaKemParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.util.DEROtherInfo;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.SecretKeySizeProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.util.Arrays;

public class JceKTSKeyUnwrapper
    extends AsymmetricKeyUnwrapper
{
    private static final SecretKeySizeProvider keySizeProvider = DefaultSecretKeySizeProvider.INSTANCE;

    private OperatorHelper helper = OperatorUtils.createDefaultHelper();
    private Map extraMappings = new HashMap();
    private PrivateKey privKey;
    private byte[] partyUInfo;
    private byte[] partyVInfo;

    public JceKTSKeyUnwrapper(AlgorithmIdentifier algorithmIdentifier, PrivateKey privKey, byte[] partyUInfo, byte[] partyVInfo)
    {
        super(algorithmIdentifier);

        this.privKey = privKey;
        this.partyUInfo = Arrays.clone(partyUInfo);
        this.partyVInfo = Arrays.clone(partyVInfo);
    }

    public JceKTSKeyUnwrapper setProvider(Provider provider)
    {
        this.helper = OperatorUtils.createProviderHelper(provider);

        return this;
    }

    public JceKTSKeyUnwrapper setProvider(String providerName)
    {
        this.helper = OperatorUtils.createNamedHelper(providerName);

        return this;
    }

    /**
     * RFC 5990 sec. 4: the KEM derives the key the DEM's key-wrapping algorithm takes, so its length
     * follows from that algorithm and is not the sender's to choose. Deriving to the length the
     * message declares instead would let a few hundred bytes of CMS ask for an arbitrary KDF output:
     * a keyLength of 2^26 allocates 64MiB before anything looks at it, and one of 2^28 overflows the
     * bit count into a negative array size. The check mirrors the RFC 9629 one in JceKEMRecipient.
     */
    private static int ktsKeySizeInBits(AlgorithmIdentifier dem, BigInteger keyLength)
        throws OperatorException
    {
        int demKeySizeInBits = keySizeProvider.getKeySize(dem);

        if (demKeySizeInBits <= 0)
        {
            throw new OperatorException("unable to determine key size for wrap algorithm " + dem.getAlgorithm());
        }

        BigInteger expected = BigInteger.valueOf((demKeySizeInBits + 7) / 8);

        if (!expected.equals(keyLength))
        {
            throw new OperatorException("keyLength " + keyLength + " inconsistent with wrap algorithm "
                + dem.getAlgorithm() + ": expected " + expected);
        }

        return demKeySizeInBits;
    }

    public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException
    {
        GenericHybridParameters params = GenericHybridParameters.getInstance(this.getAlgorithmIdentifier().getParameters());
        Cipher keyCipher = helper.createAsymmetricWrapper(this.getAlgorithmIdentifier(), extraMappings);
        String symmetricWrappingAlg = helper.getWrappingAlgorithmName(params.getDem().getAlgorithm());
        RsaKemParameters kemParameters = RsaKemParameters.getInstance(params.getKem().getParameters());
        int keySizeInBits = ktsKeySizeInBits(params.getDem(), kemParameters.getKeyLength());
        Key sKey;

        try
        {
            DEROtherInfo otherInfo = new DEROtherInfo.Builder(params.getDem(), partyUInfo, partyVInfo).build();
            KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder(symmetricWrappingAlg, keySizeInBits, otherInfo.getEncoded()).withKdfAlgorithm(kemParameters.getKeyDerivationFunction()).build();

            keyCipher.init(Cipher.UNWRAP_MODE, privKey, ktsSpec);

            sKey = keyCipher.unwrap(encryptedKey, helper.getKeyAlgorithmName(encryptedKeyAlgorithm.getAlgorithm()), Cipher.SECRET_KEY);
        }
        catch (Exception e)
        {
            throw new OperatorException("Unable to unwrap contents key: " + e.getMessage(), e);
        }

        return new JceGenericKey(encryptedKeyAlgorithm, sKey);
    }
}
