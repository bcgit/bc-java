package org.bouncycastle.operator.jcajce;

import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.cms.GenericHybridParameters;
import org.bouncycastle.asn1.cms.RsaKemParameters;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.util.DEROtherInfo;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.AsymmetricKeyWrapper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.util.Arrays;

public class JceKTSKeyWrapper
    extends AsymmetricKeyWrapper
{
    private final String symmetricWrappingAlg;
    private final int keySizeInBits;
    private final byte[] partyUInfo;
    private final byte[] partyVInfo;

    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private PublicKey publicKey;
    private SecureRandom random;

    public JceKTSKeyWrapper(PublicKey publicKey, String symmetricWrappingAlg, int keySizeInBits, byte[] partyUInfo, byte[] partyVInfo)
    {
        super(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_rsa_KEM, new GenericHybridParameters(new AlgorithmIdentifier(ISOIECObjectIdentifiers.id_kem_rsa, new RsaKemParameters(new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)), (keySizeInBits + 7) / 8)), JceSymmetricKeyWrapper.determineKeyEncAlg(symmetricWrappingAlg, keySizeInBits))));

        this.publicKey = publicKey;
        this.symmetricWrappingAlg = symmetricWrappingAlg;
        this.keySizeInBits = keySizeInBits;
        this.partyUInfo = Arrays.clone(partyUInfo);
        this.partyVInfo = Arrays.clone(partyVInfo);
    }

    public JceKTSKeyWrapper(X509Certificate certificate, String symmetricWrappingAlg, int keySizeInBits, byte[] partyUInfo, byte[] partyVInfo)
    {
        this(certificate.getPublicKey(), symmetricWrappingAlg, keySizeInBits, partyUInfo, partyVInfo);
    }

    public JceKTSKeyWrapper setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JceKTSKeyWrapper setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public JceKTSKeyWrapper setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException
    {
        Cipher keyEncryptionCipher = helper.createAsymmetricWrapper(getAlgorithmIdentifier().getAlgorithm(), new HashMap());

        try
        {
            DEROtherInfo otherInfo = new DEROtherInfo.Builder(JceSymmetricKeyWrapper.determineKeyEncAlg(symmetricWrappingAlg, keySizeInBits), partyUInfo, partyVInfo).build();
            KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder(symmetricWrappingAlg, keySizeInBits, otherInfo.getEncoded()).build();

            keyEncryptionCipher.init(Cipher.WRAP_MODE, publicKey, ktsSpec, random);

            return keyEncryptionCipher.wrap(OperatorUtils.getJceKey(encryptionKey));
        }
        catch (Exception e)
        {
            throw new OperatorException("Unable to wrap contents key: " + e.getMessage(), e);
        }
    }
}
