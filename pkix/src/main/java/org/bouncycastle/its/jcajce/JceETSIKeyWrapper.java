package org.bouncycastle.its.jcajce;

import java.security.Provider;
import java.security.interfaces.ECPublicKey;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.its.ETSIKeyWrapper;
import org.bouncycastle.jcajce.spec.IESKEMParameterSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.oer.its.ieee1609dot2.EncryptedDataEncryptionKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EciesP256EncryptedKey;
import org.bouncycastle.util.Arrays;

public class JceETSIKeyWrapper
    implements ETSIKeyWrapper
{
    private final ECPublicKey recipientKey;
    private final byte[] recipientHash;
    private final JcaJceHelper helper;

    private JceETSIKeyWrapper(ECPublicKey key, byte[] recipientHash, JcaJceHelper helper)
    {
        this.recipientKey = key;
        this.recipientHash = recipientHash;
        this.helper = helper;
    }


    public EncryptedDataEncryptionKey wrap(byte[] secretKey)
    {
        try
        {
            Cipher etsiKem = helper.createCipher("ETSIKEMwithSHA256");
            etsiKem.init(Cipher.WRAP_MODE, recipientKey, new IESKEMParameterSpec(recipientHash, true));
            byte[] wrappedKey = etsiKem.wrap(new SecretKeySpec(secretKey, "AES"));

            int size = (recipientKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;

            if (wrappedKey[0] == 0x04)
            {
                size = 2 * size + 1;
            }
            else
            {
                size = size + 1;
            }

            SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(recipientKey.getEncoded());
            ASN1ObjectIdentifier curveID = ASN1ObjectIdentifier.getInstance(pkInfo.getAlgorithm().getParameters());

            EciesP256EncryptedKey key = EciesP256EncryptedKey.builder()
                .setV(EccP256CurvePoint.createEncodedPoint(Arrays.copyOfRange(wrappedKey, 0, size)))
                .setC(Arrays.copyOfRange(wrappedKey, size, size + secretKey.length))
                .setT(Arrays.copyOfRange(wrappedKey, size + secretKey.length, wrappedKey.length))
                .createEciesP256EncryptedKey();

            if (curveID.equals(SECObjectIdentifiers.secp256r1))
            {
                return EncryptedDataEncryptionKey.eciesNistP256(key);
            }
            else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
            {
                return EncryptedDataEncryptionKey.eciesBrainpoolP256r1(key);
            }
            else
            {
                throw new IllegalStateException("recipient key curve is not P-256 or Brainpool P256r1");
            }


        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public static class Builder
    {
        private final ECPublicKey recipientKey;
        private final byte[] recipientHash;
        private JcaJceHelper helper = new DefaultJcaJceHelper();

        public Builder(ECPublicKey recipientKey, byte[] recipientHash)
        {
            this.recipientKey = recipientKey;
            this.recipientHash = recipientHash;
        }

        /**
         * Sets the JCE provider to source cryptographic primitives from.
         *
         * @param provider the JCE provider to use.
         * @return the current builder.
         */
        public Builder setProvider(Provider provider)
        {
            this.helper = new ProviderJcaJceHelper(provider);

            return this;
        }

        /**
         * Sets the JCE provider to source cryptographic primitives from.
         *
         * @param providerName the name of the JCE provider to use.
         * @return the current builder.
         */
        public Builder setProvider(String providerName)
        {
            this.helper = new NamedJcaJceHelper(providerName);

            return this;
        }

        public JceETSIKeyWrapper build()
        {
            return new JceETSIKeyWrapper(recipientKey, recipientHash, helper);
        }
    }

}
