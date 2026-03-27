package org.bouncycastle.jcajce;

import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.util.Arrays;

/**
 * LoadStoreParameter to allow for additional config with PKCS12 files.
 * <p>
 * Note: if you want a straight DER encoding of a PKCS#12 file you should use this.
 * </p>
 */
public class PKCS12StoreParameter
    implements LoadStoreParameter
{
    private final OutputStream out;
    private final ProtectionParameter protectionParameter;
    private final boolean forDEREncoding;
    private final boolean overwriteFriendlyName;
    private final AlgorithmIdentifier macAlgorithm;

    public static class PBMAC1WithPBKDF2Builder
    {
        private int iterationCount = 16384;
        private byte[] salt = null;
        private int keySizeinBits = 256;
        private ASN1ObjectIdentifier prf = PKCSObjectIdentifiers.id_hmacWithSHA256;
        private ASN1ObjectIdentifier mac = PKCSObjectIdentifiers.id_hmacWithSHA512;

        PBMAC1WithPBKDF2Builder()
        {

        }

        public PBMAC1WithPBKDF2Builder setIterationCount(int iterationCount)
        {
            this.iterationCount = iterationCount;

            return this;
        }

        public PBMAC1WithPBKDF2Builder setSalt(byte[] salt)
        {
            this.salt = Arrays.clone(salt);

            return this;
        }

        public PBMAC1WithPBKDF2Builder setKeySize(int keySizeinBits)
        {
            this.keySizeinBits = keySizeinBits;

            return this;
        }

        public PBMAC1WithPBKDF2Builder setPrf(ASN1ObjectIdentifier prf)
        {
            this.prf = prf;

            return this;
        }

        public PBMAC1WithPBKDF2Builder setMac(ASN1ObjectIdentifier mac)
        {
            this.mac = mac;

            return this;
        }

        public AlgorithmIdentifier build()
        {
            if (salt != null)
            {
                throw new IllegalStateException("salt must be non-null");
            }

            return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1, new PBMAC1Params(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(salt, iterationCount, keySizeinBits, new AlgorithmIdentifier(prf))),
                                                        new AlgorithmIdentifier(mac)));
        }
    }

    public static PBMAC1WithPBKDF2Builder pbmac1WithPBKDF2Builder()
    {
         return new PBMAC1WithPBKDF2Builder();
    }

    public static class Builder
    {
        private final OutputStream out;
        private final ProtectionParameter protectionParameter;
        private boolean forDEREncoding = true;
        private boolean overwriteFriendlyName = true;
        private AlgorithmIdentifier macAlgorithm = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);

        private Builder(OutputStream out, ProtectionParameter protectionParameter)
        {
            this.out = out;
            this.protectionParameter = protectionParameter;
        }

        public Builder setDEREncoding(boolean enable)
        {
            this.forDEREncoding = enable;

            return this;
        }

        public Builder setOverwriteFriendlyName(boolean enable)
        {
            this.overwriteFriendlyName = enable;

            return this;
        }

        public Builder setMacAlgorithm(AlgorithmIdentifier macAlgorithm)
        {
            this.macAlgorithm = macAlgorithm;

            return this;
        }
        
        public PKCS12StoreParameter build()
        {
            return new PKCS12StoreParameter(out, protectionParameter, forDEREncoding, overwriteFriendlyName, macAlgorithm);
        }
    }

    public static Builder builder(OutputStream out, char[] password)
    {
        return builder(out, new KeyStore.PasswordProtection(password));
    }

    public static Builder builder(OutputStream out, ProtectionParameter protectionParameter)
    {
        return new Builder(out, protectionParameter);
    }

    public PKCS12StoreParameter(OutputStream out, char[] password)
    {
        this(out, password, false);
    }

    public PKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter)
    {
        this(out, protectionParameter, false, true);
    }

    public PKCS12StoreParameter(OutputStream out, char[] password, boolean forDEREncoding)
    {
        this(out, new KeyStore.PasswordProtection(password), forDEREncoding, true);
    }

    public PKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter, boolean forDEREncoding)
    {
        this(out, protectionParameter, forDEREncoding, true);
    }

    public PKCS12StoreParameter(OutputStream out, char[] password, boolean forDEREncoding, boolean overwriteFriendlyName)
    {
        this(out, new KeyStore.PasswordProtection(password), forDEREncoding, overwriteFriendlyName);
    }

    public PKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter, boolean forDEREncoding, boolean overwriteFriendlyName)
    {
        this(out, protectionParameter, forDEREncoding, overwriteFriendlyName, new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE));
    }

    private PKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter, boolean forDEREncoding, boolean overwriteFriendlyName, AlgorithmIdentifier macAlgorithm)
    {
        this.out = out;
        this.protectionParameter = protectionParameter;
        this.forDEREncoding = forDEREncoding;
        this.overwriteFriendlyName = overwriteFriendlyName;
        this.macAlgorithm = macAlgorithm;
    }

    public OutputStream getOutputStream()
    {
        return out;
    }

    public ProtectionParameter getProtectionParameter()
    {
        return protectionParameter;
    }

    /**
     * Return whether the KeyStore used with this parameter should be DER encoded on saving.
     *
     * @return true for straight DER encoding, false otherwise,
     */
    public boolean isForDEREncoding()
    {
        return forDEREncoding;
    }

    /**
     * Return whether the KeyStore used with this parameter should overwrite friendlyName
     * when friendlyName is not present or does not equal the same name as alias
     *
     * @return true (default) to overwrite friendlyName, false otherwise,
     */
    public boolean isOverwriteFriendlyName()
    {
        return overwriteFriendlyName;
    }

    public AlgorithmIdentifier getMacAlgorithm()
    {
        return macAlgorithm;
    }
}
