package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

/**
 * ParameterSpec for a GOST 3410-1994/2001/2012 algorithm parameters.
 */
public class GOST3410ParameterSpec
    implements AlgorithmParameterSpec
{
    private final ASN1ObjectIdentifier publicKeyParamSet;
    private final ASN1ObjectIdentifier digestParamSet;
    private final ASN1ObjectIdentifier encryptionParamSet;

    /**
     * Constructor for signing parameters.
     *
     * @param publicKeyParamSet the curve parameter set name.
     */
    public GOST3410ParameterSpec(String publicKeyParamSet)
    {
        this(getOid(publicKeyParamSet), getDigestOid(publicKeyParamSet), null);
    }

    /**
     * Constructor for signing parameters.
     *
     * @param publicKeyParamSet the public key parameter set object identifier.
     * @param digestParamSet the object identifier for the digest algorithm to be associated with parameters.
     */
    public GOST3410ParameterSpec(ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet)
    {
        this(publicKeyParamSet, digestParamSet, null);
    }

    /**
     * Constructor for signing/encryption parameters.
     *
     * @param publicKeyParamSet the public key parameter set object identifier.
     * @param digestParamSet the object identifier for the digest algorithm to be associated with parameters.
     * @param encryptionParamSet the object identifier associated with encryption algorithm to use.
     */
    public GOST3410ParameterSpec(ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet, ASN1ObjectIdentifier encryptionParamSet)
    {
        this.publicKeyParamSet = publicKeyParamSet;
        this.digestParamSet = digestParamSet;
        this.encryptionParamSet = encryptionParamSet;
    }

    public String getPublicKeyParamSetName()
    {
        return ECGOST3410NamedCurves.getName(this.getPublicKeyParamSet());
    }

    /**
     * Return the object identifier for the public key parameter set.
     *
     * @return the OID for the public key parameter set.
     */
    public ASN1ObjectIdentifier getPublicKeyParamSet()
    {
        return publicKeyParamSet;
    }

    /**
     * Return the object identifier for the digest parameter set.
     *
     * @return the OID for the digest parameter set.
     */
    public ASN1ObjectIdentifier getDigestParamSet()
    {
        return digestParamSet;
    }

    /**
     * Return the object identifier for the encryption parameter set.
     *
     * @return the OID for the encryption parameter set.
     */
    public ASN1ObjectIdentifier getEncryptionParamSet()
    {
        return encryptionParamSet;
    }

    /**
     * Return the parameter sets, for example "GOST3410 parameters [publicKeyParamSet=GostR3410-2001-CryptoPro-A
     * (1.2.643.2.2.35.1), digestParamSet=1.2.643.2.2.30.1]".
     */
    public String toString()
    {
        StringBuilder buf = new StringBuilder("GOST3410 parameters [publicKeyParamSet=");

        buf.append((publicKeyParamSet == null) ? null : ECUtil.namedCurveToString(publicKeyParamSet.getId()));
        buf.append(", digestParamSet=").append(digestParamSet);
        if (encryptionParamSet != null)
        {
            buf.append(", encryptionParamSet=").append(encryptionParamSet);
        }

        return buf.append(']').toString();
    }

    private static ASN1ObjectIdentifier getOid(String paramName)
    {
        return ECGOST3410NamedCurves.getOID(paramName);
    }

    private static ASN1ObjectIdentifier getDigestOid(String paramName)
    {
        if (paramName.indexOf("12-512") > 0)
        {
            return RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512;
        }
        if (paramName.indexOf("12-256") > 0)
        {
            return RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
        }

        return CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet;
    }
}
