package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

public class BCECPrivateKey
    implements ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
{
    private String          algorithm = "EC";
    private boolean         withCompression;

    private transient BigInteger              d;
    private transient ECParameterSpec         ecSpec;
    private transient ProviderConfiguration   configuration;
    private transient DERBitString            publicKey;

    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    protected BCECPrivateKey()
    {
    }

    BCECPrivateKey(
        ECPrivateKey    key,
        ProviderConfiguration configuration)
    {
        this.d = key.getD();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParameters();
        this.configuration = configuration;
    }

    public BCECPrivateKey(
        String              algorithm,
        ECPrivateKeySpec    spec,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.d = spec.getD();
        this.ecSpec = spec.getParams();
        this.configuration = configuration;
    }

    public BCECPrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params,
        BCECPublicKey          pubKey,
        ECParameterSpec         spec,
        ProviderConfiguration configuration)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;
        this.d = params.getD();
        this.configuration = configuration;

        if (spec == null)
        {
            this.ecSpec = new ECParameterSpec(
                            dp.getCurve(),
                            dp.getG(),
                            dp.getN(),
                            dp.getH(),
                            dp.getSeed());
        }
        else
        {
            this.ecSpec = spec;
        }

        publicKey = getPublicKeyDetails(pubKey);
    }

    public BCECPrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params,
        ProviderConfiguration   configuration)
    {
        this.algorithm = algorithm;
        this.d = params.getD();
        this.ecSpec = null;
        this.configuration = configuration;
    }

    public BCECPrivateKey(
        String             algorithm,
        BCECPrivateKey    key)
    {
        this.algorithm = algorithm;
        this.d = key.d;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.publicKey = key.publicKey;
        this.attrCarrier = key.attrCarrier;
        this.configuration = key.configuration;
    }

    BCECPrivateKey(
        PrivateKeyInfo      info,
        ProviderConfiguration configuration)
        throws IOException
    {
        this.configuration = configuration;

        populateFromPrivKeyInfo(info);
    }

    BCECPrivateKey(
        String              algorithm,
        PrivateKeyInfo      info,
        ProviderConfiguration configuration)
        throws IOException
    {
        this.configuration = configuration;
        populateFromPrivKeyInfo(info);
        this.algorithm = algorithm;
    }

    private void populateFromPrivKeyInfo(PrivateKeyInfo info)
        throws IOException
    {
        X962Parameters      params = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());

        if (params.isNamedCurve())
        {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)params.getParameters();
            X9ECParameters      ecP = ECUtil.getNamedCurveByOid(oid);

            ecSpec = new ECNamedCurveParameterSpec(
                                        ECUtil.getCurveName(oid),
                                        ecP.getCurve(),
                                        ecP.getG(),
                                        ecP.getN(),
                                        ecP.getH(),
                                        ecP.getSeed());
        }
        else if (params.isImplicitlyCA())
        {
            ecSpec = null;
        }
        else
        {
            X9ECParameters          ecP = X9ECParameters.getInstance(params.getParameters());
            ecSpec = new ECParameterSpec(ecP.getCurve(),
                                            ecP.getG(),
                                            ecP.getN(),
                                            ecP.getH(),
                                            ecP.getSeed());
        }

        if (info.parsePrivateKey() instanceof ASN1Integer)
        {
            ASN1Integer          derD = ASN1Integer.getInstance(info.parsePrivateKey());

            this.d = derD.getValue();
        }
        else
        {
            ECPrivateKeyStructure   ec = new ECPrivateKeyStructure(ASN1Sequence.getInstance(info.parsePrivateKey()));

            this.d = ec.getKey();
            this.publicKey = ec.getPublicKey();
        }
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        X962Parameters  params = ECUtils.getDomainParametersFromName(ecSpec, withCompression);

        int orderBitLength;
        if (ecSpec == null)
        {
            orderBitLength = ECUtil.getOrderBitLength(configuration, null, this.getD());
        }
        else
        {
            orderBitLength = ECUtil.getOrderBitLength(configuration, ecSpec.getN(), this.getD());
        }

        PrivateKeyInfo          info;
        org.bouncycastle.asn1.sec.ECPrivateKey            keyStructure;

        if (publicKey != null)
        {
            keyStructure = new org.bouncycastle.asn1.sec.ECPrivateKey(orderBitLength, this.getD(), publicKey, params);
        }
        else
        {
            keyStructure = new org.bouncycastle.asn1.sec.ECPrivateKey(orderBitLength, this.getD(), params);
        }

        try
        {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), keyStructure);

            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public ECParameterSpec getParams()
    {
        return (ECParameterSpec)ecSpec;
    }

    public ECParameterSpec getParameters()
    {
        return (ECParameterSpec)ecSpec;
    }
    
    public BigInteger getD()
    {
        return d;
    }

    public void setBagAttribute(
        ASN1ObjectIdentifier oid,
        ASN1Encodable        attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public ASN1Encodable getBagAttribute(
        ASN1ObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }
    
    public void setPointFormat(String style)
    {
       withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return ecSpec;
        }

        return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
    }

    public String toString()
    {
        return ECUtil.privateKeyToString("EC", d, engineGetSpec());
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof BCECPrivateKey))
        {
            return false;
        }

        BCECPrivateKey other = (BCECPrivateKey)o;

        return getD().equals(other.getD()) && (engineGetSpec().equals(other.engineGetSpec()));
    }

    public int hashCode()
    {
        return getD().hashCode() ^ engineGetSpec().hashCode();
    }

    private DERBitString getPublicKeyDetails(BCECPublicKey   pub)
    {
        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));

            return info.getPublicKeyData();
        }
        catch (IOException e)
        {   // should never happen
            return null;
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

        this.configuration = BouncyCastleProvider.CONFIGURATION;
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
