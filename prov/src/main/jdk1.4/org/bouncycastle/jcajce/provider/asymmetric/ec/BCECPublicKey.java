package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

public class BCECPublicKey
    implements ECPublicKey, ECPointEncoder
{
    static final long serialVersionUID = 2422789860422731812L;

    private String    algorithm = "EC";
    private boolean   withCompression;

    private transient ECPublicKeyParameters   ecPublicKey;
    private transient ECParameterSpec         ecSpec;
    private transient ProviderConfiguration   configuration;

    public BCECPublicKey(
        String              algorithm,
        BCECPublicKey      key)
    {
        this.algorithm = algorithm;
        this.ecPublicKey = key.ecPublicKey;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.configuration = key.configuration;
    }

    public BCECPublicKey(
        String              algorithm,
        ECPublicKeySpec     spec,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;

        if (spec.getParams() != null)
        {
            this.ecSpec = spec.getParams();
            this.ecPublicKey = new ECPublicKeyParameters(ecSpec.getCurve().createPoint(spec.getQ().getAffineXCoord().toBigInteger(), spec.getQ().getAffineYCoord().toBigInteger()), ECUtil.getDomainParameters(configuration, spec.getParams()));
        }
        else
        {
            this.ecSpec = null;

            org.bouncycastle.jce.spec.ECParameterSpec s = configuration.getEcImplicitlyCa();

            this.ecPublicKey = new ECPublicKeyParameters(s.getCurve().createPoint(spec.getQ().getAffineXCoord().toBigInteger(), spec.getQ().getAffineYCoord().toBigInteger()), ECUtil.getDomainParameters(configuration, (ECParameterSpec)null));
        }

        this.configuration = configuration;
    }

    public BCECPublicKey(
        String                  algorithm,
        ECPublicKeyParameters   params,
        ECParameterSpec         spec,
        ProviderConfiguration   configuration)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;
        this.ecPublicKey = params;
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
    }

    public BCECPublicKey(
        String                  algorithm,
        ECPublicKeyParameters   params,
        ProviderConfiguration   configuration)
    {
        this.algorithm = algorithm;
        this.ecPublicKey = params;
        this.ecSpec = null;
        this.configuration = configuration;
    }

    BCECPublicKey(
        ECPublicKey     key,
        ProviderConfiguration configuration)
    {
        this.ecPublicKey = new ECPublicKeyParameters(key.getQ(), ECUtil.getDomainParameters(configuration, key.getParameters()));
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParameters();
        this.configuration = configuration;
    }

    BCECPublicKey(
        String            algorithm,
        ECPoint           q,
        ECParameterSpec   ecSpec,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.ecPublicKey = new ECPublicKeyParameters(q, ECUtil.getDomainParameters(configuration, ecSpec));
        this.ecSpec = ecSpec;
        this.configuration = configuration;
    }

    BCECPublicKey(
        SubjectPublicKeyInfo    info,
        ProviderConfiguration   configuration)
    {
        this.configuration = configuration;

        populateFromPubKeyInfo(info);
    }

    BCECPublicKey(
        String                  algorithm,
        SubjectPublicKeyInfo    info,
        ProviderConfiguration   configuration)
    {
        this.configuration = configuration;
        populateFromPubKeyInfo(info);
        this.algorithm = algorithm;
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo info)
    {
        X962Parameters          params = X962Parameters.getInstance(info.getAlgorithmId().getParameters());
        ECCurve                 curve;

        if (params.isNamedCurve())
        {
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
            X9ECParameters      ecP = ECUtil.getNamedCurveByOid(oid);

            ecSpec = new ECNamedCurveParameterSpec(
                                        ECUtil.getCurveName(oid),
                                        ecP.getCurve(),
                                        ecP.getG(),
                                        ecP.getN(),
                                        ecP.getH(),
                                        ecP.getSeed());
            curve = ((ECParameterSpec)ecSpec).getCurve();
        }
        else if (params.isImplicitlyCA())
        {
            ecSpec = null;
            curve = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getCurve();
        }
        else
        {
            X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());
            ecSpec = new ECParameterSpec(
                                        ecP.getCurve(),
                                        ecP.getG(),
                                        ecP.getN(),
                                        ecP.getH(),
                                        ecP.getSeed());
            curve = ((ECParameterSpec)ecSpec).getCurve();
        }

        DERBitString    bits = info.getPublicKeyData();
        byte[]          data = bits.getBytes();
        ASN1OctetString key = new DEROctetString(data);

        //
        // extra octet string - one of our old certs...
        //
        if (data[0] == 0x04 && data[1] == data.length - 2
            && (data[2] == 0x02 || data[2] == 0x03))
        {
            int qLength = new X9IntegerConverter().getByteLength(curve);

            if (qLength >= data.length - 3)
            {
                try
                {
                    key = (ASN1OctetString)ASN1Primitive.fromByteArray(data);
                }
                catch (IOException ex)
                {
                    throw new IllegalArgumentException("error recovering public key");
                }
            }
        }

        X9ECPoint derQ = new X9ECPoint(curve, key);

        this.ecPublicKey = new ECPublicKeyParameters(derQ.getPoint(), ECUtil.getDomainParameters(configuration, params));
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(
            X9ObjectIdentifiers.id_ecPublicKey,
            ECUtils.getDomainParametersFromName(ecSpec, withCompression));

        byte[] pubKeyOctets = ecPublicKey.getQ().getEncoded(withCompression);

        // stored curve is null if ImplicitlyCa
        return KeyUtil.getEncodedSubjectPublicKeyInfo(algId, pubKeyOctets);
    }

    public ECParameterSpec getParams()
    {
        return (ECParameterSpec)ecSpec;
    }

    public ECParameterSpec getParameters()
    {
        return (ECParameterSpec)ecSpec;
    }
    
    public org.bouncycastle.math.ec.ECPoint getQ()
    {
        org.bouncycastle.math.ec.ECPoint q = ecPublicKey.getQ();
        
        if (ecSpec == null)
        {
            return q.getDetachedPoint();
        }

        return ecPublicKey.getQ();
    }

    ECPublicKeyParameters engineGetKeyParameters()
    {
        return ecPublicKey;
    }

    public String toString()
    {
        return ECUtil.publicKeyToString("EC", ecPublicKey.getQ(), engineGetSpec());
    }

    public void setPointFormat(String style)
    {
       withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return (ECParameterSpec)ecSpec;
        }

        return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof BCECPublicKey))
        {
            return false;
        }

        BCECPublicKey other = (BCECPublicKey)o;

        return ecPublicKey.getQ().equals(other.ecPublicKey.getQ()) && (engineGetSpec().equals(other.engineGetSpec()));
    }

    public int hashCode()
    {
        return ecPublicKey.getQ().hashCode() ^ engineGetSpec().hashCode();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

        this.configuration = BouncyCastleProvider.CONFIGURATION;
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
