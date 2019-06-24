package org.bouncycastle.jcajce.provider.asymmetric.dstu;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ua.DSTU4145BinaryField;
import org.bouncycastle.asn1.ua.DSTU4145ECBinary;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.asn1.ua.DSTU4145PointEncoder;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;

public class BCDSTU4145PublicKey
    implements ECPublicKey, org.bouncycastle.jce.interfaces.ECPublicKey, ECPointEncoder
{
    static final long serialVersionUID = 7026240464295649314L;

    private String algorithm = "DSTU4145";
    private boolean withCompression;

    private transient ECPublicKeyParameters   ecPublicKey;
    private transient ECParameterSpec ecSpec;
    private transient DSTU4145Params dstuParams;

    public BCDSTU4145PublicKey(
        BCDSTU4145PublicKey key)
    {
        this.ecPublicKey = key.ecPublicKey;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.dstuParams = key.dstuParams;
    }

    public BCDSTU4145PublicKey(
        ECPublicKeySpec spec)
    {
        this.ecSpec = spec.getParams();
        this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(ecSpec, spec.getW()), EC5Util.getDomainParameters(null, ecSpec));
    }

    public BCDSTU4145PublicKey(
        org.bouncycastle.jce.spec.ECPublicKeySpec spec,
        ProviderConfiguration configuration)
    {
        if (spec.getParams() != null) // can be null if implictlyCa
        {
            ECCurve curve = spec.getParams().getCurve();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

            // this may seem a little long-winded but it's how we pick up the custom curve.
            this.ecPublicKey = new ECPublicKeyParameters(
                spec.getQ(), ECUtil.getDomainParameters(configuration, spec.getParams()));
            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
        }
        else
        {
            org.bouncycastle.jce.spec.ECParameterSpec s = configuration.getEcImplicitlyCa();

            this.ecPublicKey = new ECPublicKeyParameters(s.getCurve().createPoint(spec.getQ().getAffineXCoord().toBigInteger(), spec.getQ().getAffineYCoord().toBigInteger()), EC5Util.getDomainParameters(configuration, (ECParameterSpec)null));
            this.ecSpec = null;
        }
    }

    public BCDSTU4145PublicKey(
        String algorithm,
        ECPublicKeyParameters params,
        ECParameterSpec spec)
    {
        ECDomainParameters dp = params.getParameters();

        this.algorithm = algorithm;
        this.ecPublicKey = params;

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = createSpec(ellipticCurve, dp);
        }
        else
        {
            this.ecSpec = spec;
        }
    }

    public BCDSTU4145PublicKey(
        String algorithm,
        ECPublicKeyParameters params,
        org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = createSpec(ellipticCurve, dp);
        }
        else
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec);
        }

        this.ecPublicKey = params;
    }

    /*
     * called for implicitCA
     */
    public BCDSTU4145PublicKey(
        String algorithm,
        ECPublicKeyParameters params)
    {
        this.algorithm = algorithm;
        this.ecPublicKey = params;
        this.ecSpec = null;
    }

    private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp)
    {
        return new ECParameterSpec(
            ellipticCurve,
            EC5Util.convertPoint(dp.getG()),
            dp.getN(),
            dp.getH().intValue());
    }

    BCDSTU4145PublicKey(
        SubjectPublicKeyInfo info)
    {
        populateFromPubKeyInfo(info);
    }

    private void reverseBytes(byte[] bytes)
    {
        byte tmp;

        for (int i = 0; i < bytes.length / 2; i++)
        {
            tmp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = tmp;
        }
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo info)
    {
        DERBitString bits = info.getPublicKeyData();
        ASN1OctetString key;
        this.algorithm = "DSTU4145";

        try
        {
            key = (ASN1OctetString)ASN1Primitive.fromByteArray(bits.getBytes());
        }
        catch (IOException ex)
        {
            throw new IllegalArgumentException("error recovering public key");
        }

        byte[] keyEnc = key.getOctets();

        if (info.getAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145le))
        {
            reverseBytes(keyEnc);
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(info.getAlgorithm().getParameters());
        org.bouncycastle.jce.spec.ECParameterSpec spec = null;
        X9ECParameters x9Params = null;

        if (seq.getObjectAt(0) instanceof ASN1Integer)
        {
            x9Params = X9ECParameters.getInstance(seq);
            spec = new  org.bouncycastle.jce.spec.ECParameterSpec(x9Params.getCurve(), x9Params.getG(), x9Params.getN(), x9Params.getH(), x9Params.getSeed());
        }
        else
        {
            dstuParams = DSTU4145Params.getInstance(seq);

            if (dstuParams.isNamedCurve())
            {
                ASN1ObjectIdentifier curveOid = dstuParams.getNamedCurve();
                ECDomainParameters ecP = DSTU4145NamedCurves.getByOID(curveOid);

                spec = new ECNamedCurveParameterSpec(curveOid.getId(), ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
            }
            else
            {
                DSTU4145ECBinary binary = dstuParams.getECBinary();
                byte[] b_bytes = binary.getB();
                if (info.getAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145le))
                {
                    reverseBytes(b_bytes);
                }
                DSTU4145BinaryField field = binary.getField();
                ECCurve curve = new ECCurve.F2m(field.getM(), field.getK1(), field.getK2(), field.getK3(), binary.getA(), new BigInteger(1, b_bytes));
                byte[] g_bytes = binary.getG();
                if (info.getAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145le))
                {
                    reverseBytes(g_bytes);
                }
                spec = new org.bouncycastle.jce.spec.ECParameterSpec(curve, DSTU4145PointEncoder.decodePoint(curve, g_bytes), binary.getN());
            }
        }

        ECCurve curve = spec.getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getSeed());

        if (dstuParams != null)
        {
            ECPoint g = EC5Util.convertPoint(spec.getG());

            if (dstuParams.isNamedCurve())
            {
                String name = dstuParams.getNamedCurve().getId();

                ecSpec = new ECNamedCurveSpec(name, ellipticCurve, g, spec.getN(), spec.getH());
            }
            else
            {
                ecSpec = new ECParameterSpec(ellipticCurve, g, spec.getN(), spec.getH().intValue());
            }
        }
        else
        {
            ecSpec = EC5Util.convertToSpec(x9Params);
        }

        //this.q = curve.createPoint(new BigInteger(1, x), new BigInteger(1, y), false);
        this.ecPublicKey = new ECPublicKeyParameters(DSTU4145PointEncoder.decodePoint(curve, keyEnc), EC5Util.getDomainParameters(null, ecSpec));
    }

    public byte[] getSbox()
    {
        if (null != dstuParams)
        {
            return dstuParams.getDKE();
        }
        else
        {
            return DSTU4145Params.getDefaultDKE();
        }
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
        ASN1Encodable params;
        SubjectPublicKeyInfo info;

        if (dstuParams != null)
        {
            params = dstuParams;
        }
        else
        {
            if (ecSpec instanceof ECNamedCurveSpec)
            {
                params = new DSTU4145Params(new ASN1ObjectIdentifier(((ECNamedCurveSpec)ecSpec).getName()));
            }
            else
            {   // strictly speaking this may not be applicable...
                ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

                X9ECParameters ecP = new X9ECParameters(
                    curve,
                    new X9ECPoint(EC5Util.convertPoint(curve, ecSpec.getGenerator()), withCompression),
                    ecSpec.getOrder(),
                    BigInteger.valueOf(ecSpec.getCofactor()),
                    ecSpec.getCurve().getSeed());

                params = new X962Parameters(ecP);
            }
        }

        // NOTE: 'withCompression' is ignored here
        byte[] encKey = DSTU4145PointEncoder.encodePoint(ecPublicKey.getQ());

        try
        {
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(UAObjectIdentifiers.dstu4145be, params), new DEROctetString(encKey));
        }
        catch (IOException e)
        {
            return null;
        }

        return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
    }

    public ECParameterSpec getParams()
    {
        return ecSpec;
    }

    public org.bouncycastle.jce.spec.ECParameterSpec getParameters()
    {
        if (ecSpec == null)     // implictlyCA
        {
            return null;
        }

        return EC5Util.convertSpec(ecSpec);
    }

    public ECPoint getW()
    {
        return EC5Util.convertPoint(ecPublicKey.getQ());
    }

    public org.bouncycastle.math.ec.ECPoint getQ()
    {
        org.bouncycastle.math.ec.ECPoint q = ecPublicKey.getQ();

        if (ecSpec == null)
        {
            return q.getDetachedPoint();
        }

        return q;
    }

    ECPublicKeyParameters engineGetKeyParameters()
    {
        return ecPublicKey;
    }

    org.bouncycastle.jce.spec.ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return EC5Util.convertSpec(ecSpec);
        }

        return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
    }

    public String toString()
    {
        return ECUtil.publicKeyToString(algorithm, ecPublicKey.getQ(), engineGetSpec());
    }

    public void setPointFormat(String style)
    {
        withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof BCDSTU4145PublicKey))
        {
            return false;
        }

        BCDSTU4145PublicKey other = (BCDSTU4145PublicKey)o;

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
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
