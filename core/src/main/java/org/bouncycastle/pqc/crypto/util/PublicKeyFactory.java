package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Factory to create asymmetric public key parameters for asymmetric ciphers from range of
 * ASN.1 encoded SubjectPublicKeyInfo objects.
 */
public class PublicKeyFactory
{
    private static Map converters = new HashMap();

    static
    {
        converters.put(PQCObjectIdentifiers.qTESLA_p_I, new QTeslaConverter());
        converters.put(PQCObjectIdentifiers.qTESLA_p_III, new QTeslaConverter());
        converters.put(PQCObjectIdentifiers.sphincs256, new SPHINCSConverter());
        converters.put(PQCObjectIdentifiers.newHope, new NHConverter());
        converters.put(PQCObjectIdentifiers.xmss, new XMSSConverter());
        converters.put(PQCObjectIdentifiers.xmss_mt, new XMSSMTConverter());
        converters.put(IsaraObjectIdentifiers.id_alg_xmss, new XMSSConverter());
        converters.put(IsaraObjectIdentifiers.id_alg_xmssmt, new XMSSMTConverter());
        converters.put(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, new LMSConverter());
    }

    /**
     * Create a public key from a SubjectPublicKeyInfo encoding
     *
     * @param keyInfoData the SubjectPublicKeyInfo encoding
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(byte[] keyInfoData)
        throws IOException
    {
        return createKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(keyInfoData)));
    }

    /**
     * Create a public key from a SubjectPublicKeyInfo encoding read from a stream
     *
     * @param inStr the stream to read the SubjectPublicKeyInfo encoding from
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(InputStream inStr)
        throws IOException
    {
        return createKey(SubjectPublicKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    /**
     * Create a public key from the passed in SubjectPublicKeyInfo
     *
     * @param keyInfo the SubjectPublicKeyInfo containing the key data
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return createKey(keyInfo, null);
    }

    /**
     * Create a public key from the passed in SubjectPublicKeyInfo
     *
     * @param keyInfo       the SubjectPublicKeyInfo containing the key data
     * @param defaultParams default parameters that might be needed.
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        throws IOException
    {
        AlgorithmIdentifier algId = keyInfo.getAlgorithm();
        SubjectPublicKeyInfoConverter converter = (SubjectPublicKeyInfoConverter)converters.get(algId.getAlgorithm());

        if (converter != null)
        {
            return converter.getPublicKeyParameters(keyInfo, defaultParams);
        }
        else
        {
            throw new IOException("algorithm identifier in public key not recognised: " + algId.getAlgorithm());
        }
    }

    private static abstract class SubjectPublicKeyInfoConverter
    {
        abstract AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException;
    }

    private static class QTeslaConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            return new QTESLAPublicKeyParameters(Utils.qTeslaLookupSecurityCategory(keyInfo.getAlgorithm()), keyInfo.getPublicKeyData().getOctets());
        }
    }

    private static class SPHINCSConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            return new SPHINCSPublicKeyParameters(keyInfo.getPublicKeyData().getBytes(),
                Utils.sphincs256LookupTreeAlgName(SPHINCS256KeyParams.getInstance(keyInfo.getAlgorithm().getParameters())));
        }
    }

    private static class NHConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            return new NHPublicKeyParameters(keyInfo.getPublicKeyData().getBytes());
        }
    }

    private static class XMSSConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());

            if (keyParams != null)
            {
                ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();
                XMSSPublicKey xmssPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());

                return new XMSSPublicKeyParameters
                    .Builder(new XMSSParameters(keyParams.getHeight(), Utils.getDigest(treeDigest)))
                    .withPublicSeed(xmssPublicKey.getPublicSeed())
                    .withRoot(xmssPublicKey.getRoot()).build();
            }
            else
            {
                byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();

                return new XMSSPublicKeyParameters
                    .Builder(XMSSParameters.lookupByOID(Pack.bigEndianToInt(keyEnc, 0)))
                    .withPublicKey(keyEnc).build();
            }
        }
    }

    private static class XMSSMTConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());

            if (keyParams != null)
            {
                ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

                XMSSPublicKey xmssMtPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());

                return new XMSSMTPublicKeyParameters
                    .Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), Utils.getDigest(treeDigest)))
                    .withPublicSeed(xmssMtPublicKey.getPublicSeed())
                    .withRoot(xmssMtPublicKey.getRoot()).build();
            }
            else
            {
                byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();

                return new XMSSMTPublicKeyParameters
                    .Builder(XMSSMTParameters.lookupByOID(Pack.bigEndianToInt(keyEnc, 0)))
                    .withPublicKey(keyEnc).build();
            }
        }
    }

    private static class LMSConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();

            if (Pack.bigEndianToInt(keyEnc, 0) == 1)
            {
                return LMSPublicKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
            }
            else
            {
                // public key with extra tree height
                if (keyEnc.length == 64)
                {
                    keyEnc = Arrays.copyOfRange(keyEnc, 4, keyEnc.length);
                }
                return HSSPublicKeyParameters.getInstance(keyEnc);
            }
        }
    }
}
