package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.CMCEPrivateKey;
import org.bouncycastle.pqc.asn1.McElieceCCA2PrivateKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.BDS;
import org.bouncycastle.pqc.crypto.xmss.BDSStateMap;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/**
 * Factory for creating private key objects from PKCS8 PrivateKeyInfo objects.
 */
public class PrivateKeyFactory
{
    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding.
     * 
     * @param privateKeyInfoData the PrivateKeyInfo encoding
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(byte[] privateKeyInfoData) throws IOException
    {
        return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyInfoData)));
    }

    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding read from a
     * stream.
     * 
     * @param inStr the stream to read the PrivateKeyInfo encoding from
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(InputStream inStr) throws IOException
    {
        return createKey(PrivateKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    /**
     * Create a private key parameter from the passed in PKCS8 PrivateKeyInfo object.
     * 
     * @param keyInfo the PrivateKeyInfo object containing the key material
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(PrivateKeyInfo keyInfo) throws IOException
    {
        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();

        if (algOID.on(BCObjectIdentifiers.qTESLA))
        {
            ASN1OctetString qTESLAPriv = ASN1OctetString.getInstance(keyInfo.parsePrivateKey());

            return new QTESLAPrivateKeyParameters(Utils.qTeslaLookupSecurityCategory(keyInfo.getPrivateKeyAlgorithm()), qTESLAPriv.getOctets());
        }
        else if (algOID.equals(BCObjectIdentifiers.sphincs256))
        {
            return new SPHINCSPrivateKeyParameters(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets(),
                Utils.sphincs256LookupTreeAlgName(SPHINCS256KeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters())));
        }
        else if (algOID.equals(BCObjectIdentifiers.newHope))
        {
            return new NHPrivateKeyParameters(convert(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets()));
        }
        else if (algOID.equals(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            ASN1BitString pubKey = keyInfo.getPublicKeyData();

            if (Pack.bigEndianToInt(keyEnc, 0) == 1)
            {
                if (pubKey != null)
                {
                    byte[] pubEnc = pubKey.getOctets();

                    return LMSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length), Arrays.copyOfRange(pubEnc, 4, pubEnc.length));
                }
                return LMSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
            }
            else
            {
                if (pubKey != null)
                {
                    byte[] pubEnc = pubKey.getOctets();

                    return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length), pubEnc);
                }
                return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
            }
        }
        else if (algOID.on(BCObjectIdentifiers.sphincsPlus))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            SPHINCSPlusParameters spParams = SPHINCSPlusParameters.getParams(Integers.valueOf(Pack.bigEndianToInt(keyEnc, 0)));

            return new SPHINCSPlusPrivateKeyParameters(spParams, Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
        }
        else if (algOID.on(BCObjectIdentifiers.picnic))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            PicnicParameters pParams = Utils.picnicParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new PicnicPrivateKeyParameters(pParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_mceliece))
        {
            CMCEPrivateKey cmceKey = CMCEPrivateKey.getInstance(keyInfo.parsePrivateKey());
            CMCEParameters spParams = Utils.mcElieceParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new CMCEPrivateKeyParameters(spParams, cmceKey.getDelta(), cmceKey.getC(), cmceKey.getG(), cmceKey.getAlpha(), cmceKey.getS());
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_frodo))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            FrodoParameters spParams = Utils.frodoParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new FrodoPrivateKeyParameters(spParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_saber))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            SABERParameters spParams = Utils.saberParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new SABERPrivateKeyParameters(spParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_sike))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            SIKEParameters spParams = Utils.sikeParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new SIKEPrivateKeyParameters(spParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_ntru))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            NTRUParameters spParams = Utils.ntruParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new NTRUPrivateKeyParameters(spParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_kyber))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            KyberParameters spParams = Utils.kyberParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new KyberPrivateKeyParameters(spParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_ntrulprime))
        {
            ASN1Sequence keyEnc = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());

            NTRULPRimeParameters spParams = Utils.ntrulprimeParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new NTRULPRimePrivateKeyParameters(spParams,
                            ASN1OctetString.getInstance(keyEnc.getObjectAt(0)).getOctets(),
                            ASN1OctetString.getInstance(keyEnc.getObjectAt(1)).getOctets(),
                            ASN1OctetString.getInstance(keyEnc.getObjectAt(2)).getOctets(),
                            ASN1OctetString.getInstance(keyEnc.getObjectAt(3)).getOctets());
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_sntruprime))
        {
            ASN1Sequence keyEnc = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());

            SNTRUPrimeParameters spParams = Utils.sntruprimeParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new SNTRUPrimePrivateKeyParameters(spParams,
                            ASN1OctetString.getInstance(keyEnc.getObjectAt(0)).getOctets(),
                            ASN1OctetString.getInstance(keyEnc.getObjectAt(1)).getOctets(),
                            ASN1OctetString.getInstance(keyEnc.getObjectAt(2)).getOctets(),
                            ASN1OctetString.getInstance(keyEnc.getObjectAt(3)).getOctets(),
                            ASN1OctetString.getInstance(keyEnc.getObjectAt(4)).getOctets());
        }
        else if (algOID.equals(BCObjectIdentifiers.dilithium2)
            || algOID.equals(BCObjectIdentifiers.dilithium3) || algOID.equals(BCObjectIdentifiers.dilithium5))
        {
            ASN1Sequence keyEnc = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());

            DilithiumParameters spParams = Utils.dilithiumParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new DilithiumPrivateKeyParameters(spParams,
                ASN1BitString.getInstance(keyEnc.getObjectAt(0)).getOctets(),
                ASN1BitString.getInstance(keyEnc.getObjectAt(1)).getOctets(),
                ASN1BitString.getInstance(keyEnc.getObjectAt(2)).getOctets(),
                ASN1BitString.getInstance(keyEnc.getObjectAt(3)).getOctets(),
                ASN1BitString.getInstance(keyEnc.getObjectAt(4)).getOctets(),
                ASN1BitString.getInstance(keyEnc.getObjectAt(5)).getOctets());
        }
        else if (algOID.equals(BCObjectIdentifiers.falcon_512) || algOID.equals(BCObjectIdentifiers.falcon_1024))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            FalconParameters spParams = Utils.falconParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new FalconPrivateKeyParameters(spParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_bike))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            BIKEParameters bikeParams = Utils.bikeParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            byte[] h0 = Arrays.copyOfRange(keyEnc, 0, bikeParams.getRByte());
            byte[] h1 = Arrays.copyOfRange(keyEnc, bikeParams.getRByte(), 2*bikeParams.getRByte());
            byte[] sigma = Arrays.copyOfRange(keyEnc, 2*bikeParams.getRByte(), keyEnc.length);
            return new BIKEPrivateKeyParameters(h0, h1, sigma, bikeParams);
        }
        else if (algOID.equals(BCObjectIdentifiers.xmss))
        {
            XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
            ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

            XMSSPrivateKey xmssPrivateKey = XMSSPrivateKey.getInstance(keyInfo.parsePrivateKey());

            try
            {
                XMSSPrivateKeyParameters.Builder keyBuilder = new XMSSPrivateKeyParameters
                    .Builder(new XMSSParameters(keyParams.getHeight(), Utils.getDigest(treeDigest)))
                    .withIndex(xmssPrivateKey.getIndex())
                    .withSecretKeySeed(xmssPrivateKey.getSecretKeySeed())
                    .withSecretKeyPRF(xmssPrivateKey.getSecretKeyPRF())
                    .withPublicSeed(xmssPrivateKey.getPublicSeed())
                    .withRoot(xmssPrivateKey.getRoot());

                if (xmssPrivateKey.getVersion() != 0)
                {
                    keyBuilder.withMaxIndex(xmssPrivateKey.getMaxIndex());
                }

                if (xmssPrivateKey.getBdsState() != null)
                {
                    BDS bds = (BDS)XMSSUtil.deserialize(xmssPrivateKey.getBdsState(), BDS.class);
                    keyBuilder.withBDSState(bds.withWOTSDigest(treeDigest));
                }

                return keyBuilder.build();
            }
            catch (ClassNotFoundException e)
            {
                throw new IOException("ClassNotFoundException processing BDS state: " + e.getMessage());
            }
        }
        else if (algOID.equals(PQCObjectIdentifiers.xmss_mt))
        {
            XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
            ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

            try
            {
                XMSSMTPrivateKey xmssMtPrivateKey = XMSSMTPrivateKey.getInstance(keyInfo.parsePrivateKey());

                XMSSMTPrivateKeyParameters.Builder keyBuilder = new XMSSMTPrivateKeyParameters
                    .Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), Utils.getDigest(treeDigest)))
                    .withIndex(xmssMtPrivateKey.getIndex())
                    .withSecretKeySeed(xmssMtPrivateKey.getSecretKeySeed())
                    .withSecretKeyPRF(xmssMtPrivateKey.getSecretKeyPRF())
                    .withPublicSeed(xmssMtPrivateKey.getPublicSeed())
                    .withRoot(xmssMtPrivateKey.getRoot());

                if (xmssMtPrivateKey.getVersion() != 0)
                {
                    keyBuilder.withMaxIndex(xmssMtPrivateKey.getMaxIndex());
                }

                if (xmssMtPrivateKey.getBdsState() != null)
                {
                    BDSStateMap bdsState = (BDSStateMap)XMSSUtil.deserialize(xmssMtPrivateKey.getBdsState(), BDSStateMap.class);
                    keyBuilder.withBDSState(bdsState.withWOTSDigest(treeDigest));
                }

                return keyBuilder.build();
            }
            catch (ClassNotFoundException e)
            {
                throw new IOException("ClassNotFoundException processing BDS state: " + e.getMessage());
            }
        }
        else if (algOID.equals(PQCObjectIdentifiers.mcElieceCca2))
        {
            McElieceCCA2PrivateKey mKey = McElieceCCA2PrivateKey.getInstance(keyInfo.parsePrivateKey());

            return new McElieceCCA2PrivateKeyParameters(mKey.getN(), mKey.getK(), mKey.getField(), mKey.getGoppaPoly(), mKey.getP(), Utils.getDigestName(mKey.getDigest().getAlgorithm()));
        }
        else
        {
            throw new RuntimeException("algorithm identifier in private key not recognised");
        }
    }

    private static short[] convert(byte[] octets)
    {
        short[] rv = new short[octets.length / 2];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Pack.littleEndianToShort(octets, i * 2);
        }

        return rv;
    }
}
