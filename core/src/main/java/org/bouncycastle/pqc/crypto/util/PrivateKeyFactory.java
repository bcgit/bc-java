package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.CMCEPrivateKey;
import org.bouncycastle.pqc.asn1.FalconPrivateKey;
import org.bouncycastle.pqc.asn1.McElieceCCA2PrivateKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.asn1.SPHINCSPLUSPrivateKey;
import org.bouncycastle.pqc.asn1.SPHINCSPLUSPublicKey;
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
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
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
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
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
    public static AsymmetricKeyParameter createKey(byte[] privateKeyInfoData)
        throws IOException
    {
        if (privateKeyInfoData == null)
        {
            throw new IllegalArgumentException("privateKeyInfoData array null");
        }
        if (privateKeyInfoData.length == 0)
        {
            throw new IllegalArgumentException("privateKeyInfoData array empty");
        }
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
    public static AsymmetricKeyParameter createKey(InputStream inStr)
        throws IOException
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
    public static AsymmetricKeyParameter createKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        if (keyInfo == null)
        {
            throw new IllegalArgumentException("keyInfo array null");
        }

        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();

        if (algOID.on(PQCObjectIdentifiers.qTESLA))
        {
            ASN1OctetString qTESLAPriv = ASN1OctetString.getInstance(keyInfo.parsePrivateKey());

            return new QTESLAPrivateKeyParameters(Utils.qTeslaLookupSecurityCategory(algId), qTESLAPriv.getOctets());
        }
        else if (algOID.equals(PQCObjectIdentifiers.sphincs256))
        {
            return new SPHINCSPrivateKeyParameters(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets(),
                Utils.sphincs256LookupTreeAlgName(SPHINCS256KeyParams.getInstance(algId.getParameters())));
        }
        else if (algOID.equals(PQCObjectIdentifiers.newHope))
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
        else if (algOID.on(BCObjectIdentifiers.sphincsPlus) || algOID.on(BCObjectIdentifiers.sphincsPlus_interop))
        {
            SPHINCSPlusParameters spParams = Utils.sphincsPlusParamsLookup(algOID);

            ASN1Encodable obj = keyInfo.parsePrivateKey();
            if (obj instanceof ASN1Sequence)
            {
                SPHINCSPLUSPrivateKey spKey = SPHINCSPLUSPrivateKey.getInstance(obj);
                SPHINCSPLUSPublicKey publicKey = spKey.getPublicKey();
                return new SPHINCSPlusPrivateKeyParameters(spParams, spKey.getSkseed(), spKey.getSkprf(),
                    publicKey.getPkseed(), publicKey.getPkroot());
            }
            else
            {
                return new SPHINCSPlusPrivateKeyParameters(spParams, ASN1OctetString.getInstance(obj).getOctets());
            }
        }
        else if (algOID.on(BCObjectIdentifiers.picnic))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            PicnicParameters pParams = Utils.picnicParamsLookup(algOID);

            return new PicnicPrivateKeyParameters(pParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_mceliece))
        {
            CMCEPrivateKey cmceKey = CMCEPrivateKey.getInstance(keyInfo.parsePrivateKey());
            CMCEParameters spParams = Utils.mcElieceParamsLookup(algOID);

            return new CMCEPrivateKeyParameters(spParams, cmceKey.getDelta(), cmceKey.getC(), cmceKey.getG(), cmceKey.getAlpha(), cmceKey.getS());
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_frodo))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            FrodoParameters spParams = Utils.frodoParamsLookup(algOID);

            return new FrodoPrivateKeyParameters(spParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_saber))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            SABERParameters spParams = Utils.saberParamsLookup(algOID);

            return new SABERPrivateKeyParameters(spParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_ntru))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            NTRUParameters spParams = Utils.ntruParamsLookup(algOID);

            return new NTRUPrivateKeyParameters(spParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_kyber))
        {
            ASN1OctetString kyberKey = ASN1OctetString.getInstance(keyInfo.parsePrivateKey());
            KyberParameters kyberParams = Utils.kyberParamsLookup(algOID);

            return new KyberPrivateKeyParameters(kyberParams, kyberKey.getOctets());
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_ntrulprime))
        {
            ASN1Sequence keyEnc = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());

            NTRULPRimeParameters spParams = Utils.ntrulprimeParamsLookup(algOID);

            return new NTRULPRimePrivateKeyParameters(spParams,
                ASN1OctetString.getInstance(keyEnc.getObjectAt(0)).getOctets(),
                ASN1OctetString.getInstance(keyEnc.getObjectAt(1)).getOctets(),
                ASN1OctetString.getInstance(keyEnc.getObjectAt(2)).getOctets(),
                ASN1OctetString.getInstance(keyEnc.getObjectAt(3)).getOctets());
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_sntruprime))
        {
            ASN1Sequence keyEnc = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());

            SNTRUPrimeParameters spParams = Utils.sntruprimeParamsLookup(algOID);

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
            ASN1Encodable keyObj = keyInfo.parsePrivateKey();
            DilithiumParameters spParams = Utils.dilithiumParamsLookup(algOID);

            if (keyObj instanceof ASN1Sequence)
            {
                ASN1Sequence keyEnc = ASN1Sequence.getInstance(keyObj);

                int version = ASN1Integer.getInstance(keyEnc.getObjectAt(0)).intValueExact();
                if (version != 0)
                {
                    throw new IOException("unknown private key version: " + version);
                }

                if (keyInfo.getPublicKeyData() != null)
                {
                    DilithiumPublicKeyParameters pubParams = PublicKeyFactory.DilithiumConverter.getPublicKeyParams(spParams, keyInfo.getPublicKeyData());

                    return new DilithiumPrivateKeyParameters(spParams,
                        ASN1BitString.getInstance(keyEnc.getObjectAt(1)).getOctets(),
                        ASN1BitString.getInstance(keyEnc.getObjectAt(2)).getOctets(),
                        ASN1BitString.getInstance(keyEnc.getObjectAt(3)).getOctets(),
                        ASN1BitString.getInstance(keyEnc.getObjectAt(4)).getOctets(),
                        ASN1BitString.getInstance(keyEnc.getObjectAt(5)).getOctets(),
                        ASN1BitString.getInstance(keyEnc.getObjectAt(6)).getOctets(),
                        pubParams.getT1()); // encT1
                }
                else
                {
                    return new DilithiumPrivateKeyParameters(spParams,
                        ASN1BitString.getInstance(keyEnc.getObjectAt(1)).getOctets(),
                        ASN1BitString.getInstance(keyEnc.getObjectAt(2)).getOctets(),
                        ASN1BitString.getInstance(keyEnc.getObjectAt(3)).getOctets(),
                        ASN1BitString.getInstance(keyEnc.getObjectAt(4)).getOctets(),
                        ASN1BitString.getInstance(keyEnc.getObjectAt(5)).getOctets(),
                        ASN1BitString.getInstance(keyEnc.getObjectAt(6)).getOctets(),
                        null);
                }
            }
            else if (keyObj instanceof DEROctetString)
            {
                byte[] data = ASN1OctetString.getInstance(keyObj).getOctets();
                if (keyInfo.getPublicKeyData() != null)
                {
                    DilithiumPublicKeyParameters pubParams = PublicKeyFactory.DilithiumConverter.getPublicKeyParams(spParams, keyInfo.getPublicKeyData());
                    return new DilithiumPrivateKeyParameters(spParams, data, pubParams);
                }
                return new DilithiumPrivateKeyParameters(spParams, data, null);
            }
            else
            {
                throw new IOException("not supported");
            }
        }
        else if (algOID.equals(BCObjectIdentifiers.falcon_512) || algOID.equals(BCObjectIdentifiers.falcon_1024))
        {
            FalconPrivateKey falconKey = FalconPrivateKey.getInstance(keyInfo.parsePrivateKey());
            FalconParameters falconParams = Utils.falconParamsLookup(algOID);

            return new FalconPrivateKeyParameters(falconParams, falconKey.getf(), falconKey.getG(), falconKey.getF(), falconKey.getPublicKey().getH());
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_bike))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            BIKEParameters bikeParams = Utils.bikeParamsLookup(algOID);

            byte[] h0 = Arrays.copyOfRange(keyEnc, 0, bikeParams.getRByte());
            byte[] h1 = Arrays.copyOfRange(keyEnc, bikeParams.getRByte(), 2 * bikeParams.getRByte());
            byte[] sigma = Arrays.copyOfRange(keyEnc, 2 * bikeParams.getRByte(), keyEnc.length);
            return new BIKEPrivateKeyParameters(bikeParams, h0, h1, sigma);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_hqc))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            HQCParameters hqcParams = Utils.hqcParamsLookup(algOID);

            return new HQCPrivateKeyParameters(hqcParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.rainbow))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            RainbowParameters rainbowParams = Utils.rainbowParamsLookup(algOID);

            return new RainbowPrivateKeyParameters(rainbowParams, keyEnc);
        }
        else if (algOID.equals(PQCObjectIdentifiers.xmss))
        {
            XMSSKeyParams keyParams = XMSSKeyParams.getInstance(algId.getParameters());
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
            XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(algId.getParameters());
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
