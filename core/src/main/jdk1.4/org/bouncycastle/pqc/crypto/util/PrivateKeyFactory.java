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
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.CMCEPrivateKey;
import org.bouncycastle.pqc.asn1.FalconPrivateKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.asn1.SPHINCSPLUSPrivateKey;
import org.bouncycastle.pqc.asn1.SPHINCSPLUSPublicKey;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
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
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
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

        if (algOID.equals(PQCObjectIdentifiers.sphincs256))
        {
            return new SPHINCSPrivateKeyParameters(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets(),
                Utils.sphincs256LookupTreeAlgName(SPHINCS256KeyParams.getInstance(algId.getParameters())));
        }
        else if (algOID.equals(PQCObjectIdentifiers.newHope))
        {
            return new NHPrivateKeyParameters(convert(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets()));
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
        else if (Utils.slhdsaParams.containsKey(algOID))
        {
            SLHDSAParameters spParams = Utils.slhdsaParamsLookup(algOID);
            ASN1OctetString slhdsaKey = parseOctetString(keyInfo.getPrivateKey(), spParams.getN() * 4);

            return new SLHDSAPrivateKeyParameters(spParams, slhdsaKey.getOctets());
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
        else if (algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_512) ||
            algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_768) ||
            algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_1024))
        {
            ASN1Primitive mlkemKey = parsePrimitiveString(keyInfo.getPrivateKey(), 64);
            MLKEMParameters mlkemParams = Utils.mlkemParamsLookup(algOID);

            MLKEMPublicKeyParameters pubParams = null;
            if (keyInfo.getPublicKeyData() != null)
            {
                pubParams = PublicKeyFactory.MLKEMKeyConverter.getPublicKeyParams(mlkemParams, keyInfo.getPublicKeyData());
            }

            if (mlkemKey instanceof ASN1OctetString)
            {
                // TODO This should be explicitly EXPANDED_KEY or SEED (tag already removed) but is length-flexible
                return new MLKEMPrivateKeyParameters(mlkemParams, ((ASN1OctetString)mlkemKey).getOctets(), pubParams);
            }
            else if (mlkemKey instanceof ASN1Sequence)
            {
                ASN1Sequence keySeq = (ASN1Sequence)mlkemKey;
                byte[] seed = ASN1OctetString.getInstance(keySeq.getObjectAt(0)).getOctets();
                byte[] encoding = ASN1OctetString.getInstance(keySeq.getObjectAt(1)).getOctets();

                // TODO This should only allow seed but is length-flexible
                MLKEMPrivateKeyParameters mlkemPriv = new MLKEMPrivateKeyParameters(mlkemParams, seed, pubParams);
                if (!Arrays.constantTimeAreEqual(mlkemPriv.getEncoded(), encoding))
                {
                    throw new IllegalArgumentException("inconsistent " + mlkemParams.getName() + " private key");
                }

                return mlkemPriv;
            }

            throw new IllegalArgumentException("invalid " + mlkemParams.getName() + " private key");
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
        else if (Utils.mldsaParams.containsKey(algOID))
        {
            ASN1Encodable mldsaKey = parsePrimitiveString(keyInfo.getPrivateKey(), 32);
            MLDSAParameters mldsaParams = Utils.mldsaParamsLookup(algOID);

            MLDSAPublicKeyParameters pubParams = null;
            if (keyInfo.getPublicKeyData() != null)
            {
                pubParams = PublicKeyFactory.MLDSAConverter.getPublicKeyParams(mldsaParams, keyInfo.getPublicKeyData());
            }

            if (mldsaKey instanceof ASN1OctetString)
            {
                // TODO This should be explicitly EXPANDED_KEY or SEED (tag already removed) but is length-flexible
                return new MLDSAPrivateKeyParameters(mldsaParams, ((ASN1OctetString)mldsaKey).getOctets(), pubParams);
            }
            else if (mldsaKey instanceof ASN1Sequence)
            {
                ASN1Sequence keySeq = (ASN1Sequence)mldsaKey;
                byte[] seed = ASN1OctetString.getInstance(keySeq.getObjectAt(0)).getOctets();
                byte[] encoding = ASN1OctetString.getInstance(keySeq.getObjectAt(1)).getOctets();

                // TODO This should only allow seed but is length-flexible
                MLDSAPrivateKeyParameters mldsaPriv = new MLDSAPrivateKeyParameters(mldsaParams, seed, pubParams);
                if (!Arrays.constantTimeAreEqual(mldsaPriv.getEncoded(), encoding))
                {
                    throw new IllegalArgumentException("inconsistent " + mldsaParams.getName() + " private key");
                }

                return mldsaPriv;
            }

            throw new IllegalArgumentException("invalid " + mldsaParams.getName() + " private key");
        }
        else if (algOID.equals(BCObjectIdentifiers.dilithium2)
            || algOID.equals(BCObjectIdentifiers.dilithium3) || algOID.equals(BCObjectIdentifiers.dilithium5))
        {
            ASN1Encodable keyObj = keyInfo.parsePrivateKey();
            DilithiumParameters dilParams = Utils.dilithiumParamsLookup(algOID);

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
                    DilithiumPublicKeyParameters pubParams = PublicKeyFactory.DilithiumConverter.getPublicKeyParams(dilParams, keyInfo.getPublicKeyData());

                    return new DilithiumPrivateKeyParameters(dilParams,
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
                    return new DilithiumPrivateKeyParameters(dilParams,
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
                    DilithiumPublicKeyParameters pubParams = PublicKeyFactory.DilithiumConverter.getPublicKeyParams(dilParams, keyInfo.getPublicKeyData());
                    return new DilithiumPrivateKeyParameters(dilParams, data, pubParams);
                }
                return new DilithiumPrivateKeyParameters(dilParams, data, null);
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
        else
        {
            throw new RuntimeException("algorithm identifier in private key not recognised");
        }
    }

    /**
     * So it seems for the new PQC algorithms, there's a couple of approaches to what goes in the OCTET STRING
     */
    private static ASN1OctetString parseOctetString(ASN1OctetString octStr, int expectedLength)
        throws IOException
    {
        byte[] data = octStr.getOctets();
        //
        // it's the right length for a RAW encoding, just return it.
        //
        if (data.length == expectedLength)
        {
            return octStr;
        }

        //
        // possible internal OCTET STRING, possibly long form with or without the internal OCTET STRING
        ASN1OctetString obj = Utils.parseOctetData(data);

        if (obj != null)
        {
            return ASN1OctetString.getInstance(obj);
        }

        return octStr;
    }

    /**
     * So it seems for the new PQC algorithms, there's a couple of approaches to what goes in the OCTET STRING
     * and in this case there may also be SEQUENCE.
     */
    private static ASN1Primitive parsePrimitiveString(ASN1OctetString octStr, int expectedLength)
        throws IOException
    {
        byte[] data = octStr.getOctets();
        //
        // it's the right length for a RAW encoding, just return it.
        //
        if (data.length == expectedLength)
        {
            return octStr;
        }

        //
        // possible internal OCTET STRING, possibly long form with or without the internal OCTET STRING
        // or possible SEQUENCE
        ASN1Encodable obj = Utils.parseData(data);

        if (obj instanceof ASN1OctetString)
        {
            return ASN1OctetString.getInstance(obj);
        }
        if (obj instanceof ASN1Sequence)
        {
            return ASN1Sequence.getInstance(obj);
        }

        return octStr;
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
