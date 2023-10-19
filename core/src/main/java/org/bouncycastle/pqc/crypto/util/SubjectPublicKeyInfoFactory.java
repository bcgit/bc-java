package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.McElieceCCA2PublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTPublicKey;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;
import org.bouncycastle.pqc.crypto.bike.BIKEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPublicKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.qtesla.QTESLAPublicKeyParameters;

/**
 * Factory to create ASN.1 subject public key info objects from lightweight public keys.
 */
public class SubjectPublicKeyInfoFactory
{
    private SubjectPublicKeyInfoFactory()
    {

    }

    /**
     * Create a SubjectPublicKeyInfo public key.
     *
     * @param publicKey the key to be encoded into the info object.
     * @return a SubjectPublicKeyInfo representing the key.
     * @throws java.io.IOException on an error encoding the key
     */
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        if (publicKey instanceof QTESLAPublicKeyParameters)
        {
            QTESLAPublicKeyParameters keyParams = (QTESLAPublicKeyParameters)publicKey;
            AlgorithmIdentifier algorithmIdentifier = Utils.qTeslaLookupAlgID(keyParams.getSecurityCategory());

            return new SubjectPublicKeyInfo(algorithmIdentifier, keyParams.getPublicData());
        }
        else if (publicKey instanceof SPHINCSPublicKeyParameters)
        {
            SPHINCSPublicKeyParameters params = (SPHINCSPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256,
                new SPHINCS256KeyParams(Utils.sphincs256LookupTreeAlgID(params.getTreeDigest())));
            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getKeyData());
        }
        else if (publicKey instanceof NHPublicKeyParameters)
        {
            NHPublicKeyParameters params = (NHPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);
            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getPubData());
        }
        else if (publicKey instanceof LMSPublicKeyParameters)
        {
            LMSPublicKeyParameters params = (LMSPublicKeyParameters)publicKey;

            byte[] encoding = Composer.compose().u32str(1).bytes(params).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof HSSPublicKeyParameters)
        {
            HSSPublicKeyParameters params = (HSSPublicKeyParameters)publicKey;

            byte[] encoding = Composer.compose().u32str(params.getL()).bytes(params.getLMSPublicKey()).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof SPHINCSPlusPublicKeyParameters)
        {
            SPHINCSPlusPublicKeyParameters params = (SPHINCSPlusPublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params.getParameters()));
            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
        else if (publicKey instanceof CMCEPublicKeyParameters)
        {
            CMCEPublicKeyParameters params = (CMCEPublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mcElieceOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
        else if (publicKey instanceof XMSSPublicKeyParameters)
        {
            XMSSPublicKeyParameters keyParams = (XMSSPublicKeyParameters)publicKey;

            byte[] publicSeed = keyParams.getPublicSeed();
            byte[] root = keyParams.getRoot();
            byte[] keyEnc = keyParams.getEncoded();
            if (keyEnc.length > publicSeed.length + root.length)
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IsaraObjectIdentifiers.id_alg_xmss);

                return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(keyEnc));
            }
            else
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
                    new XMSSKeyParams(keyParams.getParameters().getHeight(), Utils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));

                return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSPublicKey(publicSeed, root));
            }
        }
        else if (publicKey instanceof XMSSMTPublicKeyParameters)
        {
            XMSSMTPublicKeyParameters keyParams = (XMSSMTPublicKeyParameters)publicKey;

            byte[] publicSeed = keyParams.getPublicSeed();
            byte[] root = keyParams.getRoot();
            byte[] keyEnc = keyParams.getEncoded();
            if (keyEnc.length > publicSeed.length + root.length)
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IsaraObjectIdentifiers.id_alg_xmssmt);

                return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(keyEnc));
            }
            else
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(),
                    Utils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));
                return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSMTPublicKey(keyParams.getPublicSeed(), keyParams.getRoot()));
            }
        }
        else if (publicKey instanceof McElieceCCA2PublicKeyParameters)
        {
            McElieceCCA2PublicKeyParameters pub = (McElieceCCA2PublicKeyParameters)publicKey;
            McElieceCCA2PublicKey mcEliecePub = new McElieceCCA2PublicKey(pub.getN(), pub.getT(), pub.getG(), Utils.getAlgorithmIdentifier(pub.getDigest()));
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2);

            return new SubjectPublicKeyInfo(algorithmIdentifier, mcEliecePub);
        }
        else if (publicKey instanceof FrodoPublicKeyParameters)
        {
            FrodoPublicKeyParameters params = (FrodoPublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.frodoOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof SABERPublicKeyParameters)
        {
            SABERPublicKeyParameters params = (SABERPublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.saberOidLookup(params.getParameters()));
            
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DERSequence(new DEROctetString(encoding)));
        }
        else if (publicKey instanceof PicnicPublicKeyParameters)
        {
            PicnicPublicKeyParameters params = (PicnicPublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.picnicOidLookup(params.getParameters()));
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof NTRUPublicKeyParameters)
        {
            NTRUPublicKeyParameters params = (NTRUPublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.ntruOidLookup(params.getParameters()));
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof FalconPublicKeyParameters)
        {
            FalconPublicKeyParameters params = (FalconPublicKeyParameters)publicKey;

            byte[] encoding = params.getH();
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.falconOidLookup(params.getParameters()));

            byte[] keyEnc = new byte[encoding.length + 1];
            keyEnc[0] = (byte)(0x00 + params.getParameters().getLogN());
            System.arraycopy(encoding, 0, keyEnc, 1, encoding.length);

            return new SubjectPublicKeyInfo(algorithmIdentifier, keyEnc);
        }
        else if (publicKey instanceof KyberPublicKeyParameters)
        {
            KyberPublicKeyParameters params = (KyberPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.kyberOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getEncoded());
        }
        else if (publicKey instanceof NTRULPRimePublicKeyParameters)
        {
            NTRULPRimePublicKeyParameters params = (NTRULPRimePublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.ntrulprimeOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof SNTRUPrimePublicKeyParameters)
        {
            SNTRUPrimePublicKeyParameters params = (SNTRUPrimePublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sntruprimeOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof DilithiumPublicKeyParameters)
        {
            DilithiumPublicKeyParameters params = (DilithiumPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.dilithiumOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getEncoded());
        }
        else if (publicKey instanceof BIKEPublicKeyParameters)
        {
            BIKEPublicKeyParameters params = (BIKEPublicKeyParameters) publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.bikeOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
        else if (publicKey instanceof HQCPublicKeyParameters)
        {
            HQCPublicKeyParameters params = (HQCPublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.hqcOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
        else if (publicKey instanceof RainbowPublicKeyParameters)
        {
            RainbowPublicKeyParameters params = (RainbowPublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.rainbowOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }
}
