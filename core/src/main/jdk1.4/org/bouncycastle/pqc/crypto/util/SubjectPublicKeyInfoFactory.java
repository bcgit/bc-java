package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.internal.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.crypto.bike.BIKEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPublicKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;

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
        if (publicKey instanceof SPHINCSPublicKeyParameters)
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
        else if (publicKey instanceof SLHDSAPublicKeyParameters)
        {
            SLHDSAPublicKeyParameters params = (SLHDSAPublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.slhdsaOidLookup(params.getParameters()));
            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
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
        else if (publicKey instanceof MLKEMPublicKeyParameters)
        {
            MLKEMPublicKeyParameters params = (MLKEMPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mlkemOidLookup(params.getParameters()));

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
        else if (publicKey instanceof MLDSAPublicKeyParameters)
        {
            MLDSAPublicKeyParameters params = (MLDSAPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mldsaOidLookup(params.getParameters()));

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
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }
}
