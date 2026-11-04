package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.legacy.bike.BIKEKeyGenerationParameters;
import org.bouncycastle.pqc.legacy.bike.BIKEKeyPairGenerator;
import org.bouncycastle.pqc.legacy.bike.BIKEParameters;
import org.bouncycastle.pqc.legacy.bike.BIKEPublicKeyParameters;
import org.bouncycastle.pqc.legacy.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.legacy.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.legacy.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.legacy.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * NTRU, Dilithium and BIKE public keys are written raw into the SubjectPublicKeyInfo BIT STRING, and the
 * draft form that wrapped them in an OCTET STRING is still read. A raw key is random bytes, so it can begin
 * with bytes that read as an OCTET STRING header whose length covers exactly the rest - about once in 2^32
 * keys - and must still be read as the raw key: such an NTRU key used to be rejected, and such a Dilithium
 * or BIKE key loaded as a different, shorter key. The prefix is forced onto real keys here; none of the
 * three binds its public key bytes to anything a decoder checks.
 */
public class RawPublicKeyEncodingTest
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

    public void testNTRU()
        throws Exception
    {
        NTRUParameters[] parameterSets = { NTRUParameters.ntruhps2048509, NTRUParameters.ntruhps2048677,
            NTRUParameters.ntruhps4096821, NTRUParameters.ntruhps40961229, NTRUParameters.ntruhrss701,
            NTRUParameters.ntruhrss1373 };

        for (int i = 0; i != parameterSets.length; i++)
        {
            NTRUKeyPairGenerator kpGen = new NTRUKeyPairGenerator();
            kpGen.init(new NTRUKeyGenerationParameters(RANDOM, parameterSets[i]));
            NTRUPublicKeyParameters pub = (NTRUPublicKeyParameters)kpGen.generateKeyPair().getPublic();

            checkEncodings(parameterSets[i].getName(), SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub), pub.getEncoded());
        }
    }

    public void testDilithium()
        throws Exception
    {
        DilithiumParameters[] parameterSets = { DilithiumParameters.dilithium2, DilithiumParameters.dilithium3,
            DilithiumParameters.dilithium5 };

        for (int i = 0; i != parameterSets.length; i++)
        {
            DilithiumKeyPairGenerator kpGen = new DilithiumKeyPairGenerator();
            kpGen.init(new DilithiumKeyGenerationParameters(RANDOM, parameterSets[i]));
            DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters)kpGen.generateKeyPair().getPublic();
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub);
            String name = parameterSets[i].getName();

            checkEncodings(name, spki, pub.getEncoded());

            // the draft SEQUENCE { rho, t1 } form
            DERSequence seq = new DERSequence(new ASN1Encodable[]{ new DEROctetString(pub.getRho()), new DEROctetString(pub.getT1()) });
            checkLoads(name + " SEQUENCE", new SubjectPublicKeyInfo(spki.getAlgorithm(), seq.getEncoded()), pub.getEncoded());
        }
    }

    public void testBIKE()
        throws Exception
    {
        BIKEParameters[] parameterSets = { BIKEParameters.bike128, BIKEParameters.bike192, BIKEParameters.bike256 };

        for (int i = 0; i != parameterSets.length; i++)
        {
            BIKEKeyPairGenerator kpGen = new BIKEKeyPairGenerator();
            kpGen.init(new BIKEKeyGenerationParameters(RANDOM, parameterSets[i]));
            BIKEPublicKeyParameters pub = (BIKEPublicKeyParameters)kpGen.generateKeyPair().getPublic();

            checkEncodings(parameterSets[i].getName(), SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub), pub.getEncoded());
        }
    }

    private static void checkEncodings(String name, SubjectPublicKeyInfo spki, byte[] raw)
        throws Exception
    {
        AlgorithmIdentifier algId = spki.getAlgorithm();

        // as written, and the draft OCTET STRING form
        assertTrue(name, Arrays.areEqual(raw, spki.getPublicKeyData().getOctets()));
        checkLoads(name + " raw", spki, raw);
        checkLoads(name + " wrapped", new SubjectPublicKeyInfo(algId, new DEROctetString(raw).getEncoded()), raw);

        // a raw key whose first bytes read as an OCTET STRING of everything after them
        byte[] misleading = Arrays.clone(raw);
        misleading[0] = 0x04;
        misleading[1] = (byte)0x82;
        misleading[2] = (byte)((raw.length - 4) >> 8);
        misleading[3] = (byte)(raw.length - 4);
        checkLoads(name + " raw that reads as an OCTET STRING", new SubjectPublicKeyInfo(algId, misleading), misleading);

        // a key of the wrong length is refused, raw or wrapped, rather than loaded short
        checkRejected(name + " short raw", new SubjectPublicKeyInfo(algId, Arrays.copyOf(raw, raw.length - 1)));
        checkRejected(name + " short wrapped", new SubjectPublicKeyInfo(algId, new DEROctetString(Arrays.copyOf(raw, raw.length - 1)).getEncoded()));
    }

    private static void checkLoads(String label, SubjectPublicKeyInfo spki, byte[] expected)
        throws Exception
    {
        AsymmetricKeyParameter key = PublicKeyFactory.createKey(spki);
        byte[] encoded;
        if (key instanceof NTRUPublicKeyParameters)
        {
            encoded = ((NTRUPublicKeyParameters)key).getEncoded();
        }
        else if (key instanceof DilithiumPublicKeyParameters)
        {
            encoded = ((DilithiumPublicKeyParameters)key).getEncoded();
        }
        else
        {
            encoded = ((BIKEPublicKeyParameters)key).getEncoded();
        }
        assertTrue(label + ": loaded a different key", Arrays.areEqual(expected, encoded));
    }

    private static void checkRejected(String label, SubjectPublicKeyInfo spki)
    {
        try
        {
            PublicKeyFactory.createKey(spki);
            fail(label + ": accepted");
        }
        catch (Exception e)
        {
            // expected
        }
    }
}
