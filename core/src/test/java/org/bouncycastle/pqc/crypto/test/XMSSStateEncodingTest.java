package org.bouncycastle.pqc.crypto.test;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Method;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.Strings;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.XMSSMTPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.xmss.BDS;
import org.bouncycastle.pqc.crypto.xmss.BDSStateMap;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class XMSSStateEncodingTest
    extends TestCase
{
    private static final int BDS_STATE_MAGIC = 0x42445300;
    private static final int BDS_STATE_MAP_MAGIC = 0x42444d00;
    private static final int STATE_VERSION = 1;

    public void testXmssUsesBinaryStateEncoding()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssKeyPair(params);
        XMSSPrivateKeyParameters privateKey = (XMSSPrivateKeyParameters)kp.getPrivate();

        byte[] encoding = privateKey.getEncoded();
        int stateOffset = 4 + 4 * params.getTreeDigestSize();
        assertEquals(BDS_STATE_MAGIC, Pack.bigEndianToInt(encoding, stateOffset));
        assertEquals(STATE_VERSION, Pack.bigEndianToInt(encoding, stateOffset + 4));

        XMSSPrivateKeyParameters recovered = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(encoding).build();
        assertXmssSigns(recovered, kp);
    }

    public void testXmssMtUsesBinaryStateEncoding()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssMtKeyPair(params);
        XMSSMTPrivateKeyParameters privateKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();

        byte[] encoding = privateKey.getEncoded();
        int stateOffset = (params.getHeight() + 7) / 8 + 4 * params.getTreeDigestSize();
        assertEquals(BDS_STATE_MAP_MAGIC, Pack.bigEndianToInt(encoding, stateOffset));
        assertEquals(STATE_VERSION, Pack.bigEndianToInt(encoding, stateOffset + 4));

        XMSSMTPrivateKeyParameters recovered = new XMSSMTPrivateKeyParameters.Builder(params)
            .withPrivateKey(encoding).build();
        assertXmssMtSigns(recovered, kp);
    }

    public void testXmssReadsLegacyJavaSerializedState()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssKeyPair(params);
        XMSSPrivateKeyParameters privateKey = (XMSSPrivateKeyParameters)kp.getPrivate();
        byte[] currentEncoding = privateKey.getEncoded();
        int stateOffset = 4 + 4 * params.getTreeDigestSize();
        byte[] legacyState = serializeLegacyState(privateKey, "getBDSState");
        assertTrue(currentEncoding.length - stateOffset < legacyState.length);
        byte[] legacyEncoding = Arrays.concatenate(Arrays.copyOfRange(currentEncoding, 0, stateOffset), legacyState);

        XMSSPrivateKeyParameters recovered = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(legacyEncoding).build();
        assertXmssSigns(recovered, kp);
    }

    public void testXmssMtReadsLegacyJavaSerializedState()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssMtKeyPair(params);
        XMSSMTPrivateKeyParameters privateKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();
        byte[] currentEncoding = privateKey.getEncoded();
        int stateOffset = (params.getHeight() + 7) / 8 + 4 * params.getTreeDigestSize();
        byte[] legacyState = serializeLegacyState(privateKey, "getBDSState");
        assertTrue(currentEncoding.length - stateOffset < legacyState.length);
        byte[] legacyEncoding = Arrays.concatenate(Arrays.copyOfRange(currentEncoding, 0, stateOffset), legacyState);

        XMSSMTPrivateKeyParameters recovered = new XMSSMTPrivateKeyParameters.Builder(params)
            .withPrivateKey(legacyEncoding).build();
        assertXmssMtSigns(recovered, kp);
    }

    /**
     * Recompute the trailing checksum of the BDS state inside an XMSS private key encoding, after the
     * body has been altered. SHA-256 over the key's public seed followed by the state body, per
     * BDSStateCodec.
     */
    /**
     * The encoded BDS state carries a checksum over itself, bound to the owning key's public seed, and a
     * key whose state does not match it is refused. The node values inside a BDS state cannot be checked
     * any other way - a path, stack, retain or keep node does not have its children stored beside it, so
     * recomputing one means rebuilding a subtree, which is the work the state exists to avoid - so before
     * this a corrupted state was accepted and then produced signatures that silently did not verify.
     * <p>
     * Note what this is and is not: an error-detecting code against bit rot, partial writes and truncated
     * records, not integrity protection. Anyone able to rewrite the stored key recomputes it (github #2414).
     */
    public void testStateChecksumRejectsCorruption()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        int n = params.getTreeDigestSize();
        AsymmetricCipherKeyPair kp = generateXmssKeyPair(params);
        byte[] encoding = ((XMSSPrivateKeyParameters)kp.getPrivate()).getEncoded();
        int stateOffset = 4 + 4 * n;

        //
        // Every single-byte corruption of the state is caught. Past the 8-byte magic and version it is
        // the checksum that catches it - which is the whole state body and the checksum itself. A
        // corruption inside the magic is not recognised as a codec encoding at all and falls through to
        // the legacy Java-serialization reader, which rejects it for its own reasons.
        //
        for (int i = stateOffset + 8; i != encoding.length; i++)
        {
            byte[] corrupt = Arrays.clone(encoding);
            corrupt[i] ^= 0x01;
            try
            {
                new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(corrupt).build();
                fail("no exception on corrupt state byte " + i);
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("byte " + i, "BDS state checksum does not match", e.getMessage());
            }
        }

        for (int i = stateOffset; i != stateOffset + 8; i++)
        {
            byte[] corrupt = Arrays.clone(encoding);
            corrupt[i] ^= 0x01;
            try
            {
                new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(corrupt).build();
                fail("no exception on corrupt state header byte " + i);
            }
            catch (IllegalArgumentException e)
            {
                // rejected, by the magic/version check or by the legacy reader it falls through to
            }
        }

        // a state transplanted from another key of the same parameters is caught by the seed binding,
        // even though it is internally consistent and brings its own matching root
        byte[] other = ((XMSSPrivateKeyParameters)generateXmssKeyPair(params).getPrivate()).getEncoded();
        assertEquals(encoding.length, other.length);
        byte[] transplant = Arrays.clone(encoding);
        System.arraycopy(other, 4 + 3 * n, transplant, 4 + 3 * n, other.length - (4 + 3 * n));
        try
        {
            new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(transplant).build();
            fail("state from a different key accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("BDS state checksum does not match", e.getMessage());
        }

        // and the untouched encoding still decodes and signs verifiably
        XMSSPrivateKeyParameters decoded =
            new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(encoding).build();
        XMSSSigner signer = new XMSSSigner();
        signer.init(true, decoded);
        byte[] sig = signer.generateSignature(Strings.toByteArray("message"));
        XMSSSigner verifier = new XMSSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue(verifier.verifySignature(Strings.toByteArray("message"), sig));
    }

    private static void refreshStateChecksum(byte[] encoding, XMSSParameters params)
    {
        int n = params.getTreeDigestSize();
        int publicSeedOffset = 4 + 2 * n;
        int stateOffset = 4 + 4 * n;
        int bodyEnd = encoding.length - 32;

        Digest digest = new SHA256Digest();
        digest.update(encoding, publicSeedOffset, n);
        digest.update(encoding, stateOffset, bodyEnd - stateOffset);

        byte[] sum = new byte[digest.getDigestSize()];
        digest.doFinal(sum, 0);

        System.arraycopy(sum, 0, encoding, bodyEnd, sum.length);
    }

    public void testStateCollectionCountIsBoundedBeforeAllocation()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssKeyPair(params);
        byte[] encoding = ((XMSSPrivateKeyParameters)kp.getPrivate()).getEncoded();
        int stateOffset = 4 + 4 * params.getTreeDigestSize();
        int authenticationPathCountOffset = stateOffset + 8 + 4 * 4 + 1 + 1 + 4 + 4
            + params.getTreeDigestSize();
        Pack.intToBigEndian(params.getHeight() + 1, encoding, authenticationPathCountOffset);
        //
        // The encoded state carries a checksum, which is verified before anything is parsed - so a
        // crafted encoding has to carry a valid one to reach the allocation bounds at all. That is the
        // real shape of the case these bounds guard against: the checksum detects corruption, it is not
        // authentication, so anyone crafting an encoding simply recomputes it (github #2414).
        //
        refreshStateChecksum(encoding, params);

        try
        {
            new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(encoding).build();
            fail("oversized BDS authentication path accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("BDS authentication path size out of bounds", e.getMessage());
        }
    }

    public void testXmssBuilderRejectsStateForDifferentParameters()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        XMSSPrivateKeyParameters privateKey = (XMSSPrivateKeyParameters)generateXmssKeyPair(params).getPrivate();
        XMSSParameters mismatchedParams = new XMSSParameters(6, new SHA256Digest());

        try
        {
            new XMSSPrivateKeyParameters.Builder(mismatchedParams)
                .withIndex(privateKey.getIndex())
                .withSecretKeySeed(privateKey.getSecretKeySeed())
                .withSecretKeyPRF(privateKey.getSecretKeyPRF())
                .withPublicSeed(privateKey.getPublicSeed())
                .withRoot(privateKey.getRoot())
                .withBDSState((BDS)getPrivateState(privateKey, "getBDSState"))
                .build();
            fail("XMSS BDS state for different parameters accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("BDS state does not match XMSS parameters", e.getMessage());
        }
    }

    public void testXmssMtBuilderRejectsStateForDifferentParameters()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA256Digest());
        XMSSMTPrivateKeyParameters privateKey =
            (XMSSMTPrivateKeyParameters)generateXmssMtKeyPair(params).getPrivate();
        XMSSMTParameters mismatchedParams = new XMSSMTParameters(6, 2, new SHA256Digest());

        try
        {
            new XMSSMTPrivateKeyParameters.Builder(mismatchedParams)
                .withIndex(privateKey.getIndex())
                .withSecretKeySeed(privateKey.getSecretKeySeed())
                .withSecretKeyPRF(privateKey.getSecretKeyPRF())
                .withPublicSeed(privateKey.getPublicSeed())
                .withRoot(privateKey.getRoot())
                .withBDSState((BDSStateMap)getPrivateState(privateKey, "getBDSState"))
                .build();
            fail("XMSSMT BDS state for different parameters accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("BDS state does not match XMSS parameters", e.getMessage());
        }
    }

    public void testXmssStateRoundTripsAcrossTreeUpdates()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssKeyPair(params);
        XMSSPrivateKeyParameters privateKey = (XMSSPrivateKeyParameters)kp.getPrivate();

        for (int i = 0; i < 16; i++)
        {
            byte[] encoding = privateKey.getEncoded();
            privateKey = new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(encoding).build();

            byte[] message = new byte[]{ (byte)i };
            XMSSSigner signer = new XMSSSigner();
            signer.init(true, privateKey);
            byte[] signature = signer.generateSignature(message);

            XMSSSigner verifier = new XMSSSigner();
            verifier.init(false, kp.getPublic());
            assertTrue("signature at index " + i, verifier.verifySignature(message, signature));
            privateKey = (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();
        }
    }

    public void testXmssMtStateRoundTripsAcrossTreeUpdates()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssMtKeyPair(params);
        XMSSMTPrivateKeyParameters privateKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();

        for (int i = 0; i < 16; i++)
        {
            byte[] encoding = privateKey.getEncoded();
            privateKey = new XMSSMTPrivateKeyParameters.Builder(params).withPrivateKey(encoding).build();

            byte[] message = new byte[]{ (byte)i };
            XMSSMTSigner signer = new XMSSMTSigner();
            signer.init(true, privateKey);
            byte[] signature = signer.generateSignature(message);

            XMSSMTSigner verifier = new XMSSMTSigner();
            verifier.init(false, kp.getPublic());
            assertTrue("signature at index " + i, verifier.verifySignature(message, signature));
            privateKey = (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();
        }
    }

    public void testXmssPrivateKeyInfoUsesBinaryBdsStateChoice()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssKeyPair(params);
        XMSSPrivateKeyParameters privateKey = (XMSSPrivateKeyParameters)kp.getPrivate();

        PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey);
        assertEquals(PQCObjectIdentifiers.xmss, keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

        ASN1Sequence seq = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());
        assertEquals(1, ASN1TaggedObject.getInstance(seq.getObjectAt(2)).getTagNo());
        assertTrue(XMSSPrivateKey.getInstance(seq).hasBinaryBdsState());

        XMSSPrivateKeyParameters restored = (XMSSPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo.getEncoded());
        assertXmssSigns(restored, kp);
    }

    public void testXmssPrivateKeyAcceptsLegacyBdsStateChoice()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssKeyPair(params);
        XMSSPrivateKeyParameters privateKey = (XMSSPrivateKeyParameters)kp.getPrivate();

        PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey);
        ASN1Sequence seq = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());

        // BC no longer generates the legacy alternative, so build the [0] form by hand
        ASN1Sequence legacy = legacyBdsStateSequence(seq, serializeLegacyState(privateKey, "getBDSState"));
        PrivateKeyInfo legacyInfo = new PrivateKeyInfo(keyInfo.getPrivateKeyAlgorithm(), legacy);

        ASN1Sequence legacySeq = ASN1Sequence.getInstance(legacyInfo.parsePrivateKey());
        assertEquals(0, ASN1TaggedObject.getInstance(legacySeq.getObjectAt(2)).getTagNo());
        assertFalse(XMSSPrivateKey.getInstance(legacySeq).hasBinaryBdsState());

        XMSSPrivateKeyParameters restored = (XMSSPrivateKeyParameters)PrivateKeyFactory.createKey(legacyInfo.getEncoded());
        assertXmssSigns(restored, kp);
    }

    public void testXmssPrivateKeyRejectsUnknownBdsStateChoice()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssKeyPair(params);

        PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo((XMSSPrivateKeyParameters)kp.getPrivate());
        ASN1Sequence seq = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(seq.getObjectAt(0));
        v.add(seq.getObjectAt(1));
        v.add(new DERTaggedObject(true, 2, new DEROctetString(XMSSPrivateKey.getInstance(seq).getBdsState())));

        try
        {
            XMSSPrivateKey.getInstance(new DERSequence(v));
            fail("unknown bdsState choice accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("unknown bdsState choice in XMSSPrivateKey", e.getMessage());
        }
    }

    public void testXmssMtPrivateKeyInfoUsesBinaryBdsStateChoice()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssMtKeyPair(params);
        XMSSMTPrivateKeyParameters privateKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();

        PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey);
        assertEquals(PQCObjectIdentifiers.xmss_mt, keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

        ASN1Sequence seq = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());
        assertEquals(1, ASN1TaggedObject.getInstance(seq.getObjectAt(2)).getTagNo());
        assertTrue(XMSSMTPrivateKey.getInstance(seq).hasBinaryBdsState());

        XMSSMTPrivateKeyParameters restored = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo.getEncoded());
        assertXmssMtSigns(restored, kp);
    }

    public void testXmssMtPrivateKeyAcceptsLegacyBdsStateChoice()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssMtKeyPair(params);
        XMSSMTPrivateKeyParameters privateKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();

        PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey);
        ASN1Sequence seq = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());

        // BC no longer generates the legacy alternative, so build the [0] form by hand
        ASN1Sequence legacy = legacyBdsStateSequence(seq, serializeLegacyState(privateKey, "getBDSState"));
        PrivateKeyInfo legacyInfo = new PrivateKeyInfo(keyInfo.getPrivateKeyAlgorithm(), legacy);

        ASN1Sequence legacySeq = ASN1Sequence.getInstance(legacyInfo.parsePrivateKey());
        assertEquals(0, ASN1TaggedObject.getInstance(legacySeq.getObjectAt(2)).getTagNo());
        assertFalse(XMSSMTPrivateKey.getInstance(legacySeq).hasBinaryBdsState());

        XMSSMTPrivateKeyParameters restored = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(legacyInfo.getEncoded());
        assertXmssMtSigns(restored, kp);
    }

    public void testXmssMtPrivateKeyRejectsUnknownBdsStateChoice()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA256Digest());
        AsymmetricCipherKeyPair kp = generateXmssMtKeyPair(params);

        PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo((XMSSMTPrivateKeyParameters)kp.getPrivate());
        ASN1Sequence seq = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(seq.getObjectAt(0));
        v.add(seq.getObjectAt(1));
        v.add(new DERTaggedObject(true, 2, new DEROctetString(XMSSMTPrivateKey.getInstance(seq).getBdsState())));

        try
        {
            XMSSMTPrivateKey.getInstance(new DERSequence(v));
            fail("unknown bdsState choice accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("unknown bdsState choice in XMSSMTPrivateKey", e.getMessage());
        }
    }

    private static AsymmetricCipherKeyPair generateXmssKeyPair(XMSSParameters params)
    {
        XMSSKeyPairGenerator generator = new XMSSKeyPairGenerator();
        generator.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));
        return generator.generateKeyPair();
    }

    private static AsymmetricCipherKeyPair generateXmssMtKeyPair(XMSSMTParameters params)
    {
        XMSSMTKeyPairGenerator generator = new XMSSMTKeyPairGenerator();
        generator.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));
        return generator.generateKeyPair();
    }

    /**
     * Rebuild an XMSSPrivateKey / XMSSMTPrivateKey sequence with the bdsState carried in the
     * legacy [0] alternative, which BC accepts on parsing but no longer generates.
     */
    private static ASN1Sequence legacyBdsStateSequence(ASN1Sequence seq, byte[] legacyState)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(seq.getObjectAt(0));
        v.add(seq.getObjectAt(1));
        v.add(new DERTaggedObject(true, 0, new DEROctetString(legacyState)));
        return new DERSequence(v);
    }

    private static byte[] serializeLegacyState(Object privateKey, String accessorName)
        throws Exception
    {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutputStream objectOut = new ObjectOutputStream(byteOut);
        objectOut.writeObject(getPrivateState(privateKey, accessorName));
        objectOut.close();
        return byteOut.toByteArray();
    }

    private static Object getPrivateState(Object privateKey, String accessorName)
        throws Exception
    {
        Method accessor = privateKey.getClass().getDeclaredMethod(accessorName, new Class[0]);
        accessor.setAccessible(true);
        return accessor.invoke(privateKey, new Object[0]);
    }

    private static void assertXmssSigns(XMSSPrivateKeyParameters privateKey, AsymmetricCipherKeyPair kp)
    {
        byte[] message = new byte[]{ 1, 2, 3, 4 };
        XMSSSigner signer = new XMSSSigner();
        signer.init(true, privateKey);
        byte[] signature = signer.generateSignature(message);

        XMSSSigner verifier = new XMSSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue(verifier.verifySignature(message, signature));
    }

    private static void assertXmssMtSigns(XMSSMTPrivateKeyParameters privateKey, AsymmetricCipherKeyPair kp)
    {
        byte[] message = new byte[]{ 1, 2, 3, 4 };
        XMSSMTSigner signer = new XMSSMTSigner();
        signer.init(true, privateKey);
        byte[] signature = signer.generateSignature(message);

        XMSSMTSigner verifier = new XMSSMTSigner();
        verifier.init(false, kp.getPublic());
        assertTrue(verifier.verifySignature(message, signature));
    }
}
