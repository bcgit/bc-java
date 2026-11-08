package org.bouncycastle.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.XMSSKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.crypto.signers.xmss.BDS;
import org.bouncycastle.crypto.signers.xmss.BDSStateMap;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.internal.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSMTPublicKey;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Pack;

/**
 * The XMSS / XMSS^MT (RFC 8391, SP 800-208) half of the key factories in this package, held apart
 * from them so that the distributions which exclude XMSS - the jdk1.4 and jdk1.3 Ant builds - can
 * replace this one class rather than fork four factories. Every method answers null for a key or a
 * key info that is not XMSS / XMSS^MT, which is what lets the callers fall through to their own
 * unrecognised-algorithm handling; the jdk1.4 twin answers null unconditionally.
 * <p>
 * <b>Keep the jdk1.4 twin (core/src/main/jdk1.4) in step with this class:</b> a method added
 * here and not there breaks the jdk1.4 and jdk1.3 Ant builds.
 */
class XmssKeyUtil
{
    private XmssKeyUtil()
    {
    }

    /**
     * The SubjectPublicKeyInfo for an XMSS or XMSS^MT public key, or null if the key is neither.
     */
    static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        if (publicKey instanceof XMSSPublicKeyParameters)
        {
            XMSSPublicKeyParameters keyParams = (XMSSPublicKeyParameters)publicKey;

            byte[] publicSeed = keyParams.getPublicSeed();
            byte[] root = keyParams.getRoot();
            byte[] keyEnc = keyParams.getEncoded();
            if (keyEnc.length > publicSeed.length + root.length)
            {
                // RFC 9802: raw RFC 8391 public key, no parameters, no ASN.1 wrapping.
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_xmss_hashsig);

                return new SubjectPublicKeyInfo(algorithmIdentifier, keyEnc);
            }

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
                new XMSSKeyParams(keyParams.getParameters().getHeight(), lookupTreeAlgID(keyParams.getTreeDigest())));

            return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSPublicKey(publicSeed, root));
        }
        if (publicKey instanceof XMSSMTPublicKeyParameters)
        {
            XMSSMTPublicKeyParameters keyParams = (XMSSMTPublicKeyParameters)publicKey;

            byte[] publicSeed = keyParams.getPublicSeed();
            byte[] root = keyParams.getRoot();
            byte[] keyEnc = keyParams.getEncoded();
            if (keyEnc.length > publicSeed.length + root.length)
            {
                // RFC 9802: raw RFC 8391 public key, no parameters, no ASN.1 wrapping.
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_xmssmt_hashsig);

                return new SubjectPublicKeyInfo(algorithmIdentifier, keyEnc);
            }

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt,
                new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(),
                    lookupTreeAlgID(keyParams.getTreeDigest())));

            return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSMTPublicKey(publicSeed, root));
        }

        return null;
    }

    /**
     * The PrivateKeyInfo for an XMSS or XMSS^MT private key, or null if the key is neither.
     */
    static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes)
        throws IOException
    {
        if (privateKey instanceof XMSSPrivateKeyParameters)
        {
            XMSSPrivateKeyParameters keyParams = (XMSSPrivateKeyParameters)privateKey;
            XMSSParameters params = keyParams.getParameters();

            if (params.getParameterSetOID() != 0)
            {
                // Encode any standard (RFC 8391 / SP 800-208) parameter set in the RFC 9802 form
                // (id-alg-xmss-hashsig), matching the SubjectPublicKeyInfo the public half produces,
                // so the private and public keys of a keypair share one algorithm OID. The 4-octet
                // parameter-set OID is carried ahead of the raw key so createPrivateKey() can recover
                // the full parameter set (including n) - the legacy XMSSKeyParams (height + tree-digest
                // OID only) cannot represent the SP 800-208 sets. A non-standard tree height has no
                // parameter-set OID (0) and falls through to the legacy PQCObjectIdentifiers.xmss form.
                byte[] keyEnc = Arrays.concatenate(Pack.intToBigEndian(params.getParameterSetOID()), keyParams.getEncoded());
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_xmss_hashsig);

                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(keyEnc), attributes);
            }

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
                new XMSSKeyParams(params.getHeight(), lookupTreeAlgID(keyParams.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, xmssCreateKeyStructure(keyParams), attributes);
        }
        if (privateKey instanceof XMSSMTPrivateKeyParameters)
        {
            XMSSMTPrivateKeyParameters keyParams = (XMSSMTPrivateKeyParameters)privateKey;
            XMSSMTParameters params = keyParams.getParameters();

            if (params.getParameterSetOID() != 0)
            {
                // See the XMSS branch above: any standard parameter set is encoded in the RFC 9802
                // form (id-alg-xmssmt-hashsig) with the 4-octet parameter-set OID ahead of the raw
                // key; a non-standard tree height falls through to PQCObjectIdentifiers.xmss_mt.
                byte[] keyEnc = Arrays.concatenate(Pack.intToBigEndian(params.getParameterSetOID()), keyParams.getEncoded());
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_xmssmt_hashsig);

                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(keyEnc), attributes);
            }

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt,
                new XMSSMTKeyParams(params.getHeight(), params.getLayers(), lookupTreeAlgID(keyParams.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, xmssmtCreateKeyStructure(keyParams), attributes);
        }

        return null;
    }

    /**
     * The public key parameters for an XMSS or XMSS^MT SubjectPublicKeyInfo, or null when this
     * distribution has no XMSS support. Only called for the six XMSS / XMSS^MT algorithm OIDs, so
     * this never answers null in the base tree.
     */
    static AsymmetricKeyParameter createPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOID = keyInfo.getAlgorithm().getAlgorithm();

        if (algOID.equals(PQCObjectIdentifiers.xmss_mt)
            || algOID.equals(IsaraObjectIdentifiers.id_alg_xmssmt)
            || algOID.equals(IANAObjectIdentifiers.id_alg_xmssmt_hashsig))
        {
            // Every step the encoding drives sits inside the try, the getInstance() calls included:
            // this method's contract is throws IOException, and a getInstance() left outside it
            // hands the caller an IllegalArgumentException from a key it merely tried to read.
            try
            {
                XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());

                if (keyParams != null)
                {
                    ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

                    XMSSPublicKey xmssMtPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());

                    return new XMSSMTPublicKeyParameters
                        .Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), getDigest(treeDigest)))
                        .withPublicSeed(xmssMtPublicKey.getPublicSeed())
                        .withRoot(xmssMtPublicKey.getRoot()).build();
                }

                // RFC 9802 carries the raw RFC 8391 key; the legacy draft form wrapped it in an OCTET STRING.
                byte[] keyEnc = rawPublicKey(keyInfo);

                if (keyEnc.length < 4)
                {
                    throw new IOException("XMSS^MT public key data too short");
                }

                XMSSMTParameters parameters = XMSSMTParameters.lookupByOID(Pack.bigEndianToInt(keyEnc, 0));
                if (parameters == null)
                {
                    throw new IOException("unknown XMSS^MT public key OID: " + Pack.bigEndianToInt(keyEnc, 0));
                }

                return new XMSSMTPublicKeyParameters
                    .Builder(parameters)
                    .withPublicKey(keyEnc).build();
            }
            catch (IllegalArgumentException e)
            {
                // the height and layer count are whatever the key's parameters said they were
                throw Exceptions.ioException("malformed XMSS^MT public key: " + e.getMessage(), e);
            }
            catch (ArithmeticException e)
            {
                // a height or layer count too wide for the int it is read into: the key
                // parameters take both with ASN1Integer.intValueExact(), whose
                // ArithmeticException is a sibling of IllegalArgumentException rather than
                // a subclass, so it does not reach the block above
                throw Exceptions.ioException("malformed XMSS^MT public key: " + e.getMessage(), e);
            }
        }

        if (algOID.equals(PQCObjectIdentifiers.xmss)
            || algOID.equals(IsaraObjectIdentifiers.id_alg_xmss)
            || algOID.equals(IANAObjectIdentifiers.id_alg_xmss_hashsig))
        {
            // as in the XMSS^MT branch above: the whole decode is inside the try
            try
            {
                XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());

                if (keyParams != null)
                {
                    ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();
                    XMSSPublicKey xmssPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());

                    return new XMSSPublicKeyParameters
                        .Builder(new XMSSParameters(keyParams.getHeight(), getDigest(treeDigest)))
                        .withPublicSeed(xmssPublicKey.getPublicSeed())
                        .withRoot(xmssPublicKey.getRoot()).build();
                }

                // RFC 9802 carries the raw RFC 8391 key; the legacy draft form wrapped it in an OCTET STRING.
                byte[] keyEnc = rawPublicKey(keyInfo);

                if (keyEnc.length < 4)
                {
                    throw new IOException("XMSS public key data too short");
                }

                XMSSParameters parameters = XMSSParameters.lookupByOID(Pack.bigEndianToInt(keyEnc, 0));
                if (parameters == null)
                {
                    throw new IOException("unknown XMSS public key OID: " + Pack.bigEndianToInt(keyEnc, 0));
                }

                return new XMSSPublicKeyParameters
                    .Builder(parameters)
                    .withPublicKey(keyEnc).build();
            }
            catch (IllegalArgumentException e)
            {
                // the height is whatever the key's parameters said it was
                throw Exceptions.ioException("malformed XMSS public key: " + e.getMessage(), e);
            }
            catch (ArithmeticException e)
            {
                // a height or layer count too wide for the int it is read into: the key
                // parameters take both with ASN1Integer.intValueExact(), whose
                // ArithmeticException is a sibling of IllegalArgumentException rather than
                // a subclass, so it does not reach the block above
                throw Exceptions.ioException("malformed XMSS public key: " + e.getMessage(), e);
            }
        }

        return null;
    }

    /**
     * The private key parameters for an XMSS or XMSS^MT PrivateKeyInfo, or null when this
     * distribution has no XMSS support.
     */
    static AsymmetricKeyParameter createPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOID = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (algOID.equals(PQCObjectIdentifiers.xmss)
            || algOID.equals(IsaraObjectIdentifiers.id_alg_xmss))
        {
            // as in createPublicKey: the getInstance() calls belong inside the try, and so does the
            // parameters lookup that follows them - this OID form must carry XMSSKeyParams, and
            // reading the tree digest off an absent one is a NullPointerException past throws IOException
            try
            {
                XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
                if (keyParams == null)
                {
                    throw new IOException("no parameters found in XMSS private key");
                }
                ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

                XMSSPrivateKey xmssPrivateKey = XMSSPrivateKey.getInstance(keyInfo.parsePrivateKey());

                XMSSPrivateKeyParameters.Builder keyBuilder = new XMSSPrivateKeyParameters
                    .Builder(new XMSSParameters(keyParams.getHeight(), getDigest(treeDigest)))
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
                    BDS bds = XMSSEngine.getBDSFromEncoding(xmssPrivateKey.getBdsState(), xmssPrivateKey.getPublicSeed());
                    keyBuilder.withBDSState(bds.withWOTSDigest(treeDigest));
                }

                return keyBuilder.build();
            }
            catch (ClassNotFoundException e)
            {
                throw Exceptions.ioException("ClassNotFoundException processing BDS state: " + e.getMessage(), e);
            }
            catch (IllegalArgumentException e)
            {
                // the height is whatever the key's parameters said it was
                throw Exceptions.ioException("malformed XMSS private key: " + e.getMessage(), e);
            }
            catch (IllegalStateException e)
            {
                // the stored BDS state is whatever the key carried: BDS.validate() rejects one that
                // does not match its own tree, and build() rejects a key missing a seed
                throw Exceptions.ioException("malformed XMSS private key: " + e.getMessage(), e);
            }
            catch (ArithmeticException e)
            {
                // a height or layer count too wide for the int it is read into: the key
                // parameters take both with ASN1Integer.intValueExact(), whose
                // ArithmeticException is a sibling of IllegalArgumentException rather than
                // a subclass, so it does not reach the block above
                throw Exceptions.ioException("malformed XMSS private key: " + e.getMessage(), e);
            }
        }
        if (algOID.equals(PQCObjectIdentifiers.xmss_mt)
            || algOID.equals(IsaraObjectIdentifiers.id_alg_xmssmt))
        {
            // as in the XMSS branch above
            try
            {
                XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
                if (keyParams == null)
                {
                    throw new IOException("no parameters found in XMSS^MT private key");
                }
                ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

                XMSSMTPrivateKey xmssMtPrivateKey = XMSSMTPrivateKey.getInstance(keyInfo.parsePrivateKey());

                XMSSMTPrivateKeyParameters.Builder keyBuilder = new XMSSMTPrivateKeyParameters
                    .Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), getDigest(treeDigest)))
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
                    BDSStateMap bdsState = XMSSEngine.getBDSStateMapFromEncoding(xmssMtPrivateKey.getBdsState(), xmssMtPrivateKey.getPublicSeed());
                    keyBuilder.withBDSState(bdsState.withWOTSDigest(treeDigest));
                }

                return keyBuilder.build();
            }
            catch (ClassNotFoundException e)
            {
                throw Exceptions.ioException("ClassNotFoundException processing BDS state: " + e.getMessage(), e);
            }
            catch (IllegalArgumentException e)
            {
                // the height and layer count are whatever the key's parameters said they were
                throw Exceptions.ioException("malformed XMSS^MT private key: " + e.getMessage(), e);
            }
            catch (IllegalStateException e)
            {
                // as in the XMSS branch: the stored per-layer BDS states are the key's own
                throw Exceptions.ioException("malformed XMSS^MT private key: " + e.getMessage(), e);
            }
            catch (ArithmeticException e)
            {
                // a height or layer count too wide for the int it is read into: the key
                // parameters take both with ASN1Integer.intValueExact(), whose
                // ArithmeticException is a sibling of IllegalArgumentException rather than
                // a subclass, so it does not reach the block above
                throw Exceptions.ioException("malformed XMSS^MT private key: " + e.getMessage(), e);
            }
        }
        if (algOID.equals(IANAObjectIdentifiers.id_alg_xmss_hashsig))
        {
            // RFC 9802 form used for the SP 800-208 sets: the private key octets are the 4-octet
            // parameter-set OID followed by the raw XMSSPrivateKeyParameters encoding, recovered
            // via lookupByOID so the full parameter set (including n) is restored.
            try
            {
                byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
                if (keyEnc.length < 4)
                {
                    throw new IOException("XMSS private key data too short");
                }
                int paramSet = Pack.bigEndianToInt(keyEnc, 0);
                XMSSParameters xmssParams = XMSSParameters.lookupByOID(paramSet);
                if (xmssParams == null)
                {
                    throw new IOException("unknown XMSS private key OID: " + paramSet);
                }

                return new XMSSPrivateKeyParameters.Builder(xmssParams)
                    .withPrivateKey(Arrays.copyOfRange(keyEnc, 4, keyEnc.length)).build();
            }
            catch (IllegalArgumentException e)
            {
                throw Exceptions.ioException("malformed XMSS private key: " + e.getMessage(), e);
            }
        }
        if (algOID.equals(IANAObjectIdentifiers.id_alg_xmssmt_hashsig))
        {
            try
            {
                byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
                if (keyEnc.length < 4)
                {
                    throw new IOException("XMSS^MT private key data too short");
                }
                int paramSet = Pack.bigEndianToInt(keyEnc, 0);
                XMSSMTParameters xmssmtParams = XMSSMTParameters.lookupByOID(paramSet);
                if (xmssmtParams == null)
                {
                    throw new IOException("unknown XMSS^MT private key OID: " + paramSet);
                }

                return new XMSSMTPrivateKeyParameters.Builder(xmssmtParams)
                    .withPrivateKey(Arrays.copyOfRange(keyEnc, 4, keyEnc.length)).build();
            }
            catch (IllegalArgumentException e)
            {
                throw Exceptions.ioException("malformed XMSS^MT private key: " + e.getMessage(), e);
            }
        }

        return null;
    }

    private static byte[] rawPublicKey(SubjectPublicKeyInfo keyInfo)
    {
        byte[] keyEnc = keyInfo.getPublicKeyData().getOctets();
        ASN1OctetString data = Utils.parseOctetData(keyEnc);

        return (data != null) ? data.getOctets() : keyEnc;
    }

    /**
     * The tree digest for a tree-digest OID. Taken from the signer package rather than from Utils
     * because the SP 800-208 SHAKE256/192 and SHAKE256/256 sets name id-shake256-len, which no
     * other algorithm in this package uses - and taken from there rather than kept here so that
     * the set of digests a key can be written and read under cannot drift from the set it can be
     * generated and signed with.
     */
    private static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        return XMSSEngine.getDigest(oid);
    }

    private static AlgorithmIdentifier lookupTreeAlgID(String treeDigest)
    {
        if (treeDigest.equals(XMSSKeyParameters.SHA_256))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        if (treeDigest.equals(XMSSKeyParameters.SHA_512))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
        }
        if (treeDigest.equals(XMSSKeyParameters.SHAKE128))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake128);
        }
        if (treeDigest.equals(XMSSKeyParameters.SHAKE256))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256);
        }

        throw new IllegalArgumentException("unknown tree digest: " + treeDigest);
    }

    /**
     * The ASN.1 structure an XMSS private key is written as, from the key's own fields.
     * <p>
     * It used to be built out of {@code keyParams.getEncoded()}: the whole key was serialized -
     * the four n-byte fields, and the BDS traversal state with the SHA-256 checksum over it - and
     * then that same array was taken apart again at computed offsets to recover the fields the key
     * exposes directly. The state encoding is the only part of it the ASN.1 actually needs, and
     * that is the only part built here now.
     * </p><p>
     * Under the key's monitor for the whole of it, which is what getEncoded() took for its half:
     * the index, the maximum index and the traversal state are three records of one position, and
     * reading them in three unsynchronized steps lets a signature land between two of them. That
     * was already so - the maximum index was read after getEncoded() had returned, outside the
     * monitor that produced the rest - and this closes it rather than repeating it three times
     * over. Holding another object's monitor is what BDSStateMap's copy constructor does, and for
     * the same reason.
     * </p>
     */
    private static XMSSPrivateKey xmssCreateKeyStructure(XMSSPrivateKeyParameters keyParams)
        throws IOException
    {
        int totalHeight = keyParams.getParameters().getHeight();

        synchronized (keyParams)
        {
            BDS bdsState = keyParams.getBDSState();
            int index = keyParams.getIndex();

            if (!XMSSEngine.isStoredIndexValid(totalHeight, index))
            {
                throw new IllegalArgumentException("index out of bounds");
            }

            byte[] publicSeed = keyParams.getPublicSeed();
            byte[] bdsStateBinary = XMSSEngine.getEncodedBDSState(bdsState, publicSeed);
            int maxIndex = bdsState.getMaxIndex();

            if (maxIndex != (1 << totalHeight) - 1)
            {
                return new XMSSPrivateKey(index, keyParams.getSecretKeySeed(), keyParams.getSecretKeyPRF(),
                    publicSeed, keyParams.getRoot(), bdsStateBinary, maxIndex);
            }

            return new XMSSPrivateKey(index, keyParams.getSecretKeySeed(), keyParams.getSecretKeyPRF(),
                publicSeed, keyParams.getRoot(), bdsStateBinary);
        }
    }

    /**
     * As {@link #xmssCreateKeyStructure}, for XMSS^MT, and with one difference that is not merely
     * the extra layers: the raw encoding this used to be built from writes the index into
     * {@code ceil(height / 8)} bytes, and the largest index a key can hold is 2^height - the
     * position an exhausted key sits at, one past its last leaf. At every height that is a
     * multiple of eight that index does not fit, so the field was written truncated and read back
     * as zero: an exhausted key was exported as a key at index 0 declaring a full tree of unused
     * one-time keys. It could not sign - the traversal state it carried was the exhausted one, and
     * the signer refuses that - but it was still a stored key saying the opposite of the truth
     * about a one-time key's position, which RFC 8391 sec. 1.1 is about. The index is taken from
     * the key here, and XMSSMTPrivateKey carries it as a long, so nothing narrows it.
     * </p><p>
     * validateIndex() is called for the reason toByteArray() calls it, this being the other place
     * a key is written out: the index and the per-layer states are two records of one position,
     * and one that disagrees with itself is refused on the way back in, so it is refused here
     * rather than persisted.
     * </p>
     */
    private static XMSSMTPrivateKey xmssmtCreateKeyStructure(XMSSMTPrivateKeyParameters keyParams)
        throws IOException
    {
        XMSSMTParameters params = keyParams.getParameters();
        int totalHeight = params.getHeight();

        synchronized (keyParams)
        {
            BDSStateMap bdsState = keyParams.getBDSState();
            long index = keyParams.getIndex();

            if (!XMSSEngine.isStoredIndexValid(totalHeight, index))
            {
                throw new IllegalArgumentException("index out of bounds");
            }

            byte[] publicSeed = keyParams.getPublicSeed();
            byte[] secretKeySeed = keyParams.getSecretKeySeed();
            try
            {
                bdsState.validateIndex(params, index, publicSeed, secretKeySeed);
            }
            finally
            {
                Arrays.clear(secretKeySeed);
            }

            byte[] bdsStateBinary = XMSSEngine.getEncodedBDSState(bdsState, publicSeed);
            long maxIndex = bdsState.getMaxIndex();

            if (maxIndex != (1L << totalHeight) - 1)
            {
                return new XMSSMTPrivateKey(index, keyParams.getSecretKeySeed(), keyParams.getSecretKeyPRF(),
                    publicSeed, keyParams.getRoot(), bdsStateBinary, maxIndex);
            }

            return new XMSSMTPrivateKey(index, keyParams.getSecretKeySeed(), keyParams.getSecretKeyPRF(),
                publicSeed, keyParams.getRoot(), bdsStateBinary);
        }
    }
}
