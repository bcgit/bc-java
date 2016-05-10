package com.github.gv2011.bcasn.crypto.signers;

import java.io.IOException;
import java.util.Hashtable;

import com.github.gv2011.bcasn.asn1.ASN1Encoding;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.DERNull;
import com.github.gv2011.bcasn.asn1.nist.NISTObjectIdentifiers;
import com.github.gv2011.bcasn.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.gv2011.bcasn.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.github.gv2011.bcasn.asn1.x509.AlgorithmIdentifier;
import com.github.gv2011.bcasn.asn1.x509.DigestInfo;
import com.github.gv2011.bcasn.asn1.x509.X509ObjectIdentifiers;
import com.github.gv2011.bcasn.crypto.AsymmetricBlockCipher;
import com.github.gv2011.bcasn.crypto.CipherParameters;
import com.github.gv2011.bcasn.crypto.CryptoException;
import com.github.gv2011.bcasn.crypto.DataLengthException;
import com.github.gv2011.bcasn.crypto.Digest;
import com.github.gv2011.bcasn.crypto.Signer;
import com.github.gv2011.bcasn.crypto.encodings.PKCS1Encoding;
import com.github.gv2011.bcasn.crypto.engines.RSABlindedEngine;
import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;
import com.github.gv2011.bcasn.crypto.params.ParametersWithRandom;
import com.github.gv2011.bcasn.util.Arrays;

public class RSADigestSigner
    implements Signer
{
    private final AsymmetricBlockCipher rsaEngine = new PKCS1Encoding(new RSABlindedEngine());
    private final AlgorithmIdentifier algId;
    private final Digest digest;
    private boolean forSigning;

    private static final Hashtable oidMap = new Hashtable();

    /*
     * Load OID table.
     */
    static
    {
        oidMap.put("RIPEMD128", TeleTrusTObjectIdentifiers.ripemd128);
        oidMap.put("RIPEMD160", TeleTrusTObjectIdentifiers.ripemd160);
        oidMap.put("RIPEMD256", TeleTrusTObjectIdentifiers.ripemd256);

        oidMap.put("SHA-1", X509ObjectIdentifiers.id_SHA1);
        oidMap.put("SHA-224", NISTObjectIdentifiers.id_sha224);
        oidMap.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        oidMap.put("SHA-384", NISTObjectIdentifiers.id_sha384);
        oidMap.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        oidMap.put("SHA-512/224", NISTObjectIdentifiers.id_sha512_224);
        oidMap.put("SHA-512/256", NISTObjectIdentifiers.id_sha512_256);

        oidMap.put("MD2", PKCSObjectIdentifiers.md2);
        oidMap.put("MD4", PKCSObjectIdentifiers.md4);
        oidMap.put("MD5", PKCSObjectIdentifiers.md5);
    }

    public RSADigestSigner(
        Digest digest)
    {
        this(digest, (ASN1ObjectIdentifier)oidMap.get(digest.getAlgorithmName()));
    }

    public RSADigestSigner(
        Digest digest,
        ASN1ObjectIdentifier digestOid)
    {
        this.digest = digest;
        this.algId = new AlgorithmIdentifier(digestOid, DERNull.INSTANCE);
    }

    /**
     * @deprecated
     */
    public String getAlgorithmName()
    {
        return digest.getAlgorithmName() + "withRSA";
    }

    /**
     * initialise the signer for signing or verification.
     *
     * @param forSigning
     *            true if for signing, false otherwise
     * @param parameters
     *            necessary parameters.
     */
    public void init(
        boolean          forSigning,
        CipherParameters parameters)
    {
        this.forSigning = forSigning;
        AsymmetricKeyParameter k;

        if (parameters instanceof ParametersWithRandom)
        {
            k = (AsymmetricKeyParameter)((ParametersWithRandom)parameters).getParameters();
        }
        else
        {
            k = (AsymmetricKeyParameter)parameters;
        }

        if (forSigning && !k.isPrivate())
        {
            throw new IllegalArgumentException("signing requires private key");
        }

        if (!forSigning && k.isPrivate())
        {
            throw new IllegalArgumentException("verification requires public key");
        }

        reset();

        rsaEngine.init(forSigning, parameters);
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte input)
    {
        digest.update(input);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  input,
        int     inOff,
        int     length)
    {
        digest.update(input, inOff, length);
    }

    /**
     * Generate a signature for the message we've been loaded with using the key
     * we were initialised with.
     */
    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        if (!forSigning)
        {
            throw new IllegalStateException("RSADigestSigner not initialised for signature generation.");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        try
        {
            byte[] data = derEncode(hash);
            return rsaEngine.processBlock(data, 0, data.length);
        }
        catch (IOException e)
        {
            throw new CryptoException("unable to encode signature: " + e.getMessage(), e);
        }
    }

    /**
     * return true if the internal state represents the signature described in
     * the passed in array.
     */
    public boolean verifySignature(
        byte[] signature)
    {
        if (forSigning)
        {
            throw new IllegalStateException("RSADigestSigner not initialised for verification");
        }

        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        byte[] sig;
        byte[] expected;

        try
        {
            sig = rsaEngine.processBlock(signature, 0, signature.length);
            expected = derEncode(hash);
        }
        catch (Exception e)
        {
            return false;
        }

        if (sig.length == expected.length)
        {
            return Arrays.constantTimeAreEqual(sig, expected);
        }
        else if (sig.length == expected.length - 2)  // NULL left out
        {
            int sigOffset = sig.length - hash.length - 2;
            int expectedOffset = expected.length - hash.length - 2;

            expected[1] -= 2;      // adjust lengths
            expected[3] -= 2;

            int nonEqual = 0;

            for (int i = 0; i < hash.length; i++)
            {
                nonEqual |= (sig[sigOffset + i] ^ expected[expectedOffset + i]);
            }

            for (int i = 0; i < sigOffset; i++)
            {
                nonEqual |= (sig[i] ^ expected[i]);  // check header less NULL
            }

            return nonEqual == 0;
        }
        else
        {
            Arrays.constantTimeAreEqual(expected, expected);  // keep time "steady".

            return false;
        }
    }

    public void reset()
    {
        digest.reset();
    }

    private byte[] derEncode(
        byte[] hash)
        throws IOException
    {
        DigestInfo dInfo = new DigestInfo(algId, hash);

        return dInfo.getEncoded(ASN1Encoding.DER);
    }
}
