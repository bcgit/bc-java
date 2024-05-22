package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Base class for an ECDH Public Key.
 * This type is for use with {@link PublicKeyAlgorithmTags#ECDH}.
 * The specific curve is identified by providing an OID.
 * Regarding X25519, X448, consider the following:
 * Modern implementations use dedicated key types {@link X25519PublicBCPGKey}, {@link X448PublicBCPGKey} along with
 * dedicated algorithm tags {@link PublicKeyAlgorithmTags#X25519}, {@link PublicKeyAlgorithmTags#X448}.
 * If you want to be compatible with legacy applications however, you should use this class instead.
 * Note though, that for v6 keys, {@link X25519PublicBCPGKey} or {@link X448PublicBCPGKey} MUST be used for X25519, X448.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-ecd">
 *     Crypto-Refresh - Algorithm-Specific Parts for ECDH Keys</a>
 */
public class ECDHPublicBCPGKey
    extends ECPublicBCPGKey
{
    private byte reserved;
    private byte hashFunctionId;
    private byte symAlgorithmId;

    /**
     * @param in the stream to read the packet from.
     */
    public ECDHPublicBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        super(in);

        int length = in.read();
        byte[] kdfParameters = new byte[length];
        if (kdfParameters.length != 3)
        {
            throw new IllegalStateException("kdf parameters size of 3 expected.");
        }

        in.readFully(kdfParameters);

        reserved = kdfParameters[0];
        hashFunctionId = kdfParameters[1];
        symAlgorithmId = kdfParameters[2];

        verifyHashAlgorithm();
        verifySymmetricKeyAlgorithm();
    }

    public ECDHPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        ECPoint point,
        int hashAlgorithm,
        int symmetricKeyAlgorithm)
    {
        super(oid, point);

        reserved = 1;
        hashFunctionId = (byte)hashAlgorithm;
        symAlgorithmId = (byte)symmetricKeyAlgorithm;

        verifyHashAlgorithm();
        verifySymmetricKeyAlgorithm();
    }

    public ECDHPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        BigInteger point,
        int hashAlgorithm,
        int symmetricKeyAlgorithm)
    {
        super(oid, point);

        reserved = 1;
        hashFunctionId = (byte)hashAlgorithm;
        symAlgorithmId = (byte)symmetricKeyAlgorithm;

        verifyHashAlgorithm();
        verifySymmetricKeyAlgorithm();
    }

    public byte getReserved()
    {
        return reserved;
    }

    public byte getHashAlgorithm()
    {
        return hashFunctionId;
    }

    public byte getSymmetricKeyAlgorithm()
    {
        return symAlgorithmId;
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        super.encode(out);
        out.write(0x3);
        out.write(reserved);
        out.write(hashFunctionId);
        out.write(symAlgorithmId);
    }

    private void verifyHashAlgorithm()
    {
        switch (hashFunctionId)
        {
        case HashAlgorithmTags.SHA256:
        case HashAlgorithmTags.SHA384:
        case HashAlgorithmTags.SHA512:
            break;

        default:
            throw new IllegalStateException("Hash algorithm must be SHA-256 or stronger.");
        }
    }

    private void verifySymmetricKeyAlgorithm()
    {
        switch (symAlgorithmId)
        {
        case SymmetricKeyAlgorithmTags.AES_128:
        case SymmetricKeyAlgorithmTags.AES_192:
        case SymmetricKeyAlgorithmTags.AES_256:
            break;
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
                //RFC 5581 s3: Camellia may be used in any place in OpenPGP where a symmetric cipher
                //   is usable, and it is subject to the same usage requirements
            break;
        default:
            throw new IllegalStateException("Symmetric key algorithm must be AES-128 or stronger.");
        }
    }
}
