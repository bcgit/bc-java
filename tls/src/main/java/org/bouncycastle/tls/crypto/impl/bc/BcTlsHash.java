package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.tls.crypto.TlsHash;

final class BcTlsHash
    implements TlsHash
{
    private final BcTlsCrypto crypto;
    private final int cryptoHashAlgorithm;
    private final Digest digest;

    BcTlsHash(BcTlsCrypto crypto, int cryptoHashAlgorithm)
    {
        this(crypto, cryptoHashAlgorithm, crypto.createDigest(cryptoHashAlgorithm));
    }

    private BcTlsHash(BcTlsCrypto crypto, int cryptoHashAlgorithm, Digest digest)
    {
        this.crypto = crypto;
        this.cryptoHashAlgorithm = cryptoHashAlgorithm;
        this.digest = digest;
    }

    public void update(byte[] data, int offSet, int length)
    {
        digest.update(data, offSet, length);
    }

    public byte[] calculateHash()
    {
        byte[] rv = new byte[digest.getDigestSize()];
        digest.doFinal(rv, 0);
        return rv;
    }

    public TlsHash cloneHash()
    {
        return new BcTlsHash(crypto, cryptoHashAlgorithm, crypto.cloneDigest(cryptoHashAlgorithm, digest));
    }

    public void reset()
    {
        digest.reset();
    }
}
