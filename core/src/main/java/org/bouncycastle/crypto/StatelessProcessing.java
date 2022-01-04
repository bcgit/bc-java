package org.bouncycastle.crypto;

/**
 * Ciphers that implement StatelessProcessing are thread safe for encrypt/decrypt - just not initialisation.
 */
public interface StatelessProcessing
{
    BlockCipher newInstance();
}
