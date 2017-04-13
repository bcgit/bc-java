package org.bouncycastle.pqc.crypto;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Interface for NewHope style key material exchange generators.
 */
public interface ExchangePairGenerator
{
    /**
     * Generate an exchange pair based on the sender public key.
     *
     * @param senderPublicKey the public key of the exchange initiator.
     * @return An ExchangePair derived from the sender public key.
     * @deprecated use generateExchange
     */
    ExchangePair GenerateExchange(AsymmetricKeyParameter senderPublicKey);

    /**
     * Generate an exchange pair based on the sender public key.
     *
     * @param senderPublicKey the public key of the exchange initiator.
     * @return An ExchangePair derived from the sender public key.
     */
    ExchangePair generateExchange(AsymmetricKeyParameter senderPublicKey);
}
