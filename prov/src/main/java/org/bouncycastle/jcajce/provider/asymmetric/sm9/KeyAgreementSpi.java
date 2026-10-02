package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.agreement.SM9KeyExchange;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.SM9KeyExchangeSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

/**
 * JCA adapter for the SM9 key exchange protocol (GM/T 0044.3-2016), registered as
 * {@code KeyAgreement.SM9}. The protocol is two-round, so it maps onto the
 * {@code KeyAgreement} API's two-phase form:
 * <ol>
 * <li>{@code init} with this party's key-exchange user key (from
 * {@link org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey#generateExchangeKeyPair(byte[])})
 * and an {@link SM9KeyExchangeSpec} giving the role and the agreed key length.</li>
 * <li>{@code doPhase(peerUserPublicKey, false)} - names the peer and <b>returns
 * this party's ephemeral value R</b>, whose {@link java.security.Key#getEncoded()}
 * is the 64-byte x || y form to send. The ephemeral is generated here, inside the
 * provider, under the master public key carried on this party's own user key, so
 * it cannot be mis-bound to a different master key.</li>
 * <li>{@code doPhase(peerEphemeral, true)} - the peer's R, then
 * {@code generateSecret()}.</li>
 * </ol>
 * The peer's user public key is checked to carry the same hid and master public
 * key as this party's own key; the peer's identity is taken from it, so the peer
 * is named exactly once.
 * <p>
 * The optional GM/T 0044.3 key-confirmation tags S_A / S_B have no channel in
 * this API and are available from the lightweight
 * {@link org.bouncycastle.crypto.agreement.SM9KeyExchange} only - the same
 * position {@code KeyAgreement.SM2} takes for SM2's confirmation tags.
 */
public class KeyAgreementSpi
    extends BaseAgreementSpi
{
    private SM9EncPrivateKeyParameters key;
    private SM9KeyExchangeSpec spec;
    private SecureRandom random;

    private SM9KeyExchange exchange;
    private byte[] result;

    public KeyAgreementSpi()
    {
        super("SM9", null);
    }

    protected void doInitFromKey(Key key, AlgorithmParameterSpec parameterSpec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        // drop the previous session before the new arguments are examined, so that a rejected
        // init leaves the object uninitialised rather than still holding the last key, spec and
        // ephemeral for an engineDoPhase to run against
        this.key = null;
        this.spec = null;
        this.random = null;
        this.exchange = null;
        clearResult();

        if (!(key instanceof BCSM9EncPrivateKey))
        {
            throw new InvalidKeyException(
                "SM9 key agreement requires a key-exchange user key from SM9EncMasterPrivateKey.generateExchangeKeyPair(identity)");
        }
        if (((BCSM9EncPrivateKey)key).isDestroyed())
        {
            // refused here rather than taken, when the first phase went on to send an ephemeral
            // for an exchange the key could not complete
            throw new InvalidKeyException("key destroyed");
        }
        SM9EncPrivateKeyParameters keyParams = ((BCSM9EncPrivateKey)key).getKeyParameters();
        if (!keyParams.isExchangeKey())
        {
            throw new InvalidKeyException(
                "SM9 key agreement requires a key-exchange user key from SM9EncMasterPrivateKey.generateExchangeKeyPair(identity)");
        }
        if (!(parameterSpec instanceof SM9KeyExchangeSpec))
        {
            throw new InvalidAlgorithmParameterException(
                "SM9 key agreement requires an SM9KeyExchangeSpec giving the role and the agreed key length");
        }

        this.key = keyParams;
        this.spec = (SM9KeyExchangeSpec)parameterSpec;
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
    }

    protected Key engineDoPhase(Key key, boolean lastPhase)
        throws InvalidKeyException, IllegalStateException
    {
        if (this.key == null)
        {
            throw new IllegalStateException("SM9 key agreement not initialised");
        }
        if (this.key.isDestroyed())
        {
            // the key is refused at init; one destroyed since cannot complete an exchange, so the
            // first phase does not send an ephemeral for one, as the last phase cannot derive a key
            throw new IllegalStateException("key destroyed");
        }

        if (!lastPhase)
        {
            return startExchange(key);
        }

        if (exchange == null)
        {
            throw new IllegalStateException(
                "SM9 key agreement requires doPhase with the peer's public key before the peer's ephemeral");
        }
        if (!(key instanceof BCSM9ExchangeEphemeralPublicKey))
        {
            throw new InvalidKeyException(
                "SM9 key agreement requires the peer's ephemeral value for the last phase");
        }

        try
        {
            result = exchange.calculateKey(spec.getKeyLengthBits(),
                ((BCSM9ExchangeEphemeralPublicKey)key).getPoint());
        }
        catch (IllegalArgumentException e)
        {
            // an invalid peer ephemeral point
            throw SecurityExceptions.invalidKeyException(e.getMessage(), e);
        }
        finally
        {
            // The ephemeral answers exactly one peer value: drop it, so another last phase has to
            // follow a first phase that draws a fresh one rather than combining this r with a
            // second peer R. In the finally, so that a path out of calculateKey this method does
            // not name - an unchecked throw from an outsized key length, say - cannot leave it
            // live either; the lightweight class discards its own copy on the success path.
            exchange = null;
        }

        agreementCompleted();

        return null;
    }

    /**
     * First phase: name the peer, generate this party's ephemeral value under our
     * own master key, and hand it back for transmission.
     */
    private Key startExchange(Key key)
        throws InvalidKeyException
    {
        // Drop whatever a previous agreement on this object left behind before the new peer is
        // examined. Otherwise a first phase rejected for a third party, after a completed
        // agreement with a second, left that second agreement's shared secret in place and
        // generateSecret() went on returning it - now attributed to the third party.
        clearResult();
        this.exchange = null;
        resetAgreement();

        if (!(key instanceof BCSM9EncPublicKey))
        {
            throw new InvalidKeyException(
                "SM9 key agreement requires the peer's public key from SM9EncMasterPublicKey.getUserPublicKey for the first phase");
        }
        SM9EncPublicKeyParameters peer = ((BCSM9EncPublicKey)key).getKeyParameters();
        if (peer.getHid() != this.key.getHid())
        {
            throw new InvalidKeyException("SM9 key agreement peer key hid does not match this party's key");
        }
        if (!Arrays.areEqual(peer.getMasterPublicKey().getEncoded(),
            this.key.getMasterPublicKey().getEncoded()))
        {
            throw new InvalidKeyException("SM9 key agreement peer key is not under this party's master public key");
        }

        this.exchange = new SM9KeyExchange(this.key, peer.getIdentity(), spec.isInitiator());

        ECPoint r = exchange.generateEphemeral(random);

        return new BCSM9ExchangeEphemeralPublicKey(r);
    }

    /**
     * Erase the shared secret this object holds before dropping it: generateSecret() hands out a
     * copy, so the held array would otherwise stay live, unerased, until the object was collected.
     */
    private void clearResult()
    {
        if (result != null)
        {
            Arrays.clear(result);
            result = null;
        }
    }

    protected byte[] doCalcSecret()
    {
        if (result == null)
        {
            throw new IllegalStateException("SM9 key agreement not completed");
        }
        return Arrays.clone(result);
    }
}
