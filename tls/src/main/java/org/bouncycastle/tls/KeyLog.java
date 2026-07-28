package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Seam for RFC 9850 (SSLKEYLOGFILE) key logging.
 * <p>
 * Every method here is deliberately a no-op: the standard <code>bctls</code> build has no key
 * logging and cannot be configured to acquire any. Handing the secrets that protect a connection to
 * a third party is a debugging facility that RFC 9850 sec. 1.1 says "MUST NOT be used in a
 * production system", and recommends be excluded from a deployed binary rather than merely switched
 * off in it. Java has no conditional compilation, so the equivalent is a separate artifact: the
 * <code>bctls-klog</code> build replaces this class with one that resolves a
 * <code>org.bouncycastle.tls.keylog.TlsKeyLog</code> named by a <code>java.security</code> property
 * and reports each secret to it. Swapping the jar is then the deliberate act that enables logging,
 * and no property set on a normal deployment can do so.
 * <p>
 * The call sites live in {@link TlsUtils}, at the points where the secrets RFC 9850 names come into
 * effect. They pass the secret in its (D)TLS-internal terms; mapping those onto the RFC's labels is
 * the replacement's job, so this class carries no RFC knowledge and no filtering.
 */
abstract class KeyLog
{
    /**
     * Called as a (D)TLS cipher is initialised, once per handshake, on both full and resumed
     * handshakes. TLS 1.3 also reaches this point, so a replacement has to ignore anything that is
     * not the TLS 1.2-and-earlier master secret of RFC 9850 sec. 2.2.
     *
     * @param context the context whose handshake security parameters carry the master secret.
     */
    static void logMasterSecret(TlsContext context)
    {
    }

    /**
     * Called as each TLS 1.3 secret named by RFC 9850 sec. 2.1 is derived.
     *
     * @param context the context the secret belongs to.
     * @param label the RFC 8446 key-schedule label the secret was derived under, e.g. "s hs
     *            traffic"; a replacement maps these onto the RFC 9850 labels.
     * @param secret the derived secret.
     */
    static void log13Secret(TlsContext context, String label, TlsSecret secret)
    {
    }
}
