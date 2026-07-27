package org.bouncycastle.tls.keylog;

/**
 * A sink for the connection secrets described by
 * <a href="https://www.rfc-editor.org/rfc/rfc9850.html">RFC 9850</a>, the SSLKEYLOGFILE format.
 * <p>
 * Bouncy Castle reports secrets; it does not store them. Each call corresponds to exactly one
 * record of the format defined in RFC 9850 sec. 2 &mdash; a label, the ClientHello random that
 * identifies the connection, and the secret itself &mdash; and what becomes of that record is
 * entirely this interface's business. Nothing in Bouncy Castle opens a file, honours the
 * <code>SSLKEYLOGFILE</code> environment variable, or chooses an encoding; an implementation that
 * wants the literal file format of the RFC writes the three values itself, as
 * <code>label SP client_random SP secret</code> with both byte arrays in hexadecimal:
 *
 * <pre>
 * public void log(String label, byte[] clientRandom, byte[] secret)
 * {
 *     writer.println(label + " " + Hex.toHexString(clientRandom) + " " + Hex.toHexString(secret));
 * }
 * </pre>
 * <p>
 * <b>Selecting an implementation.</b> This interface exists only in the <code>bctls-klog</code>
 * build of the Bouncy Castle TLS API; the standard <code>bctls</code> jar has no key logging in it
 * at all and no property will give it any. Running <code>bctls-klog</code> in place of
 * <code>bctls</code> is the first of the two deliberate acts needed to enable logging. The second
 * is naming an implementation in the <code>java.security</code> file of the JVM being run:
 *
 * <pre>
 * org.bouncycastle.tls.keylog.class=com.example.MyKeyLog
 * </pre>
 *
 * The named class must be public, must implement this interface, must have a public no-argument
 * constructor, and must be on the application's class path. It is read with
 * {@link java.security.Security#getProperty(String)} rather than from a system property, because
 * the security properties are an administrator's configuration channel rather than the ambient
 * namespace any library writes to. Resolution happens once, on the first secret of the first
 * handshake in the JVM; if no property is set nothing is loaded and no secret leaves the library.
 * <p>
 * Be clear about what that property is and is not. It is <em>not</em> a privilege boundary:
 * {@link java.security.Security#setProperty(String, String)} is only permission-checked under a
 * {@link SecurityManager}, which is disabled by default from JDK 17 and cannot be enabled at all
 * from JDK 24, so in a modern JVM any code running in the process can set it before the first
 * handshake. The boundary that actually holds is the artifact: only <code>bctls-klog</code> reads
 * this property or contains any of this package, and the standard <code>bctls</code> jar cannot be
 * made to disclose anything by any property at all. Deploying <code>bctls-klog</code> is therefore
 * the decision that matters &mdash; treat that jar as one that may hand out the keys to every TLS
 * connection the JVM makes, and do not ship it.
 * <p>
 * <b>Implementation contract.</b> A single instance serves the whole JVM and
 * {@link #log(String, byte[], byte[])} is called from whichever thread is running the handshake, so
 * implementations must be thread-safe. The arrays passed in are private copies the implementation
 * may keep or modify. Calls arrive as secrets are derived, in key-schedule order within a
 * connection but interleaved arbitrarily across concurrent connections; <code>clientRandom</code>
 * is what ties a record back to its connection. Anything thrown is caught and reported through
 * {@link java.util.logging}: a failing sink degrades key logging, it never disturbs the connection
 * being logged. An implementation must not itself open a TLS connection, which would re-enter the
 * log from inside the handshake it is logging.
 * <p>
 * <b>Treat <code>clientRandom</code> as untrusted.</b> It is 32 bytes chosen by the peer &mdash; by
 * a remote client, when this end is the server &mdash; so it is the one input here an attacker
 * controls. Writing it hexadecimal, as the RFC's format requires, renders it inert; writing it raw
 * into a log or file lets a peer inject line terminators and forge records. The same caution
 * applies to any name derived from it.
 * <p>
 * <b>Security.</b> The values handed to an implementation decrypt the traffic they belong to, and
 * for TLS 1.2 the master secret also authenticates it. RFC 9850 sec. 1.1 is unambiguous that this
 * "MUST NOT be used in a production system", and sec. 3 asks that access to whatever the secrets
 * are written to be confined by file permissions or an equivalent. An implementation is the last
 * place those constraints can be honoured, so honour them there.
 *
 * @see TlsKeyLogLabel
 */
public interface TlsKeyLog
{
    /**
     * Report one secret, equivalent to one line of an SSLKEYLOGFILE.
     *
     * @param label which secret this is, one of the constants of {@link TlsKeyLogLabel}.
     * @param clientRandom the 32-byte Random of the ClientHello that began the connection the
     *            secret belongs to; the connection identifier of RFC 9850 sec. 2.
     * @param secret the secret itself, its length depending on the label and the negotiated hash.
     */
    void log(String label, byte[] clientRandom, byte[] secret);
}
