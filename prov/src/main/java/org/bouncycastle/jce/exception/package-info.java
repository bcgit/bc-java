/**
 * JCE-side exception types providing a pre-Java-1.4 way to attach an underlying-cause Throwable
 * to the JCE checked-exception hierarchy.
 * <p>
 * Deprecated: obsolete now the minimum runtime carries native exception cause-chaining; throw the
 * standard {@code java.security}/{@code java.security.cert} exceptions, using the
 * {@code org.bouncycastle.jcajce.provider.util.SecurityExceptions} factories where a Java-1.4-safe
 * cause attach is needed.
 */
@Deprecated
package org.bouncycastle.jce.exception;
