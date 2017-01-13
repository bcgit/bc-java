package org.bouncycastle.est.http;

/**
 * ESTHttpClient provides a http(s) connection with TLS or Certificate-Less TLS Mutual Authentication.
 *
 * Implementations should be aware that they are responsible for
 * satisfying <a hrref="https://tools.ietf.org/html/rfc7030#section-3.3">RFC7030 3.3 - TLS Layer</a>
 * including SRP modes.
 *
 */
public interface ESTHttpClient
{
    public ESTHttpResponse doRequest(ESTHttpRequest c) throws Exception;
}
