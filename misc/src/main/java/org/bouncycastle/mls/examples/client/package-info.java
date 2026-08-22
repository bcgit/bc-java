/**
 * Test harness driving an MLS (RFC 9420) participant - key-package generation, group join,
 * message send / receive and welcome processing - over the MLS working group's gRPC
 * interoperability service, whose messages are generated from {@code src/main/proto/mls_client.proto}.
 * <p>
 * This is a test tool rather than library API, which is why it lives in the non-publishing
 * {@code misc} module: it needs {@code io.grpc} and {@code com.google.protobuf} on the
 * classpath, and it used to ship inside the published {@code bcmls} jar, whose POM and OSGi
 * manifest declared neither. The MLS library itself is {@code org.bouncycastle.mls.*} in the
 * {@code mls} module and has no gRPC dependency.
 */
package org.bouncycastle.mls.examples.client;
