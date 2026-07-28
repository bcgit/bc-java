# bctls-klog — RFC 9850 (SSLKEYLOGFILE) Key Logging

`bctls-klog` is the Bouncy Castle TLS API built with key logging present. It reports the secrets
that protect a TLS connection — in the terms of
[RFC 9850](https://www.rfc-editor.org/rfc/rfc9850.html), the SSLKEYLOGFILE format — so that a packet
capture of a connection can be decrypted by an analyser such as Wireshark.

> **This must not be used in production.** RFC 9850 sec. 1.1 is unambiguous: the format "is intended
> for use in systems where TLS only protects test data ... this mechanism MUST NOT be used in a
> production system." Anything holding these secrets can decrypt the traffic they belong to, and for
> TLS 1.2 the master secret authenticates it as well. Treat this jar as one that may hand out the
> keys to every TLS connection the JVM makes.

## How it is arranged, and why

Bouncy Castle **reports** secrets; it does not store them. There is no file, no `SSLKEYLOGFILE`
environment variable, and no encoding chosen for you. You implement a one-method interface and
decide what becomes of each record — which is also the only place the RFC's access-control
requirements can actually be honoured.97

Turning key logging on takes two deliberate acts, and both are required:

1. **Run `bctls-klog` in place of `bctls`.** The standard `bctls` jar contains no key logging at all,
   and no property will give it any.
2. **Name your implementation** in the `java.security` file of the JVM you are running.

RFC 9850 sec. 1.1 recommends that a deployed binary not be *able* to disclose its own keys, and
suggests conditional compilation to that end. Java has no conditional compilation, so the equivalent
is a separate artifact. Swapping the jar is the decision that matters; the property only selects
where the secrets go.

Because the reporting sits in the TLS key schedule itself, it covers both the low-level
`org.bouncycastle.tls` API and the BCJSSE provider (`SSLSocket`, `SSLEngine`, `HttpsURLConnection`,
…) with no difference in setup.

## 1. Get the jar

`bctls-klog` is a drop-in replacement for `bctls`: same module name (`org.bouncycastle.tls`), same
packages, plus the exported `org.bouncycastle.tls.keylog`.

**Never put `bctls` and `bctls-klog` on the same class path.** They define the same classes, and
which one wins would come down to class path order. Replace one with the other. For the same reason
`bctls-klog` is deliberately absent from the Bouncy Castle BOM — the two are alternatives, not
companions.

**Maven**:

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bctls-klog-jdk18on</artifactId>
    <version>1.86</version>
</dependency>
```

**Gradle**:

```groovy
implementation 'org.bouncycastle:bctls-klog-jdk18on:1.86'
```

It needs the same companions as `bctls` — `bcprov-jdk18on`, `bcutil-jdk18on` and `bcpkix-jdk18on`.

To build it from this source tree instead:

```
./gradlew :tls-klog:jar
# -> tls-klog/build/libs/bctls-klog-jdk18on-<version>.jar
```

## 2. Implement `TlsKeyLog`

```java
public interface TlsKeyLog
{
    void log(String label, byte[] clientRandom, byte[] secret);
}
```

Each call is exactly one record of RFC 9850 sec. 2: a label, the ClientHello random identifying the
connection, and the secret. Writing the RFC's literal file format means emitting
`label SP client_random SP secret` with both byte arrays in hexadecimal.

The smallest thing that works, to see it running:

```java
package com.example;

import org.bouncycastle.tls.keylog.TlsKeyLog;
import org.bouncycastle.util.encoders.Hex;

public class SysoutKeyLog implements TlsKeyLog
{
    public synchronized void log(String label, byte[] clientRandom, byte[] secret)
    {
        System.out.println(label + " " + Hex.toHexString(clientRandom) + " " + Hex.toHexString(secret));
    }
}
```

### A version fit to leave running

The example below is the one to copy. It is hex-encoded, thread-safe, size-bounded, and creates its
file owner-readable only. Each of those addresses something from
[Pitfalls](#pitfalls-worth-knowing-about) below, so read that section before adapting it.

```java
package com.example;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;

import org.bouncycastle.tls.keylog.TlsKeyLog;
import org.bouncycastle.util.encoders.Hex;

/**
 * Writes an RFC 9850 SSLKEYLOGFILE. The destination comes from the "example.keylog.file" system
 * property: the TlsKeyLog interface has no configuration hook, so a sink reads its own settings.
 */
public class FileKeyLog
    implements TlsKeyLog
{
    /** A remote peer can drive records without authenticating, so the file needs a ceiling. */
    private static final long MAX_BYTES = 64L * 1024 * 1024;

    private final Object lock = new Object();

    private BufferedWriter writer;
    private long written;
    private boolean full;

    public FileKeyLog() throws IOException
    {
        Path path = Paths.get(System.getProperty("example.keylog.file", "tls-keys.log"));

        // Create it before opening, so it is never briefly world-readable.
        if (!Files.exists(path))
        {
            try
            {
                Files.createFile(path,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            }
            catch (UnsupportedOperationException e)
            {
                Files.createFile(path);   // not a POSIX filesystem; restrict it by other means
            }
        }

        this.writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8,
            StandardOpenOption.WRITE, StandardOpenOption.APPEND);
    }

    public void log(String label, byte[] clientRandom, byte[] secret)
    {
        // Hex, always: clientRandom is chosen by the peer and must not reach the file raw.
        String record = label + " " + Hex.toHexString(clientRandom) + " " + Hex.toHexString(secret);

        synchronized (lock)
        {
            if (full)
            {
                return;
            }

            try
            {
                writer.write(record);
                writer.newLine();
                writer.flush();   // an analyser may be reading this file already

                written += record.length() + 1;
                if (written >= MAX_BYTES)
                {
                    full = true;
                    writer.close();
                }
            }
            catch (IOException e)
            {
                // Give up quietly rather than throw on every subsequent handshake.
                full = true;
            }
        }
    }
}
```

Requirements on the class itself, all enforced at load time:

- **public**, and implementing `org.bouncycastle.tls.keylog.TlsKeyLog`
- a **public no-argument constructor** (it may throw; key logging is then disabled and the failure
  logged)
- on the **application's class path**

The type is checked before the class is initialised or constructed, so naming something that is not
a `TlsKeyLog` disables logging rather than running any of its code.

## 3. Name it in `java.security`

Add the property to the `java.security` file of the JVM you are running (or a file supplied with
`-Djava.security.properties=`):

```properties
org.bouncycastle.tls.keylog.class=com.example.FileKeyLog
```

It is read with `Security.getProperty(...)`, resolved **once**, on the first secret of the first
handshake in the JVM. If the property is unset, nothing is loaded and no secret leaves the library.

When it does load, the library says so once through `java.util.logging`, at `WARNING`:

```
TLS key logging is enabled: connection secrets are being reported to com.example.FileKeyLog
as described by RFC 9850. This must not be done in production.
```

> **This property is not a privilege boundary.** `Security.setProperty` is only permission-checked
> under a `SecurityManager`, which is disabled by default from JDK 17 and cannot be enabled at all
> from JDK 24 — so in a modern JVM any code in the process can set it before the first handshake.
> The boundary that holds is the artifact, not the setting.

## 4. Decrypt the capture

Point Wireshark at the file: **Preferences → Protocols → TLS → (Pre)-Master-Secret log filename**.
Or from the command line:

```
tshark -o tls.keylog_file:/path/to/tls-keys.log -r capture.pcap
```

The capture and the log must come from the same connections — the `client_random` in each record is
what ties the two together.

## What gets reported

| RFC 9850 label | When |
|---|---|
| `CLIENT_RANDOM` | (D)TLS 1.2 and earlier, on full **and** resumed handshakes |
| `CLIENT_HANDSHAKE_TRAFFIC_SECRET` | TLS 1.3, once the ServerHello is sent |
| `SERVER_HANDSHAKE_TRAFFIC_SECRET` | TLS 1.3, once the ServerHello is sent |
| `CLIENT_TRAFFIC_SECRET_0` | TLS 1.3, after the server's Finished |
| `SERVER_TRAFFIC_SECRET_0` | TLS 1.3, after the server's Finished |
| `EXPORTER_SECRET` | TLS 1.3, after the server's Finished |

Both peers report independently, so running both ends of a connection in one JVM yields two
identical records per label.

Not currently reported:

- **`CLIENT_EARLY_TRAFFIC_SECRET` / `EARLY_EXPORTER_SECRET`** — defined in `TlsKeyLogLabel` and wired
  to the key schedule, but unreachable until TLS 1.3 early data is implemented.
- **`ECH_SECRET` / `ECH_CONFIG`** (RFC 9850 sec. 2.3) — Encrypted ClientHello is not implemented.
- **Post-KeyUpdate traffic secrets** — RFC 9850 defines no labels for these.

Secrets are reported **as they are derived**, so a handshake that later fails has still reported
whatever it got to — which is usually the point, when the failing handshake is what you are
debugging.

## Pitfalls worth knowing about

**`clientRandom` is chosen by an attacker.** It is 32 bytes taken verbatim from ClientHello.random.
When your JVM is the *server*, every byte belongs to whoever connected — and to nobody
authenticated, because a server derives and reports its TLS 1.3 handshake secrets as soon as it has
sent its ServerHello. Three things follow:

- **Hex-encode it.** Written raw into a log or file, a peer can embed line terminators to split and
  forge records, or path separators to escape a directory. The same goes for any file name or map
  key derived from it.
- **It is not unique.** Nothing obliges a peer to vary it, so two connections can carry the same
  value. A sink using it as a primary key or file name will have one connection's secrets collide
  with or overwrite another's.
- **It is not rate-limited.** An unauthenticated peer can drive an unbounded number of records by
  opening handshakes it never completes. Bound the size of whatever you write, rotate it, or both.

**Thread safety is yours.** One instance serves the whole JVM, and `log` is called on whichever
thread is running the handshake. Records arrive in key-schedule order within a connection but
interleaved arbitrarily across concurrent connections.

**Failures.** An `Exception` thrown out of `log` is caught and reported through `java.util.logging`,
leaving the connection alone. An `Error` is *not* caught and will abort the handshake in progress —
which is the practical reason to bound what you accumulate rather than let it reach
`OutOfMemoryError`.

**Do not open a TLS connection from inside `log`.** It would re-enter the key log from within the
handshake it is logging.

**The arrays are yours.** Both are private copies; keep or modify them freely.

**Protect the output.** RFC 9850 sec. 3 asks that access be confined by file permissions or an
equivalent. Whatever you write to is as sensitive as every private key in the JVM.

## Troubleshooting

**Nothing is reported at all.** Work down the list:

1. Is the running jar actually `bctls-klog`? Confirm the package is present:
   `unzip -l bctls-*.jar | grep 'tls/keylog/'` — the standard `bctls` matches nothing.
2. Are both `bctls` and `bctls-klog` on the class path? Remove `bctls`.
3. Is the property in the `java.security` the JVM is really using?
4. Enable `java.util.logging` at `WARNING` for `org.bouncycastle.tls.KeyLog`. Loading either
   announces itself or explains why it failed.
5. Did the first handshake already happen before the property was set? Resolution happens once.

**"is not a org.bouncycastle.tls.keylog.TlsKeyLog"** — the named class does not implement the
interface, or a second copy of the interface came from a different class loader.

**Records appear but Wireshark decrypts nothing** — check the capture covers the *whole* handshake
including ClientHello, and that a non-PFS TLS 1.2 suite is not in play with only `CLIENT_RANDOM`
available for a different connection.

## Confirming production is unaffected

Key logging cannot be enabled in a standard build. To prove a given artifact is the standard one,
check for the key-log package — not for the string "keylog", which is a near-miss:

```
unzip -l bctls-jdk18on-<version>.jar | grep 'tls/keylog/'     # no output
```

A case-insensitive search *will* turn up `org/bouncycastle/tls/KeyLog.class` in the standard jar, and
that is expected rather than alarming. It is the seam: a single inert class, a few hundred bytes,
whose methods are empty. It reads no property, references nothing in this package, and no
configuration changes that — the standard jar has no `org/bouncycastle/tls/keylog/` package at all,
which is what the command above looks for.

## See also

- [RFC 9850](https://www.rfc-editor.org/rfc/rfc9850.html) — the SSLKEYLOGFILE format
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) sec. 7.1 — the TLS 1.3 key schedule the
  labels name
- `org.bouncycastle.tls.keylog.TlsKeyLog` and `TlsKeyLogLabel` — the API, with the same guidance in
  Javadoc form
