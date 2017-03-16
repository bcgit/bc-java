package org.bouncycastle.openpgp.wot;

import static org.assertj.core.api.Assertions.*;
import static org.bouncycastle.openpgp.PGPSignature.*;
import static org.bouncycastle.openpgp.wot.TrustConst.*;

import org.bouncycastle.openpgp.wot.internal.TrustDbImpl;
import org.bouncycastle.openpgp.wot.key.PgpKey;
import org.junit.Test;

public class UpdateTrustDbTest extends AbstractTrustDbTest {

	@Test
	public void directOnly() throws Exception {
		PgpKey aliceKey = createPgpKey("alice");
		PgpKey bobKey = createPgpKey("bob");
		PgpKey cathrinKey = createPgpKey("cathrin");

		bobKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, bobKey);

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.setOwnerTrust(aliceKey.getPublicKey(), OwnerTrust.ULTIMATE);
		}

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidityRaw(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);
				assertThat(trustDb.getValidityRaw(bobKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(cathrinKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
			}
		}

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();
			assertThat(trustDb.getValidityRaw(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);
			assertThat(trustDb.getValidityRaw(bobKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(cathrinKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
		}
	}

	@Test
	public void oneIndirection() throws Exception {
		PgpKey aliceKey = createPgpKey("alice");
		PgpKey bobKey = createPgpKey("bob");
		PgpKey cathrinKey = createPgpKey("cathrin"); // not signed at all
		PgpKey danielKey = createPgpKey("daniel");
		PgpKey emilKey = createPgpKey("emil");
		PgpKey frankKey = createPgpKey("frank");
		PgpKey georgKey = createPgpKey("georg");
		PgpKey hansKey = createPgpKey("hans");

		bobKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, bobKey); // bob <= alice
		danielKey = signPublicKey(bobKey, POSITIVE_CERTIFICATION, danielKey); // daniel <= bob <= alice
		emilKey = signPublicKey(cathrinKey, POSITIVE_CERTIFICATION, emilKey); // emil <= cathrin ||| alice
		frankKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, frankKey); // frank <= alice

		georgKey = signPublicKey(frankKey, POSITIVE_CERTIFICATION, georgKey); // georg <= frank <= alice
		hansKey = signPublicKey(bobKey, CASUAL_CERTIFICATION, hansKey); // hans <= bob <= alice

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.setOwnerTrust(aliceKey.getPublicKey(), OwnerTrust.ULTIMATE);

			trustDb.setOwnerTrust(bobKey.getPublicKey(), OwnerTrust.FULL);
			trustDb.setOwnerTrust(cathrinKey.getPublicKey(), OwnerTrust.FULL);
			trustDb.setOwnerTrust(frankKey.getPublicKey(), OwnerTrust.MARGINAL);
		}

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidityRaw(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);
				assertThat(trustDb.getValidityRaw(bobKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(cathrinKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
				assertThat(trustDb.getValidityRaw(danielKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_FULL); // the signature type (CASUAL) has no effect :-(
			}
		}

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();
			assertThat(trustDb.getValidityRaw(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);
			assertThat(trustDb.getValidityRaw(bobKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(cathrinKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
			assertThat(trustDb.getValidityRaw(danielKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_FULL); // behave like GnuPG!
		}
	}

	@Test
	public void twoIndirections() throws Exception {
		PgpKey aliceKey = createPgpKey("alice");

		PgpKey bobKey = createPgpKey("bob");
		PgpKey cathrinKey = createPgpKey("cathrin");
		PgpKey danielKey = createPgpKey("daniel");
		PgpKey emilKey = createPgpKey("emil");

		PgpKey frankKey = createPgpKey("frank");
		PgpKey georgKey = createPgpKey("georg");
		PgpKey hansKey = createPgpKey("hans");
		PgpKey idaKey = createPgpKey("ida");

		PgpKey johnKey = createPgpKey("john");

		bobKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, bobKey); // bob <= alice
		cathrinKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, cathrinKey); // cathrin <= alice
		danielKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, danielKey); // daniel <= alice
		emilKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, emilKey); // emil <= alice

		frankKey = signPublicKey(bobKey, POSITIVE_CERTIFICATION, frankKey); // frank <= bob <= alice
		georgKey = signPublicKey(cathrinKey, POSITIVE_CERTIFICATION, georgKey); // georg <= cathrin <= alice
		hansKey = signPublicKey(danielKey, POSITIVE_CERTIFICATION, hansKey); // hans <= daniel <= alice
		idaKey = signPublicKey(emilKey, POSITIVE_CERTIFICATION, idaKey); // hans <= emil <= alice

		johnKey = signPublicKey(frankKey, POSITIVE_CERTIFICATION, johnKey); // john <= frank <= bob <= alice

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.setOwnerTrust(aliceKey.getPublicKey(), OwnerTrust.ULTIMATE);

			trustDb.setOwnerTrust(bobKey.getPublicKey(), OwnerTrust.MARGINAL);
			trustDb.setOwnerTrust(cathrinKey.getPublicKey(), OwnerTrust.MARGINAL);
			trustDb.setOwnerTrust(danielKey.getPublicKey(), OwnerTrust.MARGINAL);
			trustDb.setOwnerTrust(emilKey.getPublicKey(), OwnerTrust.MARGINAL);

			trustDb.setOwnerTrust(frankKey.getPublicKey(), OwnerTrust.MARGINAL);
			trustDb.setOwnerTrust(georgKey.getPublicKey(), OwnerTrust.MARGINAL);
			trustDb.setOwnerTrust(hansKey.getPublicKey(), OwnerTrust.MARGINAL);
			trustDb.setOwnerTrust(idaKey.getPublicKey(), OwnerTrust.MARGINAL);
		}

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidityRaw(bobKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(cathrinKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(danielKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(emilKey.getPublicKey())).isEqualTo(TRUST_FULL);

				assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

				assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
			}
		}

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();

			assertThat(trustDb.getValidityRaw(bobKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(cathrinKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(danielKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(emilKey.getPublicKey())).isEqualTo(TRUST_FULL);

			assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

			assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
		}

		frankKey = signPublicKey(cathrinKey, POSITIVE_CERTIFICATION, frankKey); // frank <= bob+cathrin <= alice
		georgKey = signPublicKey(bobKey, POSITIVE_CERTIFICATION, georgKey); // georg <= bob+cathrin <= alice
		hansKey = signPublicKey(emilKey, POSITIVE_CERTIFICATION, hansKey); // hans <= daniel+emil <= alice
		idaKey = signPublicKey(danielKey, POSITIVE_CERTIFICATION, idaKey); // hans <= daniel+emil <= alice

		johnKey = signPublicKey(georgKey, POSITIVE_CERTIFICATION, johnKey); // john <= frank+georg <= bob+cathrin <= alice
		johnKey = signPublicKey(hansKey, POSITIVE_CERTIFICATION, johnKey); // john <= frank+georg+hans <= bob+cathrin+daniel+emil <= alice

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

				assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
			}
		}

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();

			assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

			assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
		}


		frankKey = signPublicKey(emilKey, POSITIVE_CERTIFICATION, frankKey); // frank <= bob+cathrin+emil <= alice
		georgKey = signPublicKey(emilKey, POSITIVE_CERTIFICATION, georgKey); // georg <= bob+cathrin+emil <= alice

		// john <= frank+georg+hans <= bob+cathrin+daniel+emil <= alice

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

				assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			}
		}

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();

			assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

			assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
		}

		hansKey = signPublicKey(cathrinKey, POSITIVE_CERTIFICATION, hansKey); // hans <= cathrin+daniel+emil <= alice

		// UNCHANGED: john <= frank+georg+hans <= bob+cathrin+daniel+emil <= alice
		// only the validity of hans' key changed from MARGINAL to FULL - and is now taken into account.
		// => now there are 3 marginal signatures for john => it changes from MARGINAL to FULL, too.

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

				assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_FULL);
			}
		}

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();

			assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

			assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_FULL);
		}
	}

	@Test
	public void threeIndirections() throws Exception {
		PgpKey aliceKey = createPgpKey("alice");

		PgpKey bobKey = createPgpKey("bob");
		PgpKey cathrinKey = createPgpKey("cathrin");
		PgpKey danielKey = createPgpKey("daniel");
		PgpKey[] level1Keys = new PgpKey[] { bobKey, cathrinKey, danielKey };

		PgpKey emilKey = createPgpKey("emil");
		PgpKey frankKey = createPgpKey("frank");
		PgpKey georgKey = createPgpKey("georg");
		PgpKey[] level2Keys = new PgpKey[] { emilKey, frankKey, georgKey };

		PgpKey hansKey = createPgpKey("hans");
		PgpKey idaKey = createPgpKey("ida");
		PgpKey johnKey = createPgpKey("john");
		PgpKey[] level3Keys = new PgpKey[] { hansKey, idaKey, johnKey };

		PgpKey karlKey = createPgpKey("john");

		bobKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, bobKey); // bob <= alice
		cathrinKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, cathrinKey); // cathrin <= alice
		danielKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, danielKey); // daniel <= alice


		for (PgpKey signingKey : level1Keys) {
			emilKey = signPublicKey(signingKey, POSITIVE_CERTIFICATION, emilKey); // emil <= bob+cathrin+daniel <= alice
			frankKey = signPublicKey(signingKey, POSITIVE_CERTIFICATION, frankKey); // frank <= bob+cathrin+daniel <= alice
			georgKey = signPublicKey(signingKey, POSITIVE_CERTIFICATION, georgKey); // georg <= bob+cathrin+daniel <= alice
		}


		for (PgpKey signedKey : level3Keys) {
			signPublicKey(emilKey, POSITIVE_CERTIFICATION, signedKey);
			signPublicKey(frankKey, POSITIVE_CERTIFICATION, signedKey);
		}

		signPublicKey(georgKey, POSITIVE_CERTIFICATION, hansKey);
		signPublicKey(georgKey, POSITIVE_CERTIFICATION, idaKey);

		for (PgpKey signingKey : level3Keys)
			signPublicKey(signingKey, POSITIVE_CERTIFICATION, karlKey);

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.setOwnerTrust(aliceKey.getPublicKey(), OwnerTrust.ULTIMATE);

			for (PgpKey key : level1Keys)
				trustDb.setOwnerTrust(key.getPublicKey(), OwnerTrust.MARGINAL);

			for (PgpKey key : level2Keys)
				trustDb.setOwnerTrust(key.getPublicKey(), OwnerTrust.MARGINAL);

			for (PgpKey key : level3Keys)
				trustDb.setOwnerTrust(key.getPublicKey(), OwnerTrust.MARGINAL);
		}


		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidityRaw(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);

				assertThat(trustDb.getValidityRaw(bobKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(cathrinKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(danielKey.getPublicKey())).isEqualTo(TRUST_FULL);

				assertThat(trustDb.getValidityRaw(emilKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_FULL);

				assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

				assertThat(trustDb.getValidityRaw(karlKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			}
		}

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();

			assertThat(trustDb.getValidityRaw(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);

			assertThat(trustDb.getValidityRaw(bobKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(cathrinKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(danielKey.getPublicKey())).isEqualTo(TRUST_FULL);

			assertThat(trustDb.getValidityRaw(emilKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_FULL);

			assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

			assertThat(trustDb.getValidityRaw(karlKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
		}


		signPublicKey(georgKey, POSITIVE_CERTIFICATION, johnKey);


		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidityRaw(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);

				assertThat(trustDb.getValidityRaw(bobKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(cathrinKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(danielKey.getPublicKey())).isEqualTo(TRUST_FULL);

				assertThat(trustDb.getValidityRaw(emilKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_FULL);

				assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_FULL);
				assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_FULL);

				assertThat(trustDb.getValidityRaw(karlKey.getPublicKey())).isEqualTo(TRUST_FULL);
			}
		}

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();

			assertThat(trustDb.getValidityRaw(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);

			assertThat(trustDb.getValidityRaw(bobKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(cathrinKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(danielKey.getPublicKey())).isEqualTo(TRUST_FULL);

			assertThat(trustDb.getValidityRaw(emilKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(frankKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(georgKey.getPublicKey())).isEqualTo(TRUST_FULL);

			assertThat(trustDb.getValidityRaw(hansKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(idaKey.getPublicKey())).isEqualTo(TRUST_FULL);
			assertThat(trustDb.getValidityRaw(johnKey.getPublicKey())).isEqualTo(TRUST_FULL);

			assertThat(trustDb.getValidityRaw(karlKey.getPublicKey())).isEqualTo(TRUST_FULL);
		}
	}
}
