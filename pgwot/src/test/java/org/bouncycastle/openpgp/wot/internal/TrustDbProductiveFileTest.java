package org.bouncycastle.openpgp.wot.internal;

import static org.assertj.core.api.Assertions.*;
import static org.bouncycastle.openpgp.wot.TrustConst.*;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.openpgp.wot.AbstractTrustDbTest;
import org.bouncycastle.openpgp.wot.TrustDb;
import org.bouncycastle.openpgp.wot.internal.Mutex;
import org.bouncycastle.openpgp.wot.internal.TrustDbImpl;
import org.bouncycastle.openpgp.wot.internal.TrustDbIo;
import org.bouncycastle.openpgp.wot.internal.TrustRecord;
import org.bouncycastle.openpgp.wot.internal.TrustRecord.Trust;
import org.bouncycastle.openpgp.wot.internal.TrustRecordType;
import org.bouncycastle.openpgp.wot.key.PgpKey;
import org.bouncycastle.openpgp.wot.key.PgpKeyId;
import org.bouncycastle.openpgp.wot.key.PgpUserId;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Ignore("This test is for playing around while developing - it's not a regular test!")
public class TrustDbProductiveFileTest extends AbstractTrustDbTest {
	private static final Logger logger = LoggerFactory.getLogger(TrustDbProductiveFileTest.class);

	private Mutex mutex;

	@Override
	protected void initGnupgHomeDir() {
		String userHome = System.getProperty("user.home");
		gnupgHomeDir = new File(userHome, ".gnupg");
		mutex = Mutex.forPgpDir(gnupgHomeDir);
	}

	@Override
	protected void deleteGnupgHomeDir() {
		// nothing - MUST NOT delete our productive ".gnupg" directory!
	}

	@Test
	public void readMyProductiveTrustDb() throws Exception {
		try (TrustDbIo trustDbIo = new TrustDbIo(trustdbFile, mutex);) {
			long recordNum = -1;
			TrustRecord trustRecord;
			List<byte[]> trustFingerprints = new ArrayList<>();
			while ((trustRecord = trustDbIo.getTrustRecord(++recordNum)) != null) {
				System.out.println(trustRecord);
				if (trustRecord.getType() == TrustRecordType.TRUST)
					trustFingerprints.add(((TrustRecord.Trust) trustRecord).getFingerprint());
			}

			for (byte[] trustFingerprint : trustFingerprints) {
				Trust trust = trustDbIo.getTrustByFingerprint(trustFingerprint);
				assertThat(trust).isNotNull();
			}
		}
	}

	@Test
	public void updateMyProductiveDbHashTable() throws Exception {
		try (TrustDbIo trustDbIo = new TrustDbIo(trustdbFile, mutex);) {
			long recordNum = -1;
			TrustRecord trustRecord;
			List<TrustRecord.Trust> trusts = new ArrayList<>();
			while ((trustRecord = trustDbIo.getTrustRecord(++recordNum)) != null) {
				if (trustRecord.getType() == TrustRecordType.TRUST)
					trusts.add((TrustRecord.Trust) trustRecord);
			}

			for (TrustRecord.Trust trust : trusts) {
				trustDbIo.putTrustRecord(trust);
			}
		}
	}

	@Test
	public void readBrokenRecord() throws Exception {
		byte[] fingerprint = new byte[]
				{ -5, 17, -44, -69, 123, 36, 70, 120, 51, 122, -83, -117, -57, -65, 38, -48, -69, 97, 120, 102 };

		try (TrustDbIo trustDbIo = new TrustDbIo(trustdbFile, mutex);) {
			TrustRecord.Trust trust = trustDbIo.getTrustByFingerprint(fingerprint);
			if (trust == null) {
				long recordNum = -1;
				TrustRecord trustRecord;
				while ((trustRecord = trustDbIo.getTrustRecord(++recordNum)) != null) {
					System.out.println(trustRecord);
					if (trustRecord.getType() == TrustRecordType.TRUST) {
						TrustRecord.Trust t = (TrustRecord.Trust) trustRecord;
						if (Arrays.equals(fingerprint, t.getFingerprint()))
							fail("Trust was not found via hashtable, but found by full-scan: recordNum = " + recordNum);
					}
				}
			}
		}
		System.out.println("trust not found!!!");
	}

	@Test
	public void isExpired() throws Exception {
		PgpKey pgpKey = pgpKeyRegistry.getPgpKey(new PgpKeyId("56422A5E710E3371"));
		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.isExpired(pgpKey.getPublicKey());
		}
	}

	@Test
	public void updateMyProductiveTrustDb() throws Exception {
		runGpgCheckTrustDb();

		Map<PgpUserId, Integer> pgpUserId2ValidityOriginal = getPgpUserId2Validity();

		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();
		}

		Map<PgpUserId, Integer> pgpUserId2ValidityMine = getPgpUserId2Validity();

		for (PgpUserId pgpUserId : pgpUserId2ValidityOriginal.keySet()) {
			if (! pgpUserId2ValidityMine.containsKey(pgpUserId))
				fail(String.format("pgpUserId2ValidityMine is missing pgpUserId=%s", pgpUserId));
		}

		for (PgpUserId pgpUserId : pgpUserId2ValidityMine.keySet()) {
			if (! pgpUserId2ValidityOriginal.containsKey(pgpUserId))
				fail(String.format("pgpUserId2ValidityOriginal is missing pgpUserId=%s", pgpUserId));
		}

		int successValidityQty = 0;
		int warningValidityQty = 0;
		List<String> fatals = new ArrayList<>();
		for (Map.Entry<PgpUserId, Integer> me : pgpUserId2ValidityOriginal.entrySet()) {
			PgpUserId pgpUserId = me.getKey();
			Integer originalValidity = me.getValue();
			assertThat(originalValidity).isNotNull();

			Integer myValidity = pgpUserId2ValidityMine.get(pgpUserId);
			assertThat(myValidity).isNotNull();

			if (originalValidity.equals(myValidity))
				++successValidityQty;
			else {
				String message = String.format("myValidity is different for pgpUserId=%s: originalValidity=%d myValidity=%d",
						pgpUserId, originalValidity, myValidity);

				if (originalValidity.equals(2) && myValidity.equals(0)) {
					++warningValidityQty;
					logger.warn(message);
				}
				else if ((originalValidity & TRUST_FLAG_DISABLED) != 0 && (myValidity & TRUST_FLAG_DISABLED) != 0) {
					++warningValidityQty;
					logger.warn(message);
				}
				else {
					logger.error(message);
					fatals.add(message);
				}
			}
		}

		logger.info("updateMyProductiveTrustDb: successValidityQty={} warningValidityQty={} errorValidityQty={}",
				successValidityQty, warningValidityQty, fatals.size());

		if (! fatals.isEmpty())
			fail(fatals.toString());

		assertThat(pgpUserId2ValidityMine).isEqualTo(pgpUserId2ValidityOriginal);
	}

	private Map<PgpUserId, Integer> getPgpUserId2Validity() throws Exception {
		Map<PgpUserId, Integer> pgpUserId2Validity = new HashMap<>();
		try (TrustDb trustDb = new TrustDbImpl(trustdbFile, pgpKeyRegistry);) {
			for (PgpKey pgpKey : pgpKeyRegistry.getMasterKeys()) {
				for (PgpUserId pgpUserId : pgpKey.getPgpUserIds()) {
//					if (pgpUserId.getUserId() != null) {
						int validity = trustDb.getValidityRaw(pgpKey.getPublicKey(), pgpUserId.getNameHash());
						pgpUserId2Validity.put(pgpUserId, validity);
//					}
				}
			}
		}
		return pgpUserId2Validity;
	}

}
