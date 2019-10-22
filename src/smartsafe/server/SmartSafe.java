package smartsafe.server;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class SmartSafe extends Applet implements Constants {
	private static final byte[] version = {'0', '.', '9', '.', '2'};
	private byte[] workingArray;
	private OwnerPIN pin;
	private boolean isInitialized;
	private Key intKey;
	private Cipher intCipher;
	
	private Group[] groups;
	private Object[] selection;
	
	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new SmartSafe().register();
	}
	
	public SmartSafe() {
		isInitialized = false;
		workingArray = JCSystem.makeTransientByteArray(KeyBuilder.LENGTH_AES_128, JCSystem.CLEAR_ON_DESELECT);
		this.pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
		RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(workingArray, ZERO, KeyBuilder.LENGTH_AES_128);
		intKey = KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, true);
		((AESKey) intKey).setKey(workingArray, ZERO);
		intCipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M1, false);
		
		groups = new Group[MAX_GROUPS];
		selection = JCSystem.makeTransientObjectArray((short) 2, JCSystem.CLEAR_ON_RESET);
	}
	
	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		byte cla = buffer[ISO7816.OFFSET_CLA];
		byte ins = buffer[ISO7816.OFFSET_INS];
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];
		short lc, i, offset;
		Group selectedGroup = (Group) selection[GROUP_INDEX];
		Entry selectedEntry = (Entry) selection[ENTRY_INDEX];
		
		if (selectingApplet()) {
			return;
		}
		
		if (cla == CLA_SECURED) {
			if (!isInitialized && ins != INS_CHANGE_PIN)
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			
			if (isInitialized && !pin.isValidated())
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			
			switch (ins) {
				case INS_GET_DATA:
				case INS_SET_DATA:
					if (selectedEntry == null)
						ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					if (p1 < 0 || p1 >= selectedEntry.getNbData() || p2 != 0)
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				case INS_GET_STATS:
				case INS_ADD_ENTRY:
				case INS_DELETE_ENTRY:
				case INS_LIST_ENTRIES:
				case INS_SELECT_ENTRY:
					if (selectedGroup == null)
						ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
		}
		
		switch (cla) {
			case ISO7816.CLA_ISO7816:
				switch (ins) {
					case INS_AUTHENTICATE:
						lc = apdu.setIncomingAndReceive();
						if (pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) lc))
							return;
						ISOException.throwIt((short) (0x63C0 + pin.getTriesRemaining()));
						return;
					default:
						ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				}
				return;
			case CLA_SECURED:
				switch (ins) {
					case INS_CHANGE_PIN:
						lc = apdu.setIncomingAndReceive();
						if (p1 != 0 || p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						((OwnerPIN) pin).update(buffer, ISO7816.OFFSET_CDATA, (byte) lc);
						isInitialized = true;
						return;
					case INS_AVAILABLE:
						Util.setShort(buffer, ZERO, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
						apdu.setOutgoingAndSend(ZERO, (short) 2);
						return;
					case INS_GET_VERSION:
						Util.arrayCopyNonAtomic(version, ZERO, buffer, ZERO, (short) version.length);
						apdu.setOutgoingAndSend(ZERO, (short) version.length);
						return;
						
					case INS_CREATE_GROUP:
						lc = apdu.setIncomingAndReceive();
						if (p1 <= 0 || p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						for (i = 0; i < groups.length && groups[i] != null; i++);
						if (i >= groups.length)
							ISOException.throwIt(ISO7816.SW_FILE_FULL);
						selection[GROUP_INDEX] = groups[i] = new Group(p1);
						groups[i].setIdentifier(buffer, ISO7816.OFFSET_CDATA, lc);
						return;
					case INS_DELETE_GROUP:
						lc = apdu.setIncomingAndReceive();
						if (p1 != 0 || p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						for (i = 0; i < groups.length && groups[i] != null; i++) {
							if (groups[i].isEqual(buffer, ISO7816.OFFSET_CDATA, lc)) {
								groups[i].clear();
								groups[i] = null;
								JCSystem.requestObjectDeletion();
								return;
							}
						}
						ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
					case INS_LIST_GROUPS:
						if (p1 >= groups.length || p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						offset = (short) 0;
						for (i = p1; i < groups.length && offset < 200; i++) {
							if (groups[i] != null) {
								lc = buffer[offset] = groups[i].getIdentifier(buffer, ++offset);
								offset += lc;
							}
						}
						apdu.setOutgoingAndSend(ZERO, offset);
						if (i == groups.length)
							return;
						else
							ISOException.throwIt(SW_DATA_REMAINING);
					case INS_SELECT_GROUP:
						lc = apdu.setIncomingAndReceive();
						if (p1 != 0 || p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						for (i = 0; i < groups.length; i++) {
							if (groups[i] != null && groups[i].isEqual(buffer, ISO7816.OFFSET_CDATA, lc)) {
								selection[GROUP_INDEX] = groups[i];
								return;
							}
						}
						ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
						return;
					case INS_GET_STATS:
						selectedGroup.getStats(apdu, buffer);
						return;
						
					case INS_ADD_ENTRY:
						lc = apdu.setIncomingAndReceive();
						if (p1 < 0 || p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						selection[ENTRY_INDEX] = selectedEntry = selectedGroup.addEmptyEntry(p1);
						selectedEntry.setIdentifier(buffer, ISO7816.OFFSET_CDATA, lc);
						return;
					case INS_DELETE_ENTRY:
						lc = apdu.setIncomingAndReceive();
						if (p1 != 0 || p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						selectedGroup.deleteEntry(buffer, ISO7816.OFFSET_CDATA, lc);
						return;
					case INS_LIST_ENTRIES:
						if (p1 >= selectedGroup.getEntries().length || p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						selectedGroup.listEntries(apdu, buffer);
						return;
					case INS_SELECT_ENTRY:
						lc = apdu.setIncomingAndReceive();
						if (p1 != 0 || p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						Entry[] entries = selectedGroup.getEntries();
						for (i = 0; i < entries.length; i++) {
							if (entries[i] != null && entries[i].isEqual(buffer, ISO7816.OFFSET_CDATA, lc)) {
								selection[ENTRY_INDEX] = entries[i];
								return;
							}
						}
						ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
						return;
					case INS_GET_DATA:
						lc = apdu.setIncomingAndReceive();
						apdu.setOutgoingAndSend(ZERO, selectedEntry.getData(p1, buffer, ZERO));
						return;
					case INS_SET_DATA:
						lc = apdu.setIncomingAndReceive();
						selectedEntry.setData(p1, buffer, ISO7816.OFFSET_CDATA, lc);
						return;
						
					case INS_INIT_CRYPTO:
						if (p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						intCipher.init(intKey, p1);
						return;
					case INS_DO_CRYPTO:
						lc = apdu.setIncomingAndReceive();
						if (p1 != 0 || p2 != 0)
							ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						lc = intCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, lc, workingArray, ZERO);
						apdu.setOutgoingAndSend(ZERO, lc);
					default:
						ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				}
				return;
			default:
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
	}
}
