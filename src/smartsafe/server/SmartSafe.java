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

public class SmartSafe extends Applet implements Constants {
	private static final byte[] version = {'1', '.', '0', '.', '1'};
	private byte[] workingArray;
	private SCP03 scp;
	private OwnerPIN pin;
	private Key intKey;
	//private Cipher intCipher;
	
	private Group[] groups;
	private Object[] selection;
	
	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new SmartSafe().register();
	}
	
	public SmartSafe() {
		workingArray = JCSystem.makeTransientByteArray(KeyBuilder.LENGTH_AES_128, JCSystem.CLEAR_ON_DESELECT);
		scp = new SCP03();
		RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(workingArray, ZERO, KeyBuilder.LENGTH_AES_128);
		intKey = KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, true);
		((AESKey) intKey).setKey(workingArray, ZERO);
		//intCipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M1, false);
		
		groups = new Group[MAX_GROUPS];
		selection = JCSystem.makeTransientObjectArray((short) 2, JCSystem.CLEAR_ON_RESET);
	}
	
	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		byte cla = buffer[ISO7816.OFFSET_CLA];
		byte ins = buffer[ISO7816.OFFSET_INS];
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];
		short lc = 0, i, offset;
		Group selectedGroup = (Group) selection[GROUP_INDEX];
		Entry selectedEntry = (Entry) selection[ENTRY_INDEX];
		
		if (selectingApplet()) {
			if (pin != null) {
				if (pin.getTriesRemaining() != 0)
					Util.setShort(buffer, ZERO, (short) 0xCAFE);
				else
					Util.setShort(buffer, ZERO, (short) 0xDEAD);
			}
			else {
				Util.setShort(buffer, ZERO, (short) 0xDECA);
			}
			apdu.setOutgoingAndSend(ZERO, (short) 2);
			return;
		}
		
		if (cla == ISO7816.CLA_ISO7816) {
			switch (ins) {
				case INS_GET_VERSION:
					Util.arrayCopyNonAtomic(version, ZERO, buffer, ZERO, (short) version.length);
					apdu.setOutgoingAndSend(ZERO, (short) version.length);
					return;
				default:
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}
		
		if (pin != null) {
			switch (Util.getShort(buffer, ZERO)) {
				case CLA_INS_INIT_UPDATE:
					scp.initUpdate(apdu);
					return;
				case CLA_INS_EXT_AUTH:
					try {
						scp.externalAuth(apdu);
					} catch (ISOException e) {
						pin.check(buffer, ZERO, (byte) 1);
						ISOException.throwIt((short) (0x63C0 + pin.getTriesRemaining()));
					}
					return;
				default:
					lc = scp.unwrap(apdu);
			}
		}
		
		if (cla == CLA_SECURED) {
			if (pin == null && ins != INS_CHANGE_PIN)
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			
			if (pin != null && !pin.isValidated() && ins != INS_AUTHENTICATE)
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
			
			switch (ins) {
				case INS_AUTHENTICATE:
					if (pin == null)
						ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
					if (pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) lc))
						scp.wrap(apdu);
					ISOException.throwIt((short) (0x63C0 + pin.getTriesRemaining()));
					return;
				case INS_CHANGE_PIN:
					if (!scp.isAuthenticated())
						lc = apdu.setIncomingAndReceive();
					if (p1 != 0 || p2 != 0)
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					scp.setKeys(buffer, ISO7816.OFFSET_CDATA);
					pin = new OwnerPIN(buffer[PIN_TRY_LIMIT_OFFSET], buffer[PIN_SIZE_OFFSET]);
					pin.update(buffer, PIN_VALUE_OFFSET, (byte) (5 + lc - PIN_VALUE_OFFSET));
					if (scp.isAuthenticated())
						scp.wrap(apdu);
					return;
				case INS_AVAILABLE:
					Util.setShort(buffer, ZERO, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
					scp.wrap(apdu, (short) 2);
					return;
					
				case INS_CREATE_GROUP:
					if (p1 <= 0 || p2 != 0)
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					for (i = 0; i < groups.length && groups[i] != null; i++);
					if (i >= groups.length)
						ISOException.throwIt(ISO7816.SW_FILE_FULL);
					selection[GROUP_INDEX] = groups[i] = new Group(p1);
					groups[i].setIdentifier(buffer, ISO7816.OFFSET_CDATA, lc);
					scp.wrap(apdu);
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
							scp.wrap(apdu);
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
					scp.wrap(apdu, offset, i == groups.length ? ISO7816.SW_NO_ERROR : SW_DATA_REMAINING);
					return;
				case INS_SELECT_GROUP:
					if (p1 != 0 || p2 != 0)
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					for (i = 0; i < groups.length; i++) {
						if (groups[i] != null && groups[i].isEqual(buffer, ISO7816.OFFSET_CDATA, lc)) {
							selection[GROUP_INDEX] = groups[i];
							scp.wrap(apdu);
							return;
						}
					}
					ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
					return;
				case INS_GET_STATS:
					selectedGroup.getStats(scp, apdu, buffer);
					return;
					
				case INS_ADD_ENTRY:
					if (p1 < 0 || p2 != 0)
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					selection[ENTRY_INDEX] = selectedEntry = selectedGroup.addEmptyEntry(p1);
					selectedEntry.setIdentifier(buffer, ISO7816.OFFSET_CDATA, lc);
					scp.wrap(apdu);
					return;
				case INS_DELETE_ENTRY:
					lc = apdu.setIncomingAndReceive();
					if (p1 != 0 || p2 != 0)
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					selectedGroup.deleteEntry(buffer, ISO7816.OFFSET_CDATA, lc);
					scp.wrap(apdu);
					return;
				case INS_LIST_ENTRIES:
					if (p1 >= selectedGroup.getEntries().length || p2 != 0)
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					selectedGroup.listEntries(scp, apdu, buffer);
					return;
				case INS_SELECT_ENTRY:
					if (p1 != 0 || p2 != 0)
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					Entry[] entries = selectedGroup.getEntries();
					for (i = 0; i < entries.length; i++) {
						if (entries[i] != null && entries[i].isEqual(buffer, ISO7816.OFFSET_CDATA, lc)) {
							selection[ENTRY_INDEX] = entries[i];
							scp.wrap(apdu);
							return;
						}
					}
					ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
					return;
				case INS_GET_DATA:
					scp.wrap(apdu, selectedEntry.getData(p1, buffer, ZERO));
					return;
				case INS_SET_DATA:
					selectedEntry.setData(p1, buffer, ISO7816.OFFSET_CDATA, lc);
					scp.wrap(apdu);
					return;
					
				/*case INS_INIT_CRYPTO:
					if (p2 != 0)
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					intCipher.init(intKey, p1);
					return;
				case INS_DO_CRYPTO:
					lc = apdu.setIncomingAndReceive();
					if (p1 != 0 || p2 != 0)
						ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					lc = intCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, lc, workingArray, ZERO);
					apdu.setOutgoingAndSend(ZERO, lc);*/
				default:
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}
		ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	}
}
