package smartsafe.server;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Group extends Identity {
	private Entry[] entries;
	
	public Group(byte nbEntries) {
		entries = new Entry[nbEntries];
	}
	
	public void clear() {
		super.clear();
		for (byte i = 0; i < entries.length; i++) {
			if (entries[i] != null)
				entries[i].clear();
		}
	}
	
	public void getStats(APDU apdu, byte[] buffer) {
		short nbEntries = 0;
		for (byte i = 0; i < entries.length; i++) {
			if (entries[i] != null)
				nbEntries++;
		}
		Util.setShort(buffer, ZERO, nbEntries);
		Util.setShort(buffer, (short) 2, (short) entries.length);
		apdu.setOutgoingAndSend(ZERO, (short) 4);
	}
	public Entry[] getEntries() {
		return entries;
	}
	public Entry addEmptyEntry(byte nbData) {
		byte i;
		Entry entry = null;
		for (i = 0; i < entries.length && entries[i] != null; i++);
		if (i >= entries.length)
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		entry =  new Entry(nbData);
		entries[i] = entry;
		return entry;
	}
	public Entry getEntry(byte[] entry, short offset, short len) {
		byte i;
		for (i = 0; i < entries.length; i++) {
			if (entries[i] != null && entries[i].isEqual(entry, offset, len))
				return entries[i];
		}
		ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		return null;
	}
	public void deleteEntry(byte[] entry, short offset, short len) {
		byte i;
		for (i = 0; i < entries.length; i++) {
			if (entries[i] != null && entries[i].isEqual(entry, ISO7816.OFFSET_CDATA, len)) {
				entries[i].clear();
				entries[i] = null;
				JCSystem.requestObjectDeletion();
				return;
			}
		}
		ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
	}
	public void listEntries(SCP03 scp, APDU apdu, byte[] buffer) {
		byte i;
		short offset = ZERO;
		short len;
		for (i = buffer[ISO7816.OFFSET_P1]; i < entries.length && offset < 200; i++) {
			if (entries[i] != null) {
				len = buffer[offset] = entries[i].getIdentifier(buffer, ++offset);
				offset += len;
			}
		}
		scp.wrap(apdu, offset, i == entries.length ? ISO7816.SW_NO_ERROR : SW_DATA_REMAINING);
	}
}
