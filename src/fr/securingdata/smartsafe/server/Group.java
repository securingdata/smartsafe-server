package fr.securingdata.smartsafe.server;

public class Group extends Identity {
	List entries;
	
	public Group(byte[] buffer, short offset, short len) {
		entries = new List();
		setIdentifier(buffer, offset, len);
	}
	
	public void clear() {
		super.clear();
		entries.clear();
	}
	public short getNbEntries() {
		return entries.size();
	}
	public Entry addEmptyEntry(byte nbData) {
		Entry entry = new Entry(nbData);
		entries.add(entry);
		return entry;
	}
	public Entry getEntry(byte[] buffer, short offset, short len) {
		return (Entry) entries.get(buffer, offset, len);
	}
	public void deleteEntry(byte[] buffer, short offset, short len) {
		entries.delete(buffer, offset, len);
	}
	public short listEntries(byte[] buffer, short fromEntryNumber) {
		return entries.list(buffer, fromEntryNumber);
	}
}
