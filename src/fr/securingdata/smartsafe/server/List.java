package fr.securingdata.smartsafe.server;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class List implements Constants {
	Identity first, last;
	
	public void clear() {
		Identity it = first, next;
		while (it != null) {
			next = it.next;//Backup next as it will be erased during it.clear()
			it.clear();
			it = next;
		}
		first = last = null;
	}
	
	public short size() {
		short size = 0;
		Identity it = first;
		while (it != null) {
			it = it.next;
			size++;
		}
		return size;
	}
	
	public void add(Identity i) {
		if (first == null)
			first = i;
		else
			last.next = i;
		last = i;
	}
	
	public Identity get(byte[] buffer, short offset, short len) {
		Identity it = first;
		while (it != null) {
			if (it.isEqual(buffer, offset, len))
				return it;
			it = it.next;
		}
		ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		return null;
	}
	
	public boolean move(Identity elem, byte direction) {
		//Step 1, discard forbidden cases
		if (direction != MOVE_UP && direction != MOVE_DOWN)
			return false;
		if (direction == MOVE_UP && elem == first)
			return false;
		if (direction == MOVE_DOWN && elem == last)
			return false;
		
		//Step 2, transform MOVE_DOWN in a MOVE_UP in order to have a generic processing
		if (direction == MOVE_DOWN)
			elem = elem.next;//Not null thanks to checks performed in step 1
		
		//Step 3, initialize cursors
		Identity prev1 = null, prev2 = null;
		if (elem != first) {
			prev1 = first;
			while (prev1.next != elem) {
				prev2 = prev1;
				prev1 = prev1.next;
			}
		}
		/* At this state:
		 * - prev1 references the ancestor of elem (cannot be null)
		 * - prev2 references the ancestor of prev1 (or null if prev1 has no ancestor)
		 * */
		
		//Step 4, moving !
		
		//Case 1, elem is in the second position
		if (prev2 == null) {
			prev1.next = elem.next;
			elem.next = prev1;
			first = elem;
			return true;
		}
		
		//Case 2, other cases
		prev2.next = elem;
		prev1.next = elem.next;
		elem.next = prev1;
		
		//Case 2.1, elem is in the last position
		if (elem == last)
			last = prev1;
		return true;
	}
	
	public void remove(Identity elem) {
		//Step 1, handle specific case of removing first element
		if (elem == first) {
			first = elem.next;
			elem.next = null;
			return;
		}
		
		//Step 2, initialize cursor
		Identity prev = first;
		while (prev.next != elem) {
			prev = prev.next;
		}
		/* At this state:
		 * - prev references the ancestor of elem (not null as elem cannot be the first element)
		 * */
		
		//Step 3, removing !
		prev.next = elem.next;
		elem.next = null;
		
		//Step 3.1, specific case of removing last element
		if (elem == last)
			last = prev;
	}
	
	public void delete(byte[] buffer, short offset, short len) {
		Identity it = first, prev = null;
		while (it != null) {
			if (it.isEqual(buffer, offset, len)) {
				//Updating fields: first and last
				if (prev == null)//Deleted Id is the first of the list
					first = it.next;
				if (it == last)//Deleted Id is the last of the list (may be a combination with previous check)
					last = prev;
				
				//Updating the link if applicable
				if (prev != null)
					prev.next = it.next;
				
				it.clear();//Cleaning all the data
				return;//Entry has been deleted, exiting.
			}
			prev = it;
			it = it.next;
		}
		ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
	}
	
	public short list(byte[] buffer, short fromEntryNumber) {
		short offset = ZERO;
		
		Identity it = first;
		while (it != null && offset < 200) {
			if (fromEntryNumber != 0)
				fromEntryNumber--;
			else {
				buffer[offset] = it.getIdentifier(buffer, (short) (offset + 1));
				offset += buffer[offset];
				offset += 1;
			}
			it = it.next;
		}
		
		Util.setShort(buffer, offset, it == null ? ISO7816.SW_NO_ERROR : SW_DATA_REMAINING);
		offset += 2;
		return offset;
	}
}
