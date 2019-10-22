package smartsafe.server;

public interface Constants {
	byte PIN_TRY_LIMIT    = (byte) 0x0A;
	byte PIN_SIZE         = (byte) 0x10;
	byte MAX_GROUPS       = (byte) 0x40;

	byte CLA_SECURED      = (byte) 0x80;
	short SW_DATA_REMAINING = (short) 0x6310;
	
	byte INS_AUTHENTICATE = (byte) 0x01;
	byte INS_CHANGE_PIN   = (byte) 0x02;
	byte INS_AVAILABLE    = (byte) 0x03;
	byte INS_GET_VERSION  = (byte) 0x04;
	
	byte INS_CREATE_GROUP = (byte) 0x11;
	byte INS_DELETE_GROUP = (byte) 0x12;
	byte INS_LIST_GROUPS  = (byte) 0x13;
	byte INS_SELECT_GROUP = (byte) 0x14;
	byte INS_GET_STATS    = (byte) 0X15;
	
	byte INS_ADD_ENTRY    = (byte) 0x21;
	byte INS_DELETE_ENTRY = (byte) 0x22;
	byte INS_LIST_ENTRIES = (byte) 0x23;
	byte INS_SELECT_ENTRY = (byte) 0x24;
	byte INS_GET_DATA     = (byte) 0x25;
	byte INS_SET_DATA     = (byte) 0x26;
	
	byte INS_INIT_CRYPTO  = (byte) 0x31;
	byte INS_DO_CRYPTO    = (byte) 0x32;
	
	byte ZERO = (byte) 0x00;
	
	byte GROUP_INDEX = (byte) 0;
	byte ENTRY_INDEX = (byte) 1;
}
