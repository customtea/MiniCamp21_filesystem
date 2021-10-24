"""
https://free.pjc.co.jp/fat/mem/fatm32.html
"""

from enum import IntFlag
import datetime
import sys

class EntryAttr(IntFlag):
    READ_ONLY = 0x01
    HIDDEN = 0x02
    SYSTEM = 0x04
    VOLUME_ID = 0x08
    DIRECTORY = 0x10
    ARCHIVE = 0x20
    LONG_FILE_NAME = 0x0F
    
    def __str__(self) -> str:
        return f"{self.name}"

class State(IntFlag):
    END_TABLE = 0x00
    DELETE = 0xE5
    DELETE_ALT = 0x05
    USE = 0x33
    LAST_LONG_ENTRY = 0x40
    def __str__(self) -> str:
        return f"{self.name}"

class WindowsNTReserve(IntFlag):
    FILENAME_LITTLE = 0x08
    FILEEXTENTION_LITTLE = 0x10


class Entry:
    def __init__(self, datum32B: str) -> None:
        self.entry_state: State
        self.filename = ""
        self.file_extention = ""
        self.attr: EntryAttr
        self.WindowsNT_Reserve = 0 #only 00
        self.create_time_mill = 0 #max C7(199)
        self.create_time: datetime.time = datetime.time(0,0,0)
        self.create_day: datetime.date = datetime.date(1980,1,1)
        self.latest_access_date: datetime.date = datetime.date(1980,1,1)
        self.cluster_high = 0
        self.write_time: datetime.time = datetime.time(0,0,0)
        self.write_day: datetime.date = datetime.date(1980,1,1)
        self.cluster_low = 0
        self.file_size = 0
        
        self.lfn_statr: State
        self.lfn_order = 0
        self.lfn_name1 = ""
        self.lfn_attr: EntryAttr
        self.lfn_type = 0 #only 00
        self.lfn_checksum = 0
        self.lfn_name2 = ""
        self.lfn_cluster_low = 0 #compatibility
        self.lfn_name3 = ""

        dat = datum32B.replace(" ","")
        barray: bytearray
        for i in range(0,64,2):
            #print(dat[i:i+2])
            barray.append(int(dat[i:i+2],16))
        #print(barray)
        self.file_entry_parse(barray)
    
    def file_entry_parse(self, barray: bytearray):
        head = barray[0]
        if head in [0x00, 0xE5, 0x05]:
            self.entry_state = State(head)
            self.filename = " "
        else:
            self.entry_state = State.USE
            self.filename = chr(head)
        for i in range(1,8):
            c = barray[i]
            if c == 0x00:
                self.filename += " "
            else:
                self.filename +=  chr(c)
        for i in range(8,11):
            c = barray[i]
            if c == 0x00:
                self.file_extention += " "
            else:
                self.file_extention += chr(c)
        self.attr = EntryAttr(barray[11])
        if self.attr == EntryAttr.LONG_FILE_NAME:
            self.lfn_entry_parse(barray)
            return
        self.WindowsNT_Reserve = barray[12]
        self.create_time_mill = barray[13]
        # little endian
        t_hex  = barray[15] << 8
        t_hex += barray[14]
        self.create_time = datetime.time((t_hex & 0xf800) >> 11, (t_hex & 0x07e0) >> 5, (t_hex & 0x001f)*2 ,self.create_time_mill)
        # little endian
        t_hex  = barray[17] << 8
        t_hex += barray[16]
        self.create_day = datetime.date(1980+((t_hex & 0xfe00) >> 9), (t_hex & 0x01e0) >> 5, (t_hex & 0x001f))
        # little endian
        t_hex  = barray[19] << 8
        t_hex += barray[18]
        self.latest_access_date = datetime.date(1980+((t_hex & 0xfe00) >> 9), (t_hex & 0x01e0) >> 5, (t_hex & 0x001f))
        # little endian
        t_hex  = barray[21] << 8
        t_hex += barray[20]

        self.cluster_high = t_hex
        # little endian
        t_hex  = barray[23] << 8
        t_hex += barray[22]
        self.write_time = datetime.time((t_hex & 0xf800) >> 11, (t_hex & 0x07e0) >> 5, (t_hex & 0x001f)*2)
        # little endian
        t_hex  = barray[25] << 8
        t_hex += barray[24]
        #print(format(t_hex,'X'))
        self.write_day = datetime.date(1980+((t_hex & 0xfe00) >> 9), (t_hex & 0x01e0) >> 5, (t_hex & 0x001f))
        # little endian
        t_hex  = barray[27] << 8
        t_hex += barray[26]
        self.cluster_low = t_hex
        # little endian
        t_hex  = barray[31] << 24
        t_hex  = barray[30] << 16
        t_hex += barray[29] << 8
        t_hex += barray[28]
        if t_hex == 0xFFFFFFFF:
            self.file_size = 0
        else:
            self.file_size = t_hex
    
    def lfn_entry_parse(self, barray: bytearray):
        head = barray[0]
        if head in [0x00, 0xE5, 0x05]:
            self.lfn_statr = State(head)
            self.lfn_order = 0
        else:
            if head & 0x40 == 0x40:
                self.entry_state = State.LAST_LONG_ENTRY
                self.lfn_order = head & 0b00111111
            else:
                self.lfn_order = head & 0b00111111
            

        for i in range(1,10,2):
            c = bytearray([barray[i], barray[i+1]])
            if c == 0x0000:
                self.lfn_name1 += " "
            else:
                self.lfn_name1 += c.decode('utf-16-le')
        self.lfn_attr = EntryAttr(barray[11])
        self.lfn_type = barray[12]
        self.lfn_checksum = barray[13]
        for i in range(14,26,2):
            c = bytearray([barray[i], barray[i+1]])
            if c == 0x0000:
                self.lfn_name2 += " "
            else:
                self.lfn_name2 += c.decode('utf-16-le')

        t_hex  = barray[27] << 8
        t_hex += barray[26]
        self.lfn_cluster_low = t_hex

        for i in range(28,32,2):
            c = bytearray([barray[i], barray[i+1]])
            if c == 0x0000:
                self.lfn_name3 += " "
            else:
                self.lfn_name3 += c.decode('utf-16-le')
            

    def print_file_entry(self) -> None:
        print(f"[{self.entry_state}]".ljust(18), end="")
        print(f"|{self.filename}".ljust(9),end="")
        print(f"{self.file_extention}|".ljust(5),end="")
        print(f"[{self.attr}]".ljust(16), end="")
        print(f"Size:{self.file_size}B ".ljust(16), end="")
        print(f"Create:{self.create_day}T{self.create_time} ", end="")
        print(f"Write:{self.write_day}T{self.write_time} ", end="")
        print(f"Access:{self.latest_access_date} ", end="")
        print("Cluster:0x{}{}".format(format(self.cluster_high,'04X'),format(self.cluster_low, '04X')))
    
    def print_lfn_entry(self) -> None:
        print(f"[{self.entry_state}]".ljust(18), end="")
        print(f"|{self.lfn_order}|", end="")
        print(f"{self.lfn_name1}".ljust(5),end="")
        print(f"{self.lfn_name2}".ljust(6),end="")
        print(f"{self.lfn_name3}".ljust(5),end="")
        print(f"| {self.lfn_checksum}")

    def print_entry(self) -> None:
        if self.attr == EntryAttr.LONG_FILE_NAME:
            self.print_lfn_entry()
        else:
            self.print_file_entry()

    def __str__(self) -> str:
        return f"[{self.entry_state}] {self.filename}.{self.file_extention} [{self.attr}] Size:{self.file_size} Create:{self.create_day}T{self.create_time} Write:{self.write_day}T{self.write_time} Access:{self.latest_access_date} " + "Cluster:0x{}{}".format(format(self.cluster_high,'04X'),format(self.cluster_low, '04X'))


def main(d) -> None:
    #d = "46 41 54 33 32 44 41 54 54 58 54 20 00 5F 8D 63 AA 38 AA 38 01 00 68 63 AA 38 02 00 00 12 00 00"
    a = Entry(d)
    print(a)

def main_set() -> None:
    entries = [
    "4170 0069 006e 0065 002e 000f 00ad 7400 7800 7400 0000 ffff ffff 0000 ffff ffff",
    "5049 4e45 2020 2020 5458 5420 001d 72a0 1053 1053 0000 72a0 1053 0500 0900 0000",
    "4177 006f 0072 0064 002e 000f 00f2 7400 7800 7400 0000 ffff ffff 0000 ffff ffff",
    "574f 5244 2020 2020 5458 5420 0097 25a0 1053 1053 0000 25a0 1053 0600 0900 0000",
    "e573 0065 0063 002e 0074 000f 0077 7800 7400 0000 ffff ffff ffff 0000 ffff ffff",
    "e545 4320 2020 2020 5458 5420 002d 28a0 1053 1053 0000 28a0 1053 0700 0500 0000"

    ]


if __name__ == '__main__':
    #if len(sys.argv) == 2:
    #    l = sys.argv[1]
    #else:
    #    l = input("32Bytes ")
    #main(l)
    main_set()