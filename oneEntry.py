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
    def __str__(self) -> str:
        return f"{self.name}"


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
    
        dat = datum32B.replace(" ","")
        head = int(dat[0:2], 16)
        if head in [0x00, 0xE5, 0x05]:
            self.entry_state = State(head)
            self.filename = " "
        else:
            self.entry_state = State.USE
            self.filename = chr(head)
        for i in range(2*1,2*8,2):
            c = int(dat[i:i+2],16)
            if c == 0x00:
                self.filename += " "
            else:
                self.filename +=  chr(c)
        for i in range(2*8,2*11,2):
            c = int(dat[i:i+2],16)
            if c == 0x00:
                self.file_extention += " "
            else:
                self.file_extention += chr(c)
        self.attr = EntryAttr(int(dat[2*11:2*12],16))
        self.WindowsNT_Reserve = int(dat[2*12:2*13],16)
        self.create_time_mill = int(dat[2*13:2*14],16) * 10 
        # little endian
        t_hex  = int(dat[2*15:2*16],16) << 8
        t_hex += int(dat[2*14:2*15],16)
        self.create_time = datetime.time((t_hex & 0xf800) >> 11, (t_hex & 0x07e0) >> 5, (t_hex & 0x001f)*2 ,self.create_time_mill)
        # little endian
        t_hex  = int(dat[2*17:2*18],16) << 8
        t_hex += int(dat[2*16:2*17],16)
        self.create_day = datetime.date(1980+((t_hex & 0xfe00) >> 9), (t_hex & 0x01e0) >> 5, (t_hex & 0x001f))
        # little endian
        t_hex  = int(dat[2*19:2*20],16) << 8
        t_hex += int(dat[2*18:2*19],16)
        try:
            self.latest_access_date = datetime.date(1980+((t_hex & 0xfe00) >> 9), (t_hex & 0x01e0) >> 5, (t_hex & 0x001f))
        except:
            pass
        # little endian
        t_hex  = int(dat[2*21:2*22],16) << 8
        t_hex += int(dat[2*20:2*21],16)
        self.cluster_high = t_hex
        # little endian
        t_hex  = int(dat[2*23:2*24],16) << 8
        t_hex += int(dat[2*22:2*23],16)
        try:
            self.write_time = datetime.time((t_hex & 0xf800) >> 11, (t_hex & 0x07e0) >> 5, (t_hex & 0x001f)*2)
        except:
            pass
        # little endian
        t_hex  = int(dat[2*25:2*26],16) << 8
        t_hex += int(dat[2*24:2*25],16)
        #print(format(t_hex,'X'))
        try:
            self.write_day = datetime.date(1980+((t_hex & 0xfe00) >> 9), (t_hex & 0x01e0) >> 5, (t_hex & 0x001f))
        except:
            pass
        # little endian
        t_hex  = int(dat[2*27:2*28],16) << 8
        t_hex += int(dat[2*26:2*27],16)
        self.cluster_low = t_hex
        # little endian
        t_hex  = int(dat[2*31:2*32],16) << 24
        t_hex += int(dat[2*30:2*31],16) << 16
        t_hex += int(dat[2*29:2*30],16) << 8
        t_hex += int(dat[2*28:2*29],16)
        if t_hex == 0xFFFFFFFF:
            self.file_size = 0
        else:
            self.file_size = t_hex
    
    def print_entry(self) -> None:
        print(f"[{self.entry_state}]".ljust(12), end="")
        print(f"|{self.filename}".ljust(9),end="")
        print(f"{self.file_extention}|".ljust(5),end="")
        print(f"[{self.attr}]".ljust(16), end="")
        print(f"Size:{self.file_size}B ".ljust(16), end="")
        print(f"Create:{self.create_day}T{self.create_time} ", end="")
        print(f"Write:{self.write_day}T{self.write_time} ", end="")
        print(f"Access:{self.latest_access_date} ", end="")
        print("Cluster:0x{}{}".format(format(self.cluster_high,'04X'),format(self.cluster_low, '04X')))

    def __str__(self) -> str:
        return f"[{self.entry_state}] {self.filename}.{self.file_extention} [{self.attr}] Size:{self.file_size} Create:{self.create_day}T{self.create_time} Write:{self.write_day}T{self.write_time} Access:{self.latest_access_date} " + "Cluster:0x{}{}".format(format(self.cluster_high,'04X'),format(self.cluster_low, '04X'))


def main(d) -> None:
    #d = "46 41 54 33 32 44 41 54 54 58 54 20 00 5F 8D 63 AA 38 AA 38 01 00 68 63 AA 38 02 00 00 12 00 00"
    a = Entry(d)
    print(a)

def main_set() -> None:
    d = "4170 0069 006e 0065 002e 000f 00ad 7400 7800 7400 0000 ffff ffff 0000 ffff ffff"
    a = Entry(d)
    a.print_entry()
    d = "5049 4e45 2020 2020 5458 5420 001d 72a0 1053 1053 0000 72a0 1053 0500 0900 0000"
    a = Entry(d)
    a.print_entry()
    d = "4177 006f 0072 0064 002e 000f 00f2 7400 7800 7400 0000 ffff ffff 0000 ffff ffff"
    a = Entry(d)
    a.print_entry()
    d = "574f 5244 2020 2020 5458 5420 0097 25a0 1053 1053 0000 25a0 1053 0600 0900 0000"
    a = Entry(d)
    a.print_entry()
    d = "e573 0065 0063 002e 0074 000f 0077 7800 7400 0000 ffff ffff ffff 0000 ffff ffff"
    a = Entry(d)
    a.print_entry()
    d = "e545 4320 2020 2020 5458 5420 002d 28a0 1053 1053 0000 28a0 1053 0700 0500 0000"
    a = Entry(d)
    a.print_entry()


if __name__ == '__main__':
    #if len(sys.argv) == 2:
    #    l = sys.argv[1]
    #else:
    #    l = input("32Bytes ")
    #main(l)
    main_set()