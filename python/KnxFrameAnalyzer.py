from typing import List
from bitstring import BitArray
from textwrap import wrap

# rewrite the KnxFrameAnalyzer


# functions
def binToInt(bin: str, inString: bool = False) -> bool | List[int] | List[str] | None:
    """
    will convert a binary string to a list of integer
    parameters:
        bin: the binary string
        inString: if True the function will return a list of strings
    returns:
        bool: False if encountered an error
        List[int]: if inString is False
        List[str]: if inString is True
        None: if the string is empty
    """

    # check if the string is empty
    if len(bin) == 0:
        return None

    arr = []
    q = len(bin) // 8
    r = len(bin) % 8

    for i in range(q):
        if inString:
            arr.append(str(int(bin[i * 8 : (i + 1) * 8], 2)))
        else:
            arr.append(int(bin[i * 8 : (i + 1) * 8], 2))

    if r:
        if inString:
            arr.append(str(int(bin[q * 8 :], 2)))
        else:
            arr.append(int(bin[q * 8 :], 2))

    return arr


def binToHex(bin: str, valueOnly: bool = False) -> bool | List[str] | None:
    """
    will convert a binary string to a list of hexadecimal string
    parameters:
        bin: the binary string
        valueOnly: if True the function will ingnore the 0x prefix
        clumpse: if True the function will clumpse the bytes
    returns:
        bool: False if encountered an error
        List[str]: if valueOnly is False
        None: if the string is empty
    """

    # check if the string is empty
    if len(bin) == 0:
        return None

    arr = []
    q = len(bin) // 8
    r = len(bin) % 8

    for i in range(q):
        if valueOnly:
            arr.append(hex(int(bin[i * 8 : (i + 1) * 8], 2))[2:])
        else:
            arr.append(hex(int(bin[i * 8 : (i + 1) * 8], 2)))

    if r:
        if valueOnly:
            arr.append(hex(int(bin[q * 8 :], 2))[2:])
        else:
            arr.append(hex(int(bin[q * 8 :], 2)))

    return arr


def binToBytes(bin: str) -> bool | List[bytes] | None:
    """
    will convert a binary string to a byte
    parameters:
        bin: the binary string
    returns:
        bool: False if encountered an error
        List[bytes]: the bytes
        None: if the string is empty
    """

    # check if the string is empty
    if len(bin) == 0:
        return None

    arr = []
    q = len(bin) // 8
    r = len(bin) % 8

    for i in range(q):
        arr.append(int(bin[i * 8 : (i + 1) * 8], 2).to_bytes(1, "big"))

    if r:
        arr.append(int(bin[q * 8 :], 2).to_bytes(1, "big"))

    return arr


# holds the address
class KnxAddress:
    area: str
    line: str
    device: str

    def __init__(self, area="", line="", device=""):
        self.area = area
        self.line = line
        self.device = device


# class to hold the frame data
class KnxFrame:
    emission: str
    priority: str
    senderAddr: KnxAddress
    recvAddr: KnxAddress
    addrType: str
    hopCount: str
    length: str
    data: List[str]
    checksum: str
    terminator: str

    def __init__(self):
        self.emission = ""
        self.priority = ""
        self.senderAddr = KnxAddress()
        self.recvAddr = KnxAddress()
        self.addrType = ""
        self.hopCount = ""
        self.length = ""
        self.data = []
        self.checksum = ""
        self.terminator = ""

    def getRefactorFrame(
        self, separator: str = "", asList: bool = False
    ) -> bool | str | List[str]:
        """
        will refactor the frame to a string in binary
        parameters:
            separator: the separator between the bytes
            asList: if True the function will return a list of strings
        returns:
            bool: False if encountered an error
            str: the frame in binary
            List[str]: if asList is True
        """
        data = "10" + self.emission + "1" + self.priority + "00" + separator
        data += self.senderAddr.area + self.senderAddr.line + separator
        data += self.senderAddr.device + separator
        data += self.recvAddr.area + self.recvAddr.line + separator
        data += self.recvAddr.device + separator
        data += self.addrType + self.hopCount + self.length + separator
        for i in self.data:
            data += i + separator
        data += self.checksum + separator
        data += self.terminator

        if asList:
            return wrap(data, 8 + len(separator))
        else:
            return data

    # debug
    def debug(self, separator: str = "\n") -> str:
        """
        will return the frame data in a string
        parameters:
            separator: the separator between the bytes
        returns:
            str: the frame data
        """
        data = "emission: " + self.emission + separator
        data += "priority: " + self.priority + separator
        data += (
            "senderAddr: \n"
            + "\t"
            + "area: "
            + self.senderAddr.area
            + "\n"
            + "\t"
            + "line: "
            + self.senderAddr.line
            + "\n"
            + "\t"
            + "device: "
            + self.senderAddr.device
            + "\n"
        )
        data += (
            "recvAddr: \n"
            + "\t"
            + "area: "
            + self.recvAddr.area
            + "\n"
            + "\t"
            + "line: "
            + self.recvAddr.line
            + "\n"
            + "\t"
            + "device: "
            + self.recvAddr.device
            + "\n"
        )
        data += "addrType: " + self.addrType + separator
        data += "hopCount: " + self.hopCount + separator
        data += "length: " + self.length + separator
        data += "data: "
        for i in self.data:
            data += i
        data += separator
        data += "checksum: " + self.checksum + separator
        data += "terminator: " + self.terminator + separator

        return data


# phases of the frame analysis
# "Control Byte",
# "Sender's Area and Line",
# "Sender's Device",
# "Receiver's Area and Line",
# "Receiver's Device",
# "group address, Hop Count, length",
# "Data",
# "Checksum",
# "ACK"


# A class to analyze a KNX frame
class KnxFrameAnalyzer:
    # constructor
    def __init__(
        self,
        frame: str | bytes | int | List[str | bytes | int] | bytearray = None,
        base: str = "bytes",
    ):
        # holds the frame as a list of bits
        self.__frame: List[str] = []

        # the frame that's being analyzed
        self.__data: KnxFrame = KnxFrame()

        # holds a list of all analyzed frames
        self.__archive: list[KnxFrame] = []

        # holds the current phase of the analysis
        self.__phase: int = 0

        # holds weather or not the frame is synced
        self.__synced: bool = False

        # add the frame to the analyzer
        if frame == None:
            return

        if (type(frame) == list) | (type(frame) == bytearray):
            self.addDataList(frame, base)
        else:
            self.addData(frame, base)

    # add data to the frame
    # handles a byte at a time
    def addData(self, data: str | bytes | int, base: str = "bytes") -> bool:
        """
        parameters:
            data: string of data to be added to the frame
                it can be in bytes or string format
            base: the base of the data
                it can be "bytes", "hex", "int" or "bin"
            returns: bool
        """
        # convert the data to binary
        # we use the Bitarray library
        if base == "bytes":
            self.__frame.append(BitArray(bytes=data, length=8).bin)
        elif base == "hex":
            self.__frame.append(BitArray(hex=data, length=8).bin)
        elif base == "int":
            self.__frame.append(BitArray(uint=data, length=8).bin)
        elif base == "bin":
            self.__frame.append(data)
        else:
            return False
        return True

    # handles multiple bytes at a time
    def addDataList(
        self, data: List[str | bytes | int] | bytearray, base: str = "bytes"
    ) -> bool:
        """
        parameters:
            data: list of data to be added to the frame
                it can be in bytes or string format
            base: the base of the data
                it can be "bytes", "hex", "int" or "bin"
            returns: False if the base is not valid
        """

        # convert the data to binary
        # we use the Bitarray library
        if base == "bytes":
            for i in data:
                self.__frame.append(BitArray(bytes=i, length=8).bin)
        elif base == "hex":
            for i in data:
                self.__frame.append(BitArray(hex=i, length=8).bin)
        elif base == "int":
            for i in data:
                self.__frame.append(BitArray(uint=i, length=8).bin)
        elif base == "bin":
            for i in data:
                self.__frame.append(i)
        else:
            return False
        return True

    # check if the frame is synced
    def isSynced(self) -> bool:
        if self.__synced:
            return True

        # check if the frame is synced
        # we are dealing with non extended standard frames
        # the first 2 bits must be 10
        # the 4th bit must be 1
        # 7-8th bits must be 00
        if (
            self.__frame[0][0:2] == "10"
            and self.__frame[0][3] == "1"
            and self.__frame[0][6:8] == "00"
        ):
            self.__synced = True
            return True
        return False

    # Bytes analysis functions start here
    # analyze the control byte
    def __analyzeControlByte(self):
        # analyze the control byte
        self.__data.emission = self.__frame[0][2]
        self.__data.priority = self.__frame[0][4:6]
        self.__frame.pop(0)

        self.__phase = 1
        if len(self.__frame):
            self.__analyzeSenderAreaAndLine()

    # analyze the sender's area and line
    def __analyzeSenderAreaAndLine(self):
        # analyze the sender's area and line
        self.__data.senderAddr.area = self.__frame[0][0:4]
        self.__data.senderAddr.line = self.__frame[0][4:8]
        self.__frame.pop(0)

        self.__phase = 2
        if len(self.__frame):
            self.__analyzeSenderDevice()

    # analyze the sender's device
    def __analyzeSenderDevice(self):
        # analyze the sender's device
        self.__data.senderAddr.device = self.__frame[0]
        self.__frame.pop(0)

        self.__phase = 3
        if len(self.__frame):
            self.__analyzeReceiverAreaAndLine()

    # analyze the receiver's area and line
    def __analyzeReceiverAreaAndLine(self):
        # analyze the receiver's area and line
        self.__data.recvAddr.area = self.__frame[0][0:4]
        self.__data.recvAddr.line = self.__frame[0][4:8]
        self.__frame.pop(0)

        self.__phase = 4
        if len(self.__frame):
            self.__analyzeReceiverDevice()

    # analyze the receiver's device
    def __analyzeReceiverDevice(self):
        # analyze the receiver's device
        self.__data.recvAddr.device = self.__frame[0]
        self.__frame.pop(0)

        self.__phase = 5
        if len(self.__frame):
            self.__analyzeGroupAddressHopCountLength()

    # analyze the group address, hop count and length
    def __analyzeGroupAddressHopCountLength(self):
        # analyze the group address, hop count and length
        self.__data.addrType = self.__frame[0][0]
        self.__data.hopCount = self.__frame[0][1:4]
        self.__data.length = self.__frame[0][4:8]
        self.__frame.pop(0)

        self.__phase = 6
        if len(self.__frame):
            self.__analyzeData()

    # analyze the data
    def __analyzeData(self):
        # fortunate that i prooffreaded the code
        # you don't even know how to cut strings properly
        length = binToInt(self.__data.length)[0] + 1
        remainingLen = length - len(self.__data.data)
        frameLen = len(self.__frame)

        # check length of __frame
        if remainingLen > frameLen:
            length = frameLen
        else:
            length = remainingLen
            self.__phase = 7

        # analyze the data
        for i in range(length):
            self.__data.data.append(self.__frame[0])
            self.__frame.pop(0)

        # the data is complete
        if len(self.__frame) and (self.__phase == 7):
            self.__analyzeChecksum()

    # analyze the checksum
    def __analyzeChecksum(self):
        # analyze the checksum
        self.__data.checksum = self.__frame[0]
        self.__frame.pop(0)

        self.__phase = 8
        if len(self.__frame):
            self.__analyzeTerminator()

    # analyze the terminator
    def __analyzeTerminator(self):
        # analyze the terminator
        self.__data.terminator = self.__frame[0]
        self.__frame.pop(0)

        self.__phase = 9
        self.__reset()

    # reset the current data and push data to the archive
    def __reset(self):
        self.__archive.append(self.__data)
        self.__data = KnxFrame()
        self.__phase = 0
        self.__synced = False

        # if there still is data in the frame
        # call the analyze function again
        if len(self.__frame):
            self.analyze()

    # end of Bytes analysis functions

    # analyze the frame
    def analyze(self) -> bool:
        """
        no parameters
        returns: True if the analysis ended successfully
            False if it encountered an error
        """

        # if empty frame
        if len(self.__frame) == 0:
            return False

        # if the frame is not synced
        if not self.isSynced():
            return False

        # analyze the frame
        if self.__phase == 0:
            self.__analyzeControlByte()
        elif self.__phase == 1:
            self.__analyzeSenderAreaAndLine()
        elif self.__phase == 2:
            self.__analyzeSenderDevice()
        elif self.__phase == 3:
            self.__analyzeReceiverAreaAndLine()
        elif self.__phase == 4:
            self.__analyzeReceiverDevice()
        elif self.__phase == 5:
            self.__analyzeGroupAddressHopCountLength()
        elif self.__phase == 6:
            self.__analyzeData()
        elif self.__phase == 7:
            self.__analyzeChecksum()
        elif self.__phase == 8:
            self.__analyzeTerminator()
        else:
            # means I fucked up
            print("Error: unknown phase")
            self.__reset()

        return True

    # getters
    def getData(self, index: int = 0, deleteData: bool = True) -> KnxFrame | None:
        """
        index: index of the data in the archive
        deleteData: if true, the data will be deleted from the archive
        returns: the data in the archive
            In case of error, it will return None
        """
        if index >= len(self.__archive):
            print("Error: index out of range")
            return None

        data = self.__archive[index]
        if deleteData:
            self.__archive.pop(index)
        return data

    def getCurrentData(self) -> KnxFrame:
        """
        returns: the current data
        """
        return self.__data

    def getCurrentFrame(self) -> List[str]:
        """
        returns: the data that has not been analyzed
        """
        return self.__frame

    def getArchive(self, deleteData: bool = True) -> List[KnxFrame]:
        """
        deleteData: if true, the archive will be deleted
        returns: the archive
        """
        archive = self.__archive
        if deleteData:
            self.__archive = []
        return archive

    def size(self) -> int:
        """
        returns: the size of the archive
        """
        return len(self.__archive)

    # reset the analyzer
    def reset(self):
        """
        no parameters
        returns: nothing

        It will reset the analyzer
        """
        self.__data = KnxFrame()
        self.__frame = []
        self.__phase = 0
        self.__archive = []
        self.__synced = False
