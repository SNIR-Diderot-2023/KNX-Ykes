import threading
import serial
from typing import List


# listener class
class Listener:
    def __init__(self, port: str = ""):
        """
        :param port: the port to listen to
        by default it's empty
        :param analyzer: the analyzer to use as a list
        by default it's None and it will self manage the analyzer
        :return: None
        """
        # port
        self.port: str = port

        # data
        self.data: List[bytes] = []

        # the process
        self.t = None

        # kill the process
        self.alive = True

        self.ser = None

    def _Listener(self) -> bool:
        """
        Not supposed to be called by the user
        """
        while self.alive == True:
            # read a byte
            _data = self.ser.read()
            if _data:
                self.data.append(_data)
        return True

    # start the listener
    def Start(self) -> bool:
        """
        returns False if the port is not set
        returns True if the listener is started
        """
        self.alive = True
        if self.port == "":
            return False

        # try to open the port
        try:
            self.ser = serial.Serial(
                port=self.port,
                baudrate=9600,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.1,
            )
        except:
            self.alive = False
            return False

        self.t = threading.Thread(target=self._Listener)
        self.t.start()
        return True

    # getter and setter for class variables
    def Stop(self):
        if self.t.is_alive():
            self.alive = False
            self.t.join()

    # get port
    def GetPort(self) -> str:
        return self.port

    # sets a port
    def SetPort(self, port: str):
        self.port = port

    # get data
    def getData(
        self, asList: bool = True, delData: bool = True
    ) -> List[bytes] | bytearray:
        data = self.data
        if delData:
            self.data = []

        if asList:
            return data
        else:
            return bytearray(data)

    # size of the data
    def size(self) -> int:
        return len(self.data)
