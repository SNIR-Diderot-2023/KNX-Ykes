import threading
from KnxFrameAnalyzer import KnxFrameAnalyzer, KnxFrame
import serial
from typing import List


# listener class
class Listener:
    def __init__(self, port: str = "", analyzer: List[KnxFrameAnalyzer] = None):
        """
        :param port: the port to listen to
        by default it's empty
        :param analyzer: the analyzer to use as a list
        by default it's None and it will self manage the analyzer
        :return: None
        """
        # port
        self.port: str = port

        # workaround for KnxFrameAnalyzer
        # pass it by reference to _Listener
        # verify if the index 0 is a KnxFrameAnalyzer
        if analyzer is not None:
            self.analyzer = analyzer
        else:
            self.analyzer = [KnxFrameAnalyzer()]

        # the process
        self.t = None

        # kill the process
        self.alive = True

        # serial port
        self.ser = None

    def _Listener(self):
        """
        Not supposed to be called by the user
        """
        while self.alive == True:
            # read a byte
            data = self.ser.read()
            if data:
                # pass the byte to the analyzer
                self.analyzer[0].addData(data)
                self.analyzer[0].analyze()

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

    # get analyzerData
    def getData(self) -> KnxFrame | None:
        return self.analyzer[0].getData()

    # size of the analyzerData
    def size(self) -> int:
        return self.analyzer[0].size()
