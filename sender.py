# this code sends "hello world" to the receiver when we press any key
# until we press 'q' to quit
# rs 232 port is /dev/pst/3

import serial
import time

# open the serial port
# start bit, 8 data bits, 1 start bit, 1 parity bit, 2 stop bits

ser = serial.Serial(
    "/dev/pts/2",
    baudrate=9600,
    bytesize=serial.EIGHTBITS,
    parity=serial.PARITY_NONE,
    stopbits=serial.STOPBITS_ONE,
)

# main
# while True:
#     # read a byte
#     data = input("Enter a character: ")
#     # print the byte
#     ser.write(data.encode("charmap"))
#     if data == "q":
#         break

i = 0
while i < 1:
    i += 1
    # read a byte
    data = [0xBC, 0x12, 0x0A, 0x33, 0x03, 0xE1, 0x00, 0x81, 0x0B, 0xCC]
    data = [chr(i) for i in data]
    data = "".join(data)
    # print the byte
    ser.write(data.encode("charmap"))
    time.sleep(0.1)
