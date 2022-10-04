#!/usr/bin/env python
import ssl
import socket
import time
import os
import platform
import getpass
import re
import math


from datetime import datetime
from time import strftime

####################################################################
################# MCC Python Package ###############################
# This package is a front end that will allow end users to simply ##
# control the LNXNM with simple Python functions without the      ##
# hassle of learning Expect.                                      ##
######### Author ###################################################
# This script was written and maintained by Eduardo Borjas        ##
# 	eborjas@mrv.com			                          ##
######### Revision History #########################################
# 06/01/11      4.6+    Initial Version                           ##
# 09/29/11      4.6+    Second Round Of Updates                   ##
# 05/05/12	4.8+	Completed version			  ##
# 02/24/15	4.10	Updated for 4.10			  ##
######### Developer Notes ##########################################

class mcc:
    "MCC Class"
    ####################################################################
    ## Public Functions ################################################
    ####################################################################
    def __init__(self, ipaddr = "192.168.14.201", username = "admin", password = "admin"):                           
        # Important variables
        self.user = username         # Set to the supplied user name
        self.session_started = 0     # 0 = No Session, 1 = Open Session
        
        # Logging Variables
        self.logging = 0             # 0 = No Logging, 1 = Logging
        self.debug = -1              # 1, 2 or 3 (-1 if not debugging)
        
        # Files (Maps to "File Names")
        self.logging_file = ""
        self.debug_file = ""
        
        # File Names (Mapped from "Files")
        self.logging_file_name = ""  # If not initially specified, mcc_log.txt will be used
        self.debug_file_name = ""    # If not initially specified, mcc_debug.txt will be used
        
        # Time the script started        
        self.time_started = time.time()
        self.time_started_format = strftime("%Y-%m-%d-%H-%M-%S", time.localtime(self.time_started))

        # The MCC software version
        self.sw_ver = ""
        
        # Command Count
        self.command_count = 1
        
        # Strict Syntax
        self.strict_syntax = 0
        
        # MetaMIB Features Array
        self.meta_mib_feature_array = {}
        
        self.__lnxnm_print_debug(1, "Attempting to start a session")
        self.__lnxnm_print_debug(2, "The username being used is " + self.user);
        
        #######
        # Start the socket connection to the LNXNM (only port used is port 4433)
        self.ssl_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.ssl_sock.connect((ipaddr, 4433))
        # Read from the socket the initial line
        firstResponse = self.__lnxnm_read_lines()
        firstList = firstResponse.pop(0)
        
        # Check the return code
        #   220 - Successful, continue on
        #   421 - Unsuccessful, quit the script
        
        if ( cmp(firstList,220) == 0 ):
            # Continue on
            self.__lnxnm_print_debug(2, "Return code 220. The connection is successful.")
        elif ( cmp(firstList,421) == 0 ):
            self.__lnxnm_print_debug(2, "Return code 421. The MCC states the connection is not successful. Try again.")
            raise mccConnFail("connection unsuccessful: the network management module states the connection is not successful, try again")
        else:
            # Unknown error code
            self.__lnxnm_print_debug(2, "Unknown return code of " + str(firstList) + ". Try again.")
            raise mccUnknown("unknown error code: the error code \"" + str(firstList) + "\" is unknown, please call MRV support")

        self.__lnxnm_print_debug(2, "Attempting -- helo " + username + " " + password)
        self.__lnxnm_write_line("helo " + username + " " + password)
        secondResponse = self.__lnxnm_read_lines()
        secondList = secondResponse.pop(0)
        
        # Check the return code
        #   250 - Login Successful,
        #   530 - Permission denied, bad username or password        
        if (cmp(secondList,250) == 0):
            self.__lnxnm_print_debug(2, "Return code 250. Login is successful.")
        elif (cmp(secondList,530) == 0):
            self.__lnxnm_print_debug(2, "Return code 530. Bad username/password combination. Try again.")
            raise mccPermDeny("connection unsuccessful: the network management module states the connection is not successful, try again") 
        else:
            # Unknown error code
            self.__lnxnm_print_debug(2, "Unknown return code of " + str(secondList) + ". Try again.")
            raise mccUnknown("unknown error code: the error code \"" + str(secondList) + "\" is unknown, please call MRV support")
        
        self.session_started = 1
        


        self.sw_ver = self.Lnxnm_get("1.3.6.1.4.1.629.200.2.2")
                        
        # Check the version is correct
        self.__lnxnm_print_debug(1, "Successfully started a session. Now checking if the version is correct.")
        if (cmp(self.sw_ver,self.__lnxnm_get_desired_firmware_version()) != 0):
            self.__lnxnm_print_debug(1, "The desired NM version \"" + self.__lnxnm_get_desired_firmware_version() + "\" doesn't match the actual NM version of \"" + self.sw_ver  + "\"")
            self.session_started = 0
            
            # The user is STILL logged in, let's quit and close the socket
            # Send the "quit" command
            self.__lnxnm_print_debug(1, "Attempting -- quit")
            self.__lnxnm_write_line("quit")
            thirdResponse = self.__lnxnm_read_lines()
            thirdList = thirdResponse.pop(0)
            
            # Check the return code
            # 221 - Logout successful
            if (cmp(thirdList,221) == 0):
                # Continue on
                self.__lnxnm_print_debug(1, "Return code 221. Logout is successful.")
            else:
                raise mccUnknown("unknown error code: the error code \"" + str(thirdList) + "\" is unknown, please call MRV support")
                
            self.ssl_sock.close()
            raise mccVersMisMatch("invalid argument: the desired version NM version \"" + self.__lnxnm_get_desired_firmware_version() + "\" doesn't match the actual NM version of \"" + self.sw_ver  + "\"")
         
        self.__lnxnm_print_debug(1, "The desired NM version \"" + self.__lnxnm_get_desired_firmware_version() + "\" is correct.")
         


        # Successful start
        self.__lnxnm_print_debug(1, "Setting the session bit to " +  str(self.__session_started()) + " (0=Off,1=On).")
       
        # To support the MetaMIB, it is best to read the MetaMIB feature tables just once
        self.meta_mib_feature_array = self.Lnxnm_dump_table_metamib_feature()
       
        

    def __del__(self):
        # Kill the MCC session
        self.__lnxnm_print_debug(1, "Attempting -- quit")
        self.__lnxnm_write_line("quit")
        firstResponse = self.__lnxnm_read_lines()
        firstList = firstResponse.pop(0)
        #Check the return code
        #   221 - Logout Successful        
        if ( cmp(firstList,221) == 0 ):
            self.__lnxnm_print_debug(2, "Return code 221. Logout is successful.")
        else:
            # Unknown error code
            raise mccUnknown("unknown error code: the error code \"" + str(firstList) + "\" is unknown, please call MRV support")
        self.ssl_sock.close()
        # Set the Session Bit Off
        self.session_started = 0
        self.__lnxnm_print_debug(1, "Setting the session bit to " +  str(self.__session_started()) + " (0=Off,1=On).")
        
        # Close all log files (Maybe More Catches?)
        self.Lnxnm_logging_off()
        self.Lnxnm_debug_off()
        self.__lnxnm_print_debug(1, "Closing all debug files (if applicable).")
        
    #######################################
    ############## MCC Session Functions ##
    #######################################
    # Unlike the Tcl package we don't need a start and end function
    # Those are part of the constructor and deconstructor functions now
    
    # Return if the user is currently logged in
    def __session_started(self):
        if ( self.session_started == 1):
            self.__lnxnm_print_debug(1, "You are currently logged in" )
            return 1
        self.__lnxnm_print_debug(1, "You are currently logged out")
        return 0
    

    # Necessary firmware version - The package will not start without the correct version
    def __lnxnm_get_desired_firmware_version(self):
        return "4.10 mcc 07"

    

    #######################################
    ######Lnxnm_sync/Lnxnm_flush Functions ############
    #######################################
    def Lnxnm_sync(self):
        # This command is not the typical GET/SET command so it bypasses all of the internal functions being used
        self.__lnxnm_print_debug(2, "Lnxnm_synching the last command.")
        if (self.session_started == 1):
            self.__lnxnm_print_debug(1, "Attempting -- sync")
            self.__lnxnm_write_line("sync")
            firstResponse = self.__lnxnm_read_lines()
            firstList = firstResponse.pop(0)
               
            #Check the return code
            #   350 - OK; Output will end with <CRLF>.<CRLF> 
            #   530 - Permission Denied
            if ( cmp(firstList,350) == 0 ):
                # Continue on
                self.__lnxnm_print_debug(2, "Return code 350. Ok." )
                
                # Wait for the Lnxnm_sync to complete (when a period is received, Lnxnm_sync is completed)
                loopBreak = 1
                while (loopBreak == 1) :
                    # Keep on reading lines until a period is received
                    tempResponse = self.__lnxnm_read_lines()
                    for item in tempResponse:
                        tempString = item.pop(0)
                        if (tempString == "."):
                            loopBreak = 0
                self.__lnxnm_print_debug(1, "sync complete.")
                return 1
            elif ( cmp(firstList,530) == 0 ):
                self.__lnxnm_print_debug(2, "Return code 530. Permission denied.")
                raise mccPermDeny("permission denied: no access to " + oid)                
            else:
                # Unknown error code
                self.__lnxnm_print_debug(2, "Unknown return code of " + str(firstList) + ". Try again.")
                raise mccUnknown("unknown error code: the error code \"" + str(firstList) + "\" is unknown, please call MRV support")
        
        self.__lnxnm_print_debug(1, "Sorry but you are not logged in. Use mcc.mcc() to begin a new session.")
        raise mccNotLoggedIn("not logged in: must be logged in first before attempting commands") 
    
    def Lnxnm_flush(self):
        # This command is not the typical GET/SET command so it bypasses all of the internal functions being used
        self.__lnxnm_print_debug(2, "Lnxnm_flushing the last command.")
        if (self.session_started == 1):
            self.__lnxnm_print_debug(1, "Attempting -- flush")
            self.__lnxnm_write_line("flush")
            firstResponse = self.__lnxnm_read_lines()
            firstList = firstResponse.pop(0)
            
            #Check the return code
            #   350 - OK; Output will end with <CRLF>.<CRLF> 
            #   530 - Permission Denied
            if ( cmp(firstList,350) == 0 ):
                # Continue on
                self.__lnxnm_print_debug(2, "Return code 350. Ok." )
                
                # Wait for the Lnxnm_flush to complete (when a period is received, Lnxnm_flush is completed)
                loopBreak = 1
                while (loopBreak == 1) :
                    # Keep on reading lines until a period is received
                    tempResponse = self.__lnxnm_read_lines()
                    for item in tempResponse:
                        tempString = item.pop(0)
                        if (tempString == "."):
                            loopBreak = 0
                self.__lnxnm_print_debug(1, "Flush complete.")
                return 1
            elif ( cmp(firstList,530) == 0 ):
                self.__lnxnm_print_debug(2, "Return code 530. Permission denied.")
                raise mccPermDeny("permission denied: no access to " + oid)                
            else:
                # Unknown error code
                self.__lnxnm_print_debug(2, "Unknown return code of " + str(firstList) + ". Try again.")
                raise mccUnknown("unknown error code: the error code \"" + str(firstList) + "\" is unknown, please call MRV support")
        
        self.__lnxnm_print_debug(1, "Sorry but you are not logged in. Use mcc.mcc() to begin a new session.")
        raise mccNotLoggedIn("not logged in: must be logged in first before attempting commands") 

    #######################################
    ########## Get/Set Functions ##########
    #######################################
    
    # Send information to the MCC
    def Lnxnm_set(self, oid, args):
        # Some OID's do not require a chassis, slot, and port (simply skip these)
        # Make sure a session has been started
        if ( self.session_started == 1):
            self.__lnxnm_print_debug(1, "Attempting -- SET")
            self.__lnxnm_write_line("SET")
            sockResponse = self.__lnxnm_read_lines()
                            
            sockList = sockResponse.pop(0)
            
            #Check the return code
            #   354 - Start Command Input; End input with <CRLF>.<CRLF>
            #   530 - Permission Denied
            #   554 - Transaction Failed; Output will end with <CRLF>.<CRLF>
            if (cmp(sockList,354) == 0):
                # Continue on
                self.__lnxnm_print_debug(2, "Return code 354. Ok.")
                
                # Send the desired SET request
                self.__lnxnm_print_debug(1, "Attempting -- SET --> " + str(oid) + " ==>" + str(args))
                self.__lnxnm_write_line(str(oid) + " " + str(args) )
                # Print out a period to terminate the SET request
                self.__lnxnm_write_line(".")
                # Read the response
                sockResponse2 = self.__lnxnm_read_lines()
                
                sockList2 = sockResponse2.pop(0)
                #Check the return code
                #   250 - OK
                #   350 - OK; Output will end with <CRLF>.<CRLF> 
                #   530 - Permission Denied
                #   554 - Transaction Failed; Output will end with <CRLF>.<CRLF>
                if (cmp(sockList2,250) == 0):
                    # Continue on
                    self.__lnxnm_print_debug(2, "Return code 250. Ok.")
                    self.__lnxnm_print_debug(1, "Successful SET request.")
		    return 1
                elif (cmp(sockList2,350) == 0):
                    # Continue on
                    self.__lnxnm_print_debug(2, "Return code 350. Ok.")
                    self.__lnxnm_print_debug(1, "Successful SET request.")
                    return 1
                elif (cmp(sockList2,530) == 0):
                    self.__lnxnm_print_debug(2, "Return code 530. Permission denied.")
                    raise mccPermDeny("permission denied: no access to " + oid)
                elif (cmp(sockList2,554) == 0):
                    self.__lnxnm_print_debug(2, "Return code 554. Transaction failed.")
                    raise mccTranFail("transaction failed: failure to set OID " + oid)
                # Unknown Error Code
                self.__lnxnm_print_debug(2, "Unknown return code of " + str(sockList2) + ". Try again.")
                raise mccUnknown("unknown error code: the error code \"" + str(sockList2) + "\" is unknown, please call MRV support")
            
            elif (cmp(sockList,530) == 0):
                self.__lnxnm_print_debug(2, "Return code 530. Permission denied.")
                raise mccPermDeny("permission denied.")
            elif (cmp(sockList,554) == 0):
                self.__lnxnm_print_debug(2, "Return code 554. Transaction failed.")
                raise mccTranFail("transaction failed.")
                
            # Unknown Error Code
            self.__lnxnm_print_debug(2, "Unknown return code of " + str(sockList) + ". Try again.")
            raise mccUnknown("unknown error code: the error code \"" + str(sockList) + "\" is unknown, please call MRV support")

        self.__lnxnm_print_debug(1, "Sorry but you are not logged in. Use mcc.mcc() to begin a new session.")
        raise mccNotLoggedIn("not logged in: must be logged in first before attempting commands")  
    
    # Get information from the MCC
    def Lnxnm_get(self, oid):
        # Make sure a session has been started
        if ( self.session_started == 1):
            # Adjust for OID's without CSP!!!!!!
            self.__lnxnm_print_debug(1, "Attempting -- GET")
            self.__lnxnm_write_line("GET")
            sockResponse = self.__lnxnm_read_lines()
            sockList = sockResponse.pop(0)
            
            #Check the return code
            #   354 - Request Desired Output; End input with <CRLF>.<CRLF>
            #   530 - Permission Denied
            #   554 - Transaction Failed; End input with <CRLF>.<CRLF>
            
            if (cmp(sockList,354) == 0):
                # Continue on
                self.__lnxnm_print_debug(2, "Return code 354. Ok.")
                
                # Send the desired GET request
                self.__lnxnm_print_debug(1, "Attempting -- GET --> " + str(oid))
                self.__lnxnm_write_line(str(oid))
                # Print out a period to terminate the get request
                self.__lnxnm_write_line(".")
                sockResponse2 = self.__lnxnm_read_lines()
                sockList2 = sockResponse2.pop(0)
                
                #Check the return code
                #   350 - OK; Output will end with <CRLF>.<CRLF>
                #   530 - Permission Denied
                #   554 - Transaction Failed
                if (cmp(sockList2,350) == 0):
                    # Continue on
                    self.__lnxnm_print_debug(2, "Return code 350. Ok.")
                    
                    # Pull out the desired value
                    sockList3 = sockResponse2[0][1].split()
                    sockList3.pop(0)
                    sockList3.pop(0)
                    value = " ".join(sockList3)
                    self.__lnxnm_print_debug(1, "Successful GET request.")
                    return value
                elif (cmp(sockList2,530) == 0):
                    self.__lnxnm_print_debug(2, "Return code 530. Permission denied.")
                    raise mccPermDeny("permission denied: no access to " + oid)
                elif (cmp(sockList2,554) == 0):
                    self.__lnxnm_print_debug(2, "Return code 554. Transaction failed.")
                    raise mccTranFail("transaction failed: failure to set OID " + oid)
                    
                # Unknown Error Code
                self.__lnxnm_print_debug(2, "Unknown return code of " + str(sockList2) + ". Try again.")
                raise mccUnknown("unknown error code: the error code \"" + str(sockList2) + "\" is unknown, please call MRV support")
                
            elif (cmp(sockList,530) == 0):
                self.__lnxnm_print_debug(2, "Return code 530. Permission denied.")
                raise mccPermDeny("permission denied.")
            elif (cmp(sockList,554) == 0):
                self.__lnxnm_print_debug(2, "Return code 554. Transaction failed.")
                raise mccTranFail("transaction failed.")
                
            # Unknown Error Code
            self.__lnxnm_print_debug(2, "Unknown return code of " + str(sockList) + ". Try again.")
            raise mccUnknown("unknown error code: the error code \"" + str(sockList) + "\" is unknown, please call MRV support")

        self.__lnxnm_print_debug(1, "Sorry but you are not logged in. Use mcc.mcc() to begin a new session.")
        raise mccNotLoggedIn("not logged in: must be logged in first before attempting commands") 
    
    # Dump information from the MCC
    def Lnxnm_dump_table(self, oid):
        # Return a list of lists of the table in row/column order
        # Make sure a session has been started
        if ( self.session_started == 1):
            # Send the GET request (and read back the output)
            self.__lnxnm_print_debug(1, "Attempting -- TABLE " + oid)
            self.__lnxnm_write_line("table " + oid)
            sockResponse = self.__lnxnm_read_long_lines()
            sockList = sockResponse.pop(0)
            
            #Check the return code
            #   350 - OK; Output will end with <CRLF>.<CRLF>
            #   500 - Command Not Recognized. OID is not a table's entry object!
            #   500 - Command Not Recognized. Table '%s' is not supported here. 
            #   500 - Command Not Recognized. No such object. 
            #   530 - Permission Denied
            if (cmp(sockList,350) == 0):
                # Continue on
                self.__lnxnm_print_debug(2, "Return code 350. Ok.")
                
                # Create a list to return to the user
                retList = []
                
                sockList = sockResponse.pop(0)
                
                # Parse out the string
                tempSplit = sockList[1].split("\n")
                for y in range(len(tempSplit)):
                    rowList = []
                    tempString = tempSplit[y].split("\",\"")
                    for z in range(len(tempString)):
                        rowList.append(tempString[z].strip("\""))
                    # Discount the "period"
                    if (len(rowList) != 1):
                        retList.append(rowList)
                return retList
            elif (cmp(sockList,530) == 0):
                self.__lnxnm_print_debug(2, "Return code 530. Permission denied.")
                raise mccPermDeny("permission denied.")
            elif (cmp(sockList,500) == 0):
                self.__lnxnm_print_debug(2, "Return code 500. Command Not Recognized.")
                raise mccPermDeny("unrecognized command: inspect the debug log file for more information on the failure")
            # Unknown Error Code
            self.__lnxnm_print_debug(2, "Unknown return code of " + str(sockList) + ". Try again.")
            raise mccUnknown("unknown error code: the error code \"" + str(sockList) + "\" is unknown, please call MRV support")            
            
        self.__lnxnm_print_debug(1, "Sorry but you are not logged in. Use mcc.mcc() to begin a new session.")
        raise mccNotLoggedIn("not logged in: must be logged in first before attempting commands") 
    
    # Set information by each of the following types:
    #	Unsigned32
    #	Counter32
    #	TimeTicks (Doesn't require SET)
    #	IpAddress
    #	DisplayString 
    #	OCTET STRING
    #	INTEGER { }       (ENUM)
    #	INTEGER-
    
    # Set an Unsigned32 value
    def Lnxnm_set_unsigned32(self, oid, value, *args):
        # Set an object with unsigned32 syntax
        # The value must be an unsigned32 (integer) (0 to 4294967295)
        # If args are included, it must be exactly two where they are both integers
        #   and the first number is less than the second number
        tempValue = str(value)
        if ( self.__lnxnm_isNumber(tempValue) != 1):
            self.__lnxnm_print_debug(1, "Trying to set an unsigned32 object with an improper value of " + str(tempValue) + ".")
            raise mccInvalidArg("invalid argument: trying to set an unsigned32 object with an improper value of " + str(tempValue) + ".")
        value = int(value)
                
        # No arguments were used (using the typical range)
        if ( len(args) == 0 ) :
            if ( value < 0 or value > 4294967295) :
                self.__lnxnm_print_debug(1, "Trying to set an unsigned32 object with an out of range value of " + str(tempValue) + ".")
                raise mccInvalidArg("invalid argument: trying to set an unsigned32 object with an out of range value of " + str(tempValue) + ".")

            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        # 2 arguments were used (make sure the range is correct)
        if ( len(args) == 2 ) :
            argsVal1 = args[0]
            argsVal2 = args[1]
            
            tempValue1 = str(argsVal1)
            if ( self.__lnxnm_isNumber(tempValue1) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an unsigned32 object lower range with an improper value of " + str(tempValue1) + ".")
                raise mccInvalidArg("invalid argument: trying to set an unsigned32 object lower range with an improper value of " + str(tempValue1) + ".")            
            argsVal1 = int(argsVal1)
            
            tempValue2 = str(argsVal2)
            if ( self.__lnxnm_isNumber(tempValue1) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an unsigned32 object upper range with an improper value of " + str(tempValue2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an unsigned32 object upper range with an improper value of " + str(tempValue2) + ".")
            argsVal2 = int(argsVal2)
            
            if ( argsVal1 < 0 or argsVal1 > 4294967295) :
                self.__lnxnm_print_debug(1, "Trying to set an unsigned32 object lower range with an out of range value of " + str(argsVal1) + ".")
                raise mccInvalidArg("invalid argument: trying to set an unsigned32 object lower range with an out of range value of " + str(argsVal1) + ".")
                
            if ( argsVal2 < 0 or argsVal2 > 4294967295) :
                self.__lnxnm_print_debug(1, "Trying to set an unsigned32 object upper range with an out of range value of " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an unsigned32 object upper range with an out of range value of " + str(argsVal2) + ".")
            
            # Make sure the lower range is not greater than the upper range
            if ( argsVal1 > argsVal2) :
                self.__lnxnm_print_debug(1, "Trying to set an unsigned32 object lower range with value " + str(argsVal1) + " which is higher than the upper range with value " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an unsigned32 object lower range with value " + str(argsVal1) + " which is higher than the upper range with value " + str(argsVal2) + "")
            
            # Make sure the number is within range
            if ( argsVal1 > value or argsVal2 < value) :
                self.__lnxnm_print_debug(1, "Trying to set an unsigned32 object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an unsigned32 object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2))            
                
            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        self.__lnxnm_print_debug(1, "The wrong number of arguments were used when trying to set an unsigned32 (0 or 2 are required). The arguments were \"" + ','.join(args) + "\".")
        raise mccBadArgList("bad argument list: the wrong number of arguments were used when trying to set an unsigned32 (0 or 2 are required). The arguments were \"" + ','.join(args) + "\"")
        
    # Set a Counter32 value
    def Lnxnm_set_counter32(self, oid, value, *args):
        # Set an object with counter32 syntax
        # The value must be an counter32 (integer) (0 to 4294967295)
        # If args are included, it must be exactly two where they are both integers
        #   and the first number is less than the second number
        # From research Counter32 never has a range!
        tempValue = str(value)
        if ( self.__lnxnm_isNumber(tempValue) != 1):
            self.__lnxnm_print_debug(1, "Trying to set an counter32 object with an improper value of " + str(tempValue) + ".")
            raise mccInvalidArg("invalid argument: trying to set an counter32 object with an improper value of " + str(tempValue) + ".")
        value = int(value)
                
        # No arguments were used (using the typical range)
        if ( len(args) == 0 ) :
            if ( value < 0 or value > 4294967295) :
                self.__lnxnm_print_debug(1, "Trying to set an counter32 object with an out of range value of " + str(tempValue) + ".")
                raise mccInvalidArg("invalid argument: trying to set an counter32 object with an out of range value of " + str(tempValue) + ".")

            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        # 2 arguments were used (make sure the range is correct)
        if ( len(args) == 2 ) :
            argsVal1 = args[0]

            tempValue1 = str(argsVal1)
            if ( self.__lnxnm_isNumber(tempValue1) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an counter32 object lower range with an improper value of " + str(tempValue1) + ".")
                raise mccInvalidArg("invalid argument: trying to set an counter32 object lower range with an improper value of " + str(tempValue1) + ".")            
            argsVal1 = int(argsVal1)
            
            argsVal2 = args[1]
            tempValue2 = str(argsVal2)
            if ( self.__lnxnm_isNumber(tempValue2) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an counter32 object upper range with an improper value of " + str(tempValue2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an counter32 object upper range with an improper value of " + str(tempValue2) + ".")
            argsVal2 = int(argsVal2)
            
            if ( argsVal1 < 0 or argsVal1 > 4294967295) :
                self.__lnxnm_print_debug(1, "Trying to set an counter32 object lower range with an out of range value of " + str(argsVal1) + ".")
                raise mccInvalidArg("invalid argument: trying to set an counter32 object lower range with an out of range value of " + str(argsVal1) + ".")
                
            if ( argsVal2 < 0 or argsVal2 > 4294967295) :
                self.__lnxnm_print_debug(1, "Trying to set an counter32 object upper range with an out of range value of " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an counter32 object upper range with an out of range value of " + str(argsVal2) + ".")
            
            # Make sure the lower range is not greater than the upper range
            if ( argsVal1 > argsVal2) :
                self.__lnxnm_print_debug(1, "Trying to set an counter32 object lower range with value " + str(argsVal1) + " which is higher than the upper range with value " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an counter32 object lower range with value " + str(argsVal1) + " which is higher than the upper range with value " + str(argsVal2) + "")
            
            # Make sure the number is within range
            if ( argsVal1 > value or argsVal2 < value) :
                self.__lnxnm_print_debug(1, "Trying to set an counter32 object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an counter32 object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2))            
                
            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        self.__lnxnm_print_debug(1, "The wrong number of arguments were used when trying to set an counter32 (0 or 2 are required). The arguments were \"" + ','.join(args) + "\".")
        raise mccBadArgList("bad argument list: the wrong number of arguments were used when trying to set an counter32 (0 or 2 are required). The arguments were \"" + ','.join(args) + "\"")
    
    # Set an OCTET STRING value
    def Lnxnm_set_octet_string(self, oid, value, *args):
        # Set an object with octet string syntax
        # The value must be an octet string of size 0 to 65536
        # If args are included, it must be exactly one or two where the numbers are integers
        #   and the first number is less than the second number (if two are are specified)
        value = str(value)
        octet_string_size = self.__lnxnm_check_byte(value)
        
        if ( octet_string_size == 0) :
            self.__lnxnm_print_debug(1, "Trying to set an OCTET STRING object with an improper value of " + str(value) + ".")
            raise mccInvalidArg("invalid argument: trying to set an OCTET STRING object with an improper value of " + str(value) + ".")
            
        # No arguments were used (using the typical range)
        if ( len(args) == 0 ) :
            # Make sure the string is under size 65536
            if ( octet_string_size > 65536) :
                self.__lnxnm_print_debug(1, "Trying to set an OCTET STRING object with an out of range size of " + str(tempValue) + ". The biggest size for an OCTET STRING is 65536.")
                raise mccInvalidArg("invalid argument: trying to set an OCTET STRING object with an out of range size of " + str(tempValue) + ". The biggest size for an OCTET STRING is 65536.")
            
            # Attempt to set the OCTET STRING
            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        # One argument was used
        if ( len(args) == 1 ) :
            # Make sure the size is an integer
            argsVal1 = args[0]

            tempValue1 = str(argsVal1)
            if ( self.__lnxnm_isNumber(tempValue2) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an OCTET STRING object size with an improper value of " + str(tempValue1) + ".")
                raise mccInvalidArg("invalid argument: trying to set an OCTET STRING object size with an improper value of " + str(tempValue1) + ".")            
            argsVal1 = int(argsVal1)            
            
            # Make sure the string is equal to the desired size
            if ( octet_string_size != argsVal1) :
                self.__lnxnm_print_debug(1, "Trying to set an OCTET STRING object with an out of range size of " + str(octet_string_size) + ". The exact size for this OCTET STRING is " + str(tempValue1) +".")
                raise mccInvalidArg("invalid argument: trying to set an OCTET STRING object with an out of range size of " + str(octet_string_size) + ". The exact size for this OCTET STRING is " + str(tempValue1))            
            
            # Attempt to set the OCTET STRING
            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        # 2 arguments were used (make sure the range is correct)
        if ( len(args) == 2 ) :
            argsVal1 = args[0]
            argsVal2 = args[1]
            
            tempValue1 = str(argsVal1)
            if ( self.__lnxnm_isNumber(tempValue1) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an OCTET STRING object lower size with an improper value of " + str(tempValue1) + ".")
                raise mccInvalidArg("invalid argument: trying to set an OCTET STRING object lower size with an improper value of " + str(tempValue1) + ".")            
            argsVal1 = int(argsVal1)
            
            tempValue2 = str(argsVal2)
            if ( self.__lnxnm_isNumber(tempValue2) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an OCTET STRING object upper size with an improper value of " + str(tempValue2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an OCTET STRING object upper size with an improper value of " + str(tempValue2) + ".")
            argsVal2 = int(argsVal2)
            
            if ( argsVal1 < 0 or argsVal1 > 65536) :
                self.__lnxnm_print_debug(1, "Trying to set an OCTET STRING object lower size with an out of range value of " + str(argsVal1) + ".")
                raise mccInvalidArg("invalid argument: trying to set an OCTET STRING object lower size with an out of range value of " + str(argsVal1) + ".")
                
            if ( argsVal2 < 0 or argsVal2 > 65536) :
                self.__lnxnm_print_debug(1, "Trying to set an OCTET STRING object upper size with an out of range value of " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an OCTET STRING object upper size with an out of range value of " + str(argsVal2) + ".")
            
            # Make sure the lower size is not greater than the upper size
            if ( argsVal1 > argsVal2) :
                self.__lnxnm_print_debug(1, "Trying to set an OCTET STRING object lower size with value " + str(argsVal1) + " which is higher than the upper size with value " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an OCTET STRING object lower size with value " + str(argsVal1) + " which is higher than the upper size with value " + str(argsVal2) + "")
            
            # Make sure the size is within range
            if ( argsVal1 > octet_string_size or argsVal2 < octet_string_size) :
                self.__lnxnm_print_debug(1, "Trying to set an counter32 object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an OCTET STRING object size that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2))            
                
            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        self.__lnxnm_print_debug(1, "The wrong number of arguments were used when trying to set an counter32 (0 or 2 are required). The arguments were \"" + ','.join(args) + "\".")
        raise mccBadArgList("bad argument list: the wrong number of arguments were used when trying to set an counter32 (0 or 2 are required). The arguments were \"" + ','.join(args) + "\"")
        
        return 1
    
    # Set an IpAddress value
    def Lnxnm_set_ip_address(self, oid, value):
        # Set an object with IpAddress syntax
        # The value must be a valid Ip Address
        value = str(value)
        if (self.__lnxnm_check_ip(value) == 0):
            self.__lnxnm_print_debug(1, "Trying to set an IpAddress object with an improper address of " + value + "\".")
            raise mccInvalidArg("invalid argument: trying to set an IpAddress object with an improper address of " + value)
        
        endValue = self.Lnxnm_set(oid, value)
        # Successful set command
        self.__lnxnm_print_debug(3, "The SET command successfully returned.")
        return endValue        
    
    # Set a DisplayString value
    def Lnxnm_set_display_string(self, oid, value, *args):
        # Set an object with DisplayString syntax
        # The value must be a string of valid size
        # If args are included, it must be exactly two where they are both integers
        #   and the first number is less than the second number
        
        value = str(value)
        
        # No arguments were used (check the string size is not bigger than ?????)
        if ( len(args) == 0 ) :
            if ( len(value) > 255) :
                self.__lnxnm_print_debug(1, "Trying to set an DisplayString object that is longer than accepted 255 characters. The string is " + str(value) + ".")
                raise mccInvalidArg("invalid argument: trying to set an DisplayString object that is longer than accepted 255 characters. The string is " + str(value) + ".")

            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        # 2 arguments were used (make sure the range is correct)
        if ( len(args) == 2 ) :
            argsVal1 = args[0]

            tempValue1 = str(argsVal1)
            if ( self.__lnxnm_isNumber(tempValue1) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an DisplayString object lower range with an improper value of " + str(tempValue1) + ".")
                raise mccInvalidArg("invalid argument: trying to set an DisplayString object lower range with an improper value of " + str(tempValue1) + ".")            
            argsVal1 = int(argsVal1)
            
            argsVal2 = args[1]
            tempValue2 = str(argsVal2)
            if ( self.__lnxnm_isNumber(tempValue2) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an DisplayString object upper range with an improper value of " + str(tempValue2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an DisplayString object upper range with an improper value of " + str(tempValue2) + ".")
            argsVal2 = int(argsVal2)
            
            if ( len(value) < argsVal1):
                self.__lnxnm_print_debug(1, "Trying to set a DisplayString object (" + str(value) + ") that is smaller than the lower range of "+ str(argsVal1) + ".")
                raise mccInvalidArg("invalid argument: trying to set a DisplayString object (" + str(value) + ") that is smaller than the lower range of "+ str(argsVal1))                

            if ( len(value) > argsVal2):
                self.__lnxnm_print_debug(1, "Trying to set a DisplayString object (" + str(value) + ") that is larger than the upper range of "+ str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set a DisplayString object (" + str(value) + ") that is larger than the upper range of "+ str(argsVal2))                
            
            # Make sure the lower range is not greater than the upper range
            if ( argsVal1 > argsVal2) :
                self.__lnxnm_print_debug(1, "Trying to set an DisplayString object lower range with value " + str(argsVal1) + " which is higher than the upper range with value " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an DisplayString object lower range with value " + str(argsVal1) + " which is higher than the upper range with value " + str(argsVal2) + "")
                
            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        self.__lnxnm_print_debug(1, "The wrong number of arguments were used when trying to set an DisplayString (0 or 2 are required). The arguments were \"" + ','.join([str(y) for y in args]) + "\".")
        raise mccBadArgList("bad argument list: the wrong number of arguments were used when trying to set an DisplayString (0 or 2 are required). The arguments were \"" + ','.join([str(y) for y in args]) + "\"")
    
    # Set an Integer value
    def Lnxnm_set_integer32(self, oid, value, *args):
        # Set an object with integer syntax
        # The value must be an integer (0 to 4294967295)
        # If args are included, it must be exactly two where they are both integers
        #   and the first number is less than the second number

        tempValue = str(value)
        if ( self.__lnxnm_isNumber(tempValue) != 1):
            self.__lnxnm_print_debug(1, "Trying to set an integer object with an improper value of " + str(tempValue) + ".")
            raise mccInvalidArg("invalid argument: trying to set an integer object with an improper value of " + str(tempValue) + ".")
        value = int(value)
                
        # No arguments were used (using the typical range)
        if ( len(args) == 0 ) :
            if ( value < 0 or value > 4294967295) :
                self.__lnxnm_print_debug(1, "Trying to set an integer object with an out of range value of " + str(tempValue) + ".")
                raise mccInvalidArg("invalid argument: trying to set an integer object with an out of range value of " + str(tempValue) + ".")

            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        # 2 arguments were used (make sure the range is correct)
        if ( len(args) == 2 ) :
            argsVal1 = args[0]
            argsVal2 = args[1]
            
            tempValue1 = str(argsVal1)
            if ( self.__lnxnm_isNumber(tempValue1) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an integer object lower range with an improper value of " + str(tempValue1) + ".")
                raise mccInvalidArg("invalid argument: trying to set an integer object lower range with an improper value of " + str(tempValue1) + ".")            
            argsVal1 = int(argsVal1)
            
            tempValue2 = str(argsVal2)
            if ( self.__lnxnm_isNumber(tempValue2) != 1):
                self.__lnxnm_print_debug(1, "Trying to set an integer object upper range with an improper value of " + str(tempValue2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an integer object upper range with an improper value of " + str(tempValue2) + ".")
            argsVal2 = int(argsVal2)
    
            
            # Make sure the lower range is not greater than the upper range
            if ( argsVal1 > argsVal2) :
                self.__lnxnm_print_debug(1, "Trying to set an integer object lower range with value " + str(argsVal1) + " which is higher than the upper range with value " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an integer object lower range with value " + str(argsVal1) + " which is higher than the upper range with value " + str(argsVal2) + "")

            # Make sure the difference between both ranges is not greater than 2^32
            if ( (argsVal2 - argsVal1) > 4294967295) :
                self.__lnxnm_print_debug(1, "The difference (" + str((argsVal2 - argsVal1)) + ") beween the upper range of " +  str(argsVal2) + " and the lower range of " + str(argsVal1)  + " is greater than 4294967295.")
                raise mccInvalidArg("invalid argument: the difference (" + str((argsVal2 - argsVal1)) + ") beween the upper range of " +  str(argsVal2) + " and the lower range of " + str(argsVal1)  + " is greater than 4294967295")
                
            # Make sure the number is within range
            if ( argsVal1 > value or argsVal2 < value) :
                self.__lnxnm_print_debug(1, "Trying to set an integer object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2) + ".")
                raise mccInvalidArg("invalid argument: trying to set an integer object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2))            
                
            endValue = self.Lnxnm_set(oid, value)
            # Successful set command
            self.__lnxnm_print_debug(3, "The SET command successfully returned.")
            return endValue
        
        self.__lnxnm_print_debug(1, "The wrong number of arguments were used when trying to set an integer (0 or 2 are required). The arguments were \"" + ','.join(args) + "\".")
        raise mccBadArgList("bad argument list: the wrong number of arguments were used when trying to set an integer (0 or 2 are required). The arguments were \"" + ','.join(args) + "\"")
    
    # Set an Integer value (ENUM)
    def Lnxnm_set_enum(self, oid, value, size):
        # Set an object with integer (ENUM) syntax
        # The value must be an integer (0 to $SIZE)
        # No args are accepted
        
        tempValue = str(value)
        if ( self.__lnxnm_isNumber(tempValue) != 1):
            self.__lnxnm_print_debug(1, "Trying to set an integer object with an improper value of " + str(tempValue) + ".")
            raise mccInvalidArg("invalid argument: trying to set an integer object with an improper value of " + str(tempValue) + ".")
        value = int(value)
        
        tempSize = str(size)
        if ( self.__lnxnm_isNumber(tempSize) != 1):
            self.__lnxnm_print_debug(1, "Trying to set an integer object with an improper value of " + str(tempSize) + ".")
            raise mccInvalidArg("invalid argument: trying to set an integer object with an improper value of " + str(tempSize) + ".")
        size = int(size)
        
        # Make sure the number is within range
        if ( value < 1 or value > size) :
            self.__lnxnm_print_debug(1, "Trying to set an integer object with an out of range value of " + str(value) + ". The accepted range is 1 to " + str(size) + ".")
            raise mccInvalidArg("invalid argument: trying to set an integer object with an out of range value of " + str(value) + ". The accepted range is 1 to " + str(size))
            
        endValue = self.Lnxnm_set(oid, value)
        # Successful set command
        self.__lnxnm_print_debug(3, "The SET command successfully returned.")
        return endValue
    
    # Get information from the MetaMIB
    def Lnxnm_get_meta(self, location, adminOrOper, featureId):
        # Take the OID and find it in the features table
        # adminOper
        #	0 = Admin
        #	1 = Oper
        
        # Change the location to IfIndex notation
        ifIndex = ""
        locList = location.split(".")
        if (len(locList) == 1):
            ifIndex = self.__lnxnm_csp_to_ifIndex(locList[0])
        if (len(locList) == 2):
            ifIndex = self.__lnxnm_csp_to_ifIndex(locList[0], locList[1])
        if (len(locList) == 3):
            ifIndex = self.__lnxnm_csp_to_ifIndex(locList[0], locList[1], locList[2])
        
        # Return the variable
        if (adminOrOper == 0):
            endValue = self.Lnxnm_get("1.3.6.1.4.1.629.205.1.4.1.7." + str(ifIndex) + "." + str(featureId))
        else:
            endValue = self.Lnxnm_get("1.3.6.1.4.1.629.205.1.4.1.6." + str(ifIndex) + "." + str(featureId))
        # Successful get command
        self.__lnxnm_print_debug(3, "The GET command successfully returned.")
        return endValue
    
    # Get information from the MetaMIB (special case for enumerations)
    def Lnxnm_get_meta_enum(self, location, adminOrOper, featureId, enumList):
        # Since a string is always returned by the API, this needs to be converted
        #       into an integer value and returned to the user
        endValue = self.Lnxnm_get_meta(location, adminOrOper, featureId)
        
        # Find where in the list the value exists and return that value
        i = 0;
        for tempLine in enumList:
            if (tempLine == endValue):
                self.__lnxnm_print_debug(3, "Successfully found " + str(endValue) + " in the enumerated list of \"" + ','.join([str(y) for y in enumList]) + "\".")
                return i + 1
            i = i + 1    
        raise mccMetaFeatureNoEnum("enum not found: the enum \"" + str(endValue) + "\" was not found in the list \"" + ','.join([str(y) for y in enumList]) + "\"")
    
    # Set information via the MetaMIB
    def Lnxnm_set_meta(self, location, featureId, value):
        # Take the OID and find it in the features table
        # Change the location to ifIndex notation
        ifIndex = ""
        locList = location.split(".")
        if (len(locList) == 1):
            ifIndex = self.__lnxnm_csp_to_ifIndex(locList[0])
        if (len(locList) == 2):
            ifIndex = self.__lnxnm_csp_to_ifIndex(locList[0], locList[1])
        if (len(locList) == 3):
            ifIndex = self.__lnxnm_csp_to_ifIndex(locList[0], locList[1], locList[2])
            
        # Set the variable (if the location has it)
        endValue = self.Lnxnm_set("1.3.6.1.4.1.629.205.1.4.1.7." + str(ifIndex) + "." + str(featureId), str(value))
        # Successful set command
        self.__lnxnm_print_debug(3, "The SET command successfully returned.")
        return endValue        
        
    # Set MetaMIB information by each of the following types:
    #	Integer
    #	Float (double)
    #	Integer (ENUM)
    #	String    

    # Set an integer value in the MetaMIB
    def Lnxnm_set_meta_integer(self, location, featureId, value, *args):
        # Set an object with integer syntax                     
        #       The integer must be in the specified range (in args)
        # Make sure the value is an integer
        tempValue = str(value)
        if ( self.__lnxnm_isNumber(tempValue) != 1):
            self.__lnxnm_print_debug(1, "Trying to set an integer object with an improper value of " + str(tempValue) + ".")
            raise mccInvalidArg("invalid argument: trying to set an integer object with an improper value of " + str(tempValue) + ".")
        value = int(value)
        
        # Make sure the minimum value is an integer
        argsVal1 = args[0]
        tempArgs1 = str(argsVal1)
        if ( self.__lnxnm_isNumber(tempArgs1) != 1):
            self.__lnxnm_print_debug(1, "Trying to set an integer object lower range with an improper value of " + str(tempArgs1) + ".")
            raise mccInvalidArg("invalid argument: trying to set an integer object lower range with an improper value of " + str(tempArgs1) + ".")
        argsVal1 = int(argsVal1)        
        
        # Make sure the maximum value is an integer
        argsVal2 = args[1]
        tempArgs2 = str(argsVal2)
        if ( self.__lnxnm_isNumber(tempArgs2) != 1):
            self.__lnxnm_print_debug(1, "Trying to set an integer object upper range with an improper value of " + str(tempArgs2) + ".")
            raise mccInvalidArg("invalid argument: trying to set an integer object upper range with an improper value of " + str(tempArgs2) + ".")
        argsVal2 = int(argsVal2)                
        
        # Make sure the number is within range
        if ( argsVal1 > value or argsVal2 < value) :
            self.__lnxnm_print_debug(1, "Trying to set an integer object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2) + ".")
            raise mccInvalidArg("invalid argument: trying to set an integer object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2))                    
        
        # Try to configure the object
        endValue = self.set_meta(location,featureId,value)
        # Successful set command
        self.__lnxnm_print_debug(3, "The SET command successfully returned.")
        return endValue                    
    
    # Set a float (double) value in the MetaMIB
    def Lnxnm_set_meta_float(self, location, featureId, value, *args):
        # Set an object with float syntax                       
        #       The float must be in the specified range (in args)
        # Make sure the value is a float
        tempValue = str(value)
        if ( self.__lnxnm_float_check(tempValue) == 0):
            self.__lnxnm_print_debug(1, "Trying to set a float object with an improper value of " + str(tempValue) + ".")
            raise mccInvalidArg("invalid argument: trying to set a float object with an improper value of " + str(tempValue) + ".")
        value = float(value)
        
        # Make sure the minimum value is a float
        argsVal1 = args[0]
        tempArgs1 = str(argsVal1)
        if ( self.__lnxnm_float_check(tempArgs1) == 0):
            self.__lnxnm_print_debug(1, "Trying to set a float object lower range with an improper value of " + str(tempArgs1) + ".")
            raise mccInvalidArg("invalid argument: trying to set a float object lower range with an improper value of " + str(tempArgs1) + ".")
        argsVal1 = float(argsVal1)        
        
        # Make sure the maximum value is a float
        argsVal2 = args[1]
        tempArgs2 = str(argsVal2)
        if ( self.__lnxnm_float_check(tempArgs2) == 0):
            self.__lnxnm_print_debug(1, "Trying to set a float object upper range with an improper value of " + str(tempArgs2) + ".")
            raise mccInvalidArg("invalid argument: trying to set a float object upper range with an improper value of " + str(tempArgs2) + ".")
        argsVal2 = float(argsVal2)                
        
        # Make sure the number is within range
        if ( argsVal1 > value or argsVal2 < value) :
            self.__lnxnm_print_debug(1, "Trying to set a float object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2) + ".")
            raise mccInvalidArg("invalid argument: trying to set a float object that is out of range (" + str(value) + "); the lower range with value " + str(argsVal1) + " and the upper range with value " + str(argsVal2))                    
        
        # Try to configure the object
        endValue = self.set_meta(location, featureId, value)
        # Successful set command
        self.__lnxnm_print_debug(3, "The SET command successfully returned.")
        return endValue                    
    
    # Set an integer value (ENUM) in the MetaMIB
    def Lnxnm_set_meta_enum(self, location, featureId, value, enumList):
        # Set an object with integer (ENUM) syntax           
        #       The value must be an integer (1 to to size of enumList)    
        # No args are accepted                               
        # Make sure the value is an integer
        tempValue = str(value)
        if ( self.__lnxnm_isNumber(tempValue) != 1):
            self.__lnxnm_print_debug(1, "Trying to set an integer object with an improper value of " + str(tempValue) + ".")
            raise mccInvalidArg("invalid argument: trying to set an integer object with an improper value of " + str(tempValue) + ".")
        value = int(value)
        
        # Make sure the number is within range
        if ( value < 1 or value > len(enumList)) :
            self.__lnxnm_print_debug(1, "Trying to set an integer object with an out of range value of " + str(tempValue) + ". The accepted range is 1 to " + str(len(enumList)) + ".")
            raise mccInvalidArg("invalid argument: trying to set an integer object with an out of range value of " + str(tempValue) + ". The accepted range is 1 to " + str(len(enumList)))
    
        # Try to configure the object
        endValue = self.set_meta(location, featureId, enumList[value-1])
        # Successful set command
        self.__lnxnm_print_debug(3, "The SET command successfully returned.")
        return endValue           
    
    # Set a string value in the MetaMIB
    def Lnxnm_set_meta_string(self, location, featureId, value, *args):
        # Set an object with string syntax                     
        # The value must be a string of valid size
        # Make sure the lower range is an integer
        argsVal1 = args[0]
        tempArgs1 = str(argsVal1)
        if ( self.__lnxnm_isNumber(tempArgs1) != 1):
            self.__lnxnm_print_debug(1, "Trying to set an string object lower range with an improper value of " + str(tempArgs1) + ".")
            raise mccInvalidArg("invalid argument: trying to set an string object lower range with an improper value of " + str(tempArgs1) + ".")
        argsVal1 = int(argsVal1)       
        
        # Make sure the upper range is an interger
        argsVal2 = args[1]
        tempArgs2 = str(argsVal2)
        if ( self.__lnxnm_float_check(tempArgs2) == 0):
            self.__lnxnm_print_debug(1, "Trying to set a string object upper range with an improper value of " + str(tempArgs2) + ".")
            raise mccInvalidArg("invalid argument: trying to set a string object upper range with an improper value of " + str(tempArgs2) + ".")
        argsVal2 = float(argsVal2)    
        
        # Make sure the string is not shorter than expected
        if ( len(value) < argsVal1) :
            self.__lnxnm_print_debug(1, "Trying to set a string object (" + str(value) + ") that is smaller than the lower range of " + tempArgs1 + ".")
            raise mccInvalidArg("invalid argument: trying to set a string object (" + str(value) + ") that is smaller than the lower range of " + tempArgs1)        
        
        # Make sure the string is not longer than expected
        if ( len(value) > argsVal2) :
            self.__lnxnm_print_debug(1, "Trying to set a string object (" + str(value) + ") that is larger than the upper range of " + tempArgs2 + ".")
            raise mccInvalidArg("invalid argument: trying to set a string object (" + str(value) + ") that is larger than the upper range of " + tempArgs2)        
    
        # Try to configure the object
        endValue = self.set_meta(location, featureId, value)
        # Successful set command
        self.__lnxnm_print_debug(3, "The SET command successfully returned.")
        return endValue       

    #######################################
    ########### Smart Functions ###########
    #######################################    
    #
    # These functions are special functions that are meant to interpret
    # or combine OID variables to something more human friendly
    
    ##### Mapping (only at port level)
    ## Mapping Objects (Not to be autogenerated!)
    ## Set
    # Chassis ID - 1.3.6.1.4.1.629.200.8.1.1.46
    # Slot ID - 1.3.6.1.4.1.629.200.8.1.1.47
    # Port ID - 1.3.6.1.4.1.629.200.8.1.1.39
    # Map Clearing ID - 1.3.6.1.4.1.629.200.8.1.1.83 (to value 3)
    
    ## Get
    # Chassis ID - 1.3.6.1.4.1.629.200.8.1.1.55
    # Slot ID - 1.3.6.1.4.1.629.200.8.1.1.54
    # Port ID - 1.3.6.1.4.1.629.200.8.1.1.53
    
    # Map clear-all
    def Lnxnm_set_map_clear_all(self, chassis, slot, port):
        # Return 1 if successful
    
        # Verify the port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Verify the port has is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Map Clearing ID (set the value to 3)
        map_clearing_oid = "1.3.6.1.4.1.629.200.8.1.1.83"
        
        self.__lnxnm_print_debug(2, "Attempting to clear all mappings on " + str(chassis) + "." + str(slot) + "." + str(port) + ".")
        
        # Clear mapping on the port
        self.Lnxnm_set_integer32(str(map_clearing_oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), 3)
        self.__lnxnm_print_debug(2, "Successfully cleared the mapping on " + str(chassis) + "." + str(slot) + "." + str(port) + ".")
        return 1
    
    # Map bidir (no clearing)
    def Lnxnm_set_map_bidir(self, a_chassis, a_slot, a_port, b_chassis, b_slot, b_port):    
        # Return 1 if successful
    
        # Verify porta has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(a_chassis, a_slot, a_port)
        
        # Verify porta is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(a_chassis, a_slot, a_port)
            
        # Verify portb has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(b_chassis, b_slot, b_port)
        
        # Verify portb is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(b_chassis, b_slot, b_port)            
        
        # Mapping OID
        map_oid = "1.3.6.1.4.1.629.200.8.1.1.84"

        # Convert port A to ifIndex
        a_ifindex = self.__lnxnm_csp_to_ifIndex(a_chassis, a_slot, a_port)
        
        # Convert port B to ifIndex
        b_ifindex = self.__lnxnm_csp_to_ifIndex(b_chassis, b_slot, b_port)
               
        self.__lnxnm_print_debug(2, "Attempting to map " + str(a_chassis) + "." + str(a_slot) + "." + str(a_port) + " with " + str(b_chassis) + "." + str(b_slot) + "." + str(b_port) + ".")
        
        # Map port B to port A
        self.Lnxnm_set_integer32(str(map_oid) + "." + str(a_chassis) + "." + str(a_slot) + "." + str(a_port), b_ifindex)
        
        # Map port A to port B
        self.Lnxnm_set_integer32(str(map_oid) + "." + str(b_chassis) + "." + str(b_slot) + "." + str(b_port), a_ifindex)

        
        self.__lnxnm_print_debug(2, "Successfully mapped " + str(a_chassis) + "." + str(a_slot) + "." + str(a_port) + " with " + str(b_chassis) + "." + str(b_slot) + "." + str(b_port) + ".")
        return 1
    
    # Map with
    def Lnxnm_set_map_with(self, a_chassis, a_slot, a_port, b_chassis, b_slot, b_port):    
        # Return 1 if successful
    
        # Verify porta has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(a_chassis, a_slot, a_port)
        
        # Verify porta is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(a_chassis, a_slot, a_port)
            
        # Verify portb has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(b_chassis, b_slot, b_port)
        
        # Verify portb is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(b_chassis, b_slot, b_port)
            
        # Clear all mappings on the "from" port using set_map_clear_all
        self.Lnxnm_set_map_clear_all(a_chassis, a_slot, a_port)
        
        # Clear all mappings on the "to" port using set_map_clear_all
        self.Lnxnm_set_map_clear_all(b_chassis, b_slot, b_port)
        
        # Mapping OID
        map_oid = "1.3.6.1.4.1.629.200.8.1.1.84"

        # Convert port A to ifIndex
        a_ifindex = self.__lnxnm_csp_to_ifIndex(a_chassis, a_slot, a_port)
        
        # Convert port B to ifIndex
        b_ifindex = self.__lnxnm_csp_to_ifIndex(b_chassis, b_slot, b_port)
               
        self.__lnxnm_print_debug(2, "Attempting to map " + str(a_chassis) + "." + str(a_slot) + "." + str(a_port) + " with " + str(b_chassis) + "." + str(b_slot) + "." + str(b_port) + ".")
        
        # Map port B to port A
        self.Lnxnm_set_integer32(str(map_oid) + "." + str(a_chassis) + "." + str(a_slot) + "." + str(a_port), b_ifindex)
        
        # Map port A to port B
        self.Lnxnm_set_integer32(str(map_oid) + "." + str(b_chassis) + "." + str(b_slot) + "." + str(b_port), a_ifindex)

        self.__lnxnm_print_debug(2, "Successfully mapped " + str(a_chassis) + "." + str(a_slot) + "." + str(a_port) + " with " + str(b_chassis) + "." + str(b_slot) + "." + str(b_port) + ".")
        return 1    
    
    # Map unidir (doesn't clear)
    # This command is not needed since it is the equivalent of "::Lnxnm::Lnxnm_set_map_also_to"
    
    # Map also-to
    def Lnxnm_set_map_also_to(self, from_chassis, from_slot, from_port, to_chassis, to_slot, to_port):        
        # Return 1 if successful
    
        # Verify from-port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(from_chassis, from_slot, from_port)
        
        # Verify from-port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(from_chassis, from_slot, from_port)
            
        # Verify to-port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(to_chassis, to_slot, to_port)
        
        # Verify to-port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(to_chassis, to_slot, to_port)

        self.__lnxnm_print_debug(2, "Attempting to map " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + " with " + str(to_chassis) + "." + str(to_slot) + "." + str(to_port) + ".")        
        
        # Mapping OID
        map_oid = "1.3.6.1.4.1.629.200.8.1.1.84"

        # Convert from-port to ifIndex
        from_ifindex = self.__lnxnm_csp_to_ifIndex(from_chassis, from_slot, from_port)    
        
        # Map port from_port to to_port
        self.Lnxnm_set_integer32(str(map_oid) + "." + str(to_chassis) + "." + str(to_slot) + "." + str(to_port), from_ifindex)

        self.__lnxnm_print_debug(2, "Successfully mapped " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + " also-to " + str(to_chassis) + "." + str(to_slot) + "." + str(to_port) + ".")
        return 1
    
    # Map only-to
    def Lnxnm_set_map_only_to(self, from_chassis, from_slot, from_port, to_chassis, to_slot, to_port):        
        # Return 1 if successful
    
        # Verify from-port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(from_chassis, from_slot, from_port)
        
        # Verify from-port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(from_chassis, from_slot, from_port)
            
        # Verify to-port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(to_chassis, to_slot, to_port)
        
        # Verify to-port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(to_chassis, to_slot, to_port)

        # Future enhancement - Check if the "from" port is already only mapped to the "to" port

        self.__lnxnm_print_debug(2, "Attempting to map " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + " only-to " + str(to_chassis) + "." + str(to_slot) + "." + str(to_port) + ".")
        
        # Clear all mappings on the "from" port using set_map_clear_all
        self.Lnxnm_set_map_clear_all(from_chassis, from_slot, from_port)
        
        # Clear all mappings on the "to" port using set_map_clear_all
        self.Lnxnm_set_map_clear_all(to_chassis, to_slot, to_port)
        
        ## Map the "from" port to the "to" port       
        # Mapping OID
        map_oid = "1.3.6.1.4.1.629.200.8.1.1.84"

        # Convert from-port to ifIndex
        from_ifindex = self.__lnxnm_csp_to_ifIndex(from_chassis, from_slot, from_port)    
        
        # Map port from_port to to_port
        self.Lnxnm_set_integer32(str(map_oid) + "." + str(to_chassis) + "." + str(to_slot) + "." + str(to_port), from_ifindex)

        self.__lnxnm_print_debug(2, "Successfully mapped " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + " only-to " + str(to_chassis) + "." + str(to_slot) + "." + str(to_port) + ".")
        return 1
    
    # Map not-to
    def Lnxnm_set_map_not_to(self, from_chassis, from_slot, from_port, to_chassis, to_slot, to_port):        
        # Return 1 if successful
        # Returns 0 if the "from" port is already not mapped to the "to" port
    
        # Verify from-port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(from_chassis, from_slot, from_port)
        
        # Verify from-port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(from_chassis, from_slot, from_port)
            
        # Verify to-port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(to_chassis, to_slot, to_port)
        
        # Verify to-port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(to_chassis, to_slot, to_port)

        # We must first check that from port is mapped to the "to" port
        self.__lnxnm_print_debug(2, "Attempting to map " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + " not-to " + str(to_chassis) + "." + str(to_slot) + "." + str(to_port) + ".")
        self.__lnxnm_print_debug(1, "Checking that " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + " is currently mapped from " + str(to_chassis) + "." + str(to_slot) + "." + str(to_port) + ".")
        
        # Need to first check that the "to" port IS mapped from the "from" port
        
        # Check if the incoming mapping to the "to" port is empty
        inMap = self.Lnxnm_get_map_incoming_oper(to_chassis, to_slot, to_port)
        inMapString = '.'.join([str(y) for y in inMap])
        if (len(inMap) == 0):
            self.__lnxnm_print_debug(2, "The incoming mapping of port " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + " is empty and not the desired " + str(to_chassis) + "." + str(to_slot) + "." + str(to_port) + ". Can't do the desired not-to mapping.")
            return 0
        
        # Check if the from_port is really mapped to the to_port
        if (inMap[0] != from_chassis or inMap[1] != from_slot or inMap[2] != from_port):
            self.__lnxnm_print_debug(2, "The incoming mapping of port " + str(to_chassis) + "." + str(to_slot) + "." + str(to_port) + " is " + str(inMapString) + " and not the desired " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + ". Can't do the desired not-to mapping.")
            return 0
            
        self.__lnxnm_print_debug(2, "The incoming mapping of port " + str(to_chassis) + "." + str(to_slot) + "." + str(to_port) + " is " + str(inMapString) + " which matches the desired " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + ". Clearing the incoming mapping on " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + ".")
        
        ## Clear the incoming mappings into       
        # Mapping OID
        map_oid = "1.3.6.1.4.1.629.200.8.1.1.84"

        # Map to_port with no incoming mapping
        self.Lnxnm_set_integer32(str(map_oid) + "." + str(to_chassis) + "." + str(to_slot) + "." + str(to_port), "0")

        self.__lnxnm_print_debug(2, "Successfully mapped " + str(from_chassis) + "." + str(from_slot) + "." + str(from_port) + " note-to " + str(to_chassis) + "." + str(to_slot) + "." + str(to_port) + ".")
        return 1
    
    # Map to-self
    def Lnxnm_set_map_to_self(self, chassis, slot, port):        
        # Return 1 if successful
    
        # Verify port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Verify port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)

        # We must first check that from port is mapped to the "to" port
        self.__lnxnm_print_debug(2, "Attempting to map " + str(chassis) + "." + str(slot) + "." + str(port) + " to itself.")
        
        # Clear all mappings on the port
        self.Lnxnm_set_map_clear_all(chassis, slot, port)
        
        # Mapping OID
        map_oid = "1.3.6.1.4.1.629.200.8.1.1.84"
        
        # Convert port to ifIndex
        port_ifindex = self.__lnxnm_csp_to_ifIndex(chassis, slot, port)

        # Map port to itself
        self.Lnxnm_set_integer32(str(map_oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(port_ifindex))

        self.__lnxnm_print_debug(2, "Successfully mapped " + str(chassis) + "." + str(slot) + "." + str(port) + " to itself.")
        return 1
    
    
    # Map Display (Incoming)
    # This only returns the ADMIN mapping
    def Lnxnm_get_map_incoming_admin(self, chassis, slot, port):
        # Returns a list of the port (chassis slot port) if mapped
        #   if not mapped return an empty list
    
        # Verify port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Verify port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)

        self.__lnxnm_print_debug(2, "Attempting to get the desired incoming mapping for " + str(chassis) + "." + str(slot) + "." + str(port) + ".")
                
        # Mapping OID
        map_oid = "1.3.6.1.4.1.629.200.8.1.1.84"
        
        # Get the mapping
        endValue = str(self.Lnxnm_get(str(map_oid) + "." + str(chassis) + "." + str(slot) + "." + str(port)))
        
        if (str(endValue) == "0"):
            self.__lnxnm_print_debug(2, "There is no desired incoming mapping for " + str(chassis) + "." + str(slot) + "." + str(port) + ".")
            return []
        
        # Change the result to a list
        endValue = self.__lnxnm_ifindex_to_csp(int(endValue))
        endValueString = '.'.join([str(y) for y in endValue])
        self.__lnxnm_print_debug(2, "Successfully got the desired incoming mapping for " + str(chassis) + "." + str(slot) + "." + str(port) + " which is " + endValueString + ".")
        return endValue

    # Map Display (Incoming)
    # This only returns the OPER mapping
    def Lnxnm_get_map_incoming_oper(self, chassis, slot, port):
        # Returns a list of the port (chassis slot port) if mapped
        #   if not mapped return an empty list
    
        # Verify port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Verify port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)

        self.__lnxnm_print_debug(2, "Attempting to get the operational incoming mapping for " + str(chassis) + "." + str(slot) + "." + str(port) + ".")
                
        # Mapping OID
        map_oid = "1.3.6.1.4.1.629.200.8.1.1.85"
        
        # Get the mapping
        endValue = str(self.Lnxnm_get(str(map_oid) + "." + str(chassis) + "." + str(slot) + "." + str(port)))
        
        if (str(endValue) == "0"):
            self.__lnxnm_print_debug(2, "There is no operational incoming mapping for " + str(chassis) + "." + str(slot) + "." + str(port) + ".")
            return []
        
        # Change the result to a list
        endValue = self.__lnxnm_ifindex_to_csp(int(endValue))
        endValueString = '.'.join([str(y) for y in endValue])
        self.__lnxnm_print_debug(2, "Successfully got the operational incoming mapping for " + str(chassis) + "." + str(slot) + "." + str(port) + " which is " + endValueString + ".")
        return endValue
    
    # Map Display (Outgoing) (Future)
    
    
    ##### Protocol Selection
    # Return all protocols in an array (starting at index 0)
    def Lnxnm_get_protocol_list(self):
        self.__lnxnm_print_debug(2, "Returning the entire list of protocosl available on the MCC.")
        endList = []
        
        # Find out how many protocols there are, then create a list of protocols
    
        numOfProtocols = int(self.Lnxnm_get("1.3.6.1.4.1.629.200.2.1001"))
        
        for i in range(1, numOfProtocols + 1):
            # Find the family
            family = self.Lnxnm_get("1.3.6.1.4.1.629.200.2.1002.1.2." + str(i))
            
            # Find the rate
            endValue = self.Lnxnm_get("1.3.6.1.4.1.629.200.2.1002.1.3." + str(i))
            
            # Sometimes the rate is empty (do not append to endResult if so)
            if (len(endValue) != 0):
                endResult = str(family) + " " + str(endValue)
            else:
                endResult = str(family)
            endList.append([])
            endList[i - 1] = endResult
            
        return endList
    
    # Get Protocol (String) (Concatenates family/rate)
    def Lnxnm_get_port_protocol_string(self, chassis, slot, port):
        # Verify port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Verify port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
            
        self.__lnxnm_print_debug(2, "Finding the protocol string for " + str(chassis) + "." + str(slot) + "." + str(port) + ".")
        
        # Find the protocol number for the port
        protocolNum = self.Lnxnm_get_nbsCmmcPortProtoAdmin(chassis, slot, port)
        
        # Find the family
        family = self.Lnxnm_get("1.3.6.1.4.1.629.200.2.1002.1.2." + str(protocolNum))
        
        # Find the rate
        endValue = self.Lnxnm_get("1.3.6.1.4.1.629.200.2.1002.1.3." + str(protocolNum))
        
        # Sometimes the rate is empty (do not append to endResult if so)
        if (len(endValue) != 0):
            endResult = str(family) + " " + str(endValue)
        else:
            endResult = str(family)
        
        self.__lnxnm_print_debug(2, "Found the protocol string for " + str(chassis) + "." + str(slot) + "." + str(port) + " which is " + endResult + ".")
        return endResult
    
    # Return all protocols for a port in an array (if empty, no protocols are available)
    def Lnxnm_get_port_protocol_list(self, chassis, slot, port):
        # Returns a list of all protocols available for a port in the following form
        #   0       Index Of Protocol #1
        #   1       Protocol String #1
        #   2       Index of Protocol #2
        #   3       Protocol String #2
        #   Odd     Index of Protocol
        #   Even    Protocol String
    
        endList = []
    
        # Verify port has a valid CSP
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Verify port is not invalid (if strict syntax is used)
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        self.__lnxnm_print_debug(2, "Grabbing the entire list of protocols.")
        
        # Grab all protocols on the MCC
        protocolList = self.Lnxnm_get_protocol_list()
        
        # Find what protocols are available for a port
        # Use that information to build a port protocol list (comparing against the chassis protocol list)
        self.__lnxnm_print_debug(2, "Grabbing the protocols available for " + str(chassis) + "." + str(slot) + "." + str(port) + ".")
        
        # Grab all of the protocols supported by the port
        endValue = self.Lnxnm_get("1.3.6.1.4.1.629.200.8.1.1.72." + str(chassis) + "." + str(slot) + "." + str(port))
        
        # Get the raw binary string from the hexadecimal protocol capability string
        rawBinString = self.__lnxnm_hex2bin(''.join(endValue.split(":")))

        for i in range(0, len(rawBinString)):
            if (str(rawBinString[i]) == "1"):
                # Add the index
                endList.append(i)
                
                # Add the protocol string
                endList.append(protocolList[i - 1])
        return endList
        
        
    # Returns how long the NM has been up (in hundredths of seconds)
    def Lnxnm_get_uptime(self):
        self.__lnxnm_print_debug(2, "Attempting to get how long the network management module has been up and running.")
        
        # Get the time
        endValue = self.Lnxnm_get("1.3.6.1.2.1.1.3")
        
        self.__lnxnm_print_debug(3, "Successfully got the number of hundredth seconds the NM has been up which is " + endValue + ".")
        return endValue
    
    #######################################
    ########## Table Dump Functions #######
    #######################################
    # Dump the Port Table
    ##### BROKEN DUE TO READING IN DATA
    def Lnxnm_dump_table_port(self):
        # Return a dictionary filled with all attributes on all ports
        # The dictionary is indexed in the following model (using an array called "temp", note the user can set the array name
        #   to any name) -> temp['Chassis.Slot.Port', 'Object')]
        #
        # For example temp['1.2.3','nbsCmmcPortLIN']
        
        self.__lnxnm_print_debug(2, "Returning the port table.")
        slot_table = self.Lnxnm_dump_table("1.3.6.1.4.1.629.200.8.1.1")
        
        # Figure out how many rows and columns are in the table
        rows = len(slot_table)
        columns = len(slot_table[0])
        
        self.__lnxnm_print_debug(3, "The table has " + str(rows) + " rows and " + str(columns) + " columns.")
        
        retArr = {}
        columnName = []
        
        # Build a list of column names
        for x in range(columns):
            columnName.append(slot_table[0][x])
        
        for x in range(1,rows):
            for y in range(columns):
                retArr[slot_table[x][0] + "." + slot_table[x][1] + "." + slot_table[x][2], columnName[y]] = str(slot_table[x][y])
                self.__lnxnm_print_debug(3, "Adding [" + str(slot_table[x][0]) + "." + str(slot_table[x][1])+ "." + str(slot_table[x][2]) + "][" + str(columnName[y]) + "] = " +  str(slot_table[x][y]))
        return retArr
    
    # Dump the Slot Table
    def Lnxnm_dump_table_slot(self):
        # Return a dictionary filled with all attributes on all slots
        # The dictionary is indexed in the following model (using an array called "temp", note the user can set the array name
        #   to any name) -> temp['Chassis.Slot', 'Object')]
        #
        # For example temp['1.2','nbsCmmcSlotModuleType']
        
        self.__lnxnm_print_debug(2, "Returning the slot table.")
        slot_table = self.Lnxnm_dump_table("1.3.6.1.4.1.629.200.7.1.1")
        
        # Figure out how many rows and columns are in the table
        rows = len(slot_table)
        columns = len(slot_table[0])
        
        self.__lnxnm_print_debug(3, "The table has " + str(rows) + " rows and " + str(columns) + " columns.")
        
        retArr = {}
        columnName = []
        
        # Build a list of column names
        for x in range(columns):
            columnName.append(slot_table[0][x])
        
        for x in range(1,rows):
            for y in range(columns):
                retArr[slot_table[x][0] + "." + slot_table[x][1], columnName[y]] = str(slot_table[x][y])
                self.__lnxnm_print_debug(3, "Adding [" + str(slot_table[x][0]) + "." + str(slot_table[x][1])+ "][" + str(columnName[y]) + "] = " +  str(slot_table[x][y]))
        return retArr
           
    # Dump the Chassis Table
    def Lnxnm_dump_table_chassis(self):
        # Return a dictionary filled with all attributes on all chassis
        # The dictionary is indexed in the following model (using an dictionary
        #   called "temp", note the user can set the dictionary name
        #   to any name) -> temp['Chassis', 'Object')]
        #
        # For example temp['1','nbsCmmcChassisCrossConnect']
        
        self.__lnxnm_print_debug(2, "Returning the chassis table.")
        chassis_table = self.Lnxnm_dump_table("1.3.6.1.4.1.629.200.6.1.1")
        
        # Figure out how many rows and columns are in the table
        rows = len(chassis_table)
        columns = len(chassis_table[0])
        
        self.__lnxnm_print_debug(3, "The table has " + str(rows) + " rows and " + str(columns) + " columns.")
        
        retDict = {}
        columnName = []
        
        # Build a list of column names
        for x in range(columns):
            columnName.append(chassis_table[0][x])
        
        for x in range(1,rows):
            for y in range(columns):
                retDict[chassis_table[x][0], columnName[y]] = str(chassis_table[x][y])
                self.__lnxnm_print_debug(3, "Adding the following to retDict['" + str(chassis_table[x][0]) + "','" + str(columnName[y]) + "'] = " +  str(chassis_table[x][y]))
        return retDict
    
    # Dump the MetaMIB Features Table
    def Lnxnm_dump_table_metamib_feature(self):
        # Returns a dictionary
        #  The dictionary is indexed in the following model (using a dictionary
        #   called "temp", note the user can set the dictionary name
        #   to any name) -> temp[1, 'nbsMetaMibFeatureFamily']
        #  The output of the above above will return the MetaMIB Feature Family for the first feature in the table
    
        self.__lnxnm_print_debug(3, "Returning the metamib features table.")
        endValue = self.Lnxnm_dump_table("1.3.6.1.4.1.629.205.1.2.1")

        # Figure out how many rows and columns are in the table
        rows = len(endValue); # The second (row 0) and last row (".") are useless
        columns = len(endValue[0])
        self.__lnxnm_print_debug(3, "The table has rows " + str(rows) + " and " + str(columns) + " columns.")
        
        retDict = {}
        columnName = []
        
        # Build a list of column names
        for x in range(columns):
            columnName.append(endValue[0][x])
            
        # Skip the first two columns (header and the (null) row)
        for i in range(2,rows):
            # Build list to return
            tempList = []
            for j in range(columns):
		tempValue = endValue[i][j]
		tempValue = str(tempValue)
		tempValue = tempValue.lower()
                retDict[i-1, columnName[j]] = tempValue
                self.__lnxnm_print_debug(3, "Adding the following to retDict[" + str(i-1) + ",'" + str(columnName[j])  + "'] : " + str(tempValue) + ".")
        return retDict
    
    # Dump the MetaMIB Variables Table
    def Lnxnm_dump_table_metamib_variable(self):
        # Returns a dictionary
        #  The dictionary is indexed in the following model (using a dictionary
        #   called "temp", note the user can set the dictionary name
        #   to any name) -> temp['102001', 'nbsMetaMibVariableAdmin']
        #  The output of the above above will return the MetaMIB Variable admin value for port 1.2.1 (IfIndex notation is used)
    
        self.__lnxnm_print_debug(3, "Returning the metamib variables table.")
        endValue = self.Lnxnm_dump_table("1.3.6.1.4.1.629.205.1.4.1")

        # Figure out how many rows and columns are in the table
        rows = len(endValue); # The second (row 0) and last row (".") are useless
        columns = len(endValue[0])
        self.__lnxnm_print_debug(3, "The table has rows " + str(rows) + " and " + str(columns) + " columns.")
        
        retDict = {}
        columnName = []
        
        # Build a list of column names
        for x in range(columns):
            columnName.append(endValue[0][x])
            
        # Skip the first column (header)
        for i in range(1,rows):
            # Build list to return
            tempList = []
            featID = 0
            # Figure out the nbsMetaMibVariableID
            for j in range(columns):
		if (columnName[j] == "nbsMetaMibVariableID"):
			featID = endValue[i][j]
            for j in range(columns):
                retDict[endValue[i][0], featID, columnName[j]] = endValue[i][j]
		self.__lnxnm_print_debug(3, "Adding the following to retDict['" + str(endValue[i][0]) + "', '" + str(featID) + "', '" + str(columnName[j])  + "'] : " + str(endValue[i][j]) + ".")
        return retDict
        
    # Return a dictionary of incoming mappings (admin)
    def Lnxnm_dump_table_mapping_admin(self):
        #  The dictionary is indexed in the following model (using a dictionary
        #   called "temp", note the user can set the dictionary name
        #   to any name) -> temp['1.2.3']
        #  The output of the above above will return the incoming mapping for the port (in a 3-item list)
        
        retDict = {}
        
        self.__lnxnm_print_debug(3, "Returning the admin mapping table.")
        endValue1 = self.Lnxnm_dump_table_slot()

        # Figure out which slots are relevant MCC slots
        relevantSlotList = []
        for i in endValue1.keys():
            slotNum = i[0].strip("\'")
            slotFeature = i[1].strip("\'")
            if (slotFeature == "nbsCmmcSlotOperationType" and endValue1[i] == "physLayerSwitch"):
                relevantSlotList.append(slotNum)
        
        # Dump the entire port table
        endValue2 = self.Lnxnm_dump_table_port()
        for i in endValue2.keys():
            portNum = i[0].strip("\'")
            portFeature = i[1].strip("\'")
            slotString = endValue2[portNum, 'nbsCmmcPortChassisIndex'] + "." + endValue2[portNum, 'nbsCmmcPortSlotIndex']
            
            if (portFeature == "nbsCmmcPortZoneIfIndexAdmin"):
                for j in relevantSlotList:
                    if (slotString == j):
                        tempList = self.__lnxnm_ifindex_to_csp(str(endValue2[i]))
                        retDict[portNum] = tempList
                        
        self.__lnxnm_print_debug(3, "The table has " + str(len(retDict)) + " mappings.")
        return retDict
    
    # Return a dictionary of incoming mappings (operational)
    def Lnxnm_dump_table_mapping_oper(self):
        #  The dictionary is indexed in the following model (using a dictionary
        #   called "temp", note the user can set the dictionary name
        #   to any name) -> temp['1.2.3']
        #  The output of the above above will return the incoming mapping for the port (in a 3-item list)
        
        retDict = {}
        
        self.__lnxnm_print_debug(3, "Returning the oper mapping table.")
        endValue1 = self.Lnxnm_dump_table_slot()

        # Figure out which slots are relevant MCC slots
        relevantSlotList = []
        for i in endValue1.keys():
            slotNum = i[0].strip("\'")
            slotFeature = i[1].strip("\'")
            if (slotFeature == "nbsCmmcSlotOperationType" and endValue1[i] == "physLayerSwitch"):
                relevantSlotList.append(slotNum)
        
        # Dump the entire port table
        endValue2 = self.Lnxnm_dump_table_port()
        for i in endValue2.keys():
            portNum = i[0].strip("\'")
            portFeature = i[1].strip("\'")
            slotString = endValue2[portNum, 'nbsCmmcPortChassisIndex'] + "." + endValue2[portNum, 'nbsCmmcPortSlotIndex']
            
            if (portFeature == "nbsCmmcPortZoneIfIndexOper"):
                for j in relevantSlotList:
                    if (slotString == j):
                        tempList = self.__lnxnm_ifindex_to_csp(str(endValue2[i]))
                        retDict[portNum] = tempList
                        
        self.__lnxnm_print_debug(3, "The table has " + str(len(retDict)) + "mappings.")
        return retDict
    
    #######################################
    ########## Source Functions ###########
    #######################################
    # Return all (src) files
    def Lnxnm_source_dump_table(self):
        # Return a dictionary (keyed by source file name)
        # Each item in dictionary will be composed of a list with two items
        #   Item #1 - The description of the file
        #   Item #2 - The file version (used in PathFinder)
        
        self.__lnxnm_print_debug(2, "Returning the source table.")
        endValue = self.Lnxnm_dump_table("1.3.6.1.4.1.629.208.1.2.1")
        
        # Figure out how many rows and columns are in the table
        rows = len(endValue)
        self.__lnxnm_print_debug(3, "The table has " + str(rows) + " rows.")
        
        retDict = {}
        
        skipHeader = 0;
        for i in endValue:
            if (skipHeader):
                # Skip the header
                tempList = []
                tempList.append(i[1])
                tempList.append(i[2])
                retDict[i[0]] = tempList
                self.__lnxnm_print_debug(3, "Adding the following source file: name = \"" + i[0] + "\" description = \"" + i[1] + "\" version = \"" + i[2] + "\".")        
            skipHeader = 1
            
        return retDict

    # Load a source file
    def Lnxnm_source_load(self, sourceFile):
        self.__lnxnm_print_debug(2, "Adding to source the file \"" + str(sourceFile) + "\".")
        # Does the file exist? 1 = yes, 0 = no
        fileExists = 0
        listOfSource = self.Lnxnm_source_dump_table()
        
        self.__lnxnm_print_debug(3, "Searching for the file \"" + str(sourceFile) + "\" within the list of source files.")
        for i in listOfSource.keys():
            if (i == sourceFile):
                self.__lnxnm_print_debug(3, "Found a match.")
                # The source file desired exists
                fileExists = 1
                self.__lnxnm_print_debug(3, "Loading the file.")
                self.Lnxnm_set_enum("1.3.6.1.4.1.629.208.1.2.1.4.\"" + str(sourceFile) + "\"",2,3)
            
            
        if (fileExists):
            self.__lnxnm_print_debug(3, "Sourcing of file \"" + str(sourceFile) + "\" was successful.")
            return 1
        else:
            self.__lnxnm_print_debug(3, "Sourcing of file \"" + str(sourceFile) + "\" was not successful.")
            raise mccSourceUnavailable("source file not found: the source file \"" + str(sourceFile) + "\" was not found.")
    
    # Delete a source file
    def Lnxnm_source_delete(self, sourceFile):
        self.__lnxnm_print_debug(2, "Attempting to delete the file \"" + str(sourceFile) + "\".")
        # Does the file exist? 1 = yes, 0 = no
        fileExists = 0
        listOfSource = self.Lnxnm_source_dump_table()
        
        self.__lnxnm_print_debug(3, "Searching for the file \"" + str(sourceFile) + "\" within the list of source files.")
        for i in listOfSource.keys():
            if (i == sourceFile):
                self.__lnxnm_print_debug(3, "Found a match.")
                # The source file desired exists
                fileExists = 1
                self.__lnxnm_print_debug(3, "Deleting the file.")
                self.Lnxnm_set_enum("1.3.6.1.4.1.629.208.1.2.1.4.\"" + str(sourceFile) + "\"",3,3)
            
            
        if (fileExists):
            self.__lnxnm_print_debug(3, "Deleting of file \"" + str(sourceFile) + "\" was successful.")
            return 1
        else:
            self.__lnxnm_print_debug(3, "Deleting of file \"" + str(sourceFile) + "\" was not successful.")
            raise mccSourceUnavailable("source file not found: the source file \"" + str(sourceFile) + "\" was not found.")        
    
    #######################################
    ########## Strict Function ############
    #######################################
    def Lnxnm_strict_on(self):
        self.strict_syntax = 1;
        self.__lnxnm_print_debug(2, "Turning strict element checking on")
        return 1

    def Lnxnm_strict_off(self):
        self.strict_syntax = 0;
        self.__lnxnm_print_debug(2, "Turning strict element checking on")
        return 1
    
    def Lnxnm_get_strict(self):
        return self.strict_syntax

    #######################################
    ############## Logging Functions ######
    #######################################
    ###############################
    #### Command Logging ##########
    ###############################
    # Turn on logging
    def Lnxnm_logging_on(self, writeFile = "mcc_log.txt"):
        # Check if logging is already on
        if ( self.logging == 1):
            self.logging_file.close()
        
        self.logging = 1
        self.logging_file_name = writeFile
        
        # Do not remove the file if it exists, just append to it
        self.logging_file = open(writeFile, 'a')
        
        return 1    
    
    # Turn off logging
    def Lnxnm_logging_off(self):
        # Close the log file if needed
        if ( self.logging == 1 ):
            # Close the original file
            self.logging_file.close()
        self.logging = 0;
        return 1
    
    # Are we logging?
    def Lnxnm_get_logging(self):
        # Returns
        #   0 = Not Logging
        #   1 = Logging
        if ( self.logging == 1 ):
            return 1
        return 0
    
    # Return the filename used for logging (null sgtring returned if not logging)
    def Lnxnm_get_logging_file_name(self):
        if ( self.logging == 0 ):
            return ""
        return self.logging_file_name    
    
    ###############################
    #### Debug Logging ############
    ###############################
    # Turn on the debug log
    def Lnxnm_debug_on(self, level = 1, writeFile = "mcc_debug.txt"):
        # Check if debug logging already
        if ( self.debug > 0):
            self.debug_file.close()
        
        self.debug = level
        self.debug_file_name = writeFile
        
        # Do not remove the file if it exists, just append to it
        self.debug_file = open(writeFile, 'a')
        
        # Print the environment information to file
        self.debug_file.write("\nEnvironment Settings")
        self.debug_file.write("\n---------------------------------------------------------")
        self.debug_file.write("\nThis file was executed at " + strftime("%x %X", time.localtime(self.time_started)));
        self.debug_file.write("\nPython Version = " + platform.python_version());
        self.debug_file.write("\nOperating System = " + platform.system());
        self.debug_file.write("\nPlatform = " + platform.platform());
        self.debug_file.write("\nHostname = " + platform.node() );
        # Following line is broken in Windows
        #self.debug_file.write("\nUsername= " + os.getusername());
        self.debug_file.write("\nUsername= " + getpass.getuser());
        self.debug_file.write("\n---------------------------------------------------------\n\n")
        return 1
    
    # Turn off the debug log
    def Lnxnm_debug_off(self):
        if ( self.debug > 0 ):
            self.debug_file.close()
        self.debug = -1;
        return 1
    
    # Return the debug level
    def Lnxnm_get_debug(self):
        # 0 = Not Logging
        # > 0 Logging (Plus what level we are using)
        if ( self.debug > 0 ):
            return self.debug
        return 0
    
    # Set the debug level
    def Lnxnm_set_debug_level(self, level = 1):
        # Returns debug or 0 if we are not debug logging
        if ( self.debug != -1):
            if ( level > 3 ):
                # The debug level should never be set higher than three
                self.debug = 3
            elif (level < 1) :
                #The debug level should never be set lower than 1
                self.debug = 1
            else:
                self.debug = level
        else:
            return 0
        
        return self.debug
    
    # Return the filename used for debug logging (Return a null string if not debug logging)
    def Lnxnm_get_debug_file_name(self):
        if ( self.debug == -1 ):
            return ""
        return self.debug_file_name 

    ####################################################################
    ## End of Public Functions #########################################
    ####################################################################
    #
    ####################################################################
    ## Private Functions ###############################################
    ####################################################################
    #######################################
    ####### Read/Send Line Functions ######
    #######################################
    # Read a line from the API session
    ##### TURNS OUT WE CANT JUST READ A SINGLE LINE, WE READ THE ENTIRE CONTENTS!
    # For clean socket reads with an initial operation code, return that value 
    #   as the first item in the list. Otherwise, just return the string as is 
    #   without a leading operation code
    
    def __lnxnm_read_long_lines(self):
        # Read the entire output of the socket 
        #   On the first read there should NOT be a timeout
        #   After then, a timeout is expected, just return the entire string output from the previous reads
        self.ssl_sock.settimeout(5)
        
        # The first read should be successful
        try:
             tempString = self.ssl_sock.recv(1024)
        except socket.sslerror, msg:
            print "Timeout - Read Failure -> " + str(msg)
            sys.exit()
        
        # Continue reading from the socket until nothing is left to read
        while (1):
            # An assumption is made that the socket is not going to fail at this point since the first read was OK
            try :
                tempString += self.ssl_sock.recv(1024)
            except socket.timeout, msg:
                self.__lnxnm_print_debug(2, "Timeout - Continue Reading")
            except socket.sslerror, msg:
                break
        
        # Pull out the return code
        tempList = tempString.split('\r\n')
        tempCode = tempList.pop(0).split().pop(0)
        
        # Split the entire string using a newline delimiter
        tempList = tempString.split('\r\n')
        myList = []
        if (tempCode.isdigit()):
            myList.append(int(tempCode))
        myList.append(tempList)
        
        # Create a string to output to file
        #####
        ##### Currently we are sending the output enclosed in brackets
        #####
        tempString = ""
        for tempLine in myList:
            tempValue = str(tempLine)
            if (tempValue.isdigit() != 1):
                tempString = tempString + str(tempValue)
            
        # Write to the debug file
        self.__lnxnm_print_debug(2, "Read - " + tempString)
        
        # Write to the log file
        self.__lnxnm_print_log(tempString)
        
        # Return the lines read
        return myList
    
    
    def __lnxnm_read_lines(self):
        # Read the entire output of the socket (do only one read)
        self.ssl_sock.settimeout(5)
        
        tempString = ""
        
        # The first read should be successful
        try_count = 0
        while(1):
            try:
                 tempString += self.ssl_sock.recv(1024)
                 break;
            except socket.timeout, msg:
                self.__lnxnm_print_debug(2, "Timeout - Continue Reading")
            except socket.sslerror, msg:
                try_count += 1
                if try_count > 3:
                    print "Timeout - Read Failure -> " + str(msg)
                    raise mccUnknown("Unknown SSL error")
                time.sleep(0.3)
                #print "Timeout - Read Failure -> " + str(msg)
                #sys.exit()
        
        # Pull out the return code
        tempList = tempString.split('\r\n')
        tempCode = tempList.pop(0).split().pop(0)
        
        # Split the entire string using a newline delimiter
        tempList = tempString.split('\r\n')
        myList = []
        if (tempCode.isdigit()):
            myList.append(int(tempCode))
        myList.append(tempList)
        
        # Create a string to output to file
        #####
        ##### Currently we are sending the output enclosed in brackets
        #####
        tempString = ""
        for tempLine in myList:
            tempValue = str(tempLine)
            if (tempValue.isdigit() != 1):
                tempString = tempString + str(tempValue)
            
        # Write to the debug file
        self.__lnxnm_print_debug(2, "Read - " + tempString)
        
        # Write to the log file
        self.__lnxnm_print_log(tempString)
        
        # Return the lines read
        return myList    
    
    # Send a line to the API session
    def __lnxnm_write_line(self,tempString):
        numOfBytes = self.ssl_sock.send( tempString + "\r")
            
        # Write to the debug file
        self.__lnxnm_print_debug(2, "Write - " + tempString)
        
        # Write to the log file
        self.__lnxnm_print_log(tempString)
        
        # By sleeping a millissecond after sending the command, we never see a problem
        #   when trying to read back from the socket
        time.sleep(0.2)
        
        # Increment the command counter
        self.command_count = self.command_count + 1
        return 1
        
    #######################################
    ############## Logging Functions ######
    #######################################
    def __lnxnm_print_debug(self, level, messageToPrint):
        # Print the following to file
        # Time-Stamp
        # Command Count
        # Message
        
        timeOfCommand = strftime("%Y-%m-%d-%H-%M-%S")
        
        # Only print to file if the user wishes to
        if (self.debug >= level):
            self.debug_file.write(timeOfCommand + "\t" + str(self.command_count) + "\t" + messageToPrint + "\n")
        return 1
    
    def __lnxnm_print_log(self, cmdToSend = "N/A"):
        # Success
        # 0 = Failed
        # 1 = Passed
        
        timeOfCommand = strftime("%Y-%m-%d-%H-%M-%S")
        
        # Only print to file if the user wishes to
        if ( self.logging == 1 ):
            self.logging_file.write(timeOfCommand + "\t" + str(self.command_count) + "\t" + cmdToSend + "\n")
        return 1
    
    #######################################
    ############## Check Functions ########
    ####################################### 
    # Check that a CSP is the correct format
    def __lnxnm_check_csp(self, *args):
        # Return 1 is correct, throw an error otherwise
        # Location string (used for the error message)
        locString = " "
        
        if ( len(args) == 1 ):
            # Chassis
            # Chassis can only be the number "1"
            if ( args[0] == 1):
                return 1
            locString = str(args[0])
        elif ( len(args) == 2 ):
            # Slot
            # Chassis can only be the number "1" and Slot must be between 1 and 10
            if ( args[0] == 1 and args[1] > 0 and args[1] < 11):
                return 1
            locString = str(args[0]) + "." + str(args[1])
        elif (len(args) == 3):
            # Port
            # Chassis can only be the number "1" and Slot must be between 1 and 10
            #   and Port must be between 1 and 36
            if ( args[0] == 1 and args[1] > 0 and args[1] < 11 and args[2] > 0 and args[2] < 37):
                return 1
            locString = str(args[0]) + "." + str(args[1]) + "." + str(args[2])            
        
        errorString = 'location syntax incorrect: the location \"' + locString + '\" is not formatted correctly'
        raise mccLocSynFail(errorString)
        return 0    
    
    # Check if a string is a valid IP address (not too stringent [i.e. 0.0.0.0 is accepted])
    def __lnxnm_check_ip(self, ip):
        # First Stage - Strip all periods and create a list of IP segments
        numList = ip.split(".")
        
        # Second Stage - Verify four IP segments were sent
        if ( len(numList) != 4):
            return 0
        
        # Third Stage - Check each IP segment is a number and is between 0 and 255
        for i in numList:
            if ( i.isdigit() == 0 or int(i) < 0 or int(i) > 255 ):
                return 0
            
        # Successful IP address
        return 1
    
    # Check if a string is a valid BYTE string (hex)
    def __lnxnm_check_byte(self, bytes):
        # Return 0 if the BYTE string is incorrect
        # Returns a positive integer if correct (the integer
        #   will correspond go the number of BYTES in the string
        
        # First Stage - Strip all colons and create a list of BYTE segments
        byteList = bytes.split(":")
        
        # Second Stage - Check each BYTE segment contains two characters
        #   Each character must be a digit or a letter between A-F (upper or lower case)
        
        for i in byteList:
            # Reject if we don't have two characters
            if ( len(i) != 2):
                return 0
            # Check each digit is a valid hex digit (0-F)
            for j in [ ord( i[0].upper() ), ord( i[1].upper() ) ]:
                if ( not( j >= ord('0') and j <= ord('9')) and not( j >= ord('A') and j <= ord('F')) ):
                    return 0                                                
       
        return (len(byteList) * 2)
    
    # Join a list together with a period to make it a C.S.P
    def __lnxnm_list_to_csp (self, c_list):
        if ( len(c_list) != 3):
            errorString = 'bad argument list: the list \"' + str(c_list) + '\" is not composed of three items but rather ' + str(len(c_list)) + ' items'
            raise mccBadArgList(errorString)
        
        # Make sure each item is a number
        for i in c_list:
            i = str(i)
            if ( i.isdigit() == 0 ):
                errorString = 'invalid argument: the item \"' + i + '\" is not a digit and fails the C.S.P requirement'
                raise mccInvalidArg(errorString)
        return ".".join(map(str,c_list))
                
    # Parse a C.S.P and return a list of three items
    def __lnxnm_csp_to_list(self, csp):
        c_list = csp.split(".")
        
        # Make sure there are three items in the list (throw an error if not)
        if ( len(c_list) != 3 ):
            errorString = 'bad argument list: the C.S.P \"' + csp + '\" is not composed of three items but rather ' + str(len(c_list)) + ' items'
            raise mccBadArgList(errorString)
        
        # Make sure each item is a number
        for i in c_list:
            if ( i.isdigit() == 0 ):
                errorString = 'invalid argument: the item \"' + i + '\" is not a digit and fails the C.S.P requirement'
                raise mccInvalidArg(errorString)
        return c_list
    
    # Parse a C.S and return a list of three items
    def __lnxnm_cs_to_list(self, cs):
        c_list = cs.split(".")
        
        # Make sure there are three items in the list (throw an error if not)
        if ( len(c_list) != 2 ):
            errorString = 'bad argument list: the C.S \"' + cs + '\" is not composed of two items but rather ' + str(len(c_list)) + ' items'
            raise mccBadArgList(errorString)
        
        # Make sure each item is a number
        for i in c_list:
            if ( i.isdigit() == 0 ):
                errorString = 'invalid argument: the item \"' + i + '\" is not a digit and fails the C.S requirement'
                raise mccInvalidArg(errorString)
        return c_list    
        
    # Convert a hex number to binary
    def __lnxnm_hex2bin (self, hexString):
        # Due to leading zero's issue, figure out how many characters we need
        #   and use this for padding the answer
        tempBin = str(bin(int(hexString, 16))[2:])
        numOfCharsToPad = len(hexString) * 4 - len(tempBin)
        for x in range(0, numOfCharsToPad):
            tempBin = "0" + tempBin
        return tempBin

    # Convert a CSP into an ifIndex
    def __lnxnm_csp_to_ifIndex (self, *args):
        if ( len(args) == 3 ):
            chassis = args[0]
            slot = args[1]
            port = args[2]
        elif ( len(args) == 2 ):
            chassis = args[0]
            slot = args[1]
            port = 0
        elif ( len(args) == 1 ):
            chassis = args[0]
            slot = 0
            port = 0
        else:
            # Wrong number of arguments used
            return 0        
        return ( int(chassis) * 100000 ) + ( int(slot) * 1000 ) + int(port)

    # Convert an ifIndex into a list of three items (chassis/slot/port)
    def __lnxnm_ifindex_to_csp(self, ifIndex):
        ifIndex = int(ifIndex)
        chassis = ifIndex / 100000
        slot = ( ifIndex % 100000 ) / 1000
        port = ( ifIndex % 100000 ) % 1000
        return [ chassis, slot, port ]
        
    # Check if an element exists (only to be used when strict element enforcment is being used)
    def __lnxnm_check_element_exists(self, *args):
        # Return 1 is the element exists, throw an error otherwise
        
        # Number of Slots in a Chassis OID
        num_of_slots_oid = "1.3.6.1.4.1.629.200.6.1.1.5"
    
        # Number of Ports in a Slot OID
        num_of_ports_oid = "1.3.6.1.4.1.629.200.7.1.1.6"
        
        if (len(args) == 1):
            # Chassis
            
            errorString = "location not available: the location " + str(args[0]) + " is not available"
            
            # Chassis can only be the number 1
            if (str(args[0]) != "1"):
                raise mccLocNotAvail(errorString)
            
            return 1
        elif (len(args) == 2):
            # Slot
            
            errorString = "location not available: the location " + str(args[0]) + "." + str(args[1]) + " is not available"
            
            # Chassis can only be the number 1
            if (str(args[0]) != "1"):
                raise mccLocNotAvail(errorString)
                
            # Grab the number of slots on the chassis
            endValue = self.Lnxnm_get(num_of_slots_oid + ".1")
            
            # Successful GET command
            self.__lnxnm_print_debug(3, "The GET command successfully returned.")
            numOfSlots = endValue
            
            # Verify the slot number given is a digit
            tempSlot = str(args[1])
            if (tempSlot.isdigit() == 0):
                raise mccLocNotAvail(errorString)
            
            # Slot must be between 1 and the number of slots (if it exists)
            if (args[1] < 1 or args[1] > numOfSlots):
                raise mccLocNotAvail(errorString)
            
            # Find if a port exists on the blade (this is a hack to make sure the slot exists)
            # Grab the number of ports on the slot (will return an error if there are no ports in a non-plugged-in slot)
            endValue = self.Lnxnm_get(num_of_ports_oid + ".1." + str(args[1]))
            # Successful GET command
            self.__lnxnm_print_debug(3, "The GET command successfully returned.")
            numOfPorts = endValue
            
            # Port must be between 1 and the number of ports on the slot
            if (str(numOfPorts) == "0"):
                raise mccLocNotAvail(errorString)
            return 1
        elif (len(args) == 3):
            # Port
            
            errorString = "location not available: the location " + str(args[0]) + "." + str(args[1]) + "." + str(args[2]) + " is not available"
            
            # Chassis can only be the number 1
            if (str(args[0]) != "1"):
                raise mccLocNotAvail(errorString)
                
            # Grab the number of slots on the chassis
            endValue = self.Lnxnm_get(num_of_slots_oid + ".1")
            
            # Successful GET command
            self.__lnxnm_print_debug(3, "The GET command successfully returned.")
            numOfSlots = endValue
            
            # Verify the slot number given is a digit
            tempSlot = str(args[1])
            if (tempSlot.isdigit() == 0):
                raise mccLocNotAvail(errorString)
            
            # Slot must be between 1 and the number of slots (if it exists)
            if (int(args[1]) < 1 or int(args[1]) > int(numOfSlots)):
                raise mccLocNotAvail(errorString)
                
            # Verify the port number given is a digit
            tempPort = str(args[2])
            if (tempPort.isdigit() == 0):
                raise mccLocNotAvail(errorString)
            
            # Grab the number of ports on the slot
            endValue = self.Lnxnm_get(num_of_ports_oid + ".1." + str(args[1]))
            # Successful GET command
            self.__lnxnm_print_debug(3, "The GET command successfully returned.")
            numOfPorts = endValue
            
            # Port must be between 1 and the number of ports on the slot
            if (int(args[2]) < 1 or int(args[2]) > int(numOfPorts) ):
                raise mccLocNotAvail(errorString)
            return 1
        raise mccLocNotAvail("location not available: the location \"" + '.'.join([str(y) for y in args]) + "\" is not available")
    
    # Check if an OID is valid (ONLY TO THE MRV PROPRIETARY MIB)
    def __lnxnm_check_oid(self, oid):
        # Check if the given OID is a syntactically correct
        # Also check if the OID starts with 1.3.6.1.4.1.629.200.
        oid = str(oid)
        
        # First Stage - Check the OID starts correctly
        if (re.match("1.3.6.1.4.1.629.200.", oid)):
            # Second Stage - Check the OID doesn't end with a period (the first period has been checked in stage #1)
            #p = re.compile('.*\.')
            
            #if (p.match('.*\.', oid)):
            if (re.compile('.*\.$').search(oid,1)):
                return 0
            
            # Third Stage - Remove all periods and check only numbers exist
            numList = oid.split(".")
            for x in numList:
                if (x.isdigit() == 0):
                    return 0
            # Successful OID
            return 1
        return 0
    
    # Return the best guess as to what version should
    #   be used according to the version passed
    # Unsure this is used at all in Python
    def __lnxnm_return_version(self, tempString):
        # First pass
        #  Check against the library of past releases
        #   revHistory stores the "string" and "release" in pairs
        revHistory = []
        revHistory.append("v4.3 mcc 02")
        revHistory.append("4.3.2.0")
        revHistory.append("v4.3 mcc 02a")
        revHistory.append("4.3.2.0")
        revHistory.append("v4.3 mcc 03")
        revHistory.append("4.3.3.0")        
        revHistory.append("v4.3 mcc 03a")
        revHistory.append("4.3.3.0")
        revHistory.append("v4.3 mcc 03b")
        revHistory.append("4.3.3.0")
        revHistory.append("v4.4 mcc 01")
        revHistory.append("4.4.1.0")
        revHistory.append("v4.4 mcc 01a")
        revHistory.append("4.4.1.0")
        revHistory.append("v4.4 mcc 03")
        revHistory.append("4.4.3.0")
        revHistory.append("v4.4 mcc 05")
        revHistory.append("4.4.5.0")
        revHistory.append("v4.6 mcc 01")
        revHistory.append("4.6.1.0")
        revHistory.append("v4.6 mcc 02")
        revHistory.append("4.6.2.0")
        revHistory.append("v4.6 mcc 02a")
        revHistory.append("4.6.2.0")
        revHistory.append("v4.6 mcc 03")
        revHistory.append("4.6.3.0")     
        revHistory.append("v4.6 mcc 04")
        revHistory.append("4.6.4.0")
        revHistory.append("v4.8 mcc 01")
        revHistory.append("4.8.1.0")
        revHistory.append("v4.8 mcc 02")
        revHistory.append("4.8.2.0")
        revHistory.append("v4.8 mcc 03")
        revHistory.append("4.8.3.0")
        revHistory.append("v4.8 mcc 04")
        revHistory.append("4.8.4.0")
        
        for x in range(0,len(revHistory)):
            if (x % 2 == 0):
                if (revHistory[x] == str(tempString)):
                    return revHistory[x+1]
        
        # Second pass
        #  Try to figure out the release by parsing the string
        numBlockCount = 0; # Number of number blocks
        startNum = 0; # Bit to hold if we are starting a new numberBlock or not
        numBlock = []; # Keep all blocks in a list
        tempBlock = ""; #Temporary string for the current block
        
        # Add a character to the end of the string to make sure we count correctly
        updatedString = tempString + "X"
        for x in range (0, len(updatedString)):
            currChar = updatedString[x]
            if (currChar.isdigit()):
                # Character is a number
                if (startNum == 0):
                    startNum += 1
                    numBlockCount += 1
                    tempBlock = ""
                # Add the character to the tempblock
                tempBlock = tempBlock + currChar
            else:
                # Character is not a number
                if (startNum == 1):
                    # Closing a numberblock [get rid of leading zeroes]
                    numBlock.append(tempBlock.lstrip("0"))
                    startNum -= 1
            # Do not go over 3 number blocks
            if (numBlockCount > 3):
                # Escape
                break
        
        # Make sure we get at least 3 number blocks
        if (numBlockCount >= 3):
            return numBlock[0] + "." + numBlock[1] + "." + numBlock[2] + ".0"
        
        # If all else fails, return an error
        raise mccUnrecVer("version package not found for software version being used: the version" + str(tempString) + " was not recognized")
    
    # Return the feature ID of an object
    def __lnxnm_find_meta_feature(self, featureFamily, featureName, featureType, featureUnits):
        featureFamily = str(featureFamily)
        featureName = str(featureName)
        featureType = str(featureType)
        featureUnits = str(featureUnits)
	featureFamily = featureFamily.lower()
        featureName = featureName.lower()
        featureType = featureType.lower()
        featureUnits = featureUnits.lower()
        self.__lnxnm_print_debug(3, "Attempting to find the feature \"" + featureFamily + " ," + featureName + " ," + featureType  + " ," + featureUnits + "\".")
        
        for i in range(1,len(self.meta_mib_feature_array.keys())/6):
            if (self.meta_mib_feature_array[i,'nbsMetaMibFeatureFamily'] == featureFamily):
                if (self.meta_mib_feature_array[i,'nbsMetaMibFeatureName'] == featureName): 
                    if (self.meta_mib_feature_array[i,'nbsMetaMibFeatureType'] == featureType):
                        if (self.meta_mib_feature_array[i,'nbsMetaMibFeatureUnits'] == featureUnits):
                             return i
          
        raise mccMetaFeatureInvalid("invalid nbsMetaMib feature: the desired feature \"" + featureFamily + " ," + featureName + " ," + featureType  + " ," + featureUnits + "\" doesn't match anything in the features table")
      
    # Return whether a feature exists for a location
    def __lnxnm_exists_meta_variable(self, featureId, *args):
        # Return 1 = Exists
        # Exception = Doesn't Exist
        
        if (len(args) == 1):
            tempIfIndex = self.__lnxnm_csp_to_ifIndex(args[0])
            tempLoc = str(args[0])
            self.__lnxnm_print_debug(3, "Attempting to find the feature #" + str(featureId) + " for \"" + str(tempLoc) + "\".")
        elif (len(args) == 2):
            tempIfIndex = self.__lnxnm_csp_to_ifIndex(args[0], args[1])
            tempLoc = str(args[0]) + "." + str(args[1])
            self.__lnxnm_print_debug(3, "Attempting to find the feature #" + str(featureId) + " for \"" + str(tempLoc) + "\".")            
        elif (len(args) == 3):
            tempIfIndex = self.__lnxnm_csp_to_ifIndex(args[0], args[1], args[2])
            tempLoc = str(args[0]) + "." + str(args[1]) + "." + str(args[2])
            self.__lnxnm_print_debug(3, "Attempting to find the feature #" + str(featureId) + " for \"" + str(tempLoc) + "\".")
        else:
            raise mccMetaFeatureInvalid("bad argument list: the wrong number of arguments were used for the location. One, two, or three items should have been used. The arguments were \"" + str(args) + "\"")
           
        # Traverse the variables table
        variableArray = self.Lnxnm_dump_table_metamib_variable()
	tempString = str("('" + str(tempIfIndex) + "', '" + str(featureId) + "', 'nbsMetaMibVariableIfIndex')")
	for key in variableArray.keys():
		if (str(key) == tempString):
			return 1
        raise mccMetaFeatureInvalid("element doesn't have feature: the desired feature #" + str(featureId) + " doesn't exist for the location #" + tempLoc)
    
    # Check if a number is a float
    # Returns 1 if true, 0 otherwise
    def __lnxnm_float_check(self, number):
        # Go through all characters in the string (only accept numbers, up to a single E, up to a single dash, up to a single decimal place)
        e = 0
        dash = 0
        decimal = 0
        number = str(number)
        for x in range(0,len(number)):
            if (number[x] == "e" or number[x] == "E"):
                e = e + 1
                if (e > 1):
                    return 0
                continue
            if (number[x] == "-"):
                dash = dash + 1
                if (dash > 1):
                    return 0                
                continue            
            if (number[x] == "."):
                decimal = decimal + 1
                if (decimal > 2):
                    return 0                                
                continue
            if (number[x].isdigit() == 0):
                return 0
        
        # Periods can't be at the end of the string
        if (number[len(number)-1] == "."):
            return 0
        
        # E's cant be at the end of a string
        if (number[len(number)-1] == "e" or number[len(number)-1] == "E"):
            return 0
        
        # Dash's can't be at the end of a string (they can be in the middle, for example "3E-5")
        if (number[len(number)-1] == "-"):
            return 0
        return 1
    
    def __lnxnm_isNumber(self, value):
        value = str(value)
        if (len(value) == 1):
            if (value.isdigit() == 0):
                return 0
        else:
            if (value[0:1] == "-"):
               if (value[1:].isdigit() == 1):
                   return 1
               else:
                   return 0
            else:
                if (value[0:].isdigit() == 0):
                    return 0
        return 1
              


	# This code is auto generated via the MIB file (mrv-mcc.mib)
	# 
	# There are some special functions to deal with composition of objects
	#   For example MCC mapping and protocol selection/retrieval
	#
	# Only those objects with the correct Syntax will have Tcl procedures
	# Only the objects with the following parameters will have GET procedures
	#	MAX-ACCESS = read-write
	#	MAX-ACCESS = read-only
	#
	# Only the objects with the following parameters will have SET procedures
	#	MAX-ACCESS = read-write
	#
	
	
    #### Start - Chassis - nbsCmmcChassisModel #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.3
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 50
    #
    #	Description: 
    #	
    #	The model name of the chassis.
    #	
    def Lnxnm_get_nbsCmmcChassisModel(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.3"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisModel #### 
    #### Start - Chassis - nbsCmmcChassisNumberOfSlots #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.5
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The number of slots in the Chassis.
    #	
    def Lnxnm_get_nbsCmmcChassisNumberOfSlots(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.5"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisNumberOfSlots #### 
    #### Start - Chassis - nbsCmmcChassisHardwareRevision #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.6
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 100
    #
    #	Description: 
    #	
    #	The hardware revision of the chassis.
    #	
    def Lnxnm_get_nbsCmmcChassisHardwareRevision(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.6"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisHardwareRevision #### 
    #### Start - Chassis - nbsCmmcChassisPS1Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.7
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notInstalled
    #		2	acBad
    #		3	dcBad
    #		4	acGood
    #		5	dcGood
    #		6	notSupported
    #		7	good
    #		8	bad
    #
    #	Description: 
    #	
    #	The status of Power Supply 1.
    #	
    def Lnxnm_get_nbsCmmcChassisPS1Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.7"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisPS1Status #### 
    #### Start - Chassis - nbsCmmcChassisPS2Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.8
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notInstalled
    #		2	acBad
    #		3	dcBad
    #		4	acGood
    #		5	dcGood
    #		6	notSupported
    #		7	good
    #		8	bad
    #
    #	Description: 
    #	
    #	The status of Power Supply 2.
    #	
    def Lnxnm_get_nbsCmmcChassisPS2Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.8"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisPS2Status #### 
    #### Start - Chassis - nbsCmmcChassisPS3Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.9
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notInstalled
    #		2	acBad
    #		3	dcBad
    #		4	acGood
    #		5	dcGood
    #		6	notSupported
    #		7	good
    #		8	bad
    #
    #	Description: 
    #	
    #	The status of Power Supply 3.
    #	
    def Lnxnm_get_nbsCmmcChassisPS3Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.9"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisPS3Status #### 
    #### Start - Chassis - nbsCmmcChassisPS4Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.10
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notInstalled
    #		2	acBad
    #		3	dcBad
    #		4	acGood
    #		5	dcGood
    #		6	notSupported
    #		7	good
    #		8	bad
    #
    #	Description: 
    #	
    #	The status of Power Supply 4.
    #	
    def Lnxnm_get_nbsCmmcChassisPS4Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.10"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisPS4Status #### 
    #### Start - Chassis - nbsCmmcChassisFan1Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.11
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	bad
    #		3	good
    #		4	notInstalled
    #
    #	Description: 
    #	
    #	The status of Fan 1.
    #	
    def Lnxnm_get_nbsCmmcChassisFan1Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.11"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisFan1Status #### 
    #### Start - Chassis - nbsCmmcChassisFan2Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.12
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	bad
    #		3	good
    #		4	notInstalled
    #
    #	Description: 
    #	
    #	The status of Fan 2.
    #	
    def Lnxnm_get_nbsCmmcChassisFan2Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.12"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisFan2Status #### 
    #### Start - Chassis - nbsCmmcChassisFan3Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.13
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	bad
    #		3	good
    #		4	notInstalled
    #
    #	Description: 
    #	
    #	The status of Fan 3.
    #	
    def Lnxnm_get_nbsCmmcChassisFan3Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.13"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisFan3Status #### 
    #### Start - Chassis - nbsCmmcChassisFan4Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.14
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	bad
    #		3	good
    #		4	notInstalled
    #
    #	Description: 
    #	
    #	The status of Fan 4.
    #	
    def Lnxnm_get_nbsCmmcChassisFan4Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.14"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisFan4Status #### 
    #### Start - Chassis - nbsCmmcChassisTemperature #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.15
    #	Access = readonly
    #	Data Type = Integer
    #	Minimum Value = -2147483648
    #	Maximum Value = 2147483647
    #
    #	Description: 
    #	
    #	The temperature (degrees Celsius) of the Chassis.
    #	
    #	Not supported value: 0x80000000
    #	
    def Lnxnm_get_nbsCmmcChassisTemperature(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.15"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisTemperature #### 
    #### Start - Chassis - nbsCmmcChassisTemperatureLimit #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.16
    #	Access = readwrite
    #	Data Type = Integer
    #	Minimum Value = -100
    #	Maximum Value = 100
    #
    #	Description: 
    #	
    #	The maximum safe temperature (degrees Celsius) of the
    #	Chassis.
    #	
    #	Not supported value: 0x80000000
    #	
    def Lnxnm_get_nbsCmmcChassisTemperatureLimit(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.16"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisTemperatureLimit(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.16"
        return self.Lnxnm_set_integer32(str(oid) + "." + str(chassis), str(value), -100, 100)
    
    #### End   - Chassis - nbsCmmcChassisTemperatureLimit #### 
    #### Start - Chassis - nbsCmmcChassisTemperatureMin #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.17
    #	Access = readwrite
    #	Data Type = Integer
    #	Minimum Value = -100
    #	Maximum Value = 100
    #
    #	Description: 
    #	
    #	The minimum safe temperature (degrees Celsius) of the
    #	Chassis.
    #	
    #	Not supported value: 0x80000000
    #	
    def Lnxnm_get_nbsCmmcChassisTemperatureMin(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.17"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisTemperatureMin(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.17"
        return self.Lnxnm_set_integer32(str(oid) + "." + str(chassis), str(value), -100, 100)
    
    #### End   - Chassis - nbsCmmcChassisTemperatureMin #### 
    #### Start - Chassis - nbsCmmcChassisEnableLinkTraps #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.21
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	off
    #		3	on
    #
    #	Description: 
    #	
    #	When set, send trap to report change in link status,
    #	up or down.
    #	
    def Lnxnm_get_nbsCmmcChassisEnableLinkTraps(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.21"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisEnableLinkTraps(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.21"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis), str(value), 3)
    
    #### End   - Chassis - nbsCmmcChassisEnableLinkTraps #### 
    #### Start - Chassis - nbsCmmcChassisEnableChassisTraps #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.22
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	off
    #		3	on
    #
    #	Description: 
    #	
    #	When set, send trap to report chassis related events.
    #	
    def Lnxnm_get_nbsCmmcChassisEnableChassisTraps(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.22"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisEnableChassisTraps(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.22"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis), str(value), 3)
    
    #### End   - Chassis - nbsCmmcChassisEnableChassisTraps #### 
    #### Start - Chassis - nbsCmmcChassisEnableSlotChangeTraps #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.24
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	off
    #		3	on
    #
    #	Description: 
    #	
    #	When set, send trap to report slot change related events.
    #	
    def Lnxnm_get_nbsCmmcChassisEnableSlotChangeTraps(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.24"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisEnableSlotChangeTraps(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.24"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis), str(value), 3)
    
    #### End   - Chassis - nbsCmmcChassisEnableSlotChangeTraps #### 
    #### Start - Chassis - nbsCmmcChassisEnablePortTraps #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.25
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	off
    #		3	on
    #
    #	Description: 
    #	
    #	When set, send trap to report port change related events.
    #	
    def Lnxnm_get_nbsCmmcChassisEnablePortTraps(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.25"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisEnablePortTraps(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.25"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis), str(value), 3)
    
    #### End   - Chassis - nbsCmmcChassisEnablePortTraps #### 
    #### Start - Chassis - nbsCmmcChassisEnableModuleSpecificTraps #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.27
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	off
    #		3	on
    #
    #	Description: 
    #	
    #	When set, send trap to report change in specific cards
    #	conditions
    #	
    def Lnxnm_get_nbsCmmcChassisEnableModuleSpecificTraps(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.27"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisEnableModuleSpecificTraps(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.27"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis), str(value), 3)
    
    #### End   - Chassis - nbsCmmcChassisEnableModuleSpecificTraps #### 
    #### Start - Chassis - nbsCmmcChassisName #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.32
    #	Access = readwrite
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 50
    #
    #	Description: 
    #	
    #	The user assigned name for this chassis
    #	
    def Lnxnm_get_nbsCmmcChassisName(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.32"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisName(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.32"
        return self.Lnxnm_set_display_string(str(oid) + "." + str(chassis), str(value), 0, 50)
    
    #### End   - Chassis - nbsCmmcChassisName #### 
    #### Start - Chassis - nbsCmmcChassisEnableLINTraps #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.33
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	off
    #		3	on
    #
    #	Description: 
    #	
    #	When off(2), suppresses any traps related to Link
    #	Integrity Notification.
    #	
    def Lnxnm_get_nbsCmmcChassisEnableLINTraps(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.33"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisEnableLINTraps(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.33"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis), str(value), 3)
    
    #### End   - Chassis - nbsCmmcChassisEnableLINTraps #### 
    #### Start - Chassis - nbsCmmcChassisEnablePortChangeTraps #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.34
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	off
    #		3	on
    #
    #	Description: 
    #	
    #	When off(2), suppresses any traps related to removable
    #	Ports being inserted or removed.
    #	
    def Lnxnm_get_nbsCmmcChassisEnablePortChangeTraps(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.34"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisEnablePortChangeTraps(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.34"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis), str(value), 3)
    
    #### End   - Chassis - nbsCmmcChassisEnablePortChangeTraps #### 
    #### Start - Chassis - nbsCmmcChassisEnablePortDiagsTraps #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.35
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	off
    #		3	on
    #
    #	Description: 
    #	
    #	When off(2), suppresses any traps related to digital
    #	diagnostics being outside of safe levels.
    #	
    def Lnxnm_get_nbsCmmcChassisEnablePortDiagsTraps(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.35"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisEnablePortDiagsTraps(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.35"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis), str(value), 3)
    
    #### End   - Chassis - nbsCmmcChassisEnablePortDiagsTraps #### 
    #### Start - Chassis - nbsCmmcChassisFan5Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.36
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	bad
    #		3	good
    #		4	notInstalled
    #
    #	Description: 
    #	
    #	The status of Fan 5.
    #	
    def Lnxnm_get_nbsCmmcChassisFan5Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.36"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisFan5Status #### 
    #### Start - Chassis - nbsCmmcChassisFan6Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.37
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	bad
    #		3	good
    #		4	notInstalled
    #
    #	Description: 
    #	
    #	The status of Fan 6.
    #	
    def Lnxnm_get_nbsCmmcChassisFan6Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.37"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisFan6Status #### 
    #### Start - Chassis - nbsCmmcChassisFan7Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.38
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	bad
    #		3	good
    #		4	notInstalled
    #
    #	Description: 
    #	
    #	The status of Fan 7.
    #	
    def Lnxnm_get_nbsCmmcChassisFan7Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.38"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisFan7Status #### 
    #### Start - Chassis - nbsCmmcChassisFan8Status #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.39
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	bad
    #		3	good
    #		4	notInstalled
    #
    #	Description: 
    #	
    #	The status of Fan 8.
    #	
    def Lnxnm_get_nbsCmmcChassisFan8Status(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.39"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisFan8Status #### 
    #### Start - Chassis - nbsCmmcChassisCrossConnect #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.41
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	operating
    #		3	clearing
    #
    #	Description: 
    #	
    #	For chassis housing cross-connect blades or slots, this
    #	object is used to reflect the operating state and to clear
    #	the entire cross-connect map, including any independent maps
    #	of subordinate slots.
    #	
    #	If there are currently no cross-connect blades or slots in
    #	this chassis, the Agent must report notSupported(1).
    #	Additionally, if this object reports notSupported(1), any
    #	SNMP SET to this object should return SNMP Error 3 (bad
    #	value).
    #	
    #	The Agent should report operating(2) under normal
    #	circumstances.
    #	
    #	If this object reports operating(2), SNMP Managers are allowed
    #	to set this object to clearing (3), which instructs the Agent
    #	to erase all this chassis' cross-connect maps, including any
    #	independent maps of subordinate slots.
    #	
    def Lnxnm_get_nbsCmmcChassisCrossConnect(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.41"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    def Lnxnm_set_nbsCmmcChassisCrossConnect(self, chassis, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        oid = "1.3.6.1.4.1.629.200.6.1.1.41"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis), str(value), 3)
    
    #### End   - Chassis - nbsCmmcChassisCrossConnect #### 
    #### Start - Chassis - nbsCmmcChassisSerialNum #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.48
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 12
    #
    #	Description: 
    #	
    #	SerialNumber of this chassis.
    #	
    #	If this object is not supported, this string should be empty.
    #	
    def Lnxnm_get_nbsCmmcChassisSerialNum(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.48"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisSerialNum #### 
    #### Start - Chassis - nbsCmmcChassisPowerStatus #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.51
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	sufficient
    #		3	insufficient
    #
    #	Description: 
    #	
    #	Indicates if the total power in the chassis is sufficient or insufficient.
    #	Insufficient means that the chassis won't work in a correct mode.
    #	
    def Lnxnm_get_nbsCmmcChassisPowerStatus(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.51"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisPowerStatus #### 
    #### Start - Chassis - nbsCmmcChassisIfIndex #### 
    #	OID = 1.3.6.1.4.1.629.200.6.1.1.52
    #	Access = readonly
#	Syntax = InterfaceIndex
    #
    #	Description: 
    #	
    #	Mib2-like ifIndex of this chassis
    #	
    def Lnxnm_get_nbsCmmcChassisIfIndex(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        oid = "1.3.6.1.4.1.629.200.6.1.1.52"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis))
    
    
    #### End   - Chassis - nbsCmmcChassisIfIndex #### 
    #### Start - Slot - nbsCmmcSlotType #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.3
    #	Access = readonly
#	Syntax = NbsCmmcEnumSlotType
    #
    #	Description: 
    #	
    #	The front panel of card in the slot.
    #	
    def Lnxnm_get_nbsCmmcSlotType(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.3"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    
    #### End   - Slot - nbsCmmcSlotType #### 
    #### Start - Slot - nbsCmmcSlotModel #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.4
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 50
    #
    #	Description: 
    #	
    #	Describes the model of card that is currently in the slot.
    #	
    def Lnxnm_get_nbsCmmcSlotModel(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.4"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    
    #### End   - Slot - nbsCmmcSlotModel #### 
    #### Start - Slot - nbsCmmcSlotNumberOfPorts #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.6
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	Number of ports on the card.
    #	
    def Lnxnm_get_nbsCmmcSlotNumberOfPorts(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.6"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    
    #### End   - Slot - nbsCmmcSlotNumberOfPorts #### 
    #### Start - Slot - nbsCmmcSlotHardwareRevision #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.7
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 100
    #
    #	Description: 
    #	
    #	This describes the hardware revision of the card
    #	
    def Lnxnm_get_nbsCmmcSlotHardwareRevision(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.7"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    
    #### End   - Slot - nbsCmmcSlotHardwareRevision #### 
    #### Start - Slot - nbsCmmcSlotOperationType #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.8
    #	Access = readwrite
#	Syntax = NbsCmmcEnumSlotOperationType
    #
    #	Description: 
    #	
    #	Operation of card..
    #	
    def Lnxnm_get_nbsCmmcSlotOperationType(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.8"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    def Lnxnm_set_nbsCmmcSlotOperationType(self, chassis, slot, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        
        oid = "1.3.6.1.4.1.629.200.7.1.1.8"
    
    #### End   - Slot - nbsCmmcSlotOperationType #### 
    #### Start - Slot - nbsCmmcSlotName #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.10
    #	Access = readwrite
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 50
    #
    #	Description: 
    #	
    #	The user assigned name for this slot.
    #	
    def Lnxnm_get_nbsCmmcSlotName(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.10"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    def Lnxnm_set_nbsCmmcSlotName(self, chassis, slot, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        
        oid = "1.3.6.1.4.1.629.200.7.1.1.10"
        return self.Lnxnm_set_display_string(str(oid) + "." + str(chassis) + "." + str(slot), str(value), 0, 50)
    
    #### End   - Slot - nbsCmmcSlotName #### 
    #### Start - Slot - nbsCmmcSlotSwConfigurable #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.13
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	other
    #		2	no
    #		3	yes
    #
    #	Description: 
    #	
    #	Indicates whether card is software configurable, usually
    #	based on hardware jumper/dip switch settings.  If any changes
    #	to the hardware configuration are allowed, this value will be
    #	yes(3).  If this is no(2), SNMP GETs will work but SETs will
    #	fail with an SNMP error.  According to RFC 1157, that error
    #	should be noSuchName(2).
    #	
    def Lnxnm_get_nbsCmmcSlotSwConfigurable(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.13"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    
    #### End   - Slot - nbsCmmcSlotSwConfigurable #### 
    #### Start - Slot - nbsCmmcSlotDescr #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.22
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 100
    #
    #	Description: 
    #	
    #	Agent description of this slot.
    #	
    def Lnxnm_get_nbsCmmcSlotDescr(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.22"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    
    #### End   - Slot - nbsCmmcSlotDescr #### 
    #### Start - Slot - nbsCmmcSlotCrossConnect #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.24
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	operating
    #		3	clearing
    #
    #	Description: 
    #	
    #	For slots supporting cross-connect functionality, this
    #	object is used to reflect the operating state and
    #	clear the entire cross-connect map for this slot.
    #	
    #	If the slot is not of cross-connect type, the Agent must
    #	report notSupported(1). Additionally, if this object reports
    #	notSupported(1), any SNMP SET to this object should return
    #	SNMP Error 3 (bad value).
    #	
    #	The Agent should report operating(2) under normal
    #	circumstances.
    #	
    #	If this object reports operating(2), SNMP Managers are allowed to
    #	set this object to clearing (3), which instructs the Agent
    #	to erase the cross-connect map for this slot.
    #	
    def Lnxnm_get_nbsCmmcSlotCrossConnect(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.24"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    def Lnxnm_set_nbsCmmcSlotCrossConnect(self, chassis, slot, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        
        oid = "1.3.6.1.4.1.629.200.7.1.1.24"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot), str(value), 3)
    
    #### End   - Slot - nbsCmmcSlotCrossConnect #### 
    #### Start - Slot - nbsCmmcSlotSerialNum #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.32
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 12
    #
    #	Description: 
    #	
    #	SerialNumber of this module.
    #	
    #	If this object is not supported, this string should be empty.
    #	
    def Lnxnm_get_nbsCmmcSlotSerialNum(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.32"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    
    #### End   - Slot - nbsCmmcSlotSerialNum #### 
    #### Start - Slot - nbsCmmcSlotToggleRate #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.33
    #	Access = readwrite
    #	Data Type = Integer
    #	Minimum Value = 0
    #	Maximum Value = 2147483647
    #
    #	Description: 
    #	
    #	For crossbar products.  Used to indicate the approximate
    #	rate, in microseconds, at which this card should toggle
    #	its transmitters on and off.
    #	
    #	Not supported value: 0
    #	
    def Lnxnm_get_nbsCmmcSlotToggleRate(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.33"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    def Lnxnm_set_nbsCmmcSlotToggleRate(self, chassis, slot, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        
        oid = "1.3.6.1.4.1.629.200.7.1.1.33"
        return self.Lnxnm_set_integer32(str(oid) + "." + str(chassis) + "." + str(slot), str(value), 0, 2147483647)
    
    #### End   - Slot - nbsCmmcSlotToggleRate #### 
    #### Start - Slot - nbsCmmcSlotIfIndex #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.37
    #	Access = readonly
#	Syntax = InterfaceIndex
    #
    #	Description: 
    #	
    #	Mib2-like ifIndex of this slot
    #	
    def Lnxnm_get_nbsCmmcSlotIfIndex(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.37"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    
    #### End   - Slot - nbsCmmcSlotIfIndex #### 
    #### Start - Slot - nbsCmmcSlotModuleStatus #### 
    #	OID = 1.3.6.1.4.1.629.200.7.1.1.38
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	empty
    #		3	notReady
    #		4	ready
    #
    #	Description: 
    #	
    #	Slots that have no card installed should be reported as
    #	empty(2).
    #	
    #	Slots where a card has been physically inserted should be
    #	reported as notReady(3) while the card is loading or
    #	warming up, and installed(4) once the card is fully
    #	operational.
    #	
    #	When this object is unavailable the Agent will report
    #	the status notSupported (1).
    #	
    def Lnxnm_get_nbsCmmcSlotModuleStatus(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.200.7.1.1.38"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot))
    
    
    #### End   - Slot - nbsCmmcSlotModuleStatus #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupCyclesMin #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.3
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The fewest up/down cycles a user may request.
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupCyclesMin(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.3"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupCyclesMin #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupCyclesMax #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.4
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The most up/down cycles a user may request.  The reserved
    #	value 0 indicates there is no upper limit.
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupCyclesMax(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.4"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupCyclesMax #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupCycles #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.5
    #	Access = readwrite
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	User-assigned number of up/down cycles to perform. The
    #	reserved value 0 indicates the cycling should continue
    #	forever or until stopped by the user.
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupCycles(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.5"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    def Lnxnm_set_nbsCmmcSlotLinkToggleGroupCycles(self, chassis, slot, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        
        oid = "1.3.6.1.4.1.629.217.2.2.1.5"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_set_integer32(str(oid) + "." + str(ifIndex), str(value))
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupCycles #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupGranularity #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.6
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The hardware-dependent interval, in microseconds, between
    #	steps in nbsMccLinkToggleGroupUpRate and
    #	nbsMccLinkToggleGroupDnRate
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupGranularity(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.6"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupGranularity #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupUpRateMin #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.7
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The briefest time Up a user may request, in microseconds
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupUpRateMin(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.7"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupUpRateMin #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupUpRateMax #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.8
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The longest time Up a user may request, in microseconds
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupUpRateMax(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.8"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupUpRateMax #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupUpRate #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.9
    #	Access = readwrite
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	User-assigned duration of the Up phase of a cycle, in
    #	microseconds
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupUpRate(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.9"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    def Lnxnm_set_nbsCmmcSlotLinkToggleGroupUpRate(self, chassis, slot, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        
        oid = "1.3.6.1.4.1.629.217.2.2.1.9"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_set_integer32(str(oid) + "." + str(ifIndex), str(value))
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupUpRate #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupDnRateMin #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.10
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The briefest time Down a user may request, in microseconds
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupDnRateMin(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.10"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupDnRateMin #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupDnRateMax #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.11
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The longest time Down a user may request, in microseconds
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupDnRateMax(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.11"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupDnRateMax #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupDnRate #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.12
    #	Access = readwrite
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	User-assigned duration of the Down phase of a cycle, in
    #	microseconds
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupDnRate(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.12"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    def Lnxnm_set_nbsCmmcSlotLinkToggleGroupDnRate(self, chassis, slot, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        
        oid = "1.3.6.1.4.1.629.217.2.2.1.12"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_set_integer32(str(oid) + "." + str(ifIndex), str(value))
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupDnRate #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupAction #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.13
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	start
    #		3	stop
    #
    #	Description: 
    #	
    #	Starts and terminates link toggling.
    #	
    #	User should set this object to start(2) to initiate
    #	toggling.
    #	
    #	If the object nbsMccLinkToggleGroupCycles was set to a
    #	value greater than 0, toggling will stop automatically upon
    #	completion of the requested number of cycles. Otherwise,
    #	the user must set this object to stop(3) to halt the link
    #	toggling.
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupAction(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.13"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    def Lnxnm_set_nbsCmmcSlotLinkToggleGroupAction(self, chassis, slot, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        
        oid = "1.3.6.1.4.1.629.217.2.2.1.13"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_set_enum(str(oid) + "." + str(ifIndex), str(value), 3)
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupAction #### 
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupStatus #### 
    #	OID = 1.3.6.1.4.1.629.217.2.2.1.14
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	idle
    #		3	running
    #
    #	Description: 
    #	
    #	Displays the actual link toggling status, idle or running.
    #	
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupStatus(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.14"
        
        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    
    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupStatus #### 
    #### Start - Port - nbsCmmcPortType #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.4
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The physical type of port.  Valid port types are
    def Lnxnm_get_nbsCmmcPortType(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.4"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortType #### 
    #### Start - Port - nbsCmmcPortLink #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.6
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	other
    #		2	noSignal
    #		3	signalDetect
    #		4	link
    #		5	lock
    #
    #	Description: 
    #	
    #	The link status of the port.
    #	
    def Lnxnm_get_nbsCmmcPortLink(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.6"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortLink #### 
    #### Start - Port - nbsCmmcPortAutoNegotiation #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.7
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	off
    #		3	on
    #		4	deprecated4
    #		5	deprecated5
    #
    #	Description: 
    #	
    #	The AutoNegotiation status of a port.  AutoNegotiation
    #	may affect the port's speed, duplex, and MDI/MDIX.
    #	
    #	If this port does not offer this feature, Agent should
    #	report the value notSupported(1).
    #	
    #	To disable this feature, set the value to off(2).
    #	
    #	To enable this feature, set the value to on(3).
    #	
    #	The value autoMDIXOnly(4) is deprecated.
    #	
    #	The value custom (5) is deprecated.
    #	
    def Lnxnm_get_nbsCmmcPortAutoNegotiation(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.7"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortAutoNegotiation(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.7"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 5)
    
    #### End   - Port - nbsCmmcPortAutoNegotiation #### 
    #### Start - Port - nbsCmmcPortDuplex #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.8
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	half
    #		3	full
    #
    #	Description: 
    #	
    #	The duplex mode of the port.
    #	
    def Lnxnm_get_nbsCmmcPortDuplex(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.8"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortDuplex(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.8"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 3)
    
    #### End   - Port - nbsCmmcPortDuplex #### 
    #### Start - Port - nbsCmmcPortSpeed #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.9
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	other
    #		2	spd10Mbps
    #		3	spd100Mbps
    #		4	spdGigabit
    #		5	spd10Gbps
    #
    #	Description: 
    #	
    #	The line speed of the port.  This object is superseded
    #	by nbsCmmcPortProtoAdmin and nbsCmmcPortProtoOper.
    #	
    def Lnxnm_get_nbsCmmcPortSpeed(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.9"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortSpeed(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.9"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 5)
    
    #### End   - Port - nbsCmmcPortSpeed #### 
    #### Start - Port - nbsCmmcPortEnableAdmin #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.14
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	disable
    #		3	enable
    #		4	deprecatedAuto
    #
    #	Description: 
    #	
    #	Administratively desired operational status of the port.  For the
    #	actual operational status, please see the related object
    #	nbsCmmcPortEnableOper.
    #	
    #	The value notSupported (1) indicates that the user has no ability to
    #	disable the transceiver.
    #	
    #	Users may set this value to disable (2) to turn off the port's
    #	transceiver so that no traffic will flow through this port.
    #	
    #	For traffic to be sent and received as normal, this object should be
    #	set to enable (3).
    #	
    #	The value auto (4) has been deprecated - older Agents might report
    #	it, and Managers may attempt to set it, but newer agents will
    #	neither report nor accept this value.
    #	
    def Lnxnm_get_nbsCmmcPortEnableAdmin(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.14"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortEnableAdmin(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.14"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 4)
    
    #### End   - Port - nbsCmmcPortEnableAdmin #### 
    #### Start - Port - nbsCmmcPortLIN #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.16
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	disable
    #		3	enable
    #
    #	Description: 
    #	
    #	Line integrity check on or off.
    #	
    def Lnxnm_get_nbsCmmcPortLIN(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.16"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortLIN(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.16"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 3)
    
    #### End   - Port - nbsCmmcPortLIN #### 
    #### Start - Port - nbsCmmcPortName #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.21
    #	Access = readwrite
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 50
    #
    #	Description: 
    #	
    #	The user assigned name for this port.  This object is also
    #	used for the MIB2 object ifAlias.
    #	
    def Lnxnm_get_nbsCmmcPortName(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.21"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortName(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.21"
        return self.Lnxnm_set_display_string(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 0, 50)
    
    #### End   - Port - nbsCmmcPortName #### 
    #### Start - Port - nbsCmmcPortSerialNumber #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.28
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 50
    #
    #	Description: 
    #	
    #	Part Serial Number as reported by the component.
    #	
    #	Not supported value: 'N/A'
    #	
    def Lnxnm_get_nbsCmmcPortSerialNumber(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.28"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortSerialNumber #### 
    #### Start - Port - nbsCmmcPortVendorInfo #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.29
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 50
    #
    #	Description: 
    #	
    #	Vendor name as reported by the component.
    #	
    #	Not supported value: 'N/A'
    #	
    def Lnxnm_get_nbsCmmcPortVendorInfo(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.29"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortVendorInfo #### 
    #### Start - Port - nbsCmmcPortTemperature #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.30
    #	Access = readonly
    #	Data Type = Integer
    #	Minimum Value = -2147483648
    #	Maximum Value = 2147483647
    #
    #	Description: 
    #	
    #	The temperature (in degrees celsius) of this trans-
    #	ceiver.
    #	
    #	Not supported value: 0x80000000
    #	
    def Lnxnm_get_nbsCmmcPortTemperature(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.30"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortTemperature #### 
    #### Start - Port - nbsCmmcPortTxPower #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.31
    #	Access = readonly
    #	Data Type = Integer
    #	Minimum Value = -2147483648
    #	Maximum Value = 2147483647
    #
    #	Description: 
    #	
    #	The output power (in milli dBm) of this transmitter.
    #	
    #	Not supported value: 0x80000000
    #	
    def Lnxnm_get_nbsCmmcPortTxPower(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.31"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortTxPower #### 
    #### Start - Port - nbsCmmcPortRxPower #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.32
    #	Access = readonly
    #	Data Type = Integer
    #	Minimum Value = -2147483648
    #	Maximum Value = 2147483647
    #
    #	Description: 
    #	
    #	The received optical power (in milli dBm) of this
    #	receiver.
    #	
    #	Not supported value: 0x80000000
    #	
    def Lnxnm_get_nbsCmmcPortRxPower(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.32"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortRxPower #### 
    #### Start - Port - nbsCmmcPortBiasAmps #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.33
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The bias current (in microAmps) of this transmitter.
    #	The reserved value -1 indicates that this object is
    #	not supported.
    #	
    def Lnxnm_get_nbsCmmcPortBiasAmps(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.33"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortBiasAmps #### 
    #### Start - Port - nbsCmmcPortSupplyVolts #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.34
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The supply voltage (in milliVolts) of this transmitter.
    #	The reserved value -1 indicates that this object is
    #	not supported.
    #	
    def Lnxnm_get_nbsCmmcPortSupplyVolts(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.34"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortSupplyVolts #### 
    #### Start - Port - nbsCmmcPortMedium #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.35
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	coax
    #		3	twistedPair
    #		4	singleMode
    #		5	multiMode
    #
    #	Description: 
    #	
    #	The type of physical communications medium.
    #	
    def Lnxnm_get_nbsCmmcPortMedium(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.35"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortMedium #### 
    #### Start - Port - nbsCmmcPortConnector #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.36
    #	Access = readonly
#	Syntax = NbsCmmcEnumPortConnector
    #
    #	Description: 
    #	
    #	The type of physical connector or jack.
    #	
    def Lnxnm_get_nbsCmmcPortConnector(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.36"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortConnector #### 
    #### Start - Port - nbsCmmcPortWavelength #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.37
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The output wavelength (in nanoMeters) of this
    #	transmitter. The reserved value -1
    #	indicates that this object is not supported.
    #	
    #	This object has been superseded by
    #	nbsCmmcPortWavelengthX, which supports floating
    #	point wavelengths, and lists of wavelengths.
    #	
    def Lnxnm_get_nbsCmmcPortWavelength(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.37"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortWavelength #### 
    #### Start - Port - nbsCmmcPortDigitalDiags #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.38
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	diagsOk
    #		3	diagsWarning
    #		4	diagsAlarm
    #
    #	Description: 
    #	
    #	Indicates whether Digital Diagnostics are supported
    #	by this port.  If they are supported, this variable
    #	indicates the worst severity level among the measured
    #	diagnostic values.
    #	
    def Lnxnm_get_nbsCmmcPortDigitalDiags(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.38"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortDigitalDiags #### 
    #### Start - Port - nbsCmmcPortNominalBitRate #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.40
    #	Access = readwrite
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	This NominalBitRate variable exists for modules
    #	which support configurable speeds that may not be listed in
    #	PortSpeed.  Here can be specified the raw bit rate desired,
    #	measured in decimal Mbps.
    #	
    #	The Agent may use exactly that rate, or may substitute it with
    #	a compatible rate within an appropriate range of speeds.
    #	If the Agent receives a request  for a bitrate it cannot
    #	support, it should return the SNMP errorstatus badValue(3).
    #	
    #	For ports whose speed is unknown or not configurable, the
    #	Agent should report this value as -1.
    #	
    #	The reserved value 0 specifies that no speed is configured,
    #	and any clocking is bypassed.
    #	
    #	The following values are associated with specific protocols:
    #	44 - DS3
    #	51 - OC-1
    #	77 - Telco bus
    #	125 - Fast Ethernet (100 Mbps)
    #	126 - FDDI
    #	155 - OC-3
    #	200 - ESCON
    #	270 - SDI 270Mbps
    #	540 - SDI 540Mbps
    #	622 - OC-12
    #	1063 - 1 Gig FibreChannel
    #	1244 - OC-24
    #	1250 - Gigabit Ethernet
    #	1485 - HDTV
    #	2125 - 2 Gig FibreChannel
    #	2450 - OC-48
    #	2500 - Infiniband
    #	2666 - OC-48+FEC
    #	9953 - 10 Gig Ethernet/WAN
    #	10312 - 10 Gig Ethernet/LAN
    #	10625 - 10 Gig FibreChannel
    #	
    #	For ports that support ProtoAdmin 'userDefined', writing
    #	this object will automatically set the ProtoAdmin to
    #	'userDefined'.
    #	
    def Lnxnm_get_nbsCmmcPortNominalBitRate(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.40"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortNominalBitRate(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.40"
        return self.Lnxnm_set_integer32(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value))
    
    #### End   - Port - nbsCmmcPortNominalBitRate #### 
    #### Start - Port - nbsCmmcPortPartRev #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.42
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 50
    #
    #	Description: 
    #	
    #	Part Number and Revision level as reported by the
    #	component.
    #	
    #	Not supported value: 'N/A'
    #	
    def Lnxnm_get_nbsCmmcPortPartRev(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.42"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortPartRev #### 
    #### Start - Port - nbsCmmcPortLinked #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.44
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	no
    #		2	yes
    #
    #	Description: 
    #	
    #	Simpler, one bit version of PortLink.  The value no(1)
    #	means there is no signal detected or that signal is of
    #	poor quality.  The value yes(2) indicates a good
    #	connection.
    #	
    def Lnxnm_get_nbsCmmcPortLinked(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.44"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortLinked #### 
    #### Start - Port - nbsCmmcPortOperational #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.45
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	no
    #		2	yes
    #
    #	Description: 
    #	
    #	Indicates whether the port is in a state appropriate
    #	for normal data communications. The value no(1) means
    #	that the port is disabled or in an abnormal state such
    #	as loopback.  The value yes(2) indicates that the port
    #	is enabled and usable.
    #	
    def Lnxnm_get_nbsCmmcPortOperational(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.45"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortOperational #### 
    #### Start - Port - nbsCmmcPortAlarmCause #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.48
    #	Access = readonly
    #	Data Type = DisplayString
    #	Minimum Size = 0
    #	Maximum Size = 50
    #
    #	Description: 
    #	
    #	For Pluggable ports with Digital Diagnostics.  If there is
    #	currently no alarm condition, this string should be empty.
    #	Otherwise, this should display the most severe actual
    #	alarm condition.
    #	
    def Lnxnm_get_nbsCmmcPortAlarmCause(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.48"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortAlarmCause #### 
    #### Start - Port - nbsCmmcPortAutoNegAd #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.50
    #	Access = readwrite
    #	Data Type = OctetString
    #	Minimum Size = 2
    #	Maximum Size = 2
    #
    #	Description: 
    #	
    #	This object determines which capabilities will be advertised
    #	during auto negotiation.  Each capability is represented by
    #	one bit.  Set bit to 1 to advertise capability, 0 to deny it.
    #	
    #	Capability            Bit
    #	----------------------  ---
    #	reserved   0
    #	Flow Control   1
    #	1000 Mbps Full Duplex   2
    #	1000 Mbps Half Duplex   3
    #	100 Mbps Full Duplex   4
    #	100 Mbps Half Duplex   5
    #	10 Mbps Full Duplex   6
    #	10 Mbps Half Duplex   7
    #	
    #	OCTET STRING bitmasks count the leftmost bit (MSB) as 0.
    #	
    def Lnxnm_get_nbsCmmcPortAutoNegAd(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.50"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortAutoNegAd(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.50"
        return self.Lnxnm_set_octet_string(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 2, 2)
    
    #### End   - Port - nbsCmmcPortAutoNegAd #### 
    #### Start - Port - nbsCmmcPortAutoNegEditable #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.51
    #	Access = readonly
    #	Data Type = OctetString
    #	Minimum Size = 2
    #	Maximum Size = 2
    #
    #	Description: 
    #	
    #	This object determines which AutoNegAd bits may be changed by
    #	the user.  Bits set to 1 indicate user may choose whether to
    #	advertise the corresponding capability.  Bits are cleared if
    #	user is not allowed to change the corresponding AutoNegAd bit.
    #	
    #	Capability            Bit
    #	----------------------  ---
    #	reserved   0
    #	Flow Control   1
    #	1000 Mbps Full Duplex   2
    #	1000 Mbps Half Duplex   3
    #	100 Mbps Full Duplex   4
    #	100 Mbps Half Duplex   5
    #	10 Mbps Full Duplex   6
    #	10 Mbps Half Duplex   7
    #	
    #	OCTET STRING bitmasks count the leftmost bit (MSB) as 0.
    #	
    def Lnxnm_get_nbsCmmcPortAutoNegEditable(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.51"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortAutoNegEditable #### 
    #### Start - Port - nbsCmmcPortLinkMatch #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.56
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	disabled
    #		3	enabled
    #
    #	Description: 
    #	
    #	Some converter ports that are capable of autonegotiation
    #	(ANEG) may sometimes be between two end ports that would like
    #	to autonegotiate with each other.  The Agent can ensure
    #	that both ports in the converter/circuit settle on the same
    #	autonegotiated settings.  This feature is called LinkMatch.
    #	
    #	ANEG with LinkMatch can sometimes be a lengthy process.
    #	In order to streamline the ANEG process, users may manually
    #	configure the parameters that supporting ports will advertise
    #	during their independent autonegotiations.  This involves two
    #	steps - first to change the nbsCmmcPortAutoNegAd object to
    #	reflect the outcome desired, then to set this
    #	nbsCmmcPortLinkMatch object to the value disabled(2).
    #	
    #	The default value for this object is enabled(3).
    #	
    #	Ports that do not support this feature should return the
    #	value notSupported(1).
    #	
    def Lnxnm_get_nbsCmmcPortLinkMatch(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.56"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortLinkMatch(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.56"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 3)
    
    #### End   - Port - nbsCmmcPortLinkMatch #### 
    #### Start - Port - nbsCmmcPortMDIPinoutAdmin #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.57
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	mdi
    #		3	mdix
    #		4	autoSense
    #
    #	Description: 
    #	
    #	Connecting twisted-pair ethernet ports originally required
    #	care in choosing either straight or crossover cables.  Later,
    #	many ethernet ports added the feature that they could be
    #	configured to accept either cable pinout.  Some ports are
    #	even smart enough to detect, or autosense, the pinout they
    #	should use.
    #	
    #	This Administrative object allows users to request the port
    #	adopt a specific pinout, or to have the port autosense it.
    #	
    #	The value notSupported(1) indicates that this port
    #	cannot dynamically alter its pinout through this object.
    #	
    #	The value mdi(2) is used to connect with a straight cable to
    #	mdix ports such as those found on hubs, switches and routers.
    #	
    #	The value mdix(3) is used to connect with a straight cable to
    #	mdi ports such as those found on workstations.
    #	
    #	The value autoSense(4) indicates this port should
    #	automatically detect and change to the necessary pinout.
    #	
    #	This object has a corresponding Operational value which
    #	reports the actual pinout state.  In certain situations, the
    #	Operational value might differ from the Administrative.
    #	
    def Lnxnm_get_nbsCmmcPortMDIPinoutAdmin(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.57"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortMDIPinoutAdmin(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.57"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 4)
    
    #### End   - Port - nbsCmmcPortMDIPinoutAdmin #### 
    #### Start - Port - nbsCmmcPortTemperatureLevel #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.64
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	lowAlarm
    #		3	lowWarning
    #		4	ok
    #		5	highWarning
    #		6	highAlarm
    #
    #	Description: 
    #	
    #	This object indicates whether this port has a temperature
    #	problem.
    #	
    #	If this port does not support SFF-8472 Digital Diagnostics,
    #	this value should be notSupported(1).
    #	
    #	If Digital Diagnostics indicate temperature is below the
    #	low Alarm Threshold, this value should be lowAlarm(2).
    #	
    #	If Digital Diagnostics indicate temperature is above the
    #	low Alarm Threshold but below the low Warning threshold,
    #	this value should be lowWarning(3).
    #	
    #	If Digital Diagnostics indicate this port is within the
    #	recommended operating range, value is ok(4).
    #	
    #	If Digital Diagnostics indicate temperature is higher than
    #	the high Warning threshold, but has not crossed the Alarm
    #	threshold, this value should be highWarning (5),.
    #	
    #	If Digital Diagnostics indicate this port has crossed the
    #	high Alarm threshold, this value should be highAlarm(6).
    #	
    #	The related object nbsCmmcPortTemperature indicates what the
    #	current temperature is.
    #	
    def Lnxnm_get_nbsCmmcPortTemperatureLevel(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.64"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortTemperatureLevel #### 
    #### Start - Port - nbsCmmcPortTxPowerLevel #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.65
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	lowAlarm
    #		3	lowWarning
    #		4	ok
    #		5	highWarning
    #		6	highAlarm
    #
    #	Description: 
    #	
    #	This object indicates whether this port has a problem
    #	with its transmitter power.
    #	
    #	If this port does not support SFF-8472 Digital Diagnostics,
    #	this value should be notSupported(1).
    #	
    #	If Digital Diagnostics indicate TxPower is below the
    #	low Alarm Threshold, this value should be lowAlarm(2).
    #	
    #	If Digital Diagnostics indicate TxPower is above the
    #	low Alarm Threshold but below the low Warning threshold,
    #	this value should be lowWarning(3).
    #	
    #	If Digital Diagnostics indicate this port is within the
    #	recommended operating range, value is ok(4).
    #	
    #	If Digital Diagnostics indicate TxPower is higher than
    #	the high Warning threshold, but has not crossed the Alarm
    #	threshold, this value should be highWarning (5),.
    #	
    #	If Digital Diagnostics indicate this port has crossed the
    #	high Alarm threshold, this value should be highAlarm(6).
    #	
    #	The related object nbsCmmcPortTxPower indicates what the
    #	current TxPower is.
    #	
    def Lnxnm_get_nbsCmmcPortTxPowerLevel(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.65"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortTxPowerLevel #### 
    #### Start - Port - nbsCmmcPortRxPowerLevel #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.66
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	lowAlarm
    #		3	lowWarning
    #		4	ok
    #		5	highWarning
    #		6	highAlarm
    #
    #	Description: 
    #	
    #	This object indicates whether this port has a problem
    #	with the power of its received signal.
    #	
    #	If this port does not support SFF-8472 Digital Diagnostics,
    #	this value should be notSupported(1).
    #	
    #	If Digital Diagnostics indicate RxPower is below the
    #	low Alarm Threshold, this value should be lowAlarm(2).
    #	
    #	If Digital Diagnostics indicate RxPower is above the
    #	low Alarm Threshold but below the low Warning threshold,
    #	this value should be lowWarning(3).
    #	
    #	If Digital Diagnostics indicate this port is within the
    #	recommended operating range, value is ok(4).
    #	
    #	If Digital Diagnostics indicate RxPower is higher than
    #	the high Warning threshold, but has not crossed the Alarm
    #	threshold, this value should be highWarning (5),.
    #	
    #	If Digital Diagnostics indicate this port has crossed the
    #	high Alarm threshold, this value should be highAlarm(6).
    #	
    #	The related object nbsCmmcPortRxPower indicates what the
    #	current RxPower is.
    #	
    def Lnxnm_get_nbsCmmcPortRxPowerLevel(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.66"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortRxPowerLevel #### 
    #### Start - Port - nbsCmmcPortBiasAmpsLevel #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.67
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	lowAlarm
    #		3	lowWarning
    #		4	ok
    #		5	highWarning
    #		6	highAlarm
    #
    #	Description: 
    #	
    #	This object indicates whether this port has a problem
    #	with the electric current going through the port.
    #	
    #	If this port does not support SFF-8472 Digital Diagnostics,
    #	this value should be notSupported(1).
    #	
    #	If Digital Diagnostics indicate BiasAmps is below the
    #	low Alarm Threshold, this value should be lowAlarm(2).
    #	
    #	If Digital Diagnostics indicate BiasAmps is above the
    #	low Alarm Threshold but below the low Warning threshold,
    #	this value should be lowWarning(3).
    #	
    #	If Digital Diagnostics indicate this port is within the
    #	recommended operating range, value is ok(4).
    #	
    #	If Digital Diagnostics indicate BiasAmps is higher than
    #	the high Warning threshold, but has not crossed the Alarm
    #	threshold, this value should be highWarning (5),.
    #	
    #	If Digital Diagnostics indicate this port has crossed the
    #	high Alarm threshold, this value should be highAlarm(6).
    #	
    #	The related object nbsCmmcPortBiasAmps indicates what the
    #	current amperage is.
    #	
    def Lnxnm_get_nbsCmmcPortBiasAmpsLevel(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.67"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortBiasAmpsLevel #### 
    #### Start - Port - nbsCmmcPortSupplyVoltsLevel #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.68
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	lowAlarm
    #		3	lowWarning
    #		4	ok
    #		5	highWarning
    #		6	highAlarm
    #
    #	Description: 
    #	
    #	This object indicates whether this port has a problem
    #	with the electric voltage across the port.
    #	
    #	If this port does not support SFF-8472 Digital Diagnostics,
    #	this value should be notSupported(1).
    #	
    #	If Digital Diagnostics indicate SupplyVolts is below the
    #	low Alarm Threshold, this value should be lowAlarm(2).
    #	
    #	If Digital Diagnostics indicate SupplyVolts is above the
    #	low Alarm Threshold but below the low Warning threshold,
    #	this value should be lowWarning(3).
    #	
    #	If Digital Diagnostics indicate this port is within the
    #	recommended operating range, value is ok(4).
    #	
    #	If Digital Diagnostics indicate SupplyVolts is higher than
    #	the high Warning threshold, but has not crossed the Alarm
    #	threshold, this value should be highWarning (5),.
    #	
    #	If Digital Diagnostics indicate this port has crossed the
    #	high Alarm threshold, this value should be highAlarm(6).
    #	
    #	The related object nbsCmmcPortSupplyVolts indicates what the
    #	current supply voltage is.
    #	
    def Lnxnm_get_nbsCmmcPortSupplyVoltsLevel(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.68"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortSupplyVoltsLevel #### 
    #### Start - Port - nbsCmmcPortProtoCapabilities #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.72
    #	Access = readonly
    #	Data Type = OctetString
    #	Minimum Size = 0
    #	Maximum Size = 40
    #
    #	Description: 
    #	
    #	This bitmask indicates which protocols this port can support.
    #	This object is mandatory for all ports in systems where the
    #	nbsCmmcSysProtoTable is supported.
    #	
    #	Bit 0 is reserved.
    #	
    #	Subsequent bits refer to the nbsCmmcSysProtoTable.  Bit 1
    #	corresponds to the first table entry, Bit 2 to the second entry,
    #	and so on.  A bit is set (1) if that protocol is available for
    #	this port, cleared (0) if unavailable.
    #	
    #	Bit 1 always indicates 'custom' aka 'userDefined' is supported.
    #	Bit 2 always indicates 'bypass' aka 'transparent' is supported.
    #	
    #	OCTET STRING bitmasks count the leftmost bit (MSB) as 0.
    #	
    #	A zero length OCTET STRING indicates that this object is not
    #	supported.
    #	
    def Lnxnm_get_nbsCmmcPortProtoCapabilities(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.72"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortProtoCapabilities #### 
    #### Start - Port - nbsCmmcPortProtoAdmin #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.73
    #	Access = readwrite
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The nbsCmmcSysProtoIndex of nbsCmmcSysProtoTable corresponding
    #	to the administratively desired family and rate of this port's
    #	protocol.
    #	
    #	The value 0 is reserved for 'notSupported'
    #	
    #	The value 1 is reserved for 'custom' aka 'userDefined'.
    #	If a PortNominalBitRate set is received, PortProtoAdmin
    #	will automatically change to 1.
    #	
    #	The value 2 is reserved for 'bypass' aka 'transparent'.
    #	
    #	Not supported value: 0
    #	
    def Lnxnm_get_nbsCmmcPortProtoAdmin(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.73"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortProtoAdmin(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.73"
        return self.Lnxnm_set_integer32(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value))
    
    #### End   - Port - nbsCmmcPortProtoAdmin #### 
    #### Start - Port - nbsCmmcPortProtoOper #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.74
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The nbsCmmcSysProtoIndex of nbsCmmcSysProtoTable corresponding
    #	to the current operational family and rate of this port's
    #	protocol.
    #	
    #	The value 1 is reserved for 'custom' aka 'userDefined'.
    #	If a PortNominalBitRate set is received, PortProtoAdmin
    #	will automatically change to 1.
    #	
    #	The value 2 is reserved for 'bypass' aka 'transparent'.
    #	
    #	Not supported value: 0
    #	
    def Lnxnm_get_nbsCmmcPortProtoOper(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.74"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortProtoOper #### 
    #### Start - Port - nbsCmmcPortCableLen #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.77
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	len133
    #		3	len266
    #		4	len399
    #		5	len533
    #		6	len655
    #		7	shortHaul
    #		8	longHaul
    #
    #	Description: 
    #	
    #	This object is used to specify the expected maximum
    #	cable length for copper DSX ports such as T1, E1, and T3.
    #	
    #	If a port does not use this feature, this object should
    #	be notSupported (1).
    #	
    #	T1 T-carrier ports should specify a max cable length between
    #	0 to 655 feet using values len133 (2) through len655 (6).
    #	
    #	T3 T-carrier, E1/E3 E-carrier and STS-1 SONET ports should use
    #	either the value shortHaul (7) or longHaul (8).
    #	
    def Lnxnm_get_nbsCmmcPortCableLen(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.77"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortCableLen(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.77"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 8)
    
    #### End   - Port - nbsCmmcPortCableLen #### 
    #### Start - Port - nbsCmmcPortTermination #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.79
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	disable
    #		3	ohm120
    #		4	ohm100
    #		5	ohm75
    #
    #	Description: 
    #	
    #	Administrative setting for the line termination impedance
    #	of the port.
    #	
    #	The value disable (2) indicates that the line is to be
    #	terminated elsewhere.
    #	
    def Lnxnm_get_nbsCmmcPortTermination(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.79"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortTermination(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.79"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 5)
    
    #### End   - Port - nbsCmmcPortTermination #### 
    #### Start - Port - nbsCmmcPortTransmitUnmapped #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.81
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	disabled
    #		3	enabled
    #
    #	Description: 
    #	
    #	This object is for crossbar products.  It allows the user
    #	to choose whether this port's transmitter should be enabled
    #	or disabled when this port is not mapped to another crossbar
    #	port.
    #	
    #	Setting the value disabled(2) will cause the transmitter to
    #	be disabled while the port is unmapped.
    #	
    #	Setting the value enabled(3) will cause this port to
    #	transmit even if unmappped, unless this entire port is
    #	disabled via the nbsCmmcPortEnableAdmin object.
    #	
    #	The agent will report this object as notSupported(1) if the
    #	feature is unavailable for this port.
    #	
    def Lnxnm_get_nbsCmmcPortTransmitUnmapped(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.81"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortTransmitUnmapped(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.81"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 3)
    
    #### End   - Port - nbsCmmcPortTransmitUnmapped #### 
    #### Start - Port - nbsCmmcPortToggleMode #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.82
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	disabled
    #		3	enabled
    #
    #	Description: 
    #	
    #	This object allows to the user to toggle the transmitter of
    #	this port.
    #	
    #	The value enabled(3) causes the transmitter to blink on and
    #	off at the rate specified in nbsCmmcSlotToggleRate.
    #	
    #	The value disabled(2) disables the toggle feature.
    #	
    #	The value notSupported(1) indicates that this port does not
    #	support the toggle feature.
    #	
    def Lnxnm_get_nbsCmmcPortToggleMode(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.82"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortToggleMode(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.82"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 3)
    
    #### End   - Port - nbsCmmcPortToggleMode #### 
    #### Start - Port - nbsCmmcPortCrossConnect #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.83
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	operating
    #		3	clearing
    #
    #	Description: 
    #	
    #	For ports supporting cross-connect functionality, this
    #	object is used to reflect the operating state and clear this
    #	port from all cross-connect maps.
    #	
    #	If the port is not of cross-connect type, the Agent must
    #	report notSupported(1). Additionally, if this object reports
    #	notSupported(1), any SNMP SET to this object should return
    #	SNMP Error 3 (bad value).
    #	
    #	The Agent should report operating(2) under normal
    #	circumstances.
    #	
    #	If this object reports operating(2), SNMP Managers are allowed to
    #	set this object to clearing (3), which instructs the Agent
    #	to erase the cross-connect map for this port.
    #	
    def Lnxnm_get_nbsCmmcPortCrossConnect(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.83"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortCrossConnect(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.83"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 3)
    
    #### End   - Port - nbsCmmcPortCrossConnect #### 
    #### Start - Port - nbsCmmcPortEnableOper #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.86
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	disable
    #		3	enable
    #
    #	Description: 
    #	
    #	Actual current operational status of the port.  This object is
    #	related to the nbsCmmcPortEnableAdmin object, where users
    #	specify the administrative operational status desired.
    #	
    #	The value notSupported (1) indicates that the port has no ability to
    #	disable the transceiver.
    #	
    #	The value disable (2) indicates that this port's transceiver is not
    #	allowing traffic to flow through this port.
    #	
    #	The value enable (3) indicates that this port's transceiver allows
    #	traffic flow.
    #	
    def Lnxnm_get_nbsCmmcPortEnableOper(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.86"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortEnableOper #### 
    #### Start - Port - nbsCmmcPortMappingType #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.87
    #	Access = readwrite
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	unavailable
    #		3	open
    #		4	source
    #		5	destination
    #		6	sourceHelper
    #		7	interChasLink
    #
    #	Description: 
    #	
    #	Administrative crossbar mapping restrictions for this port.
    #	
    #	Non-crossbar ports must be reported as notSupported(1).
    #	If notSupported, any SET attempts will be rejected.  Users
    #	may not set this object to notSupported(1).
    #	
    #	Users may mark the port as unavailable(2).  If unavailable,
    #	the Agent will reject any attempts to map from or to this
    #	port.
    #	
    #	By default, each crossbar port is open(3).  Open ports have
    #	no mapping restrictions.
    #	
    #	Ports that are set to source(4) may be used as the input
    #	(nbsCmmcPortZoneIfIndexAdmin) port by any other crossbar
    #	port.  Their own input port may only be mapped to ports
    #	whose nbsCmmcPortMappingType is sourceHelper(6).
    #	
    #	Ports that are set to destination(5) may set their own input
    #	(nbsCmmcPortZoneIfIndexAdmin) port to any other crossbar
    #	port.  They may not be used as the input port for other
    #	ports.
    #	
    #	A sourceHelper(6) port is used to provide whatever sort of
    #	link indication is needed by external traffic sources that
    #	are connected to a source(4) port.
    #	
    #	Ports set to interChasLink(7) are physically cabled to
    #	another crossbar port in a separate chassis.  That
    #	connection should be entered by the user in the network
    #	topology objects nbsCmmcPortRMChassis, nbsCmmcPortRMSlot,
    #	and nbsCmmcPortRMPort for both those connected ports.
    #	
    def Lnxnm_get_nbsCmmcPortMappingType(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.87"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortMappingType(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.87"
        return self.Lnxnm_set_enum(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 7)
    
    #### End   - Port - nbsCmmcPortMappingType #### 
    #### Start - Port - nbsCmmcPortExternalLink1 #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.93
    #	Access = readwrite
#	Syntax = InterfaceIndex
    #
    #	Description: 
    #	
    #	Equivalent to the nbsCmmcPortRMChassis, nbsCmmcPortRMSlot,
    #	and nbsCmmcPortRMPort triplet.
    #	
    #	Set to 0 to indicate this port has no associated intra-node
    #	endpoint.
    #	
    def Lnxnm_get_nbsCmmcPortExternalLink1(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.93"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortExternalLink1(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.93"
    
    #### End   - Port - nbsCmmcPortExternalLink1 #### 
    #### Start - Port - nbsCmmcPortExternalLink2 #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.94
    #	Access = readwrite
#	Syntax = InterfaceIndex
    #
    #	Description: 
    #	
    #	For y-cable implementations - set by the user to indicate
    #	the second intra-node endpoint of a y-cable.
    #	
    #	Set to 0 to indicate this port has no associated intra-node
    #	y-cable endpoint.
    #	
    def Lnxnm_get_nbsCmmcPortExternalLink2(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.94"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortExternalLink2(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.94"
    
    #### End   - Port - nbsCmmcPortExternalLink2 #### 
    #### Start - Port - nbsCmmcPortNVAreaBanks #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.95
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The maximum number of executable images that can be stored
    #	locally on this module.
    #	
    #	This number does not count any memory banks that are in
    #	a modular subcomponent of this card. Please refer to
    #	nbsPartProgNVAreaStart and nbsPartProgNVAreaBanks for that
    #	information.
    #	
    #	
    #	Not supported value: 0
    #	
    def Lnxnm_get_nbsCmmcPortNVAreaBanks(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.95"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortNVAreaBanks #### 
    #### Start - Port - nbsCmmcPortFirmwareCaps #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.96
    #	Access = readonly
    #	Data Type = OctetString
    #	Minimum Size = 0
    #	Maximum Size = 16
    #
    #	Description: 
    #	
    #	This bitmask indicates which executable images this module can
    #	support.  This object is mandatory for all modules.
    #	
    #	Bit 0 is reserved.
    #	
    #	Subsequent bits refer to the nbsCmmcSysFirmwareTable.  Bit 1
    #	corresponds to the first table entry, Bit 2 to the second entry,
    #	and so on.  A bit is set (1) if that image is appropriate for this
    #	module, cleared (0) if unavailable.
    #	
    #	OCTET STRING bitmasks count the leftmost bit (MSB) as 0.
    #	
    #	A zero length OCTET STRING indicates that the
    #	nbsCmmcSysFirmwareTable is not supported by this agent.
    #	
    def Lnxnm_get_nbsCmmcPortFirmwareCaps(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.96"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortFirmwareCaps #### 
    #### Start - Port - nbsCmmcPortFirmwareLoad #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.97
    #	Access = readwrite
    #	Data Type = OctetString
    #	Minimum Size = 0
    #	Maximum Size = 16
    #
    #	Description: 
    #	
    #	This bitmask indicates which executable images this module
    #	has stored in its own NV area.  This object is mandatory for
    #	all modules.
    #	
    #	OCTET STRING bitmasks count the leftmost bit (MSB) as 0.  Bit 0
    #	indicates whether an executable image is loading.
    #	
    #	Subsequent bits refer to the nbsCmmcSysFirmwareTable.  Bit 1
    #	corresponds to the first table entry, Bit 2 to the second entry,
    #	and so on.  A bit is set (1) if that image is stored on this
    #	module, cleared (0) if not.
    #	
    #	Clearing bits has no effect. To erase an NV area, use the
    #	nbsCmmcSysNVAreaTable.
    #	
    #	Users may transfer a file to an NV area by setting the appropriate
    #	file's bit and the loading (MSB) bit to one (1).  Adding a file
    #	requires that the NM start a file transfer to this module, which
    #	is a lengthy operation. If a transfer session is already active
    #	(nbsCmmcSlotLoader is non-zero), writes to this object will be
    #	rejected.
    #	
    #	A zero length OCTET STRING indicates that the
    #	nbsCmmcSysFirmwareTable is not supported by this agent.
    #	
    def Lnxnm_get_nbsCmmcPortFirmwareLoad(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.97"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortFirmwareLoad(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.97"
        return self.Lnxnm_set_octet_string(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value), 0, 16)
    
    #### End   - Port - nbsCmmcPortFirmwareLoad #### 
    #### Start - Port - nbsCmmcPortNVAreaAdmin #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.98
    #	Access = readwrite
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	A SET on this object will force the corresponding
    #	nbsCmmcSysNvAreaStatus to primary, set this module's other
    #	memory banks to backup, and immediately load and execute
    #	the firmware image contained in the specified memory bank.
    #	
    #	A GET on this object will indicate the memory bank of this
    #	module that is currently designated as primary.
    #	
    #	Not supported value: -1
    #	
    def Lnxnm_get_nbsCmmcPortNVAreaAdmin(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.98"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    def Lnxnm_set_nbsCmmcPortNVAreaAdmin(self, chassis, slot, port, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        oid = "1.3.6.1.4.1.629.200.8.1.1.98"
        return self.Lnxnm_set_integer32(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port), str(value))
    
    #### End   - Port - nbsCmmcPortNVAreaAdmin #### 
    #### Start - Port - nbsCmmcPortNVAreaOper #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.99
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The nbsCmmcSysNVAreaBank of nbsCmmcSysNVAreaTable corresponding
    #	to the current operationally active firmware image.
    #	
    #	0 indicates the current active image is NOT in the NVAreaTable.
    #	
    #	Not supported value: -1
    #	
    def Lnxnm_get_nbsCmmcPortNVAreaOper(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.99"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortNVAreaOper #### 
    #### Start - Port - nbsCmmcPortLoader #### 
    #	OID = 1.3.6.1.4.1.629.200.8.1.1.100
    #	Access = readonly
    #	Data Type = Integer
    #
    #	Description: 
    #	
    #	The nbsCmmcSysLoaderIndex of nbsCmmcSysLoaderTable
    #	corresponding to the current loading session.
    #	
    #	0 indicates no loading session is active.
    #	
    def Lnxnm_get_nbsCmmcPortLoader(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.200.8.1.1.100"
        
        return self.Lnxnm_get(str(oid) + "." + str(chassis) + "." + str(slot) + "." + str(port))
    
    
    #### End   - Port - nbsCmmcPortLoader #### 
    #### Start - Optic - nbsOpticPortPolish #### 
    #	OID = 1.3.6.1.4.1.629.213.1.2.1.42
    #	Access = readonly
    #	Data Type = Enumeration
    #
    #	Enumerated Values
    #		#	Definition
    #		--------------------------
    #		1	notSupported
    #		2	pc
    #		3	upc
    #		4	apc
    #
    #	Description: 
    #	
    #	This object indicates the terminal polish.
    #	
    def Lnxnm_get_nbsOpticPortPolish(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        oid = "1.3.6.1.4.1.629.213.1.2.1.42"
        
        # Convert port to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot, port)
        
        return self.Lnxnm_get(str(oid) + "." + str(ifIndex))
    
    
    #### End   - Optic - nbsOpticPortPolish #### 
	# This code is auto generated via the MetaMIB
	#
	# BE AWARE THAT PROCEDURES IN THIS FILE ARE TEMPORARY AND NEED TO BE REVISITED WITH EACH NEW MCC RELEASE
	#
	# Only those objects with the correct Syntax will have Tcl procedures
	#
	# Only the objects with the following parameters will have GET procedures
	#	MAX-ACCESS = readwrite
	#	MAX-ACCESS = readonly
	#
	# Only the objects with the following parameters will have SET procedures
	#	MAX-ACCESS = readwrite
	#	MAX-ACCESS = writeonly
	#
	
	
    #### Start - Port - PortDeEmphasis
    #	Name: De-emphasis
    #	Family: Port De-emphasis
    #	Access: readwrite
    #	Element: Port
    #	Units: dB
    #	Data Type: Enum
    #
    #	Enumerated Values (Superset)
    #		#	Definition
    #		--------------------------
    #		1	0
    #		2	2
    #		3	4
    #		4	6
    #
    #	Description:
    #	Output De-emphasis
    #
    def Lnxnm_get_PortDeEmphasis(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Port De-emphasis", "De-emphasis", "Enum", "dB")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Get the administrative value
            return self.Lnxnm_get_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), 0, str(featureId), [ "0", "2", "4", "6"])
            
    def Lnxnm_get_PortDeEmphasis_oper(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Port De-emphasis", "De-emphasis", "Enum", "dB")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Get the operational value
            return self.Lnxnm_get_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), 1, str(featureId), [ "0", "2", "4", "6"])
            
    def Lnxnm_set_PortDeEmphasis(self, chassis, slot, port, value):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Port De-emphasis", "De-emphasis", "Enum", "dB")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Set the administrative value
            return self.Lnxnm_set_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), str(featureId), str(value), [ "0", "2", "4", "6"])
            
    #### End - Port - PortDeEmphasis
    #### Start - Port - PortSwing
    #	Name: Swing
    #	Family: Port Swing
    #	Access: readwrite
    #	Element: Port
    #	Units: level
    #	Data Type: Integer
    #	Range  (Superset)
    #		Minimum: 1
    #		Maximum: 6
    #
    #	Description:
    #	Output Swing
    #
    def Lnxnm_get_PortSwing(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Port Swing", "Swing", "Integer", "level")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis) + "." + str(slot) + "." + str(port), 0, str(featureId))
            
    def Lnxnm_get_PortSwing_oper(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Port Swing", "Swing", "Integer", "level")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis) + "." + str(slot) + "." + str(port), 1, str(featureId))
            
    def Lnxnm_set_PortSwing(self, chassis, slot, port, value):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Port Swing", "Swing", "Integer", "level")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Set the administrative value
            return self.Lnxnm_set_meta_integer(str(chassis) + "." + str(slot) + "." + str(port), str(featureId), str(value), 1, 6)
            
    #### End - Port - PortSwing
    #### Start - Port - PortFiberMode
    #	Name: Fiber Mode
    #	Family: Fiber Config On RJ45 Port
    #	Access: readwrite
    #	Element: Port
    #	Data Type: Enum
    #
    #	Enumerated Values (Superset)
    #		#	Definition
    #		--------------------------
    #		1	disabled
    #		2	enabled
    #
    #	Description:
    #	Set RJ45 port to work with fiber port on its line side
    #
    def Lnxnm_get_PortFiberMode(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Fiber Config On RJ45 Port", "Fiber Mode", "Enum", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Get the administrative value
            return self.Lnxnm_get_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), 0, str(featureId), [ "disabled", "enabled"])
            
    def Lnxnm_get_PortFiberMode_oper(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Fiber Config On RJ45 Port", "Fiber Mode", "Enum", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Get the operational value
            return self.Lnxnm_get_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), 1, str(featureId), [ "disabled", "enabled"])
            
    def Lnxnm_set_PortFiberMode(self, chassis, slot, port, value):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Fiber Config On RJ45 Port", "Fiber Mode", "Enum", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Set the administrative value
            return self.Lnxnm_set_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), str(featureId), str(value), [ "disabled", "enabled"])
            
    #### End - Port - PortFiberMode
    #### Start - Port - PortFiberSpeed
    #	Name: Fiber Speed
    #	Family: Fiber Config On RJ45 Port
    #	Access: readwrite
    #	Element: Port
    #	Units: Mbps
    #	Data Type: Enum
    #
    #	Enumerated Values (Superset)
    #		#	Definition
    #		--------------------------
    #		1	100
    #		2	1000
    #
    #	Description:
    #	Fiber Speed on line side of RJ45 port
    #
    def Lnxnm_get_PortFiberSpeed(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Fiber Config On RJ45 Port", "Fiber Speed", "Enum", "Mbps")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Get the administrative value
            return self.Lnxnm_get_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), 0, str(featureId), [ "100", "1000"])
            
    def Lnxnm_get_PortFiberSpeed_oper(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Fiber Config On RJ45 Port", "Fiber Speed", "Enum", "Mbps")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Get the operational value
            return self.Lnxnm_get_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), 1, str(featureId), [ "100", "1000"])
            
    def Lnxnm_set_PortFiberSpeed(self, chassis, slot, port, value):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Fiber Config On RJ45 Port", "Fiber Speed", "Enum", "Mbps")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Set the administrative value
            return self.Lnxnm_set_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), str(featureId), str(value), [ "100", "1000"])
            
    #### End - Port - PortFiberSpeed
    #### Start - Port - PortFiberAutoNeg
    #	Name: Fiber Auto-Neg
    #	Family: Fiber Config On RJ45 Port
    #	Access: readwrite
    #	Element: Port
    #	Data Type: Enum
    #
    #	Enumerated Values (Superset)
    #		#	Definition
    #		--------------------------
    #		1	disabled
    #		2	enabled
    #
    #	Description:
    #	Fiber Auto-Negotiation state on line side of RJ45 port
    #
    def Lnxnm_get_PortFiberAutoNeg(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Fiber Config On RJ45 Port", "Fiber Auto-Neg", "Enum", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Get the administrative value
            return self.Lnxnm_get_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), 0, str(featureId), [ "disabled", "enabled"])
            
    def Lnxnm_get_PortFiberAutoNeg_oper(self, chassis, slot, port):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Fiber Config On RJ45 Port", "Fiber Auto-Neg", "Enum", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Get the operational value
            return self.Lnxnm_get_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), 1, str(featureId), [ "disabled", "enabled"])
            
    def Lnxnm_set_PortFiberAutoNeg(self, chassis, slot, port, value):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Fiber Config On RJ45 Port", "Fiber Auto-Neg", "Enum", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Set the administrative value
            return self.Lnxnm_set_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), str(featureId), str(value), [ "disabled", "enabled"])
            
    #### End - Port - PortFiberAutoNeg
    #### Start - Port - PortPathTransmitters
    #	Name: Path Transmitters
    #	Family: Hd Pmc Port Config
    #	Access: writeonly
    #	Element: Port
    #	Data Type: Enum
    #
    #	Enumerated Values (Superset)
    #		#	Definition
    #		--------------------------
    #		1	disable-all
    #		2	enable-all
    #
    #	Description:
    #	The transmitter on each port in a data path
    #
    def Lnxnm_set_PortPathTransmitters(self, chassis, slot, port, value):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot, port)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot, port)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Hd Pmc Port Config", "Path Transmitters", "Enum", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot, port)):
            # Set the administrative value
            return self.Lnxnm_set_meta_enum(str(chassis) + "." + str(slot) + "." + str(port), str(featureId), str(value), [ "disable-all", "enable-all"])
            
    #### End - Port - PortPathTransmitters
    #### Start - Slot - SlotVoltMonitor
    #	Name: Blade Voltage
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Slot
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Blade Voltage Monitoring
    #
    def Lnxnm_get_SlotVoltMonitor(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Blade Voltage", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis) + "." + str(slot), 0, str(featureId))
            
    def Lnxnm_get_SlotVoltMonitor_oper(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Blade Voltage", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis, slot)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis) + "." + str(slot), 1, str(featureId))
            
    #### End - Slot - SlotVoltMonitor
    #### Start - Chassis - ChassisVoltMonitorBp1
    #	Name: Voltage Backplane & Slot 1
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Backplane and Slot 1 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitorBp1(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane & Slot 1", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitorBp1_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane & Slot 1", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitorBp1
    #### Start - Chassis - ChassisVoltMonitor1
    #	Name: Voltage Slot 1
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 1 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitor1(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 1", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitor1_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 1", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitor1
    #### Start - Chassis - ChassisVoltMonitorBp2
    #	Name: Voltage Backplane & Slot 2
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 2 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitorBp2(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane & Slot 2", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitorBp2_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane & Slot 2", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitorBp2
    #### Start - Chassis - ChassisVoltMonitor2
    #	Name: Voltage Slot 2
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 2 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitor2(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 2", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitor2_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 2", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitor2
    #### Start - Chassis - ChassisVoltMonitor3
    #	Name: Voltage Slot 3
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 3 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitor3(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 3", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitor3_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 3", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitor3
    #### Start - Chassis - ChassisVoltMonitor4
    #	Name: Voltage Slot 4
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 4 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitor4(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 4", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitor4_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 4", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitor4
    #### Start - Chassis - ChassisVoltMonitor5
    #	Name: Voltage Slot 5
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 5 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitor5(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 5", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitor5_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 5", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitor5
    #### Start - Chassis - ChassisVoltMonitorNm5
    #	Name: Voltage NM
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 5 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitorNm5(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage NM", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitorNm5_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage NM", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitorNm5
    #### Start - Chassis - ChassisVoltMonitorBp5
    #	Name: Voltage Backplane & Slot 5
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Backplane and Slot 5 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitorBp5(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane & Slot 5", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitorBp5_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane & Slot 5", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitorBp5
    #### Start - Chassis - ChassisVoltMonitor6
    #	Name: Voltage Slot 6
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 6 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitor6(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 6", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitor6_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 6", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitor6
    #### Start - Chassis - ChassisVoltMonitor7
    #	Name: Voltage Slot 7
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 7 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitor7(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 7", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitor7_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 7", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitor7
    #### Start - Chassis - ChassisVoltMonitor8
    #	Name: Voltage Slot 8
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 8 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitor8(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 8", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitor8_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Slot 8", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitor8
    #### Start - Chassis - ChassisVoltMonitorNm9
    #	Name: Voltage 288 BP NM
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Slot 9 Voltage Monitoring
    #
    def Lnxnm_get_ChassisVoltMonitorNm9(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage 288 BP NM", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisVoltMonitorNm9_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage 288 BP NM", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisVoltMonitorNm9
    #### Start - Chassis - ChassisBpVoltMonitor1
    #	Name: Voltage Backplane 1
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Backplane Voltage Monitoring 1
    #
    def Lnxnm_get_ChassisBpVoltMonitor1(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane 1", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisBpVoltMonitor1_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane 1", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisBpVoltMonitor1
    #### Start - Chassis - ChassisBpVoltMonitor2
    #	Name: Voltage Backplane 2
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Backplane Voltage Monitoring 2
    #
    def Lnxnm_get_ChassisBpVoltMonitor2(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane 2", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisBpVoltMonitor2_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane 2", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisBpVoltMonitor2
    #### Start - Chassis - ChassisBpVoltMonitor3
    #	Name: Voltage Backplane 3
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Backplane Voltage Monitoring 3
    #
    def Lnxnm_get_ChassisBpVoltMonitor3(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane 3", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisBpVoltMonitor3_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane 3", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisBpVoltMonitor3
    #### Start - Chassis - ChassisBpVoltMonitor4
    #	Name: Voltage Backplane 4
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Backplane Voltage Monitoring 4
    #
    def Lnxnm_get_ChassisBpVoltMonitor4(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane 4", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisBpVoltMonitor4_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane 4", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisBpVoltMonitor4
    #### Start - Chassis - ChassisBpVoltMonitor5
    #	Name: Voltage Backplane 5
    #	Family: Voltage Monitor
    #	Access: readonly
    #	Element: Chassis
    #	Units: Volts
    #	Data Type: Float
    #	Range  (Superset)
    #		Minimum: -inf
    #		Maximum: inf
    #
    #	Description:
    #	Backplane Voltage Monitoring 5
    #
    def Lnxnm_get_ChassisBpVoltMonitor5(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane 5", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisBpVoltMonitor5_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Voltage Monitor", "Voltage Backplane 5", "Float", "Volts")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisBpVoltMonitor5
    #### Start - Chassis - ChassisOptimInfoVer
    #	Name: Version
    #	Family: Optim File
    #	Access: readonly
    #	Element: Chassis
    #	Data Type: String
    #	String Size (Superset)
    #		Minimum Length: -inf
    #		Maximum Length: inf
    #
    #	Description:
    #	Optim File Info Ver
    #
    def Lnxnm_get_ChassisOptimInfoVer(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Optim File", "Version", "String", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisOptimInfoVer_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Optim File", "Version", "String", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisOptimInfoVer
    #### Start - Chassis - ChassisOptimInfoIdc
    #	Name: Idc
    #	Family: Optim File
    #	Access: readonly
    #	Element: Chassis
    #	Data Type: String
    #	String Size (Superset)
    #		Minimum Length: -inf
    #		Maximum Length: inf
    #
    #	Description:
    #	Optim File Info Idc
    #
    def Lnxnm_get_ChassisOptimInfoIdc(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Optim File", "Idc", "String", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisOptimInfoIdc_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Optim File", "Idc", "String", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisOptimInfoIdc
    #### Start - Chassis - ChassisOptimInfoSerialNum
    #	Name: Serial Num
    #	Family: Optim File
    #	Access: readonly
    #	Element: Chassis
    #	Data Type: String
    #	String Size (Superset)
    #		Minimum Length: -inf
    #		Maximum Length: inf
    #
    #	Description:
    #	Optim File Serial Num
    #
    def Lnxnm_get_ChassisOptimInfoSerialNum(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Optim File", "Serial Num", "String", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisOptimInfoSerialNum_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Optim File", "Serial Num", "String", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisOptimInfoSerialNum
    #### Start - Chassis - ChassisOptimInfoDate
    #	Name: Date
    #	Family: Optim File
    #	Access: readonly
    #	Element: Chassis
    #	Data Type: String
    #	String Size (Superset)
    #		Minimum Length: -inf
    #		Maximum Length: inf
    #
    #	Description:
    #	Optim File Info Date
    #
    def Lnxnm_get_ChassisOptimInfoDate(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Optim File", "Date", "String", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the administrative value
            return self.Lnxnm_get_meta(str(chassis), 0, str(featureId))
            
    def Lnxnm_get_ChassisOptimInfoDate_oper(self, chassis):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis)
        
        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis)
        
        # Find the ID for this feature
        featureId = self.__lnxnm_find_meta_feature("Optim File", "Date", "String", "")
        
        # Find if this feature exists for this location
        if (self.__lnxnm_exists_meta_variable(featureId, chassis)):
            # Get the operational value
            return self.Lnxnm_get_meta(str(chassis), 1, str(featureId))
            
    #### End - Chassis - ChassisOptimInfoDate
    #### Start - Link-Toggle - nbsCmmcSlotLinkToggleGroupMembers ####
    #   NON-autogenerated
    #
    #   OID = 1.3.6.1.4.1.629.217.2.2.1.15
    #   Access = readwrite
    #   Data Type = list
    #   Minimum Size = 0
    #   Maximum Size = 255
    #
    #   Description:
    #
    #   List of ports that belong to this group. ((1, 2, 3), (1,2,7))
    #
    def Lnxnm_get_nbsCmmcSlotLinkToggleGroupMembers(self, chassis, slot):
        # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)

        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)
        oid = "1.3.6.1.4.1.629.217.2.2.1.15"

        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)

        # Get the ":" separated string of ifIndexes from the server
        ifIndexStr = self.Lnxnm_get(str(oid) + "." + str(ifIndex))

        # Create a list of ifindexes
        ifIndexList = ifIndexStr.split(':')

        # Return a list of ifIndexes converted to csp
        return [self.__lnxnm_ifindex_to_csp(int(p)) for p in ifIndexList]


    # value must be a list
    def Lnxnm_set_nbsCmmcSlotLinkToggleGroupMembers(self, chassis, slot, value):
    # Make sure the CSP being used is the correct format
        self.__lnxnm_check_csp(chassis, slot)

        # Make sure the element being used exists
        if (self.Lnxnm_get_strict() == 1):
            self.__lnxnm_check_element_exists(chassis, slot)

        oid = "1.3.6.1.4.1.629.217.2.2.1.15"

        # Convert slot to ifIndex
        ifIndex = self.__lnxnm_csp_to_ifIndex(chassis, slot)

        ifIndexList = []
        if (len(value)):
            for port in value:
                if (len(port) != 3):
                    errorString = 'location syntax incorrect: the location \"' + str(port) + '\" is not formatted correctly'
                    raise mccLocSynFail(errorString)
                (c, s, p) = port;

                self.__lnxnm_check_csp(c, s, p)
                if (self.Lnxnm_get_strict() == 1):
                    self.__lnxnm_check_element_exists(c, s, p)
                ifIndexList.append(str(self.__lnxnm_csp_to_ifIndex(c, s, p)))
        else:
            ifIndexList = [0]

        ifIndexStr = ":".join([str(y) for y in ifIndexList])

        return self.Lnxnm_set_display_string(str(oid) + "." + str(ifIndex), ifIndexStr, 0, 255)

    #### End   - Link-Toggle - nbsCmmcSlotLinkToggleGroupMembers ####


    #######################################
    ######### End of MCC Class  ###########
    #######################################

#######################################
## MCC Class Specific Exceptions ######
#######################################
############### Native API Exceptions
# The connection is unsuccessful (421)   
class mccConnFail(Exception):
    def __init__(self, value):
        self.value = "421: " + value
    def __str__(self):
        return repr(self.value)

# The command is not recognized (500)
class mccUnrecCmd(Exception):
    def __init__(self, value):
        self.value = "500: " + value
    def __str__(self):
        return repr(self.value)

# The version of code on the MCC is unrecognized (505)
class mccUnrecVer(Exception):
    def __init__(self, value):
        self.value = "505: " + value
    def __str__(self):
        return repr(self.value)   

# Permission denied - Either on an OID or with an invalid username/password (530)
class mccPermDeny(Exception):
    def __init__(self, value):
        self.value = "530: " + value
    def __str__(self):
        return repr(self.value)

# Transaction failed (554)
class mccTranFail(Exception):
    def __init__(self, value):
        self.value = "554: " + value
    def __str__(self):
        return repr(self.value)
        
############### Python API Exceptions
# The version of NM code doesn't match the version of the Tcl-API code (1001)
class mccVersMisMatch(Exception):
    def __init__(self, value):
        self.value = "1001: " + value
    def __str__(self):
        return repr(self.value)
        
# The location syntax used is incorrect (1002)
class mccLocSynFail(Exception):
    def __init__(self, value):
        self.value = "1002: " + value
    def __str__(self):
        return repr(self.value)
            
# The location doesn't exist in the chassis (1003)
class mccLocNotAvail(Exception):
    def __init__(self, value):
        self.value = "1003: " + value
    def __str__(self):
        return repr(self.value)
            
# The user is already logged in (1004)
class mccLoggedInAlready(Exception):
    def __init__(self, value):
        self.value = "1004: " + value
    def __str__(self):
        return repr(self.value)
            
# The user is not logged in (1005)
class mccNotLoggedIn(Exception):
    def __init__(self, value):
        self.value = "1005: " + value
    def __str__(self):
        return repr(self.value)
            
# The argument list is too big or too small (1006)
class mccBadArgList(Exception):
    def __init__(self, value):
        self.value = "1006: " + value
    def __str__(self):
        return repr(self.value)
            
# The value used is invalid (1007)
class mccInvalidArg(Exception):
    def __init__(self, value):
        self.value = "1007: " + value
    def __str__(self):
        return repr(self.value)
            
# The global array for return table information has been pre-defined (1008)
class mccArrayRefUsed(Exception):
    def __init__(self, value):
        self.value = "1008: " + value
    def __str__(self):
        return repr(self.value)
            
# The MetaMIB OID doesn't exist in the defined element (1009)
class mccMetaFeatureNoLoc(Exception):
    def __init__(self, value):
        self.value = "1009: " + value
    def __str__(self):
        return repr(self.value)
            
# The MetaMIb OID isn't attached to a feature (1010)
class mccMetaFeatureInvalid(Exception):
    def __init__(self, value):
        self.value = "1010: " + value
    def __str__(self):
        return repr(self.value)
            
# The MetaMIB Enumeration returned isn't part of the list (1011)
class mccMetaFeatureNoEnum(Exception):
    def __init__(self, value):
        self.value = "1011: " + value
    def __str__(self):
        return repr(self.value)
            
# The source file being looked for isn't available (1012)
class mccSourceUnavailable(Exception):
    def __init__(self, value):
        self.value = "1012: " + value
    def __str__(self):
        return repr(self.value)

# Unknown error
class mccUnknown(Exception):
    def __init__(self, value):
        self.value = "9999: " + value
    def __str__(self):
        return repr(self.value)


