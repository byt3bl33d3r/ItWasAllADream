from impacket.structure import Structure

#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/2825d22e-c5a5-47cd-a216-3e903fd6e030
class DRIVER_INFO_2_BLOB(Structure):
    structure = (
        ('cVersion','<L'),
        ('NameOffset', '<L'),
        ('EnvironmentOffset', '<L'),
        ('DriverPathOffset', '<L'),
        ('DataFileOffset', '<L'),
        ('ConfigFileOffset', '<L'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self,data):
        Structure.fromString(self, data)
        self['ConfigFileArray'] = self.rawData[self['ConfigFileOffset']:self['DataFileOffset']].decode('utf-16-le')
        self['DataFileArray'] = self.rawData[self['DataFileOffset']:self['DriverPathOffset']].decode('utf-16-le')
        self['DriverPathArray'] = self.rawData[self['DriverPathOffset']:self['EnvironmentOffset']].decode('utf-16-le')
        self['EnvironmentArray'] = self.rawData[self['EnvironmentOffset']:self['NameOffset']].decode('utf-16-le')
        self['NameArray'] = self.rawData[self['NameOffset']:len(self.rawData)].decode('utf-16-le')
