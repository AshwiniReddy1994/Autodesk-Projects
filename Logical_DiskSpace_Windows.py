import winrm, pysnow, re, time, socket, os, sys, logging, boto3, json, requests,base64, ast, requests_ntlm, platform
from winrm.exceptions import InvalidCredentialsError, WinRMError
from winrm.protocol import Protocol
from threading import Thread
from Queue import Queue
from bs4 import BeautifulSoup
from base64 import b64decode
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def Credentials():

    try:
        SurlEncryptedValue = os.environ['ssurl']
        SurlDecryptedValue = boto3.client('kms').decrypt(CiphertextBlob=b64decode(SurlEncryptedValue))['Plaintext']
        
        SsgetsecEncryptedValue = os.environ['ssgetsec']
        SsgetsecDecryptedValue = boto3.client('kms').decrypt(CiphertextBlob=b64decode(SsgetsecEncryptedValue))['Plaintext']

        SuserEncryptedValue = os.environ['suser']
        SuserDecryptedValue = boto3.client('kms').decrypt(CiphertextBlob=b64decode(SuserEncryptedValue))['Plaintext']
       
        SpassEncryptedValue = os.environ['spass']
        SpassDecryptedValue = boto3.client('kms').decrypt(CiphertextBlob=b64decode(SpassEncryptedValue))['Plaintext']
        
        SidEncryptedValue = os.environ['sid']
        SidDecryptedValue = boto3.client('kms').decrypt(CiphertextBlob=b64decode(SidEncryptedValue))['Plaintext']
        
        SnsidEncryptedValue = os.environ['snsid']
        SnsidDecryptedValue = boto3.client('kms').decrypt(CiphertextBlob=b64decode(SnsidEncryptedValue))['Plaintext']
        
        JeasessionEncryptedValue = os.environ['jeasession']
        JeaSessionName = boto3.client('kms').decrypt(CiphertextBlob=b64decode(JeasessionEncryptedValue))['Plaintext']
        
        SnowinstanceEncryptedValue = os.environ['snowinstance']
        SnowInstanceName = boto3.client('kms').decrypt(CiphertextBlob=b64decode(SnowinstanceEncryptedValue))['Plaintext']
        
        JumpboxServerEncryptedValue = os.environ['jumpserver']
        JumpboxServerIpAddress = boto3.client('kms').decrypt(CiphertextBlob=b64decode(JumpboxServerEncryptedValue))['Plaintext']
        
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        creds = {
                 "username": SuserDecryptedValue,
                 "password": SpassDecryptedValue,
                 "organization": "",
                 "domain": "ads"
                }

        # Fetching Token Number for Service Account
        ServiceAccounToken = requests.post(SurlDecryptedValue, data=creds, headers=headers, verify=False)      
        soup = BeautifulSoup(ServiceAccounToken.content)
        token = soup.find('token').string
        secret = {
                  "secretId": SidDecryptedValue,
                  "token": token
                 }
        # Fetching Service Account Credentials
        ServiceAccounCredentials = requests.post(SsgetsecDecryptedValue, data=secret, headers=headers, verify=False)
        
        soup = BeautifulSoup(ServiceAccounCredentials.content)
        ServiceAccountCredentialsOutput = soup.findAll("value")
            
        i = 0
        for user in ServiceAccountCredentialsOutput:
            if i == 0:
                i = i + 1
            elif i <= 2:
                
                StringValue = user.string
                
                if "svc" in StringValue:
                    ServerAccountUserName = StringValue
                else:
                    ServerAccountPassword = StringValue
                i = i + 1
        
        # Fetching Token Number for Snow Account
        SnowAccounToken = requests.post(SurlDecryptedValue, data=creds, headers=headers, verify=False)      
        soup = BeautifulSoup(SnowAccounToken.content)
        token = soup.find('token').string
        secret = {
                  "secretId": SnsidDecryptedValue,
                  "token": token
                 }
        # Fetching Snow Account Credentials
        SnowCredentials = requests.post(SsgetsecDecryptedValue, data=secret, headers=headers, verify=False)
        
        soup = BeautifulSoup(SnowCredentials.content)
        SnowCredentialsOutput = soup.findAll("value")
            
        i = 0
        for user in SnowCredentialsOutput:
            if i == 0:
                i = i + 1
            elif i <= 2:
                
                StringValue = user.string
                
                if "svc" in StringValue:
                    SnowUserName = StringValue
                else:
                    SnowPassword = StringValue
                i = i + 1
        
        return ServerAccountUserName, ServerAccountPassword, JeaSessionName, SnowInstanceName, SnowUserName, SnowPassword, JumpboxServerIpAddress
        
    except Exception as e:
        logging.warning("Message : Error at Credentials()...!" + str(e))

def NonR2ServerCommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId):

    try:
        CommentsOutput = '''Autobots unable to connect to JEA (ADSK_Autobot) end point. This may be due to:
                            1) Target Server runs Windows Server 2008/2003. (JEA feature is not available on these OS)
                            2) If Server OS is Windows Server 2008 R2 onwards, run the following command to check if the JEA endpoint exists.
                            Get-PSSessionConfigurtion -Name ADSK_Autobot'''
        
        SnowAuthenication = pysnow.Client(instance = InstanceName , user = SnowUserName, password = SnowPassWord)
        IncidentList = SnowAuthenication.resource(api_path='/table/incident')
        response = IncidentList.get(query={'sys_id': SnowSysId})
        
        response.update({'comments': CommentsOutput})
        response.update({'assignment_group': 'DES Windows Operations'})
        response.update({'assigned_to': 'Autobots'})
        response.update({'incident_state': 'New'})
        response.update({'assigned_to': ''})

        logging.warning("Message : JEA is not configured.")

    except Exception as e:
        print "Message : " + str(e)

def NonR2JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PsScript, SnowSysId):

    UserNameAccount, PassWord, EndPoint, InstanceName, SnowUserName,  SnowPassWord, JumpboxServerIpAddress =  Credentials()
    
    JeaSessionOutput = WindowsInstance.run_ps("""$password= ConvertTo-SecureString '"""+PassWord+"""' -AsPlainText -Force
    $cred= New-Object System.Management.Automation.PSCredential ('"""+UserName+"""',$password)
    Invoke-Command -ComputerName  """+HostName+""" -Configurationname """+EndPoint+""" -ScriptBlock {
    """+PsScript+"""
    } -Credential $cred""")
    
    if JeaSessionOutput.status_code == 0:
        return JeaSessionOutput
    else:
        NonR2ServerCommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId)
        sys.exit()

def JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PsScript):

    JeaSessionOutput = WindowsInstance.run_ps("""$password= ConvertTo-SecureString '"""+PassWord+"""' -AsPlainText -Force
    $cred= New-Object System.Management.Automation.PSCredential ('"""+UserName+"""',$password)
    Invoke-Command -ComputerName  """+HostName+""" -Configurationname """+EndPoint+""" -ScriptBlock {
    """+PsScript+"""
    } -Credential $cred""")
    
    if JeaSessionOutput.status_code == 0:
        return JeaSessionOutput
    else:
        sys.exit()

def OsNameAndDateTime(WindowsInstance, HostName, UserName, PassWord, EndPoint, SnowSysId):

    try:
        OsName = ((NonR2JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, 'Gwmi win32_operatingsystem | ForEach-Object caption', SnowSysId)).std_out).strip()
        
        return OsName
        
    except InvalidCredentialsError:
        logging.warning("Message : Invalid Credentials, Unable to Create Session.....!")
        sys.exit()

    except Exception as e:
        logging.warning("Message : Unable to  connect to " + HostName + " Exiting..!" + str(e))
        sys.exit()

def ServerDateTime(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        DateTime = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, 'Get-Date')).std_out).strip()
        PresentDate = (datetime.strptime(DateTime, "%A, %B %d, %Y %I:%M:%S %p")).strftime("%Y%m%d_%H%M%S")

        return PresentDate
    except InvalidCredentialsError:
        logging.warning("Message : Invalid Credentials, Unable to Create Session.....!")
        sys.exit()

    except:
        logging.warning("Message : Unable to  connect to " + HostName + " Exiting..!")
        sys.exit()

def DiskUsageForThread(WindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath):

    try:
        if HighVolumePath == "C:\\":
            PsScript = 'Get-WMIObject Win32_LogicalDisk | Where-Object {$_.Name -eq "' + HighVolumePath.rstrip("\\") + '"} | Select-MyObject Name,DriveType,@{n="TotalSize(GB)";e={"{0:n2}" -f ($_.size/1gb)}},@{n="FreeSpace(GB)";e={"{0:n2}" -f ($_.freespace/1gb)}},@{n="PercentFree(%)";e={"{0:n2}" -f ($_.freespace/$_.size*100)}} | Format-List'
        
        else:
            PsScript = 'Get-WMIObject Win32_LogicalDisk | Where-Object {$_.Name -eq "' + HighVolumePath.rstrip("\\") + '"} | Select-MyObject Name,DriveType,@{n="TotalSize(GB)";e={"{0:n2}" -f ($_.size/1gb)}},@{n="FreeSpace(GB)";e={"{0:n2}" -f ($_.freespace/1gb)}},@{n="PercentFree(%)";e={"{0:n2}" -f ($_.freespace/$_.size*100)}} | Format-List'
        
        DriverDetails = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PsScript)).std_out).strip()
        
        return DriverDetails

    except:
        return ""

def DiskPercentageForThread(WindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath):

    try:
        if HighVolumePath == "C:\\":
            DriveTotalSizeScript = '(Get-WMIObject Win32_LogicalDisk | Where-Object {$_.Name -eq "' + HighVolumePath.rstrip("\\") + '"} | Select-MyObject @{n="TotalSize";e={"{0:n2}" -f ($_.size/1gb)}}).TotalSize'
            DriveFreeSpaceScript = '(Get-WMIObject Win32_LogicalDisk | Where-Object {$_.Name -eq "' + HighVolumePath.rstrip("\\") + '"} | Select-MyObject @{n="FreeSpace";e={"{0:n2}" -f ($_.freespace/1gb)}}).FreeSpace'
        
        else:
            DriveTotalSizeScript = '(Get-WMIObject Win32_LogicalDisk | Where-Object {$_.Name -eq "' + HighVolumePath.rstrip("\\") + '"} | Select-MyObject @{n="TotalSize";e={"{0:n2}" -f ($_.size/1gb)}}).TotalSize'
            DriveFreeSpaceScript = '(Get-WMIObject Win32_LogicalDisk | Where-Object {$_.Name -eq "' + HighVolumePath.rstrip("\\") + '"} | Select-MyObject @{n="FreeSpace";e={"{0:n2}" -f ($_.freespace/1gb)}}).FreeSpace'
        
        DriveTotalSizeValue = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, DriveTotalSizeScript)).std_out).strip()
        DriveFreeSpaceValue = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, DriveFreeSpaceScript)).std_out).strip()
        DriveUsedSpaceValue = float(DriveTotalSizeValue) - float(DriveFreeSpaceValue)
        
        DrivePercentageValue = (float(DriveUsedSpaceValue) / float(DriveTotalSizeValue)) * 100
        DriveUsageThreshHoldValue = re.search("([0-9]{1,2}).([0-9]{1,2})",str(DrivePercentageValue)).group(1)
        
        return DriveUsageThreshHoldValue

    except:
        return ""

def TopFiveCosumingFiles(WindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath):

    try:
        if HighVolumePath == "C:\\":
            TopFiveFilesScript = PsScript = 'Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction "SilentlyContinue" | Where-Object {$_.FullName -notlike "C:\Windows\*" -and $_.length/1MB -gt 100 -and $_.Length/1MB -lt 2048} | Select-MyObject Name, @{Name="Size(GB)";Expression={ "{0:n2}" -f ($_.Length / 1GB)}},@{Name="Path";Expression={$_.directory}},@{Name="LastWriteTime";Expression={$_.LastWriteTime}} -First 5 | Format-Table -AutoSize | Out-String -Width 200'
        else:
            TopFiveFilesScript = 'Get-ChildItem -path ' + HighVolumePath + ' -recurse -Force -ErrorAction "SilentlyContinue" | sort-Object -property length -Descending | Select-MyObject Name, @{Name="Size(GB)";Expression={ "{0:N2}" -f ($_.Length / 1GB)}},@{Name="Path";Expression={$_.directory}},@{Name="LastWriteTime";Expression={$_.LastWriteTime}} -First 5 | Format-Table -AutoSize | Out-String -Width 200'
        
        TopFiveFilesOutput = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveFilesScript)).std_out).strip()

        
        return TopFiveFilesOutput
        
    except:
        return ""

def FolderSize(WindowsInstance, HostName, UserName, PassWord, EndPoint, FolderPath):

    try:
        Size = []
        for PathName in FolderPath:
            Size.append((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '"{0:N2}" -f ((Get-ChildItem -path "' + PathName + '" -recurse -Force -ErrorAction "SilentlyContinue" | Measure-MyObject -property length -sum ).sum /1000MB) + " GB"')).std_out)
        SizeValue = [ (i.strip("\n")).strip("\r") for  i in Size]
        
        return SizeValue

    except:
        return ""

def SizeConverter(num):

    for Size in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, Size)
        num /= 1024.0

def HighestUsageUserDummy(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        UsersList = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, 'Get-ChildItem -Path C:\Users | Format-List -Property Name')).std_out).split("\n")
        UserNameListPath = []
        for i in UsersList:
            if "Name" in i:
                UserNameListPath.append("C:\\Users\\" + ((i.lstrip("Name: ")).rstrip("\r")).strip())
        
        UsersUsageOutput = FolderSize(WindowsInstance, HostName, UserName, PassWord, EndPoint, UserNameListPath)

        MaxUsage = str(max([float((i.split())[0]) for i in UsersUsageOutput]))
        HighestUsageUserNameWithSize = ""
        for key,value in (dict(zip(UserNameListPath, UsersUsageOutput))).iteritems():
            if MaxUsage in value:
                HighestUsageUserNameWithSize += key + " " + str(value)
        
        HighestUsageUserName =  HighestUsageUserNameWithSize.strip()
        
        return HighestUsageUserName
        
    except:
        return ""

def TopFiveUsersFiles(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        
        TopFiveFilesScript = PsScript = 'Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction "SilentlyContinue" | Where-Object {$_.length/1MB -gt 100 -and $_.Length/1MB -lt 5120} | Select-MyObject Name, @{Name="Size(GB)";Expression={ "{0:n2}" -f ($_.Length / 1GB)}},@{Name="Path";Expression={$_.directory}},@{Name="LastWriteTime";Expression={$_.LastWriteTime}} -First 5 | Format-Table -AutoSize | Out-String -Width 200'
        TopFiveFilesOutput = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveFilesScript)).std_out).strip()
        
        return TopFiveFilesOutput
        
    except:
        return ""

def FilesDeletionPaths(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PredefinedListToDeletion = ["C:\\Windows\\ccmcache", "C:\\Windows\\SoftwareDistribution\\Download"]
        FolderSizeOutput  = FolderSize(WindowsInstance, HostName, UserName, PassWord, EndPoint, PredefinedListToDeletion)
        PredefinedPathSize = []
        for Path, Size in zip(PredefinedListToDeletion, FolderSizeOutput):
                PredefinedPathSize.append(Path + " - Size : " + Size + ",")
        
        CcmcacheSize = int(((FolderSizeOutput[0].strip(" GB")).split("."))[0])
        SoftwareDistributionDownloadSize = int(((FolderSizeOutput[1].strip(" GB")).split("."))[0])
        
        CacheDeltionStatus = ""; DownloadDeltionStatus = ""; RecycleDeletionStatus = ""
        
        TempZippedFolderStatus = ""
        if CcmcacheSize >= 5:
            CacheDeltion = JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, 'Get-Childitem -path C:\Windows\ccmcache | Remove-Item -Recurse -Force')
            if CacheDeltion.status_code == 0:
                CacheDeltionStatus += PredefinedPathSize[0] + " Files Successfully Deleted."
        else:
            CacheDeltionStatus += PredefinedPathSize[0] + " is Less Than 5 GB,Hence Not Deleting The Content in The Folder."
        if SoftwareDistributionDownloadSize >= 5:
            DownloadDeletion = JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, 'Get-Childitem -path C:\Windows\SoftwareDistribution\Download | Remove-Item -Recurse -Force')
            if DownloadDeletion.status_code == 0:
                DownloadDeltionStatus += PredefinedPathSize[1] + " Files Successfully Deleted."
        else:
            DownloadDeltionStatus += PredefinedPathSize[1] + " is Less Than 5 GB,Hence Not Deleting The Content in The Folder."
            
        RecycleDeletion = JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, "Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -exclude *.ini -ErrorAction SilentlyContinue")
        
        if RecycleDeletion.status_code == 0:
            RecycleDeletionStatus += "C:\\$Recycle.Bin Files Successfully Deleted."
        FilesDeletionStatus = CacheDeltionStatus + "\n" + DownloadDeltionStatus + "\n" + RecycleDeletionStatus
        
        return FilesDeletionStatus

    except:
        return ""

def PreDefinedPathSizeUsage(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PredefinedPathSize = ""; PredefinedList = ["C:\\Windows\\ccmcache", "C:\\Windows\\SoftwareDistribution\\Download", "C:\\Windows\\Temp", "C:\\Temp"]
        FolderSizeOutput  = FolderSize(WindowsInstance, HostName, UserName, PassWord, EndPoint, PredefinedList)
        
        for Path, Size in zip(PredefinedList, FolderSizeOutput):
                PredefinedPathSize += Path + "  :  " + Size + "\n"
        
        return PredefinedPathSize
        
    except:
        return ""

def FolderZip(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PresentDate = ServerDateTime(WindowsInstance, HostName, UserName, PassWord, EndPoint)
        PredefinedListToCompress = ["C:\\Temp"]
        FolderSizeOutput  = FolderSize(WindowsInstance, HostName, UserName, PassWord, EndPoint, PredefinedListToCompress)
        PredefinedPathSize = [Path + " - Size: " + Size + "," for Path, Size in (zip(PredefinedListToCompress, FolderSizeOutput))]
        
        TempFolderSizeThreshHoldValue = int(((FolderSizeOutput[0].strip(" GB")).split("."))[0])
        TempZippedFolderStatus = ""
        if TempFolderSizeThreshHoldValue < 2:
            
            if TempFolderSizeThreshHoldValue > 0:
                TempZippedFolderScript = 'Compress-Archive -Path C:\Temp\* -CompressionLevel Fastest -DestinationPath C:\\Temp\\' + PresentDate + '.zip'
                TempExlcudeZipScript = "Get-ChildItem -Path  'C:\Temp' -Recurse -exclude *.zip | Remove-Item -force -recurse"
                
                TempZippedFolder = JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, TempZippedFolderScript)
                
                if TempZippedFolder.status_code == 0:
                    OrignalFilesDeletionPostZip = JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, TempExlcudeZipScript)
                    TempZippedFolderStatus +=  "\n" + "Compression Status of Temp Files: " + "\n\n" + PredefinedPathSize[0] + ' Files Under C:\\Temp were Compressed as '  + PresentDate + '.zip'
                
                return TempZippedFolderStatus
                
            else:
                return "C:\\Temp Folder is Empty."
            
        else:
            return "C:\\Temp Folder Size is Greater Than 2 GB and the Size : " + ''.join(FolderSizeOutput)

    except:
        return ""

def HcActiveTcpConnections(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        ActiveTcpConnectionsScript = "netstat -aonp tcp"
        ActiveTcpConnectionsStdout = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, ActiveTcpConnectionsScript)).std_out).strip()
        
        ActiveTcpConnectionsOutput = "\n\n" + "Health Check : " + "\n\n" + "The Active TCP Connections are :" + "\n" + ActiveTcpConnectionsStdout
        
        return ActiveTcpConnectionsOutput

    except:
        return ""

def HcSyStemInfo(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        SyStemScript = 'Get-WmiObject -class Win32_OperatingSystem |  Select-MyObject -property @{Name="Server";e={$_.CSName}},@{Name="OS";e={$_.Caption}}, @{n="LastBootTime";e={$_.ConvertToDateTime($_.LastBootUpTime)}} | Format-List | Out-String -Width 200'
        SyStemScriptStdout = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, SyStemScript)).std_out).strip()
        
        SyStemScriptStdoutOutput = "\n\n" + "Operating System Details :" + "\n\n" + SyStemScriptStdout
        
        return SyStemScriptStdoutOutput

    except:
        return ""

def HcSystemServicesInfo(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        SystemServicesScript = 'Get-WmiObject win32_service | Sort-Object StartTime | Where-Object {$_.StartMode -eq "Auto" -and $_.State -ne "Running" -and $_.Name -ne "CcmExec"} | Select-MyObject DisplayName, Name, StartMode, State | Format-Table | Out-String -Width 200'
        SystemServicesStdout = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, SystemServicesScript)).std_out).strip()
        
        SystemServicesOutput = "\n\n" + "List of Stopped Services :" + "\n\n" + SystemServicesStdout
        
        return SystemServicesOutput

    except:
        return ""

def HcMemoryInfo(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        TotalPhysicalMemory = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(GWMI Win32_OperatingSystem).TotalVisibleMemorySize')).std_out).strip()
        AvailablePhysicalMemory = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(GWMI Win32_OperatingSystem).FreePhysicalMemory')).std_out).strip()
        VirtualMemoryMax = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(GWMI Win32_OperatingSystem).TotalVirtualMemorySize')).std_out).strip()
        VirtualMemoryAvailable = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(GWMI Win32_OperatingSystem).FreeVirtualMemory')).std_out).strip()
        
        TotalPhysicalMemorySize  = SizeConverter(int(TotalPhysicalMemory) * 1000)
        AvailablePhysicalMemorySize  = SizeConverter(int(AvailablePhysicalMemory) * 1000)
        VirtualMemoryMaxSize  = SizeConverter(int(VirtualMemoryMax) * 1000)
        VirtualMemoryAvailableSize  = SizeConverter(int(VirtualMemoryAvailable) * 1000)
        
        MemoryOutput = "\n\n" + "Memory Utilization Details :" + "\n\n" + "Total Physical Memory : " + TotalPhysicalMemorySize + "\n" + "Available Physical Memory : " + AvailablePhysicalMemorySize + "\n" + "Total Virtual Memory : " + VirtualMemoryMaxSize + "\n" + "Available Virtual Memory : " + VirtualMemoryAvailableSize
        
        return MemoryOutput

    except:
        return ""

def HcPageFileInfo(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PageFileInfo = 'Get-wmiobject -class "Win32_PageFileUsage" | Format-List Name,@{Name="BaseSize";e={$_.AllocatedBaseSize}},CurrentUsage,PeakUsage | Out-String -Width 200'
        PageFileInfoStdout = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PageFileInfo)).std_out).strip()
        
        PageFileInfoOutput = "\n\n" + "Page File Details :" + "\n\n" + PageFileInfoStdout
        
        return PageFileInfoOutput

    except:
        return ""

def HcTopFiveMemoryInfo(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        TopFiveWorkingSetProcessScript = 'Get-Process | Sort WS -Descending | Select ProcessName, @{l="MemorySize(GB)";e={"{0:n2}" -f ($_.WS/1GB)}}, Id -First 5 | Format-Table | out-string -Width 200'
        TopFiveWorkingSetProcessStdout = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveWorkingSetProcessScript)).std_out).strip()
        
        TopFiveWorkingSetProcessOutput = "\n\n" + "Top 5 Memory Consumers :" + "\n\n" + TopFiveWorkingSetProcessStdout
        
        return TopFiveWorkingSetProcessOutput

    except:
        return ""

def HcTopCpuInfo(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        TopFiveCpuUsageScript = "Get-WmiObject Win32_PerfFormattedData_PerfProc_Process -ComputerName . -filter IDprocess!=0 | Sort PercentProcessorTime -Descending | Select-MyObject  Name, @{l='CPU(%)'; e={$_.PercentProcessorTime}}, @{l='ID';e={$_.IDprocess}} -First 5 | ft"
        TopFiveCpuUsageStdout = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveCpuUsageScript)).std_out).strip()
        
        TopFiveCpuUsageOutput = "\n\n" + "Top 5 CPU Consumers :" + "\n\n" + TopFiveCpuUsageStdout
        
        return TopFiveCpuUsageOutput

    except:
        return ""

def CommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId, CommentsOutput, AlertStatus):

    try:
        SnowAuthenication = pysnow.Client(instance = InstanceName , user = SnowUserName, password = SnowPassWord)
        IncidentList = SnowAuthenication.resource(api_path='/table/incident')
        response = IncidentList.get(query={'sys_id': SnowSysId})
        response.update({'comments': CommentsOutput})
        response.update({'assignment_group': 'DES Windows Operations'})
        response.update({'assigned_to': 'Autobots'})
        
        if AlertStatus:
            response.update({'incident_state': 'Resolved'})
            response.update({'u_sub_state': 'With Workaround'})
            response.update({'close_code': 'Positive Alarm (Action taken)'})
            response.update({'u_close_code_subcategory': 'Infrastructure Issue'})
            response.update({'close_notes': 'Resolved by Auobots'})
            logging.warning("Message : Script Execution is Successful.Incident State is Resolved..!")
        else:
            response.update({'incident_state': 'Awaiting Assignment'})
            response.update({'assigned_to': ''})
            logging.warning("Message : Script Execution is Successful.Incident State is Awaiting Assignment..!")

    except Exception as e:
        logging.warning("Message : " + str(e))

def lambda_handler(event, context):

    logger.info("\n" + str(event))
    
    try:
        UserNameAccount, PassWord, EndPoint, InstanceName, SnowUserName,  SnowPassWord, JumpboxServerIpAddress =  Credentials()
        UserName = "ADS\\" + UserNameAccount
        
        HostName = ""; SnowSysId = ""; ShortDescription = ""
        
        try:
            for alert in (event.get("incident")).get("alerts"):
                for tag in (alert.get("tags")):
                    if tag.get("name") == "host":
                       HostName += ((str(tag.get("value")).encode("utf-8")))
            
            for alert in (event.get("incident")).get("alerts"):
                for tag in (alert.get("tags")):
                    if tag.get("name") == "short_description":
                       ShortDescription += ((str(tag.get("value")).encode("utf-8")))

            if ((event.get("incident")).get("changedOn")) == ((event.get("incident")).get("startedOn")):
                SnowSysId += (((event.get("shareResults")).get("servicenowSysId")).encode("utf-8"))
                logger.info("\n" + "New Ticket Sys Id : " + (((event.get("shareResults")).get("servicenowSysId")).encode("utf-8")))
                
            else:
                for result in (((event.get("shareResults")).get("result"))):
                    SnowSysId += ((result.get("sys_id")).encode("utf-8"))
                    logger.info("\n" + "Reopened Ticket Sys Id : " + ((result.get("sys_id")).encode("utf-8")))

            HighVolumePath = ""
            for path in ShortDescription.split():
                if "Capacity_" in path:
                    HighVolumePath += ((path.split("-")).pop())
                    break
                if  "Capacity" in path:
                    HighVolumePath += ((path.split("Capacity")).pop())
                    break
            
            logger.info("HostName : " + HostName)
            logger.info("ShortDescription : " + "\n" + ShortDescription)
            logger.info("Drive Name : " + HighVolumePath)
        except:
            pass
    
        
        CommonWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        CommonWindowsInstanceForNonR2Servers = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        FirstWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        SecondWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        ThirdWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        FourthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        FifthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        SixthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        SeventhWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        EighthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        NinethWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        TenthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        EleventhWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        TwelvethWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        ThirteenthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        FourteenthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        
        if HighVolumePath == "C:\\" :
        
            try:
                OsNameAndDateTime(CommonWindowsInstanceForNonR2Servers, HostName, UserName, PassWord, EndPoint, SnowSysId)
                def MainThreadTwo(FunctionName, WindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath, QueueName):
                    QueueName.put(FunctionName(WindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath))
                
                def MainThread(FunctionName, WindowsInstance, HostName, UserName, PassWord, EndPoint, QueueName):
                    QueueName.put(FunctionName(WindowsInstance, HostName, UserName, PassWord, EndPoint))
                
                Disk, DiskPercentage, TopFive, HighestUser, TempFiles, Predefined, FilesDeletion = Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue()
                Thread(target = MainThreadTwo, args=(DiskUsageForThread, FirstWindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath, Disk)).start()
                Thread(target = MainThreadTwo, args=(DiskPercentageForThread, SecondWindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath, DiskPercentage)).start()
                Thread(target = MainThreadTwo, args=(TopFiveCosumingFiles, ThirdWindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath, TopFive)).start()
                Thread(target = MainThread, args=(TopFiveUsersFiles, FourthWindowsInstance, HostName, UserName, PassWord, EndPoint, HighestUser)).start()
                Thread(target = MainThread, args=(FolderZip, FifthWindowsInstance, HostName, UserName, PassWord, EndPoint, TempFiles)).start()
                Thread(target = MainThread, args=(PreDefinedPathSizeUsage, SixthWindowsInstance, HostName, UserName, PassWord, EndPoint, Predefined)).start()
                time.sleep(5)
                Thread(target = MainThread, args=(FilesDeletionPaths, SeventhWindowsInstance, HostName, UserName, PassWord, EndPoint, FilesDeletion)).start()
                
                LogicalDriveDetails = Disk.get()
                ThresholdValue = DiskPercentage.get()
                TopFiveFilesOutput  =  TopFive.get()
                HighestUsageUserName =  HighestUser.get()
                TempFilesCompressStatus = TempFiles.get()
                PreDefinedPathSizeOut = Predefined.get()
                FilesDeletionStatus = FilesDeletion.get()
                
                CdriveCommentsOne = "\n\n" + "Top 5 Files Consuming Most Disk Space :" + "\n\n" + TopFiveFilesOutput + "\n\n" + "Top 5 Files of All Users : " + "\n\n" + HighestUsageUserName
                CdriveCommentsTwo = "\n\n" + "Pre-Listed Paths and Their Size Details :" + "\n\n" + PreDefinedPathSizeOut + "\n\n" + "File/Folder Deletion Details in Pre-Listed Paths :" + "\n\n" + FilesDeletionStatus + "\n\n" + TempFilesCompressStatus 
                
                MainComments = CdriveCommentsOne + CdriveCommentsTwo
                
                DriveUsageThreshHoldValue = DiskPercentageForThread(CommonWindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath)
                print "DriveUsageThreshHoldValue : ",DriveUsageThreshHoldValue,"\n","DriveUsageThreshHoldValue : Success"
                
                logger.info("\n" + "Logical Drive Utilization (Pre Autobot Execution) : " + ThresholdValue)
                logger.info("\n" + "Logical Drive Utilization (Post Autobot Execution) : " + DriveUsageThreshHoldValue)
                
                CommentsOne = "Logical Drive Utilization (Pre Autobots Execution) " + ThresholdValue + " %" + "\n\n" + "Drive Details : " + "\n\n" + LogicalDriveDetails
                CommentsTwo = "\n\n" + "Logical Drive Utilization (Post Autobots Execution) : " + DriveUsageThreshHoldValue + " %"
                
                CdriveFinalComments = CommentsOne + MainComments + CommentsTwo
                
                if (int(DriveUsageThreshHoldValue) <= 94):
                    if len(SnowSysId) > 0:
                        logger.info("\n" + CdriveFinalComments)
                        CommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId, CdriveFinalComments, True)
                    else:
                        logger.info("\n" + CdriveFinalComments)
                        logger.info("\n" + "Message : Script Execution Successful, unable to update comments to the Snow i.e Invalid SysId or SysId is empty")
                else:
                    if len(SnowSysId) > 0:
                        logger.info("\n" + CdriveFinalComments)
                        CommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId, CdriveFinalComments, False)
                    else:
                        logger.info("\n" + CdriveFinalComments)
                        logger.info("\n" + "Message : Script Execution Successful, unable to update comments to the Snow i.e Invalid SysId or SysId is empty")
                
            except:
                pass
        else:
            OsNameAndDateTime(CommonWindowsInstanceForNonR2Servers, HostName, UserName, PassWord, EndPoint, SnowSysId)
            def MainThreadTwo(FunctionName, WindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath, QueueName):
                QueueName.put(FunctionName(WindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath))
            def MainThread(FunctionName, WindowsInstance, HostName, UserName, PassWord, EndPoint, QueueName):
                QueueName.put(FunctionName(WindowsInstance, HostName, UserName, PassWord, EndPoint))
            
            Disk, TopFive, ActiveConn, SySInfo, ServicesInfo, MemoryInfo, PageFileInform, Top5MemoryInfo, Top5CpuInfo = Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue()
            Thread(target = MainThreadTwo, args=(DiskUsageForThread, FirstWindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath, Disk)).start()
            Thread(target = MainThreadTwo, args=(TopFiveCosumingFiles, SecondWindowsInstance, HostName, UserName, PassWord, EndPoint, HighVolumePath, TopFive)).start()
            Thread(target = MainThread, args=(HcActiveTcpConnections, ThirdWindowsInstance, HostName, UserName, PassWord, EndPoint, ActiveConn)).start()
            Thread(target = MainThread, args=(HcSyStemInfo, FourteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, SySInfo)).start()
            Thread(target = MainThread, args=(HcSystemServicesInfo, FifthWindowsInstance, HostName, UserName, PassWord, EndPoint, ServicesInfo)).start()
            Thread(target = MainThread, args=(HcMemoryInfo, SixthWindowsInstance, HostName, UserName, PassWord, EndPoint, MemoryInfo)).start()
            Thread(target = MainThread, args=(HcPageFileInfo, SeventhWindowsInstance, HostName, UserName, PassWord, EndPoint, PageFileInform)).start()
            Thread(target = MainThread, args=(HcTopFiveMemoryInfo, EighthWindowsInstance, HostName, UserName, PassWord, EndPoint, Top5MemoryInfo)).start()
            Thread(target = MainThread, args=(HcTopCpuInfo, NinethWindowsInstance, HostName, UserName, PassWord, EndPoint, Top5CpuInfo)).start()
            
            LogicalDriveExceptC = Disk.get()
            TopFiveFilesOutput  =  TopFive.get()
            ActiveConnStatus = ActiveConn.get()
            SySInfoStatus = SySInfo.get()
            ServicesInfoStatus = ServicesInfo.get()
            MemoryInfoStatus = MemoryInfo.get()
            PageFileInformStatus = PageFileInform.get()
            Top5MemoryInfoStatus = Top5MemoryInfo.get()
            Top5CpuInfoStatus = Top5CpuInfo.get()
            
            CommentsOne = "Drive Details : " + "\n\n" + LogicalDriveExceptC + "\n\n" + "Top 5 Files Consuming Most Disk Space :" + "\n\n" + str(TopFiveFilesOutput)
            HealthCheckOutput = ActiveConnStatus + SySInfoStatus + ServicesInfoStatus + MemoryInfoStatus + PageFileInformStatus + Top5MemoryInfoStatus + Top5CpuInfoStatus
            
            DriveComments = CommentsOne + HealthCheckOutput
            
            if len(SnowSysId) > 0:
                logger.info("\n" + DriveComments)
                CommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId, DriveComments, False)
            else:
                logger.info("\n" + DriveComments)
                logger.info("\n" + "Message : Script Execution Successful, unable to update comments to the Snow i.e Invalid SysId or SysId is empty")
    except:
        pass