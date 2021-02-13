import winrm, pysnow, re, time, socket, os, sys, logging, boto3, json, requests, base64, ast, requests_ntlm, platform
from winrm.exceptions import InvalidCredentialsError, WinRMError
from winrm.protocol import Protocol
from threading import Thread
from Queue import Queue
from bs4 import BeautifulSoup
from base64 import b64decode
from PrededfinedProcessesToKill import*

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
        
        Payload = {'comments': CommentsOutput, 
                   'assignment_group': 'DES Windows Operations', 
                   'assigned_to': 'Autobots', 
                   'incident_state': 'New', 
                   'assigned_to': ''}
        response.update(Payload)
        
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

def ServerOsName(WindowsInstance, HostName, UserName, PassWord, EndPoint, SnowSysId):

    try:
        OsName = ((NonR2JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, 'Gwmi win32_operatingsystem | ForEach-Object caption', SnowSysId)).std_out).strip()
        
        return OsName

    except InvalidCredentialsError:
        logging.warning("Message : Invalid Credentials, Unable to Create Session.....!")
        sys.exit()

    except:
        logging.warning("Message : Unable to connect to " + HostName + " Exiting..!")
        sys.exit()

def UsageOfRam(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        TotalPhysicalRamMemory = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, "(GWMI Win32_OperatingSystem).TotalVisibleMemorySize")).std_out
        AvailablePhysicalRamMemory = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, "(GWMI Win32_OperatingSystem).FreePhysicalMemory")).std_out
        
        UsedRam = int(TotalPhysicalRamMemory) - int(AvailablePhysicalRamMemory)
        UsedRamFloatValue = (float(UsedRam) / float(int(TotalPhysicalRamMemory))) * 100
        RamUtilazation = re.search("([0-9]{1,2}).([0-9]{1,2})",str(UsedRamFloatValue)).group(1)
        
        return RamUtilazation

    except:
        return ""

def TopFiveProcess(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PsScriptOne = 'Get-WmiObject Win32_Process | Sort-Object -Descending WS | Select-MyObject ProcessName,CommandLine,@{l="MemorySize(GB)";e={"{0:n2}" -f ($_.WS/1GB)}},@{n="Owner";e={$_.GetOwner().User}} -First 5 | Out-String -Width 200'
        
        TopFiveProcessNamesAlongWithCommandline = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PsScriptOne)).std_out).strip()
        
        return TopFiveProcessNamesAlongWithCommandline

    except:
        return ""

def TopFiveProcessToKill(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PsScript = 'Get-WmiObject Win32_Process | Sort-Object -Descending WS |  Select -ExpandProperty ProcessName -First 5'
        
        TopFiveProcessListBefore = (((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PsScript)).std_out).strip()).split()
        
        TopFiveProcessList = [i.strip("\r") for i in TopFiveProcessListBefore]
        
        return TopFiveProcessList

    except:
        return ""

def StopProcess(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessesBeforeKill):

    try:
        KilledProcessNames = ""
        for process in PrededfinedProcesses:
            if process in TopFiveProcessesBeforeKill:
                try:
                    KilledProcess = JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, 'Stop-Process -name ' + ((process).strip()).rstrip(".exe") + ' -Force ')
                    if KilledProcess.status_code == 0:
                        KilledProcessNames  += str(process) + "\n"
                except:pass
                time.sleep(2)
        
        return KilledProcessNames

    except:
        return ""

def SizeConverter(num):

    for Size in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, Size)
        num /= 1024.0

def RamUsageDetails(WindowsInstance, HostName, UserName, PassWord, EndPoint):
    
    try:
        TotalPhysicalMemoryInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(GWMI Win32_OperatingSystem).TotalVisibleMemorySize')).std_out).strip()
        AvailablePhysicalMemoryInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(GWMI Win32_OperatingSystem).FreePhysicalMemory')).std_out).strip()
        VirtualMemoryMaxInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(GWMI Win32_OperatingSystem).TotalVirtualMemorySize')).std_out).strip()
        VirtualMemoryAvailableInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(GWMI Win32_OperatingSystem).FreeVirtualMemory')).std_out).strip()
        
        TotalPhysicalMemorySize  = SizeConverter(int(TotalPhysicalMemoryInfo) * 1000)
        AvailablePhysicalMemorySize  = SizeConverter(int(AvailablePhysicalMemoryInfo) * 1000)
        VirtualMemoryMaxSize  = SizeConverter(int(VirtualMemoryMaxInfo) * 1000)
        VirtualMemoryAvailableSize  = SizeConverter(int(VirtualMemoryAvailableInfo) * 1000)
        
        RamUsageDetailsOutput = "Memory Utilization Details :" + "\n\n" + "Total Physical Memory : " + TotalPhysicalMemorySize + "\n" + "Available Physical Memory : " + AvailablePhysicalMemorySize + "\n" + "Total Virtual Memory : " + VirtualMemoryMaxSize + "\n" + "Available Virtual Memory : " + VirtualMemoryAvailableSize
        
        return RamUsageDetailsOutput

    except:
        return ""

def FirstCountersPB(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessesPostKill):

    try:
        PrivateBytes = ""
        
        PbOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + (TopFiveProcessesPostKill[0]).rstrip(".exe") + ')\Private Bytes").CounterSamples[0].CookedValue')).std_out
        try:PrivateBytes += TopFiveProcessesPostKill[0] + "  :  " + str(SizeConverter(int(PbOutput))) + "\n"
        except:pass
        Comments = "Top 5 Memory Consumers Counter Details :" + "\n\n" + "ProcessName : PrivateBytes" + "\n" + str(PrivateBytes)
        
        return Comments

    except:
        return ""

def SecondCountersPB(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessesPostKill):

    try:
        PrivateBytes = ""
        
        PbOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + (TopFiveProcessesPostKill[1]).rstrip(".exe") + ')\Private Bytes").CounterSamples[0].CookedValue')).std_out
        try:PrivateBytes += TopFiveProcessesPostKill[1] + "  :  " + str(SizeConverter(int(PbOutput))) + "\n"
        except:pass
        Comments = str(PrivateBytes)
        
        return Comments

    except:
        return ""

def ThirdCountersPB(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessesPostKill):

    try:
        PrivateBytes = ""
        
        PbOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + (TopFiveProcessesPostKill[2]).rstrip(".exe") + ')\Private Bytes").CounterSamples[0].CookedValue')).std_out
        try:PrivateBytes += TopFiveProcessesPostKill[2] + "  :  " + str(SizeConverter(int(PbOutput))) + "\n"
        except:pass
        Comments = str(PrivateBytes)
        
        return Comments

    except:
        return ""

def FourthCountersPB(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessesPostKill):

    try:
        PrivateBytes = ""
        
        PbOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + (TopFiveProcessesPostKill[3]).rstrip(".exe") + ')\Private Bytes").CounterSamples[0].CookedValue')).std_out
        try:PrivateBytes += TopFiveProcessesPostKill[3] + "  :  " + str(SizeConverter(int(PbOutput))) + "\n"
        except:pass
        Comments = str(PrivateBytes)
        
        return Comments

    except:
        return ""

def FifthCountersPB(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessesPostKill):

    try:
        PrivateBytes = ""
        
        PbOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + (TopFiveProcessesPostKill[4]).rstrip(".exe") + ')\Private Bytes").CounterSamples[0].CookedValue')).std_out
        try:PrivateBytes += TopFiveProcessesPostKill[4] + "  :  " + str(SizeConverter(int(PbOutput))) + "\n"
        except:pass
        Comments = str(PrivateBytes)
        
        return Comments

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

def HcDiskInfoScript(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        DiskInfoScript = 'Get-WMIObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq "3"} | Select-MyObject Name,DriveType,@{n="TotalSize(GB)";e={"{0:n2}" -f ($_.size/1gb)}},@{n="FreeSpace(GB)";e={"{0:n2}" -f ($_.freespace/1gb)}},@{n="PercentFree(%)";e={"{0:n2}" -f ($_.freespace/$_.size*100)}} | Format-List'
        DiskInfoStdout = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, DiskInfoScript)).std_out).strip()
        
        DiskInfoOutput = "\n\n" + "Disk Utilization :" + "\n\n" + DiskInfoStdout
        
        return DiskInfoOutput

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

def HcPageFileInfo(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PageFileInfo = 'Get-wmiobject -class "Win32_PageFileUsage" | Format-List Name,@{Name="BaseSize";e={$_.AllocatedBaseSize}},CurrentUsage,PeakUsage | Out-String -Width 200'
        PageFileInfoStdout = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PageFileInfo)).std_out).strip()
        
        PageFileInfoOutput = "\n\n" + "Page File Details :" + "\n\n" + PageFileInfoStdout
        
        return PageFileInfoOutput

    except:
        return ""

def TopFiveCpuInfo(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        CpuInfo = "Get-WmiObject Win32_PerfFormattedData_PerfProc_Process -ComputerName . -filter IDprocess!=0 | Sort PercentProcessorTime -Descending | Select-MyObject  Name, @{l='CPU(%)'; e={$_.PercentProcessorTime}}, @{l='ID';e={$_.IDprocess}} -First 5 |ft"
        CpuInfoStdout = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, CpuInfo)).std_out).strip()
        
        CpuInfoOutput = "\n\n" + "Top 5 CPU Consumers :" + "\n\n" + CpuInfoStdout
        
        return CpuInfoOutput

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
            logger.info("\n" + "Message : Script Execution is Successful.Incident State is Resolved..!")
        else:
            response.update({'incident_state': 'Awaiting Assignment'})
            response.update({'assigned_to': ''})
            logger.info("\n" + "Message : Script Execution is Successful.Incident State is Awaiting Assignment..!")
    except Exception as e:
        print "Message : " + str(e)

def lambda_handler(event, context):

    logger.info("\n" + str(event))
    
    try:
        UserNameAccount, PassWord, EndPoint, InstanceName, SnowUserName,  SnowPassWord, JumpboxServerIpAddress =  Credentials()
        UserName = "ADS\\" + UserNameAccount
        
        HostName = ""; SnowSysId = ""
        
        try:
            for alert in (event.get("incident")).get("alerts"):
                for tag in (alert.get("tags")):
                    if tag.get("name") == "host":
                       HostName += ((str(tag.get("value")).encode("utf-8")))

            if ((event.get("incident")).get("changedOn")) == ((event.get("incident")).get("startedOn")):
                SnowSysId += (((event.get("shareResults")).get("servicenowSysId")).encode("utf-8"))
                logger.info("\n" + "New Ticket Sys Id : " + (((event.get("shareResults")).get("servicenowSysId")).encode("utf-8")))
                
            else:
                for result in (((event.get("shareResults")).get("result"))):
                    SnowSysId += (result.get("sys_id")).encode("utf-8")
                    logger.info("\n" + "Reopened Ticket Sys Id : " + ((result).get("sys_id")).encode("utf-8"))
            
            logger.info("HostName : " + HostName)
        
        except:
            pass
        
        WindowsMainInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        
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
        FifteenthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        SixteenthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        SeventeenthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        EighteenthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        NineteenthWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        TwentythWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        
        OsName = ServerOsName(WindowsMainInstance, HostName, UserName, PassWord, EndPoint, SnowSysId)
        
        try:
            def MainThread(FunctionName, WindowsInstance, HostName, UserName, PassWord, EndPoint, QueueName):
                QueueName.put(FunctionName(WindowsInstance, HostName, UserName, PassWord, EndPoint))
            
            UsageInfo, ProcessesInfo, ProcessesListInfo  = Queue(), Queue(), Queue()
            Thread(target = MainThread, args=(UsageOfRam, FirstWindowsInstance, HostName, UserName, PassWord, EndPoint, UsageInfo)).start()
            Thread(target = MainThread, args=(TopFiveProcess, SecondWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessesInfo)).start()
            Thread(target = MainThread, args=(TopFiveProcessToKill, ThirdWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessesListInfo)).start()
            
            RamUtilazation = UsageInfo.get()
            TopFiveMemoryConsumingProcessNames = ProcessesInfo.get()
            TopFiveProcessesBeforeKillList = ProcessesListInfo.get()
            
            def MainThreadTwo(FunctionName, WindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessName, QueueName):
                QueueName.put(FunctionName(WindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessName))
                
            KiledProcessesInfo, ProcessesInfoPostKill, RamUsageDetailsInfo, ProcessesListForCountersInfo  = Queue(), Queue(), Queue(), Queue()
            Thread(target = MainThreadTwo, args=(StopProcess, FourthWindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessesBeforeKillList, KiledProcessesInfo)).start()
            time.sleep(10)
            Thread(target = MainThread, args=(TopFiveProcess, FifthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessesInfoPostKill)).start()
            Thread(target = MainThread, args=(RamUsageDetails, SixthWindowsInstance, HostName, UserName, PassWord, EndPoint, RamUsageDetailsInfo)).start()
            Thread(target = MainThread, args=(TopFiveProcessToKill, SeventhWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessesListForCountersInfo)).start()
            
            KilledPredefinedProcesses = KiledProcessesInfo.get()
            TopFiveProcessNamesPostKill = ProcessesInfoPostKill.get()
            MemoryUtilizationDetails = RamUsageDetailsInfo.get()
            ProcessNames = ProcessesListForCountersInfo.get()
            
            FirstPB, SecondPB, ThirdPB, FourthPB, FifthPB = Queue(), Queue(), Queue(), Queue(), Queue()
            Thread(target = MainThreadTwo, args=(FirstCountersPB, EighthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FirstPB)).start()
            Thread(target = MainThreadTwo, args=(SecondCountersPB, NinethWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, SecondPB)).start()
            Thread(target = MainThreadTwo, args=(ThirdCountersPB, TenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, ThirdPB)).start()
            Thread(target = MainThreadTwo, args=(FourthCountersPB, EleventhWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FourthPB)).start()
            Thread(target = MainThreadTwo, args=(FifthCountersPB, TwelvethWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FifthPB)).start()
            
            FirstPBOut = FirstPB.get()
            SecondPBOut = SecondPB.get()
            ThirdPBOut = ThirdPB.get()
            FourthPBOut = FourthPB.get()
            FifthPBOut = FifthPB.get()
            
            ThresholdValueInfo = Queue()
            time.sleep(10)
            Thread(target = MainThread, args=(UsageOfRam, ThirteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ThresholdValueInfo)).start()
            ThresholdValue = ThresholdValueInfo.get()
            
            ActiveConn, SySInfo, HcDiskInfo, ServicesInfo, PageFileInform , CpuInfo = Queue(), Queue(), Queue(), Queue(), Queue(), Queue()
            
            Thread(target = MainThread, args=(HcActiveTcpConnections, FourteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ActiveConn)).start()
            Thread(target = MainThread, args=(HcSyStemInfo, FifteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, SySInfo)).start()
            Thread(target = MainThread, args=(HcDiskInfoScript, SixteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, HcDiskInfo)).start()
            Thread(target = MainThread, args=(HcSystemServicesInfo, SeventeenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ServicesInfo)).start()
            Thread(target = MainThread, args=(HcPageFileInfo, EighteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, PageFileInform)).start()
            Thread(target = MainThread, args=(TopFiveCpuInfo, NineteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, CpuInfo)).start()
            
            ActiveConnStatus = ActiveConn.get()
            SySInfoStatus = SySInfo.get()
            HcDiskInfoStatus = HcDiskInfo.get()
            ServicesInfoStatus = ServicesInfo.get()
            PageFileInformStatus = PageFileInform.get()
            Top5CpuInfoStatus = CpuInfo.get()
            
            HealthCheckOutput = ActiveConnStatus + SySInfoStatus + HcDiskInfoStatus + ServicesInfoStatus + PageFileInformStatus + Top5CpuInfoStatus
            
            PrivateBytesOutput = FirstPBOut + SecondPBOut + ThirdPBOut + FourthPBOut + FifthPBOut
            FirstComments = "Top 5 Memory Consumers (Pre Autobots Execution)" + "\n" + str(TopFiveMemoryConsumingProcessNames) + "\n\n" + "Pre-Listed Processes that Were Killed : " + "\n" + str(KilledPredefinedProcesses)
            SecondComments = "\n" + "Top 5 Memory Consumers (Post Autobots Execution)" + "\n" + str(TopFiveProcessNamesPostKill) + "\n"
            CounterComments = "\n" + MemoryUtilizationDetails + "\n\n" + PrivateBytesOutput
            
            CommentsOutput = "Memory Utilization (Pre Autobots Execution) : " + RamUtilazation + " %" + "\n\n" + FirstComments + SecondComments + CounterComments + "\n" + "Memory Utilization (Post Autobots Execution) : " + ThresholdValue + " %" + "\n" + HealthCheckOutput
            
            if int(ThresholdValue) >= 95:
                
                if len(SnowSysId) > 0:
                    logger.info("\n" + CommentsOutput)
                    CommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId, CommentsOutput, False)
                else:
                    logger.info("\n" + CommentsOutput)
                    logger.info("\n" + "Message : Script Execution Successful, unable to update comments to the Snow i.e Invalid SysId or SysId is empty")
            else:
                if len(SnowSysId) > 0:
                    logger.info("\n" + CommentsOutput)
                    CommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId, CommentsOutput, True)
                else:
                    logger.info("\n" + CommentsOutput)
                    logger.info("\n" + "Message : Script Execution Successful, unable to update comments to the Snow i.e Invalid SysId or SysId is empty")
        except:
            pass
    except:
        pass