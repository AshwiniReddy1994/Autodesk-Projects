import winrm, pysnow, re, time, socket, os, sys, logging, boto3, json, requests,base64, ast, requests_ntlm, platform
from winrm.exceptions import InvalidCredentialsError, WinRMError
from winrm.protocol import Protocol
from threading import Thread
from Queue import Queue
from bs4 import BeautifulSoup
from base64 import b64decode

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
        
        logging.warning("Message : JEA is not configured....!")

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

    except:
        logging.warning("Message : Unable to  connect to " + HostName + " Exiting..!")
        sys.exit()

def FirstCpuUsage(WindowsInstance, HostName, UserName, PassWord, EndPoint):
    
    try:
        CpuUsagePercentageFirst = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '((get-counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 2).countersamples.cookedvalue)')).std_out).strip()
        
        return CpuUsagePercentageFirst

    except:
        return ""

def SecondCpuUsage(WindowsInstance, HostName, UserName, PassWord, EndPoint):
    
    try:
        
        CpuUsagePercentageSecond = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '((get-counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 2).countersamples.cookedvalue)')).std_out).strip()
        
        return CpuUsagePercentageSecond

    except:
        return ""

def ThirdCpuUsage(WindowsInstance, HostName, UserName, PassWord, EndPoint):
    
    try:
        
        CpuUsagePercentageThird = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '((get-counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 2).countersamples.cookedvalue)')).std_out).strip()
        
        return CpuUsagePercentageThird

    except:
        return ""

def ConsumingMoreCpuUsageProcess(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PsScriptInfo = 'Get-WmiObject Win32_PerfFormattedData_PerfProc_Process -ComputerName . -filter IDprocess!=0 | Sort PercentProcessorTime -Descending | Select-MyObject  Name, @{l="CPU(%)"; e={$_.PercentProcessorTime}}, @{l="ID";e={$_.IDprocess}} -First 5 | Format-Table'
        
        ConsumingMoreCpuUsageProcessList = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PsScriptInfo)).std_out).strip()
        
        return ConsumingMoreCpuUsageProcessList

    except:
        return ""

def ConsumingMoreCpuUsageProcessesListForCounters(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        
        PsScriptProcessInfo = '(Get-WmiObject Win32_PerfFormattedData_PerfProc_Process -ComputerName . -filter IDprocess!=0 | Sort PercentProcessorTime -Descending | Select-MyObject  Name -First 5).Name'
        
        ProcessNames = (((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PsScriptProcessInfo)).std_out).strip()).split("\n")
        
        ProcessNamesOut = [Process.rstrip("\r") for Process in ProcessNames]
        
        return ProcessNamesOut

    except:
        return ""

def LongRunningProcess(WindowsInstance, HostName, UserName, PassWord, EndPoint):
    
    try:
        PsScript = 'Get-Process | Sort-Object CPU -desc | Select-MyObject ProcessName,StartTime,Id -First 5 | Format-Table'
        LongRunningProcessStartTime  = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PsScript)).std_out).strip()
        
        return LongRunningProcessStartTime

    except:
        return ""

def FirstProcessCountersForPT(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        PrivilegedTimeBytes = ""
        
        PrivilegedTimeScript = '''$PrivilegedOut = (Get-Counter -Counter "\Process(''' + TopFiveProcessNames[0] + ''')\% Privileged Time").CounterSamples[0].CookedValue
                                  [math]::round($PrivilegedOut, 2)'''
        PtOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PrivilegedTimeScript)).std_out
        try:PrivilegedTimeBytes += TopFiveProcessNames[0] + "  :  " + str(PtOutput)
        except:pass
        
        Comments = "\n\n" + "Top 5 Processes (Counter Details)" + "\n\n" + "ProcessName : PrivilegedTime" + "\n" + PrivilegedTimeBytes

        return Comments

    except:
        return ""

def SecondProcessCountersForPT(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        PrivilegedTimeBytes = ""
        
        PrivilegedTimeScript = '''$PrivilegedOut = (Get-Counter -Counter "\Process(''' + TopFiveProcessNames[1] + ''')\% Privileged Time").CounterSamples[0].CookedValue
                                  [math]::round($PrivilegedOut, 2)'''
        PtOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PrivilegedTimeScript)).std_out
        try:PrivilegedTimeBytes += TopFiveProcessNames[1] + "  :  " + str(PtOutput)
        except:pass
        
        PrivilegedTimeBytesOut = PrivilegedTimeBytes
        
        return PrivilegedTimeBytesOut

    except:
        return ""

def ThirdProcessCountersForPT(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        PrivilegedTimeBytes = ""
        
        PrivilegedTimeScript = '''$PrivilegedOut = (Get-Counter -Counter "\Process(''' + TopFiveProcessNames[2] + ''')\% Privileged Time").CounterSamples[0].CookedValue
                                  [math]::round($PrivilegedOut, 2)'''
        PtOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PrivilegedTimeScript)).std_out
        try:PrivilegedTimeBytes += TopFiveProcessNames[1] + "  :  " + str(PtOutput)
        except:pass
        
        PrivilegedTimeBytesOut = PrivilegedTimeBytes
        
        return PrivilegedTimeBytesOut

    except:
        return ""

def FourthProcessCountersForPT(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        PrivilegedTimeBytes = ""
        
        PrivilegedTimeScript = '''$PrivilegedOut = (Get-Counter -Counter "\Process(''' + TopFiveProcessNames[3] + ''')\% Privileged Time").CounterSamples[0].CookedValue
                                  [math]::round($PrivilegedOut, 2)'''
        PtOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PrivilegedTimeScript)).std_out
        try:PrivilegedTimeBytes += TopFiveProcessNames[1] + "  :  " + str(PtOutput)
        except:pass
        
        PrivilegedTimeBytesOut = PrivilegedTimeBytes
        
        return PrivilegedTimeBytesOut

    except:
        return ""

def FifthProcessCountersForPT(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        PrivilegedTimeBytes = ""
        
        PrivilegedTimeScript = '''$PrivilegedOut = (Get-Counter -Counter "\Process(''' + TopFiveProcessNames[4] + ''')\% Privileged Time").CounterSamples[0].CookedValue
                                  [math]::round($PrivilegedOut, 2)'''
        PtOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PrivilegedTimeScript)).std_out
        try:PrivilegedTimeBytes += TopFiveProcessNames[1] + "  :  " + str(PtOutput)
        except:pass
        
        PrivilegedTimeBytesOut = PrivilegedTimeBytes
        
        return PrivilegedTimeBytesOut

    except:
        return ""

def FirstCounterListForHC(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        HandleCountBytes = ""
        HcOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + TopFiveProcessNames[0] + ')\Handle Count").CounterSamples[0].CookedValue')).std_out
        
        try:HandleCountBytes += TopFiveProcessNames[0] + "  :  " + str(HcOutput)
        except:pass

        Comments = "\n" + "ProcessName : HandleCountCounterValue" + "\n" + HandleCountBytes

        return Comments

    except:
        return ""

def SecondCounterListForHC(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        HandleCountBytes = ""
        HcOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + TopFiveProcessNames[1].strip() + ')\Handle Count").CounterSamples[0].CookedValue')).std_out
        try:HandleCountBytes += TopFiveProcessNames[1] + "  :  " + str(HcOutput)
        except:pass
      
        Comments = HandleCountBytes

        return Comments

    except:
        return ""

def ThirdCounterListForHC(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        HandleCountBytes = ""
        HcOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + TopFiveProcessNames[2].strip() + ')\Handle Count").CounterSamples[0].CookedValue')).std_out
        try:HandleCountBytes += TopFiveProcessNames[1] + "  :  " + str(HcOutput)
        except:pass
      
        Comments = HandleCountBytes

        return Comments

    except:
        return ""

def FourthCounterListForHC(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        HandleCountBytes = ""
        HcOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + TopFiveProcessNames[3].strip() + ')\Handle Count").CounterSamples[0].CookedValue')).std_out
        try:HandleCountBytes += TopFiveProcessNames[1] + "  :  " + str(HcOutput)
        except:pass
      
        Comments = HandleCountBytes

        return Comments

    except:
        return ""

def FifthCounterListForHC(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        HandleCountBytes = ""
        HcOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + TopFiveProcessNames[4].strip() + ')\Handle Count").CounterSamples[0].CookedValue')).std_out
        try:HandleCountBytes += TopFiveProcessNames[1] + "  :  " + str(HcOutput)
        except:pass
      
        Comments = HandleCountBytes

        return Comments

    except:
        return ""

def FirstCounterListTc(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        ThreadCountBytes = ""
        PbOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + TopFiveProcessNames[0] + ')\Thread Count").CounterSamples[0].CookedValue')).std_out
        try:ThreadCountBytes += TopFiveProcessNames[0] + "  :  " + str(PbOutput)
        except:pass
        
        Comments = "\n" + "ProcessName : ThreadCountCounterValue" + "\n" + ThreadCountBytes

        return Comments

    except:
        return ""

def SecondCounterListTc(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        ThreadCountBytes = ""
        PbOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + TopFiveProcessNames[1] + ')\Thread Count").CounterSamples[0].CookedValue')).std_out
        try:ThreadCountBytes += TopFiveProcessNames[1] + "  :  " + str(PbOutput)
        except:pass
        
        Comments = ThreadCountBytes

        return Comments

    except:
        return ""

def ThirdCounterListTc(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        ThreadCountBytes = ""
        PbOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + TopFiveProcessNames[2] + ')\Thread Count").CounterSamples[0].CookedValue')).std_out
        try:ThreadCountBytes += TopFiveProcessNames[1] + "  :  " + str(PbOutput)
        except:pass
        
        Comments = ThreadCountBytes

        return Comments

    except:
        return ""

def FourthCounterListTc(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        ThreadCountBytes = ""
        PbOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + TopFiveProcessNames[3] + ')\Thread Count").CounterSamples[0].CookedValue')).std_out
        try:ThreadCountBytes += TopFiveProcessNames[1] + "  :  " + str(PbOutput)
        except:pass
        
        Comments = ThreadCountBytes

        return Comments

    except:
        return ""

def FifthCounterListTc(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveProcessNames):

    try:
        ThreadCountBytes = ""
        PbOutput = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, '(Get-Counter -Counter "\Process(' + TopFiveProcessNames[4] + ')\Thread Count").CounterSamples[0].CookedValue')).std_out
        try:ThreadCountBytes += TopFiveProcessNames[1] + "  :  " + str(PbOutput)
        except:pass
        
        Comments = ThreadCountBytes

        return Comments

    except:
        return ""

def SizeConverter(num):

    for Size in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, Size)
        num /= 1024.0

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

def CommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId, CommentsOutput):

    try:
        SnowAuthenication = pysnow.Client(instance = InstanceName , user = SnowUserName, password = SnowPassWord)
        IncidentList = SnowAuthenication.resource(api_path='/table/incident')
        response = IncidentList.get(query={'sys_id': SnowSysId})
        
        Payload = {'comments': CommentsOutput,
                   'assignment_group': 'DES Windows Operations',
                   'assigned_to': 'Autobots',
                   'incident_state': 'Awaiting Assignment',
                   'assigned_to': ''}
        
        response.update(Payload)

        logging.warning("Script Execution Successful.Incident State is Awaiting Assignment...!")

    except Exception as e:
        logging.warning("Message : " + str(e))

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
        ProcessInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        
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
        TwentyOneWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        TwentyTwoWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        TwentyThreeWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        TwentyFourWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        TwentyFiveWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        TwentySixWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        TwentySevenWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        
        OsNameAndDateTime(WindowsMainInstance, HostName, UserName, PassWord, EndPoint, SnowSysId)
        
        try:
            def MainThread(FunctionName, WindowsInstance, HostName, UserName, PassWord, EndPoint, QueueName):
                QueueName.put(FunctionName(WindowsInstance, HostName, UserName, PassWord, EndPoint))
            
            ProcessNamesInfo, ConsumingMoreCpu  = Queue(), Queue()
            Thread(target = MainThread, args=(ConsumingMoreCpuUsageProcessesListForCounters, ProcessInstance, HostName, UserName, PassWord, EndPoint, ProcessNamesInfo)).start()
            Thread(target = MainThread, args=(ConsumingMoreCpuUsageProcess, FourthWindowsInstance, HostName, UserName, PassWord, EndPoint, ConsumingMoreCpu)).start()
            
            ProcessNames = ProcessNamesInfo.get()
            ConsumingMoreCpuUsageProcessList = ConsumingMoreCpu.get()
            
            def MainThreadTwo(FunctionName, WindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNamee, QueueName):
                QueueName.put(FunctionName(WindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNamee))
            
            FirstCpuUsageInfo, SecondCpuUsageInfo, ThirdCpuUsageInfo = Queue(), Queue(), Queue()
            
            Thread(target = MainThread, args=(FirstCpuUsage, FirstWindowsInstance, HostName, UserName, PassWord, EndPoint, FirstCpuUsageInfo)).start()
            time.sleep(10)
            Thread(target = MainThread, args=(SecondCpuUsage, SecondWindowsInstance, HostName, UserName, PassWord, EndPoint, SecondCpuUsageInfo)).start()
            time.sleep(10)
            Thread(target = MainThread, args=(ThirdCpuUsage, ThirdWindowsInstance, HostName, UserName, PassWord, EndPoint, ThirdCpuUsageInfo)).start()
            
            FirstCpuUsageOut = FirstCpuUsageInfo.get()
            SecondCpuUsageOut = SecondCpuUsageInfo.get()
            ThirdCpuUsageOut = ThirdCpuUsageInfo.get()
            
            AverageCpuUsageUsageFloatValue = (float(FirstCpuUsageOut) + float(SecondCpuUsageOut) + float(ThirdCpuUsageOut))/3
            AverageCpuUsagePercentage = re.search("[0-9]{0,2}.[0-9]{0,2}",str(AverageCpuUsageUsageFloatValue)).group()
            
            LongRunning, FirstPT, SecondPT, ThirdPT, FourthPT, FifthPT, FirstHC, SecondHC, ThirdHC, FourthHC, FifthHC, FirstTC, SecondTC, ThirdTC, FourthTC, FifthTC, ActiveConn, SySInfo, HcDiskInfo, ServicesInfo, MemoryInfo, PageFileInform, Top5MemoryInfo = Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue(), Queue()
            
            
            Thread(target = MainThread, args=(LongRunningProcess, FifthWindowsInstance, HostName, UserName, PassWord, EndPoint, LongRunning)).start()
            
            Thread(target = MainThreadTwo, args=(FirstProcessCountersForPT, SixthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FirstPT)).start()
            Thread(target = MainThreadTwo, args=(SecondProcessCountersForPT, SeventhWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, SecondPT)).start()
            Thread(target = MainThreadTwo, args=(ThirdProcessCountersForPT, EighthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, ThirdPT)).start()
            Thread(target = MainThreadTwo, args=(FourthProcessCountersForPT, NinethWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FourthPT)).start()
            Thread(target = MainThreadTwo, args=(FifthProcessCountersForPT, TenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FifthPT)).start()
            
            Thread(target = MainThreadTwo, args=(FirstCounterListForHC, EleventhWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FirstHC)).start()
            Thread(target = MainThreadTwo, args=(SecondCounterListForHC, TwelvethWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, SecondHC)).start()
            Thread(target = MainThreadTwo, args=(ThirdCounterListForHC, ThirteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, ThirdHC)).start()
            Thread(target = MainThreadTwo, args=(FourthCounterListForHC, FourteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FourthHC)).start()
            Thread(target = MainThreadTwo, args=(FifthCounterListForHC, FifteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FifthHC)).start()
            
            Thread(target = MainThreadTwo, args=(FirstCounterListTc, SixteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FirstTC)).start()
            Thread(target = MainThreadTwo, args=(SecondCounterListTc, SeventeenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, SecondTC)).start()
            Thread(target = MainThreadTwo, args=(ThirdCounterListTc, EighteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, ThirdTC)).start()
            Thread(target = MainThreadTwo, args=(FourthCounterListTc, NineteenthWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FourthTC)).start()
            Thread(target = MainThreadTwo, args=(FifthCounterListTc, TwentythWindowsInstance, HostName, UserName, PassWord, EndPoint, ProcessNames, FifthTC)).start()
            
            Thread(target = MainThread, args=(HcActiveTcpConnections, TwentyOneWindowsInstance, HostName, UserName, PassWord, EndPoint, ActiveConn)).start()
            Thread(target = MainThread, args=(HcSyStemInfo, TwentyTwoWindowsInstance, HostName, UserName, PassWord, EndPoint, SySInfo)).start()
            Thread(target = MainThread, args=(HcDiskInfoScript, TwentyThreeWindowsInstance, HostName, UserName, PassWord, EndPoint, HcDiskInfo)).start()
            Thread(target = MainThread, args=(HcSystemServicesInfo, TwentyFourWindowsInstance, HostName, UserName, PassWord, EndPoint, ServicesInfo)).start()
            Thread(target = MainThread, args=(HcMemoryInfo, TwentyFiveWindowsInstance, HostName, UserName, PassWord, EndPoint, MemoryInfo)).start()
            Thread(target = MainThread, args=(HcPageFileInfo, TwentySixWindowsInstance, HostName, UserName, PassWord, EndPoint, PageFileInform)).start()
            Thread(target = MainThread, args=(HcTopFiveMemoryInfo, TwentySevenWindowsInstance, HostName, UserName, PassWord, EndPoint, Top5MemoryInfo)).start()
            
            
            LongRunningProcessNames = LongRunning.get()
            
            FirstPTOut = FirstPT.get()
            SecondPTOut = SecondPT.get()
            ThirdPTOut = ThirdPT.get()
            FourthPTOut = FourthPT.get()
            FifthPTOut = FifthPT.get()
           
            FirstHCOut = FirstHC.get()
            SecondHCOut = SecondHC.get()
            ThirdHCOut = ThirdHC.get()
            FourthHCOut = FourthHC.get()
            FifthHCOut = FifthHC.get()
            
            FirstTCOut = FirstTC.get()
            SecondTCOut = SecondTC.get()
            ThirdTCOut = ThirdTC.get()
            FourthTCOut = FourthTC.get()
            FifthTCOut = FifthTC.get()
            
            ActiveConnStatus = ActiveConn.get()
            SySInfoStatus = SySInfo.get()
            HcDiskInfoStatus = HcDiskInfo.get()
            ServicesInfoStatus = ServicesInfo.get()
            MemoryInfoStatus = MemoryInfo.get()
            PageFileInformStatus = PageFileInform.get()
            Top5MemoryInfoStatus = Top5MemoryInfo.get()
            
            CommentsOne =  "CPU Utilization : " + "\n\n" + "Average CPU Usage % Value: " + AverageCpuUsagePercentage + " %" + "\n\n" + "Top 5 Processes (By CPU Usage) " + "\n\n" + str(ConsumingMoreCpuUsageProcessList)
            CommentsTwo = "\n\n" + "Top 5 Processes (By Age)" + "\n\n" + str(LongRunningProcessNames)
            CounterComments = FirstPTOut + SecondPTOut + ThirdPTOut + FourthPTOut + FifthPTOut + FirstHCOut + SecondHCOut + ThirdHCOut + FourthHCOut + FifthHCOut + FirstTCOut + SecondTCOut + ThirdTCOut + FourthTCOut + FifthTCOut
            HealthCheckOutput = ActiveConnStatus + SySInfoStatus + HcDiskInfoStatus + ServicesInfoStatus + MemoryInfoStatus + PageFileInformStatus + Top5MemoryInfoStatus
            
            CommentsOutput = CommentsOne + CommentsTwo + CounterComments + HealthCheckOutput
            
            if len(SnowSysId) > 0:
                logger.info("\n" + CommentsOutput)
                CommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId, CommentsOutput)
            else:
                logger.info("\n" + CommentsOutput)
                logger.info("\n" + "Message : Script Execution Successful, unable to update comments to the Snow i.e Invalid SysId or SysId is empty")
            
        except:
            pass
    except:
        pass