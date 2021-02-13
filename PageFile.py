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

def ServerOsName(WindowsInstance, HostName, UserName, PassWord, EndPoint, SnowSysId):

    try:
        OsName = ((NonR2JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, 'Gwmi win32_operatingsystem | ForEach-Object caption', SnowSysId)).std_out).strip()
        
        return OsName
        
    except InvalidCredentialsError:
        logging.warning("Message : Invalid Credentials, Unable to Create Session.....!")
        sys.exit()

    except Exception as e:
        logging.warning("Message : Unable to  connect to " + HostName + " Exiting..!" + str(e))
        sys.exit()

def OsNameAndDateTime(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        DateTime = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, 'Get-Date')).std_out).strip()
        PresentDate = (datetime.strptime(DateTime, "%A, %B %d, %Y %I:%M:%S %p")).strftime("%Y%m%d_%H%M%S")
        PresentTime = (datetime.strptime(DateTime, "%A, %B %d, %Y %I:%M:%S %p")).strftime("%H:%M:%S")

        return PresentDate, PresentTime
        
    except InvalidCredentialsError:
        logging.warning("Invalid Credentials, Unable to Create Session.....!")
        sys.exit()

    except:
        logging.warning("Unable to  connect to " + HostName + " Exiting..!")
        sys.exit()

def PageFileUsage(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PsScript = 'Get-wmiobject -class "Win32_PageFileUsage" | Format-List Name,AllocatedBaseSize,CurrentUsage,PeakUsage,InstallDate'
        PageFile = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PsScript)).std_out).strip()
        
        PageFileLocation = ""; AllocatedBase = "" ; CurrentUsage = "" ; PeakUsage = ""; InstallDate = ""
        for i in PageFile.split("\n"):
            if "Name" in i:
                PageFileLocation += ((i.lstrip("Name: ")).strip())
            if "AllocatedBaseSize" in i:
                AllocatedBase += str((i.lstrip("AllocatedBaseSize: ")).strip())
            if "CurrentUsage" in i:
                CurrentUsage += ((i.lstrip("CurrentUsage: ")).strip())
            if "PeakUsage" in i:
                PeakUsage += ((i.lstrip("PeakUsage: ")).strip())
            if "InstallDate" in i:
                 InstallDate += ((i.lstrip("InstallDate: ")).strip())
        AllocatedBaseSize = SizeConverter(int(AllocatedBase) * 10 **6)
        AvialablePageFileSizeValue = ((int(AllocatedBase) - int(CurrentUsage)))
        AvialablePageFileSize = SizeConverter(AvialablePageFileSizeValue * 10 **6)
        CurrentUsageSize = SizeConverter(int(CurrentUsage) * 10 **6)
        PeakUsageSize = SizeConverter(int(PeakUsage) * 10 **6)
        PageFilePercentageValue = (float(int(CurrentUsage)) / float(int(AllocatedBase))) * 100.00
        PageFilePercentage = str(re.search("[0-9]{1,2}",str(PageFilePercentageValue)).group())
        InstalledDate = str(re.search("[0-9]{8}",str(InstallDate)).group())
        InstallaionDate = (datetime.strptime(InstalledDate, '%Y%m%d')).strftime("%d/%m/%Y")
        
        
        OutputOne = "Page File Information : " + "\n\n" + "Allocated Pagefile Memory  : " + str(AllocatedBaseSize) + "\n" + "Available Pagefile Memory  : " + str(AvialablePageFileSize)
        OutputTwo = "\n" + "Used Pagefile Memory     : " + str(CurrentUsageSize) + "\n" + "Pagefile Usage: " + str(PageFilePercentage) + " %" + "\n" + "Page File Location " + str(PageFileLocation)
        OutputThree = "\n" + "Page File Peak Usage : " +str(PeakUsageSize) + "\n" + "Page File Installation Date : " + str(InstallaionDate)
        
        PageFileDetails = OutputOne + OutputTwo + OutputThree
        
        return PageFileDetails
        
    except Exception as e:
        logging.warning("Error at PageFileUsage()...!" + str(e))

def LogmanFilesDeletion(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PsScript = '''$del_date = (Get-Date).AddDays(-180)
                      Get-ChildItem -include *.blg -Path C:\\PerfMonLogs -Recurse | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $del_date } | Remove-Item -Force'''
        OsName = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, PsScript))

    except:
        return ""

def LogmanCreation(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        PresentDate, StartTime = OsNameAndDateTime(WindowsInstance, HostName, UserName, PassWord, EndPoint)
        
        LogmanFilesDeletion(WindowsInstance, HostName, UserName, PassWord, EndPoint)
        
        BlgFileCreationScript = 'Logman.exe create counter ' + HostName + '_' + PresentDate +' -f bincirc -max 500 -c "\LogicalDisk(*)\*" "\Memory\*" "\Network Interface(*)\*" "\Paging File(*)\*" "\PhysicalDisk(*)\*" "\Server\*" "\System\*" "\Process(*)\*" "\Processor(*)\*" "\Cache\*" -si 00:00:01 -o C:\\PerfMonLogs\\' + HostName + '_' + PresentDate + '.blg'
        BlgFileStartScript = 'Logman start ' + HostName + '_' + PresentDate
        BlgFileStopScript = 'Logman stop ' + HostName + '_' + PresentDate
        BlgFileCreationInfo = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, BlgFileCreationScript))
        BlgFileStartInfo = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, BlgFileStartScript))
        time.sleep(120)
        _Date, EndTime = OsNameAndDateTime(WindowsInstance, HostName, UserName, PassWord, EndPoint)
        BlgFileStopInfo = (JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, BlgFileStopScript))
        
        CreationOutput = "\n\n" + 'Logman ' + HostName + '_' + PresentDate + '_000001' + '.blg' + ' ' + " is Successfully Created under " + "C:\\PerfMonLogs" + "\n\n"
        StartOutput = 'Logman ' + HostName + '_' + PresentDate + '_000001' + '.blg' + ' ' + " is Started at " + str(StartTime) + "\n\n"
        StopOutput = 'Logman ' + HostName + '_' + PresentDate + '_000001' + '.blg' + ' ' + " is Stopped at " + str(EndTime) + "\n"
        
        LogmanCreationOutput =  CreationOutput + StartOutput + StopOutput
        
        return LogmanCreationOutput

    except Exception as e:
        logging.warning("Message : " + stre(e))

def SizeConverter(num):

    for Size in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, Size)
        num /= 1024.0

def HealthCheck(WindowsInstance, HostName, UserName, PassWord, EndPoint):

    try:
        ActiveTcpConnectionsInfoScript = "netstat -aonp tcp"
        SyStemInfoScript = 'Get-WmiObject -class Win32_OperatingSystem |  Select-MyObject -property @{Name="Server";e={$_.CSName}},@{Name="OS";e={$_.Caption}}, @{n="LastBootTime";e={$_.ConvertToDateTime($_.LastBootUpTime)}} | Format-List | Out-String -Width 200'
        DiskInfoScript = 'Get-WMIObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq "3"} | Select-MyObject Name,DriveType,@{n="TotalSize(GB)";e={"{0:n2}" -f ($_.size/1gb)}},@{n="FreeSpace(GB)";e={"{0:n2}" -f ($_.freespace/1gb)}},@{n="PercentFree(%)";e={"{0:n2}" -f ($_.freespace/$_.size*100)}} | Format-List'
        SystemServicesInfoScript = 'Get-WmiObject win32_service | Sort-Object StartTime | Where-Object {$_.StartMode -eq "Auto" -and $_.State -ne "Running" -and $_.Name -ne "CcmExec"} | Select-MyObject DisplayName, Name, StartMode, State | Format-Table | Out-String -Width 200'
        
        TotalPhysicalMemoryInfoScript = '(GWMI Win32_OperatingSystem).TotalVisibleMemorySize'
        AvailablePhysicalMemoryInfoScript = '(GWMI Win32_OperatingSystem).FreePhysicalMemory'
        TotalVirtualMemoryInfoScript = '(GWMI Win32_OperatingSystem).TotalVirtualMemorySize'
        VirtualMemoryAvailableInfoScript = '(GWMI Win32_OperatingSystem).FreeVirtualMemory'
        TopFiveWorkingSetProcessInfoScript = 'Get-Process | Sort WS -Descending | Select ProcessName, @{l="MemorySize(GB)";e={"{0:n2}" -f ($_.WS/1GB)}}, Id -First 5 | Format-Table | out-string -Width 200'
        TopFiveCpuUsageInfoScript = "Get-WmiObject Win32_PerfFormattedData_PerfProc_Process -ComputerName . -filter IDprocess!=0 | Sort PercentProcessorTime -Descending | Select-MyObject  Name, @{l='CPU(%)'; e={$_.PercentProcessorTime}}, @{l='ID';e={$_.IDprocess}} -First 5 |ft"
        
        ActiveTcpConnectionsInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, ActiveTcpConnectionsInfoScript)).std_out).strip()
        SyStemInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, SyStemInfoScript)).std_out).strip()
        DiskInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, DiskInfoScript)).std_out).strip()
        SystemServicesInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, SystemServicesInfoScript)).std_out).strip()
        
        TotalPhysicalMemoryInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, TotalPhysicalMemoryInfoScript)).std_out).strip()
        AvailablePhysicalMemoryInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, AvailablePhysicalMemoryInfoScript)).std_out).strip()
        VirtualMemoryMaxInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, TotalVirtualMemoryInfoScript)).std_out).strip()
        VirtualMemoryAvailableInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, VirtualMemoryAvailableInfoScript)).std_out).strip()
        
        TotalPhysicalMemorySize  = SizeConverter(int(TotalPhysicalMemoryInfo) * 1000)
        AvailablePhysicalMemorySize  = SizeConverter(int(AvailablePhysicalMemoryInfo) * 1000)
        VirtualMemoryMaxSize  = SizeConverter(int(VirtualMemoryMaxInfo) * 1000)
        VirtualMemoryAvailableSize  = SizeConverter(int(VirtualMemoryAvailableInfo) * 1000)
        
        TopFiveWorkingSetProcessInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveWorkingSetProcessInfoScript)).std_out).strip()
        TopFiveCpuUsageInfo = ((JeaSession(WindowsInstance, HostName, UserName, PassWord, EndPoint, TopFiveCpuUsageInfoScript)).std_out).strip()
        
        HealthCheckOutputOne = "\n\n" + "Health Check : " + "\n\n" + "The Active TCP Connections are :" + "\n" + ActiveTcpConnectionsInfo
        HealthCheckOutputTwo = "\n\n" + "Operating System Details :" + "\n\n" + SyStemInfo + "\n\n" + "Disk Utilization :" + "\n\n" + DiskInfo
        HealthCheckOutputThree = "\n\n" + "List of Stopped Services :" + "\n\n" + SystemServicesInfo
        HealthCheckOutputFour = "\n\n" + "Memory Utilization Details :" + "\n\n" + "Total Physical Memory : " + TotalPhysicalMemorySize + "\n" + "Available Physical Memory : " + AvailablePhysicalMemorySize + "\n" + "Total Virtual Memory : " + VirtualMemoryMaxSize + "\n" + "Available Virtual Memory : " + VirtualMemoryAvailableSize
        HealthCheckOutputFive = "\n\n" + "Top 5 Memory Consumers :" + "\n\n" + TopFiveWorkingSetProcessInfo
        HealthCheckOutputSix = "\n\n" + "Top 5 CPU Consumers :" + "\n\n" + TopFiveCpuUsageInfo
        
        HealthCheckOutput = HealthCheckOutputOne + HealthCheckOutputTwo + HealthCheckOutputThree + HealthCheckOutputFour + HealthCheckOutputFive + HealthCheckOutputSix
        
        return HealthCheckOutput

    except:
        return ""

def CommentsUpdation(InstanceName, SnowUserName, SnowPassWord, SnowSysId, CommentsOutput):

    try:
        SnowAuthenication = pysnow.Client(instance = InstanceName , user = SnowUserName, password = SnowPassWord)
        IncidentList = SnowAuthenication.resource(api_path='/table/incident')
        response = IncidentList.get(query={'sys_id': SnowSysId})
        response.update({'comments': CommentsOutput})
        response.update({'assignment_group': 'DES Windows Operations'})
        response.update({'assigned_to': 'Autobots'})
        response.update({'incident_state': 'Awaiting Assignment'})
        response.update({'assigned_to': ''})

        logging.warning("Message : Script Execution Successful.Incident State is Awaiting Assignment.")

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
                    SnowSysId += ((result.get("sys_id")).encode("utf-8"))
                    logger.info("\n" + "Reopened Ticket Sys Id : " + ((result.get("sys_id")).encode("utf-8")))

            logger.info("HostName : " + HostName)
            
        except:
            pass
        
        WindowsMainInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        
        WindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        SecondWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        ThirdWindowsInstance = winrm.Session(JumpboxServerIpAddress, auth=(UserName, PassWord), transport = "ntlm", server_cert_validation='ignore')
        
        ServerOsName(WindowsMainInstance, HostName, UserName, PassWord, EndPoint, SnowSysId)
        
        try:
        
            def MainThread(FunctionName, WindowsInstance, HostName, UserName, PassWord, EndPoint, QueueName):
                QueueName.put(FunctionName(WindowsInstance, HostName, UserName, PassWord, EndPoint))
            
            LogmanCreationStorage, HealthCheckStorage, PageFileUsageStorage = Queue(), Queue(), Queue()
            Thread(target = MainThread, args=(LogmanCreation, WindowsInstance, HostName, UserName, PassWord, EndPoint, LogmanCreationStorage)).start()
            Thread(target = MainThread, args=(HealthCheck, SecondWindowsInstance, HostName, UserName, PassWord, EndPoint, HealthCheckStorage)).start()
            Thread(target = MainThread, args=(PageFileUsage, ThirdWindowsInstance, HostName, UserName, PassWord, EndPoint, PageFileUsageStorage)).start()
            
            LogmanFinalOutput  =  LogmanCreationStorage.get()
            HealthCheckComments = HealthCheckStorage.get()
            PageFileUsageComments = PageFileUsageStorage.get()
            
            
            CommentsOutput = PageFileUsageComments + LogmanFinalOutput + HealthCheckComments
            
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