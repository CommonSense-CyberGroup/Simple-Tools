#This script will show Netstat info for a specific service on a Windows PC. The user will be asked what service they wish to examine
#and then it will pul all the traffic associated with that service. It will also try and resolve the destination IP to a FQDN to display to the user

#Set initial variables
$netstat = netstat -aonf | Select-String -pattern "(TCP|UDP)"
$process_list = Get-Process
$service = Read-Host -Prompt "Name of the service you wish to see: "
$ErrorActionPreference = 'silentlycontinue'

#Run NetStat and get the output
foreach ($result in $netstat) {
   $split_array = $result -split " "
   $ip = $split_array[10]

   #Get the process name we want to look for
   $proc_ID = $split_array[$split_array.length – 1]
   $process_name = $process_list | Where-Object {$_.id -eq $proc_ID} | select processname
   
   #Only print out netstat results for the process requested and try to turn the IP to FQDN
   if ($process_name.processname -eq $service.ToLower())
   {
        #If the line is actually an ip (destination)
        if ($ip.Contains("."))
        {
            #Try to run nslookup on the IP
            try {
                    $fqdn = nslookup $ip.Split(":")[0] | Select-String Name
                    $split_array[$split_array.length – 1] = $proc_ID + " " + $process_name.processname + "   " + $fqdn
                    $split_array -join " "
                }

                #If the nslookup cannot find the IP, still print pretty
            catch {
                    $split_array[$split_array.length – 1] = $proc_ID + " " + $process_name.processname
                    $split_array -join " "
            }
        }
   }
}