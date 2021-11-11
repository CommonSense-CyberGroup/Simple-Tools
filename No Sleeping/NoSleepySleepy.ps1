#No Sleepy Sleepy
#This script will send jusk keys to the PC in order to keep the machine awake
#This was developed for use where the user cannot control their sleep settings and wich to keep the PC from locking, going to sleep, or to keep them online in a chat program

$minutes = 0
while(1) {
    #Tell user what is going on
    Write-Host "Keeping PC Awake... Ctl+C to quit..."

    #Incriment munites for output time
    $minutes++

    #Do the thing
    $no_sleep = New-Object -ComObject WScript.Shell
    $no_sleep.SendKeys('+{F15}')

    #Sleep for 59sec
    Start-Sleep -seconds 60
}
