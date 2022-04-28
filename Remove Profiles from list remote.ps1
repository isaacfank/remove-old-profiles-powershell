<#
.DESCRIPTION
    Cleans up user profiles for WaaS
.EXAMPLE
    Update Termid in beginning of script
.NOTES
    Filename:   Clean-Profiles.ps1
    Author:     Isaac Fankhauser
    Created:    2022-4-20
    Updated:    2022-4-28 9:00
    TODO:       Fully Automate Everything
#>
#
$blank = write-host " "
#
$termid = read-host -Prompt "Please enter termID of the computer"
#
#Connect with remote computer
Invoke-Command -ComputerName $termid -ScriptBlock {
    #Get-CimInstance -Class Win32_UserProfile
    $blank = Write-Host ""
    #create variable as array
    $output = @()
    $outputorph = @()
    $outputcimorph = @()
    #get profile list from ciminstance
    $CIMlistall = Get-CimInstance -Class Win32_UserProfile | Where-Object {$_.Special -ne $true}
    $CIMlisttotal = $CIMlistall.count
    Write-Host "Total Profiles listed in Windows is $CIMlisttotal"
    #pull folder items from the C:\Users path
    $Cprofall = Get-ChildItem -Path c:\Users | Sort-Object LastWriteTime -Descending
    $Cproftotal = $Cprofall.count
    $blank
    Write-Host "Total Profiles on C:\Users is $Cproftotal"
    $orphanchoice = Read-Host -Prompt "Press y to check for Orphans"
    if ($orphanchoice -eq "y"){
        #
        #BEGIN *Check for orphaned profiles*
        #
        Write-Host "Checking C:\Users for Orphaned Profiles"
        $proflistorph = Get-ChildItem -Path C:\Users | Where-Object {($_.name -ne "Default") -and ($_.name -ne "Public")}
        #Turn folder name into local path
        $proflistorph.name | ForEach-Object { 
            if (($_ -ne "default") -or ($_ -ne "public")){
                $outputorph += "C:\Users\$_"
            }else{
            Write-out "Default or Public Detected, not removing"
            }
        }
        $outputorph | ForEach-Object {
            $prof = "$_"
            $CIM = $null
            $CIM = Get-CimInstance -Class Win32_UserProfile | Where-Object {$_.LocalPath -like $prof}
            if ($CIM -eq $null){
                Write-Host "$prof is an orphaned profile. Removing folder from C:\Users"
                Remove-Item -path $prof -Recurse -Force
            } else {
            }
        }
        $profallorph = Get-ChildItem -Path c:\Users | Sort-Object LastWriteTime -Descending
        $proftotalorph = $profallorph.count
        #
        #Find orphaned CIM objects
        #
        $blank
        write-host "Finding profiles in cim with no last use time"
        $CIMlistall | ForEach-Object {
            $CIMlp = $_.LocalPath
            if ($_.lastusetime -eq $null){
                Write-Host "$CIMlp has no last use time. Removing orphaned profile"
                $_ | Remove-CimInstance
            }
        }
        #
        #END *Check for orphaned profiles*
        #
        #Display new total of profiles
        #
        $CIMlistall = Get-CimInstance -Class Win32_UserProfile | Select-Object LocalPath, lastusetime, Special | Where-Object {$_.Special -ne $true}
        $CIMlisttotal = $CIMlistall.count
        Write-Host "NEW Total Profiles listed in Windows is $CIMlisttotal"
        #pull folder items from the C:\Users path
        $Cprofall = Get-ChildItem -Path c:\Users | Sort-Object LastWriteTime -Descending
        $Cproftotal = $Cprofall.count
        $blank
        Write-Host "NEW Total Profiles on C:\Users is $Cproftotal"
    } #end of if for orphan check

    $blank
    Write-Host "Now we will clear old profiles based on latest Temp folder write"
    #
    #Choose days loop
    #
    $errorloop = 1
    #
    while ($errorloop -eq 1){
        try {
            [int]$days = read-host -prompt "Delete Profiles older than"
            #Find latest write time from C:\Users\***\AppData\Local\Temp
            $usertemplatest = @()
            $proflisttemp = Get-ChildItem -Path C:\Users | Where-Object {($_.name -ne "Default") -and ($_.name -ne "Public")}
            $proflisttemp.name | ForEach-Object {
                $lastwrite = Get-ChildItem "c:\Users\$_\AppData\Local\temp"  | 
                Sort-Object -Property LastWriteTime -Descending | 
                Select-Object -First 1 | Select-Object -ExpandProperty LastWriteTime
                $lastwrite = [DateTime]$lastwrite
                $item = New-Object PSObject
                $item | Add-Member -type NoteProperty -Name 'name' -Value "$_"
                $item | Add-Member -type NoteProperty -Name 'LastWriteTime' -Value $lastwrite
                $usertemplatest += $item
            }
            $proflist = $usertemplatest | Sort-Object LastWriteTime -Descending | Where-Object {(($_.LastWriteTime) -lt (Get-Date).AddDays(-$days)) -and ($_.name -ne "Default") -and ($_.name -ne "Public") -and ($_.name -ne $env:UserName)}
            #$proflist = Get-ChildItem -Path C:\Users | Where-Object {(($_.LastWriteTime) -lt (Get-Date).AddDays(-$days)) -and ($_.name -ne "Default") -and ($_.name -ne "Public")}
            $newtotal = $usertemplatest.count - $proflist.count
            $proflistcount = $proflist.count
            Write-Host "Removing profiles older than $days days will remove $prolistcount profiles result in $newtotal remaining"
            $choice = Read-Host -Prompt "press y to continue / Press n to choose different amount of days"
        }
        catch {
            write-host "try a number next time" 
            continue
        }
        if ($choice -ne "y"){
            Write-host "choose amount of days again"
            $blank
        }else{
	        $errorloop = 0
	        }
    }
    
    
    #
    #Turn folder name into local path
    #
    $proflist.name | ForEach-Object { 
        if (($_ -ne "default") -or ($_ -ne "public")){
            $output += "C:\Users\$_"
        }else{
        Write-out "Default or Public Detected, not removing"
        }
    }
    Read-Host -Prompt "Press Enter to delete $proflistcount profiles"
    #
    #Run remove for each
    #
    $output | ForEach-Object {
        $prof = "$_"
        $CIM = $null
        Write-Host "Removing $prof"
        $CIM = Get-CimInstance -Class Win32_UserProfile | Where-Object {$_.LocalPath -like $prof}
        if ($CIM -eq $null){
            Write-Host "$prof is an orphaned profile. Removing folder from C:\Users"
            Remove-Item -path $prof -Recurse -Force
        } else {
            $CIM | Remove-CimInstance
            Write-Host "$prof has been removed"
        }
    }
    $profallend = Get-ChildItem -Path c:\Users | Sort-Object LastWriteTime -Descending
    $proftotalend = $profallend.count
    $blank
    Write-Host "Total Profiles after removal is $proftotalend. Please enjoy the rest of your day and thank you for flying with delta airlines."
    Read-Host -prompt "Press Enter to Exit"
}