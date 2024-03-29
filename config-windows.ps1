#DEBUT

##########################IMPORTATION DE LA FONCTION POUR TESTER LES CHEMINS REGISTRE##############################
function Test-RegistryValue {

    param (
    
     [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Path,
    
    [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Value
    )
    
    try {
    
    Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
     return $true
     }
    
    catch {
    
    return $false
    
    }
    
    }
##########################FIN IMPORTATION DE LA FONCTION POUR TESTER LES CHEMINS REGISTRE##############################

write-host -ForegroundColor Red '=============================='
write-host -ForegroundColor Red '===Script Cree pour la 21H2==='
write-host -ForegroundColor Red '====adapte pour la 22H2 :)===='
write-host -ForegroundColor Red '=============================='
Write-Host 'Le script va : '
Write-Host 'installer firefox'
Write-Host 'Installer Acrobate Reader'
Write-Host 'Installer AnyDesk'
Write-Host '-Desepingler toutes les icones de la barre des taches'
Write-Host '-detacher le bouton cortana, application actives, Actualites de la barre des taches'
Write-Host "Mettre un fond d'ecran"
Write-Host "Remplacer l'acces rapide par ce pc dans l'explorer"
Write-Host "-mettre l'icone 'ce PC' sur le bureau"
write-host " "
$WebRequest = New-Object System.Net.WebClient
$DisqueD = (Test-Path 'D:\script_config_windows\')
$DisqueE = (Test-Path 'E:\script_config_windows\')
$DisqueF = (Test-Path 'F:\script_config_windows\')
if ($DisqueD -eq $true) 
{
    $scriptPath = "D:\script_config_windows"
}
elseif ($DisqueE -eq $true) 
{
    $scriptPath = "E:\script_config_windows"
} 
elseif ($DisqueF -eq $true) 
{
    $scriptPath = "F:\script_config_windows"
} 
else 
{
    Write-Host -ForegroundColor DarkRed "Emplacement introuvable, verifier que la lettre de la cle usb soit bien D,E ou F"  
    Write-Host "Si vous executez le script quand meme, il faudra :"
    Write-Host"-Installer Firefox, Adobe et Anydesk (installateurs dans le fichier exe)"
    Write-Host"-"
    Write-Host"-"
}


#-----------------------------------------------------------#
#------------------ACTIVATION PAVÉ NUMÉRIQUE----------------#
#-----------------------------------------------------------#

$pavenumerique = read-host "Activer le pave numerique ? (y/n)"
while ("y","n" -notcontains $pavenumerique) {
        write-host "veuillez saisir uniquement y pour oui  ou n pour non"
        $pavenumerique = read-host "Activer le pave numerique ? (y/n)"
}

if ($pavenumerique -eq 'y')
{
    Set-ItemProperty "HKCU:\Control Panel\Keyboard" -Name InitialKeyboardIndicators -value 2 -ErrorAction 'silentlycontinue'
    Set-ItemProperty "HKCU:\Control Panel\Keyboard" -Name KeyboardDelay -value 1 -ErrorAction 'silentlycontinue'
    Set-ItemProperty "HKCU:\Control Panel\Keyboard" -Name KeyBoardSpeed -value 31 -ErrorAction 'silentlycontinue'
    Write-host 'pave numerique active'
}

else
{
    Write-Host 'Le pave numerique est desactive.'
}


#---------------------------------------------------------------------------------------------------#
      <#-----------------------Installation de firfox, ACReader & AnyDesk ------------------------#>
#---------------------------------------------------------------------------------------------------#

#-------------------FIREFOX---------------#

$FireFoxInstaller = (Get-ChildItem $scriptPath\exe\ -Name Firefox.msi)

Write-Host -ForegroundColor Yellow "Installation de firefox ..."
if ($FireFoxInstaller -eq "Firefox.msi")
{
    Start-Process -FilePath "$env:windir\system32\msiexec.exe" -ArgumentList "/i","$scriptPath\exe\Firefox.msi","/quiet" -Wait
}
else 
{
    $WebRequest.DownloadFile("https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=fr","$env:USERPROFILE\Downloads\FirefoxInstaller.exe")
    Start-Process "$env:USERPROFILE\Downloads\FirefoxInstaller.exe"
    Remove-Item "$env:USERPROFILE\Downloads\FirefoxInstaller.exe"
}
<#-------------------Chrome---------------#

Write-Host -ForegroundColor Yellow "Installation de Chrome ..."

$FireFoxInstaller = (Get-ChildItem $scriptPath\exe\ -Name Chrome.msi)

Start-Process -FilePath "$env:windir\system32\msiexec.exe" -ArgumentList "/i","$scriptPath\exe\Chrome.msi","/quiet" -Wait#>

<#a faire plus tard
if ($Chrome -eq "Chrome.msi")
{
    Start-Process -FilePath "$env:windir\system32\msiexec.exe" -ArgumentList "/i","$scriptPath\exe\Chrome.msi","/quiet" -Wait
}
else 
{
    $WebRequest.DownloadFile("https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=fr","C:\Users\Utilisateur\Downloads\FirefoxInstaller.exe")
    Start-Process "C:\Users\Utilisateur\Downloads\FirefoxInstaller.exe"
    Remove-Item "C:\Users\Utilisateur\Downloads\FirefoxInstaller.exe"
}#>
#-------------------ANYDESK------------------#

Write-Host -ForegroundColor Yellow "Installation de AnyDesk ..."
#D:\script_config_windows\exe\AnyDesk.exe --install "C:\Program Files (x86)\AnyDesk" --start-with-win --create-desktop-icon --silent -Wait
Start-Process "$scriptPath\AnyDesk.bat"
#-------------------ACROBATE READER------------------#

Write-Host -ForegroundColor Yellow "Installation de Acrobate Reader ..."

#D:\script_config_windows\exe\AcroRdrDC2100720099_fr_FR.exe /sAll /rs /msi EULA_ACCEPT=YES 
Start-Process "$scriptPath\AcrobatReader.bat"

Do
{
    $adobePathx86 = (Test-Path 'C:\Program Files (x86)\adobe\Acrobat Reader DC\Reader\AcroRd32.exe')
    $adobePath = (Test-Path 'C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe')
    Write-Host "Adobe est en cours d'installation ... (si ce message dure plusieurs minutes, l'installer manuellement)."
    Start-Sleep 10
}
until (($adobePath -eq "True") -or ($adobePathx86 -eq "True"))

#------------------------------------------------#
#-------------Activation de AdBlock--------------#
#------------------------------------------------#

Start-Process 'C:\Program Files\Mozilla Firefox\firefox.exe' 
Write-Host 'Lancement de firefox ...'
Start-Sleep 5
$profiles = Get-ChildItem $env:UserProfile\AppData\Roaming\Mozilla\Firefox\Profiles\ -Name *
$AdBlock = $profiles[0]
$Adblock2 = $profiles[1]
#$Adblock3 = $profiles[2]
mkdir $env:UserProfile\Appdata\Roaming\Mozilla\Firefox\Profiles\$AdBlock\extensions\
mkdir $env:UserProfile\Appdata\Roaming\Mozilla\Firefox\Profiles\$AdBlock2\extensions\
#mkdir $env:UserProfile\Appdata\Roaming\Mozilla\Firefox\Profiles\$AdBlock3\extensions\
Copy-Item "$scriptPath\extensions\{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi" "$env:UserProfile\Appdata\Roaming\Mozilla\Firefox\Profiles\$AdBlock\extensions\{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi"
Copy-Item "$scriptPath\extensions\{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi" "$env:UserProfile\Appdata\Roaming\Mozilla\Firefox\Profiles\$AdBlock2\extensions\{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi"
#Copy-Item "$scriptPath\extensions\{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi" "$env:UserProfile\Appdata\Roaming\Mozilla\Firefox\Profiles\$AdBlock3\extensions\{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi"
#---------------------------------------------------------------------------------------------------#
      <#--------DESACTIVATION DU BOUTON CORTANA, APPLICATION ACTIVES, CONTACT ET TASKBAR #1---------#>
#---------------------------------------------------------------------------------------------------#

        <#--------------DECLARATION DES VARIABLES------------#>
#$background = "C:\PATH\TO\YOUR\BACKGROUND 
$boutoncortana = (Get-ItemProperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced').ShowCortanaButton
$boutonapplication = (Get-ItemProperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced').ShowTaskViewButton
$taskbar = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search").SearchboxTaskBarMode
$devTaskBar = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced").TaskbarGlomLevel
Write-Host -ForegroundColor DarkRed 1.
write-host -ForegroundColor Yellow 'Desactivation du Bouton Cortana ...'


        <#--------------DEBUT DE LA BOUCLE CORTANA--------------#>

if ($boutoncortana -eq '0')
{
    write-host 'bouton cortana deja inactif'
}

else
{
    Set-Itemproperty -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -name ShowCortanaButton -value 0
    write-host 'Bouton cortana desactive'
}


        <#--------------FIN DE LA BOUCLE CORTANA--------------#>

Write-Host "desactivation de l'icone Microsoft edge"

$Edge = "$env:USERPROFILE\Desktop\Microsoft Edge.lnk"

if (Test-Path $Edge -PathType leaf)
{
    remove-item '$env:USERPROFILE\Desktop\Microsoft Edge.lnk'
}


write-host -ForegroundColor DarkRed 1.2
write-host -ForegroundColor Yellow 'Desactivation du Bouton Application ...'

        <#--------------DEBUT DE LA BOUCLE APPLICATIONS ACTIVES--------------#>

if ($boutonapplication -eq '0')
{
    write-host 'bouton application deja inactif'
}
else
{
    Set-Itemproperty -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -name ShowTaskViewButton -value 0
    write-host 'Bouton application desactive'
}

#write-host -ForegroundColor DarkRed 1.3
#write-host -ForegroundColor Yellow 'Desactivation du bouton notifications ...'
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1 -erroraction 'silentlycontinue'
#Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1 -erroraction 'silentlycontinue'
#Write-Host "Icone Notifications supprimee"


        <#-------------FIN DE LA BOUCLE APPLICATIONS ACTIVES------------------#>

Write-Host -ForegroundColor DarkRed "1.4"
Write-Host -ForegroundColor Yellow "Desactivation de l'icone contact ..."


        <#-------------------DEBUT DE LA BOUCLE CONTACT------------------------#>

if ($icone_contact -eq 0)
{
    Write-Host 'Icone contact deja inactif'
}
else 
{
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type Dword -Value 0 -erroraction 'silentlycontinue'
    Write-Host "Icone contact desactive"
}



if ($devTaskBar -eq 1)
{
    Write-Host "Barre des taches deja configurer"
}
else 
{
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type Dword -Value 1 -erroraction 'silentlycontinue'
}


            <#-------------------FIN DE LA BOUCLE CONTACT------------------------#>

Write-Host -ForegroundColor DarkRed "1.5"
Write-Host -ForegroundColor DarkRed "Desactivation de la barre recherche ..."


            <#-------------------DEBUT DE LA BOUCLE TASKBAR------------------------#>

if ($taskbar -eq 0)
{
    Write-Host "Barre de recherche deja inactive"
}
else 
{
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskBarMode" -Type Dword -Value 0 -erroraction 'silentlycontinue'
    Write-Host "Barre de recherche desactive"
}


#-------------------------------------------------------------------#
<#----------------ICONES CE PC SUR LE BUREAU #4---------------------#>
#-------------------------------------------------------------------#

Write-Host -ForegroundColor DarkRed 4.


<################Declaration des variables################>

$icone_ce_pc = (Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel).'{20D04FE0-3AEA-1069-A2D8-08002B30309D}' 

Write-Host -ForegroundColor  Yellow "Creation de l'icone Ce PC sur le bureau ..."

    if ($icone_ce_pc -eq 0)
    {
        write-host 'Icone Ce PC deja sur le bureau'
    }
    elseif ($icone_ce_pc -eq 1)
    {
        Set-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\ -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0 -erroraction 'silentlycontinue'
        write-host 'Icone Ce PC creer'
    }
    else 
    {    
        New-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\ -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0 -PropertyType DWORD -erroraction 'silentlycontinue'
        write-host 'Icone Ce PC creer' 
    }

#---------------------------------------------------------------------------#
#-----------------------ICONES MICROSOFT EDGE ET SHOP-----------------------#
#---------------------------------------------------------------------------#

Write-Host -ForegroundColor DarkRed "6."
Write-Host -ForegroundColor Yellow "Desactivations des icones de la barre des taches ..."

Remove-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name Favorites -erroraction 'silentlycontinue'
Write-Host "icones desactivees / deja desactivees"

#-----------------------------------------------------------#
#---------------ACTUALITÉS ET CHAMPS D'INTÉRET--------------#
#-----------------------------------------------------------#

$champs_interet = (Get-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds').ShellFeedsTaskBarViewMode
Write-Host -ForegroundColor DarkRed "7."
Write-Host -ForegroundColor Yellow "Desactivation de actualites et champs d'interet ..."
if ($champs_interet -eq 2)
{
    Write-Host "Actualites et champs d'interet deja inactif"
}
else 
{
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds -Name ShellFeedsTaskBarViewMode -value 2 -erroraction 'silentlycontinue'
}

#-----------------------------------------------------------#
#---------DECOUVERTE AUTOMATIQUE DES PERIPHERIQUES----------#
#-----------------------------------------------------------#

$CheminPeripherique = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")

if ($CheminPeripherique -eq 'True' ) 
{
    New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name AutoSetup -value 0 -ErrorAction 'silentlycontinue'
}
else 
{
    New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private"
    New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name AutoSetup -value 0 -ErrorAction 'silentlycontinue'
}

#------------------------------------------------------------#
#------------REMPLACER ACCES RAPIDE PAR CE PC----------------#
#------------------------------------------------------------#

$ValeurCePc = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced").LaunchTo
Write-Host "Remplacement de l'acces rapide"
if ($valeurCePc -eq 1)
{
    Write-Host "Acces rapide deja remplace par CE PC"
}
elseif ($valeurCePc -eq 2)
{
    Write-Host ("Changement de la valeur ...")
    Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -value 1 -ErrorAction 'silentlycontinue'
}
else 
{
    Write-Host "Creation de la valeur ..."
    Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -value 1 -ErrorAction 'silentlycontinue'
}


#------------------------------------------------------------#
#-----------------CHANGEMENT FOND D'ÉCRAN--------------------#
#------------------------------------------------------------#

#Write-Host "Changement du fond d'ecran ..."
#Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -Value $background


#------------------------------------------------------------#
#----------Désactivation de l'expiration du mdp--------------#
#------------------------------------------------------------#

net accounts /maxpwage:unlimited

Write-Host -ForegroundColor DarkCyan "1 minute avant la fermeture de session."
Start-Sleep 60
Write-Host "fermeture de la session dans :"
Write-Host "3"
Start-Sleep 1
Write-Host "2"
Start-Sleep 1
Write-Host "1"
Start-Sleep 1 
shutdown.exe -l

write-host -ForegroundColor Red '==================='
write-host -ForegroundColor Red '===Fin du script==='
write-host -ForegroundColor Red '==================='
#FIN
