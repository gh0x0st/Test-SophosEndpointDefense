Function Test-SophosEndpointDefense
{
<#
	.SYNOPSIS
		Determines whether or not Sophos Endpoint Defense is currently enabled on a local or remote machine.

	.DESCRIPTION
		The Test-SophosEndpointDefense function checks whether or not Sophos Endpoint Defense is actively protecting
		Sophos components from being altered without intervention on a target machine. It currently tests if it write
	    an arbitary file to the Sophos ProgramData directly and checks for the setting of the CanStop Service property.

	.PARAMETER  ComputerName
		Indicates a computer name, or array of computers to check against.
	
	.PARAMETER  CanWrite
		Indicates to test the ability to write to the protected Sophos directory.
	
	.PARAMETER  CanStop
		Indicates to check the availability of stopping the Sophos Anti-Virus service.

	.EXAMPLE
		PS C:\> Test-SophosEndpointDefense -ComputerName SERVER1 -CanStop -CanWrite

		System  Status    TestCanWrite TestCanStop
		------  ------    ------------ -----------
		SERVER1 Protected True         True       
	
	.EXAMPLE
		PS C:\> Test-SophosEndpointDefense -ComputerName SERVER1,SERVER2 -CanWrite

		System  Status        TestCanWrite TestCanStop
		------  ------        ------------ -----------
		SERVER1 Protected     True         False   
		SERVER2 Not Protected True         False  

	.INPUTS
		System.String

	.OUTPUTS
		System.Object

	.NOTES
		Last Edit: 10/10/2019 @ 1545
		Licensed under the MIT license. See LICENSE.txt file in the project root for full license information.

	.LINK
		https://github.com/gh0x0st
#>
	[CmdletBinding()]
	param (
		[Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'default')]
		[System.String[]]$ComputerName = 'localhost',
		[Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'default')]
		[Switch]$CanWrite,
		[Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'default')]
		[Switch]$CanStop
	)
	Begin
	{
		Try
		{
			If (-not ($CanWrite -or $CanStop))
			{
				Throw "[!] You must select either the CanWrite or CanStop switch"
			}
			[System.String]$Service = 'Sophos Anti-Virus'
			[System.String]$Status = 'Unknown'
			[System.String]$ProtectedPath = '\c$\programdata\Sophos\sophos.txt'
			[System.Object]$Output = @()
		}
		Catch
		{
			Write-Error "[!]$(Get-Date -Format '[MM-dd-yyyy][HH:mm:ss]') - ScriptLine: $($_.InvocationInfo.ScriptLineNumber) | ExceptionType: $($_.Exception.GetType().FullName) | ExceptionMessage: $($_.Exception.Message)"
			Break
		}
	}
	Process
	{
		ForEach ($C in $ComputerName)
		{
			# Test if system is online
			Write-Verbose "Checking if $C is online"
			Try
			{
				[System.Boolean]$Online = Test-Connection -ComputerName $C -Count 1 -Quiet -ErrorAction Stop
			}
			Catch
			{
				[System.Boolean]$Online = $false
			}
			
			Switch ($Online)
			{
				$true
				{
					Try
					{
						Write-Verbose "Checking if $C is a supported operating system"
						[System.Object]$Version = (Get-WmiObject -Class win32_operatingsystem -ComputerName $C -ErrorAction Stop | Select-Object -ExpandProperty Version)
						
						if ([System.Version]$Version -gt '6.1.7600')
						{
							Write-Verbose "System $C is supported"
							[System.Boolean]$RunTests = $true
						}
						Else
						{
							Write-Verbose "System $C is not supported"
							[System.String]$Status = 'Not Supported'
							[System.Boolean]$RunTests = $false
						}
					}
					Catch [System.Runtime.InteropServices.COMException]
					{
						[System.Boolean]$RunTests = $False
						[System.String]$Status = 'RPC server is unavailable'
					}
					Catch [System.Management.ManagementException], [System.UnauthorizedAccessException]
					{
						[System.Boolean]$RunTests = $False
						[System.String]$Status = 'Access Denied'
					}
					Catch
					{
						Write-Error "[!]$(Get-Date -Format '[MM-dd-yyyy][HH:mm:ss]') - ScriptLine: $($_.InvocationInfo.ScriptLineNumber) | ExceptionType: $($_.Exception.GetType().FullName) | ExceptionMessage: $($_.Exception.Message)"
					}
					
					While ($RunTests)
					{
						If ($CanStop)
						{
							Write-Verbose "Running CanStop test for $C"
							# Check the availability of stopping the Sophos Anti-Virus service.
							Try
							{
								If (-not (Get-Service -DisplayName $Service -ComputerName $C -ErrorAction Stop | Select-Object -ExpandProperty CanStop))
								{
									[System.String]$Status = 'Protected'
								}
								Else
								{
									[System.String]$Status = 'Not Protected'
								}
							}
							Catch [Microsoft.PowerShell.Commands.ServiceCommandException]
							{
								[System.String]$Status = 'Service Missing'
							}
							Catch [System.InvalidOperationException]
							{
								[System.String]$Status = 'Access Denied'
							}
							Catch
							{
								Write-Error "[!]$(Get-Date -Format '[MM-dd-yyyy][HH:mm:ss]') - ScriptLine: $($_.InvocationInfo.ScriptLineNumber) | ExceptionType: $($_.Exception.GetType().FullName) | ExceptionMessage: $($_.Exception.Message)"
							}
						}
						
						If ($CanWrite)
						{
							Write-Verbose "Running CanWrite test for $C"
							# Test the ability to write to the protected Sophos directory.
							Try
							{
								If (Test-Path "\\$C\c$")
								{
									[System.IO.FileSystemInfo]$File = New-Item "\\$C\$ProtectedPath" -ErrorAction Stop
									Remove-Item $File.FullName
									[System.String]$Status = 'Not Protected'
								}
								Else
								{
									[System.String]$Status = 'Unable to access remote directory'
								}
							}
							Catch [System.UnauthorizedAccessException]
							{
								[System.String]$Status = 'Protected'
							}
							Catch
							{
								Write-Error "[!]$(Get-Date -Format '[MM-dd-yyyy][HH:mm:ss]') - ScriptLine: $($_.InvocationInfo.ScriptLineNumber) | ExceptionType: $($_.Exception.GetType().FullName) | ExceptionMessage: $($_.Exception.Message)"
							}
						}
						[System.Boolean]$RunTests = $false
					}
				}
				$false
				{
					[System.String]$Status = 'Offline'
				}
			}
			# Build results
			[System.Array]$Output += [PSCustomObject]@{ 'System' = $C; 'Status' = $Status; 'TestCanWrite' = $CanWrite; 'TestCanStop' = $CanStop }
		}
	}
	End
	{
		Try
		{
			Write-Output $Output
		}
		Catch
		{
			Write-Error "[!]$(Get-Date -Format '[MM-dd-yyyy][HH:mm:ss]') - ScriptLine: $($_.InvocationInfo.ScriptLineNumber) | ExceptionType: $($_.Exception.GetType().FullName) | ExceptionMessage: $($_.Exception.Message)"
			Break
		}
	}
}