Param(
  
  $stateDir            = "$($Env:Temp)\AcmeState",
  $contactMail         = "marcogreen@lithia.com",
  $dnsName             = @("lpp.lithia.com","uat.lpp.lithia.com","sandbox.lpp.lithia.com"),
  $STResourceGroupName = "lienpayoff-rg",
  $AppGatewayName      = "LPP-APPGWv2",
  $storageName         = "appgwcert",
  $Test                = $False
)


  Write-output "start"
  $CertificatePassword = Get-AutomationVariable -Name 'Certificate PWD'
  $password = ConvertTo-SecureString -String $CertificatePassword -Force -AsPlainText
  $connection = Get-AutomationConnection -Name "cert-renewal SP connection"

  Switch( $Test ) {
    
    $True    {$serviceName = "LetsEncrypt-Staging"} # This will issue Fake Certificates - use this for testing!
    $False   {$serviceName = "LetsEncrypt"} 
    Default  {$serviceName = "LetsEncrypt-Staging"} 
    
    }
 
  
  $Certificate = Get-AutomationCertificate -Name "cert-renewal"
  $CertThumbprint = ($Certificate.Thumbprint).ToString()    
  Write-output $CertThumbprint
  Write-output $Connection.CertificateThumbprint
  
  

  

   Write-output "login"
  Login-AzureRmAccount -ServicePrincipal -Tenant $connection.TenantID -ApplicationID $connection.ApplicationID -CertificateThumbprint $Connection.CertificateThumbprint
  
  ###Create ACME ACCOUNT
  if( test-path $stateDir ) { 
    
    Rename-Item -Path $stateDir -NewName "$($stateDir).$((get-date).Ticks)" -Force

    }

  # Create a state object and save it to the harddrive
  $state = New-ACMEState -Path $stateDir

  # Fetch the service directory and save it in the state

  Get-ACMEServiceDirectory $state -ServiceName $serviceName -PassThru

  # Get the first anti-replay nonce
  New-ACMENonce $state;

  # Create an account key. The state will make sure it's stored.
  $Key= New-ACMEAccountKey $state -PassThru;

  # Register the account key with the acme service. The account key will automatically be read from the state
  New-ACMEAccount $state -EmailAddresses $contactMail -AcceptTOS -ErrorAction SilentlyContinue;

  ###Issue the certificate
  # Load an state object to have service directory and account keys available
  $state = Get-ACMEState -Path $stateDir;

  # It might be neccessary to acquire a new nonce, so we'll just do it for the sake of the example.
  New-ACMENonce $state -PassThru;

  # Create the identifiers for the DNS names
  $identifiers =@()

  $dnsName | %{ 

    $identifiers += New-ACMEIdentifier $_ ;

    }#DNSName

  # Create the order object at the ACME service.
  $order = New-ACMEOrder $state -Identifiers $identifiers;

  # Fetch the authorizations for that order
  $authZ = Get-ACMEAuthorization -Order $order;

  #Complete the challenges
  $AuthZ | %{
    # Select a challenge to fullfill
    $challenge = Get-ACMEChallenge $state $_ "http-01";

    # Inspect the challenge data
    $challenge.Data;

    # Create the file requested by the challenge
    $tmpPath = $env:TEMP + "\"
    $FileContent = $challenge.data.Content
    $filePath = $tmpPath + $challenge.Identifier.value
    
    Set-Content -Value $fileContent -Path $filePath -Force
    
    #Get storage account to set the context
    $storageAccount = Get-AzureRmStorageAccount -ResourceGroupName $STResourceGroupName -Name $storageName
    $ctx = $storageAccount.Context
    
    Write-output "Create Blob"
    #Create the Blob
    $blobName=".well-known\acme-challenge\$($challenge.data.Filename)"
    set-azurestorageblobcontent -File $filePath -Container "public" -Context $ctx -Blob $blobName -Force

    # Check if the challenge is readable before proceeding
    $WebTest= Invoke-WebRequest $challenge.Data.AbsoluteUrl -UseBasicParsing;

    if( $webTest.StatusCode -ne 200 ){

      Throw "The challenge is not accessable over the web, check the file name or that it was created and in blob storage"
      
      }

    # Signal the ACME server that the challenge is ready
    $challenge | Complete-ACMEChallenge $state;
    
    }#AuthZ
  
  Write-output "Challenges"
  # Wait a little bit and update the order, until we see the states
  while( $order.Status -notin ("ready","invalid") ) {
    
    Start-Sleep -Seconds 10;
    $order | Update-ACMEOrder $state -PassThru;
    
    }
  #Stop if invalid
  if( $Order.Status -in ("invalid") ){

    Throw "Order status is $($Order.Status)"
    
    }

  # We should have a valid order now and should be able to complete it
  # Therefore we need a certificate key
  $certKey = New-ACMECertificateKey -Path "$stateDir\$($dnsName[0]).key.xml";

  # Complete the order - this will issue a certificate singing request
  Complete-ACMEOrder $state -Order $order -CertificateKey $certKey;

  # Now we wait until the ACME service provides the certificate url
  while( -not $order.CertificateUrl ) {

    Start-Sleep -Seconds 15
    $order | Update-Order $state -PassThru

    }

  # As soon as the url shows up we can create the PFX
  $PFXPath = "$stateDir\$($dnsName[0]).pfx" 
  Write-output "Export Cert"
  Export-ACMECertificate -Order $order -CertificateKey $certKey -Path $PFXPath -Password $Password;


  #Upload the PFX to Azure Key Vault for Safe Keeping
  $certificateName = $dnsName[0] -replace "\.","-"
  $vaultName = 'cert-renewal'

  Import-AzureKeyVaultCertificate -VaultName $vaultName -Name $certificateName -FilePath $PFXPath -Password $Password -tag @{Service = $ServiceName}
  
  ### RENEW APPLICATION GATEWAY CERTIFICATE ###

  $appgw = get-AzureRmApplicationGateway -ResourceGroupName $STResourceGroupName -Name $AppGatewayName
  $t= set-azureRmApplicationGatewaySSLCertificate -Name $dnsName[0] -ApplicationGateway $appgw -CertificateFile $PFXPath -Password $password
  $Result = Set-AzureRmApplicationGateway -ApplicationGateway $appgw
  Write-Output $Result
