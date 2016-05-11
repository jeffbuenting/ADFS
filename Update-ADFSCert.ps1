# ----- http://social.technet.microsoft.com/wiki/contents/articles/2554.ad-fs-2-0-how-to-replace-the-ssl-service-communications-token-signing-and-token-decrypting-certificates.aspx

Import-Module '\\sl-jeffb\f$\OneDrive for Business\Scripts\certificatesadmin\certificateadmin.psm1'
add-pssnapin microsoft.adfs.powershell

# ----- New cert has already been requested and imported to the Computer store on the ADFS server

# ----- Give the ADFS Service account Read access to the certificate
# ----- Need to figure out which certificate is the new one...
$Cert = Get-Cert | where ...
Set-CertificatePermission –Certificate $Cert –ServiceAccount ‘stratuslivedemo/sldemo.adfs’  –Permissions “Read”

# ----- Bind the cert to the ADFS Web Site
Import-CertWebSite -WebSiteName 'Default Web Site' -Certificate $Cert

# ----- Set certificates for the three ADFS types
Add-ADFSCertificate -CertificateType Service-Communications -ThumbPrint $Cert.ThumbPrint -IsPrimary
Add-ADFSCertificate -CertificateType Token-Encryption -ThumbPrint $Cert.ThumbPrint -IsPrimary
Add-ADFSCertificate -CertificateType token-Signing -ThumbPrint $Cert.ThumbPrint -IsPrimary

# ----- Update RelyingPartTrusts
# -----Note: This will throw warnings for the trusts that do not used federation metadata.  These will be updated on the next step
Get-ADFSRelyingPartyTrust | Update-ADFSRelyingPartyTrust

Get-ADFSRelyingPartyTrust | where { ($_.Name -like "*1233*") -or ($_.name -like "*1234*" ) } | Set-ADFSRelyingPartyTrust -EncryptionCertificate $Cert


# ----- Update the Certs on the CRM servers.

$CRMServers = "List of Servers"

# ----- Copy the new cert to the local server to prevent a double hop issue.
# ----- Copy the CertAdministration module for the same reason
$CRMServers | foreach { 
    if ( -Not (Test-Path -Path "\\$_\c$\temp" ) ) { MD "\\$_\c$\temp" }
    Copy-item -Path '\\sldemoadfs20\c$\cert\newcert.pfx' -Destination "\\$_\c$\temp" 
    Copy-item -Path '\\sl-jeffb\f$\OneDrive for Business\Scripts\certificatesadmin\Certificateadmin.psm1' -Destination "\\$_\c$\temp"
}

Invoke-Command -ComputerName $CRMServers -ScriptBlock {

    Import-Module 'c:\temp\certificateAdmin.psm1'

    # ----- Get old cert
    $OldCert = Get-Cert | where ThumbPrint -eq '4DA5EA202424102D45EE51BFB6BFDCF1494680FE'

    # ----- import cert to the computer certificate store
    $Cert = import-cert -certRootStore LocalMachine -CertStore my -CertPath c:\temp\Newcert.pfx  -Password 'Password1'
        
    # ----- Add service account permissions to certificate
    Set-CertificatePermission -certificate $Cert -ServiceAccount "NT Authority\network service"

    # ----- Bind to CRM Website
    Import-CertWebSite -WebSiteName 'Microsoft Dynamics CRM' -Certificate $Cert

    # ----- Set the certificate for Claims on CRM
    $CRMFedMetaData = Set-CRM2011Claims -EncryptionCertificate $Cert.Subject -FederationMetadataUrl "https://$ADFSServer/federationmetadata/2007-06/federationmetadata.xml" -enabled -verbose

    # ----- Update cert bindings on all websites using the old cert
    Get-CertWebsite | where certificate -eq $OldCert | get-website | foreach { 
        
        # ----- Gather website binding info
        $IPAddress,$Port,$HostHeader = (Get-WebBinding -Name $_.Name | where protocol -eq https | Select-Object -ExpandProperty BindingInformation).Split(':')
        
        Remove-CertWebSite -WebSiteName $_.Name -Certificate $OldCert -IPAddress $IPAddress -Port $Port -HostHeader $HostHeader

        import-CertWebSite -WebSiteName $_.Name -Certificate $Cert -IPAddress $IPAddress -Port $Port -HostHeader $HostHeader
    }

}









    # ----- Assign cert to the StratusLive websites
    # ----------- StratusLive-Web (1234) Website
    Import-CertWebSite -WebSiteName 'Microsoft Dynamics CRM' -Certificate $Cert -Port 1234
    # ----------- StratusLive-WebService (450 or other) website
        
    # ----- If EI is installed, configure the new cert for it.
    # ---------- StratusLive-CRMIntegration (1233) website
    # ---------- Does the service need the cert?