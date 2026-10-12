# Read-only: dumps cmdlet parameter metadata and aliases from this PowerShell.
$mods = 'Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Core'
Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility -ErrorAction SilentlyContinue
$common = [System.Management.Automation.Internal.CommonParameters].GetProperties().Name +
          [System.Management.Automation.Internal.ShouldProcessParameters].GetProperties().Name
$out = [ordered]@{ version = $PSVersionTable.PSVersion.ToString(); common = $common; cmdlets = [ordered]@{} ; aliases = [ordered]@{} }
foreach ($c0 in Get-Command -CommandType Cmdlet -Module $mods | Sort-Object Name) {
  $c = Get-Command -Name $c0.Name -CommandType Cmdlet
  $sets = @()
  foreach ($s in $c.ParameterSets) {
    $ps = @()
    foreach ($p in $s.Parameters) {
      if ($common -contains $p.Name) { continue }
      $ps += [ordered]@{ name = $p.Name; position = $p.Position; mandatory = $p.IsMandatory;
                         byvalue = $p.ValueFromPipeline; byprop = $p.ValueFromPipelineByPropertyName;
                         switch = ($p.ParameterType -eq [System.Management.Automation.SwitchParameter]);
                         aliases = @($p.Aliases); type = $p.ParameterType.Name }
    }
    $sets += [ordered]@{ name = $s.Name; default = $s.IsDefault; parameters = $ps }
  }
  $out.cmdlets[$c.Name] = [ordered]@{ module = $c.ModuleName; sets = $sets; whatif = ($c.Parameters.Keys -contains 'WhatIf') }
}
foreach ($a in Get-Alias | Sort-Object Name) { $out.aliases[$a.Name] = $a.Definition }
$out | ConvertTo-Json -Depth 8 -Compress | Set-Content -Encoding UTF8 -Path (Join-Path $PSScriptRoot 'ps51_bindings.json')
"ok " + $out.cmdlets.Count + " cmdlets, " + $out.aliases.Count + " aliases"
