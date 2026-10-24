<# Executes only the initializer's guest block with mocked identity/policy
   providers. Never opens a session or changes a real execution policy. #>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Lab.psm1'),[ref]$null,[ref]$null)
$function = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Initialize-LabGuestSession'},$false)
$command = $function.Find({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Invoke-Command'},$true)
$expression = @($command.CommandElements | Where-Object { $_ -is [Management.Automation.Language.ScriptBlockExpressionAst] })[0]
$body = $expression.ScriptBlock.Extent.Text
$guestBlock = [scriptblock]::Create($body.Substring(1,$body.Length-2))
function Get-CimInstance {
    param($ClassName,$ErrorAction)
    if ($script:mode -ceq 'identity-provider-error') { throw 'Mock identity provider error.' }
    [pscustomobject]@{Manufacturer='Microsoft Corporation';Model=$script:model}
}
function Get-ExecutionPolicy {
    param([switch]$List,$ErrorAction)
    $script:policyReads++
    if ($script:mode -ceq 'policy-provider-error') { throw 'Mock policy provider error.' }
    if ($List) { $script:policies } else { $script:effective }
}
function Set-ExecutionPolicy {
    param($Scope,$ExecutionPolicy,[switch]$Force,$ErrorAction)
    $script:setCalls++
    $script:setRequest=[pscustomobject]@{scope=$Scope;policy=$ExecutionPolicy;force=[bool]$Force}
    if ($script:mode -ceq 'set-error') { throw 'Mock set error.' }
    foreach ($policy in $script:policies) { if ($policy.Scope -ceq 'Process') { $policy.ExecutionPolicy='RemoteSigned' } }
    if ($script:mode -cne 'not-effective') { $script:effective='RemoteSigned' }
    if ($script:mode -ceq 'scope-race') { $script:policies[0].ExecutionPolicy='AllSigned' }
}
$checks=0
$originalComputerName=$env:COMPUTERNAME
try {
    foreach ($case in @('default-restricted','already-remote','group-remote','explicit-restricted','process-restricted','all-signed','bypass','unrestricted','machine-policy','user-policy','missing-scope','duplicate-scope','wrong-guest','wrong-model','identity-provider-error','policy-provider-error','set-error','not-effective','scope-race')) {
        $env:COMPUTERNAME='N2R-WIN11'
        $script:mode=$case; $script:effective='Restricted'; $script:model='Virtual Machine'; $script:setCalls=0; $script:policyReads=0; $script:setRequest=$null
        $script:policies=@(@('MachinePolicy','UserPolicy','Process','CurrentUser','LocalMachine') | ForEach-Object { [pscustomobject]@{Scope=$_;ExecutionPolicy='Undefined'} })
        switch ($case) {
            'already-remote' { $script:effective='RemoteSigned'; $script:policies[4].ExecutionPolicy='RemoteSigned' }
            'group-remote' { $script:effective='RemoteSigned'; $script:policies[0].ExecutionPolicy='RemoteSigned' }
            'explicit-restricted' { $script:policies[4].ExecutionPolicy='Restricted' }
            'process-restricted' { $script:policies[2].ExecutionPolicy='Restricted' }
            'all-signed' { $script:effective='AllSigned'; $script:policies[4].ExecutionPolicy='AllSigned' }
            'bypass' { $script:effective='Bypass'; $script:policies[2].ExecutionPolicy='Bypass' }
            'unrestricted' { $script:effective='Unrestricted'; $script:policies[4].ExecutionPolicy='Unrestricted' }
            'machine-policy' { $script:policies[0].ExecutionPolicy='Restricted' }
            'user-policy' { $script:effective='AllSigned'; $script:policies[1].ExecutionPolicy='AllSigned' }
            'missing-scope' { $script:policies=@($script:policies | Select-Object -First 4) }
            'duplicate-scope' { $script:policies[4].Scope='Process' }
            'wrong-guest' { $env:COMPUTERNAME='OTHER' }
            'wrong-model' { $script:model='Physical Computer' }
        }
        $result=& $guestBlock
        $ready=$case -in @('default-restricted','already-remote','group-remote')
        if (($result.status -ceq 'ready') -ne $ready) { throw "Unexpected initialization decision for $case." }
        $expectedSets=if($case -in @('default-restricted','set-error','not-effective','scope-race')){1}else{0}
        if ($script:setCalls -ne $expectedSets) { throw "Unexpected policy mutation for $case." }
        if ($expectedSets -and ($script:setRequest.scope -cne 'Process' -or $script:setRequest.policy -cne 'RemoteSigned' -or -not $script:setRequest.force)) { throw 'Initializer attempted a different policy or scope.' }
        if ($case -ceq 'default-restricted' -and (-not $result.changed -or $result.changedScope -cne 'Process' -or $result.before.effective -cne 'Restricted' -or $result.after.effective -cne 'RemoteSigned')) { throw 'Successful default-policy transition lacks before/after evidence.' }
        if ($case -in @('already-remote','group-remote') -and ($result.changed -or $null -ne $result.changedScope)) { throw 'Already-effective RemoteSigned was not preserved.' }
        if ($case -in @('wrong-guest','wrong-model','identity-provider-error') -and $script:policyReads -ne 0) { throw 'Policy was inspected before guest identity was validated.' }
        $checks++
    }
} finally { $env:COMPUTERNAME=$originalComputerName }
"Passed $checks guest session policy fixtures; every provider/policy operation was mocked."
