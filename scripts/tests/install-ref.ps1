# Tests how scripts/install.ps1 turns -Ref into a commit, with Invoke-WebRequest replaced by a fake
# GitHub API that answers each commit lookup from a table and records the names it was asked for.
# It runs the script's own Test-CommitHash, Find-Commit and Resolve-Ref, lifted out of the installer.
# Run it with: pwsh -NoProfile -File scripts/tests/install-ref.ps1

$ErrorActionPreference = 'Stop'

$installer = Join-Path (Split-Path $PSScriptRoot) 'install.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$null, [ref]$null)
$wanted = 'Test-CommitHash', 'Find-Commit', 'Resolve-Ref'
$found = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $wanted -contains $node.Name }, $true)
if ($found.Count -ne $wanted.Count) { throw "expected $($wanted.Count) functions in install.ps1, found $($found.Count)" }

# What GitHub answers with for an HTTP error: the exception carries the response, as in both PowerShells
class HttpFail : System.Exception {
    [object]$Response
    HttpFail([int]$code) : base("HTTP $code") {
        $this.Response = [pscustomobject]@{ StatusCode = [System.Net.HttpStatusCode]$code }
    }
}

# The installer's own variables and helpers that the three functions use
$repo = 'DaSonOfPoseidon/OBDCracker'
function Say([string]$Message) { }

# A name that isn't in the table gets 422, which is what GitHub says for a ref it doesn't have.
# Status 'net' is a failure with no HTTP answer.
function Invoke-WebRequest {
    param([switch]$UseBasicParsing, [hashtable]$Headers, [string]$Uri)
    $name = $Uri.Substring($Uri.IndexOf('/commits/') + '/commits/'.Length)
    $script:log += $name
    $entry = $script:table[$name]
    if (-not $entry) { $entry = @{ Status = 422 } }
    if ($entry.Status -eq 'net') { throw [System.InvalidOperationException]::new('no network') }
    if ($entry.Status -ne 200) { throw [HttpFail]::new($entry.Status) }
    [pscustomobject]@{ Content = $entry.Body }
}

. ([scriptblock]::Create(($found | ForEach-Object { $_.Extent.Text }) -join "`n"))

$A = 'a' * 40
$B = 'b' * 40
$script:fails = 0

function Test-Case([string]$Name, [string]$Ref, [hashtable]$Table, [string]$Commit, [string[]]$Lookups, [string]$Expect) {
    $script:table = $Table
    $script:log = @()
    $got = $null
    $err = $null
    try { $got = Resolve-Ref $Ref } catch { $err = $_.Exception.Message }
    $problems = @()
    if ($Expect) {
        if (-not $err) { $problems += "wanted an error with '$Expect', got commit '$got'" }
        elseif (-not $err.Contains($Expect)) { $problems += "error lacks '$Expect': $err" }
    } elseif ($err) {
        $problems += "unexpected error: $err"
    } elseif ($got -ne $Commit) {
        $problems += "wanted commit $Commit, got '$got'"
    }
    if ($null -ne $Lookups -and (($script:log -join ' ') -ne ($Lookups -join ' '))) {
        $problems += "wanted lookups '$($Lookups -join ' ')', got '$($script:log -join ' ')'"
    }
    foreach ($problem in $problems) {
        [Console]::Error.WriteLine("FAIL: ${Name}: $problem")
        $script:fails++
    }
}

Test-Case 'tag only' 'v1' @{ 'refs/tags/v1' = @{ Status = 200; Body = $A } } $A @('refs/tags/v1', 'refs/heads/v1')
Test-Case 'branch only' 'dev' @{ 'refs/heads/dev' = @{ Status = 200; Body = $B } } $B @('refs/tags/dev', 'refs/heads/dev')
$both = @{ 'refs/tags/v1' = @{ Status = 200; Body = $A }; 'refs/heads/v1' = @{ Status = 200; Body = $B } }
Test-Case 'both a tag and a branch (tag named)' 'v1' $both '' $null 'refs/tags/v1'
Test-Case 'both a tag and a branch (branch named)' 'v1' $both '' $null 'refs/heads/v1'
Test-Case 'both a tag and a branch (hash named)' 'v1' $both '' $null 'commit hash'
Test-Case 'a 404 counts as not found' 'v1' @{ 'refs/tags/v1' = @{ Status = 404 }; 'refs/heads/v1' = @{ Status = 200; Body = $B } } $B
Test-Case 'neither, so a short hash' 'abc1234' @{ 'abc1234' = @{ Status = 200; Body = $B } } $B @('refs/tags/abc1234', 'refs/heads/abc1234', 'abc1234')
Test-Case 'neither and not a hash' 'nonsense' @{} '' @('refs/tags/nonsense', 'refs/heads/nonsense', 'nonsense') "couldn't find"
Test-Case 'server error on the tag lookup' 'v1' @{ 'refs/tags/v1' = @{ Status = 500 }; 'refs/heads/v1' = @{ Status = 200; Body = $B } } '' @('refs/tags/v1') 'answered HTTP 500'
Test-Case 'rate limit on the branch lookup' 'v1' @{ 'refs/tags/v1' = @{ Status = 200; Body = $A }; 'refs/heads/v1' = @{ Status = 403 } } '' @('refs/tags/v1', 'refs/heads/v1') 'answered HTTP 403'
Test-Case 'server error on the fallback lookup' 'abc1234' @{ 'abc1234' = @{ Status = 502 } } '' $null 'answered HTTP 502'
Test-Case 'no answer at all' 'v1' @{ 'refs/tags/v1' = @{ Status = 'net' } } '' @('refs/tags/v1') 'no answer from GitHub'
Test-Case 'a full tag ref' 'refs/tags/v1' @{ 'refs/tags/v1' = @{ Status = 200; Body = $A }; 'refs/heads/v1' = @{ Status = 200; Body = $B } } $A @('refs/tags/v1')
Test-Case 'a full branch ref' 'refs/heads/v1' @{ 'refs/tags/v1' = @{ Status = 200; Body = $A }; 'refs/heads/v1' = @{ Status = 200; Body = $B } } $B @('refs/heads/v1')
Test-Case "a full ref that doesn't exist" 'refs/tags/v1' @{ 'v1' = @{ Status = 200; Body = $A } } '' @('refs/tags/v1') "couldn't find"
Test-Case 'a full commit hash' $A @{} $A @()
$upper = $A.ToUpperInvariant()
Test-Case 'a 40-character hash in upper case goes through the lookups' $upper @{ $upper = @{ Status = 200; Body = $A } } $A @("refs/tags/$upper", "refs/heads/$upper", $upper)
foreach ($length in 39, 41) {
    $hash = ($A + 'a').Substring(0, $length)
    Test-Case "a $length-character hash" $hash @{} '' @("refs/tags/$hash", "refs/heads/$hash", $hash) "couldn't find"
}
Test-Case 'an answer that is not a hash' 'v1' @{ 'refs/tags/v1' = @{ Status = 200; Body = 'not-a-hash' } } '' $null "isn't a commit hash"
# Windows PowerShell 5.1 hands back bytes for a content type it doesn't know
Test-Case 'an answer as bytes with a newline' 'v1' @{ 'refs/tags/v1' = @{ Status = 200; Body = [Text.Encoding]::ASCII.GetBytes("$A`n") } } $A

if ($script:fails -ne 0) {
    [Console]::Error.WriteLine("$($script:fails) check(s) failed")
    exit 1
}
Write-Host 'install-ref: all checks passed'
