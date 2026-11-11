# Function-only exact derivation of the reviewed large full-baseline readers.
# No VM, source, process or storage action is performed by this support file.
function New-PagedEnvelopeBaselineSources([string]$LabRoot,[string]$ClosedProducerGuard){
 $candidateLabRoot=$LabRoot
 $pins=@{'SourceBaselineSupport.ps1'='15fbf433444693316832766befda3cf642ba7743d49321e3f9df19c682607b97';'PagedMetadataObserverSupport.ps1'='fe478fea7f63015f6d6140154a32380fcb768b1a41a520616e1e3a6ad146c2d2';'LargePagedBaselineSupport.ps1'='9b8eea8719a75130d3e11d781a180316eecafb67ba322912b0e391bff7c639c9'}
 foreach($name in $pins.Keys){Need ((Get-FileHash -LiteralPath (Join-Path $LabRoot $name)).Hash.ToLowerInvariant()-ceq$pins[$name]) 'Exact reviewed paged baseline source required.'}
 function ReplaceOnce([string]$Text,[string]$Before,[string]$After){Need ([regex]::Matches($Text,[regex]::Escape($Before)).Count-eq1) 'One exact paged-envelope derivation anchor required.';return $Text.Replace($Before,$After)}
$largeBaselinePath=Join-Path $candidateLabRoot 'SourceBaselineSupport.ps1';$largeTokens=$null;$largeErrors=$null
$largeBaselineAst=[Management.Automation.Language.Parser]::ParseFile($largeBaselinePath,[ref]$largeTokens,[ref]$largeErrors);Need ($largeErrors.Count-eq0) 'Held original baseline syntax differs.'
function LargeBaselineFunction([string]$Name){$rows=@($largeBaselineAst.FindAll({param($n) $n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$Name},$true));Need ($rows.Count-eq1) 'One held baseline function required.';return $rows[0].Extent.Text}
$largeHostSource=LargeBaselineFunction 'ReadFreshLabSourceBaselineHost'
$largeHostSource=ReplaceOnce $largeHostSource '$m.schema_version-eq1-and$m.kind-ceq''lab-full-source-content-baseline-v1''' '$m.schema_version-eq2-and$m.kind-ceq''lab-full-source-content-baseline-pages-v2'''
$largeHostSource=ReplaceOnce $largeHostSource '$m.directories-gt256' '$m.directories-eq723'
$largeHostSource=ReplaceOnce $largeHostSource '$m.objects-le1280' '$m.objects-eq1534'
$largeHostSource=ReplaceOnce $largeHostSource '''observation-events.json''=@{key=''events'';name=''lab-fresh-observation-events.json''}}' '''observation-events.json''=@{key=''events'';name=''lab-fresh-observation-events.json''};''expectation.pages''=@{key=''expected_pages'';name=''lab-baseline-expectation.pages''};''expectation-pages.json''=@{key=''expected_page_receipt'';name=''lab-baseline-expectation-pages.json''}}'
$additionalHostLines=@(
'$additional=OpenFreshBaselineHost $AdditionalDirectoryReceiptPath $AdditionalDirectoryReceiptSha256 1MB $held $true',
' Need ($AdditionalDirectoryReceiptPath.StartsWith($LabBase+''\'',[StringComparison]::OrdinalIgnoreCase)-and$additional.value.kind-ceq''ntfs-paged-directory-object-fixture''-and$additional.value.success-eq$true-and$additional.value.created_directories-eq450-and$additional.value.created_payload_files-eq0-and$additional.value.original_payload_writes-eq0-and$additional.value.original_payload_bytes_read-eq0-and$additional.value.extent_moves-eq0-and@($additional.value.created_paths).Count-eq450-and[guid]$additional.value.source_parent_checkpoint-eq[guid]''83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b'') ''Pinned metadata-only 450-directory source fixture required.''',
' $answer.files.additional_growth=@{path=$AdditionalDirectoryReceiptPath;bytes=$additional.item.Length;sha256=$AdditionalDirectoryReceiptSha256;name=''lab-additional-directory-growth.json''}',
' Need ($total+$file.Length+$growthFile.Length+$additional.item.Length-le256MB) ''Complete large baseline metadata exceeds original combined bound.''',
' $answer.sha256=$answer.files.expectation.sha256;'
)-join[Environment]::NewLine
$largeHostSource=ReplaceOnce $largeHostSource '$answer.sha256=$answer.files.expectation.sha256;' $additionalHostLines
$largeGuestBaselineSource=LargeBaselineFunction 'ReadFreshLabSourceBaselineGuest'
$largeGuestBaselineSource=ReplaceOnce $largeGuestBaselineSource '$null=Json $path;' 'if($path.EndsWith(''.pages'',[StringComparison]::Ordinal)){$null=Hold-PagedObserverFile $path $v.sha256 64MB}else{$null=Json $path};'
$largeGuestBaselineSource=ReplaceOnce $largeGuestBaselineSource '$m.kind-ceq''lab-full-source-content-baseline-v1''' '$m.schema_version-eq2-and$m.kind-ceq''lab-full-source-content-baseline-pages-v2'''
$largeGuestBaselineSource=ReplaceOnce $largeGuestBaselineSource '$descriptor.directories-gt256' '$descriptor.directories-eq723'
$largeGuestBaselineSource=ReplaceOnce $largeGuestBaselineSource '$descriptor.objects-eq$m.objects' '$descriptor.objects-eq$m.objects-and$descriptor.objects-eq1534'
$largeGuestBaselineSource=ReplaceOnce $largeGuestBaselineSource '$script:labFreshBaseline=@{' '$additionalProof=AssertLargeAdditionalDirectories $e $m;Save ''additional-directories-baseline-verification.json'' $additionalProof;$script:labFreshBaseline=@{'

 $legacyV3=LargeBaselineFunction 'AssertLabV3Envelope'
 $legacyV3=ReplaceOnce $legacyV3 'function AssertLabV3Envelope(' 'function AssertLegacyLabV3Envelope('
 $pageText=[IO.File]::ReadAllText((Join-Path $LabRoot 'PagedMetadataObserverSupport.ps1')).Replace("`r`n","`n")
 $pageText=ReplaceOnce $pageText " Need (`$null-ne`$nativeExit-and`$nativeExit-eq0-and`$null-ne`$process-and`$process.HasExited) 'Paged observer requires actual closed public native0.'" $ClosedProducerGuard
 $pt=$null;$pe=$null;$pageAst=[Management.Automation.Language.Parser]::ParseInput($pageText,[ref]$pt,[ref]$pe);Need ($pe.Count-eq0) 'Derived typed page support parse failed.'
 $rows=@($pageAst.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'AssertLabV3Envelope'},$true));Need ($rows.Count-eq1) 'One actual-product paged count validator required.'
 $product=ReplaceOnce $rows[0].Extent.Text 'function AssertLabV3Envelope(' 'function AssertProductPagedV3Envelope('
 $guest=$legacyV3+[Environment]::NewLine+$pageText+[Environment]::NewLine+$product+[Environment]::NewLine+[IO.File]::ReadAllText((Join-Path $LabRoot 'LargePagedBaselineSupport.ps1'))+[Environment]::NewLine+$largeGuestBaselineSource
 return @{host_source=$largeHostSource;guest_source=$guest;source_pins=$pins}
}
