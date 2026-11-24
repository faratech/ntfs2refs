#Requires -Version 5.1
# Called through Windows PowerShell for its built-in WinRT OCR projection.
param(
    [Parameter(Mandatory)][string]$Frame,
    [Parameter(Mandatory)][int]$Width,
    [Parameter(Mandatory)][int]$Height
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing, System.Runtime.WindowsRuntime
$decoderType = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType=WindowsRuntime]
$bitmapType = [Windows.Graphics.Imaging.SoftwareBitmap, Windows.Foundation, ContentType=WindowsRuntime]
$resultType = [Windows.Media.Ocr.OcrResult, Windows.Foundation, ContentType=WindowsRuntime]
$engine = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType=WindowsRuntime]::TryCreateFromUserProfileLanguages()
if (-not $engine) { throw 'Windows OCR has no recognizer for the lab account' }
$asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
} | Select-Object -First 1

function Wait-Result($Operation, [type]$ResultType) {
    $task = $asTask.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
    $task.GetAwaiter().GetResult()
}

$bytes = [IO.File]::ReadAllBytes($Frame)
$pixelBytes = 2L * $Width * $Height
$offset = 0
# The lab host's Hyper-V provider can prefix the pixels with a network-order
# length that includes the four-byte prefix.
if ($bytes.LongLength -eq $pixelBytes + 4 -and
    [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($bytes, 0)) -eq $bytes.LongLength) {
    $offset = 4
}
if ($Width -le 0 -or $Height -le 0 -or $bytes.LongLength - $offset -ne $pixelBytes) {
    throw "Unexpected RGB565 console frame size for $Frame"
}
$format = [Drawing.Imaging.PixelFormat]::Format16bppRgb565
$image = [Drawing.Bitmap]::new($Width, $Height, $format)
$canvas = [Drawing.Bitmap]::new(2 * $Width + 32, 2 * $Height + 32)
$png = [IO.MemoryStream]::new()
$stream = $null; $bitmap = $null
try {
    $pixels = $image.LockBits([Drawing.Rectangle]::new(0, 0, $Width, $Height), [Drawing.Imaging.ImageLockMode]::WriteOnly, $format)
    try {
        if ($pixels.Stride -ne $Width * 2) { throw 'Unexpected RGB565 bitmap stride' }
        [Runtime.InteropServices.Marshal]::Copy($bytes, $offset, $pixels.Scan0, [int]$pixelBytes)
    } finally { $image.UnlockBits($pixels) }
    # Console text starts at the image edge. Magnify it and give the recognizer margins.
    $graphics = [Drawing.Graphics]::FromImage($canvas)
    try {
        $graphics.Clear([Drawing.Color]::Black)
        $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::NearestNeighbor
        $graphics.DrawImage($image, [Drawing.Rectangle]::new(16, 16, 2 * $Width, 2 * $Height))
    } finally { $graphics.Dispose() }
    $canvas.Save($png, [Drawing.Imaging.ImageFormat]::Png)
    $png.Position = 0
    $stream = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($png)
    $decoder = Wait-Result ($decoderType::CreateAsync($stream)) $decoderType
    $bitmap = Wait-Result ($decoder.GetSoftwareBitmapAsync()) $bitmapType
    (Wait-Result ($engine.RecognizeAsync($bitmap)) $resultType).Lines | ForEach-Object { $_.Text }
} finally {
    if ($bitmap) { $bitmap.Dispose() }
    if ($stream) { $stream.Dispose() }
    $png.Dispose()
    $canvas.Dispose()
    $image.Dispose()
}
