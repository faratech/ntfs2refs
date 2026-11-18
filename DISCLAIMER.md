# Disclaimer

Every run of `ntfs2refs.exe` and `ntfs2refs-recovery.exe` starts by printing
this warning:

```
WARNING: NTFS2REFS IS EXPERIMENTAL SOFTWARE.
FOR EVALUATION AND TESTING ONLY. DO NOT USE IT IN PRODUCTION.

IT REWRITES THE FILE SYSTEM OF A VOLUME IN PLACE, FROM NTFS TO REFS.
IT HAS BEEN TESTED ONLY ON VIRTUAL DISKS IN A LABORATORY. A FAULT IN
IT, IN WINDOWS OR IN THE HARDWARE CAN DESTROY EVERYTHING ON THE VOLUME.

BACK UP EVERYTHING ON THE VOLUME, AND CHECK THAT YOU CAN RESTORE THE
BACKUP, BEFORE YOU CONVERT. YOU USE THIS SOFTWARE ENTIRELY AT YOUR OWN
RISK. IT COMES WITH NO WARRANTY OF ANY KIND. READ DISCLAIMER.md.
```

## For evaluation and testing only

The [LICENSE](LICENSE) is a temporary evaluation licence: it lets you run the
software to evaluate and test it, on computers, disks and data that are not
in production use and that you are prepared to lose. It does not permit
production use, modification or redistribution, and Fara Technologies LLC may
withdraw it at any time.

## What "experimental" means here

- **Every conversion so far was of a virtual disk** on Hyper-V, in the
  project's laboratory, the largest holding 23 GB. None was of a physical
  disk, of a disk behind a RAID or storage controller of a vendor's own, or
  of a volume in daily use on someone's own machine.
- **What the laboratory showed, and what it did not**, is written down: the
  [feature matrix](docs/feature-matrix.md), the
  [recovery matrix](docs/recovery-matrix.md), and `ntfs2refs capabilities`,
  whose `lab_evidence.not_shown` lists what has not been tried. A case that is
  not in them has not been shown to work.
- **A conversion can be interrupted and recovered**, and the converter
  refuses what it does not know how to carry over. Both are designed and
  tested, in the laboratory. Neither replaces a backup: a fault in the
  converter, in Windows, in a driver or in the disk can leave a volume that
  neither the converter nor Windows can read.
- **ReFS is not NTFS.** Some programs and some Windows features behave
  differently on ReFS or do not support it, and starting Windows from ReFS
  is documented by Microsoft for some builds only. The guide says what the
  laboratory saw; it cannot say what every program on a machine will do.

## Before you use it

1. Back up everything on the volume to another disk.
2. Restore something from that backup, to see that it can be restored.
3. Read [the guide](docs/cli-workflow.md), and run `--check` and
   `--diagnose` before a conversion.
4. Keep the recovery command a run prints, and its working directory, until
   you have looked at the converted volume.

## No warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, LOSS OF DATA OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.

ntfs2refs is not made, endorsed or supported by Microsoft. Windows, NTFS and
ReFS are names of Microsoft's products.
