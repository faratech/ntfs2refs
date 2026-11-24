#!/usr/bin/env python3
"""Generate disposable GPT VHDX fixtures with selected NTFS index record sizes on Linux."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

VERSION = "2026.9.28"
ARCHIVE_SHA256 = "350d9415c59f7c3fa74e23985ad2d56423c6a168337368f672e2e362d8f295c8"
MIB = 1024 * 1024
OFFSET = 16 * MIB


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(MIB), b""):
            digest.update(block)
    return digest.hexdigest()


def copy_partition(partition, disk):
    """Write only allocated extents into the data partition of the new sparse disk file."""
    end = partition.stat().st_size
    with partition.open("rb") as source, disk.open("r+b") as target:
        offset = 0
        while offset < end:
            try:
                offset = os.lseek(source.fileno(), offset, os.SEEK_DATA)
            except OSError as error:
                if error.errno == errno.ENXIO:
                    break
                raise
            limit = min(end, os.lseek(source.fileno(), offset, os.SEEK_HOLE))
            if limit <= offset:
                raise ValueError("Invalid sparse partition extent")
            while offset < limit:
                data = os.pread(source.fileno(), min(MIB, limit - offset), offset)
                if not data or os.pwrite(target.fileno(), data, OFFSET + offset) != len(data):
                    raise OSError("Incomplete fixture copy")
                offset += len(data)


def make_image(tools, work, output, index_bytes, partition_bytes):
    partition = work / "partition.raw"
    disk = work / "disk.raw"
    virtual_disk = work / "fixture.vhdx"
    with partition.open("xb") as stream:
        stream.truncate(partition_bytes)
    subprocess.run([tools / "mkntfs", "-F", "-Q", "-s", "512", "-c", "4096", "-p", "32768",
                    "-H", "255", "-S", "63", "-L", "N2RINDEX", partition], check=True)
    for selector in (["-m"], ["-i", "5"]):
        info = subprocess.check_output([tools / "ntfsinfo", *selector, partition], text=True)
        match = re.search(r"^\s*Index Block Size:\s*(\d+)", info, re.MULTILINE)
        if not match or int(match.group(1)) != index_bytes:
            raise ValueError(f"NTFS volume or root index differs from {index_bytes} bytes")
    subprocess.run([tools / "ntfsfix", "-n", partition], check=True)
    with partition.open("rb") as stream:
        boot = stream.read(512)
    index_code = struct.unpack_from("<b", boot, 68)[0]
    index = 4096 * index_code if index_code > 0 else 1 << -index_code
    if (boot[3:11] != b"NTFS    " or struct.unpack_from("<H", boot, 11)[0] != 512
            or boot[13] != 8 or struct.unpack_from("<b", boot, 64)[0] != -10 or index != index_bytes):
        raise ValueError("Unexpected NTFS boot-sector geometry")

    with disk.open("xb") as stream:
        stream.truncate(OFFSET + partition_bytes + MIB)
    layout_text = ("label: gpt\nunit: sectors\n\n"
                   "start=2048,size=30720,type=E3C9E316-0B5C-4DB8-817D-F92DF00215AE\n"
                   f"start=32768,size={partition_bytes // 512},type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7\n")
    subprocess.run(["sfdisk", "--quiet", disk], input=layout_text, text=True, check=True)
    layout = json.loads(subprocess.check_output(["sfdisk", "--json", disk]))["partitiontable"]
    data = layout["partitions"][1]
    if layout["sectorsize"] != 512 or data["start"] * 512 != OFFSET or data["size"] * 512 != partition_bytes:
        raise ValueError("Unexpected GPT fixture layout")
    if partition.stat().st_size != partition_bytes:
        raise ValueError("Formatter changed the source partition length")
    copy_partition(partition, disk)
    subprocess.run(["qemu-img", "convert", "-T", "none", "-t", "none", "-f", "raw", "-O", "vhdx",
                    "-o", "subformat=dynamic,block_size=1048576", disk, virtual_disk], check=True)
    subprocess.run(["qemu-img", "compare", "-T", "none", "-f", "raw", "-F", "vhdx", disk, virtual_disk], check=True)
    path = output / f"ntfs-index-{index_bytes}.vhdx"
    shutil.copyfile(virtual_disk, path)
    digest = sha256(path)
    if digest != sha256(virtual_disk):
        raise OSError("Published fixture differs from the verified image")
    return {"image": path.name, "sha256": digest, "disk_guid": layout["id"], "partition_guid": data["uuid"],
            "partition_offset": OFFSET, "partition_bytes": partition_bytes, "sector_bytes": 512,
            "cluster_bytes": 4096, "file_record_bytes": 1024, "index_record_bytes": index_bytes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help=f"upstream ntfs-3g_ntfsprogs-{VERSION}.tgz")
    parser.add_argument("output", type=Path, help="new output directory")
    parser.add_argument("--index-bytes", nargs="+", type=int, default=[4096, 2048, 8192])
    parser.add_argument("--partition-mib", type=int, default=51200)
    args = parser.parse_args()
    if args.partition_mib <= 0 or args.partition_mib % 64:
        parser.error("Partition size must be a positive multiple of 64 MiB")
    if len(set(args.index_bytes)) != len(args.index_bytes) or any(
            n < 512 or n > 65536 or n & (n - 1) for n in args.index_bytes):
        parser.error("Select distinct power-of-two index sizes from 512 to 65536 bytes")
    archive = args.archive.resolve(strict=True)
    if sha256(archive) != ARCHIVE_SHA256:
        parser.error(f"Expected the upstream {VERSION} archive with SHA-256 {ARCHIVE_SHA256}")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cases = []
    with tempfile.TemporaryDirectory(prefix="n2r-ntfs-index-", dir="/var/tmp") as scratch:
        work = Path(scratch)
        source = work / "src"
        source.mkdir()
        subprocess.run(["tar", "-xzf", archive, "-C", source, "--strip-components=1"], check=True)
        log_path = output / "formatter-build.log"
        with log_path.open("w") as log:
            subprocess.run(["./configure", "--disable-ntfs-3g", "--disable-plugins", "--disable-shared", "--enable-static"],
                           cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True)
            jobs = str(max(1, len(os.sched_getaffinity(0)) // 4))
            subprocess.run(["make", "-j", jobs], cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True)
            tools = source / "ntfsprogs"
            formatter = tools / "mkntfs.c"
            original = formatter.read_bytes()
            default = b"vol->indx_record_size = 4096;"
            if original.count(default) != 1:
                raise ValueError("Expected one formatter index-size assignment")
            for n in args.index_bytes:
                formatter.write_bytes(original.replace(default, f"vol->indx_record_size = {n};".encode()))
                subprocess.run(["make", "-j", jobs, "mkntfs"], cwd=tools, stdout=log, stderr=subprocess.STDOUT, check=True)
                case_dir = work / str(n)
                case_dir.mkdir()
                cases.append(make_image(tools, case_dir, output, n, args.partition_mib * MIB))
    record = {"formatter_version": VERSION, "archive_sha256": ARCHIVE_SHA256, "fixtures": cases}
    (output / "fixtures.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()