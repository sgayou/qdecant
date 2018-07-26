#!/usr/bin/python3

""" Decondenses an encrypted/compressed QNXCNDFS file to enable filesystem interoperability. """

import argparse
import lzo
import os
import pathlib
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def __decrypt(key, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decondense(file, key):
    with open(file, "rb") as cnd_file:
        cnd_file_contents = cnd_file.read()

    with open(key, "rb") as key_file:
        key_file_contents = key_file.read()

    raw_size = struct.unpack("<Q", cnd_file_contents[0x10:0x18])[0]
    extents_offset = struct.unpack("<Q", cnd_file_contents[0x28:0x30])[0]
    clusters_offset = struct.unpack("<Q", cnd_file_contents[0x30:0x38])[0]
    data_start_offset = struct.unpack("<Q", cnd_file_contents[0x38:0x40])[0]

    print("Extents Table Offset: 0x{0:x}".format(extents_offset))
    print("Cluster Table Offset: 0x{0:x}".format(clusters_offset))
    print("Data Start Offset: 0x{0:x}".format(data_start_offset))

    clusters_table = cnd_file_contents[clusters_offset:data_start_offset]
    extents_table = cnd_file_contents[extents_offset:clusters_offset]

    outbuf = b""
    decrypted_cluster_offset_table = dict()

    print("Processing clusters...")
    for i in range(0, len(clusters_table), 16):
        cluster_offset, cluster_length = struct.unpack(
            "<QQ", clusters_table[i : i + 16]
        )
        print(
            "Cluster Offset: 0x{:x} Length: {} bytes".format(
                cluster_offset, cluster_length
            )
        )
        cluster_iv = cnd_file_contents[cluster_offset : cluster_offset + 0x10]
        cluster_tag = cnd_file_contents[cluster_offset + 0x10 : cluster_offset + 0x20]
        cluster_data = cnd_file_contents[
            cluster_offset + 0x20 : cluster_offset + cluster_length
        ]

        decrypted_cluster_offset_table[cluster_offset] = len(outbuf)

        # lzo.decompress is hacked up at the moment to do a lzo1c_decompress_safe instead.
        # Need to get changes merged upstream else write my own module.
        outbuf = outbuf + lzo.decompress(
            __decrypt(key_file_contents, cluster_iv, cluster_data, cluster_tag),
            False,
            0x7FFFFFFF,  # TODO, cluster size?
        )

    final_output = bytearray(raw_size)

    print("Processing extents...")
    for i in range(0, len(extents_table), 32):
        extent_start_addr, extent_bytes, extent_cluster, extent_offset = struct.unpack(
            "<QQQQ", extents_table[i : i + 32]
        )
        final_output[extent_start_addr : extent_start_addr + extent_bytes] = outbuf[
            decrypted_cluster_offset_table[
                struct.unpack(
                    "<Q", cnd_file_contents[extent_cluster : extent_cluster + 8]
                )[0]
            ]
            + extent_offset : decrypted_cluster_offset_table[
                struct.unpack(
                    "<Q", cnd_file_contents[extent_cluster : extent_cluster + 8]
                )[0]
            ]
            + extent_offset
            + extent_bytes
        ]
        print(
            "0x{:x} {} 0x{:x} 0x{:x}".format(
                extent_start_addr, extent_bytes, extent_cluster, extent_offset
            )
        )

    with open(file + ".dec", "wb") as out_file:
        out_file.write(final_output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="qnxcndfs file to decondense")
    parser.add_argument("key", help="encryption / decryption key file")
    args = parser.parse_args()

    if not pathlib.Path(args.file).is_file():
        print("The qnxcndfs path does not point to a file.")
        exit(1)

    if not pathlib.Path(args.key).is_file():
        print("The key path does not point to a file.")
        exit(1)

    decondense(args.file, args.key)
