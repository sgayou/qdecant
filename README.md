# qdecant
Decondenses an encrypted/compressed QNXCNDFS file to enable filesystem interoperability.

This is very alpha quality at the moment, and won't work without rebuilding python-lzo to use lzo1c_decompress_safe instead of lzo1x_decompress_safe. This only supports encrypted AND compressed files at the moment and does not (yet) support condensing a
filesystem back into a QNXCNDFS.

And, naturally, you'll need a decryption key for this to work.