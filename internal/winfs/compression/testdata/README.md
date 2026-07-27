# Fixtures de compresión MAM

- `sample_mam.bin`: un buffer comprimido con firma `MAM\x04` (Xpress Huffman).
  Generar en Windows con `RtlCompressBuffer` (COMPRESSION_FORMAT_XPRESS_HUFF)
  anteponiendo el header MAM de 8 bytes: `"MAM\x04"` + uint32 LE del tamaño
  descomprimido.
- `sample_mam.expected`: el contenido original antes de comprimir.

Estos fixtures no se versionan si superan pocos KB; documentar aquí cómo regenerarlos.
