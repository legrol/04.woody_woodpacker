#ifndef COMPRESS_H
# define COMPRESS_H

# include <stdint.h>
# include <stddef.h>

/*
 * 🧊 LIOFILIZACIÓN DE TEJIDO (COMPRESIÓN LZSS)
 * Extrae el agua (redundancias) del archivo binario.
 */

// Comprime el tejido (buffer). Retorna el nuevo tamaño comprimido.
size_t compress_tissue(const uint8_t *src, size_t src_size, uint8_t *out);

// Descomprime el tejido (para pruebas C locales de validación).
size_t decompress_tissue(const uint8_t *src, size_t src_size, uint8_t *out, size_t max_out);

#endif
