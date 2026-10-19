#include "compress.h"
#include <string.h>
#include <stdio.h>

/*
 * 🗜️ LZSS-Lite (Compresión)
 * Busca coincidencias hacia atrás en una "ventana" deslizante (hasta 4095 bytes).
 * 
 * Formato del flujo Liofilizado:
 * - 1 Byte de banderas (Flags): Cada bit representa un bloque.
 *   - Bit 0: Literal (se copia 1 byte tal cual).
 *   - Bit 1: Referencia (se leen 2 bytes que contienen offset y longitud).
 * - Los 8 bloques siguientes correspondientes a los 8 bits.
 */

#define WINDOW_SIZE 4095
#define MAX_MATCH_LEN 18
#define MIN_MATCH_LEN 3

size_t compress_tissue(const uint8_t *src, size_t src_size, uint8_t *out)
{
    size_t in_pos = 0;
    size_t out_pos = 0;

    while (in_pos < src_size)
    {
        size_t flags_pos = out_pos++;
        uint8_t flags = 0;
        uint8_t bit_mask = 1;

        for (int i = 0; i < 8; i++)
        {
            if (in_pos >= src_size)
                break;

            // Buscar la mejor coincidencia hacia atrás
            size_t best_offset = 0;
            size_t best_len = 0;

            size_t window_start = (in_pos > WINDOW_SIZE) ? (in_pos - WINDOW_SIZE) : 0;

            for (size_t prev = window_start; prev < in_pos; prev++)
            {
                size_t match_len = 0;
                while (in_pos + match_len < src_size && 
                       match_len < MAX_MATCH_LEN && 
                       src[prev + match_len] == src[in_pos + match_len])
                {
                    match_len++;
                }

                if (match_len >= MIN_MATCH_LEN && match_len > best_len)
                {
                    best_len = match_len;
                    best_offset = in_pos - prev;
                }
            }

            if (best_len >= MIN_MATCH_LEN)
            {
                // Bit a 1: Referencia
                flags |= bit_mask;

                // Empaquetar: Offset (12 bits) | (Longitud - MIN_MATCH_LEN) (4 bits)
                // Usamos Little Endian para comodidad en x86
                uint16_t pack = ((best_offset & 0xFFF) << 4) | ((best_len - MIN_MATCH_LEN) & 0xF);
                out[out_pos++] = pack & 0xFF;
                out[out_pos++] = (pack >> 8) & 0xFF;

                in_pos += best_len;
            }
            else
            {
                // Bit a 0: Literal
                out[out_pos++] = src[in_pos++];
            }

            bit_mask <<= 1;
        }

        out[flags_pos] = flags;
    }

    return out_pos;
}

size_t decompress_tissue(const uint8_t *src, size_t src_size, uint8_t *out, size_t max_out)
{
    size_t in_pos = 0;
    size_t out_pos = 0;

    while (in_pos < src_size && out_pos < max_out)
    {
        uint8_t flags = src[in_pos++];
        uint8_t bit_mask = 1;

        for (int i = 0; i < 8; i++)
        {
            if (in_pos >= src_size || out_pos >= max_out)
                break;

            if (flags & bit_mask)
            {
                // Referencia
                if (in_pos + 1 >= src_size) break;
                uint16_t pack = src[in_pos] | (src[in_pos + 1] << 8);
                in_pos += 2;

                size_t offset = (pack >> 4) & 0xFFF;
                size_t length = (pack & 0xF) + MIN_MATCH_LEN;

                size_t copy_src = out_pos - offset;
                for (size_t l = 0; l < length; l++)
                {
                    if (out_pos < max_out)
                        out[out_pos++] = out[copy_src + l];
                }
            }
            else
            {
                // Literal
                out[out_pos++] = src[in_pos++];
            }

            bit_mask <<= 1;
        }
    }

    return out_pos;
}
