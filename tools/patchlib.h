#ifdef UEFI
//provide Print
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
//memcpy and memcmp
#include <Library/BaseLib.h>
#ifdef DISABLE_PRINT
#define Print_patcher(...) do {} while(0)
#else
#define Print_patcher AsciiPrint
#endif
//ascii print only, no format
#define memcpy_patcher CopyMem
#define memcmp_patcher CompareMem
#define malloc AllocatePool
#define free FreePool
#define strlen AsciiStrLen
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define Print_patcher printf
#define memcpy_patcher memcpy
#define memcmp_patcher memcmp
typedef int32_t INT32;
typedef uint32_t UINT32;
typedef int8_t INT8;
typedef uint8_t UINT8;
typedef int16_t INT16;
typedef uint16_t UINT16;
typedef uint64_t UINT64;
typedef int64_t INT64;
typedef char CHAR8;
#define FALSE (1==0)
#define TRUE (1==1)
typedef uint8_t BOOLEAN;
/* ==================== 文件读取 ==================== */
INT32 read_file(const CHAR8* filename, CHAR8** data, INT32* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) return -1;
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    *data = (CHAR8*)malloc(*size);
    if (!*data) {
        fclose(file);
        return -1;
    }
    if (fread(*data, 1, *size, file) != *size) {
        free(*data);
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;
}
#endif
/* ==================== GBL patch ==================== */
INT32 patch_abl_gbl(CHAR8* buffer, INT32 size) {
    CHAR8 target[] = { 'e', 0, 'f', 0, 'i', 0, 's', 0, 'p', 0 };
    CHAR8 replacement[] = { 'n', 0, 'u', 0, 'l', 0, 'l', 0, 's', 0 };
    INT32 target_len = sizeof(target);
    for (INT32 i = 0; i < size - target_len; ++i) {
        if (memcmp_patcher(buffer + i, target, target_len) == 0) {
            memcpy_patcher(buffer + i, replacement, target_len);
            return 0;
        }
    }
    return -1;
}

/* ==================== Boot State锚点 ==================== */
INT16 Original[] = {
    -1, 0x00, 0x00, 0x34, 0x28, 0x00, 0x80, 0x52,
    0x06, 0x00, 0x00, 0x14, 0xE8, -1, 0x40, 0xF9,
    0x08, 0x01, 0x40, 0x39, 0x1F, 0x01, 0x00, 0x71,
    0xE8, 0x07, 0x9F, 0x1A, 0x08, 0x79, 0x1F, 0x53
};
INT16 Patched[] = {
    -1, -1, -1, -1, 0x08, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1
};

INT32 patch_abl_bootstate(CHAR8* buffer, INT32 size, INT8* lock_register_num, INT32* offset) {
    INT32 pattern_len = sizeof(Original) / sizeof(INT16);
    INT32 patched_count = 0;
    if (size < pattern_len) return 0;
    for (INT32 i = 0; i <= size - pattern_len; ++i) {
        BOOLEAN match = TRUE;
        for (INT32 j = 0; j < pattern_len; ++j) {
            if (Original[j] != -1 && (UINT8)buffer[i + j] != (UINT8)Original[j]) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            *lock_register_num = *(INT8*)(&buffer[i]) & 0x1F;
            *offset = (INT32)i;
            for (INT32 j = 0; j < pattern_len; ++j)
                if (Patched[j] != -1) buffer[i + j] = (char)Patched[j];
            patched_count++;
            i += pattern_len - 1;
        }
    }
    return patched_count;
}

/* ==================== 基础工具 ==================== */
static UINT32 read_instr(const CHAR8* buf, INT32 off) {
    return (UINT8)buf[off] |
           ((UINT8)buf[off + 1] << 8) |
           ((UINT8)buf[off + 2] << 16) |
           ((UINT8)buf[off + 3] << 24);
}
static void write_instr(CHAR8* buf, INT32 off, UINT32 val) {
    buf[off] = (char)(val & 0xFF);
    buf[off + 1] = (char)((val >> 8) & 0xFF);
    buf[off + 2] = (char)((val >> 16) & 0xFF);
    buf[off + 3] = (char)((val >> 24) & 0xFF);
}

#define function_start 0xd503233fu
static BOOLEAN is_function_start(const CHAR8* buf, INT32 off) {
    return read_instr(buf, off) == function_start;
}

/* ==================== 数据位置追踪集合 (C 实现) ==================== */
enum DataLocType { REG, STK64, STK8 };
struct DataLoc {
    enum DataLocType type;
    INT32 val;
};

struct LocSet {
    struct DataLoc locs[256];
    INT32 count;
};

static BOOLEAN locset_has(const struct LocSet* set, struct DataLoc l) {
    for (INT32 i = 0; i < set->count; ++i) {
        if (set->locs[i].type == l.type && set->locs[i].val == l.val)
            return TRUE;
    }
    return FALSE;
}
static BOOLEAN locset_has_reg(const struct LocSet* set, INT8 r) {
    struct DataLoc l = { REG, r };
    return locset_has(set, l);
}
static BOOLEAN locset_has_stk64(const struct LocSet* set, UINT32 i) {
    struct DataLoc l = { STK64, (INT32)i };
    return locset_has(set, l);
}
static BOOLEAN locset_has_stk8(const struct LocSet* set, UINT32 i) {
    struct DataLoc l = { STK8, (INT32)i };
    return locset_has(set, l);
}

static void locset_add(struct LocSet* set, struct DataLoc l) {
    if (!locset_has(set, l)) {
        set->locs[set->count++] = l;
    }
}
static void locset_add_reg(struct LocSet* set, INT8 r) {
    locset_add(set, (struct DataLoc){ REG, r });
}
static void locset_add_stk64(struct LocSet* set, UINT32 i) {
    locset_add(set, (struct DataLoc){ STK64, (INT32)i });
}
static void locset_add_stk8(struct LocSet* set, UINT32 i) {
    locset_add(set, (struct DataLoc){ STK8, (INT32)i });
}

static void locset_del(struct LocSet* set, struct DataLoc l) {
    for (INT32 i = 0; i < set->count; ++i) {
        if (set->locs[i].type == l.type && set->locs[i].val == l.val) {
            set->locs[i] = set->locs[set->count - 1];
            set->count--;
            break;
        }
    }
}
static void locset_del_reg(struct LocSet* set, INT8 r) {
    locset_del(set, (struct DataLoc){ REG, r });
}
static void locset_del_stk64(struct LocSet* set, UINT32 i) {
    locset_del(set, (struct DataLoc){ STK64, (INT32)i });
}
static void locset_del_stk8(struct LocSet* set, UINT32 i) {
    locset_del(set, (struct DataLoc){ STK8, (INT32)i });
}

static BOOLEAN locset_empty(const struct LocSet* set) {
    return set->count == 0;
}

static void locset_print(const struct LocSet* set) {
    Print_patcher("  LocSet{");
    for (INT32 i = 0; i < set->count; ++i) {
        if (i) Print_patcher(", ");
        switch (set->locs[i].type) {
            case REG:   Print_patcher("W%d", set->locs[i].val); break;
            case STK64: Print_patcher("[SP+0x%X]/64", set->locs[i].val); break;
            case STK8:  Print_patcher("[SP+0x%X]/8",  set->locs[i].val); break;
        }
    }
    Print_patcher("}\n");
}

/* ==================== 辅助函数 ==================== */
BOOLEAN is_ldrb(const CHAR8* buffer, INT32 offset) {
    return (read_instr(buffer, (int)offset) & 0xFFC00000) == 0x39400000;
}
INT8 dump_register_from_LDRB(const CHAR8* instr) {
    return (INT8)((UINT8)instr[0] & 0x1F);
}
BOOLEAN is_strb(const CHAR8* buffer, INT32 offset) {
    UINT32 instr = read_instr(buffer, (int)offset);
    if ((instr & 0xFFC00000) == 0x39000000) return TRUE;
    if ((instr & 0xFFE00C00) == 0x38000000) return TRUE;
    if ((instr & 0xFFE00C00) == 0x38000C00) return TRUE;
    return FALSE;
}
BOOLEAN is_ldr_x_sp(const CHAR8* buffer, INT32 offset, INT8 target_reg, UINT32* imm_out) {
    UINT32 instr = read_instr(buffer, (int)offset);
    if ((instr & 0xFFC00000) != 0xF9400000) return FALSE;
    if ((instr & 0x1F) != (UINT8)target_reg) return FALSE;
    if (((instr >> 5) & 0x1F) != 31) return FALSE;
    *imm_out = ((instr >> 10) & 0xFFF) << 3;
    return TRUE;
}
BOOLEAN is_str_x_sp(const CHAR8* buffer, INT32 offset, UINT32 expected_imm, INT8* src_reg_out) {
    UINT32 instr = read_instr(buffer, (int)offset);
    if ((instr & 0xFFC00000) != 0xF9000000) return FALSE;
    if (((instr >> 5) & 0x1F) != 31) return FALSE;
    if ((((instr >> 10) & 0xFFF) << 3) != expected_imm) return FALSE;
    *src_reg_out = (INT8)(instr & 0x1F);
    return TRUE;
}
BOOLEAN is_ldrb_sp(const CHAR8* buffer, INT32 offset, INT8 target_reg, UINT32* imm_out) {
    UINT32 instr = read_instr(buffer, (int)offset);
    if ((instr & 0xFFC00000) != 0x39400000) return FALSE;
    if ((instr & 0x1F) != (UINT8)target_reg) return FALSE;
    if (((instr >> 5) & 0x1F) != 31) return FALSE;
    *imm_out = (instr >> 10) & 0xFFF;
    return TRUE;
}
BOOLEAN is_strb_sp(const CHAR8* buffer, INT32 offset, UINT32 expected_imm, INT8* src_reg_out) {
    UINT32 instr = read_instr(buffer, (int)offset);
    if ((instr & 0xFFC00000) != 0x39000000) return FALSE;
    if (((instr >> 5) & 0x1F) != 31) return FALSE;
    if (((instr >> 10) & 0xFFF) != expected_imm) return FALSE;
    *src_reg_out = (INT8)(instr & 0x1F);
    return TRUE;
}

/* ==================== 向下数据流追踪 ==================== */
static INT32 track_forward_patch_strb(CHAR8* buffer, INT32 size, INT32 ldrb_off,
                                      INT8 src_reg, INT32 anchor_off) {
    struct LocSet set;
    set.count = 0;
    locset_add_reg(&set, src_reg);

    Print_patcher("\n=== Forward tracking from LDRB@0x%X (W%d), anchor=0x%X ===\n",
           ldrb_off, (int)src_reg, anchor_off);
    locset_print(&set);

    for (INT32 off = ldrb_off + 4; off < (int)size - 4; off += 4) {
        if (is_function_start(buffer, off)) {
            Print_patcher("0x%X: function boundary, stop\n", off);
            break;
        }
        if (locset_empty(&set)) {
            Print_patcher("  LocSet empty, stop\n");
            break;
        }

        UINT32 instr = read_instr(buffer, off);
        UINT8 rt = instr & 0x1F;
        UINT8 rn = (instr >> 5) & 0x1F;

        /* ---------- STRXt, [SP, #imm]64-bit spill ---------- */
        if ((instr & 0xFFC00000) == 0xF9000000 && rn == 31) {
            UINT32 imm = ((instr >> 10) & 0xFFF) << 3;
            if (locset_has_reg(&set, (INT8)rt)) {
                Print_patcher("  0x%X: STR X%d,[SP,#0x%X] spill64\n", off, rt, imm);
                locset_add_stk64(&set, imm);
                locset_print(&set);
            } else if (locset_has_stk64(&set, imm)) {
                Print_patcher("  0x%X: STR X%d,[SP,#0x%X] overwrite stk64 -> del\n", off, rt, imm);
                locset_del_stk64(&set, imm);
            }
            continue;
        }

        /* ---------- LDR Xt, [SP, #imm]  64-bit reload ---------- */
        if ((instr & 0xFFC00000) == 0xF9400000 && rn == 31) {
            UINT32 imm = ((instr >> 10) & 0xFFF) << 3;
            if (locset_has_stk64(&set, imm)) {
                Print_patcher("  0x%X: LDR X%d,[SP,#0x%X] reload64\n", off, rt, imm);
                locset_add_reg(&set, (INT8)rt);
                locset_print(&set);
            } else if (locset_has_reg(&set, (INT8)rt)) {
                Print_patcher("  0x%X: LDR X%d,[SP,#0x%X] overwrite reg -> del\n", off, rt, imm);
                locset_del_reg(&set, (INT8)rt);
            }
            continue;
        }

        /* ---------- STR Wt, [SP, #imm]  32-bit spill ---------- */
        if ((instr & 0xFFC00000) == 0xB9000000 && rn == 31) {
            UINT32 imm = ((instr >> 10) & 0xFFF) << 2;
            if (locset_has_reg(&set, (INT8)rt)) {
                Print_patcher("  0x%X: STR W%d,[SP,#0x%X] spill32\n", off, rt, imm);
                locset_add_stk64(&set, imm);
                locset_print(&set);
            } else if (locset_has_stk64(&set, imm)) {
                Print_patcher("  0x%X: STR W%d,[SP,#0x%X] overwrite stk -> del\n", off, rt, imm);
                locset_del_stk64(&set, imm);
            }
            continue;
        }

        /* ---------- LDR Wt, [SP, #imm]  32-bit reload ---------- */
        if ((instr & 0xFFC00000) == 0xB9400000 && rn == 31) {
            UINT32 imm = ((instr >> 10) & 0xFFF) << 2;
            if (locset_has_stk64(&set, imm)) {
                Print_patcher("  0x%X: LDR W%d,[SP,#0x%X] reload32\n", off, rt, imm);
                locset_add_reg(&set, (INT8)rt);
                locset_print(&set);
            } else if (locset_has_reg(&set, (INT8)rt)) {
                Print_patcher("  0x%X: LDR W%d,[SP,#0x%X] overwrite reg -> del\n", off, rt, imm);
                locset_del_reg(&set, (INT8)rt);
            }
            continue;
        }

        /* ---------- LDRB Wt, [任意Xn, #imm] — 外部内存覆写寄存器 ---------- */
        if ((instr & 0xFFC00000) == 0x39400000) {
            if (locset_has_reg(&set, (INT8)rt)) {
                Print_patcher("  0x%X: LDRB W%d,[X%d,#0x%X] overwrite reg -> del\n",
                       off, rt, rn, (instr >> 10) & 0xFFF);
                locset_del_reg(&set, (INT8)rt);
            }
            continue;
        }

        /* ---------- MOV Xd, Xm ---------- */
        if ((instr & 0xFFE0FFE0) == 0xAA0003E0) {
            UINT8 rd = instr & 0x1F;
            UINT8 rm = (instr >> 16) & 0x1F;
            if (locset_has_reg(&set, (INT8)rm) && rd != 31) {
                Print_patcher("  0x%X: MOV X%d,X%d propagate\n", off, rd, rm);
                locset_add_reg(&set, (INT8)rd);
                locset_print(&set);
            } else if (locset_has_reg(&set, (INT8)rd)) {
                Print_patcher("  0x%X: MOV X%d,X%d overwrite -> del\n", off, rd, rm);
                locset_del_reg(&set, (INT8)rd);
            }
            continue;
        }

        /* ---------- MOV Wd, Wm ---------- */
        if ((instr & 0xFFE0FFE0) == 0x2A0003E0) {
            UINT8 rd = instr & 0x1F;
            UINT8 rm = (instr >> 16) & 0x1F;
            if (locset_has_reg(&set, (INT8)rm) && rd != 31) {
                Print_patcher("  0x%X: MOV W%d,W%d propagate\n", off, rd, rm);
                locset_add_reg(&set, (INT8)rd);
                locset_print(&set);
            } else if (locset_has_reg(&set, (INT8)rd)) {
                Print_patcher("  0x%X: MOV W%d,W%d overwrite -> del\n", off, rd, rm);
                locset_del_reg(&set, (INT8)rd);
            }
            continue;
        }

        /* ==========================================================
           STRB — 统一判断，不区分 SP / 非SP
           ========================================================== */
        {
            BOOLEAN is_strb_instr = FALSE;
            UINT8 s_rt = 0, s_rn = 0;
            UINT32 s_imm = 0;

            if ((instr & 0xFFC00000) == 0x39000000) {
                is_strb_instr = TRUE;
                s_rt = instr & 0x1F;
                s_rn = (instr >> 5) & 0x1F;
                s_imm = (instr >> 10) & 0xFFF;
            } else if ((instr & 0xFFE00C00) == 0x38000000 ||
                       (instr & 0xFFE00C00) == 0x38000C00) {
                is_strb_instr = TRUE;
                s_rt = instr & 0x1F;
                s_rn = (instr >> 5) & 0x1F;
                s_imm = (instr >> 12) & 0x1FF;
            }

            if (is_strb_instr) {
                if (locset_has_reg(&set, (INT8)s_rt)) {
                    if (off > anchor_off) {
                        #ifndef DISABLE_PRINT
                        const CHAR8* rn_str = (s_rn == 31) ? "SP" : "Xn";
                        #endif
                        Print_patcher("  0x%X: STRB W%d,[%s,#0x%X] ** SINK (after anchor0x%X) **\n",
                               off, s_rt, rn_str, s_imm, anchor_off);
                        Print_patcher("  Before: %02X %02X %02X %02X\n",
                               (UINT8)buffer[off], (UINT8)buffer[off + 1],
                               (UINT8)buffer[off + 2], (UINT8)buffer[off + 3]);

                        UINT32 patched_instr = (instr & ~0x1Fu) | 31u;
                        write_instr(buffer, off, patched_instr);

                        Print_patcher("  After : %02X %02X %02X %02X (Rt -> WZR)\n",
                               (UINT8)buffer[off], (UINT8)buffer[off + 1],
                               (UINT8)buffer[off + 2], (UINT8)buffer[off + 3]);
                        return 1;
                    } else {
                        Print_patcher("  0x%X: STRB W%d,[X%d,#0x%X] before anchor -> spill8\n",
                               off, s_rt, s_rn, s_imm);
                        if (s_rn == 31) {
                            locset_add_stk8(&set, s_imm);
                        }
                        locset_print(&set);
                    }
                } else if (s_rn == 31 && locset_has_stk8(&set, s_imm)) {
                    Print_patcher("  0x%X: STRB W%d,[SP,#0x%X] overwrite stk8 -> del\n",
                           off, s_rt, s_imm);
                    locset_del_stk8(&set, s_imm);
                }
                continue;
            }
        }
    }

    Print_patcher("Forward tracking: no sink STRB found after anchor 0x%X\n", anchor_off);
    return -1;
}

/* ==================== 反向找LDRB 源头 + 就地向下追踪 ==================== */
INT32 find_ldrB_instructio_reverse(CHAR8* buffer, INT32 size,
                                   INT32 anchor_offset, INT8 target_register) {
    INT32 now_offset = anchor_offset - 4;
    INT8 current_target = target_register;
    INT32 bounce_count = 0;
    const INT32 MAX_BOUNCES = 8;

    while (now_offset >= 0) {
        if (is_function_start(buffer, now_offset)) {
            Print_patcher("Reached function start at 0x%X\n", now_offset);
            break;
        }

        /* ---- 64-bit 栈 reload弹跳 ---- */
        UINT32 spill_imm = 0;
        if (is_ldr_x_sp(buffer, now_offset, current_target, &spill_imm)) {
            Print_patcher("Bounce at 0x%X: LDR X%d,[SP,#0x%X]\n",
                   now_offset, (int)current_target, spill_imm);
            INT32 search = now_offset - 4;
            BOOLEAN found = FALSE;
            while (search >= 0) {
                if (is_function_start(buffer, search)) break;
                INT8 src = -1;
                if (is_str_x_sp(buffer, search, spill_imm, &src)) {
                    Print_patcher("  -> STR X%d,[SP,#0x%X] at 0x%X\n",
                           (INT32)src, spill_imm, search);
                    current_target = src;
                    now_offset = search - 4;
                    found = TRUE;
                    bounce_count++;
                    break;
                }
                search -= 4;
            }
            if (!found) {
                Print_patcher("  -> No matching STR, abort\n");
                return -1;
            }
            if (bounce_count > MAX_BOUNCES) {
                Print_patcher("Too many bounces\n");
                return -1;
            }
            continue;
        }

        /* ---- byte 级栈 reload 弹跳 ---- */
        UINT32 byte_imm = 0;
        if (is_ldrb_sp(buffer, now_offset, current_target, &byte_imm)) {
            Print_patcher("Byte bounce at 0x%X: LDRB W%d,[SP,#0x%X]\n",
                   now_offset, (int)current_target, byte_imm);
            INT32 search = now_offset - 4;
            BOOLEAN found = FALSE;
            while (search >= 0) {
                if (is_function_start(buffer, search)) break;
                INT8 src = -1;
                if (is_strb_sp(buffer, search, byte_imm, &src)) {
                    Print_patcher("  -> STRB W%d,[SP,#0x%X] at 0x%X\n",
                           (INT32)src, byte_imm, search);
                    current_target = src;
                    now_offset = search - 4;
                    found = TRUE;
                    bounce_count++;
                    break;
                }
                search -= 4;
            }
            if (!found) {
                Print_patcher("  -> No matching STRB, abort\n");
                return -1;
            }
            if (bounce_count > MAX_BOUNCES) {
                Print_patcher("Too many bounces\n");
                return -1;
            }
            continue;
        }

        /* ---- 真正源头: LDRB W{current_target}, [Xn!=SP, #imm] ---- */
        if (is_ldrb(buffer, now_offset)) {
            UINT32 instr = read_instr(buffer, now_offset);
            UINT8 rt = instr & 0x1F;
            UINT8 rn = (instr >> 5) & 0x1F;

            if ((INT8)rt == current_target && rn != 31) {
                Print_patcher("Found source LDRB at 0x%X: LDRB W%d,[X%d,#0x%X](%d bounces)\n",
                       now_offset, rt, rn, (instr >> 10) & 0xFFF, bounce_count);
                Print_patcher("  Before: %02X %02X %02X %02X\n",
                       (UINT8)buffer[now_offset], (UINT8)buffer[now_offset + 1],
                       (UINT8)buffer[now_offset + 2], (UINT8)buffer[now_offset + 3]);

                /* Patch 源头 -> MOV Wt, #1 */
                UINT32 mov_inst = 0x52800020u | (UINT8)current_target;
                write_instr(buffer, now_offset, mov_inst);

                Print_patcher("  After : %02X %02X %02X %02X (MOV W%d, #1)\n",
                       (UINT8)buffer[now_offset], (UINT8)buffer[now_offset + 1],
                       (UINT8)buffer[now_offset + 2], (UINT8)buffer[now_offset + 3],
                       (int)current_target);

                INT32 fwd = track_forward_patch_strb(
                    buffer, size,
                    now_offset,
                    current_target,
                    anchor_offset
                );
                if (fwd <= 0) {
                    Print_patcher("Warning: sink STRB not found after anchor 0x%X\n", anchor_offset);
                    return -1;
                }
                Print_patcher("Sink patched successfully.\n");
                return 0;
            }
        }

        now_offset -= 4;
    }

    return -1;
}

/* ==================== ADRL 地址计算 ==================== */
static BOOLEAN str_at(const CHAR8* buffer, INT32 size, INT64 file_off, const CHAR8* needle) {
    if (file_off < 0) return FALSE;
    INT32 len = strlen(needle);
    if ((INT32)file_off + len >= size) return FALSE;
    return memcmp_patcher(buffer + file_off, needle, len) == 0;
}

/* ==================== ADRL 三连识别工具 ==================== */
static BOOLEAN is_adrp(UINT32 instr, UINT8* rd_out) {
    if ((instr & 0x9F000000) != 0x90000000) return FALSE;
    *rd_out = instr & 0x1F;
    return TRUE;
}

static BOOLEAN is_add_imm_x(UINT32 instr, UINT8* rd_out, UINT8* rn_out, UINT32* imm_out) {
    if ((instr & 0xFF800000) == 0x91000000) {
        *rd_out = instr & 0x1F;
        *rn_out = (instr >> 5) & 0x1F;
        *imm_out = (instr >> 10) & 0xFFF;
        return TRUE;
    }
    if ((instr & 0xFF800000) == 0x91400000) {
        *rd_out = instr & 0x1F;
        *rn_out = (instr >> 5) & 0x1F;
        *imm_out = ((instr >> 10) & 0xFFF) << 12;
        return TRUE;
    }
    return FALSE;
}

static UINT32 adrp_with_rd(UINT32 instr, UINT8 new_rd) {
    return (instr & ~0x1Fu) | (new_rd & 0x1Fu);
}

static UINT32 add_with_reg(UINT32 instr, UINT8 new_reg) {
    instr = (instr & ~0x1Fu) | (new_reg & 0x1Fu);
    instr = (instr & ~(0x1Fu << 5)) | ((UINT32)(new_reg & 0x1Fu) << 5);
    return instr;
}

static INT64 calc_adrl_file_offset(const CHAR8* buffer, INT32 adrp_off, UINT64 load_base) {
    UINT32 i0 = read_instr(buffer, adrp_off);
    UINT32 i1 = read_instr(buffer, adrp_off + 4);

    UINT8 rd0 = 0, rd1 = 0, rn1 = 0;
    UINT32 add_imm = 0;
    if (!is_adrp(i0, &rd0)) return -1;
    if (!is_add_imm_x(i1, &rd1, &rn1, &add_imm)) return -1;
    if (rd1 != rd0 || rn1 != rd0) return -1;

    UINT64 pc = load_base + (UINT64)adrp_off;
    UINT64 page_pc = pc & ~0xFFFull;

    UINT64 immlo = (i0 >> 29) & 0x3;
    UINT64 immhi = (i0 >> 5) & 0x7FFFF;
    INT64 imm = (INT64)((immhi << 2) | immlo);
    if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1);
    imm <<= 12;

    UINT64 target_va = (UINT64)((INT64)page_pc + imm) + add_imm;
    INT64 file_off = (INT64)(target_va - load_base);
    return file_off;
}

INT32 patch_adrl_unlocked_to_locked(CHAR8* buffer, INT32 size, UINT64 load_base) {
    if (size < 24) return 0;

    INT32 patched = 0;

    for (INT32 i = 0; i <= size - 24; i += 4) {
        UINT32 i0 = read_instr(buffer, (int)(i + 0));
        UINT32 i1 = read_instr(buffer, (int)(i + 4));
        UINT32 i2 = read_instr(buffer, (int)(i + 8));
        UINT32 i3 = read_instr(buffer, (int)(i + 12));
        UINT32 i4 = read_instr(buffer, (int)(i + 16));
        UINT32 i5 = read_instr(buffer, (int)(i + 20));

        UINT8 xa = 0, rd1 = 0, rn1 = 0;
        UINT32 imm1 = 0;
        if (!is_adrp(i0, &xa)) continue;
        if (!is_add_imm_x(i1, &rd1, &rn1, &imm1)) continue;
        if (rd1 != xa || rn1 != xa) continue;

        UINT8 xb = 0, rd3 = 0, rn3 = 0;
        UINT32 imm3 = 0;
        if (!is_adrp(i2, &xb)) continue;
        if (!is_add_imm_x(i3, &rd3, &rn3, &imm3)) continue;
        if (rd3 != xb || rn3 != xb) continue;

        UINT8 xc = 0, rd5 = 0, rn5 = 0;
        UINT32 imm5 = 0;
        if (!is_adrp(i4, &xc)) continue;
        if (!is_add_imm_x(i5, &rd5, &rn5, &imm5)) continue;
        if (rd5 != xc || rn5 != xc) continue;

        if (xa == xb || xb == xc || xa == xc) continue;

        INT64 off0 = calc_adrl_file_offset(buffer, (int)(i + 0), load_base);
        INT64 off1 = calc_adrl_file_offset(buffer, (int)(i + 8), load_base);
        INT64 off2 = calc_adrl_file_offset(buffer, (int)(i + 16), load_base);

        if (!str_at(buffer, size, off0, "unlocked")) continue;
        if (!str_at(buffer, size, off1, "locked")) continue;
        if (!str_at(buffer, size, off2, "androidboot.vbmeta.device_state")) continue;

        Print_patcher("Found ADRL triple at 0x%X:\n", i);
        Print_patcher("  [0x%X] ADRP+ADD X%d -> file:0x%llX \"unlocked\"\n",
               i, xa, (unsigned long long)off0);
        Print_patcher("  [0x%X] ADRP+ADD X%d -> file:0x%llX \"locked\"\n",
               i + 8, xb, (unsigned long long)off1);
        Print_patcher("  [0x%X] ADRP+ADD X%d  -> file:0x%llX \"androidboot.vbmeta.device_state\"\n",
               i + 16, xc, (unsigned long long)off2);

        UINT32 new_adrp = adrp_with_rd(i2, xa);
        UINT32 new_add = add_with_reg(i3, xa);

        Print_patcher("  Patch pair-0: ADRP %08X->%08X, ADD %08X->%08X\n",
               i0, new_adrp, i1, new_add);

        write_instr(buffer, (int)(i + 0), new_adrp);
        write_instr(buffer, (int)(i + 4), new_add);

        patched++;
        i += 20;
    }

    if (patched == 0)
        Print_patcher("ADRL triple not found\n");
    else
        Print_patcher("ADRL patch applied: %d location(s)\n", patched);

    return patched;
}

INT32 patch_adrl_unlocked_to_locked_verify(CHAR8* buffer, INT32 size, UINT64 load_base) {
    if (size < 24) return 0;

    INT32 patched = 0;

    for (INT32 i = 0; i <= size - 24; i += 4) {
        UINT32 i0 = read_instr(buffer, (int)(i + 0));
        UINT32 i1 = read_instr(buffer, (int)(i + 4));
        UINT32 i2 = read_instr(buffer, (int)(i + 8));
        UINT32 i3 = read_instr(buffer, (int)(i + 12));
        UINT32 i4 = read_instr(buffer, (int)(i + 16));
        UINT32 i5 = read_instr(buffer, (int)(i + 20));

        UINT8 xa = 0, rd1 = 0, rn1 = 0;
        UINT32 imm1 = 0;
        if (!is_adrp(i0, &xa)) continue;
        if (!is_add_imm_x(i1, &rd1, &rn1, &imm1)) continue;
        if (rd1 != xa || rn1 != xa) continue;

        UINT8 xb = 0, rd3 = 0, rn3 = 0;
        UINT32 imm3 = 0;
        if (!is_adrp(i2, &xb)) continue;
        if (!is_add_imm_x(i3, &rd3, &rn3, &imm3)) continue;
        if (rd3 != xb || rn3 != xb) continue;

        UINT8 xc = 0, rd5 = 0, rn5 = 0;
        UINT32 imm5 = 0;
        if (!is_adrp(i4, &xc)) continue;
        if (!is_add_imm_x(i5, &rd5, &rn5, &imm5)) continue;
        if (rd5 != xc || rn5 != xc) continue;

        if (xa == xb || xb == xc || xa == xc) continue;

        INT64 off0 = calc_adrl_file_offset(buffer, (int)(i + 0), load_base);
        INT64 off1 = calc_adrl_file_offset(buffer, (int)(i + 8), load_base);
        INT64 off2 = calc_adrl_file_offset(buffer, (int)(i + 16), load_base);

        if (!str_at(buffer, size, off0, "locked")) continue;
        if (!str_at(buffer, size, off1, "locked")) continue;
        if (!str_at(buffer, size, off2, "androidboot.vbmeta.device_state")) continue;

        Print_patcher("Found ADRL triple at 0x%X:\n", i);
        Print_patcher("  [0x%X] ADRP+ADD X%d -> file:0x%llX \"locked\"\n",
               i, xa, (unsigned long long)off0);
        Print_patcher("  [0x%X] ADRP+ADD X%d -> file:0x%llX \"locked\"\n",
               i + 8, xb, (unsigned long long)off1);
        Print_patcher("  [0x%X] ADRP+ADD X%d  -> file:0x%llX \"androidboot.vbmeta.device_state\"\n",
               i + 16, xc, (unsigned long long)off2);
        patched++;
        i += 20;
    }

    return patched;
}
BOOLEAN PatchBuffer(CHAR8* data, INT32 size) {
    if (patch_abl_gbl((CHAR8*)data, size) != 0)
        Print_patcher("Warning: Failed to patch ABL GBL\n");

    if (patch_adrl_unlocked_to_locked((CHAR8*)data, size, 0) == 0)
        Print_patcher("Warning: ADRL triple not found, skipping\n");
    if (patch_adrl_unlocked_to_locked_verify((CHAR8*)data, size, 0) == 0)
        Print_patcher("Warning: ADRL verification failed\n");

    INT32 offset = -1;
    INT8 lock_register_num = -1;
    INT32 num_patches = patch_abl_bootstate((CHAR8*)data, size, &lock_register_num, &offset);
    if (num_patches == 0) {
        Print_patcher("Error: Failed to find/patch ABL Boot State\n");
        free(data);
        return 0;
    }
    Print_patcher("Anchor offset : 0x%X\n", offset);
    Print_patcher("Lock register : W%d\n", (int)lock_register_num);
    Print_patcher("Boot patches: %d\n", num_patches);

    if (find_ldrB_instructio_reverse((CHAR8*)data, size, offset, lock_register_num) != 0) {
        Print_patcher("Warning: Failed to patch LDRB->STRB chain for W%d\n",
               (int)lock_register_num);
    }
    return 1;
}