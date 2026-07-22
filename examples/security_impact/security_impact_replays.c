#include <limits.h>
#include <stdio.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

/* Adapted from the Linux fallocate case documented by Wang et al. (APSys 2012). */
NOINLINE long long fallocate_post_overflow_guard(long long offset,
                                                 long long len,
                                                 long long maxbytes)
{
    long long end;

    if (offset < 0 || len <= 0)
        return -22;

    end = offset + len;
    if (end > maxbytes || end < 0)
        return -27;

    return end;
}

/* A common allocation-size idiom: the overflow test follows signed multiply. */
NOINLINE int allocation_post_multiply_guard(int count, int width)
{
    int bytes;

    if (count <= 0 || width <= 0)
        return -22;

    bytes = count * width;
    if (bytes < 0 || bytes / count != width)
        return -75;

    return bytes;
}

/*
 * A bounded memory-safety witness for the allocation-size policy gap.  The
 * arena models a four-byte allocation followed by a canary.  We cap the
 * downstream write at eight bytes, so the replay exposes undersizing without
 * performing an enormous allocation or an out-of-bounds C access.
 */
NOINLINE int allocation_canary_witness(int count, int width)
{
    unsigned char arena[12];
    unsigned long long required;
    unsigned int witness_len;
    int allocated;
    int i;

    for (i = 0; i < (int)sizeof(arena); ++i)
        arena[i] = 0xCC;

    allocated = allocation_post_multiply_guard(count, width);
    if (allocated < 0)
        return allocated;
    if (allocated >= (int)sizeof(arena))
        return 0;

    required = (unsigned long long)(unsigned int)count *
               (unsigned long long)(unsigned int)width;
    witness_len = required > 8 ? 8U : (unsigned int)required;
    for (i = 0; i < (int)witness_len; ++i)
        arena[i] = 0x41;

    return (unsigned int)allocated < witness_len &&
           arena[allocated] != 0xCC;
}

/* Adapted from the ext4 shift-before-check case documented by Wang et al. */
NOINLINE int ext4_post_shift_guard(unsigned int log_groups)
{
    unsigned int groups_per_flex = 1U << log_groups;

    if (groups_per_flex == 0)
        return -1;

    return 0;
}

/* The repaired policy checks the untrusted shift amount before the operation. */
NOINLINE int ext4_pre_shift_guard(unsigned int log_groups)
{
    unsigned int groups_per_flex;

    if (log_groups >= sizeof(unsigned int) * CHAR_BIT)
        return -1;

    groups_per_flex = 1U << log_groups;
    return groups_per_flex == 0 ? -1 : 0;
}

int main(void)
{
    long long offset = LLONG_MAX - 4;
    int allocation_count = (INT_MAX / 2) + 2;

    printf("fallocate=%lld\n",
           fallocate_post_overflow_guard(offset, 8, LLONG_MAX - 1));
    printf("allocation=%d\n",
           allocation_post_multiply_guard(allocation_count, 4));
    printf("allocation_required=%llu\n",
           (unsigned long long)(unsigned int)allocation_count * 4ULL);
    printf("canary_corrupted=%d\n",
           allocation_canary_witness(allocation_count, 4));
    printf("shift_post=%d\n", ext4_post_shift_guard(32));
    printf("shift_pre=%d\n", ext4_pre_shift_guard(32));
    return 0;
}
