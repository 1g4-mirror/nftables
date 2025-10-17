#ifndef _NFT_AFLPLUSPLUS_H_
#define _NFT_AFLPLUSPLUS_H_

#include <nftables/libnftables.h>

/*
 * enum nft_afl_fuzzer_stage - current fuzzer stage
 *
 * @NFT_AFL_FUZZER_DISABLED: running without --fuzzer
 * @NFT_AFL_FUZZER_PARSER: only fuzz the parser, do not run eval step.
 * @NFT_AFL_FUZZER_EVALUATION: continue to evaluation step, if possible.
 * @NFT_AFL_FUZZER_NETLINK_RO: convert internal representation to netlink buffer but don't send any changes to the kernel.
 * @NFT_AFL_FUZZER_NETLINK_RW: send the netlink message to kernel for processing.
 */
enum nft_afl_fuzzer_stage {
	NFT_AFL_FUZZER_DISABLED,
	NFT_AFL_FUZZER_PARSER,
	NFT_AFL_FUZZER_EVALUATION,
	NFT_AFL_FUZZER_NETLINK_RO,
	NFT_AFL_FUZZER_NETLINK_RW,
};

static inline void nft_afl_print_build_info(FILE *fp)
{
#if HAVE_FUZZER_BUILD && defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
	fprintf(fp, "\nWARNING: BUILT WITH FUZZER SUPPORT AND AFL INSTRUMENTATION\n");
#elif defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
	fprintf(fp, "\nWARNING: BUILT WITH AFL INSTRUMENTATION\n");
#elif HAVE_FUZZER_BUILD
	fprintf(fp, "\nWARNING: BUILT WITH FUZZER SUPPORT BUT NO AFL INSTRUMENTATION\n");
#endif
}

#if HAVE_FUZZER_BUILD
extern int nft_afl_init(struct nft_ctx *nft, enum nft_afl_fuzzer_stage s);
extern int nft_afl_main(struct nft_ctx *nft);
#else
static inline int nft_afl_main(struct nft_ctx *ctx)
{
        return -1;
}
static inline int nft_afl_init(struct nft_ctx *nft, enum nft_afl_fuzzer_stage s){ return -1; }
#endif

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define __AFL_INIT() do { } while (0)
#endif
#endif
