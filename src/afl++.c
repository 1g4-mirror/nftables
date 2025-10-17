/*
 * Copyright (c) Red Hat GmbH.	Author: Florian Westphal <fw@strlen.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 (or any
 * later) as published by the Free Software Foundation.
 */

#include <nft.h>
#include <stdio.h>

#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/wait.h>

#include <afl++.h>
#include <nftables.h>

static const char self_fault_inject_file[] = "/proc/self/make-it-fail";

#ifdef __AFL_FUZZ_TESTCASE_LEN
/* the below macro gets passed via afl-cc, declares prototypes
 * depending on the afl-cc flavor.
 */
__AFL_FUZZ_INIT();
#else
/* this lets the source compile without afl-clang-fast/lto */
static unsigned char fuzz_buf[4096];
static ssize_t fuzz_len;

#define __AFL_FUZZ_TESTCASE_LEN fuzz_len
#define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
#define __AFL_FUZZ_INIT() do { } while (0)
#define __AFL_LOOP(x) \
   ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
#endif

struct nft_afl_state {
	FILE *make_it_fail_fp;
};

static struct nft_afl_state state;

static char *preprocess(unsigned char *input, ssize_t len)
{
	ssize_t real_len = strnlen((char *)input, len);

	if (real_len == 0)
		return NULL;

	if (real_len >= len)
		input[len - 1] = 0;

	return (char *)input;
}

static bool kernel_is_tainted(void)
{
	FILE *fp = fopen("/proc/sys/kernel/tainted", "r");
	unsigned int taint;
	bool ret = false;

	if (fp) {
		if (fscanf(fp, "%u", &taint) == 1 && taint) {
			fprintf(stderr, "Kernel is tainted: 0x%x\n", taint);
			sleep(3);	/* in case we run under fuzzer, don't restart right away */
			ret = true;
		}

		fclose(fp);
	}

	return ret;
}

static void fault_inject_write(FILE *fp, unsigned int v)
{
	rewind(fp);
	fprintf(fp, "%u\n", v);
	fflush(fp);
}

static void fault_inject_enable(const struct nft_afl_state *state)
{
	if (state->make_it_fail_fp)
		fault_inject_write(state->make_it_fail_fp, 1);
}

static void fault_inject_disable(const struct nft_afl_state *state)
{
	if (state->make_it_fail_fp)
		fault_inject_write(state->make_it_fail_fp, 0);
}

static bool nft_afl_run_cmd(struct nft_ctx *ctx, const char *input_cmd)
{
	if (kernel_is_tainted())
		return false;

	switch (ctx->afl_ctx_stage) {
	case NFT_AFL_FUZZER_PARSER:
	case NFT_AFL_FUZZER_EVALUATION:
	case NFT_AFL_FUZZER_NETLINK_RO:
		nft_run_cmd_from_buffer(ctx, input_cmd);
		return true;
	case NFT_AFL_FUZZER_NETLINK_RW:
		break;
	}

	fault_inject_enable(&state);
	nft_run_cmd_from_buffer(ctx, input_cmd);
	fault_inject_disable(&state);

	return kernel_is_tainted();
}

static FILE *fault_inject_open(void)
{
	return fopen(self_fault_inject_file, "r+");
}

static bool nft_afl_state_init(struct nft_afl_state *state)
{
	state->make_it_fail_fp = fault_inject_open();
	return true;
}

int nft_afl_init(struct nft_ctx *ctx, enum nft_afl_fuzzer_stage stage)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	const char instrumented[] = "afl instrumented";
#else
	const char instrumented[] = "no afl instrumentation";
#endif
	nft_afl_print_build_info(stderr);

	if (!nft_afl_state_init(&state))
		return -1;

	ctx->afl_ctx_stage = stage;

	if (state.make_it_fail_fp) {
		unsigned int value;
		int ret;

		rewind(state.make_it_fail_fp);
		ret = fscanf(state.make_it_fail_fp, "%u", &value);
		if (ret != 1 || value != 1) {
			fclose(state.make_it_fail_fp);
			state.make_it_fail_fp = NULL;
		}

		/* if its enabled, disable and then re-enable ONLY
		 * when submitting data to the kernel.
		 *
		 * Otherwise even libnftables memory allocations could fail
		 * which is not what we want.
		 */
		fault_inject_disable(&state);
	}

	fprintf(stderr, "starting (%s, %s fault injection)", instrumented, state.make_it_fail_fp ? "with" : "no");
	return 0;
}

int nft_afl_main(struct nft_ctx *ctx)
{
	unsigned char *buf;
	ssize_t len;

	if (kernel_is_tainted())
		return -1;

	if (state.make_it_fail_fp) {
		FILE *fp = fault_inject_open();

		/* reopen is needed because /proc/self is a symlink, i.e.
		 * fp refers to parent process, not "us".
		 */
		if (!fp) {
			fprintf(stderr, "Could not reopen %s: %s", self_fault_inject_file, strerror(errno));
			return -1;
		}

		fclose(state.make_it_fail_fp);
		state.make_it_fail_fp = fp;
	}

	buf = __AFL_FUZZ_TESTCASE_BUF;

	while (__AFL_LOOP(UINT_MAX)) {
		char *input;

		len = __AFL_FUZZ_TESTCASE_LEN;  // do not use the macro directly in a call!

		input = preprocess(buf, len);
		if (!input)
			continue;

		/* buf is null terminated at this point */
		if (!nft_afl_run_cmd(ctx, input))
			continue;

		/* Kernel is tainted.
		 * exit() will cause a restart from afl-fuzz.
		 * Avoid burning cpu cycles in this case.
		 */
		sleep(1);
	}

	/* afl-fuzz will restart us. */
	return 0;
}
