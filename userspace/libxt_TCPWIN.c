#include <stdio.h>

#include <xtables.h>

#include "xt_TCPWIN.h"

static const struct xt_option_entry tcpwin_opts[] = {
	{.name = "size", .type = XTTYPE_UINT16, .id = 0,
	 .excl = 0, .flags = XTOPT_PUT, XTOPT_POINTER(struct xt_TCPWIN_info, size)},
	XTOPT_TABLEEND,
};

static void tcpwin_help(void)
{
	printf(
		"TCPWIN target options:\n"
		"  --size			Set TCP window size to <value 0-65535>\n"
	);
}

static void tcpwin_print(const void *entry, const struct xt_entry_target *target, int numeric)
{
	const struct xt_TCPWIN_info *info = (const void *)target->data;
	printf(" tcp window:%u", info->size);
}

static void tcpwin_save(const void *entry, const struct xt_entry_target *target)
{
	const struct xt_TCPWIN_info *info = (const void *)target->data;
	printf(" --size %u", info->size);
}

static void tcpwin_parse(struct xt_option_call *cb)
{
	xtables_option_parse(cb);
}

static void tcpwin_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM,
					"TCPWIN: "
					"\"--size\" is required"
		);
}

static struct xtables_target tcpwin_tg_reg = {
	.name		= "TCPWIN",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct xt_TCPWIN_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_TCPWIN_info)),
	.help		= tcpwin_help,
	.print		= tcpwin_print,
	.save		= tcpwin_save,
	.x6_parse	= tcpwin_parse,
	.x6_fcheck	= tcpwin_check,
	.x6_options	= tcpwin_opts,
};

static void _init(void)
{
	xtables_register_target(&tcpwin_tg_reg);
}
