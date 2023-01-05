/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2023, Technology Innovation Institute
 *
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#define read_sized_data(T, d, f)			\
	do {						\
		int err;				\
		d = malloc(sizeof(T));			\
		assert(d);				\
							\
		err = fread(d, 1, sizeof(T), f);	\
		assert(err == sizeof(T));		\
							\
		d = realloc(d, sizeof(T) + d->size);	\
		assert(d);				\
							\
		err = fread(d->data, 1, d->size, f);	\
		assert(err == d->size);			\
	} while (0)

typedef uint64_t u64;
typedef uint64_t local_t;

struct ftrace_file {
	size_t size;
	struct ftrace_initial_wrap {
		size_t size;
		struct ftrace_initial *initial;
	} initial;
	struct ftrace_header_page_format_wrap {
		size_t size;
		struct ftrace_header_page_format *header_page_format;
	} header_page_format;
	struct ftrace_header_event_format_wrap {
		size_t size;
		struct ftrace_header_event_format *header_event_format;
	} header_event_format;
	struct ftrace_event_formats_wrap {
		size_t size;
		struct ftrace_event_formats *ftrace_event_formats;
	} ftrace_event_formats;
	struct event_formats_wrap {
		size_t size;
		struct event_formats *event_formats;
	} event_formats;
	struct kallsyms_info_wrap {
		size_t size;
		struct kallsyms_info *kallsyms_info;
	} kallsyms_info;
	struct printk_info_wrap {
		size_t size;
		struct printk_info *printk_info;
	} printk_info;
	struct process_info_wrap {
		size_t size;
		struct process_info *process_info;
	} process_info;
	struct header_end_wrap {
		size_t size;
		struct header_end *header_end;
	} header_end;
	struct flyrecord_wrap {
		size_t size;
		struct flyrecord *flyrecords;
	} flyrecords;
	struct padding_wrap {
		size_t size;
		char *data;
	} padding;
	struct rest_data_wrap {
		size_t size;
		char *data;
	} rest_data;
};

struct ftrace_initial {
	uint8_t magic[3];
	union {
		struct {
			char tracing[7];
			char version[1];
			char nullt[1];
		} __attribute__((packed)) ver_dec;
		char ver_str[7 + 1 + 1];
	};
	uint8_t endianess;
	uint8_t bwidth;
	uint32_t pagesize;
} __attribute__((packed));

struct ftrace_header_page_format {
	char magic[12];
	uint64_t size;

	char data[];
} __attribute__((packed));

struct ftrace_header_event_format {
	char magic[13];
	uint64_t size;

	char data[];
} __attribute__((packed));

struct ftrace_event_format {
	uint64_t size;

	char data[];
} __attribute__((packed));

struct ftrace_event_formats {
	uint32_t count;

	char data[];
} __attribute__((packed));

struct event_formats {
	uint32_t count;

	char data[];
} __attribute__((packed));

struct event_format_nxt {
	uint64_t size;
	char data[];
} __attribute__((packed)) header;

struct event_formats_nxt {
	uint32_t count;

	char data[];
} __attribute__((packed));

struct kallsyms_info {
	uint32_t size;

	char data[];
} __attribute__((packed));

struct printk_info {
	uint32_t size;

	char data[];
} __attribute__((packed));

struct process_info {
	uint64_t size;

	char data[];
} __attribute__((packed));

struct cpu_info {
	uint32_t size;

	struct {
		uint64_t offset;
		uint64_t size;
	} __attribute__((packed)) data[];
} __attribute__((packed));

struct option_data {
	uint32_t size;

	char data[];
} __attribute__((packed));

struct option {
	uint16_t option;

	char data[];
};

struct command {
	char name[10];
} __attribute__((packed));

struct header_end {
	uint32_t n_cpu;

	char data[];
} __attribute__((packed));

struct ftrace_func_field {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	unsigned long ip;
	unsigned long parent_ip;
} __attribute__((packed));

struct page_header {
	u64 timestamp;
	union {
		local_t commit;
		int overwrite;
	};
	char data[4080];
} __attribute__((packed));

struct flyrecord {
	uint64_t offset;
	uint64_t size;
} __attribute__((packed));
