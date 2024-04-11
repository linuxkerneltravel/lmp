/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H


struct event {
	unsigned long reclaim;
	unsigned long reclaimed;
	unsigned int unqueued_dirty;
	unsigned int congested;
	unsigned int writeback;
};



#endif /* __BOOTSTRAP_H */
