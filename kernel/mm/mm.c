/*
 * Copyright (c) 2020 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * OS-Lab-2020 (i.e., ChCore) is licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *   http://license.coscl.org.cn/MulanPSL
 *   THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 *   PURPOSE.
 *   See the Mulan PSL v1 for more details.
 */

#include <common/mm.h>
#include <common/kprint.h>
#include <common/macro.h>

#include "buddy.h"
#include "slab.h"
#include "page_table.h"

extern unsigned long *img_end;

#define PHYSICAL_MEM_START (24*1024*1024)	//24M

#define START_VADDR phys_to_virt(PHYSICAL_MEM_START)	//24M
#define NPAGES (128*1000)

#define PHYSICAL_MEM_END (PHYSICAL_MEM_START+NPAGES*BUDDY_PAGE_SIZE)

/*
 * Layout:
 *
 * | metadata (npages * sizeof(struct page)) | start_vaddr ... (npages * PAGE_SIZE) |
 *
 */

unsigned long get_ttbr1(void)
{
	unsigned long pgd;

	__asm__("mrs %0,ttbr1_el1":"=r"(pgd));
	return pgd;
}

/*
 * map_kernel_space: map the kernel virtual address
 * [va:va+size] to physical addres [pa:pa+size].
 * 1. get the kernel pgd address
 * 2. fill the block entry with corresponding attribution bit
 *
 */

void map_kernel_space(vaddr_t va, paddr_t pa, size_t len)
{
	// <lab2>
	vaddr_t *pgtbl = (vaddr_t *)get_ttbr1();

	pa = ROUND_DOWN(pa, PAGE_SIZE);
	va = ROUND_DOWN(va, PAGE_SIZE);
	len = ROUND_UP(len, PAGE_SIZE);

	for(int i = 0; i < len/PAGE_SIZE; i++){
		ptp_t *cur_ptp = (ptp_t *)pgtbl;
		ptp_t *next_ptp;
		pte_t *entry;
		int level = 0;
		while(level < 3){
			/* notice alloc is 1 along the way, to allocate the new page in the page table */
			int ret = get_next_ptp(cur_ptp, level, va, &next_ptp, &entry, 1);
			if(ret < 0){
				return ret;
			}
			cur_ptp = next_ptp;
			level++;
		}
		/* level == 3, get the corresponding page entry and modify the flags */
		u32 index = GET_L3_INDEX(va);
		entry = &(next_ptp->ent[index]);

		entry->pte = 0;
		entry->l3_page.is_valid = 1;
		entry->l3_page.is_page = 1;
		entry->l3_page.pfn = pa >> PAGE_SHIFT;

		entry->l3_page.UXN = 1;
		entry->l3_page.AF = 1;
		entry->l3_page.SH = 3;
		entry->l3_page.attr_index = 4;
		entry->l3_page.is_valid = 1;

		va += PAGE_SIZE;
		pa += PAGE_SIZE;
	}

	flush_tlb();

	// <lab2>
}

void kernel_space_check(void)
{
	unsigned long kernel_val;
	for (unsigned long i = 0; i < 128 * 1024 / 4; i++) {
		*(unsigned long *)(KBASE + (128 << 21) + i * PAGE_SIZE) = 1;
		kernel_val = *(unsigned long *)(KBASE + (128 << 21) + i * PAGE_SIZE);
		// kinfo("kernel_val: %lx\n", kernel_val);
		BUG_ON(kernel_val != 1);
	}
	kinfo("kernel space check pass\n");
}

struct phys_mem_pool global_mem;

void mm_init(void)
{
	vaddr_t free_mem_start = 0;
	struct page *page_meta_start = NULL;
	u64 npages = 0;
	u64 start_vaddr = 0;

	free_mem_start =
	    phys_to_virt(ROUND_UP((vaddr_t) (&img_end), PAGE_SIZE));
	npages = NPAGES;
	start_vaddr = START_VADDR;
	kdebug("[CHCORE] mm: free_mem_start is 0x%lx, free_mem_end is 0x%lx\n",
	       free_mem_start, phys_to_virt(PHYSICAL_MEM_END));

	if ((free_mem_start + npages * sizeof(struct page)) > start_vaddr) {
		BUG("kernel panic: init_mm metadata is too large!\n");
	}

	page_meta_start = (struct page *)free_mem_start;
	kdebug("page_meta_start: 0x%lx, real_start_vadd: 0x%lx,"
	       "npages: 0x%lx, meta_page_size: 0x%lx\n",
	       page_meta_start, start_vaddr, npages, sizeof(struct page));

	kdebug("img end address is: 0x%lx", &img_end);
		// img end address is: 0xa0000
	// [INFO] [CHCORE] mm: free_mem_start is 0xffffff00000a0000, free_mem_end is 0xffffff0020c00000
	// [INFO] page_meta_start: 0xffffff00000a0000, real_start_vadd: 0xffffff0001800000,npages: 0x1f400, meta_page_size: 0x20
	
	/* buddy alloctor for managing physical memory */
	init_buddy(&global_mem, page_meta_start, start_vaddr, npages);

	/* slab alloctor for allocating small memory regions */
	init_slab();

	map_kernel_space(KBASE + (128UL << 21), 128UL << 21, 128UL << 21);
	//check whether kernel space [KABSE + 256 : KBASE + 512] is mapped 
	kernel_space_check();
}
