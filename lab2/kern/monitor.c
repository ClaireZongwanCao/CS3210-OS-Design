// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE 80 // enough for one VGA text line


struct Command {
  const char *name;
  const char *desc;
  // return -1 to force monitor to exit
  int (*func)(int argc, char **argv, struct Trapframe * tf);
};

static struct Command commands[] = {
  { "help",      "Display this list of commands",        mon_help       },
  { "info-kern", "Display information about the kernel", mon_infokern   },
  { "showmappings", "Display physical pages mapping", mon_showmappings },
  { "backtrace", "Display current calling stack", mon_backtrace         },
  { "setperm", "Set or clear the permissions of current virtual address", mon_setperm },
  { "dumpv", "dump the contents of a range of memory given a virtual address", mon_dumpv},
  { "dumpp", "dump the contents of a range of memory given a physical address", mon_dumpp},
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
  int i;

  for (i = 0; i < NCOMMANDS; i++)
    cprintf("%s - %s\n", commands[i].name, commands[i].desc);
  return 0;
}

int
mon_infokern(int argc, char **argv, struct Trapframe *tf)
{
  extern char _start[], entry[], etext[], edata[], end[];

  cprintf("Special kernel symbols:\n");
  cprintf("  _start                  %08x (phys)\n", _start);
  cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
  cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
  cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
  cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
  cprintf("Kernel executable memory footprint: %dKB\n",
          ROUNDUP(end - entry, 1024) / 1024);
  return 0;
}

int
mon_dumpv(int argc, char **argv, struct Trapframe *tf){
if (argc != 3) {
cprintf("Usage: dumpv start_va end_va\n");
return 0;
}
void* start = (void*)strtol(argv[1], NULL, 0);
void* end = (void*)strtol(argv[2], NULL, 0);
cprintf("Virtual Memory Dump\n");
for (; start <= end; start++){
  cprintf("vm at %08x is %08x\n",start,  *(char*)start);
}
return 0;
}
int
mon_dumpp(int argc, char **argv, struct Trapframe *tf){
if (argc != 3) {
cprintf("Usage: dumpv start_va end_va\n");
return 0;
}
physaddr_t  start = strtol(argv[1], NULL, 0);
physaddr_t  end = strtol(argv[2], NULL, 0);
cprintf("Physical Memory Dump\n");
for (; start <= end; start++){
  cprintf("pm at %08x is %08x\n", KADDR(start),  *(char*)KADDR(start));
}
return 0;
}
int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
if (argc != 3) {
  cprintf("Usage: showmappings start_va end_va\n");
  return 0;
}
uint32_t start = strtol(argv[1], NULL, 0);
uint32_t end = strtol(argv[2], NULL, 0);
for (; start <= end; start += PGSIZE) {
   pte_t *pte = pgdir_walk(kern_pgdir, (void *)start, 0);
   if (!pte || !(*pte & PTE_P)) {
       cprintf("page not mapped\n");
   }
   else {
       cprintf("va: %08x  pa: %08x  PTE_P: %x  PTE_U: %x  PTE_W: %x\n", start, PTE_ADDR(*pte), *pte&PTE_P, *pte&PTE_U, *pte&PTE_W);
   }   
}
return 0;
}

int
mon_setperm(int argc, char **argv, struct Trapframe *tf){
if (argc != 4) {
   cprintf("Usage: setperm vaddress 0/1 P/W/U\n");
   return 0;
}
uint32_t va = strtol(argv[1], NULL, 0);
pte_t *pte = pgdir_walk(kern_pgdir, (void *)va, 0);
uint32_t perm = 0;
if (argv[3][0] == 'P') perm = PTE_P;
if (argv[3][0] == 'W') perm = PTE_W;
if (argv[3][0] == 'U') perm = PTE_U;
if (argv[2][0] == '0')
    *pte = *pte & ~perm;
else 
    *pte = *pte | perm;
cprintf("va: %08x  pa: %08x  PTE_P: %x  PTE_U: %x  PTE_W: %x\n", va, PTE_ADDR(*pte), *pte&PTE_P, *pte&PTE_U, *pte&PTE_W);
return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
  // Your code here.
  uint32_t *ebp = (uint32_t*)read_ebp();
    struct Eipdebuginfo info;
    cprintf ("Stack backtrace:\n");
    while (ebp != 0x0){
        cprintf (" ebp %08x eip %08x args %08x %08x %08x %08x %08x\n", ebp, ebp[1], ebp[2], ebp[3], ebp[4], ebp[5], ebp[6]);
        debuginfo_eip(ebp[1],&info);
        cprintf ("%s:%d: %.*s+%d\n", info.eip_file, info.eip_line, info.eip_fn_namelen,info.eip_fn_name, ebp[1]-info.eip_fn_addr);
	ebp = (uint32_t*) ebp[0];
    }
    return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
  int argc;
  char *argv[MAXARGS];
  int i;

  // Parse the command buffer into whitespace-separated arguments
  argc = 0;
  argv[argc] = 0;
  while (1) {
    // gobble whitespace
    while (*buf && strchr(WHITESPACE, *buf))
      *buf++ = 0;
    if (*buf == 0)
      break;

    // save and scan past next arg
    if (argc == MAXARGS-1) {
      cprintf("Too many arguments (max %d)\n", MAXARGS);
      return 0;
    }
    argv[argc++] = buf;
    while (*buf && !strchr(WHITESPACE, *buf))
      buf++;
  }
  argv[argc] = 0;

  // Lookup and invoke the command
  if (argc == 0)
    return 0;
  for (i = 0; i < NCOMMANDS; i++)
    if (strcmp(argv[0], commands[i].name) == 0)
      return commands[i].func(argc, argv, tf);
  cprintf("Unknown command '%s'\n", argv[0]);
  return 0;
}

void
monitor(struct Trapframe *tf)
{
  char *buf;

  cprintf("Welcome to the JOS kernel monitor!\n");
  cprintf("Type 'help' for a list of Rcommands.\n");


  while (1) {
    buf = readline("K> ");
    if (buf != NULL)
      if (runcmd(buf, tf) < 0)
        break;
  }
}
